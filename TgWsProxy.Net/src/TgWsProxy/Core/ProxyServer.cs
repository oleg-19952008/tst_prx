using System.Buffers.Binary;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using TgWsProxy.Configuration;
using TgWsProxy.Crypto;
using TgWsProxy.Observability;
using TgWsProxy.Transport.FakeTls;

namespace TgWsProxy.Core;

/// <summary>
/// Proxy listener — port of the server half of Python <c>proxy/tg_ws_proxy.py</c>
/// (<c>_run</c>: <c>asyncio.start_server</c>, per-connection task set, graceful
/// stop) as a <see cref="BackgroundService"/>: a <see cref="TcpListener"/> on
/// <c>Proxy:Host:Port</c> with an accept loop and one task per connection.
/// PROXY protocol v1 is stripped from the head of each connection when
/// <c>Proxy:ProxyProtocol=true</c> (nginx/haproxy <c>proxy_protocol</c> upstreams).
/// </summary>
public sealed class ProxyServer : BackgroundService
{
    // proxy/tg_ws_proxy.py module constants
    private const double HandshakeTimeoutSeconds = 10.0;   // read timeouts in _read_client_init
    private const double BadHandshakeDrainTimeout = 10.0;  // BAD_HANDSHAKE_DRAIN_TIMEOUT
    private const int BadHandshakeDrainLimit = 64 * 1024;  // BAD_HANDSHAKE_DRAIN_LIMIT
    private const int ProxyProtocolMaxLine = 108;          // spec: PPv1 line ≤ 107 chars + CRLF
    private const int RelayChunkSize = 16384;              // proxy_to_masking_domain chunk size

    private readonly ProxyConfig _config;
    private readonly byte[] _secret;
    private readonly IHostApplicationLifetime _lifetime;
    private readonly ILogger _log = ProgramLogger.For<ProxyServer>();
    private readonly CancellationTokenSource _stopCts = new();
    private Task _supervisor = Task.CompletedTask;

    private TcpListener? _listener;
    private volatile bool _stopping;                      // Python `stopping` flag
    private readonly object _clientsLock = new();
    private readonly HashSet<Task> _clientTasks = new();  // Python `_client_tasks`

    public ProxyServer(IOptions<ProxyConfig> config, IHostApplicationLifetime lifetime)
    {
        _config = config.Value;
        _secret = Convert.FromHexString(_config.Secret);
        _lifetime = lifetime;
    }

    /// <summary>Python <c>_run()</c>: probe FakeTLS profile, start listening, accept loop.</summary>
    private async Task SupervisorAsync()
    {
        var ct = _stopCts.Token;
        TcpListener? listener = null;
        try
        {
            // Probe before listening so a domain that resolves to this proxy
            // fails fast instead of answering itself (tg_ws_proxy._run).
            if (!string.IsNullOrEmpty(_config.FakeTlsDomain))
            {
                FakeTls.SetProfiledAppDataLen(null);
                var appdataLen = await ProbeAppDataLenAsync(_config.FakeTlsDomain, ct)
                    .ConfigureAwait(false);
                FakeTls.SetProfiledAppDataLen(appdataLen);
                if (appdataLen is null)
                    _log.LogWarning("Fake TLS profile unavailable, ServerHello uses random record sizes");
                else
                    _log.LogInformation("Fake TLS profile: first encrypted record {Len} bytes", appdataLen.Value);
            }

            if (!IPAddress.TryParse(_config.Host, out var ip))
            {
                if (!TryResolve(_config.Host, out ip))
                {
                    _log.LogError("Cannot resolve listen address {Host}", _config.Host);
                    StopHost();
                    return;
                }
            }

            listener = new TcpListener(ip, _config.Port);
            try
            {
                listener.Start();
            }
            catch (SocketException ex)
            {
                _log.LogError(ex, "Failed to bind {Host}:{Port}", _config.Host, _config.Port);
                StopHost();
                return;
            }
            _listener = listener;

            LogBanner();

            // Accept loop — Python start_server + client_cb.
            while (!ct.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await listener.AcceptTcpClientAsync(ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (SocketException ex)
                {
                    _log.LogDebug("accept failed: {Err}", ex.Message);
                    continue;
                }
                catch (ObjectDisposedException)
                {
                    break; // listener stopped during shutdown
                }

                if (_stopping)
                {
                    try { client.Close(); } // Python: `if stopping: w.close(); return`
                    catch { /* ignore */ }
                    continue;
                }

                try { client.NoDelay = true; } catch { /* best-effort TCP_NODELAY */ }
                TrySetSocketBuffers(client);

                var task = Task.Run(() => HandleClientAsync(client));
                lock (_clientsLock) _clientTasks.Add(task);
                // Observe faults so an unhandled exception never goes unnoticed.
                _ = task.ContinueWith(static t => _ = t.Exception,
                    CancellationToken.None,
                    TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
                    TaskScheduler.Default);
            }
        }
        catch (Exception ex)
        {
            // Never let an unexpected error kill the process silently.
            _log.LogError(ex, "proxy supervisor crashed");
        }
        finally
        {
            _stopping = true;
            try { listener?.Stop(); } catch { /* ignore */ }

            // Graceful shutdown: give active connections a grace window, then
            // cancel them (replacement for asyncio's task cancellation + wait_closed).
            Task[] pending;
            lock (_clientsLock) pending = _clientTasks.ToArray();
            if (pending.Length > 0)
            {
                _log.LogInformation("Waiting for {Count} active connection(s)…", pending.Length);
                await Task.WhenAny(
                    Task.WhenAll(pending),
                    Task.Delay(TimeSpan.FromSeconds(5))).ConfigureAwait(false);
            }

            _listener = null;
            _log.LogInformation("Proxy listener stopped.");
        }
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Host shutdown (Ctrl+C → StopApplication → host.StopAsync) also feeds
        // our stop token; the supervisor task does the real listening work.
        _ = stoppingToken.Register(static state =>
            ((CancellationTokenSource)state!).Cancel(), _stopCts, useSynchronizationContext: false);
        _supervisor = SupervisorAsync();
        return Task.CompletedTask;
    }

    public override Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _stopping = true;
        try { _listener?.Stop(); } catch { /* ignore */ }
        _stopCts.Cancel();
        try
        {
            await _supervisor.ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _log.LogDebug("supervisor end: {Err}", ex.Message);
        }
        await base.StopAsync(cancellationToken).ConfigureAwait(false);
    }

    public override void Dispose()
    {
        _stopping = true;
        try { _listener?.Stop(); } catch { /* ignore */ }
        _stopCts.Cancel();
        _stopCts.Dispose();
        base.Dispose();
    }

    // -----------------------------------------------------------------------
    // Per-connection handling — port of _handle_client / _read_client_init
    // -----------------------------------------------------------------------

    private async Task HandleClientAsync(TcpClient client)
    {
        ProxyStats.Shared.ConnectionsTotal++;
        ProxyStats.Shared.ConnectionsActive++;
        var label = RemoteLabel(client);
        NetworkStream? stream = null;
        try
        {
            stream = client.GetStream();

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(_stopCts.Token);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(HandshakeTimeoutSeconds));
            var ct = timeoutCts.Token;

            // ---- PROXY protocol v1 (config.proxy_protocol) -----------------
            if (_config.ProxyProtocol)
            {
                var ppLine = await ReadProxyProtocolLineAsync(stream, ct).ConfigureAwait(false);
                if (ppLine is null)
                {
                    _log.LogDebug("[{Label}] disconnected during PROXY header", label);
                    return;
                }
                var ppText = Encoding.ASCII.GetString(ppLine).Trim('\r', '\n', ' ', '\t');
                if (ppText.StartsWith("PROXY ", StringComparison.Ordinal))
                {
                    var parts = ppText.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 6)
                        label = $"{parts[2]}:{parts[4]}"; // src_addr:src_port becomes the log label
                    _log.LogDebug("[{Label}] PROXY protocol: {Line}", label, ppText);
                }
                else
                {
                    _log.LogDebug("[{Label}] expected PROXY header, got: {Got}", label,
                        TruncateForLog(ppText));
                }
            }

            // ---- first byte / Fake TLS detection (_read_client_init) --------
            var firstByte = await ReadExactlyAsync(stream, 1, ct).ConfigureAwait(false);
            if (firstByte is null)
            {
                _log.LogDebug("[{Label}] client disconnected before handshake", label);
                return;
            }

            Stream cltReader = stream, cltWriter = stream;
            byte[] handshake;

            var masking = _config.FakeTlsDomain;
            if (firstByte[0] == FakeTlsConstants.TlsRecordHandshake && !string.IsNullOrEmpty(masking))
            {
                var hdrRest = await ReadExactlyAsync(stream, 4, ct).ConfigureAwait(false);
                if (hdrRest is null)
                {
                    _log.LogDebug("[{Label}] incomplete TLS record header", label);
                    return;
                }
                var tlsHeader = new byte[5];
                tlsHeader[0] = firstByte[0];
                hdrRest.CopyTo(tlsHeader, 1);
                int recordLen = BinaryPrimitives.ReadUInt16BigEndian(tlsHeader.AsSpan(3, 2));

                var recordBody = await ReadExactlyAsync(stream, recordLen, ct).ConfigureAwait(false);
                if (recordBody is null)
                {
                    _log.LogDebug("[{Label}] incomplete TLS record body", label);
                    return;
                }

                var clientHello = new byte[5 + recordBody.Length];
                tlsHeader.CopyTo(clientHello, 0);
                recordBody.CopyTo(clientHello, 5);

                var tlsResult = FakeTls.VerifyClientHello(clientHello, _secret);
                if (tlsResult is null)
                {
                    _log.LogDebug(
                        "[{Label}] Fake TLS verify failed (size={Size} rec={Rec}) -> masking",
                        label, clientHello.Length, recordLen);
                    await ProxyToMaskingDomainAsync(client, stream, clientHello, masking, label)
                        .ConfigureAwait(false);
                    return;
                }

                _log.LogDebug("[{Label}] Fake TLS handshake ok (ts={Ts})", label, tlsResult.Timestamp);

                var serverHello = FakeTls.BuildServerHello(
                    _secret, tlsResult.ClientRandom, tlsResult.SessionId,
                    FakeTls.ParseClientHello(clientHello));

                // await asyncio.sleep(random.uniform(*SERVER_HELLO_DELAY))
                var delayMs = 8 + Random.Shared.Next(0, 17);
                await Task.Delay(delayMs, _stopCts.Token).ConfigureAwait(false);
                await cltWriter.WriteAsync(serverHello, ct).ConfigureAwait(false);
                await cltWriter.FlushAsync(ct).ConfigureAwait(false);

                var tlsStream = new FakeTlsStream(cltReader, cltWriter);
                handshake = await tlsStream
                    .ReadExactlyAsync(Obfuscated2.HandshakeLen, ct)
                    .ConfigureAwait(false) ?? Array.Empty<byte>();
                if (handshake.Length == 0)
                {
                    _log.LogDebug("[{Label}] incomplete obfs2 init inside TLS", label);
                    return;
                }
                cltReader = tlsStream;
                cltWriter = tlsStream;
            }
            else if (!string.IsNullOrEmpty(masking))
            {
                _log.LogDebug("[{Label}] non-TLS byte 0x{Byte:X2} -> HTTP redirect", label, firstByte[0]);
                var redirect = Encoding.ASCII.GetBytes(
                    $"HTTP/1.1 301 Moved Permanently\r\n" +
                    $"Location: https://{masking}/\r\n" +
                    $"Content-Length: 0\r\n" +
                    $"Connection: close\r\n\r\n");
                await cltWriter.WriteAsync(redirect, ct).ConfigureAwait(false);
                await cltWriter.FlushAsync(ct).ConfigureAwait(false);
                return;
            }
            else
            {
                var rest = await ReadExactlyAsync(stream, Obfuscated2.HandshakeLen - 1, ct)
                    .ConfigureAwait(false);
                if (rest is null)
                {
                    _log.LogDebug("[{Label}] client disconnected before handshake", label);
                    return;
                }
                handshake = new byte[Obfuscated2.HandshakeLen];
                handshake[0] = firstByte[0];
                rest.CopyTo(handshake, 1);
            }

            // ---- obfuscated2 handshake --------------------------------------
            var result = Obfuscated2.TryHandshake(handshake, _secret);
            if (result is null)
            {
                ProxyStats.Shared.AddConnectionBad();
                _log.LogWarning("[{Label}] bad handshake (wrong secret or proto)", label);
                await DrainBadHandshakeAsync(cltReader).ConfigureAwait(false);
                return;
            }

            // TODO (checklist items 6..7): MsgSplitter + WS pool bridge /
            // fallback transports once BridgeHandler lands; for now the
            // handshake-verified connection is closed like a failed one.
            _log.LogInformation(
                "[{Label}] handshake ok: DC{Dc}{Media} proto=0x{Proto:X8} (bridge not yet wired — closing)",
                label, result.Dc, result.IsMedia ? " media" : "", result.ProtoInt);
        }
        catch (OperationCanceledException) when (_stopCts.IsCancellationRequested)
        {
            _log.LogDebug("[{Label}] cancelled", label);
        }
        catch (OperationCanceledException)
        {
            _log.LogWarning("[{Label}] timeout during handshake", label);
        }
        catch (IOException ex) when (IsDisconnected(ex))
        {
            _log.LogDebug("[{Label}] client disconnected", label);
        }
        catch (SocketException ex)
        {
            _log.LogDebug("[{Label}] socket error: {Err}", label, ex.Message);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "[{Label}] unexpected: {Exc}", label, ex.Message);
        }
        finally
        {
            ProxyStats.Shared.ConnectionsActive--;
            try { stream?.Dispose(); } catch { /* writer.close() equivalent */ }
            try { client.Close(); } catch { /* ignore */ }
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// <summary>
    /// Reads one PROXY protocol v1 line ("PROXY ...\r\n") byte-wise, refusing
    /// anything longer than the 108-byte spec limit. Returns the raw line
    /// (including CRLF) or <c>null</c> on EOF mid-line.
    /// </summary>
    private static async Task<byte[]> ReadProxyProtocolLineAsync(Stream s, CancellationToken ct)
    {
        var buf = new List<byte>(ProxyProtocolMaxLine);
        var one = new byte[1];
        while (true)
        {
            int n = await s.ReadAsync(one, ct).ConfigureAwait(false);
            if (n == 0)
                return buf.Count > 0 ? buf.ToArray() : null!;
            buf.Add(one[0]);
            if (one[0] == (byte)'\n')
                break;
            if (buf.Count >= ProxyProtocolMaxLine)
                break; // oversized header — hand it to the parser and let it complain
        }
        return buf.ToArray();
    }

    /// <summary>asyncio <c>reader.readexactly(n)</c>; returns <c>null</c> on premature EOF.</summary>
    private static async Task<byte[]?> ReadExactlyAsync(Stream s, int n, CancellationToken ct)
    {
        if (n <= 0) return Array.Empty<byte>();
        var buf = new byte[n];
        var got = 0;
        while (got < n)
        {
            int r;
            try { r = await s.ReadAsync(buf.AsMemory(got, n - got), ct).ConfigureAwait(false); }
            catch (IOException) { r = 0; }
            if (r == 0) return null;
            got += r;
        }
        return buf;
    }

    /// <summary>Port of <c>_drain_bad_handshake</c> with its 10 s / 64 KiB limits.</summary>
    private static async Task DrainBadHandshakeAsync(Stream reader)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(BadHandshakeDrainTimeout));
        try
        {
            var remaining = BadHandshakeDrainLimit;
            var buf = new byte[4096];
            while (remaining > 0 && !cts.IsCancellationRequested)
            {
                var take = Math.Min(buf.Length, remaining);
                int n;
                try { n = await reader.ReadAsync(buf.AsMemory(0, take), cts.Token).ConfigureAwait(false); }
                catch { break; }
                if (n == 0) break;
                remaining -= n;
            }
        }
        catch { /* swallow, like Python's except Exception: pass */ }
    }

    /// <summary>
    /// Port of <c>proxy_to_masking_domain</c>: plain TCP splice to
    /// masking-domain:443, forwarding the original ClientHello first.
    /// </summary>
    private async Task ProxyToMaskingDomainAsync(
        TcpClient client, Stream from, byte[] initialData, string domain, string label)
    {
        TcpClient? up = null;
        try
        {
            up = new TcpClient { NoDelay = true };
            using var connCts = CancellationTokenSource.CreateLinkedTokenSource(_stopCts.Token);
            connCts.CancelAfter(TimeSpan.FromSeconds(HandshakeTimeoutSeconds));
            await up.ConnectAsync(domain, 443, connCts.Token).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _log.LogWarning("[{Label}] masking: cannot connect to {Domain}:443: {Err}",
                label, domain, ex.Message);
            up?.Dispose();
            return;
        }

        _log.LogDebug("[{Label}] masking -> {Domain}:443", label, domain);
        ProxyStats.Shared.AddConnectionMasked();

        var upStream = up.GetStream();
        try
        {
            await upStream.WriteAsync(initialData, _stopCts.Token).ConfigureAwait(false);
            await upStream.FlushAsync(_stopCts.Token).ConfigureAwait(false);
        }
        catch { /* relay below will surface it */ }

        var relayUp = RelayAsync(from, upStream, shutdownWrite: up);
        var relayDown = RelayAsync(upStream, from, shutdownWrite: client);
        await Task.WhenAll(relayUp, relayDown).ConfigureAwait(false);

        try { up.Dispose(); } catch { }
    }

    /// <summary>One direction of the masking splice (Python <c>_relay</c>).</summary>
    private async Task RelayAsync(Stream src, Stream dst, TcpClient shutdownWrite)
    {
        var buf = new byte[RelayChunkSize];
        try
        {
            while (!_stopCts.IsCancellationRequested)
            {
                int n = await src.ReadAsync(buf, _stopCts.Token).ConfigureAwait(false);
                if (n == 0) break;
                await dst.WriteAsync(buf.AsMemory(0, n), _stopCts.Token).ConfigureAwait(false);
                await dst.FlushAsync(_stopCts.Token).ConfigureAwait(false);
            }
        }
        catch { /* ConnectionReset/BrokenPipe/Cancelled equivalents */ }
        finally
        {
            try { shutdownWrite.Client.Shutdown(SocketShutdown.Send); } catch { }
        }
    }

    /// <summary>
    /// Port of <c>fake_tls.probe_appdata_len</c>: send a real TLS 1.3
    /// ClientHello to the masking site, read only the raw first flight and
    /// measure its first ApplicationData record length. The handshake is
    /// never completed.
    /// </summary>
    private async Task<int?> ProbeAppDataLenAsync(string domain, CancellationToken ct)
    {
        TcpClient? tcp = null;
        SslStreamProbe? probe = null;
        try
        {
            // Build a ClientHello via a throwaway SslStream over a memory pipe.
            probe = new SslStreamProbe(domain);
            var clientHello = await probe.BuildClientHelloAsync(ct).ConfigureAwait(false);
            if (clientHello is null) return null;

            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct, _stopCts.Token);
            deadline.CancelAfter(TimeSpan.FromSeconds(FakeTlsConstants.ProfileProbeTimeoutSeconds));

            tcp = new TcpClient { NoDelay = true };
            await tcp.ConnectAsync(domain, 443, deadline.Token).ConfigureAwait(false);
            var s = tcp.GetStream();
            await s.WriteAsync(clientHello, deadline.Token).ConfigureAwait(false);
            await s.FlushAsync(deadline.Token).ConfigureAwait(false);

            var flight = new MemoryStream();
            var buf = new byte[16384];
            while (true)
            {
                int n = await s.ReadAsync(buf, deadline.Token).ConfigureAwait(false);
                if (n == 0) return null;
                flight.Write(buf, 0, n);
                var len = FakeTls.FirstAppDataRecordLen(flight.ToArray());
                if (len is not null)
                    return len == 0 ? null : len;
            }
        }
        catch (Exception ex)
        {
            _log.LogWarning("Fake TLS profile: cannot probe {Domain}:443: {Err}", domain, ex.Message);
            return null;
        }
        finally
        {
            try { tcp?.Dispose(); } catch { }
            probe?.Dispose();
        }
    }

    private void TrySetSocketBuffers(TcpClient client)
    {
        try
        {
            client.SendBufferSize = _config.BufferSize;
            client.ReceiveBufferSize = _config.BufferSize;
        }
        catch { /* best-effort, mirrors set_sock_opts */ }
    }

    private static string RemoteLabel(TcpClient client)
    {
        try
        {
            if (client.Client.RemoteEndPoint is IPEndPoint ep)
                return $"{ep.Address}:{ep.Port}";
        }
        catch { }
        return "?";
    }

    private static bool IsDisconnected(IOException ex) =>
        ex.InnerException is SocketException
        || ex is EndOfStreamException;

    private static string TruncateForLog(string s) =>
        s.Length <= 60 ? s : s[..60];

    private static bool TryResolve(string host, out IPAddress ip)
    {
        try
        {
            foreach (var a in Dns.GetHostAddresses(host))
                if (a.AddressFamily == AddressFamily.InterNetwork)
                {
                    ip = a;
                    return true;
                }
            var any = Dns.GetHostAddresses(host);
            if (any.Length > 0) { ip = any[0]; return true; }
        }
        catch { }
        ip = IPAddress.Loopback;
        return false;
    }

    private void StopHost()
    {
        // Binding failures must not leave a service-less host running.
        _lifetime.StopApplication();
    }

    private void LogBanner()
    {
        var c = _config;
        var linkHost = GetLinkHost(c.Host);
        var domainHex = Convert.ToHexString(Encoding.ASCII.GetBytes(c.FakeTlsDomain)).ToLowerInvariant();
        var ddLink = $"tg://proxy?server={linkHost}&port={c.Port}&secret=dd{c.Secret}";
        var eeLink = $"tg://proxy?server={linkHost}&port={c.Port}&secret=ee{c.Secret}{domainHex}";

        _log.LogInformation("============================================================");
        _log.LogInformation("  Telegram MTProto WS Bridge Proxy");
        _log.LogInformation("  Listening on   {Host}:{Port}", c.Host, c.Port);
        _log.LogInformation("  Secret:        {Secret}", c.Secret);
        if (!string.IsNullOrEmpty(c.FakeTlsDomain))
            _log.LogInformation("  Fake TLS:      {Domain}", c.FakeTlsDomain);
        if (c.ProxyProtocol)
            _log.LogInformation("  PROXY protocol: v1 header expected on each connection");
        _log.LogInformation("  Target DC IPs:");
        foreach (var (dc, ip) in c.ParsedDcRedirects.OrderBy(kv => kv.Key))
            _log.LogInformation("    DC{Dc}: {Ip}", dc, ip);
        if (c.FallbackCfProxy)
        {
            var userDomain = c.CfProxyUserDomains.Count > 0
                ? string.Join(", ", c.CfProxyUserDomains) : "auto";
            _log.LogInformation("  CF proxy:      enabled ({Domain})", userDomain);
        }
        if (c.CfProxyWorkerDomains.Count > 0)
            _log.LogInformation("  CF worker:     enabled ({Domains})", string.Join(", ", c.CfProxyWorkerDomains));
        if (c.H2Enabled)
            _log.LogInformation("  CF H2 media:   enabled");
        if (c.DisableSecure)
            _log.LogInformation("  No secure:     enabled (port 80 for CF proxy/worker)");
        _log.LogInformation("============================================================");
        _log.LogInformation("  Connect:");
        _log.LogInformation("    {Link}", !string.IsNullOrEmpty(c.FakeTlsDomain) ? eeLink : ddLink);
        _log.LogInformation("============================================================");
    }

    /// <summary>Port of <c>utils.get_link_host</c>.</summary>
    internal static string GetLinkHost(string host)
    {
        if (host != "0.0.0.0")
            return host;
        try
        {
            using var s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            s.Connect("8.8.8.8", 80);
            if (s.LocalEndPoint is IPEndPoint ep)
                return ep.Address.ToString();
        }
        catch (SocketException) { }
        return "127.0.0.1";
    }
}

/// <summary>
/// Minimal TLS-record reader over an already-faked TLS session — port of
/// <c>fake_tls.FakeTlsStream</c>: yields ApplicationData payloads, skips CCS
/// records, terminates the stream on any other record type.
/// </summary>
internal sealed class FakeTlsStream : Stream
{
    private readonly Stream _reader;
    private readonly Stream _writer;
    private readonly MemoryStream _readBuf = new();
    private int _readLeft;

    public FakeTlsStream(Stream reader, Stream writer)
    {
        _reader = reader;
        _writer = writer;
    }

    public override bool CanRead => true;
    public override bool CanWrite => true;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    /// <summary>asyncio <c>readexactly(n)</c>; <c>null</c> on premature EOF.</summary>
    public async Task<byte[]?> ReadExactlyAsync(int n, CancellationToken ct = default)
    {
        while (_readBuf.Length < n)
        {
            var payload = await ReadTlsPayloadAsync(ct).ConfigureAwait(false);
            if (payload.Length == 0)
                return null;
            _readBuf.Write(payload, 0, payload.Length);
        }
        var result = new byte[n];
        _readBuf.Position = 0;
        _readBuf.ReadExactly(result);
        var rest = _readBuf.ToArray();
        _readBuf.SetLength(0);
        _readBuf.Write(rest, n, rest.Length - n);
        return result;
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
    {
        if (_readBuf.Length > 0)
        {
            var chunk = new byte[(int)Math.Min(_readBuf.Length, buffer.Length)];
            _readBuf.Position = 0;
            _readBuf.ReadExactly(chunk);
            var rest = _readBuf.ToArray();
            _readBuf.SetLength(0);
            _readBuf.Write(rest, chunk.Length, rest.Length - chunk.Length);
            chunk.CopyTo(buffer);
            return chunk.Length;
        }
        var payload = await ReadTlsPayloadAsync(ct).ConfigureAwait(false);
        if (payload.Length == 0)
            return 0;
        var take = Math.Min(payload.Length, buffer.Length);
        payload.AsMemory(0, take).CopyTo(buffer);
        if (payload.Length > take)
        {
            _readBuf.SetLength(0);
            _readBuf.Write(payload, take, payload.Length - take);
        }
        return take;
    }

    private async Task<byte[]> ReadTlsPayloadAsync(CancellationToken ct)
    {
        if (_readLeft > 0)
        {
            var buf = new byte[Math.Min(_readLeft, 65536)];
            int n;
            try { n = await _reader.ReadAsync(buf, ct).ConfigureAwait(false); }
            catch (IOException) { n = 0; }
            if (n == 0) return Array.Empty<byte>();
            _readLeft -= n;
            return buf.AsSpan(0, n).ToArray();
        }

        while (true)
        {
            var hdr = await ReadExactlyRawAsync(_reader, 5, ct).ConfigureAwait(false);
            if (hdr is null) return Array.Empty<byte>();
            byte rtype = hdr[0];
            int recLen = BinaryPrimitives.ReadUInt16BigEndian(hdr.AsSpan(3, 2));

            if (rtype == FakeTlsConstants.TlsRecordCcs)
            {
                if (recLen > 0)
                    await ReadExactlyRawAsync(_reader, recLen, ct).ConfigureAwait(false);
                continue;
            }
            if (rtype != FakeTlsConstants.TlsRecordAppData)
                return Array.Empty<byte>();

            var data = new byte[Math.Min(recLen, 65536)];
            int got;
            try { got = await _reader.ReadAsync(data, ct).ConfigureAwait(false); }
            catch (IOException) { got = 0; }
            if (got == 0) return Array.Empty<byte>();
            var remaining = recLen - got;
            if (remaining > 0) _readLeft = remaining;
            return data.AsSpan(0, got).ToArray();
        }
    }

    private static async Task<byte[]?> ReadExactlyRawAsync(Stream s, int n, CancellationToken ct)
    {
        var buf = new byte[n];
        var got = 0;
        while (got < n)
        {
            int r;
            try { r = await s.ReadAsync(buf.AsMemory(got, n - got), ct).ConfigureAwait(false); }
            catch (IOException) { return null; }
            if (r == 0) return null;
            got += r;
        }
        return buf;
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
    {
        // Writer side wraps plaintext into TLS appdata records, like
        // FakeTlsStream.write in Python (wrap_tls_record).
        await _writer.WriteAsync(FakeTls.WrapTlsRecord(buffer.Span).AsMemory(), ct).ConfigureAwait(false);
    }

    public override void Write(ReadOnlySpan<byte> buffer) =>
        WriteAsync(buffer.ToArray()).AsTask().GetAwaiter().GetResult();

    public override void Write(byte[] buffer, int offset, int count) =>
        Write(buffer.AsSpan(offset, count));

    public override void Flush() => _writer.Flush();
    public override Task FlushAsync(CancellationToken ct) => _writer.FlushAsync(ct);
    public override int Read(byte[] buffer, int offset, int count) =>
        ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
}

/// <summary>
/// Generates a real TLS 1.3 ClientHello for the FakeTLS profile probe by
/// driving <see cref="System.Net.Security.SslStream"/> against an in-memory
/// sink stream (the Python version uses an ssl.MemoryBIO for exactly this):
/// the client writes its first flight into the sink, we read it back and
/// never complete the handshake.
/// </summary>
internal sealed class SslStreamProbe : IDisposable
{
    /// <summary>Captures everything the client wrote; reads return EOF.</summary>
    private sealed class CaptureStream : Stream
    {
        private readonly MemoryStream _written = new();
        public byte[] Written => _written.ToArray();
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => _written.Length;
        public override long Position { get => _written.Position; set => _written.Position = value; }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => 0; // server side: EOF
        public override void Write(byte[] buffer, int offset, int count) => _written.Write(buffer, offset, count);
        public override void Write(ReadOnlySpan<byte> buffer) => _written.Write(buffer);
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        {
            Write(buffer, offset, count);
            return Task.CompletedTask;
        }
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
        {
            _written.Write(buffer.Span);
            return ValueTask.CompletedTask;
        }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }

    private readonly string _domain;
    private CaptureStream? _sink;
    private SslStream? _ssl;

    public SslStreamProbe(string domain) => _domain = domain;

    public async Task<byte[]?> BuildClientHelloAsync(CancellationToken ct)
    {
        try
        {
            _sink = new CaptureStream();
            _ssl = new SslStream(_sink, leaveInnerStreamOpen: false);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(2));
            try
            {
                await _ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = _domain,
                    ApplicationProtocols =
                    [
                        new SslApplicationProtocol("h2"),
                        new SslApplicationProtocol("http/1.1"),
                    ],
                }, cts.Token).ConfigureAwait(false);
            }
            catch { /* expected: the sink never feeds a ServerHello */ }

            var hello = _sink.Written;
            return hello.Length > 0 ? hello : null;
        }
        catch (Exception)
        {
            return null;
        }
    }

    public void Dispose()
    {
        try { _ssl?.Dispose(); } catch { }
        try { _sink?.Dispose(); } catch { }
    }
}
