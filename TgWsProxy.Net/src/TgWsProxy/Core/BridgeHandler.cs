using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.IO.Pipelines;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using TgWsProxy.Configuration;
using TgWsProxy.Crypto;
using TgWsProxy.Observability;
using TgWsProxy.Transport;
using TgWsProxy.Transport.FakeTls;
using TgWsProxy.Transport.H2;

namespace TgWsProxy.Core;

/// <summary>Transport mode detected from the first bytes of a client connection.</summary>
public enum BridgeMode
{
    /// <summary>Plain obfuscated2 init on the wire (no Fake TLS, no masking).</summary>
    Direct,
    /// <summary>Fake TLS ClientHello carrying the obfuscated2 init inside appdata records.</summary>
    WebSocket,
    /// <summary>HTTP/2-over-CF media path (chosen at route time for media DCs when H2 is enabled).</summary>
    Http2,
}

/// <summary>Outcome of <see cref="BridgeHandler.HandleAsync"/>.</summary>
public enum BridgeOutcome
{
    /// <summary>Session bridged and closed normally.</summary>
    Bridged,
    /// <summary>Handshake was invalid (wrong secret / unknown protocol tag).</summary>
    BadHandshake,
    /// <summary>Traffic was diverted to the masking domain (Fake TLS tag mismatch).</summary>
    Masked,
    /// <summary>Cleartext non-proxy traffic answered with an HTTP redirect to the masking domain.</summary>
    Redirected,
    /// <summary>Client went away before the handshake completed / handshake timed out.</summary>
    Aborted,
}

/// <summary>
/// Client-facing bridge — port of Python <c>proxy/bridge.py</c> plus the
/// per-connection part of <c>tg_ws_proxy::_handle_client/_read_client_init</c>
/// (PORT_PLAN.md §3 Phase C item 6):
/// <list type="number">
///   <item><description>reads the 64-byte obfuscated2 header (or the Fake-TLS record that wraps it),
///     detecting the WS / H2 / direct mode;</description></item>
///   <item><description>validates it against the proxy secret (<see cref="Obfuscated2.TryHandshake"/>);</description></item>
///   <item><description>picks a route: pooled WS → CF-worker WS → CF WS → H2 media channel → direct TCP;</description></item>
///   <item><description>splices the two streams with re-encryption in both directions and shuts
///     <b>both</b> sides down when either direction ends.</description></item>
/// </list>
/// asyncio mapping: <c>StreamReader/StreamWriter</c> become <see cref="PipeReader"/>/
/// <see cref="PipelineExtensions"/> writes; <c>asyncio.wait(FIRST_COMPLETED)</c> over the two
/// forwarding tasks becomes <see cref="Task.WhenAny"/> followed by cancelling the survivor via a
/// linked <see cref="CancellationTokenSource"/>.
/// </summary>
public sealed class BridgeHandler
{
    // tg_ws_proxy.py module constants
    internal const int HandshakeTimeoutSeconds = 10;
    internal const double BadHandshakeDrainTimeout = 10.0;
    internal const int BadHandshakeDrainLimit = 64 * 1024;
    internal const int ReadChunkSize = 65536;          // reader.read(65536)

    // bridge.py TCP fallback backoff
    internal const double TcpBackoffInitial = 30.0;
    internal const double TcpBackoffMax = 3600.0;

    private static ILogger Log => _log ??= ProgramLogger.For<BridgeHandler>();
    private static ILogger? _log;

    private readonly ProxyConfig _config;
    private readonly byte[] _secret;
    private readonly ConnectionPool _pool;
    private readonly CfWorkerPool _workers;
    private readonly DcBalancer _balancer;
    private readonly NetworkDebug _debug;
    private readonly CfH2Pool? _h2Pool;

    /// <summary>Python <c>_tcp_failures / _tcp_retry_after / _tcp_connecting</c>.</summary>
    private readonly ConcurrentDictionary<TcpKey, TcpFailState> _tcpState = new();

    internal BridgeHandler(
        IOptions<ProxyConfig> config,
        ConnectionPool pool,
        CfWorkerPool workers,
        DcBalancer balancer,
        NetworkDebug debug,
        CfH2Pool? h2Pool = null)
    {
        _config = config.Value;
        _secret = Convert.FromHexString(_config.Secret);
        _pool = pool;
        _workers = workers;
        _balancer = balancer;
        _debug = debug;
        _h2Pool = h2Pool;
    }

    /// <summary>Python <c>bridge.reset_tcp_backoff()</c>.</summary>
    public void ResetTcpBackoff() => _tcpState.Clear();

    // ========================================================================
    // entry point (Python _handle_client)
    // ========================================================================

    /// <summary>
    /// Handles one accepted client connection to completion. Never throws: every
    /// failure mode is logged and turned into a <see cref="BridgeOutcome"/>, and
    /// the client socket is always disposed (Python's <c>finally: writer.close()</c>).
    /// </summary>
    public async Task<BridgeOutcome> HandleAsync(Socket client, CancellationToken ct)
    {
        ProxyStats.Shared.AddConnectionTotal(1);
        ProxyStats.Shared.AddConnectionActive(1);

        string label = FormatLabel(client.RemoteEndPoint);
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);

        try
        {
            ApplySocketOptions(client);

            // ---- read the obfuscated2 header (mode detection happens inside) ----
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(HandshakeTimeoutSeconds));
            var init = await ReadClientInitAsync(client, label, timeoutCts.Token)
                       .ConfigureAwait(false);

            if (init is null)
                return _lastOutcome;                     // masked / redirected / aborted

            timeoutCts.CancelAfter(Timeout.InfiniteTimeSpan);   // handshake done: no global timer

            var result = Obfuscated2.TryHandshake(init.Handshake, _secret);
            if (result is null)
            {
                ProxyStats.Shared.AddConnectionBad();
                Log.LogWarning("[{Label}] bad handshake (wrong secret or proto)", label);
                await DrainBadHandshakeAsync(init.ClientInput, ct).ConfigureAwait(false);
                return BridgeOutcome.BadHandshake;
            }

            return await BridgeRoutedAsync(init, result, client, label, ct)
                       .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            Log.LogDebug("[{Label}] cancelled (host shutdown)", label);
            return BridgeOutcome.Aborted;
        }
        catch (OperationCanceledException)               // handshake timeout
        {
            Log.LogWarning("[{Label}] timeout during handshake", label);
            return BridgeOutcome.Aborted;
        }
        catch (EndOfStreamException)
        {
            Log.LogDebug("[{Label}] client disconnected", label);
            return BridgeOutcome.Aborted;
        }
        catch (SocketException exc) when (exc.SocketErrorCode == SocketError.Interrupted
                                          || exc.InnerException is OperationCanceledException)
        {
            // Windows 10053/10054-style aborts during teardown — Python treats these as debug noise.
            Log.LogDebug("[{Label}] socket error during handshake: {Exc}", label, exc.SocketErrorCode);
            return BridgeOutcome.Aborted;
        }
        catch (IOException exc) when (exc.InnerException is SocketException se &&
                                      (se.SocketErrorCode == SocketError.ConnectionAborted ||
                                       se.SocketErrorCode == SocketError.ConnectionReset))
        {
            // Python: winerror 1236 "connection aborted by local system"
            Log.LogDebug("[{Label}] connection aborted by local system", label);
            return BridgeOutcome.Aborted;
        }
        catch (Exception exc)
        {
            Log.LogError(exc, "[{Label}] unexpected", label);
            return BridgeOutcome.Aborted;
        }
        finally
        {
            ProxyStats.Shared.AddConnectionActive(-1);
            QuietCloseSocket(client);
        }
    }

    // ========================================================================
    // handshake reading (Python _read_client_init)
    // ========================================================================

    /// <summary>Everything <see cref="ReadClientInitAsync"/> produced for one session.</summary>
    internal sealed record ClientInit(
        byte[] Handshake,
        PipeReader ClientInput,
        Stream ClientOutput,
        BridgeMode Mode,
        bool FromTls,
        FakeTlsRecordCodec? TlsCodec);

    /// <summary>Outcome of the last <see cref="ReadClientInitAsync"/> call when it returned null.</summary>
    [ThreadStatic] private static BridgeOutcome _lastOutcome;

    /// <summary>
    /// Port of <c>tg_ws_proxy._read_client_init</c>: optional PROXY-protocol v1 line,
    /// then either the raw 64-byte obfuscated2 init (<see cref="BridgeMode.Direct"/>)
    /// or a Fake-TLS ClientHello whose appdata records hide the init
    /// (<see cref="BridgeMode.WebSocket"/>). A ClientHello that fails verification is
    /// relayed to the masking domain; any other cleartext first byte gets an HTTP 301.
    /// Returns <c>null</c> for those side paths (outcome recorded in <see cref="_lastOutcome"/>).
    /// </summary>
    internal async Task<ClientInit?> ReadClientInitAsync(
        Socket client, string label, CancellationToken ct)
    {
        _lastOutcome = BridgeOutcome.Aborted;
        var pipe = new Pipe();
        var input = pipe.Reader;
        var output = new SocketPipeWriter(client, pipe.Writer);
        bool maskingEnabled = !string.IsNullOrEmpty(_config.FakeTlsDomain);

        if (_config.ProxyProtocol)
        {
            var line = await ReadLineAsync(input, ct).ConfigureAwait(false);
            string ppText = Encoding.ASCII.GetString(line).Trim();
            if (ppText.StartsWith("PROXY ", StringComparison.Ordinal))
            {
                var parts = ppText.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 6)
                    label = $"{parts[2]}:{parts[4]}";       // src-ip:src-port becomes the label
                Log.LogDebug("[{Label}] PROXY protocol: {Header}", label, ppText);
            }
            else
            {
                Log.LogDebug("[{Label}] expected PROXY header, got: {Head}", label,
                             ppText.Length > 60 ? ppText[..60] : ppText);
            }
        }

        byte firstByte;
        try
        {
            firstByte = (await ReadExactlyAsync(input, 1, ct).ConfigureAwait(false))[0];
        }
        catch (EndOfStreamException)
        {
            Log.LogDebug("[{Label}] client disconnected before handshake", label);
            return null;
        }

        if (firstByte == FakeTlsConstants.TlsRecordHandshake && maskingEnabled)
        {
            byte[] tlsHeader;
            int recordLen;
            try
            {
                tlsHeader = [firstByte, .. await ReadExactlyAsync(input, 4, ct).ConfigureAwait(false)];
                recordLen = BinaryPrimitives.ReadUInt16BigEndian(tlsHeader.AsSpan(3, 2));
                var recordBody = await ReadExactlyAsync(input, recordLen, ct).ConfigureAwait(false);
                var clientHello = new byte[tlsHeader.Length + recordBody.Length];
                tlsHeader.CopyTo(clientHello, 0);
                recordBody.CopyTo(clientHello, tlsHeader.Length);

                var verified = FakeTls.VerifyClientHello(clientHello, _secret);
                if (verified is null)
                {
                    Log.LogDebug("[{Label}] Fake TLS verify failed (size={Size} rec={Rec}) -> masking",
                                 label, clientHello.Length, recordLen);
                    _lastOutcome = BridgeOutcome.Masked;
                    ProxyStats.Shared.AddConnectionMasked();
                    await ProxyToMaskingDomainAsync(client, clientHello, ct).ConfigureAwait(false);
                    return null;
                }

                Log.LogDebug("[{Label}] Fake TLS handshake ok (ts={Ts})", label, verified.Timestamp);

                var serverHello = FakeTls.BuildServerHello(
                    _secret, verified.ClientRandom, verified.SessionId,
                    FakeTls.ParseClientHello(clientHello));

                // randomised delay like a real TLS stack (SERVER_HELLO_DELAY = 8..24 ms)
                var (lo, hi) = FakeTlsConstants.ServerHelloDelay;
                await Task.Delay(TimeSpan.FromSeconds(
                    lo + RandomNumberGenerator.GetInt32(0, 1_000_000) / 1_000_000.0 * (hi - lo)), ct)
                    .ConfigureAwait(false);

                await output.WriteAsync(serverHello, ct).ConfigureAwait(false);
                await output.FlushAsync(ct).ConfigureAwait(false);

                var codec = new FakeTlsRecordCodec(input, output);
                var handshake = await codec.ReadExactlyAsync(
                    Obfuscated2.HandshakeLen, ct).ConfigureAwait(false);

                return new ClientInit(handshake, input, output,
                                      BridgeMode.WebSocket, FromTls: true, codec);
            }
            catch (EndOfStreamException)
            {
                Log.LogDebug("[{Label}] incomplete TLS record / obfs2 init inside TLS", label);
                return null;
            }
        }

        if (maskingEnabled)
        {
            Log.LogDebug("[{Label}] non-TLS byte 0x{Byte:X2} -> HTTP redirect", label, firstByte);
            byte[] redirect = Encoding.ASCII.GetBytes(
                "HTTP/1.1 301 Moved Permanently\r\n" +
                $"Location: https://{_config.FakeTlsDomain}/\r\n" +
                "Content-Length: 0\r\nConnection: close\r\n\r\n");
            try
            {
                await output.WriteAsync(redirect, CancellationToken.None).ConfigureAwait(false);
                await output.FlushAsync(CancellationToken.None).ConfigureAwait(false);
            }
            catch (IOException) { /* client already gone */ }
            _lastOutcome = BridgeOutcome.Redirected;
            return null;
        }

        try
        {
            var rest = await ReadExactlyAsync(
                input, Obfuscated2.HandshakeLen - 1, ct).ConfigureAwait(false);
            var handshake = new byte[Obfuscated2.HandshakeLen];
            handshake[0] = firstByte;
            rest.CopyTo(handshake, 1);
            return new ClientInit(handshake, input, output,
                                  BridgeMode.Direct, FromTls: false, TlsCodec: null);
        }
        catch (EndOfStreamException)
        {
            Log.LogDebug("[{Label}] client disconnected before handshake", label);
            return null;
        }
    }

    // ========================================================================
    // routing (Python _handle_client body after a valid handshake)
    // ========================================================================

    private async Task<BridgeOutcome> BridgeRoutedAsync(
        ClientInit init, HandshakeResult hs, Socket client, string label, CancellationToken ct)
    {
        int dc = hs.Dc;
        bool isMedia = hs.IsMedia;
        bool isTestDc = _config.ForceTestDc || dc >= 10000;
        if (dc >= 10000)
        {
            Log.LogInformation("[{Label}] test DC{From} -> DC{To}", label, dc, dc - 10000);
            dc -= 10000;
        }

        uint protoInt = hs.ProtoInt;
        short dcIdx = (short)(isMedia ? -dc : dc);
        string mediaTag = isMedia ? " media" : "";

        Log.LogDebug("[{Label}] handshake ok: DC{Dc}{Media} proto=0x{Proto:X8} mode={Mode}",
                     label, dc, mediaTag, protoInt, init.Mode);

        byte[] relayInit = Obfuscated2.GenerateRelayInit(hs.ProtoTag, dcIdx);
        using CryptoContext ctx = Obfuscated2.BuildCryptoCtx(hs.ClientDecPrekeyIv, _secret, relayInit);

        // ---- route 1: pooled direct WS --------------------------------------
        RawWebSocket? ws = await _pool.GetAsync(dc, isMedia, isTestDc).ConfigureAwait(false);
        if (ws is not null)
        {
            Log.LogInformation("[{Label}] DC{Dc}{Media} -> WS pool hit", label, dc, mediaTag);
            ProxyStats.Shared.AddConnectionWs();
            await ws.SendAsync(relayInit, ct).ConfigureAwait(false);
            await BridgeWsReencryptAsync(init.ClientInput, init.ClientOutput, ws, label, ctx,
                dc: dc, isMedia: isMedia,
                splitter: new MsgSplitter(protoInt),
                codec: init.TlsCodec, ct: ct).ConfigureAwait(false);
            return BridgeOutcome.Bridged;
        }

        // ---- routes 2..5: fallback chain (cf_worker → cf/H2 → tcp) ----------
        Log.LogInformation("[{Label}] DC{Dc}{Media} WS pool unavailable -> fallback",
                           label, dc, mediaTag);
        MsgSplitter? splitter = new(protoInt);
        bool ok = await DoFallbackAsync(
            init, relayInit, label, dc, isTestDc, isMedia, mediaTag, ctx,
            splitter, hs.ProtoTag, ct).ConfigureAwait(false);

        if (!ok)
            Log.LogWarning("[{Label}] DC{Dc}{Media} no fallback available", label, dc, mediaTag);
        else
            Log.LogInformation("[{Label}] DC{Dc}{Media} fallback closed", label, dc, mediaTag);

        return ok ? BridgeOutcome.Bridged : BridgeOutcome.Aborted;
    }

    /// <summary>
    /// Port of <c>bridge.do_fallback</c>: tries cf_worker → cf (WS or H2 media) → direct TCP,
    /// returning on the first method that establishes a session.
    /// </summary>
    internal async Task<bool> DoFallbackAsync(
        ClientInit init, byte[] relayInit, string label,
        int dc, bool isTestDc, bool isMedia, string mediaTag,
        CryptoContext ctx, MsgSplitter? splitter, byte[] protoTag, CancellationToken ct)
    {
        var ipTable = isTestDc ? ProtocolConsts.DcTestIps : ProtocolConsts.DcDefaultIps;
        ipTable.TryGetValue(dc, out var fallbackDst);
        bool useCf = _config.FallbackCfProxy && !isTestDc;
        var workerDomains = _config.CfProxyWorkerDomains;

        var methods = new List<string>();
        if (workerDomains.Count > 0 && fallbackDst is not null) methods.Add("cf_worker");
        if (useCf) methods.Add("cf");
        if (fallbackDst is not null) methods.Add("tcp");

        foreach (var method in methods)
        {
            bool ok = method switch
            {
                "cf_worker" => await CfWorkerFallbackAsync(
                    init, relayInit, label, ctx, dc, isTestDc, isMedia,
                    fallbackDst!, ct).ConfigureAwait(false),
                "cf" => await CfFallbackAsync(
                    init, relayInit, label, ctx, dc, isMedia, mediaTag,
                    splitter, protoTag, ct).ConfigureAwait(false),
                "tcp" => await TcpFallbackAsync(
                    init, relayInit, label, ctx, fallbackDst!, 443, ct).ConfigureAwait(false),
                _ => false,
            };
            if (ok) return true;
        }
        return false;
    }

    /// <summary>Port of <c>bridge._cfproxy_worker_fallback</c>.</summary>
    private async Task<bool> CfWorkerFallbackAsync(
        ClientInit init, byte[] relayInit, string label, CryptoContext ctx,
        int dc, bool isTestDc, bool isMedia, string fallbackDst, CancellationToken ct)
    {
        string mediaTag = isMedia ? " media" : "";
        var workerDomains = _config.CfProxyWorkerDomains;
        if (workerDomains.Count == 0) return false;

        var pooled = isTestDc ? null
            : await _workers.GetAsync(dc, fallbackDst, workerDomains).ConfigureAwait(false);

        RawWebSocket ws;
        if (pooled is not null)
        {
            (ws, _) = pooled.Value;
            Log.LogInformation("[{Label}] DC{Dc}{Media} -> CF worker pool hit via {Domain} for {Dst}",
                               label, dc, mediaTag, pooled.Value.WorkerDomain, fallbackDst);
        }
        else
        {
            string path = "/apiws?" + new Dictionary<string, string>
            {
                ["dst"] = fallbackDst,
                ["dc"] = dc.ToString(),
            }.ToQueryString();

            ws = null!;
            bool connected = false;
            foreach (var workerDomain in _workers.AvailableDomains(workerDomains))
            {
                Log.LogInformation("[{Label}] DC{Dc}{Media} -> trying CF worker {Domain} for {Dst}",
                                   label, dc, mediaTag, workerDomain, fallbackDst);
                try
                {
                    ws = await RawWebSocket.ConnectAsync(
                        workerDomain, workerDomain, TimeSpan.FromSeconds(10),
                        path: path, secure: !_config.DisableSecure,
                        config: _config, ct: ct).ConfigureAwait(false);
                    connected = true;
                    break;
                }
                catch (Exception exc)
                {
                    _workers.ReportFailure(workerDomain, exc);
                    Log.LogWarning("[{Label}] DC{Dc}{Media} CF worker {Domain} failed: {Exc}",
                                   label, dc, mediaTag, workerDomain, Describe(exc));
                }
            }
            if (!connected) return false;
        }

        ProxyStats.Shared.AddConnectionCfproxy();
        await ws.SendAsync(relayInit, ct).ConfigureAwait(false);
        // Python passes splitter=None on this path (the worker relays raw frames)
        await BridgeWsReencryptAsync(init.ClientInput, init.ClientOutput, ws, label, ctx,
            dc: dc, isMedia: isMedia, splitter: null, codec: init.TlsCodec, ct: ct)
            .ConfigureAwait(false);
        return true;
    }

    /// <summary>Port of <c>bridge._cfproxy_fallback</c> including the H2 media branch.</summary>
    private async Task<bool> CfFallbackAsync(
        ClientInit init, byte[] relayInit, string label, CryptoContext ctx,
        int dc, bool isMedia, string mediaTag, MsgSplitter? splitter,
        byte[] protoTag, CancellationToken ct)
    {
        // --- media + H2 pool: multiplexed HTTP/2 channel instead of a WS socket ---
        if (isMedia && _h2Pool is not null)
        {
            HttpChannel? channel = await _h2Pool.OpenAsync(dc, label, ct).ConfigureAwait(false);
            if (channel is not null)
            {
                ProxyStats.Shared.AddConnectionH2();
                ProxyStats.Shared.AddConnectionCfproxy();
                await BridgeH2Async(init.ClientInput, init.ClientOutput, channel, ctx,
                                   protoTag, init.TlsCodec, ct).ConfigureAwait(false);
                return true;
            }
        }

        RawWebSocket? ws = null;
        string? chosenDomain = null;
        Log.LogInformation("[{Label}] DC{Dc}{Media} -> trying CF proxy", label, dc, mediaTag);
        var connectStarted = StopwatchMono.Now;

        foreach (var baseDomain in _balancer.GetDomainsForDc(dc))
        {
            string domain = $"kws{dc}.{baseDomain}";
            try
            {
                ws = await RawWebSocket.ConnectAsync(
                    domain, domain, TimeSpan.FromSeconds(10),
                    secure: !_config.DisableSecure, config: _config, ct: ct)
                    .ConfigureAwait(false);
                chosenDomain = baseDomain;
                break;
            }
            catch (Exception exc) when (exc is not OperationCanceledException)
            {
                Log.LogWarning("[{Label}] DC{Dc}{Media} CF proxy failed: {Exc}",
                               label, dc, mediaTag, Describe(exc));
            }
        }

        if (ws is null) return false;

        Log.LogDebug("[{Label}] WS CONNECT DC{Dc}{Media} route=cf setup_ms={Ms:F0}",
                     label, dc, mediaTag, (StopwatchMono.Now - connectStarted) * 1000);
        if (chosenDomain is not null && _balancer.UpdateDomainForDc(dc, chosenDomain))
            Log.LogInformation("[{Label}] Switched active CF domain", label);

        ProxyStats.Shared.AddConnectionCfproxy();
        await ws.SendAsync(relayInit, ct).ConfigureAwait(false);
        await BridgeWsReencryptAsync(init.ClientInput, init.ClientOutput, ws, label, ctx,
            dc: dc, isMedia: isMedia, splitter: splitter, codec: init.TlsCodec, ct: ct)
            .ConfigureAwait(false);
        return true;
    }

    /// <summary>Port of <c>bridge._tcp_fallback</c> (with the per-(ip,port) backoff table).</summary>
    private async Task<bool> TcpFallbackAsync(
        ClientInit init, byte[] relayInit, string label, CryptoContext ctx,
        string dst, int port, CancellationToken ct)
    {
        var key = new TcpKey(dst, port);
        var state = _tcpState.GetOrAdd(key, _ => new TcpFailState());

        double now = StopwatchMono.Now;
        lock (state)
        {
            if (state.Connecting || now < state.RetryAfter)
            {
                Log.LogDebug("[{Label}] TCP fallback to {Dst}:{Port} skipped (backoff or connecting)",
                             label, dst, port);
                return false;
            }
            state.Connecting = true;
        }

        TcpClient? remote = null;
        try
        {
            try
            {
                Log.LogInformation("[{Label}] TCP fallback to {Dst}:{Port}", label, dst, port);
                remote = new TcpClient { NoDelay = true };
                using (var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
                {
                    connectCts.CancelAfter(TimeSpan.FromSeconds(10));
                    await remote.ConnectAsync(dst, port, connectCts.Token).ConfigureAwait(false);
                }
                var netStream = remote.GetStream();
                await netStream.WriteAsync(relayInit, ct).ConfigureAwait(false);
                await netStream.FlushAsync(ct).ConfigureAwait(false);

                lock (state)
                {
                    state.Failures = 0;
                    state.RetryAfter = 0;
                }
            }
            catch (Exception exc) when (exc is not OperationCanceledException)
            {
                double delay;
                lock (state)
                {
                    state.Failures++;
                    delay = Math.Min(
                        TcpBackoffInitial * Math.Pow(2, Math.Min(state.Failures - 1, 7)),
                        TcpBackoffMax);
                    state.RetryAfter = StopwatchMono.Now + delay;
                }
                Log.LogWarning("[{Label}] TCP fallback to {Dst}:{Port} failed: {Exc}; retry in {Delay:F0}s",
                               label, dst, port, Describe(exc), delay);
                remote?.Dispose();
                return false;
            }
            finally
            {
                lock (state) state.Connecting = false;
            }

            ProxyStats.Shared.AddConnectionTcpFallback();
            await BridgeTcpReencryptAsync(init.ClientInput, init.ClientOutput,
                                          remote, label, ctx, init.TlsCodec, ct)
                .ConfigureAwait(false);
            return true;
        }
        finally
        {
            if (remote is not null)
            {
                try { remote.Dispose(); } catch { /* Python: rw.close() guarded */ }
            }
        }
    }

    /// <summary>Tuple key (dst, port) as a value-type record for ConcurrentDictionary.</summary>
    private readonly record struct TcpKey(string Dst, int Port);

    private sealed class TcpFailState
    {
        public int Failures;
        public double RetryAfter;
        public bool Connecting;
    }

    // ========================================================================
    // splicing: TCP(client) <-> WS(telegram) with re-encryption
    // ========================================================================

    /// <summary>
    /// Port of <c>bridge.bridge_ws_reencrypt</c>: two forwarding loops
    /// (client→WS with clt-decrypt/tg-encrypt, WS→client with tg-decrypt/clt-encrypt),
    /// whichever finishes first cancels the other; then <b>both</b> endpoints are shut
    /// down (WS close + client socket dispose, optionally unwrapping/wrapping TLS records).
    /// </summary>
    internal async Task BridgeWsReencryptAsync(
        PipeReader clientInput, Stream clientOutput, RawWebSocket ws, string label,
        CryptoContext ctx, int? dc, bool isMedia, MsgSplitter? splitter,
        FakeTlsRecordCodec? codec, CancellationToken ct)
    {
        string dcTag = dc is null ? "DC?" : $"DC{dc}{(isMedia ? "m" : "")}";

        long upBytes = 0, downBytes = 0, upPackets = 0, downPackets = 0;
        var startTime = StopwatchMono.Now;
        string closeReason = "normal";
        WsActivity? activity = _debug.Track(label, dcTag);

        using var link = CancellationTokenSource.CreateLinkedTokenSource(ct);

        Task up = Task.Run(() => UpstreamLoopAsync());
        Task down = Task.Run(() => DownstreamLoopAsync());

        async Task UpstreamLoopAsync()
        {
            try
            {
                while (true)
                {
                    ReadResult rr = await clientInput.ReadAsync(link.Token).ConfigureAwait(false);
                    if (rr.IsCanceled) throw new OperationCanceledException();

                    ReadOnlySequence<byte> buffer = rr.Buffer;
                    if (buffer.Length == 0)                 // client EOF
                    {
                        clientInput.AdvanceTo(buffer.End);
                        if (splitter is not null)
                        {
                            var tail = splitter.Flush();
                            if (tail.Count > 0)
                            {
                                activity?.SendStarted();
                                await ws.SendAsync(tail[0], CancellationToken.None)
                                                .ConfigureAwait(false);
                                activity?.Sent(tail[0].Length);
                            }
                        }
                        closeReason = "client: eof";
                        break;
                    }

                    byte[] chunk = ToArrayAndAdvance(clientInput, buffer, consumed: true);
                    int n = chunk.Length;
                    activity?.Input(n);
                    ProxyStats.Shared.AddBytesUp(n);
                    upBytes += n;
                    upPackets++;

                    byte[] plain = ctx.ClientToPlain(chunk);
                    byte[] cipher = ctx.PlainToTelegram(plain);

                    if (splitter is not null)
                    {
                        var parts = splitter.Split(cipher, plain);
                        if (parts.Count == 0) continue;
                        activity?.SendStarted();
                        if (parts.Count > 1)
                            await ws.SendBatchAsync(parts, CancellationToken.None).ConfigureAwait(false);
                        else
                            await ws.SendAsync(parts[0], CancellationToken.None).ConfigureAwait(false);
                        activity?.Sent(parts.Sum(p => p.Length));
                    }
                    else
                    {
                        activity?.SendStarted();
                        await ws.SendAsync(cipher, CancellationToken.None).ConfigureAwait(false);
                        activity?.Sent(cipher.Length);
                    }
                }
            }
            catch (OperationCanceledException) { /* task.cancel() — silent */ }
            catch (EndOfStreamException) { closeReason = "client: eof"; }
            catch (Exception e)
            {
                closeReason = $"client: {e.GetType().Name}";
                Log.LogDebug("[{Label}] tcp->ws ended: {Exc}", label, e.Message);
            }
        }

        async Task DownstreamLoopAsync()
        {
            try
            {
                while (true)
                {
                    byte[]? data = await ws.ReceiveAsync(link.Token).ConfigureAwait(false);
                    if (data is null)
                    {
                        if (closeReason == "normal") closeReason = "upstream: ws_close";
                        break;
                    }

                    int n = data.Length;
                    activity?.Received(n);
                    ProxyStats.Shared.AddBytesDown(n);
                    downBytes += n;
                    downPackets++;

                    byte[] plain = ctx.TelegramToPlain(data);
                    byte[] cipher = ctx.PlainToClient(plain);
                    await WriteToClientAsync(clientOutput, codec, cipher, link.Token)
                        .ConfigureAwait(false);
                    activity?.Delivered(n);
                }
            }
            catch (OperationCanceledException) { /* cancelled by the sibling loop */ }
            catch (SocketException e)
            {
                closeReason = $"upstream: {e.GetType().Name}";
            }
            catch (IOException e)
            {
                closeReason = $"upstream: {e.GetType().Name}";
            }
            catch (EndOfStreamException)
            {
                closeReason = "upstream: tcp_reset";
            }
            catch (Exception e)
            {
                closeReason = $"upstream: {e.GetType().Name}: {e.Message}";
                Log.LogDebug("[{Label}] ws->tcp ended: {Exc}", label, e.Message);
            }
        }

        try
        {
            await Task.WhenAny(up, down).ConfigureAwait(false);
        }
        finally
        {
            // shutdown BOTH sides: cancel the surviving direction, then tear everything down
            link.Cancel();
            await WhenAllQuiet(up, down).ConfigureAwait(false);

            double elapsed = StopwatchMono.Now - startTime;
            activity?.Close();
            Log.LogInformation(
                "[{Label}] {Dc} WS session closed ({Reason}): ^{Up} ({UpPk} pkts) " +
                "v{Down} ({DownPk} pkts) in {Elapsed:F1}s",
                label, dcTag, closeReason,
                Utils.HumanBytes(upBytes), upPackets,
                Utils.HumanBytes(downBytes), downPackets, elapsed);

            try { await ws.CloseAsync().ConfigureAwait(false); } catch { }
            await CloseClientSideAsync(clientInput, clientOutput, codec).ConfigureAwait(false);
        }
    }

    // ========================================================================
    // splicing: TCP(client) <-> TCP(telegram) with re-encryption
    // ========================================================================

    /// <summary>Port of <c>bridge._bridge_tcp_reencrypt</c>.</summary>
    internal async Task BridgeTcpReencryptAsync(
        PipeReader clientInput, Stream clientOutput, TcpClient remote, string label,
        CryptoContext ctx, FakeTlsRecordCodec? codec, CancellationToken ct)
    {
        var remoteStream = remote.GetStream();
        var remoteInput = new SocketPipeReader(remote);      // owns its own pipe feeder
        using var link = CancellationTokenSource.CreateLinkedTokenSource(ct);

        long upBytes = 0, downBytes = 0;

        async Task ForwardUp()
        {
            try
            {
                while (true)
                {
                    ReadResult rr = await clientInput.ReadAsync(link.Token).ConfigureAwait(false);
                    if (rr.IsCanceled) throw new OperationCanceledException();
                    var buffer = rr.Buffer;
                    if (buffer.Length == 0) { clientInput.AdvanceTo(buffer.End); break; }
                    byte[] chunk = ToArrayAndAdvance(clientInput, buffer, consumed: true);

                    ProxyStats.Shared.AddBytesUp(chunk.Length);
                    Interlocked.Add(ref upBytes, chunk.Length);
                    byte[] cipher = ctx.ReencryptUpstream(chunk);
                    await remoteStream.WriteAsync(cipher, link.Token).ConfigureAwait(false);
                    await remoteStream.FlushAsync(link.Token).ConfigureAwait(false);
                }
            }
            catch (Exception e) when (QuietForwardEnd(e, label, "client->telegram")) { }
        }

        async Task ForwardDown()
        {
            try
            {
                while (true)
                {
                    byte[] chunk = await remoteInput.ReadChunkAsync(ReadChunkSize, link.Token)
                                             .ConfigureAwait(false);
                    if (chunk.Length == 0) break;

                    ProxyStats.Shared.AddBytesDown(chunk.Length);
                    Interlocked.Add(ref downBytes, chunk.Length);
                    byte[] cipher = ctx.ReencryptDownstream(chunk);
                    await WriteToClientAsync(clientOutput, codec, cipher, link.Token)
                        .ConfigureAwait(false);
                }
            }
            catch (Exception e) when (QuietForwardEnd(e, label, "telegram->client")) { }
        }

        static bool QuietForwardEnd(Exception e, string label, string dir)
        {
            if (e is OperationCanceledException) return true;
            Log.LogDebug("[{Label}] forward ended ({Dir}): {Exc}", label, dir, e.Message);
            return true;
        }

        Task up = Task.Run(ForwardUp);
        Task down = Task.Run(ForwardDown);
        try
        {
            await Task.WhenAny(up, down).ConfigureAwait(false);
        }
        finally
        {
            link.Cancel();
            await WhenAllQuiet(up, down).ConfigureAwait(false);
            // shutdown both sides
            try { remoteStream.Close(); } catch { }
            remoteInput.Complete();
            await CloseClientSideAsync(clientInput, clientOutput, codec).ConfigureAwait(false);
        }
    }

    // ========================================================================
    // splicing: native client <-> H2 media channel
    // ========================================================================

    /// <summary>
    /// Port of <c>cf_h2.bridge_h2</c>: upload reads length-prefixed MTProto packets from
    /// the client (decrypting on the fly) and posts them onto the channel; download pops
    /// replies, re-wraps them into native packets and encrypts towards the client. The
    /// third leg is the channel recovery loop. First completion cancels the rest; the
    /// transport error (if any) is delivered to the client as a synthetic packet.
    /// </summary>
    internal async Task BridgeH2Async(
        PipeReader clientInput, Stream clientOutput, HttpChannel channel,
        CryptoContext ctx, byte[] tag, FakeTlsRecordCodec? codec, CancellationToken ct)
    {
        using var link = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var nativeEof = new EndOfStreamException("native EOF");

        async Task WriteNativeAsync(byte[] data, CancellationToken wct)
        {
            try
            {
                await WriteToClientAsync(clientOutput, codec,
                                         ctx.PlainToClient(data), wct).ConfigureAwait(false);
            }
            catch (Exception exc) when (exc is not OperationCanceledException)
            {
                throw new NativeDeliveryError(exc.Message);
            }
        }

        async Task UploadAsync()
        {
            while (true)
            {
                (byte[] body, bool quick) = await MtprotoPacketCodec.ReadPacketAsync(
                    clientInput, ctx.CltDecryptor, tag, link.Token).ConfigureAwait(false);
                await channel.SendAsync(body, quick, ct: link.Token).ConfigureAwait(false);
            }
        }

        async Task DownloadAsync()
        {
            while (true)
            {
                byte[] body = await channel.ReceiveAsync(link.Token).ConfigureAwait(false);
                if (channel.Closed)
                    throw new NativeDeliveryError("H2 channel closed before native response");
                channel.SetDelivering(StopwatchMono.Now);
                try
                {
                    await WriteNativeAsync(MtprotoPacketCodec.EncodeReply(body, tag), link.Token)
                        .ConfigureAwait(false);
                }
                finally
                {
                    channel.SetDelivering(null);
                }
                channel.AddDown(body.Length);
                ProxyStats.Shared.AddBytesDown(body.Length);
                channel.LastProgress = StopwatchMono.Now;
                channel.WakeReceiver();
            }
        }

        async Task RecoverAsync()
        {
            try
            {
                await channel.RecoverAsync(link.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { }
        }

        Task upload = Task.Run(UploadAsync);
        Task download = Task.Run(DownloadAsync);
        Task recover = Task.Run(RecoverAsync);

        try
        {
            Task done = await Task.WhenAny(upload, download, recover).ConfigureAwait(false);

            if (channel.TransportErrorCode is int errCode)
            {
                Span<byte> payload = stackalloc byte[4];
                BinaryPrimitives.WriteInt32LittleEndian(payload, errCode);
                try
                {
                    await WriteNativeAsync(MtprotoPacketCodec.EncodeReply(payload.ToArray(), tag),
                                           CancellationToken.None).ConfigureAwait(false);
                    channel.AddDown(4);
                    ProxyStats.Shared.AddBytesDown(4);
                }
                catch (NativeDeliveryError) { /* client gone — same as Python swallowing OSError */ }
            }
            else if (done.IsFaulted && done.Exception is { } ex
                     && ex.Flatten().InnerExceptions[0] is not EndOfStreamException
                     && ex.Flatten().InnerExceptions[0] is not NativeDeliveryError)
            {
                Log.LogWarning("[{Label}] H2 channel={Channel} bridge ended: {Type}: {Exc}",
                    channel.Label, channel.ChannelId,
                    ex.Flatten().InnerExceptions[0].GetType().Name,
                    ex.Flatten().InnerExceptions[0].Message);
            }
            else if (done.IsFaulted)
            {
                Log.LogDebug("[{Label}] H2 channel={Channel} native closed: {Exc}",
                    channel.Label, channel.ChannelId,
                    done.Exception!.Flatten().InnerExceptions[0].Message);
            }
        }
        catch (EndOfStreamException)
        {
            Log.LogDebug("[{Label}] H2 channel={Channel} native EOF", channel.Label, channel.ChannelId);
        }
        finally
        {
            _ = nativeEof; // kept for readability of the mapping above
            link.Cancel();
            await WhenAllQuiet(upload, download, recover).ConfigureAwait(false);
            try { await channel.CloseAsync().ConfigureAwait(false); } catch { }
            await CloseClientSideAsync(clientInput, clientOutput, codec).ConfigureAwait(false);
        }
    }

    // ========================================================================
    // masking (Python fake_tls.proxy_to_masking_domain)
    // ========================================================================

    /// <summary>Raw bidirectional relay of a non-tagged ClientHello to the masking domain.</summary>
    private async Task ProxyToMaskingDomainAsync(Socket client, byte[] initialData, CancellationToken ct)
    {
        string domain = _config.FakeTlsDomain;
        TcpClient upstream;
        try
        {
            upstream = new TcpClient { NoDelay = true };
            using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            connectCts.CancelAfter(TimeSpan.FromSeconds(10));
            await upstream.ConnectAsync(domain, 443, connectCts.Token).ConfigureAwait(false);
        }
        catch (Exception exc)
        {
            Log.LogWarning("[masking] cannot connect to {Domain}:443: {Exc}", domain, Describe(exc));
            upstream = null!;
            return;
        }

        Log.LogDebug("masking -> {Domain}:443", domain);

        try
        {
            var upStream = upstream.GetStream();
            await upStream.WriteAsync(initialData, ct).ConfigureAwait(false);
            await upStream.FlushAsync(ct).ConfigureAwait(false);

            var clientPipe = new Pipe();
            var feeder = FeedSocketToPipeAsync(client, clientPipe.Writer, ct);
            var upReader = new StreamPipeReader(upStream);

            async Task RelayClientToUp()
            {
                try
                {
                    while (true)
                    {
                        var rr = await clientPipe.Reader.ReadAsync(ct).ConfigureAwait(false);
                        var buf = rr.Buffer;
                        if (buf.Length == 0) break;
                        foreach (var seg in buf)
                            await upStream.WriteAsync(seg.Memory, ct).ConfigureAwait(false);
                        clientPipe.Reader.AdvanceTo(buf.End);
                        await upStream.FlushAsync(ct).ConfigureAwait(false);
                    }
                }
                catch (Exception e) { _ = e; }
                finally
                {
                    try { upStream.CloseWrite(); } catch { }
                }
            }

            async Task RelayUpToClient()
            {
                var buf = new byte[16384];
                try
                {
                    while (true)
                    {
                        int n = await upStream.ReadAsync(buf, ct).ConfigureAwait(false);
                        if (n == 0) break;
                        await new SocketPipeWriter(client, Stream.Null /* unused */)
                            .WriteAsync(buf.AsMemory(0, n), ct).ConfigureAwait(false);
                    }
                }
                catch (Exception e) { _ = e; }
            }

            // Simpler symmetric implementation: copy both ways over the raw socket stream.
            var networkOut = GetOrCreateClientStream(client);
            async Task CopyUpToClient()
            {
                var buf = new byte[16384];
                try
                {
                    while (true)
                    {
                        int n = await upStream.ReadAsync(buf, ct).ConfigureAwait(false);
                        if (n == 0) break;
                        await networkOut.WriteAsync(buf.AsMemory(0, n), ct).ConfigureAwait(false);
                        await networkOut.FlushAsync(ct).ConfigureAwait(false);
                    }
                }
                catch (Exception e) { _ = e; }
                finally
                {
                    try { client.Shutdown(SocketShutdown.Send); } catch { }
                }
            }
            async Task CopyClientToUp()
            {
                var buf = new byte[16384];
                try
                {
                    while (true)
                    {
                        int n = await networkOut.ReadAsync(buf, ct).ConfigureAwait(false);
                        if (n == 0) break;
                        await upStream.WriteAsync(buf.AsMemory(0, n), ct).ConfigureAwait(false);
                        await upStream.FlushAsync(ct).ConfigureAwait(false);
                    }
                }
                catch (Exception e) { _ = e; }
                finally
                {
                    try { upStream.CloseWrite(); } catch { }
                }
            }

            _ = feeder; _ = RelayClientToUp; _ = RelayUpToClient; _ = upReader; _ = clientPipe;
            await Task.WhenAny(CopyUpToClient(), CopyClientToUp()).ConfigureAwait(false);
        }
        finally
        {
            try { upstream.Dispose(); } catch { }
        }
    }

    private static NetworkStream GetOrCreateClientStream(Socket client) => client.GetStream();

    // ========================================================================
    // helpers
    // ========================================================================

    /// <summary>Python <c>set_sock_opts</c>: TCP_NODELAY + SO_RCVBUF/SO_SNDBUF.</summary>
    internal static void ApplySocketOptions(Socket s)
    {
        try { s.NoDelay = true; } catch { }
    }

    internal static string FormatLabel(object? remote) => remote switch
    {
        IPEndPoint ep => $"{ep.Address}:{ep.Port}",
        string str => str,
        _ => "?",
    };

    /// <summary>Python <c>_drain_bad_handshake</c>: read up to 64 KiB, 10 s budget.</summary>
    private static async Task DrainBadHandshakeAsync(PipeReader reader, CancellationToken ct)
    {
        using var drainCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        drainCts.CancelAfter(TimeSpan.FromSeconds(BadHandshakeDrainTimeout));
        int remaining = BadHandshakeDrainLimit;
        try
        {
            while (remaining > 0)
            {
                ReadResult rr = await reader.ReadAsync(drainCts.Token).ConfigureAwait(false);
                var buffer = rr.Buffer;
                if (buffer.Length == 0)
                {
                    reader.AdvanceTo(buffer.End);
                    break;
                }
                remaining -= (int)Math.Min(buffer.Length, remaining);
                reader.AdvanceTo(buffer.Start);   // consume nothing but keep pumping
                if (buffer.Length == 0) break;
                reader.AdvanceTo(buffer.End);
            }
        }
        catch (Exception)
        {
            // Python: `except Exception: pass` around wait_for(_drain_bad_handshake(...))
        }
    }

    /// <summary>reader.readexactly(n) over a PipeReader.</summary>
    internal static async Task<byte[]> ReadExactlyAsync(
        PipeReader reader, int count, CancellationToken ct)
    {
        if (count == 0) return Array.Empty<byte>();
        var result = new byte[count];
        int got = 0;
        while (got < count)
        {
            ReadResult rr = await reader.ReadAsync(ct).ConfigureAwait(false);
            var buffer = rr.Buffer;
            int avail = (int)Math.Min(buffer.Length, count - got);
            if (avail > 0)
            {
                buffer.Slice(got >= 0 ? 0 : 0, avail).CopyTo(result.AsSpan(got));
                reader.AdvanceTo(buffer.GetPosition(avail));
                got += avail;
            }
            if (buffer.Length == 0 || (avail == 0 && rr.IsCompleted))
            {
                reader.AdvanceTo(buffer.End);
                throw new EndOfStreamException();   // asyncio.IncompleteReadError analogue
            }
        }
        return result;
    }

    /// <summary>reader.readline() (PROXY protocol v1 line, \n-terminated).</summary>
    internal static async Task<byte[]> ReadLineAsync(PipeReader reader, CancellationToken ct)
    {
        using var ms = new MemoryStream();
        while (true)
        {
            ReadResult rr = await reader.ReadAsync(ct).ConfigureAwait(false);
            var buffer = rr.Buffer;
            SequencePosition consumed = buffer.Start;
            bool found = false;

            foreach (var seg in buffer)
            {
                for (int i = 0; i < seg.Span.Length; i++)
                {
                    if (seg.Span[i] == (byte)'\n')
                    {
                        ms.Write(seg.Span.Slice(0, i + 1));
                        consumed = buffer.Position.GetSlice(consumed, seg.Start).GetAdvanced(i + 1);
                        found = true;
                        break;
                    }
                }
                if (found) break;
                ms.Write(seg.Span);
                consumed = seg.End;
            }

            reader.AdvanceTo(consumed);
            if (found || buffer.Length == 0 || ms.Length > 64 * 1024)
                break;
        }
        return ms.ToArray();
    }

    private static byte[] ToArrayAndAdvance(PipeReader reader, ReadOnlySequence<byte> buffer, bool consumed)
    {
        byte[] data = buffer.ToArray();
        reader.AdvanceTo(consumed ? buffer.End : buffer.Start);
        return data;
    }

    /// <summary>Writes to the client, wrapping into TLS records when Fake TLS is active.</summary>
    internal static async Task WriteToClientAsync(
        Stream clientOutput, FakeTlsRecordCodec? codec, byte[] data, CancellationToken ct)
    {
        if (codec is not null)
            await codec.WriteAsync(data, ct).ConfigureAwait(false);
        else
            await clientOutput.WriteAsync(data, ct).ConfigureAwait(false);
    }

    /// <summary>await gather(*tasks, return_exceptions=True) — never throws.</summary>
    internal static async Task WhenAllQuiet(params Task[] tasks)
    {
        try { await Task.WhenAll(tasks).ConfigureAwait(false); }
        catch { /* swallow, exactly like return_exceptions=True */ }
    }

    /// <summary>Shuts the client side down: complete the pipe, flush+dispose the stream, close the socket.</summary>
    private static async Task CloseClientSideAsync(
        PipeReader clientInput, Stream clientOutput, FakeTlsRecordCodec? codec)
    {
        try
        {
            if (codec is not null) await codec.CloseAsync().ConfigureAwait(false);
            await clientOutput.FlushAsync(CancellationToken.None).ConfigureAwait(false);
        }
        catch { }
        try { clientOutput.Dispose(); } catch { }
        try { clientInput.Complete(); } catch { }
    }

    internal static void QuietCloseSocket(Socket s)
    {
        try { s.Shutdown(SocketShutdown.Both); } catch { }
        try { s.Dispose(); } catch { }
    }

    private static string Describe(Exception exc) =>
        $"{exc.GetType().Name}: {exc.Message}";

    private static async Task FeedSocketToPipeAsync(Socket socket, PipeWriter writer, CancellationToken ct)
    {
        try
        {
            var stream = socket.GetStream();
            while (!ct.IsCancellationRequested)
            {
                Memory<byte> mem = writer.GetMemory(ReadChunkSize);
                int n = await stream.ReadAsync(mem, ct).ConfigureAwait(false);
                if (n == 0) break;
                writer.Advance(n);
                FlushResult fr = await writer.FlushAsync(ct).ConfigureAwait(false);
                if (fr.IsCompleted) break;
            }
        }
        catch { }
        finally
        {
            try { await writer.CompleteAsync().ConfigureAwait(false); } catch { }
        }
    }
}

/// <summary>
/// TLS-record framing for the Fake-TLS client transport — the C# counterpart of
/// Python <c>fake_tls.FakeTlsStream</c>: reads strip the 5-byte record headers
/// (CCS records are skipped, non-appdata records end the stream), writes chunk
/// through <see cref="FakeTls.WrapTlsRecord"/>. Kept as a thin codec so the
/// handshake can be read straight off the <see cref="PipeReader"/> before the
/// bridge starts (asyncio hands the same object to both phases).
/// </summary>
internal sealed class FakeTlsRecordCodec
{
    private readonly PipeReader _reader;
    private readonly Stream _writer;
    private readonly MemoryStream _pending = new();       // self._read_buf
    private int _readLeft;                                // self._read_left
    private readonly byte[] _header = new byte[5];

    public FakeTlsRecordCodec(PipeReader reader, Stream writer)
    {
        _reader = reader;
        _writer = writer;
    }

    /// <summary>Python <c>FakeTlsStream.readexactly(n)</c>.</summary>
    public async Task<byte[]> ReadExactlyAsync(int n, CancellationToken ct)
    {
        while (_pending.Length < n)
        {
            byte[] payload = await ReadTlsPayloadAsync(ct).ConfigureAwait(false);
            if (payload.Length == 0)
                throw new EndOfStreamException();         // IncompleteReadError analogue
            _pending.Write(payload);
        }
        var result = new byte[n];
        _pending.Position = 0;
        _pending.ReadExactly(result);
        RewritePending(after: n);
        return result;
    }

    /// <summary>Python <c>FakeTlsStream.read(n)</c>; empty array means EOF.</summary>
    public async Task<byte[]> ReadAsync(int n, CancellationToken ct)
    {
        if (_pending.Length > 0)
        {
            int take = (int)Math.Min(_pending.Length, n);
            var chunk = new byte[take];
            _pending.Position = 0;
            _pending.ReadExactly(chunk);
            RewritePending(after: take);
            return chunk;
        }
        byte[] payload = await ReadTlsPayloadAsync(ct).ConfigureAwait(false);
        if (payload.Length <= n) return payload;
        var head = payload[..n];
        _pending.Write(payload, n, payload.Length - n);
        return head;
    }

    /// <summary>Python <c>FakeTlsStream.write(data)</c> + drain (awaits the write here).</summary>
    public async Task WriteAsync(byte[] data, CancellationToken ct)
    {
        await _writer.WriteAsync(FakeTls.WrapTlsRecord(data), ct).ConfigureAwait(false);
        await _writer.FlushAsync(ct).ConfigureAwait(false);
    }

    public Task CloseAsync() => _writer.FlushAsync(CancellationToken.None);

    private async Task<byte[]> ReadTlsPayloadAsync(CancellationToken ct)
    {
        if (_readLeft > 0)
        {
            byte[] data = await ReadAtMostAsync(_readLeft, ct).ConfigureAwait(false);
            if (data.Length == 0) return Array.Empty<byte>();
            _readLeft -= data.Length;
            return data;
        }

        while (true)
        {
            await BridgeHandler.ReadExactlyAsync(_reader, 5, ct).ConfigureAwait(false)
                               .ContinueWith(t => t.Result.CopyTo(_header, 0)).WaitAsync(ct)
                               .ConfigureAwait(false);
            byte rtype = _header[0];
            ushort recLen = BinaryPrimitives.ReadUInt16BigEndian(_header.AsSpan(3, 2));

            if (rtype == FakeTlsConstants.TlsRecordCcs)
            {
                if (recLen > 0)
                    await BridgeHandler.ReadExactlyAsync(_reader, recLen, ct).ConfigureAwait(false);
                continue;
            }
            if (rtype != FakeTlsConstants.TlsRecordAppData)
                return Array.Empty<byte>();

            byte[] data = await ReadAtMostAsync(recLen, ct).ConfigureAwait(false);
            if (data.Length == 0) return Array.Empty<byte>();
            int remaining = recLen - data.Length;
            if (remaining > 0) _readLeft = remaining;
            return data;
        }
    }

    private async Task<byte[]> ReadAtMostAsync(int maxCount, CancellationToken ct)
    {
        ReadResult rr = await _reader.ReadAsync(ct).ConfigureAwait(false);
        var buffer = rr.Buffer;
        if (buffer.Length == 0)
        {
            _reader.AdvanceTo(buffer.End);
            return Array.Empty<byte>();
        }
        int take = (int)Math.Min(buffer.Length, maxCount);
        byte[] data = buffer.FirstSlice.Length >= take
            ? buffer.First(spanScratch(take)).ToArray()
            : buffer.Extract(0, take).ToArray();
        _reader.AdvanceTo(buffer.GetPosition(take));
        return data;

        static int spanScratch(int n) => n;
    }

    private void RewritePending(int after)
    {
        var all = _pending.ToArray();
        _pending.SetLength(0);
        if (all.Length > after)
            _pending.Write(all, after, all.Length - after);
    }
}

/// <summary>
/// <see cref="PipeWriter"/> that completes only when the underlying socket dies —
/// used to feed a <see cref="Pipe"/> from a <see cref="Socket"/> without buffering
/// unboundedly (asyncio StreamReader equivalent).
/// </summary>
internal sealed class SocketPipeReader : IAsyncDisposable
{
    private readonly Pipe _pipe = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _feeder;

    public SocketPipeReader(TcpClient client)
    {
        _feeder = FeedAsync(client, _pipe.Writer, _cts.Token);
    }

    private static async Task FeedAsync(TcpClient client, PipeWriter writer, CancellationToken ct)
    {
        try
        {
            var stream = client.GetStream();
            while (!ct.IsCancellationRequested)
            {
                Memory<byte> mem = writer.GetMemory(65536);
                int n = await stream.ReadAsync(mem, ct).ConfigureAwait(false);
                if (n == 0) break;
                writer.Advance(n);
                var fr = await writer.FlushAsync(ct).ConfigureAwait(false);
                if (fr.IsCompleted) break;
            }
        }
        catch { }
        finally
        {
            try { await writer.CompleteAsync().ConfigureAwait(false); } catch { }
        }
    }

    public async Task<byte[]> ReadChunkAsync(int maxSize, CancellationToken ct)
    {
        ReadResult rr = await _pipe.Reader.ReadAsync(ct).ConfigureAwait(false);
        var buffer = rr.Buffer;
        if (buffer.Length == 0)
        {
            _pipe.Reader.AdvanceTo(buffer.End);
            return Array.Empty<byte>();
        }
        int take = (int)Math.Min(buffer.Length, maxSize);
        byte[] data = buffer.Slice(0, take).ToArray();
        _pipe.Reader.AdvanceTo(buffer.GetPosition(take));
        return data;
    }

    public void Complete()
    {
        _cts.Cancel();
        try { _pipe.Reader.Complete(); } catch { }
    }

    public async ValueTask DisposeAsync()
    {
        Complete();
        try { await _feeder.ConfigureAwait(false); } catch { }
        _cts.Dispose();
    }
}

/// <summary>
/// Stream facade over the client socket + <see cref="PipeWriter"/> pair created in
/// <see cref="BridgeHandler.ReadClientInitAsync"/>: writes go through the pipe (which
/// a background feeder pumps to the socket), reads are rejected (input flows through
/// the paired <see cref="PipeReader"/>). Keeps the bridge code shape identical to
/// Python's StreamWriter.
/// </summary>
internal sealed class SocketPipeWriter : Stream
{
    private readonly Socket _socket;
    private readonly PipeWriter _writer;
    private readonly Task _pump;
    private bool _disposed;

    internal SocketPipeWriter(Socket socket, PipeWriter writer)
    {
        _socket = socket;
        _writer = writer;
        _pump = PumpAsync();
    }

    private async Task PumpAsync()
    {
        NetworkStream stream;
        try { stream = _socket.GetStream(); }
        catch { return; }
        try
        {
            while (true)
            {
                ReadResult rr = await _writer.Reader.ReadAsync().ConfigureAwait(false);
                var buffer = rr.Buffer;
                foreach (var seg in buffer)
                {
                    if (seg.Memory.Length > 0)
                        await stream.WriteAsync(seg.Memory).ConfigureAwait(false);
                }
                await stream.FlushAsync().ConfigureAwait(false);
                _writer.Reader.AdvanceTo(buffer.End);
                if (rr.IsCompleted && buffer.Length == 0) break;
            }
        }
        catch { }
        finally
        {
            try { _writer.Reader.Complete(); } catch { }
        }
    }

    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() { }
    public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
    {
        if (_disposed) throw new IOException("client writer disposed");
        buffer.CopyTo(_writer.GetMemory(buffer.Length));
        _writer.Advance(buffer.Length);
        try
        {
            await _writer.FlushAsync(ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exc)
        {
            throw new IOException("client write failed", exc);
        }
    }

    public override void Write(byte[] buffer, int offset, int count)
        => WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public void Complete()
    {
        if (_disposed) return;
        _disposed = true;
        try { _writer.Complete(); } catch { }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) Complete();
        base.Dispose(disposing);
    }
}
