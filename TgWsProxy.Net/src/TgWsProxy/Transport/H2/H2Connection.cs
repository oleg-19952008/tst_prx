using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Collections.Concurrent;
using System.Net;
using System.Runtime.InteropServices;

using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Channels;

namespace TgWsProxy.Transport.H2;

/// <summary>Options for <see cref="H2Connection"/> (defaults mirror h2_transport.py).</summary>
public sealed record H2ConnectionOptions
{
    public int MaxConcurrentStreams { get; init; } = 64;          // MAX_LANE_REQUESTS cap
    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(8);   // SETUP_TIMEOUT
    public TimeSpan WriteTimeout { get; init; } = TimeSpan.FromSeconds(10);
    public TimeSpan ReadTimeout { get; init; } = TimeSpan.FromSeconds(65);     // REQUEST_TIMEOUT
    /// <summary>Ping keep-alive period; <see cref="TimeSpan.Zero"/> disables it.</summary>
    public TimeSpan KeepAliveInterval { get; init; } = TimeSpan.FromSeconds(15);
    public TimeSpan PingTimeout { get; init; } = TimeSpan.FromSeconds(10);
    public string SniHost { get; init; } = "";
    /// <summary>
    /// Certificate policy for <see cref="H2Connection.ConnectAsync"/>. Default is strict,
    /// mirroring Python cf_h2.py::_default_ssl_context() → create_ssl_context() with
    /// check_hostname=True (certifi bundle + OS roots). Only spike/diagnostic code that
    /// terminates TLS in-process (self-signed test origins) should set this to true.
    /// </summary>
    public bool AllowInsecureTestCertificates { get; init; }
    /// <summary>Local endpoint to bind before connecting (pool source-IP rotation).</summary>
    public IPEndPoint? LocalEndpoint { get; init; }
}

/// <summary>Result of one client-initiated request/response exchange.</summary>
public sealed class H2Response
{
    private readonly H2Stream _stream;

    public H2Response(H2Stream stream, List<HpackHeader> headers)
    {
        _stream = stream;
        Headers = headers;
        Status = headers
            .FirstOrDefault(h => h.Name == ":status").ValueAscii is { Length: 3 } s
            ? int.Parse(s) : 0;
    }

    public List<HpackHeader> Headers { get; }
    public int Status { get; }

    public string Header(string name) =>
        Headers.FirstOrDefault(h => h.Name == name).ValueAscii;

    public H2Stream Stream => _stream;

    /// <summary>Streams the remaining response body to the caller.</summary>
    public async IAsyncEnumerable<byte[]> BodyAsync(
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct = default)
    {
        while (true)
        {
            byte[]? chunk = null;
            bool done = false;
            await _stream.ReadLock.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                if (_stream.ResetByPeer is { } rc)
                    throw new H2ProtocolException(rc, $"Stream {_stream.Id} reset by peer.");
                if (_stream.ConnectionError is { } ce)
                    throw ce;
                if (_stream.Chunks.Count > 0)
                    chunk = _stream.Chunks.Dequeue();
                else if (_stream.EndedByPeer)
                    done = true;
            }
            finally
            {
                _stream.ReadLock.Release();
            }
            if (done) yield break;
            if (chunk is not null)
            {
                Interlocked.Add(ref _stream._bytesDelivered, chunk.Length);
                // H2Response exposes the stream as `Stream`; local `stream` was a typo.
                _stream.Connection!.StreamConsumed(Stream, chunk.Length);
                yield return chunk;
                continue;
            }
            if (!await _stream.WaitAsync(_stream.Connection!.Options.ReadTimeout, ct)
                    .ConfigureAwait(false))
                throw new TimeoutException($"Timed out waiting for H2 stream {_stream.Id} body.");
        }
    }

    public async Task<byte[]> ReadAllAsync(int maxBytes, CancellationToken ct = default)
    {
        using var ms = new MemoryStream();
        await foreach (var chunk in BodyAsync(ct).ConfigureAwait(false))
        {
            if (ms.Length + chunk.Length > maxBytes)
                throw new InvalidOperationException("H2 response body exceeds bound.");
            ms.Write(chunk);
        }
        return ms.ToArray();
    }
}

/// <summary>
/// Minimal HTTP/2 client connection engine over an ALPN-<c>h2</c> TLS stream —
/// the .NET replacement for the Python <c>h2</c> library + <c>_Connection</c>
/// class from <c>proxy/h2_transport.py</c> (PORT_PLAN.md checklist item 6).
/// Covers: connection preface, SETTINGS (+ACK), HEADERS/CONTINUATION with HPACK,
/// DATA, WINDOW_UPDATE flow control (connection + per-stream), RST_STREAM,
/// GOAWAY and PING/ACK keep-alive with liveness enforcement.
/// </summary>
public sealed class H2Connection : IAsyncDisposable
{
    private readonly TcpClient _tcp;
    // Created after TCP connect (TcpClient.GetStream() requires a connected socket);
    // may be a dummy SslStream in CreateAttached (real transport is _net).
    private SslStream? _ssl;
    private Stream _net;
    private readonly HpackCodec _hpack = new();
    private readonly Channel<(H2FrameType Type, byte Flags, int StreamId, byte[] Payload)> _inbox =
        Channel.CreateUnbounded<(H2FrameType, byte, int, byte[])>(
            new UnboundedChannelOptions { SingleReader = true, SingleWriter = true });
    private readonly ConcurrentDictionary<int, H2Stream> _streams = new();
    private readonly SemaphoreSlim _sendGate = new(1, 1);
    private readonly object _windowLock = new();

    private Task? _readerTask;
    private Task? _dispatcherTask;
    private Task? _keepAliveTask;
    private CancellationTokenSource _cts = new();
    private volatile Exception? _error;
    private int _nextStreamId = 1;
    private int _connectionSendWindow = H2Consts.DefaultInitialWindowSize;
    private int _connectionPendingUpdate;
    private int _maxOutboundFrameSize = H2Consts.DefaultMaxFrameSize;
    private int _remoteMaxConcurrentStreams = int.MaxValue;
    private int _goawayLastStreamId = int.MaxValue;
    private TaskCompletionSource<bool> _settingsAck = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private TaskCompletionSource<bool>? _pingAck;
    private byte[]? _pendingPing;
    private long _lastActivityTicks;
    private long _pingsSent;
    private long _pingsAcked;

    public H2ConnectionOptions Options { get; }
    public string AlpnProtocol { get; private set; } = "";
    public bool IsHealthy => _error is null && _goawayLastStreamId == int.MaxValue;
    public Exception? Error => _error;
    public IReadOnlyCollection<H2Stream> Streams => _streams.Values.ToArray();
    public long PingsSent => Interlocked.Read(ref _pingsSent);
    public long PingsAcked => Interlocked.Read(ref _pingsAcked);

    private H2Connection(TcpClient tcp, SslStream? ssl, Stream net, H2ConnectionOptions options)
    {
        _tcp = tcp;
        _ssl = ssl;
        _net = net;
        Options = options;
    }

    // ------------------------------------------------------------------
    // Connection setup
    // ------------------------------------------------------------------

    /// <summary>
    /// Opens TCP+TLS to <paramref name="host"/>:<paramref name="port"/>, requires ALPN
    /// "h2" (like <c>writer.get_extra_info('ssl_object').selected_alpn_protocol() != 'h2'</c>
    /// in h2_transport.py), sends the preface and initial SETTINGS, starts the reader,
    /// dispatcher and PING keep-alive loops, then waits for the peer SETTINGS ACK.
    /// </summary>
    public static async Task<H2Connection> ConnectAsync(
        string host, int port, H2ConnectionOptions options,
        CancellationToken ct = default)
    {
        var tcp = new TcpClient();
        SslStream? ssl = null;
        try
        {
            using (var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                timeoutCts.CancelAfter(options.ConnectTimeout);
                if (options.LocalEndpoint is { } le)
                    tcp.Client.Bind(le);
                await tcp.ConnectAsync(host, port, timeoutCts.Token).ConfigureAwait(false);
            }

            // Strict validation by default — Python h2_transport.py/cf_h2.py use
            // create_ssl_context() (certifi + OS roots, check_hostname=True).
            // The blanket "accept anything" callback is opt-in only (spike/test origins).
            // NOTE: GetStream() must be called only AFTER the socket is connected.
            ssl = new SslStream(
                tcp.GetStream(), leaveInnerStreamOpen: false,
                userCertificateValidationCallback: options.AllowInsecureTestCertificates
                    ? static (_, _, _, _) => true
                    : null);

            var clientHello = new SslClientAuthenticationOptions
            {
                TargetHost = string.IsNullOrEmpty(options.SniHost) ? host : options.SniHost,
                ApplicationProtocols = [SslApplicationProtocol.Http2],
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            };
            using (var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                timeoutCts.CancelAfter(options.ConnectTimeout);
                await ssl.AuthenticateAsClientAsync(clientHello, timeoutCts.Token)
                         .ConfigureAwait(false);
            }

            if (ssl.NegotiatedApplicationProtocol != SslApplicationProtocol.Http2)
                throw new H2ProtocolException(H2ErrorCode.ProtocolError,
                    $"Origin did not negotiate h2 (ALPN: '{ssl.NegotiatedApplicationProtocol}')");

            var conn = new H2Connection(tcp, ssl, ssl, options) { AlpnProtocol = "h2" };
            conn.Start();
            await conn.WaitForSettingsAckAsync(options.ConnectTimeout, ct).ConfigureAwait(false);
            return conn;
        }
        catch
        {
            ssl?.Dispose();
            tcp.Dispose();
            throw;
        }
    }

    /// <summary>Wraps an already-established, ALPN-negotiated stream (used by tests/fake-TLS paths).</summary>
    internal static H2Connection CreateAttached(Stream duplex, H2ConnectionOptions options, string alpn = "h2")
    {
        // No SslStream here — the duplex stream is the real transport (fake-TLS / tests).
        var conn = new H2Connection(new TcpClient(), ssl: null, duplex, options)
        {
            AlpnProtocol = alpn,
        };
        conn.Start();
        return conn;
    }

    private void Start()
    {
        Volatile.Write(ref _lastActivityTicks, Environment.TickCount64);
        // Preface + our SETTINGS + connection-level WINDOW_UPDATE bump to 4 MiB,
        // exactly like h2.initiate_connection()/increment_flow_control_window().
        var outBuffer = new List<byte>(256);
        H2FrameWriter.AppendPreface(outBuffer);
        H2FrameWriter.AppendSettings(outBuffer, new Dictionary<H2SettingId, uint>
        {
            [H2SettingId.EnablePush] = 0,
            [H2SettingId.InitialWindowSize] = H2Consts.StreamReceiveWindow,
        });
        H2FrameWriter.AppendWindowUpdate(outBuffer, 0,
            H2Consts.ConnectionReceiveWindow - H2Consts.DefaultInitialWindowSize);
        _ = FlushRawAsync(outBuffer, CancellationToken.None);

        _readerTask = Task.Run(() => ReaderLoopAsync(_cts.Token));
        _dispatcherTask = Task.Run(() => DispatcherLoopAsync(_cts.Token));
        if (Options.KeepAliveInterval > TimeSpan.Zero)
            _keepAliveTask = Task.Run(() => KeepAliveLoopAsync(_cts.Token));
    }

    /// <summary>Awaits the peer SETTINGS ACK (or our own SETTINGS frame being acknowledged),
    /// mirroring h2_transport's `settings_received` gate before issuing requests.</summary>
    public async Task WaitForSettingsAckAsync(TimeSpan timeout, CancellationToken ct)
    {
        var completed = await Task.WhenAny(_settingsAck.Task, Task.Delay(timeout, ct)).ConfigureAwait(false);
        if (completed != _settingsAck.Task)
            throw new TimeoutException("Timed out waiting for H2 SETTINGS exchange.");
        await _settingsAck.Task.ConfigureAwait(false); // propagate failures
    }

    // ------------------------------------------------------------------
    // Requests
    // ------------------------------------------------------------------

    /// <summary>Sends a request and returns once response headers are received (body streams lazily).</summary>
    public async Task<H2Response> RequestAsync(
        string method, string path, string authority,
        IReadOnlyList<(string Name, byte[] Value)> headers,
        ReadOnlyMemory<byte> body, Action? onBodySent = null,
        Action? onResponseStarted = null, CancellationToken ct = default)
    {
        EnsureHealthy();
        if (_nextStreamId > _goawayLastStreamId)
            throw new H2ProtocolException(H2ErrorCode.GoawayError, "GOAWAY received; no new streams.");
        if (_streams.Count >= Math.Min(Options.MaxConcurrentStreams, _remoteMaxConcurrentStreams))
            throw new InvalidOperationException("H2 stream capacity exhausted.");

        int streamId = _nextStreamId;
        _nextStreamId += 2;
        var stream = new H2Stream(streamId)
        {
            SendWindow = Math.Min(Volatile.Read(ref _initialRemoteWindowSize), _connectionSendWindow),
            Connection = this,
        };
        _streams[streamId] = stream;

        try
        {
            var fields = new List<(string, byte[])>(headers.Count + 4)
            {
                (":method", System.Text.Encoding.ASCII.GetBytes(method)),
                (":scheme", "https"u8.ToArray()),
                (":authority", System.Text.Encoding.ASCII.GetBytes(authority)),
                (":path", System.Text.Encoding.ASCII.GetBytes(path)),
            };
            foreach (var (name, value) in headers)
            {
                string lower = name.ToLowerInvariant();
                if (lower is "host" or "connection" or "keep-alive" or "proxy-connection"
                        or "upgrade" or "transfer-encoding" or "content-length")
                    continue; // hop-by-hop / framing headers handled by H2 itself
                fields.Add((lower, value));
            }

            byte[] block;
            lock (_hpack)
                block = _hpack.Encode(fields);

            bool endStream = body.IsEmpty;
            var outBuffer = new List<byte>(block.Length + 32);
            H2FrameWriter.AppendHeaders(outBuffer, streamId, block, endStream, endHeaders: true);
            await SendAsync(outBuffer, ct).ConfigureAwait(false);

            if (!endStream)
            {
                await SendBodyAsync(stream, body, ct).ConfigureAwait(false);
                var fin = new List<byte>(16);
                H2FrameWriter.AppendData(fin, streamId, ReadOnlySpan<byte>.Empty, endStream: true);
                await SendAsync(fin, ct).ConfigureAwait(false);
                stream.State = H2StreamState.HalfClosedLocal;
                // cf_h2.py trace hook `http2.send_request_body.complete`: fires once
                // the full request body (incl. END_STREAM) has been written out.
                onBodySent?.Invoke();
            }

            // Wait for response headers (Python: `while stream.headers is None`).
            while (stream.Headers is null)
            {
                if (!await stream.WaitAsync(Options.ReadTimeout, ct).ConfigureAwait(false))
                {
                    Fail(new TimeoutException($"Timed out waiting for H2 stream {streamId} headers."));
                    throw _error!;
                }
                stream.CheckError();
                EnsureHealthy();
            }
            // cf_h2.py `response_started()` fires as soon as response headers arrive.
            onResponseStarted?.Invoke();
            return new H2Response(stream, stream.Headers);
        }
        catch
        {
            ReleaseStream(stream, resetIfOpen: true);
            throw;
        }
    }

    /// <summary>
    /// Lightweight GET used for lane preflight (cf_h2.py `_preflight`): returns the
    /// response status and verifies that we are actually on HTTP/2 (ALPN checked at connect).
    /// </summary>
    public async Task<int> PreflightStatusAsync(string authority, string path = "/api",
                                                CancellationToken ct = default)
    {
        var resp = await RequestAsync("HEAD", path, authority, [],
                             ReadOnlyMemory<byte>.Empty, ct: ct)
                       .ConfigureAwait(false);
        await resp.ReadAllAsync(int.MaxValue, ct).ConfigureAwait(false);
        ReleaseStream(resp.Stream, resetIfOpen: false);
        return resp.Status;
    }

    private async Task SendBodyAsync(H2Stream stream, ReadOnlyMemory<byte> body, CancellationToken ct)
    {
        int offset = 0;
        while (offset < body.Length)
        {
            int window;
            int frameMax;
            lock (_windowLock)
            {
                window = Math.Min(stream.SendWindow, Volatile.Read(ref _connectionSendWindow));
                frameMax = _maxOutboundFrameSize;
            }
            if (window <= 0)
            {
                // Flow-controlled: wait for a WINDOW_UPDATE event (WriteTimeout guard).
                if (!await stream.WaitAsync(Options.WriteTimeout, ct).ConfigureAwait(false))
                    throw new TimeoutException("H2 upload flow control timed out.");
                stream.CheckError();
                EnsureHealthy();
                continue;
            }
            int batch = Math.Min(body.Length - offset, Math.Min(window, H2Consts.IoBatchSize));
            var outBuffer = new List<byte>(batch + 16);
            while (batch > 0)
            {
                int n = Math.Min(batch, frameMax);
                H2FrameWriter.AppendData(outBuffer, stream.Id, body.Span[offset..(offset + n)]);
                offset += n;
                batch -= n;
                lock (_windowLock)
                {
                    stream.SendWindow -= n;
                    _connectionSendWindow -= n;
                }
            }
            await SendAsync(outBuffer, ct).ConfigureAwait(false);
        }
    }

    // ------------------------------------------------------------------
    // Sending
    // ------------------------------------------------------------------

    private async Task SendAsync(List<byte> payload, CancellationToken ct)
    {
        await _sendGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, _cts.Token);
            linked.CancelAfter(Options.WriteTimeout);
            await _net.WriteAsync(payload.ToArray(), linked.Token).ConfigureAwait(false);
            await _net.FlushAsync(linked.Token).ConfigureAwait(false);
            Volatile.Write(ref _lastActivityTicks, Environment.TickCount64);
        }
        catch (OperationCanceledException) when (!_cts.IsCancellationRequested)
        {
            var err = new TimeoutException("H2 connection write timed out.");
            Fail(err);
            throw err;
        }
        catch (IOException) when (!_cts.IsCancellationRequested)
        {
            var err = new IOException("H2 connection write failed");
            Fail(err);
            throw err;
        }
        finally
        {
            _sendGate.Release();
        }
    }

    private async Task FlushRawAsync(List<byte> data, CancellationToken ct)
    {
        try
        {
            await _net.WriteAsync(data.ToArray(), ct).ConfigureAwait(false);
            await _net.FlushAsync(ct).ConfigureAwait(false);
            Volatile.Write(ref _lastActivityTicks, Environment.TickCount64);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Fail(ex);
        }
    }

    /// <summary>Queues a PING immediately and flushes. Used by keep-alive and tests.</summary>
    internal async Task SendPingAsync(CancellationToken ct)
    {
        var opaque = new byte[8];
        RandomNumberGenerator.Fill(opaque);
        var outBuffer = new List<byte>(17);
        lock (_windowLock)
        {
            _pendingPing ??= opaque;
        }
        H2FrameWriter.AppendPing(outBuffer, opaque);
        Interlocked.Increment(ref _pingsSent);
        await SendAsync(outBuffer, ct).ConfigureAwait(false);
    }

    // ------------------------------------------------------------------
    // Reader loop (socket -> inbox channel)
    // ------------------------------------------------------------------

    private async Task ReaderLoopAsync(CancellationToken ct)
    {
        byte[] header = new byte[H2Consts.FrameHeaderSize];
        byte[] payloadMax = Array.Empty<byte>();
        try
        {
            while (!ct.IsCancellationRequested && _error is null)
            {
                await ReadExactAsync(header.AsMemory(), ct).ConfigureAwait(false);
                var h = H2FrameHeader.Parse(header);
                if (h.Length > H2Consts.MaxFrameSizeLimit)
                    throw new H2ProtocolException(H2ErrorCode.FrameSizeError,
                        $"Frame length {h.Length} exceeds limit.");
                if (payloadMax.Length < h.Length)
                    payloadMax = new byte[Math.Max(h.Length, 16 * 1024)];
                if (h.Length > 0)
                    await ReadExactAsync(payloadMax.AsMemory(0, h.Length), ct).ConfigureAwait(false);
                Volatile.Write(ref _lastActivityTicks, Environment.TickCount64);
                _inbox.Writer.TryWrite((h.Type, h.Flags, h.StreamId,
                    payloadMax.AsMemory(0, h.Length).ToArray()));
            }
        }
        catch (EndOfStreamException)
        {
            Fail(new IOException("H2 peer closed the connection"));
        }
        catch (H2ProtocolException ex)
        {
            Fail(ex);
        }
        catch (OperationCanceledException)
        {
            // shutdown
        }
        catch (IOException ex)
        {
            Fail(ex);
        }
        catch (Exception ex)
        {
            Fail(new H2ProtocolException(H2ErrorCode.InternalError, ex.Message));
        }
        finally
        {
            _inbox.Writer.TryComplete();
            WakeAllStreams();
        }
    }

    private async Task ReadExactAsync(Memory<byte> dest, CancellationToken ct)
    {
        int got = 0;
        while (got < dest.Length)
        {
            int n = await _net.ReadAsync(dest[got..], ct).ConfigureAwait(false);
            if (n == 0)
                throw new EndOfStreamException();
            got += n;
        }
    }

    // ------------------------------------------------------------------
    // Dispatcher loop (inbox -> state machines)
    // ------------------------------------------------------------------

    private async Task DispatcherLoopAsync(CancellationToken ct)
    {
        try
        {
            await foreach (var (type, flags, streamId, payload) in _inbox.Reader.ReadAllAsync()
                               .ConfigureAwait(false))
            {
                if (_error is not null) break;
                Dispatch(type, flags, streamId, payload);
            }
        }
        catch (OperationCanceledException) { }
        catch (H2ProtocolException ex) { Fail(ex); }
        catch (HpackException ex)
        {
            Fail(new H2ProtocolException(H2ErrorCode.CompressionError, ex.Message));
        }
        catch (Exception ex)
        {
            Fail(new H2ProtocolException(H2ErrorCode.InternalError, ex.Message));
        }
        finally
        {
            WakeAllStreams();
        }
    }

    private void Dispatch(H2FrameType type, byte flags, int streamId, byte[] payload)
    {
        switch (type)
        {
            case H2FrameType.Settings:
                HandleSettings(flags, payload);
                break;
            case H2FrameType.Ping:
                HandlePing(flags, payload);
                break;
            case H2FrameType.GoAway:
                HandleGoAway(payload);
                break;
            case H2FrameType.WindowUpdate:
                HandleWindowUpdate(streamId, payload);
                break;
            case H2FrameType.Headers:
                HandleHeaders(streamId, flags, payload);
                break;
            case H2FrameType.Continuation:
                HandleContinuation(streamId, flags, payload);
                break;
            case H2FrameType.Data:
                HandleData(streamId, flags, payload);
                break;
            case H2FrameType.RstStream:
                HandleRstStream(streamId, payload);
                break;
            case H2FrameType.Priority:
                // We do not implement server-side priority; ignore like the h2 lib's default.
                break;
            case H2FrameType.PushPromise:
                throw new H2ProtocolException(H2ErrorCode.ProtocolError, "Server push not allowed (ENABLE_PUSH=0).");
            default:
                throw new H2ProtocolException(H2ErrorCode.ProtocolError, $"Unknown frame type {(byte)type}.");
        }
    }

    private void HandleSettings(byte flags, byte[] payload)
    {
        if ((flags & (byte)H2Flags.Ack) != 0)
        {
            _settingsAck.TrySetResult(true);
            return;
        }
        if (payload.Length % 6 != 0)
            throw new H2ProtocolException(H2ErrorCode.FrameSizeError, "SETTINGS payload not a multiple of 6.");
        foreach (var entry in MemoryMarshalExtensions.Chunk(payload, 6))
        {
            ushort id = BinaryPrimitives.ReadUInt16BigEndian(entry.Span);
            uint value = BinaryPrimitives.ReadUInt32BigEndian(entry.Span.Slice(2));
            switch ((H2SettingId)id)
            {
                case H2SettingId.MaxConcurrentStreams:
                    Volatile.Write(ref _remoteMaxConcurrentStreams, (int)value);
                    break;
                case H2SettingId.InitialWindowSize:
                    ApplyRemoteInitialWindow((int)value);
                    break;
                case H2SettingId.MaxFrameSize:
                    if (value < H2Consts.DefaultMaxFrameSize || value > H2Consts.MaxFrameSizeLimit)
                        throw new H2ProtocolException(H2ErrorCode.ProtocolError, "SETTINGS_MAX_FRAME_SIZE out of range.");
                    Volatile.Write(ref _maxOutboundFrameSize, (int)value);
                    break;
                case H2SettingId.HeaderTableSize:
                    lock (_hpack) _hpack.SetMaxDynamicTableSize((int)value);
                    break;
                default:
                    break; // ENABLE_PUSH / MAX_HEADER_LIST_SIZE: recorded nowhere needed yet
            }
        }
        // ACK the peer's SETTINGS (client must respond, RFC 9113 §6.5.3).
        var ack = new List<byte>(9);
        H2FrameWriter.AppendSettings(ack, settings: null, ack: true);
        _ = FlushRawAsync(ack, _cts.Token);
        WakeAllStreams();
    }

    private void ApplyRemoteInitialWindow(int newValue)
    {
        // RFC 9113 §6.9.2: SETTINGS_INITIAL_WINDOW_SIZE re-scales every open
        // stream send window by the delta (may go negative → back-pressure).
        int delta = newValue - Volatile.Read(ref _initialRemoteWindowSize);
        Volatile.Write(ref _initialRemoteWindowSize, newValue);
        lock (_windowLock)
        {
            foreach (var s in _streams.Values)
                s.SendWindow += delta;
        }
        Volatile.Write(ref _remoteInitialWindowSizeInfo, newValue);
    }

    private int _initialRemoteWindowSize = H2Consts.DefaultInitialWindowSize;
    private int _remoteInitialWindowSizeInfo;
    public int RemoteInitialWindowSize => Volatile.Read(ref _remoteInitialWindowSizeInfo);

    private void HandlePing(byte flags, byte[] payload)
    {
        if (payload.Length != 8)
            throw new H2ProtocolException(H2ErrorCode.FrameSizeError, "PING payload must be 8 octets.");
        if ((flags & (byte)H2Flags.Ack) != 0)
        {
            lock (_windowLock)
            {
                if (_pendingPing is not null && _pendingPing.AsSpan().SequenceEqual(payload))
                {
                    _pendingPing = null;
                    Interlocked.Increment(ref _pingsAcked);
                }
            }
            Volatile.Write(ref _lastActivityTicks, Environment.TickCount64);
            _pingAck?.TrySetResult(true);
            return;
        }
        // Peer ping → immediate ACK.
        var outBuffer = new List<byte>(17);
        H2FrameWriter.AppendPing(outBuffer, payload, ack: true);
        _ = FlushRawAsync(outBuffer, _cts.Token);
    }

    /// <summary>Sends a PING and awaits its ACK within <paramref name="timeout"/>; false on timeout.</summary>
    public async Task<bool> PingOnceAsync(TimeSpan timeout, CancellationToken ct = default)
    {
        var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pingAck = tcs;
        await SendPingAsync(ct).ConfigureAwait(false);
        var completed = await Task.WhenAny(tcs.Task, Task.Delay(timeout, ct)).ConfigureAwait(false);
        if (completed == tcs.Task)
        {
            await tcs.Task.ConfigureAwait(false);
            return true;
        }
        return false;
    }

    private void HandleGoAway(byte[] payload)
    {
        if (payload.Length < 8)
            throw new H2ProtocolException(H2ErrorCode.FrameSizeError, "GOAWAY payload shorter than 8 octets.");
        int lastStream = BinaryPrimitives.ReadInt32BigEndian(payload) & 0x7fff_ffff;
        var code = (H2ErrorCode)BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(4));
        Volatile.Write(ref _goawayLastStreamId, lastStream);
        // Complete streams beyond lastStream; keep older ones running.
        foreach (var s in _streams.Values.Where(s => s.Id > lastStream).ToArray())
        {
            s.ResetByPeer ??= code;
            s.Notify();
            ReleaseStream(s, resetIfOpen: false);
        }
        if (code != H2ErrorCode.NoError)
            Fail(new H2ProtocolException(code, $"GOAWAY error={code} last_stream={lastStream}"));
        else
            WakeAllStreams();
    }

    private void HandleWindowUpdate(int streamId, byte[] payload)
    {
        if (payload.Length != 4)
            throw new H2ProtocolException(H2ErrorCode.FrameSizeError, "WINDOW_UPDATE payload must be 4 octets.");
        int increment = BinaryPrimitives.ReadInt32BigEndian(payload) & 0x7fff_ffff;
        if (increment == 0)
            throw new H2ProtocolException(H2ErrorCode.ProtocolError, "WINDOW_UPDATE increment must be non-zero.");
        if (streamId == 0)
        {
            lock (_windowLock)
            {
                long w = (long)Volatile.Read(ref _connectionSendWindow) + increment;
                if (w > int.MaxValue)
                    throw new H2ProtocolException(H2ErrorCode.FlowControlError, "Connection window overflow.");
                _connectionSendWindow = (int)w;
            }
            foreach (var s in _streams.Values) s.Notify();
            return;
        }
        if (_streams.TryGetValue(streamId, out var stream))
        {
            lock (_windowLock)
            {
                long w = (long)stream.SendWindow + increment;
                if (w > int.MaxValue)
                    throw new H2ProtocolException(H2ErrorCode.FlowControlError, "Stream window overflow.");
                stream.SendWindow = (int)w;
            }
            stream.Notify(); // wake body sender blocked on flow control
        }
    }

    private void HandleHeaders(int streamId, byte flags, byte[] payload)
    {
        if (streamId == 0)
            throw new H2ProtocolException(H2ErrorCode.ProtocolError, "HEADERS on stream 0.");
        if (!_streams.TryGetValue(streamId, out var stream))
            return; // unknown/closed stream: ignore per RFC after GOAWAY/reset

        var block = StripPadding(flags, payload);
        if (stream.HasOutstandingHeaders)
            throw new H2ProtocolException(H2ErrorCode.ProtocolError,
                $"HEADERS without END_HEADERS followed by another HEADERS (stream {streamId}).");
        stream.HeaderBlock ??= new List<byte>(block.Length + 16);
        stream.HeaderBlock.AddRange(block);
        stream.EndHeadersPending = (flags & (byte)H2Flags.EndHeaders) == 0;
        stream.HasOutstandingHeaders = stream.EndHeadersPending;
        if ((flags & (byte)H2Flags.EndStream) != 0)
            MarkEndedByPeer(stream);
        if (!stream.EndHeadersPending)
            DeliverHeaderBlock(stream);
        stream.Notify();
    }

    private void HandleContinuation(int streamId, byte flags, byte[] payload)
    {
        if (!_streams.TryGetValue(streamId, out var stream) || !stream.HasOutstandingHeaders)
            throw new H2ProtocolException(H2ErrorCode.ProtocolError,
                "CONTINUATION without preceding incomplete HEADERS.");
        stream.HeaderBlock!.AddRange(payload);
        stream.HasOutstandingHeaders = (flags & (byte)H2Flags.EndHeaders) == 0;
        if (!stream.HasOutstandingHeaders)
            DeliverHeaderBlock(stream);
        stream.Notify();
    }

    private void DeliverHeaderBlock(H2Stream stream)
    {
        var block = stream.HeaderBlock!.ToArray();
        stream.HeaderBlock = null;
        if (block.Length > H2Consts.MaxHeadersPayload)
            throw new H2ProtocolException(H2ErrorCode.CompressionError, "Header block too large.");
        List<HpackHeader> headers;
        lock (_hpack)
            headers = _hpack.Decode(block);
        stream.Headers = headers;
    }

    private static byte[] StripPadding(byte flags, byte[] payload)
    {
        if ((flags & (byte)H2Flags.Padded) == 0)
            return payload;
        int padLen = payload[0];
        if (padLen > payload.Length - 1)
            throw new H2ProtocolException(H2ErrorCode.FrameSizeError, "Padding longer than frame.");
        return payload.AsSpan(1, payload.Length - 1 - padLen).ToArray();
    }

    private void HandleData(int streamId, byte flags, byte[] payload)
    {
        if (streamId == 0)
            throw new H2ProtocolException(H2ErrorCode.ProtocolError, "DATA on stream 0.");
        var data = StripPadding(flags, payload);

        // Connection-level flow control accounting happens even for unknown streams.
        lock (_windowLock)
            _connectionPendingUpdate += data.Length;

        if (!_streams.TryGetValue(streamId, out var stream))
        {
            MaybeReturnConnectionWindow();
            return;
        }

        // Enforce that the peer respects our advertised receive window.
        lock (_windowLock)
        {
            if (data.Length > stream.RecvWindow)
                throw new H2ProtocolException(H2ErrorCode.FlowControlError,
                    $"DATA {data.Length} exceeds stream {streamId} window {stream.RecvWindow}.");
            stream.RecvWindow -= data.Length;
        }

        if (data.Length > 0)
        {
            stream.Chunks.Enqueue(data);
            stream.BufferedBytes += data.Length;
            stream.ReceivedBytes += data.Length;
        }
        else
        {
            // Empty DATA still consumes credit — return it right away.
            stream.PendingWindowUpdate += 0;
        }

        if ((flags & (byte)H2Flags.EndStream) != 0)
            MarkEndedByPeer(stream);

        ReturnCredit(stream);
        MaybeReturnConnectionWindow();
        stream.Notify();
    }

    private void MarkEndedByPeer(H2Stream stream)
    {
        stream.EndedByPeer = true;
        stream.State = stream.State switch
        {
            H2StreamState.Open => H2StreamState.HalfClosedRemote,
            H2StreamState.HalfClosedLocal => H2StreamState.Closed,
            var other => other,
        };
    }

    /// <summary>Consumer notifies us that <paramref name="count"/> bytes were handed upstream.</summary>
    internal void StreamConsumed(H2Stream stream, int count)
    {
        if (count <= 0 || stream.IsFinished) return;
        lock (_windowLock)
            stream.PendingWindowUpdate += count;
        if (stream.BufferedBytes >= 0)
            stream.BufferedBytes = Math.Max(0, stream.BufferedBytes - count);
        ReturnCredit(stream);
    }

    private void ReturnCredit(H2Stream stream)
    {
        int credit;
        lock (_windowLock)
        {
            // Batch small updates like h2_transport.consumed(): wait until either
            // the buffer drained or IoBatchSize worth of credit accumulated.
            if (stream.PendingWindowUpdate < H2Consts.IoBatchSize &&
                !(stream.PendingWindowUpdate > 0 && stream.BufferedBytes == 0) &&
                !stream.EndedByPeer)
                return;
            credit = stream.PendingWindowUpdate;
            stream.PendingWindowUpdate = 0;
        }
        if (credit <= 0) return;
        lock (_windowLock)
            stream.RecvWindow += credit; // keep our advertised window constant
        var outBuffer = new List<byte>(13);
        try
        {
            H2FrameWriter.AppendWindowUpdate(outBuffer, stream.Id, credit);
            _ = FlushRawAsync(outBuffer, _cts.Token);
        }
        catch (ArgumentOutOfRangeException)
        {
            // > 31-bit increment: split would be needed; practically unreachable here.
        }
    }

    private void MaybeReturnConnectionWindow()
    {
        int credit;
        lock (_windowLock)
        {
            if (_connectionPendingUpdate < H2Consts.IoBatchSize)
                return;
            credit = _connectionPendingUpdate;
            _connectionPendingUpdate = 0;
        }
        var outBuffer = new List<byte>(13);
        H2FrameWriter.AppendWindowUpdate(outBuffer, 0, credit);
        _ = FlushRawAsync(outBuffer, _cts.Token);
    }

    private void HandleRstStream(int streamId, byte[] payload)
    {
        if (streamId == 0)
            throw new H2ProtocolException(H2ErrorCode.ProtocolError, "RST_STREAM on stream 0.");
        if (payload.Length != 4)
            throw new H2ProtocolException(H2ErrorCode.FrameSizeError, "RST_STREAM payload must be 4 octets.");
        var code = (H2ErrorCode)BinaryPrimitives.ReadUInt32BigEndian(payload);
        if (_streams.TryGetValue(streamId, out var stream))
        {
            stream.ResetByPeer = code;
            stream.State = H2StreamState.Closed;
            stream.Notify();
            ReleaseStream(stream, resetIfOpen: false);
        }
    }

    // ------------------------------------------------------------------
    // Keep-alive
    // ------------------------------------------------------------------

    private async Task KeepAliveLoopAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested && _error is null)
            {
                await Task.Delay(Options.KeepAliveInterval, ct).ConfigureAwait(false);
                if (ct.IsCancellationRequested || _error is not null) break;

                long idleMs = Environment.TickCount64 - Volatile.Read(ref _lastActivityTicks);
                if (idleMs < (long)Options.KeepAliveInterval.TotalMilliseconds * 3 / 2)
                    continue; // traffic keeps the connection alive; nothing to prove

                await SendPingAsync(ct).ConfigureAwait(false);
                bool acked = await PingOnceWaitAsync(Options.PingTimeout, ct).ConfigureAwait(false);
                if (!acked)
                {
                    Fail(new IOException("H2 keep-alive PING timed out — connection considered dead."));
                    break;
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            Fail(ex);
        }
    }

    private async Task<bool> PingOnceWaitAsync(TimeSpan timeout, CancellationToken ct)
    {
        byte[] expected;
        lock (_windowLock)
            expected = _pendingPing ?? [];
        if (expected.Length == 0) return true;
        var deadline = Environment.TickCount64 + (long)timeout.TotalMilliseconds;
        while (Environment.TickCount64 < deadline && !ct.IsCancellationRequested)
        {
            lock (_windowLock)
            {
                if (_pendingPing is null) return true;
            }
            await Task.Delay(50, ct).ConfigureAwait(false);
        }
        return false;
    }

    // ------------------------------------------------------------------
    // Housekeeping
    // ------------------------------------------------------------------

    private void EnsureHealthy()
    {
        if (_error is not null) throw _error;
        if (_cts.IsCancellationRequested) throw new ObjectDisposedException(nameof(H2Connection));
    }

    internal void CheckStreamError(H2Stream stream)
    {
        if (stream.ResetByPeer is { } rc)
            throw new H2ProtocolException(rc, $"Stream {stream.Id} reset by peer.");
        if (stream.ConnectionError is { } ce) throw ce;
    }

    private void Fail(Exception error)
    {
        if (_error is not null) return;
        _error = error;
        foreach (var s in _streams.Values)
        {
            s.ConnectionError = error;
            s.Notify();
        }
        _settingsAck.TrySetException(error);
        _pingAck?.TrySetException(error);
        _inbox.Writer.TryComplete(error);
    }

    private void WakeAllStreams()
    {
        foreach (var s in _streams.Values) s.Notify();
    }

    /// <summary>Detaches a finished/abandoned stream from the connection. Used by
    /// the cf_h2 lane after it has drained a response (<c>cf_h2.py</c> closes the
    /// httpx stream once the body is consumed).</summary>
    internal void ReleaseStream(H2Stream stream, bool resetIfOpen)
    {
        _streams.TryRemove(stream.Id, out _);
        if (resetIfOpen && _error is null && !stream.EndedByPeer &&
            stream.State is H2StreamState.Open or H2StreamState.HalfClosedRemote)
        {
            var outBuffer = new List<byte>(13);
            H2FrameWriter.AppendRstStream(outBuffer, stream.Id, H2ErrorCode.Cancel);
            _ = FlushRawAsync(outBuffer, CancellationToken.None);
        }
        // Capacity may have freed up — wake any waiter blocked in RequestAsync? (callers poll)
        WakeAllStreams();
    }

    /// <summary>Closes the connection gracefully: GOAWAY(NO_ERROR), then dispose sockets.</summary>
    public async ValueTask DisposeAsync()
    {
        if (_cts.IsCancellationRequested) return;
        try
        {
            if (_error is null)
            {
                var outBuffer = new List<byte>(17);
                H2FrameWriter.AppendGoAway(outBuffer, _nextStreamId - 2, H2ErrorCode.NoError);
                await _sendGate.WaitAsync(TimeSpan.FromMilliseconds(200)).ConfigureAwait(false);
                try
                {
                    await _net.WriteAsync(outBuffer.ToArray(), CancellationToken.None)
                               .AsTask().ConfigureAwait(false);
                }
                finally { _sendGate.Release(); }
            }
        }
        catch { /* best-effort */ }
        _cts.Cancel();
        foreach (var s in _streams.Values)
            s.ConnectionError ??= new IOException("H2 connection closed");
        WakeAllStreams();
        _settingsAck.TrySetCanceled();
        _pingAck?.TrySetCanceled();
        _inbox.Writer.TryComplete();
        try { if (_readerTask is not null) await _readerTask.ConfigureAwait(false); } catch { }
        try { if (_dispatcherTask is not null) await _dispatcherTask.ConfigureAwait(false); } catch { }
        try { if (_keepAliveTask is not null) await _keepAliveTask.ConfigureAwait(false); } catch { }
        _ssl?.Dispose();
        _tcp.Dispose();
        _cts.Dispose();
        _sendGate.Dispose();
    }

    /// <summary>Force-fail like <c>_Connection.fail()</c>: mark error, wake everyone, close socket.</summary>
    public void Abandon(Exception error)
    {
        Fail(error);
        _cts.Cancel();
        try { _tcp.Close(); } catch { }
    }
}

/// <summary>Small helper: iterate fixed-size chunks of an array as spans.</summary>
internal static class MemoryMarshalExtensions
{
    public static IEnumerable<ReadOnlyMemory<byte>> Chunk(byte[] data, int size)
    {
        for (int i = 0; i + size <= data.Length; i += size)
            yield return data.AsMemory(i, size);
    }
}
