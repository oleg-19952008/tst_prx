using System.Collections.Concurrent;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using TgWsProxy.Core;
using TgWsProxy.Observability;

namespace TgWsProxy.Transport.H2;

/// <summary>
/// One Cloudflare "lane": a single H2 connection to <c>kwsN.&lt;domain&gt;</c> shared by
/// several logical channels — port of <c>proxy/cf_h2.py::_HttpLane</c>.
/// The Python class wrapped an <c>httpx.AsyncClient</c> over the custom
/// <c>H2Transport</c>; here we drive our own <see cref="H2Connection"/> engine
/// (Transport/H2) directly, which already speaks HTTP/2 with full flow control.
/// </summary>
internal sealed class HttpLane : IAsyncDisposable
{
    private static ILogger Log => _log ??= ProgramLogger.For<HttpLane>();
    private static ILogger? _log;

    /// <summary>Python: <c>MAX_LANE_REQUESTS = 64</c>, <c>REQUEST_TIMEOUT = 65s</c>.</summary>
    public const int MaxLaneRequests = CfH2Consts.MaxLaneRequests;
    public const int MaxLaneBytes = CfH2Consts.MaxLaneBytes;
    public const int MaxLaneReplyBytes = CfH2Consts.MaxLaneReplyBytes;

    public string Host { get; }
    public int LaneId { get; }

    /// <summary>Python <c>self.channels: Set[_HttpChannel]</c>.</summary>
    public ConcurrentDictionary<HttpChannel, byte> Channels { get; } = new();

    public double FailedUntil { get; set; }

    // ---- counters mirroring the Python attributes -------------------------
    public long TcpConnections;
    public long Requests;
    public long Responses;
    public long Errors;
    public long SlowHeaders;
    public long SlowBodies;
    public long Replays;
    public double MaxHeadersSeconds;
    public double MaxBodySeconds;
    public double NextWaitLog;
    public double NextSlowLog;
    public double NextCapacityLog;
    public double NextLargeSlowLog;
    public long CapacityRotations;
    public int Inflight;
    public int QueuedBytes;
    public int MaxInflight;
    public int ReplyBufferBytes;

    private readonly SemaphoreSlim _capacity = new(1, 1);
    private readonly SemaphoreSlim _connectGate = new(1, 1);
    private volatile bool _closed;
    private H2Connection? _conn;

    internal HttpLane(string host, int laneId)
    {
        Host = host;
        LaneId = laneId;
    }

    private static double Now => StopwatchMono.Now;

    private async Task<H2Connection> GetConnAsync(CancellationToken ct)
    {
        if (_conn is { IsHealthy: true } live) return live;
        await _connectGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_conn is { IsHealthy: true } again) return again;
            if (_conn is not null)
                await DisposeConnAsync().ConfigureAwait(false);

            var options = new H2ConnectionOptions
            {
                MaxConcurrentStreams = MaxLaneRequests,
                ConnectTimeout = TimeSpan.FromSeconds(CfH2Consts.SetupTimeout),   // httpx connect=8
                WriteTimeout = TimeSpan.FromSeconds(10),
                ReadTimeout = TimeSpan.FromSeconds(CfH2Consts.RequestTimeout),
                SniHost = Host,
            };
            // Python's trace hook `connection.connect_tcp.started` counted every new TCP
            // connection (H2Transport opens one per client); we open one per lane.
            TcpConnections++;
            ProxyStats.Shared.AddH2TcpConnection();
            Log.LogDebug("H2 lane={Lane} TCP_OPEN connection={Tcp} host={Host} channels={Channels}",
                         LaneId, TcpConnections, Host, Channels.Count);
            _conn = await H2Connection.ConnectAsync(Host, 443, options, ct).ConfigureAwait(false);
            return _conn;
        }
        finally
        {
            _connectGate.Release();
        }
    }

    /// <summary>Python <c>_preflight</c>: HEAD https://host/api must be HTTP/2 and 2xx/405/501.</summary>
    public async Task PreflightAsync(CancellationToken ct)
    {
        double started = Now;
        var conn = await GetConnAsync(ct).ConfigureAwait(false);
        int status = await conn.PreflightStatusAsync(Host, "/api", ct).ConfigureAwait(false);
        // ALPN h2 was enforced inside ConnectAsync — equivalent to the
        // `response.http_version != 'HTTP/2'` check in cf_h2.py.
        if (!(status is >= 200 and < 300) && status is not (405 or 501))
            throw new ConnectionError($"CF /api preflight HTTP {status}");
        Log.LogDebug("H2 lane={Lane} ready host={Host} status={Status} ms={Ms:F0}",
                     LaneId, Host, status, (Now - started) * 1000);
    }

    /// <summary>Python <c>_has_capacity</c>.</summary>
    public bool HasCapacity(int length) =>
        Inflight < MaxLaneRequests && QueuedBytes + length <= MaxLaneBytes;

    /// <summary>Python <c>_reserve</c>: waits for room unless <paramref name="wait"/> is false.</summary>
    public async Task<bool> ReserveAsync(int length, bool wait, CancellationToken ct)
    {
        await _capacity.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (!wait && !HasCapacity(length))
                return false;
            if (wait)
            {
                // asyncio.wait_for(capacity.wait_for(...), REQUEST_TIMEOUT)
                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeoutCts.CancelAfter(TimeSpan.FromSeconds(CfH2Consts.RequestTimeout));
                while (!HasCapacity(length))
                {
                    if (_closed) throw new ConnectionError("H2 lane closed");
                    try
                    {
                        await Task.Delay(50, timeoutCts.Token).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (!_closed)
                    {
                        throw new TimeoutException("H2 lane capacity wait timed out");
                    }
                }
            }
            if (_closed) throw new ConnectionError("H2 lane closed");
            Inflight++;
            QueuedBytes += length;
            MaxInflight = Math.Max(MaxInflight, Inflight);
            return true;
        }
        finally
        {
            _capacity.Release();
        }
    }

    /// <summary>Python <c>_release</c>.</summary>
    public Task ReleaseAsync(int length)
    {
        lock (_capacity)
        {
            Inflight--;
            QueuedBytes -= length;
        }
        return Task.CompletedTask;
    }

    /// <summary>
    /// Python <c>_post</c>: POSTs one MTProto packet to <c>https://host/api</c> and returns
    /// the fully-buffered reply after validating status/content-type/size bounds.
    /// </summary>
    public async Task<byte[]> PostAsync(byte[] body, HttpChannel channel, bool replay,
                                        RequestTrace? trace, CancellationToken ct)
    {
        Requests++;
        if (replay) Replays++;
        ProxyStats.Shared.AddH2Request();
        int requestId = (int)Requests;
        double started = Now;
        int buffered = 0;
        bool receiving = false;

        void ResponseStarted()
        {
            if (trace is not null && trace.HeadersAt is null)
            {
                trace.HeadersAt = Now;
                trace.Phase = "body";
            }
            if (!receiving)
            {
                channel.MarkReceiving(true);
                channel.LastProgress = Now;
                receiving = true;
            }
        }

        try
        {
            var conn = await GetConnAsync(ct).ConfigureAwait(false);
            if (trace is not null)
            {
                trace.Request = requestId;
                trace.Phase = "stream-slot";
            }

            var headers = new[]
            {
                ("content-type", System.Text.Encoding.ASCII.GetBytes("application/octet-stream")),
                ("accept-encoding", System.Text.Encoding.ASCII.GetBytes("identity")),
            };

            var resp = await conn.RequestAsync(
                "POST", "/api", Host, headers, body,
                onBodySent: () =>
                {
                    // Python cf_h2.py request_trace(): the httpx event
                    // `http2.send_request_body.complete` marks BOTH sent_since[task]
                    // and trace.sent_at for the *current* task — there is no separate
                    // MarkBodySent() step in the original.
                    channel.MarkBodySent();
                    if (trace is not null)
                    {
                        trace.SentAt = Now;
                        trace.Phase = trace.HeadersAt is null ? "headers" : "body";
                    }
                },
                onResponseStarted: ResponseStarted,
                ct).ConfigureAwait(false);

            double headersAt = Now;
            if (trace is not null)
            {
                string ray = resp.Header("cf-ray") ?? "-";
                trace.CfRay = new string(ray.Where(c => c < 128 && (char.IsAsciiLetterOrDigit(c) || c == '-')).Take(64).ToArray());
            }
            SlowHeaders += Convert.ToInt32(headersAt - started >= CfH2Consts.SlowResponseSeconds);
            MaxHeadersSeconds = Math.Max(MaxHeadersSeconds, headersAt - started);

            int status = resp.Status;
            if (status is 403 or 404 or 429 or 444)
                throw new MtprotoTransportError(-status, $"HTTP {status} cf_ray={resp.Header("cf-ray") ?? "-"}");
            if (status != 200)
                throw new ConnectionError($"CF /api HTTP {status} cf_ray={resp.Header("cf-ray") ?? "-"}");
            string contentType = resp.Header("content-type") ?? "";
            if (contentType.Contains("text/html", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("CF /api returned HTML instead of MTProto");

            ResponseStarted(); // Python calls response_started() explicitly after header checks

            long? declaredLength = null;
            if (resp.Header("content-length") is { Length: > 0 } cl && long.TryParse(cl, out var parsed))
                declaredLength = parsed;
            if (declaredLength is not null && (declaredLength < 0 || declaredLength > CfH2Consts.MaxPacket))
                throw new ReplyBufferFullException("H2 response Content-Length exceeds native packet bound");

            using var ms = new MemoryStream();
            await foreach (var chunk in resp.BodyAsync(ct).ConfigureAwait(false))
            {
                if (ms.Length + chunk.Length > CfH2Consts.MaxPacket)
                    throw new ReplyBufferFullException("H2 response exceeds native packet bound");
                if (ReplyBufferBytes + chunk.Length > MaxLaneReplyBytes)
                    throw new ReplyBufferFullException("H2 lane response buffers exceeded bound");
                ReplyBufferBytes += chunk.Length;
                buffered += chunk.Length;
                ms.Write(chunk);
                if (trace is not null) trace.Received += chunk.Length;
                channel.LastProgress = Now;
            }

            byte[] content = ms.ToArray();
            string contentEncoding = resp.Header("content-encoding") ?? "identity";
            if (declaredLength is not null && contentEncoding.Equals("identity", StringComparison.OrdinalIgnoreCase)
                && content.Length != declaredLength)
                throw new ArgumentException("incomplete H2 response body");
            if (content.Length != 0 && content.Length % 4 != 0)
                throw new ArgumentException("CF /api response is not an aligned MTProto packet");
            if (content.Length == 4)
            {
                int code = BitConverter.ToInt32(content);
                if (code < 0)
                    throw new MtprotoTransportError(code, "HTTP 200 payload");
            }

            Responses++;
            int received = content.Length;
            channel.HttpBytes += received;
            channel.SmallResponses += Convert.ToInt32(received <= CfH2Consts.SmallResponseBytes);
            channel.LargeResponses += Convert.ToInt32(received > CfH2Consts.SmallResponseBytes);

            double finished = Now;
            double bodySeconds = finished - headersAt;
            MaxBodySeconds = Math.Max(MaxBodySeconds, bodySeconds);
            SlowBodies += Convert.ToInt32(bodySeconds >= CfH2Consts.SlowResponseSeconds);
            double nextSlow = received > CfH2Consts.SmallResponseBytes ? NextLargeSlowLog : NextSlowLog;
            if (finished - started >= CfH2Consts.SlowResponseSeconds && finished >= nextSlow)
            {
                if (received > CfH2Consts.SmallResponseBytes)
                    NextLargeSlowLog = finished + CfH2Consts.DiagnosticInterval;
                else
                    NextSlowLog = finished + CfH2Consts.DiagnosticInterval;
                Log.LogDebug(
                    "H2 SLOW lane={Lane} channel={Channel} request={Req} bytes={Bytes} replay={Replay} " +
                    "headers_ms={HMs:F0} body_ms={BMs:F0} detail=[{Detail}]",
                    LaneId, channel.ChannelId, requestId, received, replay,
                    (headersAt - started) * 1000, bodySeconds * 1000,
                    trace?.Summary(finished) ?? "-");
            }

            conn.ReleaseStream(resp.Stream, resetIfOpen: false);
            return content;
        }
        catch (MtprotoTransportError)
        {
            Errors++;
            throw;
        }
        catch (ReplyBufferFullException)
        {
            throw; // memory-bound failures do not cool the domain down
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or SocketException
                                   or ArgumentException or InvalidOperationException
                                   or TimeoutException or OperationCanceledException)
        {
            // Python: (httpx.HTTPError, OSError, ValueError, BufferError) → domain cooldown.
            Errors++;
            FailedUntil = Now + CfH2Consts.DomainCooldown;
            throw;
        }
        finally
        {
            ReplyBufferBytes -= buffered;
            if (receiving) channel.MarkReceiving(false);
        }
    }

    /// <summary>Python <c>log_wait</c> — periodic diagnostics for stalled channels.</summary>
    public void LogWait(double now)
    {
        if (!Log.IsEnabled(LogLevel.Debug) || now < NextWaitLog) return;
        NextWaitLog = now + 1.0;
        var waiting = Channels.Keys
            .Where(channel =>
                ((channel.DeliveringSince is { } d && now - d >= CfH2Consts.SlowResponseSeconds)
                 // Python: only requests that are neither replay probes nor currently
                 // streaming a body count as "waiting for headers".
                 || channel.PendingAges(now).Any(a => !a.IsReplay && !a.IsReceiving
                                                      && a.Age >= CfH2Consts.SlowResponseSeconds))
                && now - channel.LastNativeSend <= CfH2Consts.ReplayMaxAge)
            .ToList();
        if (waiting.Count == 0) return;
        NextWaitLog = now + CfH2Consts.DiagnosticInterval;
        waiting.Sort((a, b) => a.ChannelId.CompareTo(b.ChannelId));
        Log.LogDebug("H2 WAIT lane={Lane} affected={Affected} inflight={Inflight} body_buffer={Buf} [{States}]",
                     LaneId, waiting.Count, Inflight, ReplyBufferBytes,
                     string.Join("; ", waiting.Take(8).Select(c => c.WaitState(now))));
        var details = waiting
            .SelectMany(channel => channel.OpenTraces(now)
                .Where(t => !t.Replay && now - t.Started >= CfH2Consts.SlowResponseSeconds)
                .Select(trace => (channel, trace)))
            .OrderBy(p => p.trace.Started)
            .Take(12)
            .ToList();
        if (details.Count > 0)
            Log.LogDebug("H2 DETAIL lane={Lane} [{Details}]", LaneId,
                         string.Join("; ", details.Select(p => p.channel.RequestDetail(p.trace, now))));
    }

    /// <summary>Python <c>log_flow</c>.</summary>
    public void LogFlow(double now)
    {
        if (!Log.IsEnabled(LogLevel.Debug)) return;
        var channels = Channels.Keys.OrderBy(c => c.ChannelId).ToList();
        for (int offset = 0; offset < channels.Count; offset += 8)
            Log.LogDebug("H2 FLOW lane={Lane} [{Flow}]", LaneId,
                         string.Join("; ", channels.Skip(offset).Take(8).Select(c => c.FlowState(now))));
    }

    /// <summary>Python <c>summary</c>.</summary>
    public string Summary() => Utils.Inv($"lane={LaneId} host={Host} channels={Channels.Count} tcp_connections={TcpConnections} " +
                                   "requests={Requests} replies={Responses} errors={Errors} inflight={Inflight} " +
                                   "max_inflight={MaxInflight} queued_bytes={QueuedBytes} reply_buffer_bytes={ReplyBufferBytes} " +
                                   "replays={Replays} capacity_rotations={CapacityRotations} slow_headers={SlowHeaders} " +
                                   "slow_bodies={SlowBodies} max_headers_ms={MaxHeadersSeconds * 1000:F0} " +
                                   "max_body_ms={MaxBodySeconds * 1000:F0}");

    /// <summary>Python <c>close</c>.</summary>
    public async ValueTask DisposeAsync()
    {
        _closed = true;
        foreach (var channel in Channels.Keys.ToList())
            await channel.CloseAsync().ConfigureAwait(false);
        await DisposeConnAsync().ConfigureAwait(false);
        Log.LogDebug("H2 CLOSED {Summary}", Summary());
        GC.SuppressFinalize(this);
    }

    private async Task DisposeConnAsync()
    {
        var conn = Interlocked.Exchange(ref _conn, null);
        if (conn is not null)
            await conn.DisposeAsync().ConfigureAwait(false);
    }
}
