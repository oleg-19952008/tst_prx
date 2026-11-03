using TgWsProxy;
using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using TgWsProxy.Core;
using TgWsProxy.Observability;

namespace TgWsProxy.Transport.H2;

/// <summary>
/// One logical MTProto-over-HTTP channel multiplexed onto an <see cref="HttpLane"/> —
/// byte-for-byte port of <c>proxy/cf_h2.py::_HttpChannel</c> (PORT_PLAN.md checklist
/// item 6, part 2). Owns: the bounded reply queue with native backpressure, the
/// per-channel capacity gate, the replay history ("re-leaking" unanswered packets)
/// and the recovery loop that re-submits them.
/// <para>
/// asyncio mapping: every Python coroutine here becomes a <see cref="Request"/> record
/// holding a <see cref="TaskCompletionSource{TResult}"/> (<c>asyncio.Task.Id</c> ≈
/// <see cref="Task.Id"/>). All shared-state mutation happens under <c>_gate</c>, which
/// plays the role of both <c>self.capacity</c> Condition and the single-threaded event
/// loop; long waits release the lock (via <see cref="SemaphoreSlim"/>) exactly like
/// <c>await condition.wait()</c>.
/// </para>
/// </summary>
internal sealed class HttpChannel : IAsyncDisposable
{
    /// <summary>Python <c>pending: Dict[asyncio.Task, int]</c> — one in-flight request.</summary>
    private sealed class Request
    {
        public long Id { get; init; }                                     // Task.Id analogue
        public required Func<Task> Runner { get; init; }                  // runs _run_request
        public required CancellationTokenSource Cts { get; init; }        // task.cancel()
        public Task? Task { get; set; }                                   // materialised on start
        public int Length { get; init; }
        public bool IsReplay { get; init; }
        public ReplayPacket? Packet { get; init; }
        public bool Completed { get; set; }                               // task.done()
        public bool Receiving { get; set; }                               // receiving_tasks membership
        public double PendingSince { get; set; }                          // pending_since[task]
        public double? SentSince { get; set; }                            // sent_since[task]
        public RequestTrace? Trace { get; set; }                          // request_traces[task]

        /// <summary>Starts the underlying task under the channel gate (idempotent).</summary>
        public Task Start() => Task ??= Runner();
    }

    private static ILogger Log => _log ??= ProgramLogger.For<HttpChannel>();
    private static ILogger? _log;

    public HttpLane Lane { get; }
    public int ChannelId { get; }
    public string Label { get; }

    // ---- state mirroring the Python __init__ -------------------------------
    private readonly object _gate = new();                 // protects everything below
    private readonly SemaphoreSlim _capacity = new(1, 1);  // asyncio.Condition `capacity`
    private readonly SemaphoreSlim _sendLock = new(1, 1);  // asyncio.Lock `send_lock`
    private readonly SemaphoreSlim _closeLock = new(1, 1); // asyncio.Lock `close_lock`
    private readonly ConcurrentQueue<object> _queue = new();   // asyncio.Queue(maxsize=16)
    private readonly AsyncAutoResetEvent _queueSignal = new();
    private int _queueCount;                               // queue.qsize() bound check

    private bool _closed;                                  // self.closed
    internal int? TransportErrorCode;                      // self.transport_error
    private int? _deliveringSinceTicks;                    // self.delivering_since (ms ticks)
    private long _replyBytes;                              // self.reply_bytes
    private int _pendingBytes;                             // self.pending_bytes
    private readonly Dictionary<long, Request> _pending = new();       // self.pending
    private readonly HashSet<long> _replayPending = new();             // self.replay_pending
    private readonly List<ReplayPacket> _replayHistory = new();        // self.replay_history
    private byte[]? _replayKey;                            // self.replay_key
    private readonly LinkedList<RequestTrace> _recentTraces = new();   // deque(maxlen=16)
    private const int RecentTracesMax = 16;

    // counters (public for lane diagnostics / bridge)
    public long Requests;                                  // self.requests
    public long Up;                                        // self.up
    public long Down;                                      // self.down
    public long QuickRequests;                             // self.quick_requests
    public long ReplayRequests;                            // self.replay_requests
    public long PollRequests;                              // self.poll_requests
    public long ReplayRotations;                           // self.replay_rotations
    public long CapacityRotations;                         // self.capacity_rotations
    public long HttpBytes;                                 // self.http_bytes
    public long SmallResponses;                            // self.small_responses
    public long LargeResponses;                            // self.large_responses
    public double Started { get; }                         // self.started
    public double LastProgress;                            // self.last_progress
    public double LastNativeSend;                          // self.last_native_send
    public double FirstPollGap;                            // self.first_poll_gap
    public double? UploadWaitSince { get; private set; }   // self.upload_wait_since
    public string UploadWaitPhase { get; private set; } = "-";
    public int UploadWaitBytes { get; private set; }
    internal bool CloseDone;                               // self.close_done

    internal double? DeliveringSince =>
        _deliveringSinceTicks is { } t ? t / 1000.0 : null;

    /// <summary>Python <c>lane.channels.add(self)</c> happens in __init__ (host does it).</summary>
    internal HttpChannel(HttpLane lane, int channelId, string label)
    {
        Lane = lane;
        ChannelId = channelId;
        Label = label;
        Started = Now;
        LastProgress = Started;
        LastNativeSend = Started;
    }

    private static double Now => StopwatchMono.Now;

    // -----------------------------------------------------------------------
    // small helpers (Python properties)
    // -----------------------------------------------------------------------

    /// <summary>Python <c>receiving_http</c>.</summary>
    public int ReceivingHttp { get { lock (_gate) return _pending.Values.Count(r => r.Receiving); } }

    /// <summary>Python <c>native_backpressure</c>: queued replies or an active native write.</summary>
    public bool NativeBackpressure
    {
        get { lock (_gate) return _replyBytes != 0 || DeliveringSince is not null; }
    }

    /// <summary>Python <c>_has_capacity</c> (must be called under <c>_gate</c>).</summary>
    private bool HasCapacityLocked(int length) =>
        _pending.Count < CfH2Consts.MaxChannelRequests &&
        _pendingBytes + length <= CfH2Consts.MaxChannelBytes;

    public bool HasCapacity(int length) { lock (_gate) return HasCapacityLocked(length); }

    /// <summary>Python <c>_wake_receiver</c>.</summary>
    public void WakeReceiver()
    {
        lock (_gate)
        {
            if (!_closed && _pending.Count == 0 && !HasNativeBackpressureLocked())
                _recoveryWakeup.Set();
        }
    }

    private bool HasNativeBackpressureLocked() =>
        _replyBytes != 0 || DeliveringSince is not null;

    private readonly AsyncManualResetEvent _recoveryWakeup = new();

    /// <summary>Python <c>MarkReceiving</c> hook used by the lane during body streaming.</summary>
    internal void MarkReceiving(bool value)
    {
        long id = Task.CurrentId ?? -1;
        lock (_gate)
        {
            if (_pending.TryGetValue(id, out var req))
                req.Receiving = value;
        }
    }

    /// <summary>
    /// Python trace hook <c>http2.send_request_body.complete</c>: records sent_since for
    /// the current request task (the lane also stamps trace.sent_at itself).
    /// </summary>
    internal void MarkBodySent()
    {
        long id = Task.CurrentId ?? -1;
        lock (_gate)
        {
            if (_pending.TryGetValue(id, out var req))
                req.SentSince = Now;
        }
    }

    /// <summary>Hook invoked by the lane when response headers arrive for the current task.</summary>
    internal void MarkHeadersReceived()
    {
        long id = Task.CurrentId ?? -1;
        lock (_gate)
        {
            if (_pending.TryGetValue(id, out var req) && req.Trace is { } t && t.HeadersAt is null)
            {
                t.HeadersAt = Now;
                t.Phase = "body";
            }
        }
    }

    // -----------------------------------------------------------------------
    // replay decision predicates (verbatim ports)
    // -----------------------------------------------------------------------

    /// <summary>Python <c>_overdue_original</c> (under gate).</summary>
    private bool OverdueOriginal(ReplayPacket entry, double now) =>
        entry.Retired ||
        entry.Originals.Any(id =>
            _pending.TryGetValue(id, out var task) &&
            task.SentSince is { } sent && !task.Receiving &&
            now - sent >= CfH2Consts.ReplayRequestSeconds);

    /// <summary>Python <c>_replay_limit</c> (under gate).</summary>
    private int ReplayLimit(ReplayPacket entry) =>
        entry.Originals.Count > 0 || entry.Retired ||
        ReferenceEquals(entry, _replayHistory[^1])
            ? CfH2Consts.ReplayMaxAttempts
            : 0;

    /// <summary>Python <c>_capacity_candidate</c> (under gate).</summary>
    private (long Id, ReplayPacket? Entry)? CapacityCandidateLocked(double now)
    {
        // sorted(self.sent_since.items(), key=lambda pair: (pair[0] not in replay_pending, pair[1]))
        var candidates = _pending.Values
            .Where(t => t.SentSince is not null)
            .OrderBy(t => t.IsReplay ? 0 : 1)
            .ThenBy(t => t.SentSince!.Value)
            .ToList();
        foreach (var task in candidates)
        {
            double sent = task.SentSince!.Value;
            if (task.Completed || task.Receiving || now - sent < CfH2Consts.ReplayRequestSeconds)
                continue;
            if (task.IsReplay)
                return (task.Id, null);
            var entry = _replayHistory.FirstOrDefault(e => e.Originals.Contains(task.Id));
            if (entry is not null && now - entry.SentAt <= CfH2Consts.ReplayMaxAge)
                return (task.Id, entry);
        }
        return null;
    }

    /// <summary>Python <c>_make_upload_room</c>: free upload capacity by cancelling a stale request.</summary>
    private async Task MakeUploadRoomAsync(double now)
    {
        HttpChannel targetChannel; long targetId;

        lock (_gate)
        {
            if (_closed || UploadWaitSince is null) return;
            double waitSince = UploadWaitSince.Value;
            string phase = UploadWaitPhase;
            int waitBytes = UploadWaitBytes;
            List<HttpChannel> channels;
            if (phase == "channel-capacity")
            {
                if (HasCapacityLocked(waitBytes)) return;
                channels = [this];
            }
            else if (phase == "lane-capacity")
            {
                if (Lane.HasCapacity(waitBytes)) return;
                // sorted(lane.channels, key=min(sent_since.values(), default=now))
                channels = Lane.Channels.Keys
                    .OrderBy(c => c.MinSentSinceOr(now))
                    .ToList();
            }
            else return;

            foreach (var channel in channels)
            {
                var candidate = channel.CapacityCandidateLocked(now);
                if (candidate is null) continue;
                targetId = candidate.Value.Id;
                var targetEntry = candidate.Value.Entry;
                targetChannel = channel;
                channel._pending.TryGetValue(targetId, out var victim);
                if (victim is not null) victim.SentSince = null;
                if (targetEntry is not null) targetEntry.Retired = true;
                if (victim?.Trace is { } trace) trace.Phase = "capacity-" + trace.Phase;
                if (now >= Lane.NextCapacityLog)
                {
                    Lane.NextCapacityLog = now + CfH2Consts.DiagnosticInterval;
                    Log.LogDebug(
                        "H2 CAPACITY lane={Lane} waiting_channel={Waiting} release_channel={Release} " +
                        "reason={Reason} replay={Replay} wait_ms={WaitMs:F0} inflight={Inflight}",
                        Lane.LaneId, ChannelId, channel.ChannelId, phase,
                        victim is not null && victim.IsReplay ? 1 : 0,
                        (now - waitSince) * 1000, Lane.Inflight);
                }
                victim?.Cts.Cancel();

                // await asyncio.gather(task, return_exceptions=True) happens off-lock.
                _ = TrackCancellationAsync(channel, targetId);
                return; // Python returns after the first cancelled candidate
            }
            return;
        }
    }

    /// <summary>Cancellation follow-up: gather the killed request, then bump rotation counters.</summary>
    private static async Task TrackCancellationAsync(HttpChannel channel, long id)
    {
        try { await channel.AwaitRequestAsync(id).ConfigureAwait(false); }
        catch { /* return_exceptions=True */ }
        lock (channel._gate)
        {
            channel.CapacityRotations++;
            channel.Lane.CapacityRotations++;
        }
    }

    private double MinSentSinceOr(double fallback)
    {
        lock (_gate)
        {
            double min = fallback;
            foreach (var t in _pending.Values)
                if (t.SentSince is { } s && s < min) min = s;
            return min;
        }
    }

    /// <summary>Python <c>_replay_blocker</c> (under gate).</summary>
    private string? ReplayBlockerLocked(ReplayPacket entry, double now)
    {
        double age = now - entry.SentAt;
        if (age < 0 || age > CfH2Consts.ReplayMaxAge) return "expired";
        if (entry.Attempts >= ReplayLimit(entry)) return "budget-used";
        if (HasNativeBackpressureLocked()) return "native-backpressure";
        if (entry.Originals.Any(id => _pending.TryGetValue(id, out var t) && t.Receiving))
            return "original-body";
        if (entry.Pending is { } pid && _pending.TryGetValue(pid, out var pt) && pt.Receiving)
            return "replay-body";
        if (entry.Replayed && now - entry.LastAttemptAt < CfH2Consts.ReplayRetrySeconds)
            return "backoff-or-progress";
        if (OverdueOriginal(entry, now)) return null;
        if (!ReferenceEquals(entry, _replayHistory[^1])
            || _pending.Values.Any(t => t.Id != entry.Pending))
            return "receiver-active";
        if (entry.Replayed && now - LastProgress < CfH2Consts.ReplayIdleSeconds)
            return "backoff-or-progress";
        return null;
    }

    /// <summary>Python <c>_replay_due</c> (under gate).</summary>
    private bool ReplayDueLocked(ReplayPacket entry, double now) =>
        ReplayBlockerLocked(entry, now) is null;

    // -----------------------------------------------------------------------
    // diagnostics strings (verbatim formats)
    // -----------------------------------------------------------------------

    /// <summary>Python <c>_wait_state</c>.</summary>
    public string WaitState(double now)
    {
        lock (_gate)
        {
            double oldest = now;
            bool hasOldest = false;
            foreach (var t in _pending.Values)
                if (!hasOldest || t.PendingSince < oldest) { oldest = t.PendingSince; hasOldest = true; }

            int recoveryLeft = _replayHistory
                .Where(e => now - e.SentAt <= CfH2Consts.ReplayMaxAge)
                .Sum(e => Math.Max(0, ReplayLimit(e) - e.Attempts));
            int waitingHeaders = _pending.Values.Count(t =>
                !t.IsReplay && !t.Receiving && now - t.PendingSince >= CfH2Consts.SlowResponseSeconds);

            return Utils.Inv($"channel={ChannelId} pending={_pending.Count} replays={_replayPending.Count} " +
                       "receiving={ReceivingHttpLocked()} ready_bytes={_replyBytes} " +
                       "native_write={(DeliveringSince is not null ? 1 : 0)} " +
                       "idle_ms={(now - LastProgress) * 1000:F0} oldest_ms={(now - oldest) * 1000:F0} " +
                       "native_age_ms={(now - LastNativeSend) * 1000:F0} " +
                       "recovery_left={recoveryLeft} waiting_headers={waitingHeaders}");
        }
    }

    private int ReceivingHttpLocked() => _pending.Values.Count(t => t.Receiving);

    /// <summary>Python <c>_request_detail</c>.</summary>
    public string RequestDetail(RequestTrace trace, double now)
    {
        lock (_gate)
        {
            var entry = _replayHistory.FirstOrDefault(e => e.Sequence == trace.Packet);
            string recovery = "not-retained";
            string attempts = "-";
            if (entry is not null)
            {
                attempts = $"{entry.Attempts}/{ReplayLimit(entry)}";
                string? blocker = ReplayBlockerLocked(entry, now);
                if (blocker is not null) recovery = blocker;
                else if (entry.Pending is { } pid && _pending.TryGetValue(pid, out var probe))
                    recovery = probe.Receiving
                        ? "replay-body"
                        : Utils.Inv($"probe-{(now - _pending.GetValueOrDefault(pid)?.PendingSince ?? now) * 1000:F0}ms");
                else if (_replayPending.Count >= CfH2Consts.MaxChannelReplays) recovery = "replay-slots";
                else if (!HasCapacityLocked(entry.Body.Length)) recovery = "channel-capacity";
                else if (!Lane.HasCapacity(entry.Body.Length)) recovery = "lane-capacity";
                else if (_sendLock.CurrentCount == 0) recovery = "send-lock";
                else recovery = "eligible";
            }
            var related = _recentTraces.Where(item => item.Packet == trace.Packet).TakeLast(2).ToList();
            return $"channel={ChannelId} {trace.Summary(now)} attempts={attempts} recovery={recovery} " +
                   $"recent=[{string.Join("; ", related.Select(item => item.Summary(now)))}]";
        }
    }

    /// <summary>Python <c>_flow_state</c>; keeps its own rolling sample like the original.</summary>
    public string FlowState(double now)
    {
        lock (_gate)
        {
            (double at, long requests, long replays, long httpBytes, long down,
             long small, long large, long polls) previous = _flowSample;
            var current = (now, Requests, ReplayRequests, HttpBytes, Down,
                           SmallResponses, LargeResponses, PollRequests);
            _flowSample = current;
            double pollGap = FirstPollGap;
            FirstPollGap = 0.0;
            var probes = _pending.Values
                .Where(t => t.Trace is not null && t.Trace.Replay)
                .Select(t => t.Trace!.Summary(now))
                .Take(2)
                .ToList();
            return Utils.Inv($"channel={ChannelId} window_ms={(now - previous.at) * 1000:F0} " +
                       $"requests={current.Item2 - previous.requests} replays={current.Item3 - previous.replays} " +
                       $"http_down={current.Item4 - previous.httpBytes} native_down={current.Item5 - previous.down} " +
                       $"small={current.Item6 - previous.small} large={current.Item7 - previous.large} " +
                       $"pending={_pending.Count} ready={_replyBytes} upload_wait={UploadWaitPhase}/" +
                       $"{(UploadWaitSince is null ? 0 : (UploadWaitSince.Value - now) * -1000):F0}ms " +
                       $"native_write_ms={(DeliveringSince is null ? 0 : (DeliveringSince.Value - now) * -1000):F0} " +
                       $"capacity_rotations={CapacityRotations} polls={current.Item8 - previous.polls} " +
                       $"first_poll_ms={pollGap * 1000:F0} probes=[{string.Join("; ", probes)}]");
        }
    }

    private (double, long, long, long, long, long, long, long) _flowSample;

    // -----------------------------------------------------------------------
    // failure / close
    // -----------------------------------------------------------------------

    /// <summary>Python <c>_fail</c>: mark dead, drain the queue, deliver the error to receive().</summary>
    private void Fail(Exception error)
    {
        lock (_gate)
        {
            if (_closed) return;
            if (error is MtprotoTransportError mte) TransportErrorCode = mte.Code;
            _closed = true;
            _recoveryWakeup.Set();
            while (_queue.TryDequeue(out _)) Interlocked.Decrement(ref _queueCount);
            _replyBytes = 0;
            EnqueueLocked(error);
        }
        _queueSignal.Set();
    }

    private void EnqueueLocked(object item)
    {
        _queue.Enqueue(item);
        Volatile.Write(ref _queueCount, Volatile.Read(ref _queueCount) + 1);
    }

    // -----------------------------------------------------------------------
    // send path (upload)
    // -----------------------------------------------------------------------

    /// <summary>Python <c>send(body, quick, replay=False)</c>.</summary>
    public async Task<bool> SendAsync(byte[] body, bool quick, bool replay = false,
                                      CancellationToken ct = default)
    {
        if (replay && _sendLock.CurrentCount == 0)
            return false;
        if (!replay)
        {
            lock (_gate)
            {
                UploadWaitSinceInternal(Now, "send-lock", body.Length);
            }
        }
        try
        {
            await _sendLock.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                return await SendInnerAsync(body, quick, replay).ConfigureAwait(false);
            }
            finally
            {
                _sendLock.Release();
                if (!replay)
                {
                    lock (_gate) UploadWaitSinceInternal(null, "-", 0);
                }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return false;
        }
    }

    private void UploadWaitSinceInternal(double? since, string phase, int bytes)
    {
        UploadWaitSince = since;
        UploadWaitPhase = phase;
        UploadWaitBytes = bytes;
    }

    private async Task<bool> SendInnerAsync(byte[] body, bool quick, bool replay)
    {
        // async with self.capacity:
        await _capacity.WaitAsync().ConfigureAwait(false);
        try
        {
            lock (_gate)
            {
                if (replay && !HasCapacityLocked(body.Length))
                    return false;
            }
            if (!replay)
            {
                SetPhase("channel-capacity", body.Length);
                await WaitChannelCapacityAsync(body.Length).ConfigureAwait(false);
            }
        }
        finally
        {
            _capacity.Release();
        }

        lock (_gate) if (_closed) throw new ConnectionError("H2 channel closed");

        if (!replay) SetPhase("lane-capacity", body.Length);
        if (!await Lane.ReserveAsync(body.Length, wait: !replay, CancellationToken.None)
                        .ConfigureAwait(false))
            return false;

        ReplayPacket? replayPacket = null;
        ReplayPacket? nativePacket = null;
        int sequence;
        RequestTrace? trace = null;

        // Launch the request task — asyncio.create_task(self._run_request(...)).
        var cts = CancellationTokenSource.CreateLinkedTokenSource(_lifetimeCts.Token);
        var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        lock (_gate)
        {
            if (_closed)
            {
                _ = Lane.ReleaseAsync(body.Length);
                throw new ConnectionError("H2 channel closed");
            }
            double now = Now;
            replayPacket = replay ? FindPacketLocked(body) : null;
            if (replay && (replayPacket is null || replayPacket.Pending is not null
                           || !ReplayDueLocked(replayPacket, now)))
            {
                _ = Lane.ReleaseAsync(body.Length);
                return false;
            }
            _pendingBytes += body.Length;
            Requests++;
            if (replay) ReplayRequests++;
            Up += body.Length;
            ProxyStats.Shared.AddBytesUp(body.Length);
            sequence = (int)Requests;
            if (!replay)
            {
                LastNativeSend = now;
                nativePacket = RememberPacketLocked(body, now);
            }
            if (quick) QuickRequests++;
            var packet = replayPacket ?? nativePacket;
            if (Log.IsEnabled(LogLevel.Debug))
                trace = new RequestTrace(packet?.Sequence ?? sequence, now, replay, body.Length);
            if (replay && replayPacket is not null)
            {
                if (!OverdueOriginal(replayPacket, now))
                {
                    PollRequests++;
                    if (!replayPacket.Replayed)
                        FirstPollGap = Math.Max(FirstPollGap, now - LastProgress);
                }
            }

            Request req = null!;
            req = new Request
            {
                Id = ++_taskSeq,                 // stable surrogate for asyncio.Task.Id
                Runner = () => RunRequestAsync(req, body, replay, packet, trace, tcs, cts.Token),
                Cts = cts,
                Length = body.Length,
                IsReplay = replay,
                Packet = packet,
                PendingSince = now,
                Trace = trace,
            };
            _pending[req.Id] = req;
            req.Start();                         // schedule immediately (create_task)

            if (nativePacket is not null)
            {
                nativePacket.Originals.Add(req.Id);
                TrimHistoryLocked(now);
            }
            if (replay && replayPacket is not null)
            {
                _replayPending.Add(req.Id);
                replayPacket.Attempts++;
                replayPacket.LastAttemptAt = now;
                replayPacket.Pending = req.Id;
            }
        }
        return true;
    }

    private long _taskSeq;

    private readonly CancellationTokenSource _lifetimeCts = new();

    private void SetPhase(string phase, int bytes)
    {
        lock (_gate)
        {
            UploadWaitSince ??= Now;
            UploadWaitPhase = phase;
            UploadWaitBytes = bytes;
        }
    }

    /// <summary>Python: wait_for(capacity.wait_for(closed or has_capacity), REQUEST_TIMEOUT).</summary>
    private async Task WaitChannelCapacityAsync(int length)
    {
        double deadline = Now + CfH2Consts.RequestTimeout;
        while (true)
        {
            lock (_gate)
            {
                if (_closed) return;              // predicate includes `self.closed`
                if (HasCapacityLocked(length)) return;
            }
            if (Now >= deadline)
                throw new TimeoutException("H2 channel capacity wait timed out");
            await Task.Delay(50).ConfigureAwait(false);
        }
    }

    /// <summary>Python <c>_find_packet</c> (under gate).</summary>
    private ReplayPacket? FindPacketLocked(byte[] body) =>
        _replayHistory.FirstOrDefault(e => e.Body.AsSpan().SequenceEqual(body));

    /// <summary>Python <c>_remember_packet</c> (under gate).</summary>
    private ReplayPacket? RememberPacketLocked(byte[] body, double now)
    {
        byte[] key = body[..Math.Min(8, body.Length)];
        if (key.SequenceEqual(new byte[8])) return null;
        if (_replayKey is null || !_replayKey.SequenceEqual(key))
        {
            _replayHistory.Clear();
            _replayKey = key;
        }
        if (body.Length > CfH2Consts.ReplayHistoryBytes) return null;
        var packet = FindPacketLocked(body);
        if (packet is null)
        {
            packet = new ReplayPacket
            {
                SentAt = now,
                Body = body,
                Sequence = (int)Requests,
            };
            _replayHistory.Add(packet);
        }
        return packet;
    }

    /// <summary>Python <c>_trim_history</c> (under gate).</summary>
    private void TrimHistoryLocked(double now)
    {
        long retainedBytes = _replayHistory.Sum(e => (long)e.Body.Length);
        while (_replayHistory.Count > CfH2Consts.ReplayHistoryPackets ||
               retainedBytes > CfH2Consts.ReplayHistoryBytes)
        {
            var victim = _replayHistory.FirstOrDefault(e =>
                             e.Originals.Count == 0 &&
                             !(e.Retired && e.Attempts < CfH2Consts.ReplayMaxAttempts &&
                               now - e.SentAt <= CfH2Consts.ReplayMaxAge))
                         ?? _replayHistory[0];
            _replayHistory.Remove(victim);
            retainedBytes -= victim.Body.Length;
        }
    }

    // -----------------------------------------------------------------------
    // request lifecycle
    // -----------------------------------------------------------------------

    private async Task RunRequestAsync(Request req, byte[] body, bool replay,
                                       ReplayPacket? packet, RequestTrace? trace,
                                       TaskCompletionSource tcs, CancellationToken ct)
    {
        try
        {
            byte[] reply = await Lane.PostAsync(body, this, replay, trace, ct)
                                   .ConfigureAwait(false);
            lock (_gate) LastProgress = Now;
            if (reply.Length != 0)
            {
                lock (_gate)
                {
                    if (!_closed)
                    {
                        byte[] replyId = reply[..Math.Min(CfH2Consts.ReplyIdPrefixLen, reply.Length)];
                        if (packet is not null && !ReplayPacket.SameReplyId(packet.ReplyId, replyId))
                        {
                            packet.ReplyId = replyId;
                            packet.Attempts = 0;
                        }
                        if (Volatile.Read(ref _queueCount) >= 16 ||
                            _replyBytes + reply.Length > CfH2Consts.MaxChannelBytes)
                        {
                            tcs.SetException(
                                new InvalidOperationException(
                                    "H2 client response queue exceeded bound")); // BufferError
                            FinishRequest(req);
                            return;
                        }
                        _replyBytes += reply.Length;
                        EnqueueLocked(reply);
                    }
                    if (trace is not null) trace.Phase = "complete";
                }
            }
            tcs.SetResult();
        }
        catch (OperationCanceledException)
        {
            if (trace is not null) lock (_gate) trace.Phase = "cancelled-" + trace.Phase;
            tcs.TrySetCanceled();
        }
        catch (MtprotoTransportError exc)
        {
            if (trace is not null) lock (_gate) trace.Phase = "transport-error";
            ProxyStats.Shared.AddH2Error();
            if (!Closed)
                Log.LogWarning(
                    "[{Label}] H2 lane={Lane} channel={Channel} host={Host} MTProto transport " +
                    "error={Error} request={Request} encrypted={Encrypted} bytes={Bytes} replay={Replay}; " +
                    "reporting to client",
                    Label, Lane.LaneId, ChannelId, Lane.Host, exc.Message,
                    trace?.Request ?? 0,
                    !body[..Math.Min(8, body.Length)].SequenceEqual(new byte[8]) ? 1 : 0,
                    body.Length, replay ? 1 : 0);
            Fail(exc);
            tcs.SetException(exc);
        }
        catch (Exception exc)
        {
            if (trace is not null) lock (_gate) trace.Phase = "error-" + exc.GetType().Name;
            ProxyStats.Shared.AddH2Error();
            if (exc is HttpRequestException or IOException or ArgumentException
                       or InvalidOperationException or TimeoutException)
            {
                Log.LogWarning(
                    "[{Label}] H2 lane={Lane} channel={Channel} request failed: {Type}: {Error}; " +
                    "detail=[{Detail}]; closing native channel, reconnect may select another domain",
                    Label, Lane.LaneId, ChannelId, exc.GetType().Name, exc.Message,
                    trace?.Summary(Now) ?? "-");
            }
            else
            {
                Log.LogError(exc, "[{Label}] H2 lane={Lane} channel={Channel} unexpected request failure",
                             Label, Lane.LaneId, ChannelId);
            }
            Fail(exc);
            tcs.SetException(exc);
        }
        finally
        {
            FinishRequest(req);
        }
    }

    /// <summary>Python <c>_finish_request</c>.</summary>
    private void FinishRequest(Request req)
    {
        ReplayPacket? packet = req.Packet;
        lock (_gate)
        {
            if (!_pending.Remove(req.Id, out var removed))
            {
                req.Completed = true;
                return;
            }
            req.Completed = true;
            int length = req.Length;
            if (req.Trace is { } trace)
            {
                trace.FinishedAt = Now;
                _recentTraces.AddLast(trace);
                while (_recentTraces.Count > RecentTracesMax) _recentTraces.RemoveFirst();
            }
            _pendingBytes -= length;
            _replayPending.Remove(req.Id);
            if (packet is null)
                packet = _replayHistory.FirstOrDefault(e =>
                    e.Originals.Contains(req.Id) || e.Pending == req.Id);
            if (packet is not null)
            {
                packet.Originals.Remove(req.Id);
                if (packet.Pending == req.Id) packet.Pending = null;
            }
        }
        _ = Lane.ReleaseAsync(req.Length);
        // async with self.capacity: notify_all() — waking capacity waiters happens via polling;
        // we still serialise through the semaphore so waiters re-check promptly.
        _ = NotifyCapacityAsync();
        WakeReceiver();
        _queueSignal.Set();
    }

    private async Task NotifyCapacityAsync()
    {
        await _capacity.WaitAsync().ConfigureAwait(false);
        _capacity.Release();
    }

    private Task AwaitRequestAsync(long id)
    {
        Request? req;
        lock (_gate) _pending.TryGetValue(id, out req);
        return req is null ? Task.CompletedTask : req.Task;
    }

    // -----------------------------------------------------------------------
    // receive path (download) — the reply queue
    // -----------------------------------------------------------------------

    /// <summary>Python <c>receive()</c>: pops the next reply, raising queued exceptions.</summary>
    public async Task<byte[]> ReceiveAsync(CancellationToken ct)
    {
        while (true)
        {
            if (_queue.TryDequeue(out var item))
            {
                Interlocked.Decrement(ref _queueCount);
                if (item is Exception error) throw error;
                byte[] reply = (byte[])item;
                lock (_gate)
                {
                    _replyBytes -= reply.Length;
                }
                WakeReceiver();
                return reply;
            }
            await _queueSignal.WaitAsync(TimeSpan.FromMilliseconds(50), ct).ConfigureAwait(false);
        }
    }

    // -----------------------------------------------------------------------
    // recovery loop
    // -----------------------------------------------------------------------

    /// <summary>Python <c>_recover</c>: periodic diagnostics + replay scheduling.</summary>
    public async Task RecoverAsync(CancellationToken ct)
    {
        try
        {
            while (!Closed)
            {
                await Task.WhenAny(
                    _recoveryWakeup.WaitAsync(ct),
                    Task.Delay(TimeSpan.FromSeconds(CfH2Consts.ReplayCheckSeconds), CancellationToken.None)
                ).ConfigureAwait(false);
                _recoveryWakeup.Reset();

                double now = Now;
                Lane.LogWait(now);
                await MakeUploadRoomAsync(now).ConfigureAwait(false);
                if (Closed || NativeBackpressure) continue;

                // priority: (not overdue, entry.sequence if overdue else -entry.sequence)
                var candidates = _snapshotHistory()
                    .OrderByDescending(e => OverdueInSnapshot(e, now))
                    .ThenBy(e => OverdueInSnapshot(e, now) ? e.Sequence : -e.Sequence)
                    .ToList();

                bool sent = false;
                foreach (var entry in candidates)
                {
                    long? replaceId;
                    lock (_gate)
                    {
                        if (!ReplayDueLocked(entry, now)) continue;
                        replaceId = entry.Pending;
                        if (replaceId is null && _replayPending.Count >= CfH2Consts.MaxChannelReplays)
                        {
                            replaceId = _pending.Values
                                .FirstOrDefault(t => t.IsReplay && !t.Receiving && !t.Completed)?.Id;
                            if (replaceId is null) continue;
                        }
                        if (replaceId is { } rid)
                        {
                            var replace = _pending.GetValueOrDefault(rid);
                            double? sentAt = replace?.SentSince;
                            if (replace is { Receiving: true } || sentAt is null
                                || now - sentAt.Value < CfH2Consts.ReplaySlotSeconds)
                                continue;
                            replace!.Cts.Cancel();
                            ReplayRotations++;
                        }
                    }

                    if (replaceId is { } cancelId)
                    {
                        try { await AwaitRequestAsync(cancelId).ConfigureAwait(false); }
                        catch { /* return_exceptions=True */ }
                    }

                    bool ok = await SendAsync(entry.Body, quick: false, replay: true, ct)
                                  .ConfigureAwait(false);
                    sent = ok;
                    break; // Python breaks after the first attempted send
                }
                _ = sent;
            }
        }
        catch (OperationCanceledException) { /* graceful shutdown */ }
    }

    private List<ReplayPacket> _snapshotHistory()
    {
        lock (_gate) return _replayHistory.ToList();
    }

    private bool OverdueInSnapshot(ReplayPacket entry, double now)
    {
        lock (_gate) return OverdueOriginal(entry, now);
    }

    // -----------------------------------------------------------------------
    // close
    // -----------------------------------------------------------------------

    /// <summary>Python <c>close()</c>.</summary>
    public async ValueTask CloseAsync()
    {
        await _closeLock.WaitAsync().ConfigureAwait(false);
        try
        {
            if (CloseDone) return;
            string waiting = WaitState(Now);
            if (Log.IsEnabled(LogLevel.Debug))
            {
                List<RequestTrace> traces;
                lock (_gate)
                    traces = _pending.Values
                        .Where(t => t.Trace is not null)
                        .Select(t => t.Trace!)
                        .OrderBy(t => t.Started)
                        .Take(3)
                        .ToList();
                if (traces.Count > 0)
                {
                    double now = Now;
                    Log.LogDebug("H2 DETAIL CLOSE lane={Lane} [{Details}]", Lane.LaneId,
                                 string.Join("; ", traces.Select(t => RequestDetail(t, now))));
                }
            }

            var closeError = new ConnectionError("H2 channel closed");
            lock (_gate)
            {
                _closed = false;               // _fail early-returns when already closed
                Fail(closeError);
                _closed = true;
            }

            List<Request> tasks;
            lock (_gate) tasks = _pending.Values.ToList();
            foreach (var req in tasks) req.Cts.Cancel();
            foreach (var req in tasks)
            {
                try { await req.Task.ConfigureAwait(false); }
                catch { /* return_exceptions=True */ }
            }
            lock (_gate)
            {
                foreach (var req in _pending.Values.ToList())
                    req.Completed = true;
                // Python drains leftovers through _finish_request; our tasks' finally
                // blocks already did that. Clear residual bookkeeping defensively:
                foreach (var req in _pending.Values.ToList())
                    _pendingBytes -= req.Length;
                _pending.Clear();
                _replayPending.Clear();
                _replayHistory.Clear();
                while (_recentTraces.Count > 0) _recentTraces.RemoveFirst();
            }
            _lifetimeCts.Cancel();
            Lane.Channels.TryRemove(this, out _);
            CloseDone = true;
            Log.LogDebug(
                "[{Label}] H2 channel={Channel} closed lane={Lane} requests={Requests} " +
                "replays={Replays} rotations={Rotations} capacity_rotations={CapRot} up={Up} down={Down} " +
                "quickack={Quick} duration={Duration:F1}s remaining_channels={Remaining}; {Waiting}",
                Label, ChannelId, Lane.LaneId, Requests, ReplayRequests, ReplayRotations,
                CapacityRotations, Up, Down, QuickRequests, Now - Started,
                Lane.Channels.Count, waiting);
        }
        finally
        {
            _closeLock.Release();
            _lifetimeCts.Dispose();
        }
    }

    /// <summary>True when the channel was closed/failed (Python <c>self.closed</c> read).</summary>
    public bool Closed { get { lock (_gate) return _closed; } }

    /// <summary>Python <c>self.delivering_since</c> setter used by the bridge around native writes.</summary>
    internal void SetDelivering(double? at)
    {
        lock (_gate) _deliveringSinceTicks = at is null ? null : (int)(at.Value * 1000);
    }

    internal void AddDown(long bytes) { lock (_gate) Down += bytes; }

    /// <summary>Python <c>channel.pending_since</c> snapshot for lane diagnostics.</summary>
    public IReadOnlyList<(long Id, double Age, bool IsReplay, bool IsReceiving)> PendingAges(double now)
    {
        lock (_gate)
            return _pending.Values
                .Select(t => (t.Id, now - t.PendingSince, t.IsReplay, t.Receiving))
                .ToList();
    }

    /// <summary>Python <c>channel.request_traces.values()</c> snapshot for lane diagnostics.</summary>
    public IReadOnlyList<RequestTrace> OpenTraces(double now)
    {
        lock (_gate)
            return _pending.Values
                .Where(t => t.Trace is not null)
                .Select(t => t.Trace!)
                .ToList();
    }

    public ValueTask DisposeAsync() => CloseAsync();
}
