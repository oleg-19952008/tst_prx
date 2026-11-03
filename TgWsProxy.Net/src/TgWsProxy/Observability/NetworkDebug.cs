using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace TgWsProxy.Observability;

/// <summary>
/// C# port of Python <c>proxy/network_debug.py::WsActivity</c> — per-WebSocket
/// flow telemetry (byte deltas, first-reply latency, worst rx gap / write times).
/// Python kept a class-level <c>active</c> set mutated from the single-threaded
/// asyncio loop; here the registry lives on <see cref="NetworkDebug"/> as a
/// thread-safe concurrent set. Instances are created through
/// <see cref="NetworkDebug.Track"/> only while debug output is enabled
/// (Python: <c>WsActivity(...) if log.isEnabledFor(logging.DEBUG) else None</c>).
/// </summary>
public sealed class WsActivity
{
    // Stopwatch.GetTimestamp()-based monotonic clock — the .NET analogue of
    // time.monotonic(). Zero means "not set" (Python: None).
    internal static readonly double s_ticksPerMs = 1000.0 / System.Diagnostics.Stopwatch.Frequency;

    internal static long NowTicks() => System.Diagnostics.Stopwatch.GetTimestamp();

    internal static double ToMs(long deltaTicks) => deltaTicks * s_ticksPerMs;

    private readonly NetworkDebug _owner;

    public string Label { get; }
    public string Dc { get; }

    public long NativeUp;
    public long WsUp;
    public long WsDown;
    public long NativeDown;

    private long _firstInput;      // 0 == Python None
    private long _firstReply;      // now - first_input at the moment of first reply
    private long _lastRx;
    private long _awaitingRx;      // 0 == None
    private long _sending;         // 0 == None
    private long _writingNative;   // 0 == None

    public double MaxRxDelayMs;
    public double MaxSendMs;
    public double MaxNativeWriteMs;

    // Sample tuple (now, native_up, ws_up, ws_down, native_down) for delta
    // lines — mirrors self.sample in Python.
    private long _sampleStamp;
    private long _sampleNativeUp;
    private long _sampleWsUp;
    private long _sampleWsDown;
    private long _sampleNativeDown;

    internal WsActivity(NetworkDebug owner, string label, string dc)
    {
        _owner = owner;
        Label = label;
        Dc = dc;
        _sampleStamp = NowTicks();
        _owner.Register(this);
        // NOTE: Debug() takes a pre-formatted message (not a structured template)
        // because callers build invariant-culture %.0f strings by hand.
        _owner.Debug($"[{label}] WS OPEN {dc}");
    }

    /// <summary>Python <c>input(length)</c> — bytes read from the local client.</summary>
    public void Input(int length)
    {
        NativeUp += length;
        if (_firstInput == 0)
            _firstInput = NowTicks();
    }

    /// <summary>Python <c>send_started()</c>.</summary>
    public void SendStarted() => _sending = NowTicks();

    /// <summary>Python <c>sent(length)</c> — bytes handed to the WebSocket.</summary>
    public void Sent(int length)
    {
        var now = NowTicks();
        WsUp += length;
        if (_sending != 0)
        {
            MaxSendMs = Math.Max(MaxSendMs, ToMs(now - _sending));
            if (_awaitingRx == 0 && (_lastRx == 0 || _lastRx < _sending))
                _awaitingRx = _sending;
        }
        _sending = 0;
    }

    /// <summary>Python <c>received(length)</c> — bytes read off the WebSocket.</summary>
    public void Received(int length)
    {
        var now = NowTicks();
        WsDown += length;
        _lastRx = now;
        if (_awaitingRx != 0)
            MaxRxDelayMs = Math.Max(MaxRxDelayMs, ToMs(now - _awaitingRx));
        if (_firstReply == 0 && _firstInput != 0)
            _firstReply = now - _firstInput;
        _awaitingRx = 0;
        _writingNative = now;
    }

    /// <summary>Python <c>delivered(length)</c> — bytes flushed to the local client.</summary>
    public void Delivered(int length)
    {
        NativeDown += length;
        if (_writingNative != 0)
            MaxNativeWriteMs = Math.Max(MaxNativeWriteMs, ToMs(NowTicks() - _writingNative));
        _writingNative = 0;
    }

    /// <summary>
    /// Python <c>summary(now)</c>: per-window byte deltas plus current in-flight
    /// timings; identical formatting ("%.0f", -1/0 sentinels), culture-invariant.
    /// </summary>
    public string Summary(long now)
    {
        var previous = (_sampleStamp, _sampleNativeUp, _sampleWsUp, _sampleWsDown, _sampleNativeDown);
        _sampleStamp = now;
        _sampleNativeUp = NativeUp;
        _sampleWsUp = WsUp;
        _sampleWsDown = WsDown;
        _sampleNativeDown = NativeDown;

        // Local of static type string — see the NetworkDebug.Debug comment:
        // FormattableString arguments bind to ILogger's generic Log<T0,T1>
        // extension overloads instead of our plain-string helper (CS1503).
        string text = FormattableString.Invariant(
            $"client={Label}" +
            $" window_ms={ToMs(now - previous.Item1):F0}" +
            $" native_up={NativeUp - previous.Item2}" +
            $" ws_up={WsUp - previous.Item3}" +
            $" ws_down={WsDown - previous.Item4}" +
            $" native_down={NativeDown - previous.Item5}" +
            $" rx_gap_ms={(_awaitingRx == 0 ? 0 : ToMs(now - _awaitingRx)):F0}" +
            $" last_rx_ms={(_lastRx == 0 ? -1 : ToMs(now - _lastRx)):F0}" +
            $" ws_write_ms={(_sending == 0 ? 0 : ToMs(now - _sending)):F0}" +
            $" native_write_ms={(_writingNative == 0 ? 0 : ToMs(now - _writingNative)):F0}");
        return text;
    }

    /// <summary>Python <c>close()</c> — deregister and log the final line.</summary>
    public void Close()
    {
        var now = NowTicks();
        _owner.Unregister(this);
        string text = FormattableString.Invariant(
            $"WS END {Dc} {Summary(now)} first_reply_ms={(_firstReply == 0 ? -1 : ToMs(_firstReply)):F0} " +
            $"max_rx_gap_ms={MaxRxDelayMs:F0} max_ws_write_ms={MaxSendMs:F0} " +
            $"max_native_write_ms={MaxNativeWriteMs:F0}");
        _owner.Debug(text);
    }
}

/// <summary>
/// C# port of <c>proxy/network_debug.py</c> (<see cref="WsActivity"/> registry +
/// <c>log_ws_flow</c>) combined with the periodic reporter task from
/// <c>tg_ws_proxy.py::log_stats</c>. The console output replaces the GUI
/// dashboard windows (PORT_PLAN.md §3 phase C item 8): every <b>5 s</b>
/// (flow cadence, Python <c>asyncio.sleep(5)</c>) grouped "WS FLOW" debug lines
/// are emitted while Debug logging is on (Python <c>isEnabledFor(DEBUG)</c>
/// gate), and every <b>60 s</b> an INFO line <c>stats: &lt;summary&gt;</c> is
/// printed — both intervals match the Python source.
/// </summary>
public sealed class NetworkDebug : IDisposable
{
    /// <summary>Python tg_ws_proxy.py: <c>await asyncio.sleep(5)</c> loop cadence.</summary>
    public static readonly TimeSpan DefaultFlowInterval = TimeSpan.FromSeconds(5);

    /// <summary>Python: <c>next_stats = now + 60</c>.</summary>
    public static readonly TimeSpan DefaultStatsInterval = TimeSpan.FromSeconds(60);

    private readonly ILogger _logger;
    private readonly ProxyStats _stats;
    private readonly ConcurrentDictionary<WsActivity, byte> _active = new();
    private Timer? _timer;
    private long _flowIntervalTicks;
    private long _statsIntervalTicks;
    private long _nextFlowTicks;
    private long _nextStatsTicks;

    /// <summary>True when Debug output is enabled (Python isEnabledFor(DEBUG)).</summary>
    public bool Enabled => _logger.IsEnabled(LogLevel.Debug);

    public NetworkDebug(ILogger<NetworkDebug> logger, ProxyStats stats)
    {
        _logger = logger;
        _stats = stats;
    }

    /// <summary>
    /// Create and register an activity (Python <c>WsActivity(label, dc)</c>).
    /// Returns <see langword="null"/> when debug output is off — callers keep the
    /// same zero-overhead path as the Python bridge.
    /// </summary>
    public WsActivity? Track(string label, string dc) =>
        Enabled ? new WsActivity(this, label, dc) : null;

    internal void Register(WsActivity activity) => _active.TryAdd(activity, 0);
    internal void Unregister(WsActivity activity) => _active.TryRemove(activity, out _);

    // NOTE: these helpers are NOT named Log/Log2 — ILogger already has generic
    // Log<T0,T1>(LogLevel, string, T0, T1) extension overloads that the compiler
    // prefers over a plain (LogLevel, string) instance method when the second
    // argument is an interpolated FormattableString (CS1503 otherwise).
    // InterpolatedStringHandler overloads also bind before a cast to string, so
    // every call site must pass a local of static type string.
    internal void Debug(string message) => _logger.LogDebug("{Message}", message);
    internal void Info(string message) => _logger.LogInformation("{Message}", message);

    /// <summary>
    /// Start the periodic console reporter (replaces the asyncio
    /// <c>log_stats()</c> task). Call once at host start.
    /// </summary>
    public void StartReporting(
        TimeSpan? flowInterval = null,
        TimeSpan? statsInterval = null)
    {
        StopReporting();
        var flow = flowInterval ?? DefaultFlowInterval;
        var statsPeriod = statsInterval ?? DefaultStatsInterval;
        _flowIntervalTicks = ToTicks(flow);
        _statsIntervalTicks = ToTicks(statsPeriod);
        var now = WsActivity.NowTicks();
        _nextFlowTicks = now + _flowIntervalTicks;
        _nextStatsTicks = now + _statsIntervalTicks;
        _timer = new Timer(static state => ((NetworkDebug)state!).Tick(),
                           this, flow, flow);
    }

    public void StopReporting()
    {
        _timer?.Dispose();
        _timer = null;
    }

    private void Tick()
    {
        try
        {
            var now = WsActivity.NowTicks();

            if (now >= _nextFlowTicks)
            {
                _nextFlowTicks = now + _flowIntervalTicks;
                LogWsFlow(now);
            }

            if (now >= _nextStatsTicks)
            {
                _nextStatsTicks = now + _statsIntervalTicks;
                // Python: log.info("stats: %s", stats.summary())
                _logger.LogInformation("stats: {Summary}", _stats.Summary());
            }
        }
        catch (Exception ex)
        {
            // A reporting failure must never take the proxy down.
            _logger.LogDebug(ex, "stats reporter failed");
        }
    }

    /// <summary>
    /// Python <c>log_ws_flow(now)</c>: bail out unless Debug is enabled, group
    /// active WS sessions by DC (sorted), sort each group by label and join up
    /// to 8 summaries per line.
    /// </summary>
    public void LogWsFlow(long now)
    {
        if (!Enabled)
            return; // log.isEnabledFor(logging.DEBUG)

        var groups = new SortedDictionary<string, List<WsActivity>>(StringComparer.Ordinal);
        foreach (var activity in _active.Keys)
        {
            if (!groups.TryGetValue(activity.Dc, out var list))
                groups[activity.Dc] = list = [];
            list.Add(activity);
        }

        foreach (var (dc, activities) in groups)
        {
            activities.Sort(static (a, b) => string.CompareOrdinal(a.Label, b.Label));
            for (var offset = 0; offset < activities.Count; offset += 8)
            {
                var chunk = new System.Text.StringBuilder();
                for (var i = offset; i < Math.Min(offset + 8, activities.Count); i++)
                {
                    if (i > offset)
                        chunk.Append("; ");
                    chunk.Append(activities[i].Summary(now));
                }
                _logger.LogDebug("WS FLOW {Dc} [{Activities}]", dc, chunk.ToString());
            }
        }
    }

    private static long ToTicks(TimeSpan interval) =>
        (long)(interval.TotalMilliseconds / WsActivity.s_ticksPerMs);

    public void Dispose() => StopReporting();
}
