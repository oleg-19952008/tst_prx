using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using TgWsProxy.Configuration;
using TgWsProxy.Observability;
using System.Diagnostics;
using TgWsProxy.Transport;

namespace TgWsProxy.Core;

/// <summary>Pool bucket key: (dc, is_media, is_test_dc) — Python <c>_WsPool</c>.</summary>
public readonly record struct PoolKey(int Dc, bool IsMedia, bool IsTestDc)
{
    public override string ToString() =>
        $"DC{Dc}{(IsTestDc ? "t" : "")}{(IsMedia ? "m" : "")}";
}

/// <summary>
/// WS connection pool to Telegram DCs — port of Python <c>proxy/pool.py::_WsPool</c>.
/// Idle connections are kept per (dc, media, test) bucket, health-checked, rotated
/// on max-age and refilled in the background with exponential backoff.
/// </summary>
public sealed class ConnectionPool : IAsyncDisposable
{
    // Constants identical to Python _WsPool
    public const double WsPoolMaxAgeSec = 120.0;
    public const double WsPoolCheckIntervalSec = 5.0;
    public const double RefillBackoffInitialSec = 1.0;
    public const double RefillBackoffMaxSec = 3600.0;

    private readonly ProxyConfig _config;
    private readonly ILogger<ConnectionPool> _log;
    private readonly CancellationTokenSource _shutdown = new();

    private readonly ConcurrentDictionary<PoolKey, ConcurrentQueue<PooledWs>> _idle = new();
    private readonly ConcurrentDictionary<PoolKey, Task> _refilling = new();
    private readonly ConcurrentDictionary<PoolKey, Task> _rotating = new();
    private readonly ConcurrentDictionary<PoolKey, int> _refillFailures = new();
    private readonly ConcurrentDictionary<PoolKey, double> _refillAfter = new();

    private volatile bool _tryFrontingFirst;
    internal bool TryFrontingFirst { get => _tryFrontingFirst; set => _tryFrontingFirst = value; }

    /// <summary>Monotonic seconds — Python time.monotonic analogue.</summary>
    internal static double Now => StopwatchMono.Now;

    internal sealed record PooledWs(RawWebSocket Ws, double Created);

    public ConnectionPool(IOptions<ProxyConfig> config, ILogger<ConnectionPool> log)
    {
        _config = config.Value;
        _log = log;
    }

    /// <summary>Python <c>_WsPool.get</c>: pop a fresh idle WS or schedule refill and return null.</summary>
    public Task<RawWebSocket?> GetAsync(int dc, bool isMedia, bool isTestDc = false)
    {
        var targetIp = _config.ParsedDcRedirects.GetValueOrDefault(dc);
        if (string.IsNullOrEmpty(targetIp) || _config.PoolSize <= 0)
            return Task.FromResult<RawWebSocket?>(null);

        var key = new PoolKey(dc, isMedia, isTestDc);
        var domains = ProtocolConsts.WsDomains(dc, isMedia);
        double now = Now;

        var bucket = _idle.GetOrAdd(key, _ => new ConcurrentQueue<PooledWs>());
        while (bucket.TryDequeue(out var pooled))
        {
            double age = now - pooled.Created;
            if (IsStale(pooled.Ws, pooled.Created, now))
            {
                QuietClose(pooled.Ws);
                continue;
            }
            ProxyStats.Shared.AddPoolHit();
            _log.LogDebug("WS pool hit {Key} (age={Age:F1}s, left={Left})", key, age, bucket.Count);
            ScheduleRefill(key, targetIp, domains);
            return Task.FromResult<RawWebSocket?>(pooled.Ws);
        }

        ProxyStats.Shared.AddPoolMiss();
        ScheduleRefill(key, targetIp, domains);
        return Task.FromResult<RawWebSocket?>(null);
    }

    internal static bool IsStale(RawWebSocket ws, double created, double now) =>
        now - created >= WsPoolMaxAgeSec || ws.Closed;

    private void ScheduleRefill(PoolKey key, string targetIp, IReadOnlyList<string> domains)
    {
        if (_config.PoolSize <= 0) return;
        ScheduleRotation(key, targetIp, domains);

        if (Now < _refillAfter.GetValueOrDefault(key, double.MinValue))
            return;

        // Start a refill only when no other refill task is registered for this key.
        var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var registered = _refilling.GetOrAdd(key, tcs.Task);
        if (!ReferenceEquals(registered, tcs.Task))
        {
            // Slot held by a stale (already completed) task → replace it once.
            if (registered.IsCompleted &&
                _refilling.TryRemove(new KeyValuePair<PoolKey, Task>(key, registered)))
            {
                var tcs2 = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                if (_refilling.TryAdd(key, tcs2.Task))
                    RunRefill(key, targetIp, domains, tcs2);
            }
            return;
        }
        RunRefill(key, targetIp, domains, tcs);
    }

    private void RunRefill(PoolKey key, string targetIp, IReadOnlyList<string> domains,
                           TaskCompletionSource tcs)
    {
        _ = Task.Run(async () =>
        {
            try
            {
                await RefillAsync(key, targetIp, domains).ConfigureAwait(false);
                tcs.TrySetResult();
            }
            catch (Exception exc)
            {
                tcs.TrySetException(exc);
            }
            finally
            {
                _refilling.TryRemove(new KeyValuePair<PoolKey, Task>(key, tcs.Task));
            }
        });
    }

    private async Task RefillAsync(PoolKey key, string targetIp, IReadOnlyList<string> domains)
    {
        var bucket = _idle.GetOrAdd(key, _ => new ConcurrentQueue<PooledWs>());
        int needed = _config.PoolSize - bucket.Count;
        if (needed <= 0) return;

        int connected = 0;
        var connectTasks = Enumerable.Range(0, needed)
            .Select(_ => ConnectOneAsync(targetIp, domains,
                    key.IsTestDc ? ProtocolConsts.WsPathTest : ProtocolConsts.WsPath))
            .ToList();

        // asyncio.as_completed analogue: consume results as they finish; pending
        // connects abort through the shutdown token on Reset().
        while (connectTasks.Count > 0)
        {
            var finished = await Task.WhenAny(connectTasks).ConfigureAwait(false);
            connectTasks.Remove(finished);
            RawWebSocket? ws = null;
            try { ws = await finished.ConfigureAwait(false); }
            catch (Exception exc)
            {
                _log.LogDebug("WS pool connect failed: {Exc}", exc.Message);
            }
            if (ws is not null)
            {
                bucket.Enqueue(new PooledWs(ws, Now));
                connected++;
            }
        }

        if (connected > 0)
        {
            _refillFailures.TryRemove(key, out _);
            _refillAfter.TryRemove(key, out _);
        }
        else
        {
            int failures = _refillFailures.AddOrUpdate(key, 1, (_, v) => v + 1);
            double delay = Math.Min(
                RefillBackoffInitialSec * Math.Pow(2, Math.Min(failures - 1, 12)),
                RefillBackoffMaxSec);
            _refillAfter[key] = Now + delay;
            _log.LogInformation("WS pool refill failed for {Key}, retry in {Delay:F0}s", key, delay);
        }
        _log.LogDebug("WS pool refilled {Key}: {Count} ready", key, bucket.Count);
    }

    private void ScheduleRotation(PoolKey key, string targetIp, IReadOnlyList<string> domains)
    {
        var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!_rotating.TryAdd(key, tcs.Task)) return;
        _ = Task.Run(async () =>
        {
            try { await RotateAsync(key, targetIp, domains).ConfigureAwait(false); }
            finally
            {
                _rotating.TryRemove(new KeyValuePair<PoolKey, Task>(key, tcs.Task));
                tcs.TrySetResult();
            }
        });
    }

    private async Task RotateAsync(PoolKey key, string targetIp, IReadOnlyList<string> domains)
    {
        while (_config.PoolSize > 0 && !_shutdown.IsCancellationRequested)
        {
            var bucket = _idle.GetOrAdd(key, _ => new ConcurrentQueue<PooledWs>());
            double now = Now;
            int expired = 0;
            var keep = new List<PooledWs>(bucket.Count);
            while (bucket.TryDequeue(out var pooled))
            {
                if (IsStale(pooled.Ws, pooled.Created, now))
                {
                    QuietClose(pooled.Ws);
                    expired++;
                }
                else keep.Add(pooled);
            }
            foreach (var p in keep) bucket.Enqueue(p);

            if (expired > 0)
                _log.LogDebug("WS pool rotated {Key}: {Expired} stale, {Ready} ready",
                    key, expired, bucket.Count);

            if (bucket.Count < _config.PoolSize)
                ScheduleRefill(key, targetIp, domains);

            double wakeAt = now + WsPoolCheckIntervalSec;
            if (keep.Count > 0)
                wakeAt = Math.Min(wakeAt, keep.Min(p => p.Created) + WsPoolMaxAgeSec);
            if (!_refilling.ContainsKey(key))
            {
                double after = _refillAfter.GetValueOrDefault(key, double.MaxValue);
                if (after > now) wakeAt = Math.Min(wakeAt, after);
            }
            double sleep = Math.Max(0, wakeAt - Now);
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(sleep), _shutdown.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { break; }
        }
    }

    /// <summary>Python <c>_connect_one</c>: try each domain, fronted/plain modes, remember what worked.</summary>
    internal async Task<RawWebSocket?> ConnectOneAsync(string targetIp,
        IReadOnlyList<string> domains, string path = ProtocolConsts.WsPath)
    {
        foreach (var domain in domains)
        {
            bool[] modes = TryFrontingFirst ? new[] { true, false } : new[] { false, true };
            foreach (bool fronted in modes)
            {
                RawWebSocket? ws = null;
                try
                {
                    ws = await RawWebSocket.ConnectAsync(
                        targetIp, domain,
                        timeout: TimeSpan.FromSeconds(fronted ? 7 : 8),
                        path: path,
                        sni: fronted ? "sprinthost.ru" : null,
                        secure: true,
                        config: _config,
                        ct: _shutdown.Token).ConfigureAwait(false);
                }
                catch (Exception exc)
                {
                    ProxyStats.Shared.AddWsError();
                    _log.LogDebug("WS pool connect {Domain}{Path} via {Ip} (fronting={Fronted}): {Exc}",
                        domain, path, targetIp, fronted, exc.GetType().Name + ": " + exc.Message);
                    continue;
                }
                TryFrontingFirst = fronted;
                if (fronted) ProxyStats.Shared.AddConnectionFronting();
                _log.LogDebug("WS pool connected {Domain}{Path} via {Ip} (fronting={Fronted})",
                    domain, path, targetIp, fronted);
                return ws;
            }
        }
        return null;
    }

    private void QuietClose(RawWebSocket ws) => _ = ws.CloseAsync().ContinueWith(
        static t => { _ = t.Exception; }, TaskScheduler.Default);

    /// <summary>Python <c>warmup</c>: kick off refills for every configured DC.</summary>
    public Task WarmupAsync()
    {
        foreach (var (dc, targetIp) in _config.ParsedDcRedirects)
        {
            foreach (bool isMedia in new[] { false, true })
            {
                var domains = ProtocolConsts.WsDomains(dc, isMedia);
                var key = new PoolKey(dc, isMedia, _config.ForceTestDc);
                ScheduleRefill(key, targetIp, domains);
            }
        }
        _log.LogInformation("WS pool warmup started for {Count} DC(s)", _config.ParsedDcRedirects.Count);
        return Task.CompletedTask;
    }

    /// <summary>Python <c>reset</c>: stop workers, close idles, clear state.</summary>
    public void Reset()
    {
        _shutdown.Cancel();
        foreach (var bucket in _idle.Values)
            while (bucket.TryDequeue(out var pooled))
            {
                try { pooled.Ws.CloseAsync().GetAwaiter().GetResult(); } catch { }
            }
        _idle.Clear();
        _refilling.Clear();
        _rotating.Clear();
        _refillFailures.Clear();
        _refillAfter.Clear();
        TryFrontingFirst = false;
    }

    public ValueTask DisposeAsync()
    {
        Reset();
        return ValueTask.CompletedTask;
    }
}

/// <summary>time.monotonic()-equivalent clock.</summary>
internal static class StopwatchMono
{
    private static readonly Stopwatch Watch = Stopwatch.StartNew();
    public static double Now => Watch.Elapsed.TotalSeconds;
}
