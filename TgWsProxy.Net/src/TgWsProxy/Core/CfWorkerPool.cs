using System.Collections.Concurrent;
using System.Web;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using TgWsProxy.Configuration;
using TgWsProxy.Observability;
using TgWsProxy.Transport;

namespace TgWsProxy.Core;

/// <summary>
/// Pool of pre-connected Cloudflare-Worker WebSockets — port of Python
/// <c>proxy/pool.py::_CfWorkerPool</c>. One idle connection per DC max
/// (PER_DC_LIMIT=1), domains rotate, exhausted domains are parked until UTC midnight.
/// </summary>
public sealed class CfWorkerPool : IAsyncDisposable
{
    public const double WsPoolMaxAgeSec = 100.0;
    public const double WsPoolCheckIntervalSec = 5.0;
    public const int PerDcLimit = 1;
    public const double RefillBackoffInitialSec = 1.0;
    public const double RefillBackoffMaxSec = 3600.0;

    private readonly ProxyConfig _config;
    private readonly ILogger<CfWorkerPool> _log;
    private readonly CancellationTokenSource _shutdown = new();

    private readonly ConcurrentDictionary<int, ConcurrentQueue<PooledWorkerWs>> _idle = new();
    private readonly ConcurrentDictionary<int, Task> _refilling = new();
    private readonly ConcurrentDictionary<int, Task> _rotating = new();
    private readonly ConcurrentDictionary<int, int> _refillFailures = new();
    private readonly ConcurrentDictionary<int, double> _refillAfter = new();
    private readonly ConcurrentDictionary<string, double> _exhaustedUntil = new();

    internal sealed record PooledWorkerWs(RawWebSocket Ws, double Created, string WorkerDomain);

    public CfWorkerPool(IOptions<ProxyConfig> config, ILogger<CfWorkerPool> log)
    {
        _config = config.Value;
        _log = log;
    }

    private static double Now => StopwatchMono.Now;
    private static double UnixNow => DateTimeOffset.UtcNow.ToUnixTimeSeconds();

    /// <summary>Python <c>_CfWorkerPool.get</c>.</summary>
    public Task<(RawWebSocket Ws, string WorkerDomain)?> GetAsync(
        int dc, string fallbackDst, IReadOnlyList<string> workerDomains)
    {
        if (_config.PoolSize <= 0 || workerDomains.Count == 0)
            return Task.FromResult<(RawWebSocket Ws, string WorkerDomain)?>(null);

        double now = Now;
        var bucket = _idle.GetOrAdd(dc, _ => new ConcurrentQueue<PooledWorkerWs>());
        while (bucket.TryDequeue(out var pooled))
        {
            double age = now - pooled.Created;
            if (IsStale(pooled.Ws, pooled.Created, now))
            {
                QuietClose(pooled.Ws);
                continue;
            }
            ProxyStats.Shared.AddCfPoolHit();
            _log.LogDebug("CF worker pool hit DC{Dc} via {Domain} (age={Age:F1}s, left={Left})",
                dc, pooled.WorkerDomain, age, bucket.Count);
            ScheduleRefill(dc, fallbackDst, workerDomains);
            return Task.FromResult<(RawWebSocket Ws, string WorkerDomain)?>((pooled.Ws, pooled.WorkerDomain));
        }

        ProxyStats.Shared.AddCfPoolMiss();
        ScheduleRefill(dc, fallbackDst, workerDomains);
        return Task.FromResult<(RawWebSocket Ws, string WorkerDomain)?>(null);
    }

    internal static bool IsStale(RawWebSocket ws, double created, double now) =>
        now - created >= WsPoolMaxAgeSec || ws.Closed;

    private void ScheduleRefill(int dc, string fallbackDst, IReadOnlyList<string> workerDomains)
    {
        if (_config.PoolSize <= 0 || workerDomains.Count == 0) return;
        ScheduleRotation(dc, fallbackDst, workerDomains);

        if (Now < _refillAfter.GetValueOrDefault(dc, double.MinValue))
            return;

        var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var registered = _refilling.GetOrAdd(dc, tcs.Task);
        if (!ReferenceEquals(registered, tcs.Task))
        {
            if (registered.IsCompleted &&
                _refilling.TryRemove(new KeyValuePair<int, Task>(dc, registered)))
            {
                var tcs2 = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                if (_refilling.TryAdd(dc, tcs2.Task))
                    RunRefill(dc, fallbackDst, workerDomains, tcs2);
            }
            return;
        }
        RunRefill(dc, fallbackDst, workerDomains, tcs);
    }

    private void RunRefill(int dc, string fallbackDst, IReadOnlyList<string> workerDomains,
                           TaskCompletionSource tcs)
    {
        _ = Task.Run(async () =>
        {
            try { await RefillAsync(dc, fallbackDst, workerDomains).ConfigureAwait(false); tcs.TrySetResult(); }
            catch (Exception exc) { tcs.TrySetException(exc); }
            finally { _refilling.TryRemove(new KeyValuePair<int, Task>(dc, tcs.Task)); }
        });
    }

    private async Task RefillAsync(int dc, string fallbackDst, IReadOnlyList<string> workerDomains)
    {
        var bucket = _idle.GetOrAdd(dc, _ => new ConcurrentQueue<PooledWorkerWs>());
        int targetSize = Math.Min(_config.PoolSize, PerDcLimit);
        int needed = targetSize - bucket.Count;
        if (needed <= 0) return;

        int connected = 0;
        for (int i = 0; i < needed; i++)
        {
            var result = await ConnectOneAsync(workerDomains, fallbackDst, dc).ConfigureAwait(false);
            if (result is null) break;
            bucket.Enqueue(new PooledWorkerWs(result.Value.Ws, Now, result.Value.WorkerDomain));
            connected++;
        }

        if (connected > 0)
        {
            _refillFailures.TryRemove(dc, out _);
            _refillAfter.TryRemove(dc, out _);
        }
        else
        {
            int failures = _refillFailures.AddOrUpdate(dc, 1, (_, v) => v + 1);
            double delay = Math.Min(RefillBackoffInitialSec * Math.Pow(2, Math.Min(failures - 1, 12)),
                                    RefillBackoffMaxSec);
            _refillAfter[dc] = Now + delay;
            _log.LogInformation("CF worker pool refill failed for DC{Dc}, retry in {Delay:F0}s", dc, delay);
        }
        _log.LogDebug("CF worker pool refilled DC{Dc}: {Count} ready", dc, bucket.Count);
    }

    private void ScheduleRotation(int dc, string fallbackDst, IReadOnlyList<string> workerDomains)
    {
        var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!_rotating.TryAdd(dc, tcs.Task)) return;
        _ = Task.Run(async () =>
        {
            try { await RotateAsync(dc, fallbackDst, workerDomains).ConfigureAwait(false); }
            finally
            {
                _rotating.TryRemove(new KeyValuePair<int, Task>(dc, tcs.Task));
                tcs.TrySetResult();
            }
        });
    }

    private async Task RotateAsync(int dc, string fallbackDst, IReadOnlyList<string> workerDomains)
    {
        while (_config.PoolSize > 0 && !_shutdown.IsCancellationRequested)
        {
            var bucket = _idle.GetOrAdd(dc, _ => new ConcurrentQueue<PooledWorkerWs>());
            double now = Now;
            int expired = 0;
            var keep = new List<PooledWorkerWs>(bucket.Count);
            while (bucket.TryDequeue(out var pooled))
            {
                if (IsStale(pooled.Ws, pooled.Created, now)) { QuietClose(pooled.Ws); expired++; }
                else keep.Add(pooled);
            }
            foreach (var p in keep) bucket.Enqueue(p);

            if (expired > 0)
                _log.LogDebug("CF worker pool rotated DC{Dc}: {Expired} stale, {Ready} ready",
                    dc, expired, bucket.Count);

            if (bucket.Count < Math.Min(_config.PoolSize, PerDcLimit))
                ScheduleRefill(dc, fallbackDst, workerDomains);

            double wakeAt = now + WsPoolCheckIntervalSec;
            if (keep.Count > 0)
                wakeAt = Math.Min(wakeAt, keep.Min(p => p.Created) + WsPoolMaxAgeSec);
            if (!_refilling.ContainsKey(dc))
            {
                double after = _refillAfter.GetValueOrDefault(dc, double.MaxValue);
                if (after > now) wakeAt = Math.Min(wakeAt, after);
            }
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(Math.Max(0, wakeAt - Now)), _shutdown.Token)
                            .ConfigureAwait(false);
            }
            catch (OperationCanceledException) { break; }
        }
    }

    /// <summary>Python <c>_connect_one</c>: /apiws?dst=&lt;ip&gt;&amp;dc=&lt;n&gt; via a healthy worker domain.</summary>
    internal async Task<(RawWebSocket Ws, string WorkerDomain)?> ConnectOneAsync(
        IReadOnlyList<string> workerDomains, string fallbackDst, int dc)
    {
        string path = $"/apiws?{new Dictionary<string, string> { ["dst"] = fallbackDst, ["dc"] = dc.ToString() }.ToQueryString()}";
        foreach (var workerDomain in AvailableDomains(workerDomains))
        {
            try
            {
                var ws = await RawWebSocket.ConnectAsync(
                    workerDomain, workerDomain,
                    timeout: TimeSpan.FromSeconds(8),
                    path: path,
                    secure: !_config.DisableSecure,
                    config: _config,
                    ct: _shutdown.Token).ConfigureAwait(false);
                return (ws, workerDomain);
            }
            catch (Exception exc)
            {
                _log.LogDebug("CF worker pool connect DC{Dc} via {Domain} for {Dst} failed: {Exc}",
                    dc, workerDomain, fallbackDst, exc.Message);
                ReportFailure(workerDomain, exc);
            }
        }
        return null;
    }

    /// <summary>Python <c>available_domains</c>: dedupe, drop exhausted, shuffle.</summary>
    public IReadOnlyList<string> AvailableDomains(IReadOnlyList<string> workerDomains)
    {
        double now = UnixNow;
        var domains = new List<string>();
        foreach (var domain in workerDomains)
        {
            if (domains.Contains(domain)) continue;
            double exhaustedUntil = _exhaustedUntil.GetValueOrDefault(domain, 0);
            if (exhaustedUntil > now) continue;
            if (exhaustedUntil != 0) _exhaustedUntil.TryRemove(domain, out _);
            domains.Add(domain);
        }
        DcBalancer.Shuffle(domains);
        return domains;
    }

    /// <summary>
    /// Python <c>report_failure</c> — currently a no-op upstream (TODO there: only 429
    /// should park a domain until UTC midnight); parity preserved.
    /// </summary>
    public void ReportFailure(string workerDomain, Exception exc)
    {
        if (exc is not WsHandshakeException wsEx || wsEx.StatusCode != 429)
            return;

        double now = UnixNow;
        if (_exhaustedUntil.GetValueOrDefault(workerDomain, 0) > now)
            return;
        double exhaustedUntil = now + (86400 - (now % 86400));
        _exhaustedUntil[workerDomain] = exhaustedUntil;
        _log.LogWarning("CF worker {Domain} reached its request limit, disabled for {Sec}s",
            workerDomain, (int)(exhaustedUntil - now));
    }

    private void QuietClose(RawWebSocket ws) => _ = ws.CloseAsync().ContinueWith(
        static t => { _ = t.Exception; }, TaskScheduler.Default);

    /// <summary>Python <c>warmup</c>: prefill DCs that have no direct redirect IP.</summary>
    public Task WarmupAsync()
    {
        var cfFallbacks = ProtocolConsts.DcDefaultIps
            .Where(kv => !_config.ParsedDcRedirects.ContainsKey(kv.Key))
            .ToDictionary(kv => kv.Key, kv => kv.Value);

        if (_config.PoolSize <= 0 || cfFallbacks.Count == 0 || _config.CfProxyWorkerDomains.Count == 0)
            return Task.CompletedTask;

        var workerDomains = _config.CfProxyWorkerDomains.ToList();
        foreach (var (dc, fallbackDst) in cfFallbacks)
            ScheduleRefill(dc, fallbackDst, workerDomains);

        _log.LogInformation("CF worker pool warmup started for {Count} DC(s)", cfFallbacks.Count);
        return Task.CompletedTask;
    }

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
        _exhaustedUntil.Clear();
    }

    public ValueTask DisposeAsync()
    {
        Reset();
        return ValueTask.CompletedTask;
    }
}

internal static class QueryStringExtensions
{
    /// <summary>urlencode equivalent (RFC 3986-ish, space→%20).</summary>
    public static string ToQueryString(this IDictionary<string, string> pairs) =>
        string.Join("&", pairs.Select(kv =>
            $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"));
}
