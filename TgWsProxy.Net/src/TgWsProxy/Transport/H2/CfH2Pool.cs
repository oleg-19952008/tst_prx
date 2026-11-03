using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using TgWsProxy.Core;
using TgWsProxy.Observability;

namespace TgWsProxy.Transport.H2;

/// <summary>
/// Pool of Cloudflare H2 lanes keyed by host — byte-for-byte port of
/// <c>proxy/cf_h2.py::CfH2Pool</c> (PORT_PLAN.md checklist п. 6). Reuses the
/// <see cref="DcBalancer"/> domain rotation exactly like the Python module
/// reuses <c>balancer.get_domains_for_dc / update_domain_for_dc</c>.
/// </summary>
internal sealed class CfH2Pool : IAsyncDisposable
{
    private static ILogger Log => _log ??= ProgramLogger.For<CfH2Pool>();
    private static ILogger? _log;

    private readonly DcBalancer _balancer;
    private readonly ConcurrentDictionary<string, HttpLane> _lanes = new();
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _locks = new();
    private readonly ConcurrentDictionary<string, double> _failedUntil = new();
    private readonly ConcurrentDictionary<int, double> _setupRetryAfter = new();
    private long _nextLane;
    private long _nextChannel;
    private volatile bool _closed;

    private static double Now => StopwatchMono.Now;

    public CfH2Pool(DcBalancer balancer) => _balancer = balancer;

    /// <summary>Python <c>CfH2Pool.open(dc, label)</c>.</summary>
    public async Task<HttpChannel?> OpenAsync(int dc, string label, CancellationToken ct)
    {
        if (_closed) throw new ConnectionError("H2 pool closed");
        if (Now < _setupRetryAfter.GetValueOrDefault(dc)) return null;

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(CfH2Consts.SetupTimeout));
        try
        {
            return await OpenInnerAsync(dc, label, cts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            _setupRetryAfter[dc] = Now + CfH2Consts.DomainCooldown;
            ProxyStats.Shared.AddH2Error();
            Log.LogWarning("[{Label}] H2 DC{Dc} setup timed out; using WS for {T:F0}s",
                           label, dc, CfH2Consts.DomainCooldown);
            return null;
        }
    }

    /// <summary>Python <c>CfH2Pool._open(dc, label)</c>.</summary>
    private async Task<HttpChannel?> OpenInnerAsync(int dc, string label, CancellationToken ct)
    {
        if (_closed) throw new ConnectionError("H2 pool closed");
        if (!ProtocolConsts.DcDefaultIps.ContainsKey(dc))
        {
            Log.LogWarning("[{Label}] H2 unsupported DC{Dc} -> existing WS route", label, dc);
            return null;
        }

        foreach (var baseDomain in _balancer.GetDomainsForDc(dc))
        {
            string host = $"kws{dc}.{baseDomain}";
            var gate = _locks.GetOrAdd(host, _ => new SemaphoreSlim(1, 1));
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                if (_closed) throw new ConnectionError("H2 pool closed");

                _lanes.TryGetValue(host, out var lane);
                double failed = Math.Max(_failedUntil.GetValueOrDefault(host),
                                         lane?.FailedUntil ?? 0);
                if (Now < failed) continue;

                if (lane is null)
                {
                    long laneId = Interlocked.Increment(ref _nextLane);
                    var fresh = new HttpLane(host, (int)laneId);
                    try
                    {
                        await fresh.PreflightAsync(ct).ConfigureAwait(false);
                    }
                    catch (Exception exc) when (exc is not OperationCanceledException)
                    {
                        ProxyStats.Shared.AddH2Error();
                        _failedUntil[host] = Now + CfH2Consts.DomainCooldown;
                        Log.LogWarning("[{Label}] H2 lane={Lane} preflight failed host={Host}: {Type}: {Msg}",
                                       label, fresh.LaneId, host, exc.GetType().Name, exc.Message);
                        await fresh.DisposeAsync().ConfigureAwait(false);
                        continue;
                    }
                    if (_closed)
                    {
                        await fresh.DisposeAsync().ConfigureAwait(false);
                        throw new ConnectionError("H2 pool closed during preflight");
                    }
                    lane = _lanes.GetOrAdd(host, fresh);
                    if (!ReferenceEquals(lane, fresh))
                        await fresh.DisposeAsync().ConfigureAwait(false);
                }

                long channelId = Interlocked.Increment(ref _nextChannel);
                var channel = new HttpChannel(lane, (int)channelId, label);
                lane.Channels.TryAdd(channel, 0);   // Python: lane.channels.add(self)
                if (_balancer.UpdateDomainForDc(dc, baseDomain))
                    Log.LogInformation("[{Label}] Switched active CF domain (H2)", label);
                Log.LogInformation(
                    "[{Label}] ROUTE DC{Dc} media -> H2 lane={Lane} channel={Ch} host={Host} " +
                    "channels={N} tcp_connections={Tcp}",
                    label, dc, lane.LaneId, channel.ChannelId, host,
                    lane.Channels.Count, lane.TcpConnections);
                return channel;
            }
            finally
            {
                gate.Release();
            }
        }

        Log.LogDebug("[{Label}] H2 DC{Dc} unavailable; using WS", label, dc);
        return null;
    }

    /// <summary>Python <c>CfH2Pool.log_stats()</c>.</summary>
    public void LogStats()
    {
        foreach (var lane in _lanes.Values)
            if (!lane.Channels.IsEmpty)
                Log.LogDebug("H2 STATS {Summary}", lane.Summary());
    }

    /// <summary>Python <c>CfH2Pool.close()</c>.</summary>
    public async ValueTask DisposeAsync()
    {
        _closed = true;
        var lanes = _lanes.Values.ToArray();
        _lanes.Clear();
        await Task.WhenAll(lanes.Select(async l =>
        {
            try { await l.DisposeAsync().ConfigureAwait(false); }
            catch { /* best-effort close, mirrors asyncio.gather without return_exceptions */ }
        })).ConfigureAwait(false);
    }
}
