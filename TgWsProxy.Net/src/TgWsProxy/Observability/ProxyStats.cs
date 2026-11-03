using System.Text;

namespace TgWsProxy.Observability;

/// <summary>
/// C# port of Python <c>proxy/stats.py::_Stats</c> — global connection/traffic
/// counters. Python mutated plain attributes from the asyncio event loop (single
/// thread); here every counter is an <see cref="Int64"/> field updated through
/// <see cref="Interlocked"/> so the class is safe under the TPL thread pool.
/// </summary>
public sealed class ProxyStats
{
    // Field order mirrors _Stats.__init__ (stats.py).
    private long _connectionsTotal;
    private long _connectionsActive;
    private long _connectionsWs;
    private long _connectionsH2;
    private long _h2TcpConnections;
    private long _h2Requests;
    private long _h2Errors;
    private long _connectionsTcpFallback;
    private long _connectionsCfproxy;
    private long _connectionsFronting;
    private long _connectionsBad;
    private long _connectionsMasked;
    private long _wsErrors;
    private long _bytesUp;
    private long _bytesDown;
    private long _poolHits;
    private long _poolMisses;
    private long _cfPoolHits;
    private long _cfPoolMisses;

    public long ConnectionsTotal => Volatile.Read(ref _connectionsTotal);
    public long ConnectionsActive => Volatile.Read(ref _connectionsActive);
    public long ConnectionsWs => Volatile.Read(ref _connectionsWs);
    public long ConnectionsH2 => Volatile.Read(ref _connectionsH2);
    public long H2TcpConnections => Volatile.Read(ref _h2TcpConnections);
    public long H2Requests => Volatile.Read(ref _h2Requests);
    public long H2Errors => Volatile.Read(ref _h2Errors);
    public long ConnectionsTcpFallback => Volatile.Read(ref _connectionsTcpFallback);
    public long ConnectionsCfproxy => Volatile.Read(ref _connectionsCfproxy);
    public long ConnectionsFronting => Volatile.Read(ref _connectionsFronting);
    public long ConnectionsBad => Volatile.Read(ref _connectionsBad);
    public long ConnectionsMasked => Volatile.Read(ref _connectionsMasked);
    public long WsErrors => Volatile.Read(ref _wsErrors);
    public long BytesUp => Volatile.Read(ref _bytesUp);
    public long BytesDown => Volatile.Read(ref _bytesDown);
    public long PoolHits => Volatile.Read(ref _poolHits);
    public long PoolMisses => Volatile.Read(ref _poolMisses);
    public long CfPoolHits => Volatile.Read(ref _cfPoolHits);
    public long CfPoolMisses => Volatile.Read(ref _cfPoolMisses);

    public void AddConnectionTotal(long delta = 1) => Interlocked.Add(ref _connectionsTotal, delta);
    public void AddConnectionActive(long delta) => Interlocked.Add(ref _connectionsActive, delta);
    public void AddConnectionsWs(long delta = 1) => Interlocked.Add(ref _connectionsWs, delta);
    public void AddConnectionsH2(long delta = 1) => Interlocked.Add(ref _connectionsH2, delta);
    public void AddH2TcpConnections(long delta = 1) => Interlocked.Add(ref _h2TcpConnections, delta);
    public void AddH2Requests(long delta = 1) => Interlocked.Add(ref _h2Requests, delta);
    public void AddH2Errors(long delta = 1) => Interlocked.Add(ref _h2Errors, delta);
    public void AddConnectionsTcpFallback(long delta = 1) => Interlocked.Add(ref _connectionsTcpFallback, delta);
    public void AddConnectionsCfproxy(long delta = 1) => Interlocked.Add(ref _connectionsCfproxy, delta);
    public void AddConnectionsFronting(long delta = 1) => Interlocked.Add(ref _connectionsFronting, delta);
    public void AddConnectionsBad(long delta = 1) => Interlocked.Add(ref _connectionsBad, delta);
    public void AddConnectionsMasked(long delta = 1) => Interlocked.Add(ref _connectionsMasked, delta);
    public void AddWsErrors(long delta = 1) => Interlocked.Add(ref _wsErrors, delta);
    public void AddBytesUp(long delta) => Interlocked.Add(ref _bytesUp, delta);
    public void AddBytesDown(long delta) => Interlocked.Add(ref _bytesDown, delta);
    public void AddPoolHit() => Interlocked.Increment(ref _poolHits);
    public void AddPoolMiss() => Interlocked.Increment(ref _poolMisses);
    public void AddCfPoolHit() => Interlocked.Increment(ref _cfPoolHits);
    public void AddCfPoolMiss() => Interlocked.Increment(ref _cfPoolMisses);

    /// <summary>
    /// Python <c>_Stats.summary()</c>: space-separated key=value block with pool
    /// hit ratios ("&lt;hits&gt;/&lt;total&gt;" or "n/a") and human-readable
    /// up/down byte counters. Culture-invariant formatting matches Python's
    /// f-strings (plain ints, "%.1f" via <see cref="Utils.HumanBytes"/>).
    /// </summary>
    public string Summary()
    {
        long poolTotal = PoolHits + PoolMisses;
        var poolS = poolTotal != 0
            ? FormattableString.Invariant($"{PoolHits}/{poolTotal}")
            : "n/a";
        long cfPoolTotal = CfPoolHits + CfPoolMisses;
        var cfPoolS = cfPoolTotal != 0
            ? FormattableString.Invariant($"{CfPoolHits}/{cfPoolTotal}")
            : "n/a";

        return new StringBuilder()
            .Append(FormattableString.Invariant($"total={ConnectionsTotal} "))
            .Append(FormattableString.Invariant($"active={ConnectionsActive} "))
            .Append(FormattableString.Invariant($"ws={ConnectionsWs} "))
            .Append(FormattableString.Invariant($"h2={ConnectionsH2} "))
            .Append(FormattableString.Invariant($"h2_tcp={H2TcpConnections} "))
            .Append(FormattableString.Invariant($"h2_req={H2Requests} "))
            .Append(FormattableString.Invariant($"h2_err={H2Errors} "))
            .Append(FormattableString.Invariant($"tcp_fb={ConnectionsTcpFallback} "))
            .Append(FormattableString.Invariant($"cf={ConnectionsCfproxy} "))
            .Append(FormattableString.Invariant($"front={ConnectionsFronting} "))
            .Append(FormattableString.Invariant($"bad={ConnectionsBad} "))
            .Append(FormattableString.Invariant($"masked={ConnectionsMasked} "))
            .Append(FormattableString.Invariant($"err={WsErrors} "))
            .Append("pool=").Append(poolS).Append(' ')
            .Append("cf_pool=").Append(cfPoolS).Append(' ')
            .Append("up=").Append(Utils.HumanBytes(BytesUp)).Append(' ')
            .Append("down=").Append(Utils.HumanBytes(BytesDown))
            .ToString();
    }
}
