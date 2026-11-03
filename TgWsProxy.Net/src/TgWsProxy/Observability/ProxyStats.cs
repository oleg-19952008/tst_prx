namespace TgWsProxy.Observability;

/// <summary>
/// Connection/traffic counters — port of Python <c>proxy/stats.py::_Stats</c>.
/// Uses Interlocked operations instead of asyncio's implicit single-thread safety.
/// </summary>
public sealed class ProxyStats
{
    public static readonly ProxyStats Shared = new();

    private long _connectionsTotal;
    private long _connectionsActive;
    private long _connectionsWs;
    private long _connectionsH2;
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
    private long _h2TcpConnections;
    private long _h2Requests;
    private long _h2Errors;

    private long Inc(ref long field, long delta = 1) => Interlocked.Add(ref field, delta);
    private long Get(ref long field) => Volatile.Read(ref field);

    public long ConnectionsTotal { get => Get(ref _connectionsTotal); set => Interlocked.Exchange(ref _connectionsTotal, value); }
    public long ConnectionsActive { get => Get(ref _connectionsActive); set => Interlocked.Exchange(ref _connectionsActive, value); }
    public long ConnectionsWs => Get(ref _connectionsWs);
    public long ConnectionsH2 => Get(ref _connectionsH2);
    public long ConnectionsTcpFallback => Get(ref _connectionsTcpFallback);
    public long ConnectionsCfproxy => Get(ref _connectionsCfproxy);
    public long ConnectionsFronting => Get(ref _connectionsFronting);
    public long ConnectionsBad => Get(ref _connectionsBad);
    public long ConnectionsMasked => Get(ref _connectionsMasked);
    public long WsErrors => Get(ref _wsErrors);
    public long BytesUp => Get(ref _bytesUp);
    public long BytesDown => Get(ref _bytesDown);
    public long PoolHits => Get(ref _poolHits);
    public long PoolMisses => Get(ref _poolMisses);
    public long CfPoolHits => Get(ref _cfPoolHits);
    public long CfPoolMisses => Get(ref _cfPoolMisses);
    public long H2TcpConnections => Get(ref _h2TcpConnections);
    public long H2Requests => Get(ref _h2Requests);
    public long H2Errors => Get(ref _h2Errors);

    public void AddConnectionWs() => Inc(ref _connectionsWs);
    public void AddConnectionH2() => Inc(ref _connectionsH2);
    public void AddConnectionTcpFallback() => Inc(ref _connectionsTcpFallback);
    public void AddConnectionCfproxy() => Inc(ref _connectionsCfproxy);
    public void AddConnectionFronting() => Inc(ref _connectionsFronting);
    public void AddConnectionBad() => Inc(ref _connectionsBad);
    public void AddConnectionMasked() => Inc(ref _connectionsMasked);
    public void AddWsError() => Inc(ref _wsErrors);
    public void AddBytesUp(long n) => Inc(ref _bytesUp, n);
    public void AddBytesDown(long n) => Inc(ref _bytesDown, n);
    public void AddPoolHit() => Inc(ref _poolHits);
    public void AddPoolMiss() => Inc(ref _poolMisses);
    public void AddCfPoolHit() => Inc(ref _cfPoolHits);
    public void AddCfPoolMiss() => Inc(ref _cfPoolMisses);
    public void AddH2TcpConnection() => Inc(ref _h2TcpConnections);
    public void AddH2Request() => Inc(ref _h2Requests);
    public void AddH2Error() => Inc(ref _h2Errors);

    /// <summary>Mirror of Python <c>_Stats.summary()</c>.</summary>
    public string Summary()
    {
        var poolTotal = PoolHits + PoolMisses;
        var poolS = poolTotal > 0 ? $"{PoolHits}/{poolTotal}" : "n/a";
        var cfPoolTotal = CfPoolHits + CfPoolMisses;
        var cfPoolS = cfPoolTotal > 0 ? $"{CfPoolHits}/{cfPoolTotal}" : "n/a";
        return $"total={ConnectionsTotal} active={ConnectionsActive} ws={ConnectionsWs} " +
               $"h2={ConnectionsH2} tcp_fb={ConnectionsTcpFallback} cf={ConnectionsCfproxy} " +
               $"front={ConnectionsFronting} bad={ConnectionsBad} masked={ConnectionsMasked} " +
               $"err={WsErrors} h2_tcp={H2TcpConnections} h2_req={H2Requests} h2_err={H2Errors} " +
               $"pool={poolS} cf_pool={cfPoolS} " +
               $"up={Core.ProtocolConsts.HumanBytes(BytesUp)} down={Core.ProtocolConsts.HumanBytes(BytesDown)}";
    }
}
