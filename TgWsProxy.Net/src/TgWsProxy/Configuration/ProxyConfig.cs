using System.ComponentModel.DataAnnotations;

namespace TgWsProxy.Configuration;

/// <summary>
/// C# port of Python <c>proxy/config.py::ProxyConfig</c> (dataclass).
/// Bound from the <c>Proxy</c> section of appsettings.json via
/// Microsoft.Extensions.Configuration (<see cref="SectionName"/>).
/// </summary>
public sealed class ProxyConfig
{
    public const string SectionName = "Proxy";

    /// <summary><c>port</c> (default 1443).</summary>
    [Range(1, 65535)]
    public int Port { get; set; } = 1443;

    /// <summary><c>host</c> (default '127.0.0.1').</summary>
    [Required]
    public string Host { get; set; } = "127.0.0.1";

    /// <summary>
    /// <c>secret</c> — hex of a 16-byte obfuscated2 secret (32 hex chars).
    /// Python default: <c>os.urandom(16).hex()</c>. Here an empty value means
    /// "generate at startup and print to console" (see <see cref="Defaults.CreateRandomSecret"/>).
    /// </summary>
    public string Secret { get; set; } = string.Empty;

    /// <summary>
    /// <c>dc_redirects</c> — DC number → IPv4. Python default:
    /// <c>{2: '149.154.167.220', 4: '149.154.167.220'}</c>.
    /// JSON keys are strings ("2"), the binder converts them to int.
    /// </summary>
    public Dictionary<int, string> DcRedirects { get; set; } = new()
    {
        [2] = "149.154.167.220",
        [4] = "149.154.167.220",
    };

    /// <summary><c>buffer_size</c> in bytes; UI/JSON expose it in KB (<c>buf_kb</c>, default 256).</summary>
    [Range(4, 16 * 1024)] // 4 KB .. 16 MB, generous sanity bounds
    public int BufferSizeKb { get; set; } = 256;

    /// <summary>Python <c>buffer_size</c> derived from <see cref="BufferSizeKb"/>.</summary>
    public int BufferSize => BufferSizeKb * 1024;

    /// <summary><c>pool_size</c> (default 4).</summary>
    [Range(1, 1024)]
    public int PoolSize { get; set; } = 4;

    /// <summary><c>fallback_cfproxy</c> (default True).</summary>
    public bool FallbackCfProxy { get; set; } = true;

    /// <summary><c>cfproxy_user_domains</c> (default []). Raw, un-normalized list.</summary>
    public List<string> CfProxyUserDomains { get; set; } = [];

    /// <summary><c>cfproxy_worker_domains</c> (default []). Raw, un-normalized list.</summary>
    public List<string> CfProxyWorkerDomains { get; set; } = [];

    /// <summary><c>cfproxy_h2_media</c> (default True).</summary>
    public bool CfProxyH2Media { get; set; } = true;

    /// <summary><c>disable_secure</c> (default False).</summary>
    public bool DisableSecure { get; set; }

    /// <summary><c>fake_tls_domain</c> (default '').</summary>
    public string FakeTlsDomain { get; set; } = string.Empty;

    /// <summary><c>proxy_protocol</c> (default False).</summary>
    public bool ProxyProtocol { get; set; }

    /// <summary><c>force_test_dc</c> (default False).</summary>
    public bool ForceTestDc { get; set; }

    /// <summary>
    /// Console stats reporter cadence in seconds (PORT_PLAN.md §3 item 8 — the
    /// periodic "stats: ..." INFO line that replaces the GUI dashboard window).
    /// Python hard-codes 60 s in <c>tg_ws_proxy.py::log_stats</c>; here it is a
    /// config knob with the same default. Values &lt;= 0 disable the report.
    /// </summary>
    [Range(-1, 86_400)]
    public int StatsIntervalSec { get; set; } = 60;

    /// <summary>
    /// WS network-debug flow dump cadence in seconds (Python
    /// <c>network_debug.log_ws_flow</c> called from the 5 s reporter loop).
    /// Only produces output while Debug logging is enabled. Values &lt;= 0
    /// disable the flow dump.
    /// </summary>
    [Range(-1, 86_400)]
    public int FlowDebugIntervalSec { get; set; } = 5;

    /// <summary>
    /// Python property <c>h2_enabled</c>:
    /// <c>cfproxy_h2_media and fallback_cfproxy and not disable_secure and not force_test_dc</c>.
    /// </summary>
    public bool H2Enabled =>
        CfProxyH2Media && FallbackCfProxy && !DisableSecure && !ForceTestDc;
}

/// <summary>
/// Helpers reproducing Python defaults / small config utilities
/// (<c>config.py</c>, <c>utils/default_config.py</c>).
/// </summary>
public static class Defaults
{
    /// <summary>Python: <c>os.urandom(16).hex()</c>.</summary>
    public static string CreateRandomSecret() =>
        Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();

    /// <summary>
    /// Python <c>coerce_domain_list</c>: split strings on whitespace/,/; , flatten lists,
    /// trim, drop empties, case-insensitive de-duplication (first occurrence wins).
    /// </summary>
    public static List<string> CoerceDomainList(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return [];

        var items = raw.Replace(',', ' ').Replace(';', ' ').Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var result = new List<string>();
        foreach (var item in items)
        {
            var trimmed = item.Trim();
            if (trimmed.Length == 0)
                continue;
            if (seen.Add(trimmed.ToLowerInvariant()))
                result.Add(trimmed);
        }
        return result;
    }
}
