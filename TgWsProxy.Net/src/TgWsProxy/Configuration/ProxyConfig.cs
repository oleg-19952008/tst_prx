using System.ComponentModel.DataAnnotations;

namespace TgWsProxy.Configuration;

/// <summary>
/// Proxy settings — schema per PORT_PLAN.md §2 (source of truth:
/// Python <c>proxy/config.py::ProxyConfig</c>). Bound from the "Proxy"
/// section of appsettings.json via <see cref="IValidateOptions{ProxyConfig}"/>.
/// </summary>
public sealed class ProxyConfig
{
    public const string SectionName = "Proxy";

    /// <summary>Listen port.</summary>
    [Range(1, 65535)]
    public int Port { get; set; } = 1443;

    /// <summary>Bind address.</summary>
    public string Host { get; set; } = "127.0.0.1";

    /// <summary>Hex obfuscated2 secret (32 hex chars). Empty → generated at startup.</summary>
    public string Secret { get; set; } = "";

    /// <summary>DC → target IP map ("&lt;dc&gt;": "&lt;ip&gt;"). Defaults mirror Python.</summary>
    public Dictionary<string, string> DcRedirects { get; set; } = new()
    {
        ["2"] = "149.154.167.220",
        ["4"] = "149.154.167.220",
    };

    /// <summary>Socket buffer size in KB (Python: buffer_size = 256*1024 bytes).</summary>
    [Range(4, 1024 * 1024)]
    public int BufferSizeKb { get; set; } = 256;

    /// <summary>WS pool size per DC bucket; 0 disables pooled direct WS.</summary>
    [Range(0, 1024)]
    public int PoolSize { get; set; } = 4;

    /// <summary>Enable Cloudflare-proxied WS fallback.</summary>
    public bool FallbackCfProxy { get; set; } = true;

    /// <summary>User CF domains for H2 media &amp; WS fallback.</summary>
    public List<string> CfProxyUserDomains { get; set; } = new();

    /// <summary>Cloudflare Worker domains (tried before other fallbacks).</summary>
    public List<string> CfProxyWorkerDomains { get; set; } = new();

    /// <summary>HTTP/2 multiplexing for CF media traffic.</summary>
    public bool CfProxyH2Media { get; set; } = true;

    /// <summary>Use plain ws:// port 80 for CF proxy/worker connections.</summary>
    public bool DisableSecure { get; set; }

    /// <summary>Fake TLS (ee-secret) masking SNI domain; empty → disabled.</summary>
    public string FakeTlsDomain { get; set; } = "";

    /// <summary>Accept PROXY protocol v1 header.</summary>
    public bool ProxyProtocol { get; set; }

    /// <summary>Force all traffic to Telegram TEST DCs.</summary>
    public bool ForceTestDc { get; set; }

    /// <summary>
    /// Python <c>h2_enabled</c>: cfproxy_h2_media and fallback_cfproxy
    /// and not disable_secure and not force_test_dc.
    /// </summary>
    public bool H2Enabled =>
        CfProxyH2Media && FallbackCfProxy && !DisableSecure && !ForceTestDc;

    /// <summary>buffer_size in bytes (Python semantics).</summary>
    public int BufferSize => Math.Max(4, BufferSizeKb) * 1024;

    /// <summary>Parsed dc_redirects with integer keys (invalid entries dropped).</summary>
    public IReadOnlyDictionary<int, string> ParsedDcRedirects
    {
        get
        {
            var result = new Dictionary<int, string>();
            foreach (var (k, v) in DcRedirects)
                if (int.TryParse(k, out var dc) && !string.IsNullOrWhiteSpace(v))
                    result[dc] = v.Trim();
            return result;
        }
    }
}

/// <summary>Startup validation — PORT_PLAN.md §2 step 3.</summary>
public sealed class ProxyConfigValidator : IValidateOptions<ProxyConfig>
{
    public ValidateOptionsResult Validate(string? name, ProxyConfig options)
    {
        var failures = new List<string>();

        if (options.Port is < 1 or > 65535)
            failures.Add($"Proxy:Port must be 1-65535, got {options.Port}");

        if (!string.IsNullOrEmpty(options.Secret))
        {
            var s = options.Secret.Trim();
            if (s.Length != 32 || !System.Text.RegularExpressions.Regex.IsMatch(s, "^[0-9a-fA-F]{32}$"))
                failures.Add("Proxy:Secret must be exactly 32 hex characters");
        }

        foreach (var (dcStr, ip) in options.DcRedirects)
        {
            if (!int.TryParse(dcStr, out _))
                failures.Add($"Proxy:DcRedirects key \"{dcStr}\" is not a DC number");
            else if (!System.Net.IPAddress.TryParse(ip, out var addr)
                     || addr.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                failures.Add($"Proxy:DcRedirects[\"{dcStr}\"]=\"{ip}\" is not a valid IPv4 address");
        }

        if (options.H2Enabled && options.CfProxyH2Media && !options.FallbackCfProxy)
            failures.Add("Inconsistent flags: CfProxyH2Media requires FallbackCfProxy");

        return failures.Count > 0
            ? ValidateOptionsResult.Fail(failures)
            : ValidateOptionsResult.Success;
    }
}
