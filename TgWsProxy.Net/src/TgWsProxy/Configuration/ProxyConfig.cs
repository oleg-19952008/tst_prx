using Microsoft.Extensions.Options;

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
    public int BufferSizeKb { get; set; } = 256;

    /// <summary>WS pool size per DC bucket; 0 disables pooled direct WS.</summary>
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

/// <summary>
/// Default values mirroring Python <c>proxy/config.py</c> / <c>utils/default_config.py</c>,
/// plus the startup secret generator used by <see cref="ProxyConfigValidator"/>.
/// </summary>
public static class Defaults
{
    /// <summary>Python: <c>os.urandom(16).hex()</c> — 16 random bytes as lowercase hex.</summary>
    public static string CreateRandomSecret()
    {
        Span<byte> buf = stackalloc byte[16];
        System.Security.Cryptography.RandomNumberGenerator.Fill(buf);
        return Convert.ToHexStringLower(buf);
    }
}
