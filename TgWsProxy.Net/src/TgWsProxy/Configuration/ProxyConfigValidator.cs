using System.Globalization;
using System.Net;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace TgWsProxy.Configuration;

/// <summary>
/// Startup validation of <see cref="ProxyConfig"/> (PORT_PLAN.md §2 step 3):
/// port range, secret format (32 hex chars or empty → generated),
/// DC redirects (valid DC numbers + IPv4 addresses), H2 flag consistency.
/// Implements both <see cref="IValidateOptions{TOptions}"/> and
/// <see cref="IPostConfigureOptions{TOptions}"/> (secret generation).
/// </summary>
public sealed class ProxyConfigValidator : IValidateOptions<ProxyConfig>, IPostConfigureOptions<ProxyConfig>
{
    private const int SecretHexLength = 32; // 16 random bytes, like os.urandom(16).hex()

    /// <summary>Optional logger for non-fatal hints (H2 flag combinations).</summary>
    public static ILogger? s_logger;

    public void PostConfigure(string? name, ProxyConfig options)
    {
        // Python default is os.urandom(16).hex(); an empty configured value means
        // "generate at startup" (the host prints it — Telegram Desktop must be
        // reconfigured manually, same as in the GUI version).
        if (string.IsNullOrWhiteSpace(options.Secret))
            options.Secret = Defaults.CreateRandomSecret();
    }

    public ValidateOptionsResult Validate(string? name, ProxyConfig options)
    {
        var failures = new List<string>();

        if (options.Port is < 1 or > 65535)
            failures.Add($"Proxy:Port must be in 1..65535 (got {options.Port}).");

        if (!IsValidHost(options.Host))
            failures.Add($"Proxy:Host must be a valid IPv4/IPv6 address or hostname (got \"{options.Host}\").");

        if (options.BufferSizeKb is < 4 or > 16 * 1024)
            failures.Add($"Proxy:BufferSizeKb must be in 4..16384 KB (got {options.BufferSizeKb}).");

        if (options.PoolSize is < 1 or > 1024)
            failures.Add($"Proxy:PoolSize must be in 1..1024 (got {options.PoolSize}).");

        // Secret: an empty value is legal (generated in PostConfigure); anything
        // else must be exactly 32 hex chars.
        if (!string.IsNullOrWhiteSpace(options.Secret) && !IsValidSecret(options.Secret))
            failures.Add("Proxy:Secret must be empty (auto-generate) or exactly 32 hexadecimal characters (16 bytes, obfuscated2 secret).");

        if (options.DcRedirects.Count == 0)
            failures.Add("Proxy:DcRedirects must contain at least one \"<dc>\": \"<ip>\" entry.");

        // DcRedirects is Dictionary<string,string> in JSON — validate the key text.
        foreach (var (dcStr, ip) in options.DcRedirects)
        {
            if (!int.TryParse(dcStr, NumberStyles.Integer, CultureInfo.InvariantCulture, out var dc)
                || dc is < 1 or > 1000)
                failures.Add($"Proxy:DcRedirects key \"{dcStr}\" must be a positive DC number.");
            if (!IsValidIpv4(ip))
                failures.Add($"Proxy:DcRedirects[\"{dcStr}\"] = \"{ip}\" is not a valid IPv4 address.");
        }

        foreach (var domain in options.CfProxyUserDomains.Concat(options.CfProxyWorkerDomains))
        {
            if (!IsValidDomain(domain))
                failures.Add($"CF proxy domain \"{domain}\" is not a valid hostname.");
        }

        if (!string.IsNullOrEmpty(options.FakeTlsDomain) && !IsValidDomain(options.FakeTlsDomain))
            failures.Add($"Proxy:FakeTlsDomain \"{options.FakeTlsDomain}\" is not a valid hostname.");

        // H2 consistency (Python h2_enabled semantics): media-H2 requested but the
        // transport it depends on is disabled — legal in Python (H2 simply switches
        // off), so we accept the config and log a hint here.
        if (options.CfProxyH2Media && (!options.FallbackCfProxy || options.DisableSecure || options.ForceTestDc))
            s_logger?.LogWarning(
                "Proxy:CfProxyH2Media = true has no effect: H2Enabled evaluates to false " +
                "(FallbackCfProxy={Fallback}, DisableSecure={NoSecure}, ForceTestDc={TestDc}).",
                options.FallbackCfProxy, options.DisableSecure, options.ForceTestDc);

        return failures.Count > 0 ? ValidateOptionsResult.Fail(failures) : ValidateOptionsResult.Success;
    }

    private static bool IsValidHost(string host) =>
        !string.IsNullOrWhiteSpace(host)
        && (IPAddress.TryParse(host, out _) || IsValidDomain(host));

    private static bool IsValidIpv4(string ip) =>
        IPAddress.TryParse(ip, out var addr)
        && addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;

    private static bool IsValidSecret(string secret) =>
        secret.Length == SecretHexLength && IsHex(secret);

    private static bool IsHex(string s)
    {
        foreach (var c in s)
            if (!(c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F'))
                return false;
        return true;
    }

    /// <summary>
    /// Port of Python <c>config.py::_is_valid_domain</c>. Note: C# <see cref="char.IsLetter"/>
    /// accepts non-ASCII letters, Python <c>str.isalpha()</c> does too for unicode strings,
    /// but label content here is restricted to ASCII alnum/dash exactly like the original's
    /// <c>ch.isalnum() or ch == '-'</c> combined with the ASCII-only intent of hostnames;
    /// punycode ("xn--...") passes because '-' and digits are allowed.
    /// </summary>
    internal static bool IsValidDomain(string domain)
    {
        if (string.IsNullOrEmpty(domain) || domain.Length > 253)
            return false;
        if (domain.StartsWith('.') || domain.EndsWith('.'))
            return false;
        var labels = domain.Split('.');
        if (labels.Length < 2)
            return false;
        foreach (var label in labels)
        {
            if (label.Length is 0 or > 63)
                return false;
            if (label[0] == '-' || label[^1] == '-')
                return false;
            foreach (var ch in label)
                if (!(IsAlnum(ch) || ch == '-'))
                    return false;
        }
        var tld = labels[^1];
        return tld.Length >= 2 && tld.Any(char.IsLetter);
    }

    /// <summary>
    /// Python parity for <c>ch.isalnum() or ch == '-'</c>: unicode letters/digits and
    /// '-' are allowed; ASCII punctuation ('!', '_') is rejected by both sides.
    /// </summary>
    private static bool IsAlnum(char ch) =>
        char.IsLetter(ch) || char.GetUnicodeCategory(ch) is
            UnicodeCategory.DecimalDigitNumber or UnicodeCategory.LetterNumber or UnicodeCategory.OtherNumber;
}
