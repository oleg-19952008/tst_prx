using System.Security.Cryptography;
using System.Text;

namespace TgWsProxy.Configuration;

/// <summary>
/// Byte-for-byte port of the CF proxy domain utilities from Python
/// <c>proxy/config.py</c>: <c>_CFPROXY_ENC</c>, <c>_dd</c> (Caesar-style
/// decoder with <c>.co.uk</c> suffix), <c>CFPROXY_DEFAULT_DOMAINS</c>,
/// <c>_fetch_cfproxy_domain_list</c> and <c>_normalize_domain_pool</c>.
/// </summary>
public static class CfProxyDomains
{
    /// <summary>Python <c>CFPROXY_DOMAINS_URL</c>.</summary>
    public const string DomainsListUrl =
        "https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/main/.github/cfproxy-domains.txt";

    /// <summary>Python <c>_CFPROXY_MIN_VALID_DOMAINS</c>.</summary>
    public const int MinValidDomains = 3;

    /// <summary>Python <c>_S</c> = chr(46)+chr(99)+chr(111)+chr(46)+chr(117)+chr(107) == ".co.uk".</summary>
    private const string Suffix = ".co.uk";

    /// <summary>Python <c>_CFPROXY_ENC</c> — obfuscated (encoded) domain list.</summary>
    private static readonly string[] CfProxyEnc =
    [
        "virkgj.com",
        "vmmzovy.com",
        "mkuosckvso.com",
        "zaewayzmplad.com",
        "twdmbzcm.com",
        "awzwsldi.com",
        "clngqrflngqin.com",
        "tjacxbqtj.com",
        "bxaxtxmrw.com",
        "dmohrsgmohcrwb.com",
        "vwbmtmoi.com",
        "khgrre.com",
        "ulihssf.com",
        "tmhqsdqmfpmk.com",
        "xwuwoqbm.com",
        "orgcnunpj.com",
        "zhkuldz.com",
        "zypoljnslxa.com",
        "efabnxaowuzs.com",
        "zaftuzsftqdq.com",
    ];

    /// <summary>
    /// Python <c>_dd(s)</c>: if the entry ends with ".com", take n = number of
    /// letters in the name part and shift every letter back by n within its own
    /// alphabet (a-z / A-Z); append ".co.uk". Non-.com entries pass through.
    /// </summary>
    public static string DecodeDomain(string s)
    {
        if (!s.EndsWith(".com", StringComparison.Ordinal))
            return s;

        var p = s[..^4];
        var n = 0;
        foreach (var c in p)
            if (char.IsAsciiLetter(c))
                n++;

        var sb = new StringBuilder(p.Length);
        foreach (var c in p)
        {
            if (char.IsAsciiLetter(c))
            {
                var baseChar = c > '`' ? 'a' : 'A'; // Python: 97 if c > '`' else 65
                sb.Append((char)(((c - baseChar - n) % 26 + 26) % 26 + baseChar));
            }
            else
            {
                sb.Append(c);
            }
        }
        return sb.ToString() + Suffix;
    }

    /// <summary>Python <c>CFPROXY_DEFAULT_DOMAINS = [_dd(d) for d in _CFPROXY_ENC]</c>.</summary>
    public static IReadOnlyList<string> DefaultDomains { get; } =
        CfProxyEnc.Select(DecodeDomain).ToList();

    /// <summary>
    /// Python <c>_fetch_cfproxy_domain_list</c>: download the encoded list from
    /// GitHub raw (cache-busting random query, UA "tg-ws-proxy"), skip blank
    /// lines and '#' comments, decode each entry via <see cref="DecodeDomain"/>.
    /// Returns an empty list on any failure (mirrors the Python except branch).
    /// </summary>
    public static async Task<List<string>> FetchAsync(HttpClient http, CancellationToken ct = default)
    {
        try
        {
            var url = DomainsListUrl + "?" + RandomString(7);
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            req.Headers.TryAddWithoutValidation("User-Agent", "tg-ws-proxy");
            using var resp = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            resp.EnsureSuccessStatusCode();
            var text = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

            var result = new List<string>();
            foreach (var line in text.Split('\n'))
            {
                var trimmed = line.Trim();
                if (trimmed.Length == 0 || trimmed.StartsWith('#'))
                    continue;
                result.Add(DecodeDomain(trimmed));
            }
            return result;
        }
        catch
        {
            // Python logs a warning here; callers of this pure helper decide logging.
            return [];
        }
    }

    /// <summary>
    /// Python <c>_normalize_domain_pool</c>: trim+lowercase, drop invalid domains
    /// (<see cref="ProxyConfigValidator.IsValidDomain"/>) and duplicates.
    /// </summary>
    public static List<string> NormalizeDomainPool(IEnumerable<string> domains)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var normalized = new List<string>();
        foreach (var domain in domains)
        {
            var item = domain.Trim().ToLowerInvariant();
            if (!ProxyConfigValidator.IsValidDomain(item))
                continue;
            if (!seen.Add(item))
                continue;
            normalized.Add(item);
        }
        return normalized;
    }

    /// <summary>Python: <c>"".join(random.choices(string.ascii_letters, k=7))</c>.</summary>
    private static string RandomString(int length)
    {
        const string letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        var sb = new StringBuilder(length);
        for (var i = 0; i < length; i++)
            sb.Append(letters[RandomNumberGenerator.GetInt32(letters.Length)]);
        return sb.ToString();
    }
}
