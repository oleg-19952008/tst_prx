namespace TgWsProxy.Core;

/// <summary>
/// Non-crypto protocol constants — DC IPs, WS domains/paths. The obfuscated2
/// handshake constants (HANDSHAKE_LEN, PROTO_TAG_*, RESERVED_*) live solely in
/// <see cref="TgWsProxy.Crypto.Obfuscated2"/> to avoid a duplicated layer.
/// Port of the remaining Python <c>proxy/utils.py</c> values.
/// </summary>
public static class ProtocolConsts
{
    /// <summary>Fallback DC IPs — from Python <c>DC_DEFAULT_IPS</c>.</summary>
    public static readonly IReadOnlyDictionary<int, string> DcDefaultIps =
        new Dictionary<int, string>
        {
            [1] = "149.154.175.50",
            [2] = "149.154.167.51",
            [3] = "149.154.175.100",
            [4] = "149.154.167.91",
            [5] = "149.154.171.5",
            [203] = "91.105.192.100",
        };

    /// <summary>Test DC IPs — from Python <c>DC_TEST_IPS</c>.</summary>
    public static readonly IReadOnlyDictionary<int, string> DcTestIps =
        new Dictionary<int, string>
        {
            [1] = "149.154.175.10",
            [2] = "149.154.167.40",
            [3] = "149.154.175.117",
        };

    public const string WsPath = "/apiws";
    public const string WsPathTest = WsPath + "_test";

    /// <summary>SNI domains used for pooled WS connections — Python <c>ws_domains()</c>.</summary>
    public static IReadOnlyList<string> WsDomains(int dc, bool isMedia)
    {
        if (dc == 203) dc = 2;
        return isMedia
            ? new[] { $"kws{dc}-1.web.telegram.org", $"kws{dc}.web.telegram.org" }
            : new[] { $"kws{dc}.web.telegram.org" };
    }

    public static string HumanBytes(double n)
    {
        foreach (var unit in new[] { "B", "KB", "MB", "GB" })
        {
            if (Math.Abs(n) < 1024) return $"{n:F1}{unit}";
            n /= 1024;
        }
        return $"{n:F1}TB";
    }
}
