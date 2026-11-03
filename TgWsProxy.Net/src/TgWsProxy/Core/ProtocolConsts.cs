namespace TgWsProxy.Core;

/// <summary>
/// MTProto obfuscated2 protocol constants — byte-for-byte port of
/// Python <c>proxy/utils.py</c> (lines with ZERO_64 … WS_PATH_TEST).
/// </summary>
public static class ProtocolConsts
{
    public static readonly byte[] Zero64 = new byte[64];

    public const int HandshakeLen = 64;
    public const int SkipLen = 8;
    public const int PrekeyLen = 32;
    public const int KeyLen = 32;
    public const int IvLen = 16;
    public const int ProtoTagPos = 56;
    public const int DcIdxPos = 60;

    public static readonly byte[] ProtoTagAbridged = { 0xEF, 0xEF, 0xEF, 0xEF };
    public static readonly byte[] ProtoTagIntermediate = { 0xEE, 0xEE, 0xEE, 0xEE };
    public static readonly byte[] ProtoTagSecure = { 0xDD, 0xDD, 0xDD, 0xDD };

    public const uint ProtoAbridgedInt = 0xEFEFEFEF;
    public const uint ProtoIntermediateInt = 0xEEEEEEEE;
    public const uint ProtoPaddedIntermediateInt = 0xDDDDDDDD;

    public static readonly byte[] ReservedFirstBytes = { 0xEF };

    public static readonly byte[][] ReservedStarts =
    {
        new byte[] { 0x48, 0x45, 0x41, 0x44 }, // HEAD
        new byte[] { 0x50, 0x4F, 0x53, 0x54 }, // POST
        new byte[] { 0x47, 0x45, 0x54, 0x20 }, // GET␠
        new byte[] { 0xEE, 0xEE, 0xEE, 0xEE },
        new byte[] { 0xDD, 0xDD, 0xDD, 0xDD },
        new byte[] { 0x16, 0x03, 0x01, 0x02 },
        new byte[] { 0x4F, 0x50, 0x54, 0x49 }, // OPTI
    };

    public static readonly byte[] ReservedContinue = { 0x00, 0x00, 0x00, 0x00 };

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
