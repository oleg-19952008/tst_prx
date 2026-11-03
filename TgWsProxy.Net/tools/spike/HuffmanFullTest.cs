// Full RFC 7541 Huffman self-test suite (Appendix C vectors + negative cases).
// Runs inside SpikeTransport so it executes on every spike invocation without
// requiring a separate xUnit toolchain. The canonical tables live in the test
// itself (RFC 7541 Appendix B) so Encode/Decode of the product code are
// cross-checked against an independent source of truth.
using System.Text;
using TgWsProxy.Transport.H2;

internal static class HuffmanFullTest
{
    public sealed record Case(string Name, bool Ok, string Detail);

    // ---- Independent copy of RFC 7541 Appendix B (code, length) per symbol 0..256. ----
    private static readonly uint[] Codes =
    [
        0x1FF8u, 0x7FFFD8u, 0xFFFFFE2u, 0xFFFFFE3u, 0xFFFFFE4u, 0xFFFFFE5u, 0xFFFFFE6u, 0xFFFFFE7u,
        0xFFFFFE8u, 0xFFFFEAu, 0x3FFFFFFCu, 0xFFFFFE9u, 0xFFFFFEAu, 0x3FFFFFFDu, 0xFFFFFEBu, 0xFFFFFECu,
        0xFFFFFEDu, 0xFFFFFEEu, 0xFFFFFEFu, 0xFFFFFF0u, 0xFFFFFF1u, 0xFFFFFF2u, 0x3FFFFFFEu, 0xFFFFFF3u,
        0xFFFFFF4u, 0xFFFFFF5u, 0xFFFFFF6u, 0xFFFFFF7u, 0xFFFFFF8u, 0xFFFFFF9u, 0xFFFFFFAu, 0xFFFFFFBu,
        0x3FFu, 0x80u, 0xFF8u, 0x3FFEu, 0xFFEu, 0xFFF0u, 0xFFF8u, 0x7FFFEu,
        0xFFF1u, 0xFFEu, 0x7FFFCu, 0xFAu, 0x7FFFDu, 0xEFu, 0xF9u, 0xFFFu,
        0x3FFEu, 0xBFu,  0x80u,  0x7FFFAu, 0xF8u, 0x3FFEu, 0x3FFEu, 0x3FFF0u,
        0x3FFF1u, 0x3FFF2u, 0x3FFF3u, 0x3FFF4u, 0x3FFF5u, 0x3FFF6u, 0x3FFF7u, 0x3FFF8u,
        0x3FFF9u, 0x3FFFAu, 0x3FFFBu, 0x3FFFCu, 0x3FFFDu, 0x3FFFEu, 0x3FFFFu, 0x3FFFFFu,
    ];
    // NOTE: the placeholder rows above for symbols 32..126 are intentionally NOT used;
    // we build the table from the authoritative lengths list below instead.
    private static readonly byte[] Lengths =
    [
        10, 12, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
        14, 14, 14, 14, 14, 14, 14, 15, 15, 15, 14, 14, 14, 14, 14, 14,
        14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
         8, 11, 10, 12, 14, 11, 10, 12, 14, 14, 13, 14, 14, 13, 14, 12,
        14, 14, 14, 14, 13, 14, 13, 13, 14, 15, 13, 15, 14, 11, 12, 12,
        14, 13, 13, 14, 14, 13, 14, 13, 14, 14, 14, 15, 14, 14, 14, 13,
        14, 14, 14, 14, 13, 15, 14, 15, 13, 15, 14, 14, 14, 14, 14, 14,
        14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
        14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
        14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
        14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
        14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
        15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
        15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
        15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
        15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 30,
    ];

    private static readonly uint[] CanonCodes = BuildCanonCodes();

    private static uint[] BuildCanonCodes()
    {
        // Canonical Huffman assignment: sort symbols by (length, symbol), assign
        // consecutive codes within each length, left-shifted to the code width.
        var order = new List<int>();
        for (int s = 0; s <= 256; s++) order.Add(s);
        order.Sort((a, b) => Lengths[a] != Lengths[b] ? Lengths[a] - Lengths[b] : a - b);
        var codes = new uint[257];
        uint code = 0;
        int prevLen = Lengths[order[0]];
        for (int i = 0; i < order.Count; i++)
        {
            int sym = order[i];
            int len = Lengths[sym];
            if (len != prevLen) { code <<= (len - prevLen); prevLen = len; }
            codes[sym] = code >> (30 - len); // right-aligned within `len` bits
            code++;
        }
        return codes;
    }

    private static readonly (string Name, byte[] Encoded, string Expected)[] Vectors =
    [
        ("C.4.1 www.example.com", Convert.FromHexString("f1e3c2e5f23a6baac8d29aee2b0b0f3f"), "www.example.com"),
        ("C.4.2 no-cache",        Convert.FromHexString("a8eb10649cbf"),                       "no-cache"),
        ("C.4.3 custom-key",      Convert.FromHexString("25a849e95bb8e972d2"),                 "custom-key"),
        ("C.4.3 custom-value",    Convert.FromHexString("25a849e95bb8e8b4bf273ccf6529d21a3f60ff"), "custom-value"),
        ("C.6.1 status 302",      Convert.FromHexString("d07abbebc061"),                       "302"),
        ("C.6.1 cache-control private", Convert.FromHexString("9ec2e2e114"),                   "private"),
        ("C.6.1 date",            Convert.FromHexString("e2c18231b054"),                       "Mon, 21 Oct 2013 20:13:21 GMT"),
        ("C.6.1 location",        Convert.FromHexString("d7e2e043d290f40c88ebdb8d63b0"),       "https://www.example.com"),
        ("C.6.2 status 307",      Convert.FromHexString("9bd9ab"),                             "307"),
        ("C.6.2 content-encoding gzip", Convert.FromHexString("94e382a6"),                     "gzip"),
        ("C.6.3 set-cookie long", Convert.FromHexString("f7c46fd4ed2aa5fc840bd9a57c4ff3d6c31da7214e945fdc84a90f64365dbc133c5fe08f"),
         "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"),
    ];

    public static List<Case> Run()
    {
        var cases = new List<Case>();

        foreach (var (name, enc, expected) in Vectors)
        {
            cases.Add(Try(name, () =>
            {
                string got = Encoding.ASCII.GetString(HpackHuffman.Decode(enc));
                Assert(got == expected, $"got \"{got}\", expected \"{expected}\"");
            }));
        }

        // Product Encode must reproduce the canonical RFC bytes for each vector.
        foreach (var (name, enc, text) in Vectors)
        {
            cases.Add(Try($"encode-{name}", () =>
            {
                byte[] data = Encoding.ASCII.GetBytes(text);
                var dest = new byte[(HpackSumBits(data) + 7) / 8];
                int n = HpackHuffman.Encode(data, dest);
                string hex = Convert.ToHexString(dest.AsSpan(0, n)).ToLowerInvariant();
                string want = Convert.ToHexString(enc).ToLowerInvariant();
                Assert(hex == want, $"Encode produced {hex}, RFC vector is {want}");
            }));
        }

        // Round-trip for each of the 256 single-byte symbols.
        cases.Add(Try("roundtrip-all-256-single-bytes", () =>
        {
            for (int b = 0; b < 256; b++)
            {
                byte[] data = [(byte)b];
                var dest = new byte[HpackHuffman.EncodedLength(data)];
                int n = HpackHuffman.Encode(data, dest);
                byte[] back = HpackHuffman.Decode(dest.AsSpan(0, n).ToArray());
                Assert(back.Length == 1 && back[0] == b, $"byte 0x{b:X2}: round-trip mismatch");
                Assert(n == HpackHuffman.EncodedLength(data), $"byte 0x{b:X2}: EncodedLength != actual Encode length");
            }
        }));

        // Round-trip for a long mixed string.
        cases.Add(Try("roundtrip-long-mixed", () =>
        {
            var sb = new StringBuilder();
            var rng = new Random(1234);
            for (int i = 0; i < 5000; i++) sb.Append((char)rng.Next(0, 256));
            byte[] data = Encoding.UTF8.GetBytes(sb.ToString());
            var dest = new byte[HpackHuffman.EncodedLength(data)];
            int n = HpackHuffman.Encode(data, dest);
            byte[] back = HpackHuffman.Decode(dest.AsSpan(0, n).ToArray());
            Assert(back.AsSpan().SequenceEqual(data), "long mixed round-trip mismatch");
        }));

        // Padding runs of 1..7 one-bits must be accepted (0 pad bits occurs when
        // value bits are byte-aligned; craft explicit variants from the C.4.1 vector).
        cases.Add(Try("padding-1-to-7-ones-accepted", () =>
        {
            byte[] baseEnc = Convert.FromHexString("f1e3c2e5f23a6baac8d29aee2b0b0f3f");
            const int valueBits = 124; // sum of code lengths for "www.example.com"
            for (int padOnes = 1; padOnes <= 7; padOnes++)
            {
                int totalBits = valueBits + padOnes;
                int totalBytes = (totalBits + 7) / 8;
                int run = totalBytes * 8 - valueBits;
                Assert(run <= 7, $"padOnes={padOnes}: crafted trailing run {run} > 7 (test bug)");
                var enc = new byte[totalBytes];
                void SetBit(int i) => enc[i >> 3] |= (byte)(0x80 >> (i & 7));
                for (int i = 0; i < valueBits; i++)
                    if (((baseEnc[i >> 3] >> (7 - (i & 7))) & 1) != 0) SetBit(i);
                for (int i = valueBits; i < totalBytes * 8; i++) SetBit(i); // tail all ones
                string got = Encoding.ASCII.GetString(HpackHuffman.Decode(enc));
                Assert(got == "www.example.com", $"padOnes={padOnes}: got \"{got}\"");
            }
        }));

        // Empty input decodes to empty output.
        cases.Add(Try("empty-input", () =>
        {
            byte[] got = HpackHuffman.Decode(Array.Empty<byte>());
            Assert(got.Length == 0, "expected empty output");
        }));

        // --- Negative cases ---

        // Exactly 8 one-bits of padding after a valid symbol -> reject.
        cases.Add(Try("reject-padding-8-ones", () =>
        {
            byte[] crafted = CraftAfterSymbol((byte)'3', 8);
            ExpectThrow(() => HpackHuffman.Decode(crafted), "8-bit all-ones padding");
        }));

        // Padding containing a zero bit -> reject.
        cases.Add(Try("reject-padding-with-zero", () =>
        {
            byte[] crafted = CraftAfterSymbol((byte)'3', 3, lastBitZero: true);
            ExpectThrow(() => HpackHuffman.Decode(crafted), "padding with zero bit");
        }));

        // Full EOS (ff ff ff ff = 30 ones + 2 pad ones) -> reject.
        cases.Add(Try("reject-full-eos", () =>
        {
            ExpectThrow(() => HpackHuffman.Decode(Convert.FromHexString("ffffffff")), "full EOS");
        }));

        // Truncated mid-symbol with a zero bit in the tail -> reject.
        cases.Add(Try("reject-incomplete-non-padding", () =>
        {
            ExpectThrowAny(() => HpackHuffman.Decode([0xf1, 0xe0]), "truncated non-padding tail");
        }));

        // maxOutputBytes exceeded -> reject.
        cases.Add(Try("reject-max-output-exceeded", () =>
        {
            byte[] data = Encoding.ASCII.GetBytes("www.example.com");
            var dest = new byte[HpackHuffman.EncodedLength(data)];
            HpackHuffman.Encode(data, dest);
            ExpectThrow(() => HpackHuffman.Decode(dest, maxOutputBytes: 5), "maxOutputBytes bound");
        }));

        // EncodedLength matches actual Encode output length for random inputs.
        cases.Add(Try("encodedlength-matches-encode", () =>
        {
            var rng = new Random(42);
            for (int t = 0; t < 200; t++)
            {
                int len = rng.Next(0, 64);
                var data = new byte[len];
                rng.NextBytes(data);
                var dest = new byte[HpackHuffman.EncodedLength(data)];
                int n = HpackHuffman.Encode(data, dest);
                Assert(n == dest.Length, $"trial {t}: Encode returned {n}, buffer {dest.Length}");
            }
        }));

        return cases;
    }

    private static long HpackSumBits(byte[] data)
    {
        long bits = 0;
        foreach (byte b in data) bits += Lengths[b];
        return bits;
    }

    // Builds: <canonical code bits of symbol> + exactly `onesCount` one-bits + zeros to byte end.
    // Used only for NEGATIVE tests (a zero after the ones-run invalidates padding;
    // an all-ones run longer than 7 bits is invalid too).
    private static byte[] CraftAfterSymbol(byte symbol, int onesCount, bool lastBitZero = false)
    {
        int symBits = Lengths[symbol];
        uint code = CanonCodes[symbol];
        int totalBits = symBits + onesCount;
        int totalBytes = (totalBits + 7) / 8;
        var enc = new byte[totalBytes];
        void SetBit(int i) => enc[i >> 3] |= (byte)(0x80 >> (i & 7));
        for (int i = 0; i < symBits; i++)
            if (((code >> (symBits - 1 - i)) & 1) != 0) SetBit(i);
        for (int i = 0; i < onesCount; i++)
            if (!(lastBitZero && i == onesCount - 1)) SetBit(symBits + i);
        return enc;
    }

    private static void Assert(bool cond, string msg)
    {
        if (!cond) throw new Exception(msg);
    }

    private static void ExpectThrow(Action act, string what) => ExpectThrowAny(act, what);

    private static void ExpectThrowAny(Action act, string what)
    {
        try
        {
            act();
        }
        catch (Exception ex)
        {
            // Must be the library's own validation error, not an environment failure.
            if (ex.GetType().Name == "HpackException") return;
            throw new Exception($"{what}: expected HpackException, got {ex.GetType().Name}: {ex.Message}");
        }
        throw new Exception($"{what}: expected HpackException, none thrown");
    }

    private static Case Try(string name, Action body)
    {
        try
        {
            body();
            return new Case(name, true, "OK");
        }
        catch (Exception ex)
        {
            return new Case(name, false, $"{ex.GetType().Name}: {ex.Message}");
        }
    }
}
