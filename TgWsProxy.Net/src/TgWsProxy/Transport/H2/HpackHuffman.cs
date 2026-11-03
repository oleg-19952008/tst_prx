using System.Buffers;
using System.Text;

namespace TgWsProxy.Transport.H2;

/// <summary>
/// HPACK string Huffman coding — RFC 7541 §5.2 and Appendix B.
/// Encoding is greedy over the canonical table; decoding walks a bitwise trie
/// built once from the same table. Byte-for-byte compatible with the Python
/// <c>hpack</c> dependency used by <c>proxy/h2_transport.py</c>.
/// </summary>
internal static class HpackHuffman
{
    // RFC 7541 Appendix B: (code, bit-length) per symbol 0..256 (index 256 = EOS).
    private static readonly uint[] EncodeCodes =
    [
        0x1FF8, 0x7FFFD8, 0xFFFFFE2, 0xFFFFFE3, 0xFFFFFE4, 0xFFFFFE5,
        0xFFFFFE6, 0xFFFFFE7, 0xFFFFFE8, 0xFFFFEA, 0x3FFFFFFC, 0xFFFFFE9,
        0xFFFFFEA, 0x3FFFFFFD, 0xFFFFFEB, 0xFFFFFEC, 0xFFFFFED, 0xFFFFFEE,
        0xFFFFFEF, 0xFFFFFF0, 0xFFFFFF1, 0xFFFFFF2, 0x3FFFFFFE, 0xFFFFFF3,
        0xFFFFFF4, 0xFFFFFF5, 0xFFFFFF6, 0xFFFFFF7, 0xFFFFFF8, 0xFFFFFF9,
        0xFFFFFFA, 0xFFFFFFB, 0x14, 0x3F8, 0x3F9, 0xFFA,
        0x1FF9, 0x15, 0xF8, 0x7FA, 0x3FA, 0x3FB,
        0xF9, 0x7FB, 0xFA, 0x16, 0x17, 0x18,
        0x0, 0x1, 0x2, 0x19, 0x1A, 0x1B,
        0x1C, 0x1D, 0x1E, 0x1F, 0x5C, 0xFB,
        0x7FFC, 0x20, 0xFFB, 0x3FC, 0x1FFA, 0x21,
        0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62,
        0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E,
        0x6F, 0x70, 0x71, 0x72, 0xFC, 0x73,
        0xFD, 0x1FFB, 0x7FFF0, 0x1FFC, 0x3FFC, 0x22,
        0x7FFD, 0x3, 0x23, 0x4, 0x24, 0x5,
        0x25, 0x26, 0x27, 0x6, 0x74, 0x75,
        0x28, 0x29, 0x2A, 0x7, 0x2B, 0x76,
        0x2C, 0x8, 0x9, 0x2D, 0x77, 0x78,
        0x79, 0x7A, 0x7B, 0x7FFE, 0x7FC, 0x3FFD,
        0x1FFD, 0xFFFFFFC, 0xFFFE6, 0x3FFFD2, 0xFFFE7, 0xFFFE8,
        0x3FFFD3, 0x3FFFD4, 0x3FFFD5, 0x7FFFD9, 0x3FFFD6, 0x7FFFDA,
        0x7FFFDB, 0x7FFFDC, 0x7FFFDD, 0x7FFFDE, 0xFFFFEB, 0x7FFFDF,
        0xFFFFEC, 0xFFFFED, 0x3FFFD7, 0x7FFFE0, 0xFFFFEE, 0x7FFFE1,
        0x7FFFE2, 0x7FFFE3, 0x7FFFE4, 0x1FFFDC, 0x3FFFD8, 0x7FFFE5,
        0x3FFFD9, 0x7FFFE6, 0x7FFFE7, 0xFFFFEF, 0x3FFFDA, 0x1FFFDD,
        0xFFFE9, 0x3FFFDB, 0x3FFFDC, 0x7FFFE8, 0x7FFFE9, 0x1FFFDE,
        0x7FFFEA, 0x3FFFDD, 0x3FFFDE, 0xFFFFF0, 0x1FFFDF, 0x3FFFDF,
        0x7FFFEB, 0x7FFFEC, 0x1FFFE0, 0x1FFFE1, 0x3FFFE0, 0x1FFFE2,
        0x7FFFED, 0x3FFFE1, 0x7FFFEE, 0x7FFFEF, 0xFFFEA, 0x3FFFE2,
        0x3FFFE3, 0x3FFFE4, 0x7FFFF0, 0x3FFFE5, 0x3FFFE6, 0x7FFFF1,
        0x3FFFFE0, 0x3FFFFE1, 0xFFFEB, 0x7FFF1, 0x3FFFE7, 0x7FFFF2,
        0x3FFFE8, 0x1FFFFEC, 0x3FFFFE2, 0x3FFFFE3, 0x3FFFFE4, 0x7FFFFDE,
        0x7FFFFDF, 0x3FFFFE5, 0xFFFFF1, 0x1FFFFED, 0x7FFF2, 0x1FFFE3,
        0x3FFFFE6, 0x7FFFFE0, 0x7FFFFE1, 0x3FFFFE7, 0x7FFFFE2, 0xFFFFF2,
        0x1FFFE4, 0x1FFFE5, 0x3FFFFE8, 0x3FFFFE9, 0xFFFFFFD, 0x7FFFFE3,
        0x7FFFFE4, 0x7FFFFE5, 0xFFFEC, 0xFFFFF3, 0xFFFED, 0x1FFFE6,
        0x3FFFE9, 0x1FFFE7, 0x1FFFE8, 0x7FFFF3, 0x3FFFEA, 0x3FFFEB,
        0x1FFFFEE, 0x1FFFFEF, 0xFFFFF4, 0xFFFFF5, 0x3FFFFEA, 0x7FFFF4,
        0x3FFFFEB, 0x7FFFFE6, 0x3FFFFEC, 0x3FFFFED, 0x7FFFFE7, 0x7FFFFE8,
        0x7FFFFE9, 0x7FFFFEA, 0x7FFFFEB, 0xFFFFFFE, 0x7FFFFEC, 0x7FFFFED,
        0x7FFFFEE, 0x7FFFFEF, 0x7FFFFF0, 0x3FFFFEE, 0x3FFFFFFF,
    ];

    private static readonly byte[] EncodeLengths =
    [
        13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28,
        28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28,
        28, 28, 28, 28, 28, 28, 28, 28, 6, 10, 10, 12,
        13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,
        5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8,
        15, 6, 12, 10, 13, 6, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,
        15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7,
        6, 6, 6, 5, 6, 7, 6, 5, 5, 6, 7, 7,
        7, 7, 7, 15, 11, 14, 13, 28, 20, 22, 20, 20,
        22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
        24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23,
        22, 23, 23, 24, 22, 21, 20, 22, 22, 23, 23, 21,
        23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21,
        23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
        26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27,
        27, 26, 24, 25, 19, 21, 26, 27, 27, 26, 27, 24,
        21, 21, 26, 26, 28, 27, 27, 27, 20, 24, 20, 21,
        22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
        26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27,
        27, 27, 27, 26, 30,
    ];

    /// <summary>Decoding trie node: children[bit] index or -1; symbol != -1 marks a leaf.</summary>
    private static readonly int[] TrieChild0;
    private static readonly int[] TrieChild1;
    private static readonly int[] TrieSymbol;

    static HpackHuffman()
    {
        // Build the binary trie for decoding. Root = node 0.
        var child0 = new List<int> { -1 };
        var child1 = new List<int> { -1 };
        var symbol = new List<int> { -1 };
        for (int s = 0; s < 256; s++)
        {
            uint code = EncodeCodes[s];
            int bits = EncodeLengths[s];
            int node = 0;
            for (int i = bits - 1; i >= 0; i--)
            {
                int bit = (int)((code >> i) & 1);
                ref int next = ref (bit == 0 ? ref child0[node] : ref child1[node]);
                if (next < 0)
                {
                    next = child0.Count;
                    child0.Add(-1);
                    child1.Add(-1);
                    symbol.Add(-1);
                }
                node = next;
            }
            symbol[node] = s;
        }
        TrieChild0 = child0.ToArray();
        TrieChild1 = child1.ToArray();
        TrieSymbol = symbol.ToArray();
    }

    /// <summary>Huffman-encoded length of <paramref name="data"/> in bytes (rounded up).</summary>
    public static int EncodedLength(ReadOnlySpan<byte> data)
    {
        long bits = 0;
        foreach (byte b in data)
            bits += EncodeLengths[b];
        return (int)((bits + 7) / 8);
    }

    /// <summary>Encodes <paramref name="data"/> into <paramref name="dest"/> (EOS padding filled with 1-bits).</summary>
    public static int Encode(ReadOnlySpan<byte> data, Span<byte> dest)
    {
        int needed = EncodedLength(data);
        if (dest.Length < needed)
            throw new ArgumentException("Destination too small for Huffman output.", nameof(dest));
        dest.Slice(0, needed).Clear();
        int bitPos = 0;
        foreach (byte b in data)
        {
            uint code = EncodeCodes[b];
            int bits = EncodeLengths[b];
            for (int i = bits - 1; i >= 0; i--)
            {
                if (((code >> i) & 1) != 0)
                    dest[bitPos >> 3] |= (byte)(0x80 >> (bitPos & 7));
                bitPos++;
            }
        }
        // Pad the remainder of the last byte with 1 bits (EOS prefix, RFC 7541 §5.2).
        while (bitPos < needed * 8)
        {
            dest[bitPos >> 3] |= (byte)(0x80 >> (bitPos & 7));
            bitPos++;
        }
        return needed;
    }

    /// <summary>
    /// Decodes a Huffman-coded block. Throws <see cref="HpackException"/> on an
    /// invalid code, an EOS symbol, or padding that is not the all-1s prefix.
    /// </summary>
    public static byte[] Decode(ReadOnlySpan<byte> src, int maxOutputBytes = 128 * 1024)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(Math.Max(64, src.Length * 2));
        try
        {
            int outLen = 0;
            int node = 0;
            int bitsConsumed = 0;
            long totalBits = (long)src.Length * 8;
            while (bitsConsumed < totalBits)
            {
                int bit = (src[bitsConsumed >> 3] >> (7 - (bitsConsumed & 7))) & 1;
                bitsConsumed++;
                node = bit == 0 ? TrieChild0[node] : TrieChild1[node];
                if (node < 0)
                    throw new HpackException("Invalid Huffman code.");
                int sym = TrieSymbol[node];
                if (sym >= 0)
                {
                    if (outLen >= buffer.Length)
                    {
                        var grown = ArrayPool<byte>.Shared.Rent(buffer.Length * 2);
                        buffer.AsSpan().CopyTo(grown);
                        ArrayPool<byte>.Shared.Return(buffer);
                        buffer = grown;
                    }
                    if (outLen >= maxOutputBytes)
                        throw new HpackException("Huffman output exceeds bound.");
                    buffer[outLen++] = (byte)sym;
                    node = 0;
                }
            }
            // End state must be the root, or sit at most 7 zero-padded bits away
            // from an EOS leaf reached through all-1 padding (RFC 7541 §5.2).
            if (node != 0 && !IsPartialLeaf(node))
                throw new HpackException("Invalid Huffman padding.");
            return buffer.AsSpan(0, outLen).ToArray();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static bool IsPartialLeaf(int node)
    {
        // A dangling node is legal only when following 1-bits leads to EOS within <= 7 steps.
        int probe = node;
        for (int i = 0; i < 7; i++)
        {
            probe = TrieChild1[probe];
            if (probe < 0) return false;
            if (TrieSymbol[probe] == 256) return true;
            if (TrieSymbol[probe] >= 0) return false;
        }
        return false;
    }

    public static string DecodeAscii(ReadOnlySpan<byte> src) =>
        Encoding.ASCII.GetString(Decode(src));
}
