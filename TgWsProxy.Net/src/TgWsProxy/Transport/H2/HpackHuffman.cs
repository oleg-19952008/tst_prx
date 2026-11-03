using System.Buffers;
using System.Text;

namespace TgWsProxy.Transport.H2;

/// <summary>
/// HPACK string Huffman coding — RFC 7541 §5.2 and Appendix B.
/// Encoding is greedy over the canonical table; decoding walks a bitwise trie
/// built once from the same table. Byte-for-byte compatible with the Python
/// <c>hpack</c> dependency used by <c>proxy/h2_transport.py</c>.
/// </summary>
public static class HpackHuffman
{
    // RFC 7541 Appendix B: (code, bit-length) per symbol 0..256 (index 256 = EOS).
    private static readonly uint[] EncodeCodes =
    [
        0x1FF8u, 0x7FFFD8u, 0xFFFFFE2u, 0xFFFFFE3u, 0xFFFFFE4u, 0xFFFFFE5u, 0xFFFFFE6u, 0xFFFFFE7u,
        0xFFFFFE8u, 0xFFFFEAu, 0x3FFFFFFCu, 0xFFFFFE9u, 0xFFFFFEAu, 0x3FFFFFFDu, 0xFFFFFEBu, 0xFFFFFECu,
        0xFFFFFEDu, 0xFFFFFEEu, 0xFFFFFEFu, 0xFFFFFF0u, 0xFFFFFF1u, 0xFFFFFF2u, 0x3FFFFFFEu, 0xFFFFFF3u,
        0xFFFFFF4u, 0xFFFFFF5u, 0xFFFFFF6u, 0xFFFFFF7u, 0xFFFFFF8u, 0xFFFFFF9u, 0xFFFFFFAu, 0xFFFFFFBu,
        0x14u, 0x3F8u, 0x3F9u, 0xFFAu, 0x1FF9u, 0x15u, 0xF8u, 0x7FAu,
        0x3FAu, 0x3FBu, 0xF9u, 0x7FBu, 0xFAu, 0x16u, 0x17u, 0x18u,
        0x0u, 0x1u, 0x2u, 0x19u, 0x1Au, 0x1Bu, 0x1Cu, 0x1Du,
        0x1Eu, 0x1Fu, 0x5Cu, 0xFBu, 0x7FFCu, 0x20u, 0xFFBu, 0x3FCu,
        0x1FFAu, 0x21u, 0x5Du, 0x5Eu, 0x5Fu, 0x60u, 0x61u, 0x62u,
        0x63u, 0x64u, 0x65u, 0x66u, 0x67u, 0x68u, 0x69u, 0x6Au,
        0x6Bu, 0x6Cu, 0x6Du, 0x6Eu, 0x6Fu, 0x70u, 0x71u, 0x72u,
        0xFCu, 0x73u, 0xF7u, 0x1FFBu, 0x7FFF0u, 0x1FFCu, 0x3FFCu, 0x22u,
        0x7FFDu, 0x3u, 0x23u, 0x4u, 0x24u, 0x5u, 0x25u, 0x26u,
        0x27u, 0x6u, 0x74u, 0x75u, 0x28u, 0x29u, 0x2Au, 0x7u,
        0x2Bu, 0x76u, 0x2Cu, 0x8u, 0x9u, 0x2Du, 0x77u, 0x78u,
        0x79u, 0x7Au, 0x7Bu, 0x7FFEu, 0x7FCu, 0x3FFDu, 0x1FFDu, 0xFFFFFFCu,
        0xFFFE6u, 0x3FFFD2u, 0xFFFE7u, 0xFFFE8u, 0x3FFFD3u, 0x3FFFD4u, 0x3FFFD5u, 0x7FFFD9u,
        0x3FFFD6u, 0x7FFFDAu, 0x7FFFDBu, 0x7FFFDCu, 0x7FFFDDu, 0x7FFFDEu, 0xFFFFEBu, 0x7FFFDFu,
        0xFFFFECu, 0xFFFFEDu, 0x3FFFD7u, 0x7FFFE0u, 0xFFFFEEu, 0x7FFFE1u, 0x7FFFE2u, 0x7FFFE3u,
        0x7FFFE4u, 0x1FFFDCu, 0x3FFFD8u, 0x7FFFE5u, 0x3FFFD9u, 0x7FFFE6u, 0x7FFFE7u, 0xFFFFEFu,
        0x3FFFDAu, 0x1FFFDDu, 0xFFFE9u, 0x3FFFDBu, 0x3FFFDCu, 0x7FFFE8u, 0x7FFFE9u, 0x1FFFDEu,
        0x7FFFEAu, 0x3FFFDDu, 0x3FFFDEu, 0xFFFFF0u, 0x1FFFDFu, 0x3FFFDFu, 0x7FFFEBu, 0x7FFFECu,
        0x1FFFE0u, 0x1FFFE1u, 0x3FFFE0u, 0x1FFFE2u, 0x7FFFEDu, 0x3FFFE1u, 0x7FFFEEu, 0x7FFFEFu,
        0xFFFEAu, 0x3FFFE2u, 0x3FFFE3u, 0x3FFFE4u, 0x7FFFF0u, 0x3FFFE5u, 0x3FFFE6u, 0x7FFFF1u,
        0x3FFFFE0u, 0x3FFFFE1u, 0xFFFEBu, 0x7FFF1u, 0x3FFFE7u, 0x7FFFF2u, 0x3FFFE8u, 0x1FFFFECu,
        0x3FFFFE2u, 0x3FFFFE3u, 0x3FFFFE4u, 0x7FFFFDEu, 0x7FFFFDFu, 0x3FFFFE5u, 0xFFFFF1u, 0x1FFFFEDu,
        0x7FFF2u, 0x1FFFE3u, 0x3FFFFE6u, 0x7FFFFE0u, 0x7FFFFE1u, 0x3FFFFE7u, 0x7FFFFE2u, 0xFFFFF2u,
        0x1FFFE4u, 0x1FFFE5u, 0x3FFFFE8u, 0x3FFFFE9u, 0xFFFFFFDu, 0x7FFFFE3u, 0x7FFFFE4u, 0x7FFFFE5u,
        0xFFFECu, 0xFFFFF3u, 0xFFFEDu, 0x1FFFE6u, 0x3FFFE9u, 0x1FFFE7u, 0x1FFFE8u, 0x7FFFF3u,
        0x3FFFEAu, 0x3FFFEBu, 0x1FFFFEEu, 0x1FFFFEFu, 0xFFFFF4u, 0xFFFFF5u, 0x3FFFFEAu, 0x7FFFF4u,
        0x3FFFFEBu, 0x7FFFFE6u, 0x3FFFFECu, 0x3FFFFEDu, 0x7FFFFE7u, 0x7FFFFE8u, 0x7FFFFE9u, 0x7FFFFEAu,
        0x7FFFFEBu, 0xFFFFFFEu, 0x7FFFFECu, 0x7FFFFEDu, 0x7FFFFEEu, 0x7FFFFEFu, 0x7FFFFF0u, 0x3FFFFEEu,
        0x3FFFFFFFu,
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
        // Insert all 257 symbols including EOS (index 256) so the decoder can
        // recognise a full-EOS input and reject it explicitly.
        for (int s = 0; s <= 256; s++)
        {
            uint code = EncodeCodes[s];
            int bits = EncodeLengths[s];
            int node = 0;
            // Traverse MSB -> LSB: codes are emitted most-significant-bit first.
            for (int i = 0; i < bits; i++)
            {
                int bit = (int)((code >> (bits - 1 - i)) & 1);
                // NOTE: do not hold a ref into the lists — Add() below may
                // reallocate their backing arrays. Index through the lists instead.
                int next = bit == 0 ? child0[node] : child1[node];
                if (next < 0)
                {
                    next = child0.Count;
                    child0.Add(-1);
                    child1.Add(-1);
                    symbol.Add(-1);
                    if (bit == 0) child0[node] = next; else child1[node] = next;
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
            int bitsSinceSymbol = 0;
            bool allOnes = true;
            long totalBits = (long)src.Length * 8;
            while (bitsConsumed < totalBits)
            {
                int bit = (src[bitsConsumed >> 3] >> (7 - (bitsConsumed & 7))) & 1;
                bitsConsumed++;
                bitsSinceSymbol++;
                if (bit == 0) allOnes = false;

                int next = bit == 0 ? TrieChild0[node] : TrieChild1[node];
                if (next < 0)
                    throw new HpackException("Invalid Huffman code.");
                node = next;

                int sym = TrieSymbol[node];
                if (sym == 256)
                    throw new HpackException("EOS in Huffman string.");
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
                    bitsSinceSymbol = 0;
                    allOnes = true;
                }
            }
            // Trailing bits must be a proper prefix of EOS, i.e. at most 7 all-1
            // bits after the last complete symbol (RFC 7541 §5.2). Any run of
            // <=7 ones is by definition an EOS prefix, so no trie walk is needed.
            if (bitsSinceSymbol > 7 || !allOnes)
                throw new HpackException("Invalid Huffman padding.");
            return buffer.AsSpan(0, outLen).ToArray();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    public static string DecodeAscii(ReadOnlySpan<byte> src) =>
        Encoding.ASCII.GetString(Decode(src));
}
