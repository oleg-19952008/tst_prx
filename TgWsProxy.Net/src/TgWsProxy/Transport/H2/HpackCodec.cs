using System.Text;

namespace TgWsProxy.Transport.H2;

/// <summary>
/// HPACK encoder/decoder — RFC 7541. Supports integer primitives (§5.1),
/// literal string primitives with/without Huffman (§5.2), the 61-entry static
/// table (§2.3.1 / Appendix A, dynamic entries start at index 62) and a bounded
/// dynamic table (§2.3.2). This replaces the Python <c>hpack</c> dependency
/// used by <c>proxy/h2_transport.py</c> (PORT_PLAN.md §3 Phase B item 5,
/// checklist item 6).
/// </summary>
internal sealed class HpackCodec(int maxDynamicTableSize = 4096)
{
    private const int StaticTableLength = 61;
    private const int DynamicBase = StaticTableLength + 1; // index of first dynamic entry

    /// <summary>Wire size of one dynamic-table entry: name+value+32 (RFC 7541 §4.1).</summary>
    private static int EntrySize(string name, byte[] value) =>
        name.Length + value.Length + 32;

    // Most recently added entry first (lowest index) — RFC 7541 §2.3.2.
    private readonly LinkedList<(string Name, byte[] Value)> _dynamic = new();
    private int _dynamicSize;
    private int _maxDynamicTableSize = Math.Clamp(maxDynamicTableSize, 0, 1 << 20);

    public int MaxDynamicTableSize => _maxDynamicTableSize;
    public int DynamicTableSize => _dynamicSize;
    public int DynamicTableEntries => _dynamic.Count;

    /// <summary>
    /// RFC 7541 Appendix A static table. Index 0 is an unused placeholder so
    /// that <c>StaticTable[i]</c> corresponds to wire index <c>i</c>.
    /// </summary>
    internal static readonly (string Name, string Value)[] StaticTable =
    [
        ("", ""),  // index 0 placeholder
        new(":authority", ""),  // 1
        new(":method", "GET"),  // 2
        new(":method", "POST"),  // 3
        new(":path", "/"),  // 4
        new(":path", "/index.html"),  // 5
        new(":scheme", "http"),  // 6
        new(":scheme", "https"),  // 7
        new(":status", "200"),  // 8
        new(":status", "204"),  // 9
        new(":status", "206"),  // 10
        new(":status", "304"),  // 11
        new(":status", "400"),  // 12
        new(":status", "404"),  // 13
        new(":status", "500"),  // 14
        new("accept-charset", ""),  // 15
        new("accept-encoding", "gzip, deflate"),  // 16
        new("accept-language", ""),  // 17
        new("accept-ranges", ""),  // 18
        new("accept", ""),  // 19
        new("access-control-allow-origin", ""),  // 20
        new("age", ""),  // 21
        new("allow", ""),  // 22
        new("authorization", ""),  // 23
        new("cache-control", ""),  // 24
        new("content-disposition", ""),  // 25
        new("content-encoding", ""),  // 26
        new("content-language", ""),  // 27
        new("content-length", ""),  // 28
        new("content-location", ""),  // 29
        new("content-range", ""),  // 30
        new("content-type", ""),  // 31
        new("cookie", ""),  // 32
        new("date", ""),  // 33
        new("etag", ""),  // 34
        new("expect", ""),  // 35
        new("expires", ""),  // 36
        new("from", ""),  // 37
        new("host", ""),  // 38
        new("if-match", ""),  // 39
        new("if-modified-since", ""),  // 40
        new("if-none-match", ""),  // 41
        new("if-range", ""),  // 42
        new("if-unmodified-since", ""),  // 43
        new("last-modified", ""),  // 44
        new("link", ""),  // 45
        new("location", ""),  // 46
        new("max-forwards", ""),  // 47
        new("proxy-authenticate", ""),  // 48
        new("proxy-authorization", ""),  // 49
        new("range", ""),  // 50
        new("referer", ""),  // 51
        new("refresh", ""),  // 52
        new("retry-after", ""),  // 53
        new("server", ""),  // 54
        new("set-cookie", ""),  // 55
        new("strict-transport-security", ""),  // 56
        new("transfer-encoding", ""),  // 57
        new("user-agent", ""),  // 58
        new("vary", ""),  // 59
        new("via", ""),  // 60
        new("www-authenticate", ""),  // 61
    ];

    static HpackCodec()
    {
        if (StaticTable.Length != StaticTableLength + 1)
            throw new InvalidOperationException("HPACK static table must hold exactly 61 entries.");
    }

    // ------------------------------------------------------------------
    // Encoder
    // ------------------------------------------------------------------

    /// <summary>Encodes a complete header list into an HPACK block fragment.</summary>
    public byte[] Encode(IReadOnlyList<(string Name, byte[] Value)> headers, bool huffman = true)
    {
        var outBuffer = new List<byte>(256);
        foreach (var (name, value) in headers)
            AppendField(outBuffer, name.ToLowerInvariant(), value, huffman);
        return outBuffer.ToArray();
    }

    private void AppendField(List<byte> outBuffer, string name, byte[] value, bool huffman)
    {
        // Full (name+value) match in the static table → indexed representation.
        for (int i = 1; i <= StaticTableLength; i++)
        {
            ref readonly var entry = ref StaticTable[i];
            if (entry.Name == name && IsAsciiEqual(entry.Value, value))
            {
                AppendInteger(outBuffer, (ulong)i, 7, 0x80);
                return;
            }
        }

        // Full match in the dynamic table → indexed representation, N=6.
        int dynFull = FindDynamic(name, value);
        if (dynFull > 0)
        {
            AppendInteger(outBuffer, (ulong)dynFull, 6, 0xC0);
            return;
        }

        // Name-only reference (static, then dynamic)?
        int nameIndex = FindStaticName(name);
        if (nameIndex < 0)
            nameIndex = FindDynamicName(name);

        if (nameIndex >= 0)
        {
            // Literal field with incremental indexing, N=6, prefix=nameIndex.
            AppendInteger(outBuffer, (ulong)nameIndex, 6, 0x40);
        }
        else
        {
            // Literal field with incremental indexing, N=0, literal name.
            AppendInteger(outBuffer, 0, 6, 0x40);
            AppendString(outBuffer, Encoding.ASCII.GetBytes(name), huffman);
        }
        AppendString(outBuffer, value, huffman);
        AddDynamic(name, value);
    }

    private static bool IsAsciiEqual(string text, byte[] value)
    {
        if (text.Length != value.Length)
            return false;
        for (int i = 0; i < value.Length; i++)
            if (value[i] != (byte)text[i])
                return false;
        return true;
    }

    private static bool IsAsciiEqual(byte[] left, byte[] right) => left.AsSpan().SequenceEqual(right);

    private int FindStaticName(string name)
    {
        for (int i = 1; i <= StaticTableLength; i++)
            if (StaticTable[i].Name == name)
                return i;
        return -1;
    }

    private int FindDynamic(string name, byte[] value)
    {
        int index = DynamicBase;
        for (var node = _dynamic.First; node is not null; node = node.Next, index++)
            if (node.Value.Name == name && IsAsciiEqual(node.Value.Value, value))
                return index;
        return -1;
    }

    private int FindDynamicName(string name)
    {
        int index = DynamicBase;
        for (var node = _dynamic.First; node is not null; node = node.Next, index++)
            if (node.Value.Name == name)
                return index;
        return -1;
    }

    private void AddDynamic(string name, byte[] value)
    {
        _dynamic.AddFirst((name, value));
        _dynamicSize += EntrySize(name, value);
        while (_dynamicSize > _maxDynamicTableSize && _dynamic.Last is { } last)
        {
            _dynamicSize -= EntrySize(last.Value.Name, last.Value.Value);
            _dynamic.RemoveLast();
        }
    }

    /// <summary>Applies a peer SETTINGS_HEADER_TABLE_SIZE update.</summary>
    public void SetMaxDynamicTableSize(int size)
    {
        _maxDynamicTableSize = Math.Clamp(size, 0, 1 << 20);
        while (_dynamicSize > _maxDynamicTableSize && _dynamic.Last is { } last)
        {
            _dynamicSize -= EntrySize(last.Value.Name, last.Value.Value);
            _dynamic.RemoveLast();
        }
    }

    internal static void AppendInteger(List<byte> outBuffer, ulong value, int prefixBits, byte prefixMask)
    {
        ulong maxPrefix = (1UL << prefixBits) - 1;
        if (value < maxPrefix)
        {
            outBuffer.Add((byte)(prefixMask | (byte)value));
            return;
        }
        outBuffer.Add((byte)(prefixMask | (byte)maxPrefix));
        value -= maxPrefix;
        while (value >= 128)
        {
            outBuffer.Add((byte)((value & 0x7F) | 0x80));
            value >>= 7;
        }
        outBuffer.Add((byte)value);
    }

    internal static void AppendString(List<byte> outBuffer, byte[] data, bool huffman)
    {
        if (huffman)
        {
            int encodedLen = HpackHuffman.EncodedLength(data);
            byte[] encoded = new byte[encodedLen];
            HpackHuffman.Encode(data, encoded);
            AppendInteger(outBuffer, (ulong)encodedLen, 7, 0x80);
            outBuffer.AddRange(encoded);
        }
        else
        {
            AppendInteger(outBuffer, (ulong)data.Length, 7, 0x00);
            outBuffer.AddRange(data);
        }
    }

    // ------------------------------------------------------------------
    // Decoder
    // ------------------------------------------------------------------

    /// <summary>Decodes a complete HPACK block fragment into header fields.</summary>
    public List<HpackHeader> Decode(ReadOnlySpan<byte> block)
    {
        var result = new List<HpackHeader>();
        int pos = 0;
        while (pos < block.Length)
        {
            byte b = block[pos];
            if ((b & 0x80) != 0)
            {
                // Indexed header field, N=7.
                int index = (int)ReadInteger(block, ref pos, 7, 0x80);
                result.Add(IndexedAt(index));
            }
            else if ((b & 0xC0) == 0x40)
            {
                // Literal with incremental indexing, N=6.
                result.Add(ReadLiteral(block, ref pos, 6, indexing: true));
            }
            else if ((b & 0xE0) == 0x00 || (b & 0xF0) == 0x10)
            {
                // Literal without indexing (N=4) / never indexed (N=4, 0x10 pattern).
                result.Add(ReadLiteral(block, ref pos, 4, indexing: false));
            }
            else if ((b & 0xE0) == 0x20)
            {
                // Dynamic table size update, N=5.
                int size = (int)ReadInteger(block, ref pos, 5, 0x20);
                SetMaxDynamicTableSize(size);
            }
            else
            {
                throw new HpackException($"Invalid HPACK representation byte 0x{b:X2}.");
            }
        }
        return result;
    }

    private HpackHeader ReadLiteral(ReadOnlySpan<byte> block, ref int pos, int prefixBits, bool indexing)
    {
        byte prefixMask = (byte)((1 << prefixBits) - 1);
        int nameIndex = (int)ReadInteger(block, ref pos, prefixBits, prefixMask);
        string name;
        if (nameIndex == 0)
            name = Encoding.ASCII.GetString(ReadString(block, ref pos)).ToLowerInvariant();
        else
            name = IndexedAt(nameIndex).Name;
        byte[] value = ReadString(block, ref pos);
        if (indexing)
            AddDynamic(name, value);
        return new HpackHeader(name, value);
    }

    private HpackHeader IndexedAt(int index)
    {
        if (index >= 1 && index <= StaticTableLength)
        {
            ref readonly var entry = ref StaticTable[index];
            return new HpackHeader(entry.Name, Encoding.ASCII.GetBytes(entry.Value));
        }
        int dynPos = index - DynamicBase;
        if (dynPos >= 0 && dynPos < _dynamic.Count)
        {
            var node = _dynamic.First;
            for (int i = 0; i < dynPos && node is not null; i++, node = node.Next)
                ;
            if (node is not null)
                return new HpackHeader(node.Value.Name, node.Value.Value);
        }
        throw new HpackException($"HPACK index out of range: {index}.");
    }

    internal static ulong ReadInteger(ReadOnlySpan<byte> data, ref int pos, int prefixBits, byte prefixMask)
    {
        if (pos >= data.Length)
            throw new HpackException("HPACK integer truncated.");
        ulong maxPrefix = (1UL << prefixBits) - 1;
        ulong value = (uint)(data[pos++] & prefixMask);
        if (value < maxPrefix)
            return value;
        int shift = 0;
        while (true)
        {
            if (pos >= data.Length)
                throw new HpackException("HPACK integer truncated.");
            byte octet = data[pos++];
            value += (ulong)(octet & 0x7F) << shift;
            if ((octet & 0x80) == 0)
                return value;
            shift += 7;
            if (shift > 28)
                throw new HpackException("HPACK integer overflow.");
        }
    }

    internal static byte[] ReadString(ReadOnlySpan<byte> data, ref int pos)
    {
        if (pos >= data.Length)
            throw new HpackException("HPACK string truncated.");
        bool huffman = (data[pos] & 0x80) != 0;
        long length = (long)ReadInteger(data, ref pos, 7, 0x80);
        if (length < 0 || length > data.Length - pos)
            throw new HpackException("HPACK string length exceeds block.");
        ReadOnlySpan<byte> raw = data.Slice(pos, (int)length);
        pos += (int)length;
        return huffman ? HpackHuffman.Decode(raw) : raw.ToArray();
    }
}
