using System.Buffers.Binary;
using TgWsProxy.Crypto;

namespace TgWsProxy.Transport;

/// <summary>
/// Splits TCP stream data into individual MTProto transport packets so each can
/// be sent as a separate WS frame — direct port of Python <c>bridge.py::MsgSplitter</c>.
/// Operates on ciphertext chunks while consuming packet lengths from the matching
/// plaintext stream (both are kept in lockstep by the caller).
/// </summary>
public sealed class MsgSplitter
{
    private readonly uint _proto;
    private readonly MemoryStream _cipherBuf = new();
    private readonly MemoryStream _plainBuf = new();
    private bool _disabled;

    public MsgSplitter(uint protoInt)
    {
        _proto = protoInt;
    }

    /// <summary>Python <c>split(chunk, plain)</c>: whole-cipher + aligned plaintext.</summary>
    public List<byte[]> Split(ReadOnlySpan<byte> chunk, ReadOnlySpan<byte> plain)
    {
        var result = new List<byte[]>();
        if (chunk.Length == 0) return result;
        if (_disabled)
        {
            result.Add(chunk.ToArray());
            return result;
        }

        _cipherBuf.Write(chunk);
        _plainBuf.Write(plain);

        byte[] cipher = _cipherBuf.ToArray();
        byte[] pl = _plainBuf.ToArray();
        int offset = 0;
        int bufLen = cipher.Length;

        while (offset < bufLen)
        {
            int? packetLen = NextPacketLen(cipher, pl, offset, bufLen - offset);
            if (packetLen is null) break;
            if (packetLen <= 0)
            {
                result.Add(offset == 0 ? cipher : cipher[offset..]);
                offset = bufLen;
                _disabled = true;
                break;
            }
            if (offset == 0 && packetLen == bufLen)
                result.Add(cipher);
            else
                result.Add(cipher[offset..(offset + packetLen.Value)]);
            offset += packetLen.Value;
        }

        if (offset > 0)
        {
            Rewrite(_cipherBuf, cipher, offset, bufLen);
            Rewrite(_plainBuf, pl, offset, bufLen);
        }
        return result;
    }

    private static void Rewrite(MemoryStream ms, byte[] source, int offset, int bufLen)
    {
        ms.SetLength(0);
        if (bufLen > offset)
            ms.Write(source, offset, bufLen - offset);
    }

    /// <summary>Python <c>flush()</c>: emit any buffered tail.</summary>
    public List<byte[]> Flush()
    {
        if (_cipherBuf.Length == 0) return new List<byte[]>();
        var tail = _cipherBuf.ToArray();
        _cipherBuf.SetLength(0);
        _plainBuf.SetLength(0);
        return new List<byte[]> { tail };
    }

    private int? NextPacketLen(byte[] cipher, byte[] plain, int offset, int avail)
    {
        if (avail <= 0) return null;
        if (_proto == Obfuscated2.ProtoAbridgedInt)
            return NextAbridgedLen(plain, offset, avail);
        if (_proto is Obfuscated2.ProtoIntermediateInt or Obfuscated2.ProtoPaddedIntermediateInt)
            return NextIntermediateLen(plain, offset, avail);
        return 0; // unknown protocol → disable after emitting the buffer
    }

    private static int? NextAbridgedLen(byte[] plain, int offset, int avail)
    {
        byte first = plain[offset];
        int payloadLen;
        int headerLen;
        if (first is 0x7F or 0xFF)
        {
            if (avail < 4) return null;
            payloadLen = ((plain[offset + 1]) | (plain[offset + 2] << 8) | (plain[offset + 3] << 16)) * 4;
            headerLen = 4;
        }
        else
        {
            payloadLen = (first & 0x7F) * 4;
            headerLen = 1;
        }
        if (payloadLen <= 0) return 0;
        int packetLen = headerLen + payloadLen;
        if (avail < packetLen) return null;
        return packetLen;
    }

    private static int? NextIntermediateLen(byte[] plain, int offset, int avail)
    {
        if (avail < 4) return null;
        int payloadLen = BinaryPrimitives.ReadInt32LittleEndian(plain.AsSpan(offset, 4)) & 0x7FFFFFFF;
        if (payloadLen <= 0) return 0;
        int packetLen = 4 + payloadLen;
        if (avail < packetLen) return null;
        return packetLen;
    }
}
