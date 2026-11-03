using System.Buffers.Binary;

namespace TgWsProxy.Transport.H2;

/// <summary>Parsed HTTP/2 frame header (9 bytes: length, type, flags, stream id).</summary>
internal readonly struct H2FrameHeader(int length, H2FrameType type, byte flags, int streamId)
{
    public int Length { get; } = length;
    public H2FrameType Type { get; } = type;
    public byte Flags { get; } = flags;
    public int StreamId { get; } = streamId;

    public bool EndStream => (Flags & (byte)H2Flags.EndStream) != 0;
    public bool EndHeaders => (Flags & (byte)H2Flags.EndHeaders) != 0;
    public bool Padded => (Flags & (byte)H2Flags.Padded) != 0;
    public bool HasPriority => (Flags & (byte)H2Flags.Priority) != 0;
    public bool IsAck => (Flags & (byte)H2Flags.Ack) != 0;

    /// <summary>Serializes the 9-byte frame header into <paramref name="dest"/>.</summary>
    public void Write(Span<byte> dest)
    {
        if (dest.Length < H2Consts.FrameHeaderSize)
            throw new ArgumentException("Frame header needs 9 bytes.", nameof(dest));
        dest[0] = (byte)(Length >> 16);
        dest[1] = (byte)(Length >> 8);
        dest[2] = (byte)Length;
        dest[3] = (byte)Type;
        dest[4] = Flags;
        BinaryPrimitives.WriteInt32BigEndian(dest.Slice(5), StreamId & 0x7fff_ffff);
    }

    public static H2FrameHeader Parse(ReadOnlySpan<byte> src)
    {
        if (src.Length < H2Consts.FrameHeaderSize)
            throw new ArgumentException("Frame header needs 9 bytes.", nameof(src));
        int length = (src[0] << 16) | (src[1] << 8) | src[2];
        var type = (H2FrameType)src[3];
        byte flags = src[4];
        int streamId = BinaryPrimitives.ReadInt32BigEndian(src.Slice(5)) & 0x7fff_ffff;
        return new H2FrameHeader(length, type, flags, streamId);
    }
}

/// <summary>
/// Minimal HTTP/2 frame writer: emits well-formed frames into a byte buffer.
/// Only the frame types our client engine needs (SETTINGS/HEADERS/DATA/PING/
/// WINDOW_UPDATE/RST_STREAM/GOAWAY/CONTINUATION) are covered — same subset the
/// Python <c>h2</c> dependency uses on the client side.
/// </summary>
internal static class H2FrameWriter
{
    /// <summary>Appends a raw frame (header + payload) to <paramref name="out"/>.</summary>
    public static void AppendFrame(List<byte> outBuffer, H2FrameType type, byte flags,
                                   int streamId, ReadOnlySpan<byte> payload)
    {
        if (payload.Length > H2Consts.MaxFrameSizeLimit)
            throw new ArgumentOutOfRangeException(nameof(payload), "Frame exceeds 24-bit length field.");
        Span<byte> header = stackalloc byte[H2Consts.FrameHeaderSize];
        new H2FrameHeader(payload.Length, type, flags, streamId).Write(header);
        CollectionsMarshalExtensions.Append(outBuffer, header);
        CollectionsMarshalExtensions.Append(outBuffer, payload);
    }

    public static void AppendSettings(List<byte> outBuffer,
                                      IReadOnlyDictionary<H2SettingId, uint>? settings = null,
                                      bool ack = false)
    {
        if (ack)
        {
            AppendFrame(outBuffer, H2FrameType.Settings, (byte)H2Flags.Ack, 0, ReadOnlySpan<byte>.Empty);
            return;
        }
        int count = settings?.Count ?? 0;
        byte[] payload = new byte[count * 6];
        int offset = 0;
        if (settings is not null)
        {
            foreach (var (id, value) in settings)
            {
                BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(offset), (ushort)id);
                BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(offset + 2), value);
                offset += 6;
            }
        }
        AppendFrame(outBuffer, H2FrameType.Settings, (byte)H2Flags.None, 0, payload);
    }

    /// <summary>HEADERS frame carrying an already-HPACK-encoded block fragment.</summary>
    public static void AppendHeaders(List<byte> outBuffer, int streamId,
                                     ReadOnlySpan<byte> hpackBlock, bool endStream, bool endHeaders)
    {
        byte flags = (byte)((endStream ? (byte)H2Flags.EndStream : 0)
                          | (endHeaders ? (byte)H2Flags.EndHeaders : 0));
        AppendFrame(outBuffer, H2FrameType.Headers, flags, streamId, hpackBlock);
    }

    public static void AppendContinuation(List<byte> outBuffer, int streamId,
                                          ReadOnlySpan<byte> hpackBlock, bool endHeaders)
    {
        AppendFrame(outBuffer, H2FrameType.Continuation,
                    (byte)(endHeaders ? (byte)H2Flags.EndHeaders : 0), streamId, hpackBlock);
    }

    public static void AppendData(List<byte> outBuffer, int streamId,
                                  ReadOnlySpan<byte> data, bool endStream = false)
    {
        AppendFrame(outBuffer, H2FrameType.Data,
                    (byte)(endStream ? (byte)H2Flags.EndStream : 0), streamId, data);
    }

    public static void AppendPing(List<byte> outBuffer, ReadOnlySpan<byte> opaque8, bool ack = false)
    {
        if (opaque8.Length != 8)
            throw new ArgumentException("PING payload must be exactly 8 bytes.", nameof(opaque8));
        AppendFrame(outBuffer, H2FrameType.Ping,
                    (byte)(ack ? (byte)H2Flags.Ack : 0), 0, opaque8);
    }

    public static void AppendWindowUpdate(List<byte> outBuffer, int streamId, int increment)
    {
        if (increment <= 0 || increment > 0x7fff_ffff)
            throw new ArgumentOutOfRangeException(nameof(increment), "WINDOW_UPDATE increment must fit 31 bits and be positive.");
        byte[] payload = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(payload, increment);
        AppendFrame(outBuffer, H2FrameType.WindowUpdate, (byte)H2Flags.None, streamId, payload);
    }

    public static void AppendRstStream(List<byte> outBuffer, int streamId, H2ErrorCode code)
    {
        byte[] payload = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(payload, (uint)code);
        AppendFrame(outBuffer, H2FrameType.RstStream, (byte)H2Flags.None, streamId, payload);
    }

    public static void AppendGoAway(List<byte> outBuffer, int lastStreamId, H2ErrorCode code,
                                    ReadOnlySpan<byte> debugData = default)
    {
        byte[] payload = new byte[8 + debugData.Length];
        BinaryPrimitives.WriteInt32BigEndian(payload, lastStreamId & 0x7fff_ffff);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(4), (uint)code);
        debugData.CopyTo(payload.AsSpan(8));
        AppendFrame(outBuffer, H2FrameType.GoAway, (byte)H2Flags.None, 0, payload);
    }

    public static void AppendPreface(List<byte> outBuffer) =>
        CollectionsMarshalExtensions.Append(outBuffer, H2Consts.ClientPreface);
}

/// <summary>Small helpers to append spans to a <see cref="List{T"/> without unsafe code.</summary>
internal static class CollectionsMarshalExtensions
{
    public static void Append(List<byte> list, ReadOnlySpan<byte> data)
    {
        int start = list.Count;
        list.AddRange(data.ToArray());
        _ = start; // keep symmetric with potential future capacity hints
    }
}
