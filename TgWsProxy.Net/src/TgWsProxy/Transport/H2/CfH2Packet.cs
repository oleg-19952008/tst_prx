using System.Buffers.Binary;
using System.Security.Cryptography;
using TgWsProxy.Core;
using TgWsProxy.Crypto;

namespace TgWsProxy.Transport.H2;

/// <summary>
/// Byte-for-byte port of the module-level helpers/constants of
/// <c>tg-ws-proxy-main_py/proxy/cf_h2.py</c> (checklist item 6, part 1):
/// native MTProto packet framing over the H2 media lane (<c>_read_packet</c>,
/// <c>_encode_reply</c>) plus the tunables that drive replay/backpressure.
/// </summary>
internal static class CfH2Consts
{
    // ---- limits (identical values to Python) ------------------------------
    public const int MaxPacket = 4 * 1024 * 1024;
    public const int MaxPlainPadding = 256;
    public const int MaxChannelRequests = 8;
    public const int MaxChannelBytes = 8 * 1024 * 1024;
    public const int MaxLaneRequests = 64;
    public const int MaxLaneBytes = 32 * 1024 * 1024;
    public const int MaxLaneReplyBytes = 32 * 1024 * 1024;

    // ---- timeouts / intervals (seconds) -----------------------------------
    public const double DomainCooldown = 30.0;
    public const double RequestTimeout = 65.0;
    public const double SetupTimeout = 8.0;
    public const double ReplayIdleSeconds = 1.0;
    public const double ReplayRequestSeconds = 3.0;
    public const double ReplayCheckSeconds = 0.25;
    public const double ReplayMaxAge = 30.0;
    public const int ReplayHistoryBytes = 64 * 1024;
    public const int ReplayHistoryPackets = 16;
    public const int MaxChannelReplays = 2;
    public const double ReplaySlotSeconds = 30.0;
    public const double ReplayRetrySeconds = 2.0;
    public const int ReplayMaxAttempts = 3;
    public const double SlowResponseSeconds = 3.0;
    public const double DiagnosticInterval = 5.0;

    public const int ReplyIdPrefixLen = 24;   // reply[:24] identity marker
    public const int SmallResponseBytes = 4096;
}

/// <summary>
/// Python <c>_ReplayPacket</c>: a retained copy of an original outbound MTProto
/// packet that may be re-submitted ("replayed") when the endpoint stops answering.
/// All mutation happens under the owning channel's lock.
/// </summary>
internal sealed class ReplayPacket
{
    public required double SentAt { get; init; }
    public required byte[] Body { get; init; }
    public required int Sequence { get; init; }

    public int Attempts { get; set; }
    public double LastAttemptAt { get; set; }
    public Task? Pending { get; set; }
    public HashSet<Task> Originals { get; } = new();
    public bool Retired { get; set; }

    /// <summary>First 24 bytes of the last accepted reply — deduplicates replays.</summary>
    public byte[]? ReplyId { get; set; }

    public bool Replayed => LastAttemptAt > 0 || Attempts > 0;
}

/// <summary>
/// Python <c>_RequestTrace</c>: per-request diagnostic timeline, only materialised
/// when Debug logging is enabled (same gate as in cf_h2.py).
/// </summary>
internal sealed class RequestTrace(int packet, double started, bool replay, int size)
{
    public int Packet { get; } = packet;
    public double Started { get; } = started;
    public bool Replay { get; } = replay;
    public int Size { get; } = size;

    public int Request { get; set; }
    public int Stream { get; set; }
    public string Phase { get; set; } = "queued";
    public double? SentAt { get; set; }
    public double? HeadersAt { get; set; }
    public double? FinishedAt { get; set; }
    public int Received { get; set; }
    public string CfRay { get; set; } = "-";

    /// <summary>Python <c>_RequestTrace.summary</c>.</summary>
    public string Summary(double now)
    {
        double end = FinishedAt ?? now;
        double headers = HeadersAt ?? end;
        double sendMs = SentAt is null ? -1 : (SentAt.Value - Started) * 1000;
        double headersMs = SentAt is null ? -1 : Math.Max(0, headers - SentAt.Value) * 1000;
        return FormattableString.Invariant(
            $"req={Request} pkt={Packet} sid={Stream} replay={(Replay ? 1 : 0)} phase={Phase} " +
            $"age_ms={(end - Started) * 1000:F0} send_ms={sendMs:F0} wait_headers_ms={headersMs:F0} " +
            $"up={Size} down={Received} ray={CfRay}");
    }
}

/// <summary>
/// Native MTProto packet codec for the H2 media bridge — port of the module-level
/// functions <c>_read_packet</c> and <c>_encode_reply</c> from cf_h2.py. Reads are
/// AES-CTR-decrypted on the fly exactly like the Python <c>plaintext()</c> helper.
/// </summary>
internal static class MtprotoPacketCodec
{
    /// <summary>Python <c>reader.readexactly</c> with EOF ⇒ <see cref="EndOfStreamException"/>.</summary>
    private static async Task ReadExactlyAsync(Stream reader, Memory<byte> buffer, CancellationToken ct)
    {
        int got = 0;
        while (got < buffer.Length)
        {
            int n = await reader.ReadAsync(buffer[got..], ct).ConfigureAwait(false);
            if (n == 0)
                throw new EndOfStreamException(); // asyncio.IncompleteReadError analogue
            got += n;
        }
    }

    /// <summary>
    /// Python <c>_read_packet</c>: decrypts one length-prefixed MTProto frame from the
    /// native client. Returns the aligned body and the quick-ack flag.
    /// Supports ABRIDGED (1/4-byte word count) and PROUD/SECURE (uint32 + padding trim).
    /// </summary>
    public static async Task<(byte[] Body, bool Quick)> ReadPacketAsync(
        Stream reader, AesCtrCipher decryptor, byte[] tag, CancellationToken ct)
    {
        async Task<byte[]> Plaintext(int count)
        {
            var buf = new byte[count];
            await ReadExactlyAsync(reader, buf, ct).ConfigureAwait(false);
            return decryptor.Update(buf);
        }

        bool quick;
        int length;
        if (tag.SequenceEqual(ProtocolConsts.ProtoTagAbridged))
        {
            byte first = (await Plaintext(1))[0];
            quick = (first & 0x80) != 0;
            int words = first & 0x7f;
            if (words == 0x7f)
            {
                var three = await Plaintext(3);
                words = three[0] | (three[1] << 8) | (three[2] << 16);
            }
            length = words * 4;
        }
        else
        {
            uint value = BinaryPrimitives.ReadUInt32LittleEndian(await Plaintext(4));
            quick = (value & 0x8000_0000u) != 0;
            length = (int)(value & 0x7fff_ffffu);
        }

        int maxLen = CfH2Consts.MaxPacket +
                     (tag.SequenceEqual(ProtocolConsts.ProtoTagSecure) ? CfH2Consts.MaxPlainPadding : 0);
        if (length < 24 || length > maxLen)
            throw new ArgumentException(
                $"native packet length outside supported range: {length}");

        byte[] body = await Plaintext(length);

        if (tag.SequenceEqual(ProtocolConsts.ProtoTagSecure))
        {
            int packetLength;
            int maxPadding;
            if (body.AsSpan(0, 8).SequenceEqual(stackalloc byte[8])) // b'\x00' * 8
            {
                packetLength = 20 + (int)BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(16, 4));
                maxPadding = CfH2Consts.MaxPlainPadding;
            }
            else
            {
                packetLength = 24 + ((length - 24) / 16) * 16;
                maxPadding = 15;
            }
            int padding = length - packetLength;
            if (packetLength < 24 || packetLength > length || padding > maxPadding)
                throw new ArgumentException(FormattableString.Invariant(
                    $"invalid padded native packet: frame={length} packet={packetLength} " +
                    $"padding={padding} limit={maxPadding}"));
            body = body[..packetLength];
        }

        if (body.Length % 4 != 0 || body.Length > CfH2Consts.MaxPacket)
            throw new ArgumentException("invalid native packet alignment or size");
        return (body, quick);
    }

    /// <summary>
    /// Python <c>_encode_reply</c>: wraps an MTProto response body into the native
    /// wire framing (ABRIDGED word-count prefix or SECURE uint32 + random padding).
    /// </summary>
    public static byte[] EncodeReply(byte[] body, byte[] tag)
    {
        if (body.Length == 0 || body.Length % 4 != 0 || body.Length > CfH2Consts.MaxPacket)
            throw new ArgumentException(
                $"invalid HTTP MTProto response length: {body.Length}");

        if (tag.SequenceEqual(ProtocolConsts.ProtoTagAbridged))
        {
            int words = body.Length / 4;
            byte[] prefix = words < 0x7f
                ? [(byte)words]
                : [(byte)0x7f, (byte)(words & 0xff), (byte)((words >> 8) & 0xff), (byte)((words >> 16) & 0xff)];
            var output = new byte[prefix.Length + body.Length];
            prefix.CopyTo(output, 0);
            body.CopyTo(output, prefix.Length);
            return output;
        }

        byte[] padding = tag.SequenceEqual(ProtocolConsts.ProtoTagSecure)
            ? RandomNumberGenerator.GetBytes(RandomNumberGenerator.GetInt32(0, 4))
            : [];
        var framed = new byte[4 + body.Length + padding.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(framed, (uint)(body.Length + padding.Length));
        body.CopyTo(framed, 4);
        padding.CopyTo(framed, 4 + body.Length);
        return framed;
    }
}
