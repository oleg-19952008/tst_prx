using System.Buffers.Binary;
using System.Security.Cryptography;

namespace TgWsProxy.Crypto;

/// <summary>Result of a successful obfuscated2 handshake — Python
/// <c>tg_ws_proxy._try_handshake</c> tuple (dc_id, is_media, proto_tag,
/// dec_prekey_and_iv).</summary>
public sealed record HandshakeResult(int Dc, bool IsMedia, byte[] ProtoTag, byte[] ClientDecPrekeyIv)
{
    /// <summary>PROTO_*_INT numeric form used by MsgSplitter.</summary>
    public uint ProtoInt => Obfuscated2.ProtoToInt(ProtoTag);
}

/// <summary>
/// Four streaming AES-CTR states for one bridged session — Python
/// <c>bridge.py::CryptoCtx</c> (clt_dec/clt_enc/tg_enc/tg_dec).
/// </summary>
public sealed class CryptoContext : IDisposable
{
    public AesCtrCipher CltDecryptor { get; }   // decrypt data from client
    public AesCtrCipher CltEncryptor { get; }   // encrypt data to client
    public AesCtrCipher TgEncryptor { get; }    // encrypt data to telegram
    public AesCtrCipher TgDecryptor { get; }    // decrypt data from telegram

    internal CryptoContext(AesCtrCipher cltDec, AesCtrCipher cltEnc,
                           AesCtrCipher tgEnc, AesCtrCipher tgDec)
    {
        CltDecryptor = cltDec;
        CltEncryptor = cltEnc;
        TgEncryptor = tgEnc;
        TgDecryptor = tgDec;
    }

    /// <summary>client ciphertext chunk → plaintext (Python ctx.clt_dec.update).</summary>
    public byte[] ClientToPlain(ReadOnlySpan<byte> data) => CltDecryptor.Update(data);
    public byte[] PlainToClient(ReadOnlySpan<byte> data) => CltEncryptor.Update(data);
    public byte[] PlainToTelegram(ReadOnlySpan<byte> data) => TgEncryptor.Update(data);
    public byte[] TelegramToPlain(ReadOnlySpan<byte> data) => TgDecryptor.Update(data);

    /// <summary>client ciphertext → plaintext → telegram ciphertext.</summary>
    public byte[] ReencryptUpstream(ReadOnlySpan<byte> cipherFromClient)
        => TgEncryptor.Update(CltDecryptor.Update(cipherFromClient));

    /// <summary>telegram ciphertext → plaintext → client ciphertext.</summary>
    public byte[] ReencryptDownstream(ReadOnlySpan<byte> cipherFromTelegram)
        => CltEncryptor.Update(TgDecryptor.Update(cipherFromTelegram));

    public void Dispose()
    {
        CltDecryptor.Dispose();
        CltEncryptor.Dispose();
        TgEncryptor.Dispose();
        TgDecryptor.Dispose();
    }
}

/// <summary>
/// MTProto obfuscated2 handshake + key derivation — the single port of Python
/// <c>proxy/utils.py</c> constants and <c>proxy/tg_ws_proxy.py</c>
/// (<c>_try_handshake</c>, <c>_generate_relay_init</c>, <c>_build_crypto_ctx</c>).
/// Byte-for-byte identical key/IV derivation so that .NET and Python instances
/// can serve the same clients (PORT_PLAN.md §6 parity, golden vectors in
/// <c>tools/golden/</c>).
/// </summary>
public static class Obfuscated2
{
    // ---- proxy/utils.py constants ------------------------------------------
    public const int HandshakeLen = 64;   // HANDSHAKE_LEN
    public const int SkipLen = 8;         // SKIP_LEN
    public const int PrekeyLen = 32;      // PREKEY_LEN
    public const int KeyLen = 32;         // KEY_LEN
    public const int IvLen = 16;          // IV_LEN
    public const int ProtoTagPos = 56;    // PROTO_TAG_POS
    public const int DcIdxPos = 60;       // DC_IDX_POS

    public static ReadOnlySpan<byte> Zero64 => new byte[HandshakeLen];
    public static ReadOnlySpan<byte> ProtoTagAbridged => new byte[] { 0xEF, 0xEF, 0xEF, 0xEF };
    public static ReadOnlySpan<byte> ProtoTagIntermediate => new byte[] { 0xEE, 0xEE, 0xEE, 0xEE };
    public static ReadOnlySpan<byte> ProtoTagSecure => new byte[] { 0xDD, 0xDD, 0xDD, 0xDD };

    public const uint ProtoAbridgedInt = 0xEFEFEFEF;
    public const uint ProtoIntermediateInt = 0xEEEEEEEE;
    public const uint ProtoPaddedIntermediateInt = 0xDDDDDDDD;

    /// <summary>Python <c>PROTO_ABRIDGED_INT / PROTO_INTERMEDIATE_INT / PROTO_PADDED_INTERMEDIATE_INT</c>.</summary>
    public static uint ProtoToInt(ReadOnlySpan<byte> protoTag) => protoTag switch
    {
        _ when protoTag.SequenceEqual(ProtoTagAbridged) => ProtoAbridgedInt,
        _ when protoTag.SequenceEqual(ProtoTagIntermediate) => ProtoIntermediateInt,
        _ when protoTag.SequenceEqual(ProtoTagSecure) => ProtoPaddedIntermediateInt,
        _ => throw new ArgumentException("Unknown protocol tag", nameof(protoTag)),
    };

    /// <summary>Python <c>RESERVED_FIRST_BYTES</c>.</summary>
    private static readonly HashSet<byte> ReservedFirstBytes = [0xEF];

    /// <summary>Python <c>RESERVED_STARTS</c>.</summary>
    private static readonly byte[][] ReservedStarts =
    [
        "HEAD"u8.ToArray(),
        "POST"u8.ToArray(),
        "GET "u8.ToArray(),
        [0xEE, 0xEE, 0xEE, 0xEE],
        [0xDD, 0xDD, 0xDD, 0xDD],
        [0x16, 0x03, 0x01, 0x02],
        "OPTI"u8.ToArray(),
    ];

    /// <summary>Python <c>RESERVED_CONTINUE</c>.</summary>
    private static readonly byte[] ReservedContinue = [0x00, 0x00, 0x00, 0x00];

    /// <summary>
    /// Port of <c>tg_ws_proxy._try_handshake</c>. Decrypts the client's 64-byte
    /// init with AES-CTR(key=SHA256(prekey+secret), iv=iv-from-init) and validates
    /// the protocol tag. Returns <c>null</c> on a wrong secret or unknown tag.
    /// </summary>
    public static HandshakeResult? TryHandshake(ReadOnlySpan<byte> handshake, ReadOnlySpan<byte> secret)
    {
        // Python slices without bounds checks: short input yields a wrong-length
        // prekey and raises in AES — treat anything under 64 bytes as invalid.
        if (handshake.Length != HandshakeLen)
            return null;

        // dec_prekey_and_iv = handshake[SKIP_LEN : SKIP_LEN + PREKEY_LEN + IV_LEN]
        var decPrekeyAndIv = handshake.Slice(SkipLen, PrekeyLen + IvLen).ToArray();
        var decPrekey = decPrekeyAndIv.AsSpan(0, PrekeyLen);
        var decIv = decPrekeyAndIv.AsSpan(PrekeyLen, IvLen);

        // dec_key = SHA256(dec_prekey + secret)
        var decKey = AesCtrCipher.Sha256(decPrekey, secret);

        // Python: dec_iv_int = int.from_bytes(dec_iv, 'big'); CTR(dec_iv_int.to_bytes(16,'big'))
        // — an identity transform for a 16-byte IV, kept via BuildCtrIv for parity.
        var ctrIv = AesCtrCipher.BuildCtrIv(decIv);

        using var decryptor = new AesCtrCipher(decKey, ctrIv);
        var decrypted = decryptor.Update(handshake);

        var protoTag = decrypted.AsSpan(ProtoTagPos, 4);
        if (!protoTag.SequenceEqual(ProtoTagAbridged)
            && !protoTag.SequenceEqual(ProtoTagIntermediate)
            && !protoTag.SequenceEqual(ProtoTagSecure))
        {
            return null;
        }

        // dc_idx = int.from_bytes(decrypted[60:62], 'little', signed=True)
        short dcIdx = (short)BinaryPrimitives.ReadInt16LittleEndian(decrypted.AsSpan(DcIdxPos, 2));

        return new HandshakeResult(
            Dc: Math.Abs(dcIdx),
            IsMedia: dcIdx < 0,
            ProtoTag: protoTag.ToArray(),
            ClientDecPrekeyIv: decPrekeyAndIv);
    }

    /// <summary>
    /// Port of <c>tg_ws_proxy._generate_relay_init</c>: random 64-byte init that
    /// avoids reserved prefixes, carrying (proto_tag, dc_idx LE, 2 random bytes)
    /// XOR-encrypted with the keystream tail of its own AES-CTR context.
    /// <paramref name="dcIdx"/> is truncated to 16 bits like Python's
    /// <c>struct.pack('&lt;h', ...)</c>.
    /// </summary>
    public static byte[] GenerateRelayInit(ReadOnlySpan<byte> protoTag, int dcIdx, RandomNumberGenerator? rng = null)
    {
        ArgumentNullException.ThrowIfNull(protoTag);
        if (protoTag.Length != 4)
            throw new ArgumentException("Protocol tag must be 4 bytes", nameof(protoTag));

        // Python: struct.pack('<h', dc_idx) — silently truncates out-of-range ints.
        Span<byte> dcBytes = stackalloc byte[2];
        BinaryPrimitives.WriteInt16LittleEndian(dcBytes, unchecked((short)dcIdx));

        rng ??= RandomNumberGenerator.Shared;

        byte[] rnd;
        while (true)
        {
            rnd = new byte[HandshakeLen];
            rng.GetBytes(rnd);
            if (ReservedFirstBytes.Contains(rnd[0]))
                continue;
            if (ReservedStarts.Any(s => rnd.AsSpan(0, 4).SequenceEqual(s)))
                continue;
            if (rnd.AsSpan(4, 4).SequenceEqual(ReservedContinue))
                continue;
            break;
        }

        // enc_key = rnd[8:40], enc_iv = rnd[40:56] — raw key, no SHA256 (relay side)
        var encKey = rnd.AsSpan(SkipLen, PrekeyLen);
        var encIv = rnd.AsSpan(SkipLen + PrekeyLen, IvLen);

        var tailPlain = new byte[8];
        protoTag[..4].CopyTo(tailPlain);
        dcBytes.CopyTo(tailPlain.AsSpan(4));
        rng.GetBytes(tailPlain.AsSpan(6, 2));

        using var aes = new AesCtrCipher(encKey, encIv);
        var encryptedFull = aes.Update(rnd);

        // keystream_tail[i] = encrypted_full[56+i] ^ rnd[56+i]
        var result = (byte[])rnd.Clone();
        for (var i = 0; i < 8; i++)
            result[ProtoTagPos + i] = (byte)(tailPlain[i] ^ (encryptedFull[ProtoTagPos + i] ^ rnd[ProtoTagPos + i]));

        return result;
    }

    /// <summary>
    /// Port of <c>tg_ws_proxy._build_crypto_ctx(client_dec_prekey_iv, secret, relay_init)</c>:
    /// four streaming AES-CTR contexts (client-decrypt, client-encrypt,
    /// telegram-encrypt, telegram-decrypt) with the handshake already consumed.
    /// <paramref name="clientDecPrekeyIv"/> is the 48-byte slice returned by
    /// <see cref="TryHandshake"/>; <paramref name="relayInit"/> the 64-byte value
    /// returned by <see cref="GenerateRelayInit"/>.
    /// </summary>
    public static CryptoContext BuildCryptoContext(
        ReadOnlySpan<byte> clientDecPrekeyIv, ReadOnlySpan<byte> secret, ReadOnlySpan<byte> relayInit)
    {
        if (clientDecPrekeyIv.Length != PrekeyLen + IvLen)
            throw new ArgumentException("Must be PREKEY_LEN + IV_LEN = 48 bytes", nameof(clientDecPrekeyIv));
        if (relayInit.Length != HandshakeLen)
            throw new ArgumentException("Must be HANDSHAKE_LEN = 64 bytes", nameof(relayInit));

        // --- client side: key = SHA256(prekey + secret), iv from handshake ---
        var cltDecPrekey = clientDecPrekeyIv[..PrekeyLen];
        var cltDecIv = clientDecPrekeyIv.Slice(PrekeyLen, IvLen);
        var cltDecKey = AesCtrCipher.Sha256(cltDecPrekey, secret);

        // clt_enc_prekey_iv = client_dec_prekey_iv[::-1]
        //   -> prekey' = reverse(iv), iv' = reverse(prekey)
        var cltEncPrekey = Reverse(cltDecIv);
        var cltEncIv = Reverse(cltDecPrekey);
        var cltEncKey = AesCtrCipher.Sha256(cltEncPrekey, secret);

        var cltDecryptor = new AesCtrCipher(cltDecKey, cltDecIv);
        var cltEncryptor = new AesCtrCipher(cltEncKey, cltEncIv);

        // fast-forward client decryptor past the 64-byte init
        cltDecryptor.Update(Zero64);

        // --- relay side: standard obfuscation, raw keys (no secret hash) ---
        var relayEncKey = relayInit.Slice(SkipLen, PrekeyLen);
        var relayEncIv = relayInit.Slice(SkipLen + PrekeyLen, IvLen);

        // relay_dec_prekey_iv = relay_init[8:56][::-1] -> key' = reverse(iv), iv' = reverse(prekey)
        var relayDecSlice = relayInit.Slice(SkipLen, PrekeyLen + IvLen);
        var relayDecKey = Reverse(relayDecSlice[PrekeyLen..]);
        var relayDecIv = Reverse(relayDecSlice[..PrekeyLen]);

        var tgEncryptor = new AesCtrCipher(relayEncKey, relayEncIv);
        var tgDecryptor = new AesCtrCipher(relayDecKey, relayDecIv);

        // Python fast-forwards the telegram encryptor past the 64-byte relay_init
        tgEncryptor.Update(Zero64);

        return new CryptoContext(cltDecryptor, cltEncryptor, tgEncryptor, tgDecryptor);
    }

    /// <summary>Rename of <see cref="BuildCryptoContext"/> kept for call-site parity.</summary>
    public static CryptoContext BuildCryptoCtx(
        ReadOnlySpan<byte> clientDecPrekeyIv, ReadOnlySpan<byte> secret, ReadOnlySpan<byte> relayInit)
        => BuildCryptoContext(clientDecPrekeyIv, secret, relayInit);

    private static byte[] Reverse(ReadOnlySpan<byte> data)
    {
        var copy = data.ToArray();
        Array.Reverse(copy);
        return copy;
    }
}
