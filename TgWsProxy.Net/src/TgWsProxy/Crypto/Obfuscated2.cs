using System.Buffers.Binary;
using System.Security.Cryptography;

namespace TgWsProxy.Crypto;

/// <summary>
/// MTProto obfuscated2 handshake + key derivation, a byte-for-byte port of the
/// helpers in Python <c>proxy/utils.py</c>, <c>proxy/tg_ws_proxy.py</c>
/// (<c>_try_handshake</c>, <c>_generate_relay_init</c>, <c>_build_crypto_ctx</c>).
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

    /// <summary>Result of <c>_try_handshake</c>: (dc_id, is_media, proto_tag, dec_prekey_and_iv).</summary>
    public sealed record ClientHandshake(int DcId, bool IsMedia, byte[] ProtoTag, byte[] DecPrekeyAndIv);

    /// <summary>
    /// Port of <c>tg_ws_proxy._try_handshake</c>. Decrypts the client's 64-byte
    /// init with AES-CTR(key=SHA256(prekey+secret), iv=iv-from-init) and validates
    /// the protocol tag. Returns <c>null</c> on a wrong secret or unknown tag.
    /// </summary>
    public static ClientHandshake? TryHandshake(ReadOnlySpan<byte> handshake, ReadOnlySpan<byte> secret)
    {
        if (handshake.Length < HandshakeLen)
            return null;

        // dec_prekey_and_iv = handshake[SKIP_LEN : SKIP_LEN + PREKEY_LEN + IV_LEN]
        var decPrekeyAndIv = handshake.Slice(SkipLen, PrekeyLen + IvLen).ToArray();
        var decPrekey = decPrekeyAndIv.AsSpan(0, PrekeyLen);
        var decIv = decPrekeyAndIv.AsSpan(PrekeyLen, IvLen);

        // dec_key = SHA256(dec_prekey + secret)
        using var decKeyHash = SHA256.Create();
        var decKey = Hash2(decKeyHash, decPrekey, secret);

        // Python: dec_iv_int = int.from_bytes(dec_iv, 'big'); CTR(dec_iv_int.to_bytes(16,'big'))
        // — an identity transform for a 16-byte IV, kept via BuildCtrIv for parity.
        var ctrIv = MtprotoAes.BuildCtrIv(decIv);

        using var aes = new MtprotoAes(decKey, ctrIv);
        var decrypted = aes.Update(handshake);

        var protoTag = decrypted.AsSpan(ProtoTagPos, 4);
        if (!protoTag.SequenceEqual(ProtoTagAbridged)
            && !protoTag.SequenceEqual(ProtoTagIntermediate)
            && !protoTag.SequenceEqual(ProtoTagSecure))
        {
            return null;
        }

        // dc_idx = int.from_bytes(decrypted[60:62], 'little', signed=True)
        short dcIdx = (short)BinaryPrimitives.ReadInt16LittleEndian(decrypted.AsSpan(DcIdxPos, 2));

        return new ClientHandshake(
            DcId: Math.Abs(dcIdx),
            IsMedia: dcIdx < 0,
            ProtoTag: protoTag.ToArray(),
            DecPrekeyAndIv: decPrekeyAndIv);
    }

    /// <summary>
    /// Port of <c>tg_ws_proxy._generate_relay_init</c>: random 64-byte init that
    /// avoids reserved prefixes, carrying (proto_tag, dc_idx LE, 2 random bytes)
    /// XOR-encrypted with the keystream tail of its own AES-CTR context.
    /// </summary>
    public static byte[] GenerateRelayInit(ReadOnlySpan<byte> protoTag, short dcIdx, RandomNumberGenerator? rng = null)
    {
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

        Span<byte> dcBytes = stackalloc byte[2];
        BinaryPrimitives.WriteInt16LittleEndian(dcBytes, dcIdx);

        var tailPlain = new byte[8];
        protoTag[..4].CopyTo(tailPlain);
        dcBytes.CopyTo(tailPlain.AsSpan(4));
        rng.GetBytes(tailPlain.AsSpan(6, 2));

        using var aes = new MtprotoAes(encKey, encIv);
        var encryptedFull = aes.Update(rnd);

        // keystream_tail[i] = encrypted_full[56+i] ^ rnd[56+i]
        var result = (byte[])rnd.Clone();
        for (var i = 0; i < 8; i++)
            result[ProtoTagPos + i] = (byte)(tailPlain[i] ^ (encryptedFull[ProtoTagPos + i] ^ rnd[ProtoTagPos + i]));

        return result;
    }

    /// <summary>
    /// Port of <c>bridge.CryptoCtx</c> built by <c>tg_ws_proxy._build_crypto_ctx</c>:
    /// four streaming AES-CTR contexts (client-decrypt, client-encrypt,
    /// telegram-encrypt, telegram-decrypt) with the handshake already consumed.
    /// </summary>
    public sealed class CryptoContext : IDisposable
    {
        public MtprotoAes ClientDecryptor { get; }   // clt_dec: decrypt data from client
        public MtprotoAes ClientEncryptor { get; }   // clt_enc: encrypt data to client
        public MtprotoAes TelegramEncryptor { get; } // tg_enc: encrypt data to telegram
        public MtprotoAes TelegramDecryptor { get; } // tg_dec: decrypt data from telegram

        internal CryptoContext(MtprotoAes cltDec, MtprotoAes cltEnc, MtprotoAes tgEnc, MtprotoAes tgDec)
        {
            ClientDecryptor = cltDec;
            ClientEncryptor = cltEnc;
            TelegramEncryptor = tgEnc;
            TelegramDecryptor = tgDec;
        }

        /// <summary>client ciphertext → plaintext → telegram ciphertext.</summary>
        public byte[] ReencryptUpstream(ReadOnlySpan<byte> cipherFromClient)
        {
            var plain = ClientDecryptor.Update(cipherFromClient);
            return TelegramEncryptor.Update(plain);
        }

        /// <summary>telegram ciphertext → plaintext → client ciphertext.</summary>
        public byte[] ReencryptDownstream(ReadOnlySpan<byte> cipherFromTelegram)
        {
            var plain = TelegramDecryptor.Update(cipherFromTelegram);
            return ClientEncryptor.Update(plain);
        }

        public void Dispose()
        {
            ClientDecryptor.Dispose();
            ClientEncryptor.Dispose();
            TelegramEncryptor.Dispose();
            TelegramDecryptor.Dispose();
        }
    }

    /// <summary>
    /// Port of <c>tg_ws_proxy._build_crypto_ctx(client_dec_prekey_iv, secret, relay_init)</c>.
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

        using var sha = SHA256.Create();

        // --- client side: key = SHA256(prekey + secret), iv from handshake ---
        var cltDecPrekey = clientDecPrekeyIv[..PrekeyLen];
        var cltDecIv = clientDecPrekeyIv.Slice(PrekeyLen, IvLen);
        var cltDecKey = Hash2(sha, cltDecPrekey, secret);

        // clt_enc_prekey_iv = client_dec_prekey_iv[::-1]
        //   -> prekey' = reverse(iv), iv' = reverse(prekey)
        var cltEncPrekey = Reverse(cltDecIv);
        var cltEncIv = Reverse(cltDecPrekey);
        var cltEncKey = Hash2(sha, cltEncPrekey, secret);

        var cltDecryptor = new MtprotoAes(cltDecKey, cltDecIv);
        var cltEncryptor = new MtprotoAes(cltEncKey, cltEncIv);

        // fast-forward client decryptor past the 64-byte init
        cltDecryptor.Update(new byte[HandshakeLen]);

        // --- relay side: standard obfuscation, raw keys (no secret hash) ---
        var relayEncKey = relayInit.Slice(SkipLen, PrekeyLen);
        var relayEncIv = relayInit.Slice(SkipLen + PrekeyLen, IvLen);

        // relay_dec_prekey_iv = relay_init[8:56][::-1] -> key' = reverse(iv), iv' = reverse(prekey)
        var relayDecSlice = relayInit.Slice(SkipLen, PrekeyLen + IvLen);
        var relayDecKey = Reverse(relayDecSlice[PrekeyLen..]);
        var relayDecIv = Reverse(relayDecSlice[..PrekeyLen]);

        var tgEncryptor = new MtprotoAes(relayEncKey, relayEncIv);
        var tgDecryptor = new MtprotoAes(relayDecKey, relayDecIv);

        // Python fast-forwards the telegram encryptor past the 64-byte relay_init
        tgEncryptor.Update(new byte[HandshakeLen]);

        return new CryptoContext(cltDecryptor, cltEncryptor, tgEncryptor, tgDecryptor);
    }

    // ---- X25519 --------------------------------------------------------------

    /// <summary>
    /// Raw X25519 scalar multiplication over 32-byte little-endian key material,
    /// matching <c>cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.exchange()</c>.
    /// .NET's <see cref="ECDiffieHellman"/> with the X25519 named curve uses the
    /// same byte ordering, so keys are passed through unchanged.
    /// </summary>
    public static byte[] X25519(ReadOnlySpan<byte> privateKey32, ReadOnlySpan<byte> publicKey32)
    {
        if (privateKey32.Length != 32)
            throw new ArgumentException("X25519 private key must be 32 bytes", nameof(privateKey32));
        if (publicKey32.Length != 32)
            throw new ArgumentException("X25519 public key must be 32 bytes", nameof(publicKey32));

        using ecdh = ECDiffieHellman.Create(EccNamedAlgorithm.X25519);
        ecdh.ImportParameters(new ECParameters
        {
            Curve = EccNamedAlgorithm.X25519,
            D = privateKey32.ToArray(),
            Q = BuildRawPublicKey(publicKey32),
        });

        using peer = ECDiffieHellman.Create();
        peer.ImportSubjectPublicKeyInfo(BuildSpki(publicKey32), out _);

        // RFC 7748 shared secret: 32-byte little-endian field element.
        return ecdh.DeriveRawSecretAgreement(peer.PublicKey).ToArray();
    }

    /// <summary>
    /// DER BIT STRING payload for an X25519 public key: a leading 0x00 sign byte
    /// plus the raw 32 bytes, unless the high bit is set — then a 0x00 pad byte is
    /// inserted so the value stays positive (matches System.Security formatting).
    /// </summary>
    private static byte[] BuildRawPublicKey(ReadOnlySpan<byte> raw32)
    {
        if ((raw32[31] & 0x80) != 0)
        {
            var withPad = new byte[33];
            raw32.CopyTo(withPad.AsSpan(1));
            return withPad;
        }
        return raw32.ToArray();
    }

    /// <summary>Build a DER SubjectPublicKeyInfo for an X25519 raw public key.</summary>
    public static byte[] BuildSpki(ReadOnlySpan<byte> rawPublicKey32)
    {
        if (rawPublicKey32.Length != 32)
            throw new ArgumentException("X25519 public key must be 32 bytes", nameof(rawPublicKey32));

        // SEQUENCE { SEQUENCE { OID 1.3.101.110 }, BIT STRING (0x00 || key) }
        ReadOnlySpan<byte> header =
        [
            0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x6C, 0x6E, 0x03, 0x21, 0x00,
        ];
        var spki = new byte[header.Length + 32];
        header.CopyTo(spki);
        rawPublicKey32.CopyTo(spki.AsSpan(header.Length));
        return spki;
    }

    // ---- small helpers --------------------------------------------------------

    private static byte[] Hash2(SHA256 sha, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        var ctx = sha.GetHasher(default);
        ctx.AppendHash(a);
        ctx.AppendHash(b);
        return ctx.GetCurrentHash();
    }

    private static byte[] Reverse(ReadOnlySpan<byte> data)
    {
        var copy = data.ToArray();
        Array.Reverse(copy);
        return copy;
    }

    private static byte[] ReverseSpan(ReadOnlySpan<byte> data) => Reverse(data);
}
