using System.Buffers.Binary;
using System.Security.Cryptography;
using TgWsProxy.Crypto;

namespace TgWsProxy.Core;

/// <summary>Result of a successful obfuscated2 handshake — Python <c>_try_handshake</c> tuple.</summary>
public sealed record HandshakeResult(int Dc, bool IsMedia, byte[] ProtoTag, byte[] ClientDecPrekeyIv)
{
    /// <summary>PROTO_*_INT numeric form used by MsgSplitter.</summary>
    public uint ProtoInt =>
        ProtoTag.SequenceEqual(ProtocolConsts.ProtoTagAbridged) ? ProtocolConsts.ProtoAbridgedInt :
        ProtoTag.SequenceEqual(ProtocolConsts.ProtoTagIntermediate) ? ProtocolConsts.ProtoIntermediateInt :
        ProtocolConsts.ProtoPaddedIntermediateInt;
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

    public CryptoContext(AesCtrCipher cltDec, AesCtrCipher cltEnc,
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

    public void Dispose()
    {
        CltDecryptor.Dispose();
        CltEncryptor.Dispose();
        TgEncryptor.Dispose();
        TgDecryptor.Dispose();
    }
}

/// <summary>
/// MTProto obfuscated2 handshake helpers — direct port of Python
/// <c>tg_ws_proxy.py::_try_handshake</c>, <c>_generate_relay_init</c> and
/// <c>_build_crypto_ctx</c>. Byte-for-byte identical key/IV derivation so that
/// .NET and Python instances can serve the same clients (PORT_PLAN.md §6 parity).
/// </summary>
public static class Obfuscated2
{
    /// <summary>Decrypt the 64-byte client init with SHA256(prekey+secret); null on bad secret/proto.</summary>
    public static HandshakeResult? TryHandshake(ReadOnlySpan<byte> handshake, byte[] secret)
    {
        var decPrekeyAndIv = handshake.Slice(ProtocolConsts.SkipLen,
            ProtocolConsts.PrekeyLen + ProtocolConsts.IvLen).ToArray();
        var decPrekey = decPrekeyAndIv[..ProtocolConsts.PrekeyLen];
        var decIv = decPrekeyAndIv[ProtocolConsts.PrekeyLen..];

        var decKey = Sha256Concat(decPrekey, secret);

        using var decryptor = new AesCtrCipher(decKey, decIv);
        var decrypted = decryptor.Update(handshake);

        var protoTag = decrypted[ProtocolConsts.ProtoTagPos..(ProtocolConsts.ProtoTagPos + 4)];
        if (!MatchesAny(protoTag, ProtocolConsts.ProtoTagAbridged,
                        ProtocolConsts.ProtoTagIntermediate,
                        ProtocolConsts.ProtoTagSecure))
            return null;

        int dcIdx = BinaryPrimitives.ReadInt16LittleEndian(
            decrypted.AsSpan(ProtocolConsts.DcIdxPos, 2));

        int dcId = Math.Abs(dcIdx);
        bool isMedia = dcIdx < 0;
        return new HandshakeResult(dcId, isMedia, protoTag, decPrekeyAndIv);
    }

    /// <summary>Python <c>_generate_relay_init</c>: fresh random 64-byte init for the relay side.</summary>
    public static byte[] GenerateRelayInit(ReadOnlySpan<byte> protoTag, short dcIdx)
    {
        byte[] rnd;
        while (true)
        {
            rnd = RandomNumberGenerator.GetBytes(ProtocolConsts.HandshakeLen);
            if (ProtocolConsts.ReservedFirstBytes.Contains(rnd[0])) continue;
            if (ProtocolConsts.ReservedStarts.Any(s => rnd.AsSpan(0, s.Length).SequenceEqual(s))) continue;
            if (rnd.AsSpan(4, 4).SequenceEqual(ProtocolConsts.ReservedContinue)) continue;
            break;
        }

        var encKey = rnd[ProtocolConsts.SkipLen..(ProtocolConsts.SkipLen + ProtocolConsts.PrekeyLen)];
        var encIv = rnd[(ProtocolConsts.SkipLen + ProtocolConsts.PrekeyLen)..
                        (ProtocolConsts.SkipLen + ProtocolConsts.PrekeyLen + ProtocolConsts.IvLen)];

        using var encryptor = new AesCtrCipher(encKey, encIv);
        var encryptedFull = encryptor.Update(rnd);

        // keystream over the last 8 bytes: ks[i] = encrypted_full[i] ^ rnd[i], i in [56..64)
        var tailPlain = new byte[8];
        protoTag.CopyTo(tailPlain.AsSpan(0));
        BinaryPrimitives.WriteInt16LittleEndian(tailPlain.AsSpan(4, 2), dcIdx);
        RandomNumberGenerator.Fill(tailPlain.AsSpan(6, 2));

        var result = (byte[])rnd.Clone();
        for (int i = ProtocolConsts.ProtoTagPos; i < ProtocolConsts.HandshakeLen; i++)
            result[i] = (byte)(tailPlain[i - ProtocolConsts.ProtoTagPos]
                               ^ encryptedFull[i] ^ rnd[i]);
        return result;
    }

    /// <summary>Python <c>_build_crypto_ctx</c>: four AES-CTR states with fast-forwarded counters.</summary>
    public static CryptoContext BuildCryptoCtx(byte[] clientDecPrekeyIv, byte[] secret, byte[] relayInit)
    {
        var cltDecPrekey = clientDecPrekeyIv[..ProtocolConsts.PrekeyLen];
        var cltDecIv = clientDecPrekeyIv[ProtocolConsts.PrekeyLen..];
        var cltDecKey = Sha256Concat(cltDecPrekey, secret);

        var cltEncPrekeyIv = Reverse(clientDecPrekeyIv);
        var cltEncKey = Sha256Concat(cltEncPrekeyIv[..ProtocolConsts.PrekeyLen], secret);
        var cltEncIv = cltEncPrekeyIv[ProtocolConsts.PrekeyLen..];

        var cltDecryptor = new AesCtrCipher(cltDecKey, cltDecIv);
        var cltEncryptor = new AesCtrCipher(cltEncKey, cltEncIv);
        // fast-forward client decryptor past the 64-byte init
        cltDecryptor.Update(ProtocolConsts.Zero64);

        // relay side: standard obfuscation (no secret hash, raw key)
        var relayEncKey = relayInit[ProtocolConsts.SkipLen..
                                    (ProtocolConsts.SkipLen + ProtocolConsts.PrekeyLen)];
        var relayEncIv = relayInit[(ProtocolConsts.SkipLen + ProtocolConsts.PrekeyLen)..
                                   (ProtocolConsts.SkipLen + ProtocolConsts.PrekeyLen + ProtocolConsts.IvLen)];

        var relaySlice = relayInit[ProtocolConsts.SkipLen..
                                   (ProtocolConsts.SkipLen + ProtocolConsts.PrekeyLen + ProtocolConsts.IvLen)];
        var relayDecPrekeyIv = Reverse(relaySlice);
        var relayDecKey = relayDecPrekeyIv[..ProtocolConsts.KeyLen];
        var relayDecIv = relayDecPrekeyIv[ProtocolConsts.KeyLen..];

        var tgEncryptor = new AesCtrCipher(relayEncKey, relayEncIv);
        var tgDecryptor = new AesCtrCipher(relayDecKey, relayDecIv);
        tgEncryptor.Update(ProtocolConsts.Zero64);

        return new CryptoContext(cltDecryptor, cltEncryptor, tgEncryptor, tgDecryptor);
    }

    // ---- X25519 --------------------------------------------------------------

    /// <summary>
    /// Raw X25519 scalar multiplication over 32-byte little-endian key material,
    /// matching <c>cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.exchange()</c>.
    /// .NET's <see cref="ECDiffieHellman"/> with the X25519 named curve uses the same
    /// byte ordering (RFC 7748), so keys are passed through unchanged. Used by the
    /// FakeTLS key_share handling and obfuscated2 ephemeral pairs (PORT_PLAN.md §3 A.2).
    /// </summary>
    public static byte[] X25519(ReadOnlySpan<byte> privateKey32, ReadOnlySpan<byte> publicKey32)
    {
        if (privateKey32.Length != 32)
            throw new ArgumentException("X25519 private key must be 32 bytes", nameof(privateKey32));
        if (publicKey32.Length != 32)
            throw new ArgumentException("X25519 public key must be 32 bytes", nameof(publicKey32));

        using var ecdh = ECDiffieHellman.Create(EccNamedAlgorithm.X25519);
        ecdh.ImportParameters(new ECParameters
        {
            Curve = EccNamedAlgorithm.X25519,
            D = privateKey32.ToArray(),
            Q = new ECPoint
            {
                X = BuildRawPublicKey(publicKey32),
                Y = Array.Empty<byte>(),
            },
        });

        using var peer = ECDiffieHellman.Create();
        peer.ImportSubjectPublicKeyInfo(BuildSpki(publicKey32), out _);

        // RFC 7748 shared secret: 32-byte little-endian field element.
        return ecdh.DeriveRawSecretAgreement(peer.PublicKey).ToArray();
    }

    /// <summary>
    /// DER BIT STRING payload for an X25519 public key: the raw 32 bytes, unless the
    /// high bit is set — then a leading 0x00 pad byte keeps the value positive
    /// (matches System.Security's formatting of X25519 public points).
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

    private static byte[] Reverse(byte[] src)
    {
        var copy = (byte[])src.Clone();
        Array.Reverse(copy);
        return copy;
    }

    private static bool MatchesAny(ReadOnlySpan<byte> tag, params byte[][] candidates)
    {
        foreach (var c in candidates)
            if (tag.SequenceEqual(c)) return true;
        return false;
    }

    /// <summary>SHA256(a + b) — Python <c>hashlib.sha256(prekey + secret).digest()</c>.</summary>
    private static byte[] Sha256Concat(byte[] a, byte[] b)
    {
        var buf = new byte[a.Length + b.Length];
        a.CopyTo(buf, 0);
        b.CopyTo(buf, a.Length);
        var hash = SHA256.HashData(buf);
        CryptographicOperations.ZeroMemory(buf);
        return hash;
    }
}
