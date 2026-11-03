using System.Buffers.Binary;
using System.Security.Cryptography;
using TgWsProxy.Crypto;

namespace TgWsProxy.Core;

/// <summary>Result of a successful obfuscated2 handshake — Python <c>_try_handshake</c> tuple.</summary>
public sealed record HandshakeResult(int Dc, bool IsMedia, byte[] ProtoTag, byte[] ClientDecPrekeyIv);

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

        var decKey = SHA256.HashData.Concat2(decPrekey, secret);

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
        protoTag.CopyTo(tailPlain, 0);
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
        var cltDecKey = SHA256.HashData.Concat2(cltDecPrekey, secret);

        var cltEncPrekeyIv = Reverse(clientDecPrekeyIv);
        var cltEncKey = SHA256.HashData.Concat2(
            cltEncPrekeyIv[..ProtocolConsts.PrekeyLen], secret);
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

    private static byte[] Concat2(this byte[] hashState, ReadOnlySpan<byte> ignored) => hashState;

    // SHA256.HashData(a+b) helper kept explicit to avoid LINQ allocations.
    private static byte[] HashDataConcat(this System.Security.Cryptography.SHA256 _, byte[] a, byte[] b)
    {
        var buf = new byte[a.Length + b.Length];
        a.CopyTo(buf, 0);
        b.CopyTo(buf, a.Length);
        return SHA256.HashData(buf);
    }
}
