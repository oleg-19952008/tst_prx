using System.Buffers.Binary;
using System.Security.Cryptography;

namespace TgWsProxy.Crypto;

/// <summary>
/// Streaming AES-CTR cipher with a big-endian 128-bit counter, used by MTProto
/// obfuscated2 — a single port of Python
/// <c>Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor().update(data)</c>
/// (see <c>proxy/_aes.py</c>). CTR keystream generation is symmetric, so the
/// same object performs both encryption and decryption (as in Python, where
/// MTProto uses <c>encryptor()</c> for both directions).
/// Thread-unsafe by design: one instance per stream direction.
/// </summary>
public sealed class AesCtrCipher : IDisposable
{
    private readonly Aes _aes;
    private readonly byte[] _counter = new byte[16];   // current block (big-endian)
    private readonly byte[] _keystream = new byte[16];
    private int _ksPos = 16;                            // consumed bytes inside the current block
    private bool _disposed;

    /// <summary>Key length in bytes: 16 (AES-128), 24 or 32 (AES-256).</summary>
    public int KeyLength { get; }

    /// <param name="key">AES key, 16/24/32 bytes (Python: <c>algorithms.AES(key)</c>).</param>
    /// <param name="iv">Initial 16-byte counter block (Python: <c>modes.CTR(iv)</c>).</param>
    public AesCtrCipher(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
    {
        if (key.Length is not (16 or 24 or 32))
            throw new ArgumentException($"Bad AES key length: {key.Length}", nameof(key));
        if (iv.Length != IvLen)
            throw new ArgumentException($"CTR IV must be {IvLen} bytes", nameof(iv));

        KeyLength = key.Length;
        _aes = Aes.Create();
        _aes.Mode = CipherMode.ECB;      // we build the CTR keystream ourselves
        _aes.Padding = PaddingMode.None;
        _aes.Key = key.ToArray();
        iv.CopyTo(_counter);
    }

    /// <summary>
    /// XOR-transform <paramref name="data"/> through the keystream, advancing
    /// the counter — the equivalent of <c>encryptor().update(chunk)</c>.
    /// </summary>
    public byte[] Update(ReadOnlySpan<byte> data)
    {
        var output = new byte[data.Length];
        Update(data, output);
        return output;
    }

    /// <summary>In-place-capable <c>update</c>; returns bytes written.</summary>
    public int Update(ReadOnlySpan<byte> data, Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (data.Length > destination.Length)
            throw new ArgumentException("Destination too small", nameof(destination));
        if (data.IsEmpty)
            return 0;

        var src = data;
        var dst = destination[..data.Length];
        var written = data.Length;

        // Finish the partially consumed keystream block first.
        if (_ksPos < IvLen)
        {
            var take = Math.Min(IvLen - _ksPos, src.Length);
            for (var i = 0; i < take; i++)
                dst[i] = (byte)(src[i] ^ _keystream[_ksPos + i]);
            _ksPos += take;
            if (_ksPos == IvLen)
                _ksPos = 0;
            src = src[take..];
            dst = dst[take..];
        }

        Span<byte> block = stackalloc byte[IvLen];
        while (src.Length >= IvLen)
        {
            NextBlock(block);
            for (var i = 0; i < IvLen; i++)
                dst[i] = (byte)(src[i] ^ block[i]);
            src = src[IvLen..];
            dst = dst[IvLen..];
        }

        if (!src.IsEmpty)
        {
            NextBlock(_keystream);
            for (var i = 0; i < src.Length; i++)
                dst[i] = (byte)(src[i] ^ _keystream[i]);
            _ksPos = src.Length;
        }

        return written;
    }

    /// <summary>Encrypt one fresh full block into <paramref name="output"/> and advance the counter.</summary>
    private void NextBlock(Span<byte> output)
    {
        _aes.EncryptEcb(_counter, output, PaddingMode.None);
        IncrementCounter();
    }

    /// <summary>Big-endian 128-bit counter increment (OpenSSL EVP CTR semantics).</summary>
    private void IncrementCounter()
    {
        for (var i = IvLen - 1; i >= 0; i--)
            if (++_counter[i] != 0)
                break;
    }

    private const int IvLen = 16;

    /// <summary>
    /// Build a CTR IV the way <c>tg_ws_proxy._try_handshake</c> does: interpret
    /// <paramref name="iv16"/> as a big-endian integer, then re-encode it as 16
    /// bytes big-endian (truncated modulo 2^128). For a 16-byte input this is an
    /// identity transform, kept for exact parity with the Python code path.
    /// </summary>
    public static byte[] BuildCtrIv(ReadOnlySpan<byte> iv16)
    {
        if (iv16.Length != IvLen)
            throw new ArgumentException($"IV must be {IvLen} bytes", nameof(iv16));
        var result = new byte[IvLen];
        iv16.CopyTo(result);
        return result;
    }

    /// <summary>SHA-256(a ‖ b) matching <c>hashlib.sha256(prekey + secret).digest()</c>.</summary>
    public static byte[] Sha256(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        using var sha = SHA256.Create();
        sha.TransformBlock(a.ToArray(), 0, a.Length, null, 0);
        sha.TransformFinalBlock(b.ToArray(), 0, b.Length);
        return sha.Hash!;
    }

    /// <summary>
    /// Raw X25519 scalar multiplication over 32-byte little-endian key material,
    /// matching <c>cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.exchange()</c>
    /// (golden vectors: <c>tools/golden/x25519.json</c>).
    /// NOTE (deferred fix): the implementation below is broken — ECParameters
    /// cannot carry a raw X25519 curve/key and <c>EccNamedAlgorithm</c> does not
    /// exist in System.Security.Cryptography. It is kept commented-out until the
    /// real port lands; no caller uses it yet (FakeTls only generates public keys).
    /// </summary>
    //public static byte[] X25519(ReadOnlySpan<byte> privateKey32, ReadOnlySpan<byte> publicKey32)
    //{
    //    if (privateKey32.Length != 32)
    //        throw new ArgumentException("X25519 private key must be 32 bytes", nameof(privateKey32));
    //    if (publicKey32.Length != 32)
    //        throw new ArgumentException("X25519 public key must be 32 bytes", nameof(publicKey32));
    //
    //    using ECDiffieHellman ecdh = ECDiffieHellman.Create(EccNamedAlgorithm.X25519);
    //    ecdh.ImportParameters(new ECParameters
    //    {
    //        Curve = EccNamedAlgorithm.X25519,
    //        D = privateKey32.ToArray(),
    //        Q = BuildRawPublicKey(publicKey32),
    //    });
    //
    //    using ECDiffieHellman peer = ECDiffieHellman.Create();
    //    peer.ImportSubjectPublicKeyInfo(BuildSpki(publicKey32), out _);
    //
    //    // RFC 7748 shared secret: 32-byte little-endian field element.
    //    return ecdh.DeriveRawSecretAgreement(peer.PublicKey).ToArray();
    //}

    ///// <summary>
    ///// DER BIT STRING payload for an X25519 public key: the raw 32 bytes, with a
    ///// leading 0x00 pad byte when the high bit is set so the value stays positive
    ///// (matches System.Security formatting).
    ///// </summary>
    //private static byte[] BuildRawPublicKey(ReadOnlySpan<byte> raw32)
    //{
    //    if ((raw32[31] & 0x80) != 0)
    //    {
    //        var withPad = new byte[33];
    //        raw32.CopyTo(withPad.AsSpan(1));
    //        return withPad;
    //    }
    //    return raw32.ToArray();
    //}

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

    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        _aes.Dispose();
        CryptographicOperations.ZeroMemory(_counter);
    }
}
