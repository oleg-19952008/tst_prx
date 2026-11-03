using System.Buffers.Binary;
using System.Numerics;
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

    /// <summary>X25519 base point u = 9 (RFC 7748 §6.1), little-endian 32 bytes.</summary>
    public static readonly byte[] X25519Basepoint = CreateBasepoint();

    private static byte[] CreateBasepoint()
    {
        var bp = new byte[32];
        bp[0] = 9;
        return bp;
    }

    /// <summary>
    /// Raw X25519 scalar multiplication over 32-byte little-endian key material,
    /// matching <c>cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.exchange()</c>
    /// and <c>.public_bytes_raw()</c> (golden vectors: <c>tools/golden/x25519.json</c>).
    /// Managed RFC 7748 Montgomery ladder on <see cref="BigInteger"/>: .NET's
    /// <c>ECDiffieHellman</c> cannot carry raw Curve25519 scalars/points (the old
    /// commented-out stub referencing the non-existent <c>EccNamedAlgorithm</c> was
    /// removed by the deferred-fix port), and this keeps single-file win-x64 builds
    /// free of extra native dependencies.
    /// </summary>
    /// <param name="privateKey32">Private scalar, 32 bytes little-endian; clamped per RFC 7748.</param>
    /// <param name="publicKey32">Peer public value u, 32 bytes little-endian.</param>
    /// <returns>The 32-byte little-endian shared secret / derived public value.</returns>
    public static byte[] X25519(ReadOnlySpan<byte> privateKey32, ReadOnlySpan<byte> publicKey32)
    {
        if (privateKey32.Length != 32)
            throw new ArgumentException("X25519 private key must be 32 bytes", nameof(privateKey32));
        if (publicKey32.Length != 32)
            throw new ArgumentException("X25519 public key must be 32 bytes", nameof(publicKey32));

        // Clamp the scalar: k[0] &= 248; k[31] &= 127; k[31] |= 64 (RFC 7748 §5).
        Span<byte> k = stackalloc byte[32];
        privateKey32.CopyTo(k);
        k[0] &= 248;
        k[31] = (byte)((k[31] & 127) | 64);

        // Decode both operands as little-endian integers, mask u modulo 2^255 - 19.
        var scalar = LeToBigInt(k);
        var p = BigInteger.Pow(Two, 255) - Nineteen;
        var u = LeToBigInt(publicKey32) % p;

        // RFC 7748 §5 (version with conditional swaps around every ladder step).
        const int bits = 255;
        var a24 = new BigInteger(121665);
        var x1 = u;
        var x2 = BigInteger.One;
        var z2 = BigInteger.Zero;
        var x3 = u;
        var z3 = BigInteger.One;

        for (var i = bits - 1; i >= 0; i--)
        {
            var kt = (scalar >> i) & BigInteger.One;
            if (kt == BigInteger.One)
            {
                (x2, x3) = (x3, x2);
                (z2, z3) = (z3, z2);
            }

            var a = Mod(x2 + z2, p);
            var aa = Mod(a * a, p);
            var b = Mod(x2 - z2, p);
            var bb = Mod(b * b, p);
            var e = Mod(aa - bb, p);
            var c = Mod(x3 + z3, p);
            var d = Mod(x3 - z3, p);
            var da = Mod(d * aa, p);
            var cb = Mod(c * bb, p);

            var nx3 = Mod((da + cb) * (da + cb), p);
            var nz3 = Mod(x1 * Mod(da - cb, p) * Mod(da - cb, p), p);
            var nx2 = Mod(aa * bb, p);
            var nz2 = Mod(e * Mod(aa + a24 * e, p), p);

            x2 = nx2;
            z2 = nz2;
            x3 = nx3;
            z3 = nz3;

            if (kt == BigInteger.One)
            {
                (x2, x3) = (x3, x2);
                (z2, z3) = (z3, z2);
            }
        }

        // Output = x2 * z2^(p-2) mod p (modular inverse via Fermat, p is prime).
        var result = Mod(x2 * ModPow(z2, p - 2, p), p);
        return BigIntToLe(result);
    }

    /// <summary>Port of <c>X25519PrivateKey.generate().public_bytes_raw()</c>: clamp(seed) · 9.</summary>
    public static byte[] X25519PublicKeyFromSeed(ReadOnlySpan<byte> seed32) =>
        X25519(seed32, X25519Basepoint);

    private static readonly BigInteger Two = new BigInteger(2);
    private static readonly BigInteger Nineteen = new BigInteger(19);

    /// <summary>Non-negative modulo (BigInteger.Remainder keeps the dividend's sign).</summary>
    private static BigInteger Mod(BigInteger value, BigInteger m)
    {
        var r = value % m;
        return r.Sign < 0 ? r + m : r;
    }

    /// <summary>Modular exponentiation (square-and-multiply over non-negative exponents).</summary>
    private static BigInteger ModPow(BigInteger baseValue, BigInteger exponent, BigInteger m)
    {
        var result = BigInteger.One;
        var b = Mod(baseValue, m);
        while (exponent > BigInteger.Zero)
        {
            if ((exponent & BigInteger.One) == BigInteger.One)
                result = Mod(result * b, m);
            b = Mod(b * b, m);
            exponent >>= 1;
        }
        return result;
    }

    /// <summary>Little-endian 32 bytes -> non-negative BigInteger.</summary>
    private static BigInteger LeToBigInt(ReadOnlySpan<byte> le32)
    {
        Span<byte> be = stackalloc byte[33];   // leading zero keeps the value positive
        for (var i = 0; i < 32; i++)
            be[32 - i] = le32[i];
        return new BigInteger(be);
    }

    /// <summary>Non-negative BigInteger -> little-endian 32 bytes (zero-padded).</summary>
    private static byte[] BigIntToLe(BigInteger value)
    {
        var be = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        var le = new byte[32];
        for (var i = 0; i < be.Length; i++)
            le[i] = be[be.Length - 1 - i];
        return le;
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

    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        _aes.Dispose();
        CryptographicOperations.ZeroMemory(_counter);
    }
}
