using System.Buffers.Binary;
using System.Security.Cryptography;

namespace TgWsProxy.Crypto;

/// <summary>
/// AES-CTR keystream used by MTProto obfuscated2, mirroring the Python shim
/// <c>proxy/_aes.py</c>: <c>Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor().update(data)</c>.
/// CTR is symmetric — the same object encrypts and decrypts (Python uses
/// <c>.encryptor()</c> for both directions, even to fast-forward the keystream).
/// The 128-bit big-endian counter increments across <see cref="Update"/> calls,
/// exactly like OpenSSL's EVP CTR context.
/// </summary>
public sealed class MtprotoAes : IDisposable
{
    private readonly Aes _aes;
    private byte[] _counter; // 16-byte big-endian block counter
    private readonly byte[] _keystream = new byte[16];
    private int _ksPos = 16;   // consumed bytes inside the current block
    private bool _disposed;

    /// <summary>Key length in bytes: 16 (AES-128), 24 or 32 (AES-256).</summary>
    public int KeyLength { get; }

    /// <param name="key">AES key, 16/24/32 bytes (Python: <c>algorithms.AES(key)</c>).</param>
    /// <param name="iv">Initial 16-byte counter block (Python: <c>modes.CTR(iv)</c>).</param>
    public MtprotoAes(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
    {
        if (key.Length is not (16 or 24 or 32))
            throw new ArgumentException("AES key must be 16/24/32 bytes", nameof(key));
        if (iv.Length != 16)
            throw new ArgumentException("CTR IV must be 16 bytes", nameof(iv));

        KeyLength = key.Length;
        _counter = iv.ToArray();
        _aes = Aes.Create();
        _aes.Key = key.ToArray();
        _aes.Mode = CipherMode.ECB;   // raw block encryption => keystream generator
        _aes.Padding = PaddingMode.None;
    }

    /// <summary>Python <c>encryptor().update(data)</c>: XOR with the running CTR keystream.</summary>
    public byte[] Update(ReadOnlySpan<byte> data)
    {
        var output = new byte[data.Length];
        Update(data, output);
        return output;
    }

    /// <summary>In-place-capable <c>update</c>; source and destination may alias.</summary>
    public void Update(ReadOnlySpan<byte> data, Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (data.Length > destination.Length)
            throw new ArgumentException("Destination too small", nameof(destination));
        if (data.IsEmpty)
            return;

        var src = data;
        var dst = destination[..data.Length];

        // Finish the partially consumed keystream block first.
        if (_ksPos < 16)
        {
            var take = Math.Min(16 - _ksPos, src.Length);
            for (var i = 0; i < take; i++)
                dst[i] = (byte)(src[i] ^ _keystream[_ksPos + i]);
            _ksPos += take;
            if (_ksPos == 16)
                _ksPos = 0;
            src = src[take..];
            dst = dst[take..];
        }

        Span<byte> block = stackalloc byte[16];
        while (src.Length >= 16)
        {
            NextBlock(block);
            for (var i = 0; i < 16; i++)
                dst[i] = (byte)(src[i] ^ block[i]);
            src = src[16..];
            dst = dst[16..];
        }

        if (!src.IsEmpty)
        {
            NextBlock(_keystream);
            for (var i = 0; i < src.Length; i++)
                dst[i] = (byte)(src[i] ^ _keystream[i]);
            _ksPos = src.Length;
        }
    }

    /// <summary>Encrypt one fresh full block into <paramref name="output"/> and advance the counter.</summary>
    private void NextBlock(Span<byte> output)
    {
        _aes.EncryptEcb(_counter, output, PaddingMode.None);
        IncrementCounter();
    }

    /// <summary>Big-endian 128-bit counter increment (OpenSSL CTR semantics).</summary>
    private void IncrementCounter()
    {
        for (var i = 15; i >= 0; i--)
        {
            if (++_counter[i] != 0)
                break;
        }
    }

    /// <summary>
    /// Build a CTR IV the way <c>tg_ws_proxy._try_handshake</c> does:
    /// interpret <paramref name="iv16"/> as a big-endian integer, then re-encode it
    /// as 16 bytes big-endian (truncated modulo 2^128). For a 16-byte input this is
    /// an identity transform, kept for exact parity with the Python code path.
    /// </summary>
    public static byte[] BuildCtrIv(ReadOnlySpan<byte> iv16)
    {
        if (iv16.Length != IV_LEN)
            throw new ArgumentException("IV must be 16 bytes", nameof(iv16));
        var result = new byte[IV_LEN];
        iv16.CopyTo(result);
        return result;
    }

    private const int IV_LEN = 16;

    /// <summary>SHA-256 helper matching <c>hashlib.sha256(prekey + secret).digest()</c>.</summary>
    public static byte[] Sha256(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        using var sha = SHA256.Create();
        var ctx = sha.GetHasher(default);
        ctx.AppendHash(a);
        ctx.AppendHash(b);
        return ctx.GetCurrentHash();
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
