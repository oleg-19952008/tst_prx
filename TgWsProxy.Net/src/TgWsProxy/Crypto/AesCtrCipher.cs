using System.Security.Cryptography;

namespace TgWsProxy.Crypto;

/// <summary>
/// Streaming AES-256-CTR cipher with a big-endian 128-bit counter,
/// semantically identical to Python
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
    private int _ksPos = 16;                            // exhausted initially
    private bool _disposed;

    public AesCtrCipher(byte[] key, byte[] iv)
    {
        if (key.Length is not (16 or 24 or 32))
            throw new ArgumentException($"Bad AES key length: {key.Length}");
        if (iv.Length != 16)
            throw new ArgumentException($"Bad IV length: {iv.Length}");

        _aes = Aes.Create();
        _aes.Mode = CipherMode.ECB;      // we build the CTR keystream ourselves
        _aes.Padding = PaddingMode.None;
        _aes.Key = key;
        iv.CopyTo(_counter, 0);
    }

    /// <summary>
    /// XOR-transform <paramref name="data"/> through the keystream, advancing
    /// the counter — the equivalent of <c>encryptor().update(chunk)</c>.
    /// </summary>
    public byte[] Update(ReadOnlySpan<byte> data)
    {
        var output = new byte[data.Length];
        Apply(data, output);
        return output;
    }

    public void Update(ReadOnlySpan<byte> data, Span<byte> output) => Apply(data, output);

    private void Apply(ReadOnlySpan<byte> input, Span<byte> output)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        int i = 0;
        while (i < input.Length)
        {
            if (_ksPos == 16)
            {
                _aes.TransformBlock(_counter, 0, _keystream, 0);
                IncrementCounter();
                _ksPos = 0;
            }
            int take = Math.Min(16 - _ksPos, input.Length - i);
            for (int k = 0; k < take; k++)
                output[i + k] = (byte)(input[i + k] ^ _keystream[_ksPos + k]);
            _ksPos += take;
            i += take;
        }
    }

    private static void IncrementCounter(byte[] counter)
    {
        for (int idx = 15; idx >= 0; idx--)
            if (++counter[idx] != 0)
                break;
    }

    public void Dispose() => _aes.Dispose();
}
