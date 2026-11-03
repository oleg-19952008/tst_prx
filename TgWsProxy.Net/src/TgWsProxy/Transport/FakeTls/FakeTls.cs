using System.Buffers.Binary;
using System.Security.Cryptography;

namespace TgWsProxy.Transport.FakeTls;

/// <summary>
/// Constants of the mini-TLS stack, mirroring <c>proxy/fake_tls.py</c>.
/// </summary>
public static class FakeTlsConstants
{
    public const byte TlsRecordHandshake = 0x16;
    public const byte TlsRecordCcs = 0x14;
    public const byte TlsRecordAppData = 0x17;

    public static readonly byte[] TlsVersion10 = [0x03, 0x01];
    public static readonly byte[] TlsVersion12 = [0x03, 0x03];
    public static readonly byte[] TlsVersion13 = [0x03, 0x04];

    public const int ClientRandomOffset = 11;
    public const int ClientRandomLen = 32;
    public const int SessionIdOffset = 44;
    public const int SessionIdLen = 32;

    public const int TimestampTolerance = 120;

    public const int TlsAppDataMax = 16384;

    public const ushort ExtSupportedVersions = 0x002B;
    public const ushort ExtKeyShare = 0x0033;

    public const ushort GroupX25519 = 0x001D;
    public const ushort GroupX25519Mlkem768 = 0x11EC;

    public const int X25519KeyLen = 32;
    public const int X25519Mlkem768ClientShareLen = 1216;
    public const int Mlkem768CiphertextLen = 1088;

    /// <summary>CIPHER_PREFERENCE — TLS 1.3 suites in typical server pick order.</summary>
    public static readonly ushort[] CipherPreference = [0x1301, 0x1303, 0x1302];

    public const int AppDataMin = 64;
    /// <summary>FALLBACK_APPDATA_RANGE = (64, 160) — inclusive bounds (Python randint).</summary>
    public static readonly (int Min, int Max) FallbackAppDataRange = (64, 160);

    /// <summary>SERVER_HELLO_DELAY = (0.008, 0.024) seconds.</summary>
    public static readonly (double Min, double Max) ServerHelloDelay = (0.008, 0.024);

    public const int ProfileProbeTimeoutSeconds = 5;

    /// <summary>_CCS_FRAME = b'\x14\x03\x03\x00\x01\x01'.</summary>
    public static readonly byte[] CcsFrame = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];

    public const int ShRandomOffset = 11;
}

/// <summary>Python <c>ClientHelloInfo(NamedTuple)</c>.</summary>
public sealed record ClientHelloInfo(
    IReadOnlySet<int> CipherSuites,
    IReadOnlyDictionary<int, int> KeyShares)
{
    /// <summary>Python <c>_EMPTY_HELLO_INFO</c>.</summary>
    public static readonly ClientHelloInfo Empty =
        new(new HashSet<int>(), new Dictionary<int, int>());
}

/// <summary>
/// Byte-for-byte port of the server-side mini-TLS generator from
/// <c>proxy/fake_tls.py</c>: ClientHello verification against the obfuscated2
/// secret, parsing, ServerHello + CCS + ApplicationData first-flight building,
/// TLS record wrapping and the profiled appdata length.
/// All randomness flows through a single seam (<see cref="FillRandom"/> /
/// <see cref="NextInt32"/>) so tests can replay the exact byte stream the
/// Python golden vectors were generated with (tools/golden/README.md).
/// </summary>
public static class FakeTls
{
    [ThreadStatic]
    private static RandomNumberGenerator? _rng;

    /// <summary>RNG seam: fills <paramref name="buffer"/> like Python <c>os.urandom(len)</c>.</summary>
    public static Action<byte[]> FillRandom = buffer =>
        (_rng ??= RandomNumberGenerator.Create()).GetBytes(buffer);

    /// <summary>
    /// Inclusive uniform int in [minValue, maxValue], mirroring Python
    /// <c>random.randint</c>. Tests replace it together with
    /// <see cref="FillRandom"/> to reproduce golden streams.
    /// </summary>
    public static Func<int, int, int> NextInt32 = (minValue, maxValue) =>
        RandomNumberGenerator.GetInt32(minValue, maxValue + 1);

    private static byte[] RandomBytes(int count)
    {
        var bytes = new byte[count];
        FillRandom(bytes);
        return bytes;
    }

    // _profiled_appdata_len: set once at startup by probe_appdata_len()
    private static int? _profiledAppDataLen;

    /// <summary>Result of <c>verify_client_hello</c>: (client_random, session_id, timestamp).</summary>
    public sealed record VerifiedHello(byte[] ClientRandom, byte[] SessionId, uint Timestamp);

    /// <summary>
    /// Port of <c>verify_client_hello(data, secret)</c>. Returns <c>null</c> when
    /// the record is not a tagged ClientHello or the timestamp is outside tolerance.
    /// </summary>
    public static VerifiedHello? VerifyClientHello(ReadOnlySpan<byte> data, ReadOnlySpan<byte> secret)
    {
        var n = data.Length;
        // 5 (record hdr) + 6 (hs type+len+version) + 32 (random) = 43
        if (n < 43)
            return null;
        if (data[0] != FakeTlsConstants.TlsRecordHandshake)
            return null;
        if (data[5] != 0x01)
            return null;

        var clientRandom = data.Slice(FakeTlsConstants.ClientRandomOffset, FakeTlsConstants.ClientRandomLen).ToArray();

        var zeroed = data.ToArray();
        Array.Clear(zeroed, FakeTlsConstants.ClientRandomOffset, FakeTlsConstants.ClientRandomLen);

        var expected = HMACSHA256.HashData(secret, zeroed);

        if (!CryptographicOperations.FixedTimeEquals(
                expected.AsSpan(0, 28), clientRandom.AsSpan(0, 28)))
        {
            return null;
        }

        Span<byte> tsXor = stackalloc byte[4];
        for (var i = 0; i < 4; i++)
            tsXor[i] = (byte)(clientRandom[28 + i] ^ expected[28 + i]);
        var timestamp = BinaryPrimitives.ReadUInt32LittleEndian(tsXor);

        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (Math.Abs(now - timestamp) > FakeTlsConstants.TimestampTolerance)
            return null;

        var sessionId = new byte[FakeTlsConstants.SessionIdLen];
        if (n >= FakeTlsConstants.SessionIdOffset + FakeTlsConstants.SessionIdLen
            && data[43] == 0x20)
        {
            data.Slice(FakeTlsConstants.SessionIdOffset, FakeTlsConstants.SessionIdLen).CopyTo(sessionId);
        }

        return new VerifiedHello(clientRandom, sessionId, timestamp);
    }

    /// <summary>
    /// Port of <c>parse_client_hello(data)</c>: offered cipher suites and
    /// key_share group → share-length map. Malformed input yields
    /// <see cref="ClientHelloInfo.Empty"/> so callers fall back to plain
    /// X25519 / TLS_AES_128_GCM_SHA256.
    /// </summary>
    public static ClientHelloInfo ParseClientHello(ReadOnlySpan<byte> data)
    {
        try
        {
            var pos = 5 + 4 + 2 + FakeTlsConstants.ClientRandomLen;
            pos += 1 + data[pos];

            var suitesLen = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(pos, 2));
            pos += 2;
            var suitesEnd = pos + suitesLen;
            if (suitesEnd > data.Length)
                return ClientHelloInfo.Empty;

            var suites = new HashSet<int>();
            // Python: range(pos, suites_end - 1, 2) — pairs fully inside [pos, suites_end)
            for (var off = pos; off + 2 <= suitesEnd; off += 2)
                suites.Add(BinaryPrimitives.ReadUInt16BigEndian(data.Slice(off, 2)));
            pos = suitesEnd;

            pos += 1 + data[pos];

            var extTotal = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(pos, 2));
            pos += 2;
            var extEnd = Math.Min(pos + extTotal, data.Length);
            var keyShares = new Dictionary<int, int>();

            while (pos + 4 <= extEnd)
            {
                var extType = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(pos, 2));
                var extLen = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(pos + 2, 2));
                pos += 4;
                if (extType == FakeTlsConstants.ExtKeyShare && pos + 2 <= extEnd)
                {
                    var sharesEnd = Math.Min(
                        pos + 2 + BinaryPrimitives.ReadUInt16BigEndian(data.Slice(pos, 2)), extEnd);
                    var off = pos + 2;
                    while (off + 4 <= sharesEnd)
                    {
                        var group = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(off, 2));
                        var keyLen = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(off + 2, 2));
                        off += 4 + keyLen;
                        if (off <= sharesEnd)
                            keyShares.TryAdd(group, keyLen);
                    }
                }
                pos += extLen;
            }

            return new ClientHelloInfo(suites, keyShares);
        }
        catch (Exception e) when (e is ArgumentException or IndexOutOfRangeException or OverflowException)
        {
            // Python: except (IndexError, struct.error)
            return ClientHelloInfo.Empty;
        }
    }

    /// <summary>Port of <c>_select_cipher_suite(info)</c>.</summary>
    public static ushort SelectCipherSuite(ClientHelloInfo info)
    {
        foreach (var suite in FakeTlsConstants.CipherPreference)
        {
            if (info.CipherSuites.Contains(suite))
                return suite;
        }
        return FakeTlsConstants.CipherPreference[0];
    }

    /// <summary>
    /// Port of <c>_x25519_public_key()</c>: a real X25519 public key when the
    /// platform provides it; otherwise random bytes with the top bit cleared
    /// ("field elements below 2^255"), exactly like the Python fallback.
    /// </summary>
    public static byte[] X25519PublicKey()
    {
        try
        {
            using var ecdh = ECDiffieHellman.Create(EccNamedAlgorithm.X25519);
            var spki = ecdh.PublicKey.ExportSubjectPublicKeyInfo();
            // SPKI ends with 0x04 || raw 32-byte little-endian key
            var key = new byte[32];
            Array.Copy(spki, spki.Length - 32, key, 0, 32);
            return key;
        }
        catch (CryptographicException)
        {
            var key = new byte[FakeTlsConstants.X25519KeyLen];
            Rng.GetBytes(key);
            key[^1] &= 0x7F;
            return key;
        }
    }

    /// <summary>Port of <c>_server_key_share(info)</c>: (group, key_exchange).</summary>
    public static (ushort Group, byte[] KeyExchange) ServerKeyShare(ClientHelloInfo info)
    {
        // Mirror the hybrid post-quantum group when the client offers it.
        if (info.KeyShares.TryGetValue(FakeTlsConstants.GroupX25519Mlkem768, out var shareLen)
            && shareLen == FakeTlsConstants.X25519Mlkem768ClientShareLen)
        {
            var mlkem = new byte[FakeTlsConstants.Mlkem768CiphertextLen];
            Rng.GetBytes(mlkem);
            var x25519 = X25519PublicKey();
            var exchange = new byte[mlkem.Length + x25519.Length];
            mlkem.CopyTo(exchange, 0);
            x25519.CopyTo(exchange, mlkem.Length);
            return (FakeTlsConstants.GroupX25519Mlkem768, exchange);
        }
        return (FakeTlsConstants.GroupX25519, X25519PublicKey());
    }

    /// <summary>Port of <c>_appdata_len()</c>.</summary>
    public static int AppDataLength()
    {
        if (_profiledAppDataLen.HasValue)
            return _profiledAppDataLen.Value;
        var (lo, hi) = FakeTlsConstants.FallbackAppDataRange;
        return RandomNumberGenerator.GetInt32(lo, hi + 1); // Python randint is inclusive
    }

    /// <summary>
    /// Port of <c>build_server_hello(secret, client_random, session_id, info)</c>:
    /// ServerHello + CCS + one ApplicationData record, with the ServerHello
    /// random field replaced by HMAC-SHA256(secret, client_random || response).
    /// </summary>
    public static byte[] BuildServerHello(
        ReadOnlySpan<byte> secret,
        ReadOnlySpan<byte> clientRandom,
        ReadOnlySpan<byte> sessionId,
        ClientHelloInfo? info = null)
    {
        info ??= ClientHelloInfo.Empty;

        var (group, keyExchange) = ServerKeyShare(info);

        // extensions = supported_versions(0x0304) + key_share(group, keyExchange)
        using var exts = new MemoryStream();
        WriteUInt16BE(exts, FakeTlsConstants.ExtSupportedVersions);
        WriteUInt16BE(exts, 2);
        WriteUInt16BE(exts, 0x0304);

        WriteUInt16BE(exts, FakeTlsConstants.ExtKeyShare);
        WriteUInt16BE(exts, (ushort)(4 + keyExchange.Length));
        WriteUInt16BE(exts, group);
        WriteUInt16BE(exts, (ushort)keyExchange.Length);
        exts.Write(keyExchange);
        var extensions = exts.ToArray();

        // body = version12 || 32 zero bytes || len(sid) || sid || suite || 0x00 || ext_len || exts
        using var bodyMs = new MemoryStream();
        bodyMs.Write(FakeTlsConstants.TlsVersion12);
        bodyMs.Write(new byte[32]);
        bodyMs.WriteByte((byte)sessionId.Length);
        bodyMs.Write(sessionId);
        WriteUInt16BE(bodyMs, SelectCipherSuite(info));
        bodyMs.WriteByte(0x00); // empty compression method
        WriteUInt16BE(bodyMs, (ushort)extensions.Length);
        bodyMs.Write(extensions);
        var body = bodyMs.ToArray();

        // message = 0x02 || uint24(len(body)) || body
        using var msgMs = new MemoryStream();
        msgMs.WriteByte(0x02);
        msgMs.WriteByte((byte)(body.Length >> 16));
        msgMs.WriteByte((byte)(body.Length >> 8));
        msgMs.WriteByte((byte)body.Length);
        msgMs.Write(body);
        var message = msgMs.ToArray();

        // server_hello record = 0x16 || 0x0303 || uint16(len(message)) || message
        using var shMs = new MemoryStream();
        shMs.WriteByte(FakeTlsConstants.TlsRecordHandshake);
        shMs.Write(FakeTlsConstants.TlsVersion12);
        WriteUInt16BE(shMs, (ushort)message.Length);
        shMs.Write(message);

        // + CCS frame + one randomized ApplicationData record
        shMs.Write(FakeTlsConstants.CcsFrame);

        var appDataLen = AppDataLength();
        shMs.WriteByte(FakeTlsConstants.TlsRecordAppData);
        shMs.Write(FakeTlsConstants.TlsVersion12);
        WriteUInt16BE(shMs, (ushort)appDataLen);
        var appPayload = new byte[appDataLen];
        Rng.GetBytes(appPayload);
        shMs.Write(appPayload);

        var response = shMs.ToArray();

        // server_random = HMAC(secret, client_random || response)
        using var hmac = new HMACSHA256(secret.ToArray());
        using var hmacInput = new MemoryStream();
        hmacInput.Write(clientRandom);
        hmacInput.Write(response);
        var serverRandom = hmac.ComputeHash(hmacInput.ToArray());

        Array.Copy(serverRandom, 0, response, FakeTlsConstants.ShRandomOffset, 32);
        return response;
    }

    /// <summary>Port of <c>set_profiled_appdata_len(length)</c>.</summary>
    public static void SetProfiledAppDataLen(int? length)
    {
        if (length is null)
        {
            _profiledAppDataLen = null;
            return;
        }
        _profiledAppDataLen = Math.Max(
            FakeTlsConstants.AppDataMin,
            Math.Min(length.Value, FakeTlsConstants.TlsAppDataMax));
    }

    /// <summary>Current profiled first-appdata length (for tests/diagnostics).</summary>
    public static int? ProfiledAppDataLen => _profiledAppDataLen;

    /// <summary>
    /// Port of <c>first_appdata_record_len(data)</c>: length of the first
    /// ApplicationData record in a server flight; <c>null</c> while more data is
    /// needed; <c>0</c> if the flight cannot contain one.
    /// </summary>
    public static int? FirstAppDataRecordLen(ReadOnlySpan<byte> data)
    {
        var pos = 0;
        while (pos + 5 <= data.Length)
        {
            var rtype = data[pos];
            var recLen = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(pos + 3, 2));
            if (rtype == FakeTlsConstants.TlsRecordAppData)
                return recLen;
            if (rtype != FakeTlsConstants.TlsRecordHandshake && rtype != FakeTlsConstants.TlsRecordCcs)
                return 0;
            pos += 5 + recLen;
        }
        return null;
    }

    /// <summary>Port of <c>wrap_tls_record(data)</c>: chunk into ≤16384-byte appdata records.</summary>
    public static byte[] WrapTlsRecord(ReadOnlySpan<byte> data)
    {
        using var ms = new MemoryStream();
        var offset = 0;
        while (offset < data.Length)
        {
            var take = Math.Min(FakeTlsConstants.TlsAppDataMax, data.Length - offset);
            ms.Write([0x17, 0x03, 0x03]);
            WriteUInt16BE(ms, (ushort)take);
            ms.Write(data.Slice(offset, take));
            offset += take;
        }
        return ms.ToArray();
    }

    private static void WriteUInt16BE(Stream s, ushort value)
    {
        Span<byte> buf = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(buf, value);
        s.Write(buf);
    }
}
