using System.Buffers.Binary;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using TgWsProxy.Configuration;
using TgWsProxy.Core;

namespace TgWsProxy.Transport;

/// <summary>HTTP status carried by a failed WS handshake (Python WsHandshakeError).</summary>
public sealed class WsHandshakeException : Exception
{
    public int StatusCode { get; }
    public string StatusLine { get; }
    public Dictionary<string, string> Headers { get; }
    public string? Location { get; }

    public WsHandshakeException(int statusCode, string statusLine,
                                Dictionary<string, string>? headers = null,
                                string? location = null)
        : base($"HTTP {statusCode}: {statusLine}")
    {
        StatusCode = statusCode;
        StatusLine = statusLine;
        Headers = headers ?? new();
        Location = location;
    }

    public bool IsRedirect => StatusCode is 301 or 302 or 303 or 307 or 308;
}

/// <summary>
/// Raw WebSocket client over TLS — port of Python <c>proxy/raw_websocket.py::RawWebSocket</c>.
/// Uses <see cref="SslStream"/> with an overridden ClientHello SNI (Telegram DC IPs present
/// certificates that don't match the kws*.web.telegram.org names), mirroring the Python
/// <c>server_hostname=sni</c> trick. Phase-4 work (full FakeTLS/self-TLS stack) will replace
/// only the handshake layer; frame codec stays.
/// </summary>
public sealed class RawWebSocket : IAsyncDisposable
{
    public const byte OpCont = 0x0;
    public const byte OpBinary = 0x2;
    public const byte OpClose = 0x8;
    public const byte OpPing = 0x9;
    public const byte OpPong = 0xA;

    public const int MaxMessageLen = 16 * 1024 * 1024;

    private readonly TcpClient _tcp;
    private readonly Stream _stream;          // SslStream or NetworkStream (secure=false)
    private readonly byte[] _readHeaderBuf = new byte[16];
    private readonly MemoryStream _frag = new();
    private int _closeCodeSent;
    private volatile bool _closedFlag;

    public bool Closed => _closedFlag || !_tcp.Connected;
    public DateTime CreatedMonotonicUtc { get; } = DateTime.UtcNow;

    private RawWebSocket(TcpClient tcp, Stream stream)
    {
        _tcp = tcp;
        _stream = stream;
    }

    /// <summary>
    /// Python <c>RawWebSocket.connect(host, domain, timeout, path, sni, secure)</c>.
    /// Connects to <paramref name="host"/>:443 (or :80 when insecure), performs TLS with
    /// SNI=<paramref name="sni"/> ?? <paramref name="domain"/>, then the HTTP/1.1 Upgrade.
    /// </summary>
    public static async Task<RawWebSocket> ConnectAsync(
        string host, string domain, TimeSpan timeout,
        string path = ProtocolConsts.WsPath,
        string? sni = null, bool secure = true,
        ProxyConfig? config = null, CancellationToken ct = default)
    {
        var tcp = new TcpClient { NoDelay = true };
        if (config is not null)
        {
            try { tcp.SendBufferSize = config.BufferSize; tcp.ReceiveBufferSize = config.BufferSize; }
            catch { /* best-effort, like set_sock_opts */ }
        }

        // NOTE: NetworkStream must only be obtained AFTER ConnectAsync — TcpClient.GetStream()
        // throws InvalidOperationException while the socket is not connected.
        Stream? stream = null;
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);

            int port = secure ? 443 : 80;
            await tcp.ConnectAsync(host, port, cts.Token).ConfigureAwait(false);
            stream = tcp.GetStream();

            if (secure)
            {
                // Mirrors Python raw_websocket.py:
                //   ssl_context = _ssl_ctx_fronting if sni else _ssl_ctx
                // where _ssl_ctx_fronting = create_ssl_context(check_hostname=False).
                // Fronted connections (SNI override, e.g. "sprinthost.ru") validate the
                // certificate chain but skip the hostname match, because the DC IP serves
                // a certificate that doesn't cover the SNI name. Unfronted connections get
                // full default validation (chain + name against `domain`).
                var skipHostnameCheck = sni is not null && !string.Equals(sni, domain, StringComparison.OrdinalIgnoreCase);
                var ssl = new SslStream(
                    stream, leaveInnerStreamOpen: false,
                    userCertificateValidationCallback: skipHostnameCheck
                        ? static (_, cert, chain, errors) =>
                            cert is not null &&
                            (errors & ~SslPolicyErrors.RemoteCertificateNameMismatch) == SslPolicyErrors.None
                        : null);
                var options = new SslClientAuthenticationOptions
                {
                    TargetHost = sni ?? domain,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                };
                await ssl.AuthenticateAsClientAsync(options, cts.Token).ConfigureAwait(false);
                stream = ssl;
            }

            string wsKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
            var req = new StringBuilder()
                .Append($"GET {path} HTTP/1.1\r\n")
                .Append($"Host: {domain}\r\n")
                .Append("Upgrade: websocket\r\n")
                .Append("Connection: Upgrade\r\n")
                .Append($"Sec-WebSocket-Key: {wsKey}\r\n")
                .Append("Sec-WebSocket-Version: 13\r\n")
                .Append("Sec-WebSocket-Protocol: binary\r\n")
                .Append("\r\n");
            byte[] reqBytes = Encoding.ASCII.GetBytes(req.ToString());
            await stream.WriteAsync(reqBytes, cts.Token).ConfigureAwait(false);
            await stream.FlushAsync(cts.Token).ConfigureAwait(false);

            var (status, statusLine, headers) = await ReadHttpHeadAsync(stream, cts.Token)
                .ConfigureAwait(false);

            if (status == 101)
                return new RawWebSocket(tcp, stream);

            stream.Dispose();
            tcp.Dispose();
            headers.TryGetValue("location", out var location);
            throw new WsHandshakeException(status, statusLine, headers, location);
        }
        catch
        {
            if (stream is not null) TryDispose(stream);
            tcp.Dispose();
            throw;
        }
    }

    private static void TryDispose(IDisposable d) { try { d.Dispose(); } catch { } }

    private static async Task<(int status, string statusLine, Dictionary<string, string> headers)>
        ReadHttpHeadAsync(Stream stream, CancellationToken ct)
    {
        // Read line-by-line until the blank terminator line (Python readline() loop).
        var lineBuf = new List<byte>(128);
        var one = new byte[1];
        var lines = new List<string>();
        while (true)
        {
            int n = await stream.ReadAsync(one, 0, 1, ct).ConfigureAwait(false);
            if (n == 0) break;                       // EOF → empty/partial response
            if (one[0] == (byte)'\n')
            {
                if (lineBuf.Count > 0 && lineBuf[^1] == (byte)'\r')
                    lineBuf.RemoveAt(lineBuf.Count - 1);
                if (lineBuf.Count == 0)
                    break;                            // blank line: end of headers
                lines.Add(Encoding.UTF8.GetString(lineBuf.ToArray()).Trim());
                lineBuf.Clear();
                if (lines.Count > 512) break;         // safety bound
            }
            else
            {
                lineBuf.Add(one[0]);
                if (lineBuf.Count > 64 * 1024) break;
            }
        }

        var headers = new Dictionary<string, string>();
        if (lines.Count == 0)
            return (0, "empty response", headers);

        var parts = lines[0].Split(' ', 3);
        int status = parts.Length >= 2 && int.TryParse(parts[1], out var s) ? s : 0;
        for (int i = 1; i < lines.Count; i++)
        {
            int colon = lines[i].IndexOf(':');
            if (colon > 0)
                headers[lines[i][..colon].Trim().ToLowerInvariant()] = lines[i][(colon + 1)..].Trim();
        }
        return (status, lines[0], headers);
    }

    /// <summary>Send one masked binary frame (Python <c>send</c>).</summary>
    public async Task SendAsync(ReadOnlyMemory<byte> data, CancellationToken ct = default)
    {
        if (_closedFlag) throw new IOException("WebSocket closed");
        var frame = BuildFrame(OpBinary, data.Span, mask: true);
        await _stream.WriteAsync(frame, ct).ConfigureAwait(false);
        await _stream.FlushAsync(ct).ConfigureAwait(false);
    }

    /// <summary>Write several frames then flush once (Python <c>send_batch</c>).</summary>
    public async Task SendBatchAsync(IReadOnlyList<byte[]> parts, CancellationToken ct = default)
    {
        if (_closedFlag) throw new IOException("WebSocket closed");
        foreach (var part in parts)
            await _stream.WriteAsync(BuildFrame(OpBinary, part, mask: true), ct).ConfigureAwait(false);
        await _stream.FlushAsync(ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Receive the next binary message; auto-answers PING, skips PONG, handles CLOSE.
    /// Returns null at close/EOF (Python <c>recv</c>).
    /// </summary>
    public async Task<byte[]?> ReceiveAsync(CancellationToken ct = default)
    {
        while (!_closedFlag)
        {
            var (opcode, payload, fin) = await ReadFrameAsync(ct).ConfigureAwait(false);

            if (opcode == OpClose)
            {
                _closedFlag = true;
                try
                {
                    byte[] echo = payload.Length >= 2 ? payload[..2] : Array.Empty<byte>();
                    await _stream.WriteAsync(BuildFrame(OpClose, echo, mask: true), ct)
                                  .ConfigureAwait(false);
                    await _stream.FlushAsync(ct).ConfigureAwait(false);
                }
                catch { /* ignore, as Python does */ }
                return null;
            }

            if (opcode == OpPing)
            {
                try
                {
                    await _stream.WriteAsync(BuildFrame(OpPong, payload, mask: true), ct)
                                  .ConfigureAwait(false);
                    await _stream.FlushAsync(ct).ConfigureAwait(false);
                }
                catch { }
                continue;
            }

            if (opcode == OpPong)
                continue;

            if (opcode is OpCont or 0x1 or OpBinary)
            {
                if (fin && _frag.Length == 0)
                    return payload;
                _frag.Write(payload, 0, payload.Length);
                if (_frag.Length > MaxMessageLen)
                    throw new IOException($"WS message too large: {_frag.Length} bytes");
                if (!fin) continue;
                var message = _frag.ToArray();
                _frag.SetLength(0);
                return message;
            }
        }
        return null;
    }

    public async Task CloseAsync()
    {
        try
        {
            if (!_closedFlag)
            {
                _closedFlag = true;
                try
                {
                    await _stream.WriteAsync(BuildFrame(OpClose, ReadOnlySpan<byte>.Empty, mask: true))
                                .ConfigureAwait(false);
                    await _stream.FlushAsync().ConfigureAwait(false);
                }
                catch { }
            }
        }
        finally
        {
            try { _stream.Dispose(); } catch { }
            try { _tcp.Dispose(); } catch { }
        }
    }

    public ValueTask DisposeAsync() { CloseAsync().GetAwaiter().GetResult(); return ValueTask.CompletedTask; }

    private async Task<(byte opcode, byte[] payload, bool fin)> ReadFrameAsync(CancellationToken ct)
    {
        await ReadExactlyAsync(_readHeaderBuf.AsMemory(0, 2), ct).ConfigureAwait(false);
        bool fin = (_readHeaderBuf[0] & 0x80) != 0;
        byte opcode = (byte)(_readHeaderBuf[0] & 0x0F);
        long length = (long)(_readHeaderBuf[1] & 0x7F);
        bool masked = (_readHeaderBuf[1] & 0x80) != 0;

        if (length == 126)
        {
            await ReadExactlyAsync(_readHeaderBuf.AsMemory(0, 2), ct).ConfigureAwait(false);
            length = BinaryPrimitives.ReadUInt16BigEndian(_readHeaderBuf.AsSpan(0, 2));
        }
        else if (length == 127)
        {
            await ReadExactlyAsync(_readHeaderBuf.AsMemory(0, 8), ct).ConfigureAwait(false);
            length = (long)BinaryPrimitives.ReadUInt64BigEndian(_readHeaderBuf.AsSpan(0, 8));
        }

        if (length > MaxMessageLen)
            throw new IOException($"WS frame too large: {length} bytes");

        byte[] maskKey = Array.Empty<byte>();
        if (masked)
        {
            maskKey = new byte[4];
            await ReadExactlyAsync(maskKey, ct).ConfigureAwait(false);
        }

        var payload = new byte[length];
        if (length > 0)
            await ReadExactlyAsync(payload, ct).ConfigureAwait(false);
        if (masked)
            XorMaskInPlace(payload, maskKey);
        return (opcode, payload, fin);
    }

    private async Task ReadExactlyAsync(Memory<byte> buffer, CancellationToken ct)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int n = await _stream.ReadAsync(buffer[total..], ct).ConfigureAwait(false);
            if (n == 0)
                throw new EndOfStreamException();
            total += n;
        }
    }

    private static byte[] BuildFrame(byte opcode, ReadOnlySpan<byte> data, bool mask)
    {
        long length = data.Length;
        int extLen = length < 126 ? 0 : length <= ushort.MaxValue ? 2 : 8;
        int maskLen = mask ? 4 : 0;
        var frame = new byte[2 + extLen + maskLen + (int)length];

        frame[0] = (byte)(0x80 | opcode);
        int pos = 2;
        if (extLen == 2)
        {
            frame[1] = mask ? (byte)(0x80 | 126) : (byte)126;
            BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(2, 2), (ushort)length);
            pos = 4;
        }
        else if (extLen == 8)
        {
            frame[1] = mask ? (byte)(0x80 | 127) : (byte)127;
            BinaryPrimitives.WriteUInt64BigEndian(frame.AsSpan(2, 8), (ulong)length);
            pos = 10;
        }
        else
        {
            frame[1] = mask ? (byte)(0x80 | (int)length) : (byte)length;
        }

        data.CopyTo(frame.AsSpan(pos));
        if (mask)
        {
            byte[] maskKey = RandomNumberGenerator.GetBytes(4);
            maskKey.CopyTo(frame.AsSpan(pos));
            pos += 4;
            XorMaskInPlace(frame.AsSpan(pos, (int)length), maskKey);
        }
        return frame;
    }

    private static void XorMaskInPlace(Span<byte> data, ReadOnlySpan<byte> mask)
    {
        for (int i = 0; i < data.Length; i++)
            data[i] ^= mask[i % 4];
    }

    private static void XorMaskInPlace(byte[] data, byte[] mask) => XorMaskInPlace(data.AsSpan(), mask);
}
