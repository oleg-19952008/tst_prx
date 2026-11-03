namespace TgWsProxy.Transport.H2;

/// <summary>Raised for HPACK/HTTP2 protocol violations recoverable at the connection level.</summary>
internal sealed class HpackException(string message) : Exception(message);

/// <summary>Raised for unrecoverable HTTP/2 connection-level protocol errors (GOAWAY condition).</summary>
internal sealed class H2ProtocolException(H2ErrorCode code, string message)
    : Exception(message)
{
    public H2ErrorCode Code { get; } = code;
}
