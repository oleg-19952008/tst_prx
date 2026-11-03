namespace TgWsProxy.Transport.H2;

/// <summary>
/// Exception types used by the cf_h2 port (<c>proxy/cf_h2.py</c>). The Python code
/// distinguishes three failure classes on the media path:
/// <list type="bullet">
///   <item><description><see cref="NativeDeliveryError"/> — the local (Telegram Desktop)
///   socket is gone; the bridge just ends quietly.</description></item>
///   <item><description><see cref="ReplyBufferFullException"/> — a lane/channel memory
///   bound was hit; treated as a retryable transport error upstream.</description></item>
///   <item><description><see cref="MtprotoTransportError"/> — an endpoint-level MTProto
///   error (HTTP 403/404/429/444 or a negative int32 payload) that must be reported to
///   the native client as a real packet, not just EOF.</description></item>
/// </list>
/// </summary>
internal sealed class NativeDeliveryError(string message) : IOException(message);

/// <summary>Python <c>_ReplyBufferFull(BufferError)</c>.</summary>
internal sealed class ReplyBufferFullException(string message) : InvalidOperationException(message);

/// <summary>Python <c>_MTProtoTransportError</c>: carries the negative error code for the client.</summary>
internal sealed class MtprotoTransportError(int code, string source)
    : Exception($"{code} ({source})")
{
    public int Code { get; } = code;
}
