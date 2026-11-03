namespace TgWsProxy.Transport.H2;

/// <summary>
/// HTTP/2 wire constants (RFC 9113) shared by the frame codec, HPACK and the
/// connection engine. Mirrors what the Python stack (<c>h2</c> library +
/// <c>proxy/h2_transport.py</c>) relies on.
/// </summary>
internal static class H2Consts
{
    /// <summary>Client connection preface (RFC 9113 §3.4).</summary>
    public static ReadOnlySpan<byte> ClientPreface =>
        "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8;

    public const int FrameHeaderSize = 9;
    public const int MaxFrameSizeLimit = 16 * 1024 * 1024 - 1; // 24-bit length field

    /// <summary>Default SETTINGS_INITIAL_WINDOW_SIZE (RFC 9113 §6.5.2, §6.9.2).</summary>
    public const int DefaultInitialWindowSize = 65535;

    /// <summary>Default max frame size (RFC 9113 §6.5.2).</summary>
    public const int DefaultMaxFrameSize = 16384;

    /// <summary>Stream receive window used by the port (<c>h2_transport.STREAM_RECEIVE_WINDOW</c>).</summary>
    public const int StreamReceiveWindow = 256 * 1024;

    /// <summary>Connection receive window (<c>h2_transport.CONNECTION_RECEIVE_WINDOW</c>).</summary>
    public const int ConnectionReceiveWindow = 4 * 1024 * 1024;

    /// <summary>I/O batch size (<c>h2_transport.IO_BATCH_SIZE</c>): WINDOW_UPDATE aggregation quantum.</summary>
    public const int IoBatchSize = 64 * 1024;

    /// <summary>Maximum HEADERS payload we are willing to buffer at once.</summary>
    public const int MaxHeadersPayload = 128 * 1024;
}

/// <summary>HTTP/2 frame types (RFC 9113 §6).</summary>
internal enum H2FrameType : byte
{
    Data = 0x0,
    Headers = 0x1,
    Priority = 0x2,
    RstStream = 0x3,
    Settings = 0x4,
    PushPromise = 0x5,
    Ping = 0x6,
    GoAway = 0x7,
    WindowUpdate = 0x8,
    Continuation = 0x9,
}

/// <summary>HTTP/2 frame flags (RFC 9113 §6).</summary>
[Flags]
internal enum H2Flags : byte
{
    None = 0,
    /// <summary>DATA/HEADERS: half-closed (remote) after this frame.</summary>
    EndStream = 0x1,
    /// <summary>SETTINGS / PING: acknowledgement.</summary>
    Ack = 0x1,
    /// <summary>HEADERS: priority block (5 bytes) present.</summary>
    Priority = 0x20,
    /// <summary>HEADERS/DATA/PUSH_PROMISE: padding present.</summary>
    Padded = 0x8,
    /// <summary>HEADERS/CONTINUATION: header block is complete.</summary>
    EndHeaders = 0x4,
}

/// <summary>HTTP/2 error codes (RFC 9113 §7). Values match <c>h2.errors.ErrorCodes</c>.</summary>
public enum H2ErrorCode : uint
{
    NoError = 0x0,
    ProtocolError = 0x1,
    InternalError = 0x2,
    FlowControlError = 0x3,
    SettingsTimeout = 0x4,
    StreamClosed = 0x5,
    FrameRefused = 0x6,
    Cancel = 0x7,
    CompressionError = 0x8,
    GoawayError = 0x9,
    ConnectError = 0xa,
    EnhanceYourCalm = 0xb,
    ExcessiveLoad = 0xc,
    MissingAuthority = 0xd,
    FrameSizeError = 0x10000001, // h2-library-specific pseudo code (FrameTooLargeError)
}

/// <summary>HTTP/2 SETTINGS identifiers (RFC 9113 §6.5.2).</summary>
internal enum H2SettingId : ushort
{
    HeaderTableSize = 0x1,
    EnablePush = 0x2,
    MaxConcurrentStreams = 0x3,
    InitialWindowSize = 0x4,
    MaxFrameSize = 0x5,
    MaxHeaderListSize = 0x6,
}
