namespace TgWsProxy.Transport.H2;

/// <summary>
/// A single decoded HPACK header field: lowercase name + raw value bytes.
/// Values are kept as bytes because MTProto payload headers (e.g. the
/// binary body of a <c>POST /api</c> exchange) are not valid text.
/// </summary>
public readonly record struct HpackHeader(string Name, byte[] Value)
{
    /// <summary>Value interpreted as ASCII text (used for pseudo-headers like :status).</summary>
    public string ValueAscii => System.Text.Encoding.ASCII.GetString(Value);

    public override string ToString() => $"{Name}: {ValueAscii}";
}
