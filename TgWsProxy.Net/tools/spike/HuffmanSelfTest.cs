// RFC 7541 Appendix C.4.1 golden check for the HPACK Huffman decoder/encoder.
// Runs as part of SpikeTransport (exit code contributes to spike result).
using System.Text;
using TgWsProxy.Transport.H2;

internal static class HuffmanSelfTest
{
    public static (bool ok, string detail) RunC41()
    {
        // C.4.1: "www.example.com" encoded (request text, no literal flag byte).
        byte[] encoded = Convert.FromHexString(
            "f1e3c2e5f23a6baac8d29aee2b0b0f3f".Replace(" ", ""));
        const string expected = "www.example.com";

        byte[] decoded;
        try
        {
            decoded = HpackHuffman.Decode(encoded);
        }
        catch (Exception ex)
        {
            return (false, $"Decode threw {ex.GetType().Name}: {ex.Message}");
        }

        string text = Encoding.ASCII.GetString(decoded);
        if (text != expected)
            return (false, $"Decode returned \"{text}\", expected \"{expected}\"");

        // Round-trip: re-encode must reproduce the canonical octets.
        var dest = new byte[HpackHuffman.EncodedLength(decoded)];
        int n = HpackHuffman.Encode(decoded, dest);
        string hex = Convert.ToHexString(dest.AsSpan(0, n)).ToLowerInvariant();
        if (hex != "f1e3c2e5f23a6baac8d29aee2b0b0f3f")
            return (false, $"Encode round-trip produced {hex}, expected f1e3c2e5f23a6baac8d29aee2b0b0f3f");

        return (true, $"C.4.1 decode+encode round-trip OK (\"{text}\", {n} bytes)");
    }
}
