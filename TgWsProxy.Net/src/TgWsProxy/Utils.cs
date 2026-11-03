using System.Net;
using System.Net.Sockets;

namespace TgWsProxy;

/// <summary>
/// Small helpers ported from <c>tg-ws-proxy-main_py/proxy/utils.py</c>.
/// </summary>
public static class Utils
{
    /// <summary>
    /// Python <c>utils.get_link_host(host)</c>: when the proxy binds to the
    /// wildcard address <c>0.0.0.0</c>, discover this machine's LAN IPv4 by
    /// "connecting" a connectionless UDP socket to 8.8.8.8:80 (no packets are
    /// sent; the OS just picks the source address of the default route) and
    /// fall back to <c>127.0.0.1</c> on any socket error. Any other bind
    /// address is returned unchanged — it is used verbatim in the
    /// <c>tg://proxy?server=…&amp;port=…&amp;secret=dd…</c> / <c>ee…</c> links
    /// printed at startup (see tg_ws_proxy.py).
    /// </summary>
    public static string GetLinkHost(string host)
    {
        if (host != "0.0.0.0")
            return host;

        try
        {
            using var s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            // Dagram sockets are connectionless: Connect() only selects the
            // outgoing interface/route, exactly like the Python version.
            s.Connect(IPAddress.Parse("8.8.8.8"), 80);
            if (s.LocalEndPoint is IPEndPoint ep
                && ep.Address.AddressFamily == AddressFamily.InterNetwork)
            {
                return ep.Address.ToString();
            }
        }
        catch (SocketException)
        {
            // Python: except OSError → link_host = '127.0.0.1'
        }
        return "127.0.0.1";
    }

    /// <summary>
    /// Startup banner helper — Python <c>tg_ws_proxy.run_server()</c>:
    /// <c>dd_link = f"tg://proxy?server={link_host}&amp;port={port}&amp;secret=dd{secret}"</c>.
    /// </summary>
    public static string BuildDdLink(string linkHost, int port, string secret) =>
        $"tg://proxy?server={linkHost}&port={port}&secret=dd{secret}";

    /// <summary>
    /// Fake-TLS ("ee") variant — Python:
    /// <c>secret=ee{secret}{ftls.encode('ascii').hex()}</c>. Returns an empty
    /// string when no Fake TLS domain is configured (same as Python's
    /// <c>ee_link = ""</c>).
    /// </summary>
    public static string BuildEeLink(string linkHost, int port, string secret, string fakeTlsDomain)
    {
        if (string.IsNullOrEmpty(fakeTlsDomain))
            return "";
        var domainHex = Convert.ToHexString(System.Text.Encoding.ASCII.GetBytes(fakeTlsDomain))
            .ToLowerInvariant(); // Python bytes.hex() is lowercase
        return $"tg://proxy?server={linkHost}&port={port}&secret=ee{secret}{domainHex}";
    }

    /// <summary>
    /// Python <c>utils.human_bytes</c>: divide by 1024 while |n| &gt;= 1024 over
    /// the units B, KB, MB, GB, finally TB — always one decimal place.
    /// The C# version keeps the value in <see cref="double"/> after the first
    /// division exactly like Python's true-division does.
    /// </summary>
    public static string HumanBytes(long n)
    {
        double v = n;
        foreach (var unit in new[] { "B", "KB", "MB", "GB" })
        {
            if (Math.Abs(v) < 1024)
                return FormattableString.Invariant($"{v:F1}{unit}");
            v /= 1024;
        }
        return FormattableString.Invariant($"{v:F1}TB");
    }
}
