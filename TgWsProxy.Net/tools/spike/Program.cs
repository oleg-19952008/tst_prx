// Transport spike (PORT_PLAN.md §6, checklist items 5–6).
//
// Verifies the two hand-written transport stacks against LIVE endpoints:
//   A) RawWebSocket handshake (TCP -> SslStream -> HTTP/1.1 Upgrade) against a real
//      Telegram DC fronting IP using a web.telegram.org WS domain (SNI override), i.e.
//      exactly the path ConnectionPool uses at runtime.
//   B) H2Connection preflight (TCP -> SslStream ALPN h2 -> preface/SETTINGS -> HEAD)
//      against a Cloudflare worker domain from CfProxyDomains (the cf_h2 fallback path).
//
// Usage:
//   dotnet run --project tools/spike -- [options]
//     --dc <n>          DC id to probe (default: 2, media domain kws2.web.telegram.org)
//     --host <ip>       override DC IP (default: ProtocolConsts.DcDefaultIps[dc])
//     --domain <d>      override WS domain (default: WsDomains(dc, media)[0])
//     --no-sni          do not send an SNI override (direct validation against domain)
//     --cf-domain <d>   override CF worker domain for the H2 test
//                       (default: first decoded CfProxyDomains entry)
//     --skip-ws         run only the H2 part
//     --skip-h2         run only the WS part
//     --json <path>     also write machine-readable results to <path>
//
// Exit code: 0 = all requested spikes passed, 1 = at least one failed.
// The console output is designed to be pasted verbatim into docs/SPIKE_RESULTS.md.

using System.Diagnostics;
using System.Text.Json;
using TgWsProxy.Configuration;
using TgWsProxy.Core;
using TgWsProxy.Transport;
using TgWsProxy.Transport.H2;

var opts = ParseArgs(args);

Console.WriteLine($"SpikeTransport — {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}Z");
Console.WriteLine($".NET: {Environment.Version}, OS: {Environment.OSVersion}");
Console.WriteLine();

int failures = 0;
var results = new List<Dictionary<string, object?>>();
// [HPACK] offline unit check — RFC 7541 Appendix C.4.1 golden vector.
var (huffOk, huffDetail) = HuffmanSelfTest.RunC41();
Console.WriteLine($"[HPACK-C.4.1] {(huffOk ? "PASS" : "FAIL")} — {huffDetail}");
results.Add(new Dictionary<string, object?> { ["test"] = "hpack_huffman_c41", ["pass"] = huffOk, ["detail"] = huffDetail });
if (!huffOk) failures++;


if (!opts.SkipWs)
    results.Add(await RunWsSpikeAsync(opts));
if (!opts.SkipH2)
    results.Add(await RunH2SpikeAsync(opts));

failures = results.Count(r => (bool)r["pass"] == false);

if (opts.JsonPath is not null)
{
    await File.WriteAllTextAsync(opts.JsonPath,
        JsonSerializer.Serialize(results, new JsonSerializerOptions { WriteIndented = true }));
    Console.WriteLine($"\nJSON results written to {opts.JsonPath}");
}

Console.WriteLine();
Console.WriteLine(failures == 0
    ? "SPIKE RESULT: PASS (" + results.Count + " checks)"
    : $"SPIKE RESULT: FAIL ({failures}/{results.Count} checks failed)");
return failures == 0 ? 0 : 1;

// ----------------------------------------------------------------------
// A) Raw WebSocket handshake against a real Telegram DC endpoint
// ----------------------------------------------------------------------

static async Task<Dictionary<string, object?>> RunWsSpikeAsync(SpikeOptions opts)
{
    string host = opts.DcHost ?? (ProtocolConsts.DcDefaultIps.TryGetValue(opts.Dc, out var ip)
        ? ip : throw new InvalidOperationException($"No default IP for DC {opts.Dc}"));
    string domain = opts.WsDomain ?? ProtocolConsts.WsDomains(opts.Dc, isMedia: true)[0];
    string? sni = opts.NoSni ? null : domain; // fronting-style SNI override when set

    Console.WriteLine($"[WS] target tcp://{host}:443  Host: {domain}  SNI: {sni ?? "(none — direct)"}");
    var sw = Stopwatch.StartNew();
    var res = new Dictionary<string, object?>
    { ["check"] = "ws_handshake", ["host"] = host, ["domain"] = domain, ["sni"] = sni };
    try
    {
        await using var ws = await RawWebSocket.ConnectAsync(
            host, domain, TimeSpan.FromSeconds(10),
            path: ProtocolConsts.WsPath, sni: sni, secure: true);
        sw.Stop();
        Console.WriteLine($"[WS] PASS — HTTP 101 upgrade in {sw.ElapsedMilliseconds} ms; " +
                          $"TLS negotiated, connection open (Closed={ws.Closed})");
        // Round-trip sanity: send a zero-length ping frame and expect any reply/close
        // to surface without exceptions (parser smoke-test against a live peer).
        await ws.SendBatchAsync([[]], CancellationToken.None);
        res["pass"] = true;
        res["elapsed_ms"] = sw.ElapsedMilliseconds;
    }
    catch (Exception ex)
    {
        sw.Stop();
        Console.WriteLine($"[WS] FAIL after {sw.ElapsedMilliseconds} ms: {ex.GetType().Name}: {ex.Message}");
        if (ex is WsHandshakeException wse)
            Console.WriteLine($"[WS]   status={wse.StatusCode} line='{wse.StatusLine}' redirect={wse.IsRedirect}");
        res["pass"] = false;
        res["error"] = $"{ex.GetType().Name}: {ex.Message}";
        res["elapsed_ms"] = sw.ElapsedMilliseconds;
    }
    Console.WriteLine();
    return res;
}

// ----------------------------------------------------------------------
// B) H2 preflight (ALPN h2 + SETTINGS exchange + HEAD /api) against CF domain
// ----------------------------------------------------------------------

static async Task<Dictionary<string, object?>> RunH2SpikeAsync(SpikeOptions opts)
{
    // Exactly the lane host used by HttpLane/_preflight in cf_h2.py: kws<dc>.<cf domain>.
    string baseDomain = opts.CfDomain ?? CfProxyDomains.DefaultDomains[0];
    string authority = $"kws{opts.Dc}.{baseDomain}";
    Console.WriteLine($"[H2] target https://{authority}/api  (preflight HEAD via own H2 stack)");
    var sw = Stopwatch.StartNew();
    var res = new Dictionary<string, object?> { ["check"] = "h2_preflight", ["authority"] = authority };
    try
    {
        var options = new H2ConnectionOptions
        {
            SniHost = authority,
            ConnectTimeout = TimeSpan.FromSeconds(10),
            KeepAliveInterval = TimeSpan.Zero, // single-shot spike: no ping loop needed
        };
        await using var conn = await H2Connection.ConnectAsync(authority, 443, options);
        int status = await conn.PreflightStatusAsync(authority, "/api");
        sw.Stop();
        // Same acceptance rule as HttpLane.PreflightAsync (cf_h2.py::_preflight):
        // 2xx, 405 or 501 prove TCP+TLS(ALPN h2)+framing+HPACK round-trip works live.
        bool ok = (status is >= 200 and < 300) || status is 405 or 501;
        Console.WriteLine($"[H2] {(ok ? "PASS" : "FAIL")} — ALPN '{conn.AlpnProtocol}', " +
                          $"SETTINGS acked, HEAD /api -> HTTP {status} in {sw.ElapsedMilliseconds} ms");
        res["pass"] = ok;
        res["status"] = status;
        res["alpn"] = conn.AlpnProtocol;
        res["elapsed_ms"] = sw.ElapsedMilliseconds;
    }
    catch (Exception ex)
    {
        sw.Stop();
        Console.WriteLine($"[H2] FAIL after {sw.ElapsedMilliseconds} ms: {ex.GetType().Name}: {ex.Message}");
        res["pass"] = false;
        res["error"] = $"{ex.GetType().Name}: {ex.Message}";
        res["elapsed_ms"] = sw.ElapsedMilliseconds;
    }
    Console.WriteLine();
    return res;
}

// ----------------------------------------------------------------------

static SpikeOptions ParseArgs(string[] args)
{
    var o = new SpikeOptions();
    for (int i = 0; i < args.Length; i++)
    {
        string Next() => i + 1 < args.Length ? args[++i]
            : throw new ArgumentException($"Missing value for {args[i]}");
        switch (args[i])
        {
            case "--dc": o.Dc = int.Parse(Next()); break;
            case "--host": o.DcHost = Next(); break;
            case "--domain": o.WsDomain = Next(); break;
            case "--no-sni": o.NoSni = true; break;
            case "--cf-domain": o.CfDomain = Next(); break;
            case "--skip-ws": o.SkipWs = true; break;
            case "--skip-h2": o.SkipH2 = true; break;
            case "--json": o.JsonPath = Next(); break;
            default: throw new ArgumentException($"Unknown option: {args[i]}");
        }
    }
    return o;
}

sealed class SpikeOptions
{
    public int Dc { get; set; } = 2;
    public string? DcHost { get; set; }
    public string? WsDomain { get; set; }
    public bool NoSni { get; set; }
    public string? CfDomain { get; set; }
    public bool SkipWs { get; set; }
    public bool SkipH2 { get; set; }
    public string? JsonPath { get; set; }
}
