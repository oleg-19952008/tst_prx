using System.Net.Sockets; // SocketException handling (PORT_PLAN.md §3 item 9)
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using TgWsProxy.Configuration;
using TgWsProxy.Observability;

const string AppTitle = "TgWsProxy";

// ---------------------------------------------------------------------------
// CLI contract (PORT_PLAN.md §1):
//   TgWsProxy.exe                 — run with appsettings.json next to the exe
//   TgWsProxy.exe --config <path> — override configuration file
//   TgWsProxy.exe --version       — print version and exit 0
//   Ctrl+C                        — graceful shutdown via IHostApplicationLifetime
// ---------------------------------------------------------------------------

if (args.Contains("--version", StringComparer.OrdinalIgnoreCase))
{
    var version = typeof(Program).Assembly.GetName().Version;
    Console.WriteLine($"{AppTitle} {version?.ToString(3) ?? "0.0.0"} (.NET port of tg-ws-proxy)");
    return 0;
}

string? configPath = null;
for (var i = 0; i < args.Length - 1; i++)
{
    if (string.Equals(args[i], "--config", StringComparison.OrdinalIgnoreCase))
    {
        configPath = args[i + 1];
        break;
    }
}

if (args.Length == 1 && File.Exists(args[0]))
    configPath = args[0]; // positional path also accepted

var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
{
    Args = args,
    ApplicationName = AppTitle,
    ContentRootPath = AppContext.BaseDirectory,
});

if (configPath is not null)
{
    if (!File.Exists(configPath))
    {
        Console.Error.WriteLine($"Config file not found: {configPath}");
        return 2;
    }
    // Replace the default appsettings.json with the user-specified file.
    builder.Configuration.Sources.Clear();
    builder.Configuration.AddJsonFile(Path.GetFullPath(configPath), optional: false, reloadOnChange: false);
}

// --- Configuration binding + validation (PORT_PLAN.md §2) -------------------
builder.Services.Configure<ProxyConfig>(builder.Configuration.GetSection(ProxyConfig.SectionName));
builder.Services.AddSingleton<ProxyConfigValidator>();
builder.Services.AddSingleton<IValidateOptions<ProxyConfig>>(sp => sp.GetRequiredService<ProxyConfigValidator>());
builder.Services.AddSingleton<IPostConfigureOptions<ProxyConfig>>(sp => sp.GetRequiredService<ProxyConfigValidator>());

// --- Observability (PORT_PLAN.md §3 item 8) ---------------------------------
// ProxyStats          — Python proxy/stats.py::_Stats (Interlocked counters)
// NetworkDebug        — Python proxy/network_debug.py (WsActivity registry +
//                       log_ws_flow) plus the periodic console reporter that
//                       replaces the GUI dashboard windows.
builder.Services.AddSingleton<ProxyStats>();
builder.Services.AddSingleton<NetworkDebug>();

var host = builder.Build();

var logger = host.Services.GetRequiredService<ILoggerFactory>().CreateLogger(AppTitle);
var lifetime = host.Services.GetRequiredService<IHostApplicationLifetime>();

ProxyConfig config;
try
{
    config = host.Services.GetRequiredService<IOptions<ProxyConfig>>().Value;
}
catch (OptionsValidationException ex)
{
    foreach (var failure in ex.Failures)
        logger.LogError("Invalid configuration: {Failure}", failure);
    return 2;
}

ProxyConfigValidator.s_logger = logger;

logger.LogInformation(
    "{Title} starting: {Host}:{Port}, pool={PoolSize}, buffer={BufferKb} KB, H2={H2}, DC redirects: {Dcs}",
    AppTitle, config.Host, config.Port, config.PoolSize, config.BufferSizeKb, config.H2Enabled,
    string.Join(", ", config.DcRedirects.OrderBy(kv => kv.Key).Select(kv => $"{kv.Key}->{kv.Value}")));

// Print the secret when it was auto-generated (empty in config) — Telegram
// Desktop must be pointed at it manually, mirroring the GUI behaviour.
var configuredSecret = builder.Configuration[$"{ProxyConfig.SectionName}:{nameof(ProxyConfig.Secret)}"];
if (string.IsNullOrWhiteSpace(configuredSecret))
    logger.LogInformation("No Proxy:Secret configured — generated one-time secret: {Secret}", config.Secret);

// --- Stats / network-debug console reporting (checklist item 8) -------------
var stats = host.Services.GetRequiredService<ProxyStats>();
var debug = host.Services.GetRequiredService<NetworkDebug>();

TimeSpan? FlowInterval() => config.FlowDebugIntervalSec > 0
    ? TimeSpan.FromSeconds(config.FlowDebugIntervalSec)
    : null;
TimeSpan? StatsInterval() => config.StatsIntervalSec > 0
    ? TimeSpan.FromSeconds(config.StatsIntervalSec)
    : null;

// The reporter loop mirrors tg_ws_proxy.py::log_stats: flow dumps every 5 s
// while Debug logging is enabled, "stats: ..." INFO line every 60 s (both
// cadences configurable). If the stats report is disabled but flow debugging
// is on, keep the faster timer so WS FLOW lines still appear.
var timerPeriod = StatsInterval() ?? FlowInterval();
if (timerPeriod is { } period)
{
    debug.StartReporting(
        FlowInterval() ?? period,
        StatsInterval() ?? TimeSpan.FromDays(365)); // effectively disables INFO line
    logger.LogInformation(
        "Console reporter: stats every {Stats}s, WS-flow debug every {Flow}s (Debug level required){Suffix}",
        config.StatsIntervalSec, config.FlowDebugIntervalSec,
        debug.Enabled ? " — ACTIVE (Debug logging on)" : "");
}

// TODO (checklist items 3..7): BridgeHandler / ConnectionPool / DcBalancer /
// FakeTLS / WS+H2 transports as a BackgroundService (item 9's ProxyServer).
// Until then the host simply idles until a shutdown signal so that hosting,
// Ctrl+C handling and the stats reporter are exercised end-to-end.
logger.LogInformation("Skeleton build: proxy core not yet ported. Press Ctrl+C to exit.");

using var shutdownCts = new CancellationTokenSource();

// Graceful shutdown wiring (PORT_PLAN.md §1/§3 item 9): Ctrl+C (and SIGTERM via
// ProcessExit) cancels the wait below; the generic host's ConsoleLifetime also
// observes these signals, so StopApplication keeps both paths consistent.
void RequestShutdown(string reason)
{
    logger.LogInformation("{Reason} received — shutting down.", reason);
    lifetime.StopApplication();
    shutdownCts.Cancel();
}

Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true; // defer to graceful shutdown instead of hard kill
    RequestShutdown("Ctrl+C");
};
AppDomain.CurrentDomain.ProcessExit += (_, _) => RequestShutdown("Process exit");
lifetime.ApplicationStopping.Register(() => shutdownCts.Cancel());

try
{
    await Task.Delay(Timeout.Infinite, shutdownCts.Token).ConfigureAwait(false);
}
catch (OperationCanceledException)
{
    // expected on shutdown
}
catch (SocketException ex)
{
    // PORT_PLAN.md §3 item 9: socket-level failures must be reported, not crash
    // silently with a raw stack trace.
    logger.LogError(ex, "Socket error while running: {Message}", ex.Message);
}
catch (Exception ex)
{
    logger.LogCritical(ex, "Unexpected failure while running.");
    shutdownCts.Cancel();
    debug.StopReporting();
    return 1;
}

// Python tg_ws_proxy.py: "Shutting down. Final stats: %s"
debug.StopReporting();
logger.LogInformation("Shutting down. Final stats: {Summary}", stats.Summary());

await host.StopAsync(CancellationToken.None).ConfigureAwait(false);

logger.LogInformation("{Title} stopped.", AppTitle);
return 0;

/// <summary>Marker type so <c>typeof(Program)</c> works with top-level statements.</summary>
internal static partial class Program;
