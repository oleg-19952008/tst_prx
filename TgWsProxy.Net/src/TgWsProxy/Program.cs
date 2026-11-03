using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using TgWsProxy.Configuration;
using TgWsProxy.Core;
using TgWsProxy;   // ProgramLogger (ambient logger factory, set once at startup)

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

// --- Proxy listener (PORT_PLAN.md §3 phase D, checklist item 9) -------------
builder.Services.AddHostedService<ProxyServer>();

var host = builder.Build();

ProgramLogger.SetFactory(host.Services.GetRequiredService<ILoggerFactory>());

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

logger.LogInformation(
    "{Title} starting: {Host}:{Port}, pool={PoolSize}, buffer={BufferKb} KB, H2={H2}, DC redirects: {Dcs}",
    AppTitle, config.Host, config.Port, config.PoolSize, config.BufferSizeKb, config.H2Enabled,
    string.Join(", ", config.DcRedirects.OrderBy(kv => kv.Key).Select(kv => $"{kv.Key}->{kv.Value}")));

// Print the secret when it was auto-generated (empty in config) — Telegram
// Desktop must be pointed at it manually, mirroring the GUI behaviour.
var configuredSecret = builder.Configuration[$"{ProxyConfig.SectionName}:{nameof(ProxyConfig.Secret)}"];
if (string.IsNullOrWhiteSpace(configuredSecret))
    logger.LogInformation("No Proxy:Secret configured — generated one-time secret: {Secret}", config.Secret);

// The proxy listener runs as a hosted BackgroundService (Core/ProxyServer.cs):
// TcpListener on Proxy:Host / Proxy:Port, PROXY protocol v1 when enabled,
// graceful shutdown through the host lifetime. Here we just run the host and
// wait for it to stop (Ctrl+C → StopApplication).
using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true; // let the host perform graceful shutdown
    logger.LogInformation("Ctrl+C received — shutting down.");
    lifetime.StopApplication();
    cts.Cancel();
};
AppDomain.CurrentDomain.ProcessExit += (_, _) => cts.Cancel();

try
{
    await host.RunAsync(cts.Token).ConfigureAwait(false);
}
catch (OperationCanceledException)
{
    // expected on shutdown
}

logger.LogInformation("{Title} stopped.", AppTitle);
return 0;

/// <summary>Marker type so <c>typeof(Program)</c> works with top-level statements.</summary>
internal static partial class Program;
