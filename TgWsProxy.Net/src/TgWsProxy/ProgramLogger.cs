using Microsoft.Extensions.Logging;

namespace TgWsProxy;

/// <summary>
/// Ambient logger factory used by ported components that mirror Python module-level
/// loggers (e.g. <c>log = logging.getLogger('tg-mtproto-proxy')</c>). The host sets
/// <see cref="Factory"/> once during startup; before that, a silent console logger is
/// returned so library code never crashes in unit-test scenarios.
/// </summary>
internal static class ProgramLogger
{
    private static ILoggerFactory? _factory;

    /// <summary>Category name shared with the Python logger of the ported modules.</summary>
    public const string Category = "tg-mtproto-proxy";

    public static void SetFactory(ILoggerFactory factory) => _factory = factory;

    public static ILogger For<T>() => Factory().CreateLogger(Category);

    public static ILogger For(string category) => Factory().CreateLogger(category);

    private static ILoggerFactory Factory() =>
        _factory ??= Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory.Instance;
}
