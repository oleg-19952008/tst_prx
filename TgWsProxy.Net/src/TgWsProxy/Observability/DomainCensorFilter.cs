using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace TgWsProxy.Observability;

/// <summary>
/// Port of <c>proxy/utils.py::DomainCensorFilter</c> — a logging filter that
/// masks domain names in log output while keeping <c>telegram.org</c> (and its
/// sub-domains) and <c>*.log</c> hostnames intact. The pure text transform is
/// exposed as <see cref="Wrap"/>/<see cref="CensorMatch"/>;
/// <see cref="Logger"/> wraps an <see cref="ILogger"/> so every formatted
/// message passes through the censor before being written (the .NET analogue
/// of attaching the filter to the console/file handlers in Python).
/// </summary>
public static partial class DomainCensorFilter
{
    /// <summary>
    /// Python regex:
    /// <code>
    /// (?&lt;![\w-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?![\w-])
    /// </code>
    /// .NET's engine understands the same look-behind/look-ahead and ASCII
    /// character classes, so the pattern is kept byte-identical to Python for
    /// the golden-file comparison (<c>tools/golden/domain_censor.json</c>).
    /// </summary>
    [GeneratedRegex(
        @"(?<![\w-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?![\w-])",
        RegexOptions.CultureInvariant)]
    private static partial Regex DomainPattern();

    /// <summary>
    /// Censor one regex match exactly like Python's <c>_censor_match</c>:
    /// whitelist <c>telegram.org</c>/sub-domains and names ending in
    /// <c>.log</c> (case-folded, trailing dot stripped), otherwise replace the
    /// tail of every label except the last one with asterisks
    /// (keep <c>len(label)//2</c> leading characters).
    /// </summary>
    public static string CensorMatch(string domain)
    {
        // str.casefold() ≈ ToLowerInvariant() for the ASCII-only matches the
        // regex can produce; rstrip('.') removes ALL trailing dots. Note: the
        // check runs on the *normalized* copy, but EndsWith below is
        // case-sensitive ordinal — identical to Python, which compares the
        // casefolded string against lowercase literals.
        var normalized = domain.ToLowerInvariant().TrimEnd('.');
        if (normalized == "telegram.org"
            || normalized.EndsWith(".telegram.org", StringComparison.Ordinal)
            || normalized.EndsWith(".log", StringComparison.Ordinal))
        {
            return domain;
        }

        var parts = domain.Split('.');
        if (parts.Length < 2)
            return domain;

        var sb = new StringBuilder(domain.Length);
        for (var i = 0; i < parts.Length; i++)
        {
            if (i > 0) sb.Append('.');
            var part = parts[i];
            if (i == parts.Length - 1)
            {
                sb.Append(part);
            }
            else
            {
                int half = part.Length / 2; // integer floor division, like Python
                sb.Append(part, 0, half);
                sb.Append('*', part.Length - half);
            }
        }
        return sb.ToString();
    }

    /// <summary>
    /// Equivalent of <c>domain_pattern.sub(_censor_match, message)</c> —
    /// censors every domain found in <paramref name="message"/>.
    /// </summary>
    public static string Wrap(string message) =>
        DomainPattern().Replace(message, m => CensorMatch(m.Value));

    /// <summary>
    /// Returns a censoring decorator around <paramref name="inner"/>: state
    /// scopes are delegated unchanged, and every log message is passed through
    /// <see cref="Wrap"/> before reaching the inner logger (mirrors Python's
    /// <c>console.addFilter(DomainCensorFilter())</c>).
    /// </summary>
    public static ILogger Logger(ILogger inner) => new CensoringLogger(inner);

    private sealed class CensoringLogger : ILogger
    {
        private readonly ILogger _inner;

        public CensoringLogger(ILogger inner) => _inner = inner;

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull
            => _inner.BeginScope(state);

        public bool IsEnabled(LogLevel logLevel) => _inner.IsEnabled(logLevel);

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (!_inner.IsEnabled(logLevel))
                return;

            var message = formatter(state, exception);
            _inner.Log(logLevel, eventId, Wrap(message), exception, static (s, e) => s);
        }
    }
}
