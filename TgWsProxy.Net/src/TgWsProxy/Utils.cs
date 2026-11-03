namespace TgWsProxy;

/// <summary>
/// Small helpers ported from <c>tg-ws-proxy-main_py/proxy/utils.py</c>.
/// </summary>
public static class Utils
{
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

    /// <summary>Formats an interpolated string with invariant culture — the C#
    /// equivalent of Python's locale-independent <c>"%.1f" % x</c> formatting.
    /// Needed because <see cref="System.Runtime.CompilerServices"/> only applies
    /// invariant culture when the callee parameter type is FormattableString.</summary>
    public static string Inv(FormattableString fs) =>
        string.Format(System.Globalization.CultureInfo.InvariantCulture, fs.Format, fs.GetArguments());

    /// <summary>
    /// Overload for pre-composed plain strings: interpolations that were built by
    /// concatenating several $-strings degrade to <c>string</c>; format them with the
    /// invariant culture anyway (they may still contain format specifiers).
    /// </summary>
    public static string Inv(string s) => s;
}
