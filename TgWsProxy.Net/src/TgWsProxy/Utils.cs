using System.Buffers;
using System.IO.Pipelines;

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

    /// <summary>Identity overload for already-materialised strings (e.g. results of
    /// concatenating two FormattableStrings with <c>+</c>, which yields <c>string</c>).
    /// Such strings are produced by interpolated literals whose holes were formatted
    /// with the current culture — callers must not rely on this overload for
    /// culture-sensitive numeric holes; merge those into a single $"" literal instead.</summary>
    public static string Inv(string s) => s;
}

/// <summary>
/// Minimal <see cref="PipeReader"/> facade over a <see cref="System.IO.Stream"/> —
/// the C# counterpart of wrapping an asyncio StreamReader in a pipe. Not used by
/// the current bridge paths (kept for parity with the Python helper surface).
/// </summary>
internal sealed class StreamPipeReader : PipeReader
{
    private readonly System.IO.Stream _stream;

    public StreamPipeReader(System.IO.Stream stream) => _stream = stream;

    public override async ValueTask<ReadResult> ReadAsync(CancellationToken cancellationToken = default)
    {
        var mem = ArrayPool<byte>.Shared.Rent(65536);
        try
        {
            int n = await _stream.ReadAsync(mem.AsMemory(), cancellationToken).ConfigureAwait(false);
            var seq = new ReadOnlySequence<byte>(n == 0 ? Array.Empty<byte>() : mem.AsMemory(0, n));
            return new ReadResult(seq, isCanceled: false, isCompleted: n == 0);
        }
        finally
        {
            if (mem.Length != 0) ArrayPool<byte>.Shared.Return(mem);
        }
    }

    public override bool TryRead(out ReadResult result)
    {
        result = default;
        return false;   // stream-backed: nothing is buffered synchronously
    }

    public override void AdvanceTo(SequencePosition consumed) { }

    public override void AdvanceTo(SequencePosition consumed, SequencePosition examined) { }

    public override void CancelPendingRead() { }

    public override void Complete(Exception? exception = null)
    {
        try { _stream.Dispose(); } catch { }
    }
}
