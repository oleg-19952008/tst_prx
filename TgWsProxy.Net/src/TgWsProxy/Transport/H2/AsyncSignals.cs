namespace TgWsProxy.Transport.H2;

/// <summary>
/// Minimal async-friendly signalling primitives for the cf_h2 port. The Python
/// original uses <c>asyncio.Event</c> (set/clear/wait); the BCL equivalents lack
/// that exact surface (<see cref="System.Threading.SemaphoreSlim"/> has no
/// <c>Set()</c>, <see cref="System.Threading.ManualResetEventSlim"/> has no
/// <c>WaitAsync</c>). These types close the gap without a third-party library
/// (PORT_PLAN.md: no external deps).
/// </summary>
internal sealed class AsyncAutoResetEvent
{
    private TaskCompletionSource<bool> _tcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly object _lock = new();

    /// <summary>Python <c>event.set()</c>: release one waiter (or latch until the next wait).</summary>
    public void Set()
    {
        lock (_lock) _tcs.TrySetResult(true);
    }

    /// <summary>
    /// Python <c>await asyncio.wait_for(event.wait(), timeout)</c>. Returns when
    /// signalled; throws <see cref="OperationCanceledException"/> only if
    /// <paramref name="ct"/> fires before the timeout elapses.
    /// </summary>
    public async Task WaitAsync(TimeSpan timeout, CancellationToken ct = default)
    {
        Task wait;
        lock (_lock) wait = _tcs.Task;
        var completed = await Task.WhenAny(wait, Task.Delay(timeout, ct)).ConfigureAwait(false);
        if (completed != wait) await completed.ConfigureAwait(false); // propagate cancellation
        lock (_lock)
        {
            // auto-reset: consume the signal and swap in a fresh TCS for the next producer
            if (_tcs.Task.IsCompleted)
                _tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        }
    }
}

/// <summary>Async mirror of Python's <c>asyncio.Event</c> (manual reset).</summary>
internal sealed class AsyncManualResetEvent
{
    private TaskCompletionSource<bool> _tcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly object _lock = new();

    /// <summary>Python <c>event.set()</c>.</summary>
    public void Set()
    {
        lock (_lock) _tcs.TrySetResult(true);
    }

    /// <summary>Python <c>event.clear()</c>.</summary>
    public void Reset()
    {
        lock (_lock)
        {
            if (!_tcs.Task.IsCompleted) return;
            _tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        }
    }

    /// <summary>Python <c>await event.wait()</c>.</summary>
    public Task WaitAsync(CancellationToken ct = default)
    {
        Task wait;
        lock (_lock) wait = _tcs.Task;
        return ct.CanBeCanceled ? wait.WaitAsync(ct) : wait;
    }
}
