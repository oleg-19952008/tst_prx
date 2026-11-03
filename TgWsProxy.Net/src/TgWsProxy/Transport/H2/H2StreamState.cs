namespace TgWsProxy.Transport.H2;

/// <summary>HTTP/2 stream lifecycle states (RFC 9113 §5.1).</summary>
public enum H2StreamState : byte
{
    Idle,
    ReservedLocal,
    ReservedRemote,
    Open,
    HalfClosedLocal,   // we sent END_STREAM, peer may still send
    HalfClosedRemote,  // peer sent END_STREAM, we may still send
    Closed,
}

/// <summary>
/// Per-stream bookkeeping for <see cref="H2Connection"/>: flow-control windows,
/// inbound header-block reassembly (HEADERS + CONTINUATION), response queue and
/// completion signalling. Mirrors the role of <c>_ResponseStream</c> in
/// <c>proxy/h2_transport.py</c>, but as a plain data holder — all socket I/O
/// lives on the connection so a single reader task drives every stream.
/// </summary>
public sealed class H2Stream(int id)
{
    public int Id { get; } = id;
    public H2StreamState State { get; set; } = H2StreamState.Open;

    /// <summary>Owning connection (set when registered).</summary>
    public H2Connection? Connection { get; set; }

    /// <summary>Connection-level failure propagated to this stream (mirrors _ResponseStream.error).</summary>
    public Exception? ConnectionError { get; set; }

    /// <summary>Serializes body consumers for this stream.</summary>
    public SemaphoreSlim ReadLock { get; } = new(1, 1);

    /// <summary>Total bytes handed to the consumer (window-credit accounting).</summary>
    internal long _bytesDelivered;

    /// <summary>True while a HEADERS block is awaiting its CONTINUATION frames.</summary>
    public bool HasOutstandingHeaders { get; set; }

    /// <summary>Peer send window we may consume (credits to send DATA).</summary>
    public int SendWindow { get; set; } = H2Consts.DefaultInitialWindowSize;

    /// <summary>Our advertised receive window remaining (peer may send this much).</summary>
    public int RecvWindow { get; set; } = H2Consts.StreamReceiveWindow;

    // --- Inbound header block reassembly -----------------------------------
    public List<byte>? HeaderBlock { get; set; }
    public bool EndHeadersPending { get; set; }

    // --- Response state ------------------------------------------------------
    public List<HpackHeader>? Headers { get; set; }
    public int? Status => Headers is { } h
        ? h.FirstOrDefault(x => x.Name == ":status").ValueAscii is { Length: > 0 } s
            ? int.Parse(s) : null
        : null;

    /// <summary>Received DATA chunks awaiting delivery to the consumer.</summary>
    public Queue<byte[]> Chunks { get; } = new();
    public long ReceivedBytes { get; set; }
    public bool EndedByPeer { get; set; }
    public H2ErrorCode? ResetByPeer { get; set; }

    /// <summary>Set whenever new inbound data/state arrives or the stream fails.</summary>
    public SemaphoreSlim Signal { get; } = new(0);

    /// <summary>Total bytes queued in <see cref="Chunks"/> (for WINDOW_UPDATE batching).</summary>
    public int BufferedBytes { get; set; }

    /// <summary>Credit not yet returned to the peer via WINDOW_UPDATE.</summary>
    public int PendingWindowUpdate { get; set; }

    public bool IsFinished =>
        State == H2StreamState.Closed || EndedByPeer || ResetByPeer is not null;

    /// <summary>Throws if this stream was reset by the peer or the connection failed.</summary>
    public void CheckError()
    {
        if (ResetByPeer is { } rc)
            throw new H2ProtocolException(rc, $"Stream {Id} reset by peer: {rc}.");
        if (ConnectionError is { } ce)
            throw ce;
    }

    /// <summary>Wakes any waiter exactly once per event without losing signals.</summary>
    public void Notify()
    {
        // Drain-then-release would race; releasing beyond one waiter is harmless
        // because waiters loop-check predicates.
        try { Signal.Release(); } catch (SemaphoreFullException) { /* max count guard */ }
    }

    /// <summary>Waits for the next inbound event with a timeout; false on timeout.</summary>
    public async ValueTask<bool> WaitAsync(TimeSpan timeout, CancellationToken ct)
    {
        try
        {
            await Signal.WaitAsync(timeout, ct).ConfigureAwait(false);
            return true;
        }
        catch (TimeoutException)
        {
            return false;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
    }
}
