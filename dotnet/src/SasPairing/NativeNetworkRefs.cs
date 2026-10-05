namespace SasPairing;

/// <summary>
/// One exact native run handle of one connection (P9-D-003 Q, P9-D-004): the reference behind exactly one public
/// <see cref="SasPairingRun"/>. The identity is the native handle, never the request ID: a replacement run under
/// a reused request ID gets its own reference, and no reference is ever retargeted. The request ID is routing
/// metadata only: known when a drive event reported the run, and explicitly unknown for a locally started
/// Initiator until an event names that exact handle (it is never invented). A reference may be stale (its run
/// ended without a visible event); it is invalidated when an event or a local action makes its end visible, or
/// when its connection, the owner loop, the host, or a parent ends.
/// </summary>
internal sealed class NativeRunRef
{
    private byte[]? _requestId;

    /// <summary>A run a drive event reported under <paramref name="requestId"/>.</summary>
    internal NativeRunRef(ulong handle, ReadOnlySpan<byte> requestId)
    {
        Handle = handle;
        _requestId = requestId.ToArray();
    }

    /// <summary>A locally started run: its request ID is unknown until a drive event names this exact handle.</summary>
    internal NativeRunRef(ulong handle)
    {
        Handle = handle;
        _requestId = null;
    }

    /// <summary>The exact native run handle.</summary>
    internal ulong Handle { get; }

    /// <summary>Whether no visible ending or teardown has invalidated the reference.</summary>
    internal bool IsValid { get; private set; } = true;

    /// <summary>The request ID the run was reported under, or null while it is unknown (routing metadata only).</summary>
    internal ReadOnlySpan<byte> RequestId => _requestId;

    /// <summary>Whether the request ID is known.</summary>
    internal bool HasRequestId => _requestId is not null;

    /// <summary>Whether the run is known to be routed under exactly <paramref name="requestId"/>; never while unknown.</summary>
    internal bool IsRoutedUnder(ReadOnlySpan<byte> requestId) => _requestId is { } known && requestId.SequenceEqual(known);

    /// <summary>
    /// Records the request ID reported for this exact handle: true when it was unknown (now known) or equal;
    /// false when a different one is already known, which the frozen ABI never reports for one run handle.
    /// </summary>
    internal bool Learn(ReadOnlySpan<byte> requestId)
    {
        if (_requestId is null)
        {
            _requestId = requestId.ToArray();
            return true;
        }

        return IsRoutedUnder(requestId);
    }

    internal void Invalidate() => IsValid = false;
}

/// <summary>
/// One exact native result handle, owned by the runtime (P9-D-003 R, P9-D-005): the reference behind exactly one
/// public <see cref="SasPairingResult"/>. Valid until the result is disposed or its runtime is disposed.
/// </summary>
internal sealed class NativeResultRef
{
    internal NativeResultRef(ulong handle)
    {
        Handle = handle;
    }

    /// <summary>The exact native result handle.</summary>
    internal ulong Handle { get; }

    /// <summary>Whether the result is still open (false once it or its runtime was disposed).</summary>
    internal bool IsValid { get; private set; } = true;

    internal void Invalidate() => IsValid = false;
}

/// <summary>
/// The runtime-owned results (P9-D-003 R, P9-D-005): the one public <see cref="SasPairingResult"/> of every open
/// native result handle a drive delivered, and every result handle ever delivered under the runtime. A result
/// belongs to the runtime, never to a connection, host, or authority, so it survives all of them; only its own
/// disposal or the runtime's ends it. The handle history outlives a result's disposal, so a handle delivered twice
/// is detected even after the first result was disposed (native never reuses a handle). Not enumerable outside
/// the package: a consumer obtains each result only from the event that delivered it. Accessed only under the
/// runtime lock.
/// </summary>
internal sealed class NativeResultStore
{
    private readonly HashSet<ulong> _delivered = [];
    private readonly Dictionary<ulong, SasPairingResult> _live = [];

    /// <summary>The number of result handles delivered to this runtime (open or not).</summary>
    internal int DeliveredCount => _delivered.Count;

    /// <summary>The open results, which the runtime's disposal ends (tests).</summary>
    internal IReadOnlyCollection<SasPairingResult> Live => _live.Values;

    /// <summary>Whether <paramref name="handle"/> was ever delivered before (open or disposed).</summary>
    internal bool WasDelivered(ulong handle) => _delivered.Contains(handle);

    /// <summary>The open result of <paramref name="handle"/>, or null (tests).</summary>
    internal SasPairingResult? Find(ulong handle) => _live.GetValueOrDefault(handle);

    /// <summary>Wraps a newly delivered <paramref name="handle"/> in its one public result; the caller checked that it is new.</summary>
    internal SasPairingResult Retain(SasPairingRuntime runtime, ulong handle)
    {
        SasPairingResult result = new(runtime, new NativeResultRef(handle));
        _delivered.Add(handle);
        _live.Add(handle, result);
        return result;
    }

    /// <summary>Forgets an open result disposed on its own (its handle stays in the history).</summary>
    internal void Forget(SasPairingResult result) => _live.Remove(result.Ref.Handle);

    /// <summary>The runtime was disposed: native runtime destroy dropped every result, so each is disposed locally, with no native call.</summary>
    internal void InvalidateAll()
    {
        foreach (SasPairingResult result in _live.Values)
        {
            result.Ref.Invalidate();
        }

        _live.Clear();
    }
}
