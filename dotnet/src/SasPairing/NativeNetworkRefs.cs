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

/// <summary>One exact native result handle, owned by the runtime (P9-D-003 R), package-internal until P9.5.</summary>
internal sealed class NativeResultRef
{
    internal NativeResultRef(ulong handle)
    {
        Handle = handle;
    }

    /// <summary>The exact native result handle.</summary>
    internal ulong Handle { get; }

    /// <summary>Whether the runtime still holds the result (false once the runtime was disposed).</summary>
    internal bool IsValid { get; private set; } = true;

    internal void Invalidate() => IsValid = false;
}

/// <summary>
/// The runtime-owned store of every native result handle a drive delivered (P9-D-003 R). A result belongs to
/// the runtime, never to a connection, host, or authority, so it survives all of them; only the runtime's
/// disposal invalidates it. The handle history is kept for the runtime's lifetime, so a handle delivered twice
/// is detected. Nothing is read or destroyed here (P9.5). Accessed only under the runtime lock.
/// </summary>
internal sealed class NativeResultStore
{
    private readonly Dictionary<ulong, NativeResultRef> _delivered = [];

    /// <summary>The number of results delivered to this runtime.</summary>
    internal int Count => _delivered.Count;

    /// <summary>Whether <paramref name="handle"/> was delivered before (live or invalidated).</summary>
    internal bool WasDelivered(ulong handle) => _delivered.ContainsKey(handle);

    /// <summary>The reference of a delivered handle, or null.</summary>
    internal NativeResultRef? Find(ulong handle) => _delivered.GetValueOrDefault(handle);

    /// <summary>Retains a newly delivered <paramref name="handle"/>; the caller checked that it is new.</summary>
    internal NativeResultRef Retain(ulong handle)
    {
        NativeResultRef result = new(handle);
        _delivered.Add(handle, result);
        return result;
    }

    /// <summary>The runtime was disposed: native runtime destroy dropped every result.</summary>
    internal void InvalidateAll()
    {
        foreach (NativeResultRef result in _delivered.Values)
        {
            result.Invalidate();
        }
    }
}
