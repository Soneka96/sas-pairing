namespace SasPairing;

/// <summary>
/// One live accepted connection of a host's owner loop (P9-D-003): local and volatile; not a socket, request
/// ID, peer identity, authentication, or trust.
/// </summary>
/// <remarks>
/// Every drive event of one native connection carries this same object. It is disposed by
/// <see cref="Dispose"/>, by a <see cref="SasPairingEventKind.ConnectionClosed"/> event (before the batch is
/// returned), by <see cref="SasPairingHost.DetachListener"/>, by an owner-loop failure, and by disposing its
/// host or a parent; a disposed connection stays disposed. There is no finalizer: dispose it deterministically
/// when it is no longer wanted, in particular after an event with
/// <see cref="SasPairingEvent.ShouldDisposeConnection"/>.
/// </remarks>
public sealed class SasPairingConnection : IDisposable
{
    private const string DisposeOperation = "SasPairingConnection.Dispose";

    private readonly SasPairingHost _host;

    /// <summary>The exact-handle runs of this connection; never keyed by request ID.</summary>
    private readonly Dictionary<ulong, NativeRunRef> _runs = [];
    private bool _disposed;

    internal SasPairingConnection(SasPairingHost host, ulong handle)
    {
        _host = host;
        Handle = handle;
    }

    /// <summary>
    /// Whether this connection was disposed, by <see cref="Dispose"/>, by its own end, or by the end of its
    /// owner loop, listener, host, or a parent.
    /// </summary>
    public bool IsDisposed
    {
        get
        {
            lock (_host.Authority.Runtime.Gate)
            {
                return _disposed;
            }
        }
    }

    /// <summary>The exact native connection handle. Internal only; never exposed or printed.</summary>
    internal ulong Handle { get; }

    /// <summary>The live run references of this connection (tests and P9.4).</summary>
    internal IReadOnlyCollection<NativeRunRef> Runs => _runs.Values;

    /// <summary>
    /// Closes the connection with exactly one native call (cleanup: allowed after
    /// <see cref="SasPairingStatus.Fatal"/> and after a contract violation). No CANCEL is sent and nothing is
    /// retried. The connection is disposed whatever the native result, and a failure is then thrown once. When
    /// the result is <see cref="SasPairingStatus.OwnershipUncertain"/> the host's owner loop failed closed:
    /// every other connection of the host is disposed too (without a native call) and the host becomes
    /// <see cref="SasPairingHostNetworkState.FailedClosed"/>. Later calls do nothing.
    /// </summary>
    /// <exception cref="SasPairingNativeException">The native close reported a failure (first call only).</exception>
    public void Dispose()
    {
        SasPairingRuntime runtime = _host.Authority.Runtime;
        int status;
        lock (runtime.Gate)
        {
            if (_disposed)
            {
                return;
            }

            status = _host.Network.Close(this);
        }

        runtime.Context.ThrowIfFailed(DisposeOperation, status);
    }

    /// <summary>
    /// The reference of the exact native run <paramref name="handle"/> that an event named under
    /// <paramref name="requestId"/>: the existing one, or a new one after the references under the same request
    /// ID were retired (a live new run proves the earlier one under that request ID ended). Null when the same
    /// handle is reported under a different request ID, which the frozen ABI never does.
    /// </summary>
    internal NativeRunRef? RunFor(ulong handle, ReadOnlySpan<byte> requestId)
    {
        if (_runs.TryGetValue(handle, out NativeRunRef? existing))
        {
            if (!existing.HasRequestId)
            {
                Retire(requestId);
            }

            return existing.Learn(requestId) ? existing : null;
        }

        Retire(requestId);
        NativeRunRef run = new(handle, requestId);
        _runs.Add(handle, run);
        return run;
    }

    /// <summary>Invalidates every run known to be routed under <paramref name="requestId"/>: an event made its end visible.</summary>
    internal void Retire(ReadOnlySpan<byte> requestId)
    {
        List<ulong> retired = [];
        foreach ((ulong handle, NativeRunRef run) in _runs)
        {
            if (run.IsRoutedUnder(requestId))
            {
                run.Invalidate();
                retired.Add(handle);
            }
        }

        foreach (ulong handle in retired)
        {
            _runs.Remove(handle);
        }
    }

    /// <summary>Marks this connection disposed and invalidates every run of it, with no native call.</summary>
    internal void InvalidateLocally()
    {
        _disposed = true;
        foreach (NativeRunRef run in _runs.Values)
        {
            run.Invalidate();
        }

        _runs.Clear();
    }
}
