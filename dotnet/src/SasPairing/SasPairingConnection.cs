namespace SasPairing;

/// <summary>
/// One live accepted connection of a host's owner loop (P9-D-003): local and volatile; not a socket, request
/// ID, peer identity, authentication, or trust. Its ceremony runs are <see cref="SasPairingRun"/> objects
/// (P9-D-004); <see cref="StartInitiator"/> starts a local Initiator on it.
/// </summary>
/// <remarks>
/// Every drive event of one native connection carries this same object. It is disposed by
/// <see cref="Dispose"/>, by a <see cref="SasPairingEventKind.ConnectionClosed"/> event (before the batch is
/// returned), by <see cref="SasPairingHost.DetachListener"/>, by an owner-loop failure, and by disposing its
/// host or a parent; a disposed connection stays disposed. There is no finalizer: dispose it deterministically
/// when it is no longer wanted, in particular after an event with
/// <see cref="SasPairingEvent.ShouldDisposeConnection"/>. When it is disposed, every run of it ends.
/// </remarks>
public sealed class SasPairingConnection : IDisposable
{
    private const string DisposeOperation = "SasPairingConnection.Dispose";

    private readonly SasPairingHost _host;

    /// <summary>The live runs of this connection, keyed by exact native run handle; never by request ID.</summary>
    private readonly Dictionary<ulong, SasPairingRun> _runs = [];
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

    /// <summary>The host of this connection.</summary>
    internal SasPairingHost Host => _host;

    /// <summary>The live runs of this connection (tests).</summary>
    internal IReadOnlyCollection<SasPairingRun> Runs => _runs.Values;

    /// <summary>
    /// Starts an honest local Initiator on this connection with exactly one native call, from the explicit
    /// trusted-local configuration <paramref name="local"/> and the exact expected peer Bootstrap
    /// <paramref name="expected"/> (null for none). The native core generates and reserves the request ID and
    /// routes the run; its START is retained for a later <see cref="SasPairingHost.Drive"/>. Nothing is driven,
    /// authorized, exposed, or spent here, and the request ID is not returned: the new run's request ID becomes
    /// known only when a drive event names it.
    /// </summary>
    /// <param name="local">This endpoint's trusted-local Initiator configuration (not the host's Responder Bootstrap, never peer input).</param>
    /// <param name="expected">The exact expected peer Bootstrap, or null for none.</param>
    /// <returns><see cref="SasPairingLocalEvent.InitiatorStarted"/> with the new <see cref="SasPairingRun"/> and <c>WritePending</c>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="local"/> is null.</exception>
    /// <exception cref="ObjectDisposedException">The connection was disposed (no native call).</exception>
    /// <exception cref="SasPairingNativeException">
    /// The native start was refused, for example <see cref="SasPairingStatus.WritePending"/> (an earlier frame is
    /// still retained: nothing started), <see cref="SasPairingStatus.InvalidBootstrap"/>, or
    /// <see cref="SasPairingStatus.ResourceLimited"/>.
    /// </exception>
    /// <exception cref="SasPairingContractException">The native library broke the ABI v1 contract, now or earlier in this process.</exception>
    public SasPairingLocalAction StartInitiator(SasPairingBootstrap local, SasPairingBootstrap? expected = null)
    {
        ArgumentNullException.ThrowIfNull(local);
        lock (_host.Authority.Runtime.Gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return CeremonyControl.Start(this, local, expected);
        }
    }

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
    /// The run of the exact native run <paramref name="handle"/> that an event named under
    /// <paramref name="requestId"/>: the existing object, or a new one after the runs known under the same request
    /// ID were ended (a live new run proves the earlier one under that request ID ended). A locally started run
    /// learns its request ID here, once, after the other runs under it were ended. Null when the same handle is
    /// reported under a different request ID, which the frozen ABI never does.
    /// </summary>
    internal SasPairingRun? RunFor(ulong handle, ReadOnlySpan<byte> requestId)
    {
        if (_runs.TryGetValue(handle, out SasPairingRun? existing))
        {
            if (!existing.Ref.HasRequestId)
            {
                Retire(requestId);
            }

            return existing.Ref.Learn(requestId) ? existing : null;
        }

        Retire(requestId);
        SasPairingRun run = new(this, new NativeRunRef(handle, requestId));
        _runs.Add(handle, run);
        return run;
    }

    /// <summary>The new run of a successful local Initiator start, with its request ID unknown; the caller checked that the handle is new.</summary>
    internal SasPairingRun StartRun(ulong handle)
    {
        SasPairingRun run = new(this, new NativeRunRef(handle));
        _runs.Add(handle, run);
        return run;
    }

    /// <summary>Whether <paramref name="handle"/> is a live run of this connection.</summary>
    internal bool HasRun(ulong handle) => _runs.ContainsKey(handle);

    /// <summary>Ends exactly <paramref name="run"/>: its native handle is invalid from now on. Never retargets.</summary>
    internal void EndRun(SasPairingRun run)
    {
        run.Ref.Invalidate();
        if (_runs.TryGetValue(run.Ref.Handle, out SasPairingRun? held) && ReferenceEquals(held, run))
        {
            _runs.Remove(run.Ref.Handle);
        }
    }

    /// <summary>Invalidates every run known to be routed under <paramref name="requestId"/>: an event made its end visible.</summary>
    internal void Retire(ReadOnlySpan<byte> requestId)
    {
        List<ulong> retired = [];
        foreach ((ulong handle, SasPairingRun run) in _runs)
        {
            if (run.Ref.IsRoutedUnder(requestId))
            {
                run.Ref.Invalidate();
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
        foreach (SasPairingRun run in _runs.Values)
        {
            run.Ref.Invalidate();
        }

        _runs.Clear();
    }
}
