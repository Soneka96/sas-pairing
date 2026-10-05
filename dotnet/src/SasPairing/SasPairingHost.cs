namespace SasPairing;

/// <summary>
/// One hosting context (one native core router) of a <see cref="SasPairingAuthority"/>, with at most one
/// attached Windows listener and the cooperative network drive over it. A host is not a socket, connection,
/// peer, run, or security session: several hosts of one authority share its opportunity budget and START
/// limiter.
/// </summary>
/// <remarks>
/// <para>
/// Disposing makes exactly one native destroy call, which also closes an attached listener and every
/// connection; the authority and its other hosts stay valid. The host is disposed even when the native call
/// reports a failure, which the first <see cref="Dispose"/> then throws as <see cref="SasPairingNativeException"/>;
/// later calls do nothing. Releasing the authority or disposing the runtime destroys the host natively and marks
/// this wrapper disposed without a call of its own. Either way every <see cref="SasPairingConnection"/> of the
/// host becomes disposed locally and <see cref="NetworkState"/> becomes <see cref="SasPairingHostNetworkState.Detached"/>.
/// </para>
/// <para>
/// Network progress happens only inside <see cref="Drive"/> and <see cref="RecheckAfterResume"/>, one bounded
/// synchronous native call each: the package runs no background loop, task, timer, thread, or callback. Calls
/// on one runtime tree are serialized, so a drive (which can wait up to about 250 ms) also delays the other
/// calls of the tree; choose a scheduling strategy that suits the application, and do not drive on a UI thread
/// or in a loop with no pause.
/// </para>
/// </remarks>
public sealed class SasPairingHost : IDisposable
{
    private const string DisposeOperation = "SasPairingHost.Dispose";
    private const string DetachOperation = "SasPairingHost.DetachListener";
    private const string DriveOperation = "SasPairingHost.Drive";
    private const string RecheckOperation = "SasPairingHost.RecheckAfterResume";

    private readonly SasPairingAuthority _authority;
    private bool _disposed;

    internal SasPairingHost(SasPairingAuthority authority, ulong handle)
    {
        _authority = authority;
        Handle = handle;
        Network = new HostNetwork(this);
    }

    /// <summary>
    /// Whether this host was disposed, directly or because its authority or runtime was disposed. A disposed
    /// host refuses every operation locally.
    /// </summary>
    public bool IsDisposed
    {
        get
        {
            lock (_authority.Runtime.Gate)
            {
                return _disposed;
            }
        }
    }

    /// <summary>
    /// The network state: <see cref="SasPairingHostNetworkState.Detached"/>, <see cref="SasPairingHostNetworkState.Attached"/>,
    /// <see cref="SasPairingHostNetworkState.ListenerDisabled"/>, or <see cref="SasPairingHostNetworkState.FailedClosed"/>.
    /// </summary>
    public SasPairingHostNetworkState NetworkState
    {
        get
        {
            lock (_authority.Runtime.Gate)
            {
                return Network.State;
            }
        }
    }

    /// <summary>The owning authority.</summary>
    internal SasPairingAuthority Authority => _authority;

    /// <summary>The exact native host handle. Internal only; never exposed or printed.</summary>
    internal ulong Handle { get; }

    /// <summary>The host's network context.</summary>
    internal HostNetwork Network { get; }

    /// <summary>
    /// Hands the listening socket of <paramref name="listener"/> to the native library and attaches it to this
    /// host, with <paramref name="local"/> as the host's Responder Bootstrap and <paramref name="expected"/> as
    /// the exact expected peer Bootstrap (null for none). Nothing is driven: no accept, connection, or event
    /// happens here. One listener per host: to replace it, call <see cref="DetachListener"/>, then attach again.
    /// </summary>
    /// <remarks>
    /// Socket ownership follows the native in/out slot, and <see cref="SasPairingWindowsListenerSocket.IsTransferred"/>
    /// is updated before any exception is thrown. A failure before the native library adopts the socket (for
    /// example <see cref="SasPairingStatus.InvalidBootstrap"/>, <see cref="SasPairingStatus.ListenerAlreadyAttached"/>,
    /// or <see cref="SasPairingStatus.UnsupportedPlatform"/>) leaves it untransferred, still the caller's through
    /// the token. Once adopted, the native library owns and closes it, also when it then reports
    /// <see cref="SasPairingStatus.ListenerSetupFailed"/> or <see cref="SasPairingStatus.Fatal"/> (the host is
    /// then <see cref="SasPairingHostNetworkState.Detached"/>). The Bootstraps are validated by the native core only.
    /// </remarks>
    /// <param name="listener">The handoff token of the application's listening socket.</param>
    /// <param name="local">The host's own Responder Bootstrap.</param>
    /// <param name="expected">The exact expected peer Bootstrap, or null for none.</param>
    /// <exception cref="ArgumentNullException"><paramref name="listener"/> or <paramref name="local"/> is null.</exception>
    /// <exception cref="ObjectDisposedException">The host or the token was disposed.</exception>
    /// <exception cref="InvalidOperationException">The token was already transferred, or another attach of it is in progress.</exception>
    /// <exception cref="SasPairingNativeException">The native attach failed (normal operations are refused after <see cref="SasPairingStatus.Fatal"/>).</exception>
    /// <exception cref="SasPairingContractException">The native library broke the ABI v1 contract, now or earlier in this process.</exception>
    public void AttachWindowsListener(SasPairingWindowsListenerSocket listener, SasPairingBootstrap local, SasPairingBootstrap? expected = null)
    {
        ArgumentNullException.ThrowIfNull(listener);
        ArgumentNullException.ThrowIfNull(local);
        lock (_authority.Runtime.Gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            Network.Attach(listener, local, expected);
        }
    }

    /// <summary>
    /// Detaches the listener with exactly one native call (cleanup: allowed after <see cref="SasPairingStatus.Fatal"/>
    /// and after a contract violation, and idempotent natively, so it may be called in any network state). The
    /// native library closes the listener and every connection; every <see cref="SasPairingConnection"/> of
    /// this host becomes disposed locally and the state becomes <see cref="SasPairingHostNetworkState.Detached"/>,
    /// whatever the native result, which is then thrown if it is a failure. The host, its authority, and all
    /// accounting stay; a new listener may be attached afterwards.
    /// </summary>
    /// <exception cref="ObjectDisposedException">The host was disposed.</exception>
    /// <exception cref="SasPairingNativeException">The native detach reported a failure (for example <see cref="SasPairingStatus.OwnershipUncertain"/>).</exception>
    public void DetachListener()
    {
        int status;
        lock (_authority.Runtime.Gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            status = Network.Detach();
        }

        _authority.Runtime.Context.ThrowIfFailed(DetachOperation, status);
    }

    /// <summary>
    /// Drives the host's owner loop with exactly one bounded native call (deadline sweeps, at most one
    /// readiness wait of up to about 250 ms, at most one socket operation per connection, at most one accept)
    /// and returns everything it reported. Synchronous; nothing is retried or scheduled.
    /// </summary>
    /// <remarks>
    /// Process every event of the batch, also when <see cref="SasPairingDriveBatch.Failure"/> is set: the owner
    /// loop then failed closed after producing them, every connection is disposed, and the host is
    /// <see cref="SasPairingHostNetworkState.FailedClosed"/> (detach the listener or dispose the host). After an
    /// event with <see cref="SasPairingEvent.ShouldDisposeConnection"/>, dispose that connection once the batch
    /// was processed. Do not call this in a loop without a pause: a persistently ready socket can make it
    /// return at once.
    /// </remarks>
    /// <returns>The events of this one call, in native order, and the owner loop's failure if any.</returns>
    /// <exception cref="ObjectDisposedException">The host was disposed.</exception>
    /// <exception cref="SasPairingNativeException">
    /// The call itself failed and drove nothing, for example <see cref="SasPairingStatus.ListenerNotAttached"/>,
    /// <see cref="SasPairingStatus.HandlesExhausted"/>, <see cref="SasPairingStatus.UnsupportedPlatform"/>, or
    /// <see cref="SasPairingStatus.Fatal"/>.
    /// </exception>
    /// <exception cref="SasPairingContractException">The native library broke the ABI v1 contract, now or earlier in this process.</exception>
    public SasPairingDriveBatch Drive() => DriveOnce(DriveOperation, recheck: false);

    /// <summary>
    /// Makes exactly one native resume recheck: one deadline sweep of the owner loop and nothing else (no
    /// readiness wait, socket read or write, or accept), with the same batch model as <see cref="Drive"/>. Call it
    /// only after trusted application code observed an OS resume; the package subscribes to no power event.
    /// </summary>
    /// <returns>The events of this one call, in native order, and the owner loop's failure if any.</returns>
    /// <exception cref="ObjectDisposedException">The host was disposed.</exception>
    /// <exception cref="SasPairingNativeException">The call itself failed and checked nothing.</exception>
    /// <exception cref="SasPairingContractException">The native library broke the ABI v1 contract, now or earlier in this process.</exception>
    public SasPairingDriveBatch RecheckAfterResume() => DriveOnce(RecheckOperation, recheck: true);

    /// <summary>
    /// Destroys the host with exactly one native call, which also closes its listener and every connection.
    /// The host is disposed even when the native call reports a failure, which is then thrown. Later calls do
    /// nothing. Allowed after <see cref="SasPairingStatus.Fatal"/> and after a contract violation.
    /// </summary>
    /// <exception cref="SasPairingNativeException">The native destroy reported a failure (first call only).</exception>
    public void Dispose()
    {
        SasPairingRuntime runtime = _authority.Runtime;
        int status;
        lock (runtime.Gate)
        {
            if (_disposed)
            {
                return;
            }

            try
            {
                status = runtime.Context.Lifecycle.HostDestroy(runtime.Handle, Handle);
            }
            finally
            {
                InvalidateLocally();
                _authority.Forget(this);
            }
        }

        runtime.Context.ThrowIfFailed(DisposeOperation, status);
    }

    /// <summary>
    /// Marks this host disposed, Detached, and every connection of it disposed, with no native call (a native
    /// cleanup of this host or a parent already ended them).
    /// </summary>
    internal void InvalidateLocally()
    {
        _disposed = true;
        Network.Teardown(SasPairingHostNetworkState.Detached);
    }

    private SasPairingDriveBatch DriveOnce(string operation, bool recheck)
    {
        lock (_authority.Runtime.Gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return Network.Drive(operation, recheck);
        }
    }
}
