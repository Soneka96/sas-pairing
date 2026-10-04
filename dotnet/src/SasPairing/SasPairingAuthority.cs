using SasPairing.Interop;

namespace SasPairing;

/// <summary>
/// One registered authority of a <see cref="SasPairingRuntime"/>, holding the authority's OS ownership; the
/// owning parent of its <see cref="SasPairingHost"/> objects.
/// </summary>
/// <remarks>
/// The authority's opportunity budget and START limiter belong to this process's session for the authority,
/// not to this object: disposing it and registering the same scope again continues them. Disposing makes
/// exactly one native release call, which itself destroys every host of the authority; their wrappers then
/// become disposed locally. The first <see cref="Dispose"/> may throw <see cref="SasPairingNativeException"/>
/// if the native release reports a failure (for example <see cref="SasPairingStatus.OwnershipUncertain"/>);
/// the authority and its hosts are disposed all the same, and later calls do nothing.
/// </remarks>
public sealed class SasPairingAuthority : IDisposable
{
    private const string StatusOperation = "SasPairingAuthority.GetStatus";
    private const string CreateHostOperation = "SasPairingAuthority.CreateHost";
    private const string DisposeOperation = "SasPairingAuthority.Dispose";

    private readonly SasPairingRuntime _runtime;
    private readonly HashSet<SasPairingHost> _hosts = [];
    private bool _disposed;

    internal SasPairingAuthority(SasPairingRuntime runtime, ulong handle)
    {
        _runtime = runtime;
        Handle = handle;
    }

    /// <summary>
    /// Whether this authority was disposed, directly or because its runtime was disposed. A disposed
    /// authority refuses every operation locally.
    /// </summary>
    public bool IsDisposed
    {
        get
        {
            lock (_runtime.Gate)
            {
                return _disposed;
            }
        }
    }

    /// <summary>The owning runtime.</summary>
    internal SasPairingRuntime Runtime => _runtime;

    /// <summary>The exact native authority handle. Internal only; never exposed or printed.</summary>
    internal ulong Handle { get; }

    /// <summary>The live hosts of this authority (tests).</summary>
    internal int HostCount => _hosts.Count;

    private NativeProcessContext Context => _runtime.Context;

    /// <summary>
    /// Reads one snapshot of the authority's state from the native library: <see cref="SasPairingAuthorityState.Ready"/>
    /// with 1 to 10 remaining opportunities, or <see cref="SasPairingAuthorityState.Busy"/> or
    /// <see cref="SasPairingAuthorityState.Exhausted"/> with 0.
    /// </summary>
    /// <returns>The validated snapshot.</returns>
    /// <exception cref="ObjectDisposedException">The authority was disposed.</exception>
    /// <exception cref="SasPairingNativeException">The native status query failed.</exception>
    /// <exception cref="SasPairingContractException">
    /// The native library reported success with an impossible state, now or earlier in this process.
    /// </exception>
    public SasPairingAuthorityStatus GetStatus()
    {
        lock (_runtime.Gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            Context.AdmitNormal(StatusOperation);
            NativeAuthorityStatusOutcome status = Context.Lifecycle.AuthorityStatus(_runtime.Handle, Handle);
            Context.ThrowIfFailed(StatusOperation, status.Status);
            return Validate(Context, status.State, status.Remaining);
        }
    }

    /// <summary>
    /// Creates a host (one hosting context) for this authority. It does no networking and changes no
    /// accounting; several hosts of one authority share its opportunity budget.
    /// </summary>
    /// <returns>The new host, owned by this authority.</returns>
    /// <exception cref="ObjectDisposedException">The authority was disposed.</exception>
    /// <exception cref="SasPairingNativeException">Host creation failed.</exception>
    /// <exception cref="SasPairingContractException">The native library broke the ABI v1 contract, now or earlier in this process.</exception>
    public SasPairingHost CreateHost()
    {
        lock (_runtime.Gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            Context.AdmitNormal(CreateHostOperation);
            NativeCreateOutcome created = Context.Lifecycle.HostCreate(_runtime.Handle, Handle);
            Context.ThrowIfFailed(CreateHostOperation, created.Status);
            SasPairingHost host = new(this, Context.RequireHandle(CreateHostOperation, created.Handle));
            _hosts.Add(host);
            return host;
        }
    }

    /// <summary>
    /// Releases the authority with exactly one native call, which also destroys every host of it; their
    /// wrappers become disposed locally. The authority is disposed even when the native call reports a
    /// failure, which is then thrown. Later calls do nothing. Allowed after <see cref="SasPairingStatus.Fatal"/>
    /// and after a contract violation.
    /// </summary>
    /// <exception cref="SasPairingNativeException">The native release reported a failure (first call only).</exception>
    public void Dispose()
    {
        int status;
        lock (_runtime.Gate)
        {
            if (_disposed)
            {
                return;
            }

            try
            {
                status = Context.Lifecycle.AuthorityRelease(_runtime.Handle, Handle);
            }
            finally
            {
                InvalidateLocally();
                _runtime.Forget(this);
            }
        }

        Context.ThrowIfFailed(DisposeOperation, status);
    }

    /// <summary>Marks this authority and every host of it disposed, with no native call (a parent's cleanup did it).</summary>
    internal void InvalidateLocally()
    {
        _disposed = true;
        foreach (SasPairingHost host in _hosts)
        {
            host.InvalidateLocally();
        }

        _hosts.Clear();
    }

    /// <summary>Forgets a host disposed on its own (its native destroy was already attempted).</summary>
    internal void Forget(SasPairingHost host) => _hosts.Remove(host);

    /// <summary>
    /// Validates one successful native status snapshot against the frozen contract: READY with 1 to 10,
    /// BUSY with 0, EXHAUSTED with 0. Anything else latches a contract violation. One snapshot only: no
    /// earlier snapshot is remembered or compared.
    /// </summary>
    internal static SasPairingAuthorityStatus Validate(NativeProcessContext context, uint state, uint remaining) => state switch
    {
        AbiV1Constants.SAS_PAIRING_AUTHORITY_READY when remaining is >= 1 and <= NativeProcessContext.MaxAuthorityOpportunities =>
            new SasPairingAuthorityStatus(SasPairingAuthorityState.Ready, remaining),
        AbiV1Constants.SAS_PAIRING_AUTHORITY_BUSY when remaining == 0 =>
            new SasPairingAuthorityStatus(SasPairingAuthorityState.Busy, 0),
        AbiV1Constants.SAS_PAIRING_AUTHORITY_EXHAUSTED when remaining == 0 =>
            new SasPairingAuthorityStatus(SasPairingAuthorityState.Exhausted, 0),
        _ => throw context.ViolateContract(StatusOperation, $"returned authority state {state} with {remaining} remaining opportunities (allowed: READY with 1 to {NativeProcessContext.MaxAuthorityOpportunities}, BUSY with 0, EXHAUSTED with 0)"),
    };
}
