namespace SasPairing;

/// <summary>
/// One hosting context (one native core router) of a <see cref="SasPairingAuthority"/>. A host is not a
/// socket, connection, peer, run, or security session: several hosts of one authority share its opportunity
/// budget and START limiter. Listener and network operations are not part of this increment.
/// </summary>
/// <remarks>
/// Disposing makes exactly one native destroy call; the authority and its other hosts stay valid. The host is
/// disposed even when the native call reports a failure, which the first <see cref="Dispose"/> then throws as
/// <see cref="SasPairingNativeException"/>; later calls do nothing. Releasing the authority or disposing the
/// runtime destroys the host natively and marks this wrapper disposed without a call of its own.
/// </remarks>
public sealed class SasPairingHost : IDisposable
{
    private const string DisposeOperation = "SasPairingHost.Dispose";

    private readonly SasPairingAuthority _authority;
    private bool _disposed;

    internal SasPairingHost(SasPairingAuthority authority, ulong handle)
    {
        _authority = authority;
        Handle = handle;
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

    /// <summary>The owning authority.</summary>
    internal SasPairingAuthority Authority => _authority;

    /// <summary>The exact native host handle. Internal only; never exposed or printed.</summary>
    internal ulong Handle { get; }

    /// <summary>
    /// Destroys the host with exactly one native call. The host is disposed even when the native call reports
    /// a failure, which is then thrown. Later calls do nothing. Allowed after <see cref="SasPairingStatus.Fatal"/>
    /// and after a contract violation.
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
                _disposed = true;
                _authority.Forget(this);
            }
        }

        runtime.Context.ThrowIfFailed(DisposeOperation, status);
    }

    /// <summary>Marks this host disposed with no native call (a parent's cleanup destroyed it natively).</summary>
    internal void InvalidateLocally() => _disposed = true;
}
