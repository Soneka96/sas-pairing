using SasPairing.Interop;

namespace SasPairing;

/// <summary>
/// The one native runtime of this process: the owning root of <see cref="SasPairingAuthority"/> and, through
/// them, <see cref="SasPairingHost"/> objects.
/// </summary>
/// <remarks>
/// <para>
/// A runtime is a native object lifetime, not a security session. Disposing it and creating another reuses
/// the same loaded native library and the same process state: authority opportunity accounting, START
/// limiting, every other same-process security state, and an observed <see cref="SasPairingStatus.Fatal"/> or
/// contract violation all continue. Only an OS process restart starts a fresh native process session.
/// </para>
/// <para>
/// Dispose it deterministically (<c>using</c> or <c>try</c>/<c>finally</c>); there is no finalizer. Disposing
/// makes exactly one native destroy call, which itself destroys every host and releases every authority of
/// the runtime; their wrappers then become disposed locally, without a native call of their own. The first
/// <see cref="Dispose"/> may throw <see cref="SasPairingNativeException"/> if native cleanup reports a
/// failure; the runtime is disposed all the same, and later calls do nothing.
/// </para>
/// <para>
/// Calls on one runtime and its authorities and hosts are serialized, so the objects may be used from several
/// threads; the native library allows one active runtime per process.
/// </para>
/// </remarks>
public sealed class SasPairingRuntime : IDisposable
{
    private const string CreateOperation = "SasPairingRuntime.Create";
    private const string RegisterOperation = "SasPairingRuntime.RegisterAuthority";
    private const string DisposeOperation = "SasPairingRuntime.Dispose";

    private readonly HashSet<SasPairingAuthority> _authorities = [];
    private bool _disposed;

    private SasPairingRuntime(NativeProcessContext context, ulong handle)
    {
        Context = context;
        Handle = handle;
    }

    /// <summary>Whether this runtime was disposed. A disposed runtime refuses every operation locally.</summary>
    public bool IsDisposed
    {
        get
        {
            lock (Gate)
            {
                return _disposed;
            }
        }
    }

    /// <summary>The process context below every runtime.</summary>
    internal NativeProcessContext Context { get; }

    /// <summary>The one lock of this runtime's object tree.</summary>
    internal Lock Gate { get; } = new();

    /// <summary>The exact native runtime handle. Internal only; never exposed or printed.</summary>
    internal ulong Handle { get; }

    /// <summary>
    /// Every result a drive of this runtime delivered (P9-D-003 R): owned by the runtime, never by a connection,
    /// host, or authority; invalidated only by the runtime's disposal.
    /// </summary>
    internal NativeResultStore Results { get; } = new();

    /// <summary>
    /// Creates the native runtime of this process, loading the native library from the absolute
    /// <paramref name="nativeLibraryPath"/> the first time. The library is loaded once per process and never
    /// unloaded; once loaded, later calls ignore the path. Nothing is searched for or discovered.
    /// </summary>
    /// <param name="nativeLibraryPath">The fully qualified path of the native ABI v1 library.</param>
    /// <returns>The new runtime. Another call while it is active fails with <see cref="SasPairingStatus.AlreadyInitialized"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="nativeLibraryPath"/> is null.</exception>
    /// <exception cref="SasPairingInitializationException">The native library could not be loaded or verified.</exception>
    /// <exception cref="SasPairingNativeException">
    /// <c>sas_pairing_runtime_create</c> failed, for example <see cref="SasPairingStatus.AlreadyInitialized"/>
    /// while another runtime is active, or <see cref="SasPairingStatus.Fatal"/>, also when native fatal was
    /// observed earlier in this process (then no native call is made).
    /// </exception>
    /// <exception cref="SasPairingContractException">The native library broke the ABI v1 contract, now or earlier in this process.</exception>
    public static SasPairingRuntime Create(string nativeLibraryPath)
    {
        ArgumentNullException.ThrowIfNull(nativeLibraryPath);
        return Create(NativeProcessContextSource.Process, nativeLibraryPath);
    }

    /// <summary><see cref="Create(string)"/> over another context source (tests).</summary>
    internal static SasPairingRuntime Create(NativeProcessContextSource source, string nativeLibraryPath) =>
        CreateIn(source.Initialize(nativeLibraryPath));

    /// <summary>Creates a runtime over an already initialized <paramref name="context"/> (tests use fake contexts).</summary>
    internal static SasPairingRuntime CreateIn(NativeProcessContext context)
    {
        context.AdmitNormal(CreateOperation);
        NativeCreateOutcome created = context.Lifecycle.RuntimeCreate();
        context.ThrowIfFailed(CreateOperation, created.Status);
        return new SasPairingRuntime(context, context.RequireHandle(CreateOperation, created.Handle));
    }

    /// <summary>
    /// Registers the authority named by <paramref name="scope"/> and takes its OS ownership. The scope is
    /// arbitrary binary data, passed to the native library byte for byte with its exact length (it is not
    /// text and has no terminator); the native core validates it.
    /// </summary>
    /// <param name="scope">The authority scope bytes. Copied by the native library during the call.</param>
    /// <returns>The registered authority, owned by this runtime.</returns>
    /// <exception cref="ObjectDisposedException">The runtime was disposed.</exception>
    /// <exception cref="SasPairingNativeException">
    /// Registration failed, for example <see cref="SasPairingStatus.InvalidScope"/>,
    /// <see cref="SasPairingStatus.AlreadyRegistered"/>, or <see cref="SasPairingStatus.UnsupportedPlatform"/>
    /// on platforms other than Windows.
    /// </exception>
    /// <exception cref="SasPairingContractException">The native library broke the ABI v1 contract, now or earlier in this process.</exception>
    public SasPairingAuthority RegisterAuthority(ReadOnlySpan<byte> scope)
    {
        lock (Gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            Context.AdmitNormal(RegisterOperation);
            NativeCreateOutcome registered = Context.Lifecycle.AuthorityRegister(Handle, scope);
            Context.ThrowIfFailed(RegisterOperation, registered.Status);
            SasPairingAuthority authority = new(this, Context.RequireHandle(RegisterOperation, registered.Handle));
            _authorities.Add(authority);
            return authority;
        }
    }

    /// <summary>
    /// Destroys the native runtime with exactly one native call, which also closes every listener and
    /// connection, destroys every host, releases every authority, and drops every result of it; their wrappers
    /// become disposed locally. The runtime is disposed even when the
    /// native call reports a failure, which is then thrown. Later calls do nothing. Allowed after
    /// <see cref="SasPairingStatus.Fatal"/> and after a contract violation.
    /// </summary>
    /// <exception cref="SasPairingNativeException">Native cleanup reported a failure (first call only).</exception>
    public void Dispose()
    {
        int status;
        lock (Gate)
        {
            if (_disposed)
            {
                return;
            }

            try
            {
                status = Context.Lifecycle.RuntimeDestroy(Handle);
            }
            finally
            {
                _disposed = true;
                foreach (SasPairingAuthority authority in _authorities)
                {
                    authority.InvalidateLocally();
                }

                _authorities.Clear();
                Results.InvalidateAll();
            }
        }

        Context.ThrowIfFailed(DisposeOperation, status);
    }

    /// <summary>Forgets an authority disposed on its own (its native release was already attempted).</summary>
    internal void Forget(SasPairingAuthority authority) => _authorities.Remove(authority);

    /// <summary>The live authorities of this runtime (tests).</summary>
    internal int AuthorityCount => _authorities.Count;
}
