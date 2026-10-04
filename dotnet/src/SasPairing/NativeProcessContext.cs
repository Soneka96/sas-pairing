using SasPairing.Interop;

namespace SasPairing;

/// <summary>
/// The native state of this process as the wrapper sees it (P9-D-002, P9-D-003, P9-D-004): the one verified ABI v1
/// binding, the lifecycle-native, network-native, and ceremony-native services over it, and two process latches that never reset, the observed native
/// <c>SAS_PAIRING_FATAL</c> and the observed wrapper contract violation (an impossible success output).
/// Shared below every runtime: disposing a runtime and creating another reuses it, latches included.
/// </summary>
/// <remarks>
/// Normal operations (runtime create, authority register, authority status, host create, listener attach,
/// drive, resume recheck, Initiator start, and the eight run ceremony operations) are admitted by
/// <see cref="AdmitNormal"/>, which checks, in order, the contract latch and then the fatal latch, and makes no
/// native call when either is set; the object-local disposed check comes before it in each wrapper. Cleanup
/// operations (runtime destroy, authority release, host destroy, listener detach, connection close) are never
/// admission-checked: they always make their one native call. Production obtains the one context from
/// <see cref="NativeProcessContextSource.Process"/>; tests construct their own over a fake service.
/// </remarks>
internal sealed class NativeProcessContext
{
    /// <summary>The largest remaining-opportunity count a READY authority status can report (frozen core value).</summary>
    internal const uint MaxAuthorityOpportunities = 10;

    private int _fatal;
    private string? _contractViolation;

    internal NativeProcessContext(INativeLifecycleApi lifecycle, INativeNetworkApi network, INativeCeremonyApi ceremony, NativeAbiV1? binding = null)
    {
        Lifecycle = lifecycle;
        Network = network;
        Ceremony = ceremony;
        Binding = binding;
    }

    /// <summary>The one verified ABI v1 binding of the process (null only for test contexts over a fake service).</summary>
    internal NativeAbiV1? Binding { get; }

    /// <summary>The lifecycle-native service.</summary>
    internal INativeLifecycleApi Lifecycle { get; }

    /// <summary>The network-native service, over the same binding as <see cref="Lifecycle"/>.</summary>
    internal INativeNetworkApi Network { get; }

    /// <summary>The ceremony-native service, over the same binding as <see cref="Lifecycle"/>.</summary>
    internal INativeCeremonyApi Ceremony { get; }

    /// <summary>Whether <c>SAS_PAIRING_FATAL</c> was observed in this process. Never cleared.</summary>
    internal bool IsFatal => Volatile.Read(ref _fatal) != 0;

    /// <summary>Whether an impossible native success output was observed in this process. Never cleared.</summary>
    internal bool IsContractViolated => Volatile.Read(ref _contractViolation) is not null;

    /// <summary>
    /// Admits a normal operation, or throws without any native call: <see cref="SasPairingContractException"/>
    /// after a contract violation, then <see cref="SasPairingNativeException"/> (<c>Fatal</c>) after native fatal.
    /// </summary>
    internal void AdmitNormal(string operation)
    {
        if (Volatile.Read(ref _contractViolation) is { } violation)
        {
            throw new SasPairingContractException(
                operation,
                $"{operation} was refused without entering the native library: a native ABI v1 contract violation was observed earlier in this process ({violation}). Restart the OS process.");
        }

        if (IsFatal)
        {
            throw new SasPairingNativeException(
                operation,
                (int)SasPairingStatus.Fatal,
                $"{operation} was refused without entering the native library: native status {SasPairingNativeException.Name((int)SasPairingStatus.Fatal)} was observed earlier in this process. The native state is permanently fatal; only an OS process restart recovers.");
        }
    }

    /// <summary>
    /// Returns when <paramref name="status"/> is <c>SAS_PAIRING_OK</c>; otherwise latches native fatal for
    /// status 900 and throws <see cref="SasPairingNativeException"/>. Any other value, known or unknown, is a
    /// failure that latches nothing.
    /// </summary>
    internal void ThrowIfFailed(string operation, int status)
    {
        if (status != AbiV1Constants.SAS_PAIRING_OK)
        {
            throw Failed(operation, status);
        }
    }

    /// <summary>
    /// The exception of the non-zero <paramref name="status"/>, after latching native fatal for status 900. Any
    /// other value, known or unknown, latches nothing.
    /// </summary>
    internal SasPairingNativeException Failed(string operation, int status)
    {
        if (status == AbiV1Constants.SAS_PAIRING_FATAL)
        {
            Volatile.Write(ref _fatal, 1);
            return new SasPairingNativeException(
                operation,
                status,
                $"{operation} failed with native status {SasPairingNativeException.Name(status)}. The native state of this process is permanently fatal: every later normal operation is refused, cleanup still runs, and only an OS process restart recovers.");
        }

        return new SasPairingNativeException(operation, status, $"{operation} failed with native status {SasPairingNativeException.Name(status)}.");
    }

    /// <summary>
    /// Records a status without throwing: latches native fatal for status 900 and does nothing else. Used for
    /// a drive's <c>out_failure</c>, whose batch must still be returned, and before a contract violation is
    /// thrown over a status that was not otherwise processed.
    /// </summary>
    internal void Observe(int status)
    {
        if (status == AbiV1Constants.SAS_PAIRING_FATAL)
        {
            Volatile.Write(ref _fatal, 1);
        }
    }

    /// <summary>
    /// Requires the non-zero handle that a successful native create must return; latches a contract violation
    /// and throws <see cref="SasPairingContractException"/> for zero.
    /// </summary>
    internal ulong RequireHandle(string operation, ulong handle) =>
        handle != 0 ? handle : throw ViolateContract(operation, "returned the invalid handle 0");

    /// <summary>Latches a contract violation of a successful call (the first description is kept) and returns the exception to throw.</summary>
    internal SasPairingContractException ViolateContract(string operation, string violation) =>
        BreakContract(operation, $"reported success but {violation}");

    /// <summary>
    /// Latches a contract violation whatever the call's status (the first description is kept) and returns the
    /// exception to throw; <paramref name="violation"/> completes "the native library ...".
    /// </summary>
    internal SasPairingContractException BreakContract(string operation, string violation)
    {
        string description = $"{operation}: the native library {violation}";
        Interlocked.CompareExchange(ref _contractViolation, description, null);
        return new SasPairingContractException(
            operation,
            $"{description}, which native ABI v1 forbids. Normal operations are refused for the rest of this process; cleanup still runs; restart the OS process.");
    }
}

/// <summary>
/// Creates the one <see cref="NativeProcessContext"/> over a loader's one binding, translating the private
/// loader failure into the public <see cref="SasPairingInitializationException"/>: the one place where it
/// becomes public. Production uses <see cref="Process"/> over <see cref="NativeAbiV1Loader.Process"/>; tests
/// construct their own over a fake platform and fake native services. There is no reset.
/// </summary>
internal sealed class NativeProcessContextSource
{
    private readonly NativeAbiV1Loader _loader;
    private readonly Func<NativeAbiV1, INativeLifecycleApi> _lifecycle;
    private readonly Func<NativeAbiV1, INativeNetworkApi> _network;
    private readonly Func<NativeAbiV1, INativeCeremonyApi> _ceremony;
    private readonly Lock _gate = new();
    private NativeProcessContext? _context;

    internal NativeProcessContextSource(
        NativeAbiV1Loader loader,
        Func<NativeAbiV1, INativeLifecycleApi> lifecycle,
        Func<NativeAbiV1, INativeNetworkApi> network,
        Func<NativeAbiV1, INativeCeremonyApi> ceremony)
    {
        _loader = loader;
        _lifecycle = lifecycle;
        _network = network;
        _ceremony = ceremony;
    }

    /// <summary>
    /// The source of this process: the P9.1 process loader and the real lifecycle, network, and ceremony
    /// exports, all over the one function table of the one image.
    /// </summary>
    internal static NativeProcessContextSource Process { get; } =
        new(NativeAbiV1Loader.Process, abi => new FfiNativeLifecycleApi(abi.Functions), abi => new FfiNativeNetworkApi(abi.Functions), abi => new FfiNativeCeremonyApi(abi.Functions));

    /// <summary>
    /// Initializes the loader once (later calls return its one binding without loading anything) and returns
    /// the one context over that binding; throws <see cref="SasPairingInitializationException"/>.
    /// </summary>
    internal NativeProcessContext Initialize(string libraryPath)
    {
        NativeAbiV1 binding;
        try
        {
            binding = _loader.Initialize(libraryPath);
        }
        catch (NativeInitializationException failure)
        {
            // Deliberately no inner exception: the private loader type stays an implementation detail.
            throw new SasPairingInitializationException(Translate(failure.Failure), failure.Message);
        }

        lock (_gate)
        {
            return _context ??= new NativeProcessContext(_lifecycle(binding), _network(binding), _ceremony(binding), binding);
        }
    }

    /// <summary>
    /// The exhaustive private-to-public category translation. A new loader category has no public meaning
    /// until one is decided here; until then it fails loudly (and the tests enumerate every category).
    /// </summary>
    internal static SasPairingInitializationFailure Translate(NativeInitializationFailure failure) => failure switch
    {
        NativeInitializationFailure.UnsupportedPointerWidth => SasPairingInitializationFailure.UnsupportedPointerWidth,
        NativeInitializationFailure.InvalidLibraryPath => SasPairingInitializationFailure.InvalidLibraryPath,
        NativeInitializationFailure.OpenFailed => SasPairingInitializationFailure.OpenFailed,
        NativeInitializationFailure.MissingSymbol => SasPairingInitializationFailure.MissingSymbol,
        NativeInitializationFailure.BindingFailed => SasPairingInitializationFailure.BindingFailed,
        NativeInitializationFailure.AbiVersionQueryFailed => SasPairingInitializationFailure.AbiVersionQueryFailed,
        NativeInitializationFailure.AbiVersionMismatch => SasPairingInitializationFailure.AbiVersionMismatch,
        _ => throw new ArgumentOutOfRangeException(nameof(failure), failure, "An initialization failure category without a public meaning."),
    };
}
