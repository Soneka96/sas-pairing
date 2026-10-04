using System.Runtime.InteropServices;

namespace SasPairing.Interop;

/// <summary>One loaded native image, as the loader sees it.</summary>
internal interface INativeImage
{
    /// <summary>Looks up an export by its exact name. A lookup only: nothing is called.</summary>
    bool TryGetExport(string name, out nint address);
}

/// <summary>
/// What the loader needs from the platform. Production uses <see cref="ProcessNativePlatform"/>; tests supply
/// their own to drive the state machine, never through the process loader.
/// </summary>
internal interface INativePlatform
{
    /// <summary>The process pointer width in bytes.</summary>
    int PointerSize { get; }

    /// <summary>
    /// Validates an explicit library path (fully qualified, an existing file) and returns its canonical form,
    /// or throws <see cref="NativeInitializationException"/> with
    /// <see cref="NativeInitializationFailure.InvalidLibraryPath"/>. Never searches for a library.
    /// </summary>
    string ResolveLibraryPath(string libraryPath);

    /// <summary>Loads the image at the canonical <paramref name="path"/>, or throws if the OS cannot.</summary>
    INativeImage Open(string path);
}

/// <summary>The loader state machine of P9-D-001.</summary>
internal enum NativeLoaderState
{
    /// <summary>No image is loaded. A pre-load failure leaves the loader here, so a later attempt may retry.</summary>
    Uninitialized,

    /// <summary>One image is loaded and verified; every later initialization returns the same binding.</summary>
    Ready,

    /// <summary>An image was loaded and then failed verification: permanent for the process.</summary>
    PermanentlyFailedAfterLoad,
}

/// <summary>
/// Process-lifetime loading of the one sas-pairing native library image (P9-D-001, P7-D-002, ABI contract
/// sections 14 and 21).
/// </summary>
/// <remarks>
/// <para>
/// Initialization order: (1) the process pointer width must be 8 bytes, else failure before any path work;
/// (2) the explicit path must be fully qualified and name an existing file, and is canonicalized; (3) exactly
/// one <c>NativeLibrary.Load</c> of that canonical path; (4) the image is retained; (5) all 25 frozen exports
/// are preflighted by exact name; (6) the function table is bound; (7) <c>sas_pairing_abi_version()</c> is
/// called, the only native call during initialization; (8) it must return exactly 1; (9) the binding is
/// published. Failures in steps 1 to 3 leave the loader uninitialized with nothing retained. Any failure
/// after step 3 is permanent: the image stays referenced and is never freed, no other path is ever inspected
/// or loaded, and every later call throws the same exception. Once ready, every later call returns the same
/// <see cref="NativeAbiV1"/> without inspecting its path argument or loading anything.
/// </para>
/// <para>
/// There is deliberately no unload, free, dispose, finalizer, reload, reset, or replace operation: the native
/// state is module state of the loaded image, so unloading it or loading another copy would leave the
/// supported contract, and the only recovery from <c>SAS_PAIRING_FATAL</c> is an OS process restart.
/// </para>
/// <para>
/// Supported model: one SasPairing assembly instance, loaded normally into the default
/// <c>AssemblyLoadContext</c>, owns the one native image of the OS process through <see cref="Process"/>.
/// Loading the assembly again in another load context would create another loader; that is outside the
/// supported model and is never a recovery mechanism. Nothing here can detect or prevent it.
/// </para>
/// </remarks>
internal sealed class NativeAbiV1Loader
{
    /// <summary>The pointer width (bytes) of the only supported native target: the frozen layouts are 64-bit.</summary>
    internal const int SupportedPointerSize = 8;

    private readonly INativePlatform _platform;
    private readonly Lock _gate = new();
    private NativeLoaderState _state = NativeLoaderState.Uninitialized;
    private NativeAbiV1? _ready;
    private NativeInitializationException? _permanentFailure;

    // A loaded image that failed verification, kept only so that it stays strongly referenced for the rest
    // of the process. It is never used, freed, or replaced.
    private INativeImage? _failedImage;

    internal NativeAbiV1Loader(INativePlatform platform)
    {
        _platform = platform;
    }

    /// <summary>
    /// The loader of this process, over the real platform. The one production entry point for the native
    /// library; tests of the state machine construct their own loaders instead.
    /// </summary>
    internal static NativeAbiV1Loader Process { get; } = new(ProcessNativePlatform.Instance);

    /// <summary>The current state.</summary>
    internal NativeLoaderState State
    {
        get
        {
            lock (_gate)
            {
                return _state;
            }
        }
    }

    /// <summary>The image held for the rest of the process (ready or failed after load), or null if none was loaded.</summary>
    internal INativeImage? RetainedImage
    {
        get
        {
            lock (_gate)
            {
                return _ready?.Image ?? _failedImage;
            }
        }
    }

    /// <summary>
    /// Loads and verifies the native library at the explicit absolute <paramref name="libraryPath"/> once.
    /// Returns the one <see cref="NativeAbiV1"/>; throws <see cref="NativeInitializationException"/>.
    /// </summary>
    internal NativeAbiV1 Initialize(string libraryPath)
    {
        lock (_gate)
        {
            switch (_state)
            {
                case NativeLoaderState.Ready:
                    return _ready!;
                case NativeLoaderState.PermanentlyFailedAfterLoad:
                    throw _permanentFailure!;
                case NativeLoaderState.Uninitialized:
                default:
                    break;
            }

            // Before an image is loaded: these failures leave the loader uninitialized.
            int pointerSize = _platform.PointerSize;
            if (pointerSize != SupportedPointerSize)
            {
                throw new NativeInitializationException(
                    NativeInitializationFailure.UnsupportedPointerWidth,
                    $"sas-pairing native ABI v1 supports only {SupportedPointerSize}-byte pointers; this process has {pointerSize}-byte pointers. No library was opened.");
            }

            string path = _platform.ResolveLibraryPath(libraryPath);
            INativeImage image;
            try
            {
                image = _platform.Open(path);
            }
            catch (Exception error) when (error is not NativeInitializationException)
            {
                throw new NativeInitializationException(
                    NativeInitializationFailure.OpenFailed,
                    $"Could not load the native library at \"{path}\": {error.Message}",
                    error);
            }

            // An image is now loaded and can never be unloaded: every failure from here on is permanent.
            try
            {
                return Verify(path, image);
            }
            catch (NativeInitializationException failure) when (failure.ProcessRestartRequired)
            {
                Poison(image, failure);
                throw;
            }
            catch (Exception error)
            {
                NativeInitializationException failure = new(
                    NativeInitializationFailure.BindingFailed,
                    $"Binding the native library at \"{path}\" failed: {error.Message}",
                    error);
                Poison(image, failure);
                throw failure;
            }
        }
    }

    private NativeAbiV1 Verify(string path, INativeImage image)
    {
        List<string> missing = [];
        foreach (string export in AbiV1Exports.Names)
        {
            if (!image.TryGetExport(export, out nint address) || address == 0)
            {
                missing.Add(export);
            }
        }

        if (missing.Count != 0)
        {
            throw new NativeInitializationException(
                NativeInitializationFailure.MissingSymbol,
                $"The native library at \"{path}\" lacks {missing.Count} of the {AbiV1Exports.Names.Count} frozen ABI v1 exports: {string.Join(", ", missing)}.");
        }

        AbiV1FunctionTable functions = AbiV1FunctionTable.Bind(image);
        uint version = functions.QueryAbiVersion();
        if (version == AbiV1Constants.SAS_PAIRING_ABI_VERSION_INVALID)
        {
            throw new NativeInitializationException(
                NativeInitializationFailure.AbiVersionQueryFailed,
                $"sas_pairing_abi_version() returned 0 (the version query failed inside the native library) for \"{path}\"; expected = {AbiV1Constants.SAS_PAIRING_ABI_VERSION}, actual = 0.");
        }

        if (version != AbiV1Constants.SAS_PAIRING_ABI_VERSION)
        {
            throw new NativeInitializationException(
                NativeInitializationFailure.AbiVersionMismatch,
                $"The native library at \"{path}\" implements ABI version {version}; expected = {AbiV1Constants.SAS_PAIRING_ABI_VERSION}, actual = {version}.");
        }

        _ready = new NativeAbiV1(path, image, functions, version);
        _state = NativeLoaderState.Ready;
        return _ready;
    }

    private void Poison(INativeImage image, NativeInitializationException failure)
    {
        _failedImage = image;
        _permanentFailure = failure;
        _state = NativeLoaderState.PermanentlyFailedAfterLoad;
    }
}

/// <summary>The real platform: <see cref="NativeLibrary"/> and the file system, with no library search.</summary>
internal sealed class ProcessNativePlatform : INativePlatform
{
    private ProcessNativePlatform()
    {
    }

    internal static ProcessNativePlatform Instance { get; } = new();

    public int PointerSize => IntPtr.Size;

    public string ResolveLibraryPath(string libraryPath)
    {
        if (string.IsNullOrEmpty(libraryPath))
        {
            throw Invalid(libraryPath, "the path is empty");
        }

        // A bare name or relative path would let the OS loader search for the library.
        if (!Path.IsPathFullyQualified(libraryPath))
        {
            throw Invalid(libraryPath, "the path must be absolute (fully qualified)");
        }

        string full = Path.GetFullPath(libraryPath);
        if (!File.Exists(full))
        {
            throw Invalid(libraryPath, "no such file");
        }

        try
        {
            string canonical = File.ResolveLinkTarget(full, returnFinalTarget: true)?.FullName ?? full;
            if (!File.Exists(canonical))
            {
                throw Invalid(libraryPath, "the link target is not an existing file");
            }

            return canonical;
        }
        catch (IOException error)
        {
            throw Invalid(libraryPath, error.Message);
        }
        catch (UnauthorizedAccessException error)
        {
            throw Invalid(libraryPath, error.Message);
        }
    }

    // The one NativeLibrary.Load of production code: an explicit, canonical, fully qualified path only. The
    // handle is never passed to NativeLibrary.Free.
    public INativeImage Open(string path) => new LoadedImage(NativeLibrary.Load(path));

    private static NativeInitializationException Invalid(string libraryPath, string why) => new(
        NativeInitializationFailure.InvalidLibraryPath,
        $"Invalid sas-pairing native library path \"{libraryPath}\": {why}. No library was opened.");

    /// <summary>A loaded OS module, strongly referenced and never freed.</summary>
    private sealed class LoadedImage(nint handle) : INativeImage
    {
        private readonly nint _handle = handle;

        public bool TryGetExport(string name, out nint address) => NativeLibrary.TryGetExport(_handle, name, out address);
    }
}
