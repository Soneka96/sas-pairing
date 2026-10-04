namespace SasPairing.Interop;

/// <summary>
/// Why native ABI v1 initialization failed (P9-D-001). The first three happen before an image is loaded and
/// may be retried after the cause is fixed; the rest happen after <c>NativeLibrary.Load</c> returned an image
/// and are permanent for the process, because the image is never unloaded (P7-D-002). Internal: P9.2 defines
/// the public initialization error surface.
/// </summary>
internal enum NativeInitializationFailure
{
    /// <summary>Pre-load: the process pointer width is not 8 bytes. Nothing was validated or opened.</summary>
    UnsupportedPointerWidth,

    /// <summary>Pre-load: the path is empty, not fully qualified, or not an existing file. Nothing was opened.</summary>
    InvalidLibraryPath,

    /// <summary>Pre-load: <c>NativeLibrary.Load</c> failed, so no image handle was obtained.</summary>
    OpenFailed,

    /// <summary>Post-load: the loaded image lacks one or more of the 25 frozen exports.</summary>
    MissingSymbol,

    /// <summary>Post-load: building the function table over the loaded image failed.</summary>
    BindingFailed,

    /// <summary>Post-load: <c>sas_pairing_abi_version()</c> returned 0 (the query itself failed natively).</summary>
    AbiVersionQueryFailed,

    /// <summary>Post-load: <c>sas_pairing_abi_version()</c> returned a version other than 1.</summary>
    AbiVersionMismatch,
}

/// <summary>Classification helpers for <see cref="NativeInitializationFailure"/>.</summary>
internal static class NativeInitializationFailureExtensions
{
    /// <summary>
    /// True when the failure happened after an image was loaded: the loader is then permanently failed for
    /// this process, and the only recovery is to correct the native library and restart the OS process.
    /// </summary>
    internal static bool IsPostLoad(this NativeInitializationFailure failure) => failure switch
    {
        NativeInitializationFailure.UnsupportedPointerWidth => false,
        NativeInitializationFailure.InvalidLibraryPath => false,
        NativeInitializationFailure.OpenFailed => false,
        NativeInitializationFailure.MissingSymbol => true,
        NativeInitializationFailure.BindingFailed => true,
        NativeInitializationFailure.AbiVersionQueryFailed => true,
        NativeInitializationFailure.AbiVersionMismatch => true,
        _ => throw new ArgumentOutOfRangeException(nameof(failure), failure, "Unknown initialization failure."),
    };
}

/// <summary>Native ABI v1 initialization failed; see <see cref="Failure"/>.</summary>
internal sealed class NativeInitializationException : Exception
{
    internal NativeInitializationException(NativeInitializationFailure failure, string message, Exception? innerException = null)
        : base(Compose(failure, message), innerException)
    {
        Failure = failure;
    }

    /// <summary>The failure category.</summary>
    internal NativeInitializationFailure Failure { get; }

    /// <summary>True for a post-load failure: correct the native library, then restart the OS process.</summary>
    internal bool ProcessRestartRequired => Failure.IsPostLoad();

    private static string Compose(NativeInitializationFailure failure, string message) =>
        failure.IsPostLoad()
            ? $"{message} The loaded native image is never unloaded or replaced: correct the native library, then restart the OS process."
            : message;
}
