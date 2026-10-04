namespace SasPairing;

/// <summary>
/// Why loading or verifying the native library failed in <see cref="SasPairingRuntime.Create(string)"/>. No
/// native status exists for these failures: the native library was not (or not correctly) available.
/// </summary>
/// <remarks>
/// The first three happen before any library image is loaded and may be retried after the cause is fixed.
/// The other four happen after an image was loaded, which is never unloaded or replaced: every later
/// initialization in this process fails the same way, and only correcting the native library and restarting
/// the OS process recovers (<see cref="SasPairingInitializationException.ProcessRestartRequired"/>).
/// </remarks>
public enum SasPairingInitializationFailure
{
    /// <summary>The process is not 64-bit; nothing was opened. May be retried in a 64-bit process.</summary>
    UnsupportedPointerWidth,

    /// <summary>The path is empty, not fully qualified, or not an existing file; nothing was opened.</summary>
    InvalidLibraryPath,

    /// <summary>The operating system could not load the file as a library; no image was obtained.</summary>
    OpenFailed,

    /// <summary>The loaded library lacks one or more of the 25 frozen ABI v1 exports. Restart required.</summary>
    MissingSymbol,

    /// <summary>Binding the exports of the loaded library failed. Restart required.</summary>
    BindingFailed,

    /// <summary>The loaded library's ABI version query failed (it reported 0). Restart required.</summary>
    AbiVersionQueryFailed,

    /// <summary>The loaded library implements an ABI version other than 1. Restart required.</summary>
    AbiVersionMismatch,
}
