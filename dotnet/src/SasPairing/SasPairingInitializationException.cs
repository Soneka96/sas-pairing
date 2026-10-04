namespace SasPairing;

/// <summary>
/// The native library could not be loaded or verified as native ABI v1 (see <see cref="Failure"/>). Thrown
/// only by <see cref="SasPairingRuntime.Create(string)"/>; it carries no native status.
/// </summary>
public sealed class SasPairingInitializationException : Exception
{
    internal SasPairingInitializationException(SasPairingInitializationFailure failure, string message)
        : base(message)
    {
        Failure = failure;
    }

    /// <summary>The failure category.</summary>
    public SasPairingInitializationFailure Failure { get; }

    /// <summary>
    /// True when a native image was already loaded (<see cref="SasPairingInitializationFailure.MissingSymbol"/>,
    /// <see cref="SasPairingInitializationFailure.BindingFailed"/>,
    /// <see cref="SasPairingInitializationFailure.AbiVersionQueryFailed"/>,
    /// <see cref="SasPairingInitializationFailure.AbiVersionMismatch"/>): every later initialization in this
    /// process fails the same way; correct the native library and restart the OS process. False when nothing
    /// was loaded, so a later call may succeed once the cause is fixed.
    /// </summary>
    public bool ProcessRestartRequired => Failure switch
    {
        SasPairingInitializationFailure.UnsupportedPointerWidth => false,
        SasPairingInitializationFailure.InvalidLibraryPath => false,
        SasPairingInitializationFailure.OpenFailed => false,
        SasPairingInitializationFailure.MissingSymbol => true,
        SasPairingInitializationFailure.BindingFailed => true,
        SasPairingInitializationFailure.AbiVersionQueryFailed => true,
        SasPairingInitializationFailure.AbiVersionMismatch => true,
        _ => true,
    };
}
