namespace SasPairing;

/// <summary>
/// A method was called on a <see cref="SasPairingRun"/> that this package already knows has ended (P9-D-004).
/// A local lifecycle error: no native call was made, and it carries no native status.
/// </summary>
/// <remarks>
/// The first native <see cref="SasPairingStatus.RunEnded"/> for a run not yet known to have ended is thrown as
/// that <see cref="SasPairingNativeException"/>; only later calls on the run throw this exception. It is not a
/// trust verdict and does not require a process restart.
/// </remarks>
public sealed class SasPairingRunEndedException : Exception
{
    internal SasPairingRunEndedException(string operation)
        : base($"{operation} was refused without entering the native library: the run has ended.")
    {
        Operation = operation;
    }

    /// <summary>The public operation that was refused, for example <c>SasPairingRun.ApproveSas</c>.</summary>
    public string Operation { get; }
}
