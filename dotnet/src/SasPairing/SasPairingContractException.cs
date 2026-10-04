namespace SasPairing;

/// <summary>
/// The native library reported success but returned an output that the frozen native ABI v1 contract makes
/// impossible (for example a zero handle, or an authority state outside READY 1 to 10, BUSY 0, or
/// EXHAUSTED 0), or a normal operation was refused because such a violation was observed earlier in this
/// process.
/// </summary>
/// <remarks>
/// After a contract violation the wrapper fails closed for the rest of the process: every later normal
/// operation is refused without entering the native library, while cleanup (<c>Dispose</c>) still runs.
/// There is no reset or recovery other than restarting the OS process.
/// </remarks>
public sealed class SasPairingContractException : Exception
{
    internal SasPairingContractException(string operation, string message)
        : base(message)
    {
        Operation = operation;
    }

    /// <summary>The public operation that observed the violation or was refused because of it.</summary>
    public string Operation { get; }

    /// <summary>Always true: only an OS process restart recovers from a native contract violation.</summary>
    public bool ProcessRestartRequired { get; } = true;
}
