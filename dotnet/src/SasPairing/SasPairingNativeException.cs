namespace SasPairing;

/// <summary>
/// A native operation returned a non-zero status, or a normal operation was refused without entering the
/// native library because <see cref="SasPairingStatus.Fatal"/> was observed earlier in this process.
/// </summary>
/// <remarks>
/// The status is the outcome of one operation, never a trust verdict about a peer. The message names the
/// operation and the status only: it never contains a native handle or authority scope bytes.
/// </remarks>
public sealed class SasPairingNativeException : Exception
{
    internal SasPairingNativeException(string operation, int statusCode, string message)
        : base(message)
    {
        Operation = operation;
        StatusCode = statusCode;
    }

    /// <summary>The public operation that failed, for example <c>SasPairingAuthority.GetStatus</c>.</summary>
    public string Operation { get; }

    /// <summary>The exact non-zero native status, preserved even when it is not a known <see cref="SasPairingStatus"/>.</summary>
    public int StatusCode { get; }

    /// <summary>The status as a frozen <see cref="SasPairingStatus"/>, or null for an unknown (future) status.</summary>
    public SasPairingStatus? KnownStatus => Describe(StatusCode);

    /// <summary>
    /// True only for <see cref="SasPairingStatus.Fatal"/> (900): the native state of this process is
    /// permanently fatal, every later normal operation is refused, and only an OS process restart recovers.
    /// An unknown status is a failure but not fatal.
    /// </summary>
    public bool ProcessRestartRequired => StatusCode == (int)SasPairingStatus.Fatal;

    internal static SasPairingStatus? Describe(int statusCode) =>
        Enum.IsDefined((SasPairingStatus)statusCode) ? (SasPairingStatus)statusCode : null;

    internal static string Name(int statusCode) =>
        Describe(statusCode) is { } known ? $"{known} ({statusCode})" : $"unknown status {statusCode}";
}
