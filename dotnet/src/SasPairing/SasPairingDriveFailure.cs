namespace SasPairing;

/// <summary>
/// The owner loop's own failure reported by an otherwise successful drive or recheck (the native
/// <c>out_failure</c>): the loop failed closed, and every event of the same batch is still valid. Not an
/// exception and not a trust verdict (P9-D-003).
/// </summary>
public sealed class SasPairingDriveFailure
{
    internal SasPairingDriveFailure(int statusCode)
    {
        StatusCode = statusCode;
    }

    /// <summary>
    /// The exact non-zero native status, for example <see cref="SasPairingStatus.NetworkPollFailed"/>,
    /// <see cref="SasPairingStatus.OwnershipUncertain"/>, <see cref="SasPairingStatus.OwnerLoopClosed"/>, or
    /// <see cref="SasPairingStatus.Fatal"/>; preserved even when it is not a known status.
    /// </summary>
    public int StatusCode { get; }

    /// <summary>The status as a frozen <see cref="SasPairingStatus"/>, or null for an unknown (future) status.</summary>
    public SasPairingStatus? KnownStatus => SasPairingNativeException.Describe(StatusCode);

    /// <summary>
    /// True only for <see cref="SasPairingStatus.Fatal"/> (900): the native state of this process is now
    /// permanently fatal; after cleanup, only an OS process restart recovers.
    /// </summary>
    public bool ProcessRestartRequired => StatusCode == (int)SasPairingStatus.Fatal;
}
