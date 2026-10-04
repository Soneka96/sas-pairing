namespace SasPairing;

/// <summary>
/// The reason a verified peer CANCEL carried (<see cref="SasPairingProtocolEvent.PeerCancel"/>), with its frozen
/// native value.
/// </summary>
public enum SasPairingCancelReason
{
    /// <summary>Not a peer CANCEL.</summary>
    None = 0,

    /// <summary>The peer's user rejected the SAS comparison.</summary>
    UserRejection = 1,

    /// <summary>The peer's user cancelled.</summary>
    UserCancellation = 2,

    /// <summary>The peer's ceremony timed out.</summary>
    Timeout = 3,

    /// <summary>A local policy of the peer failed.</summary>
    LocalPolicyFailure = 4,
}
