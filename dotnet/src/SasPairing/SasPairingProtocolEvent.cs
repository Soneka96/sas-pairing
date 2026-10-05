namespace SasPairing;

/// <summary>
/// What one dispatched inbound frame did, with its frozen native value. Metadata reported by the native core:
/// this package parses no frame and judges no protocol sequence.
/// </summary>
public enum SasPairingProtocolEvent
{
    /// <summary>No inbound frame was dispatched.</summary>
    None = 0,

    /// <summary>A new START was admitted; its ACCEPT is retained for writing.</summary>
    StartAccepted = 1,

    /// <summary>A duplicate START.</summary>
    StartDuplicate = 2,

    /// <summary>An ACCEPT.</summary>
    Accept = 3,

    /// <summary>The Initiator's key.</summary>
    InitiatorKey = 4,

    /// <summary>The Responder's key.</summary>
    ResponderKey = 5,

    /// <summary>A BOOTSTRAP_MAC the native core verified.</summary>
    BootstrapMacAuthenticated = 6,

    /// <summary>An exact duplicate of the verified BOOTSTRAP_MAC.</summary>
    BootstrapMacDuplicate = 7,

    /// <summary>An INITIATOR_FINISH (no result yet).</summary>
    InitiatorFinish = 8,

    /// <summary>A duplicate INITIATOR_FINISH.</summary>
    InitiatorFinishDuplicate = 9,

    /// <summary>The Responder's FINISH ACK; the Initiator's final ACK is now retained (no result yet).</summary>
    ResponderFinishAck = 10,

    /// <summary>The Initiator's FINISH ACK: this Responder completed locally, and the event carries a result.</summary>
    InitiatorFinishAck = 11,

    /// <summary>A verified peer CANCEL ended the run; see <see cref="SasPairingEvent.CancelReason"/>.</summary>
    PeerCancel = 12,
}
