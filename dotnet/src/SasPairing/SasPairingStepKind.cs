namespace SasPairing;

/// <summary>
/// What one <see cref="SasPairingEventKind.ConnectionStep"/> did, with its frozen native value.
/// </summary>
public enum SasPairingStepKind
{
    /// <summary>Not a step event, or a step with nothing more to report than its flags or its result.</summary>
    None = 0,

    /// <summary>One inbound frame was dispatched; see <see cref="SasPairingEvent.ProtocolEvent"/>.</summary>
    Inbound = 1,

    /// <summary>A frame was refused by its START attempt or run (run-local); see <see cref="SasPairingEvent.Reason"/>.</summary>
    Refused = 2,

    /// <summary>A run ended by its own deadline processing; see <see cref="SasPairingEvent.DeadlineKind"/> and <see cref="SasPairingEvent.CancelState"/>.</summary>
    Deadline = 3,

    /// <summary>The connection's retained frame was written locally (not proof that the peer received it).</summary>
    Written = 4,

    /// <summary>The Initiator's final ACK was written locally and confirmed.</summary>
    Confirmed = 5,

    /// <summary>The final ACK was written but its run refused confirmation; see <see cref="SasPairingEvent.Reason"/>.</summary>
    Unconfirmed = 6,

    /// <summary>The retained frame's run ended before any byte was written; the frame was dropped.</summary>
    Discarded = 7,
}
