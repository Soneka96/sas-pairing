namespace SasPairing;

/// <summary>
/// What one successful trusted-local ceremony action did, as reported by the native core, with its frozen
/// native value (P9-D-004). Every value is a successful outcome (a refusal is a
/// <see cref="SasPairingNativeException"/> instead), and none is a trust verdict.
/// </summary>
public enum SasPairingLocalEvent
{
    /// <summary>A local Initiator was routed and its START is retained for a later drive. No opportunity was spent.</summary>
    InitiatorStarted = 1,

    /// <summary>Fresh ceremony-specific exposure consent was recorded on exactly this run. Nothing was exposed, reserved, spent, or sent.</summary>
    ExposureAuthorized = 2,

    /// <summary>
    /// The authorization was consumed, the authority's guard and one opportunity were reserved (spent: never
    /// refunded), and this role's key is retained for a later drive.
    /// </summary>
    KeyExposed = 3,

    /// <summary>Local MATCH was recorded for the exact ceremony identity. Nothing was sent; BOOTSTRAP_MAC was not emitted.</summary>
    SasApproved = 4,

    /// <summary>Local MATCH was already recorded; nothing changed.</summary>
    SasAlreadyApproved = 5,

    /// <summary>This run's own BOOTSTRAP_MAC was produced once and is retained for a later drive.</summary>
    BootstrapMacEmitted = 6,

    /// <summary>BOOTSTRAP_MAC was already produced; nothing was recomputed or sent.</summary>
    BootstrapMacAlreadyEmitted = 7,

    /// <summary>
    /// INITIATOR_FINISH was produced once and is retained for a later drive. There is no result yet: the native
    /// library confirms the final ACK itself on a later drive.
    /// </summary>
    InitiatorFinishEmitted = 8,

    /// <summary>INITIATOR_FINISH was already produced; nothing was recomputed or sent.</summary>
    InitiatorFinishAlreadyEmitted = 9,

    /// <summary>
    /// Local MISMATCH: the run ended with no result and its opportunity stays spent. A best-effort authenticated
    /// CANCEL may be retained (<see cref="SasPairingLocalAction.WritePending"/>).
    /// </summary>
    SasRejected = 10,

    /// <summary>Local CANCEL: as <see cref="SasRejected"/>, with the distinct user-cancellation reason.</summary>
    SasCancelled = 11,

    /// <summary>
    /// The run's own deadline ended it first, and the requested action did NOT happen. See
    /// <see cref="SasPairingLocalAction.DeadlineKind"/>; a timeout CANCEL may be retained.
    /// </summary>
    Deadline = 12,
}
