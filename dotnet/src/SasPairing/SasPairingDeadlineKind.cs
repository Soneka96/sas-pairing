namespace SasPairing;

/// <summary>
/// How a run ended by its own deadline processing, with its frozen native value. A timeout, the pending
/// pre-exposure resource expiry, and an unusable clock are different outcomes.
/// </summary>
public enum SasPairingDeadlineKind
{
    /// <summary>Not a deadline ending.</summary>
    None = 0,

    /// <summary>The run's absolute timeout.</summary>
    AbsoluteTimeout = 1,

    /// <summary>The run's inactivity timeout.</summary>
    InactivityTimeout = 2,

    /// <summary>The pending pre-exposure resource lifetime expired (not a timeout).</summary>
    PendingExpired = 3,

    /// <summary>The clock was unusable, so the run failed closed (not a timeout).</summary>
    ClockUnavailable = 4,
}
