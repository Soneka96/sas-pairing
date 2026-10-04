namespace SasPairing;

/// <summary>
/// What became of a deadline's best-effort authenticated CANCEL locally, with its frozen native value; never
/// whether the peer received it.
/// </summary>
public enum SasPairingCancelState
{
    /// <summary>Not a deadline ending.</summary>
    None = 0,

    /// <summary>No CANCEL was built (no shared SAS, or not a timeout).</summary>
    NotBuilt = 1,

    /// <summary>The CANCEL is now the connection's retained frame (best effort, never confirmed).</summary>
    Pending = 2,

    /// <summary>Another frame occupied the one retained slot, so the CANCEL was dropped.</summary>
    Dropped = 3,
}
