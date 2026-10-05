namespace SasPairing;

/// <summary>The state of a registered authority, as reported by <see cref="SasPairingAuthority.GetStatus"/>.</summary>
public enum SasPairingAuthorityState
{
    /// <summary>The authority can start a ceremony; 1 to 10 opportunities remain in this process session.</summary>
    Ready = 1,

    /// <summary>A ceremony of the authority is live; no opportunity count is reported.</summary>
    Busy = 2,

    /// <summary>The authority has no opportunity left in this process session.</summary>
    Exhausted = 3,
}
