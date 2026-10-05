namespace SasPairing;

/// <summary>
/// One immutable snapshot of an authority's state, as the native library reported it. The native library is
/// the only authority on opportunity accounting: the wrapper validates each snapshot against the frozen
/// contract (<see cref="SasPairingAuthorityState.Ready"/> with 1 to 10, otherwise 0) and keeps no budget,
/// counter, or expectation of how snapshots follow each other.
/// </summary>
/// <param name="State">The authority state.</param>
/// <param name="RemainingOpportunities">
/// The remaining opportunities of this process session: 1 to 10 when <see cref="State"/> is
/// <see cref="SasPairingAuthorityState.Ready"/>, otherwise 0.
/// </param>
public readonly record struct SasPairingAuthorityStatus(SasPairingAuthorityState State, uint RemainingOpportunities);
