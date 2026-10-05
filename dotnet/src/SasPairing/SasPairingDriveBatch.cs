namespace SasPairing;

/// <summary>
/// The result of one bounded <see cref="SasPairingHost.Drive"/> or <see cref="SasPairingHost.RecheckAfterResume"/>:
/// every event the native call produced, in native order, and the owner loop's own failure if it failed during
/// the call (P9-D-003). Immutable.
/// </summary>
/// <remarks>
/// A batch can carry useful events and a <see cref="Failure"/> at the same time: process every event, then act
/// on the failure (the host is then <see cref="SasPairingHostNetworkState.FailedClosed"/>).
/// </remarks>
public sealed class SasPairingDriveBatch
{
    internal SasPairingDriveBatch(SasPairingEvent[] events, SasPairingDriveFailure? failure)
    {
        Events = Array.AsReadOnly(events);
        Failure = failure;
    }

    /// <summary>The events, in exactly the order the native call reported them (read-only; possibly empty).</summary>
    public IReadOnlyList<SasPairingEvent> Events { get; }

    /// <summary>
    /// Null when the owner loop did not fail; otherwise it failed closed after producing <see cref="Events"/>,
    /// every connection of the host is disposed, and the host is <see cref="SasPairingHostNetworkState.FailedClosed"/>.
    /// </summary>
    public SasPairingDriveFailure? Failure { get; }
}
