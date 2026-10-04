namespace SasPairing;

/// <summary>
/// The outcome of one successful trusted-local ceremony action (P9-D-004). Immutable; made only by this package.
/// A local action never carries a protocol frame or a result.
/// </summary>
public sealed class SasPairingLocalAction
{
    internal SasPairingLocalAction(SasPairingLocalEvent @event, SasPairingRun? run, SasPairingDeadlineKind deadlineKind, bool writePending)
    {
        Event = @event;
        Run = run;
        DeadlineKind = deadlineKind;
        WritePending = writePending;
    }

    /// <summary>What the action did.</summary>
    public SasPairingLocalEvent Event { get; }

    /// <summary>
    /// The run that is still live after the action: the same object the action was called on, or the new run
    /// of <see cref="SasPairingConnection.StartInitiator"/>. Null once the action ended the run
    /// (<see cref="SasPairingLocalEvent.SasRejected"/>, <see cref="SasPairingLocalEvent.SasCancelled"/>, or
    /// <see cref="SasPairingLocalEvent.Deadline"/>); the old <see cref="SasPairingRun"/> then reports
    /// <see cref="SasPairingRun.IsEnded"/>.
    /// </summary>
    public SasPairingRun? Run { get; }

    /// <summary>How the run's own deadline ended it: not <see cref="SasPairingDeadlineKind.None"/> exactly for <see cref="SasPairingLocalEvent.Deadline"/>.</summary>
    public SasPairingDeadlineKind DeadlineKind { get; }

    /// <summary>
    /// The action ran, and the native library now retains its output (or a deadline's timeout CANCEL) for its
    /// connection, to write it on a later <see cref="SasPairingHost.Drive"/>. Nothing is driven automatically.
    /// </summary>
    /// <remarks>
    /// Not the same as a <see cref="SasPairingNativeException"/> with <see cref="SasPairingStatus.WritePending"/>,
    /// which means the requested action did NOT run because an earlier frame is still retained: drive, then retry
    /// only if the application still wants to.
    /// </remarks>
    public bool WritePending { get; }
}
