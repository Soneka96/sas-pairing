namespace SasPairing;

/// <summary>
/// One drive event, as reported by the native core (P9-D-003). Operational metadata only: no protocol frame,
/// trust verdict, or authentication result. Immutable.
/// </summary>
public sealed class SasPairingEvent
{
    private readonly byte[] _requestId;

    internal SasPairingEvent(
        SasPairingEventKind kind,
        SasPairingConnection? connection,
        SasPairingStepKind stepKind,
        SasPairingProtocolEvent protocolEvent,
        SasPairingEventReason reason,
        SasPairingDeadlineKind deadlineKind,
        SasPairingCancelState cancelState,
        SasPairingCancelReason cancelReason,
        bool writePending,
        bool runUntracked,
        byte[] requestId,
        SasPairingRun? run,
        SasPairingResult? result)
    {
        Kind = kind;
        Connection = connection;
        StepKind = stepKind;
        ProtocolEvent = protocolEvent;
        Reason = reason;
        DeadlineKind = deadlineKind;
        CancelState = cancelState;
        CancelReason = cancelReason;
        WritePending = writePending;
        RunUntracked = runUntracked;
        _requestId = requestId;
        Run = run;
        Result = result;
    }

    /// <summary>The kind of the event.</summary>
    public SasPairingEventKind Kind { get; }

    /// <summary>
    /// The connection the event names: the same object for every event of one native connection. Null for
    /// <see cref="SasPairingEventKind.AcceptRefused"/> and <see cref="SasPairingEventKind.ListenerDisabled"/>.
    /// For <see cref="SasPairingEventKind.ConnectionClosed"/> it is already disposed.
    /// </summary>
    public SasPairingConnection? Connection { get; }

    /// <summary>What a <see cref="SasPairingEventKind.ConnectionStep"/> did; <see cref="SasPairingStepKind.None"/> otherwise.</summary>
    public SasPairingStepKind StepKind { get; }

    /// <summary>What a dispatched inbound frame did (<see cref="SasPairingStepKind.Inbound"/>).</summary>
    public SasPairingProtocolEvent ProtocolEvent { get; }

    /// <summary>The operational reason of a refusal or ending; never a verdict about the peer.</summary>
    public SasPairingEventReason Reason { get; }

    /// <summary>How a run ended by its own deadline processing (<see cref="SasPairingStepKind.Deadline"/>).</summary>
    public SasPairingDeadlineKind DeadlineKind { get; }

    /// <summary>What became of a deadline's best-effort CANCEL locally.</summary>
    public SasPairingCancelState CancelState { get; }

    /// <summary>The reason a verified peer CANCEL carried (<see cref="SasPairingProtocolEvent.PeerCancel"/>).</summary>
    public SasPairingCancelReason CancelReason { get; }

    /// <summary>
    /// The connection still holds one outbound frame, which the native library writes itself on a later drive.
    /// Not a failure, a busy authority, a trust signal, or a ceremony approval.
    /// </summary>
    public bool WritePending { get; }

    /// <summary>
    /// The event names a live run that got no run handle (its connection already holds the maximum number of
    /// run handles), so no trusted local ceremony action can ever target that run. See
    /// <see cref="ShouldDisposeConnection"/>.
    /// </summary>
    public bool RunUntracked { get; }

    /// <summary>
    /// The exact request ID bytes (0 to 64 of them): routing and correlation data only, never a run, ceremony
    /// identity, peer identity, or authentication, and never text.
    /// </summary>
    public ReadOnlySpan<byte> RequestId => _requestId;

    /// <summary>
    /// The live run the event names, tracked by its exact native run handle: the same object for every event and
    /// local action of that native run (also the run returned by <see cref="SasPairingConnection.StartInitiator"/>).
    /// Null when the event names no live run (for example after the run ended, or with <see cref="RunUntracked"/>).
    /// </summary>
    public SasPairingRun? Run { get; }

    /// <summary>Whether the event names a live run that the package tracks by its exact native run handle: exactly <c>Run is not null</c>.</summary>
    public bool HasTrackedRun => Run is not null;

    /// <summary>
    /// The new local verified result this event delivered, or null. The runtime owns it (not the connection, run,
    /// host, or authority), and this event is the only place it is ever returned: keep it, read it with
    /// <see cref="SasPairingResult.Read"/>, and dispose it when it is no longer wanted. It means only that THIS
    /// endpoint completed its ceremony locally: not that the peer completed or received the final message, not
    /// a bilateral commit, and not trust.
    /// </summary>
    public SasPairingResult? Result { get; }

    /// <summary>Whether the event delivered a new local verified result: exactly <c>Result is not null</c>.</summary>
    public bool HasResult => Result is not null;

    /// <summary>
    /// True exactly when <see cref="RunUntracked"/> is set on an event that names a connection: after processing
    /// the whole batch, the consumer SHOULD call <c>evt.Connection?.Dispose()</c>, because no trusted local
    /// action can target the untracked run. The drive never disposes the connection itself.
    /// </summary>
    public bool ShouldDisposeConnection => RunUntracked && Connection is not null;
}
