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
        NativeRunRef? run,
        NativeResultRef? result)
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

    /// <summary>Whether the event names a live run that the package tracks by its exact native run handle.</summary>
    public bool HasTrackedRun => Run is not null;

    /// <summary>
    /// Whether the event delivered a new local verified result, which the runtime now holds. It means only that
    /// this endpoint completed locally: not that the peer succeeded, not a bilateral commit, and not trust.
    /// </summary>
    public bool HasResult => Result is not null;

    /// <summary>
    /// True exactly when <see cref="RunUntracked"/> is set on an event that names a connection: after processing
    /// the whole batch, the consumer SHOULD call <c>evt.Connection?.Dispose()</c>, because no trusted local
    /// action can target the untracked run. The drive never disposes the connection itself.
    /// </summary>
    public bool ShouldDisposeConnection => RunUntracked && Connection is not null;

    /// <summary>The exact run reference the event names (package-internal until P9.4).</summary>
    internal NativeRunRef? Run { get; }

    /// <summary>The runtime-owned result reference the event delivered (package-internal until P9.5).</summary>
    internal NativeResultRef? Result { get; }
}
