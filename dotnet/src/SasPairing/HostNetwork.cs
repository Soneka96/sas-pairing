using SasPairing.Interop;

namespace SasPairing;

/// <summary>
/// The package-internal network context of one <see cref="SasPairingHost"/> (P9-D-003): its network state,
/// its live connection wrappers keyed by exact native connection handle, and the five network operations with
/// their ownership and event-mapping rules. Every member runs under the runtime lock, called by the host or
/// a connection after its own disposed check.
/// </summary>
internal sealed class HostNetwork
{
    private const string AttachOperation = "SasPairingHost.AttachWindowsListener";

    private const uint KnownFlags = AbiV1Constants.SAS_PAIRING_EVENT_FLAG_WRITE_PENDING | AbiV1Constants.SAS_PAIRING_EVENT_FLAG_RUN_UNTRACKED;

    private readonly SasPairingHost _host;
    private readonly Dictionary<ulong, SasPairingConnection> _connections = [];

    internal HostNetwork(SasPairingHost host)
    {
        _host = host;
    }

    internal SasPairingHostNetworkState State { get; private set; } = SasPairingHostNetworkState.Detached;

    /// <summary>The live connections of the host (tests).</summary>
    internal IReadOnlyCollection<SasPairingConnection> Connections => _connections.Values;

    private SasPairingRuntime Runtime => _host.Authority.Runtime;

    private NativeProcessContext Context => Runtime.Context;

    /// <summary>
    /// Attach (normal). Order: the token's single-attempt gate, admission, one native call, the token updated
    /// from the slot before anything is thrown, the slot transition validated, the status processed, then
    /// <see cref="SasPairingHostNetworkState.Attached"/> on success.
    /// </summary>
    internal void Attach(SasPairingWindowsListenerSocket listener, SasPairingBootstrap local, SasPairingBootstrap? expected)
    {
        nuint offered = listener.BeginAttempt();
        NativeAttachOutcome outcome;
        try
        {
            Context.AdmitNormal(AttachOperation);
            outcome = Context.Network.AttachWindowsListener(Runtime.Handle, _host.Handle, offered, local.Native, expected?.Native);
        }
        catch
        {
            listener.AbandonAttempt();
            throw;
        }

        // The slot is the only evidence of who owns the socket: the token follows it before any status is acted on.
        ListenerSlotTransition slot = listener.CompleteAttempt(offered, outcome.ListenerSlotAfterCall);
        int status = outcome.Status;
        if (slot == ListenerSlotTransition.Adopted)
        {
            // Adoption happens only on a host without a listener; a failed setup leaves it without one.
            State = SasPairingHostNetworkState.Detached;
        }

        if (BrokenAttach(slot, status) is { } broken)
        {
            Context.Observe(status);
            throw Context.BreakContract(AttachOperation, broken);
        }

        Context.ThrowIfFailed(AttachOperation, status);
        State = SasPairingHostNetworkState.Attached;
    }

    /// <summary>Detach (cleanup, repeatable): one native call, then every connection is disposed locally and the state is Detached, whatever the status.</summary>
    internal int Detach()
    {
        int status;
        try
        {
            status = Context.Network.DetachListener(Runtime.Handle, _host.Handle);
        }
        finally
        {
            Teardown(SasPairingHostNetworkState.Detached);
        }

        return status;
    }

    /// <summary>One bounded native drive or one resume recheck (normal), mapped into a batch.</summary>
    internal SasPairingDriveBatch Drive(string operation, bool recheck)
    {
        Context.AdmitNormal(operation);
        NativeDriveOutcome outcome = recheck
            ? Context.Network.RecheckAfterResume(Runtime.Handle, _host.Handle)
            : Context.Network.Drive(Runtime.Handle, _host.Handle);
        Context.ThrowIfFailed(operation, outcome.Status);
        return Map(operation, outcome);
    }

    /// <summary>
    /// Closes one connection (cleanup): one native call, then the connection is disposed and forgotten whatever
    /// the status; <c>OWNERSHIP_UNCERTAIN</c> fails the whole host closed locally. Returns the status.
    /// </summary>
    internal int Close(SasPairingConnection connection)
    {
        int status;
        try
        {
            status = Context.Network.ConnectionClose(Runtime.Handle, _host.Handle, connection.Handle);
        }
        finally
        {
            _connections.Remove(connection.Handle);
            connection.InvalidateLocally();
        }

        if (status == AbiV1Constants.SAS_PAIRING_OWNERSHIP_UNCERTAIN)
        {
            Teardown(SasPairingHostNetworkState.FailedClosed);
        }

        return status;
    }

    /// <summary>
    /// Native reported that <paramref name="connection"/> ended during a ceremony call (<c>CONNECTION_ENDED</c>):
    /// it is disposed and forgotten, and every run of it ends, with no native close call.
    /// </summary>
    internal void EndConnection(SasPairingConnection connection)
    {
        _connections.Remove(connection.Handle);
        connection.InvalidateLocally();
    }

    /// <summary>Whether <paramref name="run"/> is a live run handle of any connection of this host.</summary>
    internal bool HoldsRun(ulong run) => _connections.Values.Any(c => c.HasRun(run));

    /// <summary>Every connection is disposed locally (no native call), and the host takes <paramref name="state"/>.</summary>
    internal void Teardown(SasPairingHostNetworkState state)
    {
        foreach (SasPairingConnection connection in _connections.Values)
        {
            connection.InvalidateLocally();
        }

        _connections.Clear();
        State = state;
    }

    private static string? BrokenAttach(ListenerSlotTransition slot, int status) => slot switch
    {
        ListenerSlotTransition.Impossible =>
            $"returned status {SasPairingNativeException.Name(status)} with a socket slot holding neither the offered socket nor SAS_PAIRING_SOCKET_INVALID",
        ListenerSlotTransition.Retained when status is AbiV1Constants.SAS_PAIRING_OK or AbiV1Constants.SAS_PAIRING_LISTENER_SETUP_FAILED =>
            $"returned status {SasPairingNativeException.Name(status)} but left the offered socket in the slot (only an adopted socket can be attached or fail setup)",
        ListenerSlotTransition.Adopted when status is AbiV1Constants.SAS_PAIRING_INVALID_ARGUMENT or AbiV1Constants.SAS_PAIRING_INVALID_HANDLE
            or AbiV1Constants.SAS_PAIRING_UNSUPPORTED_PLATFORM or AbiV1Constants.SAS_PAIRING_INVALID_BOOTSTRAP or AbiV1Constants.SAS_PAIRING_LISTENER_ALREADY_ATTACHED =>
            $"returned the pre-adoption status {SasPairingNativeException.Name(status)} but adopted the socket",
        _ => null,
    };

    /// <summary>
    /// Maps every record in native order, then lets a non-zero <c>out_failure</c> take effect: the fatal latch
    /// (without throwing), every connection disposed, and the host failed closed. A contract violation stops
    /// the mapping; results already retained stay with the runtime, and the failure still takes effect.
    /// </summary>
    private SasPairingDriveBatch Map(string operation, NativeDriveOutcome outcome)
    {
        int failure = outcome.Failure;
        SasPairingEvent[] events = new SasPairingEvent[outcome.Events.Length];
        try
        {
            if (outcome.Count > AbiV1Constants.SAS_PAIRING_MAX_DRIVE_EVENTS)
            {
                throw Context.ViolateContract(operation, $"reported {outcome.Count} events (at most {AbiV1Constants.SAS_PAIRING_MAX_DRIVE_EVENTS})");
            }

            if (failure == AbiV1Constants.SAS_PAIRING_OWNER_LOOP_CLOSED && outcome.Count != 0)
            {
                throw Context.ViolateContract(operation, "reported events with OWNER_LOOP_CLOSED, which drives nothing");
            }

            for (int i = 0; i < events.Length; i++)
            {
                events[i] = Apply(operation, outcome.Events[i]);
            }

            if (failure != AbiV1Constants.SAS_PAIRING_OK
                && SasPairingNativeException.Describe(failure) is { } known
                && known is not (SasPairingStatus.NetworkPollFailed or SasPairingStatus.OwnershipUncertain or SasPairingStatus.OwnerLoopClosed or SasPairingStatus.Fatal))
            {
                throw Context.ViolateContract(operation, $"reported the owner-loop failure {SasPairingNativeException.Name(failure)}, which ABI v1 never reports there");
            }
        }
        finally
        {
            if (failure != AbiV1Constants.SAS_PAIRING_OK)
            {
                // The events above stay delivered; then the loop's failure takes effect.
                Context.Observe(failure);
                Teardown(SasPairingHostNetworkState.FailedClosed);
            }
        }

        return new SasPairingDriveBatch(events, failure == AbiV1Constants.SAS_PAIRING_OK ? null : new SasPairingDriveFailure(failure));
    }

    /// <summary>Checks one record against the frozen structural invariants, then applies it to the host.</summary>
    private SasPairingEvent Apply(string operation, NativeEventRecord record)
    {
        SasPairingContractException Broken(string what) => Context.ViolateContract(operation, $"returned a drive event with {what}");

        SasPairingEventKind kind = Known<SasPairingEventKind>(record.Kind) ?? throw Broken($"unknown event kind {record.Kind}");
        SasPairingStepKind stepKind = Known<SasPairingStepKind>(record.StepKind) ?? throw Broken($"unknown step kind {record.StepKind}");
        SasPairingProtocolEvent protocolEvent = Known<SasPairingProtocolEvent>(record.ProtocolEvent) ?? throw Broken($"unknown protocol event {record.ProtocolEvent}");
        SasPairingEventReason reason = Known<SasPairingEventReason>(record.Reason) ?? throw Broken($"unknown reason {record.Reason}");
        SasPairingDeadlineKind deadlineKind = Known<SasPairingDeadlineKind>(record.DeadlineKind) ?? throw Broken($"unknown deadline kind {record.DeadlineKind}");
        SasPairingCancelState cancelState = Known<SasPairingCancelState>(record.CancelState) ?? throw Broken($"unknown cancel state {record.CancelState}");
        SasPairingCancelReason cancelReason = Known<SasPairingCancelReason>(record.CancelReason) ?? throw Broken($"unknown cancel reason {record.CancelReason}");
        if ((record.Flags & ~KnownFlags) != 0)
        {
            throw Broken($"unknown flag bits 0x{record.Flags & ~KnownFlags:X}");
        }

        if (record.Reserved != 0)
        {
            throw Broken("a non-zero reserved field");
        }

        if (record.RequestIdLength > AbiV1Constants.SAS_PAIRING_MAX_REQUEST_ID_LEN)
        {
            throw Broken($"request ID length {record.RequestIdLength} (at most {AbiV1Constants.SAS_PAIRING_MAX_REQUEST_ID_LEN})");
        }

        int length = (int)record.RequestIdLength;
        if (record.RequestId.AsSpan(length).ContainsAnyExcept((byte)0))
        {
            throw Broken("a non-zero request ID byte past its length");
        }

        bool connectionEvent = kind is SasPairingEventKind.ConnectionAccepted or SasPairingEventKind.ConnectionStep or SasPairingEventKind.ConnectionClosed;
        if (connectionEvent != (record.Connection != AbiV1Constants.SAS_PAIRING_CONNECTION_INVALID))
        {
            throw Broken(connectionEvent ? $"kind {kind} without a connection" : $"kind {kind} with a connection");
        }

        if (kind != SasPairingEventKind.ConnectionStep && (record.Run != 0 || record.Result != 0 || record.Flags != 0))
        {
            throw Broken($"kind {kind} with a run, a result, or flags");
        }

        if (record.Run != 0 && record.Result != 0)
        {
            throw Broken("both a run and a result");
        }

        bool runUntracked = (record.Flags & AbiV1Constants.SAS_PAIRING_EVENT_FLAG_RUN_UNTRACKED) != 0;
        if (runUntracked && record.Run != 0)
        {
            throw Broken("RUN_UNTRACKED and a run");
        }

        byte[] requestId = record.RequestId[..length];
        SasPairingConnection? connection = null;
        SasPairingRun? run = null;
        NativeResultRef? result = null;
        switch (kind)
        {
            case SasPairingEventKind.ConnectionAccepted:
                if (_connections.ContainsKey(record.Connection))
                {
                    throw Broken("a second ConnectionAccepted for a live connection");
                }

                connection = new SasPairingConnection(_host, record.Connection);
                _connections.Add(record.Connection, connection);
                break;
            case SasPairingEventKind.ListenerDisabled:
                // The listener is gone; existing connections continue and stay valid.
                State = SasPairingHostNetworkState.ListenerDisabled;
                break;
            case SasPairingEventKind.ConnectionStep:
                connection = _connections.GetValueOrDefault(record.Connection) ?? throw Broken("a ConnectionStep for a connection the host does not hold");
                (run, result) = Track(operation, connection, record, stepKind, protocolEvent, runUntracked, requestId);
                break;
            case SasPairingEventKind.ConnectionClosed:
                if (!_connections.Remove(record.Connection, out connection))
                {
                    throw Broken("a ConnectionClosed for a connection the host does not hold");
                }

                // Native already ended it: no close call.
                connection.InvalidateLocally();
                break;
            case SasPairingEventKind.AcceptRefused:
            default:
                break;
        }

        return new SasPairingEvent(
            kind,
            connection,
            stepKind,
            protocolEvent,
            reason,
            deadlineKind,
            cancelState,
            cancelReason,
            (record.Flags & AbiV1Constants.SAS_PAIRING_EVENT_FLAG_WRITE_PENDING) != 0,
            runUntracked,
            requestId,
            run,
            result);
    }

    /// <summary>The frozen run-reference rules (ABI contract §18.6) and runtime result retention of one step.</summary>
    private (SasPairingRun? Run, NativeResultRef? Result) Track(
        string operation,
        SasPairingConnection connection,
        NativeEventRecord record,
        SasPairingStepKind stepKind,
        SasPairingProtocolEvent protocolEvent,
        bool runUntracked,
        byte[] requestId)
    {
        if (record.Result != 0)
        {
            // A local verified completion: the run is terminal, and the result belongs to the runtime. Native
            // delivers each result once and never reuses a handle. Nothing of it is read here.
            NativeResultStore results = Runtime.Results;
            if (results.WasDelivered(record.Result))
            {
                throw Context.ViolateContract(operation, "returned a drive event with a result handle that was already delivered");
            }

            connection.Retire(requestId);
            return (null, results.Retain(record.Result));
        }

        if (record.Run != 0)
        {
            return (connection.RunFor(record.Run, requestId) ?? throw Context.ViolateContract(operation, "returned a drive event naming a run handle under a different request ID"), null);
        }

        // Endings the event makes visible; RUN_UNTRACKED names a live run and ends nothing.
        bool visibleEnd = stepKind switch
        {
            SasPairingStepKind.Inbound => protocolEvent != SasPairingProtocolEvent.StartDuplicate && !runUntracked,
            SasPairingStepKind.Deadline => requestId.Length != 0,
            _ => false,
        };
        if (visibleEnd)
        {
            connection.Retire(requestId);
        }

        return (null, null);
    }

    /// <summary>The public value of a frozen native namespace value, or null when the frozen namespace does not define it.</summary>
    internal static T? Known<T>(uint value)
        where T : struct, Enum =>
        value <= int.MaxValue && Enum.IsDefined(typeof(T), (int)value) ? (T)Enum.ToObject(typeof(T), (int)value) : null;
}
