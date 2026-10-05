using SasPairing.Interop;

namespace SasPairing;

/// <summary>The exact native handles one ceremony call names. Internal only; never exposed or printed.</summary>
internal readonly record struct CeremonyTarget(ulong Runtime, ulong Host, ulong Connection, ulong Run);

/// <summary>
/// One successful outcome a ceremony method allows (P9-D-004): the local event, whether the run stays live
/// (the same run, or the new run of a start), and the required write-pending flag (null: either).
/// </summary>
internal readonly record struct CeremonyOutcome(SasPairingLocalEvent Event, bool Live, bool? WritePending);

/// <summary>
/// The package-internal trusted-local ceremony rules of P9-D-004, shared by
/// <see cref="SasPairingConnection.StartInitiator"/> and every <see cref="SasPairingRun"/> method: the frozen
/// per-method outcome tables, the one validation of a successful action or presentation record, and the one
/// handler of the lifetime effects of a non-zero ceremony status. It makes no native call itself, chains no
/// action, and drives nothing. Every member runs under the runtime lock.
/// </summary>
internal static class CeremonyControl
{
    private const string StartOperation = "SasPairingConnection.StartInitiator";

    private const uint KnownActionFlags = AbiV1Constants.SAS_PAIRING_ACTION_FLAG_WRITE_PENDING;

    private const int DecimalLength = (int)AbiV1Constants.SAS_PAIRING_SAS_DECIMAL_LEN;

    private static readonly CeremonyOutcome DeadlineOutcome = new(SasPairingLocalEvent.Deadline, Live: false, WritePending: null);

    internal static CeremonyOutcome[] StartOutcomes { get; } = [new(SasPairingLocalEvent.InitiatorStarted, Live: true, WritePending: true)];

    internal static CeremonyOutcome[] AuthorizeOutcomes { get; } = [new(SasPairingLocalEvent.ExposureAuthorized, Live: true, WritePending: false), DeadlineOutcome];

    internal static CeremonyOutcome[] ExposeOutcomes { get; } = [new(SasPairingLocalEvent.KeyExposed, Live: true, WritePending: true), DeadlineOutcome];

    internal static CeremonyOutcome[] ApproveOutcomes { get; } =
        [new(SasPairingLocalEvent.SasApproved, Live: true, WritePending: false), new(SasPairingLocalEvent.SasAlreadyApproved, Live: true, WritePending: false), DeadlineOutcome];

    internal static CeremonyOutcome[] BootstrapMacOutcomes { get; } =
        [new(SasPairingLocalEvent.BootstrapMacEmitted, Live: true, WritePending: true), new(SasPairingLocalEvent.BootstrapMacAlreadyEmitted, Live: true, WritePending: false), DeadlineOutcome];

    internal static CeremonyOutcome[] RejectOutcomes { get; } = [new(SasPairingLocalEvent.SasRejected, Live: false, WritePending: null), DeadlineOutcome];

    internal static CeremonyOutcome[] CancelOutcomes { get; } = [new(SasPairingLocalEvent.SasCancelled, Live: false, WritePending: null), DeadlineOutcome];

    internal static CeremonyOutcome[] FinishOutcomes { get; } =
        [new(SasPairingLocalEvent.InitiatorFinishEmitted, Live: true, WritePending: true), new(SasPairingLocalEvent.InitiatorFinishAlreadyEmitted, Live: true, WritePending: false), DeadlineOutcome];

    /// <summary>
    /// <see cref="SasPairingConnection.StartInitiator"/> after the connection's disposed check: admission, exactly
    /// one native start, then its settlement (a new run only after a structurally valid success).
    /// </summary>
    internal static SasPairingLocalAction Start(SasPairingConnection connection, SasPairingBootstrap local, SasPairingBootstrap? expected)
    {
        SasPairingHost host = connection.Host;
        NativeProcessContext context = host.Authority.Runtime.Context;
        context.AdmitNormal(StartOperation);
        NativeActionOutcome outcome = context.Ceremony.StartInitiator(host.Authority.Runtime.Handle, host.Handle, connection.Handle, local.Native, expected?.Native);
        return SettleAction(StartOperation, StartOutcomes, outcome, connection, null);
    }

    /// <summary>
    /// Settles one action call: a non-zero status goes to <see cref="Failure"/>; a successful record is checked
    /// against the frozen invariants and the outcomes <paramref name="allowed"/> for the called method before any
    /// run state changes, then applied. <paramref name="input"/> is the run acted on, or null for a start.
    /// </summary>
    internal static SasPairingLocalAction SettleAction(string operation, CeremonyOutcome[] allowed, NativeActionOutcome outcome, SasPairingConnection connection, SasPairingRun? input)
    {
        if (outcome.Status != AbiV1Constants.SAS_PAIRING_OK)
        {
            throw Failure(operation, outcome.Status, connection, input);
        }

        NativeProcessContext context = connection.Host.Authority.Runtime.Context;
        SasPairingContractException Broken(string what) => context.ViolateContract(operation, $"returned a local action with {what}");

        NativeActionRecord record = outcome.Action ?? throw Broken("no action record");
        if (record.Reserved != 0)
        {
            throw Broken("a non-zero reserved field");
        }

        if ((record.Flags & ~KnownActionFlags) != 0)
        {
            throw Broken($"unknown flag bits 0x{record.Flags & ~KnownActionFlags:X}");
        }

        SasPairingLocalEvent localEvent = HostNetwork.Known<SasPairingLocalEvent>(record.Event) ?? throw Broken($"unknown local event {record.Event}");
        SasPairingDeadlineKind deadlineKind = HostNetwork.Known<SasPairingDeadlineKind>(record.DeadlineKind) ?? throw Broken($"unknown deadline kind {record.DeadlineKind}");
        if ((localEvent == SasPairingLocalEvent.Deadline) != (deadlineKind != SasPairingDeadlineKind.None))
        {
            throw Broken($"deadline kind {deadlineKind} on {localEvent}");
        }

        bool writePending = (record.Flags & AbiV1Constants.SAS_PAIRING_ACTION_FLAG_WRITE_PENDING) != 0;
        CeremonyOutcome expected = Array.Find(allowed, o => o.Event == localEvent);
        if (expected.Event != localEvent)
        {
            throw Broken($"{localEvent}, which is not an outcome of this operation");
        }

        if (expected.WritePending is { } required && required != writePending)
        {
            throw Broken($"{localEvent} {(writePending ? "with" : "without")} WRITE_PENDING");
        }

        if (!expected.Live)
        {
            if (record.Run != AbiV1Constants.SAS_PAIRING_RUN_INVALID)
            {
                throw Broken($"{localEvent} and a live run");
            }

            // Terminal: the run's handle is invalid natively from now on.
            connection.EndRun(input!);
            return new SasPairingLocalAction(localEvent, null, deadlineKind, writePending);
        }

        if (input is not null)
        {
            // The same exact run stays live: never another handle, never retargeted.
            if (record.Run != input.Ref.Handle)
            {
                throw Broken(record.Run == AbiV1Constants.SAS_PAIRING_RUN_INVALID ? $"{localEvent} without its live run" : $"{localEvent} and a different run");
            }

            return new SasPairingLocalAction(localEvent, input, deadlineKind, writePending);
        }

        // A start: a new exact run, with its request ID unknown until a drive event names it.
        if (record.Run == AbiV1Constants.SAS_PAIRING_RUN_INVALID)
        {
            throw Broken($"{localEvent} without a run");
        }

        if (connection.Host.Network.HoldsRun(record.Run))
        {
            throw Broken($"{localEvent} and the handle of a live run");
        }

        return new SasPairingLocalAction(localEvent, connection.StartRun(record.Run), deadlineKind, writePending);
    }

    /// <summary>
    /// Settles one presentation call: a non-zero status goes to <see cref="Failure"/>; a successful record is
    /// checked exactly (P9-D-004) and becomes null (<c>available = 0</c>) or an immutable presentation.
    /// </summary>
    internal static SasPairingSasPresentation? SettlePresentation(string operation, NativePresentationOutcome outcome, SasPairingRun run)
    {
        if (outcome.Status != AbiV1Constants.SAS_PAIRING_OK)
        {
            throw Failure(operation, outcome.Status, run.Connection, run);
        }

        NativeProcessContext context = run.Connection.Host.Authority.Runtime.Context;
        SasPairingContractException Broken(string what) => context.ViolateContract(operation, $"returned a SAS presentation with {what}");

        NativePresentationRecord record = outcome.Presentation ?? throw Broken("no presentation record");
        if (record.CeremonyIdentity.Length != SasPairingCeremonyIdentity.Length || record.Decimal.Length != DecimalLength || record.ReservedTail.Length != 2)
        {
            throw Broken("fields of the wrong length");
        }

        if (record.Reserved != 0)
        {
            throw Broken("a non-zero reserved field");
        }

        if (record.ReservedTail.AsSpan().ContainsAnyExcept((byte)0))
        {
            throw Broken("a non-zero reserved tail");
        }

        switch (record.Available)
        {
            case 0:
                if (record.CeremonyIdentity.AsSpan().ContainsAnyExcept((byte)0) || record.Decimal.AsSpan().ContainsAnyExcept((byte)0))
                {
                    throw Broken("available = 0 and a non-zero identity or decimal byte");
                }

                return null;
            case 1:
                char[] display = new char[DecimalLength];
                for (int i = 0; i < DecimalLength; i++)
                {
                    byte b = record.Decimal[i];
                    bool valid = i is 4 or 9 ? b == (byte)' ' : b is >= (byte)'0' and <= (byte)'9';
                    if (!valid)
                    {
                        throw Broken("a decimal SAS that is not exactly NNNN NNNN NNNN");
                    }

                    display[i] = (char)b;
                }

                return new SasPairingSasPresentation(new SasPairingCeremonyIdentity(record.CeremonyIdentity), new string(display));
            default:
                throw Broken($"available = {record.Available}");
        }
    }

    /// <summary>
    /// The one place that applies the frozen lifetime effects of a non-zero ceremony status (P9-D-004) and
    /// returns the exact native exception (latching <c>FATAL</c>). Nothing else is inferred: <c>WRITE_PENDING</c>,
    /// every ceremony or core refusal, and an unknown status change no state, and <c>FATAL</c> ends nothing.
    /// </summary>
    internal static SasPairingNativeException Failure(string operation, int status, SasPairingConnection connection, SasPairingRun? run)
    {
        HostNetwork network = connection.Host.Network;
        switch (status)
        {
            case AbiV1Constants.SAS_PAIRING_RUN_ENDED when run is not null:
                // The exact run is no longer routed; native removed its handle.
                connection.EndRun(run);
                break;
            case AbiV1Constants.SAS_PAIRING_CONNECTION_ENDED:
                // The connection and every run of it are invalid natively: no close call.
                network.EndConnection(connection);
                break;
            case AbiV1Constants.SAS_PAIRING_OWNERSHIP_UNCERTAIN:
            case AbiV1Constants.SAS_PAIRING_OWNER_LOOP_CLOSED:
                // The owner loop failed closed: every connection and run of the host is invalid.
                network.Teardown(SasPairingHostNetworkState.FailedClosed);
                break;
            default:
                break;
        }

        return connection.Host.Authority.Runtime.Context.Failed(operation, status);
    }
}
