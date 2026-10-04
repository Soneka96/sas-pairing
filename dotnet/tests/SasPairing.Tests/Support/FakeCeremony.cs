using SasPairing.Interop;

namespace SasPairing.Tests.Support;

/// <summary>One recorded call of the fake ceremony service, with its exact handles and inputs.</summary>
internal sealed record FakeCeremonyCall(string Export, ulong[] Arguments, NativeBootstrapBytes? Local = null, NativeBootstrapBytes? Expected = null, byte[]? Identity = null);

/// <summary>
/// A fake ceremony-native service with deterministic outcomes and an exact call log. By default every call
/// succeeds with the frozen normal outcome of its export (a start issues a fresh run handle from 7000 with
/// <c>WRITE_PENDING</c>; an action keeps the run it names; reject and cancel end it; presentation answers
/// <c>available = 0</c>); outcomes can be queued per kind. It shares one fake process context with
/// <see cref="FakeLifecycleApi"/> and <see cref="FakeNetworkApi"/>.
/// </summary>
internal sealed class FakeCeremonyApi : INativeCeremonyApi
{
    internal const string StartExport = "sas_pairing_connection_start_initiator";
    internal const string AuthorizeExport = "sas_pairing_run_authorize_exposure";
    internal const string ExposeExport = "sas_pairing_run_expose_key";
    internal const string PresentationExport = "sas_pairing_run_presentation";
    internal const string ApproveExport = "sas_pairing_run_approve_sas";
    internal const string BootstrapMacExport = "sas_pairing_run_emit_bootstrap_mac";
    internal const string RejectExport = "sas_pairing_run_reject_sas";
    internal const string CancelExport = "sas_pairing_run_cancel_sas";
    internal const string FinishExport = "sas_pairing_run_emit_initiator_finish";

    private const uint WritePending = AbiV1Constants.SAS_PAIRING_ACTION_FLAG_WRITE_PENDING;

    private readonly Queue<Func<ulong, NativeActionOutcome>> _actions = new();
    private readonly Queue<NativePresentationOutcome> _presentations = new();
    private ulong _nextRun = 7000;

    internal List<FakeCeremonyCall> Calls { get; } = [];

    internal int Count(string export) => Calls.Count(c => c.Export == export);

    internal int Total => Calls.Count;

    /// <summary>Queues the outcome of the next start or action call.</summary>
    internal void Next(int status, NativeActionRecord? record = null) => _actions.Enqueue(_ => new NativeActionOutcome(status, record));

    /// <summary>Queues the next action outcome as a function of the run handle the call named (0 for a start).</summary>
    internal void Next(Func<ulong, NativeActionOutcome> outcome) => _actions.Enqueue(outcome);

    /// <summary>Queues the outcome of the next presentation call.</summary>
    internal void NextPresentation(int status, NativePresentationRecord? record = null) => _presentations.Enqueue(new NativePresentationOutcome(status, record));

    public NativeActionOutcome StartInitiator(ulong runtime, ulong host, ulong connection, NativeBootstrapBytes local, NativeBootstrapBytes? expected)
    {
        Calls.Add(new FakeCeremonyCall(StartExport, [runtime, host, connection], local, expected));
        return Outcome(0, () => Actions.Of(AbiV1Constants.SAS_PAIRING_LOCAL_EVENT_INITIATOR_STARTED, _nextRun++, WritePending));
    }

    public NativeActionOutcome AuthorizeExposure(ulong runtime, ulong host, ulong connection, ulong run) =>
        Act(AuthorizeExport, [runtime, host, connection, run], null, () => Actions.Of(AbiV1Constants.SAS_PAIRING_LOCAL_EVENT_EXPOSURE_AUTHORIZED, run));

    public NativeActionOutcome ExposeKey(ulong runtime, ulong host, ulong connection, ulong run) =>
        Act(ExposeExport, [runtime, host, connection, run], null, () => Actions.Of(AbiV1Constants.SAS_PAIRING_LOCAL_EVENT_KEY_EXPOSED, run, WritePending));

    public NativePresentationOutcome Presentation(ulong runtime, ulong host, ulong connection, ulong run)
    {
        Calls.Add(new FakeCeremonyCall(PresentationExport, [runtime, host, connection, run]));
        return _presentations.TryDequeue(out NativePresentationOutcome outcome) ? outcome : new NativePresentationOutcome(0, Presentations.None());
    }

    public NativeActionOutcome ApproveSas(ulong runtime, ulong host, ulong connection, ulong run, ReadOnlySpan<byte> ceremonyIdentity) =>
        Act(ApproveExport, [runtime, host, connection, run], ceremonyIdentity.ToArray(), () => Actions.Of(AbiV1Constants.SAS_PAIRING_LOCAL_EVENT_SAS_APPROVED, run));

    public NativeActionOutcome EmitBootstrapMac(ulong runtime, ulong host, ulong connection, ulong run) =>
        Act(BootstrapMacExport, [runtime, host, connection, run], null, () => Actions.Of(AbiV1Constants.SAS_PAIRING_LOCAL_EVENT_BOOTSTRAP_MAC_EMITTED, run, WritePending));

    public NativeActionOutcome RejectSas(ulong runtime, ulong host, ulong connection, ulong run, ReadOnlySpan<byte> ceremonyIdentity) =>
        Act(RejectExport, [runtime, host, connection, run], ceremonyIdentity.ToArray(), () => Actions.Of(AbiV1Constants.SAS_PAIRING_LOCAL_EVENT_SAS_REJECTED, 0, WritePending));

    public NativeActionOutcome CancelSas(ulong runtime, ulong host, ulong connection, ulong run, ReadOnlySpan<byte> ceremonyIdentity) =>
        Act(CancelExport, [runtime, host, connection, run], ceremonyIdentity.ToArray(), () => Actions.Of(AbiV1Constants.SAS_PAIRING_LOCAL_EVENT_SAS_CANCELLED, 0, WritePending));

    public NativeActionOutcome EmitInitiatorFinish(ulong runtime, ulong host, ulong connection, ulong run) =>
        Act(FinishExport, [runtime, host, connection, run], null, () => Actions.Of(AbiV1Constants.SAS_PAIRING_LOCAL_EVENT_INITIATOR_FINISH_EMITTED, run, WritePending));

    private NativeActionOutcome Act(string export, ulong[] arguments, byte[]? identity, Func<NativeActionRecord> normal)
    {
        Calls.Add(new FakeCeremonyCall(export, arguments, Identity: identity));
        return Outcome(arguments[3], normal);
    }

    private NativeActionOutcome Outcome(ulong run, Func<NativeActionRecord> normal) =>
        _actions.TryDequeue(out Func<ulong, NativeActionOutcome>? outcome) ? outcome(run) : new NativeActionOutcome(0, normal());
}

/// <summary>Builders of raw native action records.</summary>
internal static class Actions
{
    internal static NativeActionRecord Of(uint localEvent, ulong run, uint flags = 0, uint deadline = 0, uint reserved = 0) => new(localEvent, deadline, flags, reserved, run);
}

/// <summary>Builders of raw native SAS presentation records.</summary>
internal static class Presentations
{
    internal const string Display = "1234 5678 9012";

    /// <summary>A distinctive identity (0x00, 0x80, 0xFF, then <paramref name="seed"/> repeated).</summary>
    internal static byte[] Identity(byte seed = 0x5A) => [0x00, 0x80, 0xFF, .. Enumerable.Repeat(seed, 29)];

    internal static NativePresentationRecord None() => new(0, 0, new byte[32], new byte[14], new byte[2]);

    internal static NativePresentationRecord Live(byte[]? identity = null, string display = Display) =>
        new(1, 0, identity ?? Identity(), [.. display.Select(c => (byte)c)], new byte[2]);
}
