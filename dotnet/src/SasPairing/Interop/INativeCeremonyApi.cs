namespace SasPairing.Interop;

/// <summary>
/// One <c>sas_pairing_action_t</c>, copied field by field into managed memory during the call that produced it.
/// Raw values: nothing is interpreted here.
/// </summary>
internal readonly record struct NativeActionRecord(uint Event, uint DeadlineKind, uint Flags, uint Reserved, ulong Run);

/// <summary>
/// The status of one trusted-local action call and its copied record. <see cref="Action"/> is set only when
/// <see cref="Status"/> is <c>SAS_PAIRING_OK</c>; on any other status the (zeroed) output is not read.
/// </summary>
internal readonly record struct NativeActionOutcome(int Status, NativeActionRecord? Action);

/// <summary>
/// One <c>sas_pairing_sas_presentation_t</c>, copied byte for byte into managed memory during the call that
/// produced it: all 32 identity bytes, all 14 decimal bytes, and both tail bytes. Raw values: nothing is
/// interpreted here.
/// </summary>
internal sealed record NativePresentationRecord(uint Available, uint Reserved, byte[] CeremonyIdentity, byte[] Decimal, byte[] ReservedTail);

/// <summary>
/// The status of one <c>sas_pairing_run_presentation</c> call and its copied record, set only on
/// <c>SAS_PAIRING_OK</c>.
/// </summary>
internal readonly record struct NativePresentationOutcome(int Status, NativePresentationRecord? Presentation);

/// <summary>
/// The private ceremony-native service of P9-D-004: exactly the nine frozen ABI v1 trusted-local ceremony
/// exports, one method each, with raw statuses, raw handles, and raw copied records. It validates and
/// interprets nothing and chains nothing: admission, outcome validation, run lifetime, and status translation
/// belong to the high-level wrappers. Production uses <see cref="FfiNativeCeremonyApi"/>; tests supply fakes.
/// </summary>
internal interface INativeCeremonyApi
{
    /// <summary>
    /// <c>sas_pairing_connection_start_initiator(runtime, host, connection, &amp;local, expected, &amp;out_action)</c>
    /// with <paramref name="expected"/> null for no expected peer Bootstrap.
    /// </summary>
    NativeActionOutcome StartInitiator(ulong runtime, ulong host, ulong connection, NativeBootstrapBytes local, NativeBootstrapBytes? expected);

    /// <summary><c>sas_pairing_run_authorize_exposure(runtime, host, connection, run, &amp;out_action)</c>.</summary>
    NativeActionOutcome AuthorizeExposure(ulong runtime, ulong host, ulong connection, ulong run);

    /// <summary><c>sas_pairing_run_expose_key(runtime, host, connection, run, &amp;out_action)</c>.</summary>
    NativeActionOutcome ExposeKey(ulong runtime, ulong host, ulong connection, ulong run);

    /// <summary><c>sas_pairing_run_presentation(runtime, host, connection, run, &amp;out_presentation)</c>.</summary>
    NativePresentationOutcome Presentation(ulong runtime, ulong host, ulong connection, ulong run);

    /// <summary><c>sas_pairing_run_approve_sas(runtime, host, connection, run, ceremony_identity, &amp;out_action)</c> with exactly 32 identity bytes.</summary>
    NativeActionOutcome ApproveSas(ulong runtime, ulong host, ulong connection, ulong run, ReadOnlySpan<byte> ceremonyIdentity);

    /// <summary><c>sas_pairing_run_emit_bootstrap_mac(runtime, host, connection, run, &amp;out_action)</c>.</summary>
    NativeActionOutcome EmitBootstrapMac(ulong runtime, ulong host, ulong connection, ulong run);

    /// <summary><c>sas_pairing_run_reject_sas(runtime, host, connection, run, ceremony_identity, &amp;out_action)</c> with exactly 32 identity bytes.</summary>
    NativeActionOutcome RejectSas(ulong runtime, ulong host, ulong connection, ulong run, ReadOnlySpan<byte> ceremonyIdentity);

    /// <summary><c>sas_pairing_run_cancel_sas(runtime, host, connection, run, ceremony_identity, &amp;out_action)</c> with exactly 32 identity bytes.</summary>
    NativeActionOutcome CancelSas(ulong runtime, ulong host, ulong connection, ulong run, ReadOnlySpan<byte> ceremonyIdentity);

    /// <summary><c>sas_pairing_run_emit_initiator_finish(runtime, host, connection, run, &amp;out_action)</c>.</summary>
    NativeActionOutcome EmitInitiatorFinish(ulong runtime, ulong host, ulong connection, ulong run);
}
