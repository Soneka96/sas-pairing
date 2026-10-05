namespace SasPairing.Interop;

/// <summary>
/// The production <see cref="INativeCeremonyApi"/>: the nine trusted-local ceremony exports called through the
/// verified <see cref="AbiV1FunctionTable"/> of the one loaded image (P9-D-004). Each output record is a zeroed,
/// aligned stack local passed for the one synchronous call and copied into managed memory only when the call
/// returns <c>SAS_PAIRING_OK</c>; a decision's 32 identity bytes and a start's Bootstraps are pinned for exactly
/// that call. No pointer outlives a call, no native allocation is returned, and nothing is retained.
/// </summary>
// UNSAFE: the ceremony exports take caller-owned output records, Bootstrap views, and identity bytes as raw pointers.
internal sealed unsafe class FfiNativeCeremonyApi : INativeCeremonyApi
{
    /// <summary>The frozen length of <c>ceremony_identity</c> (an inline <c>uint8_t[32]</c> of the header).</summary>
    private const int CeremonyIdentityLength = 32;

    private const int DecimalLength = (int)AbiV1Constants.SAS_PAIRING_SAS_DECIMAL_LEN;

    private readonly AbiV1FunctionTable _functions;

    internal FfiNativeCeremonyApi(AbiV1FunctionTable functions)
    {
        _functions = functions;
    }

    public NativeActionOutcome StartInitiator(ulong runtime, ulong host, ulong connection, NativeBootstrapBytes local, NativeBootstrapBytes? expected)
    {
        NativeActionRecord? copied = null;

        // The Bootstraps go through the one marshalling path shared with listener attach.
        int status = NativeBootstrapMarshalling.Call(local, expected, (localView, expectedView) =>
        {
            sas_pairing_action_t action = default;
            int called = _functions.sas_pairing_connection_start_initiator(runtime, host, connection, localView, expectedView, &action);
            copied = Copy(called, &action);
            return called;
        });

        return new NativeActionOutcome(status, copied);
    }

    public NativeActionOutcome AuthorizeExposure(ulong runtime, ulong host, ulong connection, ulong run)
    {
        sas_pairing_action_t action = default;
        int status = _functions.sas_pairing_run_authorize_exposure(runtime, host, connection, run, &action);
        return new NativeActionOutcome(status, Copy(status, &action));
    }

    public NativeActionOutcome ExposeKey(ulong runtime, ulong host, ulong connection, ulong run)
    {
        sas_pairing_action_t action = default;
        int status = _functions.sas_pairing_run_expose_key(runtime, host, connection, run, &action);
        return new NativeActionOutcome(status, Copy(status, &action));
    }

    public NativePresentationOutcome Presentation(ulong runtime, ulong host, ulong connection, ulong run)
    {
        sas_pairing_sas_presentation_t presentation = default;
        int status = _functions.sas_pairing_run_presentation(runtime, host, connection, run, &presentation);
        if (status != AbiV1Constants.SAS_PAIRING_OK)
        {
            return new NativePresentationOutcome(status, null);
        }

        return new NativePresentationOutcome(status, new NativePresentationRecord(
            presentation.available,
            presentation.reserved,
            new ReadOnlySpan<byte>(presentation.ceremony_identity, CeremonyIdentityLength).ToArray(),
            new ReadOnlySpan<byte>(presentation.@decimal, DecimalLength).ToArray(),
            new ReadOnlySpan<byte>(presentation.reserved_tail, 2).ToArray()));
    }

    public NativeActionOutcome ApproveSas(ulong runtime, ulong host, ulong connection, ulong run, ReadOnlySpan<byte> ceremonyIdentity)
    {
        sas_pairing_action_t action = default;
        int status;
        fixed (byte* identity = Identity(ceremonyIdentity))
        {
            status = _functions.sas_pairing_run_approve_sas(runtime, host, connection, run, identity, &action);
        }

        return new NativeActionOutcome(status, Copy(status, &action));
    }

    public NativeActionOutcome EmitBootstrapMac(ulong runtime, ulong host, ulong connection, ulong run)
    {
        sas_pairing_action_t action = default;
        int status = _functions.sas_pairing_run_emit_bootstrap_mac(runtime, host, connection, run, &action);
        return new NativeActionOutcome(status, Copy(status, &action));
    }

    public NativeActionOutcome RejectSas(ulong runtime, ulong host, ulong connection, ulong run, ReadOnlySpan<byte> ceremonyIdentity)
    {
        sas_pairing_action_t action = default;
        int status;
        fixed (byte* identity = Identity(ceremonyIdentity))
        {
            status = _functions.sas_pairing_run_reject_sas(runtime, host, connection, run, identity, &action);
        }

        return new NativeActionOutcome(status, Copy(status, &action));
    }

    public NativeActionOutcome CancelSas(ulong runtime, ulong host, ulong connection, ulong run, ReadOnlySpan<byte> ceremonyIdentity)
    {
        sas_pairing_action_t action = default;
        int status;
        fixed (byte* identity = Identity(ceremonyIdentity))
        {
            status = _functions.sas_pairing_run_cancel_sas(runtime, host, connection, run, identity, &action);
        }

        return new NativeActionOutcome(status, Copy(status, &action));
    }

    public NativeActionOutcome EmitInitiatorFinish(ulong runtime, ulong host, ulong connection, ulong run)
    {
        sas_pairing_action_t action = default;
        int status = _functions.sas_pairing_run_emit_initiator_finish(runtime, host, connection, run, &action);
        return new NativeActionOutcome(status, Copy(status, &action));
    }

    /// <summary>
    /// The exact 32 bytes native reads: anything shorter would let native read past the caller's memory, so it
    /// is refused before the call (the public identity type always holds exactly 32).
    /// </summary>
    private static ReadOnlySpan<byte> Identity(ReadOnlySpan<byte> ceremonyIdentity) =>
        ceremonyIdentity.Length == CeremonyIdentityLength
            ? ceremonyIdentity
            : throw new ArgumentException($"A ceremony identity is exactly {CeremonyIdentityLength} bytes.", nameof(ceremonyIdentity));

    /// <summary>The record copied field by field on <c>SAS_PAIRING_OK</c>; nothing is read on any other status.</summary>
    private static NativeActionRecord? Copy(int status, sas_pairing_action_t* action) =>
        status == AbiV1Constants.SAS_PAIRING_OK
            ? new NativeActionRecord(action->@event, action->deadline_kind, action->flags, action->reserved, action->run)
            : null;
}
