namespace SasPairing.Interop;

/// <summary>
/// The production <see cref="INativeNetworkApi"/>: the five network exports called through the verified
/// <see cref="AbiV1FunctionTable"/> of the one loaded image (P9-D-003). The socket in/out slot, the event
/// array, and both drive outputs are stack locals passed for the one synchronous call; the Bootstrap bytes are
/// pinned for exactly that call. Every produced event is copied into managed memory before the call returns.
/// No pointer outlives a call, no native allocation is returned, and nothing is retained.
/// </summary>
// UNSAFE: the network exports take a caller-owned socket slot, Bootstrap views, an event array, and output slots as raw pointers.
internal sealed unsafe class FfiNativeNetworkApi : INativeNetworkApi
{
    private const int EventCapacity = (int)AbiV1Constants.SAS_PAIRING_MAX_DRIVE_EVENTS;

    private static readonly NativeBootstrapBytes NoBootstrap = new([], [], [], []);

    private readonly AbiV1FunctionTable _functions;

    internal FfiNativeNetworkApi(AbiV1FunctionTable functions)
    {
        _functions = functions;
    }

    public NativeAttachOutcome AttachWindowsListener(ulong runtime, ulong host, nuint listener, NativeBootstrapBytes local, NativeBootstrapBytes? expected)
    {
        nuint slot = listener;
        NativeBootstrapBytes peer = expected ?? NoBootstrap;
        int status;

        // Every field is pinned only for this call (the library copies the bytes); an empty field pins
        // nothing and is passed as NULL with length 0.
        fixed (byte* la = local.ApplicationIdentity, lk = local.KeyAlgorithm, lp = local.PublicKey, ls = local.SharedContext)
        fixed (byte* ea = peer.ApplicationIdentity, ek = peer.KeyAlgorithm, ep = peer.PublicKey, es = peer.SharedContext)
        {
            sas_pairing_bootstrap_view_t localView = NativeBootstrapMarshalling.View(local, la, lk, lp, ls);
            sas_pairing_bootstrap_view_t expectedView = NativeBootstrapMarshalling.View(peer, ea, ek, ep, es);
            status = _functions.sas_pairing_host_attach_windows_listener(runtime, host, &slot, &localView, expected is null ? null : &expectedView);
        }

        return new NativeAttachOutcome(status, slot);
    }

    public int DetachListener(ulong runtime, ulong host) => _functions.sas_pairing_host_detach_listener(runtime, host);

    public NativeDriveOutcome Drive(ulong runtime, ulong host) => DriveOnce(_functions.sas_pairing_host_drive, runtime, host);

    public NativeDriveOutcome RecheckAfterResume(ulong runtime, ulong host) => DriveOnce(_functions.sas_pairing_host_recheck_after_resume, runtime, host);

    public int ConnectionClose(ulong runtime, ulong host, ulong connection) => _functions.sas_pairing_connection_close(runtime, host, connection);

    private static NativeDriveOutcome DriveOnce(delegate* unmanaged[Cdecl]<ulong, ulong, sas_pairing_event_t*, nuint, nuint*, int*, int> call, ulong runtime, ulong host)
    {
        // Always the frozen capacity: never a size query, never more.
        sas_pairing_event_t* events = stackalloc sas_pairing_event_t[EventCapacity];
        new Span<byte>(events, EventCapacity * sizeof(sas_pairing_event_t)).Clear();
        nuint count = 0;
        int failure = AbiV1Constants.SAS_PAIRING_OK;
        int status = call(runtime, host, events, AbiV1Constants.SAS_PAIRING_MAX_DRIVE_EVENTS, &count, &failure);

        NativeEventRecord[] copied = [];
        if (status == AbiV1Constants.SAS_PAIRING_OK)
        {
            copied = new NativeEventRecord[(int)nuint.Min(count, AbiV1Constants.SAS_PAIRING_MAX_DRIVE_EVENTS)];
            for (int i = 0; i < copied.Length; i++)
            {
                copied[i] = Copy(&events[i]);
            }
        }

        return new NativeDriveOutcome(status, count, failure, copied);
    }

    private static NativeEventRecord Copy(sas_pairing_event_t* record) => new(
        record->kind,
        record->step_kind,
        record->protocol_event,
        record->reason,
        record->deadline_kind,
        record->cancel_state,
        record->cancel_reason,
        record->flags,
        record->connection,
        record->run,
        record->result,
        record->request_id_len,
        record->reserved,
        new ReadOnlySpan<byte>(record->request_id, (int)AbiV1Constants.SAS_PAIRING_MAX_REQUEST_ID_LEN).ToArray());
}
