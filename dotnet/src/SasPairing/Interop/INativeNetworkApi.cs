namespace SasPairing.Interop;

/// <summary>
/// The four byte strings of one Bootstrap configuration, as package-owned arrays that are never mutated or
/// exposed (an empty field is an empty array). The input of the one Bootstrap marshalling path
/// (<see cref="NativeBootstrapMarshalling"/>).
/// </summary>
internal sealed record NativeBootstrapBytes(byte[] ApplicationIdentity, byte[] KeyAlgorithm, byte[] PublicKey, byte[] SharedContext);

/// <summary>
/// The status of one <c>sas_pairing_host_attach_windows_listener</c> call and the value its in/out socket slot
/// held after the call: the offered socket (not adopted) or <c>SAS_PAIRING_SOCKET_INVALID</c> (adopted).
/// </summary>
internal readonly record struct NativeAttachOutcome(int Status, nuint ListenerSlotAfterCall);

/// <summary>
/// One <c>sas_pairing_event_t</c>, copied field by field into managed memory during the call that produced it.
/// <see cref="RequestId"/> holds all 64 bytes of the record's inline array, including the bytes past
/// <see cref="RequestIdLength"/>. Raw values: nothing is interpreted here.
/// </summary>
internal sealed record NativeEventRecord(
    uint Kind,
    uint StepKind,
    uint ProtocolEvent,
    uint Reason,
    uint DeadlineKind,
    uint CancelState,
    uint CancelReason,
    uint Flags,
    ulong Connection,
    ulong Run,
    ulong Result,
    uint RequestIdLength,
    uint Reserved,
    byte[] RequestId);

/// <summary>
/// The raw outcome of one drive or resume recheck: the function status, <c>*out_count</c>, <c>*out_failure</c>,
/// and the copied records. On <c>SAS_PAIRING_OK</c>, <see cref="Events"/> holds the first
/// <c>min(Count, 17)</c> records (the call never had room for more); otherwise it is empty.
/// </summary>
internal sealed record NativeDriveOutcome(int Status, nuint Count, int Failure, NativeEventRecord[] Events);

/// <summary>
/// The private network-native service of P9-D-003: exactly the five frozen ABI v1 network exports, one method
/// each, with raw statuses, raw handles, and raw socket values. It validates and interprets nothing:
/// admission, ownership, event mapping, and status translation belong to the high-level wrappers and
/// <see cref="NativeProcessContext"/>. Production uses <see cref="FfiNativeNetworkApi"/>; tests supply fakes.
/// </summary>
internal interface INativeNetworkApi
{
    /// <summary>
    /// <c>sas_pairing_host_attach_windows_listener(runtime, host, &amp;slot, &amp;local, expected)</c> with the
    /// slot initialized to <paramref name="listener"/> and <paramref name="expected"/> null for no expected
    /// peer Bootstrap.
    /// </summary>
    NativeAttachOutcome AttachWindowsListener(ulong runtime, ulong host, nuint listener, NativeBootstrapBytes local, NativeBootstrapBytes? expected);

    /// <summary><c>sas_pairing_host_detach_listener(runtime, host)</c>.</summary>
    int DetachListener(ulong runtime, ulong host);

    /// <summary><c>sas_pairing_host_drive(runtime, host, events, 17, &amp;out_count, &amp;out_failure)</c>.</summary>
    NativeDriveOutcome Drive(ulong runtime, ulong host);

    /// <summary><c>sas_pairing_host_recheck_after_resume(runtime, host, events, 17, &amp;out_count, &amp;out_failure)</c>.</summary>
    NativeDriveOutcome RecheckAfterResume(ulong runtime, ulong host);

    /// <summary><c>sas_pairing_connection_close(runtime, host, connection)</c>.</summary>
    int ConnectionClose(ulong runtime, ulong host, ulong connection);
}
