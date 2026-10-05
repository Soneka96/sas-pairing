namespace SasPairing.Interop;

/// <summary>
/// One <c>sas_pairing_result_info_t</c>, copied field by field into managed memory during the call that produced
/// it: all 32 identity bytes and the six integers. Raw values: nothing is interpreted here.
/// </summary>
internal sealed record NativeResultInfoRecord(
    byte[] CeremonyIdentity,
    uint PeerRole,
    uint ProfileVersion,
    uint RequestIdLength,
    uint PeerBootstrapLength,
    uint SharedContextLength,
    uint ProfileIdentifierLength);

/// <summary>
/// The status of one <c>sas_pairing_result_info</c> call and its copied record. <see cref="Info"/> is set only
/// when <see cref="Status"/> is <c>SAS_PAIRING_OK</c>; on any other status the (zeroed) output is not read.
/// </summary>
internal readonly record struct NativeResultInfoOutcome(int Status, NativeResultInfoRecord? Info);

/// <summary>
/// The status of one <c>sas_pairing_result_copy</c> call, the raw <c>*out_required</c> value it wrote, and, only
/// on <c>SAS_PAIRING_OK</c>, a managed copy of the bytes it wrote into the buffer (never more than the capacity).
/// On any other status <see cref="Bytes"/> is null: the buffer is not meaningful.
/// </summary>
internal readonly record struct NativeResultCopyOutcome(int Status, nuint Required, byte[]? Bytes);

/// <summary>
/// The private result-native service of P9-D-005: exactly the three frozen ABI v1 result-data exports, one
/// method each, with raw statuses and raw copied values. It validates, interprets, negotiates, and retries
/// nothing: admission, the info and copy contracts, snapshot construction, and lifetime belong to
/// <see cref="SasPairingResult"/>. Production uses <see cref="FfiNativeResultApi"/>; tests supply fakes.
/// </summary>
internal interface INativeResultApi
{
    /// <summary><c>sas_pairing_result_info(runtime, result, &amp;out_info)</c>.</summary>
    NativeResultInfoOutcome ResultInfo(ulong runtime, ulong result);

    /// <summary>
    /// <c>sas_pairing_result_copy(runtime, result, field, buffer, capacity, &amp;out_required)</c> into a buffer of
    /// exactly <paramref name="capacity"/> bytes (<c>NULL</c> when it is 0).
    /// </summary>
    NativeResultCopyOutcome ResultCopy(ulong runtime, ulong result, uint field, int capacity);

    /// <summary><c>sas_pairing_result_destroy(runtime, result)</c>.</summary>
    int ResultDestroy(ulong runtime, ulong result);
}
