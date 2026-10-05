namespace SasPairing.Interop;

/// <summary>
/// The production <see cref="INativeResultApi"/>: the three result-data exports called through the verified
/// <see cref="AbiV1FunctionTable"/> of the one loaded image (P9-D-005). The info record is a zeroed, aligned stack
/// local passed for the one synchronous call and copied into managed memory only when the call returns
/// <c>SAS_PAIRING_OK</c>; a copy's buffer has exactly the requested capacity (no terminator byte) and is pinned for
/// exactly that call, and its <c>size_t</c> output is a stack local. No pointer outlives a call, no native
/// allocation is returned, and nothing is retained.
/// </summary>
// UNSAFE: the result exports take a caller-owned info record, a caller byte buffer, and a size_t slot as raw pointers.
internal sealed unsafe class FfiNativeResultApi : INativeResultApi
{
    /// <summary>The frozen length of <c>ceremony_identity</c> (an inline <c>uint8_t[32]</c> of the header).</summary>
    private const int CeremonyIdentityLength = 32;

    private readonly AbiV1FunctionTable _functions;

    internal FfiNativeResultApi(AbiV1FunctionTable functions)
    {
        _functions = functions;
    }

    public NativeResultInfoOutcome ResultInfo(ulong runtime, ulong result)
    {
        sas_pairing_result_info_t info = default;
        int status = _functions.sas_pairing_result_info(runtime, result, &info);
        if (status != AbiV1Constants.SAS_PAIRING_OK)
        {
            return new NativeResultInfoOutcome(status, null);
        }

        return new NativeResultInfoOutcome(status, new NativeResultInfoRecord(
            new ReadOnlySpan<byte>(info.ceremony_identity, CeremonyIdentityLength).ToArray(),
            info.peer_role,
            info.profile_version,
            info.request_id_len,
            info.peer_bootstrap_len,
            info.shared_context_len,
            info.profile_identifier_len));
    }

    public NativeResultCopyOutcome ResultCopy(ulong runtime, ulong result, uint field, int capacity)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(capacity);

        // Exactly the requested capacity: no terminator, no slack, no size query. A zero capacity passes a null
        // buffer, which the export accepts only with capacity 0.
        byte[] buffer = new byte[capacity];
        nuint required = 0;
        int status;
        if (capacity == 0)
        {
            status = _functions.sas_pairing_result_copy(runtime, result, field, null, 0, &required);
        }
        else
        {
            fixed (byte* data = buffer)
            {
                status = _functions.sas_pairing_result_copy(runtime, result, field, data, (nuint)capacity, &required);
            }
        }

        if (status != AbiV1Constants.SAS_PAIRING_OK)
        {
            return new NativeResultCopyOutcome(status, required, null);
        }

        // Never more than the buffer holds, whatever the export reported.
        int written = required < (nuint)capacity ? (int)required : capacity;
        return new NativeResultCopyOutcome(status, required, written == capacity ? buffer : buffer[..written]);
    }

    public int ResultDestroy(ulong runtime, ulong result) => _functions.sas_pairing_result_destroy(runtime, result);
}
