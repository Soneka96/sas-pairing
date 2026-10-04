namespace SasPairing.Interop;

/// <summary>
/// The production <see cref="INativeLifecycleApi"/>: the seven lifecycle exports called through the verified
/// <see cref="AbiV1FunctionTable"/> of the one loaded image (P9-D-002). Every output is a stack local whose
/// address is passed for the duration of the one synchronous call; the scope bytes are pinned for exactly
/// that call. No pointer outlives a call, no native allocation is returned, and nothing is retained.
/// </summary>
// UNSAFE: the lifecycle exports take caller-owned output slots and a borrowed scope byte range as raw pointers.
internal sealed unsafe class FfiNativeLifecycleApi : INativeLifecycleApi
{
    private readonly AbiV1FunctionTable _functions;

    internal FfiNativeLifecycleApi(AbiV1FunctionTable functions)
    {
        _functions = functions;
    }

    public NativeCreateOutcome RuntimeCreate()
    {
        ulong runtime = AbiV1Constants.SAS_PAIRING_RUNTIME_INVALID;
        int status = _functions.sas_pairing_runtime_create(&runtime);
        return new NativeCreateOutcome(status, runtime);
    }

    public int RuntimeDestroy(ulong runtime) => _functions.sas_pairing_runtime_destroy(runtime);

    public NativeCreateOutcome AuthorityRegister(ulong runtime, ReadOnlySpan<byte> scope)
    {
        ulong authority = AbiV1Constants.SAS_PAIRING_AUTHORITY_INVALID;
        int status;

        // The exact span bytes and length, pinned only for this call (the core copies them). An empty span
        // passes a null pointer with length 0, which the native library accepts and answers with
        // SAS_PAIRING_INVALID_SCOPE; the wrapper does not duplicate that validation.
        fixed (byte* bytes = scope)
        {
            status = _functions.sas_pairing_authority_register(runtime, scope.IsEmpty ? null : bytes, (nuint)scope.Length, &authority);
        }

        return new NativeCreateOutcome(status, authority);
    }

    public int AuthorityRelease(ulong runtime, ulong authority) => _functions.sas_pairing_authority_release(runtime, authority);

    public NativeAuthorityStatusOutcome AuthorityStatus(ulong runtime, ulong authority)
    {
        uint state = AbiV1Constants.SAS_PAIRING_AUTHORITY_STATE_INVALID;
        uint remaining = 0;
        int status = _functions.sas_pairing_authority_status(runtime, authority, &state, &remaining);
        return new NativeAuthorityStatusOutcome(status, state, remaining);
    }

    public NativeCreateOutcome HostCreate(ulong runtime, ulong authority)
    {
        ulong host = AbiV1Constants.SAS_PAIRING_HOST_INVALID;
        int status = _functions.sas_pairing_host_create(runtime, authority, &host);
        return new NativeCreateOutcome(status, host);
    }

    public int HostDestroy(ulong runtime, ulong host) => _functions.sas_pairing_host_destroy(runtime, host);
}
