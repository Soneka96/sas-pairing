namespace SasPairing.Interop;

/// <summary>
/// The status and output handle of one native create call (<c>sas_pairing_runtime_create</c>,
/// <c>sas_pairing_authority_register</c>, <c>sas_pairing_host_create</c>). <see cref="Handle"/> means
/// something only when <see cref="Status"/> is <c>SAS_PAIRING_OK</c>.
/// </summary>
internal readonly record struct NativeCreateOutcome(int Status, ulong Handle);

/// <summary>
/// The status and both outputs of one <c>sas_pairing_authority_status</c> call: the raw
/// <c>sas_pairing_authority_state_t</c> and the remaining opportunities, meaningful only on
/// <c>SAS_PAIRING_OK</c>.
/// </summary>
internal readonly record struct NativeAuthorityStatusOutcome(int Status, uint State, uint Remaining);

/// <summary>
/// The private lifecycle-native service of P9-D-002: exactly the seven frozen ABI v1 lifecycle exports, one
/// method each, with raw statuses and raw handles. It validates nothing and interprets nothing: admission,
/// status translation, output validation, and ownership belong to the high-level wrappers and
/// <see cref="NativeProcessContext"/>. Production uses <see cref="FfiNativeLifecycleApi"/>; tests supply
/// fakes.
/// </summary>
internal interface INativeLifecycleApi
{
    /// <summary><c>sas_pairing_runtime_create(&amp;out_runtime)</c>.</summary>
    NativeCreateOutcome RuntimeCreate();

    /// <summary><c>sas_pairing_runtime_destroy(runtime)</c>.</summary>
    int RuntimeDestroy(ulong runtime);

    /// <summary>
    /// <c>sas_pairing_authority_register(runtime, scope, scope_len, &amp;out_authority)</c> with exactly the
    /// bytes and the length of <paramref name="scope"/>: binary, never text, no terminator.
    /// </summary>
    NativeCreateOutcome AuthorityRegister(ulong runtime, ReadOnlySpan<byte> scope);

    /// <summary><c>sas_pairing_authority_release(runtime, authority)</c>.</summary>
    int AuthorityRelease(ulong runtime, ulong authority);

    /// <summary><c>sas_pairing_authority_status(runtime, authority, &amp;out_state, &amp;out_remaining)</c>.</summary>
    NativeAuthorityStatusOutcome AuthorityStatus(ulong runtime, ulong authority);

    /// <summary><c>sas_pairing_host_create(runtime, authority, &amp;out_host)</c>.</summary>
    NativeCreateOutcome HostCreate(ulong runtime, ulong authority);

    /// <summary><c>sas_pairing_host_destroy(runtime, host)</c>.</summary>
    int HostDestroy(ulong runtime, ulong host);
}
