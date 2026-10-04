using System.Runtime.CompilerServices;

namespace SasPairing.Interop;

/// <summary>
/// The 25 frozen native ABI v1 exports (P7-D-013 item 2, manifest section 2), in manifest order. The one list
/// of required symbols: the loader preflights exactly these names, and the tests check it against the
/// manifest, the header, and the fields of <see cref="AbiV1FunctionTable"/>.
/// </summary>
internal static class AbiV1Exports
{
    internal static IReadOnlyList<string> Names { get; } =
    [
        "sas_pairing_abi_version",
        "sas_pairing_runtime_create",
        "sas_pairing_runtime_destroy",
        "sas_pairing_authority_register",
        "sas_pairing_authority_release",
        "sas_pairing_authority_status",
        "sas_pairing_host_create",
        "sas_pairing_host_destroy",
        "sas_pairing_host_attach_windows_listener",
        "sas_pairing_host_detach_listener",
        "sas_pairing_host_drive",
        "sas_pairing_host_recheck_after_resume",
        "sas_pairing_connection_close",
        "sas_pairing_result_info",
        "sas_pairing_result_copy",
        "sas_pairing_result_destroy",
        "sas_pairing_connection_start_initiator",
        "sas_pairing_run_authorize_exposure",
        "sas_pairing_run_expose_key",
        "sas_pairing_run_presentation",
        "sas_pairing_run_approve_sas",
        "sas_pairing_run_emit_bootstrap_mac",
        "sas_pairing_run_reject_sas",
        "sas_pairing_run_cancel_sas",
        "sas_pairing_run_emit_initiator_finish",
    ];
}

/// <summary>An export could not be bound after the symbol preflight passed.</summary>
internal sealed class AbiV1BindingException(string message) : Exception(message);

/// <summary>
/// The private ABI v1 function table: one unmanaged C function pointer per frozen export, each field named
/// exactly as its export and resolved by that name (<c>nameof</c>), so a field and its symbol cannot drift
/// apart. Built only by the loader, only after all 25 symbols were found, over an image that stays loaded for
/// the rest of the process. Never public: no function pointer, raw handle, or native record leaves the
/// assembly.
/// </summary>
/// <remarks>
/// Type mapping (P9-D-001): <c>sas_pairing_status_t</c> (<c>int32_t</c>) is <c>int</c>; <c>uint32_t</c> and
/// every <c>uint32_t</c> namespace is <c>uint</c>; the six <c>uint64_t</c> handles are <c>ulong</c>;
/// <c>size_t</c> and <c>uintptr_t</c> (<c>sas_pairing_socket_t</c>) are the pointer-sized <c>nuint</c>;
/// <c>uint8_t</c> is <c>byte</c>; every pointer is an unmanaged pointer (C <c>const</c> is not expressible and
/// is kept as a calling rule). The calling convention is the platform C convention (<c>Cdecl</c>; on Windows
/// x64 the one Microsoft x64 convention). The tests compare every signature with the header declaration.
/// </remarks>
// UNSAFE: unmanaged function pointers are the exact, allocation-free representation of the C exports.
internal sealed unsafe class AbiV1FunctionTable
{
    // Lifecycle.
    internal readonly delegate* unmanaged[Cdecl]<uint> sas_pairing_abi_version;
    internal readonly delegate* unmanaged[Cdecl]<ulong*, int> sas_pairing_runtime_create;
    internal readonly delegate* unmanaged[Cdecl]<ulong, int> sas_pairing_runtime_destroy;
    internal readonly delegate* unmanaged[Cdecl]<ulong, byte*, nuint, ulong*, int> sas_pairing_authority_register;
    internal readonly delegate* unmanaged[Cdecl]<ulong, ulong, int> sas_pairing_authority_release;
    internal readonly delegate* unmanaged[Cdecl]<ulong, ulong, uint*, uint*, int> sas_pairing_authority_status;
    internal readonly delegate* unmanaged[Cdecl]<ulong, ulong, ulong*, int> sas_pairing_host_create;
    internal readonly delegate* unmanaged[Cdecl]<ulong, ulong, int> sas_pairing_host_destroy;

    // Network.
    internal readonly delegate* unmanaged[Cdecl]<ulong, ulong, nuint*, sas_pairing_bootstrap_view_t*, sas_pairing_bootstrap_view_t*, int> sas_pairing_host_attach_windows_listener;
    internal readonly delegate* unmanaged[Cdecl]<ulong, ulong, int> sas_pairing_host_detach_listener;
    internal readonly delegate* unmanaged[Cdecl]<ulong, ulong, sas_pairing_event_t*, nuint, nuint*, int*, int> sas_pairing_host_drive;
    internal readonly delegate* unmanaged[Cdecl]<ulong, ulong, sas_pairing_event_t*, nuint, nuint*, int*, int> sas_pairing_host_recheck_after_resume;
    internal readonly delegate* unmanaged[Cdecl]<ulong, ulong, ulong, int> sas_pairing_connection_close;

    // Results.
    internal readonly delegate* unmanaged[Cdecl]<ulong, ulong, sas_pairing_result_info_t*, int> sas_pairing_result_info;
    internal readonly delegate* unmanaged[Cdecl]<ulong, ulong, uint, byte*, nuint, nuint*, int> sas_pairing_result_copy;
    internal readonly delegate* unmanaged[Cdecl]<ulong, ulong, int> sas_pairing_result_destroy;

    // Trusted local ceremony control.
    internal readonly delegate* unmanaged[Cdecl]<ulong, ulong, ulong, sas_pairing_bootstrap_view_t*, sas_pairing_bootstrap_view_t*, sas_pairing_action_t*, int> sas_pairing_connection_start_initiator;
    internal readonly delegate* unmanaged[Cdecl]<ulong, ulong, ulong, ulong, sas_pairing_action_t*, int> sas_pairing_run_authorize_exposure;
    internal readonly delegate* unmanaged[Cdecl]<ulong, ulong, ulong, ulong, sas_pairing_action_t*, int> sas_pairing_run_expose_key;
    internal readonly delegate* unmanaged[Cdecl]<ulong, ulong, ulong, ulong, sas_pairing_sas_presentation_t*, int> sas_pairing_run_presentation;
    internal readonly delegate* unmanaged[Cdecl]<ulong, ulong, ulong, ulong, byte*, sas_pairing_action_t*, int> sas_pairing_run_approve_sas;
    internal readonly delegate* unmanaged[Cdecl]<ulong, ulong, ulong, ulong, sas_pairing_action_t*, int> sas_pairing_run_emit_bootstrap_mac;
    internal readonly delegate* unmanaged[Cdecl]<ulong, ulong, ulong, ulong, byte*, sas_pairing_action_t*, int> sas_pairing_run_reject_sas;
    internal readonly delegate* unmanaged[Cdecl]<ulong, ulong, ulong, ulong, byte*, sas_pairing_action_t*, int> sas_pairing_run_cancel_sas;
    internal readonly delegate* unmanaged[Cdecl]<ulong, ulong, ulong, ulong, sas_pairing_action_t*, int> sas_pairing_run_emit_initiator_finish;

    private AbiV1FunctionTable(INativeImage image)
    {
        // UNSAFE: each address comes from the loaded image's export of exactly this name, and the cast only
        // assigns the frozen signature to it; nothing is called here.
        sas_pairing_abi_version = (delegate* unmanaged[Cdecl]<uint>)Resolve(image, nameof(sas_pairing_abi_version));
        sas_pairing_runtime_create = (delegate* unmanaged[Cdecl]<ulong*, int>)Resolve(image, nameof(sas_pairing_runtime_create));
        sas_pairing_runtime_destroy = (delegate* unmanaged[Cdecl]<ulong, int>)Resolve(image, nameof(sas_pairing_runtime_destroy));
        sas_pairing_authority_register = (delegate* unmanaged[Cdecl]<ulong, byte*, nuint, ulong*, int>)Resolve(image, nameof(sas_pairing_authority_register));
        sas_pairing_authority_release = (delegate* unmanaged[Cdecl]<ulong, ulong, int>)Resolve(image, nameof(sas_pairing_authority_release));
        sas_pairing_authority_status = (delegate* unmanaged[Cdecl]<ulong, ulong, uint*, uint*, int>)Resolve(image, nameof(sas_pairing_authority_status));
        sas_pairing_host_create = (delegate* unmanaged[Cdecl]<ulong, ulong, ulong*, int>)Resolve(image, nameof(sas_pairing_host_create));
        sas_pairing_host_destroy = (delegate* unmanaged[Cdecl]<ulong, ulong, int>)Resolve(image, nameof(sas_pairing_host_destroy));
        sas_pairing_host_attach_windows_listener = (delegate* unmanaged[Cdecl]<ulong, ulong, nuint*, sas_pairing_bootstrap_view_t*, sas_pairing_bootstrap_view_t*, int>)Resolve(image, nameof(sas_pairing_host_attach_windows_listener));
        sas_pairing_host_detach_listener = (delegate* unmanaged[Cdecl]<ulong, ulong, int>)Resolve(image, nameof(sas_pairing_host_detach_listener));
        sas_pairing_host_drive = (delegate* unmanaged[Cdecl]<ulong, ulong, sas_pairing_event_t*, nuint, nuint*, int*, int>)Resolve(image, nameof(sas_pairing_host_drive));
        sas_pairing_host_recheck_after_resume = (delegate* unmanaged[Cdecl]<ulong, ulong, sas_pairing_event_t*, nuint, nuint*, int*, int>)Resolve(image, nameof(sas_pairing_host_recheck_after_resume));
        sas_pairing_connection_close = (delegate* unmanaged[Cdecl]<ulong, ulong, ulong, int>)Resolve(image, nameof(sas_pairing_connection_close));
        sas_pairing_result_info = (delegate* unmanaged[Cdecl]<ulong, ulong, sas_pairing_result_info_t*, int>)Resolve(image, nameof(sas_pairing_result_info));
        sas_pairing_result_copy = (delegate* unmanaged[Cdecl]<ulong, ulong, uint, byte*, nuint, nuint*, int>)Resolve(image, nameof(sas_pairing_result_copy));
        sas_pairing_result_destroy = (delegate* unmanaged[Cdecl]<ulong, ulong, int>)Resolve(image, nameof(sas_pairing_result_destroy));
        sas_pairing_connection_start_initiator = (delegate* unmanaged[Cdecl]<ulong, ulong, ulong, sas_pairing_bootstrap_view_t*, sas_pairing_bootstrap_view_t*, sas_pairing_action_t*, int>)Resolve(image, nameof(sas_pairing_connection_start_initiator));
        sas_pairing_run_authorize_exposure = (delegate* unmanaged[Cdecl]<ulong, ulong, ulong, ulong, sas_pairing_action_t*, int>)Resolve(image, nameof(sas_pairing_run_authorize_exposure));
        sas_pairing_run_expose_key = (delegate* unmanaged[Cdecl]<ulong, ulong, ulong, ulong, sas_pairing_action_t*, int>)Resolve(image, nameof(sas_pairing_run_expose_key));
        sas_pairing_run_presentation = (delegate* unmanaged[Cdecl]<ulong, ulong, ulong, ulong, sas_pairing_sas_presentation_t*, int>)Resolve(image, nameof(sas_pairing_run_presentation));
        sas_pairing_run_approve_sas = (delegate* unmanaged[Cdecl]<ulong, ulong, ulong, ulong, byte*, sas_pairing_action_t*, int>)Resolve(image, nameof(sas_pairing_run_approve_sas));
        sas_pairing_run_emit_bootstrap_mac = (delegate* unmanaged[Cdecl]<ulong, ulong, ulong, ulong, sas_pairing_action_t*, int>)Resolve(image, nameof(sas_pairing_run_emit_bootstrap_mac));
        sas_pairing_run_reject_sas = (delegate* unmanaged[Cdecl]<ulong, ulong, ulong, ulong, byte*, sas_pairing_action_t*, int>)Resolve(image, nameof(sas_pairing_run_reject_sas));
        sas_pairing_run_cancel_sas = (delegate* unmanaged[Cdecl]<ulong, ulong, ulong, ulong, byte*, sas_pairing_action_t*, int>)Resolve(image, nameof(sas_pairing_run_cancel_sas));
        sas_pairing_run_emit_initiator_finish = (delegate* unmanaged[Cdecl]<ulong, ulong, ulong, ulong, sas_pairing_action_t*, int>)Resolve(image, nameof(sas_pairing_run_emit_initiator_finish));
    }

    /// <summary>Binds all 25 exports of <paramref name="image"/>; throws <see cref="AbiV1BindingException"/>.</summary>
    internal static AbiV1FunctionTable Bind(INativeImage image) => new(image);

    /// <summary>
    /// Calls <c>sas_pairing_abi_version()</c>, the only native call made during initialization. It takes no
    /// argument, touches no caller memory, and is a constant query in every native state.
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    internal uint QueryAbiVersion() => sas_pairing_abi_version();

    private static nint Resolve(INativeImage image, string export)
    {
        if (!image.TryGetExport(export, out nint address) || address == 0)
        {
            throw new AbiV1BindingException($"The export {export} could not be bound.");
        }

        return address;
    }
}
