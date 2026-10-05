using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using SasPairing.Interop;

namespace SasPairing.Tests.Support;

/// <summary>One recorded call of a fake ceremony export, with what it saw in caller memory.</summary>
internal sealed record FakeCeremonyExportCall(
    string Export,
    ulong[] Arguments,
    nint Output,
    bool OutputZeroOnEntry,
    SeenBootstrap? Local = null,
    SeenBootstrap? Expected = null,
    nint IdentityPointer = 0,
    byte[]? Identity = null);

/// <summary>
/// Real unmanaged C-convention functions standing in for the nine ceremony exports, bound through the real
/// <see cref="AbiV1FunctionTable"/>, so <see cref="FfiNativeCeremonyApi"/> makes real function-pointer calls. Each
/// records its exact handles, its output record address and whether it was zero on entry, the Bootstrap views,
/// and the 32 identity bytes it read during the call; then it writes the configured output record (also on a
/// failure, to prove a failed call copies nothing) and returns the configured status.
/// </summary>
internal static unsafe class FakeCeremonyExports
{
    private static readonly List<FakeCeremonyExportCall> s_calls = [];

    internal static IReadOnlyList<FakeCeremonyExportCall> Calls => s_calls;

    internal static int Status { get; set; }

    internal static sas_pairing_action_t ActionOut { get; set; }

    internal static sas_pairing_sas_presentation_t PresentationOut { get; set; }

    /// <summary>An image exporting all 25 symbols: version 1, the lifecycle and network fakes, and these nine ceremony fakes.</summary>
    internal static FakeImage Image()
    {
        FakeImage network = FakeNetworkExports.Image();
        Dictionary<string, nint> exports = AbiV1Exports.Names.ToDictionary(n => n, n => network.TryGetExport(n, out nint address) ? address : 0);
        exports["sas_pairing_connection_start_initiator"] = (nint)(delegate* unmanaged[Cdecl]<ulong, ulong, ulong, sas_pairing_bootstrap_view_t*, sas_pairing_bootstrap_view_t*, sas_pairing_action_t*, int>)&Start;
        exports["sas_pairing_run_authorize_exposure"] = (nint)(delegate* unmanaged[Cdecl]<ulong, ulong, ulong, ulong, sas_pairing_action_t*, int>)&Authorize;
        exports["sas_pairing_run_expose_key"] = (nint)(delegate* unmanaged[Cdecl]<ulong, ulong, ulong, ulong, sas_pairing_action_t*, int>)&Expose;
        exports["sas_pairing_run_presentation"] = (nint)(delegate* unmanaged[Cdecl]<ulong, ulong, ulong, ulong, sas_pairing_sas_presentation_t*, int>)&Present;
        exports["sas_pairing_run_approve_sas"] = (nint)(delegate* unmanaged[Cdecl]<ulong, ulong, ulong, ulong, byte*, sas_pairing_action_t*, int>)&Approve;
        exports["sas_pairing_run_emit_bootstrap_mac"] = (nint)(delegate* unmanaged[Cdecl]<ulong, ulong, ulong, ulong, sas_pairing_action_t*, int>)&BootstrapMac;
        exports["sas_pairing_run_reject_sas"] = (nint)(delegate* unmanaged[Cdecl]<ulong, ulong, ulong, ulong, byte*, sas_pairing_action_t*, int>)&Reject;
        exports["sas_pairing_run_cancel_sas"] = (nint)(delegate* unmanaged[Cdecl]<ulong, ulong, ulong, ulong, byte*, sas_pairing_action_t*, int>)&Cancel;
        exports["sas_pairing_run_emit_initiator_finish"] = (nint)(delegate* unmanaged[Cdecl]<ulong, ulong, ulong, ulong, sas_pairing_action_t*, int>)&Finish;
        return new FakeImage(exports);
    }

    internal static void Reset()
    {
        s_calls.Clear();
        Status = 0;
        ActionOut = default;
        PresentationOut = default;
    }

    private static bool Zero<T>(T* record)
        where T : unmanaged => !new ReadOnlySpan<byte>(record, sizeof(T)).ContainsAnyExcept((byte)0);

    private static int Acted(string export, ulong[] arguments, sas_pairing_action_t* output, SeenBootstrap? local = null, SeenBootstrap? expected = null, byte* identity = null)
    {
        s_calls.Add(new FakeCeremonyExportCall(
            export,
            arguments,
            (nint)output,
            Zero(output),
            local,
            expected,
            (nint)identity,
            identity is null ? null : new ReadOnlySpan<byte>(identity, 32).ToArray()));
        *output = ActionOut;
        return Status;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int Start(ulong runtime, ulong host, ulong connection, sas_pairing_bootstrap_view_t* local, sas_pairing_bootstrap_view_t* expected, sas_pairing_action_t* output) =>
        Acted("sas_pairing_connection_start_initiator", [runtime, host, connection], output, FakeNetworkExports.Read(local), FakeNetworkExports.Read(expected));

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int Authorize(ulong runtime, ulong host, ulong connection, ulong run, sas_pairing_action_t* output) =>
        Acted("sas_pairing_run_authorize_exposure", [runtime, host, connection, run], output);

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int Expose(ulong runtime, ulong host, ulong connection, ulong run, sas_pairing_action_t* output) =>
        Acted("sas_pairing_run_expose_key", [runtime, host, connection, run], output);

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int Present(ulong runtime, ulong host, ulong connection, ulong run, sas_pairing_sas_presentation_t* output)
    {
        s_calls.Add(new FakeCeremonyExportCall("sas_pairing_run_presentation", [runtime, host, connection, run], (nint)output, Zero(output)));
        *output = PresentationOut;
        return Status;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int Approve(ulong runtime, ulong host, ulong connection, ulong run, byte* identity, sas_pairing_action_t* output) =>
        Acted("sas_pairing_run_approve_sas", [runtime, host, connection, run], output, identity: identity);

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int BootstrapMac(ulong runtime, ulong host, ulong connection, ulong run, sas_pairing_action_t* output) =>
        Acted("sas_pairing_run_emit_bootstrap_mac", [runtime, host, connection, run], output);

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int Reject(ulong runtime, ulong host, ulong connection, ulong run, byte* identity, sas_pairing_action_t* output) =>
        Acted("sas_pairing_run_reject_sas", [runtime, host, connection, run], output, identity: identity);

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int Cancel(ulong runtime, ulong host, ulong connection, ulong run, byte* identity, sas_pairing_action_t* output) =>
        Acted("sas_pairing_run_cancel_sas", [runtime, host, connection, run], output, identity: identity);

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int Finish(ulong runtime, ulong host, ulong connection, ulong run, sas_pairing_action_t* output) =>
        Acted("sas_pairing_run_emit_initiator_finish", [runtime, host, connection, run], output);
}
