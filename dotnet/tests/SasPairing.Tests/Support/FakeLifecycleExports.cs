using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using SasPairing.Interop;

namespace SasPairing.Tests.Support;

/// <summary>One recorded call of a fake lifecycle export: its scalar arguments and what it saw in caller memory.</summary>
internal sealed record FakeExportCall(
    string Export,
    ulong[] Arguments,
    nint[] OutputSlots,
    ulong[] OutputValuesOnEntry,
    nint ScopePointer,
    nuint ScopeLength,
    byte[]? ScopeBytes);

/// <summary>
/// Real unmanaged C-convention functions standing in for the seven lifecycle exports, bound through the real
/// <see cref="AbiV1FunctionTable"/>, so <see cref="FfiNativeLifecycleApi"/> makes real function-pointer calls.
/// Each records its exact arguments, the output slot addresses and their values on entry, and the scope
/// bytes read during the call, then writes the configured outputs and returns the configured status.
/// </summary>
internal static unsafe class FakeLifecycleExports
{
    private static readonly List<FakeExportCall> s_calls = [];

    internal static IReadOnlyList<FakeExportCall> Calls => s_calls;

    internal static int Status { get; set; }

    internal static ulong HandleOut { get; set; }

    internal static uint StateOut { get; set; }

    internal static uint RemainingOut { get; set; }

    /// <summary>An image exporting all 25 symbols: version 1, the seven recording lifecycle fakes, and the rest unexpected.</summary>
    internal static FakeImage Image()
    {
        FakeImage image = FakeImage.Complete(FakeExports.Version1);
        Dictionary<string, nint> exports = AbiV1Exports.Names.ToDictionary(n => n, n => image.TryGetExport(n, out nint address) ? address : 0);
        exports["sas_pairing_runtime_create"] = (nint)(delegate* unmanaged[Cdecl]<ulong*, int>)&RuntimeCreate;
        exports["sas_pairing_runtime_destroy"] = (nint)(delegate* unmanaged[Cdecl]<ulong, int>)&RuntimeDestroy;
        exports["sas_pairing_authority_register"] = (nint)(delegate* unmanaged[Cdecl]<ulong, byte*, nuint, ulong*, int>)&AuthorityRegister;
        exports["sas_pairing_authority_release"] = (nint)(delegate* unmanaged[Cdecl]<ulong, ulong, int>)&AuthorityRelease;
        exports["sas_pairing_authority_status"] = (nint)(delegate* unmanaged[Cdecl]<ulong, ulong, uint*, uint*, int>)&AuthorityStatus;
        exports["sas_pairing_host_create"] = (nint)(delegate* unmanaged[Cdecl]<ulong, ulong, ulong*, int>)&HostCreate;
        exports["sas_pairing_host_destroy"] = (nint)(delegate* unmanaged[Cdecl]<ulong, ulong, int>)&HostDestroy;
        return new FakeImage(exports);
    }

    internal static void Reset()
    {
        s_calls.Clear();
        Status = 0;
        HandleOut = 0;
        StateOut = 0;
        RemainingOut = 0;
    }

    private static void Record(string export, ulong[] arguments, nint[] slots, ulong[] onEntry, nint scope = 0, nuint length = 0, byte[]? bytes = null) =>
        s_calls.Add(new FakeExportCall(export, arguments, slots, onEntry, scope, length, bytes));

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int RuntimeCreate(ulong* outRuntime)
    {
        Record("sas_pairing_runtime_create", [], [(nint)outRuntime], [*outRuntime]);
        *outRuntime = HandleOut;
        return Status;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int RuntimeDestroy(ulong runtime)
    {
        Record("sas_pairing_runtime_destroy", [runtime], [], []);
        return Status;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int AuthorityRegister(ulong runtime, byte* scope, nuint scopeLength, ulong* outAuthority)
    {
        // The bytes are read during the call only, exactly as the native core copies them.
        byte[]? bytes = scope is null ? null : new ReadOnlySpan<byte>(scope, checked((int)scopeLength)).ToArray();
        Record("sas_pairing_authority_register", [runtime], [(nint)outAuthority], [*outAuthority], (nint)scope, scopeLength, bytes);
        *outAuthority = HandleOut;
        return Status;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int AuthorityRelease(ulong runtime, ulong authority)
    {
        Record("sas_pairing_authority_release", [runtime, authority], [], []);
        return Status;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int AuthorityStatus(ulong runtime, ulong authority, uint* outState, uint* outRemaining)
    {
        Record("sas_pairing_authority_status", [runtime, authority], [(nint)outState, (nint)outRemaining], [*outState, *outRemaining]);
        *outState = StateOut;
        *outRemaining = RemainingOut;
        return Status;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int HostCreate(ulong runtime, ulong authority, ulong* outHost)
    {
        Record("sas_pairing_host_create", [runtime, authority], [(nint)outHost], [*outHost]);
        *outHost = HandleOut;
        return Status;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int HostDestroy(ulong runtime, ulong host)
    {
        Record("sas_pairing_host_destroy", [runtime, host], [], []);
        return Status;
    }
}
