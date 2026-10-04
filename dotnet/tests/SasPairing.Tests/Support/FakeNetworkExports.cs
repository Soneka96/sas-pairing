using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using SasPairing.Interop;

namespace SasPairing.Tests.Support;

/// <summary>One Bootstrap view as the fake attach export read it during the call: per field, the pointer, the length, and the bytes.</summary>
internal sealed record SeenBootstrap(nint ViewAddress, (nint Data, nuint Length, byte[]? Bytes)[] Fields);

/// <summary>One recorded call of a fake network export, with what it saw in caller memory.</summary>
internal sealed record FakeNetworkExportCall(
    string Export,
    ulong[] Arguments,
    nint SocketSlot = 0,
    nuint SocketOnEntry = 0,
    SeenBootstrap? Local = null,
    SeenBootstrap? Expected = null,
    nint Events = 0,
    nuint Capacity = 0,
    nint CountSlot = 0,
    nint FailureSlot = 0,
    nuint CountOnEntry = 0,
    int FailureOnEntry = 0,
    bool EventsZeroOnEntry = false);

/// <summary>
/// Real unmanaged C-convention functions standing in for the five network exports, bound through the real
/// <see cref="AbiV1FunctionTable"/>, so <see cref="FfiNativeNetworkApi"/> makes real function-pointer calls. Each
/// records its exact arguments and what it read in caller memory during the call, then writes the configured
/// outputs and returns the configured status.
/// </summary>
internal static unsafe class FakeNetworkExports
{
    private static readonly List<FakeNetworkExportCall> s_calls = [];

    internal static IReadOnlyList<FakeNetworkExportCall> Calls => s_calls;

    internal static int Status { get; set; }

    internal static nuint SocketOut { get; set; }

    internal static nuint CountOut { get; set; }

    internal static int FailureOut { get; set; }

    /// <summary>The records the fake drive writes into the caller's array (at most its capacity).</summary>
    internal static List<sas_pairing_event_t> EventsOut { get; } = [];

    /// <summary>An image exporting all 25 symbols: version 1, the seven lifecycle fakes, and these five network fakes.</summary>
    internal static FakeImage Image()
    {
        FakeImage lifecycle = FakeLifecycleExports.Image();
        Dictionary<string, nint> exports = AbiV1Exports.Names.ToDictionary(n => n, n => lifecycle.TryGetExport(n, out nint address) ? address : 0);
        exports["sas_pairing_host_attach_windows_listener"] = (nint)(delegate* unmanaged[Cdecl]<ulong, ulong, nuint*, sas_pairing_bootstrap_view_t*, sas_pairing_bootstrap_view_t*, int>)&Attach;
        exports["sas_pairing_host_detach_listener"] = (nint)(delegate* unmanaged[Cdecl]<ulong, ulong, int>)&Detach;
        exports["sas_pairing_host_drive"] = (nint)(delegate* unmanaged[Cdecl]<ulong, ulong, sas_pairing_event_t*, nuint, nuint*, int*, int>)&Drive;
        exports["sas_pairing_host_recheck_after_resume"] = (nint)(delegate* unmanaged[Cdecl]<ulong, ulong, sas_pairing_event_t*, nuint, nuint*, int*, int>)&Recheck;
        exports["sas_pairing_connection_close"] = (nint)(delegate* unmanaged[Cdecl]<ulong, ulong, ulong, int>)&Close;
        return new FakeImage(exports);
    }

    internal static void Reset()
    {
        s_calls.Clear();
        Status = 0;
        SocketOut = 0;
        CountOut = 0;
        FailureOut = 0;
        EventsOut.Clear();
    }

    private static SeenBootstrap? Read(sas_pairing_bootstrap_view_t* view)
    {
        if (view is null)
        {
            return null;
        }

        static (nint, nuint, byte[]?) Field(sas_pairing_bytes_view_t field) =>
            ((nint)field.data, field.len, field.data is null ? null : new ReadOnlySpan<byte>(field.data, checked((int)field.len)).ToArray());

        return new SeenBootstrap((nint)view, [Field(view->application_identity), Field(view->key_algorithm), Field(view->public_key), Field(view->shared_context)]);
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int Attach(ulong runtime, ulong host, nuint* slot, sas_pairing_bootstrap_view_t* local, sas_pairing_bootstrap_view_t* expected)
    {
        s_calls.Add(new FakeNetworkExportCall("sas_pairing_host_attach_windows_listener", [runtime, host], (nint)slot, *slot, Read(local), Read(expected)));
        *slot = SocketOut;
        return Status;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int Detach(ulong runtime, ulong host)
    {
        s_calls.Add(new FakeNetworkExportCall("sas_pairing_host_detach_listener", [runtime, host]));
        return Status;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int Drive(ulong runtime, ulong host, sas_pairing_event_t* events, nuint capacity, nuint* count, int* failure) =>
        DriveOnce("sas_pairing_host_drive", runtime, host, events, capacity, count, failure);

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int Recheck(ulong runtime, ulong host, sas_pairing_event_t* events, nuint capacity, nuint* count, int* failure) =>
        DriveOnce("sas_pairing_host_recheck_after_resume", runtime, host, events, capacity, count, failure);

    private static int DriveOnce(string export, ulong runtime, ulong host, sas_pairing_event_t* events, nuint capacity, nuint* count, int* failure)
    {
        bool zero = !new ReadOnlySpan<byte>(events, checked((int)capacity) * sizeof(sas_pairing_event_t)).ContainsAnyExcept((byte)0);
        s_calls.Add(new FakeNetworkExportCall(export, [runtime, host], Events: (nint)events, Capacity: capacity, CountSlot: (nint)count, FailureSlot: (nint)failure, CountOnEntry: *count, FailureOnEntry: *failure, EventsZeroOnEntry: zero));
        for (int i = 0; i < EventsOut.Count && (nuint)i < capacity; i++)
        {
            events[i] = EventsOut[i];
        }

        *count = CountOut;
        *failure = FailureOut;
        return Status;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int Close(ulong runtime, ulong host, ulong connection)
    {
        s_calls.Add(new FakeNetworkExportCall("sas_pairing_connection_close", [runtime, host, connection]));
        return Status;
    }
}
