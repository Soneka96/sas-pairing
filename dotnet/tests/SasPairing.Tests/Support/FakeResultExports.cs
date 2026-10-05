using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using SasPairing.Interop;

namespace SasPairing.Tests.Support;

/// <summary>One recorded call of a fake result export, with what it saw in caller memory.</summary>
internal sealed record FakeResultExportCall(
    string Export,
    ulong[] Arguments,
    nint Output = 0,
    bool OutputZeroOnEntry = false,
    uint Field = 0,
    nint Buffer = 0,
    nuint Capacity = 0,
    nint RequiredSlot = 0,
    nuint RequiredOnEntry = 0);

/// <summary>
/// Real unmanaged C-convention functions standing in for the three result exports, bound through the real
/// <see cref="AbiV1FunctionTable"/>, so <see cref="FfiNativeResultApi"/> makes real function-pointer calls. Each
/// records its exact handles and the caller memory it saw (the info record address and whether it was zero on
/// entry; the field, buffer, capacity, and <c>size_t</c> slot of a copy); then it writes the configured outputs
/// (also on a failure, to prove a failed call is not read) and returns the configured status.
/// </summary>
internal static unsafe class FakeResultExports
{
    private static readonly List<FakeResultExportCall> s_calls = [];

    internal static IReadOnlyList<FakeResultExportCall> Calls => s_calls;

    internal static int Status { get; set; }

    internal static sas_pairing_result_info_t InfoOut { get; set; }

    /// <summary>The value a copy writes to <c>*out_required</c>.</summary>
    internal static nuint RequiredOut { get; set; }

    /// <summary>The bytes a copy writes into the caller's buffer, never more than its capacity.</summary>
    internal static byte[] CopyBytes { get; set; } = [];

    /// <summary>An image exporting all 25 symbols: the earlier fakes and these three result fakes.</summary>
    internal static FakeImage Image()
    {
        FakeImage ceremony = FakeCeremonyExports.Image();
        Dictionary<string, nint> exports = AbiV1Exports.Names.ToDictionary(n => n, n => ceremony.TryGetExport(n, out nint address) ? address : 0);
        exports["sas_pairing_result_info"] = (nint)(delegate* unmanaged[Cdecl]<ulong, ulong, sas_pairing_result_info_t*, int>)&Info;
        exports["sas_pairing_result_copy"] = (nint)(delegate* unmanaged[Cdecl]<ulong, ulong, uint, byte*, nuint, nuint*, int>)&Copy;
        exports["sas_pairing_result_destroy"] = (nint)(delegate* unmanaged[Cdecl]<ulong, ulong, int>)&Destroy;
        return new FakeImage(exports);
    }

    internal static void Reset()
    {
        s_calls.Clear();
        Status = 0;
        InfoOut = default;
        RequiredOut = 0;
        CopyBytes = [];
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int Info(ulong runtime, ulong result, sas_pairing_result_info_t* output)
    {
        bool zero = !new ReadOnlySpan<byte>(output, sizeof(sas_pairing_result_info_t)).ContainsAnyExcept((byte)0);
        s_calls.Add(new FakeResultExportCall("sas_pairing_result_info", [runtime, result], (nint)output, zero));
        *output = InfoOut;
        return Status;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int Copy(ulong runtime, ulong result, uint field, byte* buffer, nuint capacity, nuint* required)
    {
        s_calls.Add(new FakeResultExportCall("sas_pairing_result_copy", [runtime, result], Field: field, Buffer: (nint)buffer, Capacity: capacity, RequiredSlot: (nint)required, RequiredOnEntry: *required));
        *required = RequiredOut;
        int written = (int)Math.Min((nuint)CopyBytes.Length, capacity);
        CopyBytes.AsSpan(0, written).CopyTo(new Span<byte>(buffer, written));
        return Status;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int Destroy(ulong runtime, ulong result)
    {
        s_calls.Add(new FakeResultExportCall("sas_pairing_result_destroy", [runtime, result]));
        return Status;
    }
}
