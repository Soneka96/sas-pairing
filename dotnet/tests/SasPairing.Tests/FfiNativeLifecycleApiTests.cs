using System.Text.RegularExpressions;
using SasPairing.Interop;
using SasPairing.Tests.Support;

namespace SasPairing.Tests;

/// <summary>
/// The private lifecycle-native service at the real function-pointer boundary, independent of the high-level
/// wrappers: <see cref="FfiNativeLifecycleApi"/> over the real <see cref="AbiV1FunctionTable"/> bound to
/// recording unmanaged fakes. Exact arguments, output slots, statuses, and the binary scope byte range.
/// </summary>
public sealed partial class FfiNativeLifecycleApiTests
{
    private const ulong Runtime = 0x0102_0304_0506_0708;
    private const ulong Authority = 0x1112_1314_1516_1718;
    private const ulong Host = 0x2122_2324_2526_2728;

    private readonly FfiNativeLifecycleApi _api;

    public FfiNativeLifecycleApiTests()
    {
        FakeExports.Reset();
        FakeLifecycleExports.Reset();
        _api = new FfiNativeLifecycleApi(AbiV1FunctionTable.Bind(FakeLifecycleExports.Image()));
    }

    private static FakeExportCall Single(string export)
    {
        FakeExportCall call = Assert.Single(FakeLifecycleExports.Calls);
        Assert.Equal(export, call.Export);
        return call;
    }

    private static void AssertOutputSlot(nint slot, int alignment)
    {
        Assert.NotEqual(0, slot);
        Assert.Equal(0, slot % alignment);
    }

    [Fact]
    public void RuntimeCreatePassesOneZeroedAlignedSlotAndReturnsStatusAndHandleRaw()
    {
        FakeLifecycleExports.HandleOut = Runtime;

        NativeCreateOutcome created = _api.RuntimeCreate();

        Assert.Equal(new NativeCreateOutcome(0, Runtime), created);
        FakeExportCall call = Single("sas_pairing_runtime_create");
        AssertOutputSlot(Assert.Single(call.OutputSlots), sizeof(ulong));
        Assert.Equal([0ul], call.OutputValuesOnEntry);

        // The service interprets nothing: a failure status comes back raw with whatever was written.
        FakeLifecycleExports.Status = AbiV1Constants.SAS_PAIRING_ALREADY_INITIALIZED;
        FakeLifecycleExports.HandleOut = 0;
        Assert.Equal(new NativeCreateOutcome(3, 0), _api.RuntimeCreate());
        Assert.Equal(0, FakeExports.UnexpectedCalls);
    }

    [Fact]
    public void DestroyReleaseAndHostCallsPassTheExactHandles()
    {
        FakeLifecycleExports.Status = AbiV1Constants.SAS_PAIRING_OWNERSHIP_UNCERTAIN;

        Assert.Equal(104, _api.RuntimeDestroy(Runtime));
        Assert.Equal(104, _api.AuthorityRelease(Runtime, Authority));
        Assert.Equal(104, _api.HostDestroy(Runtime, Host));

        Assert.Equal(["sas_pairing_runtime_destroy", "sas_pairing_authority_release", "sas_pairing_host_destroy"], FakeLifecycleExports.Calls.Select(c => c.Export));
        Assert.Equal([Runtime], FakeLifecycleExports.Calls[0].Arguments);
        Assert.Equal([Runtime, Authority], FakeLifecycleExports.Calls[1].Arguments);
        Assert.Equal([Runtime, Host], FakeLifecycleExports.Calls[2].Arguments);
        Assert.Equal(0, FakeExports.UnexpectedCalls);
    }

    [Fact]
    public void HostCreatePassesRuntimeAuthorityAndOneZeroedAlignedSlot()
    {
        FakeLifecycleExports.HandleOut = Host;

        Assert.Equal(new NativeCreateOutcome(0, Host), _api.HostCreate(Runtime, Authority));

        FakeExportCall call = Single("sas_pairing_host_create");
        Assert.Equal([Runtime, Authority], call.Arguments);
        AssertOutputSlot(Assert.Single(call.OutputSlots), sizeof(ulong));
        Assert.Equal([0ul], call.OutputValuesOnEntry);
    }

    [Fact]
    public void AuthorityStatusPassesTwoDistinctAlignedSlotsAndReturnsTheRawOutputs()
    {
        FakeLifecycleExports.StateOut = 77;
        FakeLifecycleExports.RemainingOut = uint.MaxValue;

        Assert.Equal(new NativeAuthorityStatusOutcome(0, 77, uint.MaxValue), _api.AuthorityStatus(Runtime, Authority));

        FakeExportCall call = Single("sas_pairing_authority_status");
        Assert.Equal([Runtime, Authority], call.Arguments);
        Assert.Equal(2, call.OutputSlots.Length);
        AssertOutputSlot(call.OutputSlots[0], sizeof(uint));
        AssertOutputSlot(call.OutputSlots[1], sizeof(uint));
        Assert.True(Math.Abs(call.OutputSlots[0] - call.OutputSlots[1]) >= sizeof(uint), "the two output slots must not overlap");
        Assert.Equal([0ul, 0ul], call.OutputValuesOnEntry); // INVALID and 0 before the call
    }

    [Fact]
    public unsafe void ANonEmptyScopeIsTheExactSpanBytesAndLengthPinnedInPlace()
    {
        byte[] buffer = [0xEE, 0x00, 0x80, 0xFF, 0x00, 0x41, 0xEE];
        FakeLifecycleExports.HandleOut = Authority;
        NativeCreateOutcome registered;
        nint expectedPointer;
        fixed (byte* start = &buffer[1])
        {
            expectedPointer = (nint)start;
            registered = _api.AuthorityRegister(Runtime, buffer.AsSpan(1, 5));
        }

        Assert.Equal(new NativeCreateOutcome(0, Authority), registered);
        FakeExportCall call = Single("sas_pairing_authority_register");
        Assert.Equal([Runtime], call.Arguments);
        Assert.Equal(5u, call.ScopeLength);
        Assert.Equal(expectedPointer, call.ScopePointer); // the caller's own bytes: no copy, no conversion
        Assert.Equal([0x00, 0x80, 0xFF, 0x00, 0x41], call.ScopeBytes);
        AssertOutputSlot(Assert.Single(call.OutputSlots), sizeof(ulong));
        Assert.Equal([0ul], call.OutputValuesOnEntry);

        // The scope range never overlaps the output slot (the native library would refuse that).
        Assert.True(call.OutputSlots[0] + sizeof(ulong) <= call.ScopePointer || call.ScopePointer + (nint)call.ScopeLength <= call.OutputSlots[0]);
    }

    [Fact]
    public void AnEmptyScopeIsANullPointerWithLengthZero()
    {
        FakeLifecycleExports.Status = AbiV1Constants.SAS_PAIRING_INVALID_SCOPE;
        byte[] buffer = [0x01, 0x02];

        Assert.Equal(new NativeCreateOutcome(100, 0), _api.AuthorityRegister(Runtime, []));
        Assert.Equal(new NativeCreateOutcome(100, 0), _api.AuthorityRegister(Runtime, buffer.AsSpan(1, 0)));

        Assert.All(FakeLifecycleExports.Calls, call =>
        {
            Assert.Equal(0, call.ScopePointer);
            Assert.Equal(0u, call.ScopeLength);
            Assert.Null(call.ScopeBytes);
        });
    }

    [Fact]
    public void TheServiceCallsExactlyTheSevenLifecycleExportsAndNothingElse()
    {
        string code = ProductionSource.Code("Interop/FfiNativeLifecycleApi.cs");
        string[] used = [.. TableField().Matches(code).Select(m => m.Value).Distinct().Order(StringComparer.Ordinal)];
        Assert.Equal(
            ["sas_pairing_authority_register", "sas_pairing_authority_release", "sas_pairing_authority_status", "sas_pairing_host_create", "sas_pairing_host_destroy", "sas_pairing_runtime_create", "sas_pairing_runtime_destroy"],
            used);
        Assert.Equal(7, typeof(INativeLifecycleApi).GetMethods().Length);

        // No wrapper outside the services calls an export; the three uses of the function table outside Interop/
        // build the production lifecycle, network, and ceremony services over the one process binding.
        foreach ((string file, string other) in ProductionSource.AllCode().Where(f => !f.File.StartsWith("Interop/", StringComparison.Ordinal)))
        {
            Assert.DoesNotMatch(TableField(), other);
            int uses = other.Split("Functions").Length - 1;
            Assert.Equal(file == "NativeProcessContext.cs" ? 3 : 0, uses);
        }

        Assert.Contains("new FfiNativeLifecycleApi(abi.Functions)", ProductionSource.Code("NativeProcessContext.cs"), StringComparison.Ordinal);
    }

    [GeneratedRegex(@"(?<=_functions\.)sas_pairing_\w+|(?<![""\w])sas_pairing_[a-z_]+(?=\()")]
    private static partial Regex TableField();
}
