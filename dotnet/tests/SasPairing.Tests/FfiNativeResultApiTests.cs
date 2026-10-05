using System.Reflection;
using System.Text.RegularExpressions;
using SasPairing.Interop;
using SasPairing.Tests.Support;

namespace SasPairing.Tests;

/// <summary>
/// The private result-native service at the real function-pointer boundary, independent of the high-level
/// result: <see cref="FfiNativeResultApi"/> over the real <see cref="AbiV1FunctionTable"/> bound to recording
/// unmanaged fakes. Exact handles and field selectors, a zeroed aligned info record copied only on OK, a copy
/// buffer of exactly the requested capacity (<c>NULL</c> for 0) with a writable <c>size_t</c> slot, no byte read
/// on a failure or past the capacity, and exactly one destroy.
/// </summary>
public sealed partial class FfiNativeResultApiTests
{
    private const ulong Runtime = 0x0102_0304_0506_0708;
    private const ulong Result = 0x5152_5354_5556_5758;

    private readonly FfiNativeResultApi _api;

    public FfiNativeResultApiTests()
    {
        FakeExports.Reset();
        FakeLifecycleExports.Reset();
        FakeNetworkExports.Reset();
        FakeCeremonyExports.Reset();
        FakeResultExports.Reset();
        _api = new FfiNativeResultApi(AbiV1FunctionTable.Bind(FakeResultExports.Image()));
    }

    private static unsafe sas_pairing_result_info_t Info()
    {
        sas_pairing_result_info_t info = new()
        {
            peer_role = 2,
            profile_version = 0x0001_0002,
            request_id_len = 16,
            peer_bootstrap_len = 126,
            shared_context_len = 0,
            profile_identifier_len = 38,
        };
        for (int i = 0; i < 32; i++)
        {
            info.ceremony_identity[i] = (byte)(0xE0 ^ i);
        }

        return info;
    }

    [Fact]
    public void InfoPassesTheExactHandlesAndOneZeroedAlignedRecordAndCopiesItOnOk()
    {
        FakeResultExports.InfoOut = Info();

        NativeResultInfoOutcome outcome = _api.ResultInfo(Runtime, Result);

        FakeResultExportCall call = Assert.Single(FakeResultExports.Calls);
        Assert.Equal("sas_pairing_result_info", call.Export);
        Assert.Equal([Runtime, Result], call.Arguments);
        Assert.NotEqual(0, call.Output);
        Assert.Equal(0, call.Output % 4);
        Assert.True(call.OutputZeroOnEntry);

        // Copied raw on OK: nothing is interpreted (an impossible role or length is passed on unchanged).
        Assert.Equal(0, outcome.Status);
        NativeResultInfoRecord info = outcome.Info!;
        Assert.Equal([.. Enumerable.Range(0, 32).Select(i => (byte)(0xE0 ^ i))], info.CeremonyIdentity);
        Assert.Equal((2u, 0x0001_0002u, 16u, 126u, 0u, 38u), (info.PeerRole, info.ProfileVersion, info.RequestIdLength, info.PeerBootstrapLength, info.SharedContextLength, info.ProfileIdentifierLength));
        Assert.Equal(0, FakeExports.UnexpectedCalls);
    }

    [Theory]
    [InlineData(AbiV1Constants.SAS_PAIRING_INVALID_ARGUMENT)]
    [InlineData(AbiV1Constants.SAS_PAIRING_INVALID_HANDLE)]
    [InlineData(AbiV1Constants.SAS_PAIRING_FATAL)]
    [InlineData(777)]
    public void AFailedInfoCopiesNothing(int status)
    {
        FakeResultExports.InfoOut = Info();
        FakeResultExports.Status = status;

        NativeResultInfoOutcome outcome = _api.ResultInfo(Runtime, Result);

        Assert.Equal(status, outcome.Status);
        Assert.Null(outcome.Info);
    }

    [Theory]
    [InlineData(AbiV1Constants.SAS_PAIRING_RESULT_FIELD_REQUEST_ID)]
    [InlineData(AbiV1Constants.SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_PEER_BOOTSTRAP)]
    [InlineData(AbiV1Constants.SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_SHARED_CONTEXT)]
    [InlineData(AbiV1Constants.SAS_PAIRING_RESULT_FIELD_PROFILE_IDENTIFIER)]
    public void ACopyPassesTheExactHandlesFieldAndCapacityAndAWritableRequiredSlot(uint field)
    {
        byte[] bytes = [0x00, 0x80, 0xFF, 0x00, 0x41];
        FakeResultExports.CopyBytes = bytes;
        FakeResultExports.RequiredOut = 5;

        NativeResultCopyOutcome outcome = _api.ResultCopy(Runtime, Result, field, 5);

        FakeResultExportCall call = Assert.Single(FakeResultExports.Calls);
        Assert.Equal(("sas_pairing_result_copy", field, (nuint)5), (call.Export, call.Field, call.Capacity));
        Assert.Equal([Runtime, Result], call.Arguments);
        Assert.NotEqual(0, call.Buffer);
        Assert.NotEqual(0, call.RequiredSlot);
        Assert.Equal(0, call.RequiredSlot % IntPtr.Size);
        Assert.Equal((nuint)0, call.RequiredOnEntry);

        // The slot is not inside the buffer, and the buffer has exactly the capacity: no terminator byte.
        Assert.True(call.RequiredSlot + IntPtr.Size <= call.Buffer || call.RequiredSlot >= call.Buffer + 5);
        Assert.Equal((0, (nuint)5), (outcome.Status, outcome.Required));
        Assert.Equal(bytes, outcome.Bytes);
        Assert.NotSame(bytes, outcome.Bytes);
    }

    [Fact]
    public void AZeroCapacityCopyPassesANullBufferAndReturnsNoBytes()
    {
        NativeResultCopyOutcome outcome = _api.ResultCopy(Runtime, Result, AbiV1Constants.SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_SHARED_CONTEXT, 0);

        FakeResultExportCall call = Assert.Single(FakeResultExports.Calls);
        Assert.Equal((0, (nuint)0), (call.Buffer, call.Capacity));
        Assert.NotEqual(0, call.RequiredSlot);
        Assert.Equal((0, (nuint)0), (outcome.Status, outcome.Required));
        Assert.Empty(outcome.Bytes!);
    }

    [Theory]
    [InlineData(3, 3)]
    [InlineData(9, 6)]
    [InlineData(1000, 6)]
    public void AnOkCopyNeverReturnsMoreThanTheCapacityOrTheReportedLength(int required, int returned)
    {
        FakeResultExports.CopyBytes = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        FakeResultExports.RequiredOut = (nuint)required;

        NativeResultCopyOutcome outcome = _api.ResultCopy(Runtime, Result, AbiV1Constants.SAS_PAIRING_RESULT_FIELD_REQUEST_ID, 6);

        // The raw required value is passed on for the wrapper to judge; the bytes stop at min(required, capacity).
        Assert.Equal((nuint)required, outcome.Required);
        Assert.Equal([.. Enumerable.Range(1, returned).Select(i => (byte)i)], outcome.Bytes!);
    }

    [Theory]
    [InlineData(AbiV1Constants.SAS_PAIRING_BUFFER_TOO_SMALL)]
    [InlineData(AbiV1Constants.SAS_PAIRING_INVALID_HANDLE)]
    [InlineData(AbiV1Constants.SAS_PAIRING_INVALID_ARGUMENT)]
    [InlineData(AbiV1Constants.SAS_PAIRING_FATAL)]
    public void AFailedCopyReturnsNoBytesButKeepsTheRequiredValue(int status)
    {
        FakeResultExports.Status = status;
        FakeResultExports.CopyBytes = [9, 9, 9, 9];
        FakeResultExports.RequiredOut = 12;

        NativeResultCopyOutcome outcome = _api.ResultCopy(Runtime, Result, AbiV1Constants.SAS_PAIRING_RESULT_FIELD_PROFILE_IDENTIFIER, 4);

        Assert.Equal((status, (nuint)12), (outcome.Status, outcome.Required));
        Assert.Null(outcome.Bytes);
    }

    [Fact]
    public void ANegativeCapacityIsRefusedBeforeTheCall()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => _api.ResultCopy(Runtime, Result, 1, -1));
        Assert.Empty(FakeResultExports.Calls);
    }

    [Theory]
    [InlineData(AbiV1Constants.SAS_PAIRING_OK)]
    [InlineData(AbiV1Constants.SAS_PAIRING_INVALID_HANDLE)]
    [InlineData(AbiV1Constants.SAS_PAIRING_FATAL)]
    public void DestroyIsOneCallWithTheExactHandlesAndItsRawStatus(int status)
    {
        FakeResultExports.Status = status;

        Assert.Equal(status, _api.ResultDestroy(Runtime, Result));

        FakeResultExportCall call = Assert.Single(FakeResultExports.Calls);
        Assert.Equal("sas_pairing_result_destroy", call.Export);
        Assert.Equal([Runtime, Result], call.Arguments);
    }

    [Fact]
    public void TheServiceCallsExactlyTheThreeResultExportsAndNoPointerEscapes()
    {
        string code = ProductionSource.Code("Interop/FfiNativeResultApi.cs");
        string[] used = [.. TableField().Matches(code).Select(m => m.Value).Distinct().Order(StringComparer.Ordinal)];
        Assert.Equal(["sas_pairing_result_copy", "sas_pairing_result_destroy", "sas_pairing_result_info"], used);
        Assert.Equal(["ResultCopy", "ResultDestroy", "ResultInfo"], typeof(INativeResultApi).GetMethods().Select(m => m.Name).Order(StringComparer.Ordinal));
        Assert.Contains("new FfiNativeResultApi(abi.Functions)", ProductionSource.Code("NativeProcessContext.cs"), StringComparison.Ordinal);

        // The raw outcomes carry managed copies and integers only: no pointer, native record, or address.
        foreach (Type type in new[] { typeof(NativeResultInfoRecord), typeof(NativeResultInfoOutcome), typeof(NativeResultCopyOutcome) })
        {
            foreach (FieldInfo field in type.GetFields(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public))
            {
                Assert.False(field.FieldType.IsPointer || field.FieldType == typeof(nint) || field.FieldType.Name.StartsWith("sas_pairing_", StringComparison.Ordinal), $"{type.Name}.{field.Name}");
            }
        }

        Assert.All(typeof(INativeResultApi).GetMethods(), m => Assert.DoesNotContain(m.GetParameters(), p => p.ParameterType.IsPointer));
    }

    [GeneratedRegex(@"(?<=_functions\.)sas_pairing_\w+")]
    private static partial Regex TableField();
}
