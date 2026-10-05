using System.Text.RegularExpressions;
using SasPairing.Interop;
using SasPairing.Tests.Support;

namespace SasPairing.Tests;

/// <summary>
/// The private network-native service at the real function-pointer boundary, independent of the high-level
/// wrappers: <see cref="FfiNativeNetworkApi"/> over the real <see cref="AbiV1FunctionTable"/> bound to recording
/// unmanaged fakes. Exact handles, the socket in/out slot, the Bootstrap pointers and bytes, the frozen event
/// capacity, distinct drive outputs, and records copied into managed memory.
/// </summary>
public sealed partial class FfiNativeNetworkApiTests
{
    private const ulong Runtime = 0x0102_0304_0506_0708;
    private const ulong Host = 0x2122_2324_2526_2728;
    private const ulong Connection = 0x3132_3334_3536_3738;

    private readonly FfiNativeNetworkApi _api;

    public FfiNativeNetworkApiTests()
    {
        FakeExports.Reset();
        FakeLifecycleExports.Reset();
        FakeNetworkExports.Reset();
        _api = new FfiNativeNetworkApi(AbiV1FunctionTable.Bind(FakeNetworkExports.Image()));
    }

    private static FakeNetworkExportCall Single(string export)
    {
        FakeNetworkExportCall call = Assert.Single(FakeNetworkExports.Calls);
        Assert.Equal(export, call.Export);
        return call;
    }

    [Fact]
    public void AttachPassesTheSocketInAnAlignedSlotAndReturnsTheSlotAfterTheCall()
    {
        FakeNetworkExports.SocketOut = AbiV1Constants.SAS_PAIRING_SOCKET_INVALID;
        NativeBootstrapBytes local = new([1], [2], [3], [4]);

        NativeAttachOutcome adopted = _api.AttachWindowsListener(Runtime, Host, 0xBEEF, local, null);

        Assert.Equal(new NativeAttachOutcome(0, AbiV1Constants.SAS_PAIRING_SOCKET_INVALID), adopted);
        FakeNetworkExportCall call = Single("sas_pairing_host_attach_windows_listener");
        Assert.Equal([Runtime, Host], call.Arguments);
        Assert.NotEqual(0, call.SocketSlot);
        Assert.Equal(0, call.SocketSlot % IntPtr.Size);
        Assert.Equal((nuint)0xBEEF, call.SocketOnEntry);
        Assert.Null(call.Expected);
        Assert.NotNull(call.Local);
        Assert.Equal(0, call.Local.ViewAddress % IntPtr.Size);

        // The raw slot value comes back uninterpreted, whatever it is.
        FakeNetworkExports.Status = AbiV1Constants.SAS_PAIRING_INVALID_BOOTSTRAP;
        FakeNetworkExports.SocketOut = 0xBEEF;
        Assert.Equal(new NativeAttachOutcome(203, 0xBEEF), _api.AttachWindowsListener(Runtime, Host, 0xBEEF, local, null));
        FakeNetworkExports.SocketOut = 0x7777;
        Assert.Equal(new NativeAttachOutcome(203, 0x7777), _api.AttachWindowsListener(Runtime, Host, 0xBEEF, local, null));
        Assert.Equal(0, FakeExports.UnexpectedCalls);
    }

    [Fact]
    public void BootstrapFieldsArriveAsTheExactPinnedBytesAndEmptyFieldsAsNullWithLengthZero()
    {
        byte[] application = [0x00, 0x80, 0xFF];
        byte[] key = [0xFF, 0x00, 0x80, 0x00];
        NativeBootstrapBytes local = new(application, [], key, []);
        NativeBootstrapBytes expected = new([], [0x78, 0x00], [], [0x00]);

        _api.AttachWindowsListener(Runtime, Host, 1, local, expected);

        FakeNetworkExportCall call = Single("sas_pairing_host_attach_windows_listener");
        (nint Data, nuint Length, byte[]? Bytes)[] l = call.Local!.Fields;
        Assert.Equal(new byte[] { 0x00, 0x80, 0xFF }, l[0].Bytes);
        Assert.Equal((nuint)3, l[0].Length);
        Assert.Equal((0, (nuint)0, (byte[]?)null), l[1]);
        Assert.Equal(new byte[] { 0xFF, 0x00, 0x80, 0x00 }, l[2].Bytes);
        Assert.Equal((0, (nuint)0, (byte[]?)null), l[3]);

        (nint Data, nuint Length, byte[]? Bytes)[] e = call.Expected!.Fields;
        Assert.Equal((0, (nuint)0, (byte[]?)null), e[0]);
        Assert.Equal(new byte[] { 0x78, 0x00 }, e[1].Bytes);
        Assert.Equal((0, (nuint)0, (byte[]?)null), e[2]);
        Assert.Equal(new byte[] { 0x00 }, e[3].Bytes);
        Assert.NotEqual(call.Local.ViewAddress, call.Expected.ViewAddress);

        // No terminator, encoding, or copy: the pinned addresses are distinct non-null field memory.
        Assert.All(new[] { l[0].Data, l[2].Data, e[1].Data, e[3].Data }, address => Assert.NotEqual(0, address));
    }

    [Fact]
    public void DriveAndRecheckPassSeventeenZeroedRecordsAndDistinctAlignedOutputs()
    {
        _api.Drive(Runtime, Host);
        _api.RecheckAfterResume(Runtime, Host);

        Assert.Equal(["sas_pairing_host_drive", "sas_pairing_host_recheck_after_resume"], FakeNetworkExports.Calls.Select(c => c.Export));
        foreach (FakeNetworkExportCall call in FakeNetworkExports.Calls)
        {
            Assert.Equal([Runtime, Host], call.Arguments);
            Assert.Equal((nuint)17, call.Capacity);
            Assert.NotEqual(0, call.Events);
            Assert.Equal(0, call.Events % 8);
            Assert.True(call.EventsZeroOnEntry);
            Assert.NotEqual(call.CountSlot, call.FailureSlot);
            Assert.Equal(0, call.CountSlot % IntPtr.Size);
            Assert.Equal(0, call.FailureSlot % sizeof(int));
            Assert.Equal((nuint)0, call.CountOnEntry);
            Assert.Equal(0, call.FailureOnEntry);

            // The outputs do not overlap the event array.
            nint end = call.Events + (17 * 128);
            Assert.False(call.CountSlot >= call.Events && call.CountSlot < end);
            Assert.False(call.FailureSlot >= call.Events && call.FailureSlot < end);
        }
    }

    [Fact]
    public unsafe void ProducedRecordsAreCopiedFieldByFieldWithAllRequestIdBytes()
    {
        sas_pairing_event_t record = new()
        {
            kind = 4,
            step_kind = 1,
            protocol_event = 6,
            reason = 3,
            deadline_kind = 2,
            cancel_state = 1,
            cancel_reason = 4,
            flags = 3,
            connection = Connection,
            run = 0x4142,
            result = 0x5152,
            request_id_len = 3,
            reserved = 7,
        };
        record.request_id[0] = 0x00;
        record.request_id[1] = 0x80;
        record.request_id[2] = 0xFF;
        record.request_id[63] = 0x99;
        FakeNetworkExports.EventsOut.Add(record);
        FakeNetworkExports.EventsOut.Add(new sas_pairing_event_t { kind = 1, connection = 5 });
        FakeNetworkExports.CountOut = 2;
        FakeNetworkExports.FailureOut = AbiV1Constants.SAS_PAIRING_NETWORK_POLL_FAILED;

        NativeDriveOutcome outcome = _api.Drive(Runtime, Host);

        Assert.Equal(0, outcome.Status);
        Assert.Equal((nuint)2, outcome.Count);
        Assert.Equal(404, outcome.Failure);
        NativeEventRecord copied = outcome.Events[0];
        Assert.Equal((4u, 1u, 6u, 3u, 2u, 1u, 4u, 3u), (copied.Kind, copied.StepKind, copied.ProtocolEvent, copied.Reason, copied.DeadlineKind, copied.CancelState, copied.CancelReason, copied.Flags));
        Assert.Equal((Connection, 0x4142ul, 0x5152ul, 3u, 7u), (copied.Connection, copied.Run, copied.Result, copied.RequestIdLength, copied.Reserved));
        Assert.Equal(64, copied.RequestId.Length);
        Assert.Equal(new byte[] { 0x00, 0x80, 0xFF }, copied.RequestId[..3]);
        Assert.Equal(0x99, copied.RequestId[63]);
        Assert.Equal((1u, 5ul), (outcome.Events[1].Kind, outcome.Events[1].Connection));
    }

    [Fact]
    public void ACountOverTheCapacityIsReportedRawButNeverReadPastTheArray()
    {
        FakeNetworkExports.CountOut = 18;
        NativeDriveOutcome outcome = _api.Drive(Runtime, Host);
        Assert.Equal((nuint)18, outcome.Count);
        Assert.Equal(17, outcome.Events.Length);

        // A failed call copies nothing, whatever it wrote.
        FakeNetworkExports.Status = AbiV1Constants.SAS_PAIRING_BUFFER_TOO_SMALL;
        FakeNetworkExports.CountOut = 17;
        NativeDriveOutcome failed = _api.RecheckAfterResume(Runtime, Host);
        Assert.Equal((300, (nuint)17), (failed.Status, failed.Count));
        Assert.Empty(failed.Events);
    }

    [Fact]
    public void DetachAndCloseCallTheExactHandles()
    {
        FakeNetworkExports.Status = AbiV1Constants.SAS_PAIRING_OWNERSHIP_UNCERTAIN;
        Assert.Equal(104, _api.DetachListener(Runtime, Host));
        Assert.Equal(104, _api.ConnectionClose(Runtime, Host, Connection));
        Assert.Equal([Runtime, Host], FakeNetworkExports.Calls[0].Arguments);
        Assert.Equal("sas_pairing_connection_close", FakeNetworkExports.Calls[1].Export);
        Assert.Equal([Runtime, Host, Connection], FakeNetworkExports.Calls[1].Arguments);
    }

    [Fact]
    public void TheServiceCallsExactlyTheFiveNetworkExportsAndNothingElse()
    {
        string code = ProductionSource.Code("Interop/FfiNativeNetworkApi.cs");
        string[] used = [.. TableField().Matches(code).Select(m => m.Value).Distinct().Order(StringComparer.Ordinal)];
        Assert.Equal(
            ["sas_pairing_connection_close", "sas_pairing_host_attach_windows_listener", "sas_pairing_host_detach_listener", "sas_pairing_host_drive", "sas_pairing_host_recheck_after_resume"],
            used);
        Assert.Equal(5, typeof(INativeNetworkApi).GetMethods().Length);
        Assert.Contains("new FfiNativeNetworkApi(abi.Functions)", ProductionSource.Code("NativeProcessContext.cs"), StringComparison.Ordinal);

        // Always the frozen capacity: no size query, no other capacity.
        Assert.Contains("AbiV1Constants.SAS_PAIRING_MAX_DRIVE_EVENTS, &count, &failure", code, StringComparison.Ordinal);
        Assert.DoesNotMatch(@"null,\s*0", code);
    }

    [GeneratedRegex(@"(?<=_functions\.)sas_pairing_\w+|(?<![""\w])sas_pairing_[a-z_]+(?=\()")]
    private static partial Regex TableField();
}
