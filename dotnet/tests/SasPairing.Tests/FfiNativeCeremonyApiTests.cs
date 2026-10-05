using System.Text.RegularExpressions;
using SasPairing.Interop;
using SasPairing.Tests.Support;

namespace SasPairing.Tests;

/// <summary>
/// The private ceremony-native service at the real function-pointer boundary, independent of the high-level
/// wrappers: <see cref="FfiNativeCeremonyApi"/> over the real <see cref="AbiV1FunctionTable"/> bound to recording
/// unmanaged fakes. Exact handles for all nine exports, the shared Bootstrap marshalling of start and attach, the
/// exact 32 identity bytes of a decision, zeroed and aligned output records, and records copied only on OK.
/// </summary>
public sealed partial class FfiNativeCeremonyApiTests
{
    private const ulong Runtime = 0x0102_0304_0506_0708;
    private const ulong Host = 0x2122_2324_2526_2728;
    private const ulong Connection = 0x3132_3334_3536_3738;
    private const ulong Run = 0x4142_4344_4546_4748;

    private readonly FfiNativeCeremonyApi _api;
    private readonly FfiNativeNetworkApi _network;

    public FfiNativeCeremonyApiTests()
    {
        FakeExports.Reset();
        FakeLifecycleExports.Reset();
        FakeNetworkExports.Reset();
        FakeCeremonyExports.Reset();
        AbiV1FunctionTable table = AbiV1FunctionTable.Bind(FakeCeremonyExports.Image());
        _api = new FfiNativeCeremonyApi(table);
        _network = new FfiNativeNetworkApi(table);
    }

    private static byte[] Identity() => [0x00, 0x80, 0xFF, .. Enumerable.Range(3, 29).Select(i => (byte)i)];

    /// <summary>Calls the service method for <paramref name="export"/> on the fixed handles.</summary>
    private NativeActionOutcome Act(string export, byte[]? identity = null) => export switch
    {
        "sas_pairing_run_authorize_exposure" => _api.AuthorizeExposure(Runtime, Host, Connection, Run),
        "sas_pairing_run_expose_key" => _api.ExposeKey(Runtime, Host, Connection, Run),
        "sas_pairing_run_approve_sas" => _api.ApproveSas(Runtime, Host, Connection, Run, identity ?? Identity()),
        "sas_pairing_run_emit_bootstrap_mac" => _api.EmitBootstrapMac(Runtime, Host, Connection, Run),
        "sas_pairing_run_reject_sas" => _api.RejectSas(Runtime, Host, Connection, Run, identity ?? Identity()),
        "sas_pairing_run_cancel_sas" => _api.CancelSas(Runtime, Host, Connection, Run, identity ?? Identity()),
        "sas_pairing_run_emit_initiator_finish" => _api.EmitInitiatorFinish(Runtime, Host, Connection, Run),
        _ => throw new ArgumentOutOfRangeException(nameof(export)),
    };

    public static TheoryData<string> RunExports =>
    [
        "sas_pairing_run_authorize_exposure", "sas_pairing_run_expose_key", "sas_pairing_run_approve_sas", "sas_pairing_run_emit_bootstrap_mac",
        "sas_pairing_run_reject_sas", "sas_pairing_run_cancel_sas", "sas_pairing_run_emit_initiator_finish",
    ];

    [Theory]
    [MemberData(nameof(RunExports))]
    public void EveryRunActionPassesTheExactHandlesAndOneZeroedAlignedRecord(string export)
    {
        FakeCeremonyExports.ActionOut = new sas_pairing_action_t { @event = 3, deadline_kind = 2, flags = 0x80000001, reserved = 7, run = Run };

        NativeActionOutcome outcome = Act(export);

        FakeCeremonyExportCall call = Assert.Single(FakeCeremonyExports.Calls);
        Assert.Equal(export, call.Export);
        Assert.Equal([Runtime, Host, Connection, Run], call.Arguments);
        Assert.NotEqual(0, call.Output);
        Assert.Equal(0, call.Output % 8);
        Assert.True(call.OutputZeroOnEntry);

        // Copied raw on OK: nothing is interpreted here.
        Assert.Equal(0, outcome.Status);
        Assert.Equal(new NativeActionRecord(3, 2, 0x80000001, 7, Run), outcome.Action);
        Assert.Equal(0, FakeExports.UnexpectedCalls);
    }

    [Theory]
    [MemberData(nameof(RunExports))]
    public void AFailedActionCopiesNothing(string export)
    {
        FakeCeremonyExports.Status = AbiV1Constants.SAS_PAIRING_WRITE_PENDING;
        FakeCeremonyExports.ActionOut = new sas_pairing_action_t { @event = 4, run = Run };

        NativeActionOutcome outcome = Act(export);

        Assert.Equal(new NativeActionOutcome(205, null), outcome);
    }

    [Theory]
    [InlineData("sas_pairing_run_approve_sas")]
    [InlineData("sas_pairing_run_reject_sas")]
    [InlineData("sas_pairing_run_cancel_sas")]
    public void ADecisionPassesExactlyTheThirtyTwoIdentityBytesOutsideTheOutputRecord(string export)
    {
        byte[] identity = Identity();

        Act(export, identity);

        FakeCeremonyExportCall call = Assert.Single(FakeCeremonyExports.Calls);
        Assert.NotEqual(0, call.IdentityPointer);
        Assert.Equal(identity, call.Identity);
        Assert.False(call.IdentityPointer + 32 > call.Output && call.Output + 24 > call.IdentityPointer, "the identity overlaps the output record");

        // Anything but exactly 32 bytes is refused before the call: native would read 32.
        FakeCeremonyExports.Reset();
        Assert.Throws<ArgumentException>(() => Act(export, new byte[31]));
        Assert.Throws<ArgumentException>(() => Act(export, new byte[33]));
        Assert.Throws<ArgumentException>(() => Act(export, []));
        Assert.Empty(FakeCeremonyExports.Calls);
    }

    [Fact]
    public void StartPassesTheExactHandlesAndBootstrapsThroughTheSharedMarshalling()
    {
        NativeBootstrapBytes local = new([0x00, 0x80, 0xFF], [], [0xFF, 0x00, 0x80, 0x00], []);
        NativeBootstrapBytes expected = new([], [0x78, 0x00], [], [0x00]);
        FakeCeremonyExports.ActionOut = new sas_pairing_action_t { @event = 1, flags = 1, run = 0x7000 };

        NativeActionOutcome started = _api.StartInitiator(Runtime, Host, Connection, local, expected);
        NativeActionOutcome withoutExpected = _api.StartInitiator(Runtime, Host, Connection, local, null);

        Assert.Equal(new NativeActionRecord(1, 0, 1, 0, 0x7000), started.Action);
        FakeCeremonyExportCall call = FakeCeremonyExports.Calls[0];
        Assert.Equal("sas_pairing_connection_start_initiator", call.Export);
        Assert.Equal([Runtime, Host, Connection], call.Arguments);
        Assert.True(call.OutputZeroOnEntry);
        Assert.Equal(0, call.Output % 8);
        Assert.Equal(0, call.Local!.ViewAddress % IntPtr.Size);
        Assert.NotEqual(call.Local.ViewAddress, call.Expected!.ViewAddress);
        Assert.Null(FakeCeremonyExports.Calls[1].Expected);
        Assert.NotNull(withoutExpected.Action);

        // Listener attach and Initiator start marshal the same Bootstrap bytes identically: per field the same
        // length, the same bytes, and NULL with length 0 for an empty field.
        _network.AttachWindowsListener(Runtime, Host, 1, local, expected);
        FakeNetworkExportCall attach = Assert.Single(FakeNetworkExports.Calls);
        AssertSameSemantics(attach.Local!, call.Local);
        AssertSameSemantics(attach.Expected!, call.Expected);
        Assert.Equal((0, (nuint)0, (byte[]?)null), call.Local.Fields[1]);
        Assert.Equal(new byte[] { 0x00, 0x80, 0xFF }, call.Local.Fields[0].Bytes);
    }

    private static void AssertSameSemantics(SeenBootstrap attach, SeenBootstrap start)
    {
        for (int i = 0; i < 4; i++)
        {
            Assert.Equal(attach.Fields[i].Length, start.Fields[i].Length);
            Assert.Equal(attach.Fields[i].Bytes, start.Fields[i].Bytes);
            Assert.Equal(attach.Fields[i].Data == 0, start.Fields[i].Data == 0);
        }
    }

    [Fact]
    public unsafe void APresentationIsCopiedByteForByteOnlyOnOk()
    {
        sas_pairing_sas_presentation_t record = new() { available = 1, reserved = 9 };
        byte[] identity = Identity();
        for (int i = 0; i < 32; i++)
        {
            record.ceremony_identity[i] = identity[i];
        }

        for (int i = 0; i < 14; i++)
        {
            record.@decimal[i] = (byte)"9876 5432 1098"[i];
        }

        record.reserved_tail[0] = 0x11;
        record.reserved_tail[1] = 0x22;
        FakeCeremonyExports.PresentationOut = record;

        NativePresentationOutcome outcome = _api.Presentation(Runtime, Host, Connection, Run);

        FakeCeremonyExportCall call = Assert.Single(FakeCeremonyExports.Calls);
        Assert.Equal("sas_pairing_run_presentation", call.Export);
        Assert.Equal([Runtime, Host, Connection, Run], call.Arguments);
        Assert.True(call.OutputZeroOnEntry);
        Assert.Equal(0, call.Output % 4);
        NativePresentationRecord copied = outcome.Presentation!;
        Assert.Equal((1u, 9u), (copied.Available, copied.Reserved));
        Assert.Equal(identity, copied.CeremonyIdentity);
        Assert.Equal("9876 5432 1098"u8.ToArray(), copied.Decimal);
        Assert.Equal(new byte[] { 0x11, 0x22 }, copied.ReservedTail);

        FakeCeremonyExports.Status = AbiV1Constants.SAS_PAIRING_RUN_ENDED;
        Assert.Equal(new NativePresentationOutcome(204, null), _api.Presentation(Runtime, Host, Connection, Run));
    }

    [Fact]
    public void TheServiceCallsExactlyTheNineCeremonyExportsAndSharesTheBootstrapPath()
    {
        string code = ProductionSource.Code("Interop/FfiNativeCeremonyApi.cs");
        string[] used = [.. TableField().Matches(code).Select(m => m.Value).Distinct().Order(StringComparer.Ordinal)];
        Assert.Equal(
            [
                "sas_pairing_connection_start_initiator", "sas_pairing_run_approve_sas", "sas_pairing_run_authorize_exposure", "sas_pairing_run_cancel_sas",
                "sas_pairing_run_emit_bootstrap_mac", "sas_pairing_run_emit_initiator_finish", "sas_pairing_run_expose_key", "sas_pairing_run_presentation",
                "sas_pairing_run_reject_sas",
            ],
            used);
        Assert.Equal(9, typeof(INativeCeremonyApi).GetMethods().Length);
        Assert.Contains("new FfiNativeCeremonyApi(abi.Functions)", ProductionSource.Code("NativeProcessContext.cs"), StringComparison.Ordinal);

        // One Bootstrap marshalling path: both callers use it once, and only it pins Bootstrap fields or builds views.
        foreach (string file in new[] { "Interop/FfiNativeCeremonyApi.cs", "Interop/FfiNativeNetworkApi.cs" })
        {
            Assert.Single(Regex.Matches(ProductionSource.Code(file), @"NativeBootstrapMarshalling\.Call\("));
        }

        foreach ((string file, string other) in ProductionSource.AllCode().Where(f => f.File != "Interop/NativeBootstrapMarshalling.cs"))
        {
            Assert.DoesNotMatch(@"\.ApplicationIdentity\s*,|new\s+sas_pairing_bootstrap_view_t|sas_pairing_bootstrap_view_t\s+\w+\s*=", other);
            Assert.False(other.Contains("sas_pairing_bytes_view_t", StringComparison.Ordinal) && file != "Interop/AbiV1Structs.cs", file);
        }

        // Records are copied only on OK, and no result export is reachable from the ceremony service.
        Assert.DoesNotContain("sas_pairing_result_", code, StringComparison.Ordinal);
    }

    [GeneratedRegex(@"(?<=_functions\.)sas_pairing_\w+|(?<![""\w])sas_pairing_[a-z_]+(?=\()")]
    private static partial Regex TableField();
}
