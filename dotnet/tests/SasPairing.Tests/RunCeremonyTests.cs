using SasPairing.Interop;
using SasPairing.Tests.Support;

namespace SasPairing.Tests;

/// <summary>
/// P9-D-004 run identity and trusted-local ceremony control over the fake services (every platform): one public
/// run per exact native run handle, the unknown request ID of a local start and its one-time learning, the frozen
/// per-method outcome tables, the <c>WRITE_PENDING</c> status-versus-flag distinction, one native call per
/// method with no chaining or driving, known-ended runs refused locally, and the lifetime effects of every
/// ceremony status.
/// </summary>
public sealed class RunCeremonyTests
{
    private const int Ok = 0;
    private const uint WritePendingFlag = AbiV1Constants.SAS_PAIRING_ACTION_FLAG_WRITE_PENDING;

    private static readonly byte[] RequestA = [0x00, 0x80, 0xFF, 0x41];
    private static readonly byte[] RequestB = [0x42];

    /// <summary>The seven public actions on an existing run.</summary>
    private static readonly string[] RunActions = ["AuthorizeExposure", "ExposeKey", "ApproveSas", "EmitBootstrapMac", "RejectSas", "CancelSas", "EmitInitiatorFinish"];

    /// <summary>The frozen per-method outcome table of P9-D-004, written independently of the production table: (event, live, write pending; null for either).</summary>
    private static readonly Dictionary<string, (uint Event, bool Live, bool? WritePending)[]> Allowed = new()
    {
        ["StartInitiator"] = [(1, true, true)],
        ["AuthorizeExposure"] = [(2, true, false), (12, false, null)],
        ["ExposeKey"] = [(3, true, true), (12, false, null)],
        ["ApproveSas"] = [(4, true, false), (5, true, false), (12, false, null)],
        ["EmitBootstrapMac"] = [(6, true, true), (7, true, false), (12, false, null)],
        ["RejectSas"] = [(10, false, null), (12, false, null)],
        ["CancelSas"] = [(11, false, null), (12, false, null)],
        ["EmitInitiatorFinish"] = [(8, true, true), (9, true, false), (12, false, null)],
    };

    private static readonly Dictionary<string, string> ExportOf = new()
    {
        ["StartInitiator"] = FakeCeremonyApi.StartExport,
        ["AuthorizeExposure"] = FakeCeremonyApi.AuthorizeExport,
        ["ExposeKey"] = FakeCeremonyApi.ExposeExport,
        ["Presentation"] = FakeCeremonyApi.PresentationExport,
        ["ApproveSas"] = FakeCeremonyApi.ApproveExport,
        ["EmitBootstrapMac"] = FakeCeremonyApi.BootstrapMacExport,
        ["RejectSas"] = FakeCeremonyApi.RejectExport,
        ["CancelSas"] = FakeCeremonyApi.CancelExport,
        ["EmitInitiatorFinish"] = FakeCeremonyApi.FinishExport,
    };

    public static TheoryData<string> Actions => [.. RunActions];

    public static TheoryData<string> Methods => [.. RunActions, "Presentation"];

    private static SasPairingCeremonyIdentity Identity(byte seed = 0x5A) => new(Presentations.Identity(seed));

    /// <summary>Calls the public method <paramref name="method"/> of <paramref name="run"/>; Presentation returns null.</summary>
    private static SasPairingLocalAction? Invoke(SasPairingRun run, string method, SasPairingCeremonyIdentity? identity = null) => method switch
    {
        "AuthorizeExposure" => run.AuthorizeExposure(),
        "ExposeKey" => run.ExposeKey(),
        "ApproveSas" => run.ApproveSas(identity ?? Identity()),
        "EmitBootstrapMac" => run.EmitBootstrapMac(),
        "RejectSas" => run.RejectSas(identity ?? Identity()),
        "CancelSas" => run.CancelSas(identity ?? Identity()),
        "EmitInitiatorFinish" => run.EmitInitiatorFinish(),
        "Presentation" => Present(run),
        _ => throw new ArgumentOutOfRangeException(nameof(method)),
    };

    private static SasPairingLocalAction? Present(SasPairingRun run)
    {
        _ = run.Presentation();
        return null;
    }

    /// <summary>A fake tree with an attached listener and one accepted connection 100.</summary>
    private static (FakeTree Tree, SasPairingConnection Connection) Connected()
    {
        FakeTree tree = new();
        return (tree, tree.AttachWithConnections(100).Single());
    }

    /// <summary>A Responder run reported by a drive event (handle 500 under request ID A on connection 100).</summary>
    private static SasPairingRun ResponderRun(FakeTree tree, ulong connection = 100, ulong handle = 500, byte[]? requestId = null)
    {
        tree.Network.Next(Ok, Ok, Records.Inbound(connection, AbiV1Constants.SAS_PAIRING_PROTOCOL_EVENT_START_ACCEPTED, requestId ?? RequestA, run: handle, flags: AbiV1Constants.SAS_PAIRING_EVENT_FLAG_WRITE_PENDING));
        return Assert.Single(tree.Host.Drive().Events).Run!;
    }

    private static void AssertContractViolation(FakeTree tree, Action action)
    {
        Assert.Throws<SasPairingContractException>(action);
        Assert.True(tree.Context.IsContractViolated);
    }

    [Fact]
    public void StartInitiatorReturnsTheNewRunWithWritePendingAndInventsNoRequestId()
    {
        (FakeTree tree, SasPairingConnection connection) = Connected();
        SasPairingBootstrap local = FakeTree.Bootstrap(3);
        SasPairingBootstrap expected = FakeTree.Bootstrap(4);

        SasPairingLocalAction started = connection.StartInitiator(local, expected);

        FakeCeremonyCall call = Assert.Single(tree.Ceremony.Calls);
        Assert.Equal(FakeCeremonyApi.StartExport, call.Export);
        Assert.Equal([tree.Runtime.Handle, tree.Host.Handle, 100ul], call.Arguments);
        Assert.Same(local.Native, call.Local);
        Assert.Same(expected.Native, call.Expected);
        Assert.Equal(SasPairingLocalEvent.InitiatorStarted, started.Event);
        Assert.True(started.WritePending);
        Assert.Equal(SasPairingDeadlineKind.None, started.DeadlineKind);
        SasPairingRun run = Assert.IsType<SasPairingRun>(started.Run);
        Assert.False(run.IsEnded);
        Assert.Same(run, Assert.Single(connection.Runs));
        Assert.Equal(7000ul, run.Ref.Handle);
        Assert.False(run.Ref.HasRequestId);
        Assert.True(run.Ref.RequestId.IsEmpty);

        // Nothing else happened: no drive (only the accepting one of the setup), no status query.
        Assert.Equal(1, tree.Network.Count(FakeNetworkApi.DriveExport));
        Assert.Equal(0, tree.Lifecycle.Count(FakeLifecycleApi.AuthorityStatusExport));
        Assert.DoesNotContain("7000", run.ToString()!, StringComparison.Ordinal);

        // No expected Bootstrap is a null view.
        connection.StartInitiator(local);
        Assert.Null(tree.Ceremony.Calls[1].Expected);
    }

    [Fact]
    public void AWritePendingStartStatusMeansNothingStartedAndNothingIsDrivenOrRetried()
    {
        (FakeTree tree, SasPairingConnection connection) = Connected();
        tree.Ceremony.Next(AbiV1Constants.SAS_PAIRING_WRITE_PENDING, Support.Actions.Of(1, 7777, WritePendingFlag));

        SasPairingNativeException failure = Assert.Throws<SasPairingNativeException>(() => connection.StartInitiator(FakeTree.Bootstrap()));

        Assert.Equal(205, failure.StatusCode);
        Assert.Equal(SasPairingStatus.WritePending, failure.KnownStatus);
        Assert.Equal("SasPairingConnection.StartInitiator", failure.Operation);
        Assert.Empty(connection.Runs);
        Assert.Equal(1, tree.Ceremony.Total);
        Assert.Equal(1, tree.Network.Count(FakeNetworkApi.DriveExport)); // the accepting drive only
        Assert.False(connection.IsDisposed);
        Assert.False(tree.Context.IsContractViolated || tree.Context.IsFatal);
    }

    [Theory]
    [InlineData("event", 2u, 7000ul, WritePendingFlag, 0u, 0u)]
    [InlineData("deadline event", 12u, 0ul, WritePendingFlag, 1u, 0u)]
    [InlineData("run 0", 1u, 0ul, WritePendingFlag, 0u, 0u)]
    [InlineData("no write pending", 1u, 7000ul, 0u, 0u, 0u)]
    [InlineData("unknown flag", 1u, 7000ul, WritePendingFlag | 0x2u, 0u, 0u)]
    [InlineData("deadline kind", 1u, 7000ul, WritePendingFlag, 2u, 0u)]
    [InlineData("reserved", 1u, 7000ul, WritePendingFlag, 0u, 1u)]
    public void AnImpossibleStartOutputLatchesTheContractViolationAndCreatesNoRun(string what, uint localEvent, ulong run, uint flags, uint deadline, uint reserved)
    {
        (FakeTree tree, SasPairingConnection connection) = Connected();
        tree.Ceremony.Next(Ok, Support.Actions.Of(localEvent, run, flags, deadline, reserved));

        AssertContractViolation(tree, () => connection.StartInitiator(FakeTree.Bootstrap()));

        Assert.Empty(connection.Runs);
        Assert.NotNull(what);
    }

    [Fact]
    public void AStartReturningTheHandleOfALiveRunIsAContractViolationAndRetargetsNothing()
    {
        FakeTree tree = new();
        SasPairingConnection[] connections = tree.AttachWithConnections(100, 101);
        SasPairingRun live = connections[0].StartInitiator(FakeTree.Bootstrap()).Run!;
        tree.Ceremony.Next(Ok, Support.Actions.Of(1, live.Ref.Handle, WritePendingFlag));
        AssertContractViolation(tree, () => connections[0].StartInitiator(FakeTree.Bootstrap()));
        Assert.Same(live, Assert.Single(connections[0].Runs));

        // The handle of a live run on another connection of the host is refused too.
        FakeTree second = new();
        SasPairingConnection[] others = second.AttachWithConnections(100, 101);
        SasPairingRun elsewhere = ResponderRun(second, 101, 900);
        second.Ceremony.Next(Ok, Support.Actions.Of(1, 900, WritePendingFlag));
        AssertContractViolation(second, () => others[0].StartInitiator(FakeTree.Bootstrap()));

        Assert.False(live.IsEnded || elsewhere.IsEnded);
        Assert.Empty(others[0].Runs);
        Assert.Same(elsewhere, Assert.Single(others[1].Runs));
    }

    [Fact]
    public void TheStartedRunIsTheEventRunAndLearnsItsRequestIdOnce()
    {
        (FakeTree tree, SasPairingConnection connection) = Connected();
        SasPairingRun run = connection.StartInitiator(FakeTree.Bootstrap()).Run!;

        // Before learning, no request-ID retirement can match the run.
        tree.Network.Next(Ok, Ok, Records.Inbound(100, AbiV1Constants.SAS_PAIRING_PROTOCOL_EVENT_PEER_CANCEL, RequestA) with { CancelReason = AbiV1Constants.SAS_PAIRING_CANCEL_REASON_TIMEOUT });
        tree.Network.Next(Ok, Ok, Records.Step(100, AbiV1Constants.SAS_PAIRING_STEP_DEADLINE, requestId: RequestA) with { DeadlineKind = AbiV1Constants.SAS_PAIRING_DEADLINE_ABSOLUTE_TIMEOUT });
        tree.Host.Drive();
        tree.Host.Drive();
        Assert.False(run.IsEnded);
        Assert.False(run.Ref.HasRequestId);

        // A run under request ID A reported by the network, then the first event naming the local run under A:
        // the other run under A ends first, then the local run learns A.
        SasPairingRun responder = ResponderRun(tree, 100, 500, RequestA);
        tree.Network.Next(Ok, Ok, Records.Inbound(100, AbiV1Constants.SAS_PAIRING_PROTOCOL_EVENT_ACCEPT, RequestA, run: run.Ref.Handle));
        SasPairingEvent accept = Assert.Single(tree.Host.Drive().Events);

        Assert.Same(run, accept.Run);
        Assert.True(accept.HasTrackedRun);
        Assert.False(run.IsEnded);
        Assert.Equal(RequestA, run.Ref.RequestId.ToArray());
        Assert.True(responder.IsEnded);
        Assert.Same(run, Assert.Single(connection.Runs));

        // The same request ID again is fine; a later action carries the same object.
        tree.Network.Next(Ok, Ok, Records.Inbound(100, AbiV1Constants.SAS_PAIRING_PROTOCOL_EVENT_RESPONDER_KEY, RequestA, run: run.Ref.Handle));
        Assert.Same(run, Assert.Single(tree.Host.Drive().Events).Run);
        Assert.Same(run, run.AuthorizeExposure().Run);

        // A different request ID for the same handle is a contract violation.
        tree.Network.Next(Ok, Ok, Records.Inbound(100, AbiV1Constants.SAS_PAIRING_PROTOCOL_EVENT_RESPONDER_KEY, RequestB, run: run.Ref.Handle));
        AssertContractViolation(tree, () => tree.Host.Drive());
        Assert.Equal(RequestA, run.Ref.RequestId.ToArray());
    }

    [Fact]
    public void ARequestIdReusedByANewHandleIsANewRunAndEndsTheOldOne()
    {
        (FakeTree tree, SasPairingConnection connection) = Connected();
        SasPairingRun first = ResponderRun(tree, 100, 100, RequestA);
        SasPairingRun second = ResponderRun(tree, 100, 101, RequestA);

        Assert.NotSame(first, second);
        Assert.True(first.IsEnded);
        Assert.False(second.IsEnded);
        Assert.Equal(100ul, first.Ref.Handle);
        Assert.Equal(101ul, second.Ref.Handle);
        Assert.Same(second, Assert.Single(connection.Runs));

        // The old object is never retargeted: it refuses locally, the new one reaches native with its own handle.
        Assert.Throws<SasPairingRunEndedException>(() => first.AuthorizeExposure());
        second.AuthorizeExposure();
        Assert.Equal(101ul, Assert.Single(tree.Ceremony.Calls).Arguments[3]);
    }

    [Fact]
    public void AuthorizeExposureIsOneCallThatExposesAndSpendsNothing()
    {
        (FakeTree tree, _) = Connected();
        SasPairingRun run = ResponderRun(tree);

        SasPairingLocalAction authorized = run.AuthorizeExposure();

        Assert.Equal((SasPairingLocalEvent.ExposureAuthorized, false, SasPairingDeadlineKind.None), (authorized.Event, authorized.WritePending, authorized.DeadlineKind));
        Assert.Same(run, authorized.Run);
        FakeCeremonyCall call = Assert.Single(tree.Ceremony.Calls);
        Assert.Equal(FakeCeremonyApi.AuthorizeExport, call.Export);
        Assert.Equal([tree.Runtime.Handle, tree.Host.Handle, 100ul, 500ul], call.Arguments);
        Assert.Equal(0, tree.Ceremony.Count(FakeCeremonyApi.ExposeExport));
        Assert.Equal(0, tree.Lifecycle.Count(FakeLifecycleApi.AuthorityStatusExport));
        Assert.Equal(2, tree.Network.Count(FakeNetworkApi.DriveExport)); // the setup's accepting and reporting drives only
    }

    [Fact]
    public void ExposeKeyIsTheOneNativeSpendingCallAndTheWrapperKeepsNoBudget()
    {
        (FakeTree tree, _) = Connected();
        SasPairingRun run = ResponderRun(tree);

        SasPairingLocalAction exposed = run.ExposeKey();

        Assert.Equal((SasPairingLocalEvent.KeyExposed, true), (exposed.Event, exposed.WritePending));
        Assert.Same(run, exposed.Run);
        Assert.Equal(FakeCeremonyApi.ExposeExport, Assert.Single(tree.Ceremony.Calls).Export);
        Assert.Equal(0, tree.Lifecycle.Count(FakeLifecycleApi.AuthorityStatusExport));

        // Accounting stays native: the next status snapshot is whatever native says, with no expected decrement.
        tree.Lifecycle.AuthorityStatusOutcome = () => new NativeAuthorityStatusOutcome(Ok, AbiV1Constants.SAS_PAIRING_AUTHORITY_READY, 10);
        Assert.Equal(new SasPairingAuthorityStatus(SasPairingAuthorityState.Ready, 10), tree.Authority.GetStatus());
    }

    [Fact]
    public void ApproveSasPassesTheExactIdentityAndChainsNothing()
    {
        (FakeTree tree, _) = Connected();
        SasPairingRun run = ResponderRun(tree);
        SasPairingCeremonyIdentity identity = Identity(0x77);

        SasPairingLocalAction approved = run.ApproveSas(identity);
        tree.Ceremony.Next(_ => new NativeActionOutcome(Ok, Support.Actions.Of(AbiV1Constants.SAS_PAIRING_LOCAL_EVENT_SAS_ALREADY_APPROVED, 500)));
        SasPairingLocalAction again = run.ApproveSas(identity);

        Assert.Equal((SasPairingLocalEvent.SasApproved, false), (approved.Event, approved.WritePending));
        Assert.Equal((SasPairingLocalEvent.SasAlreadyApproved, false), (again.Event, again.WritePending));
        Assert.Same(run, approved.Run);
        Assert.All(tree.Ceremony.Calls, c => Assert.Equal(FakeCeremonyApi.ApproveExport, c.Export));
        Assert.Equal(identity.Bytes.ToArray(), tree.Ceremony.Calls[0].Identity);
        Assert.Equal(0, tree.Ceremony.Count(FakeCeremonyApi.BootstrapMacExport));
        Assert.Equal(0, tree.Ceremony.Count(FakeCeremonyApi.FinishExport));
        Assert.Equal(2, tree.Network.Count(FakeNetworkApi.DriveExport)); // the setup's drives only
    }

    [Fact]
    public void EmitBootstrapMacIsOneCallAndNeverFinishes()
    {
        (FakeTree tree, _) = Connected();
        SasPairingRun run = ResponderRun(tree);

        SasPairingLocalAction emitted = run.EmitBootstrapMac();
        tree.Ceremony.Next(_ => new NativeActionOutcome(Ok, Support.Actions.Of(AbiV1Constants.SAS_PAIRING_LOCAL_EVENT_BOOTSTRAP_MAC_ALREADY_EMITTED, 500)));
        SasPairingLocalAction again = run.EmitBootstrapMac();

        Assert.Equal((SasPairingLocalEvent.BootstrapMacEmitted, true), (emitted.Event, emitted.WritePending));
        Assert.Equal((SasPairingLocalEvent.BootstrapMacAlreadyEmitted, false), (again.Event, again.WritePending));
        Assert.Same(run, again.Run);
        Assert.Equal(2, tree.Ceremony.Total);
        Assert.Equal(0, tree.Ceremony.Count(FakeCeremonyApi.FinishExport));
        Assert.Equal(2, tree.Network.Count(FakeNetworkApi.DriveExport)); // the setup's drives only
    }

    [Fact]
    public void EmitInitiatorFinishIsExplicitAndItsRepeatIsAlreadyEmitted()
    {
        (FakeTree tree, SasPairingConnection connection) = Connected();
        SasPairingRun run = connection.StartInitiator(FakeTree.Bootstrap()).Run!;

        SasPairingLocalAction finish = run.EmitInitiatorFinish();
        tree.Ceremony.Next(r => new NativeActionOutcome(Ok, Support.Actions.Of(AbiV1Constants.SAS_PAIRING_LOCAL_EVENT_INITIATOR_FINISH_ALREADY_EMITTED, r)));
        SasPairingLocalAction again = run.EmitInitiatorFinish();

        Assert.Equal((SasPairingLocalEvent.InitiatorFinishEmitted, true), (finish.Event, finish.WritePending));
        Assert.Equal((SasPairingLocalEvent.InitiatorFinishAlreadyEmitted, false), (again.Event, again.WritePending));
        Assert.Same(run, finish.Run);
        Assert.Equal(2, tree.Ceremony.Count(FakeCeremonyApi.FinishExport));
        Assert.Equal(1, tree.Network.Count(FakeNetworkApi.DriveExport)); // only the accepting drive: nothing drives
    }

    [Theory]
    [InlineData("RejectSas", true)]
    [InlineData("RejectSas", false)]
    [InlineData("CancelSas", true)]
    [InlineData("CancelSas", false)]
    public void ASuccessfulRejectOrCancelEndsTheRunButNotTheConnection(string method, bool writePending)
    {
        (FakeTree tree, SasPairingConnection connection) = Connected();
        SasPairingRun run = ResponderRun(tree);
        uint localEvent = method == "RejectSas" ? AbiV1Constants.SAS_PAIRING_LOCAL_EVENT_SAS_REJECTED : AbiV1Constants.SAS_PAIRING_LOCAL_EVENT_SAS_CANCELLED;
        tree.Ceremony.Next(Ok, Support.Actions.Of(localEvent, 0, writePending ? WritePendingFlag : 0));
        SasPairingCeremonyIdentity identity = Identity(0x31);

        SasPairingLocalAction ended = Invoke(run, method, identity)!;

        Assert.Equal(method == "RejectSas" ? SasPairingLocalEvent.SasRejected : SasPairingLocalEvent.SasCancelled, ended.Event);
        Assert.Null(ended.Run);
        Assert.Equal(writePending, ended.WritePending);
        Assert.Equal(SasPairingDeadlineKind.None, ended.DeadlineKind);
        Assert.True(run.IsEnded);
        Assert.Empty(connection.Runs);
        Assert.Equal(identity.Bytes.ToArray(), Assert.Single(tree.Ceremony.Calls).Identity);
        Assert.Equal(ExportOf[method], tree.Ceremony.Calls[0].Export);

        // Every later method fails locally with no native call; the connection stays open.
        foreach (string later in RunActions.Append("Presentation"))
        {
            SasPairingRunEndedException refused = Assert.Throws<SasPairingRunEndedException>(() => Invoke(run, later));
            Assert.Equal("SasPairingRun." + later, refused.Operation);
        }

        Assert.Equal(1, tree.Ceremony.Total);
        Assert.False(connection.IsDisposed);
        Assert.Equal(0, tree.Network.Count(FakeNetworkApi.CloseExport));
        Assert.Equal(SasPairingHostNetworkState.Attached, tree.Host.NetworkState);
    }

    [Theory]
    [MemberData(nameof(DeadlineCases))]
    public void ASuccessfulDeadlineEndsTheRunWhateverWasRequested(string method, bool writePending, uint kind)
    {
        (FakeTree tree, SasPairingConnection connection) = Connected();
        SasPairingRun run = ResponderRun(tree);
        tree.Ceremony.Next(Ok, Support.Actions.Of(AbiV1Constants.SAS_PAIRING_LOCAL_EVENT_DEADLINE, 0, writePending ? WritePendingFlag : 0, kind));

        SasPairingLocalAction deadline = Invoke(run, method)!;

        Assert.Equal(SasPairingLocalEvent.Deadline, deadline.Event);
        Assert.Equal((SasPairingDeadlineKind)kind, deadline.DeadlineKind);
        Assert.Null(deadline.Run);
        Assert.Equal(writePending, deadline.WritePending);
        Assert.True(run.IsEnded);
        Assert.Empty(connection.Runs);
        Assert.Throws<SasPairingRunEndedException>(() => run.Presentation());
        Assert.Equal(1, tree.Ceremony.Total);
    }

    public static TheoryData<string, bool, uint> DeadlineCases()
    {
        TheoryData<string, bool, uint> cases = [];
        uint kind = 1;
        foreach (string method in RunActions)
        {
            cases.Add(method, true, kind);
            cases.Add(method, false, (kind % 4) + 1);
            kind = (kind % 4) + 1;
        }

        return cases;
    }

    [Theory]
    [MemberData(nameof(Methods))]
    public void TheFirstNativeRunEndedIsTheNativeExceptionAndLaterCallsAreLocal(string method)
    {
        (FakeTree tree, SasPairingConnection connection) = Connected();
        SasPairingRun run = ResponderRun(tree);
        SasPairingRun sibling = ResponderRun(tree, 100, 501, RequestB);
        if (method == "Presentation")
        {
            tree.Ceremony.NextPresentation(AbiV1Constants.SAS_PAIRING_RUN_ENDED);
        }
        else
        {
            tree.Ceremony.Next(AbiV1Constants.SAS_PAIRING_RUN_ENDED);
        }

        SasPairingNativeException first = Assert.Throws<SasPairingNativeException>(() => Invoke(run, method));

        Assert.Equal(204, first.StatusCode);
        Assert.Equal(SasPairingStatus.RunEnded, first.KnownStatus);
        Assert.False(first.ProcessRestartRequired);
        Assert.True(run.IsEnded);
        Assert.Same(sibling, Assert.Single(connection.Runs));
        Assert.False(sibling.IsEnded || connection.IsDisposed);

        SasPairingRunEndedException later = Assert.Throws<SasPairingRunEndedException>(() => Invoke(run, method));
        Assert.Equal("SasPairingRun." + method, later.Operation);
        Assert.Equal(1, tree.Ceremony.Total);
        Assert.False(tree.Context.IsFatal || tree.Context.IsContractViolated);
    }

    [Theory]
    [MemberData(nameof(Methods))]
    public void ConnectionEndedDisposesThatConnectionAndItsRunsWithoutAClose(string method)
    {
        FakeTree tree = new();
        SasPairingConnection[] connections = tree.AttachWithConnections(100, 101);
        SasPairingRun a1 = ResponderRun(tree, 100, 500, RequestA);
        SasPairingRun a2 = connections[0].StartInitiator(FakeTree.Bootstrap()).Run!;
        SasPairingRun b1 = ResponderRun(tree, 101, 600, RequestA);
        if (method == "Presentation")
        {
            tree.Ceremony.NextPresentation(AbiV1Constants.SAS_PAIRING_CONNECTION_ENDED);
        }
        else
        {
            tree.Ceremony.Next(AbiV1Constants.SAS_PAIRING_CONNECTION_ENDED);
        }

        SasPairingNativeException ended = Assert.Throws<SasPairingNativeException>(() => Invoke(a1, method));

        Assert.Equal(SasPairingStatus.ConnectionEnded, ended.KnownStatus);
        Assert.True(connections[0].IsDisposed);
        Assert.True(a1.IsEnded && a2.IsEnded);
        Assert.False(connections[1].IsDisposed || b1.IsEnded);
        Assert.Same(connections[1], Assert.Single(tree.Host.Network.Connections));
        Assert.Equal(0, tree.Network.Count(FakeNetworkApi.CloseExport));
        Assert.Equal(SasPairingHostNetworkState.Attached, tree.Host.NetworkState);

        // The disposed connection refuses a start locally; disposing it again makes no close call.
        Assert.Throws<ObjectDisposedException>(() => connections[0].StartInitiator(FakeTree.Bootstrap()));
        connections[0].Dispose();
        Assert.Equal(0, tree.Network.Count(FakeNetworkApi.CloseExport));
        b1.AuthorizeExposure();
    }

    [Theory]
    [InlineData("AuthorizeExposure", 104)]
    [InlineData("Presentation", 104)]
    [InlineData("EmitBootstrapMac", 403)]
    [InlineData("Presentation", 403)]
    [InlineData("StartInitiator", 104)]
    [InlineData("StartInitiator", 403)]
    public void AnOwnerLoopFailureFailsTheHostClosedWithNoChildCleanup(string method, int status)
    {
        FakeTree tree = new();
        SasPairingConnection[] connections = tree.AttachWithConnections(100, 101);
        SasPairingRun a = ResponderRun(tree, 100, 500, RequestA);
        SasPairingRun b = ResponderRun(tree, 101, 600, RequestB);
        if (method == "Presentation")
        {
            tree.Ceremony.NextPresentation(status);
        }
        else
        {
            tree.Ceremony.Next(status);
        }

        SasPairingNativeException failure = Assert.Throws<SasPairingNativeException>(() =>
        {
            if (method == "StartInitiator")
            {
                connections[1].StartInitiator(FakeTree.Bootstrap());
            }
            else
            {
                Invoke(a, method);
            }
        });

        Assert.Equal(status, failure.StatusCode);
        Assert.Equal(SasPairingHostNetworkState.FailedClosed, tree.Host.NetworkState);
        Assert.All(connections, c => Assert.True(c.IsDisposed));
        Assert.True(a.IsEnded && b.IsEnded);
        Assert.Empty(tree.Host.Network.Connections);
        Assert.Equal(0, tree.Network.Count(FakeNetworkApi.CloseExport));
        Assert.Equal(0, tree.Network.Count(FakeNetworkApi.DetachExport));
        Assert.False(tree.Context.IsFatal);
        Assert.Throws<SasPairingRunEndedException>(() => b.EmitInitiatorFinish());
    }

    [Theory]
    [InlineData("ApproveSas")]
    [InlineData("Presentation")]
    [InlineData("StartInitiator")]
    public void FatalLatchesButEndsNoRunOrConnectionAndCleanupStillRuns(string method)
    {
        (FakeTree tree, SasPairingConnection connection) = Connected();
        SasPairingRun run = ResponderRun(tree);
        if (method == "Presentation")
        {
            tree.Ceremony.NextPresentation(AbiV1Constants.SAS_PAIRING_FATAL);
        }
        else
        {
            tree.Ceremony.Next(AbiV1Constants.SAS_PAIRING_FATAL);
        }

        SasPairingNativeException fatal = Assert.Throws<SasPairingNativeException>(() =>
        {
            if (method == "StartInitiator")
            {
                connection.StartInitiator(FakeTree.Bootstrap());
            }
            else
            {
                Invoke(run, method);
            }
        });

        Assert.True(fatal.ProcessRestartRequired);
        Assert.True(tree.Context.IsFatal);
        Assert.False(run.IsEnded);
        Assert.False(connection.IsDisposed);
        int calls = tree.Ceremony.Total;

        // Every later normal ceremony operation is refused locally.
        foreach (string later in RunActions.Append("Presentation"))
        {
            Assert.Equal(SasPairingStatus.Fatal, Assert.Throws<SasPairingNativeException>(() => Invoke(run, later)).KnownStatus);
        }

        Assert.Equal(SasPairingStatus.Fatal, Assert.Throws<SasPairingNativeException>(() => connection.StartInitiator(FakeTree.Bootstrap())).KnownStatus);
        Assert.Equal(calls, tree.Ceremony.Total);

        // Cleanup still enters native.
        connection.Dispose();
        tree.Host.DetachListener();
        tree.Host.Dispose();
        tree.Authority.Dispose();
        tree.Runtime.Dispose();
        Assert.Equal(1, tree.Network.Count(FakeNetworkApi.CloseExport));
        Assert.Equal(1, tree.Network.Count(FakeNetworkApi.DetachExport));
        Assert.Equal(1, tree.Lifecycle.Count(FakeLifecycleApi.HostDestroyExport));
        Assert.Equal(1, tree.Lifecycle.Count(FakeLifecycleApi.AuthorityReleaseExport));
        Assert.Equal(1, tree.Lifecycle.Count(FakeLifecycleApi.RuntimeDestroyExport));
        Assert.True(run.IsEnded);
    }

    [Fact]
    public void AResponderFinishRefusalKeepsTheRunUsable()
    {
        (FakeTree tree, _) = Connected();
        SasPairingRun run = ResponderRun(tree);
        tree.Ceremony.Next(AbiV1Constants.SAS_PAIRING_NOT_INITIATOR);

        SasPairingNativeException refused = Assert.Throws<SasPairingNativeException>(() => run.EmitInitiatorFinish());

        Assert.Equal(217, refused.StatusCode);
        Assert.Equal(SasPairingStatus.NotInitiator, refused.KnownStatus);
        Assert.False(run.IsEnded);
        run.Presentation();
        run.EmitBootstrapMac();
        Assert.Equal([FakeCeremonyApi.FinishExport, FakeCeremonyApi.PresentationExport, FakeCeremonyApi.BootstrapMacExport], tree.Ceremony.Calls.Select(c => c.Export));
    }

    [Theory]
    [MemberData(nameof(Actions))]
    public void AWritePendingStatusMeansTheActionDidNotRunAndNothingIsRetried(string method)
    {
        (FakeTree tree, SasPairingConnection connection) = Connected();
        SasPairingRun run = ResponderRun(tree);
        tree.Ceremony.Next(AbiV1Constants.SAS_PAIRING_WRITE_PENDING, Support.Actions.Of(4, 500));

        SasPairingNativeException pending = Assert.Throws<SasPairingNativeException>(() => Invoke(run, method));

        Assert.Equal(SasPairingStatus.WritePending, pending.KnownStatus);
        Assert.False(run.IsEnded);
        Assert.Same(run, Assert.Single(connection.Runs));
        Assert.Equal(1, tree.Ceremony.Total);
        Assert.Equal(2, tree.Network.Count(FakeNetworkApi.DriveExport)); // the setup's drives only: no automatic drive
        Assert.False(tree.Context.IsFatal || tree.Context.IsContractViolated);
    }

    [Theory]
    [MemberData(nameof(OrdinaryRefusals))]
    public void AnOrdinaryRefusalIsTheExactStatusAndChangesNoLifetime(string method, int status)
    {
        (FakeTree tree, SasPairingConnection connection) = Connected();
        SasPairingRun run = ResponderRun(tree);
        tree.Ceremony.Next(status);

        SasPairingNativeException refused = Assert.Throws<SasPairingNativeException>(() => Invoke(run, method));

        Assert.Equal(status, refused.StatusCode);
        Assert.Equal("SasPairingRun." + method, refused.Operation);
        Assert.False(refused.ProcessRestartRequired);
        Assert.False(run.IsEnded || connection.IsDisposed);
        Assert.Equal(SasPairingHostNetworkState.Attached, tree.Host.NetworkState);
        Assert.False(tree.Context.IsFatal || tree.Context.IsContractViolated);

        // The next call still reaches native.
        run.Presentation();
        Assert.Equal(2, tree.Ceremony.Total);
    }

    public static TheoryData<string, int> OrdinaryRefusals()
    {
        int[] statuses =
        [
            AbiV1Constants.SAS_PAIRING_MISSING_AUTHORIZATION, AbiV1Constants.SAS_PAIRING_BUSY, AbiV1Constants.SAS_PAIRING_EXHAUSTED,
            AbiV1Constants.SAS_PAIRING_CEREMONY_IDENTITY_MISMATCH, AbiV1Constants.SAS_PAIRING_NOT_LOCALLY_APPROVED, AbiV1Constants.SAS_PAIRING_NOT_INITIATOR,
            AbiV1Constants.SAS_PAIRING_CEREMONY_INVALID_STATE, AbiV1Constants.SAS_PAIRING_NO_LIVE_SAS, AbiV1Constants.SAS_PAIRING_APPROVALS_NOT_AUTHENTICATED,
            AbiV1Constants.SAS_PAIRING_INVALID_HANDLE, AbiV1Constants.SAS_PAIRING_LISTENER_NOT_ATTACHED, 777,
        ];
        TheoryData<string, int> cases = [];
        for (int i = 0; i < statuses.Length; i++)
        {
            cases.Add(RunActions[i % RunActions.Length], statuses[i]);
        }

        return cases;
    }

    [Theory]
    [MemberData(nameof(WrongRunCases))]
    public void ALiveOutcomeNamingAnotherRunIsAContractViolationAndRetargetsNothing(string method, uint localEvent, uint flags, ulong reportedRun)
    {
        (FakeTree tree, SasPairingConnection connection) = Connected();
        SasPairingRun run = ResponderRun(tree);
        SasPairingRun other = ResponderRun(tree, 100, 501, RequestB);
        tree.Ceremony.Next(Ok, Support.Actions.Of(localEvent, reportedRun, flags));

        AssertContractViolation(tree, () => Invoke(run, method));

        Assert.False(run.IsEnded || other.IsEnded);
        Assert.Equal(500ul, run.Ref.Handle);
        Assert.Equal(2, connection.Runs.Count);
    }

    public static TheoryData<string, uint, uint, ulong> WrongRunCases()
    {
        TheoryData<string, uint, uint, ulong> cases = [];
        foreach ((string method, (uint Event, bool Live, bool? WritePending)[] outcomes) in Allowed.Where(a => a.Key != "StartInitiator"))
        {
            foreach ((uint localEvent, bool live, bool? writePending) in outcomes.Where(o => o.Live))
            {
                uint flags = writePending == true ? WritePendingFlag : 0;
                cases.Add(method, localEvent, flags, 0);
                cases.Add(method, localEvent, flags, 501);
                cases.Add(method, localEvent, flags, 0x5A5A);
            }
        }

        return cases;
    }

    [Theory]
    [InlineData("RejectSas", 10u, 0u)]
    [InlineData("CancelSas", 11u, 0u)]
    [InlineData("AuthorizeExposure", 12u, 1u)]
    [InlineData("RejectSas", 12u, 3u)]
    public void ATerminalOutcomeWithALiveRunIsAContractViolation(string method, uint localEvent, uint deadline)
    {
        (FakeTree tree, _) = Connected();
        SasPairingRun run = ResponderRun(tree);
        tree.Ceremony.Next(Ok, Support.Actions.Of(localEvent, 500, WritePendingFlag, deadline));

        AssertContractViolation(tree, () => Invoke(run, method));

        // Validation happens before any lifetime change.
        Assert.False(run.IsEnded);
    }

    [Theory]
    [InlineData(0u)]
    [InlineData(13u)]
    [InlineData(uint.MaxValue)]
    public void AnUnknownLocalEventIsAContractViolation(uint localEvent)
    {
        (FakeTree tree, SasPairingConnection connection) = Connected();
        SasPairingRun run = ResponderRun(tree);
        tree.Ceremony.Next(Ok, Support.Actions.Of(localEvent, 500));
        AssertContractViolation(tree, () => run.AuthorizeExposure());

        (FakeTree start, SasPairingConnection other) = Connected();
        start.Ceremony.Next(Ok, Support.Actions.Of(localEvent, 7000, WritePendingFlag));
        AssertContractViolation(start, () => other.StartInitiator(FakeTree.Bootstrap()));
        Assert.False(Enum.IsDefined((SasPairingLocalEvent)(int)localEvent));
        Assert.NotNull(connection);
    }

    [Theory]
    [InlineData(0x2u)]
    [InlineData(0x80000000u)]
    [InlineData(0x80000001u)]
    public void AnUnknownActionFlagIsAContractViolation(uint flags)
    {
        (FakeTree tree, _) = Connected();
        SasPairingRun run = ResponderRun(tree);
        tree.Ceremony.Next(Ok, Support.Actions.Of(AbiV1Constants.SAS_PAIRING_LOCAL_EVENT_EXPOSURE_AUTHORIZED, 500, flags));

        AssertContractViolation(tree, () => run.AuthorizeExposure());
    }

    [Theory]
    [InlineData("AuthorizeExposure", 2u, 0u)]
    [InlineData("ExposeKey", 3u, WritePendingFlag)]
    [InlineData("RejectSas", 10u, 0u)]
    public void ANonZeroReservedFieldIsAContractViolation(string method, uint localEvent, uint flags)
    {
        (FakeTree tree, _) = Connected();
        SasPairingRun run = ResponderRun(tree);
        tree.Ceremony.Next(Ok, Support.Actions.Of(localEvent, localEvent == 10 ? 0 : 500ul, flags, reserved: 1));

        AssertContractViolation(tree, () => Invoke(run, method));
        Assert.False(run.IsEnded);
    }

    [Theory]
    [MemberData(nameof(WrongWritePendingCases))]
    public void AWritePendingFlagTheMethodDoesNotAllowIsAContractViolation(string method, uint localEvent, uint flags)
    {
        (FakeTree tree, SasPairingConnection connection) = Connected();
        SasPairingRun run = ResponderRun(tree);
        tree.Ceremony.Next(Ok, Support.Actions.Of(localEvent, 500, flags));

        AssertContractViolation(tree, () => Invoke(run, method));
        Assert.NotNull(connection);
    }

    public static TheoryData<string, uint, uint> WrongWritePendingCases()
    {
        TheoryData<string, uint, uint> cases = [];
        foreach ((string method, (uint Event, bool Live, bool? WritePending)[] outcomes) in Allowed.Where(a => a.Key != "StartInitiator"))
        {
            foreach ((uint localEvent, bool _, bool? writePending) in outcomes.Where(o => o.WritePending is not null))
            {
                cases.Add(method, localEvent, writePending == true ? 0 : WritePendingFlag);
            }
        }

        return cases;
    }

    [Theory]
    [MemberData(nameof(DisallowedEvents))]
    public void EveryKnownEventTheMethodDoesNotAllowIsAContractViolation(string method, uint localEvent)
    {
        (FakeTree tree, SasPairingConnection connection) = Connected();
        SasPairingRun run = ResponderRun(tree);

        // Otherwise well formed: a live run for a live-type event, none for a terminal one, a deadline kind only for Deadline.
        bool terminal = localEvent is 10 or 11 or 12;
        uint deadline = localEvent == 12 ? AbiV1Constants.SAS_PAIRING_DEADLINE_INACTIVITY_TIMEOUT : 0;
        ulong reported = method == "StartInitiator" ? 7000ul : terminal ? 0ul : 500ul;
        tree.Ceremony.Next(Ok, Support.Actions.Of(localEvent, reported, WritePendingFlag, deadline));

        AssertContractViolation(tree, () =>
        {
            if (method == "StartInitiator")
            {
                connection.StartInitiator(FakeTree.Bootstrap());
            }
            else
            {
                Invoke(run, method);
            }
        });

        Assert.False(run.IsEnded);
        Assert.Same(run, Assert.Single(connection.Runs));
    }

    public static TheoryData<string, uint> DisallowedEvents()
    {
        TheoryData<string, uint> cases = [];
        foreach ((string method, (uint Event, bool Live, bool? WritePending)[] outcomes) in Allowed)
        {
            for (uint localEvent = 1; localEvent <= 12; localEvent++)
            {
                if (!outcomes.Any(o => o.Event == localEvent))
                {
                    cases.Add(method, localEvent);
                }
            }
        }

        return cases;
    }

    [Theory]
    [MemberData(nameof(AllowedOutcomes))]
    public void EveryAllowedOutcomeIsAccepted(string method, uint localEvent, bool live, bool writePending)
    {
        (FakeTree tree, SasPairingConnection connection) = Connected();
        SasPairingRun run = ResponderRun(tree);
        uint deadline = localEvent == 12 ? AbiV1Constants.SAS_PAIRING_DEADLINE_CLOCK_UNAVAILABLE : 0;
        ulong reported = !live ? 0ul : method == "StartInitiator" ? 7000ul : 500ul;
        tree.Ceremony.Next(Ok, Support.Actions.Of(localEvent, reported, writePending ? WritePendingFlag : 0, deadline));

        SasPairingLocalAction action = method == "StartInitiator" ? connection.StartInitiator(FakeTree.Bootstrap()) : Invoke(run, method)!;

        Assert.Equal((SasPairingLocalEvent)(int)localEvent, action.Event);
        Assert.Equal(writePending, action.WritePending);
        Assert.Equal(live, action.Run is not null);
        Assert.Equal(method != "StartInitiator" && !live, run.IsEnded);
        if (live && method != "StartInitiator")
        {
            Assert.Same(run, action.Run);
        }

        Assert.False(tree.Context.IsContractViolated);
    }

    public static TheoryData<string, uint, bool, bool> AllowedOutcomes()
    {
        TheoryData<string, uint, bool, bool> cases = [];
        foreach ((string method, (uint Event, bool Live, bool? WritePending)[] outcomes) in Allowed)
        {
            foreach ((uint localEvent, bool live, bool? writePending) in outcomes)
            {
                foreach (bool flag in writePending is { } required ? [required] : new[] { false, true })
                {
                    cases.Add(method, localEvent, live, flag);
                }
            }
        }

        return cases;
    }

    [Fact]
    public void AKnownEndedRunRefusesLocallyEvenAfterTheProcessLatched()
    {
        (FakeTree tree, _) = Connected();
        SasPairingRun ended = ResponderRun(tree);
        SasPairingRun live = ResponderRun(tree, 100, 501, RequestB);
        ended.RejectSas(Identity());
        int calls = tree.Ceremony.Total;

        // Native FATAL observed elsewhere: the ended run still reports its own ending first.
        tree.Ceremony.Next(AbiV1Constants.SAS_PAIRING_FATAL);
        Assert.Throws<SasPairingNativeException>(() => live.AuthorizeExposure());
        Assert.Throws<SasPairingRunEndedException>(() => ended.AuthorizeExposure());

        _ = tree.Context.ViolateContract("test", "a probe");
        foreach (string method in RunActions.Append("Presentation"))
        {
            Assert.Throws<SasPairingRunEndedException>(() => Invoke(ended, method));
            Assert.Throws<SasPairingContractException>(() => Invoke(live, method));
        }

        Assert.Equal(calls + 1, tree.Ceremony.Total);
    }

    [Fact]
    public void AfterAContractViolationEveryNormalCeremonyOperationIsRefusedLocally()
    {
        (FakeTree tree, SasPairingConnection connection) = Connected();
        SasPairingRun run = ResponderRun(tree);
        _ = tree.Context.ViolateContract("test", "a probe");

        Assert.Throws<SasPairingContractException>(() => connection.StartInitiator(FakeTree.Bootstrap()));
        foreach (string method in RunActions.Append("Presentation"))
        {
            Assert.Throws<SasPairingContractException>(() => Invoke(run, method));
        }

        Assert.Equal(0, tree.Ceremony.Total);
        Assert.False(run.IsEnded);
        connection.Dispose();
        Assert.Equal(1, tree.Network.Count(FakeNetworkApi.CloseExport));
    }

    [Fact]
    public void ADisposedConnectionRefusesAStartLocallyAndItsRunsEnd()
    {
        (FakeTree tree, SasPairingConnection connection) = Connected();
        SasPairingRun local = connection.StartInitiator(FakeTree.Bootstrap()).Run!;
        SasPairingRun responder = ResponderRun(tree);

        connection.Dispose();

        Assert.True(local.IsEnded && responder.IsEnded);
        ObjectDisposedException disposed = Assert.Throws<ObjectDisposedException>(() => connection.StartInitiator(FakeTree.Bootstrap()));
        Assert.Contains(nameof(SasPairingConnection), disposed.ObjectName, StringComparison.Ordinal);
        Assert.Throws<SasPairingRunEndedException>(() => local.ExposeKey());
        Assert.Equal(1, tree.Ceremony.Total);
        Assert.Throws<ArgumentNullException>(() => connection.StartInitiator(null!));
        Assert.Throws<ArgumentNullException>(() => responder.ApproveSas(null!));
        Assert.Throws<ArgumentNullException>(() => responder.RejectSas(null!));
        Assert.Throws<ArgumentNullException>(() => responder.CancelSas(null!));
    }

    [Fact]
    public void EveryTeardownEndsTheRunsItInvalidates()
    {
        FakeTree tree = new();
        SasPairingConnection[] connections = tree.AttachWithConnections(100, 101, 102);
        SasPairingRun closedByPeer = ResponderRun(tree, 100, 500, RequestA);
        SasPairingRun detached = connections[1].StartInitiator(FakeTree.Bootstrap()).Run!;
        tree.Network.Next(Ok, Ok, Records.Closed(100));
        tree.Host.Drive();
        Assert.True(closedByPeer.IsEnded);
        Assert.False(detached.IsEnded);
        tree.Host.DetachListener();
        Assert.True(detached.IsEnded);

        foreach (Action<FakeTree> teardown in new Action<FakeTree>[] { t => t.Host.Dispose(), t => t.Authority.Dispose(), t => t.Runtime.Dispose() })
        {
            FakeTree other = new();
            SasPairingConnection c = other.AttachWithConnections(100).Single();
            SasPairingRun run = c.StartInitiator(FakeTree.Bootstrap()).Run!;
            teardown(other);
            Assert.True(run.IsEnded);
            Assert.Throws<SasPairingRunEndedException>(() => run.Presentation());
            Assert.Equal(1, other.Ceremony.Total);
        }

        // An owner-loop failure reported by a drive ends every run too.
        FakeTree failing = new();
        SasPairingConnection f = failing.AttachWithConnections(100).Single();
        SasPairingRun failed = f.StartInitiator(FakeTree.Bootstrap()).Run!;
        failing.Network.Next(Ok, AbiV1Constants.SAS_PAIRING_NETWORK_POLL_FAILED);
        failing.Host.Drive();
        Assert.True(failed.IsEnded);
    }

    [Fact]
    public void AResultEventEndsTheRunUnderItsRequestIdAndStaysPrivate()
    {
        (FakeTree tree, SasPairingConnection connection) = Connected();
        SasPairingRun initiator = connection.StartInitiator(FakeTree.Bootstrap()).Run!;
        tree.Network.Next(Ok, Ok, Records.Inbound(100, AbiV1Constants.SAS_PAIRING_PROTOCOL_EVENT_ACCEPT, RequestA, run: initiator.Ref.Handle));
        tree.Host.Drive();
        SasPairingRun responder = ResponderRun(tree, 100, 600, RequestB);

        tree.Network.Next(
            Ok,
            Ok,
            Records.Step(100, AbiV1Constants.SAS_PAIRING_STEP_CONFIRMED, result: 0x700, requestId: RequestA),
            Records.Inbound(100, AbiV1Constants.SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH_ACK, RequestB, result: 0x701));
        IReadOnlyList<SasPairingEvent> events = tree.Host.Drive().Events;

        Assert.All(events, e => Assert.True(e.HasResult));
        Assert.All(events, e => Assert.Null(e.Run));
        Assert.True(initiator.IsEnded && responder.IsEnded);
        Assert.Empty(connection.Runs);
        Assert.DoesNotContain(tree.Ceremony.Calls, c => c.Export.Contains("result", StringComparison.Ordinal));
    }
}
