using System.Reflection;
using System.Text.RegularExpressions;
using SasPairing.Interop;
using SasPairing.Tests.Support;

namespace SasPairing.Tests;

/// <summary>
/// P9-D-003 cooperative drive over the fake network service (every platform): one native call per drive or
/// recheck, the function status versus <c>out_failure</c>, events delivered before an owner-loop failure takes
/// effect, the frozen event namespaces, the structural record checks, and the network states.
/// </summary>
public sealed partial class NetworkDriveTests
{
    private const int Ok = 0;

    private static readonly byte[] RequestA = [0x00, 0x80, 0xFF, 0x41];

    [Fact]
    public void OneDriveIsExactlyOneNativeDriveAndAnEmptyBatchIsValid()
    {
        FakeTree tree = new();
        tree.Attach();

        SasPairingDriveBatch batch = tree.Host.Drive();

        Assert.Empty(batch.Events);
        Assert.Null(batch.Failure);
        FakeNetworkCall call = Assert.Single(tree.Network.Calls, c => c.Export == FakeNetworkApi.DriveExport);
        Assert.Equal([tree.Runtime.Handle, tree.Host.Handle], call.Arguments);
        Assert.Equal(0, tree.Network.Count(FakeNetworkApi.RecheckExport));
        Assert.Equal(SasPairingHostNetworkState.Attached, tree.Host.NetworkState);
    }

    [Fact]
    public void RecheckIsExactlyOneNativeRecheckWithTheSameBatchModel()
    {
        FakeTree tree = new();
        SasPairingConnection connection = tree.AttachWithConnections(100).Single();
        tree.Network.Next(Ok, Ok, Records.Event(AbiV1Constants.SAS_PAIRING_EVENT_CONNECTION_STEP, 100, AbiV1Constants.SAS_PAIRING_STEP_DEADLINE, deadline: AbiV1Constants.SAS_PAIRING_DEADLINE_INACTIVITY_TIMEOUT, cancelState: AbiV1Constants.SAS_PAIRING_CANCEL_STATE_PENDING, requestId: RequestA, flags: AbiV1Constants.SAS_PAIRING_EVENT_FLAG_WRITE_PENDING));
        int drives = tree.Network.Count(FakeNetworkApi.DriveExport);

        SasPairingDriveBatch batch = tree.Host.RecheckAfterResume();

        Assert.Equal(1, tree.Network.Count(FakeNetworkApi.RecheckExport));
        Assert.Equal(drives, tree.Network.Count(FakeNetworkApi.DriveExport));
        SasPairingEvent deadline = Assert.Single(batch.Events);
        Assert.Same(connection, deadline.Connection);
        Assert.Equal(SasPairingStepKind.Deadline, deadline.StepKind);
        Assert.Equal(SasPairingDeadlineKind.InactivityTimeout, deadline.DeadlineKind);
        Assert.Equal(SasPairingCancelState.Pending, deadline.CancelState);
        Assert.True(deadline.WritePending);
        Assert.Equal(RequestA, deadline.RequestId.ToArray());
    }

    [Theory]
    [InlineData(402)]
    [InlineData(4)]
    [InlineData(103)]
    [InlineData(2)]
    [InlineData(300)]
    [InlineData(777)]
    public void ANonZeroFunctionStatusReturnsNoBatchAndChangesNoNetworkState(int status)
    {
        FakeTree tree = new();
        SasPairingConnection connection = tree.AttachWithConnections(100).Single();
        tree.Network.Next(status, Ok);

        SasPairingNativeException failure = Assert.Throws<SasPairingNativeException>(tree.Host.Drive);

        Assert.Equal(status, failure.StatusCode);
        Assert.Equal("SasPairingHost.Drive", failure.Operation);
        Assert.Equal(SasPairingHostNetworkState.Attached, tree.Host.NetworkState);
        Assert.False(connection.IsDisposed);
        Assert.False(tree.Context.IsFatal || tree.Context.IsContractViolated);
    }

    [Fact]
    public void AFunctionStatusFatalLatchesAndReturnsNoBatch()
    {
        FakeTree tree = new();
        SasPairingConnection connection = tree.AttachWithConnections(100).Single();
        tree.Network.Next(AbiV1Constants.SAS_PAIRING_FATAL, Ok);

        SasPairingNativeException failure = Assert.Throws<SasPairingNativeException>(tree.Host.RecheckAfterResume);

        Assert.True(failure.ProcessRestartRequired);
        Assert.Equal("SasPairingHost.RecheckAfterResume", failure.Operation);
        Assert.True(tree.Context.IsFatal);
        Assert.Equal(SasPairingHostNetworkState.Attached, tree.Host.NetworkState);
        Assert.False(connection.IsDisposed);
    }

    [Theory]
    [InlineData(404)]
    [InlineData(104)]
    [InlineData(900)]
    [InlineData(5555)]
    public void EventsReturnedWithAnOwnerLoopFailureAreAllDeliveredBeforeTheHostFailsClosed(int outFailure)
    {
        FakeTree tree = new();
        SasPairingConnection older = tree.AttachWithConnections(50).Single();
        tree.Network.Next(Ok, outFailure, Records.Accepted(100), Records.Step(100), Records.Refused());

        SasPairingDriveBatch batch = tree.Host.Drive();

        Assert.Equal([SasPairingEventKind.ConnectionAccepted, SasPairingEventKind.ConnectionStep, SasPairingEventKind.AcceptRefused], batch.Events.Select(e => e.Kind));
        SasPairingConnection accepted = batch.Events[0].Connection!;
        Assert.Same(accepted, batch.Events[1].Connection);
        Assert.True(accepted.IsDisposed);
        Assert.True(older.IsDisposed);
        Assert.Empty(tree.Host.Network.Connections);
        Assert.Equal(SasPairingHostNetworkState.FailedClosed, tree.Host.NetworkState);
        Assert.NotNull(batch.Failure);
        Assert.Equal(outFailure, batch.Failure.StatusCode);
        Assert.Equal(SasPairingNativeException.Describe(outFailure), batch.Failure.KnownStatus);
        Assert.Equal(outFailure == 900, batch.Failure.ProcessRestartRequired);
        Assert.Equal(outFailure == 900, tree.Context.IsFatal);
        Assert.False(tree.Context.IsContractViolated);
        Assert.Equal(0, tree.Network.Count(FakeNetworkApi.CloseExport));
    }

    [Fact]
    public void OwnerLoopClosedAndAnUnknownFailureWithNoEventFailTheHostClosed()
    {
        foreach (int outFailure in new[] { AbiV1Constants.SAS_PAIRING_OWNER_LOOP_CLOSED, 777 })
        {
            FakeTree tree = new();
            SasPairingConnection connection = tree.AttachWithConnections(100).Single();
            tree.Network.Next(Ok, outFailure);

            SasPairingDriveBatch batch = tree.Host.Drive();

            Assert.Empty(batch.Events);
            Assert.Equal(outFailure, batch.Failure!.StatusCode);
            Assert.Equal(outFailure == 777 ? null : SasPairingStatus.OwnerLoopClosed, batch.Failure.KnownStatus);
            Assert.False(batch.Failure.ProcessRestartRequired);
            Assert.True(connection.IsDisposed);
            Assert.Equal(SasPairingHostNetworkState.FailedClosed, tree.Host.NetworkState);

            // Nothing is fabricated afterwards: the next drive is a real native call.
            int drives = tree.Network.Count(FakeNetworkApi.DriveExport);
            tree.Network.Next(Ok, AbiV1Constants.SAS_PAIRING_OWNER_LOOP_CLOSED);
            Assert.Equal(403, tree.Host.Drive().Failure!.StatusCode);
            Assert.Equal(drives + 1, tree.Network.Count(FakeNetworkApi.DriveExport));
        }
    }

    [Fact]
    public void AFatalOwnerLoopFailureReturnsTheBatchLatchesFatalAndLeavesOnlyCleanup()
    {
        FakeTree tree = new();
        tree.Attach();
        tree.Network.Next(Ok, AbiV1Constants.SAS_PAIRING_FATAL, Records.Accepted(100));

        SasPairingDriveBatch batch = tree.Host.Drive();

        SasPairingEvent accepted = Assert.Single(batch.Events);
        Assert.Equal(900, batch.Failure!.StatusCode);
        Assert.True(batch.Failure.ProcessRestartRequired);
        Assert.True(tree.Context.IsFatal);
        Assert.Equal(SasPairingHostNetworkState.FailedClosed, tree.Host.NetworkState);
        Assert.True(accepted.Connection!.IsDisposed);

        // Every later normal operation fails locally with no native call.
        int network = tree.Network.Total;
        int lifecycle = tree.Lifecycle.Total;
        Assert.Equal(900, Assert.Throws<SasPairingNativeException>(tree.Host.Drive).StatusCode);
        Assert.Equal(900, Assert.Throws<SasPairingNativeException>(tree.Host.RecheckAfterResume).StatusCode);
        Assert.Equal(900, Assert.Throws<SasPairingNativeException>(() => tree.Host.AttachWindowsListener(FakeTree.Token(), FakeTree.Bootstrap())).StatusCode);
        Assert.Equal(900, Assert.Throws<SasPairingNativeException>(() => tree.Authority.GetStatus()).StatusCode);
        Assert.Equal(900, Assert.Throws<SasPairingNativeException>(() => tree.Authority.CreateHost()).StatusCode);
        Assert.Equal(network, tree.Network.Total);
        Assert.Equal(lifecycle, tree.Lifecycle.Total);

        // Cleanup still runs natively.
        accepted.Connection.Dispose();
        tree.Host.DetachListener();
        tree.Host.Dispose();
        tree.Authority.Dispose();
        tree.Runtime.Dispose();
        Assert.Equal(network + 1, tree.Network.Total);
        Assert.Equal(lifecycle + 3, tree.Lifecycle.Total);
    }

    [Fact]
    public void EventOrderIsPreservedExactlyAndTheBatchIsReadOnly()
    {
        FakeTree tree = new();
        tree.Attach();
        tree.Network.Next(Ok, Ok, Records.Refused(), Records.Accepted(100), Records.Accepted(101), Records.Step(101), Records.Step(100), Records.Closed(101), Records.ListenerDisabled());

        SasPairingDriveBatch batch = tree.Host.Drive();

        Assert.Equal(
            [SasPairingEventKind.AcceptRefused, SasPairingEventKind.ConnectionAccepted, SasPairingEventKind.ConnectionAccepted, SasPairingEventKind.ConnectionStep, SasPairingEventKind.ConnectionStep, SasPairingEventKind.ConnectionClosed, SasPairingEventKind.ListenerDisabled],
            batch.Events.Select(e => e.Kind));
        Assert.Same(batch.Events[2].Connection, batch.Events[3].Connection);
        Assert.Same(batch.Events[1].Connection, batch.Events[4].Connection);
        Assert.Null(batch.Events[0].Connection);
        Assert.Null(batch.Events[6].Connection);
        Assert.IsNotType<SasPairingEvent[]>(batch.Events);
        Assert.Throws<NotSupportedException>(() => ((IList<SasPairingEvent>)batch.Events).Add(batch.Events[0]));
        Assert.Throws<NotSupportedException>(() => ((IList<SasPairingEvent>)batch.Events)[0] = batch.Events[1]);
    }

    [Fact]
    public void ListenerDisabledKeepsExistingConnectionsAlive()
    {
        FakeTree tree = new();
        SasPairingConnection connection = tree.AttachWithConnections(100).Single();
        tree.Network.Next(Ok, Ok, Records.ListenerDisabled());

        SasPairingEvent disabled = Assert.Single(tree.Host.Drive().Events);

        Assert.Equal(SasPairingEventReason.ListenerIo, disabled.Reason);
        Assert.Equal(SasPairingHostNetworkState.ListenerDisabled, tree.Host.NetworkState);
        Assert.False(connection.IsDisposed);

        tree.Network.Next(Ok, Ok, Records.Step(100));
        Assert.Same(connection, Assert.Single(tree.Host.Drive().Events).Connection);
        Assert.Equal(SasPairingHostNetworkState.ListenerDisabled, tree.Host.NetworkState);

        tree.Host.DetachListener();
        Assert.True(connection.IsDisposed);
        Assert.Equal(SasPairingHostNetworkState.Detached, tree.Host.NetworkState);
    }

    [Fact]
    public void DriveAdmissionIsDisposedThenLatchesWithNoNativeCall()
    {
        FakeTree tree = new();
        tree.Attach();
        SasPairingHost other = tree.Authority.CreateHost();
        other.Dispose();
        Assert.Throws<ObjectDisposedException>(other.Drive);
        Assert.Throws<ObjectDisposedException>(other.RecheckAfterResume);

        _ = tree.Context.ViolateContract("test", "a probe");
        Assert.Throws<SasPairingContractException>(tree.Host.Drive);
        Assert.Throws<SasPairingContractException>(tree.Host.RecheckAfterResume);
        Assert.Equal(0, tree.Network.Count(FakeNetworkApi.DriveExport) + tree.Network.Count(FakeNetworkApi.RecheckExport));
    }

    [Fact]
    public void ThePublicEventEnumsCarryExactlyTheFrozenValues()
    {
        Dictionary<string, uint> frozen = typeof(AbiV1Constants)
            .GetFields(BindingFlags.NonPublic | BindingFlags.Static)
            .Where(f => f.FieldType == typeof(uint) && f.IsLiteral)
            .ToDictionary(f => f.Name, f => (uint)f.GetRawConstantValue()!);

        AssertNamespace<SasPairingEventKind>(frozen, "SAS_PAIRING_EVENT_", ["SAS_PAIRING_EVENT_INVALID"], ["SAS_PAIRING_EVENT_REASON_", "SAS_PAIRING_EVENT_FLAG_"]);
        AssertNamespace<SasPairingStepKind>(frozen, "SAS_PAIRING_STEP_", [], []);
        AssertNamespace<SasPairingProtocolEvent>(frozen, "SAS_PAIRING_PROTOCOL_EVENT_", [], []);
        AssertNamespace<SasPairingEventReason>(frozen, "SAS_PAIRING_EVENT_REASON_", [], []);
        AssertNamespace<SasPairingDeadlineKind>(frozen, "SAS_PAIRING_DEADLINE_", [], []);
        AssertNamespace<SasPairingCancelState>(frozen, "SAS_PAIRING_CANCEL_STATE_", [], []);
        AssertNamespace<SasPairingCancelReason>(frozen, "SAS_PAIRING_CANCEL_REASON_", [], []);
        Assert.Equal(["Detached", "Attached", "ListenerDisabled", "FailedClosed"], Enum.GetNames<SasPairingHostNetworkState>());
    }

    private static void AssertNamespace<T>(Dictionary<string, uint> frozen, string prefix, string[] notPublic, string[] otherNamespaces)
        where T : struct, Enum
    {
        string[] names = [.. frozen.Keys.Where(n => n.StartsWith(prefix, StringComparison.Ordinal) && !otherNamespaces.Any(o => n.StartsWith(o, StringComparison.Ordinal)) && !notPublic.Contains(n))];
        T[] values = Enum.GetValues<T>();
        Assert.Equal(names.Length, values.Length);
        foreach (T value in values)
        {
            string native = prefix + PascalBoundary().Replace(value.ToString(), "_$1").ToUpperInvariant();
            Assert.True(frozen.TryGetValue(native, out uint expected), $"{typeof(T).Name}.{value} has no frozen constant {native}");
            Assert.Equal(expected, Convert.ToUInt32(value, System.Globalization.CultureInfo.InvariantCulture));
        }
    }

    [Theory]
    [InlineData("kind", 0u)]
    [InlineData("kind", 6u)]
    [InlineData("step", 8u)]
    [InlineData("protocol", 13u)]
    [InlineData("reason", 16u)]
    [InlineData("deadline", 5u)]
    [InlineData("cancelState", 4u)]
    [InlineData("cancelReason", 5u)]
    [InlineData("flags", 0x4u)]
    [InlineData("flags", 0x8000_0000u)]
    [InlineData("reserved", 1u)]
    [InlineData("requestIdLength", 65u)]
    [InlineData("requestIdLength", uint.MaxValue)]
    public void AnUnknownValueOrABrokenRecordLatchesTheContractViolation(string field, uint value)
    {
        FakeTree tree = new();
        tree.AttachWithConnections(100);
        NativeEventRecord step = Records.Step(100);
        tree.Network.Next(Ok, Ok, field switch
        {
            "kind" => step with { Kind = value },
            "step" => step with { StepKind = value },
            "protocol" => step with { ProtocolEvent = value },
            "reason" => step with { Reason = value },
            "deadline" => step with { DeadlineKind = value },
            "cancelState" => step with { CancelState = value },
            "cancelReason" => step with { CancelReason = value },
            "flags" => step with { Flags = value },
            "reserved" => step with { Reserved = value },
            _ => step with { RequestIdLength = value },
        });

        Assert.Throws<SasPairingContractException>(tree.Host.Drive);

        Assert.True(tree.Context.IsContractViolated);
        Assert.Throws<SasPairingContractException>(tree.Host.Drive);
        tree.Host.DetachListener(); // cleanup still runs
    }

    public static TheoryData<string> BrokenRecords() =>
    [
        "accepted without a connection", "step without a connection", "closed without a connection", "refused with a connection",
        "disabled with a connection", "accepted with a run", "closed with a result", "refused with flags", "a run and a result",
        "untracked with a run", "a byte past the request ID", "more than 17", "events with OWNER_LOOP_CLOSED",
        "a known non-loop failure", "a duplicate accept", "an unknown step connection", "an unknown closed connection",
        "a run under another request ID",
    ];

    [Theory]
    [MemberData(nameof(BrokenRecords))]
    public void AStructurallyImpossibleBatchLatchesTheContractViolation(string broken)
    {
        FakeTree tree = new();
        tree.AttachWithConnections(100);
        byte[] past = new byte[64];
        past[10] = 1;
        NativeEventRecord[] events = broken switch
        {
            "accepted without a connection" => [Records.Accepted(0)],
            "step without a connection" => [Records.Step(0)],
            "closed without a connection" => [Records.Closed(0)],
            "refused with a connection" => [Records.Refused() with { Connection = 100 }],
            "disabled with a connection" => [Records.ListenerDisabled() with { Connection = 100 }],
            "accepted with a run" => [Records.Accepted(101) with { Run = 5 }],
            "closed with a result" => [Records.Closed(100) with { Result = 5 }],
            "refused with flags" => [Records.Refused() with { Flags = AbiV1Constants.SAS_PAIRING_EVENT_FLAG_WRITE_PENDING }],
            "a run and a result" => [Records.Inbound(100, AbiV1Constants.SAS_PAIRING_PROTOCOL_EVENT_ACCEPT, RequestA, run: 5, result: 6)],
            "untracked with a run" => [Records.Inbound(100, AbiV1Constants.SAS_PAIRING_PROTOCOL_EVENT_START_ACCEPTED, RequestA, run: 5, flags: AbiV1Constants.SAS_PAIRING_EVENT_FLAG_RUN_UNTRACKED)],
            "a byte past the request ID" => [Records.Step(100) with { RequestId = past, RequestIdLength = 10 }],
            "a duplicate accept" => [Records.Accepted(100)],
            "an unknown step connection" => [Records.Step(777)],
            "an unknown closed connection" => [Records.Closed(777)],
            "a run under another request ID" => [Records.Inbound(100, AbiV1Constants.SAS_PAIRING_PROTOCOL_EVENT_ACCEPT, RequestA, run: 5), Records.Inbound(100, AbiV1Constants.SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_KEY, [0x42], run: 5)],
            _ => [],
        };
        switch (broken)
        {
            case "more than 17":
                tree.Network.NextRaw(new NativeDriveOutcome(Ok, 18, Ok, [.. Enumerable.Range(0, 17).Select(_ => Records.Refused())]));
                break;
            case "events with OWNER_LOOP_CLOSED":
                tree.Network.Next(Ok, AbiV1Constants.SAS_PAIRING_OWNER_LOOP_CLOSED, Records.Refused());
                break;
            case "a known non-loop failure":
                tree.Network.Next(Ok, AbiV1Constants.SAS_PAIRING_INVALID_HANDLE, Records.Refused());
                break;
            default:
                tree.Network.Next(Ok, Ok, events);
                break;
        }

        Assert.Throws<SasPairingContractException>(tree.Host.Drive);
        Assert.True(tree.Context.IsContractViolated);
        if (broken is "events with OWNER_LOOP_CLOSED" or "a known non-loop failure")
        {
            // The owner-loop failure still takes effect.
            Assert.Equal(SasPairingHostNetworkState.FailedClosed, tree.Host.NetworkState);
        }
    }

    [Fact]
    public void RecordFieldsOutsideTheirEventAreAcceptedWhenStructurallyLegal()
    {
        FakeTree tree = new();
        tree.AttachWithConnections(100);
        byte[] longest = [.. Enumerable.Range(0, 64).Select(i => (byte)(255 - i))];
        tree.Network.Next(
            Ok,
            Ok,
            Records.Step(100, AbiV1Constants.SAS_PAIRING_STEP_NONE, flags: AbiV1Constants.SAS_PAIRING_EVENT_FLAG_WRITE_PENDING),
            Records.Inbound(100, AbiV1Constants.SAS_PAIRING_PROTOCOL_EVENT_START_DUPLICATE, longest),
            Records.Inbound(100, AbiV1Constants.SAS_PAIRING_PROTOCOL_EVENT_PEER_CANCEL, [0x00]) with { CancelReason = AbiV1Constants.SAS_PAIRING_CANCEL_REASON_USER_REJECTION },
            Records.Step(100, AbiV1Constants.SAS_PAIRING_STEP_UNCONFIRMED) with { Reason = AbiV1Constants.SAS_PAIRING_EVENT_REASON_ROUTE_REFUSED });

        IReadOnlyList<SasPairingEvent> events = tree.Host.Drive().Events;

        Assert.Equal(SasPairingStepKind.None, events[0].StepKind);
        Assert.True(events[0].WritePending);
        Assert.True(events[0].RequestId.IsEmpty);
        Assert.Equal(longest, events[1].RequestId.ToArray());
        Assert.Equal(SasPairingProtocolEvent.StartDuplicate, events[1].ProtocolEvent);
        Assert.Equal(SasPairingCancelReason.UserRejection, events[2].CancelReason);
        Assert.Equal(new byte[] { 0x00 }, events[2].RequestId.ToArray());
        Assert.Equal(SasPairingEventReason.RouteRefused, events[3].Reason);
        Assert.All(events, e => Assert.False(e.HasTrackedRun || e.HasResult || e.RunUntracked || e.ShouldDisposeConnection));
        Assert.False(tree.Context.IsContractViolated);
    }

    [GeneratedRegex(@"(?<=[a-z0-9])([A-Z])")]
    private static partial Regex PascalBoundary();
}
