using SasPairing.Interop;
using SasPairing.Tests.Support;

namespace SasPairing.Tests;

/// <summary>
/// P9-D-003 connection, run, and result ownership over the fake network service (every platform): one object
/// per native connection, deterministic consuming cleanup, owner-loop failure, <c>RUN_UNTRACKED</c> guidance,
/// exact-handle run references, runtime-owned result references, and the one-call parent cascade.
/// </summary>
public sealed class ConnectionOwnershipTests
{
    private const int Ok = 0;

    private static readonly byte[] RequestA = [0x00, 0x80, 0xFF, 0x41];
    private static readonly byte[] RequestB = [0x42];

    [Fact]
    public void EveryEventOfOneNativeConnectionCarriesTheSameObject()
    {
        FakeTree tree = new();
        tree.Attach();
        tree.Network.Next(Ok, Ok, Records.Accepted(100), Records.Step(100));
        tree.Network.Next(Ok, Ok, Records.Step(100, AbiV1Constants.SAS_PAIRING_STEP_NONE), Records.Closed(100));

        SasPairingDriveBatch first = tree.Host.Drive();
        SasPairingConnection connection = first.Events[0].Connection!;
        Assert.False(connection.IsDisposed);
        Assert.Same(connection, first.Events[1].Connection);
        Assert.Same(connection, Assert.Single(tree.Host.Network.Connections));

        SasPairingDriveBatch second = tree.Host.Drive();

        Assert.Same(connection, second.Events[0].Connection);
        SasPairingEvent closed = second.Events[1];
        Assert.Same(connection, closed.Connection);
        Assert.Equal(SasPairingEventReason.PeerClosed, closed.Reason);
        Assert.True(connection.IsDisposed);
        Assert.Empty(tree.Host.Network.Connections);

        // Native already ended it: no close call now or on a later Dispose.
        connection.Dispose();
        Assert.Equal(0, tree.Network.Count(FakeNetworkApi.CloseExport));
        Assert.DoesNotContain("100", connection.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void DisposeClosesOnceNativelyAndIsIdempotent()
    {
        FakeTree tree = new();
        SasPairingConnection[] connections = tree.AttachWithConnections(100, 101);

        connections[0].Dispose();
        connections[0].Dispose();

        FakeNetworkCall close = Assert.Single(tree.Network.Calls, c => c.Export == FakeNetworkApi.CloseExport);
        Assert.Equal([tree.Runtime.Handle, tree.Host.Handle, 100ul], close.Arguments);
        Assert.True(connections[0].IsDisposed);
        Assert.False(connections[1].IsDisposed);
        Assert.Same(connections[1], Assert.Single(tree.Host.Network.Connections));
        Assert.Equal(SasPairingHostNetworkState.Attached, tree.Host.NetworkState);
    }

    [Theory]
    [InlineData(2)]
    [InlineData(402)]
    [InlineData(103)]
    [InlineData(777)]
    public void AFailedCloseIsConsumingAndNeverRetried(int status)
    {
        FakeTree tree = new();
        SasPairingConnection[] connections = tree.AttachWithConnections(100, 101);
        tree.Network.CloseStatus = status;

        SasPairingNativeException failure = Assert.Throws<SasPairingNativeException>(connections[0].Dispose);

        Assert.Equal(status, failure.StatusCode);
        Assert.Equal("SasPairingConnection.Dispose", failure.Operation);
        Assert.True(connections[0].IsDisposed);
        connections[0].Dispose();
        Assert.Equal(1, tree.Network.Count(FakeNetworkApi.CloseExport));
        Assert.False(connections[1].IsDisposed);
        Assert.Equal(SasPairingHostNetworkState.Attached, tree.Host.NetworkState);
    }

    [Fact]
    public void OwnershipUncertainFromACloseFailsTheWholeHostClosedLocally()
    {
        FakeTree tree = new();
        SasPairingConnection[] connections = tree.AttachWithConnections(100, 101);
        tree.Network.CloseStatus = AbiV1Constants.SAS_PAIRING_OWNERSHIP_UNCERTAIN;

        SasPairingNativeException failure = Assert.Throws<SasPairingNativeException>(connections[0].Dispose);

        Assert.Equal(SasPairingStatus.OwnershipUncertain, failure.KnownStatus);
        Assert.All(connections, c => Assert.True(c.IsDisposed));
        Assert.Equal(SasPairingHostNetworkState.FailedClosed, tree.Host.NetworkState);
        connections[1].Dispose();
        Assert.Equal(1, tree.Network.Count(FakeNetworkApi.CloseExport));
    }

    [Fact]
    public void AFatalCloseLatchesButLeavesSiblingsForExplicitCleanup()
    {
        FakeTree tree = new();
        SasPairingConnection[] connections = tree.AttachWithConnections(100, 101);
        tree.Network.CloseStatus = AbiV1Constants.SAS_PAIRING_FATAL;

        Assert.True(Assert.Throws<SasPairingNativeException>(connections[0].Dispose).ProcessRestartRequired);

        Assert.True(tree.Context.IsFatal);
        Assert.True(connections[0].IsDisposed);
        Assert.False(connections[1].IsDisposed);

        // Cleanup after FATAL still enters native.
        tree.Network.CloseStatus = Ok;
        connections[1].Dispose();
        Assert.Equal(2, tree.Network.Count(FakeNetworkApi.CloseExport));
        Assert.Throws<SasPairingNativeException>(tree.Host.Drive);
    }

    [Fact]
    public void CloseRunsAfterAContractViolation()
    {
        FakeTree tree = new();
        SasPairingConnection connection = tree.AttachWithConnections(100).Single();
        _ = tree.Context.ViolateContract("test", "a probe");

        connection.Dispose();

        Assert.Equal(1, tree.Network.Count(FakeNetworkApi.CloseExport));
        Assert.True(connection.IsDisposed);
    }

    [Fact]
    public void RunUntrackedTellsTheConsumerToDisposeAndTheDriveDisposesNothing()
    {
        FakeTree tree = new();
        SasPairingConnection connection = tree.AttachWithConnections(100).Single();
        tree.Network.Next(Ok, Ok, Records.Inbound(100, AbiV1Constants.SAS_PAIRING_PROTOCOL_EVENT_START_ACCEPTED, RequestA, flags: AbiV1Constants.SAS_PAIRING_EVENT_FLAG_RUN_UNTRACKED | AbiV1Constants.SAS_PAIRING_EVENT_FLAG_WRITE_PENDING));

        SasPairingEvent untracked = Assert.Single(tree.Host.Drive().Events);

        Assert.True(untracked.RunUntracked);
        Assert.False(untracked.HasTrackedRun);
        Assert.True(untracked.ShouldDisposeConnection);
        Assert.True(untracked.WritePending);
        Assert.Same(connection, untracked.Connection);
        Assert.False(connection.IsDisposed);
        Assert.Empty(connection.Runs);
        Assert.Equal(0, tree.Network.Count(FakeNetworkApi.CloseExport));

        // The consumer's explicit disposal is the one native close.
        untracked.Connection!.Dispose();
        Assert.Equal(1, tree.Network.Count(FakeNetworkApi.CloseExport));
    }

    [Fact]
    public void RunReferencesFollowTheExactNativeHandleNeverTheRequestId()
    {
        FakeTree tree = new();
        SasPairingConnection connection = tree.AttachWithConnections(100).Single();
        tree.Network.Next(Ok, Ok, Records.Inbound(100, AbiV1Constants.SAS_PAIRING_PROTOCOL_EVENT_START_ACCEPTED, RequestA, run: 500));
        tree.Network.Next(Ok, Ok, Records.Inbound(100, AbiV1Constants.SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_KEY, RequestA, run: 500));

        SasPairingEvent started = Assert.Single(tree.Host.Drive().Events);
        SasPairingEvent keyed = Assert.Single(tree.Host.Drive().Events);

        Assert.True(started.HasTrackedRun);
        NativeRunRef first = started.Run!.Ref;
        Assert.Same(first, keyed.Run!.Ref);
        Assert.Equal(500ul, first.Handle);
        Assert.Equal(RequestA, first.RequestId.ToArray());

        // A new exact run under the reused request ID gets its own reference; the old one is retired, never retargeted.
        tree.Network.Next(Ok, Ok, Records.Inbound(100, AbiV1Constants.SAS_PAIRING_PROTOCOL_EVENT_START_ACCEPTED, RequestA, run: 501));
        NativeRunRef second = Assert.Single(tree.Host.Drive().Events).Run!.Ref;
        Assert.NotSame(first, second);
        Assert.Equal(500ul, first.Handle);
        Assert.False(first.IsValid);
        Assert.True(second.IsValid);
        Assert.Same(second, Assert.Single(connection.Runs).Ref);

        // A duplicate START names no run and ends nothing; a run under another request ID is independent.
        tree.Network.Next(Ok, Ok, Records.Inbound(100, AbiV1Constants.SAS_PAIRING_PROTOCOL_EVENT_START_DUPLICATE, RequestA), Records.Inbound(100, AbiV1Constants.SAS_PAIRING_PROTOCOL_EVENT_START_ACCEPTED, RequestB, run: 502));
        IReadOnlyList<SasPairingEvent> events = tree.Host.Drive().Events;
        Assert.False(events[0].HasTrackedRun);
        Assert.True(second.IsValid);
        NativeRunRef third = events[1].Run!.Ref;
        Assert.Equal(2, connection.Runs.Count);

        // A visible ending (an inbound frame without a run) retires exactly the runs under its request ID.
        tree.Network.Next(Ok, Ok, Records.Inbound(100, AbiV1Constants.SAS_PAIRING_PROTOCOL_EVENT_PEER_CANCEL, RequestA) with { CancelReason = AbiV1Constants.SAS_PAIRING_CANCEL_REASON_TIMEOUT });
        Assert.False(Assert.Single(tree.Host.Drive().Events).HasTrackedRun);
        Assert.False(second.IsValid);
        Assert.True(third.IsValid);

        // A deadline without a request ID ends nothing visibly; with one, it retires that request ID.
        tree.Network.Next(Ok, Ok, Records.Step(100, AbiV1Constants.SAS_PAIRING_STEP_DEADLINE) with { DeadlineKind = AbiV1Constants.SAS_PAIRING_DEADLINE_ABSOLUTE_TIMEOUT });
        tree.Host.Drive();
        Assert.True(third.IsValid);
        tree.Network.Next(Ok, Ok, Records.Step(100, AbiV1Constants.SAS_PAIRING_STEP_DEADLINE, requestId: RequestB) with { DeadlineKind = AbiV1Constants.SAS_PAIRING_DEADLINE_PENDING_EXPIRED });
        tree.Host.Drive();
        Assert.False(third.IsValid);
        Assert.Empty(connection.Runs);
    }

    [Fact]
    public void TheEndOfAConnectionInvalidatesItsRuns()
    {
        FakeTree tree = new();
        SasPairingConnection[] connections = tree.AttachWithConnections(100, 101, 102);
        tree.Network.Next(
            Ok,
            Ok,
            Records.Inbound(100, AbiV1Constants.SAS_PAIRING_PROTOCOL_EVENT_START_ACCEPTED, RequestA, run: 500),
            Records.Inbound(101, AbiV1Constants.SAS_PAIRING_PROTOCOL_EVENT_START_ACCEPTED, RequestA, run: 501),
            Records.Inbound(102, AbiV1Constants.SAS_PAIRING_PROTOCOL_EVENT_START_ACCEPTED, RequestA, run: 502));
        NativeRunRef[] runs = [.. tree.Host.Drive().Events.Select(e => e.Run!.Ref)];

        // The same request ID on another connection is another run.
        Assert.Equal(3, runs.Distinct().Count());
        Assert.All(runs, r => Assert.True(r.IsValid));

        connections[0].Dispose();
        Assert.False(runs[0].IsValid);
        tree.Network.Next(Ok, Ok, Records.Closed(101));
        tree.Host.Drive();
        Assert.False(runs[1].IsValid);
        Assert.True(runs[2].IsValid);
        tree.Host.DetachListener();
        Assert.False(runs[2].IsValid);
    }

    [Fact]
    public void ResultsAreRuntimeOwnedAndSurviveEveryNetworkParentUntilTheRuntimeIsDisposed()
    {
        FakeTree tree = new();
        SasPairingConnection[] connections = tree.AttachWithConnections(100, 101);
        tree.Network.Next(
            Ok,
            Ok,
            Records.Inbound(100, AbiV1Constants.SAS_PAIRING_PROTOCOL_EVENT_START_ACCEPTED, RequestA, run: 500),
            Records.Inbound(100, AbiV1Constants.SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH_ACK, RequestA, result: 0x700),
            Records.Step(101, AbiV1Constants.SAS_PAIRING_STEP_CONFIRMED, result: 0x701, requestId: RequestB));

        IReadOnlyList<SasPairingEvent> events = tree.Host.Drive().Events;

        NativeRunRef run = events[0].Run!.Ref;
        Assert.True(events[1].HasResult);
        Assert.False(events[1].HasTrackedRun);
        Assert.False(run.IsValid); // a result makes the run's end visible
        NativeResultRef responder = events[1].Result!;
        NativeResultRef initiator = events[2].Result!;
        Assert.Equal(0x700ul, responder.Handle);
        Assert.Same(responder, tree.Runtime.Results.Find(0x700));
        Assert.Same(initiator, tree.Runtime.Results.Find(0x701));

        connections[0].Dispose();
        tree.Host.DetachListener();
        tree.Host.Dispose();
        tree.Authority.Dispose();
        Assert.True(responder.IsValid && initiator.IsValid);
        Assert.Equal(2, tree.Runtime.Results.Count);

        tree.Runtime.Dispose();
        Assert.False(responder.IsValid || initiator.IsValid);

        // No result is ever destroyed or read in P9.3: no such export is called.
        Assert.DoesNotContain(tree.Network.Calls, c => c.Export.Contains("result", StringComparison.Ordinal));
        Assert.DoesNotContain(tree.Lifecycle.Calls, c => c.Export.Contains("result", StringComparison.Ordinal));
    }

    [Fact]
    public void AResultSurvivesAnOwnerLoopFailureAndAContractViolationLaterInItsBatch()
    {
        FakeTree failing = new();
        failing.AttachWithConnections(100);
        failing.Network.Next(Ok, AbiV1Constants.SAS_PAIRING_NETWORK_POLL_FAILED, Records.Step(100, AbiV1Constants.SAS_PAIRING_STEP_CONFIRMED, result: 0x700, requestId: RequestA));
        SasPairingDriveBatch batch = failing.Host.Drive();
        Assert.True(Assert.Single(batch.Events).Result!.IsValid);
        Assert.Equal(SasPairingHostNetworkState.FailedClosed, failing.Host.NetworkState);

        FakeTree broken = new();
        broken.AttachWithConnections(100);
        broken.Network.Next(Ok, Ok, Records.Step(100, AbiV1Constants.SAS_PAIRING_STEP_CONFIRMED, result: 0x700, requestId: RequestA), Records.Step(777));
        Assert.Throws<SasPairingContractException>(broken.Host.Drive);
        Assert.True(broken.Runtime.Results.Find(0x700)!.IsValid);
    }

    [Fact]
    public void AResultHandleDeliveredTwiceIsAContractViolation()
    {
        FakeTree tree = new();
        tree.AttachWithConnections(100, 101);
        tree.Network.Next(Ok, Ok, Records.Step(100, AbiV1Constants.SAS_PAIRING_STEP_CONFIRMED, result: 500, requestId: RequestA));
        tree.Host.Drive();
        tree.Network.Next(Ok, Ok, Records.Step(101, AbiV1Constants.SAS_PAIRING_STEP_CONFIRMED, result: 500, requestId: RequestB));

        Assert.Throws<SasPairingContractException>(tree.Host.Drive);

        Assert.True(tree.Context.IsContractViolated);
        Assert.Equal(1, tree.Runtime.Results.Count);
    }

    [Fact]
    public void HostDisposeIsOneDestroyCallThatDisposesItsConnectionsLocally()
    {
        FakeTree tree = new();
        SasPairingConnection[] connections = tree.AttachWithConnections(100, 101);

        tree.Host.Dispose();

        Assert.Equal(1, tree.Lifecycle.Count(FakeLifecycleApi.HostDestroyExport));
        Assert.Equal(0, tree.Network.Count(FakeNetworkApi.DetachExport) + tree.Network.Count(FakeNetworkApi.CloseExport));
        Assert.All(connections, c => Assert.True(c.IsDisposed));
        Assert.Equal(SasPairingHostNetworkState.Detached, tree.Host.NetworkState);
        connections[0].Dispose();
        Assert.Equal(0, tree.Network.Count(FakeNetworkApi.CloseExport));
    }

    [Fact]
    public void AuthorityDisposeIsOneReleaseCallThatDisposesHostsAndConnectionsLocally()
    {
        FakeTree tree = new();
        SasPairingConnection[] connections = tree.AttachWithConnections(100, 101);

        tree.Authority.Dispose();

        Assert.Equal(1, tree.Lifecycle.Count(FakeLifecycleApi.AuthorityReleaseExport));
        Assert.Equal(0, tree.Lifecycle.Count(FakeLifecycleApi.HostDestroyExport));
        Assert.Equal(0, tree.Network.Count(FakeNetworkApi.DetachExport) + tree.Network.Count(FakeNetworkApi.CloseExport));
        Assert.True(tree.Host.IsDisposed);
        Assert.All(connections, c => Assert.True(c.IsDisposed));
        Assert.Equal(SasPairingHostNetworkState.Detached, tree.Host.NetworkState);
    }

    [Fact]
    public void RuntimeDisposeIsOneDestroyCallThatDisposesTheWholeTreeLocally()
    {
        FakeTree tree = new();
        SasPairingConnection[] connections = tree.AttachWithConnections(100, 101);
        int lifecycle = tree.Lifecycle.Total;
        int network = tree.Network.Total;

        tree.Runtime.Dispose();

        Assert.Equal(lifecycle + 1, tree.Lifecycle.Total);
        Assert.Equal(1, tree.Lifecycle.Count(FakeLifecycleApi.RuntimeDestroyExport));
        Assert.Equal(network, tree.Network.Total);
        Assert.True(tree.Authority.IsDisposed && tree.Host.IsDisposed);
        Assert.All(connections, c => Assert.True(c.IsDisposed));
        Assert.Equal(SasPairingHostNetworkState.Detached, tree.Host.NetworkState);
    }
}
