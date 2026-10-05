using System.Reflection;
using System.Runtime.InteropServices;
using SasPairing.Interop;
using SasPairing.Tests.Support;

namespace SasPairing.Tests;

/// <summary>
/// P9-D-005 result ownership over the fake services (every platform): one public runtime-owned result per exact
/// native result handle, delivered only by its event; a delivered-handle history that outlives disposal; survival
/// of every lower-level teardown and of native FATAL; one consuming, idempotent destroy that stays allowed after
/// both latches; the runtime cascade with no child destroy; retention before a later contract violation in the
/// same batch; and no effect of reading or disposing on accounting, runs, or networking.
/// </summary>
public sealed class ResultOwnershipTests
{
    private const int Ok = 0;

    private static readonly byte[] RequestA = [0x00, 0x80, 0xFF, 0x41];
    private static readonly byte[] RequestB = [0x42];

    private static NativeEventRecord Completed(ulong connection, ulong result, byte[]? requestId = null) =>
        Records.Step(connection, AbiV1Constants.SAS_PAIRING_STEP_CONFIRMED, result: result, requestId: requestId ?? RequestA);

    /// <summary>A tree with connections 100 and 101 and the result <paramref name="handle"/> delivered on 100.</summary>
    private static (FakeTree Tree, SasPairingConnection[] Connections, SasPairingEvent Event) Delivered(ulong handle = 500)
    {
        FakeTree tree = new();
        SasPairingConnection[] connections = tree.AttachWithConnections(100, 101);
        tree.Network.Next(Ok, Ok, Completed(100, handle));
        return (tree, connections, Assert.Single(tree.Host.Drive().Events));
    }

    /// <summary>Latches native FATAL through a normal operation that reports it.</summary>
    private static void LatchFatal(FakeTree tree)
    {
        tree.Lifecycle.AuthorityStatusOutcome = () => new NativeAuthorityStatusOutcome(AbiV1Constants.SAS_PAIRING_FATAL, 0, 0);
        Assert.Equal(SasPairingStatus.Fatal, Assert.Throws<SasPairingNativeException>(() => tree.Authority.GetStatus()).KnownStatus);
        Assert.True(tree.Context.IsFatal);
    }

    /// <summary>Latches a wrapper contract violation through an impossible drive event (unknown kind 99).</summary>
    private static void LatchContract(FakeTree tree)
    {
        tree.Network.Next(Ok, Ok, Records.Event(99));
        Assert.Throws<SasPairingContractException>(tree.Host.Drive);
        Assert.True(tree.Context.IsContractViolated);
    }

    [Fact]
    public void TheEventCarriesTheOneRuntimeOwnedResultOfItsNativeHandle()
    {
        (FakeTree tree, _, SasPairingEvent evt) = Delivered();

        SasPairingResult result = Assert.IsType<SasPairingResult>(evt.Result);
        Assert.True(evt.HasResult);
        Assert.Same(result, evt.Result); // the getter creates no wrapper
        Assert.Same(result, tree.Runtime.ResultStore.Find(500));
        Assert.Equal(500ul, result.Ref.Handle);
        Assert.False(result.IsDisposed);
        Assert.Null(evt.Run);

        // Runtime-owned: the result holds its runtime and its exact reference, nothing below the runtime.
        string[] fields = [.. typeof(SasPairingResult).GetFields(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public).Select(f => $"{f.FieldType.Name} {f.Name}").Order(StringComparer.Ordinal)];
        Assert.Equal(["NativeResultRef <Ref>k__BackingField", "SasPairingRuntime _runtime"], fields);

        // Delivery reads, destroys, and drives nothing.
        Assert.Equal(0, tree.Results.Total);
    }

    [Fact]
    public void HasResultIsExactlyResultIsNotNullOnEveryEvent()
    {
        FakeTree tree = new();
        tree.Attach();
        tree.Network.Next(
            Ok,
            Ok,
            Records.Accepted(100),
            Records.Refused(),
            Records.Inbound(100, AbiV1Constants.SAS_PAIRING_PROTOCOL_EVENT_START_ACCEPTED, RequestA, run: 600),
            Records.Step(100),
            Completed(100, 500, RequestB),
            Records.ListenerDisabled(),
            Records.Closed(100));

        IReadOnlyList<SasPairingEvent> events = tree.Host.Drive().Events;

        Assert.All(events, e => Assert.Equal(e.Result is not null, e.HasResult));
        Assert.Equal([false, false, false, false, true, false, false], events.Select(e => e.HasResult));
    }

    [Fact]
    public void DifferentHandlesAreDifferentObjectsWithReferenceIdentityOnly()
    {
        FakeTree tree = new();
        tree.AttachWithConnections(100, 101);
        tree.Network.Next(Ok, Ok, Completed(100, 500), Completed(101, 501, RequestB));

        IReadOnlyList<SasPairingEvent> events = tree.Host.Drive().Events;
        SasPairingResult first = events[0].Result!;
        SasPairingResult second = events[1].Result!;

        Assert.NotSame(first, second);
        Assert.Equal((500ul, 501ul), (first.Ref.Handle, second.Ref.Handle));

        // Equal data (the fake reports the same data for both) never makes results equal: no value equality.
        Assert.False(first.Equals(second));
        Assert.Equal(typeof(object), typeof(SasPairingResult).GetMethod(nameof(Equals), [typeof(object)])!.DeclaringType);
        Assert.Equal(typeof(object), typeof(SasPairingResult).GetMethod(nameof(GetHashCode), Type.EmptyTypes)!.DeclaringType);
        Assert.Null(typeof(SasPairingResult).GetMethod("op_Equality"));
        Assert.False(typeof(IEquatable<SasPairingResult>).IsAssignableFrom(typeof(SasPairingResult)));
        Assert.Equal(first.Read().CeremonyIdentity, second.Read().CeremonyIdentity);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ADuplicateHandleIsAContractViolationAlsoAfterTheFirstResultWasDisposed(bool disposedFirst)
    {
        (FakeTree tree, _, SasPairingEvent evt) = Delivered(500);
        SasPairingResult first = evt.Result!;
        if (disposedFirst)
        {
            first.Dispose();
            Assert.Empty(tree.Runtime.ResultStore.Live);
        }

        tree.Network.Next(Ok, Ok, Completed(101, 500, RequestB));

        Assert.Throws<SasPairingContractException>(tree.Host.Drive);

        Assert.True(tree.Context.IsContractViolated);
        Assert.Equal(1, tree.Runtime.ResultStore.DeliveredCount);
        Assert.Equal(disposedFirst ? [] : [first], tree.Runtime.ResultStore.Live);
        Assert.Equal(disposedFirst, first.IsDisposed);
        Assert.Equal(disposedFirst ? 1 : 0, tree.Results.Count(FakeResultApi.DestroyExport));
    }

    public static TheoryData<string> Teardowns =>
    [
        "connection dispose", "connection closed event", "detach", "host dispose", "authority dispose", "owner-loop failure", "ownership uncertain close",
        "native fatal", "host and authority dispose",
    ];

    [Theory]
    [MemberData(nameof(Teardowns))]
    public void AResultSurvivesEveryTeardownBelowTheRuntimeAndStaysReadableAndDestroyable(string teardown)
    {
        (FakeTree tree, SasPairingConnection[] connections, SasPairingEvent evt) = Delivered();
        SasPairingResult result = evt.Result!;
        switch (teardown)
        {
            case "connection dispose":
                connections[0].Dispose();
                Assert.True(connections[0].IsDisposed);
                break;
            case "connection closed event":
                tree.Network.Next(Ok, Ok, Records.Closed(100));
                tree.Host.Drive();
                Assert.True(connections[0].IsDisposed);
                break;
            case "detach":
                tree.Host.DetachListener();
                Assert.All(connections, c => Assert.True(c.IsDisposed));
                break;
            case "host dispose":
                tree.Host.Dispose();
                break;
            case "authority dispose":
                tree.Authority.Dispose();
                Assert.True(tree.Host.IsDisposed);
                break;
            case "owner-loop failure":
                tree.Network.Next(Ok, AbiV1Constants.SAS_PAIRING_NETWORK_POLL_FAILED);
                tree.Host.Drive();
                Assert.Equal(SasPairingHostNetworkState.FailedClosed, tree.Host.NetworkState);
                break;
            case "ownership uncertain close":
                tree.Network.CloseStatus = AbiV1Constants.SAS_PAIRING_OWNERSHIP_UNCERTAIN;
                Assert.Throws<SasPairingNativeException>(connections[1].Dispose);
                Assert.Equal(SasPairingHostNetworkState.FailedClosed, tree.Host.NetworkState);
                break;
            case "native fatal":
                LatchFatal(tree);
                break;
            case "host and authority dispose":
                tree.Host.Dispose();
                tree.Authority.Dispose();
                break;
        }

        Assert.False(result.IsDisposed);
        Assert.Same(result, tree.Runtime.ResultStore.Find(500));
        Assert.Equal(0, tree.Results.Total);

        // Still readable: one info and four copies on the exact handles.
        SasPairingResultData data = result.Read();
        Assert.True(data.RequestId.SequenceEqual(tree.Results.Data.RequestId));
        Assert.Equal(5, tree.Results.Total);
        Assert.All(tree.Results.Calls, c => Assert.Equal([tree.Runtime.Handle, 500ul], c.Arguments));

        // Still destroyable: exactly one native destroy, which succeeds.
        result.Dispose();
        Assert.True(result.IsDisposed);
        FakeResultCall destroy = Assert.Single(tree.Results.Calls, c => c.Export == FakeResultApi.DestroyExport);
        Assert.Equal([tree.Runtime.Handle, 500ul], destroy.Arguments);
    }

    [Fact]
    public void TheFirstDisposeIsOneDestroyAndEveryLaterDisposeIsANoOp()
    {
        (FakeTree tree, _, SasPairingEvent evt) = Delivered();
        SasPairingResult result = evt.Result!;

        result.Dispose();

        Assert.True(result.IsDisposed);
        Assert.Equal([tree.Runtime.Handle, 500ul], Assert.Single(tree.Results.Calls).Arguments);
        Assert.Empty(tree.Runtime.ResultStore.Live);
        Assert.True(tree.Runtime.ResultStore.WasDelivered(500));

        result.Dispose();
        result.Dispose();
        Assert.Equal(1, tree.Results.Total);

        ObjectDisposedException disposed = Assert.Throws<ObjectDisposedException>(result.Read);
        Assert.Equal(typeof(SasPairingResult).FullName, disposed.ObjectName);
        Assert.Equal(1, tree.Results.Total);
    }

    [Theory]
    [InlineData(AbiV1Constants.SAS_PAIRING_INVALID_HANDLE)]
    [InlineData(AbiV1Constants.SAS_PAIRING_FATAL)]
    [InlineData(777)]
    public void AFailedDestroyIsConsumingThrownOnceAndNeverRetried(int status)
    {
        (FakeTree tree, _, SasPairingEvent evt) = Delivered();
        SasPairingResult result = evt.Result!;
        tree.Results.DestroyStatus = status;

        SasPairingNativeException failure = Assert.Throws<SasPairingNativeException>(result.Dispose);

        Assert.Equal(status, failure.StatusCode);
        Assert.Equal("SasPairingResult.Dispose", failure.Operation);
        Assert.Equal(status == AbiV1Constants.SAS_PAIRING_FATAL, tree.Context.IsFatal);
        Assert.True(result.IsDisposed);
        result.Dispose();
        Assert.Equal(1, tree.Results.Count(FakeResultApi.DestroyExport));
        Assert.Throws<ObjectDisposedException>(result.Read);
        Assert.Equal(1, tree.Results.Total);
    }

    [Theory]
    [InlineData("fatal")]
    [InlineData("contract")]
    public void DisposeStillDestroysAfterNativeFatalAndAfterAContractViolation(string latch)
    {
        (FakeTree tree, _, SasPairingEvent evt) = Delivered();
        SasPairingResult result = evt.Result!;
        if (latch == "fatal")
        {
            LatchFatal(tree);
        }
        else
        {
            LatchContract(tree);
        }

        result.Dispose();

        Assert.True(result.IsDisposed);
        Assert.Equal([tree.Runtime.Handle, 500ul], Assert.Single(tree.Results.Calls, c => c.Export == FakeResultApi.DestroyExport).Arguments);
        Assert.Equal(1, tree.Results.Total);
    }

    [Fact]
    public void RuntimeDisposeIsOneRuntimeDestroyAndNoResultDestroy()
    {
        FakeTree tree = new();
        tree.AttachWithConnections(100, 101);
        tree.Network.Next(Ok, Ok, Completed(100, 500), Completed(101, 501, RequestB));
        tree.Host.Drive();
        tree.Network.Next(Ok, Ok, Completed(100, 502, RequestB));
        SasPairingResult[] results = [.. tree.Host.Drive().Events.Select(e => e.Result!).Prepend(tree.Runtime.ResultStore.Find(501)!).Prepend(tree.Runtime.ResultStore.Find(500)!)];
        Assert.Equal([500ul, 501ul, 502ul], results.Select(r => r.Ref.Handle));
        results[1].Dispose();
        int lifecycle = tree.Lifecycle.Total;

        tree.Runtime.Dispose();

        Assert.Equal(lifecycle + 1, tree.Lifecycle.Total);
        Assert.Equal(1, tree.Lifecycle.Count(FakeLifecycleApi.RuntimeDestroyExport));
        Assert.Equal(1, tree.Results.Count(FakeResultApi.DestroyExport)); // only the explicit one before the cascade
        Assert.All(results, r => Assert.True(r.IsDisposed));
        Assert.Empty(tree.Runtime.ResultStore.Live);

        // After the native cascade a result's Dispose and Read make no native call: nothing manufactures INVALID_HANDLE.
        foreach (SasPairingResult result in results)
        {
            result.Dispose();
            Assert.Throws<ObjectDisposedException>(result.Read);
        }

        Assert.Equal(1, tree.Results.Total);
        Assert.Equal(1, tree.Lifecycle.Count(FakeLifecycleApi.RuntimeDestroyExport));
    }

    [Fact]
    public void AFailedRuntimeDestroyStillDisposesEveryResultLocallyWithoutAResultDestroy()
    {
        (FakeTree tree, _, SasPairingEvent evt) = Delivered();
        tree.Lifecycle.RuntimeDestroyStatus = AbiV1Constants.SAS_PAIRING_FATAL;

        Assert.Throws<SasPairingNativeException>(tree.Runtime.Dispose);

        Assert.True(evt.Result!.IsDisposed);
        evt.Result.Dispose();
        Assert.Equal(0, tree.Results.Total);
    }

    [Fact]
    public void AResultRetainedBeforeALaterContractViolationInItsBatchStaysOwnedByTheRuntime()
    {
        FakeTree tree = new();
        tree.AttachWithConnections(100);
        tree.Network.Next(Ok, Ok, Completed(100, 500), Records.Step(777));

        Assert.Throws<SasPairingContractException>(tree.Host.Drive);

        // No batch was returned, but the native result is neither forgotten nor destroyed behind the caller's back.
        SasPairingResult retained = tree.Runtime.ResultStore.Find(500)!;
        Assert.False(retained.IsDisposed);
        Assert.Equal(0, tree.Results.Total);

        tree.Runtime.Dispose();

        Assert.True(retained.IsDisposed);
        Assert.Equal(0, tree.Results.Total);
        Assert.Equal(1, tree.Lifecycle.Count(FakeLifecycleApi.RuntimeDestroyExport));
    }

    [Fact]
    public void ReadingAndDisposingAlterNoAccountingRunConnectionOrNetworkState()
    {
        FakeTree tree = new();
        SasPairingConnection connection = tree.AttachWithConnections(100, 101)[0];
        SasPairingRun run = connection.StartInitiator(FakeTree.Bootstrap()).Run!;
        tree.Network.Next(Ok, Ok, Completed(101, 500));
        SasPairingResult result = Assert.Single(tree.Host.Drive().Events).Result!;
        (int lifecycle, int network, int ceremony) = (tree.Lifecycle.Total, tree.Network.Total, tree.Ceremony.Total);

        result.Read();
        result.Read();
        result.Dispose();

        // Only the three result exports were called: no authority status or accounting call, no drive, no
        // ceremony step, no start, and no new result.
        Assert.Equal((lifecycle, network, ceremony), (tree.Lifecycle.Total, tree.Network.Total, tree.Ceremony.Total));
        Assert.Equal(11, tree.Results.Total);
        Assert.Equal(1, tree.Runtime.ResultStore.DeliveredCount);
        Assert.False(run.IsEnded);
        Assert.Same(run, Assert.Single(connection.Runs));
        Assert.False(connection.IsDisposed);
        Assert.Equal(SasPairingHostNetworkState.Attached, tree.Host.NetworkState);
        Assert.Equal(new SasPairingAuthorityStatus(SasPairingAuthorityState.Ready, 10), tree.Authority.GetStatus());
    }

    [Fact]
    public void ConcurrentDisposeMakesOneNativeDestroy()
    {
        (FakeTree tree, _, SasPairingEvent evt) = Delivered();
        SasPairingResult result = evt.Result!;
        Exception?[] errors = new Exception?[16];
        using Barrier barrier = new(errors.Length);
        Thread[] threads =
        [
            .. Enumerable.Range(0, errors.Length).Select(i => new Thread(() =>
            {
                barrier.SignalAndWait();
                try
                {
                    result.Dispose();
                }
                catch (Exception error)
                {
                    // Recorded and asserted below: an exception escaping a worker thread would end the test host.
                    errors[i] = error;
                }
            })),
        ];
        foreach (Thread thread in threads)
        {
            thread.Start();
        }

        foreach (Thread thread in threads)
        {
            thread.Join();
        }

        Assert.All(errors, Assert.Null);
        Assert.Equal(1, tree.Results.Count(FakeResultApi.DestroyExport));
        Assert.True(result.IsDisposed);
    }

    [Fact]
    public void ThePeerRoleHasExactlyTheTwoFrozenValues()
    {
        Assert.Equal(["Initiator", "Responder"], Enum.GetNames<SasPairingPeerRole>());
        Assert.Equal((int)AbiV1Constants.SAS_PAIRING_ROLE_INITIATOR, (int)SasPairingPeerRole.Initiator);
        Assert.Equal((int)AbiV1Constants.SAS_PAIRING_ROLE_RESPONDER, (int)SasPairingPeerRole.Responder);
        Assert.Equal(1, (int)SasPairingPeerRole.Initiator);
        Assert.Equal(2, (int)SasPairingPeerRole.Responder);
        Assert.False(Enum.IsDefined(typeof(SasPairingPeerRole), (int)AbiV1Constants.SAS_PAIRING_ROLE_INVALID));
    }

    [Fact]
    public void AResultHasNoFinalizerNoSafeHandleAndNoAsynchronousApi()
    {
        Type type = typeof(SasPairingResult);
        Assert.True(typeof(IDisposable).IsAssignableFrom(type));
        Assert.False(typeof(IAsyncDisposable).IsAssignableFrom(type));
        Assert.Null(type.GetMethod("Finalize", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.DeclaredOnly));
        Assert.DoesNotContain(type.GetFields(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public), f => typeof(SafeHandle).IsAssignableFrom(f.FieldType));
        Assert.DoesNotContain(type.GetMethods(), m => m.Name.EndsWith("Async", StringComparison.Ordinal));
        Assert.DoesNotContain(typeof(SasPairingResultData).GetInterfaces(), i => i == typeof(IDisposable) || i == typeof(IAsyncDisposable));
        Assert.False(typeof(IDisposable).IsAssignableFrom(typeof(NativeResultRef)));
    }
}
