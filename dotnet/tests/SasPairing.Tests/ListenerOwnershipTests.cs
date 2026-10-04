using System.Net;
using System.Net.Sockets;
using SasPairing.Interop;
using SasPairing.Tests.Support;

namespace SasPairing.Tests;

/// <summary>
/// P9-D-003 listener ownership over the fake network service (every platform): the Bootstrap, the attach
/// ownership matrix driven by the in/out slot, the token's single-attempt gate and disposal, attach admission
/// and order, repeatable detach and replacement, and the platform rule of <c>FromSocket</c>.
/// </summary>
public sealed class ListenerOwnershipTests
{
    private const nuint Offered = 0x1234;
    private static readonly nuint Invalid = AbiV1Constants.SAS_PAIRING_SOCKET_INVALID;

    private static (SasPairingWindowsListenerSocket Token, FakeListenerResource Resource) NewToken(nuint value = Offered)
    {
        FakeListenerResource resource = new(value);
        return (SasPairingWindowsListenerSocket.FromResource(resource), resource);
    }

    [Fact]
    public void TheBootstrapIsAnImmutableBinaryCopy()
    {
        byte[] application = [0x00, 0x80, 0xFF];
        byte[] algorithm = [0x78, 0x00];
        byte[] key = [0xFF, 0x80, 0x00, 0x01];
        byte[] context = [0x80];
        SasPairingBootstrap bootstrap = new(application, algorithm, key, context);

        application[0] = 0x55;
        algorithm[1] = 0x55;
        key[3] = 0x55;
        context[0] = 0x55;

        Assert.Equal(new byte[] { 0x00, 0x80, 0xFF }, bootstrap.ApplicationIdentity.ToArray());
        Assert.Equal(new byte[] { 0x78, 0x00 }, bootstrap.KeyAlgorithm.ToArray());
        Assert.Equal(new byte[] { 0xFF, 0x80, 0x00, 0x01 }, bootstrap.PublicKey.ToArray());
        Assert.Equal(new byte[] { 0x80 }, bootstrap.SharedContext.ToArray());

        // Each read is a read-only view of the package's copy; a copied-out array cannot change it either.
        bootstrap.PublicKey.ToArray()[0] = 0x11;
        Assert.Equal(0xFF, bootstrap.PublicKey[0]);
        Assert.True(new SasPairingBootstrap([], [], [], []).SharedContext.IsEmpty);
    }

    [Fact]
    public void TheBootstrapIsNotValidatedInCSharp()
    {
        // Bytes the native core would refuse are accepted here unchanged: the core is the only validator.
        SasPairingBootstrap odd = new([], "X25519 not lowercase"u8, new byte[20000], [0x00]);
        Assert.Equal(20000, odd.PublicKey.Length);

        FakeTree tree = new();
        tree.Network.AttachOutcome = socket => new NativeAttachOutcome(AbiV1Constants.SAS_PAIRING_INVALID_BOOTSTRAP, socket);
        SasPairingNativeException failure = Assert.Throws<SasPairingNativeException>(() => tree.Host.AttachWindowsListener(FakeTree.Token(), odd));
        Assert.Equal(SasPairingStatus.InvalidBootstrap, failure.KnownStatus);
        Assert.Equal(20000, tree.Network.Calls.Single().Local!.PublicKey.Length);
    }

    [Fact]
    public void AttachPassesTheExactHandlesSocketAndBootstrapBytesAndDrivesNothing()
    {
        FakeTree tree = new();
        SasPairingBootstrap local = new([0x00, 0x80, 0xFF], "x25519"u8, [7, 7], []);
        SasPairingBootstrap expected = new([0xFF], "x25519"u8, [9], [0x00, 0x01]);

        tree.Host.AttachWindowsListener(NewToken(0xABCD).Token, local);
        FakeNetworkCall first = tree.Network.Calls.Single();
        Assert.Equal(FakeNetworkApi.AttachExport, first.Export);
        Assert.Equal([tree.Runtime.Handle, tree.Host.Handle], first.Arguments);
        Assert.Equal((nuint)0xABCD, first.Socket);
        Assert.Equal(new byte[] { 0x00, 0x80, 0xFF }, first.Local!.ApplicationIdentity);
        Assert.Equal("x25519"u8.ToArray(), first.Local.KeyAlgorithm);
        Assert.Equal(new byte[] { 7, 7 }, first.Local.PublicKey);
        Assert.Empty(first.Local.SharedContext);
        Assert.False(first.ExpectedGiven);

        tree.Host.DetachListener();
        tree.Host.AttachWindowsListener(NewToken().Token, local, expected);
        FakeNetworkCall second = tree.Network.Calls.Last();
        Assert.True(second.ExpectedGiven);
        Assert.Equal(new byte[] { 0xFF }, second.Expected!.ApplicationIdentity);
        Assert.Equal(new byte[] { 0x00, 0x01 }, second.Expected.SharedContext);

        // Attach drives, accepts, and creates nothing.
        Assert.Equal(0, tree.Network.Count(FakeNetworkApi.DriveExport) + tree.Network.Count(FakeNetworkApi.RecheckExport));
        Assert.Empty(tree.Host.Network.Connections);
    }

    /// <summary>The P9-D-003 attach ownership matrix: status, post-call slot, and what must follow.</summary>
    [Theory]
    [InlineData("A", 0, "invalid", true, "Attached", "none")]
    [InlineData("B", 203, "original", false, "Detached", "native")]
    [InlineData("D", 401, "invalid", true, "Detached", "native")]
    [InlineData("E", 900, "original", false, "Detached", "fatal")]
    [InlineData("F", 900, "invalid", true, "Detached", "fatal")]
    [InlineData("G", 0, "original", false, "Detached", "contract")]
    [InlineData("H", 0, "other", true, "Detached", "contract")]
    [InlineData("H2", 401, "other", true, "Detached", "contract")]
    [InlineData("I", 1, "original", false, "Detached", "native")]
    [InlineData("J", 2, "original", false, "Detached", "native")]
    [InlineData("K", 103, "original", false, "Detached", "native")]
    [InlineData("L", 401, "original", false, "Detached", "contract")]
    [InlineData("M", 203, "invalid", true, "Detached", "contract")]
    [InlineData("N", 777, "original", false, "Detached", "native")]
    public void TheSlotDecidesOwnershipBeforeAnyStatusIsThrown(string row, int status, string slot, bool transferred, string state, string failure)
    {
        FakeTree tree = new();
        (SasPairingWindowsListenerSocket token, FakeListenerResource resource) = NewToken();
        tree.Network.AttachOutcome = offered => new NativeAttachOutcome(status, slot switch
        {
            "invalid" => Invalid,
            "original" => offered,
            _ => offered + 1,
        });

        Exception? thrown = Record.Exception(() => tree.Host.AttachWindowsListener(token, FakeTree.Bootstrap()));

        Assert.True(transferred == token.IsTransferred, row);
        Assert.Equal(transferred ? 1 : 0, resource.Releases);
        Assert.Equal(0, resource.Closes);
        Assert.Equal(Enum.Parse<SasPairingHostNetworkState>(state), tree.Host.NetworkState);
        Assert.Equal(1, tree.Network.Count(FakeNetworkApi.AttachExport));
        switch (failure)
        {
            case "none":
                Assert.Null(thrown);
                break;
            case "native":
                Assert.Equal(status, Assert.IsType<SasPairingNativeException>(thrown).StatusCode);
                Assert.False(tree.Context.IsFatal || tree.Context.IsContractViolated);
                break;
            case "fatal":
                Assert.Equal(900, Assert.IsType<SasPairingNativeException>(thrown).StatusCode);
                Assert.True(tree.Context.IsFatal);
                break;
            case "contract":
                Assert.IsType<SasPairingContractException>(thrown);
                Assert.True(tree.Context.IsContractViolated);
                Assert.Equal(status == 900, tree.Context.IsFatal);
                break;
        }

        // Cleanup stays available in every case.
        tree.Host.DetachListener();
        Assert.Equal(1, tree.Network.Count(FakeNetworkApi.DetachExport));
    }

    [Fact]
    public void ListenerAlreadyAttachedKeepsTheOfferedSocketTheCallersAndTheCurrentListenerAttached()
    {
        FakeTree tree = new();
        tree.Attach();
        (SasPairingWindowsListenerSocket second, FakeListenerResource resource) = NewToken(0x9999);
        tree.Network.AttachOutcome = offered => new NativeAttachOutcome(AbiV1Constants.SAS_PAIRING_LISTENER_ALREADY_ATTACHED, offered);

        SasPairingNativeException failure = Assert.Throws<SasPairingNativeException>(() => tree.Host.AttachWindowsListener(second, FakeTree.Bootstrap()));

        Assert.Equal(SasPairingStatus.ListenerAlreadyAttached, failure.KnownStatus);
        Assert.False(second.IsTransferred);
        Assert.Equal((0, 0), (resource.Releases, resource.Closes));
        Assert.Equal(SasPairingHostNetworkState.Attached, tree.Host.NetworkState);
    }

    [Fact]
    public void APreAdoptionFailureLeavesTheTokenReusableAndAnAdoptedTokenIsRefusedLocally()
    {
        FakeTree tree = new();
        (SasPairingWindowsListenerSocket token, FakeListenerResource resource) = NewToken();
        tree.Network.AttachOutcome = offered => new NativeAttachOutcome(AbiV1Constants.SAS_PAIRING_INVALID_BOOTSTRAP, offered);
        Assert.Throws<SasPairingNativeException>(() => tree.Host.AttachWindowsListener(token, FakeTree.Bootstrap()));
        Assert.False(token.IsTransferred);

        tree.Network.AttachOutcome = _ => new NativeAttachOutcome(0, Invalid);
        tree.Host.AttachWindowsListener(token, FakeTree.Bootstrap());
        Assert.True(token.IsTransferred);
        Assert.Equal(1, resource.Releases);

        // A transferred token is never offered again: local refusal, no native call, on any host.
        int calls = tree.Network.Total;
        Assert.Throws<InvalidOperationException>(() => tree.Host.AttachWindowsListener(token, FakeTree.Bootstrap()));
        FakeTree other = new();
        Assert.Throws<InvalidOperationException>(() => other.Host.AttachWindowsListener(token, FakeTree.Bootstrap()));
        Assert.Equal(calls, tree.Network.Total);
        Assert.Equal(0, other.Network.Total);
        Assert.Equal(1, resource.Releases);

        // Disposing a transferred token does nothing: the native library owns the socket.
        token.Dispose();
        Assert.Equal(0, resource.Closes);
    }

    [Fact]
    public void AnImpossibleSlotConsumesTheTokenSoTheSocketCanNeverBeClosedTwice()
    {
        FakeTree tree = new();
        (SasPairingWindowsListenerSocket token, FakeListenerResource resource) = NewToken();
        tree.Network.AttachOutcome = _ => new NativeAttachOutcome(AbiV1Constants.SAS_PAIRING_LISTENER_SETUP_FAILED, 0x5555);

        Assert.Throws<SasPairingContractException>(() => tree.Host.AttachWindowsListener(token, FakeTree.Bootstrap()));

        Assert.True(token.IsTransferred);
        Assert.Equal(1, resource.Releases);
        token.Dispose();
        Assert.Equal(0, resource.Closes);
        Assert.Throws<InvalidOperationException>(() => tree.Host.AttachWindowsListener(token, FakeTree.Bootstrap()));
        Assert.NotEqual(SasPairingHostNetworkState.Attached, tree.Host.NetworkState);
    }

    [Fact]
    public void ADisposedTokenClosesItsSocketOnceAndIsRefusedLocally()
    {
        FakeTree tree = new();
        (SasPairingWindowsListenerSocket token, FakeListenerResource resource) = NewToken();
        token.Dispose();
        token.Dispose();
        Assert.Equal(1, resource.Closes);
        Assert.Throws<ObjectDisposedException>(() => tree.Host.AttachWindowsListener(token, FakeTree.Bootstrap()));
        Assert.Equal(0, tree.Network.Total);
        Assert.False(token.IsTransferred);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ADisposeDuringAnAttachTakesEffectOnlyIfTheSocketWasNotAdopted(bool adopted)
    {
        FakeTree tree = new();
        (SasPairingWindowsListenerSocket token, FakeListenerResource resource) = NewToken();
        tree.Network.DuringAttach = () =>
        {
            token.Dispose();
            Assert.Equal(0, resource.Closes); // deferred while the native call holds the socket
        };
        tree.Network.AttachOutcome = offered => adopted ? new NativeAttachOutcome(0, Invalid) : new NativeAttachOutcome(AbiV1Constants.SAS_PAIRING_INVALID_BOOTSTRAP, offered);

        Exception? thrown = Record.Exception(() => tree.Host.AttachWindowsListener(token, FakeTree.Bootstrap()));

        Assert.Equal(adopted, thrown is null);
        Assert.Equal(adopted, token.IsTransferred);
        Assert.Equal(adopted ? (1, 0) : (0, 1), (resource.Releases, resource.Closes));
        if (!adopted)
        {
            Assert.Throws<ObjectDisposedException>(() => tree.Host.AttachWindowsListener(token, FakeTree.Bootstrap()));
        }
    }

    [Fact]
    public void OneTokenIsOfferedToAtMostOneNativeAttachAtATime()
    {
        // Two runtime trees (two fake contexts, so two locks): the first attach is held inside its native call
        // while the second offers the same token.
        FakeTree first = new();
        FakeTree second = new();
        (SasPairingWindowsListenerSocket token, FakeListenerResource resource) = NewToken();
        using ManualResetEventSlim inside = new();
        using ManualResetEventSlim release = new();
        first.Network.DuringAttach = () =>
        {
            inside.Set();
            release.Wait(TimeSpan.FromSeconds(30), TestContext.Current.CancellationToken);
        };
        first.Network.AttachOutcome = offered => new NativeAttachOutcome(AbiV1Constants.SAS_PAIRING_INVALID_BOOTSTRAP, offered);

        Exception? workerFailure = null;
        Thread worker = new(() => workerFailure = Record.Exception(() => first.Host.AttachWindowsListener(token, FakeTree.Bootstrap())));
        worker.Start();
        Assert.True(inside.Wait(TimeSpan.FromSeconds(30), TestContext.Current.CancellationToken));

        Assert.Throws<InvalidOperationException>(() => second.Host.AttachWindowsListener(token, FakeTree.Bootstrap()));
        Assert.Equal(0, second.Network.Total);

        release.Set();
        Assert.True(worker.Join(TimeSpan.FromSeconds(30)));
        Assert.IsType<SasPairingNativeException>(workerFailure);

        // The pre-adoption failure released the gate: the same token now attaches elsewhere.
        second.Host.AttachWindowsListener(token, FakeTree.Bootstrap());
        Assert.True(token.IsTransferred);
        Assert.Equal(1, resource.Releases);
    }

    [Fact]
    public void AttachAdmissionIsDisposedHostThenTokenGateThenLatches()
    {
        FakeTree tree = new();
        (SasPairingWindowsListenerSocket token, FakeListenerResource resource) = NewToken();
        Assert.Throws<ArgumentNullException>(() => tree.Host.AttachWindowsListener(null!, FakeTree.Bootstrap()));
        Assert.Throws<ArgumentNullException>(() => tree.Host.AttachWindowsListener(token, null!));

        SasPairingHost disposed = tree.Authority.CreateHost();
        disposed.Dispose();
        Assert.Throws<ObjectDisposedException>(() => disposed.AttachWindowsListener(token, FakeTree.Bootstrap()));

        // A latch refuses attach without a native call and leaves the token untouched and reusable.
        tree.Context.Observe(AbiV1Constants.SAS_PAIRING_FATAL);
        SasPairingNativeException fatal = Assert.Throws<SasPairingNativeException>(() => tree.Host.AttachWindowsListener(token, FakeTree.Bootstrap()));
        Assert.True(fatal.ProcessRestartRequired);
        Assert.Equal(0, tree.Network.Total);
        Assert.False(token.IsTransferred);
        Assert.Equal((0, 0), (resource.Releases, resource.Closes));

        FakeTree other = new();
        other.Host.AttachWindowsListener(token, FakeTree.Bootstrap());
        Assert.True(token.IsTransferred);

        FakeTree violated = new();
        _ = violated.Context.ViolateContract("test", "a probe");
        Assert.Throws<SasPairingContractException>(() => violated.Host.AttachWindowsListener(FakeTree.Token(), FakeTree.Bootstrap()));
        Assert.Equal(0, violated.Network.Total);
    }

    [Fact]
    public void DetachIsRepeatableCleanupThatKeepsTheHostAndClosesNoConnectionIndividually()
    {
        FakeTree tree = new();
        SasPairingConnection[] connections = tree.AttachWithConnections(100, 101);
        Assert.Equal(SasPairingHostNetworkState.Attached, tree.Host.NetworkState);

        tree.Host.DetachListener();

        Assert.Equal(SasPairingHostNetworkState.Detached, tree.Host.NetworkState);
        Assert.All(connections, c => Assert.True(c.IsDisposed));
        Assert.Empty(tree.Host.Network.Connections);
        Assert.Equal(0, tree.Network.Count(FakeNetworkApi.CloseExport));
        Assert.False(tree.Host.IsDisposed || tree.Authority.IsDisposed || tree.Runtime.IsDisposed);
        Assert.Equal([tree.Runtime.Handle, tree.Host.Handle], tree.Network.Calls.Last().Arguments);

        // Repeatable: every explicit call reaches the native idempotent detach, also when nothing is attached.
        tree.Host.DetachListener();
        tree.Host.DetachListener();
        Assert.Equal(3, tree.Network.Count(FakeNetworkApi.DetachExport));
        connections[0].Dispose();
        Assert.Equal(0, tree.Network.Count(FakeNetworkApi.CloseExport));

        // Replacement is detach, then attach; nothing is reset.
        SasPairingWindowsListenerSocket l2 = FakeTree.Token(0x2222);
        tree.Host.AttachWindowsListener(l2, FakeTree.Bootstrap());
        Assert.True(l2.IsTransferred);
        Assert.Equal(SasPairingHostNetworkState.Attached, tree.Host.NetworkState);
        Assert.Equal(1, tree.Lifecycle.Count(FakeLifecycleApi.HostCreateExport));
    }

    [Fact]
    public void AFailedDetachStillDetachesLocallyAndIsThrownOnce()
    {
        FakeTree tree = new();
        SasPairingConnection[] connections = tree.AttachWithConnections(100);
        tree.Network.DetachStatus = AbiV1Constants.SAS_PAIRING_OWNERSHIP_UNCERTAIN;

        SasPairingNativeException failure = Assert.Throws<SasPairingNativeException>(tree.Host.DetachListener);

        Assert.Equal(SasPairingStatus.OwnershipUncertain, failure.KnownStatus);
        Assert.Equal("SasPairingHost.DetachListener", failure.Operation);
        Assert.Equal(SasPairingHostNetworkState.Detached, tree.Host.NetworkState);
        Assert.True(connections[0].IsDisposed);
        Assert.Equal(0, tree.Network.Count(FakeNetworkApi.CloseExport));
        Assert.False(tree.Host.IsDisposed);
    }

    [Fact]
    public void DetachRunsAfterFatalAndAfterAContractViolationAndNeverOnADisposedHost()
    {
        FakeTree fatal = new();
        SasPairingConnection[] connections = fatal.AttachWithConnections(100);
        fatal.Context.Observe(AbiV1Constants.SAS_PAIRING_FATAL);
        fatal.Host.DetachListener();
        Assert.Equal(1, fatal.Network.Count(FakeNetworkApi.DetachExport));
        Assert.True(connections[0].IsDisposed);
        Assert.True(fatal.Context.IsFatal);

        FakeTree violated = new();
        violated.Attach();
        _ = violated.Context.ViolateContract("test", "a probe");
        violated.Host.DetachListener();
        Assert.Equal(1, violated.Network.Count(FakeNetworkApi.DetachExport));

        violated.Host.Dispose();
        Assert.Throws<ObjectDisposedException>(violated.Host.DetachListener);
        Assert.Equal(1, violated.Network.Count(FakeNetworkApi.DetachExport));
    }

    [Fact]
    public void FromSocketIsWindowsOnlyAndTakesTheCallersSocketIntoTheToken()
    {
        Assert.Throws<ArgumentNullException>(() => SasPairingWindowsListenerSocket.FromSocket(null!));
        using Socket listener = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        listener.Listen(4);
        int port = ((IPEndPoint)listener.LocalEndPoint!).Port;

        if (!OperatingSystem.IsWindows())
        {
            // Refused before the socket is touched: it is still the caller's, open and listening.
            Assert.Throws<PlatformNotSupportedException>(() => SasPairingWindowsListenerSocket.FromSocket(listener));
            Assert.False(listener.SafeHandle.IsClosed);
            Assert.True(listener.IsBound);
            return;
        }

        SasPairingWindowsListenerSocket token = SasPairingWindowsListenerSocket.FromSocket(listener);
        Assert.False(token.IsTransferred);

        // The caller's Socket object was closed by .NET; the listening socket lives on in the token.
        Assert.Throws<ObjectDisposedException>(() => listener.LocalEndPoint);
        listener.Dispose();
        using (Socket client = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
        {
            client.Connect(IPAddress.Loopback, port);
        }

        // Disposing the untransferred token closes the socket: nothing listens on the port any more.
        token.Dispose();
        using Socket refused = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        Assert.Throws<SocketException>(() => refused.Connect(IPAddress.Loopback, port));
        Assert.Throws<ObjectDisposedException>(() => FakeAttach(token));
    }

    private static void FakeAttach(SasPairingWindowsListenerSocket token) => new FakeTree().Host.AttachWindowsListener(token, FakeTree.Bootstrap());
}
