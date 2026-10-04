using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace SasPairing.Tests;

/// <summary>
/// The P9.3 network wrapper through the PUBLIC API against the real native library named by
/// <c>SAS_PAIRING_NATIVE_LIBRARY</c> (built from the same commit in CI). On Windows: the managed socket
/// handoff (the native listener keeps working after the caller's <see cref="Socket"/> is disposed and every
/// managed finalizer ran), accept and peer close with one connection object, deterministic connection disposal,
/// listener replacement, and one resume recheck. On Linux: the listener token is refused with
/// <see cref="PlatformNotSupportedException"/> and no host can exist (authority registration fails closed); no
/// Linux pairing is claimed. Every wait is bounded; nothing loops forever.
/// </summary>
[Collection(RealNativeTests.Name)]
public sealed class NativeNetworkArtifactTests
{
    private const int MaxDrives = 40;

    /// <summary>
    /// The Bootstrap the core's own ABI listener tests accept (<c>core/src/abi/tests/listener.rs</c>, the view
    /// also used by the reviewed P8 Dart real-network tests): application <c>p7-listener-application</c>, key
    /// algorithm <c>x25519</c>, a 32-byte key of 7s, and an empty shared context.
    /// </summary>
    private static SasPairingBootstrap ValidBootstrap() => new("p7-listener-application"u8, "x25519"u8, [.. Enumerable.Repeat((byte)7, 32)], []);

    /// <summary>The same with the uppercase key algorithm the core refuses (<c>invalid_view</c> there).</summary>
    private static SasPairingBootstrap InvalidBootstrap() => new("p7-listener-application"u8, "X25519"u8, [.. Enumerable.Repeat((byte)7, 32)], []);

    private static byte[] UniqueScope(string tag) => [.. "sas-pairing-dotnet-p9.3-"u8, .. System.Text.Encoding.ASCII.GetBytes(tag), 0x00, 0x80, 0xFF, .. Guid.NewGuid().ToByteArray()];

    /// <summary>The application's part: a loopback TCP socket bound to an ephemeral port and listening.</summary>
    private static (Socket Listener, int Port) ApplicationListener()
    {
        Socket listener = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        listener.Listen(8);
        return (listener, ((IPEndPoint)listener.LocalEndPoint!).Port);
    }

    private static Socket Connect(int port)
    {
        Socket client = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        client.Connect(IPAddress.Loopback, port);
        return client;
    }

    /// <summary>Drives at most <see cref="MaxDrives"/> times, pausing between calls, until an event matches; returns every event seen.</summary>
    private static List<SasPairingEvent> DriveUntil(SasPairingHost host, Func<SasPairingEvent, bool> until)
    {
        List<SasPairingEvent> seen = [];
        for (int i = 0; i < MaxDrives; i++)
        {
            SasPairingDriveBatch batch = host.Drive();
            Assert.Null(batch.Failure);
            seen.AddRange(batch.Events);
            if (batch.Events.Any(until))
            {
                return seen;
            }

            Thread.Sleep(20);
        }

        Assert.Fail($"no matching event after {MaxDrives} drives: {string.Join(", ", seen.Select(e => e.Kind))}");
        return seen;
    }

    private static SasPairingConnection Accept(SasPairingHost host) =>
        DriveUntil(host, e => e.Kind == SasPairingEventKind.ConnectionAccepted).Single(e => e.Kind == SasPairingEventKind.ConnectionAccepted).Connection!;

    /// <summary>Off Windows: the token is refused before the socket is touched, and no host can exist.</summary>
    private static void AssertNoLinuxPairing(string path)
    {
        (Socket listener, _) = ApplicationListener();
        using (listener)
        {
            Assert.Throws<PlatformNotSupportedException>(() => SasPairingWindowsListenerSocket.FromSocket(listener));
            Assert.False(listener.SafeHandle.IsClosed);
        }

        using SasPairingRuntime runtime = SasPairingRuntime.Create(path);
        SasPairingNativeException failure = Assert.Throws<SasPairingNativeException>(() => runtime.RegisterAuthority(UniqueScope("linux")));
        Assert.Equal(SasPairingStatus.UnsupportedPlatform, failure.KnownStatus);
    }

    [Fact]
    public void TheSocketIsTransferredAndTheNativeListenerOutlivesTheCallersSocketAndEveryFinalizer()
    {
        string path = NativeArtifactTests.ArtifactPath();
        if (!OperatingSystem.IsWindows())
        {
            AssertNoLinuxPairing(path);
            return;
        }

        SasPairingRuntime runtime = SasPairingRuntime.Create(path);
        try
        {
            SasPairingHost host = runtime.RegisterAuthority(UniqueScope("transfer")).CreateHost();
            Assert.Equal(SasPairingHostNetworkState.Detached, host.NetworkState);
            Assert.Equal(SasPairingStatus.ListenerNotAttached, Assert.Throws<SasPairingNativeException>(host.Drive).KnownStatus);

            // A pre-adoption refusal: the socket stays the caller's (through the token), and disposing the token closes it.
            (Socket refusedSocket, int refusedPort) = ApplicationListener();
            SasPairingWindowsListenerSocket refused = SasPairingWindowsListenerSocket.FromSocket(refusedSocket);
            Assert.Equal(SasPairingStatus.InvalidBootstrap, Assert.Throws<SasPairingNativeException>(() => host.AttachWindowsListener(refused, InvalidBootstrap())).KnownStatus);
            Assert.False(refused.IsTransferred);
            Assert.Equal(SasPairingHostNetworkState.Detached, host.NetworkState);
            refused.Dispose();
            Assert.Throws<SocketException>(() => Connect(refusedPort).Dispose());

            (Socket listener, int port) = ApplicationListener();
            SasPairingWindowsListenerSocket token = SasPairingWindowsListenerSocket.FromSocket(listener);
            host.AttachWindowsListener(token, ValidBootstrap());
            Assert.True(token.IsTransferred);
            Assert.Equal(SasPairingHostNetworkState.Attached, host.NetworkState);

            // A second listener is refused before adoption and stays the caller's.
            (Socket otherSocket, _) = ApplicationListener();
            using SasPairingWindowsListenerSocket other = SasPairingWindowsListenerSocket.FromSocket(otherSocket);
            Assert.Equal(SasPairingStatus.ListenerAlreadyAttached, Assert.Throws<SasPairingNativeException>(() => host.AttachWindowsListener(other, ValidBootstrap())).KnownStatus);
            Assert.False(other.IsTransferred);

            // The application disposes its original Socket and every managed finalizer runs: nothing closes the
            // native-owned socket, which still accepts.
            listener.Dispose();
            token.Dispose();
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
            using Socket client = Connect(port);
            SasPairingConnection connection = Accept(host);
            Assert.False(connection.IsDisposed);

            // One drive with nothing ready waits about 250 ms at most.
            Stopwatch watch = Stopwatch.StartNew();
            SasPairingDriveBatch quiet = host.Drive();
            Assert.Null(quiet.Failure);
            Assert.True(watch.ElapsedMilliseconds < 5000, $"{watch.ElapsedMilliseconds} ms");

            host.DetachListener();
            Assert.Equal(SasPairingHostNetworkState.Detached, host.NetworkState);
            Assert.True(connection.IsDisposed);
            Assert.False(host.IsDisposed);
            Assert.Equal(SasPairingStatus.ListenerNotAttached, Assert.Throws<SasPairingNativeException>(host.Drive).KnownStatus);
            host.DetachListener(); // idempotent natively
        }
        finally
        {
            runtime.Dispose();
        }

        Assert.False(runtime.Context.IsFatal || runtime.Context.IsContractViolated);
    }

    [Fact]
    public void AnAcceptedConnectionIsOneObjectUntilThePeerClosesIt()
    {
        string path = NativeArtifactTests.ArtifactPath();
        if (!OperatingSystem.IsWindows())
        {
            AssertNoLinuxPairing(path);
            return;
        }

        using SasPairingRuntime runtime = SasPairingRuntime.Create(path);
        SasPairingHost host = runtime.RegisterAuthority(UniqueScope("accept")).CreateHost();
        (Socket listener, int port) = ApplicationListener();
        host.AttachWindowsListener(SasPairingWindowsListenerSocket.FromSocket(listener), ValidBootstrap());

        Socket client = Connect(port);
        SasPairingConnection connection = Accept(host);
        Assert.False(connection.IsDisposed);

        client.Shutdown(SocketShutdown.Both);
        client.Dispose();
        List<SasPairingEvent> later = DriveUntil(host, e => e.Kind == SasPairingEventKind.ConnectionClosed);

        SasPairingEvent closed = later.Single(e => e.Kind == SasPairingEventKind.ConnectionClosed);
        Assert.Same(connection, closed.Connection);
        Assert.All(later.Where(e => e.Connection is not null), e => Assert.Same(connection, e.Connection));
        Assert.True(connection.IsDisposed);
        connection.Dispose(); // already ended natively: no call, no exception
        Assert.Equal(SasPairingHostNetworkState.Attached, host.NetworkState);
        host.DetachListener();
    }

    [Fact]
    public void AManuallyDisposedConnectionIsClosedDeterministically()
    {
        string path = NativeArtifactTests.ArtifactPath();
        if (!OperatingSystem.IsWindows())
        {
            AssertNoLinuxPairing(path);
            return;
        }

        using SasPairingRuntime runtime = SasPairingRuntime.Create(path);
        SasPairingHost host = runtime.RegisterAuthority(UniqueScope("dispose")).CreateHost();
        (Socket listener, int port) = ApplicationListener();
        host.AttachWindowsListener(SasPairingWindowsListenerSocket.FromSocket(listener), ValidBootstrap());
        using Socket client = Connect(port);
        SasPairingConnection connection = Accept(host);

        connection.Dispose();
        Assert.True(connection.IsDisposed);
        connection.Dispose();

        // The peer sees the close (end of stream or a reset), and the host keeps running.
        client.ReceiveTimeout = 5000;
        try
        {
            Assert.Equal(0, client.Receive(new byte[16]));
        }
        catch (SocketException reset) when (reset.SocketErrorCode == SocketError.ConnectionReset)
        {
        }

        Assert.Null(host.Drive().Failure);
        Assert.Equal(SasPairingHostNetworkState.Attached, host.NetworkState);
        host.Dispose();
        Assert.Equal(SasPairingHostNetworkState.Detached, host.NetworkState);
    }

    [Fact]
    public void AListenerIsReplacedByDetachThenAttach()
    {
        string path = NativeArtifactTests.ArtifactPath();
        if (!OperatingSystem.IsWindows())
        {
            AssertNoLinuxPairing(path);
            return;
        }

        using SasPairingRuntime runtime = SasPairingRuntime.Create(path);
        SasPairingAuthority authority = runtime.RegisterAuthority(UniqueScope("replace"));
        SasPairingHost host = authority.CreateHost();
        SasPairingAuthorityStatus before = authority.GetStatus();

        (Socket s1, int p1) = ApplicationListener();
        SasPairingWindowsListenerSocket l1 = SasPairingWindowsListenerSocket.FromSocket(s1);
        host.AttachWindowsListener(l1, ValidBootstrap());
        using Socket client1 = Connect(p1);
        SasPairingConnection c1 = Accept(host);

        host.DetachListener();
        Assert.True(c1.IsDisposed);
        Assert.Equal(SasPairingHostNetworkState.Detached, host.NetworkState);

        (Socket s2, int p2) = ApplicationListener();
        SasPairingWindowsListenerSocket l2 = SasPairingWindowsListenerSocket.FromSocket(s2);
        host.AttachWindowsListener(l2, ValidBootstrap());
        Assert.True(l1.IsTransferred && l2.IsTransferred);
        Assert.Throws<InvalidOperationException>(() => host.AttachWindowsListener(l1, ValidBootstrap()));
        using Socket client2 = Connect(p2);
        SasPairingConnection c2 = Accept(host);

        Assert.NotSame(c1, c2);
        Assert.False(c2.IsDisposed);
        Assert.Equal(SasPairingHostNetworkState.Attached, host.NetworkState);

        // L1 is gone with its detach; replacement resets no accounting.
        Assert.Throws<SocketException>(() => Connect(p1).Dispose());
        Assert.Equal(before, authority.GetStatus());
        host.DetachListener();
    }

    [Fact]
    public void OneRecheckAfterResumeIsOneNativeSweep()
    {
        string path = NativeArtifactTests.ArtifactPath();
        if (!OperatingSystem.IsWindows())
        {
            AssertNoLinuxPairing(path);
            return;
        }

        using SasPairingRuntime runtime = SasPairingRuntime.Create(path);
        SasPairingHost host = runtime.RegisterAuthority(UniqueScope("recheck")).CreateHost();
        Assert.Equal(SasPairingStatus.ListenerNotAttached, Assert.Throws<SasPairingNativeException>(host.RecheckAfterResume).KnownStatus);
        (Socket listener, int port) = ApplicationListener();
        host.AttachWindowsListener(SasPairingWindowsListenerSocket.FromSocket(listener), ValidBootstrap());

        // A waiting client is not accepted by a recheck: it only sweeps deadlines.
        using Socket client = Connect(port);
        SasPairingDriveBatch resumed = host.RecheckAfterResume();

        Assert.Null(resumed.Failure);
        Assert.DoesNotContain(resumed.Events, e => e.Kind == SasPairingEventKind.ConnectionAccepted);
        Assert.Equal(SasPairingHostNetworkState.Attached, host.NetworkState);
        Assert.False(Accept(host).IsDisposed);
        host.DetachListener();
    }
}
