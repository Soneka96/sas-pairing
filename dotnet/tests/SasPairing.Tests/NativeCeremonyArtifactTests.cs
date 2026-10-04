using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace SasPairing.Tests;

/// <summary>
/// The P9.4 trusted-local ceremony through the PUBLIC .NET API against the real native library named by
/// <c>SAS_PAIRING_NATIVE_LIBRARY</c> (built from the same commit in CI). One runtime holds two independent
/// endpoints (authority, host, listener, accepted connection each); a test-only relay copies bytes between two
/// loopback clients, unchanged. Every protocol frame is produced, written, read, and judged by the native library
/// inside a public drive; the test plays both users, compares the two SAS displays itself, and makes every
/// ceremony step explicitly. On Linux no pairing exists (the token is refused and authority registration fails
/// closed); no Linux pairing is claimed. Every wait is bounded; nothing loops forever, and nothing is threaded.
/// </summary>
[Collection(RealNativeTests.Name)]
public sealed partial class NativeCeremonyArtifactTests
{
    private const int MaxRounds = 80;

    private static readonly byte[] SharedContext = "p9.4 two-sided shared context"u8.ToArray();

    /// <summary>Endpoint A's trusted-local configuration (the protocol Initiator).</summary>
    private static SasPairingBootstrap BootstrapA() => new("p9.4 two-sided endpoint A (Initiator)"u8, "p94.test-key"u8, [.. Enumerable.Repeat((byte)0xA9, 32)], SharedContext);

    /// <summary>Endpoint B's trusted-local configuration (the protocol Responder).</summary>
    private static SasPairingBootstrap BootstrapB() => new("p9.4 two-sided endpoint B (Responder)"u8, "p94.test-key"u8, [.. Enumerable.Repeat((byte)0xB9, 32)], SharedContext);

    private static byte[] UniqueScope(string tag) => [.. "sas-pairing-dotnet-p9.4-"u8, .. System.Text.Encoding.ASCII.GetBytes(tag), 0x00, 0x80, 0xFF, .. Guid.NewGuid().ToByteArray()];

    private static (Socket Listener, int Port) ApplicationListener()
    {
        Socket listener = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        listener.Listen(8);
        return (listener, ((IPEndPoint)listener.LocalEndPoint!).Port);
    }

    private static bool Inbound(SasPairingEvent e, SasPairingProtocolEvent protocol) =>
        e.Kind == SasPairingEventKind.ConnectionStep && e.StepKind == SasPairingStepKind.Inbound && e.ProtocolEvent == protocol;

    private static SasPairingAuthorityStatus Ready(uint remaining) => new(SasPairingAuthorityState.Ready, remaining);

    /// <summary>
    /// TEST-ONLY byte-transparent relay between two loopback TCP clients: every byte read from one socket is
    /// written to the other unchanged. It never parses, builds, inspects, or alters a protocol frame and computes
    /// nothing; it only counts bytes. It is pumped synchronously between drives (no thread, task, or timer).
    /// </summary>
    private sealed class Relay : IDisposable
    {
        private readonly Socket _a;
        private readonly Socket _b;
        private readonly byte[] _buffer = new byte[64 * 1024];

        internal Relay(int portA, int portB)
        {
            _a = Connect(portA);
            _b = Connect(portB);
        }

        internal long AToB { get; private set; }

        internal long BToA { get; private set; }

        internal void Pump()
        {
            AToB += Copy(_a, _b);
            BToA += Copy(_b, _a);
        }

        public void Dispose()
        {
            _a.Dispose();
            _b.Dispose();
        }

        private static Socket Connect(int port)
        {
            Socket client = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            client.Connect(IPAddress.Loopback, port);
            return client;
        }

        private int Copy(Socket from, Socket to)
        {
            int copied = 0;
            while (from.Available > 0)
            {
                int read = from.Receive(_buffer);
                to.Send(_buffer, 0, read, SocketFlags.None);
                copied += read;
            }

            return copied;
        }
    }

    /// <summary>Two hosts driven alternately (each drive one bounded native call), with the relay pumped between them; every event kept per host, in order.</summary>
    private sealed class Pump(SasPairingHost a, SasPairingHost b, Relay relay)
    {
        internal List<SasPairingEvent> EventsA { get; } = [];

        internal List<SasPairingEvent> EventsB { get; } = [];

        /// <summary>Drives both hosts until <paramref name="done"/> holds over the events produced from now on (bounded).</summary>
        internal void Until(string what, Func<IReadOnlyList<SasPairingEvent>, IReadOnlyList<SasPairingEvent>, bool> done)
        {
            int fromA = EventsA.Count;
            int fromB = EventsB.Count;
            for (int round = 0; round < MaxRounds; round++)
            {
                Once(a);
                relay.Pump();
                Once(b);
                relay.Pump();
                if (done(EventsA[fromA..], EventsB[fromB..]))
                {
                    return;
                }
            }

            Assert.Fail($"no \"{what}\" after {MaxRounds} rounds: A [{Describe(EventsA[fromA..])}] B [{Describe(EventsB[fromB..])}]");
        }

        /// <summary>One drive of <paramref name="host"/> alone: the events it produced.</summary>
        internal IReadOnlyList<SasPairingEvent> Once(SasPairingHost host)
        {
            SasPairingDriveBatch batch = host.Drive();
            Assert.Null(batch.Failure);
            (ReferenceEquals(host, a) ? EventsA : EventsB).AddRange(batch.Events);
            return batch.Events;
        }

        private static string Describe(IEnumerable<SasPairingEvent> events) =>
            string.Join(", ", events.Select(e => $"{e.Kind}/{e.StepKind}/{e.ProtocolEvent}{(e.HasTrackedRun ? "/run" : "")}{(e.HasResult ? "/result" : "")}"));
    }

    /// <summary>One endpoint: its authority, host, and the handoff token of its listening socket.</summary>
    private sealed record Endpoint(SasPairingAuthority Authority, SasPairingHost Host, SasPairingWindowsListenerSocket Token, int Port);

    private static Endpoint Open(SasPairingRuntime runtime, string tag, SasPairingBootstrap local, SasPairingBootstrap expected)
    {
        SasPairingAuthority authority = runtime.RegisterAuthority(UniqueScope(tag));
        SasPairingHost host = authority.CreateHost();
        (Socket listener, int port) = ApplicationListener();
        SasPairingWindowsListenerSocket token = SasPairingWindowsListenerSocket.FromSocket(listener);
        host.AttachWindowsListener(token, local, expected);
        Assert.True(token.IsTransferred);
        return new Endpoint(authority, host, token, port);
    }

    /// <summary>The two endpoints, the relay, and both accepted connections.</summary>
    private static (Endpoint A, Endpoint B, Relay Relay, Pump Pump, SasPairingConnection ConnectionA, SasPairingConnection ConnectionB) Connect(SasPairingRuntime runtime, string tag)
    {
        Endpoint a = Open(runtime, tag + "-a", BootstrapA(), BootstrapB());
        Endpoint b = Open(runtime, tag + "-b", BootstrapB(), BootstrapA());
        Assert.Equal(Ready(10), a.Authority.GetStatus());
        Assert.Equal(Ready(10), b.Authority.GetStatus());

        Relay relay = new(a.Port, b.Port);
        Pump pump = new(a.Host, b.Host, relay);
        static bool Accepted(SasPairingEvent e) => e.Kind == SasPairingEventKind.ConnectionAccepted;
        pump.Until("both accepted", (_, _) => pump.EventsA.Any(Accepted) && pump.EventsB.Any(Accepted));
        return (a, b, relay, pump, pump.EventsA.Single(Accepted).Connection!, pump.EventsB.Single(Accepted).Connection!);
    }

    /// <summary>Off Windows: the token is refused before the socket is touched, and no host can exist.</summary>
    private static void AssertNoLinuxPairing(string path)
    {
        (Socket listener, _) = ApplicationListener();
        using (listener)
        {
            Assert.Throws<PlatformNotSupportedException>(() => SasPairingWindowsListenerSocket.FromSocket(listener));
        }

        using SasPairingRuntime runtime = SasPairingRuntime.Create(path);
        Assert.Equal(SasPairingStatus.UnsupportedPlatform, Assert.Throws<SasPairingNativeException>(() => runtime.RegisterAuthority(UniqueScope("linux"))).KnownStatus);
    }

    [Fact]
    public void TheTwoSidedCeremonyRunsThroughThePublicApiWithEveryStepExplicit()
    {
        string path = NativeArtifactTests.ArtifactPath();
        if (!OperatingSystem.IsWindows())
        {
            AssertNoLinuxPairing(path);
            return;
        }

        SasPairingRuntime runtime = SasPairingRuntime.Create(path);
        Relay? relay = null;
        try
        {
            (Endpoint a, Endpoint b, relay, Pump pump, SasPairingConnection connectionA, SasPairingConnection connectionB) = Connect(runtime, "healthy");

            // 1. Endpoint A starts the Initiator explicitly: nothing is driven, authorized, or spent.
            SasPairingLocalAction started = connectionA.StartInitiator(BootstrapA(), BootstrapB());
            Assert.Equal((SasPairingLocalEvent.InitiatorStarted, true, SasPairingDeadlineKind.None), (started.Event, started.WritePending, started.DeadlineKind));
            SasPairingRun runA = started.Run!;
            Assert.False(runA.IsEnded);

            // A second start while START is still retained did NOT run (status 205), and nothing recovers it.
            SasPairingNativeException pendingStart = Assert.Throws<SasPairingNativeException>(() => connectionA.StartInitiator(BootstrapA(), BootstrapB()));
            Assert.Equal((205, SasPairingStatus.WritePending), (pendingStart.StatusCode, pendingStart.KnownStatus));
            Assert.Same(runA, Assert.Single(connectionA.Runs));

            // 2. The Responder run surfaces on B through a drive event; ACCEPT is retained there.
            pump.Until("START_ACCEPTED at B", (_, eb) => eb.Any(e => Inbound(e, SasPairingProtocolEvent.StartAccepted)));
            SasPairingEvent startAccepted = pump.EventsB.Single(e => Inbound(e, SasPairingProtocolEvent.StartAccepted));
            Assert.Same(connectionB, startAccepted.Connection);
            Assert.True(startAccepted.HasTrackedRun);
            SasPairingRun runB = startAccepted.Run!;
            Assert.Equal(16, startAccepted.RequestId.Length);

            // 3. ACCEPT reaches A and names A's run: the very object StartInitiator returned.
            pump.Until("ACCEPT at A", (ea, _) => ea.Any(e => Inbound(e, SasPairingProtocolEvent.Accept)));
            SasPairingEvent accept = pump.EventsA.Single(e => Inbound(e, SasPairingProtocolEvent.Accept));
            Assert.Same(runA, accept.Run);
            Assert.True(accept.RequestId.SequenceEqual(startAccepted.RequestId));

            // 4. A: explicit authorization (spends nothing), then the explicit spending exposure.
            SasPairingLocalAction authorizedA = runA.AuthorizeExposure();
            Assert.Equal((SasPairingLocalEvent.ExposureAuthorized, false), (authorizedA.Event, authorizedA.WritePending));
            Assert.Same(runA, authorizedA.Run);
            Assert.Equal(Ready(10), a.Authority.GetStatus());
            SasPairingLocalAction exposedA = runA.ExposeKey();
            Assert.Equal((SasPairingLocalEvent.KeyExposed, true), (exposedA.Event, exposedA.WritePending));
            Assert.Same(runA, exposedA.Run);
            Assert.Equal(new SasPairingAuthorityStatus(SasPairingAuthorityState.Busy, 0), a.Authority.GetStatus());

            // Read-only presentation while A's key is retained reaches native: no SAS exists yet.
            Assert.Null(runA.Presentation());

            // 5. INITIATOR_KEY reaches B on B's run.
            pump.Until("INITIATOR_KEY at B", (_, eb) => eb.Any(e => Inbound(e, SasPairingProtocolEvent.InitiatorKey)));
            Assert.Same(runB, pump.EventsB.Single(e => Inbound(e, SasPairingProtocolEvent.InitiatorKey)).Run);

            // 6. B: explicit authorization and exposure; B's SAS is presentable while its own key is still retained.
            Assert.Equal(SasPairingLocalEvent.ExposureAuthorized, runB.AuthorizeExposure().Event);
            Assert.Equal(Ready(10), b.Authority.GetStatus());
            SasPairingLocalAction exposedB = runB.ExposeKey();
            Assert.Equal((SasPairingLocalEvent.KeyExposed, true), (exposedB.Event, exposedB.WritePending));
            Assert.Equal(new SasPairingAuthorityStatus(SasPairingAuthorityState.Busy, 0), b.Authority.GetStatus());
            SasPairingSasPresentation presentationB = runB.Presentation()!;
            Assert.NotNull(presentationB);

            // 7. RESPONDER_KEY reaches A; A's SAS is live.
            pump.Until("RESPONDER_KEY at A", (ea, _) => ea.Any(e => Inbound(e, SasPairingProtocolEvent.ResponderKey)));
            SasPairingSasPresentation presentationA = runA.Presentation()!;
            Assert.NotNull(presentationA);

            // 8. The test plays both users: it compares the two displays itself, and only then decides MATCH.
            Assert.Matches(DecimalShape(), presentationA.DecimalDisplay);
            Assert.Matches(DecimalShape(), presentationB.DecimalDisplay);
            Assert.Equal(presentationA.DecimalDisplay, presentationB.DecimalDisplay);
            Assert.Equal(presentationA.CeremonyIdentity, presentationB.CeremonyIdentity);
            Assert.Equal(32, presentationA.CeremonyIdentity.Bytes.Length);
            TestContext.Current.TestOutputHelper?.WriteLine(
                $"SAS A \"{presentationA.DecimalDisplay}\" B \"{presentationB.DecimalDisplay}\"; identity A {Convert.ToHexString(presentationA.CeremonyIdentity.Bytes)} B {Convert.ToHexString(presentationB.CeremonyIdentity.Bytes)}");

            SasPairingLocalAction approvedA = runA.ApproveSas(presentationA.CeremonyIdentity);
            Assert.Equal((SasPairingLocalEvent.SasApproved, false), (approvedA.Event, approvedA.WritePending));

            // MATCH emitted nothing: one drive of each host authenticates no BOOTSTRAP_MAC anywhere.
            IReadOnlyList<SasPairingEvent> afterApproveA = pump.Once(a.Host);
            relay.Pump();
            IReadOnlyList<SasPairingEvent> afterApproveB = pump.Once(b.Host);
            Assert.DoesNotContain(afterApproveA.Concat(afterApproveB), e => Inbound(e, SasPairingProtocolEvent.BootstrapMacAuthenticated));
            Assert.Null(runA.Presentation()); // decided locally: nothing left to present

            // 9. A's BOOTSTRAP_MAC is its own explicit step. A second mutating action before the drive did NOT run
            //    (205); after the frame was written, the retry reports the MAC as already emitted (produced once).
            SasPairingLocalAction macA = runA.EmitBootstrapMac();
            Assert.Equal((SasPairingLocalEvent.BootstrapMacEmitted, true), (macA.Event, macA.WritePending));
            Assert.Equal(SasPairingStatus.WritePending, Assert.Throws<SasPairingNativeException>(() => runA.EmitBootstrapMac()).KnownStatus);
            pump.Until("A's MAC written", (ea, _) => ea.Any(e => ReferenceEquals(e.Connection, connectionA) && e.StepKind == SasPairingStepKind.Written));
            SasPairingLocalAction macAgainA = runA.EmitBootstrapMac();
            Assert.Equal((SasPairingLocalEvent.BootstrapMacAlreadyEmitted, false), (macAgainA.Event, macAgainA.WritePending));
            Assert.Same(runA, macAgainA.Run);

            // 10. B: MATCH, then its own MAC, each explicit.
            SasPairingLocalAction approvedB = runB.ApproveSas(presentationB.CeremonyIdentity);
            Assert.Equal((SasPairingLocalEvent.SasApproved, false), (approvedB.Event, approvedB.WritePending));
            SasPairingLocalAction macB = runB.EmitBootstrapMac();
            Assert.Equal((SasPairingLocalEvent.BootstrapMacEmitted, true), (macB.Event, macB.WritePending));

            // 11. Both MACs are authenticated by their peers, on the same run objects.
            pump.Until("both MACs authenticated", (_, _) =>
                pump.EventsA.Any(e => Inbound(e, SasPairingProtocolEvent.BootstrapMacAuthenticated)) && pump.EventsB.Any(e => Inbound(e, SasPairingProtocolEvent.BootstrapMacAuthenticated)));
            Assert.Same(runA, pump.EventsA.Single(e => Inbound(e, SasPairingProtocolEvent.BootstrapMacAuthenticated)).Run);
            Assert.Same(runB, pump.EventsB.Single(e => Inbound(e, SasPairingProtocolEvent.BootstrapMacAuthenticated)).Run);

            // With nothing retained on B, the Responder's INITIATOR_FINISH is refused by its role, and its run continues.
            SasPairingNativeException notInitiator = Assert.Throws<SasPairingNativeException>(() => runB.EmitInitiatorFinish());
            Assert.Equal((217, SasPairingStatus.NotInitiator), (notInitiator.StatusCode, notInitiator.KnownStatus));
            Assert.False(runB.IsEnded);

            // 12. Only the Initiator, explicitly, emits INITIATOR_FINISH. There is no final-ACK call: the native
            //     library writes the frames and confirms the final ACK itself.
            SasPairingLocalAction finishA = runA.EmitInitiatorFinish();
            Assert.Equal((SasPairingLocalEvent.InitiatorFinishEmitted, true), (finishA.Event, finishA.WritePending));
            Assert.Same(runA, finishA.Run);

            // 13. Drive until each endpoint surfaced its local result. Nothing of it is read (P9.5).
            pump.Until("both local results", (_, _) => pump.EventsA.Any(e => e.HasResult) && pump.EventsB.Any(e => e.HasResult));
            for (int i = 0; i < 3; i++)
            {
                pump.Once(a.Host);
                relay.Pump();
                pump.Once(b.Host);
            }

            SasPairingEvent resultA = Assert.Single(pump.EventsA, e => e.HasResult);
            SasPairingEvent resultB = Assert.Single(pump.EventsB, e => e.HasResult);
            Assert.Equal(SasPairingStepKind.Confirmed, resultA.StepKind);
            Assert.True(Inbound(resultB, SasPairingProtocolEvent.InitiatorFinishAck));
            Assert.Null(resultA.Run);
            Assert.Null(resultB.Run);

            // 14. Both runs have visibly ended; a later step is refused locally, before native.
            Assert.True(runA.IsEnded);
            Assert.True(runB.IsEnded);
            Assert.Equal("SasPairingRun.EmitInitiatorFinish", Assert.Throws<SasPairingRunEndedException>(() => runA.EmitInitiatorFinish()).Operation);
            Assert.Throws<SasPairingRunEndedException>(() => runB.Presentation());

            // 15. Native accounting only: each authority spent exactly one opportunity, at its exposure.
            Assert.Equal(Ready(9), a.Authority.GetStatus());
            Assert.Equal(Ready(9), b.Authority.GetStatus());
            Assert.True(relay.AToB > 0 && relay.BToA > 0);
            Assert.Single(pump.EventsB, e => Inbound(e, SasPairingProtocolEvent.StartAccepted));
            TestContext.Current.TestOutputHelper?.WriteLine(
                $"results A {pump.EventsA.Count(e => e.HasResult)} B {pump.EventsB.Count(e => e.HasResult)}; authorities A {a.Authority.GetStatus()} B {b.Authority.GetStatus()}; relay A->B {relay.AToB} B->A {relay.BToA} bytes; request ID {startAccepted.RequestId.Length} bytes");

            a.Host.DetachListener();
            b.Host.DetachListener();
            Assert.True(connectionA.IsDisposed && connectionB.IsDisposed);
        }
        finally
        {
            relay?.Dispose();
            runtime.Dispose();
        }

        Assert.False(runtime.Context.IsFatal || runtime.Context.IsContractViolated);
    }

    [Fact]
    public void AnUnpresentedIdentityIsRefusedNativelyAndAnExplicitMismatchEndsTheRun()
    {
        string path = NativeArtifactTests.ArtifactPath();
        if (!OperatingSystem.IsWindows())
        {
            AssertNoLinuxPairing(path);
            return;
        }

        SasPairingRuntime runtime = SasPairingRuntime.Create(path);
        Relay? relay = null;
        try
        {
            (Endpoint a, Endpoint b, relay, Pump pump, SasPairingConnection connectionA, SasPairingConnection connectionB) = Connect(runtime, "mismatch");
            SasPairingRun runA = connectionA.StartInitiator(BootstrapA(), BootstrapB()).Run!;
            pump.Until("START_ACCEPTED at B", (_, eb) => eb.Any(e => Inbound(e, SasPairingProtocolEvent.StartAccepted)));
            SasPairingRun runB = pump.EventsB.Single(e => Inbound(e, SasPairingProtocolEvent.StartAccepted)).Run!;
            pump.Until("ACCEPT at A", (ea, _) => ea.Any(e => Inbound(e, SasPairingProtocolEvent.Accept)));
            runA.AuthorizeExposure();
            runA.ExposeKey();
            pump.Until("INITIATOR_KEY at B", (_, eb) => eb.Any(e => Inbound(e, SasPairingProtocolEvent.InitiatorKey)));
            runB.AuthorizeExposure();
            runB.ExposeKey();
            pump.Until("RESPONDER_KEY at A", (ea, _) => ea.Any(e => Inbound(e, SasPairingProtocolEvent.ResponderKey)));
            SasPairingSasPresentation presentationA = runA.Presentation()!;

            // An identity that was never presented (test-only construction) is judged by native alone: 208, no change.
            byte[] other = presentationA.CeremonyIdentity.Bytes.ToArray();
            other[0] ^= 0xFF;
            SasPairingNativeException mismatch = Assert.Throws<SasPairingNativeException>(() => runA.ApproveSas(new SasPairingCeremonyIdentity(other)));
            Assert.Equal((208, SasPairingStatus.CeremonyIdentityMismatch), (mismatch.StatusCode, mismatch.KnownStatus));
            Assert.False(runA.IsEnded);
            Assert.Equal(presentationA.CeremonyIdentity, runA.Presentation()!.CeremonyIdentity);

            // The user chose MISMATCH: the run ends at once, its opportunity stays spent, the connection stays open.
            SasPairingLocalAction rejected = runA.RejectSas(presentationA.CeremonyIdentity);
            Assert.Equal(SasPairingLocalEvent.SasRejected, rejected.Event);
            Assert.Null(rejected.Run);
            Assert.True(runA.IsEnded);
            Assert.False(connectionA.IsDisposed);
            Assert.Throws<SasPairingRunEndedException>(() => runA.ApproveSas(presentationA.CeremonyIdentity));

            // The SAS existed, so native built and retained the best-effort authenticated CANCEL; a drive writes it,
            // and it reaches B as a verified peer cancel that ends B's run visibly (no automatic close anywhere).
            Assert.True(rejected.WritePending);
            pump.Until("PEER_CANCEL at B", (_, eb) => eb.Any(e => Inbound(e, SasPairingProtocolEvent.PeerCancel)));
            Assert.Equal(SasPairingCancelReason.UserRejection, pump.EventsB.Single(e => Inbound(e, SasPairingProtocolEvent.PeerCancel)).CancelReason);
            Assert.True(runB.IsEnded);

            Assert.DoesNotContain(pump.EventsA.Concat(pump.EventsB), e => e.HasResult);
            Assert.Equal(Ready(9), a.Authority.GetStatus());
            Assert.Equal(Ready(9), b.Authority.GetStatus());
            Assert.False(connectionB.IsDisposed);
        }
        finally
        {
            relay?.Dispose();
            runtime.Dispose();
        }

        Assert.False(runtime.Context.IsFatal || runtime.Context.IsContractViolated);
    }

    [GeneratedRegex(@"^[0-9]{4} [0-9]{4} [0-9]{4}$")]
    private static partial Regex DecimalShape();
}
