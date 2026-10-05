using System.Text.Json;
using SasPairing.Tests.Support;
using static SasPairing.Tests.NativeCeremonyArtifactTests;

namespace SasPairing.Tests;

/// <summary>
/// The P9.5 PairingResult API through the PUBLIC .NET API against the real native library named by
/// <c>SAS_PAIRING_NATIVE_LIBRARY</c> (built from the same commit in CI). The healthy P9.4 two-endpoint ceremony is
/// run with the frozen P3 remote test-vector Bootstrap inputs (<c>vectors/p3-remote-vodozemac-draft-01.json</c>), so
/// every authenticated byte field of each local result can be compared with exact source-proven fixture bytes
/// without any C# protocol encoder. This flow happens to complete on BOTH endpoints because the test drives both
/// honestly; one endpoint's result never proves that the other holds one (P6-D-005). On Linux no pairing exists
/// (the token is refused and authority registration fails closed); no Linux pairing is claimed.
/// </summary>
[Collection(RealNativeTests.Name)]
public sealed class NativeResultArtifactTests
{
    /// <summary>The frozen P3 remote test vector: the Bootstrap inputs and their exact canonical frames.</summary>
    private sealed record RemoteVector(
        SasPairingBootstrap Initiator,
        SasPairingBootstrap Responder,
        byte[] InitiatorFrame,
        byte[] ResponderFrame,
        byte[] SharedContext,
        byte[] ProfileIdentifier,
        uint ProfileVersion)
    {
        internal static RemoteVector Load()
        {
            using JsonDocument document = JsonDocument.Parse(File.ReadAllText(FrozenAbi.PathOf("vectors", "p3-remote-vodozemac-draft-01.json")));
            JsonElement root = document.RootElement;
            static byte[] Hex(JsonElement element) => Convert.FromHexString(element.GetProperty("hex").GetString()!);
            SasPairingBootstrap Bootstrap(string side)
            {
                JsonElement fields = root.GetProperty("bootstraps").GetProperty(side).GetProperty("fields");
                return new SasPairingBootstrap(
                    Hex(fields.GetProperty("application_identity")),
                    Hex(fields.GetProperty("key_algorithm")),
                    Hex(fields.GetProperty("public_key")),
                    Hex(fields.GetProperty("shared_context")));
            }

            JsonElement metadata = root.GetProperty("metadata");
            return new RemoteVector(
                Bootstrap("initiator"),
                Bootstrap("responder"),
                Hex(root.GetProperty("bootstraps").GetProperty("initiator")),
                Hex(root.GetProperty("bootstraps").GetProperty("responder")),
                Hex(root.GetProperty("inputs").GetProperty("shared_context")),
                [.. metadata.GetProperty("profile_identifier").GetString()!.Select(c => checked((byte)c))],
                metadata.GetProperty("profile_version").GetProperty("value").GetUInt32());
        }
    }

    private static void AssertSameData(SasPairingResultData expected, SasPairingResultData actual)
    {
        Assert.Equal(expected.CeremonyIdentity, actual.CeremonyIdentity);
        Assert.Equal((expected.PeerRole, expected.ProfileVersion), (actual.PeerRole, actual.ProfileVersion));
        Assert.True(expected.RequestId.SequenceEqual(actual.RequestId));
        Assert.True(expected.AuthenticatedPeerBootstrap.SequenceEqual(actual.AuthenticatedPeerBootstrap));
        Assert.True(expected.AuthenticatedSharedContext.SequenceEqual(actual.AuthenticatedSharedContext));
        Assert.True(expected.ProfileIdentifier.SequenceEqual(actual.ProfileIdentifier));
    }

    [Fact]
    public void BothLocalResultsAreReadThroughThePublicApiAndOutliveEveryLowerParent()
    {
        string path = NativeArtifactTests.ArtifactPath();
        if (!OperatingSystem.IsWindows())
        {
            AssertNoLinuxPairing(path);
            return;
        }

        RemoteVector vector = RemoteVector.Load();
        Assert.Equal(126, vector.InitiatorFrame.Length);
        Assert.Equal(126, vector.ResponderFrame.Length);
        SasPairingRuntime runtime = SasPairingRuntime.Create(path);
        Relay? relay = null;
        try
        {
            (Endpoint a, Endpoint b, relay, Pump pump, SasPairingConnection connectionA, SasPairingConnection connectionB) = Connect(runtime, "p95-result", vector.Initiator, vector.Responder);

            // 1. The healthy P9.4 ceremony, every step explicit: A is the Initiator, B the Responder.
            SasPairingRun runA = connectionA.StartInitiator(vector.Initiator, vector.Responder).Run!;
            pump.Until("START_ACCEPTED at B", (_, eb) => eb.Any(e => Inbound(e, SasPairingProtocolEvent.StartAccepted)));
            SasPairingEvent startAccepted = pump.EventsB.Single(e => Inbound(e, SasPairingProtocolEvent.StartAccepted));
            SasPairingRun runB = startAccepted.Run!;
            byte[] requestId = startAccepted.RequestId.ToArray();
            pump.Until("ACCEPT at A", (ea, _) => ea.Any(e => Inbound(e, SasPairingProtocolEvent.Accept)));
            Assert.True(pump.EventsA.Single(e => Inbound(e, SasPairingProtocolEvent.Accept)).RequestId.SequenceEqual(requestId));
            runA.AuthorizeExposure();
            runA.ExposeKey();
            pump.Until("INITIATOR_KEY at B", (_, eb) => eb.Any(e => Inbound(e, SasPairingProtocolEvent.InitiatorKey)));
            runB.AuthorizeExposure();
            runB.ExposeKey();
            SasPairingSasPresentation presentationB = runB.Presentation()!;
            pump.Until("RESPONDER_KEY at A", (ea, _) => ea.Any(e => Inbound(e, SasPairingProtocolEvent.ResponderKey)));
            SasPairingSasPresentation presentationA = runA.Presentation()!;

            // The test plays both users: it compares the displays itself before deciding MATCH on each side.
            Assert.Equal(presentationA.DecimalDisplay, presentationB.DecimalDisplay);
            runA.ApproveSas(presentationA.CeremonyIdentity);
            runA.EmitBootstrapMac();
            runB.ApproveSas(presentationB.CeremonyIdentity);
            runB.EmitBootstrapMac();
            pump.Until("both MACs authenticated", (_, _) =>
                pump.EventsA.Any(e => Inbound(e, SasPairingProtocolEvent.BootstrapMacAuthenticated)) && pump.EventsB.Any(e => Inbound(e, SasPairingProtocolEvent.BootstrapMacAuthenticated)));
            runA.EmitInitiatorFinish();
            pump.Until("both local results", (_, _) => pump.EventsA.Any(e => e.HasResult) && pump.EventsB.Any(e => e.HasResult));
            for (int i = 0; i < 3; i++)
            {
                pump.Once(a.Host);
                relay.Pump();
                pump.Once(b.Host);
            }

            // 2. Each side's single result event carries its public, runtime-owned result. This flow happens to
            //    produce both because both were driven honestly; neither result implies the other.
            SasPairingEvent eventA = Assert.Single(pump.EventsA, e => e.HasResult);
            SasPairingEvent eventB = Assert.Single(pump.EventsB, e => e.HasResult);
            SasPairingResult resultA = eventA.Result!;
            SasPairingResult resultB = eventB.Result!;
            Assert.True(eventA.HasResult && eventA.Result is not null);
            Assert.True(eventB.HasResult && eventB.Result is not null);
            Assert.Same(resultA, eventA.Result);
            Assert.NotSame(resultA, resultB);
            Assert.False(resultA.IsDisposed || resultB.IsDisposed);
            Assert.True(eventA.RequestId.SequenceEqual(requestId) && eventB.RequestId.SequenceEqual(requestId));

            // 3. Read both through the public API only.
            SasPairingResultData dataA = resultA.Read();
            SasPairingResultData dataB = resultB.Read();

            // The PEER's role: A (the Initiator) reports a Responder peer, B (the Responder) an Initiator peer.
            Assert.Equal(SasPairingPeerRole.Responder, dataA.PeerRole);
            Assert.Equal(SasPairingPeerRole.Initiator, dataB.PeerRole);

            // The ceremony identity each endpoint was presented, and the same transcript on both sides.
            Assert.Equal(presentationA.CeremonyIdentity, dataA.CeremonyIdentity);
            Assert.Equal(presentationB.CeremonyIdentity, dataB.CeremonyIdentity);
            Assert.Equal(dataA.CeremonyIdentity, dataB.CeremonyIdentity);

            // The exact request-ID bytes the drive events reported (16 CSPRNG bytes, never text).
            Assert.Equal(16, dataA.RequestId.Length);
            Assert.True(dataA.RequestId.SequenceEqual(requestId));
            Assert.True(dataB.RequestId.SequenceEqual(requestId));

            // The frozen profile: version 1 (protocol.rs VERSION, vector metadata) and the exact identifier bytes.
            Assert.Equal(1u, vector.ProfileVersion);
            Assert.Equal((vector.ProfileVersion, vector.ProfileVersion), (dataA.ProfileVersion, dataB.ProfileVersion));
            Assert.True(dataA.ProfileIdentifier.SequenceEqual(vector.ProfileIdentifier));
            Assert.True(dataB.ProfileIdentifier.SequenceEqual(vector.ProfileIdentifier));
            Assert.True(dataA.ProfileIdentifier.SequenceEqual("sas-pairing-vodozemac-profile-draft-01"u8));

            // The authenticated shared context and the peer's exact canonical Bootstrap frame, byte for byte the
            // frozen fixture's: A holds the Responder's frame, B the Initiator's. Nothing here parses either.
            Assert.True(dataA.AuthenticatedSharedContext.SequenceEqual(vector.SharedContext));
            Assert.True(dataB.AuthenticatedSharedContext.SequenceEqual(vector.SharedContext));
            Assert.True(dataA.AuthenticatedPeerBootstrap.SequenceEqual(vector.ResponderFrame));
            Assert.True(dataB.AuthenticatedPeerBootstrap.SequenceEqual(vector.InitiatorFrame));
            AssertSameData(dataA, resultA.Read());
            TestContext.Current.TestOutputHelper?.WriteLine(
                $"identity {Convert.ToHexString(dataA.CeremonyIdentity.Bytes)}; request ID {Convert.ToHexString(dataA.RequestId)}; peer Bootstrap A {dataA.AuthenticatedPeerBootstrap.Length} B {dataB.AuthenticatedPeerBootstrap.Length} bytes");

            // 4. Tear down every lower parent while the runtime lives: connections, listeners, hosts, authorities.
            connectionA.Dispose();
            connectionB.Dispose();
            a.Host.DetachListener();
            b.Host.DetachListener();
            a.Host.Dispose();
            b.Host.Dispose();
            a.Authority.Dispose();
            b.Authority.Dispose();
            Assert.True(runA.IsEnded && runB.IsEnded && a.Authority.IsDisposed && b.Authority.IsDisposed && !runtime.IsDisposed);

            // Both results are still open and readable: the runtime owns them.
            Assert.False(resultA.IsDisposed || resultB.IsDisposed);
            AssertSameData(dataA, resultA.Read());
            AssertSameData(dataB, resultB.Read());

            // 5. Result A is disposed explicitly with its one native destroy (it succeeds: no exception); a second
            //    Dispose does nothing; reading it is refused locally; its earlier snapshot stays usable.
            resultA.Dispose();
            Assert.True(resultA.IsDisposed);
            resultA.Dispose();
            Assert.Throws<ObjectDisposedException>(resultA.Read);
            Assert.True(dataA.AuthenticatedPeerBootstrap.SequenceEqual(vector.ResponderFrame));
            Assert.False(resultB.IsDisposed);
            AssertSameData(dataB, resultB.Read());
        }
        finally
        {
            relay?.Dispose();
            runtime.Dispose();
        }

        Assert.False(runtime.Context.IsFatal || runtime.Context.IsContractViolated);
    }

    [Fact]
    public void TheRuntimeCascadeEndsAnOpenResultWithoutAChildDestroyAndItsSnapshotStaysUsable()
    {
        string path = NativeArtifactTests.ArtifactPath();
        if (!OperatingSystem.IsWindows())
        {
            AssertNoLinuxPairing(path);
            return;
        }

        RemoteVector vector = RemoteVector.Load();
        SasPairingRuntime runtime = SasPairingRuntime.Create(path);
        Relay? relay = null;
        SasPairingResult? resultB = null;
        SasPairingResultData? dataB = null;
        try
        {
            (Endpoint a, Endpoint b, relay, Pump pump, SasPairingConnection connectionA, _) = Connect(runtime, "p95-cascade", vector.Initiator, vector.Responder);
            SasPairingRun runA = connectionA.StartInitiator(vector.Initiator, vector.Responder).Run!;
            pump.Until("START_ACCEPTED at B", (_, eb) => eb.Any(e => Inbound(e, SasPairingProtocolEvent.StartAccepted)));
            SasPairingRun runB = pump.EventsB.Single(e => Inbound(e, SasPairingProtocolEvent.StartAccepted)).Run!;
            pump.Until("ACCEPT at A", (ea, _) => ea.Any(e => Inbound(e, SasPairingProtocolEvent.Accept)));
            runA.AuthorizeExposure();
            runA.ExposeKey();
            pump.Until("INITIATOR_KEY at B", (_, eb) => eb.Any(e => Inbound(e, SasPairingProtocolEvent.InitiatorKey)));
            runB.AuthorizeExposure();
            runB.ExposeKey();
            SasPairingSasPresentation presentationB = runB.Presentation()!;
            pump.Until("RESPONDER_KEY at A", (ea, _) => ea.Any(e => Inbound(e, SasPairingProtocolEvent.ResponderKey)));
            SasPairingSasPresentation presentationA = runA.Presentation()!;
            Assert.Equal(presentationA.DecimalDisplay, presentationB.DecimalDisplay);
            runA.ApproveSas(presentationA.CeremonyIdentity);
            runA.EmitBootstrapMac();
            runB.ApproveSas(presentationB.CeremonyIdentity);
            runB.EmitBootstrapMac();
            pump.Until("both MACs authenticated", (_, _) =>
                pump.EventsA.Any(e => Inbound(e, SasPairingProtocolEvent.BootstrapMacAuthenticated)) && pump.EventsB.Any(e => Inbound(e, SasPairingProtocolEvent.BootstrapMacAuthenticated)));
            runA.EmitInitiatorFinish();
            pump.Until("B's local result", (_, eb) => eb.Any(e => e.HasResult));

            // Only B's result is used here; whatever A holds is irrelevant to it (local completion only).
            resultB = Assert.Single(pump.EventsB, e => e.HasResult).Result!;
            dataB = resultB.Read();
            Assert.Equal(SasPairingPeerRole.Initiator, dataB.PeerRole);
            Assert.True(dataB.AuthenticatedPeerBootstrap.SequenceEqual(vector.InitiatorFrame));
            a.Host.DetachListener();
            b.Host.DetachListener();
        }
        finally
        {
            relay?.Dispose();
            runtime.Dispose();
        }

        // The runtime's one native destroy dropped the open result; the wrapper only marked it disposed. A later
        // Dispose makes no native call (a call on the destroyed runtime would report INVALID_HANDLE and throw).
        Assert.True(resultB!.IsDisposed);
        resultB.Dispose();
        Assert.Throws<ObjectDisposedException>(resultB.Read);
        Assert.Equal(SasPairingPeerRole.Initiator, dataB!.PeerRole);
        Assert.True(dataB.AuthenticatedPeerBootstrap.SequenceEqual(vector.InitiatorFrame));
        Assert.True(dataB.AuthenticatedSharedContext.SequenceEqual(vector.SharedContext));
        Assert.Equal(32, dataB.CeremonyIdentity.Bytes.Length);
        Assert.False(runtime.Context.IsFatal || runtime.Context.IsContractViolated);
    }
}
