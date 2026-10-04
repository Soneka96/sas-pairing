using System.Reflection;
using SasPairing.Interop;
using SasPairing.Tests.Support;

namespace SasPairing.Tests;

/// <summary>
/// P9-D-004 SAS presentation and ceremony identity over the fake services (every platform): read-only
/// presentation that always reaches native (also while a frame is retained), the exact <c>available</c> 0 and 1
/// record contracts and the strict <c>NNNN NNNN NNNN</c> display, the immutable 32-byte identity with value
/// equality and no public constructor, and decisions that pass the supplied identity to native unchecked.
/// </summary>
public sealed class SasPresentationTests
{
    private const int Ok = 0;

    private static (FakeTree Tree, SasPairingRun Run) LiveRun()
    {
        FakeTree tree = new();
        tree.AttachWithConnections(100);
        tree.Network.Next(Ok, Ok, Records.Inbound(100, AbiV1Constants.SAS_PAIRING_PROTOCOL_EVENT_START_ACCEPTED, [0x41], run: 500));
        return (tree, Assert.Single(tree.Host.Drive().Events).Run!);
    }

    private static SasPairingSasPresentation Present(FakeTree tree, SasPairingRun run, byte[] identity, string display = Presentations.Display)
    {
        tree.Ceremony.NextPresentation(Ok, Presentations.Live(identity, display));
        return run.Presentation()!;
    }

    [Fact]
    public void NoPresentedSasIsNullAndTheRunStaysLive()
    {
        (FakeTree tree, SasPairingRun run) = LiveRun();

        Assert.Null(run.Presentation());

        FakeCeremonyCall call = Assert.Single(tree.Ceremony.Calls);
        Assert.Equal(FakeCeremonyApi.PresentationExport, call.Export);
        Assert.Equal([tree.Runtime.Handle, tree.Host.Handle, 100ul, 500ul], call.Arguments);
        Assert.False(run.IsEnded);
        Assert.False(tree.Context.IsContractViolated);
    }

    [Theory]
    [InlineData("reserved", 0)]
    [InlineData("identity", 0)]
    [InlineData("identity", 31)]
    [InlineData("decimal", 0)]
    [InlineData("decimal", 13)]
    [InlineData("tail", 0)]
    [InlineData("tail", 1)]
    public void AvailableZeroWithAnyNonZeroByteIsAContractViolation(string field, int index)
    {
        (FakeTree tree, SasPairingRun run) = LiveRun();
        NativePresentationRecord none = Presentations.None();
        NativePresentationRecord record = field switch
        {
            "reserved" => none with { Reserved = 1 },
            "identity" => none with { CeremonyIdentity = Set(new byte[32], index) },
            "decimal" => none with { Decimal = Set(new byte[14], index) },
            _ => none with { ReservedTail = Set(new byte[2], index) },
        };
        tree.Ceremony.NextPresentation(Ok, record);

        Assert.Throws<SasPairingContractException>(() => run.Presentation());

        Assert.True(tree.Context.IsContractViolated);
        Assert.False(run.IsEnded);
    }

    private static byte[] Set(byte[] bytes, int index)
    {
        bytes[index] = (byte)'1';
        return bytes;
    }

    [Fact]
    public void ALivePresentationIsTheExactIdentityAndDisplayAndChangesNothing()
    {
        (FakeTree tree, SasPairingRun run) = LiveRun();
        byte[] identity = Presentations.Identity(0x33);

        SasPairingSasPresentation presentation = Present(tree, run, identity, "0000 9999 1234");

        Assert.Equal("0000 9999 1234", presentation.DecimalDisplay);
        Assert.Equal(identity, presentation.CeremonyIdentity.Bytes.ToArray());
        Assert.False(run.IsEnded);
        Assert.Equal(1, tree.Ceremony.Total);
        Assert.Equal(2, tree.Network.Count(FakeNetworkApi.DriveExport)); // the setup's drives only
        Assert.Equal(0, tree.Lifecycle.Count(FakeLifecycleApi.AuthorityStatusExport));
    }

    public static TheoryData<string, uint, uint, byte[], byte[]> Malformed()
    {
        static byte[] Ascii(string text) => [.. text.Select(c => (byte)c)];
        byte[] valid = Ascii(Presentations.Display);
        TheoryData<string, uint, uint, byte[], byte[]> cases = new()
        {
            { "available 2", 2, 0, valid, new byte[2] },
            { "available max", uint.MaxValue, 0, valid, new byte[2] },
            { "reserved", 1, 1, valid, new byte[2] },
            { "tail 0", 1, 0, valid, [1, 0] },
            { "tail 1", 1, 0, valid, [0, 0x80] },
            { "tab", 1, 0, Ascii("1234\t5678 9012"), new byte[2] },
            { "letter", 1, 0, Ascii("1234 5678 901A"), new byte[2] },
            { "NUL", 1, 0, Ascii("1234 5678 901\0"), new byte[2] },
            { "misplaced space", 1, 0, Ascii("123 45678 9012"), new byte[2] },
            { "missing spaces", 1, 0, Ascii("12345678901234"), new byte[2] },
            { "all spaces", 1, 0, Ascii("              "), new byte[2] },
            { "slash", 1, 0, Ascii("1234 5678 /012"), new byte[2] },
            { "colon", 1, 0, Ascii("1234 5678 :012"), new byte[2] },
            { "high bit", 1, 0, [.. valid[..13], 0xB9], new byte[2] },
            { "UTF-8 multibyte digit", 1, 0, [.. valid[..12], 0xD9, 0xA1], new byte[2] }, // U+0661 ARABIC-INDIC DIGIT ONE
            { "fullwidth digit", 1, 0, [0xEF, 0xBC, 0x91, .. valid[3..]], new byte[2] }, // U+FF11 FULLWIDTH DIGIT ONE
        };
        return cases;
    }

    [Theory]
    [MemberData(nameof(Malformed))]
    public void AMalformedLivePresentationIsAContractViolation(string what, uint available, uint reserved, byte[] display, byte[] tail)
    {
        (FakeTree tree, SasPairingRun run) = LiveRun();
        tree.Ceremony.NextPresentation(Ok, new NativePresentationRecord(available, reserved, Presentations.Identity(), display, tail));

        SasPairingContractException violation = Assert.Throws<SasPairingContractException>(() => run.Presentation());

        Assert.Equal("SasPairingRun.Presentation", violation.Operation);
        Assert.True(tree.Context.IsContractViolated, what);

        // The process is latched: later normal ceremony calls are refused locally.
        Assert.Throws<SasPairingContractException>(() => run.Presentation());
        Assert.Equal(1, tree.Ceremony.Total);
    }

    [Fact]
    public void PresentationStillReachesNativeAfterAWritePendingAction()
    {
        (FakeTree tree, SasPairingRun run) = LiveRun();
        Assert.True(run.ExposeKey().WritePending);

        Present(tree, run, Presentations.Identity());
        tree.Ceremony.NextPresentation(AbiV1Constants.SAS_PAIRING_NO_LIVE_SAS);
        Assert.Equal(SasPairingStatus.NoLiveSas, Assert.Throws<SasPairingNativeException>(() => run.Presentation()).KnownStatus);

        Assert.Equal([FakeCeremonyApi.ExposeExport, FakeCeremonyApi.PresentationExport, FakeCeremonyApi.PresentationExport], tree.Ceremony.Calls.Select(c => c.Export));
        Assert.False(run.IsEnded);
    }

    [Fact]
    public void TheIdentityIsAnImmutableCopyOfExactlyThirtyTwoBytes()
    {
        (FakeTree tree, SasPairingRun run) = LiveRun();
        byte[] source = Presentations.Identity(0x44);
        NativePresentationRecord record = Presentations.Live(source);
        tree.Ceremony.NextPresentation(Ok, record);

        SasPairingCeremonyIdentity identity = run.Presentation()!.CeremonyIdentity;
        source[5] ^= 0xFF;
        record.CeremonyIdentity[6] ^= 0xFF;

        Assert.Equal(32, identity.Bytes.Length);
        Assert.Equal(Presentations.Identity(0x44), identity.Bytes.ToArray());
        Assert.True(identity.Bytes.SequenceEqual(identity.Bytes));
        Assert.Equal(typeof(ReadOnlySpan<byte>), typeof(SasPairingCeremonyIdentity).GetProperty("Bytes")!.PropertyType);
        Assert.Null(typeof(SasPairingCeremonyIdentity).GetProperty("Bytes")!.SetMethod);
        Assert.Empty(typeof(SasPairingCeremonyIdentity).GetConstructors());
        Assert.All(
            typeof(SasPairingCeremonyIdentity).GetFields(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public),
            f => Assert.True(f.IsInitOnly && f.IsPrivate, f.Name));
        Assert.All(
            new[] { typeof(SasPairingSasPresentation), typeof(SasPairingLocalAction) }.SelectMany(t => t.GetProperties()),
            p => Assert.Null(p.SetMethod));
        Assert.Throws<ArgumentException>(() => new SasPairingCeremonyIdentity(new byte[31]));
        Assert.Throws<ArgumentException>(() => new SasPairingCeremonyIdentity(new byte[33]));
    }

    [Fact]
    public void IdentitiesAreEqualExactlyWhenTheirBytesAre()
    {
        (FakeTree tree, SasPairingRun run) = LiveRun();
        SasPairingCeremonyIdentity first = Present(tree, run, Presentations.Identity(0x10)).CeremonyIdentity;
        SasPairingCeremonyIdentity same = Present(tree, run, Presentations.Identity(0x10)).CeremonyIdentity;
        byte[] lastDiffers = Presentations.Identity(0x10);
        lastDiffers[31] ^= 0x01;
        SasPairingCeremonyIdentity different = Present(tree, run, lastDiffers).CeremonyIdentity;

        Assert.NotSame(first, same);
        Assert.True(first.Equals(same));
        Assert.True(first.Equals((object)same));
        Assert.True(first == same);
        Assert.False(first != same);
        Assert.Equal(first.GetHashCode(), same.GetHashCode());
        Assert.False(first.Equals(different));
        Assert.True(first != different);
        Assert.False(first.Equals(null));
        Assert.False(first == null);
        Assert.True((SasPairingCeremonyIdentity?)null == null);
        Assert.Single(new HashSet<SasPairingCeremonyIdentity> { first, same });
    }

    [Theory]
    [InlineData("ApproveSas")]
    [InlineData("RejectSas")]
    [InlineData("CancelSas")]
    public void ADecisionPassesTheSuppliedIdentityToNativeWhichAloneJudgesIt(string method)
    {
        FakeTree tree = new();
        tree.AttachWithConnections(100);
        tree.Network.Next(
            Ok,
            Ok,
            Records.Inbound(100, AbiV1Constants.SAS_PAIRING_PROTOCOL_EVENT_START_ACCEPTED, [0x41], run: 500),
            Records.Inbound(100, AbiV1Constants.SAS_PAIRING_PROTOCOL_EVENT_START_ACCEPTED, [0x42], run: 501));
        IReadOnlyList<SasPairingEvent> events = tree.Host.Drive().Events;
        SasPairingRun runA = events[0].Run!;
        SasPairingRun runB = events[1].Run!;
        SasPairingCeremonyIdentity identityA = Present(tree, runA, Presentations.Identity(0xA1)).CeremonyIdentity;
        tree.Ceremony.Calls.Clear();
        tree.Ceremony.Next(AbiV1Constants.SAS_PAIRING_CEREMONY_IDENTITY_MISMATCH);

        // Run A's identity on run B: no local judgement, exactly one native call with exactly those bytes.
        SasPairingNativeException mismatch = Assert.Throws<SasPairingNativeException>(() => method switch
        {
            "ApproveSas" => runB.ApproveSas(identityA),
            "RejectSas" => runB.RejectSas(identityA),
            _ => runB.CancelSas(identityA),
        });

        Assert.Equal(208, mismatch.StatusCode);
        Assert.Equal(SasPairingStatus.CeremonyIdentityMismatch, mismatch.KnownStatus);
        FakeCeremonyCall call = Assert.Single(tree.Ceremony.Calls);
        Assert.Equal(501ul, call.Arguments[3]);
        Assert.Equal(Presentations.Identity(0xA1), call.Identity);
        Assert.False(runA.IsEnded || runB.IsEnded);
        Assert.False(tree.Context.IsContractViolated);
    }

    [Fact]
    public void TheLocalEventEnumIsExactlyTheTwelveFrozenSuccessValues()
    {
        Dictionary<string, uint> frozen = typeof(AbiV1Constants)
            .GetFields(BindingFlags.NonPublic | BindingFlags.Static)
            .Where(f => f.Name.StartsWith("SAS_PAIRING_LOCAL_EVENT_", StringComparison.Ordinal))
            .ToDictionary(f => f.Name["SAS_PAIRING_LOCAL_EVENT_".Length..], f => (uint)f.GetRawConstantValue()!);
        Assert.Equal(13, frozen.Count);
        Assert.Equal(0u, frozen["INVALID"]);

        SasPairingLocalEvent[] values = Enum.GetValues<SasPairingLocalEvent>();
        Assert.Equal(12, values.Length);
        Assert.Equal(typeof(int), Enum.GetUnderlyingType(typeof(SasPairingLocalEvent)));
        foreach (SasPairingLocalEvent value in values)
        {
            string native = string.Concat(value.ToString().Select((c, i) => i > 0 && char.IsUpper(c) ? "_" + c : c.ToString())).ToUpperInvariant();
            Assert.Equal(frozen[native], (uint)value);
        }

        Assert.False(Enum.IsDefined((SasPairingLocalEvent)0));
        Assert.Equal(1u, AbiV1Constants.SAS_PAIRING_ACTION_FLAG_WRITE_PENDING);
    }
}
