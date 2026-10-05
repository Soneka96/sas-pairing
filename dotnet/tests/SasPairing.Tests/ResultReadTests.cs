using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using SasPairing.Interop;
using SasPairing.Tests.Support;

namespace SasPairing.Tests;

/// <summary>
/// P9-D-005 result reads over the fake result service (every platform): one info and exactly one copy per field
/// at the info lengths, no size query, negotiation, or retry; the info and copy success contracts (identity length,
/// peer role, source-proven bounds, required length, byte count, <c>BUFFER_TOO_SMALL</c> at the reported length);
/// exact native failures with nothing partial and the result left open; data admission after native FATAL but not
/// after a contract violation; and immutable, detached, exact binary snapshots.
/// </summary>
public sealed class ResultReadTests
{
    private const int Ok = 0;

    private static readonly uint[] Fields =
    [
        AbiV1Constants.SAS_PAIRING_RESULT_FIELD_REQUEST_ID,
        AbiV1Constants.SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_PEER_BOOTSTRAP,
        AbiV1Constants.SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_SHARED_CONTEXT,
        AbiV1Constants.SAS_PAIRING_RESULT_FIELD_PROFILE_IDENTIFIER,
    ];

    /// <summary>A tree holding one delivered result (handle 500) whose fake reports <paramref name="data"/>.</summary>
    private static (FakeTree Tree, SasPairingResult Result) Delivered(FakeResultData? data = null)
    {
        FakeTree tree = new();
        tree.AttachWithConnections(100);
        if (data is not null)
        {
            tree.Results.Data = data;
        }

        tree.Network.Next(Ok, Ok, Records.Step(100, AbiV1Constants.SAS_PAIRING_STEP_CONFIRMED, result: 500, requestId: [0x41]));
        return (tree, Assert.Single(tree.Host.Drive().Events).Result!);
    }

    /// <summary>The info of <paramref name="data"/> with one length replaced.</summary>
    private static NativeResultInfoRecord WithLength(FakeResultData data, uint field, uint length)
    {
        NativeResultInfoRecord info = data.Info();
        return field switch
        {
            1 => info with { RequestIdLength = length },
            2 => info with { PeerBootstrapLength = length },
            3 => info with { SharedContextLength = length },
            _ => info with { ProfileIdentifierLength = length },
        };
    }

    private static void AssertData(FakeResultData expected, SasPairingResultData data)
    {
        Assert.True(data.CeremonyIdentity.Bytes.SequenceEqual(expected.Identity));
        Assert.Equal((int)expected.PeerRole, (int)data.PeerRole);
        Assert.Equal(expected.ProfileVersion, data.ProfileVersion);
        Assert.True(data.RequestId.SequenceEqual(expected.RequestId));
        Assert.True(data.AuthenticatedPeerBootstrap.SequenceEqual(expected.PeerBootstrap));
        Assert.True(data.AuthenticatedSharedContext.SequenceEqual(expected.SharedContext));
        Assert.True(data.ProfileIdentifier.SequenceEqual(expected.ProfileIdentifier));
    }

    [Fact]
    public void OneReadIsOneInfoThenExactlyOneCopyPerFieldAtTheReportedLength()
    {
        (FakeTree tree, SasPairingResult result) = Delivered();
        FakeResultData expected = tree.Results.Data;

        SasPairingResultData data = result.Read();

        AssertData(expected, data);
        Assert.Equal(SasPairingPeerRole.Responder, data.PeerRole);
        Assert.Equal(1u, data.ProfileVersion);
        Assert.Equal(
            [
                (FakeResultApi.InfoExport, 0u, -1),
                (FakeResultApi.CopyExport, 1u, expected.RequestId.Length),
                (FakeResultApi.CopyExport, 2u, expected.PeerBootstrap.Length),
                (FakeResultApi.CopyExport, 3u, expected.SharedContext.Length),
                (FakeResultApi.CopyExport, 4u, expected.ProfileIdentifier.Length),
            ],
            tree.Results.Calls.Select(c => (c.Export, c.Field, c.Capacity)));
        Assert.All(tree.Results.Calls, c => Assert.Equal([tree.Runtime.Handle, 500ul], c.Arguments));
        Assert.False(result.IsDisposed);
    }

    [Fact]
    public void EveryReadIsAFreshCompleteNativeReadAndReturnsAnIndependentSnapshot()
    {
        (FakeTree tree, SasPairingResult result) = Delivered();

        SasPairingResultData first = result.Read();
        tree.Results.Data = tree.Results.Data with { RequestId = [0x7F], PeerRole = AbiV1Constants.SAS_PAIRING_ROLE_INITIATOR };
        SasPairingResultData second = result.Read();

        // Nothing is cached: the second read reached native again (the fake changed what it reports).
        Assert.Equal(10, tree.Results.Total);
        Assert.NotSame(first, second);
        Assert.True(first.RequestId.SequenceEqual(FakeResultData.Default().RequestId));
        Assert.True(second.RequestId.SequenceEqual((byte[])[0x7F]));
        Assert.Equal((SasPairingPeerRole.Responder, SasPairingPeerRole.Initiator), (first.PeerRole, second.PeerRole));
        Assert.NotSame(first.CeremonyIdentity, second.CeremonyIdentity);
        Assert.Equal(first.CeremonyIdentity, second.CeremonyIdentity);
        Assert.False(Unsafe.AreSame(ref MemoryMarshal.GetReference(first.ProfileIdentifier), ref MemoryMarshal.GetReference(second.ProfileIdentifier)));
    }

    [Theory]
    [InlineData(1u)]
    [InlineData(2u)]
    [InlineData(3u)]
    [InlineData(4u)]
    public void AZeroLengthFieldIsCopiedOnceAtCapacityZeroAndReadsEmpty(uint field)
    {
        FakeResultData data = FakeResultData.Default();
        data = field switch
        {
            1 => data with { RequestId = [] },
            2 => data with { PeerBootstrap = [] },
            3 => data with { SharedContext = [] },
            _ => data with { ProfileIdentifier = [] },
        };
        (FakeTree tree, SasPairingResult result) = Delivered(data);

        SasPairingResultData read = result.Read();

        AssertData(data, read);
        Assert.Equal(0, Assert.Single(tree.Results.Calls, c => c.Field == field).Capacity);
        Assert.Equal(4, tree.Results.Count(FakeResultApi.CopyExport));
    }

    [Fact]
    public void EveryFieldIsTheExactBinaryWithNoTextOrTerminatorConversion()
    {
        // Embedded and trailing NUL, high-bit bytes, and invalid UTF-8 survive exactly.
        FakeResultData data = FakeResultData.Default() with
        {
            RequestId = [0x00, 0xC3, 0x28, 0x00],
            PeerBootstrap = [0xFF, 0xFE, 0x00, 0x80, 0xED, 0xA0, 0x80, 0x00],
            SharedContext = [0x00],
            ProfileIdentifier = [0x73, 0x00, 0xFF],
        };
        (_, SasPairingResult result) = Delivered(data);

        AssertData(data, result.Read());
    }

    [Fact]
    public void TheSnapshotIsImmutableDetachedAndSurvivesResultAndRuntimeDisposal()
    {
        byte[] bootstrap = [0x53, 0x41, 0x53, 0x50, 0x00, 0xFF];
        (FakeTree tree, SasPairingResult result) = Delivered();
        tree.Results.CopyOutcome = (field, capacity) => field == AbiV1Constants.SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_PEER_BOOTSTRAP
            ? new NativeResultCopyOutcome(Ok, (nuint)bootstrap.Length, bootstrap)
            : null;
        tree.Results.InfoOutcome = _ => new NativeResultInfoOutcome(Ok, tree.Results.Data.Info() with { PeerBootstrapLength = (uint)bootstrap.Length });

        SasPairingResultData data = result.Read();

        // A defensive copy: changing the array the service returned (or the fake's data) changes nothing.
        bootstrap[0] = 0x00;
        tree.Results.Data.RequestId[0] = 0x99;
        Assert.True(data.AuthenticatedPeerBootstrap.SequenceEqual((byte[])[0x53, 0x41, 0x53, 0x50, 0x00, 0xFF]));
        Assert.True(data.RequestId.SequenceEqual(FakeResultData.Default().RequestId));

        result.Dispose();
        tree.Runtime.Dispose();
        Assert.True(data.AuthenticatedPeerBootstrap.SequenceEqual((byte[])[0x53, 0x41, 0x53, 0x50, 0x00, 0xFF]));
        Assert.Equal(SasPairingPeerRole.Responder, data.PeerRole);
        Assert.Equal(32, data.CeremonyIdentity.Bytes.Length);

        // Read-only spans, no setters, no public constructor, no native reference held.
        PropertyInfo[] properties = typeof(SasPairingResultData).GetProperties();
        Assert.All(properties, p => Assert.Null(p.SetMethod));
        Assert.All(
            properties.Where(p => p.Name is not ("CeremonyIdentity" or "PeerRole" or "ProfileVersion")),
            p => Assert.Equal(typeof(ReadOnlySpan<byte>), p.PropertyType));
        Assert.Empty(typeof(SasPairingResultData).GetConstructors());
        Assert.All(
            typeof(SasPairingResultData).GetFields(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public),
            f => Assert.Contains(f.FieldType, new[] { typeof(byte[]), typeof(SasPairingCeremonyIdentity), typeof(SasPairingPeerRole), typeof(uint) }));
    }

    [Fact]
    public void TheCeremonyIdentityIsTheP94ValueType()
    {
        (FakeTree tree, SasPairingResult result) = Delivered();

        SasPairingCeremonyIdentity identity = result.Read().CeremonyIdentity;

        Assert.IsType<SasPairingCeremonyIdentity>(identity);
        SasPairingCeremonyIdentity presented = new(tree.Results.Data.Identity);
        Assert.Equal(presented, identity);
        Assert.True(presented == identity);
        Assert.Equal(presented.GetHashCode(), identity.GetHashCode());
        Assert.Empty(typeof(SasPairingCeremonyIdentity).GetConstructors());
    }

    [Theory]
    [InlineData(AbiV1Constants.SAS_PAIRING_ROLE_INITIATOR, SasPairingPeerRole.Initiator)]
    [InlineData(AbiV1Constants.SAS_PAIRING_ROLE_RESPONDER, SasPairingPeerRole.Responder)]
    public void TheTwoFrozenPeerRolesMapToThePublicRole(uint role, SasPairingPeerRole expected)
    {
        (_, SasPairingResult result) = Delivered(FakeResultData.Default() with { PeerRole = role });

        Assert.Equal(expected, result.Read().PeerRole);
    }

    [Theory]
    [InlineData(AbiV1Constants.SAS_PAIRING_ROLE_INVALID)]
    [InlineData(3u)]
    [InlineData(uint.MaxValue)]
    public void AnyOtherPeerRoleOnASuccessfulInfoIsAContractViolation(uint role)
    {
        (FakeTree tree, SasPairingResult result) = Delivered(FakeResultData.Default() with { PeerRole = role });

        SasPairingContractException violation = Assert.Throws<SasPairingContractException>(result.Read);

        Assert.Equal("SasPairingResult.Read", violation.Operation);
        Assert.True(tree.Context.IsContractViolated);
        Assert.Equal(1, tree.Results.Total); // the info only: no copy
        Assert.False(result.IsDisposed);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(31)]
    [InlineData(33)]
    public void AnInfoWithoutExactlyThirtyTwoIdentityBytesIsAContractViolation(int length)
    {
        (FakeTree tree, SasPairingResult result) = Delivered(FakeResultData.Default() with { Identity = new byte[length] });

        Assert.Throws<SasPairingContractException>(result.Read);

        Assert.True(tree.Context.IsContractViolated);
        Assert.Equal(1, tree.Results.Total);
    }

    [Fact]
    public void AnOkInfoWithoutARecordIsAContractViolation()
    {
        (FakeTree tree, SasPairingResult result) = Delivered();
        tree.Results.InfoOutcome = _ => new NativeResultInfoOutcome(Ok, null);

        Assert.Throws<SasPairingContractException>(result.Read);

        Assert.Equal(1, tree.Results.Total);
    }

    [Theory]
    [InlineData(1u, 65u)]
    [InlineData(1u, 0x8000_0000u)]
    [InlineData(1u, uint.MaxValue)]
    [InlineData(2u, 16_385u)]
    [InlineData(2u, 0x8000_0000u)]
    [InlineData(2u, uint.MaxValue)]
    [InlineData(3u, 8_193u)]
    [InlineData(3u, 0x8000_0000u)]
    [InlineData(3u, uint.MaxValue)]
    [InlineData(4u, 39u)]
    [InlineData(4u, 0x8000_0000u)]
    [InlineData(4u, uint.MaxValue)]
    public void AnInfoLengthAboveItsSourceProvenBoundIsAContractViolationBeforeAnyCopy(uint field, uint length)
    {
        (FakeTree tree, SasPairingResult result) = Delivered();
        tree.Results.InfoOutcome = _ => new NativeResultInfoOutcome(Ok, WithLength(tree.Results.Data, field, length));

        SasPairingContractException violation = Assert.Throws<SasPairingContractException>(result.Read);

        // Refused before any buffer is allocated or any copy is made.
        Assert.Contains(length.ToString(System.Globalization.CultureInfo.InvariantCulture), violation.Message, StringComparison.Ordinal);
        Assert.Equal(1, tree.Results.Total);
        Assert.True(tree.Context.IsContractViolated);
        Assert.False(result.IsDisposed);
    }

    [Fact]
    public void EveryFieldAtExactlyItsSourceProvenBoundIsRead()
    {
        FakeResultData data = FakeResultData.Default() with
        {
            RequestId = [.. Enumerable.Repeat((byte)0x01, 64)],
            PeerBootstrap = [.. Enumerable.Repeat((byte)0xFF, 16_384)],
            SharedContext = [.. Enumerable.Repeat((byte)0x00, 8_192)],
            ProfileIdentifier = [.. Enumerable.Repeat((byte)0x80, 38)],
        };
        (FakeTree tree, SasPairingResult result) = Delivered(data);

        AssertData(data, result.Read());

        Assert.Equal([64, 16_384, 8_192, 38], tree.Results.Calls.Where(c => c.Export == FakeResultApi.CopyExport).Select(c => c.Capacity));
        Assert.Equal((64u, 16_384u, 8_192u, 38u), (SasPairingResult.MaxRequestIdLength, SasPairingResult.MaxPeerBootstrapLength, SasPairingResult.MaxSharedContextLength, SasPairingResult.MaxProfileIdentifierLength));
    }

    [Theory]
    [InlineData(0u)]
    [InlineData(1u)]
    [InlineData(2u)]
    [InlineData(65_535u)]
    [InlineData(uint.MaxValue)]
    public void TheProfileVersionIsExposedExactlyAsData(uint version)
    {
        (_, SasPairingResult result) = Delivered(FakeResultData.Default() with { ProfileVersion = version });

        Assert.Equal(version, result.Read().ProfileVersion);
    }

    [Theory]
    [InlineData(AbiV1Constants.SAS_PAIRING_INVALID_HANDLE)]
    [InlineData(AbiV1Constants.SAS_PAIRING_INVALID_ARGUMENT)]
    [InlineData(AbiV1Constants.SAS_PAIRING_FATAL)]
    [InlineData(777)]
    public void AnInfoFailureIsTheExactNativeExceptionWithNothingCopiedAndTheResultOpen(int status)
    {
        (FakeTree tree, SasPairingResult result) = Delivered();
        tree.Results.InfoOutcome = _ => new NativeResultInfoOutcome(status, null);

        SasPairingNativeException failure = Assert.Throws<SasPairingNativeException>(result.Read);

        Assert.Equal((status, "SasPairingResult.Read"), (failure.StatusCode, failure.Operation));
        Assert.Equal(status == AbiV1Constants.SAS_PAIRING_FATAL, tree.Context.IsFatal);
        Assert.False(tree.Context.IsContractViolated);
        Assert.Equal(1, tree.Results.Total);
        Assert.False(result.IsDisposed);

        // A later read is still admitted, also after FATAL (data access), and succeeds once native answers OK.
        tree.Results.InfoOutcome = null;
        AssertData(tree.Results.Data, result.Read());
        Assert.Equal(6, tree.Results.Total);
    }

    public static TheoryData<uint, int> CopyFailures()
    {
        TheoryData<uint, int> data = [];
        foreach (uint field in Fields)
        {
            foreach (int status in new[] { AbiV1Constants.SAS_PAIRING_INVALID_HANDLE, AbiV1Constants.SAS_PAIRING_INVALID_ARGUMENT, AbiV1Constants.SAS_PAIRING_FATAL, 777 })
            {
                data.Add(field, status);
            }
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(CopyFailures))]
    public void ACopyFailureIsTheExactNativeExceptionWithNothingPartialAndTheResultOpen(uint field, int status)
    {
        (FakeTree tree, SasPairingResult result) = Delivered();
        tree.Results.CopyOutcome = (f, _) => f == field ? new NativeResultCopyOutcome(status, 0, null) : null;

        SasPairingNativeException failure = Assert.Throws<SasPairingNativeException>(result.Read);

        Assert.Equal(status, failure.StatusCode);
        Assert.Equal(status == AbiV1Constants.SAS_PAIRING_FATAL, tree.Context.IsFatal);
        Assert.Equal(1 + (int)field, tree.Results.Total); // info, then the copies up to the failing one: no later copy, no retry
        Assert.Equal(1, tree.Results.Calls.Count(c => c.Field == field));
        Assert.False(result.IsDisposed);

        tree.Results.CopyOutcome = null;
        AssertData(tree.Results.Data, result.Read());
    }

    public static TheoryData<uint, string> CopyContracts()
    {
        TheoryData<uint, string> data = [];
        foreach (uint field in Fields)
        {
            foreach (string broken in new[] { "required shorter", "required longer", "buffer too small", "buffer too small asking more", "fewer bytes", "more bytes", "no bytes" })
            {
                data.Add(field, broken);
            }
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(CopyContracts))]
    public void ACopyThatBreaksItsInfoLengthIsAContractViolationWithNoRetry(uint field, string broken)
    {
        (FakeTree tree, SasPairingResult result) = Delivered();
        int length = tree.Results.Data.Field(field).Length;
        nuint expected = (nuint)length;
        tree.Results.CopyOutcome = (f, _) => f != field ? null : broken switch
        {
            "required shorter" => new NativeResultCopyOutcome(Ok, expected - 1, new byte[length - 1]),
            "required longer" => new NativeResultCopyOutcome(Ok, expected + 1, new byte[length]),
            "buffer too small" => new NativeResultCopyOutcome(AbiV1Constants.SAS_PAIRING_BUFFER_TOO_SMALL, expected, null),
            "buffer too small asking more" => new NativeResultCopyOutcome(AbiV1Constants.SAS_PAIRING_BUFFER_TOO_SMALL, expected + 1, null),
            "fewer bytes" => new NativeResultCopyOutcome(Ok, expected, new byte[length - 1]),
            "more bytes" => new NativeResultCopyOutcome(Ok, expected, new byte[length + 1]),
            _ => new NativeResultCopyOutcome(Ok, expected, null),
        };

        SasPairingContractException violation = Assert.Throws<SasPairingContractException>(result.Read);

        Assert.Equal("SasPairingResult.Read", violation.Operation);
        Assert.True(tree.Context.IsContractViolated);
        Assert.False(tree.Context.IsFatal);
        Assert.Equal(1, tree.Results.Calls.Count(c => c.Field == field)); // never resized or retried
        Assert.Equal(length, tree.Results.Calls.Single(c => c.Field == field).Capacity);
        Assert.Equal(1 + (int)field, tree.Results.Total);
        Assert.False(result.IsDisposed);

        // The wrapper no longer trusts native output: a later read is refused locally, but cleanup still runs.
        int calls = tree.Results.Total;
        Assert.Throws<SasPairingContractException>(result.Read);
        Assert.Equal(calls, tree.Results.Total);
        result.Dispose();
        Assert.Equal(calls + 1, tree.Results.Total);
        Assert.Equal(FakeResultApi.DestroyExport, tree.Results.Calls[^1].Export);
    }

    [Fact]
    public void AReadIsAdmittedAfterNativeFatalWhileNormalWorkStaysRefused()
    {
        (FakeTree tree, SasPairingResult result) = Delivered();
        tree.Lifecycle.AuthorityStatusOutcome = () => new NativeAuthorityStatusOutcome(AbiV1Constants.SAS_PAIRING_FATAL, 0, 0);
        Assert.Throws<SasPairingNativeException>(() => tree.Authority.GetStatus());
        Assert.True(tree.Context.IsFatal);

        SasPairingResultData data = result.Read();

        AssertData(tree.Results.Data, data);
        Assert.Equal(1, tree.Results.Count(FakeResultApi.InfoExport));
        Assert.Equal(4, tree.Results.Count(FakeResultApi.CopyExport));

        // This is data access only, never recovery: a normal operation is still refused without a native call.
        int drives = tree.Network.Count(FakeNetworkApi.DriveExport);
        Assert.Equal(SasPairingStatus.Fatal, Assert.Throws<SasPairingNativeException>(tree.Host.Drive).KnownStatus);
        Assert.Equal(drives, tree.Network.Count(FakeNetworkApi.DriveExport));
    }

    [Fact]
    public void AReadIsRefusedLocallyAfterAContractViolationElsewhereAndDisposeStillDestroys()
    {
        (FakeTree tree, SasPairingResult result) = Delivered();
        tree.Network.Next(Ok, Ok, Records.Event(99));
        Assert.Throws<SasPairingContractException>(tree.Host.Drive);

        SasPairingContractException refused = Assert.Throws<SasPairingContractException>(result.Read);

        Assert.Equal("SasPairingResult.Read", refused.Operation);
        Assert.Equal(0, tree.Results.Total);
        Assert.False(result.IsDisposed);

        result.Dispose();
        Assert.Equal(FakeResultApi.DestroyExport, Assert.Single(tree.Results.Calls).Export);
        Assert.True(result.IsDisposed);
    }

    [Fact]
    public void TheDisposedCheckComesBeforeTheContractLatch()
    {
        (FakeTree tree, SasPairingResult result) = Delivered();
        result.Dispose();
        tree.Network.Next(Ok, Ok, Records.Event(99));
        Assert.Throws<SasPairingContractException>(tree.Host.Drive);

        Assert.Throws<ObjectDisposedException>(result.Read);

        Assert.Equal(1, tree.Results.Total);
    }

    [Fact]
    public void DataAdmissionRefusesOnlyTheContractLatchNeverNativeFatal()
    {
        (NativeProcessContext context, _) = FakeContext.Create();
        context.AdmitData("op");

        _ = context.Failed("op", AbiV1Constants.SAS_PAIRING_FATAL);
        Assert.True(context.IsFatal);
        context.AdmitData("op");
        Assert.Throws<SasPairingNativeException>(() => context.AdmitNormal("op"));

        _ = context.ViolateContract("op", "returned something impossible");
        Assert.Equal("data op", Assert.Throws<SasPairingContractException>(() => context.AdmitData("data op")).Operation);
        Assert.Throws<SasPairingContractException>(() => context.AdmitNormal("op"));
    }
}
