using SasPairing.Interop;

namespace SasPairing.Tests.Support;

/// <summary>One recorded call of the fake result service, with its exact handles, field selector, and capacity.</summary>
internal sealed record FakeResultCall(string Export, ulong[] Arguments, uint Field = 0, int Capacity = -1);

/// <summary>
/// The data a fake native result reports: the info fields and the four variable fields, raw. The defaults are
/// distinctive binary values (with 0x00, 0x80, and 0xFF bytes, never text) and the frozen profile identifier.
/// </summary>
internal sealed record FakeResultData(
    byte[] Identity,
    uint PeerRole,
    uint ProfileVersion,
    byte[] RequestId,
    byte[] PeerBootstrap,
    byte[] SharedContext,
    byte[] ProfileIdentifier)
{
    internal static FakeResultData Default() => new(
        Presentations.Identity(0x6B),
        AbiV1Constants.SAS_PAIRING_ROLE_RESPONDER,
        1,
        [0x00, 0x80, 0xFF, 0x41],
        [0x53, 0x41, 0x53, 0x00, 0x80, 0xFF, 0x20, 0x01, 0x00],
        [0xFF, 0x00, 0x80],
        "sas-pairing-vodozemac-profile-draft-01"u8.ToArray());

    internal NativeResultInfoRecord Info() =>
        new(Identity, PeerRole, ProfileVersion, (uint)RequestId.Length, (uint)PeerBootstrap.Length, (uint)SharedContext.Length, (uint)ProfileIdentifier.Length);

    internal byte[] Field(uint field) => field switch
    {
        AbiV1Constants.SAS_PAIRING_RESULT_FIELD_REQUEST_ID => RequestId,
        AbiV1Constants.SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_PEER_BOOTSTRAP => PeerBootstrap,
        AbiV1Constants.SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_SHARED_CONTEXT => SharedContext,
        AbiV1Constants.SAS_PAIRING_RESULT_FIELD_PROFILE_IDENTIFIER => ProfileIdentifier,
        _ => throw new ArgumentOutOfRangeException(nameof(field)),
    };
}

/// <summary>
/// A fake result-native service with deterministic outcomes and an exact call log. By default every result answers
/// info with <see cref="Data"/>, a copy at a sufficient capacity with exactly the field's bytes (a smaller capacity
/// with <c>BUFFER_TOO_SMALL</c>, as native would), and destroy with <see cref="DestroyStatus"/>; each can be
/// overridden. It shares one fake process context with the other fake services.
/// </summary>
internal sealed class FakeResultApi : INativeResultApi
{
    internal const string InfoExport = "sas_pairing_result_info";
    internal const string CopyExport = "sas_pairing_result_copy";
    internal const string DestroyExport = "sas_pairing_result_destroy";

    internal List<FakeResultCall> Calls { get; } = [];

    /// <summary>The data every result reports by default.</summary>
    internal FakeResultData Data { get; set; } = FakeResultData.Default();

    /// <summary>Overrides the info outcome (default: <c>OK</c> with <see cref="Data"/>).</summary>
    internal Func<ulong, NativeResultInfoOutcome>? InfoOutcome { get; set; }

    /// <summary>Overrides a copy outcome by field and capacity; null from it means the default behaviour.</summary>
    internal Func<uint, int, NativeResultCopyOutcome?>? CopyOutcome { get; set; }

    internal int DestroyStatus { get; set; }

    internal int Count(string export) => Calls.Count(c => c.Export == export);

    internal int Total => Calls.Count;

    public NativeResultInfoOutcome ResultInfo(ulong runtime, ulong result)
    {
        Calls.Add(new FakeResultCall(InfoExport, [runtime, result]));
        return InfoOutcome?.Invoke(result) ?? new NativeResultInfoOutcome(AbiV1Constants.SAS_PAIRING_OK, Data.Info());
    }

    public NativeResultCopyOutcome ResultCopy(ulong runtime, ulong result, uint field, int capacity)
    {
        Calls.Add(new FakeResultCall(CopyExport, [runtime, result], field, capacity));
        if (CopyOutcome?.Invoke(field, capacity) is { } overridden)
        {
            return overridden;
        }

        byte[] bytes = Data.Field(field);
        return capacity < bytes.Length
            ? new NativeResultCopyOutcome(AbiV1Constants.SAS_PAIRING_BUFFER_TOO_SMALL, (nuint)bytes.Length, null)
            : new NativeResultCopyOutcome(AbiV1Constants.SAS_PAIRING_OK, (nuint)bytes.Length, [.. bytes]);
    }

    public int ResultDestroy(ulong runtime, ulong result)
    {
        Calls.Add(new FakeResultCall(DestroyExport, [runtime, result]));
        return DestroyStatus;
    }
}
