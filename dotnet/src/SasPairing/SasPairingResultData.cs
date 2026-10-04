namespace SasPairing;

/// <summary>
/// An immutable snapshot of one local verified result, made only by <see cref="SasPairingResult.Read"/>
/// (P9-D-005).
/// </summary>
/// <remarks>
/// <para>
/// <b>Local completion only.</b> These values were authenticated by THIS endpoint's locally completed SAS
/// ceremony. They do not prove that the peer completed, received the final message, holds a result of its own, or
/// stored anything, and they are not a bilateral commit or established trust. They are inputs to the
/// application's own policy; this package persists, enrolls, and trusts nothing.
/// </para>
/// <para>
/// <b>Detached.</b> Plain managed data: it stays usable after <see cref="SasPairingResult.Dispose"/> and after
/// <see cref="SasPairingRuntime.Dispose"/>, and owns nothing native. Every byte field is this object's own copy,
/// exposed read-only, and is exactly the bytes the native core reported: nothing is decoded, parsed, trimmed, or
/// terminated, and no field is text.
/// </para>
/// </remarks>
public sealed class SasPairingResultData
{
    private readonly byte[] _requestId;
    private readonly byte[] _authenticatedPeerBootstrap;
    private readonly byte[] _authenticatedSharedContext;
    private readonly byte[] _profileIdentifier;

    internal SasPairingResultData(
        SasPairingCeremonyIdentity ceremonyIdentity,
        SasPairingPeerRole peerRole,
        uint profileVersion,
        ReadOnlySpan<byte> requestId,
        ReadOnlySpan<byte> authenticatedPeerBootstrap,
        ReadOnlySpan<byte> authenticatedSharedContext,
        ReadOnlySpan<byte> profileIdentifier)
    {
        CeremonyIdentity = ceremonyIdentity;
        PeerRole = peerRole;
        ProfileVersion = profileVersion;
        _requestId = requestId.ToArray();
        _authenticatedPeerBootstrap = authenticatedPeerBootstrap.ToArray();
        _authenticatedSharedContext = authenticatedSharedContext.ToArray();
        _profileIdentifier = profileIdentifier.ToArray();
    }

    /// <summary>
    /// The 32-byte transcript-derived ceremony identity: the same value the SAS presentation of this ceremony
    /// carried (<see cref="SasPairingSasPresentation.CeremonyIdentity"/>). Not a request ID, handle, peer identity,
    /// or trust key.
    /// </summary>
    public SasPairingCeremonyIdentity CeremonyIdentity { get; }

    /// <summary>The PEER's role in the ceremony, never this endpoint's.</summary>
    public SasPairingPeerRole PeerRole { get; }

    /// <summary>The protocol profile version, exactly as reported: data, not a compatibility or trust decision.</summary>
    public uint ProfileVersion { get; }

    /// <summary>
    /// The ceremony's request ID: exact routing and correlation bytes only, never text, a GUID, a result identity,
    /// a run identity, or a peer identity.
    /// </summary>
    public ReadOnlySpan<byte> RequestId => _requestId;

    /// <summary>
    /// The exact canonical Bootstrap frame the peer supplied in this ceremony under the approved SAS flow, as the
    /// native core returned it. This package does not parse, split, or re-encode it, and does not enroll or trust
    /// it: what to do with it is application policy.
    /// </summary>
    public ReadOnlySpan<byte> AuthenticatedPeerBootstrap => _authenticatedPeerBootstrap;

    /// <summary>The authenticated shared context: exact opaque bytes, possibly empty, never interpreted here.</summary>
    public ReadOnlySpan<byte> AuthenticatedSharedContext => _authenticatedSharedContext;

    /// <summary>The protocol profile identifier, as exact bytes: not decoded, compared, or used to select anything here.</summary>
    public ReadOnlySpan<byte> ProfileIdentifier => _profileIdentifier;
}
