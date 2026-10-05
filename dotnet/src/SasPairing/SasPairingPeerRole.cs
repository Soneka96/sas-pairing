namespace SasPairing;

/// <summary>
/// The PEER's role in the ceremony a result completed, as the native core reports it, with its frozen native value
/// (P9-D-005). Never this endpoint's own role: an Initiator's result normally reports <see cref="Responder"/>, a
/// Responder's result <see cref="Initiator"/>. Native <c>SAS_PAIRING_ROLE_INVALID</c> (0) is not a public value:
/// a successful result never reports it.
/// </summary>
public enum SasPairingPeerRole
{
    /// <summary>The peer was the ceremony's Initiator.</summary>
    Initiator = 1,

    /// <summary>The peer was the ceremony's Responder.</summary>
    Responder = 2,
}
