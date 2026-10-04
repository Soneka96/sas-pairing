namespace SasPairing;

/// <summary>
/// The operational reason of a refusal or ending, with its frozen native value. Never evidence about the peer,
/// authentication, a SAS, or compromise: an I/O error is not an attack, and a peer close is not a rejection.
/// </summary>
public enum SasPairingEventReason
{
    /// <summary>No reason applies.</summary>
    None = 0,

    /// <summary>A transport or admission refusal (accept work, live cap, START limiter, pending caps).</summary>
    ResourceLimited = 1,

    /// <summary>The read reached the end of the stream.</summary>
    PeerClosed = 2,

    /// <summary>A local socket failure (the OS error kind is not part of the contract).</summary>
    SocketIo = 3,

    /// <summary>The run owning a partially written frame ended.</summary>
    AbandonedPartialFrame = 4,

    /// <summary>Error or invalid-handle readiness on the connection (for example a reset).</summary>
    ReadinessFailure = 5,

    /// <summary>An accept error.</summary>
    ListenerIo = 6,

    /// <summary>Error, hang-up, or invalid-handle readiness on the listener.</summary>
    ListenerReadiness = 7,

    /// <summary>A run-local routing or ceremony refusal.</summary>
    RouteRefused = 8,

    /// <summary>Shared authority state or cleanup was uncertain.</summary>
    OwnershipUncertain = 9,

    /// <summary>The connection's router session is unknown.</summary>
    OtherHostFailure = 10,

    /// <summary>Framing, an undefined type, or an oversized or unroutable frame.</summary>
    InvalidFrame = 11,

    /// <summary>A transport frame or connection deadline.</summary>
    TransportDeadline = 12,

    /// <summary>A transport or ceremony clock was unusable.</summary>
    ClockUnavailable = 13,

    /// <summary>A session-fatal routing failure.</summary>
    SessionProtocolFailure = 14,

    /// <summary>The connection had already ended.</summary>
    AlreadyClosed = 15,
}
