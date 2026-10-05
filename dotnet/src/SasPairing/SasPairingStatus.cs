namespace SasPairing;

/// <summary>
/// The 48 frozen native ABI v1 status codes (<c>sas_pairing_status_t</c>), each with exactly its native
/// value. A status is the outcome of one operation: it never classifies a peer as trusted, malicious, or
/// compromised, and it is never a security verdict.
/// </summary>
/// <remarks>
/// Every non-zero value is a failure, including a value this enum does not name: such an unknown status is
/// kept as <see cref="SasPairingNativeException.StatusCode"/> with a null
/// <see cref="SasPairingNativeException.KnownStatus"/>, and is never treated as success. Only
/// <see cref="Fatal"/> requires an OS process restart.
/// </remarks>
public enum SasPairingStatus : int
{
    /// <summary>Success (<c>SAS_PAIRING_OK</c>).</summary>
    Ok = 0,

    /// <summary>A required argument or output pointer was invalid; nothing was written.</summary>
    InvalidArgument = 1,

    /// <summary>A handle was zero, unknown, of another kind, or already destroyed or released.</summary>
    InvalidHandle = 2,

    /// <summary>A runtime is already active in this process; it was not replaced.</summary>
    AlreadyInitialized = 3,

    /// <summary>The process-wide handle counter is exhausted.</summary>
    HandlesExhausted = 4,

    /// <summary>The authority scope is invalid (for example empty).</summary>
    InvalidScope = 100,

    /// <summary>The authority is already registered in this process.</summary>
    AlreadyRegistered = 101,

    /// <summary>The authority's OS ownership is unavailable.</summary>
    OwnershipUnavailable = 102,

    /// <summary>The operation is not supported on this platform (it fails closed).</summary>
    UnsupportedPlatform = 103,

    /// <summary>Ownership or cleanup could not be established with certainty.</summary>
    OwnershipUncertain = 104,

    /// <summary>The authority is busy with a live ceremony.</summary>
    Busy = 105,

    /// <summary>The authority's opportunities are exhausted for this process session.</summary>
    Exhausted = 106,

    /// <summary>A bounded resource limit was reached.</summary>
    ResourceLimited = 107,

    /// <summary>A required local authorization is missing.</summary>
    MissingAuthorization = 200,

    /// <summary>A local authorization is stale.</summary>
    StaleAuthorization = 201,

    /// <summary>The ceremony was terminated.</summary>
    Terminated = 202,

    /// <summary>The supplied Bootstrap configuration failed the core's Bootstrap validation.</summary>
    InvalidBootstrap = 203,

    /// <summary>The named run is no longer live.</summary>
    RunEnded = 204,

    /// <summary>The connection still holds an outbound frame: drive the host, then retry if still appropriate.</summary>
    WritePending = 205,

    /// <summary>The ceremony is not in a state that allows the local action.</summary>
    CeremonyInvalidState = 206,

    /// <summary>No live SAS is available.</summary>
    NoLiveSas = 207,

    /// <summary>The decision named a ceremony identity other than the presented one.</summary>
    CeremonyIdentityMismatch = 208,

    /// <summary>The action requires a local approval that was not given.</summary>
    NotLocallyApproved = 209,

    /// <summary>A message came from an unexpected sender role.</summary>
    UnexpectedSenderRole = 210,

    /// <summary>A request ID was invalid.</summary>
    InvalidRequestId = 211,

    /// <summary>A request ID could not be generated.</summary>
    RequestIdGenerationFailed = 212,

    /// <summary>A request ID did not match.</summary>
    RequestIdMismatch = 213,

    /// <summary>The shared context did not match.</summary>
    SharedContextMismatch = 214,

    /// <summary>The expected peer did not match.</summary>
    ExpectedPeerMismatch = 215,

    /// <summary>The approvals are not authenticated.</summary>
    ApprovalsNotAuthenticated = 216,

    /// <summary>The local side is not the Initiator.</summary>
    NotInitiator = 217,

    /// <summary>The transcript did not match.</summary>
    TranscriptMismatch = 218,

    /// <summary>The ceremony has already completed.</summary>
    Completed = 219,

    /// <summary>No final ACK is pending.</summary>
    NoPendingFinalAck = 220,

    /// <summary>The final ACK did not match.</summary>
    FinalAckMismatch = 221,

    /// <summary>The ceremony deadline was reached.</summary>
    CeremonyTimedOut = 222,

    /// <summary>The ceremony clock is unavailable.</summary>
    CeremonyClockUnavailable = 223,

    /// <summary>A pending ceremony expired.</summary>
    PendingExpired = 224,

    /// <summary>The ceremony codec failed.</summary>
    CeremonyCodecError = 225,

    /// <summary>A ceremony cryptographic operation failed inside the native core.</summary>
    CeremonyCryptoError = 226,

    /// <summary>A caller buffer is too small; nothing was copied.</summary>
    BufferTooSmall = 300,

    /// <summary>A listener is already attached to the host.</summary>
    ListenerAlreadyAttached = 400,

    /// <summary>Setting up the listener failed.</summary>
    ListenerSetupFailed = 401,

    /// <summary>No listener is attached to the host.</summary>
    ListenerNotAttached = 402,

    /// <summary>The host's owner loop is closed.</summary>
    OwnerLoopClosed = 403,

    /// <summary>Network polling failed.</summary>
    NetworkPollFailed = 404,

    /// <summary>The connection ended during the call; its handles are invalid. Lifecycle only.</summary>
    ConnectionEnded = 405,

    /// <summary>
    /// The native state of this process is permanently fatal (a contained native panic). Every later normal
    /// operation is refused; cleanup still works; only an OS process restart recovers.
    /// </summary>
    Fatal = 900,
}
