//! Frozen ABI v1 status codes (`int32_t`), mirrored by `core/include/sas_pairing.h`.
//!
//! Values are explicit and never renumbered or reused. Ranges:
//! 1–99 ABI, lifecycle, and arguments; 100–199 authority, resource, and core; 200–299 ceremony
//! and protocol; 300–399 buffers and data results; 400–499 host, listener, and transport-boundary
//! lifecycle; 900–999 fatal and internal. Wrappers treat
//! every non-zero value, including unknown ones, as failure. The core `Error` discriminant is
//! never exposed: [`map_core_error`] is the one explicit translation (P7-D-004), and
//! [`map_ceremony_error`] the one translation of a ceremony refusal of a trusted local action
//! (P7-D-012).

use crate::{Error, ceremony::CeremonyError, router::RouteError};

/// The operation completed.
pub const SAS_PAIRING_OK: i32 = 0;
/// A required pointer was null or misaligned; nothing was written through it.
pub const SAS_PAIRING_INVALID_ARGUMENT: i32 = 1;
/// The handle is zero, unknown, or already destroyed.
pub const SAS_PAIRING_INVALID_HANDLE: i32 = 2;
/// A runtime is already active in this process; it was not replaced.
pub const SAS_PAIRING_ALREADY_INITIALIZED: i32 = 3;
/// The process can never issue another handle: handles are not reused or wrapped (P7-D-001).
pub const SAS_PAIRING_HANDLES_EXHAUSTED: i32 = 4;

// Authority, resource, and core errors (100–199). Each carries the reviewed core meaning of the
// `Error` variant it translates; the ABI adds no interpretation.

/// The scope is empty or longer than the core accepts.
pub const SAS_PAIRING_INVALID_SCOPE: i32 = 100;
/// This authority is already registered in this process; the active registration is untouched.
pub const SAS_PAIRING_ALREADY_REGISTERED: i32 = 101;
/// The authority's OS ownership could not be acquired (for example another process holds it).
pub const SAS_PAIRING_OWNERSHIP_UNAVAILABLE: i32 = 102;
/// The platform has no supported OS ownership mechanism; nothing was registered.
pub const SAS_PAIRING_UNSUPPORTED_PLATFORM: i32 = 103;
/// Ownership or accounting state is uncertain; the core fails closed until process restart.
pub const SAS_PAIRING_OWNERSHIP_UNCERTAIN: i32 = 104;
/// The authority is in use.
pub const SAS_PAIRING_BUSY: i32 = 105;
/// The authority's opportunity budget for this process session is spent.
pub const SAS_PAIRING_EXHAUSTED: i32 = 106;
/// Generic pre-exposure resource or admission refusal; spends and refunds no opportunity.
pub const SAS_PAIRING_RESOURCE_LIMITED: i32 = 107;

// Ceremony and protocol errors (200–299).

/// A reservation was attempted without local authorization.
pub const SAS_PAIRING_MISSING_AUTHORIZATION: i32 = 200;
/// The authorization or ceremony does not belong to this exact ceremony and authority.
pub const SAS_PAIRING_STALE_AUTHORIZATION: i32 = 201;
/// The ceremony is already terminal.
pub const SAS_PAIRING_TERMINATED: i32 = 202;
/// The supplied trusted-local Bootstrap configuration failed the core's own Bootstrap
/// validation (`Bootstrap::new`); nothing was created (P7-D-006).
#[cfg_attr(
    all(not(windows), not(test)),
    expect(dead_code, reason = "no listener can be attached off Windows")
)]
pub const SAS_PAIRING_INVALID_BOOTSTRAP: i32 = 203;
/// The run handle named an exact run that is no longer routed: it ended. The handle is invalid
/// from then on (P7-D-012).
pub const SAS_PAIRING_RUN_ENDED: i32 = 204;
/// A trusted local action did not run because the connection still retains one outbound frame
/// awaiting socket progress; drive the host and retry (P7-D-011). Not a refusal by anyone.
#[cfg_attr(
    all(not(windows), not(test)),
    expect(dead_code, reason = "no connection exists off Windows")
)]
pub const SAS_PAIRING_WRITE_PENDING: i32 = 205;

// Run-local ceremony refusals of a trusted local action (P7-D-012): one value per
// `CeremonyError` variant other than `Owner`, which keeps its P7-D-004 value. Local operation
// outcomes, never a verdict about the peer, authentication, or compromise.

pub const SAS_PAIRING_CEREMONY_INVALID_STATE: i32 = 206;
pub const SAS_PAIRING_NO_LIVE_SAS: i32 = 207;
pub const SAS_PAIRING_CEREMONY_IDENTITY_MISMATCH: i32 = 208;
pub const SAS_PAIRING_NOT_LOCALLY_APPROVED: i32 = 209;
pub const SAS_PAIRING_UNEXPECTED_SENDER_ROLE: i32 = 210;
pub const SAS_PAIRING_INVALID_REQUEST_ID: i32 = 211;
pub const SAS_PAIRING_REQUEST_ID_GENERATION_FAILED: i32 = 212;
pub const SAS_PAIRING_REQUEST_ID_MISMATCH: i32 = 213;
pub const SAS_PAIRING_SHARED_CONTEXT_MISMATCH: i32 = 214;
pub const SAS_PAIRING_EXPECTED_PEER_MISMATCH: i32 = 215;
pub const SAS_PAIRING_APPROVALS_NOT_AUTHENTICATED: i32 = 216;
pub const SAS_PAIRING_NOT_INITIATOR: i32 = 217;
pub const SAS_PAIRING_TRANSCRIPT_MISMATCH: i32 = 218;
pub const SAS_PAIRING_COMPLETED: i32 = 219;
pub const SAS_PAIRING_NO_PENDING_FINAL_ACK: i32 = 220;
pub const SAS_PAIRING_FINAL_ACK_MISMATCH: i32 = 221;
pub const SAS_PAIRING_CEREMONY_TIMED_OUT: i32 = 222;
pub const SAS_PAIRING_CEREMONY_CLOCK_UNAVAILABLE: i32 = 223;
pub const SAS_PAIRING_PENDING_EXPIRED: i32 = 224;
pub const SAS_PAIRING_CEREMONY_CODEC_ERROR: i32 = 225;
pub const SAS_PAIRING_CEREMONY_CRYPTO_ERROR: i32 = 226;

// Buffers and data results (300–399).

/// A caller buffer is smaller than required; nothing was copied, no work was done, and the
/// required size was reported (P7-D-008, P7-D-010).
pub const SAS_PAIRING_BUFFER_TOO_SMALL: i32 = 300;

// Host, listener, and transport-boundary lifecycle (400–499).

/// The host already has a listener and owner loop; the new socket was not adopted.
#[cfg_attr(
    all(not(windows), not(test)),
    expect(dead_code, reason = "no listener can be attached off Windows")
)]
pub const SAS_PAIRING_LISTENER_ALREADY_ATTACHED: i32 = 400;
/// The adopted listener could not be configured for the owner loop; Rust closed it.
#[cfg_attr(
    all(not(windows), not(test)),
    expect(dead_code, reason = "no listener can be attached off Windows")
)]
pub const SAS_PAIRING_LISTENER_SETUP_FAILED: i32 = 401;
/// The host has no listener and owner loop: nothing was driven or closed (P7-D-008).
#[cfg_attr(
    all(not(windows), not(test)),
    expect(dead_code, reason = "no listener can be attached off Windows")
)]
pub const SAS_PAIRING_LISTENER_NOT_ATTACHED: i32 = 402;
/// The host's owner loop had already failed closed: nothing was driven; detach it (P7-D-008).
#[cfg_attr(
    all(not(windows), not(test)),
    expect(dead_code, reason = "no owner loop exists off Windows")
)]
pub const SAS_PAIRING_OWNER_LOOP_CLOSED: i32 = 403;
/// The owner loop's readiness wait failed, so it failed closed (P7-D-008). The WinSock code is
/// diagnostic only and never part of the ABI.
#[cfg_attr(
    all(not(windows), not(test)),
    expect(dead_code, reason = "no owner loop exists off Windows")
)]
pub const SAS_PAIRING_NETWORK_POLL_FAILED: i32 = 404;
/// A trusted local action was admitted against a live connection, and the reviewed adapter or
/// host ended that connection during the call: the connection handle and every run handle of it
/// are invalid. Lifecycle only: never an attack, authentication, SAS, or compromise verdict
/// (P7-D-012).
#[cfg_attr(
    all(not(windows), not(test)),
    expect(dead_code, reason = "no connection exists off Windows")
)]
pub const SAS_PAIRING_CONNECTION_ENDED: i32 = 405;

/// A Rust panic was contained: the native ABI state of this process is permanently fatal, and
/// only a new OS process recovers (P6-D-004, P7-D-001). Distinct from every ordinary error.
pub const SAS_PAIRING_FATAL: i32 = 900;

/// The one translation of a core [`Error`] into its frozen ABI status (P7-D-004). Exhaustive and
/// wildcard-free, so a new core variant does not compile until P7 decides its ABI value.
pub(super) fn map_core_error(error: Error) -> i32 {
    match error {
        Error::InvalidScope => SAS_PAIRING_INVALID_SCOPE,
        Error::AlreadyRegistered => SAS_PAIRING_ALREADY_REGISTERED,
        Error::OwnershipUnavailable => SAS_PAIRING_OWNERSHIP_UNAVAILABLE,
        Error::UnsupportedPlatform => SAS_PAIRING_UNSUPPORTED_PLATFORM,
        Error::OwnershipUncertain => SAS_PAIRING_OWNERSHIP_UNCERTAIN,
        Error::Busy => SAS_PAIRING_BUSY,
        Error::Exhausted => SAS_PAIRING_EXHAUSTED,
        Error::ResourceLimited => SAS_PAIRING_RESOURCE_LIMITED,
        Error::MissingAuthorization => SAS_PAIRING_MISSING_AUTHORIZATION,
        Error::StaleAuthorization => SAS_PAIRING_STALE_AUTHORIZATION,
        Error::Terminated => SAS_PAIRING_TERMINATED,
    }
}

/// The one translation of a run-local [`CeremonyError`] refusal of a trusted local action into
/// its frozen ABI status (P7-D-012). `Owner` keeps the P7-D-004 value of its core `Error`; every
/// other variant has its own value. Exhaustive and wildcard-free, with no discriminant, `Debug`,
/// or `Display`, so a new variant does not compile until P7 decides its ABI value.
#[cfg_attr(
    all(not(windows), not(test)),
    expect(dead_code, reason = "no local action runs off Windows")
)]
pub(super) fn map_ceremony_error(error: &CeremonyError) -> i32 {
    match error {
        CeremonyError::Owner(error) => map_core_error(error.clone()),
        CeremonyError::Codec(_) => SAS_PAIRING_CEREMONY_CODEC_ERROR,
        CeremonyError::Crypto(_) => SAS_PAIRING_CEREMONY_CRYPTO_ERROR,
        CeremonyError::InvalidState => SAS_PAIRING_CEREMONY_INVALID_STATE,
        CeremonyError::NoLiveSas => SAS_PAIRING_NO_LIVE_SAS,
        CeremonyError::CeremonyIdentityMismatch => SAS_PAIRING_CEREMONY_IDENTITY_MISMATCH,
        CeremonyError::NotLocallyApproved => SAS_PAIRING_NOT_LOCALLY_APPROVED,
        CeremonyError::UnexpectedSenderRole => SAS_PAIRING_UNEXPECTED_SENDER_ROLE,
        CeremonyError::InvalidRequestId => SAS_PAIRING_INVALID_REQUEST_ID,
        CeremonyError::RequestIdGenerationFailed => SAS_PAIRING_REQUEST_ID_GENERATION_FAILED,
        CeremonyError::RequestIdMismatch => SAS_PAIRING_REQUEST_ID_MISMATCH,
        CeremonyError::SharedContextMismatch => SAS_PAIRING_SHARED_CONTEXT_MISMATCH,
        CeremonyError::ExpectedPeerMismatch => SAS_PAIRING_EXPECTED_PEER_MISMATCH,
        CeremonyError::ApprovalsNotAuthenticated => SAS_PAIRING_APPROVALS_NOT_AUTHENTICATED,
        CeremonyError::NotInitiator => SAS_PAIRING_NOT_INITIATOR,
        CeremonyError::TranscriptMismatch => SAS_PAIRING_TRANSCRIPT_MISMATCH,
        CeremonyError::Completed => SAS_PAIRING_COMPLETED,
        CeremonyError::NoPendingFinalAck => SAS_PAIRING_NO_PENDING_FINAL_ACK,
        CeremonyError::FinalAckMismatch => SAS_PAIRING_FINAL_ACK_MISMATCH,
        CeremonyError::TimedOut(_) => SAS_PAIRING_CEREMONY_TIMED_OUT,
        CeremonyError::ClockUnavailable => SAS_PAIRING_CEREMONY_CLOCK_UNAVAILABLE,
        CeremonyError::PendingExpired => SAS_PAIRING_PENDING_EXPIRED,
    }
}

/// The run-local refusal of a trusted local action on an EXISTING run: `UnknownRoute` (the exact
/// run is no longer routed) is `RUN_ENDED`, and a ceremony refusal goes through
/// [`map_ceremony_error`]. `UnknownSession` and `SessionProtocolFailure` end the connection in
/// the host, so they never arrive as a run-local refusal; `None` marks that broken invariant,
/// which the caller treats as fatal rather than misreport the connection's state.
#[cfg_attr(
    all(not(windows), not(test)),
    expect(dead_code, reason = "no local action runs off Windows")
)]
pub(super) fn map_run_refusal(error: &RouteError) -> Option<i32> {
    match error {
        RouteError::UnknownRoute => Some(SAS_PAIRING_RUN_ENDED),
        RouteError::Ceremony(error) => Some(map_ceremony_error(error)),
        RouteError::UnknownSession | RouteError::SessionProtocolFailure => None,
    }
}
