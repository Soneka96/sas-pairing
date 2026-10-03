//! Frozen ABI v1 status codes (`int32_t`), mirrored by `core/include/sas_pairing.h`.
//!
//! Values are explicit and never renumbered or reused. Ranges:
//! 1–99 ABI, lifecycle, and arguments; 100–199 authority, resource, and core; 200–299 ceremony
//! and protocol; 300–399 buffers and data results; 400–499 host, listener, and transport-boundary
//! lifecycle; 900–999 fatal and internal. Wrappers treat
//! every non-zero value, including unknown ones, as failure. The core `Error` discriminant is
//! never exposed: [`map_core_error`] is the one explicit translation (P7-D-004).

use crate::Error;

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
