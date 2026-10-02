//! Frozen ABI v1 status codes (`int32_t`), mirrored by `core/include/sas_pairing.h`.
//!
//! Values are explicit and never renumbered or reused. Ranges reserved for later increments:
//! 1–99 ABI, lifecycle, and arguments; 100–199 authority, resource, and core; 200–299 ceremony
//! and protocol; 300–399 buffers and data results; 900–999 fatal and internal. Wrappers treat
//! every non-zero value, including unknown ones, as failure. The core `Error` discriminant is
//! never exposed directly; later increments map it explicitly.

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
/// A Rust panic was contained: the native ABI state of this process is permanently fatal, and
/// only a new OS process recovers (P6-D-004, P7-D-001). Distinct from every ordinary error.
pub const SAS_PAIRING_FATAL: i32 = 900;
