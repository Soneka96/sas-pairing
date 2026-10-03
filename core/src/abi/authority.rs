//! Authority lifecycle through the native ABI (P7-D-003).
//!
//! An authority handle names one ABI object lifetime: one active registration of a real core
//! [`TrustedAuthority`], owned by the runtime. It is not the authority's identity and not its
//! process session. Release or runtime destroy ends the registration (its OS lease); the core's
//! process session, with its opportunity budget and START limiter, outlives every handle for the
//! rest of the OS process (P6-D-002), under the loader invariant of P7-D-002.

use std::num::NonZeroU64;

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

use super::{
    runtime::{AbiState, Admission},
    status::{SAS_PAIRING_INVALID_HANDLE, SAS_PAIRING_OK, map_core_error},
};
use crate::{Status, TrustedAuthority};

/// `sas_pairing_authority_t`: an opaque process-local handle; `0` is never valid.
pub(super) type AuthorityHandle = u64;

/// `sas_pairing_authority_state_t` values. Fixed numbers, never the Rust `Status` layout.
pub(super) const SAS_PAIRING_AUTHORITY_STATE_INVALID: u32 = 0;
pub(super) const SAS_PAIRING_AUTHORITY_READY: u32 = 1;
pub(super) const SAS_PAIRING_AUTHORITY_BUSY: u32 = 2;
pub(super) const SAS_PAIRING_AUTHORITY_EXHAUSTED: u32 = 3;

/// Calls into the reviewed core made by authority operations (tests only), to show that no
/// normal operation re-enters the core after fatal.
#[cfg(test)]
pub(super) static CORE_ENTRIES: AtomicUsize = AtomicUsize::new(0);

/// Every call from an authority operation into the reviewed core goes through here.
fn enter_core<T>(op: impl FnOnce() -> T) -> T {
    #[cfg(test)]
    CORE_ENTRIES.fetch_add(1, Ordering::SeqCst);
    op()
}

/// Translates the core's authority status into `(state, remaining)`; `remaining` is non-zero
/// only for `READY`.
pub(super) fn authority_state(status: Status) -> (u32, u32) {
    match status {
        Status::Ready { remaining } => (SAS_PAIRING_AUTHORITY_READY, u32::from(remaining)),
        Status::Busy => (SAS_PAIRING_AUTHORITY_BUSY, 0),
        Status::Exhausted => (SAS_PAIRING_AUTHORITY_EXHAUSTED, 0),
    }
}

fn owned(handle: AuthorityHandle) -> Result<NonZeroU64, i32> {
    NonZeroU64::new(handle).ok_or(SAS_PAIRING_INVALID_HANDLE)
}

impl AbiState {
    /// Registers `scope` with the core under the live runtime `runtime`.
    ///
    /// The handle is reserved before the core is entered, so a core registration can never
    /// lack a handle. A core error burns the reserved value (it is never issued or reused) and
    /// installs nothing; exhaustion fails before the core is entered.
    pub(super) fn register_authority(&self, runtime: u64, scope: &[u8]) -> Result<NonZeroU64, i32> {
        self.with_runtime(runtime, Admission::Normal, |live| {
            let handle = self.allocate_handle()?;
            let authority =
                enter_core(|| TrustedAuthority::register(scope)).map_err(map_core_error)?;
            live.authorities.insert(handle, authority);
            Ok(handle)
        })
    }

    /// Releases `authority`: its handle leaves the runtime first and is invalid forever, then
    /// the core's explicit release runs and its result is mapped. A failed release never
    /// restores the handle. Admitted in the fatal state, as cleanup.
    pub(super) fn release_authority(&self, runtime: u64, authority: AuthorityHandle) -> i32 {
        let released = self.with_runtime(runtime, Admission::Cleanup, |live| {
            let authority = live
                .authorities
                .remove(&owned(authority)?)
                .ok_or(SAS_PAIRING_INVALID_HANDLE)?;
            enter_core(|| authority.release()).map_err(map_core_error)
        });
        match released {
            Ok(()) => SAS_PAIRING_OK,
            Err(status) => status,
        }
    }

    /// Reads `authority`'s status through the core's own status path.
    pub(super) fn authority_status(
        &self,
        runtime: u64,
        authority: AuthorityHandle,
    ) -> Result<(u32, u32), i32> {
        self.with_runtime(runtime, Admission::Normal, |live| {
            let authority = live
                .authorities
                .get(&owned(authority)?)
                .ok_or(SAS_PAIRING_INVALID_HANDLE)?;
            let status = enter_core(|| authority.executor().status()).map_err(map_core_error)?;
            Ok(authority_state(status))
        })
    }
}
