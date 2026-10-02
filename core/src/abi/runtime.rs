//! Native runtime lifecycle and handles (P7-D-001).
//!
//! At most one runtime is active per OS process, and the runtime is the fatal-containment unit.
//! Handles are opaque process-local `u64` values drawn from one monotonic counter: never zero,
//! never reused, and never wrapped. P7.1 runtimes own no core state: creating one registers no
//! authority, takes no OS lock, starts no listener, and generates no protocol randomness.

use std::{
    num::NonZeroU64,
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
};

use super::{
    panic_boundary::FatalState,
    status::{
        SAS_PAIRING_ALREADY_INITIALIZED, SAS_PAIRING_FATAL, SAS_PAIRING_HANDLES_EXHAUSTED,
        SAS_PAIRING_INVALID_HANDLE, SAS_PAIRING_OK,
    },
};

/// Issues each handle value at most once per process. `0` is the exhausted sentinel: after
/// `u64::MAX` has been issued, allocation fails forever instead of wrapping to an old value.
pub(super) struct HandleCounter(AtomicU64);

impl HandleCounter {
    pub(super) const fn new() -> Self {
        Self(AtomicU64::new(1))
    }

    /// A test-local counter whose next handle is `next` (exhaustion tests only; production has
    /// exactly one counter per process and no way to move it).
    #[cfg(test)]
    pub(super) const fn starting_at(next: u64) -> Self {
        Self(AtomicU64::new(next))
    }

    pub(super) fn allocate(&self) -> Option<NonZeroU64> {
        let mut next = self.0.load(Ordering::SeqCst);
        loop {
            let handle = NonZeroU64::new(next)?;
            match self.0.compare_exchange_weak(
                next,
                next.wrapping_add(1),
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return Some(handle),
                Err(current) => next = current,
            }
        }
    }
}

/// The active runtime. P7.1 holds no core state; later increments attach their resources here.
struct Runtime {
    handle: NonZeroU64,
}

impl Runtime {
    /// Best-effort destruction, run after the handle is already invalid. Never starts protocol
    /// work, clears fatal state, or creates accounting.
    fn destroy(self) {}
}

/// The native ABI state of one process: the fatal marker, the handle counter, and the one
/// active-runtime slot. Production uses exactly one (`abi::PROCESS`); tests build local ones.
pub(super) struct AbiState {
    pub(super) fatal: FatalState,
    handles: HandleCounter,
    active: Mutex<Option<Runtime>>,
}

impl AbiState {
    pub(super) const fn new() -> Self {
        Self::with_handles(HandleCounter::new())
    }

    pub(super) const fn with_handles(handles: HandleCounter) -> Self {
        Self {
            fatal: FatalState::new(),
            handles,
            active: Mutex::new(None),
        }
    }

    /// Creates the process's one runtime. A fatal process creates nothing; an active runtime is
    /// never replaced; a handle is allocated only once creation is certain to succeed.
    pub(super) fn create(&self) -> Result<NonZeroU64, i32> {
        let Ok(mut active) = self.active.lock() else {
            // Poisoning means a panic was caught while the slot was held.
            self.fatal.mark();
            return Err(SAS_PAIRING_FATAL);
        };
        if self.fatal.is_set() {
            return Err(SAS_PAIRING_FATAL);
        }
        if active.is_some() {
            return Err(SAS_PAIRING_ALREADY_INITIALIZED);
        }
        let handle = self
            .handles
            .allocate()
            .ok_or(SAS_PAIRING_HANDLES_EXHAUSTED)?;
        *active = Some(Runtime { handle });
        Ok(handle)
    }

    /// Destroys the runtime named by `handle`. This is the cleanup path, so fatal state and a
    /// poisoned slot do not prevent it; it never clears fatal state. The handle is removed from
    /// the slot first and the runtime is destroyed after the lock is released.
    pub(super) fn destroy(&self, handle: u64) -> i32 {
        let Some(handle) = NonZeroU64::new(handle) else {
            return SAS_PAIRING_INVALID_HANDLE;
        };
        let removed = {
            let mut active = self.active.lock().unwrap_or_else(PoisonError::into_inner);
            match &*active {
                Some(runtime) if runtime.handle == handle => active.take(),
                _ => None,
            }
        };
        match removed {
            Some(runtime) => {
                runtime.destroy();
                SAS_PAIRING_OK
            }
            None => SAS_PAIRING_INVALID_HANDLE,
        }
    }

    /// Test seam: panic while holding the runtime slot, poisoning it (run inside `contain`).
    #[cfg(test)]
    pub(super) fn panic_while_holding_runtime_slot(&self) -> i32 {
        let _active = self.active.lock();
        panic!("injected panic while the runtime slot is held");
    }
}
