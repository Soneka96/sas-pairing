//! The one panic-containment primitive of the native ABI (P6-D-004, P7-D-001).
//!
//! Every export reaches Rust work only through [`contain`] (via `abi::dispatch`), so no Rust
//! panic or unwind crosses `extern "C"`. A caught panic marks the fatal state first, then the
//! payload is leaked unseen, then the caller's stable fallback is returned.

use std::{
    mem,
    panic::{self, AssertUnwindSafe},
    sync::atomic::{AtomicBool, Ordering},
};

/// Process-lifetime fatal marker. It can only be set: there is no clear or reset path, and a
/// fresh state exists only in a new OS process (or a test-local instance).
pub(super) struct FatalState(AtomicBool);

impl FatalState {
    pub(super) const fn new() -> Self {
        Self(AtomicBool::new(false))
    }

    /// Records a caught panic. A single atomic store: allocation-free, lock-free, and unable to
    /// panic, so it never depends on a mutex the panic may have poisoned.
    pub(super) fn mark(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub(super) fn is_set(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// Runs `op`, containing any unwinding panic.
///
/// On `Err(payload)`: mark `fatal`, then suppress the payload's destructor (P6.4.1: dropping it
/// could panic again outside this boundary and abort the host), then return `fallback`. The
/// payload is never downcast, formatted, inspected, or returned; the leak is bounded by the number
/// of fatal events and reclaimed at process exit. `T: Copy` keeps the fallback destructor-free.
///
/// `AssertUnwindSafe` is sound here because a caught panic makes the whole ABI state fatal: no
/// normal operation runs on possibly half-updated state again, and destroy only removes entries.
pub(super) fn contain<T: Copy>(fatal: &FatalState, fallback: T, op: impl FnOnce() -> T) -> T {
    match panic::catch_unwind(AssertUnwindSafe(op)) {
        Ok(value) => value,
        Err(payload) => {
            fatal.mark();
            mem::forget(payload);
            fallback
        }
    }
}
