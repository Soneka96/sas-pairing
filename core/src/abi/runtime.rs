//! Native runtime lifecycle and handles (P7-D-001, P7-D-003, P7-D-005, P7-D-010).
//!
//! At most one runtime is active per OS process, and the runtime is the fatal-containment unit.
//! Handles of every kind (runtimes, authorities, hosts, connections, runs, results) are opaque
//! process-local `u64` values drawn from one monotonic counter: never zero, never reused, never
//! wrapped, and never equal across kinds. Creating a runtime registers no authority, takes no OS
//! lock, starts no listener, and generates no protocol randomness. The runtime owns the
//! authorities registered through it, the hosts created for them (and, through the hosts, their
//! listeners, owner loops, and connection and run references), and every surfaced
//! `PairingResult`. Every operation that issues a handle runs while holding the runtime slot, so
//! it serializes with every other, with release, and with destroy.

use std::{
    collections::BTreeMap,
    num::NonZeroU64,
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
};

use super::{
    hosting::HostContext,
    panic_boundary::FatalState,
    status::{
        SAS_PAIRING_ALREADY_INITIALIZED, SAS_PAIRING_FATAL, SAS_PAIRING_HANDLES_EXHAUSTED,
        SAS_PAIRING_INVALID_HANDLE, SAS_PAIRING_OK,
    },
};
use crate::{TrustedAuthority, ceremony::PairingResult};

/// Issues each handle value at most once per process, across every handle kind. `0` is the
/// exhausted sentinel: after `u64::MAX` has been issued, allocation fails forever instead of
/// wrapping to an old value.
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

    /// Whether `count` more handles can still be issued, without issuing any: the counter's
    /// next value and every value up to `count - 1` above it exist. Non-consuming, so a check
    /// that is followed by fewer (or no) allocations burns nothing.
    #[cfg_attr(
        all(not(windows), not(test)),
        expect(
            dead_code,
            reason = "only a Windows drive issues handles after a preflight"
        )
    )]
    pub(super) fn can_allocate(&self, count: u64) -> bool {
        match self.0.load(Ordering::SeqCst) {
            0 => count == 0,
            next => u64::MAX - next >= count.saturating_sub(1),
        }
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

/// The active runtime: the owning root of the authorities registered through it and of the
/// hosts created for them.
pub(super) struct Runtime {
    handle: NonZeroU64,
    /// The real core authorities, keyed by their opaque handles. The map owns them, so Rust
    /// RAII stays authoritative: removing an entry is the only way to end its ABI lifetime.
    pub(super) authorities: BTreeMap<NonZeroU64, TrustedAuthority>,
    /// The hosting contexts, keyed by their opaque handles; each names its parent authority in
    /// `authorities` and owns its router (P7-D-005) and any network context (P7-D-007). Each is
    /// boxed, so a host context never moves once created: map changes and removal move only
    /// the outer box, never the router box an owner loop borrows through.
    pub(super) hosts: BTreeMap<NonZeroU64, Box<HostContext>>,
    /// Every `PairingResult` a drive surfaced, keyed by its opaque result handle (P7-D-010).
    /// Owned here, at the runtime, and not under a host or connection, so a surfaced local
    /// completion outlives its connection, listener, host, and authority; only result destroy
    /// and runtime destroy end it. Each entry is immutable once inserted.
    pub(super) results: BTreeMap<NonZeroU64, PairingResult>,
}

impl Runtime {
    /// Best-effort destruction, run after the runtime handle (and with it every child handle)
    /// is already invalid. First every host's network context (its owner loop, listener, and
    /// connections) ends while its router is still alive (P7-D-007). Then the hosts drop: their
    /// routers hold executor clones of the authorities, so every router must be gone before
    /// authority ownership ends. Then every owned authority drops, which releases its OS lease
    /// through the core's own `Drop` (an uncertain release is recorded by the core and fails
    /// that authority's registration closed). Never starts protocol work, clears fatal state, or
    /// creates accounting. The surfaced results (plain immutable data) are dropped last.
    fn destroy(self) {
        let Self {
            handle: _,
            authorities,
            mut hosts,
            results,
        } = self;
        for host in hosts.values_mut() {
            let _ = host.detach_network();
        }
        drop(hosts);
        drop(authorities);
        drop(results);
    }
}

/// How an operation on a live runtime is admitted.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Admission {
    /// A normal operation that may enter the core: refused with `FATAL` once the process is
    /// fatal, and a poisoned runtime slot makes the process fatal.
    Normal,
    /// Cleanup (authority release, host destroy, listener detach, connection close): admitted
    /// in the fatal state and on a poisoned slot, like runtime destroy. It never clears fatal
    /// state.
    Cleanup,
    /// Reading or destroying ABI-owned result data that already exists (P7-D-010): admitted in
    /// the fatal state and on a poisoned slot like cleanup, but a separate path because it never
    /// enters the core at all. It creates no result, resumes no run, changes no accounting, and
    /// never clears fatal state.
    Data,
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
        let handle = self.allocate_handle()?;
        *active = Some(Runtime {
            handle,
            authorities: BTreeMap::new(),
            hosts: BTreeMap::new(),
            results: BTreeMap::new(),
        });
        Ok(handle)
    }

    /// Issues the next opaque handle from the one shared counter.
    pub(super) fn allocate_handle(&self) -> Result<NonZeroU64, i32> {
        self.handles.allocate().ok_or(SAS_PAIRING_HANDLES_EXHAUSTED)
    }

    /// Whether `count` more handles can be issued, issuing none (the drive preflight,
    /// P7-D-008). The answer stays true until the caller has allocated them as long as the
    /// caller holds the runtime slot: every handle allocation (runtime create, authority
    /// register, host create, and drive conversion) happens under that one mutex.
    #[cfg_attr(
        not(windows),
        expect(
            dead_code,
            reason = "only a Windows drive issues handles after a preflight"
        )
    )]
    pub(super) fn can_allocate_handles(&self, count: u64) -> bool {
        self.handles.can_allocate(count)
    }

    /// Runs `op` on the live runtime named `runtime` while holding the runtime slot, so the
    /// operation completes before any destroy can begin and nothing is admitted after one.
    ///
    /// Order (contract §15.7): fatal state (normal operations only), then the runtime handle; the
    /// caller has already validated its raw arguments.
    pub(super) fn with_runtime<T>(
        &self,
        runtime: u64,
        admission: Admission,
        op: impl FnOnce(&mut Runtime) -> Result<T, i32>,
    ) -> Result<T, i32> {
        let normal = admission == Admission::Normal;
        if normal && self.fatal.is_set() {
            return Err(SAS_PAIRING_FATAL);
        }
        let mut active = match self.active.lock() {
            Ok(active) => active,
            // Poisoning means a panic was caught while the slot was held.
            Err(_) if normal => {
                self.fatal.mark();
                return Err(SAS_PAIRING_FATAL);
            }
            Err(poisoned) => poisoned.into_inner(),
        };
        // Recheck under the slot: a panic caught elsewhere since the first check wins.
        if normal && self.fatal.is_set() {
            return Err(SAS_PAIRING_FATAL);
        }
        match active.as_mut() {
            Some(live) if live.handle.get() == runtime => op(live),
            _ => Err(SAS_PAIRING_INVALID_HANDLE),
        }
    }

    /// Destroys the runtime named by `handle`, cascading to every host and authority it owns.
    /// This is the cleanup path, so fatal state and a poisoned slot do not prevent it; it never
    /// clears fatal state. The runtime leaves the slot first, so its handle and every child
    /// authority and host handle are invalid before cleanup starts; cleanup finishes before the slot is released,
    /// so no operation can observe a half-destroyed runtime.
    pub(super) fn destroy(&self, handle: u64) -> i32 {
        let Some(handle) = NonZeroU64::new(handle) else {
            return SAS_PAIRING_INVALID_HANDLE;
        };
        let mut active = self.active.lock().unwrap_or_else(PoisonError::into_inner);
        let removed = match &*active {
            Some(runtime) if runtime.handle == handle => active.take(),
            _ => None,
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
