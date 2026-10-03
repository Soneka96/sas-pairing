//! Hosting contexts through the native ABI (P7-D-005).
//!
//! A host handle names one ABI object lifetime: one local routing and hosting context for one
//! registered authority, owning one real core [`Router`] built over that authority's executor.
//! It is not the authority, not its registration, and not its process session: several hosts of
//! one authority share the authority's budget, START limiter, guard, and process session through
//! the core's shared state, and creating or destroying a host changes none of them.
//!
//! The router lives in a `Box`, so its address stays put while the runtime's maps change. That
//! is groundwork for a later owner loop that borrows it; this module creates no longer-lived
//! borrow, raw pointer, or `'static` reference. A host has no listener, socket, connection, or
//! thread yet.

use std::num::NonZeroU64;

#[cfg(test)]
use std::cell::Cell;

use super::{
    authority::enter_core,
    runtime::{AbiState, Admission, Runtime},
    status::{
        SAS_PAIRING_FATAL, SAS_PAIRING_INVALID_HANDLE, SAS_PAIRING_OK,
        SAS_PAIRING_OWNERSHIP_UNCERTAIN,
    },
};
use crate::{
    CeremonyExecutor, Error,
    ceremony::CeremonyError,
    router::{RouteError, Router},
};

/// `sas_pairing_host_t`: an opaque process-local handle; `0` is never valid.
pub(super) type HostHandle = u64;

/// One hosting context: its parent authority and the router it owns.
pub(super) struct HostContext {
    /// The authority handle this host was created under; it names an authority of the same
    /// runtime for as long as this host exists (release and destroy remove the host first).
    pub(super) authority: NonZeroU64,
    /// The real core router. Boxed for a heap-stable address; dropping the context drops it,
    /// and with it every routed run and its executor clone.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "owned for its lifetime only; P7.4 drives it")
    )]
    pub(super) router: Box<Router>,
}

#[cfg(test)]
thread_local! {
    /// `Router::new` calls made by host creation on this thread (tests only), to show that a
    /// fatal or exhausted host creation never builds a router.
    pub(super) static ROUTER_CONSTRUCTIONS: Cell<usize> = const { Cell::new(0) };
    /// Replaces the result of the next real `Router::new` on this thread after it has run
    /// (tests only): the fault returns the substitute error, or panics while the new router is
    /// still alive, so the unwind drops it.
    pub(super) static ROUTER_FAULT: Cell<Option<fn() -> RouteError>> = const { Cell::new(None) };
}

/// Builds one router with the reviewed constructor.
fn construct_router(executor: CeremonyExecutor) -> Result<Router, RouteError> {
    #[cfg(test)]
    ROUTER_CONSTRUCTIONS.with(|count| count.set(count.get() + 1));
    let router = Router::new(executor);
    #[cfg(test)]
    if let Some(fault) = ROUTER_FAULT.take() {
        let substitute = fault();
        drop(router);
        return Err(substitute);
    }
    router
}

/// The narrow translation of a `Router::new` failure. Its one documented failure, router-ID
/// exhaustion, is `OwnershipUncertain`; anything else breaks the constructor's invariant and is
/// treated as fatal, never as an ordinary host-creation failure.
pub(super) fn router_creation_status(error: &RouteError) -> i32 {
    match error {
        RouteError::Ceremony(CeremonyError::Owner(Error::OwnershipUncertain)) => {
            SAS_PAIRING_OWNERSHIP_UNCERTAIN
        }
        _ => SAS_PAIRING_FATAL,
    }
}

impl Runtime {
    /// Removes every host of `authority` from the runtime, then drops them (their routers and
    /// executor clones). Their handles are invalid from the removal on.
    pub(super) fn destroy_hosts_of(&mut self, authority: NonZeroU64) {
        let children: Vec<NonZeroU64> = self
            .hosts
            .iter()
            .filter(|(_, host)| host.authority == authority)
            .map(|(handle, _)| *handle)
            .collect();
        let removed: Vec<HostContext> = children
            .iter()
            .filter_map(|handle| self.hosts.remove(handle))
            .collect();
        drop(removed);
    }
}

impl AbiState {
    /// Creates a host for `authority` under the live runtime `runtime`.
    ///
    /// Order (contract §16.2): fatal state and runtime (through `with_runtime`), the authority,
    /// then the handle is reserved, then the router is built. A constructor failure burns the
    /// reserved value and installs nothing; exhaustion fails before any router exists.
    pub(super) fn create_host(&self, runtime: u64, authority: u64) -> Result<NonZeroU64, i32> {
        self.with_runtime(runtime, Admission::Normal, |live| {
            let authority = NonZeroU64::new(authority).ok_or(SAS_PAIRING_INVALID_HANDLE)?;
            let parent = live
                .authorities
                .get(&authority)
                .ok_or(SAS_PAIRING_INVALID_HANDLE)?;
            let handle = self.allocate_handle()?;
            let router = enter_core(|| construct_router(parent.executor())).map_err(|error| {
                let status = router_creation_status(&error);
                if status == SAS_PAIRING_FATAL {
                    self.fatal.mark();
                }
                status
            })?;
            live.hosts.insert(
                handle,
                HostContext {
                    authority,
                    router: Box::new(router),
                },
            );
            Ok(handle)
        })
    }

    /// Destroys `host`: it leaves the runtime first (invalid forever), then its router drops.
    /// Its authority and sibling hosts are untouched. Admitted in the fatal state, as cleanup.
    pub(super) fn destroy_host(&self, runtime: u64, host: HostHandle) -> i32 {
        let destroyed = self.with_runtime(runtime, Admission::Cleanup, |live| {
            let host = NonZeroU64::new(host).ok_or(SAS_PAIRING_INVALID_HANDLE)?;
            let removed = live.hosts.remove(&host).ok_or(SAS_PAIRING_INVALID_HANDLE)?;
            drop(removed);
            Ok(())
        });
        match destroyed {
            Ok(()) => SAS_PAIRING_OK,
            Err(status) => status,
        }
    }
}
