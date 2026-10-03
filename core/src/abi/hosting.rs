//! Hosting contexts through the native ABI (P7-D-005, P7-D-007).
//!
//! A host handle names one ABI object lifetime: one local routing and hosting context for one
//! registered authority, owning one real core [`Router`] built over that authority's executor.
//! It is not the authority, not its registration, and not its process session: several hosts of
//! one authority share the authority's budget, START limiter, guard, and process session through
//! the core's shared state, and creating or destroying a host changes none of them.
//!
//! The router lives in a `Box`, so its address stays put while the runtime's maps change. Since
//! P7.4 a host may also own one Windows network context: one `WindowsOwnerLoop` over a listener
//! the caller bound, which borrows that boxed router for as long as it exists. This module is the
//! only place that borrow is created, stored, and ended ([`router_for_owner_loop`], the one
//! lifetime extension of the ABI), and the network context is always torn down while the router
//! is alive. Since P7.5 this module also runs the loop's bounded drive, resume recheck, and
//! connection close (P7-D-008), and since P7.6 its trusted local ceremony actions and SAS
//! presentation, one reviewed owner-loop call each (P7-D-011, P7-D-012). It hands back only owned
//! values: no reference to the router, the loop, or the network context leaves it. The host's
//! connection and run references
//! ([`Bindings`], P7-D-009) live beside the network context and end with it.

use std::num::NonZeroU64;

#[cfg(test)]
use std::cell::Cell;
#[cfg(not(windows))]
use std::convert::Infallible;
#[cfg(windows)]
use std::net::TcpListener;
#[cfg(all(test, windows))]
use std::{
    cell::RefCell,
    sync::{Arc, PoisonError, Weak},
};

use super::{
    authority::enter_core,
    runtime::{AbiState, Admission, Runtime},
    status::{SAS_PAIRING_FATAL, SAS_PAIRING_INVALID_HANDLE, SAS_PAIRING_OWNERSHIP_UNCERTAIN},
};
#[cfg(windows)]
use super::{
    control::{Decision, Request},
    network::{Bindings, DriveMode},
};
use crate::{
    CeremonyExecutor, Error,
    ceremony::CeremonyError,
    router::{RouteError, Router},
};
#[cfg(windows)]
use crate::{
    TrustedAuthority,
    ceremony::SasPresentation,
    protocol::Bootstrap,
    router::RunRef,
    windows_owner_loop::{ConnectionRef, OwnerLoopError, OwnerStep, WindowsOwnerLoop},
    windows_tcp::{Acted, Refused},
};

/// `sas_pairing_host_t`: an opaque process-local handle; `0` is never valid.
pub(super) type HostHandle = u64;

/// One owner-loop trusted local action: applied, refused with the connection live, or the
/// loop's own refusal (P7-D-011).
#[cfg(windows)]
pub(super) type ActionOutcome = Result<Result<Acted, Refused>, OwnerLoopError>;
/// One owner-loop presentation (P7-D-012).
#[cfg(windows)]
pub(super) type PresentationOutcome =
    Result<Result<Option<SasPresentation>, RouteError>, OwnerLoopError>;

/// Why closing a host's network context was not clean: the owner loop's own report.
#[cfg(windows)]
pub(super) type CloseError = OwnerLoopError;
/// No network context can exist off Windows, so closing one never fails.
#[cfg(not(windows))]
pub(super) type CloseError = Infallible;

/// One hosting context: its parent authority, its optional network context, and its router.
///
/// Lifetime rule (P7-D-007): `network` borrows the router behind `router`, so it must be gone
/// before the router is dropped. Every teardown path ends it explicitly through
/// [`HostContext::detach_network`] first: detach, host destroy, authority release, runtime
/// destroy, and this type's `Drop`. Declaring `network` before `router` makes the field drop
/// order agree as a second line of defence only.
pub(super) struct HostContext {
    /// The authority handle this host was created under; it names an authority of the same
    /// runtime for as long as this host exists (release and destroy remove the host first).
    pub(super) authority: NonZeroU64,
    /// The Windows owner loop over a caller-bound listener, if one is attached. Private: it is
    /// created only by `attach_network` and ended only by `detach_network`, and no reference to
    /// it or to its router borrow leaves this module (tests aside).
    network: Option<WindowsNetworkContext>,
    /// The ABI connection and run references of the current network context (P7-D-009): empty
    /// whenever `network` is `None`, and cleared before the network context ends on every path,
    /// so no reference from one owner loop survives into a replacement.
    #[cfg(windows)]
    bindings: Bindings,
    /// The real core router. Boxed for a heap-stable address; never reassigned, moved out of its
    /// box, or borrowed mutably, so a network context's borrow stays valid while it exists.
    /// Dropping the context drops it, and with it every routed run and its executor clone.
    #[cfg_attr(
        all(not(test), not(windows)),
        expect(
            dead_code,
            reason = "owned for its lifetime only; no owner loop exists off Windows"
        )
    )]
    router: Box<Router>,
}

impl HostContext {
    fn new(authority: NonZeroU64, router: Router) -> Self {
        Self {
            authority,
            network: None,
            #[cfg(windows)]
            bindings: Bindings::new(),
            router: Box::new(router),
        }
    }

    /// The host's router, borrowed for as long as `self` is (tests only).
    #[cfg(test)]
    pub(super) fn router(&self) -> &Router {
        &self.router
    }

    /// Whether a network context (one owner loop and its listener) is attached.
    #[cfg(windows)]
    pub(super) fn has_network(&self) -> bool {
        self.network.is_some()
    }

    /// Builds the owner loop over `listener` with the reviewed constructor and stores it as
    /// this host's network context. The caller has checked that none is attached. On an error
    /// nothing is stored, and the constructor has already dropped (closed) the listener.
    #[cfg(windows)]
    pub(super) fn attach_network(
        &mut self,
        listener: TcpListener,
        local: Bootstrap,
        expected: Option<Bootstrap>,
    ) -> Result<(), OwnerLoopError> {
        debug_assert!(self.network.is_none(), "one network context per host");
        // SAFETY: `self.router` is this host context's own boxed router, and the extended
        // reference goes only into `self.network` below (directly or inside the owner loop and
        // the connections it will accept). Every invariant listed on `router_for_owner_loop`
        // holds: the box is never replaced or moved out of, the network context never leaves
        // this host context, and every path that drops the host context or its router ends the
        // network context first.
        let router = unsafe { router_for_owner_loop(&self.router) };
        let owner_loop = enter_core(|| construct_owner_loop(listener, router, local, expected))?;
        self.network = Some(WindowsNetworkContext {
            owner_loop,
            #[cfg(test)]
            probe: DropProbe::new(router),
        });
        Ok(())
    }

    /// Ends the network context, if any, while the router is still alive: every connection and
    /// run reference is invalidated first, then the network context leaves `self`, then the
    /// owner loop closes its listener and every connection it owns, then it is dropped. Returns
    /// the loop's own close report. Idempotent; the router is untouched.
    pub(super) fn detach_network(&mut self) -> Result<(), CloseError> {
        #[cfg(windows)]
        self.bindings.clear();
        match self.network.take() {
            Some(network) => network.close(),
            None => Ok(()),
        }
    }

    /// One bounded owner-loop call (`drive_once`, or `recheck_after_resume` for
    /// `DriveMode::Resume`) on the attached loop, entered as core work; `None` without a network
    /// context. The step is returned by value: it holds no reference to the router or the loop.
    #[cfg(windows)]
    pub(super) fn step_network(
        &mut self,
        mode: DriveMode,
    ) -> Option<Result<OwnerStep, OwnerLoopError>> {
        let network = self.network.as_mut()?;
        Some(enter_core(|| {
            #[cfg(test)]
            NETWORK_STEPS.with(|count| count.set(count.get() + 1));
            #[cfg_attr(
                not(test),
                expect(unused_mut, reason = "only the test seam rewrites it")
            )]
            let mut stepped = match mode {
                DriveMode::Drive => network.owner_loop.drive_once(),
                DriveMode::Resume => network.owner_loop.recheck_after_resume(),
            };
            #[cfg(test)]
            if let Some(fault) = DRIVE_FAULT.take() {
                fault(&mut network.owner_loop, &mut stepped);
            }
            stepped
        }))
    }

    /// The owner loop's own close of exactly `connection` (its one teardown, no CANCEL),
    /// entered as core work; `None` without a network context. The caller has already removed
    /// the connection's references from [`Bindings`].
    #[cfg(windows)]
    pub(super) fn close_network_connection(
        &mut self,
        connection: ConnectionRef,
    ) -> Option<Result<(), OwnerLoopError>> {
        let network = self.network.as_mut()?;
        Some(enter_core(|| {
            network.owner_loop.close_connection(connection)
        }))
    }

    /// The connection and run references of the current network context.
    #[cfg(windows)]
    pub(super) fn bindings_mut(&mut self) -> &mut Bindings {
        &mut self.bindings
    }

    /// The connection and run references, read-only.
    #[cfg(windows)]
    pub(super) fn bindings(&self) -> &Bindings {
        &self.bindings
    }

    /// The owner loop's trusted local Initiator start on exactly `connection` (P7-D-011),
    /// entered as core work; `None` without a network context. The outcome is returned by value
    /// and holds no reference to the router or the loop; the started run's START is the
    /// adapter's retained frame, never returned.
    #[cfg(windows)]
    pub(super) fn start_initiator(
        &mut self,
        connection: ConnectionRef,
        local: Bootstrap,
        expected: Option<Bootstrap>,
    ) -> Option<ActionOutcome> {
        let network = self.network.as_mut()?;
        Some(enter_core(|| {
            #[cfg(test)]
            LOCAL_ACTIONS.with(|count| count.set(count.get() + 1));
            #[cfg(test)]
            if let Some(clock) = START_CLOCK.take() {
                let mut started = network.owner_loop.start_initiator_with(
                    connection,
                    clock,
                    &mut crate::request_id::OsRequestIds,
                    local,
                    expected,
                );
                if let Some(fault) = ACTION_FAULT.take() {
                    fault(&mut network.owner_loop, connection, &mut started);
                }
                return started;
            }
            #[cfg_attr(
                not(test),
                expect(unused_mut, reason = "only the test seam rewrites it")
            )]
            let mut started = network
                .owner_loop
                .start_initiator(connection, local, expected);
            #[cfg(test)]
            if let Some(fault) = ACTION_FAULT.take() {
                fault(&mut network.owner_loop, connection, &mut started);
            }
            started
        }))
    }

    /// Exactly one reviewed owner-loop action for `request` on the exact run `run` of
    /// `connection` (P7-D-011), entered as core work; `None` without a network context.
    /// `authority` is the host's own parent authority, used only by exposure authorization and
    /// only for this call. Nothing is chained: one request is one owner-loop call.
    #[cfg(windows)]
    pub(super) fn act_on_run(
        &mut self,
        connection: ConnectionRef,
        run: &RunRef,
        request: Request,
        authority: &TrustedAuthority,
    ) -> Option<ActionOutcome> {
        let network = self.network.as_mut()?;
        Some(enter_core(|| {
            #[cfg(test)]
            LOCAL_ACTIONS.with(|count| count.set(count.get() + 1));
            let owner_loop = &mut network.owner_loop;
            #[cfg_attr(
                not(test),
                expect(unused_mut, reason = "only the test seam rewrites it")
            )]
            let mut acted = match request {
                Request::AuthorizeExposure => {
                    owner_loop.authorize_exposure(connection, run, authority)
                }
                Request::ExposeKey => owner_loop.expose_key(connection, run),
                Request::EmitBootstrapMac => owner_loop.emit_bootstrap_mac(connection, run),
                Request::EmitInitiatorFinish => owner_loop.emit_initiator_finish(connection, run),
                Request::Decide(Decision::Approve, identity) => {
                    owner_loop.approve_sas(connection, run, &identity)
                }
                Request::Decide(Decision::Reject, identity) => {
                    owner_loop.reject_sas(connection, run, &identity)
                }
                Request::Decide(Decision::Cancel, identity) => {
                    owner_loop.cancel_sas(connection, run, &identity)
                }
            };
            #[cfg(test)]
            if let Some(fault) = ACTION_FAULT.take() {
                fault(owner_loop, connection, &mut acted);
            }
            acted
        }))
    }

    /// The owner loop's read-only presentation of the exact run `run` of `connection`
    /// (P7-D-012), entered as core work; `None` without a network context.
    #[cfg(windows)]
    pub(super) fn presentation(
        &mut self,
        connection: ConnectionRef,
        run: &RunRef,
    ) -> Option<PresentationOutcome> {
        let network = self.network.as_mut()?;
        Some(enter_core(|| {
            #[cfg(test)]
            LOCAL_ACTIONS.with(|count| count.set(count.get() + 1));
            #[cfg_attr(
                not(test),
                expect(unused_mut, reason = "only the test seam rewrites it")
            )]
            let mut presented = network.owner_loop.presentation(connection, run);
            #[cfg(test)]
            if let Some(fault) = PRESENTATION_FAULT.take() {
                fault(&mut network.owner_loop, connection, &mut presented);
            }
            presented
        }))
    }

    /// The attached owner loop, for internal tests that drive it without any ABI export.
    #[cfg(all(test, windows))]
    pub(super) fn owner_loop_for_test(&mut self) -> Option<&mut WindowsOwnerLoop<'static>> {
        self.network.as_mut().map(|network| &mut network.owner_loop)
    }
}

impl Drop for HostContext {
    /// The last line of the lifetime rule: whatever path drops a host context, its network
    /// context ends here, before the fields (and so the router) are dropped. Normal teardown
    /// paths have already detached it, so this is then a no-op; a close report is dropped, as
    /// every drop-path cleanup is best effort.
    fn drop(&mut self) {
        let _ = self.detach_network();
    }
}

/// One Windows network context of a host: the owner loop over one already-bound listener and
/// the connections it accepts, all borrowing the host's router.
#[cfg(windows)]
pub(super) struct WindowsNetworkContext {
    /// `'static` is not a claim that the router lives forever: it stands for "as long as the
    /// owning host context's router", which the lifetime rule on [`HostContext`] guarantees.
    owner_loop: WindowsOwnerLoop<'static>,
    /// Test evidence only, declared after `owner_loop` so it drops after the loop and every
    /// connection: it records what it observes then.
    #[cfg(test)]
    #[expect(dead_code, reason = "held only for its Drop")]
    probe: DropProbe,
}

/// No network context exists off Windows.
#[cfg(not(windows))]
pub(super) enum WindowsNetworkContext {}

#[cfg(windows)]
impl WindowsNetworkContext {
    /// Closes the listener and every connection (the loop's one shutdown), then drops it all.
    fn close(mut self) -> Result<(), CloseError> {
        let closed = self.owner_loop.close();
        drop(self);
        closed
    }
}

#[cfg(not(windows))]
impl WindowsNetworkContext {
    fn close(self) -> Result<(), CloseError> {
        match self {}
    }
}

/// Extends the borrow of a host's boxed router to `'static` so the host can store an owner loop
/// that borrows it (P7-D-007). This is the native ABI's one lifetime extension; nothing else
/// stores a borrow of a router.
///
/// # Safety
///
/// The caller must uphold, for as long as the returned reference or anything holding it exists:
///
/// 1. `router` is the router owned by one [`HostContext`]'s `Box<Router>`. A box's heap
///    allocation never moves while the box exists. Host contexts are themselves boxed in the
///    runtime's map, so after construction a host context, and with it the router's box, is
///    never moved or passed by value: map changes, removal, and the cascades move only the
///    outer box pointer, and teardown runs in place.
/// 2. The router's box is never replaced or reassigned, the router is never moved out of it,
///    nothing writes through it, and no `&mut Router` is ever created: the field is private to
///    this module and only read.
/// 3. The returned reference is stored only in that same host context's network context: in its
///    owner loop, and in the connections that loop accepts, which the loop owns and which die
///    with it. The network context never leaves its host context (its field is private, and no
///    method moves it elsewhere).
/// 4. The network context is ended before the router is dropped, on every path: explicit
///    detach, host destroy, the authority-release and runtime-destroy cascades (which remove a
///    host, then detach its network, then drop the router), and `HostContext::drop` as the
///    backstop, which runs before any field is dropped.
/// 5. Neither the reference, nor any reference to the network context or its owner loop, nor
///    any router pointer crosses the ABI or is returned by any function (tests aside).
///
/// Under these rules the referent outlives every use, so the reference is valid whenever it is
/// used, although its type claims more.
#[cfg(windows)]
unsafe fn router_for_owner_loop(router: &Router) -> &'static Router {
    let router: *const Router = router;
    // SAFETY: `router` comes from a live `&Router`, so it is non-null, aligned, and points to an
    // initialized `Router`. The caller's contract above keeps that allocation alive, in place,
    // and free of `&mut` access for as long as the returned reference exists.
    unsafe { &*router }
}

/// Builds one owner loop with the reviewed constructor, exactly as the core expects.
#[cfg(windows)]
fn construct_owner_loop(
    listener: TcpListener,
    router: &'static Router,
    local: Bootstrap,
    expected: Option<Bootstrap>,
) -> Result<WindowsOwnerLoop<'static>, OwnerLoopError> {
    #[cfg(test)]
    OWNER_LOOP_CONSTRUCTIONS.with(|count| count.set(count.get() + 1));
    let owner_loop = WindowsOwnerLoop::from_bound_listener(listener, router, local, expected);
    #[cfg(test)]
    if let Some(fault) = OWNER_LOOP_FAULT.take() {
        let substitute = fault();
        drop(owner_loop);
        return Err(substitute);
    }
    owner_loop
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

/// A test fault applied to one real owner-loop step, with the loop itself (tests only).
#[cfg(all(test, windows))]
pub(super) type DriveFault =
    fn(&mut WindowsOwnerLoop<'static>, &mut Result<OwnerStep, OwnerLoopError>);
/// A test fault applied to one real trusted local action's outcome, with the loop and the
/// connection it named (tests only).
#[cfg(all(test, windows))]
pub(super) type ActionFault = fn(&mut WindowsOwnerLoop<'static>, ConnectionRef, &mut ActionOutcome);
/// A test fault applied to one real presentation's outcome (tests only).
#[cfg(all(test, windows))]
pub(super) type PresentationFault =
    fn(&mut WindowsOwnerLoop<'static>, ConnectionRef, &mut PresentationOutcome);

#[cfg(all(test, windows))]
thread_local! {
    /// `WindowsOwnerLoop::from_bound_listener` calls made on this thread (tests only).
    pub(super) static OWNER_LOOP_CONSTRUCTIONS: Cell<usize> = const { Cell::new(0) };
    /// Replaces the result of the next real owner-loop constructor on this thread after it has
    /// run (tests only): the loop it built (and its listener) is dropped and the substitute
    /// error returned.
    pub(super) static OWNER_LOOP_FAULT: Cell<Option<fn() -> OwnerLoopError>> =
        const { Cell::new(None) };
    /// Owner-loop drive and recheck calls made on this thread (tests only): evidence that a
    /// refused call (buffer, handles, fatal, no listener) did no network work at all.
    pub(super) static NETWORK_STEPS: Cell<usize> = const { Cell::new(0) };
    /// Rewrites the next real owner-loop step on this thread after it ran (tests only), with
    /// the loop itself, so a test can fail the hosting context closed after real events exist.
    pub(super) static DRIVE_FAULT: Cell<Option<DriveFault>> = const { Cell::new(None) };
    /// Owner-loop trusted local actions and presentations made on this thread (tests only):
    /// evidence that a refused call (arguments, fatal, handles, run cap, handle space) never
    /// reached the owner loop.
    pub(super) static LOCAL_ACTIONS: Cell<usize> = const { Cell::new(0) };
    /// Rewrites the next real local action's outcome on this thread after it ran (tests only),
    /// with the loop itself, so a test can end the connection or fail the loop closed after a
    /// real action, or present an outcome the core never produces.
    pub(super) static ACTION_FAULT: Cell<Option<ActionFault>> = const { Cell::new(None) };
    /// As `ACTION_FAULT`, for the next real presentation (tests only).
    pub(super) static PRESENTATION_FAULT: Cell<Option<PresentationFault>> =
        const { Cell::new(None) };
    /// Starts the next local Initiator on this thread with this ceremony clock instead of a
    /// system clock (tests only), through the owner loop's own test entry point, so a test can
    /// move that run past its deadlines.
    pub(super) static START_CLOCK: RefCell<Option<crate::deadline::Clock>> =
        const { RefCell::new(None) };
    /// What each network context dropped on this thread observed once its owner loop and every
    /// connection were gone (tests only): `(other holders of the authority state, live
    /// connections of the authority)`, or `None` if the authority state was already gone.
    pub(super) static NETWORK_DROPS: RefCell<Vec<Option<(usize, usize)>>> =
        const { RefCell::new(Vec::new()) };
}

/// Drop-order evidence (tests only): holds no router reference, only a weak reference to the
/// authority state the router's executor shares, and records, when it drops (after the owner
/// loop), how many holders that state still has (the router's executor is one while the router
/// lives) and how many live connections the authority still counts.
#[cfg(all(test, windows))]
struct DropProbe(Weak<crate::State>);

#[cfg(all(test, windows))]
impl DropProbe {
    fn new(router: &Router) -> Self {
        Self(Arc::downgrade(&router.authority().0))
    }
}

#[cfg(all(test, windows))]
impl Drop for DropProbe {
    fn drop(&mut self) {
        let observed = self.0.upgrade().map(|state| {
            let live = state
                .shared
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .live_connections;
            // Minus the strong reference this upgrade holds.
            (Arc::strong_count(&state) - 1, live)
        });
        NETWORK_DROPS.with(|drops| drops.borrow_mut().push(observed));
    }
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
    /// Removes every host of `authority` from the runtime (their handles are invalid from
    /// here on), then ends each one's network context while its router is still alive, then
    /// drops them (their routers and executor clones).
    pub(super) fn destroy_hosts_of(&mut self, authority: NonZeroU64) {
        let children: Vec<NonZeroU64> = self
            .hosts
            .iter()
            .filter(|(_, host)| host.authority == authority)
            .map(|(handle, _)| *handle)
            .collect();
        let mut removed: Vec<Box<HostContext>> = children
            .iter()
            .filter_map(|handle| self.hosts.remove(handle))
            .collect();
        for host in &mut removed {
            // Best effort, as for every cascade: an uncertain connection cleanup stays recorded
            // in the authority's own state.
            let _ = host.detach_network();
        }
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
            live.hosts
                .insert(handle, Box::new(HostContext::new(authority, router)));
            Ok(handle)
        })
    }

    /// Destroys `host`: it leaves the runtime first (invalid forever), then its network context
    /// (if any) ends while its router is alive, then the router drops. Its authority and sibling
    /// hosts are untouched. Admitted in the fatal state, as cleanup. Returns the network close
    /// report (`OK` without a network); the handle is invalid whatever it says.
    pub(super) fn destroy_host(&self, runtime: u64, host: HostHandle) -> i32 {
        let destroyed = self.with_runtime(runtime, Admission::Cleanup, |live| {
            let host = NonZeroU64::new(host).ok_or(SAS_PAIRING_INVALID_HANDLE)?;
            let mut removed = live.hosts.remove(&host).ok_or(SAS_PAIRING_INVALID_HANDLE)?;
            let closed = removed.detach_network();
            drop(removed);
            Ok(closed)
        });
        match destroyed {
            Ok(closed) => self.network_close_status(closed),
            Err(status) => status,
        }
    }
}
