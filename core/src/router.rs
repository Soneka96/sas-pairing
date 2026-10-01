//! Crate-private P3 §4/§10/§11.2 pre-establishment routing: protocol state is located by the
//! local session context together with the request ID, never by the request ID alone.
//!
//! A `Router` belongs to one pairing authority (it holds that authority's executor) and owns
//! every run routed through it. It issues opaque, volatile `SessionHandle`s for a future
//! transport adapter's local connection/session contexts; nothing received over the wire can
//! create or select one. The routing key is `(SessionHandle, request_id)`: the same request ID
//! on two sessions names two independent runs, and a message is only ever delivered to the run
//! under its own session and its own exact request ID. The router decides only WHERE bytes go
//! and classifies START as new, exact duplicate, or conflict; `RemoteCeremony` still decides
//! whether a message is legal and authentic. After establishment `ceremony_identity` stays
//! the security identity; the routing key is never authentication, trust, or authority, and
//! is never part of any transcript, MAC, wire frame, or `PairingResult`.
//!
//! Session lifecycle: OPEN -> CLOSING -> CLOSED. Every operation on a session enters it with a
//! `Lease` while it is OPEN, in a table critical section. The OPEN -> CLOSING transition
//! (`begin_close`) happens in a table critical section too, so it is one linearization point:
//! an operation either entered before it or is refused with `UnknownSession`. Teardown then
//! waits, holding nothing but the session's lifecycle mutex (which the wait releases), until
//! every lease is gone. An operation that entered earlier finishes its current step, except
//! that route creation (Responder admission, routed Initiator) never installs into a CLOSING
//! session: it discards its new run, so its permit, pending slot, or request-ID reservation is
//! released before its lease is. Only then are the session's routes detached and its runs
//! terminated; CLOSED is reached only if that cleanup is certain.
//!
//! Idle deadline driving: `poll_session_deadlines` lets the one owner of a session drive the
//! existing `RemoteCeremony::poll_deadlines` across that session's runs, with no scheduler. Each
//! call inspects at most `MAX_CEREMONY_POLLS_PER_CALL` routes, found one at a time by a seek in
//! the ordered route map (no scan, no index, no allocation proportional to the route count),
//! from a caller-held `DeadlineCursor` that advances in request-ID order and wraps, so every
//! continuously live run is reached. A claim still being admitted and a run whose lock is busy
//! are skipped as inspected work, never waited for. The call stops at the first terminal
//! deadline outcome, so it returns at most one.
//!
//! Lock order: run mutex -> table mutex -> lifecycle mutex. The lifecycle mutex is a leaf, so a
//! lease may be dropped anywhere. Authority shared state is taken by ceremony work under a run
//! mutex (or with none held) and never while a router lock is acquired after it. Teardown waits
//! only on the lifecycle condition variable and only with no run, table, or shared lock held.
//! An operation must not re-enter the router (for example, close its own session from inside a
//! `with_run` closure): its own lease would then never drain.
//!
//! No socket, listener, byte transport, frame buffering, reconnect, or resume exists here.
#![allow(dead_code)] // Used only by tests until a transport adapter exists.
#[cfg(test)]
use crate::test_hook::{self, Point};
use crate::{
    CeremonyExecutor, Error as OwnerError, Role,
    ceremony::{
        CeremonyError, CompletionReceipt, DeadlineOutcome, PairingResult, PeerApproval,
        PeerCancellation, RemoteCeremony, Timeout,
    },
    deadline::{Clock, system_clock},
    protocol::{self, Bootstrap},
    request_id::{OsRequestIds, RequestIdGenerator},
};
use std::{
    collections::{BTreeMap, HashMap, btree_map::Entry},
    ops::Bound,
    sync::{
        Arc, Condvar, Mutex, MutexGuard, PoisonError, TryLockError,
        atomic::{AtomicU64, Ordering},
    },
};

static NEXT_ROUTER: AtomicU64 = AtomicU64::new(1);

/// Hard per-call work bound of `poll_session_deadlines`: route candidates inspected (polled,
/// busy, or still being admitted). An implementation work cap only: not a P3 limit, a ceremony
/// count cap, or a security parameter, and unrelated to the pending (4) and connection (16) caps.
pub(crate) const MAX_CEREMONY_POLLS_PER_CALL: usize = 8;

/// One live local session context of one `Router`: "this locally distinct transport/session
/// context" and nothing more. It is not peer identity, authentication, possession, trust,
/// authorization, or ceremony identity, and it never appears on the wire or in any
/// cryptographic input. Only `Router::open_session` creates one. It names its router, so a
/// handle from another router is unknown here, and session numbers are never reissued, so a
/// closed handle stays invalid. Volatile: never persisted or resumed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct SessionHandle {
    router: u64,
    session: u64,
}

/// Ordered by session, then request-ID bytes, so one session's routes are contiguous in the
/// route map. The order is local scheduling plumbing for deadline driving, never protocol data.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct RoutingKey {
    session: SessionHandle,
    /// Canonical peer-controlled or locally generated opaque bytes (1..=64).
    request_id: Vec<u8>,
}

/// A routed run. Only the router holds it; dispatch clones the `Arc` just long enough to take
/// the run's own lock, so the run has exactly one owner and one mutation path at a time.
type Run = Arc<Mutex<RemoteCeremony>>;

enum Route {
    /// A new START owns this key while it is admitted outside the table lock. It keeps the
    /// exact START bytes so a concurrent copy is a duplicate and a changed START a conflict.
    Admitting {
        claim: u64,
        start: Vec<u8>,
        conflicted: bool,
    },
    Active(Run),
}

/// One session's lifecycle. OPEN: in the table, not closing. CLOSING: in the table, closing;
/// nothing new may enter, and teardown waits for `in_flight` to reach zero. CLOSED: removed
/// from the table; the handle is never reissued, so it stays invalid forever.
#[derive(Default)]
struct Lifecycle {
    activity: Mutex<Activity>,
    settled: Condvar,
}

#[derive(Default)]
struct Activity {
    closing: bool,
    /// Operations that entered while OPEN and have not yet released their lease.
    in_flight: usize,
    /// How the teardown that won `begin_close` ended; `None` before it ends. Read only by
    /// `close_session_settled` callers waiting on another caller's teardown.
    ended: Option<Ended>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ended {
    /// CLOSED: every run terminated and every resource released.
    Closed,
    /// Cleanup could not be established: CLOSING forever.
    Uncertain,
}

/// One operation's membership in an OPEN session. Locals an operation creates after taking
/// its lease (a new run with its permit, pending slot, or request-ID reservation) are dropped
/// before it, so a waiting teardown resumes only after they were released.
struct Lease(Arc<Lifecycle>);

impl Lease {
    /// Whether the session began closing since this operation entered. Called by route
    /// creation inside the table critical section that would install its route.
    fn closing(&self) -> Result<bool, RouteError> {
        Ok(activity(&self.0)?.closing)
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        // Counted even if poisoned, so a waiting teardown wakes and reports the poison as
        // `OwnershipUncertain` instead of hanging.
        let mut activity = self
            .0
            .activity
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        activity.in_flight -= 1;
        if activity.closing && activity.in_flight == 0 {
            self.0.settled.notify_all();
        }
    }
}

struct Table {
    next_session: u64,
    next_claim: u64,
    /// OPEN and CLOSING sessions; a CLOSED session is absent.
    sessions: HashMap<u64, Arc<Lifecycle>>,
    /// Ordered so the deadline driver finds a session's next route by one seek, with no
    /// auxiliary index that could go stale.
    routes: BTreeMap<RoutingKey, Route>,
}

/// Session-bound routing for one pairing authority. Its resource controls (START limiter,
/// pending and preliminary caps, guard, opportunity budget) stay in the authority's shared
/// state, so sessions, and even several routers of one authority, share them. Every method
/// borrows the router, so it cannot be dropped while any operation (or lease) is live; dropping
/// it drops every routed run, whose own cleanup releases its slot, reservation, or guard.
pub(crate) struct Router {
    id: u64,
    executor: CeremonyExecutor,
    table: Mutex<Table>,
}

/// Narrow local routing outcomes. None of them says anything about the peer, its
/// authentication, an SAS, compromise, or the opportunity budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RouteError {
    /// The handle names no OPEN session of this router: never issued here, closing, or closed.
    /// Nothing was changed.
    UnknownSession,
    /// A local action (`with_run`) or a START given to `deliver` (which never admits) names no
    /// run under this exact `(session, request_id)`; nothing was changed.
    UnknownRoute,
    /// P3 §11.2/§11.4 session-fatal routing failure: a structurally routable non-START frame
    /// named no route on its live session. It reached no run, and when this is returned the
    /// session was already torn down exactly as by `close_session`. A local session failure,
    /// not authentication evidence, compromise, SAS mismatch, or opportunity exhaustion.
    SessionProtocolFailure,
    /// The codec rejected the input before routing, admission refused it, or the routed run
    /// returned this outcome (and applied its own terminal rules).
    Ceremony(CeremonyError),
}

impl From<CeremonyError> for RouteError {
    fn from(e: CeremonyError) -> Self {
        Self::Ceremony(e)
    }
}
impl From<protocol::CodecError> for RouteError {
    fn from(e: protocol::CodecError) -> Self {
        Self::Ceremony(e.into())
    }
}

fn uncertain() -> RouteError {
    RouteError::Ceremony(CeremonyError::Owner(OwnerError::OwnershipUncertain))
}

/// START routing outcome for a live session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StartRouting {
    /// A new routing key: the Responder run was admitted and installed. Send this ACCEPT.
    Accepted(Vec<u8>),
    /// An exact duplicate of the START that owns this key (installed or still being admitted):
    /// ignored with no admission, limiter charge, permit, slot, key generation, deadline
    /// change, or output.
    Duplicate,
}

/// The routed run's outcome for one inbound frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Inbound {
    StartDuplicate,
    Accept,
    InitiatorKey,
    ResponderKey,
    BootstrapMac(PeerApproval),
    Completion(CompletionReceipt),
    Cancel(PeerCancellation),
}

/// One operation on a routed run. `result` is the immutable `PairingResult`, present exactly
/// when this operation reached local success; the route was then already removed.
#[derive(Debug)]
pub(crate) struct Routed<T> {
    pub(crate) output: T,
    pub(crate) result: Option<PairingResult>,
}

/// One session's deadline-driver position: the request ID most recently inspected (`None`
/// before the first). Local scheduling plumbing owned by the session's one driver: not peer
/// data, authentication, or identity, never persisted, hashed, or sent. The key it names may
/// since have been removed or reused; it is only a position in request-ID order.
#[derive(Debug, Default)]
pub(crate) struct DeadlineCursor {
    after: Option<Vec<u8>>,
}

/// How a polled run ended by deadline processing. The run is ALREADY terminal and its route
/// removed; none of these is a result, peer evidence, or an opportunity outcome.
#[derive(Debug)]
pub(crate) enum DeadlineEnded {
    /// P3 §11.3 local timeout, with the authenticated CANCEL bytes when a shared SAS existed.
    TimedOut(Timeout),
    /// The fixed pending pre-exposure resource lifetime ended; nothing to send.
    PendingExpired,
    /// The run's ceremony clock was unusable; it failed closed with no timeout claim.
    ClockUnavailable,
}

/// One terminal deadline outcome and the routing key of its run (diagnostic only).
#[derive(Debug)]
pub(crate) struct DeadlineEvent {
    pub(crate) request_id: Vec<u8>,
    pub(crate) ended: DeadlineEnded,
}

/// One bounded `poll_session_deadlines` call: `inspected <= MAX_CEREMONY_POLLS_PER_CALL`
/// candidates and at most one terminal deadline outcome.
#[derive(Debug, Default)]
pub(crate) struct DeadlinePoll {
    pub(crate) inspected: usize,
    pub(crate) event: Option<DeadlineEvent>,
    /// Request IDs this call inspected, in order, and how (tests only; bounded by the cap).
    #[cfg(test)]
    pub(crate) trace: Vec<(Vec<u8>, Inspected)>,
    /// Route-map seeks this call made (tests only).
    #[cfg(test)]
    pub(crate) seeks: usize,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Inspected {
    Admitting,
    Busy,
    Polled,
}

/// One deadline-driver selection step.
enum Next {
    /// The session began closing: nothing more enters.
    Closing,
    /// No route of the session after the position.
    End,
    /// The next route: its exact run, or `None` for a START claim still being admitted.
    Route(RoutingKey, Option<Run>),
}

/// One inspected run's deadline poll.
enum Polled {
    /// Another operation holds the run; it was not touched.
    Busy,
    /// Live and unexpired (or already finished): nothing to report.
    Live,
    Ended(DeadlineEnded),
}

/// What a new START needs beyond its bytes: the Responder's local configuration.
struct NewResponder {
    clock: Clock,
    local: Bootstrap,
    expected: Option<Bootstrap>,
}

enum StartRoute {
    New(Lease, u64),
    Duplicate,
    Existing(Lease, Run),
}

/// Where an inbound non-START frame goes.
enum Dispatch {
    Run(Lease, Run),
    /// No route under its key: the session is already CLOSING and must be torn down.
    Unrouted(Arc<Lifecycle>),
}

impl Router {
    pub(crate) fn new(executor: CeremonyExecutor) -> Result<Self, RouteError> {
        let id = NEXT_ROUTER
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| uncertain())?;
        Ok(Self {
            id,
            executor,
            table: Mutex::new(Table {
                next_session: 1,
                next_claim: 1,
                sessions: HashMap::new(),
                routes: BTreeMap::new(),
            }),
        })
    }

    /// Issues a fresh local session handle. This is local lifecycle state for a future
    /// transport adapter, not socket creation.
    pub(crate) fn open_session(&self) -> Result<SessionHandle, RouteError> {
        let mut table = self.table()?;
        let session = table.next_session;
        // Never reissued: exhaustion fails closed rather than wrapping onto an old handle.
        table.next_session = session.checked_add(1).ok_or_else(uncertain)?;
        table.sessions.insert(session, Arc::default());
        Ok(SessionHandle {
            router: self.id,
            session,
        })
    }

    /// Ends a local session without waiting for or notifying the peer. Atomically the session
    /// becomes CLOSING, so no new operation can enter it; this call then waits until every
    /// operation that entered earlier has returned. In-progress route creation (a START being
    /// admitted, a routed Initiator being built) never installs into a CLOSING session and
    /// returns no ACCEPT or START: its run, with its permit, pending slot, or request-ID
    /// reservation, is dropped first. An already-entered operation on an installed run finishes
    /// its current step under the run's lock and keeps its outcome. Every route under the
    /// session is then removed and each run terminated through its existing cleanup: SAS,
    /// approval, and any pending final ACK are dropped before the guard is released; pending
    /// slots and request-ID reservations are released; consumed opportunities stay consumed;
    /// no result is created and no CANCEL is emitted. Nothing resumes on another session, and
    /// the keys can never be reused because the handle is never reissued. START limiter
    /// charges are not refunded and no authority control is reset.
    ///
    /// `Ok(())` means all of that is complete: nothing of this session remains or can still
    /// produce output. A CLOSING or CLOSED handle is `UnknownSession`. If cleanup cannot be
    /// established (poisoned state, uncertain guard release), the error is returned and the
    /// session stays CLOSING forever, never reopened.
    pub(crate) fn close_session(&self, session: SessionHandle) -> Result<(), RouteError> {
        let lifecycle = self.begin_close(&*self.table()?, session)?;
        self.finish_close(session, &lifecycle)
    }

    /// `close_session` for the one owner of `session`'s transport connection, which must learn
    /// whether the session is safely CLOSED however its teardown began, before it releases
    /// transport capacity. An OPEN session is closed exactly as by `close_session`. A session
    /// already CLOSING (another caller's teardown, such as `deliver`'s session-fatal routing
    /// failure) is waited for, holding no router lock, until that teardown ends; its outcome is
    /// returned. An already CLOSED session is `Ok(())`. Uncertain cleanup, here or in the other
    /// teardown, is `OwnershipUncertain`. A handle this router never issued is `UnknownSession`.
    pub(crate) fn close_session_settled(&self, session: SessionHandle) -> Result<(), RouteError> {
        let (lifecycle, won) = {
            let table = self.table()?;
            if session.router != self.id || !(1..table.next_session).contains(&session.session) {
                return Err(RouteError::UnknownSession);
            }
            let Some(lifecycle) = table.sessions.get(&session.session) else {
                return Ok(());
            };
            let mut activity = activity(lifecycle)?;
            let won = !activity.closing;
            activity.closing = true;
            drop(activity);
            (lifecycle.clone(), won)
        };
        if won {
            return self.finish_close(session, &lifecycle);
        }
        let mut activity = activity(&lifecycle)?;
        loop {
            match activity.ended {
                Some(Ended::Closed) => return Ok(()),
                Some(Ended::Uncertain) => return Err(uncertain()),
                None => activity = lifecycle.settled.wait(activity).map_err(|_| uncertain())?,
            }
        }
    }

    /// The pairing authority this router belongs to.
    pub(crate) fn authority(&self) -> &CeremonyExecutor {
        &self.executor
    }

    /// OPEN and CLOSING sessions (tests only; read-only).
    #[cfg(test)]
    pub(crate) fn sessions_for_test(&self) -> usize {
        self.table.lock().unwrap().sessions.len()
    }

    /// Admitting and installed routes over every session (tests only; read-only).
    #[cfg(test)]
    pub(crate) fn routes_for_test(&self) -> usize {
        self.table.lock().unwrap().routes.len()
    }

    /// The installed run under exactly `(session, request_id)` (tests only).
    #[cfg(test)]
    pub(crate) fn run_for_test(
        &self,
        session: SessionHandle,
        request_id: &[u8],
    ) -> Arc<Mutex<RemoteCeremony>> {
        let key = RoutingKey {
            session,
            request_id: request_id.to_vec(),
        };
        match self.table.lock().unwrap().routes.get(&key) {
            Some(Route::Active(run)) => run.clone(),
            _ => panic!("no installed run under that key"),
        }
    }

    /// Inbound START on `session`. An exact duplicate or conflict for an existing key goes to
    /// that run (see `StartRouting`); a changed START for an existing key terminally fails it
    /// and is never a new candidate. Only a key that is absent is claimed atomically and then
    /// admitted, outside the table lock, through the unchanged Responder order: START limiter
    /// -> preliminary permit -> semantic validation -> pending slot -> ephemeral and commitment
    /// -> ACCEPT. The run is installed only after that succeeds and only if the session is
    /// still OPEN; any failure removes the claim.
    pub(crate) fn receive_start(
        &self,
        session: SessionHandle,
        bytes: &[u8],
        local: Bootstrap,
        expected: Option<Bootstrap>,
    ) -> Result<StartRouting, RouteError> {
        self.receive_start_with_clock(system_clock(), session, bytes, local, expected)
    }

    /// `receive_start` with the injected ceremony clock a new run would use.
    pub(crate) fn receive_start_with_clock(
        &self,
        clock: Clock,
        session: SessionHandle,
        bytes: &[u8],
        local: Bootstrap,
        expected: Option<Bootstrap>,
    ) -> Result<StartRouting, RouteError> {
        let new = NewResponder {
            clock,
            local,
            expected,
        };
        self.route_start(session, bytes, Some(new))
    }

    /// Delivers one inbound frame to the run routed under `session` and the frame's own request
    /// ID, mapping its wire type to that run's existing entrypoint, which validates type, role,
    /// sequencing, duplicates, and authentication. Never a lookup by request ID alone, and
    /// never a fallback to another run. A START here reaches only an existing run (only
    /// `receive_start` admits); with no route it is `UnknownRoute` with no effect.
    ///
    /// A structurally routable non-START frame (it passed `route_fields`: complete canonical
    /// frame, defined type, exact profile ID, 1..=64-byte request ID) with no route under its
    /// key on this live session is P3's session-fatal routing failure: the frame reaches no
    /// run, the session is torn down exactly as by `close_session` (every run on it, however
    /// many, becomes terminal; other sessions are untouched), and `SessionProtocolFailure` is
    /// returned once that is complete. A non-START frame for a key whose START is still being
    /// admitted is out of order for that key only: the admission is discarded.
    pub(crate) fn deliver(
        &self,
        session: SessionHandle,
        bytes: &[u8],
    ) -> Result<Routed<Inbound>, RouteError> {
        let (kind, request_id) = protocol::route_fields(bytes)?;
        if kind == 1 {
            self.route_start(session, bytes, None)?;
            return Ok(Routed {
                output: Inbound::StartDuplicate,
                result: None,
            });
        }
        let key = RoutingKey {
            session,
            request_id: request_id.to_vec(),
        };
        let (_lease, run) = match self.dispatch(&key)? {
            Dispatch::Run(lease, run) => (lease, run),
            Dispatch::Unrouted(lifecycle) => {
                self.finish_close(session, &lifecycle)?;
                return Err(RouteError::SessionProtocolFailure);
            }
        };
        self.on_run(&key, &run, |run| {
            Ok(match kind {
                2 => run.receive_accept(bytes).map(|()| Inbound::Accept)?,
                3 => run
                    .receive_initiator_key(bytes)
                    .map(|()| Inbound::InitiatorKey)?,
                4 => run
                    .receive_responder_key(bytes)
                    .map(|()| Inbound::ResponderKey)?,
                5 => Inbound::BootstrapMac(run.receive_bootstrap_mac(bytes)?),
                6..=8 => Inbound::Completion(run.receive_completion(bytes)?),
                _ => Inbound::Cancel(run.receive_cancel(bytes)?),
            })
        })
    }

    /// A local action (authorization, SAS decision, own MAC or finish emission, send
    /// confirmation, deadline poll, ...) on the run routed under exactly `(session,
    /// request_id)`. Inbound frames must use `deliver`/`receive_start`, which take the request
    /// ID from the frame itself. A local action naming no run is `UnknownRoute`, not a session
    /// failure: it is not peer input. `op` must not call back into the router.
    pub(crate) fn with_run<T>(
        &self,
        session: SessionHandle,
        request_id: &[u8],
        op: impl FnOnce(&mut RemoteCeremony) -> Result<T, CeremonyError>,
    ) -> Result<Routed<T>, RouteError> {
        let key = RoutingKey {
            session,
            request_id: request_id.to_vec(),
        };
        let (_lease, run) = self.active(&key)?;
        self.on_run(&key, &run, op)
    }

    /// Honest local Initiator on `session`: the core generates and reserves the 16-byte request
    /// ID exactly as `RemoteCeremony::initiator` does, then the run is registered under
    /// `(session, request_id)` before its START bytes are returned. If that key is already
    /// routed on this session (a peer-chosen START ID), the run is discarded, its reservation
    /// released, and a fresh ID generated, so colliding local state never reaches the wire. If
    /// the session began closing meanwhile, the run is discarded (releasing its reservation)
    /// and `UnknownSession` is returned instead of START. Returns `(request_id, START bytes)`.
    pub(crate) fn start_initiator(
        &self,
        session: SessionHandle,
        local: Bootstrap,
        expected: Option<Bootstrap>,
    ) -> Result<(Vec<u8>, Vec<u8>), RouteError> {
        self.start_initiator_with(system_clock(), &mut OsRequestIds, session, local, expected)
    }

    /// `start_initiator` with an injected ceremony clock and request-ID source.
    pub(crate) fn start_initiator_with(
        &self,
        clock: Clock,
        ids: &mut dyn RequestIdGenerator,
        session: SessionHandle,
        local: Bootstrap,
        expected: Option<Bootstrap>,
    ) -> Result<(Vec<u8>, Vec<u8>), RouteError> {
        let lease = self.enter(&*self.table()?, session)?;
        loop {
            // Declared after `lease`, so every early return drops the run (and its
            // reservation) before the lease.
            let admission = self
                .executor
                .begin(Role::Initiator)
                .map_err(CeremonyError::from)?;
            let mut run = RemoteCeremony::initiator_with(
                clock.clone(),
                &mut *ids,
                self.executor.clone(),
                admission,
                local.clone(),
                expected.clone(),
            )?;
            let start = run.start()?;
            let request_id = protocol::route_fields(&start)?.1.to_vec();
            #[cfg(test)]
            test_hook::fire(Point::InitiatorStarted);
            let mut run = Some(run);
            let mut guard = self.table()?;
            let table = &mut *guard;
            let closing = lease.closing()?;
            if !closing {
                let key = RoutingKey {
                    session,
                    request_id: request_id.clone(),
                };
                if let Entry::Vacant(slot) = table.routes.entry(key) {
                    let run = run.take().expect("run not yet installed");
                    slot.insert(Route::Active(Arc::new(Mutex::new(run))));
                }
            }
            drop(guard);
            match run {
                None => return Ok((request_id, start)),
                // Dropping the uninstalled run releases its request-ID reservation.
                Some(run) if !closing => drop(run),
                Some(run) => {
                    drop(run);
                    return Err(RouteError::UnknownSession);
                }
            }
        }
    }

    /// Bounded, cooperative idle deadline driving for `session`, for its one owner (the host
    /// connection), with no scheduler, thread, or timer. Each Active run reached gets exactly the
    /// existing `RemoteCeremony::poll_deadlines`, which alone decides expiry (absolute,
    /// inactivity and its suspension, the fixed pending lifetime, timeout CANCEL, cleanup);
    /// polling is not progress and refreshes nothing. Routes are visited after `cursor` in
    /// request-ID order, wrapping at most once per call and never past where the call began, so
    /// one call inspects each route at most once and at most `MAX_CEREMONY_POLLS_PER_CALL` in
    /// all. A START claim still being admitted and a run whose lock another operation holds count
    /// as inspected and are skipped without waiting; that run's next state-advancing operation
    /// enforces its own deadlines. The call stops at the first run that ends (timeout, pending
    /// expiry, or unusable clock), whose route is removed only if it still names that exact run;
    /// the session and its other runs stay live. Only routes of `session` are visited.
    ///
    /// The call holds one lease: a CLOSING or CLOSED session is `UnknownSession`, and once the
    /// session begins closing the call finishes only its current run and returns. A poisoned run
    /// lock, uncertain cleanup, or any other run failure is `OwnershipUncertain`, never run-local.
    pub(crate) fn poll_session_deadlines(
        &self,
        session: SessionHandle,
        cursor: &mut DeadlineCursor,
    ) -> Result<DeadlinePoll, RouteError> {
        let lease = self.enter(&*self.table()?, session)?;
        let mut poll = DeadlinePoll::default();
        let start = cursor.after.clone();
        let mut wrapped = false;
        while poll.inspected < MAX_CEREMONY_POLLS_PER_CALL {
            let next = self.next_route(&lease, session, cursor.after.as_deref())?;
            #[cfg(test)]
            {
                poll.seeks += 1;
            }
            let (key, run) = match next {
                Next::Closing => break,
                // Every route of the session was reached by this call.
                Next::End if wrapped || start.is_none() => break,
                Next::End => {
                    cursor.after = None;
                    wrapped = true;
                    continue;
                }
                Next::Route(key, _)
                    if wrapped
                        && start
                            .as_deref()
                            .is_some_and(|start| key.request_id.as_slice() > start) =>
                {
                    break;
                }
                Next::Route(key, run) => (key, run),
            };
            cursor.after = Some(key.request_id.clone());
            poll.inspected += 1;
            let Some(run) = run else {
                #[cfg(test)]
                poll.trace.push((key.request_id, Inspected::Admitting));
                continue;
            };
            #[cfg(test)]
            test_hook::fire(Point::DeadlineSelected);
            let polled = self.poll_run(&key, &run)?;
            #[cfg(test)]
            poll.trace.push((
                key.request_id.clone(),
                match polled {
                    Polled::Busy => Inspected::Busy,
                    _ => Inspected::Polled,
                },
            ));
            if let Polled::Ended(ended) = polled {
                poll.event = Some(DeadlineEvent {
                    request_id: key.request_id,
                    ended,
                });
                break;
            }
        }
        Ok(poll)
    }

    /// One selection step, in one table critical section: `Closing` once the session began
    /// closing; otherwise the first route of `session` strictly after `after` (or its first
    /// route), found by one ordered-map seek that clones only that key and that run's `Arc`.
    fn next_route(
        &self,
        lease: &Lease,
        session: SessionHandle,
        after: Option<&[u8]>,
    ) -> Result<Next, RouteError> {
        let table = self.table()?;
        if lease.closing()? {
            return Ok(Next::Closing);
        }
        let from = RoutingKey {
            session,
            request_id: after.unwrap_or_default().to_vec(),
        };
        let lower = match after {
            Some(_) => Bound::Excluded(&from),
            None => Bound::Included(&from),
        };
        Ok(match table.routes.range((lower, Bound::Unbounded)).next() {
            Some((key, route)) if key.session == session => Next::Route(
                key.clone(),
                match route {
                    Route::Active(run) => Some(run.clone()),
                    Route::Admitting { .. } => None,
                },
            ),
            _ => Next::End,
        })
    }

    /// Polls one selected run outside the table lock, never waiting for its lock: a busy run is
    /// left untouched. If it ended, its own cleanup already ran under its lock; only then is the
    /// route removed, and only if it still names this exact run.
    fn poll_run(&self, key: &RoutingKey, run: &Run) -> Result<Polled, RouteError> {
        let mut ceremony = match run.try_lock() {
            Ok(ceremony) => ceremony,
            Err(TryLockError::WouldBlock) => return Ok(Polled::Busy),
            Err(TryLockError::Poisoned(_)) => return Err(uncertain()),
        };
        #[cfg(test)]
        test_hook::fire(Point::DeadlineRunLocked);
        let outcome = ceremony.poll_deadlines();
        if self.remove_finished(key, run, &ceremony)?.is_some() {
            // Deadline processing never succeeds: a routed succeeded run is a broken invariant.
            return Err(uncertain());
        }
        Ok(match outcome {
            Ok(DeadlineOutcome::Active | DeadlineOutcome::Finished) => Polled::Live,
            Ok(DeadlineOutcome::TimedOut(timeout)) => {
                Polled::Ended(DeadlineEnded::TimedOut(timeout))
            }
            Ok(DeadlineOutcome::PendingExpired) => Polled::Ended(DeadlineEnded::PendingExpired),
            Err(CeremonyError::ClockUnavailable) => Polled::Ended(DeadlineEnded::ClockUnavailable),
            // Uncertain guard or resource release, or anything unexpected: never run-local.
            Err(_) => return Err(uncertain()),
        })
    }

    fn route_start(
        &self,
        session: SessionHandle,
        bytes: &[u8],
        new: Option<NewResponder>,
    ) -> Result<StartRouting, RouteError> {
        let (kind, request_id) = protocol::route_fields(bytes)?;
        if kind != 1 {
            return Err(protocol::CodecError::InvalidField("message_type").into());
        }
        let key = RoutingKey {
            session,
            request_id: request_id.to_vec(),
        };
        let (lease, claim) = match self.classify_start(&key, bytes, new.is_some())? {
            StartRoute::New(lease, claim) => (lease, claim),
            StartRoute::Duplicate => return Ok(StartRouting::Duplicate),
            StartRoute::Existing(_lease, run) => {
                // Duplicate or conflict for that run only; never a new candidate.
                self.on_run(&key, &run, |run| run.receive_start_duplicate(bytes))?;
                return Ok(StartRouting::Duplicate);
            }
        };
        let NewResponder {
            clock,
            local,
            expected,
        } = new.expect("only a new responder claims");
        // Bounded admission and its cryptography run without the table lock. Declared after
        // `lease`, so a returned or discarded run is dropped before the lease.
        let admitted = self
            .executor
            .begin(Role::Responder)
            .map_err(CeremonyError::from)
            .and_then(|admission| {
                RemoteCeremony::responder_with_clock(
                    clock,
                    self.executor.clone(),
                    admission,
                    bytes,
                    local,
                    expected,
                )
            });
        let mut table = self.table()?;
        let closing = lease.closing()?;
        let (ours, conflicted) = match table.routes.get(&key) {
            Some(Route::Admitting {
                claim: owner,
                conflicted,
                ..
            }) if *owner == claim => (true, *conflicted),
            _ => (false, false),
        };
        match admitted {
            Ok((run, accept)) if ours && !conflicted && !closing => {
                table
                    .routes
                    .insert(key, Route::Active(Arc::new(Mutex::new(run))));
                Ok(StartRouting::Accepted(accept))
            }
            Ok((run, _accept)) => {
                // Conflicted or session closing: the run is made terminal (and its slot
                // released) before the key can be claimed again; the ACCEPT is never returned.
                drop(table);
                drop(run);
                if ours {
                    self.release_claim(&key, claim)?;
                }
                if closing {
                    Err(RouteError::UnknownSession)
                } else {
                    Err(CeremonyError::InvalidState.into())
                }
            }
            Err(error) => {
                if ours {
                    table.routes.remove(&key);
                }
                Err(error.into())
            }
        }
    }

    /// One critical section: enter the OPEN session, then exactly one of claim-new (absent key,
    /// only when `claim_new`), exact in-progress duplicate, conflict (marks an in-progress
    /// claim conflicted so its admission is discarded), or the installed run.
    fn classify_start(
        &self,
        key: &RoutingKey,
        bytes: &[u8],
        claim_new: bool,
    ) -> Result<StartRoute, RouteError> {
        // Structural START candidate checks first, so malformed input never claims a key.
        let structural = protocol::start_candidate(bytes).map(|_| ());
        let mut guard = self.table()?;
        let table = &mut *guard;
        let lease = self.enter(table, key.session)?;
        match table.routes.entry(key.clone()) {
            Entry::Vacant(_) if !claim_new => Err(RouteError::UnknownRoute),
            Entry::Vacant(slot) => {
                structural?;
                let claim = table.next_claim;
                table.next_claim = claim.checked_add(1).ok_or_else(uncertain)?;
                slot.insert(Route::Admitting {
                    claim,
                    start: bytes.to_vec(),
                    conflicted: false,
                });
                Ok(StartRoute::New(lease, claim))
            }
            Entry::Occupied(mut slot) => match slot.get_mut() {
                Route::Admitting {
                    start, conflicted, ..
                } => {
                    if !*conflicted && start.as_slice() == bytes {
                        Ok(StartRoute::Duplicate)
                    } else {
                        *conflicted = true;
                        Err(CeremonyError::InvalidState.into())
                    }
                }
                Route::Active(run) => Ok(StartRoute::Existing(lease, run.clone())),
            },
        }
    }

    fn release_claim(&self, key: &RoutingKey, claim: u64) -> Result<(), RouteError> {
        let mut table = self.table()?;
        if matches!(table.routes.get(key), Some(Route::Admitting { claim: owner, .. }) if *owner == claim)
        {
            table.routes.remove(key);
        }
        Ok(())
    }

    /// The installed run under exactly `key`, entered for a local action. An in-progress START
    /// admission is not routable.
    fn active(&self, key: &RoutingKey) -> Result<(Lease, Run), RouteError> {
        let table = self.table()?;
        let lease = self.enter(&table, key.session)?;
        match table.routes.get(key) {
            Some(Route::Active(run)) => Ok((lease, run.clone())),
            _ => Err(RouteError::UnknownRoute),
        }
    }

    /// For an inbound non-START frame, in one critical section: enter the OPEN session and take
    /// the installed run under exactly `key`. A START still being admitted under `key` is
    /// marked conflicted, so that admission is discarded (out of order for that key only). No
    /// route at all makes the session CLOSING in this same critical section, so no other run
    /// is guessed at and nothing new can enter before the teardown.
    fn dispatch(&self, key: &RoutingKey) -> Result<Dispatch, RouteError> {
        let mut guard = self.table()?;
        let table = &mut *guard;
        let lease = self.enter(table, key.session)?;
        match table.routes.get_mut(key) {
            Some(Route::Active(run)) => Ok(Dispatch::Run(lease, run.clone())),
            Some(Route::Admitting { conflicted, .. }) => {
                *conflicted = true;
                Err(CeremonyError::InvalidState.into())
            }
            None => {
                drop(lease);
                Ok(Dispatch::Unrouted(self.begin_close(table, key.session)?))
            }
        }
    }

    /// Runs `op` under the run's own lock, never the table lock. If the run is finished
    /// afterwards, its own terminal cleanup (I1/I2 invalidation, then guard, slot, and
    /// reservation release) has already happened; only then is the route removed and the key
    /// reusable. The caller that removes the route of a succeeded run receives its result.
    fn on_run<T>(
        &self,
        key: &RoutingKey,
        run: &Run,
        op: impl FnOnce(&mut RemoteCeremony) -> Result<T, CeremonyError>,
    ) -> Result<Routed<T>, RouteError> {
        let mut ceremony = lock(run)?;
        let outcome = op(&mut ceremony);
        let result = self.remove_finished(key, run, &ceremony)?;
        Ok(Routed {
            output: outcome?,
            result,
        })
    }

    /// Called under `run`'s own lock. If the run is finished, removes its route, but only while
    /// `key` still names this exact run (never a replacement under a reused key), and returns
    /// its result to that one remover.
    fn remove_finished(
        &self,
        key: &RoutingKey,
        run: &Run,
        ceremony: &RemoteCeremony,
    ) -> Result<Option<PairingResult>, RouteError> {
        if !ceremony.is_finished() {
            return Ok(None);
        }
        let mut table = self.table()?;
        if matches!(table.routes.get(key), Some(Route::Active(current)) if Arc::ptr_eq(current, run))
        {
            table.routes.remove(key);
            return Ok(ceremony.result().cloned());
        }
        Ok(None)
    }

    /// Enters an OPEN session for one operation, inside the caller's table critical section so
    /// it is ordered against `begin_close`.
    fn enter(&self, table: &Table, session: SessionHandle) -> Result<Lease, RouteError> {
        let lifecycle = self.lifecycle(table, session)?;
        let mut activity = activity(lifecycle)?;
        if activity.closing {
            return Err(RouteError::UnknownSession);
        }
        activity.in_flight = activity.in_flight.checked_add(1).ok_or_else(uncertain)?;
        drop(activity);
        Ok(Lease(lifecycle.clone()))
    }

    /// OPEN -> CLOSING, inside the caller's table critical section: the close linearization
    /// point. Only one caller wins; a CLOSING or CLOSED session is `UnknownSession`.
    fn begin_close(
        &self,
        table: &Table,
        session: SessionHandle,
    ) -> Result<Arc<Lifecycle>, RouteError> {
        let lifecycle = self.lifecycle(table, session)?;
        let mut activity = activity(lifecycle)?;
        if activity.closing {
            return Err(RouteError::UnknownSession);
        }
        activity.closing = true;
        drop(activity);
        Ok(lifecycle.clone())
    }

    /// The one session teardown, shared by `close_session` and the session-fatal routing
    /// failure, run by the caller that won `begin_close` while it holds no router lock or lease.
    /// It waits for every earlier operation to return, then detaches every route of the session
    /// and terminates each run outside the table lock, and only then makes the session CLOSED.
    /// Its outcome is recorded for `close_session_settled` waiters.
    fn finish_close(
        &self,
        session: SessionHandle,
        lifecycle: &Lifecycle,
    ) -> Result<(), RouteError> {
        let outcome = self.teardown(session, lifecycle);
        // Recorded even if poisoned, so a waiter wakes and then fails closed on the poison.
        let mut activity = lifecycle
            .activity
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        activity.ended = Some(match outcome {
            Ok(()) => Ended::Closed,
            Err(_) => Ended::Uncertain,
        });
        lifecycle.settled.notify_all();
        outcome
    }

    fn teardown(&self, session: SessionHandle, lifecycle: &Lifecycle) -> Result<(), RouteError> {
        {
            let mut activity = activity(lifecycle)?;
            while activity.in_flight > 0 {
                #[cfg(test)]
                test_hook::fire(Point::CloseWaiting {
                    in_flight: activity.in_flight,
                });
                activity = lifecycle.settled.wait(activity).map_err(|_| uncertain())?;
            }
        }
        // Nothing of this session runs and nothing can enter, so no claim can remain and no
        // route can appear: every creator either installed before closing or discarded its run.
        let runs: Vec<Run> = {
            let mut table = self.table()?;
            let mut runs = Vec::new();
            table.routes.retain(|key, route| {
                if key.session != session {
                    return true;
                }
                if let Route::Active(run) = route {
                    runs.push(run.clone());
                }
                false
            });
            runs
        };
        let mut outcome = Ok(());
        for run in runs {
            let ended = lock(&run).and_then(|mut run| Ok(run.terminate()?));
            if outcome.is_ok() {
                outcome = ended;
            }
        }
        // Uncertain cleanup leaves the session CLOSING forever: never reopened, never CLOSED.
        outcome?;
        self.table()?.sessions.remove(&session.session);
        Ok(())
    }

    fn lifecycle<'t>(
        &self,
        table: &'t Table,
        session: SessionHandle,
    ) -> Result<&'t Arc<Lifecycle>, RouteError> {
        if session.router != self.id {
            return Err(RouteError::UnknownSession);
        }
        table
            .sessions
            .get(&session.session)
            .ok_or(RouteError::UnknownSession)
    }

    fn table(&self) -> Result<MutexGuard<'_, Table>, RouteError> {
        self.table.lock().map_err(|_| uncertain())
    }
}

/// A poisoned lifecycle lock fails closed: the session admits nothing and cannot be reported
/// closed.
fn activity(lifecycle: &Lifecycle) -> Result<MutexGuard<'_, Activity>, RouteError> {
    lifecycle.activity.lock().map_err(|_| uncertain())
}

/// A poisoned run lock fails closed; the run stays routed and its resources stay held.
fn lock(run: &Run) -> Result<MutexGuard<'_, RemoteCeremony>, RouteError> {
    run.lock().map_err(|_| uncertain())
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::{
        Status, TrustedAuthority,
        ceremony::{
            BootstrapMacEmission, DeadlineOutcome, FinishEmission, LocalCancellation, SasApproval,
        },
        deadline::{ABSOLUTE_DEADLINE, Deadline, INACTIVITY_DEADLINE, ManualClock},
        protocol::{CancelReason, Message},
        start_limiter::{REFILL_PERIOD, ROLLING_WINDOW, StartLimiterSnapshot},
    };
    use serde_json::Value;
    use std::{
        collections::VecDeque,
        sync::{
            Barrier,
            mpsc::{self, Receiver, Sender},
        },
        thread::{self, Scope, ScopedJoinHandle},
        time::Duration,
    };

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
    fn vector(name: &str) -> Vec<u8> {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../vectors/p3-remote-vodozemac-draft-01.json"
        ))
        .unwrap();
        hex(fixture["wire_messages"][name]["hex"].as_str().unwrap())
    }
    /// The fixture Initiator's bootstrap (from START).
    fn initiator_bootstrap() -> Bootstrap {
        match protocol::decode(&vector("START")).unwrap().message {
            Message::Start { bootstrap, .. } => bootstrap,
            _ => unreachable!(),
        }
    }
    /// The fixture Responder's bootstrap (from ACCEPT); same shared context as the Initiator's.
    fn responder_bootstrap() -> Bootstrap {
        match protocol::decode(&vector("ACCEPT")).unwrap().message {
            Message::Accept { bootstrap, .. } => bootstrap,
            _ => unreachable!(),
        }
    }
    /// A canonical START with `request_id` and the fixture Initiator bootstrap.
    fn start_frame(request_id: &[u8]) -> Vec<u8> {
        Message::Start {
            request_id: request_id.to_vec(),
            bootstrap: initiator_bootstrap(),
        }
        .encode()
        .unwrap()
    }
    /// The same request ID with other canonical bytes (another application identity).
    fn changed_start(request_id: &[u8]) -> Vec<u8> {
        let b = initiator_bootstrap();
        let bootstrap = Bootstrap::new(
            b"another application".to_vec(),
            b.key_algorithm().to_vec(),
            b.public_key().to_vec(),
            b.shared_context().to_vec(),
        )
        .unwrap();
        Message::Start {
            request_id: request_id.to_vec(),
            bootstrap,
        }
        .encode()
        .unwrap()
    }
    /// A valid-looking INITIATOR_KEY for `request_id`.
    fn initiator_key(request_id: &[u8]) -> Vec<u8> {
        Message::InitiatorKey {
            request_id: request_id.to_vec(),
            public_key: [9; 32],
        }
        .encode()
        .unwrap()
    }
    /// `frame` (an INITIATOR_KEY) re-encoded under another request ID.
    fn with_request_id(frame: &[u8], request_id: &[u8]) -> Vec<u8> {
        match protocol::decode(frame).unwrap().message {
            Message::InitiatorKey { public_key, .. } => Message::InitiatorKey {
                request_id: request_id.to_vec(),
                public_key,
            }
            .encode()
            .unwrap(),
            _ => unreachable!(),
        }
    }
    const BAD: RouteError = RouteError::Ceremony(CeremonyError::InvalidState);

    struct ScriptedIds(VecDeque<[u8; 16]>);
    impl RequestIdGenerator for ScriptedIds {
        fn generate(&mut self) -> Option<[u8; 16]> {
            Some(self.0.pop_front().expect("request-ID script exhausted"))
        }
    }
    fn script<const N: usize>(ids: [[u8; 16]; N]) -> ScriptedIds {
        ScriptedIds(ids.into())
    }

    /// One authority (START limiter on a hand clock) and its router.
    struct Node {
        authority: TrustedAuthority,
        executor: CeremonyExecutor,
        limiter: Arc<ManualClock>,
        router: Router,
    }
    impl Node {
        fn new(scope: &str) -> Self {
            let limiter = ManualClock::new();
            let authority =
                TrustedAuthority::register_with_limiter_clock(scope.as_bytes(), limiter.clone())
                    .unwrap();
            let executor = authority.executor();
            let router = Router::new(executor.clone()).unwrap();
            Self {
                authority,
                executor,
                limiter,
                router,
            }
        }
        fn release(self) {
            drop(self.router);
            drop(self.executor);
            self.authority.release().unwrap();
        }
        fn session(&self) -> SessionHandle {
            self.router.open_session().unwrap()
        }
        fn receive(
            &self,
            session: SessionHandle,
            start: &[u8],
        ) -> Result<StartRouting, RouteError> {
            self.router
                .receive_start(session, start, responder_bootstrap(), None)
        }
        fn receive_at(
            &self,
            clock: &Arc<ManualClock>,
            session: SessionHandle,
            start: &[u8],
        ) -> Result<StartRouting, RouteError> {
            self.router.receive_start_with_clock(
                clock.clone(),
                session,
                start,
                responder_bootstrap(),
                None,
            )
        }
        fn accept(&self, session: SessionHandle, start: &[u8]) -> Vec<u8> {
            match self.receive(session, start) {
                Ok(StartRouting::Accepted(accept)) => accept,
                other => panic!("START not admitted: {other:?}"),
            }
        }
        fn initiate(&self, session: SessionHandle) -> (Vec<u8>, Vec<u8>) {
            self.router
                .start_initiator(session, initiator_bootstrap(), None)
                .unwrap()
        }
        fn local<T>(
            &self,
            session: SessionHandle,
            request_id: &[u8],
            op: impl FnOnce(&mut RemoteCeremony) -> Result<T, CeremonyError>,
        ) -> Routed<T> {
            self.router.with_run(session, request_id, op).unwrap()
        }
        fn state(&self, session: SessionHandle, request_id: &[u8]) -> &'static str {
            self.local(session, request_id, |run| Ok(run.state_label_for_test()))
                .output
        }
        fn limiter(&self) -> StartLimiterSnapshot {
            self.executor.start_limiter_snapshot()
        }
        fn pending(&self) -> usize {
            self.executor.0.shared.lock().unwrap().pending_responders
        }
        fn permits(&self) -> usize {
            self.executor
                .0
                .shared
                .lock()
                .unwrap()
                .preliminary_operations
        }
        fn reserved(&self) -> usize {
            self.executor
                .0
                .shared
                .lock()
                .unwrap()
                .initiator_request_ids
                .len()
        }
        fn status(&self) -> Status {
            self.executor.status().unwrap()
        }
        fn routes(&self) -> usize {
            self.router.table.lock().unwrap().routes.len()
        }
        /// `(routes, pending Responders, preliminary permits, Initiator ID reservations)`.
        fn resources(&self) -> (usize, usize, usize, usize) {
            (
                self.routes(),
                self.pending(),
                self.permits(),
                self.reserved(),
            )
        }
        /// One full rolling window of limiter time: credit 4 and no live records again.
        fn refill(&self) {
            self.limiter.advance(ROLLING_WINDOW);
        }
    }

    /// Routed key exchange from `accept` to both live SAS presentations; returns the identity.
    fn exchange(
        i: &Node,
        si: SessionHandle,
        r: &Node,
        sr: SessionHandle,
        id: &[u8],
        accept: &[u8],
    ) -> [u8; 32] {
        assert_eq!(
            i.router.deliver(si, accept).unwrap().output,
            Inbound::Accept
        );
        i.local(si, id, |run| run.authorize(&i.authority));
        let ikey = i.local(si, id, |run| run.expose_key()).output;
        assert_eq!(
            r.router.deliver(sr, &ikey).unwrap().output,
            Inbound::InitiatorKey
        );
        r.local(sr, id, |run| run.authorize(&r.authority));
        let rkey = r.local(sr, id, |run| run.expose_key()).output;
        assert_eq!(
            i.router.deliver(si, &rkey).unwrap().output,
            Inbound::ResponderKey
        );
        let identity = |node: &Node, session| {
            *node
                .local(session, id, |run| Ok(run.presentation()))
                .output
                .unwrap()
                .ceremony_identity()
        };
        let ours = identity(i, si);
        assert_eq!(ours, identity(r, sr));
        ours
    }

    /// Two authorities, each with one session; the Initiator's run is routed and started.
    fn initiated(scope: &str) -> (Node, SessionHandle, Node, SessionHandle, Vec<u8>, Vec<u8>) {
        let i = Node::new(&format!("{scope}-i"));
        let r = Node::new(&format!("{scope}-r"));
        let (si, sr) = (i.session(), r.session());
        let (id, start) = i.initiate(si);
        (i, si, r, sr, id, start)
    }

    #[test]
    fn sessions_are_distinct_and_closed_or_foreign_handles_are_rejected() {
        let node = Node::new("router-sessions");
        let other = Router::new(node.executor.clone()).unwrap();
        let (a, b) = (node.session(), node.session());
        let foreign = other.open_session().unwrap();
        assert!(a != b && a != foreign && b != foreign);
        node.router.close_session(a).unwrap();
        let x = [1; 16];
        assert_eq!(
            node.receive(a, &start_frame(&x)),
            Err(RouteError::UnknownSession)
        );
        assert_eq!(
            node.router.deliver(a, &initiator_key(&x)).unwrap_err(),
            RouteError::UnknownSession
        );
        assert_eq!(
            node.router.with_run(a, &x, |_| Ok(())).unwrap_err(),
            RouteError::UnknownSession
        );
        assert_eq!(
            node.router.start_initiator(a, initiator_bootstrap(), None),
            Err(RouteError::UnknownSession)
        );
        assert_eq!(
            node.router.close_session(a),
            Err(RouteError::UnknownSession)
        );
        // Another router's handle names nothing here, even with the same session number.
        assert_eq!(
            node.receive(foreign, &start_frame(&x)),
            Err(RouteError::UnknownSession)
        );
        assert_eq!(
            node.router.close_session(foreign),
            Err(RouteError::UnknownSession)
        );
        // Closed handles are never reissued.
        let c = node.session();
        assert!(c != a && c != b);
        // A rejected handle charged, reserved, and created nothing.
        let limiter = node.limiter();
        assert_eq!((limiter.tokens, limiter.rolling), (4, 0));
        assert_eq!((node.reserved(), node.pending(), node.routes()), (0, 0, 0));
        drop(other);
        node.release();
    }

    #[test]
    fn exact_duplicate_starts_are_ignored_without_charge_output_or_new_state() {
        let (i, si, r, sr, id, start) = initiated("router-duplicate");
        assert_eq!(id.len(), 16);
        let accept = r.accept(sr, &start);
        let charged = r.limiter();
        assert_eq!((charged.tokens, charged.rolling, r.pending()), (3, 1, 1));
        for _ in 0..100 {
            assert_eq!(r.receive(sr, &start), Ok(StartRouting::Duplicate));
        }
        assert_eq!(
            r.router.deliver(sr, &start).unwrap().output,
            Inbound::StartDuplicate
        );
        // The limiter clock did not move: its state is exactly as after the one admission.
        assert_eq!(r.limiter(), charged);
        assert_eq!((r.pending(), r.permits(), r.routes()), (1, 0, 1));
        assert_eq!(r.state(sr, &id), "ResponderAcceptSentAwaitInitiatorKey");
        assert_eq!(r.status(), Status::Ready { remaining: 10 });
        // No second ephemeral: the Initiator verifies RESPONDER_KEY against the commitment in
        // the one original ACCEPT.
        exchange(&i, si, &r, sr, &id, &accept);
        assert_eq!(r.limiter(), charged);
        i.release();
        r.release();
    }

    #[test]
    fn duplicates_and_misrouted_input_buy_no_time_and_timeout_frees_the_key() {
        let r = Node::new("router-time");
        let clock = ManualClock::new();
        let (a, b) = (r.session(), r.session());
        let x = [7; 16];
        let start = start_frame(&x);
        assert!(matches!(
            r.receive_at(&clock, a, &start),
            Ok(StartRouting::Accepted(_))
        ));
        clock.advance(INACTIVITY_DEADLINE - Duration::from_nanos(1));
        assert_eq!(r.receive_at(&clock, a, &start), Ok(StartRouting::Duplicate));
        // Misrouted onto B, where it names no route: fatal to B only, never input to A's run.
        assert_eq!(
            r.router.deliver(b, &initiator_key(&x)).unwrap_err(),
            RouteError::SessionProtocolFailure
        );
        assert_eq!(
            r.router.deliver(b, &initiator_key(&x)).unwrap_err(),
            RouteError::UnknownSession
        );
        assert_eq!(
            r.local(a, &x, |run| run.poll_deadlines()).output,
            DeadlineOutcome::Active
        );
        clock.advance(Duration::from_nanos(1));
        // Had any of that refreshed inactivity, only the fixed pending lifetime would expire.
        let polled = r.local(a, &x, |run| run.poll_deadlines());
        assert!(matches!(
            polled.output,
            DeadlineOutcome::TimedOut(ref t)
                if t.expired() == Deadline::Inactivity && t.cancel().is_none()
        ));
        assert!(polled.result.is_none());
        assert_eq!((r.routes(), r.pending()), (0, 0));
        assert_eq!(
            r.router.with_run(a, &x, |_| Ok(())).unwrap_err(),
            RouteError::UnknownRoute
        );
        // The still-live session may begin a fresh, newly charged run under the same key.
        let before = r.limiter();
        assert!(matches!(
            r.receive_at(&clock, a, &start),
            Ok(StartRouting::Accepted(_))
        ));
        assert_eq!(r.limiter().rolling, before.rolling + 1);
        assert_eq!(r.state(a, &x), "ResponderAcceptSentAwaitInitiatorKey");
        r.release();
    }

    #[test]
    fn local_termination_protocol_failure_and_pending_expiry_remove_routes() {
        let r = Node::new("router-cleanup");
        let clock = ManualClock::new();
        let a = r.session();
        let (x, y, z) = ([1; 16], [2; 16], [3; 16]);
        for id in [x, y, z] {
            assert!(matches!(
                r.receive_at(&clock, a, &start_frame(&id)),
                Ok(StartRouting::Accepted(_))
            ));
        }
        clock.advance(Duration::from_secs(30));
        // A wrong-state frame routed to a live run is that run's protocol failure.
        let mac = Message::BootstrapMac {
            request_id: y.to_vec(),
            sender: protocol::Role::Initiator,
            mac: [0; 32],
        }
        .encode()
        .unwrap();
        assert_eq!(r.router.deliver(a, &mac).unwrap_err(), BAD);
        // Local pre-SAS cancellation is plain termination.
        r.local(a, &z, |run| run.terminate());
        assert_eq!((r.routes(), r.pending()), (1, 1));
        // Progress at 30 s restarts inactivity but never the fixed pending lifetime.
        assert_eq!(
            r.router.deliver(a, &initiator_key(&x)).unwrap().output,
            Inbound::InitiatorKey
        );
        clock.advance(Duration::from_secs(30));
        assert_eq!(
            r.local(a, &x, |run| run.poll_deadlines()).output,
            DeadlineOutcome::PendingExpired
        );
        assert_eq!((r.routes(), r.pending(), r.permits()), (0, 0, 0));
        assert_eq!(r.status(), Status::Ready { remaining: 10 });
        r.release();
    }

    #[test]
    fn a_changed_start_fails_the_existing_run_and_never_creates_a_second() {
        let r = Node::new("router-conflict");
        let a = r.session();
        let x = [3; 16];
        r.accept(a, &start_frame(&x));
        let charged = r.limiter();
        assert_eq!(r.receive(a, &changed_start(&x)), Err(BAD));
        // The conflict belongs to the existing key: it is not a new limiter candidate.
        assert_eq!(r.limiter(), charged);
        assert_eq!((r.routes(), r.pending(), r.permits()), (0, 0, 0));
        assert_eq!(r.status(), Status::Ready { remaining: 10 });
        // Only now is the key reusable: the changed START is a fresh, charged candidate.
        r.accept(a, &changed_start(&x));
        assert_eq!(r.limiter().rolling, charged.rolling + 1);
        // `deliver` never admits: a START for an unknown key stays unrouted and uncharged.
        let limiter = r.limiter();
        assert_eq!(
            r.router.deliver(a, &start_frame(&[4; 16])).unwrap_err(),
            RouteError::UnknownRoute
        );
        // A changed START delivered to the new run fails it too.
        assert_eq!(r.router.deliver(a, &start_frame(&x)).unwrap_err(), BAD);
        assert_eq!(r.limiter(), limiter);
        assert_eq!((r.routes(), r.pending()), (0, 0));
        r.release();
    }

    #[test]
    fn a_changed_start_after_exposure_keeps_the_opportunity_and_yields_no_result() {
        let (i, si, r, sr, id, start) = initiated("router-conflict-exposed");
        let accept = r.accept(sr, &start);
        exchange(&i, si, &r, sr, &id, &accept);
        assert_eq!(r.status(), Status::Busy);
        let limiter = r.limiter();
        assert_eq!(r.receive(sr, &changed_start(&id)), Err(BAD));
        assert_eq!(r.status(), Status::Ready { remaining: 9 });
        assert_eq!((r.routes(), r.limiter()), (0, limiter));
        i.release();
        r.release();
    }

    #[test]
    fn the_same_request_id_on_another_session_is_an_independent_run() {
        let r = Node::new("router-cross-session");
        let (a, b) = (r.session(), r.session());
        let x = [5; 16];
        let start = start_frame(&x);
        let accept_a = r.accept(a, &start);
        // Byte-identical START on another session: not a duplicate, a new charged run.
        let accept_b = r.accept(b, &start);
        assert_ne!(
            accept_a, accept_b,
            "fresh Responder ephemeral and commitment"
        );
        let limiter = r.limiter();
        assert_eq!((limiter.tokens, limiter.rolling), (2, 2));
        assert_eq!((r.pending(), r.routes()), (2, 2));
        // Duplicate and conflict rules apply per key: only B's run is affected.
        assert_eq!(r.receive(b, &start), Ok(StartRouting::Duplicate));
        assert_eq!(r.receive(b, &changed_start(&x)), Err(BAD));
        assert_eq!(r.limiter(), limiter);
        assert_eq!(r.state(a, &x), "ResponderAcceptSentAwaitInitiatorKey");
        assert_eq!((r.pending(), r.routes()), (1, 1));
        assert_eq!(
            r.router.with_run(b, &x, |_| Ok(())).unwrap_err(),
            RouteError::UnknownRoute
        );
        // Canonical peer IDs of any length 1..=64 route; nothing requires 16 bytes.
        r.accept(b, &start_frame(&[0xAA]));
        r.accept(b, &start_frame(&[0xBB; 64]));
        assert_eq!(r.state(b, &[0xAA]), "ResponderAcceptSentAwaitInitiatorKey");
        assert_eq!(
            r.state(b, &[0xBB; 64]),
            "ResponderAcceptSentAwaitInitiatorKey"
        );
        assert_eq!(r.pending(), 3);
        r.release();
    }

    #[test]
    fn later_messages_reach_only_the_run_under_their_own_session_and_request_id() {
        let (i, si, r, a, id, start) = initiated("router-injection");
        let (b, c) = (r.session(), r.session());
        let accept = r.accept(a, &start);
        assert_eq!(
            i.router.deliver(si, &accept).unwrap().output,
            Inbound::Accept
        );
        i.local(si, &id, |run| run.authorize(&i.authority));
        let ikey = i.local(si, &id, |run| run.expose_key()).output;
        let limiter = r.limiter();
        // Session C has no run for this ID: it reaches no run and is fatal to C only.
        assert_eq!(
            r.router.deliver(c, &ikey).unwrap_err(),
            RouteError::SessionProtocolFailure
        );
        // No DH, permit, guard, opportunity, or state change happened in A's run.
        assert_eq!(r.state(a, &id), "ResponderAcceptSentAwaitInitiatorKey");
        assert_eq!((r.permits(), r.pending(), r.limiter()), (0, 1, limiter));
        assert_eq!(r.status(), Status::Ready { remaining: 10 });
        // Once B owns its own run under the same ID, B's input goes only there.
        r.accept(b, &start);
        assert_eq!(
            r.router.deliver(b, &ikey).unwrap().output,
            Inbound::InitiatorKey
        );
        assert_eq!(r.state(b, &id), "ResponderAwaitAuthorization");
        assert_eq!(r.state(a, &id), "ResponderAcceptSentAwaitInitiatorKey");
        // A's own exchange still completes with its own peer.
        assert_eq!(
            r.router.deliver(a, &ikey).unwrap().output,
            Inbound::InitiatorKey
        );
        r.local(a, &id, |run| run.authorize(&r.authority));
        let rkey = r.local(a, &id, |run| run.expose_key()).output;
        assert_eq!(
            i.router.deliver(si, &rkey).unwrap().output,
            Inbound::ResponderKey
        );
        assert!(
            i.local(si, &id, |run| Ok(run.is_awaiting_approval()))
                .output
        );
        i.release();
        r.release();
    }

    /// Runs `starts` concurrently on `node`, released together by one barrier.
    fn race(
        node: &Node,
        starts: &[(SessionHandle, Vec<u8>)],
    ) -> Vec<Result<StartRouting, RouteError>> {
        let barrier = Barrier::new(starts.len());
        thread::scope(|scope| {
            let handles: Vec<_> = starts
                .iter()
                .map(|(session, start)| {
                    let barrier = &barrier;
                    scope.spawn(move || {
                        barrier.wait();
                        node.receive(*session, start)
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        })
    }

    #[test]
    fn concurrent_identical_starts_create_exactly_one_run() {
        let r = Node::new("router-race-identical");
        let start = start_frame(&[6; 16]);
        for _ in 0..25 {
            r.refill();
            let a = r.session();
            let outcomes = race(&r, &vec![(a, start.clone()); 8]);
            let accepted = outcomes
                .iter()
                .filter(|o| matches!(o, Ok(StartRouting::Accepted(_))))
                .count();
            let duplicates = outcomes
                .iter()
                .filter(|o| **o == Ok(StartRouting::Duplicate))
                .count();
            assert_eq!((accepted, duplicates), (1, 7), "{outcomes:?}");
            // One limiter charge, one slot, one run; nothing left in progress.
            let limiter = r.limiter();
            assert_eq!((limiter.tokens, limiter.rolling), (3, 1));
            assert_eq!((r.pending(), r.permits(), r.routes()), (1, 0, 1));
            r.router.close_session(a).unwrap();
            assert_eq!((r.pending(), r.routes()), (0, 0));
        }
        r.release();
    }

    #[test]
    fn concurrent_conflicting_starts_never_leave_two_live_runs() {
        let r = Node::new("router-race-conflict");
        let x = [7; 16];
        for _ in 0..25 {
            r.refill();
            let a = r.session();
            let outcomes = race(&r, &[(a, start_frame(&x)), (a, changed_start(&x))]);
            // Whichever claimed the key, the other conflicts with it and the key fails.
            assert!(
                outcomes
                    .iter()
                    .all(|o| matches!(o, Ok(StartRouting::Accepted(_))) || *o == Err(BAD)),
                "{outcomes:?}"
            );
            assert!(outcomes.contains(&Err(BAD)), "{outcomes:?}");
            // Exactly the claiming candidate was charged; no run, slot, or permit survives.
            let limiter = r.limiter();
            assert_eq!((limiter.tokens, limiter.rolling), (3, 1));
            assert_eq!((r.routes(), r.pending(), r.permits()), (0, 0, 0));
            assert_eq!(r.status(), Status::Ready { remaining: 10 });
            // The key is free again for a fresh candidate.
            r.accept(a, &start_frame(&x));
            r.router.close_session(a).unwrap();
        }
        r.release();
    }

    #[test]
    fn concurrent_equal_request_ids_on_two_sessions_admit_independently() {
        let r = Node::new("router-race-sessions");
        let x = [8; 16];
        let start = start_frame(&x);
        for _ in 0..25 {
            r.refill();
            let (a, b) = (r.session(), r.session());
            let outcomes = race(&r, &[(a, start.clone()), (b, start.clone())]);
            let accepts: Vec<_> = outcomes
                .into_iter()
                .map(|o| match o {
                    Ok(StartRouting::Accepted(accept)) => accept,
                    other => panic!("not independently admitted: {other:?}"),
                })
                .collect();
            assert_ne!(accepts[0], accepts[1]);
            let limiter = r.limiter();
            assert_eq!((limiter.tokens, limiter.rolling), (2, 2));
            assert_eq!((r.pending(), r.routes()), (2, 2));
            r.router.close_session(a).unwrap();
            assert_eq!(r.state(b, &x), "ResponderAcceptSentAwaitInitiatorKey");
            r.router.close_session(b).unwrap();
        }
        r.release();
    }

    #[test]
    fn closing_a_session_ends_all_its_runs_and_leaves_other_sessions_alone() {
        let r = Node::new("router-close");
        let (a, b) = (r.session(), r.session());
        for id in [[1; 16], [2; 16], [3; 16]] {
            r.accept(a, &start_frame(&id));
        }
        r.accept(b, &start_frame(&[1; 16]));
        let limiter = r.limiter();
        assert_eq!((r.pending(), r.routes()), (4, 4));
        r.router.close_session(a).unwrap();
        assert_eq!((r.pending(), r.routes(), r.permits()), (1, 1, 0));
        assert_eq!(r.status(), Status::Ready { remaining: 10 });
        assert_eq!(r.limiter(), limiter);
        assert_eq!(r.state(b, &[1; 16]), "ResponderAcceptSentAwaitInitiatorKey");
        // A's runs ended; nothing was transferred to B.
        assert_eq!(
            r.router.with_run(b, &[2; 16], |_| Ok(())).unwrap_err(),
            RouteError::UnknownRoute
        );
        assert_eq!(
            r.router.deliver(a, &initiator_key(&[1; 16])).unwrap_err(),
            RouteError::UnknownSession
        );
        assert_eq!(
            r.receive(a, &start_frame(&[2; 16])),
            Err(RouteError::UnknownSession)
        );
        assert_eq!(r.limiter(), limiter);
        r.release();
    }

    #[test]
    fn closing_a_session_after_exposure_keeps_the_opportunity_and_emits_nothing() {
        let (i, si, r, sr, id, start) = initiated("router-close-exposed");
        let accept = r.accept(sr, &start);
        exchange(&i, si, &r, sr, &id, &accept);
        assert_eq!(r.status(), Status::Busy);
        // No output exists to send: transport loss is local terminal failure only.
        assert_eq!(r.router.close_session(sr), Ok(()));
        assert_eq!(r.status(), Status::Ready { remaining: 9 });
        assert_eq!((r.routes(), r.pending()), (0, 0));
        // The peer is not notified and nothing resumes on a new session.
        assert_eq!(i.state(si, &id), "AwaitLocalApproval");
        let c = r.session();
        assert_eq!(
            r.router.with_run(c, &id, |_| Ok(())).unwrap_err(),
            RouteError::UnknownRoute
        );
        i.release();
        r.release();
    }

    #[test]
    fn closing_a_session_resets_no_authority_control() {
        let r = Node::new("router-close-limiter");
        let a = r.session();
        for n in 1..=4u8 {
            r.accept(a, &start_frame(&[n; 16]));
        }
        let exhausted = r.limiter();
        assert_eq!((exhausted.tokens, exhausted.rolling), (0, 4));
        r.router.close_session(a).unwrap();
        let b = r.session();
        assert_eq!(
            r.receive(b, &start_frame(&[9; 16])),
            Err(RouteError::Ceremony(CeremonyError::Owner(
                OwnerError::ResourceLimited
            )))
        );
        assert_eq!(r.limiter(), exhausted);
        assert_eq!((r.routes(), r.pending()), (0, 0));
        assert_eq!(r.status(), Status::Ready { remaining: 10 });
        // Only elapsed limiter time restores credit.
        r.limiter.advance(REFILL_PERIOD);
        r.accept(b, &start_frame(&[9; 16]));
        r.release();
    }

    #[test]
    fn post_sas_timeout_and_verified_peer_cancel_remove_both_routes() {
        let i = Node::new("router-timeout-cancel-i");
        let r = Node::new("router-timeout-cancel-r");
        let (si, sr) = (i.session(), r.session());
        let (ci, cr) = (ManualClock::new(), ManualClock::new());
        let (id, start) = i
            .router
            .start_initiator_with(
                ci.clone(),
                &mut OsRequestIds,
                si,
                initiator_bootstrap(),
                None,
            )
            .unwrap();
        let Ok(StartRouting::Accepted(accept)) = r.receive_at(&cr, sr, &start) else {
            panic!("START not admitted");
        };
        exchange(&i, si, &r, sr, &id, &accept);
        ci.advance(ABSOLUTE_DEADLINE);
        let DeadlineOutcome::TimedOut(timeout) =
            i.local(si, &id, |run| run.poll_deadlines()).output
        else {
            panic!("no timeout");
        };
        let cancel = timeout.cancel().expect("post-SAS timeout CANCEL").to_vec();
        assert_eq!((i.routes(), i.reserved()), (0, 0));
        assert_eq!(i.status(), Status::Ready { remaining: 9 });
        let delivered = r.router.deliver(sr, &cancel).unwrap();
        assert!(matches!(
            delivered.output,
            Inbound::Cancel(c) if c.reason() == CancelReason::Timeout
        ));
        assert!(delivered.result.is_none());
        assert_eq!(r.routes(), 0);
        assert_eq!(r.status(), Status::Ready { remaining: 9 });
        // Nothing is revived: the replayed CANCEL names a stale ID on a live session, which is
        // that session's routing failure, not a second cancellation or a refund.
        assert_eq!(
            r.router.deliver(sr, &cancel).unwrap_err(),
            RouteError::SessionProtocolFailure
        );
        assert_eq!(r.status(), Status::Ready { remaining: 9 });
        // A replayed START is only a completely new ceremony.
        let c = r.session();
        assert_ne!(r.accept(c, &start), accept);
        assert_eq!(r.state(c, &id), "ResponderAcceptSentAwaitInitiatorKey");
        assert_eq!(r.local(c, &id, |run| Ok(run.presentation())).output, None);
        i.release();
        r.release();
    }

    #[test]
    fn local_cancel_and_verified_peer_cancel_remove_both_routes() {
        let (i, si, r, sr, id, start) = initiated("router-local-cancel");
        let accept = r.accept(sr, &start);
        let identity = exchange(&i, si, &r, sr, &id, &accept);
        let cancelled = r.local(sr, &id, |run| run.cancel_sas(&identity));
        let LocalCancellation::Emitted(cancel) = cancelled.output else {
            panic!("no CANCEL");
        };
        assert_eq!(r.routes(), 0);
        assert!(matches!(
            i.router.deliver(si, &cancel).unwrap().output,
            Inbound::Cancel(c) if c.reason() == CancelReason::UserCancellation
        ));
        assert_eq!((i.routes(), i.reserved()), (0, 0));
        assert_eq!(i.status(), Status::Ready { remaining: 9 });
        assert_eq!(r.status(), Status::Ready { remaining: 9 });
        i.release();
        r.release();
    }

    #[test]
    fn success_removes_both_routes_and_hands_out_the_result_once() {
        let (i, si, r, sr, id, start) = initiated("router-success");
        let accept = r.accept(sr, &start);
        let identity = exchange(&i, si, &r, sr, &id, &accept);
        let mut macs = Vec::new();
        for (node, session) in [(&i, si), (&r, sr)] {
            let approval = node.local(session, &id, |run| run.approve_sas(&identity));
            assert_eq!(approval.output, SasApproval::Recorded);
            match node
                .local(session, &id, |run| run.emit_bootstrap_mac())
                .output
            {
                BootstrapMacEmission::Emitted(mac) => macs.push(mac),
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(
            r.router.deliver(sr, &macs[0]).unwrap().output,
            Inbound::BootstrapMac(PeerApproval::Authenticated)
        );
        assert_eq!(
            i.router.deliver(si, &macs[1]).unwrap().output,
            Inbound::BootstrapMac(PeerApproval::Authenticated)
        );
        let FinishEmission::Emitted(finish) =
            i.local(si, &id, |run| run.emit_initiator_finish()).output
        else {
            panic!("no INITIATOR_FINISH");
        };
        let Inbound::Completion(CompletionReceipt::SendResponderFinishAck(ack)) =
            r.router.deliver(sr, &finish).unwrap().output
        else {
            panic!("no RESPONDER_FINISH_ACK");
        };
        let Inbound::Completion(CompletionReceipt::SendInitiatorFinishAck(final_ack)) =
            i.router.deliver(si, &ack).unwrap().output
        else {
            panic!("no INITIATOR_FINISH_ACK");
        };
        // Producing the final ACK is not success: the Initiator stays routed.
        assert_eq!(i.routes(), 1);
        let responder = r.router.deliver(sr, &final_ack).unwrap();
        assert_eq!(
            responder.output,
            Inbound::Completion(CompletionReceipt::Succeeded)
        );
        let responder = responder.result.expect("Responder result");
        assert_eq!(r.routes(), 0);
        let initiator = i
            .router
            .with_run(si, &id, |run| {
                run.confirm_initiator_finish_ack_sent(&final_ack)
            })
            .unwrap()
            .result
            .expect("Initiator result");
        assert_eq!((i.routes(), i.reserved()), (0, 0));
        // `ceremony_identity` is the security identity; the request ID is diagnostic only.
        assert_eq!(initiator.ceremony_identity(), &identity);
        assert_eq!(responder.ceremony_identity(), &identity);
        assert_eq!(initiator.request_id(), id.as_slice());
        assert_eq!(responder.peer_role(), Role::Initiator);
        // Later traffic reaches nothing and cannot alter or duplicate either result: a stale
        // frame on the live session is that session's routing failure, never a second result.
        assert_eq!(
            r.router.deliver(sr, &final_ack).unwrap_err(),
            RouteError::SessionProtocolFailure
        );
        assert_eq!(responder.ceremony_identity(), &identity);
        assert_eq!(
            i.router
                .with_run(si, &id, |run| {
                    run.confirm_initiator_finish_ack_sent(&final_ack)
                })
                .unwrap_err(),
            RouteError::UnknownRoute
        );
        assert_eq!(i.status(), Status::Ready { remaining: 9 });
        assert_eq!(r.status(), Status::Ready { remaining: 9 });
        i.release();
        r.release();
    }

    #[test]
    fn equal_request_ids_never_share_ceremony_identity_or_approval() {
        let (i1, i2) = (Node::new("router-alias-i1"), Node::new("router-alias-i2"));
        let r = Node::new("router-alias-r");
        let x = [0x5A; 16];
        let (s1, s2) = (i1.session(), i2.session());
        let begin = |node: &Node, session| {
            node.router
                .start_initiator_with(
                    system_clock(),
                    &mut script([x]),
                    session,
                    initiator_bootstrap(),
                    None,
                )
                .unwrap()
        };
        let (first, second) = (begin(&i1, s1), begin(&i2, s2));
        assert_eq!(first, second, "byte-identical START from two authorities");
        let (a, b) = (r.session(), r.session());
        let accept_a = r.accept(a, &first.1);
        let accept_b = r.accept(b, &second.1);
        assert_ne!(accept_a, accept_b);
        let identity_a = exchange(&i1, s1, &r, a, &x, &accept_a);
        // A's SAS and approval cannot reach B.
        assert_eq!(
            r.router
                .with_run(b, &x, |run| run.approve_sas(&identity_a))
                .unwrap_err(),
            RouteError::Ceremony(CeremonyError::NoLiveSas)
        );
        r.local(a, &x, |run| run.cancel_sas(&identity_a));
        let identity_b = exchange(&i2, s2, &r, b, &x, &accept_b);
        assert_ne!(
            identity_a, identity_b,
            "equal request IDs, distinct ceremonies"
        );
        assert_eq!(
            r.router
                .with_run(b, &x, |run| run.approve_sas(&identity_a))
                .unwrap_err(),
            RouteError::Ceremony(CeremonyError::CeremonyIdentityMismatch)
        );
        assert_eq!(r.state(b, &x), "AwaitLocalApproval");
        assert_eq!(
            r.local(b, &x, |run| run.approve_sas(&identity_b)).output,
            SasApproval::Recorded
        );
        i1.release();
        i2.release();
        r.release();
    }

    #[test]
    fn initiator_routes_are_registered_before_start_and_regenerate_on_collision() {
        let node = Node::new("router-initiator");
        let a = node.session();
        let (y, z) = ([0x11; 16], [0x22; 16]);
        // A peer's START already owns (a, y).
        node.accept(a, &start_frame(&y));
        let begin = |session, ids: &mut ScriptedIds| {
            node.router
                .start_initiator_with(system_clock(), ids, session, initiator_bootstrap(), None)
                .unwrap()
        };
        let (id, start) = begin(a, &mut script([y, z]));
        assert_eq!(id, z.to_vec());
        assert_eq!(protocol::route_fields(&start).unwrap(), (1, z.as_slice()));
        // The discarded candidate's reservation was released with its run.
        assert_eq!(node.reserved(), 1);
        assert_eq!(node.state(a, &y), "ResponderAcceptSentAwaitInitiatorKey");
        assert_eq!(node.state(a, &z), "InitiatorAwaitAccept");
        // The authority-wide reservation still refuses z on another session; y is free there.
        let b = node.session();
        assert_eq!(begin(b, &mut script([z, y])).0, y.to_vec());
        assert_eq!((node.reserved(), node.routes()), (2, 3));
        // An echoed START reaches the Initiator run, which (not the router) rejects it.
        assert_eq!(node.router.deliver(a, &start).unwrap_err(), BAD);
        assert_eq!((node.reserved(), node.routes()), (1, 2));
        node.release();
    }

    #[test]
    fn dropping_the_router_releases_every_routed_resource() {
        let (i, si, r, sr, id, start) = initiated("router-drop");
        let accept = r.accept(sr, &start);
        exchange(&i, si, &r, sr, &id, &accept);
        r.accept(r.session(), &start_frame(&[0x44; 16]));
        r.initiate(r.session());
        assert_eq!(
            (r.pending(), r.reserved(), r.status()),
            (1, 1, Status::Busy)
        );
        let Node {
            authority,
            executor,
            router,
            ..
        } = r;
        drop(router);
        {
            let shared = executor.0.shared.lock().unwrap();
            assert_eq!(
                (
                    shared.pending_responders,
                    shared.preliminary_operations,
                    shared.initiator_request_ids.len(),
                    shared.active,
                    shared.remaining,
                ),
                (0, 0, 0, None, 9)
            );
        }
        drop(executor);
        authority.release().unwrap();
        i.release();
    }

    const CLOSED: RouteError = RouteError::UnknownSession;

    /// A closing or closed session admits nothing: no START, frame, local action, Initiator, or
    /// second close reaches the limiter, a run, or any resource.
    fn assert_rejects_everything(node: &Node, session: SessionHandle) {
        let x = [0x5E; 16];
        assert_eq!(node.receive(session, &start_frame(&x)), Err(CLOSED));
        assert_eq!(
            node.router
                .deliver(session, &initiator_key(&x))
                .unwrap_err(),
            CLOSED
        );
        assert_eq!(
            node.router.with_run(session, &x, |_| Ok(())).unwrap_err(),
            CLOSED
        );
        assert_eq!(
            node.router
                .start_initiator(session, initiator_bootstrap(), None),
            Err(CLOSED)
        );
        assert_eq!(node.router.close_session(session), Err(CLOSED));
        assert_eq!(
            node.router
                .poll_session_deadlines(session, &mut DeadlineCursor::default())
                .unwrap_err(),
            CLOSED
        );
    }

    /// For this thread only: on reaching `at`, announce it on `arrived`, then wait for `resume`.
    fn pause_at(at: Point, arrived: Sender<()>, resume: Receiver<()>) {
        test_hook::install(move |point| {
            if point == at {
                arrived.send(()).unwrap();
                resume.recv().unwrap();
            }
        });
    }

    type Closed = (Result<(), RouteError>, (usize, usize, usize, usize));

    /// Closes `session` on a new thread. Its teardown reports the in-flight count each time it
    /// is about to wait; the thread returns the outcome and the resources at return.
    fn close_on<'scope>(
        scope: &'scope Scope<'scope, '_>,
        node: &'scope Node,
        session: SessionHandle,
    ) -> (ScopedJoinHandle<'scope, Closed>, Receiver<usize>) {
        let (waiting, waits) = mpsc::channel();
        let handle = scope.spawn(move || {
            test_hook::install(move |point| {
                if let Point::CloseWaiting { in_flight } = point {
                    waiting.send(in_flight).unwrap();
                }
            });
            let closed = node.router.close_session(session);
            (closed, node.resources())
        });
        (handle, waits)
    }

    fn bootstrap_mac(request_id: &[u8]) -> Vec<u8> {
        Message::BootstrapMac {
            request_id: request_id.to_vec(),
            sender: protocol::Role::Initiator,
            mac: [0; 32],
        }
        .encode()
        .unwrap()
    }

    #[test]
    fn an_unknown_non_start_route_closes_a_one_run_session_without_guessing_that_run() {
        let (i, si, r, a, id, start) = initiated("router-unknown-one");
        let accept = r.accept(a, &start);
        assert_eq!(
            i.router.deliver(si, &accept).unwrap().output,
            Inbound::Accept
        );
        i.local(si, &id, |run| run.authorize(&i.authority));
        let ikey = i.local(si, &id, |run| run.expose_key()).output;
        let limiter = r.limiter();
        assert_eq!(r.resources(), (1, 1, 0, 0));
        // X's own INITIATOR_KEY under an ID with no route on A. Had it fallen back to A's only
        // run, that run would have answered (`InitiatorKey` or its own failure).
        let misrouted = with_request_id(&ikey, &[0x77; 16]);
        assert_eq!(
            r.router.deliver(a, &misrouted).unwrap_err(),
            RouteError::SessionProtocolFailure
        );
        // Already torn down when reported: X terminal, its route and slot gone, no result.
        assert_eq!(r.resources(), (0, 0, 0, 0));
        assert_eq!(r.status(), Status::Ready { remaining: 10 });
        assert_eq!(r.limiter(), limiter);
        assert_rejects_everything(&r, a);
        assert_eq!(r.router.deliver(a, &ikey).unwrap_err(), CLOSED);
        // The handle is never live again; a new session is fresh and owes nothing to A.
        let b = r.session();
        assert_ne!(a, b);
        r.accept(b, &start);
        assert_eq!(r.limiter().rolling, limiter.rolling + 1);
        assert_eq!(r.state(b, &id), "ResponderAcceptSentAwaitInitiatorKey");
        i.release();
        r.release();
    }

    #[test]
    fn an_unknown_non_start_route_fails_every_run_on_its_session_and_only_that_session() {
        let r = Node::new("router-unknown-many");
        let clock = ManualClock::new();
        let (a, b) = (r.session(), r.session());
        let (x, y, z, q) = ([1; 16], [2; 16], [3; 16], [9; 16]);
        for (session, id) in [(a, x), (a, y), (a, z), (b, x)] {
            assert!(matches!(
                r.receive_at(&clock, session, &start_frame(&id)),
                Ok(StartRouting::Accepted(_))
            ));
        }
        assert_eq!(r.resources(), (4, 4, 0, 0));
        let limiter = r.limiter();
        clock.advance(Duration::from_secs(30));
        assert_eq!(
            r.router.deliver(a, &bootstrap_mac(&q)).unwrap_err(),
            RouteError::SessionProtocolFailure
        );
        // Q reached nobody; X, Y, and Z on A all ended; B's equal-ID X is untouched.
        assert_eq!(r.resources(), (1, 1, 0, 0));
        assert_eq!(r.status(), Status::Ready { remaining: 10 });
        assert_eq!(r.limiter(), limiter, "no limiter refund or reset");
        assert_rejects_everything(&r, a);
        assert_eq!(r.state(b, &x), "ResponderAcceptSentAwaitInitiatorKey");
        // B's deadlines were neither refreshed nor disturbed.
        clock.advance(INACTIVITY_DEADLINE - Duration::from_secs(30) - Duration::from_nanos(1));
        assert_eq!(
            r.local(b, &x, |run| run.poll_deadlines()).output,
            DeadlineOutcome::Active
        );
        clock.advance(Duration::from_nanos(1));
        assert!(matches!(
            r.local(b, &x, |run| run.poll_deadlines()).output,
            DeadlineOutcome::TimedOut(ref t) if t.expired() == Deadline::Inactivity
        ));
        // B is still open and routable.
        r.refill();
        r.accept(b, &start_frame(&y));
        assert_eq!(r.resources(), (1, 1, 0, 0));
        r.release();
    }

    #[test]
    fn an_unknown_route_after_exposure_keeps_the_opportunity_and_sends_nothing() {
        let (i, si, r, sr, id, start) = initiated("router-unknown-exposed");
        let accept = r.accept(sr, &start);
        exchange(&i, si, &r, sr, &id, &accept);
        r.accept(sr, &start_frame(&[0x44; 16]));
        assert_eq!(r.status(), Status::Busy);
        assert_eq!(r.resources(), (2, 1, 0, 0));
        let cancel = Message::Cancel {
            request_id: vec![0x99; 16],
            sender: protocol::Role::Initiator,
            reason: CancelReason::UserCancellation,
            mac: [0; 32],
        }
        .encode()
        .unwrap();
        // No authenticated statement names the exposed run, so nothing is sent for it.
        assert_eq!(
            r.router.deliver(sr, &cancel).unwrap_err(),
            RouteError::SessionProtocolFailure
        );
        // SAS, approval, and session state dropped, then the guard released; the opportunity
        // stays spent and no result exists.
        assert_eq!(r.status(), Status::Ready { remaining: 9 });
        assert_eq!(r.resources(), (0, 0, 0, 0));
        assert_rejects_everything(&r, sr);
        // The peer was not notified.
        assert_eq!(i.state(si, &id), "AwaitLocalApproval");
        i.release();
        r.release();
    }

    #[test]
    fn a_non_start_frame_for_a_start_still_being_admitted_fails_only_that_admission() {
        let r = Node::new("router-unknown-admitting");
        let a = r.session();
        let (x, y) = ([1; 16], [2; 16]);
        r.accept(a, &start_frame(&y));
        let (arrived, arrival) = mpsc::channel();
        let (resume, resumed) = mpsc::channel();
        thread::scope(|scope| {
            let admit = scope.spawn(|| {
                pause_at(Point::ResponderAdmitted, arrived, resumed);
                r.receive(a, &start_frame(&x))
            });
            arrival.recv().unwrap();
            // The key is claimed, so this frame is out of order for X, not an unknown route.
            assert_eq!(r.router.deliver(a, &initiator_key(&x)).unwrap_err(), BAD);
            resume.send(()).unwrap();
            assert_eq!(admit.join().unwrap(), Err(BAD));
        });
        // X's admission was discarded with its slot; A and Y stayed live.
        assert_eq!(r.resources(), (1, 1, 0, 0));
        assert_eq!(r.state(a, &y), "ResponderAcceptSentAwaitInitiatorKey");
        r.release();
    }

    #[test]
    fn closing_during_responder_admission_waits_for_its_resources_and_suppresses_accept() {
        let r = Node::new("router-close-admission");
        let (a, b) = (r.session(), r.session());
        r.accept(b, &start_frame(&[2; 16]));
        let (arrived, arrival) = mpsc::channel();
        let (resume, resumed) = mpsc::channel();
        thread::scope(|scope| {
            let admit = scope.spawn(|| {
                pause_at(Point::ResponderAdmitted, arrived, resumed);
                r.receive(a, &start_frame(&[1; 16]))
            });
            arrival.recv().unwrap();
            // Paused after limiter admission with a permit and a pending slot held.
            let charged = r.limiter();
            assert_eq!((charged.tokens, charged.rolling), (2, 2));
            assert_eq!(r.resources(), (2, 2, 1, 0));
            let (close, waits) = close_on(scope, &r, a);
            // Close is now waiting on the one in-flight admission; A admits nothing new.
            assert_eq!(waits.recv().unwrap(), 1);
            assert_rejects_everything(&r, a);
            assert!(!close.is_finished());
            assert_eq!(r.resources(), (2, 2, 1, 0));
            resume.send(()).unwrap();
            // The admission observed the closing session: no ACCEPT, no route.
            assert_eq!(admit.join().unwrap(), Err(CLOSED));
            // When close returned, A's permit and slot were already released; B's remain.
            assert_eq!(close.join().unwrap(), (Ok(()), (1, 1, 0, 0)));
            // START admission is never refunded and nothing else was charged.
            assert_eq!(r.limiter(), charged);
        });
        assert_eq!(r.state(b, &[2; 16]), "ResponderAcceptSentAwaitInitiatorKey");
        assert_eq!(r.status(), Status::Ready { remaining: 10 });
        r.release();
    }

    #[test]
    fn closing_with_only_admitting_claims_waits_for_every_admission() {
        let r = Node::new("router-close-claims");
        let a = r.session();
        let (arrived, arrival) = mpsc::channel();
        thread::scope(|scope| {
            let mut resumes = Vec::new();
            let admissions: Vec<_> = [[1; 16], [2; 16]]
                .into_iter()
                .map(|id| {
                    let (resume, resumed) = mpsc::channel();
                    resumes.push(resume);
                    let arrived = arrived.clone();
                    let r = &r;
                    scope.spawn(move || {
                        pause_at(Point::ResponderAdmitted, arrived, resumed);
                        r.receive(a, &start_frame(&id))
                    })
                })
                .collect();
            arrival.recv().unwrap();
            arrival.recv().unwrap();
            // Both permits and two slots held; no route is Active yet, both keys are claimed.
            assert_eq!(r.resources(), (2, 2, 2, 0));
            assert!(
                r.router
                    .table
                    .lock()
                    .unwrap()
                    .routes
                    .values()
                    .all(|route| matches!(route, Route::Admitting { .. }))
            );
            let (close, waits) = close_on(scope, &r, a);
            assert_eq!(waits.recv().unwrap(), 2);
            assert_rejects_everything(&r, a);
            assert!(!close.is_finished());
            let mut admissions = admissions.into_iter();
            resumes[0].send(()).unwrap();
            assert_eq!(admissions.next().unwrap().join().unwrap(), Err(CLOSED));
            // One admission has unwound and released its permit and slot; close still waits.
            assert_eq!(r.resources(), (1, 1, 1, 0));
            assert!(!close.is_finished());
            resumes[1].send(()).unwrap();
            assert_eq!(admissions.next().unwrap().join().unwrap(), Err(CLOSED));
            assert_eq!(close.join().unwrap(), (Ok(()), (0, 0, 0, 0)));
        });
        // Both limiter charges stay; no SAS opportunity was involved.
        let limiter = r.limiter();
        assert_eq!((limiter.tokens, limiter.rolling), (2, 2));
        assert_eq!(r.status(), Status::Ready { remaining: 10 });
        r.release();
    }

    #[test]
    fn closing_during_initiator_creation_releases_the_reservation_and_suppresses_start() {
        let node = Node::new("router-close-initiator");
        let (a, b) = (node.session(), node.session());
        node.initiate(b);
        let (arrived, arrival) = mpsc::channel();
        let (resume, resumed) = mpsc::channel();
        thread::scope(|scope| {
            let create = scope.spawn(|| {
                pause_at(Point::InitiatorStarted, arrived, resumed);
                node.router.start_initiator(a, initiator_bootstrap(), None)
            });
            arrival.recv().unwrap();
            // START is built and its generated ID reserved, but nothing is routed yet.
            assert_eq!(node.resources(), (1, 0, 0, 2));
            let (close, waits) = close_on(scope, &node, a);
            assert_eq!(waits.recv().unwrap(), 1);
            assert_rejects_everything(&node, a);
            assert!(!close.is_finished());
            assert_eq!(node.reserved(), 2);
            resume.send(()).unwrap();
            // No usable START for the closed session.
            assert_eq!(create.join().unwrap(), Err(CLOSED));
            // The reservation was released before close returned; B's Initiator remains.
            assert_eq!(close.join().unwrap(), (Ok(()), (1, 0, 0, 1)));
        });
        assert_eq!(node.status(), Status::Ready { remaining: 10 });
        node.release();
    }

    #[test]
    fn closing_during_an_entered_run_operation_waits_and_then_terminates_the_run() {
        let (i, si, r, sr, id, start) = initiated("router-close-dispatch");
        let accept = r.accept(sr, &start);
        assert_eq!(
            i.router.deliver(si, &accept).unwrap().output,
            Inbound::Accept
        );
        i.local(si, &id, |run| run.authorize(&i.authority));
        let ikey = i.local(si, &id, |run| run.expose_key()).output;
        let (arrived, arrival) = mpsc::channel();
        let (resume, resumed) = mpsc::channel::<()>();
        thread::scope(|scope| {
            let op = scope.spawn(|| {
                r.router.with_run(sr, &id, move |run| {
                    arrived.send(()).unwrap();
                    resumed.recv().unwrap();
                    // Close never touched the run while this operation held it.
                    assert_eq!(
                        run.state_label_for_test(),
                        "ResponderAcceptSentAwaitInitiatorKey"
                    );
                    run.receive_initiator_key(&ikey)
                })
            });
            arrival.recv().unwrap();
            let (close, waits) = close_on(scope, &r, sr);
            assert_eq!(waits.recv().unwrap(), 1);
            assert_rejects_everything(&r, sr);
            assert!(!close.is_finished());
            resume.send(()).unwrap();
            // Entered before the close point, so it completes and keeps its outcome.
            let done = op.join().unwrap().unwrap();
            assert!(done.result.is_none());
            // Then close terminated the run: route, slot, and permit all gone.
            assert_eq!(close.join().unwrap(), (Ok(()), (0, 0, 0, 0)));
        });
        assert_eq!(r.status(), Status::Ready { remaining: 10 });
        i.release();
        r.release();
    }

    #[test]
    fn uncertain_session_teardown_fails_closed_and_never_reopens() {
        let r = Node::new("router-close-uncertain");
        let (a, b, c) = (r.session(), r.session(), r.session());
        let x = [1; 16];
        for session in [a, b, c] {
            r.accept(session, &start_frame(&x));
        }
        // A poisoned lifecycle admits nothing and cannot be reported closed.
        let lifecycle = r.router.table.lock().unwrap().sessions[&a.session].clone();
        let _ = thread::spawn(move || {
            let _activity = lifecycle.activity.lock().unwrap();
            panic!("simulate uncertain session state");
        })
        .join();
        assert_eq!(r.router.close_session(a), Err(uncertain()));
        assert_eq!(r.receive(a, &start_frame(&[2; 16])), Err(uncertain()));
        assert_eq!(
            r.router.with_run(a, &x, |_| Ok(())).unwrap_err(),
            uncertain()
        );
        // Uncertain run cleanup leaves the session CLOSING for good: never reported closed.
        let run = match r.router.table.lock().unwrap().routes.get(&RoutingKey {
            session: b,
            request_id: x.to_vec(),
        }) {
            Some(Route::Active(run)) => run.clone(),
            _ => unreachable!(),
        };
        let _ = thread::spawn(move || {
            let _run = run.lock().unwrap();
            panic!("simulate uncertain run state");
        })
        .join();
        assert_eq!(r.router.close_session(b), Err(uncertain()));
        assert_rejects_everything(&r, b);
        assert!(
            r.router
                .table
                .lock()
                .unwrap()
                .sessions
                .contains_key(&b.session)
        );
        // Other sessions are unaffected.
        assert_eq!(r.state(c, &x), "ResponderAcceptSentAwaitInitiatorKey");
        r.router.close_session(c).unwrap();
        r.release();
    }

    const MAX: usize = MAX_CEREMONY_POLLS_PER_CALL;

    /// A 16-byte request ID whose order is `n`'s.
    fn ordered(n: u16) -> [u8; 16] {
        let mut id = [0; 16];
        id[..2].copy_from_slice(&n.to_be_bytes());
        id
    }

    /// Routes an Initiator on `session` under `id`, with the ceremony clock `clock`.
    fn initiate_as(node: &Node, clock: &Arc<ManualClock>, session: SessionHandle, id: [u8; 16]) {
        let (routed, _) = node
            .router
            .start_initiator_with(
                clock.clone(),
                &mut script([id]),
                session,
                initiator_bootstrap(),
                None,
            )
            .unwrap();
        assert_eq!(routed, id.to_vec());
    }

    /// One deadline-driver call; nothing in these tests expires, and no call inspects a route
    /// twice or exceeds the work cap.
    fn poll_live(node: &Node, session: SessionHandle, cursor: &mut DeadlineCursor) -> Vec<Vec<u8>> {
        let poll = node.router.poll_session_deadlines(session, cursor).unwrap();
        assert!(poll.event.is_none());
        assert!(poll.inspected <= MAX);
        assert_eq!(poll.inspected, poll.trace.len());
        let ids: Vec<_> = poll.trace.into_iter().map(|(id, _)| id).collect();
        let mut distinct = ids.clone();
        distinct.sort();
        distinct.dedup();
        assert_eq!(distinct.len(), ids.len(), "a route twice in one call");
        ids
    }

    #[test]
    fn deadline_polls_are_bounded_per_call_and_reach_every_route_in_turn() {
        let r = Node::new("router-deadline-fair");
        let clock = ManualClock::new();
        let (a, b, c) = (r.session(), r.session(), r.session());
        // More local Initiators on A than the pending Responder cap or two batches: routes are
        // not limited to 4, so the driver cannot assume they are.
        let n = 2 * MAX + 3;
        let ids: Vec<Vec<u8>> = (1..=n as u16).map(|i| ordered(i).to_vec()).collect();
        for i in 1..=n as u16 {
            initiate_as(&r, &clock, a, ordered(i));
        }
        // B's routes (IDs below and above A's) must never be visited from A.
        for i in [0, 500, 999] {
            initiate_as(&r, &clock, b, ordered(i));
        }
        let mut cursor = DeadlineCursor::default();
        let mut visited = Vec::new();
        for _ in 0..6 {
            let before = r.routes();
            let batch = poll_live(&r, a, &mut cursor);
            assert_eq!(batch.len(), MAX, "a full batch while more routes exist");
            visited.extend(batch);
            assert_eq!(r.routes(), before);
        }
        // Strict round robin: every route once before any route twice, then again in turn,
        // wrapping safely at the end.
        let cycle: Vec<_> = ids.iter().cycle().take(visited.len()).cloned().collect();
        assert_eq!(visited, cycle);
        assert_eq!(r.state(b, &ordered(0)), "InitiatorAwaitAccept");

        // Per-call selection work does not grow with the route count: 200 more routes on C cost
        // each call the same number of ordered-map seeks, and all 200 are reached in 25 calls.
        let many: Vec<_> = (1000..1200).map(|i| ordered(i).to_vec()).collect();
        for i in 1000..1200 {
            initiate_as(&r, &clock, c, ordered(i));
        }
        let mut cursor = DeadlineCursor::default();
        let mut visited = Vec::new();
        for _ in 0..25 {
            let poll = r.router.poll_session_deadlines(c, &mut cursor).unwrap();
            assert_eq!((poll.inspected, poll.seeks), (MAX, MAX));
            assert!(poll.trace.iter().all(|(_, how)| *how == Inspected::Polled));
            visited.extend(poll.trace.into_iter().map(|(id, _)| id));
        }
        assert_eq!(visited, many);
        // Reaching the end wraps within the same bounded call: one extra seek.
        let poll = r.router.poll_session_deadlines(c, &mut cursor).unwrap();
        assert_eq!((poll.inspected, poll.seeks), (MAX, MAX + 1));
        assert_eq!(poll.trace[0].0, many[0]);
        // Polling changed nothing: no route, reservation, or state.
        assert_eq!(r.resources(), (n + 3 + 200, 0, 0, n + 3 + 200));
        for session in [a, b, c] {
            r.router.close_session(session).unwrap();
        }
        assert_eq!(r.resources(), (0, 0, 0, 0));
        r.release();
    }

    #[test]
    fn deadline_cursor_survives_route_removal_insertion_and_few_routes() {
        let r = Node::new("router-deadline-churn");
        let clock = ManualClock::new();
        let a = r.session();
        let ids =
            |ns: &[u16]| -> Vec<Vec<u8>> { ns.iter().map(|n| ordered(*n).to_vec()).collect() };
        for n in (10..=120).step_by(10) {
            initiate_as(&r, &clock, a, ordered(n));
        }
        let mut cursor = DeadlineCursor::default();
        assert_eq!(
            poll_live(&r, a, &mut cursor),
            ids(&[10, 20, 30, 40, 50, 60, 70, 80])
        );
        // Remove routes before (20), exactly at (80), and after (100) the cursor; insert one
        // before (15) and one after (85) it.
        for n in [20, 80, 100] {
            r.local(a, &ordered(n), |run| run.terminate());
        }
        initiate_as(&r, &clock, a, ordered(15));
        initiate_as(&r, &clock, a, ordered(85));
        // Resumes after the removed cursor key, wraps, and reaches both insertions; nothing
        // removed is ever visited and nothing restarts from the beginning.
        assert_eq!(
            poll_live(&r, a, &mut cursor),
            ids(&[85, 90, 110, 120, 10, 15, 30, 40])
        );
        assert_eq!(
            poll_live(&r, a, &mut cursor),
            ids(&[50, 60, 70, 85, 90, 110, 120, 10])
        );
        // The map holds exactly the live routes: no index or tombstone remains for the removed.
        assert_eq!(r.resources(), (11, 0, 0, 11));

        // Fewer routes than the cap: each call reaches each route once and stops.
        let b = r.session();
        let mut cursor = DeadlineCursor::default();
        assert!(poll_live(&r, b, &mut cursor).is_empty());
        initiate_as(&r, &clock, b, ordered(7));
        for _ in 0..3 {
            assert_eq!(poll_live(&r, b, &mut cursor), ids(&[7]));
        }
        initiate_as(&r, &clock, b, ordered(3));
        assert_eq!(poll_live(&r, b, &mut cursor), ids(&[3, 7]));
        assert_eq!(poll_live(&r, b, &mut cursor), ids(&[3, 7]));
        for session in [a, b] {
            r.router.close_session(session).unwrap();
        }
        assert_eq!(r.resources(), (0, 0, 0, 0));
        r.release();
    }

    #[test]
    fn a_deadline_poll_never_removes_a_replacement_run_under_a_reused_key() {
        let r = Node::new("router-deadline-reuse");
        let (old_clock, new_clock) = (ManualClock::new(), ManualClock::new());
        let a = r.session();
        let k = ordered(5);
        initiate_as(&r, &old_clock, a, k);
        let (arrived, arrival) = mpsc::channel();
        let (resume, resumed) = mpsc::channel();
        thread::scope(|scope| {
            let poll = scope.spawn(|| {
                pause_at(Point::DeadlineSelected, arrived, resumed);
                r.router
                    .poll_session_deadlines(a, &mut DeadlineCursor::default())
            });
            // The driver holds the old run's `Arc` with no lock. Meanwhile that run ends, its
            // route and reservation go, and a fresh run is routed under the same key.
            arrival.recv().unwrap();
            r.local(a, &k, |run| run.terminate());
            assert_eq!(r.resources(), (0, 0, 0, 0));
            initiate_as(&r, &new_clock, a, k);
            resume.send(()).unwrap();
            let polled = poll.join().unwrap().unwrap();
            // It polled the old, finished run: no event, and the replacement stays routed.
            assert_eq!(polled.inspected, 1);
            assert!(polled.event.is_none());
        });
        assert_eq!(r.resources(), (1, 0, 0, 1));
        assert_eq!(r.state(a, &k), "InitiatorAwaitAccept");
        // The replacement keeps its own deadlines: the old clock is irrelevant to it.
        old_clock.advance(ABSOLUTE_DEADLINE);
        let mut cursor = DeadlineCursor::default();
        assert_eq!(poll_live(&r, a, &mut cursor), vec![k.to_vec()]);
        new_clock.advance(INACTIVITY_DEADLINE);
        let polled = r.router.poll_session_deadlines(a, &mut cursor).unwrap();
        assert!(matches!(
            polled.event,
            Some(DeadlineEvent { ref request_id, ended: DeadlineEnded::TimedOut(ref t) })
                if *request_id == k.to_vec() && t.expired() == Deadline::Inactivity
        ));
        assert_eq!(r.resources(), (0, 0, 0, 0));
        r.release();
    }

    #[test]
    fn closing_during_a_deadline_poll_waits_for_its_current_run_only() {
        let r = Node::new("router-deadline-close");
        let clock = ManualClock::new();
        let (a, b) = (r.session(), r.session());
        for n in 1..=3 {
            initiate_as(&r, &clock, a, ordered(n));
        }
        initiate_as(&r, &clock, b, ordered(9));
        let (arrived, arrival) = mpsc::channel();
        let (resume, resumed) = mpsc::channel();
        thread::scope(|scope| {
            let poll = scope.spawn(|| {
                pause_at(Point::DeadlineRunLocked, arrived, resumed);
                r.router
                    .poll_session_deadlines(a, &mut DeadlineCursor::default())
            });
            arrival.recv().unwrap();
            // The driver holds the first run's lock and its lease, but no table lock: other
            // routing work proceeds.
            assert_eq!(r.resources(), (4, 0, 0, 4));
            assert_eq!(r.state(b, &ordered(9)), "InitiatorAwaitAccept");
            let (close, waits) = close_on(scope, &r, a);
            assert_eq!(waits.recv().unwrap(), 1);
            assert_rejects_everything(&r, a);
            assert!(!close.is_finished());
            resume.send(()).unwrap();
            // Entered before the close point: it finished its one current run and stopped.
            let polled = poll.join().unwrap().unwrap();
            assert_eq!(polled.inspected, 1);
            assert_eq!(polled.trace, vec![(ordered(1).to_vec(), Inspected::Polled)]);
            assert_eq!(close.join().unwrap(), (Ok(()), (1, 0, 0, 1)));
        });
        assert_eq!(r.state(b, &ordered(9)), "InitiatorAwaitAccept");
        r.release();
    }
}
