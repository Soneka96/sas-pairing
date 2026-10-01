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
//! No socket, listener, byte transport, frame buffering, reconnect, or resume exists here.
#![allow(dead_code)] // Used only by tests until a transport adapter exists.
use crate::{
    CeremonyExecutor, Error as OwnerError, Role,
    ceremony::{
        CeremonyError, CompletionReceipt, PairingResult, PeerApproval, PeerCancellation,
        RemoteCeremony,
    },
    deadline::{Clock, system_clock},
    protocol::{self, Bootstrap},
    request_id::{OsRequestIds, RequestIdGenerator},
};
use std::{
    collections::{HashMap, HashSet, hash_map::Entry},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
};

static NEXT_ROUTER: AtomicU64 = AtomicU64::new(1);

/// One live local session context of one `Router`: "this locally distinct transport/session
/// context" and nothing more. It is not peer identity, authentication, possession, trust,
/// authorization, or ceremony identity, and it never appears on the wire or in any
/// cryptographic input. Only `Router::open_session` creates one. It names its router, so a
/// handle from another router is unknown here, and session numbers are never reissued, so a
/// closed handle stays invalid. Volatile: never persisted or resumed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct SessionHandle {
    router: u64,
    session: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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

struct Table {
    next_session: u64,
    next_claim: u64,
    sessions: HashSet<u64>,
    routes: HashMap<RoutingKey, Route>,
}

/// Session-bound routing for one pairing authority. Its resource controls (START limiter,
/// pending and preliminary caps, guard, opportunity budget) stay in the authority's shared
/// state, so sessions, and even several routers of one authority, share them. Dropping the
/// router drops every routed run, whose own cleanup releases its slot, reservation, or guard.
pub(crate) struct Router {
    id: u64,
    executor: CeremonyExecutor,
    table: Mutex<Table>,
}

/// Narrow local routing outcomes. `UnknownSession` and `UnknownRoute` mean only that the
/// input names no live local session or no routed run; they say nothing about the peer, its
/// authentication, an SAS, compromise, or the opportunity budget, and change nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RouteError {
    /// The handle names no live session of this router: never issued here, or closed.
    UnknownSession,
    /// No run is routed under this exact `(session, request_id)`; nothing was changed.
    UnknownRoute,
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

/// What a new START needs beyond its bytes: the Responder's local configuration.
struct NewResponder {
    clock: Clock,
    local: Bootstrap,
    expected: Option<Bootstrap>,
}

enum StartRoute {
    New(u64),
    Duplicate,
    Existing(Run),
}

impl Router {
    pub(crate) fn new(executor: CeremonyExecutor) -> Result<Self, RouteError> {
        let id = NEXT_ROUTER
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| uncertain())?;
        Ok(Self {
            id,
            executor,
            table: Mutex::new(Table {
                next_session: 1,
                next_claim: 1,
                sessions: HashSet::new(),
                routes: HashMap::new(),
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
        table.sessions.insert(session);
        Ok(SessionHandle {
            router: self.id,
            session,
        })
    }

    /// Ends a local session without waiting for or notifying the peer. Atomically the handle
    /// becomes unknown and every route under it, including START admissions in progress, is
    /// removed; the keys can never be reused because the handle is never reissued. Each
    /// removed run is then terminated through its existing cleanup: SAS, approval, and any
    /// pending final ACK are dropped before the guard is released; pending slots and request-ID
    /// reservations are released; consumed opportunities stay consumed; no result is created
    /// and no CANCEL is emitted. Nothing resumes on another session. The authority's START
    /// limiter, budget, and other controls are untouched.
    pub(crate) fn close_session(&self, session: SessionHandle) -> Result<(), RouteError> {
        let runs: Vec<Run> = {
            let mut guard = self.table()?;
            let table = &mut *guard;
            if !self.live(table, session) {
                return Err(RouteError::UnknownSession);
            }
            table.sessions.remove(&session.session);
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
        outcome
    }

    /// Inbound START on `session`. An exact duplicate or conflict for an existing key goes to
    /// that run (see `StartRouting`); a changed START for an existing key terminally fails it
    /// and is never a new candidate. Only a key that is absent is claimed atomically and then
    /// admitted, outside the table lock, through the unchanged Responder order: START limiter
    /// -> preliminary permit -> semantic validation -> pending slot -> ephemeral and commitment
    /// -> ACCEPT. The run is installed only after that succeeds; any failure removes the claim.
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
    /// never a fallback to another run: anything else is `UnknownRoute` with no effect. A START
    /// here reaches only an existing run; only `receive_start` admits a new one.
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
        let run = self.active(&key)?;
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
    /// ID from the frame itself.
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
        let run = self.active(&key)?;
        self.on_run(&key, &run, op)
    }

    /// Honest local Initiator on `session`: the core generates and reserves the 16-byte request
    /// ID exactly as `RemoteCeremony::initiator` does, then the run is registered under
    /// `(session, request_id)` before its START bytes are returned. If that key is already
    /// routed on this session (a peer-chosen START ID), the run is discarded, its reservation
    /// released, and a fresh ID generated, so colliding local state never reaches the wire.
    /// Returns `(request_id, START bytes)`.
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
        loop {
            if !self.live(&*self.table()?, session) {
                return Err(RouteError::UnknownSession);
            }
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
            let mut run = Some(run);
            let mut guard = self.table()?;
            let table = &mut *guard;
            let live = self.live(table, session);
            if live {
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
                Some(run) if live => drop(run),
                Some(_) => return Err(RouteError::UnknownSession),
            }
        }
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
        let claim = match self.classify_start(&key, bytes, new.is_some())? {
            StartRoute::New(claim) => claim,
            StartRoute::Duplicate => return Ok(StartRouting::Duplicate),
            StartRoute::Existing(run) => {
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
        // Bounded admission and its cryptography run without the table lock.
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
        let (ours, conflicted) = match table.routes.get(&key) {
            Some(Route::Admitting {
                claim: owner,
                conflicted,
                ..
            }) if *owner == claim => (true, *conflicted),
            // The session was closed meanwhile; its claims are gone.
            _ => (false, false),
        };
        match admitted {
            Ok((run, accept)) if ours && !conflicted => {
                table
                    .routes
                    .insert(key, Route::Active(Arc::new(Mutex::new(run))));
                Ok(StartRouting::Accepted(accept))
            }
            Ok((run, _accept)) => {
                // Conflicted or session closed: the run is made terminal (and its slot
                // released) before the key can be claimed again; the ACCEPT is never returned.
                drop(table);
                drop(run);
                if ours {
                    self.release_claim(&key, claim)?;
                    Err(CeremonyError::InvalidState.into())
                } else {
                    Err(RouteError::UnknownSession)
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

    /// One critical section: session check, then exactly one of claim-new (absent key, only
    /// when `claim_new`), exact in-progress duplicate, conflict (marks an in-progress claim
    /// conflicted so its admission is discarded), or the installed run.
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
        if !self.live(table, key.session) {
            return Err(RouteError::UnknownSession);
        }
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
                Ok(StartRoute::New(claim))
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
                Route::Active(run) => Ok(StartRoute::Existing(run.clone())),
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

    /// The installed run under exactly `key`. An in-progress START admission is not routable.
    fn active(&self, key: &RoutingKey) -> Result<Run, RouteError> {
        let table = self.table()?;
        if !self.live(&table, key.session) {
            return Err(RouteError::UnknownSession);
        }
        match table.routes.get(key) {
            Some(Route::Active(run)) => Ok(run.clone()),
            _ => Err(RouteError::UnknownRoute),
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
        let mut result = None;
        if ceremony.is_finished() {
            let mut table = self.table()?;
            if matches!(table.routes.get(key), Some(Route::Active(current)) if Arc::ptr_eq(current, run))
            {
                table.routes.remove(key);
                result = ceremony.result().cloned();
            }
        }
        Ok(Routed {
            output: outcome?,
            result,
        })
    }

    fn live(&self, table: &Table, session: SessionHandle) -> bool {
        session.router == self.id && table.sessions.contains(&session.session)
    }

    fn table(&self) -> Result<MutexGuard<'_, Table>, RouteError> {
        self.table.lock().map_err(|_| uncertain())
    }
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
    use std::{collections::VecDeque, sync::Barrier, thread, time::Duration};

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
        assert_eq!(
            r.router.deliver(b, &initiator_key(&x)).unwrap_err(),
            RouteError::UnknownRoute
        );
        assert_eq!(
            r.router.deliver(a, &initiator_key(&[8; 16])).unwrap_err(),
            RouteError::UnknownRoute
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
        let b = r.session();
        let accept = r.accept(a, &start);
        assert_eq!(
            i.router.deliver(si, &accept).unwrap().output,
            Inbound::Accept
        );
        i.local(si, &id, |run| run.authorize(&i.authority));
        let ikey = i.local(si, &id, |run| run.expose_key()).output;
        let limiter = r.limiter();
        // Session B has no run for this ID: rejected before reaching any run.
        assert_eq!(
            r.router.deliver(b, &ikey).unwrap_err(),
            RouteError::UnknownRoute
        );
        // Session A has no run for another ID: no fallback to A's only run.
        assert_eq!(
            r.router
                .deliver(a, &with_request_id(&ikey, &[0x77; 16]))
                .unwrap_err(),
            RouteError::UnknownRoute
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
        // Nothing is revived; a replayed START is only a completely new ceremony.
        assert_eq!(
            r.router.deliver(sr, &cancel).unwrap_err(),
            RouteError::UnknownRoute
        );
        assert_ne!(r.accept(sr, &start), accept);
        assert_eq!(r.state(sr, &id), "ResponderAcceptSentAwaitInitiatorKey");
        assert_eq!(r.local(sr, &id, |run| Ok(run.presentation())).output, None);
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
        // Later traffic reaches nothing and cannot alter or duplicate either result.
        assert_eq!(
            r.router.deliver(sr, &final_ack).unwrap_err(),
            RouteError::UnknownRoute
        );
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
}
