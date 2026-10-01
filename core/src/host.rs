//! Crate-private, socket-free host dispatch: the thin layer a future socket adapter drives
//! between one `TransportConnection` and its one `Router` session. Nothing here opens, reads,
//! writes, schedules, sleeps, or spawns. The adapter supplies received bytes, polls, a final-ACK
//! send confirmation, and a close; it receives, per call, at most one dispatched frame with at
//! most one protocol event, one outbound frame, and one `PairingResult`.
//!
//! Responsibilities stay split. The transport owns connection admission, bounded frame
//! assembly, its 10 s / 2 s frame deadlines, and teardown. The Router owns `(session,
//! request_id)` routing, START admission, and the runs. This layer only classifies each
//! complete frame at the protocol's dispatch boundary (`protocol::routable`: common fields, and
//! for START the structural candidate, never the bootstrap), calls `receive_start` or
//! `deliver`, maps the outcome, and ends the connection when its session can no longer
//! continue. It tracks no ceremony state, opens no session, and never bypasses frame assembly.
//!
//! Connection scope of each outcome:
//! - Structurally unroutable complete frame (wrong profile ID, request ID outside 1..=64): a
//!   codec/transport rejection (P3 §3.1, §11.1.1, §11.2). It reaches no run, admission, or
//!   limiter and cannot be attributed to any run, so the connection and its session end.
//! - Router session-fatal outcomes (`SessionProtocolFailure`: P3 §11.2 unknown route),
//!   `UnknownSession` (the session is already closing or closed), and `OwnershipUncertain`
//!   end the connection through the transport's one teardown, which settles the Router
//!   session before releasing the live count and keeps it held if cleanup is uncertain.
//! - Every other Router error is the outcome of one START attempt or one run (limiter or
//!   capacity refusal, semantic START rejection, wrong state, changed duplicate, MAC failure,
//!   ...), already applied by the Router and ceremony. The connection, its session, and its
//!   other runs continue.
//!
//! Outbound frames are produced, never sent here: returning bytes is not a send, and a local
//! send is never peer receipt. Only an INITIATOR_FINISH_ACK carries a send boundary: the
//! Initiator has no result until the adapter, after fully writing exactly those bytes, hands the
//! single-use `FinalAck` back to `confirm_sent`, which goes through the run's own
//! `confirm_initiator_finish_ack_sent`. Nothing is retained for retransmission and exact
//! duplicate inbound frames produce no repeated output.
//!
//! Ceremony deadlines are driven while idle by `poll_ceremony_deadlines`, a separate explicit
//! call (never folded into `receive` or the transport frame-deadline poll): one bounded,
//! cooperative pass over this connection's own Router session, which returns at most one
//! run-local deadline event and at most one timeout CANCEL frame. The deadline semantics are
//! the runs' own; this layer only drives them. Local ceremony actions (authorization, SAS
//! decisions, own MAC and INITIATOR_FINISH emission, local cancel, Initiator start) remain
//! direct Router actions. Clocks stay separate: the transport clock is the connection's, the
//! START limiter clock the authority's, and new Responders get a fresh production ceremony
//! clock (test-injectable).
//!
//! Lock order: no lock is held here. Every Router call returns, with its leases and guards
//! released, before any teardown, so the "no close from inside `with_run`" rule holds.
#![allow(dead_code)] // Used only by tests until a socket adapter exists.
use crate::{
    Error as OwnerError,
    ceremony::{CeremonyError, CompletionReceipt, PairingResult, PeerApproval, PeerCancellation},
    deadline::{Clock, Deadline, system_clock},
    protocol::{self, Bootstrap, CodecError, Routable},
    router::{
        DeadlineCursor, DeadlineEnded, DeadlineEvent, DeadlinePoll, Inbound, RouteError, Routed,
        SessionHandle, StartRouting,
    },
    transport::{Fed, TransportConnection, TransportError},
};

/// Why the connection ended. Every `Err` from a `HostConnection` method means the connection
/// is closed (or its teardown is uncertain and its live count held); errors that leave it live
/// are returned inside `Ok`. None of these is authentication, SAS-mismatch, compromise, or
/// opportunity-exhaustion evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HostError {
    /// A transport failure or refusal (`Closed`: it had already ended), or an uncertain
    /// teardown (`OwnershipUncertain`), which keeps the live count held.
    Transport(TransportError),
    /// A complete frame failed the dispatch boundary; it reached no Router state.
    Unroutable(CodecError),
    /// The Router session can no longer continue: `SessionProtocolFailure`, `UnknownSession`,
    /// or `OwnershipUncertain`.
    Routing(RouteError),
}

/// What the one dispatched frame did. Diagnostic and sequencing data only; outputs are in
/// `Dispatched::outbound` and `Dispatched::result`, never copied here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostEvent {
    /// A new START was admitted and its Responder run installed; the outbound frame is ACCEPT.
    StartAccepted,
    /// An exact duplicate START for an existing key: ignored, nothing sent.
    StartDuplicate,
    Accept,
    InitiatorKey,
    ResponderKey,
    /// A peer BOOTSTRAP_MAC verified, or an exact duplicate of the verified one.
    BootstrapMac(PeerApproval),
    /// R verified INITIATOR_FINISH; the outbound frame is RESPONDER_FINISH_ACK. No result yet.
    InitiatorFinish,
    /// An exact duplicate of the verified INITIATOR_FINISH: ignored, nothing sent.
    InitiatorFinishDuplicate,
    /// I verified RESPONDER_FINISH_ACK; the outbound frame is the final INITIATOR_FINISH_ACK,
    /// which needs `confirm_sent`. No result yet.
    ResponderFinishAck,
    /// R verified INITIATOR_FINISH_ACK and succeeded locally; the result is attached.
    InitiatorFinishAck,
    /// A verified peer CANCEL ended the run without a result.
    Cancel(PeerCancellation),
}

/// The one protocol frame the dispatched inbound transition produced, for the adapter to write.
/// Produced is not sent, and sent is not received by the peer.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outbound {
    /// ACCEPT or RESPONDER_FINISH_ACK. Nothing waits for or learns whether it is sent; a lost
    /// frame is never retried.
    Frame(Vec<u8>),
    /// The Initiator's final INITIATOR_FINISH_ACK and its single-use send confirmation.
    FinalAck(FinalAck),
}

impl Outbound {
    /// The exact frame to write.
    pub(crate) fn bytes(&self) -> &[u8] {
        match self {
            Self::Frame(bytes) => bytes,
            Self::FinalAck(ack) => &ack.bytes,
        }
    }
}

/// A produced INITIATOR_FINISH_ACK and the trusted-local capability to confirm its send. The
/// adapter keeps it while writing and passes it to `HostConnection::confirm_sent` only after
/// the complete frame was written locally; a partial or failed write is never confirmed, and
/// peer receipt is never known. Only this module creates one, from the exact bytes the run
/// produced, so no application-chosen bytes can be confirmed; it is not `Clone`, so it is
/// confirmed at most once. It is local plumbing, not cryptographic authority.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct FinalAck {
    session: SessionHandle,
    request_id: Vec<u8>,
    bytes: Vec<u8>,
}

impl FinalAck {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// The outcome of one complete frame the Router accepted.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Dispatched {
    /// The frame's request ID: the routing key on this connection, for local actions on that
    /// run. Routing and diagnostic data only, never identity.
    pub(crate) request_id: Vec<u8>,
    pub(crate) event: HostEvent,
    pub(crate) outbound: Option<Outbound>,
    /// Present exactly when this frame brought its run to local success (the Responder's
    /// final ACK); that run's route is already removed.
    pub(crate) result: Option<PairingResult>,
}

/// How one run ended by its own deadline processing. Run-local: the connection, its session, and
/// its other runs continue. None of these is a result, peer-authentication evidence, an SAS
/// mismatch, or an opportunity outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CeremonyDeadline {
    /// P3 §11.3 local timeout; which deadline is diagnostic only (one wire reason, `0x03`). Any
    /// authenticated CANCEL is the poll's `outbound` frame.
    TimedOut(Deadline),
    /// The fixed 60-second pending pre-exposure resource lifetime ended: a local resource
    /// outcome with nothing to send, not a timeout claim about the peer.
    PendingExpired,
    /// The run's ceremony clock was unusable, so it failed closed. Not a timeout.
    ClockUnavailable,
}

/// One terminal deadline outcome. The run is ALREADY terminal: no result, its SAS, approval,
/// and any pending final ACK dropped, its guard, pending slot, or request-ID reservation
/// released, and any consumed opportunity kept; its route is removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CeremonyDeadlineEvent {
    /// The run's routing key on this connection; routing and diagnostic data only.
    pub(crate) request_id: Vec<u8>,
    pub(crate) kind: CeremonyDeadline,
}

/// One bounded `poll_ceremony_deadlines`. There is never a `PairingResult`: no deadline can
/// produce success.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CeremonyPoll {
    /// Routes inspected by this call, at most `router::MAX_CEREMONY_POLLS_PER_CALL`.
    pub(crate) inspected: usize,
    pub(crate) event: Option<CeremonyDeadlineEvent>,
    /// The authenticated timeout CANCEL (reason `0x03`) the run built before dropping its
    /// shared SAS, as an ordinary frame: best effort, produced not sent, needing no send
    /// confirmation, never retried. The run is already terminal whether or not it is written.
    pub(crate) outbound: Option<Outbound>,
}

/// One `receive`: `consumed` leading input bytes were taken (the caller feeds the rest again),
/// and `frame` is the one complete frame finished and dispatched by this call, if any: its
/// outcome, or the Router's refusal of that attempt or run with the connection still live.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct HostFed {
    pub(crate) consumed: usize,
    pub(crate) frame: Option<Result<Dispatched, RouteError>>,
}

/// One live connection's host side: its `TransportConnection` (and so its one Router session
/// and live count) plus the local Responder configuration for new STARTs. Dropping it drops the
/// transport connection, whose own teardown runs once.
pub(crate) struct HostConnection<'r> {
    transport: TransportConnection<'r>,
    /// Local Responder configuration. Never taken from the wire, a request ID, or a peer
    /// bootstrap; cloned only into each new START admission.
    local: Bootstrap,
    expected: Option<Bootstrap>,
    /// Ceremony clock for new Responders: `None` in production (a fresh system clock each, as
    /// `Router::receive_start`); a test-injected hand clock otherwise. Never the transport clock.
    ceremony_clock: Option<Clock>,
    /// Where the next `poll_ceremony_deadlines` resumes in this session's routes. Local only.
    deadlines: DeadlineCursor,
}

impl<'r> HostConnection<'r> {
    /// Wraps an admitted connection (`AcceptPermit` -> `TransportConnection`); it opens no
    /// session and takes no other capacity.
    pub(crate) fn new(
        transport: TransportConnection<'r>,
        local: Bootstrap,
        expected: Option<Bootstrap>,
    ) -> Self {
        Self {
            transport,
            local,
            expected,
            ceremony_clock: None,
            deadlines: DeadlineCursor::default(),
        }
    }

    /// `new` with a hand ceremony clock for new Responders, distinct from the transport clock.
    #[cfg(test)]
    pub(crate) fn with_ceremony_clock(
        transport: TransportConnection<'r>,
        local: Bootstrap,
        expected: Option<Bootstrap>,
        clock: Clock,
    ) -> Self {
        Self {
            ceremony_clock: Some(clock),
            ..Self::new(transport, local, expected)
        }
    }

    /// This connection's one Router session, for local actions through `Router::with_run`.
    pub(crate) fn session(&self) -> SessionHandle {
        self.transport.session()
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.transport.is_closed()
    }

    /// Feeds received bytes to the transport assembler and dispatches the one frame they
    /// complete, if any. Remaining input is not taken: the caller feeds it again.
    pub(crate) fn receive(&mut self, input: &[u8]) -> Result<HostFed, HostError> {
        let Fed { consumed, frame } = self.transport.feed(input).map_err(HostError::Transport)?;
        let frame = match frame {
            Some(frame) => Some(self.dispatch(&frame)?),
            None => None,
        };
        Ok(HostFed { consumed, frame })
    }

    /// The transport frame-deadline poll; expiry ends the connection with no dispatch.
    pub(crate) fn poll_frame_deadlines(&mut self) -> Result<(), HostError> {
        self.transport
            .poll_frame_deadlines()
            .map_err(HostError::Transport)
    }

    /// Drives this connection's ceremony deadlines while no input arrives: one bounded pass of
    /// `Router::poll_session_deadlines` over this connection's own session only, resuming where
    /// the previous call stopped. It inspects at most `MAX_CEREMONY_POLLS_PER_CALL` routes,
    /// skips (never waits for) a run another operation holds or a START still being admitted,
    /// and stops at the first run that ends, so it returns at most one event and at most one
    /// outbound frame; the caller may poll again at once. It is never progress: it refreshes no
    /// deadline. A timeout, pending expiry, or unusable ceremony clock ends only that run; the
    /// connection stays live. A session already closing or closed, or uncertain cleanup, ends
    /// the connection through the transport's one teardown (live count held if uncertain).
    pub(crate) fn poll_ceremony_deadlines(&mut self) -> Result<CeremonyPoll, HostError> {
        if self.transport.is_closed() {
            return Err(HostError::Transport(TransportError::Closed));
        }
        let polled = self
            .transport
            .router()
            .poll_session_deadlines(self.transport.session(), &mut self.deadlines);
        let DeadlinePoll {
            inspected, event, ..
        } = match polled {
            Ok(poll) => poll,
            // `UnknownSession` or `OwnershipUncertain`: the session cannot continue.
            Err(error) => return Err(self.end(HostError::Routing(error))),
        };
        let mut outbound = None;
        let event = event.map(|DeadlineEvent { request_id, ended }| {
            let kind = match ended {
                DeadlineEnded::TimedOut(timeout) => {
                    outbound = timeout
                        .cancel()
                        .map(|cancel| Outbound::Frame(cancel.to_vec()));
                    CeremonyDeadline::TimedOut(timeout.expired())
                }
                DeadlineEnded::PendingExpired => CeremonyDeadline::PendingExpired,
                DeadlineEnded::ClockUnavailable => CeremonyDeadline::ClockUnavailable,
            };
            CeremonyDeadlineEvent { request_id, kind }
        });
        Ok(CeremonyPoll {
            inspected,
            event,
            outbound,
        })
    }

    /// The Initiator's P3 §9 send boundary: call only after the complete `sent.bytes()` frame
    /// was written locally. Its run's `confirm_initiator_finish_ack_sent` decides, against its
    /// exact pending bytes, deadlines, and state; on success the result is returned once, the
    /// route removed, and the guard released, while this connection stays live. A token of
    /// another connection, or for a run that already ended, creates nothing (`UnknownRoute`).
    pub(crate) fn confirm_sent(
        &mut self,
        sent: FinalAck,
    ) -> Result<Result<PairingResult, RouteError>, HostError> {
        if self.transport.is_closed() {
            return Err(HostError::Transport(TransportError::Closed));
        }
        let FinalAck {
            session,
            request_id,
            bytes,
        } = sent;
        if session != self.transport.session() {
            return Ok(Err(RouteError::UnknownRoute));
        }
        let confirmed = self
            .transport
            .router()
            .with_run(session, &request_id, |run| {
                run.confirm_initiator_finish_ack_sent(&bytes)
            });
        match confirmed {
            Ok(Routed {
                result: Some(result),
                ..
            }) => Ok(Ok(result)),
            // Unreachable: a confirmed run has succeeded and this call removed its route.
            Ok(Routed { result: None, .. }) => Err(self.end(HostError::Routing(
                RouteError::Ceremony(CeremonyError::Owner(OwnerError::OwnershipUncertain)),
            ))),
            Err(error) if ends_session(&error) => Err(self.end(HostError::Routing(error))),
            Err(error) => Ok(Err(error)),
        }
    }

    /// Explicit local close: the transport's one teardown.
    pub(crate) fn close(self) -> Result<(), HostError> {
        self.transport.close().map_err(HostError::Transport)
    }

    fn dispatch(&mut self, frame: &[u8]) -> Result<Result<Dispatched, RouteError>, HostError> {
        let router = self.transport.router();
        let session = self.transport.session();
        let routed = match protocol::routable(frame) {
            Ok(Routable::Start { request_id }) => {
                let clock = self.ceremony_clock.clone().unwrap_or_else(system_clock);
                router
                    .receive_start_with_clock(
                        clock,
                        session,
                        frame,
                        self.local.clone(),
                        self.expected.clone(),
                    )
                    .map(|start| {
                        let (event, outbound) = match start {
                            StartRouting::Accepted(accept) => {
                                (HostEvent::StartAccepted, Some(Outbound::Frame(accept)))
                            }
                            StartRouting::Duplicate => (HostEvent::StartDuplicate, None),
                        };
                        Dispatched {
                            request_id: request_id.to_vec(),
                            event,
                            outbound,
                            result: None,
                        }
                    })
            }
            Ok(Routable::Run { request_id }) => router
                .deliver(session, frame)
                .map(|routed| inbound(session, request_id, routed)),
            Err(error) => return Err(self.end(HostError::Unroutable(error))),
        };
        match routed {
            Err(error) if ends_session(&error) => Err(self.end(HostError::Routing(error))),
            other => Ok(other),
        }
    }

    /// Ends the connection through the transport's one teardown (Router session settled, then
    /// the live count released) and reports `cause`, or the transport's `OwnershipUncertain`
    /// if that teardown could not be established.
    fn end(&mut self, cause: HostError) -> HostError {
        match self.transport.close_in_place() {
            Ok(()) => cause,
            Err(error) => HostError::Transport(error),
        }
    }
}

/// Router outcomes after which this connection's session cannot continue.
fn ends_session(error: &RouteError) -> bool {
    matches!(
        error,
        RouteError::SessionProtocolFailure
            | RouteError::UnknownSession
            | RouteError::Ceremony(CeremonyError::Owner(OwnerError::OwnershipUncertain))
    )
}

fn inbound(session: SessionHandle, request_id: &[u8], routed: Routed<Inbound>) -> Dispatched {
    let (event, outbound) = match routed.output {
        Inbound::StartDuplicate => (HostEvent::StartDuplicate, None),
        Inbound::Accept => (HostEvent::Accept, None),
        Inbound::InitiatorKey => (HostEvent::InitiatorKey, None),
        Inbound::ResponderKey => (HostEvent::ResponderKey, None),
        Inbound::BootstrapMac(approval) => (HostEvent::BootstrapMac(approval), None),
        Inbound::Completion(CompletionReceipt::SendResponderFinishAck(ack)) => {
            (HostEvent::InitiatorFinish, Some(Outbound::Frame(ack)))
        }
        Inbound::Completion(CompletionReceipt::AlreadyAccepted) => {
            (HostEvent::InitiatorFinishDuplicate, None)
        }
        Inbound::Completion(CompletionReceipt::SendInitiatorFinishAck(bytes)) => (
            HostEvent::ResponderFinishAck,
            Some(Outbound::FinalAck(FinalAck {
                session,
                request_id: request_id.to_vec(),
                bytes,
            })),
        ),
        Inbound::Completion(CompletionReceipt::Succeeded) => (HostEvent::InitiatorFinishAck, None),
        Inbound::Cancel(cancel) => (HostEvent::Cancel(cancel), None),
    };
    Dispatched {
        request_id: request_id.to_vec(),
        event,
        outbound,
        result: routed.result,
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::{
        CeremonyExecutor, Status, TrustedAuthority,
        ceremony::{
            BootstrapMacEmission, DeadlineOutcome, FinishEmission, LocalCancellation,
            RemoteCeremony, SasApproval,
        },
        deadline::{ABSOLUTE_DEADLINE, INACTIVITY_DEADLINE, ManualClock},
        protocol::{CancelReason, MAX_FRAME, Message, PROFILE_ID, Role},
        request_id::{OsRequestIds, RequestIdGenerator},
        router::{MAX_CEREMONY_POLLS_PER_CALL, Router},
        start_limiter::{REFILL_PERIOD, StartLimiterSnapshot},
        test_hook::{self, Point},
        transport::{AcceptPermit, IDLE_READ_DEADLINE, WHOLE_FRAME_DEADLINE},
    };
    use serde_json::Value;
    use std::{
        sync::{Arc, PoisonError, mpsc},
        thread,
        time::Duration,
    };

    const NS: Duration = Duration::from_nanos(1);
    const MS: Duration = Duration::from_millis(1);
    const BAD: RouteError = RouteError::Ceremony(CeremonyError::InvalidState);

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
    fn initiator_bootstrap() -> Bootstrap {
        match protocol::decode(&vector("START")).unwrap().message {
            Message::Start { bootstrap, .. } => bootstrap,
            _ => unreachable!(),
        }
    }
    fn responder_bootstrap() -> Bootstrap {
        match protocol::decode(&vector("ACCEPT")).unwrap().message {
            Message::Accept { bootstrap, .. } => bootstrap,
            _ => unreachable!(),
        }
    }
    /// The fixture Initiator's key with another application identity and shared context.
    fn bootstrap_with(application_identity: &[u8], shared_context: &[u8]) -> Bootstrap {
        let b = initiator_bootstrap();
        Bootstrap::new(
            application_identity.to_vec(),
            b.key_algorithm().to_vec(),
            b.public_key().to_vec(),
            shared_context.to_vec(),
        )
        .unwrap()
    }
    fn start_with(request_id: &[u8], bootstrap: Bootstrap) -> Vec<u8> {
        Message::Start {
            request_id: request_id.to_vec(),
            bootstrap,
        }
        .encode()
        .unwrap()
    }
    fn start(request_id: &[u8]) -> Vec<u8> {
        start_with(request_id, initiator_bootstrap())
    }
    /// The same request ID with other canonical bytes (another application identity).
    fn changed_start(request_id: &[u8]) -> Vec<u8> {
        let context = initiator_bootstrap().shared_context().to_vec();
        start_with(request_id, bootstrap_with(b"another application", &context))
    }
    fn initiator_key(request_id: &[u8]) -> Vec<u8> {
        Message::InitiatorKey {
            request_id: request_id.to_vec(),
            public_key: [9; 32],
        }
        .encode()
        .unwrap()
    }
    /// A canonical wire CANCEL with a zero tag (not authenticated by anyone).
    fn cancel(request_id: &[u8]) -> Vec<u8> {
        Message::Cancel {
            request_id: request_id.to_vec(),
            sender: Role::Initiator,
            reason: CancelReason::UserCancellation,
            mac: [0; 32],
        }
        .encode()
        .unwrap()
    }
    /// A wire-shaped frame with arbitrary fields and no semantic validation.
    fn frame(kind: u8, fields: &[&[u8]]) -> Vec<u8> {
        let mut out = b"SASPAIR\0\x01".to_vec();
        out.push(kind);
        for field in fields {
            out.extend_from_slice(&(field.len() as u32).to_be_bytes());
            out.extend_from_slice(field);
        }
        out
    }

    /// One authority (START limiter on its own hand clock) and its router.
    struct Node {
        trusted: TrustedAuthority,
        executor: CeremonyExecutor,
        limiter: Arc<ManualClock>,
        router: Router,
    }
    impl Node {
        fn new(scope: &str) -> Self {
            let limiter = ManualClock::new();
            let trusted =
                TrustedAuthority::register_with_limiter_clock(scope.as_bytes(), limiter.clone())
                    .unwrap();
            let executor = trusted.executor();
            let router = Router::new(executor.clone()).unwrap();
            Self {
                trusted,
                executor,
                limiter,
                router,
            }
        }
        fn release(self) {
            drop(self.router);
            drop(self.executor);
            self.trusted.release().unwrap();
        }
        /// An admitted connection (accept permit, then live) wrapped by a host whose transport
        /// clock and new-Responder ceremony clock are the two given hand clocks.
        fn host(
            &self,
            transport: &Arc<ManualClock>,
            ceremony: &Arc<ManualClock>,
        ) -> HostConnection<'_> {
            let connection = AcceptPermit::begin(&self.router)
                .unwrap()
                .activate_with_clock(transport.clone())
                .unwrap();
            HostConnection::with_ceremony_clock(
                connection,
                responder_bootstrap(),
                None,
                ceremony.clone(),
            )
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
        /// `(burst tokens, rolling records)`.
        fn charged(&self) -> (u8, usize) {
            let limiter = self.limiter();
            (limiter.tokens, limiter.rolling)
        }
        /// `(live connections, incomplete frames, pending Responders)`, read even if poisoned.
        fn counts(&self) -> (usize, usize, usize) {
            let shared = self
                .executor
                .0
                .shared
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            (
                shared.live_connections,
                shared.incomplete_frames,
                shared.pending_responders,
            )
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
        fn routes(&self) -> usize {
            self.router.routes_for_test()
        }
        fn status(&self) -> Status {
            self.executor.status().unwrap()
        }
    }

    fn assert_open(router: &Router, session: SessionHandle) {
        let probe = router.with_run(session, &[0xEE], |_| Ok(()));
        assert_eq!(probe.unwrap_err(), RouteError::UnknownRoute);
    }
    fn assert_closed(router: &Router, session: SessionHandle) {
        let probe = router.with_run(session, &[0xEE], |_| Ok(()));
        assert_eq!(probe.unwrap_err(), RouteError::UnknownSession);
    }

    /// Feeds `bytes` in `chunk`-byte reads; only the last read completes a frame, whose
    /// dispatch outcome is returned (the connection stays live).
    fn deliver_in(
        host: &mut HostConnection<'_>,
        bytes: &[u8],
        chunk: usize,
    ) -> Result<Dispatched, RouteError> {
        let mut reads = bytes.chunks(chunk).peekable();
        while let Some(read) = reads.next() {
            let fed = host.receive(read).unwrap();
            assert_eq!(fed.consumed, read.len());
            if reads.peek().is_none() {
                return fed.frame.expect("frame complete");
            }
            assert_eq!(fed.frame, None);
        }
        unreachable!("empty frame")
    }
    /// Feeds `bytes` in `chunk`-byte reads and returns the error that ends the connection on
    /// the last read.
    fn fail_in(host: &mut HostConnection<'_>, bytes: &[u8], chunk: usize) -> HostError {
        let (last, body) = bytes.split_last().unwrap();
        for read in body.chunks(chunk) {
            let fed = host.receive(read).unwrap();
            assert_eq!((fed.consumed, fed.frame), (read.len(), None));
        }
        host.receive(std::slice::from_ref(last)).unwrap_err()
    }
    /// The one ordinary outbound frame of a dispatch.
    fn frame_out(dispatched: Dispatched) -> Vec<u8> {
        match dispatched.outbound {
            Some(Outbound::Frame(bytes)) => bytes,
            other => panic!("no ordinary outbound frame: {other:?}"),
        }
    }
    /// Admits a new START on `host` and returns its ACCEPT.
    fn admit(host: &mut HostConnection<'_>, start: &[u8]) -> Vec<u8> {
        let dispatched = deliver_in(host, start, 64).unwrap();
        assert_eq!(dispatched.event, HostEvent::StartAccepted);
        frame_out(dispatched)
    }
    /// Poisons the run under `(session, id)` by panicking inside an operation on it.
    fn poison_run(router: &Router, session: SessionHandle, id: &[u8]) {
        thread::scope(|scope| {
            let op = scope.spawn(|| {
                router.with_run(session, id, |_| -> Result<(), CeremonyError> {
                    panic!("simulate uncertain run state")
                })
            });
            assert!(op.join().is_err());
        });
    }

    /// A routed Initiator on `ih` (ceremony clock `ci`) and a Responder admitted through `rh`,
    /// every frame crossing a host fragmented, up to both live SAS presentations. Returns the
    /// request ID and the shared `ceremony_identity`.
    fn establish(
        i: &Node,
        ih: &mut HostConnection<'_>,
        r: &Node,
        rh: &mut HostConnection<'_>,
        ci: &Arc<ManualClock>,
    ) -> (Vec<u8>, [u8; 32]) {
        let (si, sr) = (ih.session(), rh.session());
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
        let accepted = deliver_in(rh, &start, 7).unwrap();
        assert_eq!(accepted.request_id, id);
        let accept = frame_out(accepted);
        assert_eq!(
            deliver_in(ih, &accept, 11).unwrap().event,
            HostEvent::Accept
        );
        i.local(si, &id, |run| run.authorize(&i.trusted));
        let ikey = i.local(si, &id, |run| run.expose_key()).output;
        assert_eq!(
            deliver_in(rh, &ikey, 5).unwrap().event,
            HostEvent::InitiatorKey
        );
        r.local(sr, &id, |run| run.authorize(&r.trusted));
        let rkey = r.local(sr, &id, |run| run.expose_key()).output;
        assert_eq!(
            deliver_in(ih, &rkey, 5).unwrap().event,
            HostEvent::ResponderKey
        );
        let identity = |node: &Node, session| {
            *node
                .local(session, &id, |run| Ok(run.presentation()))
                .output
                .unwrap()
                .ceremony_identity()
        };
        let ours = identity(i, si);
        assert_eq!(ours, identity(r, sr));
        (id, ours)
    }

    /// From `establish` through both local approvals, both BOOTSTRAP_MACs (each through the
    /// peer's host, then again as an ignored exact duplicate), INITIATOR_FINISH and its ACK, to
    /// the Initiator's produced final ACK. Returns the request ID, identity, and that final ACK.
    fn until_final_ack(
        i: &Node,
        ih: &mut HostConnection<'_>,
        r: &Node,
        rh: &mut HostConnection<'_>,
        ci: &Arc<ManualClock>,
    ) -> (Vec<u8>, [u8; 32], FinalAck) {
        let (id, identity) = establish(i, ih, r, rh, ci);
        let (si, sr) = (ih.session(), rh.session());
        let mut macs = Vec::new();
        for (node, session) in [(i, si), (r, sr)] {
            let approved = node.local(session, &id, |run| run.approve_sas(&identity));
            assert_eq!(approved.output, SasApproval::Recorded);
            match node
                .local(session, &id, |run| run.emit_bootstrap_mac())
                .output
            {
                BootstrapMacEmission::Emitted(mac) => macs.push(mac),
                other => panic!("{other:?}"),
            }
        }
        fn peer_mac(host: &mut HostConnection<'_>, mac: &[u8]) {
            for approval in [
                PeerApproval::Authenticated,
                PeerApproval::AlreadyAuthenticated,
            ] {
                let dispatched = deliver_in(host, mac, 9).unwrap();
                assert_eq!(
                    (dispatched.event, dispatched.outbound, dispatched.result),
                    (HostEvent::BootstrapMac(approval), None, None)
                );
            }
        }
        peer_mac(rh, &macs[0]);
        peer_mac(ih, &macs[1]);
        let FinishEmission::Emitted(finish) =
            i.local(si, &id, |run| run.emit_initiator_finish()).output
        else {
            panic!("no INITIATOR_FINISH");
        };
        let dispatched = deliver_in(rh, &finish, 17).unwrap();
        assert_eq!(
            (dispatched.event, &dispatched.result),
            (HostEvent::InitiatorFinish, &None)
        );
        let ack = frame_out(dispatched);
        assert!(matches!(
            protocol::decode(&ack).unwrap().message,
            Message::ResponderFinishAck { .. }
        ));
        // An exact duplicate INITIATOR_FINISH is ignored: no second RESPONDER_FINISH_ACK.
        assert_eq!(
            deliver_in(rh, &finish, finish.len()).unwrap(),
            Dispatched {
                request_id: id.clone(),
                event: HostEvent::InitiatorFinishDuplicate,
                outbound: None,
                result: None,
            }
        );
        let dispatched = deliver_in(ih, &ack, 6).unwrap();
        assert_eq!(
            (dispatched.event, &dispatched.result),
            (HostEvent::ResponderFinishAck, &None)
        );
        let Some(Outbound::FinalAck(final_ack)) = dispatched.outbound else {
            panic!("no confirmable final ACK");
        };
        assert!(matches!(
            protocol::decode(final_ack.bytes()).unwrap().message,
            Message::InitiatorFinishAck { .. }
        ));
        // Produced is not success: the Initiator stays routed, pending, and guard-holding.
        assert_eq!(i.state(si, &id), "AwaitInitiatorFinishAckSend");
        assert_eq!((i.routes(), i.status()), (1, Status::Busy));
        (id, identity, final_ack)
    }

    #[test]
    fn a_fragmented_start_reaches_the_router_once_complete_and_returns_its_accept() {
        let (i, r) = (Node::new("host-start-i"), Node::new("host-start-r"));
        let (tc, cc, ci) = (ManualClock::new(), ManualClock::new(), ManualClock::new());
        let mut ih = i.host(&tc, &ci);
        assert_eq!(r.router.sessions_for_test(), 0);
        let mut rh = r.host(&tc, &cc);
        // One admitted connection wraps exactly one session, and nothing else exists yet.
        assert_eq!(r.router.sessions_for_test(), 1);
        assert_eq!(
            (r.counts(), r.charged(), r.routes()),
            ((1, 0, 0), (4, 0), 0)
        );
        let (id, start) = i
            .router
            .start_initiator_with(
                ci.clone(),
                &mut OsRequestIds,
                ih.session(),
                initiator_bootstrap(),
                None,
            )
            .unwrap();
        let (last, body) = start.split_last().unwrap();
        for byte in body {
            assert_eq!(
                rh.receive(std::slice::from_ref(byte)).unwrap(),
                HostFed {
                    consumed: 1,
                    frame: None
                }
            );
            // No Router work, limiter charge, or route before the frame is complete.
            assert_eq!(
                (r.counts(), r.charged(), r.routes()),
                ((1, 1, 0), (4, 0), 0)
            );
            tc.advance(MS);
        }
        let fed = rh.receive(std::slice::from_ref(last)).unwrap();
        assert_eq!(fed.consumed, 1);
        let dispatched = fed.frame.unwrap().unwrap();
        assert_eq!(
            (dispatched.event, dispatched.request_id.as_slice()),
            (HostEvent::StartAccepted, id.as_slice())
        );
        assert_eq!(dispatched.result, None);
        let accept = frame_out(dispatched);
        let decoded = protocol::decode(&accept).unwrap();
        assert_eq!(decoded.canonical_bytes(), accept.as_slice());
        assert!(
            matches!(decoded.message, Message::Accept { ref request_id, .. } if *request_id == id)
        );
        // Exactly one admission, one route, one pending Responder; the incomplete frame is gone
        // and the connection stays live.
        assert_eq!(
            (r.counts(), r.charged(), r.routes()),
            ((1, 0, 1), (3, 1), 1)
        );
        assert_eq!(
            r.state(rh.session(), &id),
            "ResponderAcceptSentAwaitInitiatorKey"
        );
        assert!(!rh.is_closed());
        assert_eq!(r.router.sessions_for_test(), 1);
        // The returned ACCEPT is the one the Initiator's run verifies.
        assert_eq!(
            deliver_in(&mut ih, &accept, 3).unwrap().event,
            HostEvent::Accept
        );
        drop((ih, rh));
        assert_eq!(r.counts(), (0, 0, 0));
        i.release();
        r.release();
    }

    #[test]
    fn frames_sharing_one_input_are_dispatched_one_per_call() {
        let r = Node::new("host-one-per-call");
        let (tc, cc) = (ManualClock::new(), ManualClock::new());
        let mut rh = r.host(&tc, &cc);
        let session = rh.session();
        let (x, y) = ([1; 16], [2; 16]);
        let (sx, kx) = (start(&x), initiator_key(&x));
        let both = [sx.as_slice(), &kx].concat();
        let first = rh.receive(&both).unwrap();
        assert_eq!(first.consumed, sx.len());
        assert_eq!(
            first.frame.unwrap().unwrap().event,
            HostEvent::StartAccepted
        );
        // The INITIATOR_KEY was neither taken nor dispatched.
        assert_eq!(r.state(session, &x), "ResponderAcceptSentAwaitInitiatorKey");
        let second = rh.receive(&both[first.consumed..]).unwrap();
        assert_eq!(second.consumed, kx.len());
        assert_eq!(
            second.frame.unwrap().unwrap(),
            Dispatched {
                request_id: x.to_vec(),
                event: HostEvent::InitiatorKey,
                outbound: None,
                result: None,
            }
        );
        assert_eq!(r.state(session, &x), "ResponderAwaitAuthorization");
        // A complete START followed by the beginning of the next frame.
        let (sy, ky) = (start(&y), initiator_key(&y));
        let mixed = [sy.as_slice(), &ky[..9]].concat();
        let fed = rh.receive(&mixed).unwrap();
        assert_eq!(fed.consumed, sy.len());
        assert_eq!(fed.frame.unwrap().unwrap().event, HostEvent::StartAccepted);
        assert_eq!(r.counts(), (1, 0, 2));
        assert_eq!(
            rh.receive(&mixed[sy.len()..]).unwrap(),
            HostFed {
                consumed: 9,
                frame: None
            }
        );
        assert_eq!(r.counts(), (1, 1, 2));
        let fed = rh.receive(&ky[9..]).unwrap();
        assert_eq!(fed.consumed, ky.len() - 9);
        assert_eq!(fed.frame.unwrap().unwrap().event, HostEvent::InitiatorKey);
        assert_eq!(r.counts(), (1, 0, 2));
        // A long buffer of exact duplicates: one frame per call, never an output or a charge.
        let charged = r.limiter();
        let stream = sx.repeat(20);
        let (mut rest, mut calls) = (stream.as_slice(), 0);
        while !rest.is_empty() {
            let fed = rh.receive(rest).unwrap();
            let dispatched = fed.frame.unwrap().unwrap();
            assert_eq!(
                (dispatched.event, dispatched.outbound),
                (HostEvent::StartDuplicate, None)
            );
            rest = &rest[fed.consumed..];
            calls += 1;
        }
        assert_eq!(calls, 20);
        assert_eq!(r.limiter(), charged);
        assert_eq!((r.counts(), r.routes()), ((1, 0, 2), 2));
        drop(rh);
        r.release();
    }

    #[test]
    fn an_exact_duplicate_start_through_the_host_changes_nothing() {
        let r = Node::new("host-duplicate-start");
        let (tc, cc) = (ManualClock::new(), ManualClock::new());
        let mut rh = r.host(&tc, &cc);
        let x = [3; 16];
        let sx = start(&x);
        admit(&mut rh, &sx);
        let charged = r.limiter();
        assert_eq!((charged.tokens, charged.rolling), (3, 1));
        cc.advance(INACTIVITY_DEADLINE - NS);
        for chunk in [sx.len(), 1, 40] {
            assert_eq!(
                deliver_in(&mut rh, &sx, chunk).unwrap(),
                Dispatched {
                    request_id: x.to_vec(),
                    event: HostEvent::StartDuplicate,
                    outbound: None,
                    result: None,
                }
            );
        }
        // No charge, slot, ephemeral, second route, or state change.
        assert_eq!(r.limiter(), charged);
        assert_eq!((r.counts(), r.routes()), ((1, 0, 1), 1));
        assert_eq!(
            r.state(rh.session(), &x),
            "ResponderAcceptSentAwaitInitiatorKey"
        );
        // Nor a deadline refresh: one more nanosecond of ceremony time ends the run.
        cc.advance(NS);
        assert_ne!(
            r.local(rh.session(), &x, |run| run.poll_deadlines()).output,
            DeadlineOutcome::Active
        );
        assert_eq!((r.counts(), r.routes()), ((1, 0, 0), 0));
        assert!(!rh.is_closed());
        drop(rh);
        r.release();
    }

    #[test]
    fn rejected_start_attempts_are_charged_and_leave_the_connection_live() {
        let r = Node::new("host-start-rejections");
        let (tc, cc) = (ManualClock::new(), ManualClock::new());
        let mut rh = r.host(&tc, &cc);
        let y = [4; 16];
        admit(&mut rh, &start(&y));
        assert_eq!(r.charged(), (3, 1));
        // A START candidate with a garbage bootstrap goes to admission without being decoded
        // first: charged, then rejected semantically, with no pending run or ACCEPT.
        let garbage = frame(1, &[PROFILE_ID, &[5; 16], &[0xFF; 3]]);
        assert_eq!(
            deliver_in(&mut rh, &garbage, 6),
            Err(RouteError::Ceremony(CeremonyError::Codec(
                CodecError::Truncated
            )))
        );
        assert_eq!(
            (r.charged(), r.counts(), r.routes()),
            ((2, 2), (1, 0, 1), 1)
        );
        // A well-formed bootstrap with another shared context: charged, then refused.
        let other_context = start_with(&[6; 16], bootstrap_with(b"app", b"other context"));
        assert_eq!(
            deliver_in(&mut rh, &other_context, 6),
            Err(RouteError::Ceremony(CeremonyError::SharedContextMismatch))
        );
        assert_eq!(
            (r.charged(), r.counts(), r.routes()),
            ((1, 3), (1, 0, 1), 1)
        );
        // The connection and its run are untouched, and a valid START at the same instant sees
        // every earlier charge.
        assert!(!rh.is_closed());
        assert_eq!(
            r.state(rh.session(), &y),
            "ResponderAcceptSentAwaitInitiatorKey"
        );
        admit(&mut rh, &start(&[7; 16]));
        assert_eq!(r.charged(), (0, 4));
        // A limiter refusal is a generic, nonfatal attempt outcome too.
        assert_eq!(
            deliver_in(&mut rh, &start(&[8; 16]), 64),
            Err(RouteError::Ceremony(CeremonyError::Owner(
                OwnerError::ResourceLimited
            )))
        );
        assert_eq!(
            (r.charged(), r.counts(), r.routes()),
            ((0, 4), (1, 0, 2), 2)
        );
        assert!(!rh.is_closed());
        assert_eq!(r.status(), Status::Ready { remaining: 10 });
        drop(rh);
        r.release();
    }

    #[test]
    fn a_structurally_unroutable_complete_frame_closes_its_connection_before_router_work() {
        let r = Node::new("host-unroutable");
        let (tc, cc) = (ManualClock::new(), ManualClock::new());
        let mut other = r.host(&tc, &cc);
        let z = [0x0A; 16];
        admit(&mut other, &start(&z));
        let bootstrap = initiator_bootstrap();
        let ibootstrap = bootstrap.canonical_bytes();
        let mut bad_profile = start(&[1; 16]);
        bad_profile[14] ^= 1;
        let profile = CodecError::InvalidField("profile_id");
        let request_id = CodecError::InvalidField("request_id");
        let cases: [(&str, Vec<u8>, CodecError); 6] = [
            ("START profile", bad_profile, profile.clone()),
            (
                "START empty request ID",
                frame(1, &[PROFILE_ID, &[], ibootstrap]),
                request_id.clone(),
            ),
            (
                "START 65-byte request ID",
                frame(1, &[PROFILE_ID, &[7; 65], ibootstrap]),
                request_id.clone(),
            ),
            (
                "INITIATOR_KEY profile",
                frame(3, &[b"sas-pairing-local-profile", &[1; 16], &[9; 32]]),
                profile,
            ),
            (
                "CANCEL 65-byte request ID",
                frame(9, &[PROFILE_ID, &[1; 65], &[1], &[2], &[0; 32]]),
                request_id.clone(),
            ),
            (
                "maximum-size BOOTSTRAP_MAC with an empty request ID",
                frame(
                    5,
                    &[
                        PROFILE_ID,
                        &[],
                        &[1],
                        &vec![0; MAX_FRAME - 27 - PROFILE_ID.len()],
                    ],
                ),
                request_id,
            ),
        ];
        for (name, bytes, expected) in cases {
            assert!(bytes.len() <= MAX_FRAME, "{name}");
            r.limiter.advance(REFILL_PERIOD);
            let mut host = r.host(&tc, &cc);
            let session = host.session();
            // A live run on this connection, which must end with it.
            admit(&mut host, &start(&[1; 16]));
            let charged = r.limiter();
            assert_eq!(r.counts(), (2, 0, 2), "{name}");
            assert_eq!(
                fail_in(&mut host, &bytes, 5000),
                HostError::Unroutable(expected),
                "{name}"
            );
            // Connection and session ended and its run terminated; no limiter charge, Router
            // state, or output; the other connection is untouched.
            assert!(host.is_closed(), "{name}");
            assert_closed(&r.router, session);
            assert_eq!(r.limiter(), charged, "{name}");
            assert_eq!((r.counts(), r.routes()), ((1, 0, 1), 1), "{name}");
            assert_eq!(
                host.receive(&start(&[2; 16])),
                Err(HostError::Transport(TransportError::Closed))
            );
        }
        assert_eq!(
            r.state(other.session(), &z),
            "ResponderAcceptSentAwaitInitiatorKey"
        );
        assert_eq!(r.status(), Status::Ready { remaining: 10 });
        drop(other);
        r.release();
    }

    #[test]
    fn non_start_frames_reach_only_the_run_under_their_own_session_and_request_id() {
        let r = Node::new("host-exact-route");
        let (tc, cc) = (ManualClock::new(), ManualClock::new());
        let (mut a, mut b) = (r.host(&tc, &cc), r.host(&tc, &cc));
        let x = [5; 16];
        let (accept_a, accept_b) = (admit(&mut a, &start(&x)), admit(&mut b, &start(&x)));
        assert_ne!(accept_a, accept_b, "independent runs");
        assert_eq!(
            deliver_in(&mut a, &initiator_key(&x), 7).unwrap(),
            Dispatched {
                request_id: x.to_vec(),
                event: HostEvent::InitiatorKey,
                outbound: None,
                result: None,
            }
        );
        assert_eq!(r.state(a.session(), &x), "ResponderAwaitAuthorization");
        assert_eq!(
            r.state(b.session(), &x),
            "ResponderAcceptSentAwaitInitiatorKey"
        );
        drop((a, b));
        r.release();
    }

    #[test]
    fn an_unknown_route_closes_only_its_connection_after_settling_its_session() {
        let r = Node::new("host-unknown-route");
        let (tc, cc) = (ManualClock::new(), ManualClock::new());
        let (mut a, mut b) = (r.host(&tc, &cc), r.host(&tc, &cc));
        let (sa, sb) = (a.session(), b.session());
        let (x, y, q) = ([1; 16], [2; 16], [9; 16]);
        admit(&mut a, &start(&x));
        admit(&mut a, &start(&y));
        admit(&mut b, &start(&x));
        assert_eq!((r.counts(), r.routes()), ((2, 0, 3), 3));
        let charged = r.limiter();
        // At the transport's "session CLOSED" point A's runs are gone, but its live count is
        // still held: it is released only after the Router teardown settled.
        let (seen_tx, seen) = mpsc::channel();
        let executor = r.executor.clone();
        test_hook::install(move |point| {
            if point == Point::TransportSessionClosed {
                let shared = executor.0.shared.lock().unwrap();
                seen_tx
                    .send((shared.live_connections, shared.pending_responders))
                    .unwrap();
            }
        });
        assert_eq!(
            fail_in(&mut a, &initiator_key(&q), 20),
            HostError::Routing(RouteError::SessionProtocolFailure)
        );
        test_hook::install(|_| {});
        assert_eq!(seen.try_recv().unwrap(), (2, 1));
        assert!(seen.try_recv().is_err(), "one teardown");
        // A is closed; its session is CLOSED; no output, result, or limiter change; B and its
        // equal-ID run are untouched.
        assert!(a.is_closed());
        assert_closed(&r.router, sa);
        assert_eq!((r.counts(), r.routes()), ((1, 0, 1), 1));
        assert_eq!(r.limiter(), charged);
        assert_eq!(r.state(sb, &x), "ResponderAcceptSentAwaitInitiatorKey");
        assert_eq!(
            a.receive(&start(&x)),
            Err(HostError::Transport(TransportError::Closed))
        );
        assert_eq!(
            a.poll_frame_deadlines(),
            Err(HostError::Transport(TransportError::Closed))
        );
        // An unknown-route CANCEL is the same session-fatal case.
        assert_eq!(
            fail_in(&mut b, &cancel(&q), 30),
            HostError::Routing(RouteError::SessionProtocolFailure)
        );
        assert!(b.is_closed());
        assert_closed(&r.router, sb);
        assert_eq!((r.counts(), r.routes()), ((0, 0, 0), 0));
        // Dropping closed hosts releases nothing a second time.
        drop((a, b));
        assert_eq!(r.counts(), (0, 0, 0));
        assert_eq!(r.router.sessions_for_test(), 0);
        assert_eq!(r.status(), Status::Ready { remaining: 10 });
        r.release();
    }

    #[test]
    fn a_run_local_protocol_error_fails_only_that_run() {
        let r = Node::new("host-run-local");
        let (tc, cc) = (ManualClock::new(), ManualClock::new());
        let mut h = r.host(&tc, &cc);
        let session = h.session();
        let (x, y) = ([1; 16], [2; 16]);
        admit(&mut h, &start(&x));
        admit(&mut h, &start(&y));
        let mac = Message::BootstrapMac {
            request_id: x.to_vec(),
            sender: Role::Initiator,
            mac: [0; 32],
        }
        .encode()
        .unwrap();
        // Wrong state for X: X fails; Y, the session, and the connection continue.
        assert_eq!(deliver_in(&mut h, &mac, 13), Err(BAD));
        assert_eq!((r.counts(), r.routes()), ((1, 0, 1), 1));
        assert_eq!(
            r.router.with_run(session, &x, |_| Ok(())).unwrap_err(),
            RouteError::UnknownRoute
        );
        assert_eq!(r.state(session, &y), "ResponderAcceptSentAwaitInitiatorKey");
        assert!(!h.is_closed());
        // A changed START for Y fails only Y, and never becomes a new candidate.
        let charged = r.limiter();
        assert_eq!(deliver_in(&mut h, &changed_start(&y), 64), Err(BAD));
        assert_eq!(r.limiter(), charged);
        assert_eq!((r.counts(), r.routes()), ((1, 0, 0), 0));
        assert!(!h.is_closed());
        assert_open(&r.router, session);
        // The freed key is a fresh, newly charged candidate on the same connection.
        admit(&mut h, &start(&x));
        assert_eq!(r.limiter().rolling, charged.rolling + 1);
        drop(h);
        r.release();
    }

    #[test]
    fn completion_through_two_hosts_yields_each_result_once_and_keeps_both_connections() {
        let (i, r) = (Node::new("host-complete-i"), Node::new("host-complete-r"));
        let (tc, ci, cr) = (ManualClock::new(), ManualClock::new(), ManualClock::new());
        let (mut ih, mut rh) = (i.host(&tc, &ci), r.host(&tc, &cr));
        let (si, sr) = (ih.session(), rh.session());
        let (id, identity, final_ack) = until_final_ack(&i, &mut ih, &r, &mut rh, &ci);
        let wire = final_ack.bytes().to_vec();
        // The Responder succeeds on the exact final ACK, with no output.
        let dispatched = deliver_in(&mut rh, &wire, 10).unwrap();
        assert_eq!(
            (dispatched.event, &dispatched.outbound),
            (HostEvent::InitiatorFinishAck, &None)
        );
        let responder = dispatched.result.expect("Responder result");
        assert_eq!(
            (r.routes(), r.status()),
            (0, Status::Ready { remaining: 9 })
        );
        // The Initiator still has no result: only its adapter's confirmation of a full local
        // write creates one.
        assert_eq!((i.routes(), i.status()), (1, Status::Busy));
        let copy = FinalAck {
            session: si,
            request_id: id.clone(),
            bytes: wire.clone(),
        };
        let initiator = ih.confirm_sent(final_ack).unwrap().unwrap();
        assert_eq!(
            (i.routes(), i.reserved(), i.status()),
            (0, 0, Status::Ready { remaining: 9 })
        );
        assert_eq!(initiator.request_id(), id.as_slice());
        assert_eq!(initiator.ceremony_identity(), &identity);
        assert_eq!(responder.ceremony_identity(), &identity);
        assert_eq!(initiator.peer_role(), crate::Role::Responder);
        assert_eq!(responder.peer_role(), crate::Role::Initiator);
        // A token is consumed by its confirmation; even a forged copy of it creates nothing.
        assert_eq!(ih.confirm_sent(copy), Ok(Err(RouteError::UnknownRoute)));
        // Success closes neither connection nor session, and releases no live count.
        assert!(!ih.is_closed() && !rh.is_closed());
        assert_eq!((i.counts(), r.counts()), ((1, 0, 0), (1, 0, 0)));
        assert_open(&i.router, si);
        assert_open(&r.router, sr);
        // The same connection admits a fresh, independent run.
        admit(&mut rh, &start(&[0x42; 16]));
        assert_eq!(r.counts(), (1, 0, 1));
        // Stale completion traffic names no run on a live session: session-fatal, no result.
        assert_eq!(
            fail_in(&mut rh, &wire, 10),
            HostError::Routing(RouteError::SessionProtocolFailure)
        );
        assert!(rh.is_closed());
        assert_eq!(
            (r.counts(), r.status()),
            ((0, 0, 0), Status::Ready { remaining: 9 })
        );
        assert_eq!(responder.ceremony_identity(), &identity);
        drop((ih, rh));
        i.release();
        r.release();
    }

    #[test]
    fn an_unconfirmed_final_ack_never_becomes_success() {
        let (i, r) = (Node::new("host-final-ack-i"), Node::new("host-final-ack-r"));
        let (tc, ci, cr) = (ManualClock::new(), ManualClock::new(), ManualClock::new());

        // (a) Explicit close before the write was confirmed: no result, the pending ACK and run
        // gone, the guard released, the opportunity kept, and the live count released.
        let (mut ih, mut rh) = (i.host(&tc, &ci), r.host(&tc, &cr));
        let (id, _, stale) = until_final_ack(&i, &mut ih, &r, &mut rh, &ci);
        ih.close().unwrap();
        assert_eq!(
            (i.routes(), i.reserved(), i.status(), i.counts()),
            (0, 0, Status::Ready { remaining: 9 }, (0, 0, 0))
        );
        // R never received the final ACK: no result there either. Closing R ends its run.
        assert_eq!(r.state(rh.session(), &id), "AwaitInitiatorFinishAck");
        rh.close().unwrap();
        // The retained token names no run on any other connection.
        let mut ih = i.host(&tc, &ci);
        assert_eq!(ih.confirm_sent(stale), Ok(Err(RouteError::UnknownRoute)));
        assert_eq!(
            (i.routes(), i.status()),
            (0, Status::Ready { remaining: 9 })
        );

        // (b) The session failed before confirmation: the closed host confirms nothing.
        let mut rh = r.host(&tc, &cr);
        let (_, _, stale) = until_final_ack(&i, &mut ih, &r, &mut rh, &ci);
        assert_eq!(
            fail_in(&mut ih, &initiator_key(&[0x77; 16]), 50),
            HostError::Routing(RouteError::SessionProtocolFailure)
        );
        assert_eq!(
            ih.confirm_sent(stale),
            Err(HostError::Transport(TransportError::Closed))
        );
        assert_eq!(
            (i.routes(), i.reserved(), i.status(), i.counts()),
            (0, 0, Status::Ready { remaining: 8 }, (0, 0, 0))
        );
        rh.close().unwrap();
        drop(ih);

        // (c) The run timed out before confirmation: its own deadline check refuses it, and
        // the connection stays live.
        let (mut ih, mut rh) = (i.host(&tc, &ci), r.host(&tc, &cr));
        let (_, _, late) = until_final_ack(&i, &mut ih, &r, &mut rh, &ci);
        ci.advance(ABSOLUTE_DEADLINE);
        assert!(matches!(
            ih.confirm_sent(late),
            Ok(Err(RouteError::Ceremony(CeremonyError::TimedOut(_))))
        ));
        assert_eq!(
            (i.routes(), i.reserved(), i.status()),
            (0, 0, Status::Ready { remaining: 7 })
        );
        assert!(!ih.is_closed());
        assert_eq!(i.counts(), (1, 0, 0));
        drop((ih, rh));
        assert_eq!(
            (r.routes(), r.counts(), r.status()),
            (0, (0, 0, 0), Status::Ready { remaining: 7 })
        );
        i.release();
        r.release();
    }

    #[test]
    fn a_verified_peer_cancel_ends_only_its_run_and_an_invalid_one_only_its_target() {
        let (i, r) = (Node::new("host-cancel-i"), Node::new("host-cancel-r"));
        let (tc, ci, cr) = (ManualClock::new(), ManualClock::new(), ManualClock::new());
        let (mut ih, mut rh) = (i.host(&tc, &ci), r.host(&tc, &cr));
        let (id, identity) = establish(&i, &mut ih, &r, &mut rh, &ci);
        let y = [0x44; 16];
        admit(&mut rh, &start(&y));
        assert_eq!((r.routes(), r.status()), (2, Status::Busy));
        let LocalCancellation::Emitted(verified) = i
            .local(ih.session(), &id, |run| run.cancel_sas(&identity))
            .output
        else {
            panic!("no CANCEL");
        };
        let dispatched = deliver_in(&mut rh, &verified, 8).unwrap();
        assert!(matches!(
            dispatched.event,
            HostEvent::Cancel(c) if c.reason() == CancelReason::UserCancellation
        ));
        assert_eq!((dispatched.outbound, dispatched.result), (None, None));
        // That run is terminal with its opportunity kept; Y and the connection continue.
        assert_eq!(
            (r.routes(), r.status()),
            (1, Status::Ready { remaining: 9 })
        );
        assert_eq!(r.counts(), (1, 0, 1));
        assert!(!rh.is_closed());
        // A wire CANCEL for the pre-SAS run Y is invalid input that fails only Y.
        assert!(matches!(
            deliver_in(&mut rh, &cancel(&y), 9),
            Err(RouteError::Ceremony(_))
        ));
        assert_eq!((r.routes(), r.counts()), (0, (1, 0, 0)));
        assert!(!rh.is_closed());
        assert_open(&r.router, rh.session());
        drop((ih, rh));
        i.release();
        r.release();
    }

    #[test]
    fn transport_deadlines_through_the_host_close_the_connection_before_any_dispatch() {
        let r = Node::new("host-transport-deadlines");
        let (tc, cc) = (ManualClock::new(), ManualClock::new());
        let s = start(&[2; 16]);

        // Idle: no byte for 2 s.
        let mut h = r.host(&tc, &cc);
        let session = h.session();
        admit(&mut h, &start(&[1; 16]));
        let charged = r.limiter();
        assert_eq!(h.receive(&s[..30]).unwrap().frame, None);
        assert_eq!(r.counts(), (1, 1, 1));
        tc.advance(IDLE_READ_DEADLINE - NS);
        assert_eq!(h.poll_frame_deadlines(), Ok(()));
        tc.advance(NS);
        assert_eq!(
            h.poll_frame_deadlines(),
            Err(HostError::Transport(TransportError::IdleTimeout))
        );
        assert!(h.is_closed());
        assert_closed(&r.router, session);
        // The incomplete START charged nothing; the admitted run was torn down with the
        // connection, not by a ceremony deadline (that clock never moved).
        assert_eq!(
            (r.limiter(), r.counts(), r.routes()),
            (charged, (0, 0, 0), 0)
        );
        assert_eq!(
            h.receive(&s[30..]),
            Err(HostError::Transport(TransportError::Closed))
        );

        drop(h);

        // Whole frame: progress every 1.9 s, so only the 10-second deadline can expire.
        let tc = ManualClock::new();
        let mut h = r.host(&tc, &cc);
        h.receive(&s[..1]).unwrap();
        for n in 1..=5 {
            tc.set(Duration::from_millis(1900 * n as u64));
            assert_eq!(h.receive(&s[n..n + 1]).unwrap().consumed, 1);
        }
        tc.set(WHOLE_FRAME_DEADLINE);
        assert_eq!(
            h.receive(&s[6..]),
            Err(HostError::Transport(TransportError::WholeFrameTimeout))
        );
        assert!(h.is_closed());
        assert_eq!(
            (r.limiter(), r.counts(), r.routes()),
            (charged, (0, 0, 0), 0)
        );
        drop(h);
        r.release();
    }

    #[test]
    fn an_incomplete_frame_refusal_through_the_host_closes_only_that_connection() {
        let r = Node::new("host-incomplete-cap");
        let (tc, cc) = (ManualClock::new(), ManualClock::new());
        let s = start(&[3; 16]);
        let mut held: Vec<_> = (0..4).map(|_| r.host(&tc, &cc)).collect();
        for h in &mut held {
            assert_eq!(h.receive(&s[..5]).unwrap().frame, None);
        }
        assert_eq!(r.counts(), (4, 4, 0));
        let mut fifth = r.host(&tc, &cc);
        let session = fifth.session();
        assert_eq!(
            fifth.receive(&s[..5]),
            Err(HostError::Transport(TransportError::ResourceLimited))
        );
        assert!(fifth.is_closed());
        assert_closed(&r.router, session);
        assert_eq!((r.counts(), r.charged()), ((4, 4, 0), (4, 0)));
        // The four held frames complete and dispatch normally, each its own new candidate.
        for h in &mut held {
            let fed = h.receive(&s[5..]).unwrap();
            assert_eq!(fed.frame.unwrap().unwrap().event, HostEvent::StartAccepted);
        }
        assert_eq!((r.counts(), r.charged()), ((4, 0, 4), (0, 4)));
        drop((held, fifth));
        assert_eq!(r.counts(), (0, 0, 0));
        r.release();
    }

    #[test]
    fn transport_ceremony_and_limiter_clocks_stay_in_their_own_domains() {
        let r = Node::new("host-clocks");
        let (tc, cc) = (ManualClock::new(), ManualClock::new());
        let mut h = r.host(&tc, &cc);
        let session = h.session();
        let x = [1; 16];
        admit(&mut h, &start(&x));
        // Transport time is neither ceremony time nor limiter time.
        tc.advance(Duration::from_secs(3600));
        assert_eq!(h.poll_frame_deadlines(), Ok(()));
        assert_eq!(
            r.local(session, &x, |run| run.poll_deadlines()).output,
            DeadlineOutcome::Active
        );
        assert_eq!(r.charged(), (3, 1));
        // Ceremony time ends the run but never a frame in progress on its connection.
        let s = start(&[2; 16]);
        h.receive(&s[..20]).unwrap();
        cc.advance(INACTIVITY_DEADLINE);
        assert_ne!(
            r.local(session, &x, |run| run.poll_deadlines()).output,
            DeadlineOutcome::Active
        );
        assert_eq!(h.poll_frame_deadlines(), Ok(()));
        assert_eq!(r.counts(), (1, 1, 0));
        // Limiter time refills credit (seen at the next admission) and does nothing else.
        r.limiter.advance(REFILL_PERIOD);
        assert_eq!(h.poll_frame_deadlines(), Ok(()));
        // The frame completes on transport time; its new run starts on ceremony time now, and
        // its admission found the refilled token: 3 + 1 - 1.
        admit(&mut h, &s[20..]);
        cc.advance(INACTIVITY_DEADLINE - NS);
        assert_eq!(
            r.local(session, &[2; 16], |run| run.poll_deadlines())
                .output,
            DeadlineOutcome::Active
        );
        assert_eq!(r.charged(), (3, 2));
        drop(h);
        r.release();
    }

    #[test]
    fn a_session_ended_elsewhere_or_uncertain_ends_the_host_connection_fail_closed() {
        let r = Node::new("host-session-ended");
        let (tc, cc) = (ManualClock::new(), ManualClock::new());
        // Closed elsewhere: the next dispatch finds no session, and the transport settles it.
        let mut h = r.host(&tc, &cc);
        r.router.close_session(h.session()).unwrap();
        assert_eq!(r.counts(), (1, 0, 0));
        assert_eq!(
            fail_in(&mut h, &start(&[1; 16]), 40),
            HostError::Routing(RouteError::UnknownSession)
        );
        assert!(h.is_closed());
        assert_eq!((r.counts(), r.charged()), ((0, 0, 0), (4, 0)));
        drop(h);
        // Uncertain run state: the connection ends, and since its Router teardown cannot be
        // established the live count stays held for good.
        let mut h = r.host(&tc, &cc);
        let x = [2; 16];
        admit(&mut h, &start(&x));
        poison_run(&r.router, h.session(), &x);
        assert_eq!(
            fail_in(&mut h, &initiator_key(&x), 40),
            HostError::Transport(TransportError::OwnershipUncertain)
        );
        assert!(h.is_closed());
        assert_eq!(r.counts().0, 1);
        drop(h);
        assert_eq!(r.counts().0, 1);
        // Explicit close and drop of healthy connections each release exactly once.
        let mut h = r.host(&tc, &cc);
        admit(&mut h, &start(&[3; 16]));
        h.receive(&start(&[4; 16])[..9]).unwrap();
        assert_eq!(r.counts(), (2, 1, 1));
        assert_eq!(h.close(), Ok(()));
        assert_eq!(r.counts(), (1, 0, 0));
        let mut h = r.host(&tc, &cc);
        admit(&mut h, &start(&[5; 16]));
        drop(h);
        assert_eq!(r.counts(), (1, 0, 0));
        r.release();
    }

    /// A request-ID source that yields exactly one scripted ID.
    struct OneId(Option<[u8; 16]>);
    impl RequestIdGenerator for OneId {
        fn generate(&mut self) -> Option<[u8; 16]> {
            self.0.take()
        }
    }

    /// Routes a local Initiator under `id` on `host`'s session, with ceremony clock `clock`.
    fn initiate_on(node: &Node, host: &HostConnection<'_>, clock: &Arc<ManualClock>, id: [u8; 16]) {
        let (routed, _) = node
            .router
            .start_initiator_with(
                clock.clone(),
                &mut OneId(Some(id)),
                host.session(),
                initiator_bootstrap(),
                None,
            )
            .unwrap();
        assert_eq!(routed, id.to_vec());
    }

    /// One deadline poll that ended nothing; returns how many routes it inspected.
    fn idle(host: &mut HostConnection<'_>) -> usize {
        let poll = host.poll_ceremony_deadlines().unwrap();
        assert_eq!((poll.event, poll.outbound), (None, None));
        assert!(poll.inspected <= MAX_CEREMONY_POLLS_PER_CALL);
        poll.inspected
    }

    fn ended(request_id: &[u8], kind: CeremonyDeadline) -> Option<CeremonyDeadlineEvent> {
        Some(CeremonyDeadlineEvent {
            request_id: request_id.to_vec(),
            kind,
        })
    }

    /// The ordinary outbound frame of a poll: a canonical timeout CANCEL from `sender` for
    /// `request_id`, returned exactly as the run built it.
    fn timeout_cancel(outbound: Option<Outbound>, request_id: &[u8], sender: Role) -> Vec<u8> {
        let Some(Outbound::Frame(cancel)) = outbound else {
            panic!("no ordinary CANCEL frame: {outbound:?}");
        };
        let decoded = protocol::decode(&cancel).unwrap();
        assert_eq!(decoded.canonical_bytes(), cancel.as_slice());
        assert!(matches!(
            decoded.message,
            Message::Cancel { request_id: ref id, sender: from, reason: CancelReason::Timeout, .. }
                if id == request_id && from == sender
        ));
        cancel
    }

    const INACTIVITY: CeremonyDeadline = CeremonyDeadline::TimedOut(Deadline::Inactivity);
    const ABSOLUTE: CeremonyDeadline = CeremonyDeadline::TimedOut(Deadline::Absolute);

    #[test]
    fn idle_pre_sas_runs_are_driven_to_expiry_one_run_per_call() {
        let r = Node::new("host-deadline-pre-sas");
        let (tc, cc, ci) = (ManualClock::new(), ManualClock::new(), ManualClock::new());
        let (mut h, mut g) = (r.host(&tc, &cc), r.host(&tc, &cc));
        let session = h.session();
        let (x, y, z) = ([0x10; 16], [0x20; 16], [0x30; 16]);
        // On H: a local Initiator X (holding a request-ID reservation) and a peer's Responder
        // Y. On another connection G of the same router: a Responder Z.
        initiate_on(&r, &h, &ci, x);
        admit(&mut h, &start(&y));
        admit(&mut g, &start(&z));
        let charged = r.limiter();
        assert_eq!((r.routes(), r.reserved(), r.counts()), (3, 1, (2, 0, 2)));
        // Polls are not progress: X's inactivity keeps running from its creation.
        assert_eq!(idle(&mut h), 2);
        ci.advance(INACTIVITY_DEADLINE - NS);
        for _ in 0..3 {
            assert_eq!(idle(&mut h), 2);
        }
        ci.advance(NS);
        // Neither received frames nor the transport frame poll drive ceremony deadlines.
        assert_eq!(
            deliver_in(&mut h, &start(&y), 64).unwrap().event,
            HostEvent::StartDuplicate
        );
        assert_eq!(h.poll_frame_deadlines(), Ok(()));
        assert_eq!(r.state(session, &x), "InitiatorAwaitAccept");
        // Exactly at 60 s the driver ends X: before SAS there is no authenticated CANCEL.
        assert_eq!(
            h.poll_ceremony_deadlines().unwrap(),
            CeremonyPoll {
                inspected: 1,
                event: ended(&x, INACTIVITY),
                outbound: None,
            }
        );
        // X alone ended: its route and reservation are gone and no result exists; Y, Z, both
        // connections, the limiter, and the budget are untouched.
        assert_eq!((r.routes(), r.reserved(), r.counts()), (2, 0, (2, 0, 2)));
        assert_eq!(
            r.router.with_run(session, &x, |_| Ok(())).unwrap_err(),
            RouteError::UnknownRoute
        );
        assert_eq!(r.state(session, &y), "ResponderAcceptSentAwaitInitiatorKey");
        assert!(!h.is_closed());
        assert_eq!(r.limiter(), charged);
        assert_eq!(r.status(), Status::Ready { remaining: 10 });
        // The same request ID routes a fresh run on the live session, under its own clock;
        // the driver never mistakes it for the expired one.
        initiate_on(&r, &h, &ManualClock::new(), x);
        ci.advance(ABSOLUTE_DEADLINE);
        assert_eq!(idle(&mut h), 2);
        assert_eq!(r.state(session, &x), "InitiatorAwaitAccept");
        // At five minutes Y's absolute deadline (reported before the also-expired inactivity)
        // ends it: no CANCEL before SAS, its pending slot released, its START charge kept.
        cc.advance(ABSOLUTE_DEADLINE);
        assert_eq!(
            h.poll_ceremony_deadlines().unwrap(),
            CeremonyPoll {
                inspected: 1,
                event: ended(&y, ABSOLUTE),
                outbound: None,
            }
        );
        assert_eq!(
            (r.routes(), r.counts(), r.limiter()),
            (2, (2, 0, 1), charged)
        );
        // Z is just as expired, but only G's own driver reaches it.
        assert_eq!(idle(&mut h), 1);
        assert_eq!(r.routes(), 2);
        assert_eq!(
            g.poll_ceremony_deadlines().unwrap(),
            CeremonyPoll {
                inspected: 1,
                event: ended(&z, ABSOLUTE),
                outbound: None,
            }
        );
        assert_eq!((r.routes(), r.counts()), (1, (2, 0, 0)));
        // Run timeouts closed neither connection; H admits a fresh, newly charged run.
        assert!(!h.is_closed() && !g.is_closed());
        admit(&mut h, &start(&y));
        assert_eq!(r.limiter().rolling, charged.rolling + 1);
        drop((h, g));
        r.release();
    }

    #[test]
    fn the_fixed_pending_lifetime_is_driven_without_refresh_and_frees_its_slot() {
        let r = Node::new("host-deadline-pending");
        let (tc, cc) = (ManualClock::new(), ManualClock::new());
        let mut h = r.host(&tc, &cc);
        let session = h.session();
        let ids: Vec<[u8; 16]> = (1..=4).map(|n| [n; 16]).collect();
        for id in &ids {
            admit(&mut h, &start(id));
        }
        assert_eq!((r.counts(), r.charged()), ((1, 0, 4), (0, 4)));
        // At 30 s the first Responder makes every legal pre-exposure step: INITIATOR_KEY (with
        // its DH) and a recorded exposure authorization. Both restart its inactivity window;
        // neither extends its pending lifetime.
        cc.advance(Duration::from_secs(30));
        assert_eq!(
            deliver_in(&mut h, &initiator_key(&ids[0]), 9)
                .unwrap()
                .event,
            HostEvent::InitiatorKey
        );
        r.local(session, &ids[0], |run| run.authorize(&r.trusted));
        assert_eq!(r.state(session, &ids[0]), "ResponderAwaitAuthorization");
        let charged = r.limiter();
        cc.advance(Duration::from_secs(30) - NS);
        assert_eq!(idle(&mut h), 4);
        cc.advance(NS);
        // Exactly 60 s after its admission: a local resource expiry, with nothing to send.
        assert_eq!(
            h.poll_ceremony_deadlines().unwrap(),
            CeremonyPoll {
                inspected: 1,
                event: ended(&ids[0], CeremonyDeadline::PendingExpired),
                outbound: None,
            }
        );
        // Its slot is free; no limiter charge was refunded and no opportunity touched.
        assert_eq!(
            (r.counts(), r.routes(), r.limiter()),
            ((1, 0, 3), 3, charged)
        );
        assert_eq!(r.status(), Status::Ready { remaining: 10 });
        // A new START takes the freed slot once the limiter itself has credit again.
        r.limiter.advance(REFILL_PERIOD);
        admit(&mut h, &start(&[5; 16]));
        assert_eq!(r.counts(), (1, 0, 4));
        // The three other runs also expired; each later call ends exactly one (their own
        // inactivity diagnostic, evaluated before the equal pending lifetime), with no CANCEL.
        for id in &ids[1..] {
            assert_eq!(
                h.poll_ceremony_deadlines().unwrap(),
                CeremonyPoll {
                    inspected: 1,
                    event: ended(id, INACTIVITY),
                    outbound: None,
                }
            );
        }
        assert_eq!((r.counts(), r.routes()), ((1, 0, 1), 1));
        assert_eq!(r.limiter().rolling, charged.rolling + 1);
        assert!(!h.is_closed());
        drop(h);
        r.release();
    }

    #[test]
    fn post_sas_timeout_surfaces_one_authenticated_cancel_after_the_human_wait() {
        let (i, r) = (
            Node::new("host-deadline-sas-i"),
            Node::new("host-deadline-sas-r"),
        );
        let (tc, ci, cr) = (ManualClock::new(), ManualClock::new(), ManualClock::new());
        let (mut ih, mut rh) = (i.host(&tc, &ci), r.host(&tc, &cr));
        let (si, sr) = (ih.session(), rh.session());
        let (id, identity) = establish(&i, &mut ih, &r, &mut rh, &ci);
        assert_eq!((i.status(), r.status()), (Status::Busy, Status::Busy));
        // The complete SAS awaits the human: inactivity is suspended, so polls long past 60 s
        // find the run live, still presenting its SAS.
        ci.advance(2 * INACTIVITY_DEADLINE);
        for _ in 0..3 {
            assert_eq!(idle(&mut ih), 1);
        }
        assert!(
            i.local(si, &id, |run| Ok(run.presentation()))
                .output
                .is_some()
        );
        // I matches and emits its approval MAC; R verifies it while R's own human decision is
        // still open, which keeps R in the suspended human wait.
        assert_eq!(
            i.local(si, &id, |run| run.approve_sas(&identity)).output,
            SasApproval::Recorded
        );
        let BootstrapMacEmission::Emitted(mac) =
            i.local(si, &id, |run| run.emit_bootstrap_mac()).output
        else {
            panic!("no BOOTSTRAP_MAC");
        };
        assert_eq!(
            deliver_in(&mut rh, &mac, 9).unwrap().event,
            HostEvent::BootstrapMac(PeerApproval::Authenticated)
        );
        assert_eq!(r.state(sr, &id), "AwaitLocalApproval");
        // A second Responder Y is prepared on R, unexposed, while R's guard is held.
        let y = [0x77; 16];
        cr.advance(ABSOLUTE_DEADLINE - NS);
        admit(&mut rh, &start(&y));
        assert_eq!(
            deliver_in(&mut rh, &initiator_key(&y), 9).unwrap().event,
            HostEvent::InitiatorKey
        );
        // Minutes past any inactivity window, one nanosecond before the absolute deadline.
        assert_eq!(idle(&mut rh), 2);
        assert_eq!(r.status(), Status::Busy);
        cr.advance(NS);
        let poll = rh.poll_ceremony_deadlines().unwrap();
        assert!(poll.inspected <= 2);
        assert_eq!(poll.event, ended(&id, ABSOLUTE));
        // The exact bytes the run built while its SAS existed, as an ordinary frame.
        let cancel = timeout_cancel(poll.outbound, &id, Role::Responder);
        // Already terminal before anything is sent: route gone, guard released after
        // invalidation, opportunity kept, connection live, and Y not exposed automatically.
        assert_eq!(
            (r.routes(), r.status()),
            (1, Status::Ready { remaining: 9 })
        );
        assert!(!rh.is_closed());
        assert_eq!(r.state(sr, &y), "ResponderAwaitAuthorization");
        // Nothing is retained or repeated for resending.
        assert_eq!(idle(&mut rh), 1);
        // Best effort only, but authentic: I verifies the timeout CANCEL for exactly its run.
        let dispatched = deliver_in(&mut ih, &cancel, 13).unwrap();
        assert!(matches!(
            dispatched.event,
            HostEvent::Cancel(c) if c.reason() == CancelReason::Timeout
        ));
        assert_eq!((dispatched.outbound, dispatched.result), (None, None));
        assert_eq!(
            (i.routes(), i.reserved(), i.status()),
            (0, 0, Status::Ready { remaining: 9 })
        );
        assert!(!ih.is_closed());
        // Y may now obtain its own fresh authorization and cross exposure normally.
        r.local(sr, &y, |run| run.authorize(&r.trusted));
        r.local(sr, &y, |run| run.expose_key());
        assert_eq!(r.status(), Status::Busy);
        drop((ih, rh));
        assert_eq!(r.status(), Status::Ready { remaining: 8 });
        i.release();
        r.release();
    }

    #[test]
    fn a_final_ack_awaiting_its_send_times_out_through_the_driver_with_no_result() {
        let (i, r) = (
            Node::new("host-deadline-ack-i"),
            Node::new("host-deadline-ack-r"),
        );
        let (tc, ci, cr) = (ManualClock::new(), ManualClock::new(), ManualClock::new());
        let (mut ih, mut rh) = (i.host(&tc, &ci), r.host(&tc, &cr));
        let (id, _, final_ack) = until_final_ack(&i, &mut ih, &r, &mut rh, &ci);
        ci.advance(INACTIVITY_DEADLINE - NS);
        assert_eq!(idle(&mut ih), 1);
        assert_eq!(i.state(ih.session(), &id), "AwaitInitiatorFinishAckSend");
        ci.advance(NS);
        let poll = ih.poll_ceremony_deadlines().unwrap();
        assert_eq!((poll.inspected, &poll.event), (1, &ended(&id, INACTIVITY)));
        let cancel = timeout_cancel(poll.outbound, &id, Role::Initiator);
        // No result; the pending final ACK, SAS, and session dropped, then the guard released;
        // the opportunity and the connection kept.
        assert_eq!(
            (i.routes(), i.reserved(), i.status()),
            (0, 0, Status::Ready { remaining: 9 })
        );
        assert!(!ih.is_closed());
        // The final-ACK token from before the timeout can never create a result.
        assert_eq!(
            ih.confirm_sent(final_ack),
            Ok(Err(RouteError::UnknownRoute))
        );
        assert_eq!(i.status(), Status::Ready { remaining: 9 });
        // R, still awaiting that final ACK, authenticates the timeout CANCEL: no result either.
        let dispatched = deliver_in(&mut rh, &cancel, 7).unwrap();
        assert!(matches!(
            dispatched.event,
            HostEvent::Cancel(c) if c.reason() == CancelReason::Timeout
        ));
        assert_eq!(dispatched.result, None);
        assert_eq!(
            (r.routes(), r.status()),
            (0, Status::Ready { remaining: 9 })
        );
        drop((ih, rh));
        i.release();
        r.release();
    }

    #[test]
    fn the_driver_skips_a_busy_run_and_an_admitting_start_without_waiting() {
        let r = Node::new("host-deadline-skip");
        let (tc, cc) = (ManualClock::new(), ManualClock::new());
        let mut h = r.host(&tc, &cc);
        let session = h.session();
        let (x, y) = ([1; 16], [2; 16]);
        admit(&mut h, &start(&x));
        admit(&mut h, &start(&y));
        cc.advance(INACTIVITY_DEADLINE);
        // Another operation holds X, first in order; Y behind it has expired.
        let run = r.router.run_for_test(session, &x);
        let held = run.lock().unwrap();
        assert_eq!(
            h.poll_ceremony_deadlines().unwrap(),
            CeremonyPoll {
                inspected: 2,
                event: ended(&y, INACTIVITY),
                outbound: None,
            }
        );
        // X was neither waited for nor changed; Y ended alone.
        assert_eq!(
            held.state_label_for_test(),
            "ResponderAcceptSentAwaitInitiatorKey"
        );
        drop(held);
        drop(run);
        assert_eq!((r.routes(), r.counts()), (1, (1, 0, 1)));
        // Released, X is polled normally by a later call.
        assert_eq!(
            h.poll_ceremony_deadlines().unwrap(),
            CeremonyPoll {
                inspected: 1,
                event: ended(&x, INACTIVITY),
                outbound: None,
            }
        );
        assert_eq!((r.routes(), r.counts()), (0, (1, 0, 0)));

        // A new START for Z, before W in order, pauses mid-admission with its limiter charge,
        // permit, and pending slot; W behind it has expired.
        let (z, w) = ([0x0A; 16], [0x0B; 16]);
        admit(&mut h, &start(&w));
        cc.advance(INACTIVITY_DEADLINE);
        let (arrived, arrival) = mpsc::channel();
        let (resume, resumed) = mpsc::channel::<()>();
        thread::scope(|scope| {
            let admission = scope.spawn(|| {
                test_hook::install(move |point| {
                    if point == Point::ResponderAdmitted {
                        arrived.send(()).unwrap();
                        resumed.recv().unwrap();
                    }
                });
                r.router.receive_start_with_clock(
                    ManualClock::new(),
                    session,
                    &start(&z),
                    responder_bootstrap(),
                    None,
                )
            });
            arrival.recv().unwrap();
            let charged = r.charged();
            assert_eq!(r.counts(), (1, 0, 2));
            // The claim is inspected work, skipped without waiting for its admission.
            assert_eq!(
                h.poll_ceremony_deadlines().unwrap(),
                CeremonyPoll {
                    inspected: 2,
                    event: ended(&w, INACTIVITY),
                    outbound: None,
                }
            );
            // Only W's slot was released; the claim's charge and slot are untouched.
            assert_eq!((r.charged(), r.counts()), (charged, (1, 0, 1)));
            resume.send(()).unwrap();
            assert!(matches!(
                admission.join().unwrap(),
                Ok(StartRouting::Accepted(_))
            ));
        });
        // It installed normally, and later polls reach it like any run.
        assert_eq!(r.state(session, &z), "ResponderAcceptSentAwaitInitiatorKey");
        assert_eq!(idle(&mut h), 1);
        assert_eq!((r.routes(), r.counts()), (1, (1, 0, 1)));
        drop(h);
        r.release();
    }

    #[test]
    fn an_unusable_ceremony_clock_fails_only_its_run_and_a_poisoned_run_ends_the_connection() {
        let r = Node::new("host-deadline-clock");
        let (tc, cc, cx, cy) = (
            ManualClock::new(),
            ManualClock::new(),
            ManualClock::new(),
            ManualClock::new(),
        );
        let mut h = r.host(&tc, &cc);
        let session = h.session();
        let (x, y, z) = ([1; 16], [2; 16], [3; 16]);
        initiate_on(&r, &h, &cx, x);
        initiate_on(&r, &h, &cy, y);
        // No value: X fails closed, which is neither a timeout claim nor anything to send.
        cx.fail();
        assert_eq!(
            h.poll_ceremony_deadlines().unwrap(),
            CeremonyPoll {
                inspected: 1,
                event: ended(&x, CeremonyDeadline::ClockUnavailable),
                outbound: None,
            }
        );
        assert_eq!((r.routes(), r.reserved()), (1, 1));
        assert_eq!(r.state(session, &y), "InitiatorAwaitAccept");
        assert!(!h.is_closed());
        // A backwards reading is the same run-local failure.
        cy.advance(Duration::from_secs(10));
        assert_eq!(idle(&mut h), 1);
        cy.set(Duration::from_secs(5));
        assert_eq!(
            h.poll_ceremony_deadlines().unwrap(),
            CeremonyPoll {
                inspected: 1,
                event: ended(&y, CeremonyDeadline::ClockUnavailable),
                outbound: None,
            }
        );
        assert_eq!((r.routes(), r.reserved(), r.counts()), (0, 0, (1, 0, 0)));
        assert!(!h.is_closed());
        assert_eq!(r.status(), Status::Ready { remaining: 10 });
        // A poisoned run lock is ownership uncertainty, not a run outcome: the connection ends,
        // and since its Router teardown is uncertain its live count stays held for good.
        admit(&mut h, &start(&z));
        poison_run(&r.router, session, &z);
        assert_eq!(
            h.poll_ceremony_deadlines(),
            Err(HostError::Transport(TransportError::OwnershipUncertain))
        );
        assert!(h.is_closed());
        assert_eq!(r.counts().0, 1);
        assert_eq!(
            h.poll_ceremony_deadlines(),
            Err(HostError::Transport(TransportError::Closed))
        );
        drop(h);
        assert_eq!(r.counts().0, 1);
        r.release();
    }

    #[test]
    fn uncertain_cleanup_of_a_timed_out_exposed_run_ends_the_connection_and_sends_nothing() {
        let (i, r) = (
            Node::new("host-deadline-uncertain-i"),
            Node::new("host-deadline-uncertain-r"),
        );
        let (tc, ci, cr) = (ManualClock::new(), ManualClock::new(), ManualClock::new());
        let (mut ih, mut rh) = (i.host(&tc, &ci), r.host(&tc, &cr));
        establish(&i, &mut ih, &r, &mut rh, &ci);
        ci.advance(ABSOLUTE_DEADLINE);
        // The authority's shared state becomes unusable, so the guard release on timeout
        // cannot be established.
        let executor = i.executor.clone();
        let _ = thread::spawn(move || {
            let _shared = executor.0.shared.lock().unwrap();
            panic!("simulate uncertain guard state");
        })
        .join();
        // The run is terminal, but its built CANCEL is withheld with the uncertain cleanup, no
        // event is reported as run-local, and the connection ends with its live count held.
        assert_eq!(
            ih.poll_ceremony_deadlines(),
            Err(HostError::Transport(TransportError::OwnershipUncertain))
        );
        assert!(ih.is_closed());
        assert_eq!((i.counts().0, i.routes()), (1, 0));
        drop(ih);
        assert_eq!(i.counts().0, 1);
        drop(rh);
        i.release();
        r.release();
    }

    #[test]
    fn a_deadline_poll_never_enters_a_session_that_began_closing() {
        let r = Node::new("host-deadline-closed");
        let (tc, cc) = (ManualClock::new(), ManualClock::new());
        let mut h = r.host(&tc, &cc);
        admit(&mut h, &start(&[1; 16]));
        cc.advance(ABSOLUTE_DEADLINE);
        // Closed elsewhere first: its teardown ended the run (no CANCEL, no result), and no
        // deadline poll can reach it afterwards; the host settles and ends the connection.
        r.router.close_session(h.session()).unwrap();
        assert_eq!(
            h.poll_ceremony_deadlines(),
            Err(HostError::Routing(RouteError::UnknownSession))
        );
        assert!(h.is_closed());
        assert_eq!((r.counts(), r.routes()), ((0, 0, 0), 0));
        assert_eq!(
            h.poll_ceremony_deadlines(),
            Err(HostError::Transport(TransportError::Closed))
        );
        drop(h);
        r.release();
    }
}
