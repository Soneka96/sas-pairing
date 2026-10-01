//! Crate-private remote ceremony through SAS establishment, local human comparison, the
//! authenticated BOOTSTRAP_MAC approval exchange, and the three-message authenticated finish
//! handshake that yields a local, ceremony-scoped `PairingResult`. After SAS establishment,
//! local reject/cancel emits a best-effort authenticated CANCEL and a verified peer CANCEL
//! terminates the run without a result.
//! The P3 11.3 five-minute absolute and 60-second inactivity deadlines are enforced before
//! every state-advancing operation and by `poll_deadlines`; no scheduler exists, so the host's
//! bounded deadline driver (called by a future adapter) drives the poll while a run is idle.
//! The honest Initiator generates its 16-byte request ID with the OS CSPRNG and atomically
//! reserves it in the authority's active local Initiator namespace before START can exist;
//! fixed request IDs are accepted only by `#[cfg(test)]` constructors.
//! P3 11.1.1 core pre-exposure controls: the authority-wide START admission limiter (burst 4,
//! 1 token / 5 s; at most 12 per rolling 60 s), at most 4 pending (accepted, unexposed)
//! Responders and 2 concurrent expensive preliminary operations per authority, and a fixed
//! 60-second pending resource lifetime from admission. Session + request-ID routing lives in
//! `router`, the socket-free transport controls in `transport`, and complete-frame dispatch in
//! `host`, which also drives ceremony deadlines boundedly on request; no scheduler or real
//! socket exists.
#![allow(dead_code)] // The protocol remains internal until later P4 work defines its complete API.
use crate::{
    Authorization, Ceremony, CeremonyExecutor, Error as OwnerError, PendingAdmission,
    RequestIdReservation, Role, StartLimit, TrustedAuthority,
    crypto::{self, Completion, EphemeralSas, Established},
    deadline::{
        CeremonyDeadlines, Clock, Deadline, Inactivity, Verdict, pending_expired, system_clock,
    },
    protocol::{self, Bootstrap, CancelReason, DecodedMessage, Message},
    request_id::{OsRequestIds, RequestIdGenerator},
};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CeremonyError {
    Owner(OwnerError),
    Codec(protocol::CodecError),
    Crypto(crypto::Error),
    InvalidState,
    /// No SAS of this ceremony is live: not yet established, or the ceremony is terminal.
    NoLiveSas,
    /// A local comparison decision targeted a different `ceremony_identity`.
    CeremonyIdentityMismatch,
    /// Own BOOTSTRAP_MAC requested before the local human MATCH was recorded.
    NotLocallyApproved,
    /// A bidirectional message carried a sender role other than the expected peer role.
    UnexpectedSenderRole,
    InvalidRequestId,
    /// The OS CSPRNG produced no request ID: no START, reservation, or ceremony exists.
    RequestIdGenerationFailed,
    RequestIdMismatch,
    SharedContextMismatch,
    ExpectedPeerMismatch,
    /// INITIATOR_FINISH requested before both approvals were authenticated.
    ApprovalsNotAuthenticated,
    /// Only the Initiator may start the completion handshake.
    NotInitiator,
    /// A completion message carried a transcript digest other than our `ceremony_identity`.
    TranscriptMismatch,
    /// The run already reached local success; later input is rejected without any effect.
    Completed,
    /// A final-ACK send confirmation arrived while no INITIATOR_FINISH_ACK awaits sending.
    NoPendingFinalAck,
    /// A send confirmation named bytes other than this run's pending INITIATOR_FINISH_ACK.
    FinalAckMismatch,
    /// A deadline had expired when this operation was attempted; the input was not applied
    /// and the run is ALREADY terminal (see `Timeout`).
    TimedOut(Timeout),
    /// The monotonic clock gave no value, went backwards, or elapsed time was not computable.
    /// The run failed closed (terminal, no result) without claiming an authenticated timeout.
    ClockUnavailable,
    /// The fixed 60-second pending pre-exposure resource lifetime ended before this Responder
    /// crossed exposure; the input was not applied and the run is ALREADY terminal. A generic
    /// local resource outcome: no CANCEL, no timeout claim about the peer, nothing spent.
    PendingExpired,
}
impl From<OwnerError> for CeremonyError {
    fn from(e: OwnerError) -> Self {
        Self::Owner(e)
    }
}
impl From<protocol::CodecError> for CeremonyError {
    fn from(e: protocol::CodecError) -> Self {
        Self::Codec(e)
    }
}
impl From<crypto::Error> for CeremonyError {
    fn from(e: crypto::Error) -> Self {
        Self::Crypto(e)
    }
}

enum State {
    InitiatorCreated {
        start: DecodedMessage,
        local: Bootstrap,
        expected: Option<Bootstrap>,
    },
    InitiatorAwaitAccept {
        start: DecodedMessage,
        local: Bootstrap,
        expected: Option<Bootstrap>,
    },
    InitiatorAwaitAuthorization {
        start: DecodedMessage,
        accept: DecodedMessage,
        authorization: Option<Authorization>,
    },
    InitiatorAwaitResponderKey {
        start: DecodedMessage,
        accept: DecodedMessage,
        ephemeral: EphemeralSas,
        ikey: DecodedMessage,
    },
    ResponderAcceptSentAwaitInitiatorKey {
        start: DecodedMessage,
        accept: DecodedMessage,
        ephemeral: EphemeralSas,
        rpub: [u8; 32],
    },
    ResponderAwaitAuthorization {
        start: DecodedMessage,
        accept: DecodedMessage,
        ikey: DecodedMessage,
        established: Established,
        rpub: [u8; 32],
        authorization: Option<Authorization>,
    },
    /// The transcript and `ceremony_identity` are fixed; the complete SAS awaits a local decision.
    /// A verified peer BOOTSTRAP_MAC authenticates only the peer's approval, never ours.
    AwaitLocalApproval { session: SasSession, peer: PeerMac },
    /// Local human MATCH recorded for exactly this identity; own BOOTSTRAP_MAC not yet emitted.
    LocallyApprovedAwaitingAuthentication { session: SasSession, peer: PeerMac },
    /// Own BOOTSTRAP_MAC emitted once; the peer's approval MAC has not yet been verified.
    LocalMacSentAwaitingPeerMac { session: SasSession },
    /// Local approval recorded, own BOOTSTRAP_MAC emitted, and peer BOOTSTRAP_MAC verified.
    /// Not success. I may now emit INITIATOR_FINISH; R emits nothing and awaits it (P3
    /// `AwaitInitiatorFinish`). The session is retained and the guard stays held.
    ApprovalsAuthenticatedAwaitingCompletion { session: SasSession },
    /// I emitted INITIATOR_FINISH once and awaits RESPONDER_FINISH_ACK.
    AwaitResponderFinish { session: SasSession },
    /// R verified INITIATOR_FINISH, emitted RESPONDER_FINISH_ACK once, and awaits the final ACK.
    AwaitInitiatorFinishAck { session: SasSession },
    /// I verified RESPONDER_FINISH_ACK and produced exactly one INITIATOR_FINISH_ACK, retained
    /// here byte for byte. Not success: no result exists until the local send boundary for
    /// exactly these bytes is confirmed. The session is retained and the guard stays held.
    AwaitInitiatorFinishAckSend {
        session: SasSession,
        final_ack: Vec<u8>,
    },
    /// Local verified completion. Only the immutable result remains: no SAS, session, approval,
    /// or guard. Irrevocably terminal; later input cannot alter it.
    Succeeded(PairingResult),
    /// Failed, rejected, cancelled, or otherwise terminated without a result.
    Terminal,
}

/// Whether the peer's BOOTSTRAP_MAC has been verified while our own approval is incomplete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerMac {
    Pending,
    Verified,
}

impl State {
    /// The single inactivity-timer mapping (P3 11.3). Inactivity is suspended only while the
    /// complete SAS is presented and awaits a deliberate human decision, even after the peer's
    /// approval MAC verified; every other live state waits for machine/protocol progress. `None`
    /// means no deadline applies. Deliberately exhaustive: a new state must choose its mode.
    fn inactivity(&self) -> Option<Inactivity> {
        match self {
            State::AwaitLocalApproval { .. } => Some(Inactivity::Suspended),
            State::InitiatorCreated { .. }
            | State::InitiatorAwaitAccept { .. }
            | State::InitiatorAwaitAuthorization { .. }
            | State::InitiatorAwaitResponderKey { .. }
            | State::ResponderAcceptSentAwaitInitiatorKey { .. }
            | State::ResponderAwaitAuthorization { .. }
            | State::LocallyApprovedAwaitingAuthentication { .. }
            | State::LocalMacSentAwaitingPeerMac { .. }
            | State::ApprovalsAuthenticatedAwaitingCompletion { .. }
            | State::AwaitResponderFinish { .. }
            | State::AwaitInitiatorFinishAck { .. }
            | State::AwaitInitiatorFinishAckSend { .. } => Some(Inactivity::Running),
            State::Succeeded(_) | State::Terminal => None,
        }
    }

    /// Changes exactly when the run makes protocol progress: a new state, a recorded exposure
    /// authorization, or a verified peer approval MAC. Exact duplicates, idempotent repeats,
    /// and refused or stale input leave it unchanged.
    fn progress_point(&self) -> (std::mem::Discriminant<State>, bool) {
        let recorded = match self {
            State::InitiatorAwaitAuthorization { authorization, .. }
            | State::ResponderAwaitAuthorization { authorization, .. } => authorization.is_some(),
            State::AwaitLocalApproval { peer, .. }
            | State::LocallyApprovedAwaitingAuthentication { peer, .. } => {
                *peer == PeerMac::Verified
            }
            _ => false,
        };
        (std::mem::discriminant(self), recorded)
    }
}

/// Established-ceremony material, owned only by its state variant so every terminal
/// transition drops it. Retained for approval and completion authentication; never exposed.
struct SasSession {
    role: Role,
    ceremony_identity: [u8; 32],
    sas_bytes: [u8; 6],
    decimal: String,
    request_id: Vec<u8>,
    local_bootstrap: Bootstrap,
    peer_bootstrap: Bootstrap,
    established: Established,
}

impl SasSession {
    fn new(
        role: Role,
        start: &DecodedMessage,
        accept: &DecodedMessage,
        ikey: &DecodedMessage,
        rkey: &DecodedMessage,
        established: Established,
    ) -> Result<Self, CeremonyError> {
        let (ceremony_identity, _) = crypto::transcript_identity(start, accept, ikey, rkey)?;
        let (_, info) = crypto::sas_info(start, accept, ikey, rkey)?;
        let (bytes, decimal) = established.sas(&info);
        let (request_id, initiator) = match &start.message {
            Message::Start {
                request_id,
                bootstrap,
            } => (request_id.clone(), bootstrap.clone()),
            _ => return Err(CeremonyError::InvalidState),
        };
        let responder = match &accept.message {
            Message::Accept { bootstrap, .. } => bootstrap.clone(),
            _ => return Err(CeremonyError::InvalidState),
        };
        let (local_bootstrap, peer_bootstrap) = match role {
            Role::Initiator => (initiator, responder),
            Role::Responder => (responder, initiator),
        };
        Ok(Self {
            role,
            ceremony_identity,
            sas_bytes: *bytes.as_bytes(),
            decimal,
            request_id,
            local_bootstrap,
            peer_bootstrap,
            established,
        })
    }
}

/// What a local comparison interface needs for exactly one live ceremony. It is data only:
/// holding it authorizes nothing, and every decision is rechecked against live ceremony state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SasPresentation {
    ceremony_identity: [u8; 32],
    decimal: String,
}

impl SasPresentation {
    pub(crate) fn ceremony_identity(&self) -> &[u8; 32] {
        &self.ceremony_identity
    }
    /// The complete `NNNN NNNN NNNN` value to compare with the peer's display.
    pub(crate) fn decimal(&self) -> &str {
        &self.decimal
    }
}

/// Human SAS MATCH outcome. Distinct from exposure `Authorization`: it is recorded after
/// exposure, never reserves, consumes, acquires, or releases anything, and emits no output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SasApproval {
    Recorded,
    AlreadyRecorded,
}

/// Own BOOTSTRAP_MAC output. The frame is produced exactly once; a repeated request is
/// `AlreadyEmitted` with no bytes, no MAC calculation, and no state or accounting change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BootstrapMacEmission {
    Emitted(Vec<u8>),
    AlreadyEmitted,
}

/// Inbound peer BOOTSTRAP_MAC outcome. `AlreadyAuthenticated` is an exact duplicate of the
/// accepted frame, ignored without MAC verification or any state change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeerApproval {
    Authenticated,
    AlreadyAuthenticated,
}

/// Own INITIATOR_FINISH output. The frame is produced exactly once; a repeated request is
/// `AlreadyEmitted` with no bytes, no MAC calculation, and no state or accounting change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FinishEmission {
    Emitted(Vec<u8>),
    AlreadyEmitted,
}

/// Outcome of one verified inbound completion message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CompletionReceipt {
    /// R verified INITIATOR_FINISH: send this RESPONDER_FINISH_ACK. R has no result yet.
    SendResponderFinishAck(Vec<u8>),
    /// I verified RESPONDER_FINISH_ACK: send this final INITIATOR_FINISH_ACK. I has no result
    /// until `confirm_initiator_finish_ack_sent` confirms the local send of exactly these
    /// bytes. Nothing will ever confirm that R receives it.
    SendInitiatorFinishAck(Vec<u8>),
    /// R verified INITIATOR_FINISH_ACK and reached local success. Nothing is sent.
    Succeeded,
    /// Exact duplicate of the accepted INITIATOR_FINISH, ignored without MAC work or output.
    AlreadyAccepted,
}

/// Local post-SAS reject/cancel outcome. Both variants mean the ceremony is ALREADY terminal:
/// no result, SAS/session/approval and any pending final ACK dropped, guard released, and the
/// consumed opportunity kept. Neither variant reports anything about the network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LocalCancellation {
    /// Authenticated CANCEL for best-effort sending. Returning it is not sending it; no send
    /// confirmation, delivery acknowledgement, or peer response exists or is awaited.
    Emitted(Vec<u8>),
    /// Authenticated CANCEL construction failed, so there is nothing to send. No
    /// unauthenticated substitute is ever produced.
    NotEmitted,
}

/// A verified peer CANCEL. The run is already terminal with no result. The reason is
/// authenticated diagnostic data only: not a trust verdict, identity claim, or result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PeerCancellation {
    reason: CancelReason,
}

impl PeerCancellation {
    pub(crate) fn reason(&self) -> CancelReason {
        self.reason
    }
}

/// `poll_deadlines` outcome. Polling never refreshes either deadline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DeadlineOutcome {
    /// Live and not expired; nothing changed.
    Active,
    /// A deadline expired; the run is ALREADY terminal.
    TimedOut(Timeout),
    /// The pending pre-exposure resource lifetime ended; the run is ALREADY terminal.
    PendingExpired,
    /// Already terminal or succeeded: no deadline applies and nothing changed.
    Finished,
}

/// A local P3 11.3 timeout. The run is ALREADY terminal: no result, the SAS, session,
/// approval, and any pending final ACK dropped, the guard released, and any consumed
/// opportunity kept. Nothing about the network is reported or awaited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Timeout {
    expired: Deadline,
    cancel: Option<Vec<u8>>,
}

impl Timeout {
    /// Diagnostic only; both deadlines use the one wire reason `0x03` timeout.
    pub(crate) fn expired(&self) -> Deadline {
        self.expired
    }
    /// Authenticated CANCEL reason `0x03` for best-effort sending, present only when a shared
    /// SAS existed and construction succeeded. Before SAS establishment no authenticated
    /// CANCEL exists. Returning it is not sending it.
    pub(crate) fn cancel(&self) -> Option<&[u8]> {
        self.cancel.as_deref()
    }
}

/// P3 9 local verified completion for exactly one ceremony. It is NOT bilateral success: it
/// does not mean the peer received the final message, returned its own result, or durably
/// stored trust, and no distributed commit or common knowledge exists. The Initiator's final
/// INITIATOR_FINISH_ACK may be lost after it was sent and the Initiator holds this result.
///
/// It reports the exact bootstrap bytes the peer supplied in this ceremony under the approved
/// SAS flow. It is not an identity-truth, authorization, trust, or proof-of-possession verdict,
/// and holds no DH secret, session, ephemeral key, reusable secret, or local authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PairingResult {
    request_id: Vec<u8>,
    ceremony_identity: [u8; 32],
    peer_role: Role,
    authenticated_peer_bootstrap: Vec<u8>,
    authenticated_shared_context: Vec<u8>,
    profile_identifier: &'static [u8],
    profile_version: u16,
}

impl PairingResult {
    fn new(
        role: Role,
        request_id: &[u8],
        ceremony_identity: [u8; 32],
        peer_bootstrap: &Bootstrap,
    ) -> Self {
        Self {
            request_id: request_id.to_vec(),
            ceremony_identity,
            peer_role: peer_of(role),
            // Exact retained canonical frame as received, never re-serialized from fields.
            authenticated_peer_bootstrap: peer_bootstrap.canonical_bytes().to_vec(),
            // Byte-equal to our independently supplied context by the pre-exposure check.
            authenticated_shared_context: peer_bootstrap.shared_context().to_vec(),
            profile_identifier: protocol::PROFILE_ID,
            profile_version: protocol::VERSION,
        }
    }
    /// Original routing/diagnostic handle only; never the ceremony identity.
    pub(crate) fn request_id(&self) -> &[u8] {
        &self.request_id
    }
    pub(crate) fn ceremony_identity(&self) -> &[u8; 32] {
        &self.ceremony_identity
    }
    pub(crate) fn peer_role(&self) -> Role {
        self.peer_role
    }
    pub(crate) fn authenticated_peer_bootstrap(&self) -> &[u8] {
        &self.authenticated_peer_bootstrap
    }
    pub(crate) fn authenticated_shared_context(&self) -> &[u8] {
        &self.authenticated_shared_context
    }
    pub(crate) fn profile_identifier(&self) -> &[u8] {
        self.profile_identifier
    }
    pub(crate) fn profile_version(&self) -> u16 {
        self.profile_version
    }
}

pub(crate) struct RemoteCeremony {
    executor: CeremonyExecutor,
    admission: Ceremony,
    state: State,
    seen: Vec<(u8, Vec<u8>)>,
    clock: Clock,
    deadlines: CeremonyDeadlines,
}

impl RemoteCeremony {
    /// Honest local Initiator (P3 §4). The application supplies only its executor, admission
    /// ceremony, local canonical bootstrap, and optional expected peer; it never chooses the
    /// request ID. The core generates 16 raw bytes with the OS CSPRNG and atomically reserves
    /// them in the authority's active local Initiator namespace before building START, so
    /// `start()` can only return bytes whose ID is already reserved. The reservation is owned by
    /// `admission`, spends no opportunity, acquires no guard, and is released exactly once at
    /// terminal cleanup or drop. Deadlines use a production `Instant`-backed monotonic clock.
    pub(crate) fn initiator(
        executor: CeremonyExecutor,
        admission: Ceremony,
        local: Bootstrap,
        expected: Option<Bootstrap>,
    ) -> Result<Self, CeremonyError> {
        let clock = system_clock();
        Self::initiator_with(
            clock,
            &mut OsRequestIds,
            executor,
            admission,
            local,
            expected,
        )
    }

    /// `initiator` with an injected clock and request-ID source. A collision with another live
    /// local Initiator is an internal retry, never an error; only generator failure, uncertain
    /// shared state, or construction failure escapes. The shared lock is held only for each
    /// check-and-insert, never while generating. Any failure after reservation drops
    /// `admission`, whose cleanup releases the ID.
    pub(crate) fn initiator_with(
        clock: Clock,
        ids: &mut dyn RequestIdGenerator,
        executor: CeremonyExecutor,
        mut admission: Ceremony,
        local: Bootstrap,
        expected: Option<Bootstrap>,
    ) -> Result<Self, CeremonyError> {
        if admission.role() != Role::Initiator {
            return Err(CeremonyError::InvalidState);
        }
        let request_id = loop {
            let candidate = ids
                .generate()
                .ok_or(CeremonyError::RequestIdGenerationFailed)?;
            match executor.reserve_request_id(&mut admission, candidate)? {
                RequestIdReservation::Reserved => break candidate,
                RequestIdReservation::Collision => continue,
                RequestIdReservation::NotEligible => return Err(CeremonyError::InvalidState),
            }
        };
        let start = protocol::decode(
            &Message::Start {
                request_id: request_id.to_vec(),
                bootstrap: local.clone(),
            }
            .encode()?,
        )?;
        Self::initiator_from_start(clock, executor, admission, start, local, expected)
    }

    /// Test-only fixed-request-ID Initiator for deterministic vectors. It reserves nothing in
    /// the active namespace, so equal IDs may coexist under test control.
    #[cfg(test)]
    fn initiator_with_fixed_start_for_test(
        executor: CeremonyExecutor,
        admission: Ceremony,
        start_bytes: &[u8],
        local: Bootstrap,
        expected: Option<Bootstrap>,
    ) -> Result<Self, CeremonyError> {
        let clock = system_clock();
        Self::initiator_with_fixed_start_and_clock_for_test(
            clock,
            executor,
            admission,
            start_bytes,
            local,
            expected,
        )
    }

    /// `initiator_with_fixed_start_for_test` with an injected monotonic clock.
    #[cfg(test)]
    fn initiator_with_fixed_start_and_clock_for_test(
        clock: Clock,
        executor: CeremonyExecutor,
        admission: Ceremony,
        start_bytes: &[u8],
        local: Bootstrap,
        expected: Option<Bootstrap>,
    ) -> Result<Self, CeremonyError> {
        let start = protocol::decode(start_bytes)?;
        Self::initiator_from_start(clock, executor, admission, start, local, expected)
    }

    fn initiator_from_start(
        clock: Clock,
        executor: CeremonyExecutor,
        admission: Ceremony,
        start: DecodedMessage,
        local: Bootstrap,
        expected: Option<Bootstrap>,
    ) -> Result<Self, CeremonyError> {
        validate_initiator_request_id(&start)?;
        let peer = match &start.message {
            Message::Start { bootstrap, .. } => bootstrap,
            _ => return Err(CeremonyError::InvalidState),
        };
        if admission.role() != Role::Initiator {
            return Err(CeremonyError::InvalidState);
        }
        if local.shared_context() != peer.shared_context() {
            return Err(CeremonyError::SharedContextMismatch);
        }
        if local.canonical_bytes() != peer.canonical_bytes() {
            return Err(CeremonyError::InvalidState);
        }
        // P3 11.3: the Initiator's absolute deadline starts when its local state is created.
        let now = clock.now().ok_or(CeremonyError::ClockUnavailable)?;
        Ok(Self {
            executor,
            admission,
            state: State::InitiatorCreated {
                start,
                local,
                expected,
            },
            seen: Vec::new(),
            clock,
            deadlines: CeremonyDeadlines::start(now),
        })
    }

    /// Accept START after pre-exposure checks; ACCEPT carries commitment but never R_pub.
    /// Deadlines use a production `Instant`-backed monotonic clock.
    pub(crate) fn responder(
        executor: CeremonyExecutor,
        admission: Ceremony,
        start_bytes: &[u8],
        local: Bootstrap,
        expected: Option<Bootstrap>,
    ) -> Result<(Self, Vec<u8>), CeremonyError> {
        let clock = system_clock();
        Self::responder_with_clock(clock, executor, admission, start_bytes, local, expected)
    }

    /// `responder` with an injected monotonic clock used for this run's whole lifetime. The
    /// START limiter never uses it: it reads only the authority's own limiter clock.
    ///
    /// P3 10 order: structural START candidate parse (frame, header, type, field count,
    /// profile, request ID; the bootstrap stays opaque) -> one atomic authority START limiter
    /// admission -> one preliminary-work permit -> START semantic validation (nested bootstrap
    /// frame, maxima, grammar, context, expected peer) -> read the clock, then immediately
    /// acquire a pending Responder slot recording that instant -> fresh ephemeral state,
    /// commitment, and ACCEPT -> release the permit. A codec rejection before the candidate
    /// boundary charges nothing. Limiter, permit, or slot refusal is `Owner(ResourceLimited)`
    /// with no ACCEPT; an unusable limiter clock is `ClockUnavailable`. Once the limiter has
    /// admitted, every later failure keeps its charge. Nothing spends an opportunity or touches
    /// the exposed-ceremony guard. Any failure after slot admission drops `admission`, whose
    /// cleanup releases the slot. A START routed to an existing run is never a new candidate:
    /// it goes to `receive_start_duplicate`, which does not reach the limiter.
    pub(crate) fn responder_with_clock(
        clock: Clock,
        executor: CeremonyExecutor,
        mut admission: Ceremony,
        start_bytes: &[u8],
        local: Bootstrap,
        expected: Option<Bootstrap>,
    ) -> Result<(Self, Vec<u8>), CeremonyError> {
        let candidate = protocol::start_candidate(start_bytes)?;
        match executor.admit_start(&admission)? {
            StartLimit::Admitted => {}
            StartLimit::Refused => return Err(CeremonyError::Owner(OwnerError::ResourceLimited)),
            StartLimit::UnsafeClock => return Err(CeremonyError::ClockUnavailable),
            StartLimit::NotEligible => return Err(CeremonyError::InvalidState),
        }
        let permit = executor.preliminary_permit()?;
        let start = candidate.decode()?;
        let Message::Start {
            request_id,
            bootstrap: peer,
        } = &start.message
        else {
            return Err(CeremonyError::InvalidState);
        };
        let request_id = request_id.clone();
        validate_bootstraps(&local, peer, expected.as_ref())?;
        // Read first, then admit: the fixed pending lifetime may start marginally early under
        // contention but never late. P3 11.3 starts the absolute deadline at the same instant,
        // when the START passes local admission into active state.
        let now = clock.now().ok_or(CeremonyError::ClockUnavailable)?;
        match executor.admit_pending_responder(&mut admission, now)? {
            PendingAdmission::Admitted => {}
            PendingAdmission::NotEligible => return Err(CeremonyError::InvalidState),
        }
        #[cfg(test)]
        crate::test_hook::fire(crate::test_hook::Point::ResponderAdmitted);
        let ephemeral = EphemeralSas::new();
        let rpub = ephemeral.public_key();
        let commitment = crypto::commitment(&start, &rpub)?;
        let accept_bytes = Message::Accept {
            request_id,
            commitment,
            bootstrap: local,
        }
        .encode()?;
        let accept = protocol::decode(&accept_bytes)?;
        drop(permit);
        let run = Self {
            executor,
            admission,
            state: State::ResponderAcceptSentAwaitInitiatorKey {
                start: start.clone(),
                accept,
                ephemeral,
                rpub,
            },
            seen: vec![(1, start.canonical_bytes().to_vec())],
            clock,
            deadlines: CeremonyDeadlines::start(now),
        };
        Ok((run, accept_bytes))
    }

    /// Crate-private hook that drives expiry while idle, called by the host's bounded deadline
    /// driver (`Router::poll_session_deadlines`): no scheduler, thread, or timer exists. It reads the injected clock and, if a deadline has
    /// expired, times the run out (see `time_out`). A clock that gives no value or goes
    /// backwards fails the run closed with `ClockUnavailable` and no CANCEL. Uncertain guard
    /// release is `Owner(OwnershipUncertain)` with any built CANCEL withheld. It equally
    /// expires a pending Responder whose fixed resource lifetime ended (`PendingExpired`).
    pub(crate) fn poll_deadlines(&mut self) -> Result<DeadlineOutcome, CeremonyError> {
        match self.enforce_deadlines() {
            Ok(Some(_)) => Ok(DeadlineOutcome::Active),
            Ok(None) => Ok(DeadlineOutcome::Finished),
            Err(CeremonyError::TimedOut(timeout)) => Ok(DeadlineOutcome::TimedOut(timeout)),
            Err(CeremonyError::PendingExpired) => Ok(DeadlineOutcome::PendingExpired),
            Err(error) => Err(error),
        }
    }

    /// Runs one entrypoint that can advance the ceremony. Deadlines are enforced first, so an
    /// expired run times out instead of accepting the input. Afterwards the inactivity window
    /// restarts at the checked instant only if the run made protocol progress (its
    /// `progress_point` changed) and is still live; duplicates, idempotent repeats, and
    /// refused input change nothing and buy no time. The absolute deadline is never touched.
    fn step<T>(
        &mut self,
        op: impl FnOnce(&mut Self) -> Result<T, CeremonyError>,
    ) -> Result<T, CeremonyError> {
        let Some(now) = self.enforce_deadlines()? else {
            return op(self);
        };
        let before = self.state.progress_point();
        let result = op(self);
        if self.state.inactivity().is_some() && self.state.progress_point() != before {
            self.deadlines.record_progress(now);
        }
        result
    }

    /// `Ok(Some(now))` while live and unexpired; `Ok(None)` once terminal or succeeded, where
    /// deadlines no longer apply and the clock is not read. Otherwise the run is already
    /// terminal: `TimedOut`, `PendingExpired`, or `ClockUnavailable` for an unusable clock.
    ///
    /// The ceremony deadlines are evaluated first, then, only while this Responder still holds
    /// its pending slot, the separate fixed resource lifetime from its admission instant. When
    /// both have expired the ceremony diagnostic is reported; that order is a local choice, not
    /// P3 precedence, and before exposure both outcomes have identical effects.
    fn enforce_deadlines(&mut self) -> Result<Option<Duration>, CeremonyError> {
        let Some(inactivity) = self.state.inactivity() else {
            return Ok(None);
        };
        let now = self.clock.now();
        let now = match self.deadlines.check(now, inactivity) {
            Verdict::Live => now,
            Verdict::Expired(deadline) => {
                return Err(CeremonyError::TimedOut(self.time_out(deadline)?));
            }
            Verdict::UnsafeClock => None,
        };
        let pending = match (now, self.admission.pending_responder) {
            (Some(now), Some(admitted)) => pending_expired(admitted, now),
            (Some(_), None) => Some(false),
            (None, _) => None,
        };
        match pending {
            Some(false) => Ok(now),
            Some(true) => {
                // Pre-exposure resource expiry: no shared SAS exists, so there is no CANCEL.
                self.terminate()?;
                Err(CeremonyError::PendingExpired)
            }
            None => {
                // An unusable clock is not evidence of a timeout: fail closed, claim nothing.
                self.terminate()?;
                Err(CeremonyError::ClockUnavailable)
            }
        }
    }

    /// Core-owned P3 11.3 local timeout; no caller-supplied identity is involved. With a live
    /// `SasSession` it follows local cancellation exactly: build the authenticated CANCEL
    /// reason `0x03` while `EstablishedSas` exists, drop the session, release the guard, and
    /// only then return the bytes. Before shared SAS establishment it is local terminal
    /// failure with no wire output.
    fn time_out(&mut self, expired: Deadline) -> Result<Timeout, CeremonyError> {
        let cancel = self.end_with_cancel(CancelReason::Timeout)?;
        Ok(Timeout { expired, cancel })
    }

    pub(crate) fn start(&mut self) -> Result<Vec<u8>, CeremonyError> {
        self.step(Self::start_inner)
    }

    fn start_inner(&mut self) -> Result<Vec<u8>, CeremonyError> {
        if !matches!(self.state, State::InitiatorCreated { .. }) {
            return self.reject_order();
        }
        let State::InitiatorCreated {
            start,
            local,
            expected,
        } = std::mem::replace(&mut self.state, State::Terminal)
        else {
            return self.reject_order();
        };
        let bytes = start.canonical_bytes().to_vec();
        self.state = State::InitiatorAwaitAccept {
            start,
            local,
            expected,
        };
        Ok(bytes)
    }

    pub(crate) fn receive_start_duplicate(&mut self, bytes: &[u8]) -> Result<(), CeremonyError> {
        self.step(|run| run.receive_start_duplicate_inner(bytes))
    }

    fn receive_start_duplicate_inner(&mut self, bytes: &[u8]) -> Result<(), CeremonyError> {
        let msg = self.decode(bytes)?;
        if !matches!(msg.message, Message::Start { .. }) {
            return self.reject_order();
        }
        if self.duplicate(1, bytes)? {
            Ok(())
        } else {
            self.reject_order()
        }
    }

    /// This run's local in-memory instance: its admission `Ceremony`'s process-unique, never
    /// reissued ID. Router plumbing only, so a local reference can tell this run from a later
    /// one under a reused routing key. Never on the wire, in any transcript or MAC, in a result,
    /// or persisted; not `ceremony_identity`, peer identity, authentication, or authorization.
    pub(crate) fn instance(&self) -> u64 {
        self.admission.id
    }

    pub(crate) fn is_awaiting_approval(&self) -> bool {
        matches!(self.state, State::AwaitLocalApproval { .. })
    }

    pub(crate) fn is_locally_approved(&self) -> bool {
        matches!(
            self.state,
            State::LocallyApprovedAwaitingAuthentication { .. }
        ) || self.is_own_mac_emitted()
    }

    pub(crate) fn is_own_mac_emitted(&self) -> bool {
        matches!(self.state, State::LocalMacSentAwaitingPeerMac { .. }) || self.in_completion()
    }

    /// Both approvals authenticated and the run is inside the live finish handshake.
    fn in_completion(&self) -> bool {
        matches!(
            self.state,
            State::ApprovalsAuthenticatedAwaitingCompletion { .. }
                | State::AwaitResponderFinish { .. }
                | State::AwaitInitiatorFinishAck { .. }
                | State::AwaitInitiatorFinishAckSend { .. }
        )
    }

    pub(crate) fn is_peer_approval_authenticated(&self) -> bool {
        matches!(
            self.state,
            State::AwaitLocalApproval {
                peer: PeerMac::Verified,
                ..
            } | State::LocallyApprovedAwaitingAuthentication {
                peer: PeerMac::Verified,
                ..
            }
        ) || self.in_completion()
    }

    /// Both approval conditions hold and no finish message has been sent or accepted yet.
    pub(crate) fn is_ready_for_completion(&self) -> bool {
        matches!(
            self.state,
            State::ApprovalsAuthenticatedAwaitingCompletion { .. }
        )
    }

    /// Irrevocably terminal or locally succeeded: no later input can change this run.
    pub(crate) fn is_finished(&self) -> bool {
        matches!(self.state, State::Terminal | State::Succeeded(_))
    }

    /// The immutable local result, only after this role's own success point. Repeated calls
    /// return the same data and cause no transition.
    pub(crate) fn result(&self) -> Option<&PairingResult> {
        match &self.state {
            State::Succeeded(result) => Some(result),
            _ => None,
        }
    }

    /// Available only while this exact SAS awaits a local decision (I2), including after a
    /// peer approval MAC is verified. It never exists before `ceremony_identity` is fixed and
    /// is withdrawn by local approval or any terminal path. It is also withheld, read-only and
    /// without refreshing anything, once a deadline has expired or the clock is unusable, even
    /// before the next poll or operation makes the run terminal.
    pub(crate) fn presentation(&self) -> Option<SasPresentation> {
        match &self.state {
            State::AwaitLocalApproval { session, .. } if self.deadlines_live() => {
                Some(SasPresentation {
                    ceremony_identity: session.ceremony_identity,
                    decimal: session.decimal.clone(),
                })
            }
            _ => None,
        }
    }

    /// Read-only: a live state whose deadlines have not expired under a usable clock.
    fn deadlines_live(&self) -> bool {
        self.state.inactivity().is_some_and(|inactivity| {
            self.deadlines.evaluate(self.clock.now(), inactivity) == Verdict::Live
        })
    }

    /// Local MATCH for exactly this transcript-derived identity. A request ID is never accepted.
    pub(crate) fn approve_sas(
        &mut self,
        ceremony_identity: &[u8; 32],
    ) -> Result<SasApproval, CeremonyError> {
        self.step(|run| run.approve_sas_inner(ceremony_identity))
    }

    fn approve_sas_inner(
        &mut self,
        ceremony_identity: &[u8; 32],
    ) -> Result<SasApproval, CeremonyError> {
        self.live_session(ceremony_identity)?;
        if self.is_locally_approved() {
            return Ok(SasApproval::AlreadyRecorded);
        }
        let State::AwaitLocalApproval { session, peer } =
            std::mem::replace(&mut self.state, State::Terminal)
        else {
            unreachable!()
        };
        self.state = State::LocallyApprovedAwaitingAuthentication { session, peer };
        Ok(SasApproval::Recorded)
    }

    /// Produces own canonical BOOTSTRAP_MAC exactly once, only after local MATCH. Before local
    /// approval, or with no live SAS, it fails without output or effect; it never approves.
    pub(crate) fn emit_bootstrap_mac(&mut self) -> Result<BootstrapMacEmission, CeremonyError> {
        self.step(Self::emit_bootstrap_mac_inner)
    }

    fn emit_bootstrap_mac_inner(&mut self) -> Result<BootstrapMacEmission, CeremonyError> {
        match &self.state {
            State::LocallyApprovedAwaitingAuthentication { .. } => {}
            State::LocalMacSentAwaitingPeerMac { .. }
            | State::ApprovalsAuthenticatedAwaitingCompletion { .. }
            | State::AwaitResponderFinish { .. }
            | State::AwaitInitiatorFinishAck { .. }
            | State::AwaitInitiatorFinishAckSend { .. } => {
                return Ok(BootstrapMacEmission::AlreadyEmitted);
            }
            State::AwaitLocalApproval { .. } => return Err(CeremonyError::NotLocallyApproved),
            _ => return Err(CeremonyError::NoLiveSas),
        }
        let State::LocallyApprovedAwaitingAuthentication { session, peer } =
            std::mem::replace(&mut self.state, State::Terminal)
        else {
            unreachable!()
        };
        let sender = wire_role(session.role);
        let bytes = match own_bootstrap_mac(&session, sender) {
            Ok(bytes) => bytes,
            Err(error) => return self.fail(error),
        };
        self.state = match peer {
            PeerMac::Pending => State::LocalMacSentAwaitingPeerMac { session },
            PeerMac::Verified => State::ApprovalsAuthenticatedAwaitingCompletion { session },
        };
        Ok(BootstrapMacEmission::Emitted(bytes))
    }

    /// Verifies the peer's BOOTSTRAP_MAC against the expected approval statement reconstructed
    /// from retained ceremony state: peer role, this `ceremony_identity`, the six raw SAS bytes,
    /// and the peer's retained canonical bootstrap. It records only the peer's approval.
    pub(crate) fn receive_bootstrap_mac(
        &mut self,
        bytes: &[u8],
    ) -> Result<PeerApproval, CeremonyError> {
        self.step(|run| run.receive_bootstrap_mac_inner(bytes))
    }

    fn receive_bootstrap_mac_inner(&mut self, bytes: &[u8]) -> Result<PeerApproval, CeremonyError> {
        let msg = self.decode(bytes)?;
        if !matches!(msg.message, Message::BootstrapMac { .. }) {
            return self.reject_order();
        }
        if self.duplicate(5, bytes)? {
            return Ok(PeerApproval::AlreadyAuthenticated);
        }
        let session = match &self.state {
            State::AwaitLocalApproval {
                session,
                peer: PeerMac::Pending,
            }
            | State::LocallyApprovedAwaitingAuthentication {
                session,
                peer: PeerMac::Pending,
            }
            | State::LocalMacSentAwaitingPeerMac { session } => session,
            _ => return self.reject_order(),
        };
        let Message::BootstrapMac {
            request_id,
            sender,
            mac,
        } = &msg.message
        else {
            unreachable!()
        };
        let expected_sender = wire_role(peer_of(session.role));
        let verified = if *request_id != session.request_id {
            Err(CeremonyError::RequestIdMismatch)
        } else if *sender != expected_sender {
            Err(CeremonyError::UnexpectedSenderRole)
        } else {
            crypto::bootstrap_mac_strings(
                expected_sender,
                &session.ceremony_identity,
                &session.sas_bytes,
                &session.peer_bootstrap,
            )
            .and_then(|(input, info)| session.established.verify_mac(&input, &info, mac))
            .map_err(CeremonyError::from)
        };
        if let Err(error) = verified {
            return self.fail(error);
        }
        self.seen.push((5, bytes.to_vec()));
        self.state = match std::mem::replace(&mut self.state, State::Terminal) {
            State::AwaitLocalApproval { session, .. } => State::AwaitLocalApproval {
                session,
                peer: PeerMac::Verified,
            },
            State::LocallyApprovedAwaitingAuthentication { session, .. } => {
                State::LocallyApprovedAwaitingAuthentication {
                    session,
                    peer: PeerMac::Verified,
                }
            }
            State::LocalMacSentAwaitingPeerMac { session } => {
                State::ApprovalsAuthenticatedAwaitingCompletion { session }
            }
            _ => unreachable!(),
        };
        Ok(PeerApproval::Authenticated)
    }

    /// Initiator-only start of the P3 9 finish handshake, legal only once both approvals are
    /// authenticated. Produces exactly one INITIATOR_FINISH (`0x06`: exact request ID, our
    /// `ceremony_identity` as transcript digest, vodozemac tag over the `0x35` auth frame) and
    /// enters `AwaitResponderFinish`. A repeat is `AlreadyEmitted` without MAC work. Every
    /// refusal is non-terminal and has no effect. Consumes no opportunity, needs no new
    /// exposure authorization, and keeps the one guard already held.
    pub(crate) fn emit_initiator_finish(&mut self) -> Result<FinishEmission, CeremonyError> {
        self.step(Self::emit_initiator_finish_inner)
    }

    fn emit_initiator_finish_inner(&mut self) -> Result<FinishEmission, CeremonyError> {
        if matches!(self.state, State::Succeeded(_)) {
            return Err(CeremonyError::Completed);
        }
        if self.admission.role() != Role::Initiator {
            return Err(CeremonyError::NotInitiator);
        }
        match &self.state {
            State::ApprovalsAuthenticatedAwaitingCompletion { .. } => {}
            State::AwaitResponderFinish { .. } | State::AwaitInitiatorFinishAckSend { .. } => {
                return Ok(FinishEmission::AlreadyEmitted);
            }
            _ if self.session().is_some() => {
                return Err(CeremonyError::ApprovalsNotAuthenticated);
            }
            _ => return Err(CeremonyError::NoLiveSas),
        }
        let State::ApprovalsAuthenticatedAwaitingCompletion { session } =
            std::mem::replace(&mut self.state, State::Terminal)
        else {
            unreachable!()
        };
        let bytes = match completion_frame(&session, Completion::InitiatorFinish) {
            Ok(bytes) => bytes,
            Err(error) => return self.fail(error),
        };
        self.state = State::AwaitResponderFinish { session };
        Ok(FinishEmission::Emitted(bytes))
    }

    /// Receives INITIATOR_FINISH (R), RESPONDER_FINISH_ACK (I), or INITIATOR_FINISH_ACK (R).
    /// Before any transition it applies the exact/changed-duplicate rules and checks that this
    /// role and state expect exactly this step, the request ID, the transcript digest against
    /// our `ceremony_identity`, and the vodozemac tag over the auth frame and context
    /// reconstructed from local state. Anything else is terminal with no result. Messages are
    /// never queued. After local success every later input is rejected as `Completed`
    /// without touching the result.
    pub(crate) fn receive_completion(
        &mut self,
        bytes: &[u8],
    ) -> Result<CompletionReceipt, CeremonyError> {
        self.step(|run| run.receive_completion_inner(bytes))
    }

    fn receive_completion_inner(
        &mut self,
        bytes: &[u8],
    ) -> Result<CompletionReceipt, CeremonyError> {
        if matches!(self.state, State::Succeeded(_)) {
            return Err(CeremonyError::Completed);
        }
        let msg = self.decode(bytes)?;
        let Some((step, request_id, transcript, mac)) = completion_fields(&msg.message) else {
            return self.reject_order();
        };
        if self.duplicate(completion_wire_type(step), bytes)? {
            return Ok(CompletionReceipt::AlreadyAccepted);
        }
        let session = match (&self.state, step) {
            (
                State::ApprovalsAuthenticatedAwaitingCompletion { session },
                Completion::InitiatorFinish,
            )
            | (State::AwaitResponderFinish { session }, Completion::ResponderFinishAck)
            | (State::AwaitInitiatorFinishAck { session }, Completion::InitiatorFinishAck)
                if wire_role(session.role) == step.receiver() =>
            {
                session
            }
            _ => return self.reject_order(),
        };
        let verified = if request_id != session.request_id {
            Err(CeremonyError::RequestIdMismatch)
        } else if *transcript != session.ceremony_identity {
            Err(CeremonyError::TranscriptMismatch)
        } else {
            crypto::completion_mac_strings(step, &session.ceremony_identity)
                .and_then(|(input, info)| session.established.verify_mac(&input, &info, mac))
                .map_err(CeremonyError::from)
        };
        if let Err(error) = verified {
            return self.fail(error);
        }
        let session = match std::mem::replace(&mut self.state, State::Terminal) {
            State::ApprovalsAuthenticatedAwaitingCompletion { session }
            | State::AwaitResponderFinish { session }
            | State::AwaitInitiatorFinishAck { session } => session,
            _ => unreachable!(),
        };
        match step {
            Completion::InitiatorFinish => {
                let ack = match completion_frame(&session, Completion::ResponderFinishAck) {
                    Ok(bytes) => bytes,
                    Err(error) => return self.fail(error),
                };
                self.seen.push((completion_wire_type(step), bytes.to_vec()));
                self.state = State::AwaitInitiatorFinishAck { session };
                Ok(CompletionReceipt::SendResponderFinishAck(ack))
            }
            Completion::ResponderFinishAck => {
                let ack = match completion_frame(&session, Completion::InitiatorFinishAck) {
                    Ok(bytes) => bytes,
                    Err(error) => return self.fail(error),
                };
                // Produced, not sent: no result until the send boundary is confirmed.
                self.seen.push((completion_wire_type(step), bytes.to_vec()));
                self.state = State::AwaitInitiatorFinishAckSend {
                    session,
                    final_ack: ack.clone(),
                };
                Ok(CompletionReceipt::SendInitiatorFinishAck(ack))
            }
            Completion::InitiatorFinishAck => {
                self.succeed(session)?;
                Ok(CompletionReceipt::Succeeded)
            }
        }
    }

    /// Internal transport-adapter contract: the adapter calls this only after its local send
    /// operation accepted exactly the INITIATOR_FINISH_ACK bytes this run returned. That is the
    /// Initiator's P3 9 success point. It is a local send boundary only, NOT proof that R
    /// received, verified, or succeeded, and not a delivery or storage receipt; there is no
    /// fourth message. The core performs no network I/O here. Bytes other than the pending
    /// frame, or a call with no pending frame, are rejected without any effect and never
    /// create a result; after success the call is `Completed`. Deadlines are checked first: a
    /// confirmation arriving after expiry times the run out and never creates a result.
    pub(crate) fn confirm_initiator_finish_ack_sent(
        &mut self,
        sent: &[u8],
    ) -> Result<(), CeremonyError> {
        self.step(|run| run.confirm_initiator_finish_ack_sent_inner(sent))
    }

    fn confirm_initiator_finish_ack_sent_inner(
        &mut self,
        sent: &[u8],
    ) -> Result<(), CeremonyError> {
        match &self.state {
            State::Succeeded(_) => return Err(CeremonyError::Completed),
            State::AwaitInitiatorFinishAckSend { final_ack, .. } if final_ack == sent => {}
            State::AwaitInitiatorFinishAckSend { .. } => {
                return Err(CeremonyError::FinalAckMismatch);
            }
            _ => return Err(CeremonyError::NoPendingFinalAck),
        }
        let State::AwaitInitiatorFinishAckSend { session, .. } =
            std::mem::replace(&mut self.state, State::Terminal)
        else {
            unreachable!()
        };
        self.succeed(session)
    }

    /// Success cleanup: build the immutable result, drop the session (vodozemac state, SAS
    /// bytes, approval) and duplicate-tracking state, and only then release the guard. The
    /// consumed opportunity stays consumed. An uncertain guard release fails closed: the run
    /// ends without a result even if a final ACK was already sent.
    fn succeed(&mut self, session: SasSession) -> Result<(), CeremonyError> {
        let result = PairingResult::new(
            session.role,
            &session.request_id,
            session.ceremony_identity,
            &session.peer_bootstrap,
        );
        drop(session);
        self.seen = Vec::new();
        self.state = State::Terminal;
        self.executor.terminate(&mut self.admission)?;
        self.state = State::Succeeded(result);
        Ok(())
    }

    /// Local MISMATCH/REJECT: terminal failure with CANCEL reason `0x01` user rejection. See
    /// `cancel_locally` for ordering and outcomes.
    pub(crate) fn reject_sas(
        &mut self,
        ceremony_identity: &[u8; 32],
    ) -> Result<LocalCancellation, CeremonyError> {
        self.step(|run| run.cancel_locally(ceremony_identity, CancelReason::UserRejection))
    }

    /// Local CANCEL: terminal failure with CANCEL reason `0x02` user cancellation. See
    /// `cancel_locally` for ordering and outcomes.
    pub(crate) fn cancel_sas(
        &mut self,
        ceremony_identity: &[u8; 32],
    ) -> Result<LocalCancellation, CeremonyError> {
        self.step(|run| run.cancel_locally(ceremony_identity, CancelReason::UserCancellation))
    }

    /// P3 11.3 local cancellation of the live established ceremony `ceremony_identity`, for any
    /// defined reason (core-owned timeout shares `end_with_cancel` without an identity).
    /// Order: exact-identity check; build the authenticated CANCEL while `EstablishedSas` still
    /// exists; irrevocably drop the session (SAS, approval, any pending final ACK); release the
    /// guard; only then hand back the bytes. Past the identity check the run is terminal on
    /// every path, and local terminality never waits for any send or peer receipt:
    /// - `Ok(Emitted(bytes))`: best-effort output only;
    /// - `Ok(NotEmitted)`: construction failed, nothing to send;
    /// - `Err(Owner(OwnershipUncertain))`: the session is already dropped, the guard stays
    ///   conservatively held, and the built frame is withheld.
    ///
    /// A wrong identity or no live SAS (`CeremonyIdentityMismatch`/`NoLiveSas`, including before
    /// SAS establishment and after success) is rejected without any effect. Nothing is refunded
    /// and no result is created.
    fn cancel_locally(
        &mut self,
        ceremony_identity: &[u8; 32],
        reason: CancelReason,
    ) -> Result<LocalCancellation, CeremonyError> {
        self.live_session(ceremony_identity)?;
        Ok(match self.end_with_cancel(reason)? {
            Some(bytes) => LocalCancellation::Emitted(bytes),
            None => LocalCancellation::NotEmitted,
        })
    }

    /// Shared local-termination order for cancellation and timeout: build the authenticated
    /// CANCEL for `reason` while a live `SasSession` (and its `EstablishedSas`) still exists,
    /// then terminate (drop the session, SAS, approval, and any pending final ACK, then release
    /// the guard), and only then hand back the bytes. `None` when no shared SAS exists or
    /// construction failed; the run is terminal either way. Uncertain guard release returns
    /// `Owner(OwnershipUncertain)` and withholds the built frame.
    fn end_with_cancel(&mut self, reason: CancelReason) -> Result<Option<Vec<u8>>, CeremonyError> {
        let notification = self
            .session()
            .and_then(|session| own_cancel(session, reason).ok());
        self.terminate()?;
        Ok(notification)
    }

    /// Receives the peer's CANCEL (P3 11.3). With a live established SAS it requires canonical
    /// decoding (including a defined reason code), the exact request ID, and the expected peer
    /// sender role, then reconstructs the `0x34` frame and `0x38` context with the peer as
    /// sender, this endpoint as receiver, the local `ceremony_identity`, and the received reason,
    /// and verifies the tag with vodozemac. Only then is it authenticated peer cancellation: the
    /// run becomes terminal with no result, the session (and any pending final ACK) is dropped,
    /// and only then is the guard released. Nothing is sent in response. Any other CANCEL,
    /// including every CANCEL before SAS establishment (no MAC work is possible), is terminal
    /// protocol failure and never reported as peer cancellation. Once terminal nothing changes;
    /// after success it is `Completed`.
    pub(crate) fn receive_cancel(
        &mut self,
        bytes: &[u8],
    ) -> Result<PeerCancellation, CeremonyError> {
        self.step(|run| run.receive_cancel_inner(bytes))
    }

    fn receive_cancel_inner(&mut self, bytes: &[u8]) -> Result<PeerCancellation, CeremonyError> {
        if matches!(self.state, State::Succeeded(_)) {
            return Err(CeremonyError::Completed);
        }
        let msg = self.decode(bytes)?;
        let Message::Cancel {
            request_id,
            sender,
            reason,
            mac,
        } = &msg.message
        else {
            return self.reject_order();
        };
        let Some(session) = self.session() else {
            return self.reject_order();
        };
        let (peer, local) = (wire_role(peer_of(session.role)), wire_role(session.role));
        let verified = if *request_id != session.request_id {
            Err(CeremonyError::RequestIdMismatch)
        } else if *sender != peer {
            Err(CeremonyError::UnexpectedSenderRole)
        } else {
            crypto::cancel_mac_strings(peer, local, &session.ceremony_identity, *reason)
                .and_then(|(input, info)| session.established.verify_mac(&input, &info, mac))
                .map_err(CeremonyError::from)
        };
        if let Err(error) = verified {
            return self.fail(error);
        }
        let reason = *reason;
        self.terminate()?;
        Ok(PeerCancellation { reason })
    }

    /// Callbacks for another identity, or for no live SAS, are rejected without any effect,
    /// so a stale callback can neither approve nor disturb this ceremony.
    fn live_session(&self, ceremony_identity: &[u8; 32]) -> Result<&SasSession, CeremonyError> {
        let session = self.session().ok_or(CeremonyError::NoLiveSas)?;
        if session.ceremony_identity != *ceremony_identity {
            return Err(CeremonyError::CeremonyIdentityMismatch);
        }
        Ok(session)
    }

    fn session(&self) -> Option<&SasSession> {
        match &self.state {
            State::AwaitLocalApproval { session, .. }
            | State::LocallyApprovedAwaitingAuthentication { session, .. }
            | State::LocalMacSentAwaitingPeerMac { session }
            | State::ApprovalsAuthenticatedAwaitingCompletion { session }
            | State::AwaitResponderFinish { session }
            | State::AwaitInitiatorFinishAck { session }
            | State::AwaitInitiatorFinishAckSend { session, .. } => Some(session),
            _ => None,
        }
    }

    #[cfg(test)]
    fn sas_bytes_for_test(&self) -> Option<[u8; 6]> {
        self.session().map(|session| session.sas_bytes)
    }

    /// Read-only state name, so routing tests can show a run was left untouched.
    #[cfg(test)]
    pub(crate) fn state_label_for_test(&self) -> &'static str {
        match &self.state {
            State::InitiatorCreated { .. } => "InitiatorCreated",
            State::InitiatorAwaitAccept { .. } => "InitiatorAwaitAccept",
            State::InitiatorAwaitAuthorization { .. } => "InitiatorAwaitAuthorization",
            State::InitiatorAwaitResponderKey { .. } => "InitiatorAwaitResponderKey",
            State::ResponderAcceptSentAwaitInitiatorKey { .. } => {
                "ResponderAcceptSentAwaitInitiatorKey"
            }
            State::ResponderAwaitAuthorization { .. } => "ResponderAwaitAuthorization",
            State::AwaitLocalApproval { .. } => "AwaitLocalApproval",
            State::LocallyApprovedAwaitingAuthentication { .. } => {
                "LocallyApprovedAwaitingAuthentication"
            }
            State::LocalMacSentAwaitingPeerMac { .. } => "LocalMacSentAwaitingPeerMac",
            State::ApprovalsAuthenticatedAwaitingCompletion { .. } => {
                "ApprovalsAuthenticatedAwaitingCompletion"
            }
            State::AwaitResponderFinish { .. } => "AwaitResponderFinish",
            State::AwaitInitiatorFinishAck { .. } => "AwaitInitiatorFinishAck",
            State::AwaitInitiatorFinishAckSend { .. } => "AwaitInitiatorFinishAckSend",
            State::Succeeded(_) => "Succeeded",
            State::Terminal => "Terminal",
        }
    }

    pub(crate) fn receive_accept(&mut self, bytes: &[u8]) -> Result<(), CeremonyError> {
        self.step(|run| run.receive_accept_inner(bytes))
    }

    fn receive_accept_inner(&mut self, bytes: &[u8]) -> Result<(), CeremonyError> {
        let msg = self.decode(bytes)?;
        if self.duplicate(2, bytes)? {
            return Ok(());
        }
        let (start, local, expected) = match &self.state {
            State::InitiatorAwaitAccept {
                start,
                local,
                expected,
            } => (start, local, expected),
            _ => return self.reject_order(),
        };
        let peer = match &msg.message {
            Message::Accept {
                request_id,
                bootstrap,
                ..
            } => {
                if request_id != request_id_of(start)? {
                    return self.fail(CeremonyError::RequestIdMismatch);
                }
                bootstrap
            }
            _ => return self.reject_order(),
        };
        if let Err(error) = validate_bootstraps(local, peer, expected.as_ref()) {
            return self.fail(error);
        }
        self.seen.push((2, bytes.to_vec()));
        let State::InitiatorAwaitAccept { start, .. } =
            std::mem::replace(&mut self.state, State::Terminal)
        else {
            unreachable!()
        };
        self.state = State::InitiatorAwaitAuthorization {
            start,
            accept: msg,
            authorization: None,
        };
        Ok(())
    }

    pub(crate) fn receive_initiator_key(&mut self, bytes: &[u8]) -> Result<(), CeremonyError> {
        self.step(|run| run.receive_initiator_key_inner(bytes))
    }

    fn receive_initiator_key_inner(&mut self, bytes: &[u8]) -> Result<(), CeremonyError> {
        let msg = self.decode(bytes)?;
        if self.duplicate(3, bytes)? {
            return Ok(());
        }
        let (request_id, public_key) = match &msg.message {
            Message::InitiatorKey {
                request_id,
                public_key,
            } => (request_id, public_key),
            _ => return self.reject_order(),
        };
        let State::ResponderAcceptSentAwaitInitiatorKey {
            start,
            accept,
            ephemeral,
            rpub,
        } = std::mem::replace(&mut self.state, State::Terminal)
        else {
            return self.reject_order();
        };
        if request_id != request_id_of(&start)? {
            return self.fail(CeremonyError::RequestIdMismatch);
        }
        // Pre-exposure DH/contributory validation is bounded preliminary work: without an
        // immediately available permit the run ends unexposed rather than waiting. The consuming
        // DH runs at most once; the permit is released when it ends either way.
        let permit = match self.executor.preliminary_permit() {
            Ok(permit) => permit,
            Err(error) => return self.fail(error.into()),
        };
        let established = ephemeral.establish(public_key);
        drop(permit);
        let established = match established {
            Ok(value) => value,
            Err(error) => return self.fail(error.into()),
        };
        self.seen.push((3, bytes.to_vec()));
        self.state = State::ResponderAwaitAuthorization {
            start,
            accept,
            ikey: msg,
            established,
            rpub,
            authorization: None,
        };
        Ok(())
    }

    pub(crate) fn receive_responder_key(&mut self, bytes: &[u8]) -> Result<(), CeremonyError> {
        self.step(|run| run.receive_responder_key_inner(bytes))
    }

    fn receive_responder_key_inner(&mut self, bytes: &[u8]) -> Result<(), CeremonyError> {
        let msg = self.decode(bytes)?;
        if self.duplicate(4, bytes)? {
            return Ok(());
        }
        let (request_id, public_key) = match &msg.message {
            Message::ResponderKey {
                request_id,
                public_key,
            } => (request_id, public_key),
            _ => return self.reject_order(),
        };
        let State::InitiatorAwaitResponderKey {
            start,
            accept,
            ephemeral,
            ikey,
        } = std::mem::replace(&mut self.state, State::Terminal)
        else {
            return self.reject_order();
        };
        if request_id != request_id_of(&start)? {
            return self.fail(CeremonyError::RequestIdMismatch);
        }
        let commitment = match &accept.message {
            Message::Accept { commitment, .. } => commitment,
            _ => return self.fail(CeremonyError::InvalidState),
        };
        if let Err(error) = crypto::verify_commitment(&start, public_key, commitment) {
            return self.fail(error.into());
        }
        let established = match ephemeral.establish(public_key) {
            Ok(value) => value,
            Err(error) => return self.fail(error.into()),
        };
        self.seen.push((4, bytes.to_vec()));
        let session =
            match SasSession::new(Role::Initiator, &start, &accept, &ikey, &msg, established) {
                Ok(value) => value,
                Err(error) => return self.fail(error),
            };
        self.state = State::AwaitLocalApproval {
            session,
            peer: PeerMac::Pending,
        };
        Ok(())
    }

    /// Called only after the role-specific preconditions are satisfied.
    pub(crate) fn authorize(&mut self, authority: &TrustedAuthority) -> Result<(), CeremonyError> {
        self.step(|run| run.authorize_inner(authority))
    }

    fn authorize_inner(&mut self, authority: &TrustedAuthority) -> Result<(), CeremonyError> {
        if !matches!(
            self.state,
            State::InitiatorAwaitAuthorization {
                authorization: None,
                ..
            } | State::ResponderAwaitAuthorization {
                authorization: None,
                ..
            }
        ) {
            return self.fail(CeremonyError::InvalidState);
        }
        let token = match authority.authorize(&mut self.admission) {
            Ok(token) => token,
            Err(error) => return self.fail(error.into()),
        };
        match &mut self.state {
            State::InitiatorAwaitAuthorization { authorization, .. }
            | State::ResponderAwaitAuthorization { authorization, .. } => {
                *authorization = Some(token);
                Ok(())
            }
            _ => unreachable!(),
        }
    }

    /// Atomically reserves immediately before returning this role's public contribution.
    pub(crate) fn expose_key(&mut self) -> Result<Vec<u8>, CeremonyError> {
        self.step(Self::expose_key_inner)
    }

    fn expose_key_inner(&mut self) -> Result<Vec<u8>, CeremonyError> {
        let state = std::mem::replace(&mut self.state, State::Terminal);
        match state {
            State::InitiatorAwaitAuthorization {
                start,
                accept,
                authorization: Some(token),
            } => {
                // Ephemeral generation is bounded preliminary work. Take the permit before the
                // reservation so a refusal ends the run unexposed with nothing spent; it is held
                // only until INITIATOR_KEY is built, never across waits.
                let permit = match self.executor.preliminary_permit() {
                    Ok(permit) => permit,
                    Err(error) => return self.fail(error.into()),
                };
                if let Err(error) = self.executor.reserve(&mut self.admission, Some(token)) {
                    drop(permit);
                    self.state = State::InitiatorAwaitAuthorization {
                        start,
                        accept,
                        authorization: None,
                    };
                    return self.fail(error.into());
                }
                let ephemeral = EphemeralSas::new();
                let public_key = ephemeral.public_key();
                let request_id = match &start.message {
                    Message::Start { request_id, .. } => request_id.clone(),
                    _ => return self.fail(CeremonyError::InvalidState),
                };
                let bytes = match (Message::InitiatorKey {
                    request_id,
                    public_key,
                })
                .encode()
                {
                    Ok(value) => value,
                    Err(error) => return self.fail(error.into()),
                };
                let ikey = match protocol::decode(&bytes) {
                    Ok(value) => value,
                    Err(error) => return self.fail(error.into()),
                };
                drop(permit);
                self.state = State::InitiatorAwaitResponderKey {
                    start,
                    accept,
                    ephemeral,
                    ikey,
                };
                Ok(bytes)
            }
            State::ResponderAwaitAuthorization {
                start,
                accept,
                ikey,
                established,
                rpub,
                authorization: Some(token),
            } => {
                if let Err(error) = self.executor.reserve(&mut self.admission, Some(token)) {
                    self.state = State::ResponderAwaitAuthorization {
                        start,
                        accept,
                        ikey,
                        established,
                        rpub,
                        authorization: None,
                    };
                    return self.fail(error.into());
                }
                let request_id = match &start.message {
                    Message::Start { request_id, .. } => request_id.clone(),
                    _ => return self.fail(CeremonyError::InvalidState),
                };
                let bytes = match (Message::ResponderKey {
                    request_id,
                    public_key: rpub,
                })
                .encode()
                {
                    Ok(value) => value,
                    Err(error) => return self.fail(error.into()),
                };
                let rkey = match protocol::decode(&bytes) {
                    Ok(value) => value,
                    Err(error) => return self.fail(error.into()),
                };
                let session = match SasSession::new(
                    Role::Responder,
                    &start,
                    &accept,
                    &ikey,
                    &rkey,
                    established,
                ) {
                    Ok(value) => value,
                    Err(error) => return self.fail(error),
                };
                // RESPONDER_KEY now exists for release: R has crossed its exposure boundary and
                // is no longer pending pre-exposure state, so its slot and the fixed resource
                // lifetime end here. Uncertain release fails closed and withholds the bytes.
                if let Err(error) = self.executor.release_pending_responder(&mut self.admission) {
                    return self.fail(error.into());
                }
                self.state = State::AwaitLocalApproval {
                    session,
                    peer: PeerMac::Pending,
                };
                Ok(bytes)
            }
            other => {
                self.state = other;
                self.fail(OwnerError::MissingAuthorization.into())
            }
        }
    }

    /// I1/I2: the assignment drops any SAS session and local approval before the
    /// executor releases the authority guard. Opportunities are never refunded.
    /// A locally succeeded run is already terminal; its result is left untouched.
    pub(crate) fn terminate(&mut self) -> Result<(), CeremonyError> {
        if matches!(self.state, State::Terminal | State::Succeeded(_)) {
            return Ok(());
        }
        self.state = State::Terminal;
        self.executor.terminate(&mut self.admission)?;
        Ok(())
    }

    fn decode(&mut self, bytes: &[u8]) -> Result<DecodedMessage, CeremonyError> {
        match protocol::decode(bytes) {
            Ok(msg) => Ok(msg),
            Err(error) => self.fail(error.into()),
        }
    }
    fn duplicate(&mut self, kind: u8, bytes: &[u8]) -> Result<bool, CeremonyError> {
        if matches!(self.state, State::Succeeded(_)) {
            return Err(CeremonyError::Completed);
        }
        if matches!(self.state, State::Terminal) {
            return self.fail(CeremonyError::InvalidState);
        }
        if let Some((_, previous)) = self.seen.iter().find(|(seen, _)| *seen == kind) {
            if previous == bytes {
                return Ok(true);
            }
            return self.fail(CeremonyError::InvalidState);
        }
        Ok(false)
    }
    fn reject_order<T>(&mut self) -> Result<T, CeremonyError> {
        self.fail(CeremonyError::InvalidState)
    }
    fn fail<T>(&mut self, error: CeremonyError) -> Result<T, CeremonyError> {
        // Success is terminal too: later input is rejected without replacing the result.
        if matches!(self.state, State::Succeeded(_)) {
            return Err(error);
        }
        self.state = State::Terminal;
        let _ = self.executor.terminate(&mut self.admission);
        Err(error)
    }
}

impl Drop for RemoteCeremony {
    fn drop(&mut self) {
        // Drop ephemeral, SAS, and local-approval state before Ceremony's Drop releases the guard.
        self.state = State::Terminal;
    }
}

fn wire_role(role: Role) -> protocol::Role {
    match role {
        Role::Initiator => protocol::Role::Initiator,
        Role::Responder => protocol::Role::Responder,
    }
}
fn peer_of(role: Role) -> Role {
    match role {
        Role::Initiator => Role::Responder,
        Role::Responder => Role::Initiator,
    }
}
/// Own approval statement: our role, this identity and SAS, and OUR canonical bootstrap.
fn own_bootstrap_mac(
    session: &SasSession,
    sender: protocol::Role,
) -> Result<Vec<u8>, CeremonyError> {
    let (input, info) = crypto::bootstrap_mac_strings(
        sender,
        &session.ceremony_identity,
        &session.sas_bytes,
        &session.local_bootstrap,
    )?;
    let mac = session.established.calculate_mac(&input, &info)?;
    Ok(Message::BootstrapMac {
        request_id: session.request_id.clone(),
        sender,
        mac,
    }
    .encode()?)
}
/// Own authenticated CANCEL: exact request ID, our role, `reason`, and the vodozemac tag over
/// the `0x34` frame and `0x38` context with us as sender and the peer as receiver.
fn own_cancel(session: &SasSession, reason: CancelReason) -> Result<Vec<u8>, CeremonyError> {
    let (sender, receiver) = (wire_role(session.role), wire_role(peer_of(session.role)));
    let (input, info) =
        crypto::cancel_mac_strings(sender, receiver, &session.ceremony_identity, reason)?;
    let mac = session.established.calculate_mac(&input, &info)?;
    Ok(Message::Cancel {
        request_id: session.request_id.clone(),
        sender,
        reason,
        mac,
    }
    .encode()?)
}
/// Own completion frame for `step`: exact request ID, `ceremony_identity` as the transcript
/// digest, and the vodozemac tag over the fixed-mapping auth frame and `0x32` context.
fn completion_frame(session: &SasSession, step: Completion) -> Result<Vec<u8>, CeremonyError> {
    debug_assert_eq!(step.sender(), wire_role(session.role));
    let (input, info) = crypto::completion_mac_strings(step, &session.ceremony_identity)?;
    let mac = session.established.calculate_mac(&input, &info)?;
    let message = completion_message(
        step,
        session.request_id.clone(),
        session.ceremony_identity,
        mac,
    );
    Ok(message.encode()?)
}
fn completion_message(
    step: Completion,
    request_id: Vec<u8>,
    transcript: [u8; 32],
    mac: [u8; 32],
) -> Message {
    match step {
        Completion::InitiatorFinish => Message::InitiatorFinish {
            request_id,
            transcript,
            mac,
        },
        Completion::ResponderFinishAck => Message::ResponderFinishAck {
            request_id,
            transcript,
            mac,
        },
        Completion::InitiatorFinishAck => Message::InitiatorFinishAck {
            request_id,
            transcript,
            mac,
        },
    }
}
/// A completion message's step, request ID, transcript digest, and raw tag.
type CompletionFields<'a> = (Completion, &'a [u8], &'a [u8; 32], &'a [u8; 32]);
/// Splits a completion wire message into its step and fields; `None` for every other type.
fn completion_fields(message: &Message) -> Option<CompletionFields<'_>> {
    match message {
        Message::InitiatorFinish {
            request_id,
            transcript,
            mac,
        } => Some((Completion::InitiatorFinish, request_id, transcript, mac)),
        Message::ResponderFinishAck {
            request_id,
            transcript,
            mac,
        } => Some((Completion::ResponderFinishAck, request_id, transcript, mac)),
        Message::InitiatorFinishAck {
            request_id,
            transcript,
            mac,
        } => Some((Completion::InitiatorFinishAck, request_id, transcript, mac)),
        _ => None,
    }
}
fn completion_wire_type(step: Completion) -> u8 {
    match step {
        Completion::InitiatorFinish => 6,
        Completion::ResponderFinishAck => 7,
        Completion::InitiatorFinishAck => 8,
    }
}
fn request_id_of(message: &DecodedMessage) -> Result<&[u8], CeremonyError> {
    match &message.message {
        Message::Start { request_id, .. } => Ok(request_id),
        _ => Err(CeremonyError::InvalidState),
    }
}
fn validate_initiator_request_id(message: &DecodedMessage) -> Result<(), CeremonyError> {
    if request_id_of(message)?.len() == 16 {
        Ok(())
    } else {
        Err(CeremonyError::InvalidRequestId)
    }
}
fn validate_bootstraps(
    local: &Bootstrap,
    peer: &Bootstrap,
    expected: Option<&Bootstrap>,
) -> Result<(), CeremonyError> {
    if local.shared_context() != peer.shared_context() {
        return Err(CeremonyError::SharedContextMismatch);
    }
    if expected.is_some_and(|v| {
        v.application_identity() != peer.application_identity()
            || v.key_algorithm() != peer.key_algorithm()
            || v.public_key() != peer.public_key()
    }) {
        return Err(CeremonyError::ExpectedPeerMismatch);
    }
    Ok(())
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::{
        Status,
        deadline::{
            ABSOLUTE_DEADLINE, INACTIVITY_DEADLINE, ManualClock, PENDING_PRE_EXPOSURE_DEADLINE,
        },
        protocol,
        start_limiter::{ROLLING_WINDOW, StartLimiterSnapshot},
    };
    use serde_json::Value;
    use std::{
        collections::HashSet,
        sync::{
            Arc, Barrier,
            atomic::{AtomicUsize, Ordering as AtomicOrdering},
            mpsc,
        },
    };

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
    fn fixture() -> Value {
        serde_json::from_str(include_str!(
            "../../vectors/p3-remote-vodozemac-draft-01.json"
        ))
        .unwrap()
    }
    fn vector(name: &str) -> Vec<u8> {
        hex(fixture()["wire_messages"][name]["hex"].as_str().unwrap())
    }
    fn decoded(name: &str) -> DecodedMessage {
        protocol::decode(&vector(name)).unwrap()
    }
    fn bootstrap(message: &DecodedMessage, start: bool) -> Bootstrap {
        match &message.message {
            Message::Start { bootstrap, .. } if start => bootstrap.clone(),
            Message::Accept { bootstrap, .. } if !start => bootstrap.clone(),
            _ => panic!("wrong vector message"),
        }
    }
    fn start_with_context(context: &[u8]) -> Vec<u8> {
        let mut b = bootstrap(&decoded("START"), true);
        b = Bootstrap::new(
            b.application_identity().to_vec(),
            b.key_algorithm().to_vec(),
            b.public_key().to_vec(),
            context.to_vec(),
        )
        .unwrap();
        Message::Start {
            request_id: vec![0x42; 16],
            bootstrap: b,
        }
        .encode()
        .unwrap()
    }
    fn executor(scope: &[u8]) -> (TrustedAuthority, CeremonyExecutor) {
        let authority = TrustedAuthority::register(scope).unwrap();
        let executor = authority.executor();
        (authority, executor)
    }

    #[test]
    fn both_roles_reserve_at_key_release_and_derive_same_internal_sas() {
        let start = vector("START");
        let local_i = bootstrap(&decoded("START"), true);
        let local_r = bootstrap(&decoded("ACCEPT"), false);
        let (authority_i, executor_i) = executor(b"ceremony-positive-i");
        let (authority_r, executor_r) = executor(b"ceremony-positive-r");
        let mut initiator = RemoteCeremony::initiator_with_fixed_start_for_test(
            executor_i.clone(),
            executor_i.begin(Role::Initiator).unwrap(),
            &start,
            local_i,
            None,
        )
        .unwrap();
        assert_eq!(initiator.start().unwrap(), start);
        let (mut responder, accept) = RemoteCeremony::responder(
            executor_r.clone(),
            executor_r.begin(Role::Responder).unwrap(),
            &start,
            local_r,
            None,
        )
        .unwrap();
        responder.receive_start_duplicate(&start).unwrap();
        let accept_decoded = protocol::decode(&accept).unwrap();
        assert!(matches!(accept_decoded.message, Message::Accept { .. }));
        assert!(!matches!(
            accept_decoded.message,
            Message::ResponderKey { .. }
        ));
        initiator.receive_accept(&accept).unwrap();
        initiator.receive_accept(&accept).unwrap();
        assert_eq!(
            executor_i.status().unwrap(),
            Status::Ready { remaining: 10 }
        );
        initiator.authorize(&authority_i).unwrap();
        let ikey = initiator.expose_key().unwrap();
        assert_eq!(executor_i.status().unwrap(), Status::Busy);
        responder.receive_initiator_key(&ikey).unwrap();
        responder.receive_initiator_key(&ikey).unwrap();
        responder.authorize(&authority_r).unwrap();
        let rkey = responder.expose_key().unwrap();
        assert_eq!(executor_r.status().unwrap(), Status::Busy);
        let rk = protocol::decode(&rkey).unwrap();
        let public_key = match rk.message {
            Message::ResponderKey { public_key, .. } => public_key,
            _ => unreachable!(),
        };
        let committed = match accept_decoded.message {
            Message::Accept { commitment, .. } => commitment,
            _ => unreachable!(),
        };
        assert_eq!(
            crypto::commitment(&protocol::decode(&start).unwrap(), &public_key).unwrap(),
            committed
        );
        initiator.receive_responder_key(&rkey).unwrap();
        initiator.receive_responder_key(&rkey).unwrap();
        assert!(initiator.is_awaiting_approval());
        assert!(responder.is_awaiting_approval());
        assert!(initiator.presentation().is_some());
        assert_eq!(initiator.presentation(), responder.presentation());
        assert_eq!(
            initiator.sas_bytes_for_test(),
            responder.sas_bytes_for_test()
        );
        assert_eq!(executor_i.status().unwrap(), Status::Busy);
        assert_eq!(executor_r.status().unwrap(), Status::Busy);
        initiator.terminate().unwrap();
        responder.terminate().unwrap();
        assert_eq!(initiator.presentation(), None);
        assert_eq!(responder.presentation(), None);
        assert_eq!(initiator.sas_bytes_for_test(), None);
        assert_eq!(executor_i.status().unwrap(), Status::Ready { remaining: 9 });
        assert_eq!(executor_r.status().unwrap(), Status::Ready { remaining: 9 });
        drop(initiator);
        drop(responder);
        drop(executor_i);
        drop(executor_r);
        authority_i.release().unwrap();
        authority_r.release().unwrap();
    }

    #[test]
    fn request_id_lengths_follow_role_specific_rules() {
        let local_i = bootstrap(&decoded("START"), true);
        let local_r = bootstrap(&decoded("ACCEPT"), false);

        for len in [1, 16, 64] {
            let start = Message::Start {
                request_id: vec![0x42; len],
                bootstrap: local_i.clone(),
            }
            .encode()
            .unwrap();
            let (authority, exec) = executor(format!("responder-request-id-{len}").as_bytes());
            let (responder, accept) = RemoteCeremony::responder(
                exec.clone(),
                exec.begin(Role::Responder).unwrap(),
                &start,
                local_r.clone(),
                None,
            )
            .unwrap();
            assert!(
                matches!(protocol::decode(&accept).unwrap().message, Message::Accept { request_id, .. } if request_id.len() == len)
            );
            assert_eq!(exec.status().unwrap(), Status::Ready { remaining: 10 });
            assert!(
                reserved_ids(&exec).is_empty(),
                "peer IDs are never reserved"
            );
            drop(responder);
            drop(exec);
            authority.release().unwrap();

            let (authority, exec) = executor(format!("initiator-request-id-{len}").as_bytes());
            let result = RemoteCeremony::initiator_with_fixed_start_for_test(
                exec.clone(),
                exec.begin(Role::Initiator).unwrap(),
                &start,
                local_i.clone(),
                None,
            );
            match result {
                Ok(run) if len == 16 => drop(run),
                Err(error) if len != 16 => assert_eq!(error, CeremonyError::InvalidRequestId),
                _ => panic!("initiator accepted an invalid request ID length"),
            }
            assert_eq!(exec.status().unwrap(), Status::Ready { remaining: 10 });
            drop(exec);
            authority.release().unwrap();
        }
    }

    #[test]
    fn missing_authorization_never_exposes_or_spends() {
        let local_i = bootstrap(&decoded("START"), true);
        let local_r = bootstrap(&decoded("ACCEPT"), false);
        let (authority_i, exec_i) = executor(b"ceremony-no-auth-i");
        let mut i = RemoteCeremony::initiator_with_fixed_start_for_test(
            exec_i.clone(),
            exec_i.begin(Role::Initiator).unwrap(),
            &vector("START"),
            local_i,
            None,
        )
        .unwrap();
        i.start().unwrap();
        i.receive_accept(&vector("ACCEPT")).unwrap();
        assert_eq!(
            i.expose_key(),
            Err(CeremonyError::Owner(OwnerError::MissingAuthorization))
        );
        assert_eq!(exec_i.status().unwrap(), Status::Ready { remaining: 10 });
        assert!(i.terminate().is_ok());
        drop(i);
        drop(exec_i);
        authority_i.release().unwrap();

        let (authority_r, exec_r) = executor(b"ceremony-no-auth-r");
        let (mut r, accept) = RemoteCeremony::responder(
            exec_r.clone(),
            exec_r.begin(Role::Responder).unwrap(),
            &vector("START"),
            local_r,
            None,
        )
        .unwrap();
        let request_id = match protocol::decode(&accept).unwrap().message {
            Message::Accept { request_id, .. } => request_id,
            _ => unreachable!(),
        };
        let ikey = Message::InitiatorKey {
            request_id,
            public_key: match decoded("INITIATOR_KEY").message {
                Message::InitiatorKey { public_key, .. } => public_key,
                _ => unreachable!(),
            },
        }
        .encode()
        .unwrap();
        r.receive_initiator_key(&ikey).unwrap();
        assert_eq!(
            r.expose_key(),
            Err(CeremonyError::Owner(OwnerError::MissingAuthorization))
        );
        assert_eq!(exec_r.status().unwrap(), Status::Ready { remaining: 10 });
        drop(r);
        drop(exec_r);
        authority_r.release().unwrap();
    }

    #[test]
    fn mismatch_noncontributory_busy_and_terminal_paths_do_not_leak_or_refund() {
        let start = vector("START");
        let mut wrong = bootstrap(&decoded("START"), true);
        wrong = Bootstrap::new(
            wrong.application_identity().to_vec(),
            wrong.key_algorithm().to_vec(),
            wrong.public_key().to_vec(),
            b"different context".to_vec(),
        )
        .unwrap();
        let (authority_ctx_i, exec_ctx_i) = executor(b"ceremony-context-i");
        assert_eq!(
            RemoteCeremony::initiator_with_fixed_start_for_test(
                exec_ctx_i.clone(),
                exec_ctx_i.begin(Role::Initiator).unwrap(),
                &start,
                wrong.clone(),
                None
            )
            .err()
            .unwrap(),
            CeremonyError::SharedContextMismatch
        );
        assert_eq!(
            exec_ctx_i.status().unwrap(),
            Status::Ready { remaining: 10 }
        );
        drop(exec_ctx_i);
        authority_ctx_i.release().unwrap();
        let (authority_ctx_r, exec_ctx_r) = executor(b"ceremony-context-r");
        assert_eq!(
            RemoteCeremony::responder(
                exec_ctx_r.clone(),
                exec_ctx_r.begin(Role::Responder).unwrap(),
                &start,
                wrong,
                None
            )
            .err()
            .unwrap(),
            CeremonyError::SharedContextMismatch
        );
        assert_eq!(
            exec_ctx_r.status().unwrap(),
            Status::Ready { remaining: 10 }
        );
        drop(exec_ctx_r);
        authority_ctx_r.release().unwrap();

        let mut expected = bootstrap(&decoded("ACCEPT"), false);
        expected = Bootstrap::new(
            expected.application_identity().to_vec(),
            expected.key_algorithm().to_vec(),
            vec![0x99; expected.public_key().len()],
            expected.shared_context().to_vec(),
        )
        .unwrap();
        let (authority_peer_i, exec_peer_i) = executor(b"ceremony-expected-peer-i");
        let mut peer_i = RemoteCeremony::initiator_with_fixed_start_for_test(
            exec_peer_i.clone(),
            exec_peer_i.begin(Role::Initiator).unwrap(),
            &start,
            bootstrap(&decoded("START"), true),
            Some(expected.clone()),
        )
        .unwrap();
        peer_i.start().unwrap();
        assert_eq!(
            peer_i.receive_accept(&vector("ACCEPT")),
            Err(CeremonyError::ExpectedPeerMismatch)
        );
        assert_eq!(
            exec_peer_i.status().unwrap(),
            Status::Ready { remaining: 10 }
        );
        drop(peer_i);
        drop(exec_peer_i);
        authority_peer_i.release().unwrap();

        let (authority_peer_r, exec_peer_r) = executor(b"ceremony-expected-peer-r");
        assert_eq!(
            RemoteCeremony::responder(
                exec_peer_r.clone(),
                exec_peer_r.begin(Role::Responder).unwrap(),
                &start,
                bootstrap(&decoded("ACCEPT"), false),
                Some(expected),
            )
            .err()
            .unwrap(),
            CeremonyError::ExpectedPeerMismatch
        );
        assert_eq!(
            exec_peer_r.status().unwrap(),
            Status::Ready { remaining: 10 }
        );
        drop(exec_peer_r);
        authority_peer_r.release().unwrap();

        let short_start = Message::Start {
            request_id: vec![1],
            bootstrap: bootstrap(&decoded("START"), true),
        }
        .encode()
        .unwrap();
        let (authority_id, exec_id) = executor(b"ceremony-invalid-request-id");
        assert_eq!(
            RemoteCeremony::initiator_with_fixed_start_for_test(
                exec_id.clone(),
                exec_id.begin(Role::Initiator).unwrap(),
                &short_start,
                bootstrap(&decoded("START"), true),
                None,
            )
            .err()
            .unwrap(),
            CeremonyError::InvalidRequestId
        );
        assert_eq!(exec_id.status().unwrap(), Status::Ready { remaining: 10 });
        drop(exec_id);
        authority_id.release().unwrap();

        let local_r = bootstrap(&decoded("ACCEPT"), false);
        let (authority_bad, exec_bad) = executor(b"ceremony-noncontributory");
        let (mut r, _) = RemoteCeremony::responder(
            exec_bad.clone(),
            exec_bad.begin(Role::Responder).unwrap(),
            &start,
            local_r,
            None,
        )
        .unwrap();
        let request_id = match decoded("START").message {
            Message::Start { request_id, .. } => request_id,
            _ => unreachable!(),
        };
        let bad_ikey = Message::InitiatorKey {
            request_id,
            public_key: [0; 32],
        }
        .encode()
        .unwrap();
        assert!(matches!(
            r.receive_initiator_key(&bad_ikey),
            Err(CeremonyError::Crypto(crypto::Error::NonContributory))
        ));
        assert_eq!(exec_bad.status().unwrap(), Status::Ready { remaining: 10 });
        drop(r);
        drop(exec_bad);
        authority_bad.release().unwrap();

        let (authority_busy, exec_busy) = executor(b"ceremony-busy");
        let local_i = bootstrap(&decoded("START"), true);
        let mut first = RemoteCeremony::initiator_with_fixed_start_for_test(
            exec_busy.clone(),
            exec_busy.begin(Role::Initiator).unwrap(),
            &start,
            local_i.clone(),
            None,
        )
        .unwrap();
        first.start().unwrap();
        first.receive_accept(&vector("ACCEPT")).unwrap();
        first.authorize(&authority_busy).unwrap();
        first.expose_key().unwrap();
        let mut second = RemoteCeremony::initiator_with_fixed_start_for_test(
            exec_busy.clone(),
            exec_busy.begin(Role::Initiator).unwrap(),
            &start,
            local_i,
            None,
        )
        .unwrap();
        second.start().unwrap();
        second.receive_accept(&vector("ACCEPT")).unwrap();
        second.authorize(&authority_busy).unwrap();
        assert_eq!(
            second.expose_key(),
            Err(CeremonyError::Owner(OwnerError::Busy))
        );
        assert_eq!(exec_busy.status().unwrap(), Status::Busy);
        first.terminate().unwrap();
        assert_eq!(exec_busy.status().unwrap(), Status::Ready { remaining: 9 });
        drop(first);
        drop(second);
        drop(exec_busy);
        authority_busy.release().unwrap();
    }

    #[test]
    fn commitment_mismatch_duplicate_mutation_ordering_and_terminal_irreversibility() {
        let start = vector("START");
        let local_i = bootstrap(&decoded("START"), true);
        let (authority, exec) = executor(b"ceremony-irreversible");
        let mut run = RemoteCeremony::initiator_with_fixed_start_for_test(
            exec.clone(),
            exec.begin(Role::Initiator).unwrap(),
            &start,
            local_i,
            None,
        )
        .unwrap();
        run.start().unwrap();
        run.receive_accept(&vector("ACCEPT")).unwrap();
        run.receive_accept(&vector("ACCEPT")).unwrap();
        let mut changed = vector("ACCEPT");
        *changed.last_mut().unwrap() ^= 1;
        assert!(run.receive_accept(&changed).is_err());
        assert_eq!(exec.status().unwrap(), Status::Ready { remaining: 10 });
        assert!(run.receive_accept(&vector("ACCEPT")).is_err());
        drop(run);

        let mut run = RemoteCeremony::initiator_with_fixed_start_for_test(
            exec.clone(),
            exec.begin(Role::Initiator).unwrap(),
            &start,
            bootstrap(&decoded("START"), true),
            None,
        )
        .unwrap();
        run.start().unwrap();
        run.receive_accept(&vector("ACCEPT")).unwrap();
        run.authorize(&authority).unwrap();
        let ikey = run.expose_key().unwrap();
        let request_id = match protocol::decode(&ikey).unwrap().message {
            Message::InitiatorKey { request_id, .. } => request_id,
            _ => unreachable!(),
        };
        let bad_rkey = Message::ResponderKey {
            request_id,
            public_key: [7; 32],
        }
        .encode()
        .unwrap();
        assert!(matches!(
            run.receive_responder_key(&bad_rkey),
            Err(CeremonyError::Crypto(crypto::Error::CommitmentMismatch))
        ));
        assert_eq!(exec.status().unwrap(), Status::Ready { remaining: 9 });
        assert!(run.receive_responder_key(&vector("RESPONDER_KEY")).is_err());
        drop(run);

        let mut run = RemoteCeremony::initiator_with_fixed_start_for_test(
            exec.clone(),
            exec.begin(Role::Initiator).unwrap(),
            &start,
            bootstrap(&decoded("START"), true),
            None,
        )
        .unwrap();
        run.start().unwrap();
        let zero = [0; 32];
        let commitment = crypto::commitment(&protocol::decode(&start).unwrap(), &zero).unwrap();
        let request_id = match decoded("START").message {
            Message::Start { request_id, .. } => request_id,
            _ => unreachable!(),
        };
        let accept = Message::Accept {
            request_id: request_id.clone(),
            commitment,
            bootstrap: bootstrap(&decoded("ACCEPT"), false),
        }
        .encode()
        .unwrap();
        run.receive_accept(&accept).unwrap();
        run.authorize(&authority).unwrap();
        run.expose_key().unwrap();
        let noncontributory = Message::ResponderKey {
            request_id,
            public_key: zero,
        }
        .encode()
        .unwrap();
        assert!(matches!(
            run.receive_responder_key(&noncontributory),
            Err(CeremonyError::Crypto(crypto::Error::NonContributory))
        ));
        assert_eq!(exec.status().unwrap(), Status::Ready { remaining: 8 });
        drop(run);

        let mut run = RemoteCeremony::initiator_with_fixed_start_for_test(
            exec.clone(),
            exec.begin(Role::Initiator).unwrap(),
            &start,
            bootstrap(&decoded("START"), true),
            None,
        )
        .unwrap();
        run.start().unwrap();
        assert!(run.receive_responder_key(&vector("RESPONDER_KEY")).is_err());
        assert_eq!(exec.status().unwrap(), Status::Ready { remaining: 8 });
        drop(run);
        drop(exec);
        authority.release().unwrap();
    }

    #[test]
    fn prepared_responder_never_auto_reveals_after_busy_reservation() {
        let start = vector("START");
        let (authority, executor) = executor(b"ceremony-prepared-busy");
        let mut initiator = RemoteCeremony::initiator_with_fixed_start_for_test(
            executor.clone(),
            executor.begin(Role::Initiator).unwrap(),
            &start,
            bootstrap(&decoded("START"), true),
            None,
        )
        .unwrap();
        initiator.start().unwrap();
        initiator.receive_accept(&vector("ACCEPT")).unwrap();
        initiator.authorize(&authority).unwrap();
        let ikey = initiator.expose_key().unwrap();

        let (mut responder, accept) = RemoteCeremony::responder(
            executor.clone(),
            executor.begin(Role::Responder).unwrap(),
            &start,
            bootstrap(&decoded("ACCEPT"), false),
            None,
        )
        .unwrap();
        responder.receive_start_duplicate(&start).unwrap();
        responder.receive_initiator_key(&ikey).unwrap();
        responder.authorize(&authority).unwrap();
        assert_eq!(
            responder.expose_key(),
            Err(CeremonyError::Owner(OwnerError::Busy))
        );
        assert!(matches!(
            protocol::decode(&accept).unwrap().message,
            Message::Accept { .. }
        ));
        assert_eq!(executor.status().unwrap(), Status::Busy);

        initiator.terminate().unwrap();
        assert_eq!(executor.status().unwrap(), Status::Ready { remaining: 9 });
        assert!(responder.authorize(&authority).is_err());
        assert!(responder.expose_key().is_err());
        assert_eq!(executor.status().unwrap(), Status::Ready { remaining: 9 });
        drop(initiator);
        drop(responder);
        drop(executor);
        authority.release().unwrap();
    }

    struct Authorities {
        i: TrustedAuthority,
        ei: CeremonyExecutor,
        r: TrustedAuthority,
        er: CeremonyExecutor,
        /// Each authority's one injected START-limiter clock; never a ceremony clock.
        li: Arc<ManualClock>,
        lr: Arc<ManualClock>,
    }
    impl Authorities {
        fn new(scope: &str) -> Self {
            let (i, ei, li) = limited_executor(format!("{scope}-i").as_bytes());
            let (r, er, lr) = limited_executor(format!("{scope}-r").as_bytes());
            Self {
                i,
                ei,
                r,
                er,
                li,
                lr,
            }
        }
        fn release(self) {
            drop(self.ei);
            drop(self.er);
            self.i.release().unwrap();
            self.r.release().unwrap();
        }
    }
    struct Pair {
        i: RemoteCeremony,
        r: RemoteCeremony,
        wire: [Vec<u8>; 4],
    }
    impl Pair {
        fn identity(&self) -> [u8; 32] {
            *self.i.presentation().unwrap().ceremony_identity()
        }
    }

    /// An authority whose START limiter reads one test-controlled clock.
    fn limited_executor(scope: &[u8]) -> (TrustedAuthority, CeremonyExecutor, Arc<ManualClock>) {
        let clock = ManualClock::new();
        let authority =
            TrustedAuthority::register_with_limiter_clock(scope, clock.clone()).unwrap();
        let executor = authority.executor();
        (authority, executor, clock)
    }

    /// Lets one full rolling window of limiter time pass on both authorities, so their START
    /// limiters are full and empty again. Tests of other controls use this before each new
    /// Responder so only the control under test can refuse; limiter tests never do.
    fn refill_start_limiters(a: &Authorities) {
        a.li.advance(ROLLING_WINDOW);
        a.lr.advance(ROLLING_WINDOW);
    }

    fn vector_request_id() -> Vec<u8> {
        request_id_of(&decoded("START")).unwrap().to_vec()
    }

    fn remaining(executor: &CeremonyExecutor) -> u8 {
        executor.0.shared.lock().unwrap().remaining
    }

    fn assert_no_live_sas(run: &RemoteCeremony) {
        assert_eq!(run.presentation(), None);
        assert_eq!(run.sas_bytes_for_test(), None);
        assert!(!run.is_awaiting_approval() && !run.is_locally_approved());
    }

    /// Runs one legal key exchange with the fixed-request-ID vector START and fresh keys.
    /// No SAS presentation may exist, and no local decision may apply, before both keys.
    fn establish(a: &Authorities) -> Pair {
        establish_with(a, system_clock(), system_clock())
    }

    /// `establish` with injected per-endpoint clocks.
    fn establish_with(a: &Authorities, clock_i: Clock, clock_r: Clock) -> Pair {
        let i = RemoteCeremony::initiator_with_fixed_start_and_clock_for_test(
            clock_i,
            a.ei.clone(),
            a.ei.begin(Role::Initiator).unwrap(),
            &vector("START"),
            bootstrap(&decoded("START"), true),
            None,
        )
        .unwrap();
        establish_from(a, i, clock_r)
    }

    /// Runs one legal key exchange from a created, not yet started Initiator.
    fn establish_from(a: &Authorities, i: RemoteCeremony, clock_r: Clock) -> Pair {
        refill_start_limiters(a);
        exchange_keys(a, i, clock_r)
    }

    /// `establish_from` without refilling the START limiters.
    fn exchange_keys(a: &Authorities, mut i: RemoteCeremony, clock_r: Clock) -> Pair {
        assert_no_live_sas(&i);
        let start = i.start().unwrap();
        let (mut r, accept) = RemoteCeremony::responder_with_clock(
            clock_r,
            a.er.clone(),
            a.er.begin(Role::Responder).unwrap(),
            &start,
            bootstrap(&decoded("ACCEPT"), false),
            None,
        )
        .unwrap();
        assert_no_live_sas(&r);
        i.receive_accept(&accept).unwrap();
        assert_eq!(i.approve_sas(&[0; 32]), Err(CeremonyError::NoLiveSas));
        i.authorize(&a.i).unwrap();
        let ikey = i.expose_key().unwrap();
        assert_no_live_sas(&i);
        r.receive_initiator_key(&ikey).unwrap();
        assert_eq!(r.cancel_sas(&[0; 32]), Err(CeremonyError::NoLiveSas));
        assert_no_live_sas(&r);
        r.authorize(&a.r).unwrap();
        let rkey = r.expose_key().unwrap();
        assert_no_live_sas(&i);
        i.receive_responder_key(&rkey).unwrap();
        assert!(i.is_awaiting_approval() && r.is_awaiting_approval());
        Pair {
            i,
            r,
            wire: [start, accept, ikey, rkey],
        }
    }

    fn matrix_decimal(bytes: &[u8; 6]) -> String {
        let b = bytes.map(u16::from);
        let first = ((b[0] << 5) | (b[1] >> 3)) + 1000;
        let second = (((b[1] & 0x7) << 10) | (b[2] << 2) | (b[3] >> 6)) + 1000;
        let third = (((b[3] & 0x3f) << 7) | (b[4] >> 1)) + 1000;
        format!("{first:04} {second:04} {third:04}")
    }

    #[test]
    fn complete_sas_is_presented_only_after_transcript_identity_is_fixed() {
        let sas = &fixture()["sas"];
        let raw: [u8; 6] = hex(sas["raw_bytes"]["hex"].as_str().unwrap())
            .try_into()
            .unwrap();
        assert_eq!(
            matrix_decimal(&raw),
            sas["decimal_values"]["rendered"].as_str().unwrap()
        );

        let a = Authorities::new("sas-presentation");
        let pair = establish(&a);
        let (pi, pr) = (
            pair.i.presentation().unwrap(),
            pair.r.presentation().unwrap(),
        );
        assert_eq!(pi, pr);
        let wire: Vec<_> = pair
            .wire
            .iter()
            .map(|b| protocol::decode(b).unwrap())
            .collect();
        let (identity, _) =
            crypto::transcript_identity(&wire[0], &wire[1], &wire[2], &wire[3]).unwrap();
        assert_eq!(*pi.ceremony_identity(), identity);
        let bytes = pair.i.sas_bytes_for_test().unwrap();
        assert_eq!(Some(bytes), pair.r.sas_bytes_for_test());
        assert_eq!(pi.decimal(), matrix_decimal(&bytes));
        assert!(
            pi.decimal()
                .split(' ')
                .map(|g| g.parse::<u16>().unwrap())
                .all(|g| (1000..=9191).contains(&g))
        );
        assert_eq!(pi.decimal().len(), 14);
        assert_eq!(a.ei.status().unwrap(), Status::Busy);
        assert_eq!(a.er.status().unwrap(), Status::Busy);
        assert_eq!((remaining(&a.ei), remaining(&a.er)), (9, 9));
        drop(pair);
        a.release();
    }

    #[test]
    fn exact_identity_approval_is_local_only_idempotent_and_retains_mac_material() {
        let a = Authorities::new("sas-approve");
        let mut pair = establish(&a);
        let id = pair.identity();
        let bytes = pair.i.sas_bytes_for_test();
        for (run, role) in [
            (&mut pair.i, Role::Initiator),
            (&mut pair.r, Role::Responder),
        ] {
            let seen = run.seen.len();
            assert_eq!(run.approve_sas(&id), Ok(SasApproval::Recorded));
            assert!(run.is_locally_approved() && !run.is_awaiting_approval());
            // The comparison prompt is complete; approval creates no new display.
            assert_eq!(run.presentation(), None);
            assert_eq!(run.approve_sas(&id), Ok(SasApproval::AlreadyRecorded));
            assert!(run.is_locally_approved());
            // No exposure authorization is issued, consumed, or reacquired; no wire output.
            assert!(run.admission.authorization.is_none() && !run.admission.terminal);
            assert_eq!(run.seen.len(), seen);
            match &run.state {
                State::LocallyApprovedAwaitingAuthentication { session, peer } => {
                    assert_eq!(*peer, PeerMac::Pending);
                    assert_eq!(session.role, role);
                    assert_eq!(session.ceremony_identity, id);
                    assert_eq!(Some(session.sas_bytes), bytes);
                    assert_eq!(session.request_id, vector_request_id());
                    let (initiator, responder) = (
                        bootstrap(&decoded("START"), true),
                        bootstrap(&decoded("ACCEPT"), false),
                    );
                    let expected = match role {
                        Role::Initiator => (&initiator, &responder),
                        Role::Responder => (&responder, &initiator),
                    };
                    assert_eq!(
                        (&session.local_bootstrap, &session.peer_bootstrap),
                        expected
                    );
                }
                _ => panic!("approval did not retain the established session"),
            }
        }
        assert_eq!(a.ei.status().unwrap(), Status::Busy);
        assert_eq!(a.er.status().unwrap(), Status::Busy);
        assert_eq!((remaining(&a.ei), remaining(&a.er)), (9, 9));
        drop(pair);
        a.release();
    }

    #[test]
    fn wrong_identity_or_request_id_callbacks_have_no_effect() {
        let a = Authorities::new("sas-wrong-identity");
        let mut pair = establish(&a);
        let id = pair.identity();
        let before = pair.i.presentation();
        let mut request_id_target = [0; 32];
        request_id_target[..16].copy_from_slice(&vector_request_id());
        for bit in [0, 7, 255] {
            let mut wrong = id;
            wrong[bit / 8] ^= 1 << (bit % 8);
            for target in [wrong, request_id_target] {
                for run in [&mut pair.i, &mut pair.r] {
                    let mismatch = CeremonyError::CeremonyIdentityMismatch;
                    assert_eq!(run.approve_sas(&target), Err(mismatch.clone()));
                    assert_eq!(run.reject_sas(&target), Err(mismatch.clone()));
                    assert_eq!(run.cancel_sas(&target), Err(mismatch));
                    assert!(run.is_awaiting_approval());
                    assert!(run.admission.authorization.is_none());
                }
            }
        }
        assert_eq!(pair.i.presentation(), before);
        assert_eq!(a.ei.status().unwrap(), Status::Busy);
        assert_eq!((remaining(&a.ei), remaining(&a.er)), (9, 9));

        pair.i.approve_sas(&id).unwrap();
        let mut wrong = id;
        wrong[31] ^= 0x80;
        assert_eq!(
            pair.i.cancel_sas(&wrong),
            Err(CeremonyError::CeremonyIdentityMismatch)
        );
        assert!(pair.i.is_locally_approved());
        assert_eq!(a.ei.status().unwrap(), Status::Busy);
        drop(pair);
        a.release();
    }

    #[test]
    fn same_request_id_with_different_transcript_cannot_transfer_approval() {
        let (first, second) = (
            Authorities::new("sas-same-request-a"),
            Authorities::new("sas-same-request-b"),
        );
        let mut a = establish(&first);
        let mut b = establish(&second);
        assert_eq!(a.wire[0], b.wire[0], "both runs use the identical START");
        let request_id = |p: &Pair| match protocol::decode(&p.wire[3]).unwrap().message {
            Message::ResponderKey { request_id, .. } => request_id,
            _ => unreachable!(),
        };
        assert_eq!(request_id(&a), request_id(&b));
        let (id_a, id_b) = (a.identity(), b.identity());
        assert_ne!(
            id_a, id_b,
            "fresh key material yields a distinct transcript"
        );

        for run in [&mut b.i, &mut b.r] {
            assert_eq!(
                run.approve_sas(&id_a),
                Err(CeremonyError::CeremonyIdentityMismatch)
            );
            assert!(run.is_awaiting_approval());
        }
        assert_eq!(a.i.approve_sas(&id_a), Ok(SasApproval::Recorded));
        assert!(!b.i.is_locally_approved());
        a.i.terminate().unwrap();
        a.r.terminate().unwrap();
        assert_eq!(
            b.i.approve_sas(&id_a),
            Err(CeremonyError::CeremonyIdentityMismatch)
        );
        assert_eq!(b.i.approve_sas(&id_b), Ok(SasApproval::Recorded));
        assert_eq!(b.r.approve_sas(&id_b), Ok(SasApproval::Recorded));
        drop(a);
        drop(b);
        first.release();
        second.release();
    }

    fn assert_stale(run: &mut RemoteCeremony, id: &[u8; 32]) {
        assert_no_live_sas(run);
        assert_eq!(run.approve_sas(id), Err(CeremonyError::NoLiveSas));
        assert_eq!(run.reject_sas(id), Err(CeremonyError::NoLiveSas));
        assert_eq!(run.cancel_sas(id), Err(CeremonyError::NoLiveSas));
        assert_no_live_sas(run);
    }

    /// The authenticated CANCEL a local reject/cancel returned for best-effort sending.
    fn emitted_cancel(outcome: Result<LocalCancellation, CeremonyError>) -> Vec<u8> {
        match outcome {
            Ok(LocalCancellation::Emitted(bytes)) => bytes,
            other => panic!("expected an authenticated CANCEL, got {other:?}"),
        }
    }

    fn cancel_parts(bytes: &[u8]) -> (Vec<u8>, protocol::Role, CancelReason, [u8; 32]) {
        match protocol::decode(bytes).unwrap().message {
            Message::Cancel {
                request_id,
                sender,
                reason,
                mac,
            } => (request_id, sender, reason, mac),
            _ => panic!("not a CANCEL"),
        }
    }

    fn cancel_wire(
        request_id: Vec<u8>,
        sender: protocol::Role,
        reason: CancelReason,
        mac: [u8; 32],
    ) -> Vec<u8> {
        Message::Cancel {
            request_id,
            sender,
            reason,
            mac,
        }
        .encode()
        .unwrap()
    }

    #[test]
    fn local_reject_is_terminal_and_keeps_the_opportunity_consumed() {
        let a = Authorities::new("sas-reject");
        let mut pair = establish(&a);
        let id = pair.identity();
        let cancel = emitted_cancel(pair.i.reject_sas(&id));
        assert_eq!(cancel_parts(&cancel).2, CancelReason::UserRejection);
        assert_stale(&mut pair.i, &id);
        assert_eq!(a.ei.status().unwrap(), Status::Ready { remaining: 9 });
        assert!(pair.i.admission.terminal);
        // The peer is a separate endpoint; nothing reaches it unless the CANCEL is delivered.
        assert!(pair.r.is_awaiting_approval());
        assert_eq!(a.er.status().unwrap(), Status::Busy);
        pair.r.approve_sas(&id).unwrap();
        let cancel = emitted_cancel(pair.r.reject_sas(&id));
        assert_eq!(cancel_parts(&cancel).2, CancelReason::UserRejection);
        assert_stale(&mut pair.r, &id);
        assert_eq!(a.er.status().unwrap(), Status::Ready { remaining: 9 });
        drop(pair);
        a.release();
    }

    #[test]
    fn local_cancel_is_terminal_and_only_returns_best_effort_output() {
        let a = Authorities::new("sas-cancel");
        let mut pair = establish(&a);
        let id = pair.identity();
        let seen = pair.i.seen.len();
        let cancel = emitted_cancel(pair.i.cancel_sas(&id));
        assert_eq!(cancel_parts(&cancel).2, CancelReason::UserCancellation);
        assert_eq!(pair.i.seen.len(), seen);
        assert_stale(&mut pair.i, &id);
        assert_eq!(a.ei.status().unwrap(), Status::Ready { remaining: 9 });
        pair.r.approve_sas(&id).unwrap();
        emitted_cancel(pair.r.cancel_sas(&id));
        assert_stale(&mut pair.r, &id);
        assert_eq!(a.er.status().unwrap(), Status::Ready { remaining: 9 });
        drop(pair);
        a.release();
    }

    #[test]
    fn generic_termination_failure_and_drop_invalidate_sas() {
        let a = Authorities::new("sas-terminate");
        let mut pair = establish(&a);
        let id = pair.identity();
        pair.i.terminate().unwrap();
        assert_stale(&mut pair.i, &id);
        assert_eq!(a.ei.status().unwrap(), Status::Ready { remaining: 9 });
        drop(pair.r);
        assert_eq!(a.er.status().unwrap(), Status::Ready { remaining: 9 });
        drop(pair.i);

        let mut pair = establish(&a);
        let id = pair.identity();
        let mut changed = pair.wire[3].clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(pair.i.receive_responder_key(&changed).is_err());
        assert_stale(&mut pair.i, &id);
        assert!(pair.r.receive_initiator_key(&pair.wire[0]).is_err());
        assert_stale(&mut pair.r, &id);
        assert_eq!((remaining(&a.ei), remaining(&a.er)), (8, 8));
        assert_eq!(a.ei.status().unwrap(), Status::Ready { remaining: 8 });
        assert_eq!(a.er.status().unwrap(), Status::Ready { remaining: 8 });
        drop(pair);
        a.release();
    }

    #[test]
    fn terminated_approved_ceremony_cannot_be_revived_or_resumed() {
        let a = Authorities::new("sas-approved-terminate");
        let mut old = establish(&a);
        let id = old.identity();
        old.i.approve_sas(&id).unwrap();
        old.r.approve_sas(&id).unwrap();
        old.i.terminate().unwrap();
        old.r.terminate().unwrap();
        for run in [&mut old.i, &mut old.r] {
            assert_stale(run, &id);
            assert!(run.authorize(&a.i).is_err() && run.expose_key().is_err());
        }
        assert!(old.i.receive_responder_key(&old.wire[3]).is_err());
        assert!(old.r.receive_initiator_key(&old.wire[2]).is_err());
        assert_stale(&mut old.i, &id);
        assert_eq!(a.ei.status().unwrap(), Status::Ready { remaining: 9 });
        assert_eq!(a.er.status().unwrap(), Status::Ready { remaining: 9 });

        // R-OWNER-011: a retry is a new authorized exposure with a new identity.
        let mut retry = establish(&a);
        assert_ne!(retry.identity(), id);
        assert_eq!(
            retry.i.approve_sas(&id),
            Err(CeremonyError::CeremonyIdentityMismatch)
        );
        assert_eq!((remaining(&a.ei), remaining(&a.er)), (8, 8));
        drop(retry);
        drop(old);
        a.release();
    }

    #[test]
    fn sas_is_invalidated_even_when_guard_release_is_uncertain() {
        let a = Authorities::new("sas-uncertain-release");
        let mut pair = establish(&a);
        let id = pair.identity();
        let poisoned = a.ei.clone();
        let _ = std::thread::spawn(move || {
            let _shared = poisoned.0.shared.lock().unwrap();
            panic!("simulate uncertain guard state");
        })
        .join();
        assert_eq!(
            pair.i.reject_sas(&id),
            Err(CeremonyError::Owner(OwnerError::OwnershipUncertain))
        );
        assert_stale(&mut pair.i, &id);
        // Fail closed: invalidation is complete, but the guard is never released uncertainly.
        match a.ei.0.shared.lock() {
            Err(poisoned) => assert!(poisoned.into_inner().active.is_some()),
            Ok(_) => panic!("shared state unexpectedly recovered"),
        }
        drop(pair);
        a.release();
    }

    fn emitted(run: &mut RemoteCeremony) -> Vec<u8> {
        match run.emit_bootstrap_mac().unwrap() {
            BootstrapMacEmission::Emitted(bytes) => bytes,
            BootstrapMacEmission::AlreadyEmitted => panic!("expected a first emission"),
        }
    }

    fn approve_and_emit(run: &mut RemoteCeremony, id: &[u8; 32]) -> Vec<u8> {
        assert_eq!(run.approve_sas(id), Ok(SasApproval::Recorded));
        emitted(run)
    }

    fn mac_fields(bytes: &[u8]) -> (Vec<u8>, protocol::Role, [u8; 32]) {
        match protocol::decode(bytes).unwrap().message {
            Message::BootstrapMac {
                request_id,
                sender,
                mac,
            } => (request_id, sender, mac),
            _ => panic!("not a BOOTSTRAP_MAC"),
        }
    }

    fn mac_frame(request_id: Vec<u8>, sender: protocol::Role, mac: [u8; 32]) -> Vec<u8> {
        Message::BootstrapMac {
            request_id,
            sender,
            mac,
        }
        .encode()
        .unwrap()
    }

    /// Ready for the later finish handshake, but never success: the SAS session is retained,
    /// no exposure authorization exists, the guard is Busy, and the opportunity stays spent.
    fn assert_ready_not_success(run: &RemoteCeremony, executor: &CeremonyExecutor) {
        assert!(run.is_ready_for_completion());
        assert!(run.is_locally_approved() && run.is_own_mac_emitted());
        assert!(run.is_peer_approval_authenticated());
        assert_eq!(run.presentation(), None);
        assert!(run.sas_bytes_for_test().is_some());
        assert!(run.admission.authorization.is_none() && !run.admission.terminal);
        assert_eq!(executor.status().unwrap(), Status::Busy);
        assert_eq!(remaining(executor), 9);
    }

    #[test]
    fn live_bootstrap_macs_local_approval_first_reach_completion_ready_only() {
        let a = Authorities::new("mac-local-first");
        let mut pair = establish(&a);
        let id = pair.identity();
        let (i_seen, r_seen) = (pair.i.seen.len(), pair.r.seen.len());

        let i_mac = approve_and_emit(&mut pair.i, &id);
        let (i_request_id, i_sender, i_tag) = mac_fields(&i_mac);
        assert_eq!(
            (i_request_id, i_sender),
            (vector_request_id(), protocol::Role::Initiator)
        );
        assert!(pair.i.is_own_mac_emitted() && !pair.i.is_peer_approval_authenticated());
        assert!(!pair.i.is_ready_for_completion());
        let ops = crypto::mac_operations();
        assert_eq!(
            pair.i.emit_bootstrap_mac(),
            Ok(BootstrapMacEmission::AlreadyEmitted)
        );
        assert_eq!(crypto::mac_operations(), ops, "no second MAC calculation");

        assert_eq!(
            pair.r.receive_bootstrap_mac(&i_mac),
            Ok(PeerApproval::Authenticated)
        );
        // R authenticated I's approval only; R's own human decision is still pending.
        assert!(pair.r.is_awaiting_approval() && !pair.r.is_locally_approved());
        assert!(pair.r.is_peer_approval_authenticated());
        assert!(pair.r.presentation().is_some());
        assert_eq!(
            pair.r.emit_bootstrap_mac(),
            Err(CeremonyError::NotLocallyApproved)
        );

        let r_mac = approve_and_emit(&mut pair.r, &id);
        let (r_request_id, r_sender, r_tag) = mac_fields(&r_mac);
        assert_eq!(
            (r_request_id, r_sender),
            (vector_request_id(), protocol::Role::Responder)
        );
        assert_ready_not_success(&pair.r, &a.er);
        assert_eq!(
            pair.i.receive_bootstrap_mac(&r_mac),
            Ok(PeerApproval::Authenticated)
        );
        assert_ready_not_success(&pair.i, &a.ei);
        assert_ne!(i_tag, r_tag);
        // Each side retained exactly one accepted peer BOOTSTRAP_MAC and nothing else new.
        assert_eq!(
            (pair.i.seen.len(), pair.r.seen.len()),
            (i_seen + 1, r_seen + 1)
        );
        drop(pair);
        assert_eq!(a.ei.status().unwrap(), Status::Ready { remaining: 9 });
        assert_eq!(a.er.status().unwrap(), Status::Ready { remaining: 9 });
        a.release();
    }

    #[test]
    fn peer_mac_first_keeps_sas_displayed_and_never_approves_locally() {
        let a = Authorities::new("mac-peer-first");
        let mut pair = establish(&a);
        let id = pair.identity();
        let r_mac = approve_and_emit(&mut pair.r, &id);
        let displayed = pair.i.presentation();

        assert_eq!(
            pair.i.receive_bootstrap_mac(&r_mac),
            Ok(PeerApproval::Authenticated)
        );
        assert_eq!(pair.i.presentation(), displayed, "SAS stays live (I2)");
        assert!(pair.i.is_awaiting_approval() && !pair.i.is_locally_approved());
        assert!(pair.i.is_peer_approval_authenticated() && !pair.i.is_own_mac_emitted());
        assert!(!pair.i.is_ready_for_completion());
        let ops = crypto::mac_operations();
        assert_eq!(
            pair.i.emit_bootstrap_mac(),
            Err(CeremonyError::NotLocallyApproved)
        );
        assert_eq!(crypto::mac_operations(), ops);
        assert_eq!(pair.i.presentation(), displayed);
        assert_eq!(a.ei.status().unwrap(), Status::Busy);

        assert_eq!(pair.i.approve_sas(&id), Ok(SasApproval::Recorded));
        assert_eq!(pair.i.presentation(), None);
        assert!(!pair.i.is_ready_for_completion(), "own MAC not yet emitted");
        let i_mac = emitted(&mut pair.i);
        assert_ready_not_success(&pair.i, &a.ei);
        assert_eq!(
            pair.r.receive_bootstrap_mac(&i_mac),
            Ok(PeerApproval::Authenticated)
        );
        assert_ready_not_success(&pair.r, &a.er);
        drop(pair);
        a.release();
    }

    #[test]
    fn own_bootstrap_mac_requires_live_local_approval() {
        let a = Authorities::new("mac-no-approval");
        let start = vector("START");
        let mut pre = RemoteCeremony::initiator_with_fixed_start_for_test(
            a.ei.clone(),
            a.ei.begin(Role::Initiator).unwrap(),
            &start,
            bootstrap(&decoded("START"), true),
            None,
        )
        .unwrap();
        assert_eq!(pre.emit_bootstrap_mac(), Err(CeremonyError::NoLiveSas));
        pre.start().unwrap();
        assert_eq!(pre.emit_bootstrap_mac(), Err(CeremonyError::NoLiveSas));
        drop(pre);

        let mut pair = establish(&a);
        let id = pair.identity();
        let ops = crypto::mac_operations();
        for run in [&mut pair.i, &mut pair.r] {
            let seen = run.seen.len();
            assert_eq!(
                run.emit_bootstrap_mac(),
                Err(CeremonyError::NotLocallyApproved)
            );
            assert!(run.is_awaiting_approval() && run.presentation().is_some());
            assert!(!run.is_own_mac_emitted() && run.seen.len() == seen);
        }
        assert_eq!(crypto::mac_operations(), ops);
        pair.i.cancel_sas(&id).unwrap();
        assert_eq!(pair.i.emit_bootstrap_mac(), Err(CeremonyError::NoLiveSas));
        assert_eq!((remaining(&a.ei), remaining(&a.er)), (9, 9));
        drop(pair);
        a.release();
    }

    /// Delivers `mutate(valid R MAC)` to an approved I, then proves I1/I2: terminal, SAS and
    /// session dropped, guard released with the opportunity kept, and nothing revives it.
    fn assert_bad_peer_mac_is_terminal(
        scope: &str,
        mutate: impl Fn(&[u8]) -> Vec<u8>,
        expected: CeremonyError,
    ) {
        let a = Authorities::new(scope);
        let mut pair = establish(&a);
        let id = pair.identity();
        let r_mac = approve_and_emit(&mut pair.r, &id);
        assert_eq!(pair.i.approve_sas(&id), Ok(SasApproval::Recorded));
        let bad = mutate(&r_mac);
        assert_ne!(bad, r_mac);
        assert_eq!(pair.i.receive_bootstrap_mac(&bad), Err(expected));
        assert_stale(&mut pair.i, &id);
        assert!(pair.i.admission.terminal);
        assert_eq!(a.ei.status().unwrap(), Status::Ready { remaining: 9 });
        // A later valid MAC, a local approval, or an emission cannot revive the ceremony.
        assert!(pair.i.receive_bootstrap_mac(&r_mac).is_err());
        assert_eq!(pair.i.approve_sas(&id), Err(CeremonyError::NoLiveSas));
        assert_eq!(pair.i.emit_bootstrap_mac(), Err(CeremonyError::NoLiveSas));
        assert!(!pair.i.is_ready_for_completion() && !pair.i.is_peer_approval_authenticated());
        assert_stale(&mut pair.i, &id);
        assert_eq!(a.ei.status().unwrap(), Status::Ready { remaining: 9 });
        drop(pair);
        a.release();
    }

    #[test]
    fn wrong_role_request_id_tag_or_frame_is_terminal() {
        // I's own role on an otherwise valid-looking frame.
        assert_bad_peer_mac_is_terminal(
            "mac-own-role",
            |valid| {
                let (request_id, _, mac) = mac_fields(valid);
                mac_frame(request_id, protocol::Role::Initiator, mac)
            },
            CeremonyError::UnexpectedSenderRole,
        );
        assert_bad_peer_mac_is_terminal(
            "mac-request-id",
            |valid| {
                let (mut request_id, sender, mac) = mac_fields(valid);
                request_id[0] ^= 1;
                mac_frame(request_id, sender, mac)
            },
            CeremonyError::RequestIdMismatch,
        );
        assert_bad_peer_mac_is_terminal(
            "mac-bit-flip",
            |valid| {
                let (request_id, sender, mut mac) = mac_fields(valid);
                mac[31] ^= 0x01;
                mac_frame(request_id, sender, mac)
            },
            CeremonyError::Crypto(crypto::Error::MacMismatch),
        );
        assert_bad_peer_mac_is_terminal(
            "mac-short-tag",
            |valid| {
                // Declare and carry a 31-byte tag: rejected by the codec before any MAC work.
                let mut short = valid[..valid.len() - 1].to_vec();
                let at = short.len() - 35;
                short[at..at + 4].copy_from_slice(&31u32.to_be_bytes());
                short
            },
            CeremonyError::Codec(protocol::CodecError::InvalidField("fixed_32")),
        );
        assert_bad_peer_mac_is_terminal(
            "mac-other-type",
            |_| vector("RESPONDER_KEY"),
            CeremonyError::InvalidState,
        );
    }

    #[test]
    fn bootstrap_mac_from_another_ceremony_with_same_request_id_fails() {
        let (first, second) = (
            Authorities::new("mac-cross-a"),
            Authorities::new("mac-cross-b"),
        );
        let mut a = establish(&first);
        let mut b = establish(&second);
        let (id_a, id_b) = (a.identity(), b.identity());
        assert_ne!(id_a, id_b);
        let foreign = approve_and_emit(&mut a.r, &id_a);
        let own = approve_and_emit(&mut b.r, &id_b);
        let (request_a, sender_a, _) = mac_fields(&foreign);
        let (request_b, sender_b, _) = mac_fields(&own);
        assert_eq!((request_a, sender_a), (request_b, sender_b));
        assert_eq!(
            b.i.receive_bootstrap_mac(&foreign),
            Err(CeremonyError::Crypto(crypto::Error::MacMismatch))
        );
        assert_stale(&mut b.i, &id_b);
        assert!(b.i.receive_bootstrap_mac(&own).is_err());
        assert_eq!(second.ei.status().unwrap(), Status::Ready { remaining: 9 });
        // The foreign ceremony is unaffected and still authenticates its own peer MAC.
        assert_eq!(
            a.i.receive_bootstrap_mac(&foreign),
            Ok(PeerApproval::Authenticated)
        );
        drop(a);
        drop(b);
        first.release();
        second.release();
    }

    /// Verifies a received tag with the live session against caller-altered reconstruction.
    fn verify_reconstructed(
        run: &RemoteCeremony,
        frame: Vec<u8>,
        context: Vec<u8>,
        tag: &[u8; 32],
    ) -> Result<(), crypto::Error> {
        let (input, info) = crypto::mac_strings(&frame, &context).unwrap();
        run.session()
            .unwrap()
            .established
            .verify_mac(&input, &info, tag)
    }

    #[test]
    fn peer_mac_binds_identity_sas_sender_bootstrap_roles_and_purpose() {
        use protocol::Role::{Initiator as I, Responder as R};
        const PURPOSE: &[u8] = b"match-approve-bootstrap";
        let a = Authorities::new("mac-binding");
        let mut pair = establish(&a);
        let id = pair.identity();
        let frame = |role, id: &[u8; 32], sas: &[u8; 6], boot: &Bootstrap| {
            crypto::approval_frame(role, id, sas, boot).unwrap()
        };
        let context = |purpose: &[u8], s, r, id: &[u8; 32]| {
            crypto::approval_context(purpose, s, r, id).unwrap()
        };
        for (sender, receiver) in [(R, I), (I, R)] {
            let (sender_run, receiver_run) = match sender {
                R => (&mut pair.r, &pair.i),
                I => (&mut pair.i, &pair.r),
            };
            let tag = mac_fields(&approve_and_emit(sender_run, &id)).2;
            let session = receiver_run.session().unwrap();
            let (sas, peer, local) = (
                session.sas_bytes,
                session.peer_bootstrap.clone(),
                session.local_bootstrap.clone(),
            );
            assert_eq!(
                verify_reconstructed(
                    receiver_run,
                    frame(sender, &id, &sas, &peer),
                    context(PURPOSE, sender, receiver, &id),
                    &tag
                ),
                Ok(())
            );
            let mut other_id = id;
            other_id[0] ^= 1;
            let mut other_sas = sas;
            other_sas[5] ^= 1;
            let good_frame = frame(sender, &id, &sas, &peer);
            let good_context = context(PURPOSE, sender, receiver, &id);
            for (frame, context) in [
                // ceremony_identity in the approval frame and in the context.
                (frame(sender, &other_id, &sas, &peer), good_context.clone()),
                (
                    good_frame.clone(),
                    context(PURPOSE, sender, receiver, &other_id),
                ),
                // Six raw SAS bytes.
                (frame(sender, &id, &other_sas, &peer), good_context.clone()),
                // Sender bootstrap: the receiver's own bootstrap is the wrong statement.
                (frame(sender, &id, &sas, &local), good_context.clone()),
                // Sender role in the frame; sender and receiver roles in the context.
                (frame(receiver, &id, &sas, &peer), good_context.clone()),
                (
                    good_frame.clone(),
                    context(PURPOSE, receiver, receiver, &id),
                ),
                (good_frame.clone(), context(PURPOSE, sender, sender, &id)),
                // Opposite direction and a different purpose.
                (good_frame.clone(), context(PURPOSE, receiver, sender, &id)),
                (
                    good_frame.clone(),
                    context(b"initiator-finish", sender, receiver, &id),
                ),
            ] {
                assert_eq!(
                    verify_reconstructed(receiver_run, frame, context, &tag),
                    Err(crypto::Error::MacMismatch)
                );
            }
        }
        drop(pair);
        a.release();
    }

    #[test]
    fn exact_duplicate_is_idempotent_and_changed_duplicate_is_terminal() {
        let a = Authorities::new("mac-duplicates");
        // Peer MAC accepted before local approval: duplicates keep the SAS displayed.
        let mut pair = establish(&a);
        let id = pair.identity();
        let r_mac = approve_and_emit(&mut pair.r, &id);
        pair.i.receive_bootstrap_mac(&r_mac).unwrap();
        let (seen, ops, shown) = (
            pair.i.seen.len(),
            crypto::mac_operations(),
            pair.i.presentation(),
        );
        for _ in 0..2 {
            assert_eq!(
                pair.i.receive_bootstrap_mac(&r_mac),
                Ok(PeerApproval::AlreadyAuthenticated)
            );
        }
        assert_eq!(
            (pair.i.seen.len(), crypto::mac_operations()),
            (seen, ops),
            "no retained copy and no repeated MAC verification"
        );
        assert_eq!(pair.i.presentation(), shown);
        assert!(pair.i.is_awaiting_approval() && pair.i.is_peer_approval_authenticated());
        let (request_id, sender, mut mac) = mac_fields(&r_mac);
        mac[0] ^= 0x80;
        assert_eq!(
            pair.i
                .receive_bootstrap_mac(&mac_frame(request_id, sender, mac)),
            Err(CeremonyError::InvalidState)
        );
        assert_stale(&mut pair.i, &id);
        assert_eq!(a.ei.status().unwrap(), Status::Ready { remaining: 9 });
        drop(pair);

        a.release();

        // In the completion-ready state, an exact duplicate changes nothing; a changed one fails.
        let a = Authorities::new("mac-duplicates-ready");
        let mut pair = establish(&a);
        let id = pair.identity();
        let r_mac = approve_and_emit(&mut pair.r, &id);
        let i_mac = approve_and_emit(&mut pair.i, &id);
        pair.i.receive_bootstrap_mac(&r_mac).unwrap();
        pair.r.receive_bootstrap_mac(&i_mac).unwrap();
        let ops = crypto::mac_operations();
        assert_eq!(
            pair.i.receive_bootstrap_mac(&r_mac),
            Ok(PeerApproval::AlreadyAuthenticated)
        );
        assert_eq!(
            pair.i.emit_bootstrap_mac(),
            Ok(BootstrapMacEmission::AlreadyEmitted)
        );
        assert_eq!(pair.i.approve_sas(&id), Ok(SasApproval::AlreadyRecorded));
        assert_eq!(crypto::mac_operations(), ops);
        assert_ready_not_success(&pair.i, &a.ei);
        let (request_id, sender, mut mac) = mac_fields(&r_mac);
        mac[16] ^= 0x04;
        assert_eq!(
            pair.i
                .receive_bootstrap_mac(&mac_frame(request_id, sender, mac)),
            Err(CeremonyError::InvalidState)
        );
        assert_stale(&mut pair.i, &id);
        assert!(!pair.i.is_ready_for_completion());
        assert!(pair.i.receive_bootstrap_mac(&r_mac).is_err());
        assert_eq!(a.ei.status().unwrap(), Status::Ready { remaining: 9 });
        // The peer endpoint is independent and remains ready; nothing is sent to it.
        assert!(pair.r.is_ready_for_completion());
        drop(pair);
        a.release();
    }

    #[test]
    fn local_reject_or_cancel_during_mac_stage_is_terminal() {
        let a = Authorities::new("mac-cancel");
        let mut expected = 10;
        let stages: [fn(&mut Pair, &[u8; 32]); 4] = [
            // Peer MAC verified, no local decision yet.
            |p, id| {
                let m = approve_and_emit(&mut p.r, id);
                p.i.receive_bootstrap_mac(&m).unwrap();
            },
            // Locally approved, own MAC not emitted.
            |p, id| {
                p.i.approve_sas(id).unwrap();
            },
            // Own MAC emitted, awaiting the peer's.
            |p, id| {
                approve_and_emit(&mut p.i, id);
            },
            // Both approval conditions satisfied.
            |p, id| {
                let m = approve_and_emit(&mut p.r, id);
                approve_and_emit(&mut p.i, id);
                p.i.receive_bootstrap_mac(&m).unwrap();
            },
        ];
        for (index, stage) in stages.iter().enumerate() {
            for reject in [false, true] {
                let mut pair = establish(&a);
                expected -= 1;
                let id = pair.identity();
                stage(&mut pair, &id);
                let seen = pair.i.seen.len();
                let (result, reason) = if reject {
                    (pair.i.reject_sas(&id), CancelReason::UserRejection)
                } else {
                    (pair.i.cancel_sas(&id), CancelReason::UserCancellation)
                };
                let cancel = emitted_cancel(result);
                assert_eq!(pair.i.seen.len(), seen);
                assert_stale(&mut pair.i, &id);
                assert!(!pair.i.is_ready_for_completion());
                assert_eq!(pair.i.emit_bootstrap_mac(), Err(CeremonyError::NoLiveSas));
                assert_eq!(
                    a.ei.status().unwrap(),
                    Status::Ready {
                        remaining: expected
                    }
                );
                // The peer, live in whatever approval stage it reached, authenticates it.
                assert_eq!(
                    pair.r.receive_cancel(&cancel).map(|c| c.reason()),
                    Ok(reason),
                    "stage {index}"
                );
                assert_stale(&mut pair.r, &id);
                assert_eq!(
                    a.er.status().unwrap(),
                    Status::Ready {
                        remaining: expected
                    }
                );
                drop(pair);
            }
        }
        a.release();
    }

    #[test]
    fn bootstrap_mac_before_sas_establishment_is_terminal_and_spends_nothing() {
        let a = Authorities::new("mac-early");
        let (mut r, _) = RemoteCeremony::responder(
            a.er.clone(),
            a.er.begin(Role::Responder).unwrap(),
            &vector("START"),
            bootstrap(&decoded("ACCEPT"), false),
            None,
        )
        .unwrap();
        let early = mac_frame(vector_request_id(), protocol::Role::Initiator, [7; 32]);
        assert_eq!(
            r.receive_bootstrap_mac(&early),
            Err(CeremonyError::InvalidState)
        );
        assert!(r.admission.terminal);
        assert!(r.expose_key().is_err());
        assert_eq!(a.er.status().unwrap(), Status::Ready { remaining: 10 });
        drop(r);
        a.release();
    }

    #[test]
    fn bad_peer_mac_invalidates_sas_even_when_guard_release_is_uncertain() {
        let a = Authorities::new("mac-uncertain-release");
        let mut pair = establish(&a);
        let id = pair.identity();
        let (request_id, sender, mut mac) = mac_fields(&approve_and_emit(&mut pair.r, &id));
        mac[3] ^= 0x20;
        let poisoned = a.ei.clone();
        let _ = std::thread::spawn(move || {
            let _shared = poisoned.0.shared.lock().unwrap();
            panic!("simulate uncertain guard state");
        })
        .join();
        assert_eq!(
            pair.i
                .receive_bootstrap_mac(&mac_frame(request_id, sender, mac)),
            Err(CeremonyError::Crypto(crypto::Error::MacMismatch))
        );
        assert_stale(&mut pair.i, &id);
        // Fail closed: invalidation is complete, but the guard is never released uncertainly.
        match a.ei.0.shared.lock() {
            Err(poisoned) => assert!(poisoned.into_inner().active.is_some()),
            Ok(_) => panic!("shared state unexpectedly recovered"),
        }
        drop(pair);
        a.release();
    }

    // ---- Authenticated finish handshake and local PairingResult ----

    const STEPS: [Completion; 3] = [
        Completion::InitiatorFinish,
        Completion::ResponderFinishAck,
        Completion::InitiatorFinishAck,
    ];

    /// Exchanges both BOOTSTRAP_MACs so each side is ready for the finish handshake.
    fn authenticate(pair: &mut Pair, id: &[u8; 32]) {
        let r_mac = approve_and_emit(&mut pair.r, id);
        let i_mac = approve_and_emit(&mut pair.i, id);
        pair.i.receive_bootstrap_mac(&r_mac).unwrap();
        pair.r.receive_bootstrap_mac(&i_mac).unwrap();
        assert!(pair.i.is_ready_for_completion() && pair.r.is_ready_for_completion());
    }

    fn approvals_authenticated(a: &Authorities) -> (Pair, [u8; 32]) {
        let mut pair = establish(a);
        let id = pair.identity();
        authenticate(&mut pair, &id);
        assert_ready_not_success(&pair.i, &a.ei);
        assert_ready_not_success(&pair.r, &a.er);
        (pair, id)
    }

    fn finish(run: &mut RemoteCeremony) -> Vec<u8> {
        match run.emit_initiator_finish().unwrap() {
            FinishEmission::Emitted(bytes) => bytes,
            FinishEmission::AlreadyEmitted => panic!("expected a first INITIATOR_FINISH"),
        }
    }

    fn responder_ack(run: &mut RemoteCeremony, initiator_finish: &[u8]) -> Vec<u8> {
        match run.receive_completion(initiator_finish).unwrap() {
            CompletionReceipt::SendResponderFinishAck(bytes) => bytes,
            other => panic!("expected RESPONDER_FINISH_ACK, got {other:?}"),
        }
    }

    fn initiator_ack(run: &mut RemoteCeremony, responder_finish_ack: &[u8]) -> Vec<u8> {
        match run.receive_completion(responder_finish_ack).unwrap() {
            CompletionReceipt::SendInitiatorFinishAck(bytes) => bytes,
            other => panic!("expected INITIATOR_FINISH_ACK, got {other:?}"),
        }
    }

    /// Stands in for the future transport adapter: its local send accepted exactly `ack`.
    fn confirm_sent(run: &mut RemoteCeremony, ack: &[u8]) {
        assert_eq!(run.confirm_initiator_finish_ack_sent(ack), Ok(()));
    }

    /// I produced the final ACK but its send is unconfirmed: no result, the exact frame and
    /// the live session retained, the guard still held, and the one opportunity consumed.
    fn assert_final_ack_pending(run: &RemoteCeremony, executor: &CeremonyExecutor, ack: &[u8]) {
        match &run.state {
            State::AwaitInitiatorFinishAckSend { final_ack, .. } => assert_eq!(final_ack, ack),
            _ => panic!("expected a pending final ACK send"),
        }
        assert_eq!(run.result(), None);
        assert!(run.session().is_some() && run.sas_bytes_for_test().is_some());
        assert!(!run.admission.terminal && run.admission.authorization.is_none());
        assert_eq!(executor.status().unwrap(), Status::Busy);
        assert_eq!(remaining(executor), 9);
    }

    fn finish_parts(bytes: &[u8]) -> (Completion, Vec<u8>, [u8; 32], [u8; 32]) {
        let msg = protocol::decode(bytes).unwrap();
        let (step, request_id, transcript, mac) = completion_fields(&msg.message).unwrap();
        (step, request_id.to_vec(), *transcript, *mac)
    }

    fn finish_wire(step: Completion, request_id: Vec<u8>, id: [u8; 32], mac: [u8; 32]) -> Vec<u8> {
        completion_message(step, request_id, id, mac)
            .encode()
            .unwrap()
    }

    fn endpoint(pair: &mut Pair, role: protocol::Role) -> &mut RemoteCeremony {
        match role {
            protocol::Role::Initiator => &mut pair.i,
            protocol::Role::Responder => &mut pair.r,
        }
    }

    fn other(role: protocol::Role) -> protocol::Role {
        match role {
            protocol::Role::Initiator => protocol::Role::Responder,
            protocol::Role::Responder => protocol::Role::Initiator,
        }
    }

    fn endpoint_executor(a: &Authorities, role: protocol::Role) -> &CeremonyExecutor {
        match role {
            protocol::Role::Initiator => &a.ei,
            protocol::Role::Responder => &a.er,
        }
    }

    /// Drives a fresh pair until `step`'s receiver awaits it; returns that valid frame.
    fn drive_to(a: &Authorities, step: Completion) -> (Pair, [u8; 32], Vec<u8>) {
        let (mut pair, id) = approvals_authenticated(a);
        let i_finish = finish(&mut pair.i);
        if step == Completion::InitiatorFinish {
            return (pair, id, i_finish);
        }
        let r_ack = responder_ack(&mut pair.r, &i_finish);
        if step == Completion::ResponderFinishAck {
            return (pair, id, r_ack);
        }
        let i_ack = initiator_ack(&mut pair.i, &r_ack);
        confirm_sent(&mut pair.i, &i_ack);
        (pair, id, i_ack)
    }

    /// Local success: an immutable result, no live SAS, session, approval, or duplicate state,
    /// inert callbacks, the guard released, and the one consumed opportunity kept.
    fn assert_succeeded(run: &mut RemoteCeremony, executor: &CeremonyExecutor, id: &[u8; 32]) {
        let result = run.result().cloned().expect("local result");
        assert_eq!(result.ceremony_identity(), id);
        assert_stale(run, id);
        assert!(run.session().is_none() && run.seen.is_empty());
        assert!(!run.is_ready_for_completion() && !run.is_peer_approval_authenticated());
        assert!(run.admission.terminal && run.admission.authorization.is_none());
        assert_eq!(executor.status().unwrap(), Status::Ready { remaining: 9 });
        assert_eq!(run.result(), Some(&result));
    }

    /// Terminal failure: no result, SAS and session dropped, guard released, opportunity kept.
    fn assert_failed(run: &mut RemoteCeremony, executor: &CeremonyExecutor, id: &[u8; 32]) {
        assert!(matches!(run.state, State::Terminal));
        assert_eq!(run.result(), None);
        assert_stale(run, id);
        assert!(run.admission.terminal);
        assert_eq!(executor.status().unwrap(), Status::Ready { remaining: 9 });
    }

    fn assert_matches_fixture_result(result: &PairingResult, name: &str, with_identity: bool) {
        let json = fixture();
        let r = &json["result_semantics"][name];
        let h = |key: &str| hex(r[key].as_str().unwrap());
        assert_eq!(result.request_id(), h("request_id"));
        if with_identity {
            assert_eq!(
                result.ceremony_identity().as_slice(),
                h("ceremony_identity")
            );
        }
        assert_eq!(
            format!("{:?}", result.peer_role()),
            r["peer_role"].as_str().unwrap()
        );
        assert_eq!(
            result.authenticated_peer_bootstrap(),
            h("authenticated_peer_bootstrap")
        );
        assert_eq!(
            result.authenticated_shared_context(),
            h("authenticated_shared_context")
        );
        assert_eq!(
            result.profile_identifier(),
            r["profile_identifier"].as_str().unwrap().as_bytes()
        );
        assert_eq!(
            u64::from(result.profile_version()),
            r["profile_version"].as_u64().unwrap()
        );
    }

    #[test]
    fn completion_wire_frames_and_result_shape_match_authoritative_vector() {
        let json = fixture();
        let id: [u8; 32] = hex(json["ceremony_identity"]["hex"].as_str().unwrap())
            .try_into()
            .unwrap();
        let rid = vector_request_id();
        for (name, wire, step) in [
            ("initiator_finish", "INITIATOR_FINISH", STEPS[0]),
            ("responder_finish_ack", "RESPONDER_FINISH_ACK", STEPS[1]),
            ("initiator_finish_ack", "INITIATOR_FINISH_ACK", STEPS[2]),
        ] {
            // Fixture tags come from fixed test-only secrets; they are framed, not recomputed.
            let tag: [u8; 32] = hex(
                json["completion"]["authentications"][name]["raw_mac"]["hex"]
                    .as_str()
                    .unwrap(),
            )
            .try_into()
            .unwrap();
            let bytes = finish_wire(step, rid.clone(), id, tag);
            assert_eq!(bytes, vector(wire));
            assert_eq!(bytes[9], completion_wire_type(step));
            assert_eq!(finish_parts(&vector(wire)), (step, rid.clone(), id, tag));
        }
        assert_eq!(
            STEPS.map(completion_wire_type),
            [0x06, 0x07, 0x08],
            "wire types differ from the 0x35-0x37 auth-frame types"
        );
        // Result fields derive from the vector ceremony inputs for each role.
        let (initiator, responder) = (
            bootstrap(&decoded("START"), true),
            bootstrap(&decoded("ACCEPT"), false),
        );
        for (role, peer, name) in [
            (Role::Initiator, &responder, "initiator"),
            (Role::Responder, &initiator, "responder"),
        ] {
            let result = PairingResult::new(role, &rid, id, peer);
            assert_matches_fixture_result(&result, name, true);
        }
    }

    #[test]
    fn live_three_message_completion_yields_reciprocal_local_results() {
        let a = Authorities::new("finish-full");
        let (mut pair, id) = approvals_authenticated(&a);
        let ops = crypto::mac_operations();

        let i_finish = finish(&mut pair.i);
        assert_eq!(crypto::mac_operations(), ops + 1);
        assert_eq!(i_finish[9], 0x06);
        let (step, rid, digest, _) = finish_parts(&i_finish);
        assert_eq!((step, rid, digest), (STEPS[0], vector_request_id(), id));
        assert!(matches!(pair.i.state, State::AwaitResponderFinish { .. }));
        assert!(pair.i.result().is_none() && pair.i.sas_bytes_for_test().is_some());
        // Completion needs no new exposure authorization, second guard, or opportunity.
        assert!(pair.i.admission.authorization.is_none() && !pair.i.admission.terminal);
        assert_eq!(a.ei.status().unwrap(), Status::Busy);

        let r_ack = responder_ack(&mut pair.r, &i_finish);
        assert_eq!(
            crypto::mac_operations(),
            ops + 3,
            "one verify, one calculate"
        );
        assert_eq!(r_ack[9], 0x07);
        let (step, rid, digest, _) = finish_parts(&r_ack);
        assert_eq!((step, rid, digest), (STEPS[1], vector_request_id(), id));
        // R verified I's progress but has no result until the final ACK verifies.
        assert!(matches!(
            pair.r.state,
            State::AwaitInitiatorFinishAck { .. }
        ));
        assert!(pair.r.result().is_none() && pair.r.sas_bytes_for_test().is_some());
        assert_eq!(a.er.status().unwrap(), Status::Busy);

        let i_ack = initiator_ack(&mut pair.i, &r_ack);
        assert_eq!(crypto::mac_operations(), ops + 5);
        assert_eq!(i_ack[9], 0x08);
        let (step, rid, digest, _) = finish_parts(&i_ack);
        assert_eq!((step, rid, digest), (STEPS[2], vector_request_id(), id));
        // Producing the final ACK is not success: I awaits its local send boundary.
        assert_final_ack_pending(&pair.i, &a.ei, &i_ack);

        confirm_sent(&mut pair.i, &i_ack);
        assert_eq!(
            crypto::mac_operations(),
            ops + 5,
            "confirmation does no MAC work"
        );
        assert_succeeded(&mut pair.i, &a.ei, &id);

        assert_eq!(
            pair.r.receive_completion(&i_ack),
            Ok(CompletionReceipt::Succeeded)
        );
        assert_eq!(crypto::mac_operations(), ops + 6);
        assert_succeeded(&mut pair.r, &a.er, &id);

        let (ri, rr) = (pair.i.result().unwrap(), pair.r.result().unwrap());
        assert_eq!((ri.ceremony_identity(), rr.ceremony_identity()), (&id, &id));
        assert_eq!(
            (ri.peer_role(), rr.peer_role()),
            (Role::Responder, Role::Initiator)
        );
        // Each holds the OTHER endpoint's exact canonical bootstrap frame.
        let (initiator, responder) = (
            bootstrap(&decoded("START"), true),
            bootstrap(&decoded("ACCEPT"), false),
        );
        assert_eq!(
            ri.authenticated_peer_bootstrap(),
            responder.canonical_bytes()
        );
        assert_eq!(
            rr.authenticated_peer_bootstrap(),
            initiator.canonical_bytes()
        );
        assert_eq!(
            ri.authenticated_shared_context(),
            rr.authenticated_shared_context()
        );
        assert_eq!(
            ri.authenticated_shared_context(),
            initiator.shared_context()
        );
        assert_eq!(ri.request_id(), rr.request_id());
        assert_eq!(
            (ri.profile_identifier(), ri.profile_version()),
            (rr.profile_identifier(), rr.profile_version())
        );
        // Everything except the fresh ceremony identity equals the fixture's result semantics.
        assert_matches_fixture_result(ri, "initiator", false);
        assert_matches_fixture_result(rr, "responder", false);
        drop(pair);
        assert_eq!((remaining(&a.ei), remaining(&a.er)), (9, 9));
        a.release();
    }

    /// P3 9: local verified completion is not atomic bilateral success. The Initiator reaches
    /// its result once the final ACK crosses its local send boundary; nothing acknowledges that
    /// ACK, so its loss after sending leaves the Responder waiting with no result. There is no
    /// fourth message.
    #[test]
    fn final_ack_lost_after_send_leaves_only_the_initiator_with_a_local_result() {
        let a = Authorities::new("finish-lost-final-ack");
        let (mut pair, id) = approvals_authenticated(&a);
        let i_finish = finish(&mut pair.i);
        let r_ack = responder_ack(&mut pair.r, &i_finish);
        let undelivered = initiator_ack(&mut pair.i, &r_ack);
        confirm_sent(&mut pair.i, &undelivered);

        assert_succeeded(&mut pair.i, &a.ei, &id);
        let result_i = pair.i.result().cloned();

        assert_eq!(pair.r.result(), None);
        assert!(matches!(
            pair.r.state,
            State::AwaitInitiatorFinishAck { .. }
        ));
        assert!(pair.r.session().is_some() && pair.r.sas_bytes_for_test().is_some());
        assert!(!pair.r.admission.terminal);
        assert_eq!(a.er.status().unwrap(), Status::Busy);
        assert_eq!(remaining(&a.er), 9);

        // I has nothing further to send or wait for.
        assert_eq!(
            pair.i.emit_initiator_finish(),
            Err(CeremonyError::Completed)
        );
        assert_eq!(
            pair.i.receive_completion(&r_ack),
            Err(CeremonyError::Completed)
        );
        assert_eq!(
            pair.i.confirm_initiator_finish_ack_sent(&undelivered),
            Err(CeremonyError::Completed)
        );
        // R later ends locally (here: local CANCEL) with no result; I's result is unaffected,
        // even if R's authenticated CANCEL then reaches I.
        let cancel = emitted_cancel(pair.r.cancel_sas(&id));
        assert_failed(&mut pair.r, &a.er, &id);
        let ops = crypto::mac_operations();
        assert_eq!(
            pair.i.receive_cancel(&cancel),
            Err(CeremonyError::Completed)
        );
        assert_eq!(crypto::mac_operations(), ops);
        assert_eq!(pair.i.result().cloned(), result_i);
        assert_succeeded(&mut pair.i, &a.ei, &id);
        drop(pair);
        a.release();
    }

    /// The corrected success point: a produced but never-sent final ACK yields no result.
    #[test]
    fn final_ack_never_sent_leaves_the_initiator_without_a_result() {
        let a = Authorities::new("finish-never-sent");
        let (mut pair, id) = approvals_authenticated(&a);
        let i_finish = finish(&mut pair.i);
        let r_ack = responder_ack(&mut pair.r, &i_finish);
        let unsent = initiator_ack(&mut pair.i, &r_ack);

        assert_final_ack_pending(&pair.i, &a.ei, &unsent);
        assert!(pair.i.is_own_mac_emitted() && pair.i.is_peer_approval_authenticated());
        assert!(!pair.i.is_ready_for_completion());
        let ops = crypto::mac_operations();
        assert_eq!(
            pair.i.emit_initiator_finish(),
            Ok(FinishEmission::AlreadyEmitted)
        );
        assert_eq!(
            pair.i.emit_bootstrap_mac(),
            Ok(BootstrapMacEmission::AlreadyEmitted)
        );
        assert_eq!(crypto::mac_operations(), ops);
        assert_final_ack_pending(&pair.i, &a.ei, &unsent);
        // R is exactly where a lost final ACK leaves it.
        assert!(matches!(
            pair.r.state,
            State::AwaitInitiatorFinishAck { .. }
        ));
        assert_eq!(pair.r.result(), None);
        assert_eq!(a.er.status().unwrap(), Status::Busy);

        // Local termination before the send boundary: failure, never success.
        pair.i.terminate().unwrap();
        assert_failed(&mut pair.i, &a.ei, &id);
        assert_eq!(
            pair.i.confirm_initiator_finish_ack_sent(&unsent),
            Err(CeremonyError::NoPendingFinalAck)
        );
        assert_failed(&mut pair.i, &a.ei, &id);
        assert_eq!((remaining(&a.ei), remaining(&a.er)), (9, 9));
        drop(pair);
        a.release();
    }

    #[test]
    fn send_confirmation_is_bound_to_the_exact_pending_final_ack() {
        let (first, second) = (
            Authorities::new("finish-confirm-a"),
            Authorities::new("finish-confirm-b"),
        );
        let (mut pair, id) = approvals_authenticated(&first);
        let (mut other, other_id) = approvals_authenticated(&second);

        // Before any final ACK exists, on either role, confirmation has no effect.
        let i_finish = finish(&mut pair.i);
        let r_ack = responder_ack(&mut pair.r, &i_finish);
        for (run, executor) in [(&mut pair.i, &first.ei), (&mut pair.r, &first.er)] {
            let seen = run.seen.len();
            assert_eq!(
                run.confirm_initiator_finish_ack_sent(&r_ack),
                Err(CeremonyError::NoPendingFinalAck)
            );
            assert_eq!(run.seen.len(), seen);
            assert!(run.session().is_some() && run.result().is_none());
            assert_eq!(executor.status().unwrap(), Status::Busy);
        }
        assert!(matches!(pair.i.state, State::AwaitResponderFinish { .. }));
        assert!(matches!(
            pair.r.state,
            State::AwaitInitiatorFinishAck { .. }
        ));

        let i_ack = initiator_ack(&mut pair.i, &r_ack);
        let o_finish = finish(&mut other.i);
        let o_r_ack = responder_ack(&mut other.r, &o_finish);
        let o_ack = initiator_ack(&mut other.i, &o_r_ack);
        // Same request ID and step, but another ceremony's identity and tag.
        assert_eq!(finish_parts(&o_ack).1, finish_parts(&i_ack).1);
        assert_ne!(o_ack, i_ack);
        let mut flipped = i_ack.clone();
        *flipped.last_mut().unwrap() ^= 1;
        let ops = crypto::mac_operations();
        for wrong in [
            o_ack.clone(),
            flipped,
            i_ack[..i_ack.len() - 1].to_vec(),
            r_ack.clone(),
            i_finish.clone(),
            Vec::new(),
        ] {
            assert_eq!(
                pair.i.confirm_initiator_finish_ack_sent(&wrong),
                Err(CeremonyError::FinalAckMismatch)
            );
            // Rejected without effect: still pending, no result, nothing released.
            assert_final_ack_pending(&pair.i, &first.ei, &i_ack);
        }
        // Stale callback from this ceremony into the other one: also no effect.
        assert_eq!(
            other.i.confirm_initiator_finish_ack_sent(&i_ack),
            Err(CeremonyError::FinalAckMismatch)
        );
        assert_final_ack_pending(&other.i, &second.ei, &o_ack);
        assert_eq!(crypto::mac_operations(), ops);

        // The exact frame confirms each ceremony's own success, once.
        confirm_sent(&mut pair.i, &i_ack);
        assert_succeeded(&mut pair.i, &first.ei, &id);
        let result = pair.i.result().cloned();
        for _ in 0..2 {
            assert_eq!(
                pair.i.confirm_initiator_finish_ack_sent(&i_ack),
                Err(CeremonyError::Completed)
            );
        }
        assert_eq!(pair.i.result().cloned(), result);
        confirm_sent(&mut other.i, &o_ack);
        assert_succeeded(&mut other.i, &second.ei, &other_id);
        assert_eq!(pair.i.result().cloned(), result);
        assert_ne!(other.i.result().cloned(), result);

        // Responder success is unchanged: only a verified final ACK completes it.
        assert_eq!(pair.r.result(), None);
        assert_eq!(
            pair.r.receive_completion(&i_ack),
            Ok(CompletionReceipt::Succeeded)
        );
        assert_succeeded(&mut pair.r, &first.er, &id);
        drop((pair, other));
        first.release();
        second.release();
    }

    #[test]
    fn local_reject_or_cancel_before_send_confirmation_cannot_be_revived() {
        for reject in [false, true] {
            let a = Authorities::new(&format!("finish-pending-local-{reject}"));
            let (mut pair, id) = approvals_authenticated(&a);
            let i_finish = finish(&mut pair.i);
            let r_ack = responder_ack(&mut pair.r, &i_finish);
            let i_ack = initiator_ack(&mut pair.i, &r_ack);
            assert_final_ack_pending(&pair.i, &a.ei, &i_ack);
            let outcome = if reject {
                pair.i.reject_sas(&id)
            } else {
                pair.i.cancel_sas(&id)
            };
            let cancel = emitted_cancel(outcome);
            // The pending ACK and the session are gone, and the guard was then released.
            assert_failed(&mut pair.i, &a.ei, &id);
            // R, awaiting the final ACK, authenticates the CANCEL instead and ends without one.
            assert!(pair.r.receive_cancel(&cancel).is_ok());
            assert_failed(&mut pair.r, &a.er, &id);
            assert!(pair.r.receive_completion(&i_ack).is_err());
            assert_eq!(pair.r.result(), None);
            // A late send confirmation or duplicate ACK cannot revive the run.
            assert_eq!(
                pair.i.confirm_initiator_finish_ack_sent(&i_ack),
                Err(CeremonyError::NoPendingFinalAck)
            );
            assert!(pair.i.receive_completion(&r_ack).is_err());
            assert!(pair.i.emit_initiator_finish().is_err());
            assert_failed(&mut pair.i, &a.ei, &id);
            assert_eq!(remaining(&a.ei), 9);
            drop(pair);
            a.release();
        }
    }

    #[test]
    fn initiator_finish_requires_authenticated_approvals_and_the_initiator_role() {
        let a = Authorities::new("finish-preconditions");
        let mut pre = RemoteCeremony::initiator_with_fixed_start_for_test(
            a.ei.clone(),
            a.ei.begin(Role::Initiator).unwrap(),
            &vector("START"),
            bootstrap(&decoded("START"), true),
            None,
        )
        .unwrap();
        assert_eq!(pre.emit_initiator_finish(), Err(CeremonyError::NoLiveSas));
        drop(pre);

        let not_yet = Err(CeremonyError::ApprovalsNotAuthenticated);
        let mut pair = establish(&a);
        let id = pair.identity();
        let ops = crypto::mac_operations();
        // SAS displayed; then locally approved; then own MAC emitted with the peer's pending.
        assert_eq!(pair.i.emit_initiator_finish(), not_yet);
        pair.i.approve_sas(&id).unwrap();
        assert_eq!(pair.i.emit_initiator_finish(), not_yet);
        let i_mac = emitted(&mut pair.i);
        let ops_after_mac = crypto::mac_operations();
        assert_eq!(ops_after_mac, ops + 1);
        assert_eq!(pair.i.emit_initiator_finish(), not_yet);
        assert!(pair.i.is_own_mac_emitted() && !pair.i.is_ready_for_completion());

        // The Responder can never start completion, even once ready.
        assert_eq!(
            pair.r.emit_initiator_finish(),
            Err(CeremonyError::NotInitiator)
        );
        pair.r.receive_bootstrap_mac(&i_mac).unwrap();
        let r_mac = approve_and_emit(&mut pair.r, &id);
        assert!(pair.r.is_ready_for_completion());
        let (ops, seen) = (crypto::mac_operations(), pair.r.seen.len());
        assert_eq!(
            pair.r.emit_initiator_finish(),
            Err(CeremonyError::NotInitiator)
        );
        assert_eq!((crypto::mac_operations(), pair.r.seen.len()), (ops, seen));
        assert!(pair.r.is_ready_for_completion(), "refusal has no effect");

        // Once both approvals are authenticated, I emits exactly one INITIATOR_FINISH.
        pair.i.receive_bootstrap_mac(&r_mac).unwrap();
        finish(&mut pair.i);
        let ops = crypto::mac_operations();
        for _ in 0..2 {
            assert_eq!(
                pair.i.emit_initiator_finish(),
                Ok(FinishEmission::AlreadyEmitted)
            );
        }
        assert_eq!(crypto::mac_operations(), ops, "no repeated MAC calculation");
        assert!(matches!(pair.i.state, State::AwaitResponderFinish { .. }));
        assert!(pair.i.admission.authorization.is_none());
        assert_eq!(a.ei.status().unwrap(), Status::Busy);
        assert_eq!((remaining(&a.ei), remaining(&a.er)), (9, 9));
        drop(pair);

        // Peer MAC verified first while local approval is still pending: still refused.
        let mut pair = establish(&a);
        let id = pair.identity();
        let r_mac = approve_and_emit(&mut pair.r, &id);
        pair.i.receive_bootstrap_mac(&r_mac).unwrap();
        assert_eq!(pair.i.emit_initiator_finish(), not_yet);
        pair.i.approve_sas(&id).unwrap();
        assert_eq!(pair.i.emit_initiator_finish(), not_yet);
        assert!(pair.i.presentation().is_none() && !pair.i.is_ready_for_completion());
        // After termination there is no live SAS at all.
        pair.i.cancel_sas(&id).unwrap();
        assert_eq!(
            pair.i.emit_initiator_finish(),
            Err(CeremonyError::NoLiveSas)
        );
        drop(pair);
        a.release();
    }

    /// Delivers `mutate(valid frame)` for `step` to its receiver and proves terminal failure
    /// with no result, MAC work only where the tag had to be checked, and no revival.
    fn assert_bad_finish_is_terminal(
        scope: &str,
        step: Completion,
        mutate: impl Fn(&[u8]) -> Vec<u8>,
        expected: CeremonyError,
    ) {
        let a = Authorities::new(scope);
        let (mut pair, id, valid) = drive_to(&a, step);
        let sender_result = endpoint(&mut pair, step.sender()).result().cloned();
        let bad = mutate(&valid);
        assert_ne!(bad, valid);
        let checks_mac = matches!(expected, CeremonyError::Crypto(_));
        let run = endpoint(&mut pair, step.receiver());
        let ops = crypto::mac_operations();
        assert_eq!(run.receive_completion(&bad), Err(expected));
        assert_eq!(crypto::mac_operations(), ops + usize::from(checks_mac));
        assert_failed(run, endpoint_executor(&a, step.receiver()), &id);
        // A later valid frame or emission cannot revive the run or create a result.
        assert!(run.receive_completion(&valid).is_err());
        assert!(run.emit_initiator_finish().is_err());
        assert_failed(run, endpoint_executor(&a, step.receiver()), &id);
        // The sender is a separate endpoint. If it already produced the final ACK, its local
        // result stays exactly as it was.
        assert_eq!(
            endpoint(&mut pair, step.sender()).result().cloned(),
            sender_result
        );
        assert_eq!(
            sender_result.is_some(),
            step == Completion::InitiatorFinishAck
        );
        drop(pair);
        a.release();
    }

    #[test]
    fn corrupted_finish_mac_is_terminal_at_every_step() {
        for (index, step) in STEPS.into_iter().enumerate() {
            assert_bad_finish_is_terminal(
                &format!("finish-bad-mac-{index}"),
                step,
                |valid| {
                    let (step, rid, digest, mut mac) = finish_parts(valid);
                    mac[31] ^= 0x01;
                    finish_wire(step, rid, digest, mac)
                },
                CeremonyError::Crypto(crypto::Error::MacMismatch),
            );
        }
    }

    #[test]
    fn wrong_transcript_digest_or_request_id_is_terminal_at_every_step() {
        for (index, step) in STEPS.into_iter().enumerate() {
            // One digest bit; the rest of the frame stays valid. Rejected by the explicit
            // digest check before any MAC work.
            assert_bad_finish_is_terminal(
                &format!("finish-digest-{index}"),
                step,
                |valid| {
                    let (step, rid, mut digest, mac) = finish_parts(valid);
                    digest[13] ^= 0x10;
                    finish_wire(step, rid, digest, mac)
                },
                CeremonyError::TranscriptMismatch,
            );
            assert_bad_finish_is_terminal(
                &format!("finish-request-id-{index}"),
                step,
                |valid| {
                    let (step, mut rid, digest, mac) = finish_parts(valid);
                    rid[0] ^= 0x01;
                    finish_wire(step, rid, digest, mac)
                },
                CeremonyError::RequestIdMismatch,
            );
            // A truncated tag never reaches MAC verification.
            assert_bad_finish_is_terminal(
                &format!("finish-short-tag-{index}"),
                step,
                |valid| {
                    let mut short = valid[..valid.len() - 1].to_vec();
                    let at = short.len() - 35;
                    short[at..at + 4].copy_from_slice(&31u32.to_be_bytes());
                    short
                },
                CeremonyError::Codec(protocol::CodecError::InvalidField("fixed_32")),
            );
        }
    }

    #[test]
    fn finish_macs_bind_type_purpose_direction_and_identity() {
        let mismatch = Err(crypto::Error::MacMismatch);
        for (index, step) in STEPS.into_iter().enumerate() {
            let a = Authorities::new(&format!("finish-binding-{index}"));
            let (mut pair, id, valid) = drive_to(&a, step);
            let tag = finish_parts(&valid).3;
            let run = &*endpoint(&mut pair, step.receiver());
            let verify = |kind: u8, purpose: &[u8], s, r, id: &[u8; 32]| {
                let (input, info) =
                    crypto::completion_mac_strings_for_test(kind, purpose, s, r, id);
                run.session()
                    .unwrap()
                    .established
                    .verify_mac(&input, &info, &tag)
            };
            let (t, p, s, r) = (
                step.auth_frame_type(),
                step.purpose(),
                step.sender(),
                step.receiver(),
            );
            assert_eq!(verify(t, p, s, r, &id), Ok(()));
            let mut other_id = id;
            other_id[17] ^= 0x40;
            // Swapped direction, both roles equal, and another ceremony identity.
            assert_eq!(verify(t, p, r, s, &id), mismatch);
            assert_eq!(verify(t, p, s, s, &id), mismatch);
            assert_eq!(verify(t, p, r, r, &id), mismatch);
            assert_eq!(verify(t, p, s, r, &other_id), mismatch);
            // A generic purpose is not a completion purpose.
            assert_eq!(verify(t, b"finish", s, r, &id), mismatch);
            for other in STEPS.into_iter().filter(|other| *other != step) {
                // Type changed with the purpose unchanged, purpose changed with the type
                // unchanged, and the other step's complete reconstruction.
                assert_eq!(verify(other.auth_frame_type(), p, s, r, &id), mismatch);
                assert_eq!(verify(t, other.purpose(), s, r, &id), mismatch);
                assert_eq!(
                    verify(
                        other.auth_frame_type(),
                        other.purpose(),
                        other.sender(),
                        other.receiver(),
                        &id
                    ),
                    mismatch
                );
            }
            drop(pair);
            a.release();
        }
    }

    #[test]
    fn a_finish_tag_cannot_authenticate_another_finish_step() {
        let a = Authorities::new("finish-cross-step");
        let (mut pair, id) = approvals_authenticated(&a);
        let i_finish = finish(&mut pair.i);
        responder_ack(&mut pair.r, &i_finish);
        let (_, rid, digest, finish_tag) = finish_parts(&i_finish);
        // Same sender, receiver, request ID, and digest as the final ACK; only the step differs.
        let as_final_ack = finish_wire(STEPS[2], rid.clone(), digest, finish_tag);
        assert_eq!(
            pair.r.receive_completion(&as_final_ack),
            Err(CeremonyError::Crypto(crypto::Error::MacMismatch))
        );
        assert_failed(&mut pair.r, &a.er, &id);
        // I's own-direction tag relabelled as the Responder's ACK.
        let as_responder_ack = finish_wire(STEPS[1], rid, digest, finish_tag);
        assert_eq!(
            pair.i.receive_completion(&as_responder_ack),
            Err(CeremonyError::Crypto(crypto::Error::MacMismatch))
        );
        assert_failed(&mut pair.i, &a.ei, &id);
        drop(pair);
        a.release();
    }

    #[test]
    fn finish_from_another_ceremony_with_the_same_request_id_fails() {
        let (first, second, third) = (
            Authorities::new("finish-cross-a"),
            Authorities::new("finish-cross-b"),
            Authorities::new("finish-cross-c"),
        );
        let (mut a, id_a) = approvals_authenticated(&first);
        let (mut b, id_b) = approvals_authenticated(&second);
        let (mut c, id_c) = approvals_authenticated(&third);
        assert!(id_a != id_b && id_a != id_c && id_b != id_c);
        let foreign = finish(&mut a.i);
        let own = finish(&mut b.i);
        let (_, rid, _, tag_a) = finish_parts(&foreign);
        assert_eq!(rid, finish_parts(&own).1, "identical request IDs");

        // As sent, the digest names ceremony A: rejected before any MAC work.
        let ops = crypto::mac_operations();
        assert_eq!(
            b.r.receive_completion(&foreign),
            Err(CeremonyError::TranscriptMismatch)
        );
        assert_eq!(crypto::mac_operations(), ops);
        assert_failed(&mut b.r, &second.er, &id_b);
        assert!(b.r.receive_completion(&own).is_err());
        assert_failed(&mut b.r, &second.er, &id_b);

        // Relabelled with C's digest, A's tag still cannot authenticate C.
        let relabelled = finish_wire(STEPS[0], rid, id_c, tag_a);
        assert_eq!(
            c.r.receive_completion(&relabelled),
            Err(CeremonyError::Crypto(crypto::Error::MacMismatch))
        );
        assert_failed(&mut c.r, &third.er, &id_c);

        // Ceremony A is unaffected and completes with its own identity.
        let r_ack = responder_ack(&mut a.r, &foreign);
        let i_ack = initiator_ack(&mut a.i, &r_ack);
        assert_eq!(
            a.r.receive_completion(&i_ack),
            Ok(CompletionReceipt::Succeeded)
        );
        assert_eq!(a.r.result().unwrap().ceremony_identity(), &id_a);
        drop((a, b, c));
        first.release();
        second.release();
        third.release();
    }

    #[test]
    fn exact_finish_duplicate_is_idempotent_and_changed_duplicate_is_terminal() {
        let a = Authorities::new("finish-duplicates");
        let (mut pair, id) = approvals_authenticated(&a);
        let i_finish = finish(&mut pair.i);
        let r_ack = responder_ack(&mut pair.r, &i_finish);
        let (seen, ops) = (pair.r.seen.len(), crypto::mac_operations());
        for _ in 0..2 {
            // No second RESPONDER_FINISH_ACK, MAC verification, retained copy, or transition.
            assert_eq!(
                pair.r.receive_completion(&i_finish),
                Ok(CompletionReceipt::AlreadyAccepted)
            );
        }
        assert_eq!((pair.r.seen.len(), crypto::mac_operations()), (seen, ops));
        assert!(matches!(
            pair.r.state,
            State::AwaitInitiatorFinishAck { .. }
        ));
        assert_eq!(pair.r.result(), None);
        assert_eq!(a.er.status().unwrap(), Status::Busy);

        // Changed bytes for the already accepted INITIATOR_FINISH: terminal while active.
        let (step, rid, digest, mut mac) = finish_parts(&i_finish);
        mac[0] ^= 0x80;
        assert_eq!(
            pair.r
                .receive_completion(&finish_wire(step, rid, digest, mac)),
            Err(CeremonyError::InvalidState)
        );
        assert_eq!(crypto::mac_operations(), ops);
        assert_failed(&mut pair.r, &a.er, &id);

        // While I's final ACK awaits its send boundary, an exact duplicate RESPONDER_FINISH_ACK
        // is ignored: no second final ACK, MAC work, result, accounting, or guard change.
        let i_ack = initiator_ack(&mut pair.i, &r_ack);
        let (seen, ops) = (pair.i.seen.len(), crypto::mac_operations());
        for _ in 0..2 {
            assert_eq!(
                pair.i.receive_completion(&r_ack),
                Ok(CompletionReceipt::AlreadyAccepted)
            );
        }
        assert_eq!((pair.i.seen.len(), crypto::mac_operations()), (seen, ops));
        assert_final_ack_pending(&pair.i, &a.ei, &i_ack);
        // After success a duplicate is rejected and changes nothing.
        confirm_sent(&mut pair.i, &i_ack);
        let result = pair.i.result().cloned();
        assert_eq!(
            pair.i.receive_completion(&r_ack),
            Err(CeremonyError::Completed)
        );
        assert_eq!(pair.i.result().cloned(), result);
        // The correct final ACK cannot revive the failed Responder.
        assert!(pair.r.receive_completion(&i_ack).is_err());
        assert_failed(&mut pair.r, &a.er, &id);
        drop(pair);
        a.release();

        // A changed RESPONDER_FINISH_ACK while the final ACK is pending is terminal, and the
        // pending ACK can no longer be confirmed.
        let a = Authorities::new("finish-duplicates-pending");
        let (mut pair, id) = approvals_authenticated(&a);
        let i_finish = finish(&mut pair.i);
        let r_ack = responder_ack(&mut pair.r, &i_finish);
        let i_ack = initiator_ack(&mut pair.i, &r_ack);
        let (step, rid, digest, mut mac) = finish_parts(&r_ack);
        mac[5] ^= 0x04;
        let ops = crypto::mac_operations();
        assert_eq!(
            pair.i
                .receive_completion(&finish_wire(step, rid, digest, mac)),
            Err(CeremonyError::InvalidState)
        );
        assert_eq!(crypto::mac_operations(), ops);
        assert_failed(&mut pair.i, &a.ei, &id);
        assert_eq!(
            pair.i.confirm_initiator_finish_ack_sent(&i_ack),
            Err(CeremonyError::NoPendingFinalAck)
        );
        assert_failed(&mut pair.i, &a.ei, &id);
        drop(pair);
        a.release();
    }

    #[test]
    fn out_of_order_or_wrong_role_completion_is_terminal_without_mac_work() {
        type Setup = fn(&mut Pair, &[u8; 32]);
        let cases: [(Completion, protocol::Role, Setup); 9] = [
            // I receives RESPONDER_FINISH_ACK before it emitted INITIATOR_FINISH.
            (STEPS[1], protocol::Role::Initiator, authenticate),
            // I, ready but not yet finished, receives an INITIATOR_FINISH (its own direction).
            (STEPS[0], protocol::Role::Initiator, authenticate),
            // R receives INITIATOR_FINISH_ACK before it sent RESPONDER_FINISH_ACK.
            (STEPS[2], protocol::Role::Responder, authenticate),
            // R receives a Responder-direction message.
            (STEPS[1], protocol::Role::Responder, authenticate),
            // I receives Initiator-direction messages while awaiting R's ACK.
            (STEPS[0], protocol::Role::Initiator, |p, id| {
                authenticate(p, id);
                finish(&mut p.i);
            }),
            (STEPS[2], protocol::Role::Initiator, |p, id| {
                authenticate(p, id);
                finish(&mut p.i);
            }),
            // R awaiting the final ACK receives a RESPONDER_FINISH_ACK.
            (STEPS[1], protocol::Role::Responder, |p, id| {
                authenticate(p, id);
                let f = finish(&mut p.i);
                responder_ack(&mut p.r, &f);
            }),
            // R receives INITIATOR_FINISH before I's approval MAC is verified.
            (STEPS[0], protocol::Role::Responder, |p, id| {
                approve_and_emit(&mut p.r, id);
            }),
            // R receives INITIATOR_FINISH while its SAS is still displayed.
            (STEPS[0], protocol::Role::Responder, |_, _| {}),
        ];
        for (index, (step, receiver, setup)) in cases.into_iter().enumerate() {
            let a = Authorities::new(&format!("finish-order-{index}"));
            let mut pair = establish(&a);
            let id = pair.identity();
            setup(&mut pair, &id);
            // Correct request ID and digest; the tag is never examined.
            let frame = finish_wire(step, vector_request_id(), id, [0x5a; 32]);
            let run = endpoint(&mut pair, receiver);
            let ops = crypto::mac_operations();
            assert_eq!(
                run.receive_completion(&frame),
                Err(CeremonyError::InvalidState),
                "case {index}"
            );
            assert_eq!(crypto::mac_operations(), ops);
            assert_failed(run, endpoint_executor(&a, receiver), &id);
            drop(pair);
            a.release();
        }

        // A non-completion message offered as completion input is also terminal.
        let a = Authorities::new("finish-order-other-type");
        let (mut pair, id) = approvals_authenticated(&a);
        let rkey = pair.wire[3].clone();
        assert_eq!(
            pair.r.receive_completion(&rkey),
            Err(CeremonyError::InvalidState)
        );
        assert_failed(&mut pair.r, &a.er, &id);
        drop(pair);
        a.release();
    }

    #[test]
    fn local_reject_or_cancel_during_completion_is_terminal_without_result() {
        type Setup = fn(&mut Pair, &[u8; 32]);
        let stages: [(protocol::Role, Setup); 4] = [
            // I awaiting RESPONDER_FINISH_ACK.
            (protocol::Role::Initiator, |p, id| {
                authenticate(p, id);
                finish(&mut p.i);
            }),
            // I holding its produced but unconfirmed final ACK.
            (protocol::Role::Initiator, |p, id| {
                authenticate(p, id);
                let f = finish(&mut p.i);
                let ack = responder_ack(&mut p.r, &f);
                initiator_ack(&mut p.i, &ack);
            }),
            // R awaiting INITIATOR_FINISH.
            (protocol::Role::Responder, authenticate),
            // R awaiting the final INITIATOR_FINISH_ACK.
            (protocol::Role::Responder, |p, id| {
                authenticate(p, id);
                let f = finish(&mut p.i);
                responder_ack(&mut p.r, &f);
            }),
        ];
        for (index, (role, setup)) in stages.into_iter().enumerate() {
            for reject in [false, true] {
                let a = Authorities::new(&format!("finish-local-{index}-{reject}"));
                let mut pair = establish(&a);
                let id = pair.identity();
                setup(&mut pair, &id);
                let run = endpoint(&mut pair, role);
                let seen = run.seen.len();
                let (outcome, reason) = if reject {
                    (run.reject_sas(&id), CancelReason::UserRejection)
                } else {
                    (run.cancel_sas(&id), CancelReason::UserCancellation)
                };
                let cancel = emitted_cancel(outcome);
                assert_eq!(run.seen.len(), seen, "no inbound state recorded");
                assert_failed(run, endpoint_executor(&a, role), &id);
                assert!(run.emit_initiator_finish().is_err());
                // The live peer, wherever completion left it, authenticates and ends too.
                let peer = endpoint(&mut pair, other(role));
                assert_eq!(
                    peer.receive_cancel(&cancel).map(|c| c.reason()),
                    Ok(reason),
                    "stage {index}"
                );
                assert_failed(peer, endpoint_executor(&a, other(role)), &id);
                drop(pair);
                a.release();
            }
        }
    }

    #[test]
    fn local_success_is_immutable_and_retains_no_live_state() {
        let a = Authorities::new("finish-immutable");
        let (mut pair, id) = approvals_authenticated(&a);
        let i_finish = finish(&mut pair.i);
        let r_ack = responder_ack(&mut pair.r, &i_finish);
        let i_ack = initiator_ack(&mut pair.i, &r_ack);
        confirm_sent(&mut pair.i, &i_ack);
        pair.r.receive_completion(&i_ack).unwrap();
        let wire = pair.wire.clone();
        let bootstrap_mac = mac_frame(vector_request_id(), protocol::Role::Initiator, [1; 32]);
        for (run, executor, authority) in [(&mut pair.i, &a.ei, &a.i), (&mut pair.r, &a.er, &a.r)] {
            let result = run.result().cloned().unwrap();
            let ops = crypto::mac_operations();
            for frame in [&i_finish, &r_ack, &i_ack] {
                assert_eq!(run.receive_completion(frame), Err(CeremonyError::Completed));
                let mut changed = frame.clone();
                *changed.last_mut().unwrap() ^= 1;
                assert_eq!(
                    run.receive_completion(&changed),
                    Err(CeremonyError::Completed)
                );
            }
            assert_eq!(
                run.receive_completion(b"not a frame"),
                Err(CeremonyError::Completed)
            );
            assert_eq!(
                run.receive_bootstrap_mac(&bootstrap_mac),
                Err(CeremonyError::Completed)
            );
            assert!(run.receive_bootstrap_mac(b"not a frame").is_err());
            assert!(run.receive_start_duplicate(&wire[0]).is_err());
            assert!(run.receive_accept(&wire[1]).is_err());
            assert!(run.receive_initiator_key(&wire[2]).is_err());
            assert!(run.receive_responder_key(&wire[3]).is_err());
            assert!(run.start().is_err());
            assert!(run.authorize(authority).is_err());
            assert!(run.expose_key().is_err());
            assert_eq!(run.emit_initiator_finish(), Err(CeremonyError::Completed));
            assert_eq!(
                run.confirm_initiator_finish_ack_sent(&i_ack),
                Err(CeremonyError::Completed)
            );
            assert_eq!(run.emit_bootstrap_mac(), Err(CeremonyError::NoLiveSas));
            // Old approval, reject, and cancel callbacks have no live SAS to act on.
            assert_eq!(run.approve_sas(&id), Err(CeremonyError::NoLiveSas));
            assert_eq!(run.reject_sas(&id), Err(CeremonyError::NoLiveSas));
            assert_eq!(run.cancel_sas(&id), Err(CeremonyError::NoLiveSas));
            assert_eq!(run.terminate(), Ok(()));
            assert_eq!(run.presentation(), None);
            assert_eq!(crypto::mac_operations(), ops);
            assert_eq!(run.result(), Some(&result));
            assert_succeeded(run, executor, &id);
        }
        drop(pair);
        a.release();
    }

    #[test]
    fn uncertain_guard_release_at_the_success_point_fails_closed_without_result() {
        let a = Authorities::new("finish-uncertain-release");
        let (mut pair, id) = approvals_authenticated(&a);
        let i_finish = finish(&mut pair.i);
        let r_ack = responder_ack(&mut pair.r, &i_finish);
        let i_ack = initiator_ack(&mut pair.i, &r_ack);
        let poisoned = a.ei.clone();
        let _ = std::thread::spawn(move || {
            let _shared = poisoned.0.shared.lock().unwrap();
            panic!("simulate uncertain guard state");
        })
        .join();
        // The final ACK was sent, yet no result is released; the session is already dropped.
        assert_eq!(
            pair.i.confirm_initiator_finish_ack_sent(&i_ack),
            Err(CeremonyError::Owner(OwnerError::OwnershipUncertain))
        );
        assert_eq!(pair.i.result(), None);
        assert!(matches!(pair.i.state, State::Terminal));
        assert_stale(&mut pair.i, &id);
        assert_eq!(
            pair.i.confirm_initiator_finish_ack_sent(&i_ack),
            Err(CeremonyError::NoPendingFinalAck)
        );
        assert!(pair.i.receive_completion(&r_ack).is_err());
        assert_eq!(pair.i.result(), None);
        match a.ei.0.shared.lock() {
            Err(poisoned) => assert!(poisoned.into_inner().active.is_some()),
            Ok(_) => panic!("shared state unexpectedly recovered"),
        }
        drop(pair);
        a.release();
    }

    // ---- Authenticated CANCEL ----

    const REASONS: [CancelReason; 4] = [
        CancelReason::UserRejection,
        CancelReason::UserCancellation,
        CancelReason::Timeout,
        CancelReason::LocalPolicyFailure,
    ];

    fn poison(executor: &CeremonyExecutor) {
        let poisoned = executor.clone();
        let _ = std::thread::spawn(move || {
            let _shared = poisoned.0.shared.lock().unwrap();
            panic!("simulate uncertain guard state");
        })
        .join();
    }

    /// Fail closed: the guard is still held and the consumed opportunity is not refunded.
    fn assert_guard_held_uncertainly(executor: &CeremonyExecutor) {
        match executor.0.shared.lock() {
            Err(poisoned) => {
                let shared = poisoned.into_inner();
                assert!(shared.active.is_some());
                assert_eq!(shared.remaining, 9);
            }
            Ok(_) => panic!("shared state unexpectedly recovered"),
        }
    }

    #[test]
    fn live_local_cancel_i_to_r_is_terminal_first_then_authenticated_by_the_peer() {
        let a = Authorities::new("cancel-live-i-to-r");
        let mut pair = establish(&a);
        let id = pair.identity();
        let ops = crypto::mac_operations();
        let cancel = emitted_cancel(pair.i.cancel_sas(&id));
        assert_eq!(
            crypto::mac_operations(),
            ops + 1,
            "one vodozemac calculate_mac"
        );
        assert_eq!(cancel[9], 0x09);
        let (rid, sender, reason, _) = cancel_parts(&cancel);
        assert_eq!(
            (rid, sender, reason),
            (
                vector_request_id(),
                protocol::Role::Initiator,
                CancelReason::UserCancellation
            )
        );
        // Terminal before any peer receipt: no result, session, or SAS; guard released; 9 left.
        assert_failed(&mut pair.i, &a.ei, &id);
        assert!(pair.i.session().is_none() && pair.i.presentation().is_none());
        // The peer is untouched until delivery.
        assert!(pair.r.is_awaiting_approval() && pair.r.presentation().is_some());
        assert_eq!(a.er.status().unwrap(), Status::Busy);

        let ops = crypto::mac_operations();
        assert_eq!(
            pair.r.receive_cancel(&cancel),
            Ok(PeerCancellation {
                reason: CancelReason::UserCancellation
            })
        );
        assert_eq!(
            crypto::mac_operations(),
            ops + 1,
            "one vodozemac verify_mac"
        );
        assert_failed(&mut pair.r, &a.er, &id);
        assert!(pair.r.admission.authorization.is_none());
        assert_eq!((remaining(&a.ei), remaining(&a.er)), (9, 9));
        drop(pair);
        a.release();
    }

    #[test]
    fn live_timeout_cancel_r_to_i_is_authenticated_without_any_timer() {
        let a = Authorities::new("cancel-live-r-to-i");
        let (mut pair, id) = approvals_authenticated(&a);
        // The private reason-generic path; deadline expiry reaches the same construction.
        let cancel = emitted_cancel(pair.r.cancel_locally(&id, CancelReason::Timeout));
        let (rid, sender, reason, _) = cancel_parts(&cancel);
        assert_eq!(
            (rid, sender, reason),
            (
                vector_request_id(),
                protocol::Role::Responder,
                CancelReason::Timeout
            )
        );
        assert_failed(&mut pair.r, &a.er, &id);
        assert!(pair.i.is_ready_for_completion());
        assert_eq!(
            pair.i.receive_cancel(&cancel).map(|c| c.reason()),
            Ok(CancelReason::Timeout)
        );
        assert_failed(&mut pair.i, &a.ei, &id);
        // No INITIATOR_FINISH can follow.
        assert_eq!(
            pair.i.emit_initiator_finish(),
            Err(CeremonyError::NoLiveSas)
        );
        drop(pair);
        a.release();
    }

    #[test]
    fn every_defined_reason_authenticates_in_both_directions() {
        for sender in [protocol::Role::Initiator, protocol::Role::Responder] {
            let a = Authorities::new(&format!("cancel-reasons-{sender:?}"));
            for reason in REASONS {
                let mut pair = establish(&a);
                let id = pair.identity();
                let cancel =
                    emitted_cancel(endpoint(&mut pair, sender).cancel_locally(&id, reason));
                assert_eq!(cancel_parts(&cancel).1, sender);
                assert_eq!(cancel_parts(&cancel).2, reason);
                let receiver = endpoint(&mut pair, other(sender));
                assert_eq!(
                    receiver.receive_cancel(&cancel).map(|c| c.reason()),
                    Ok(reason)
                );
                assert_stale(receiver, &id);
                assert!(receiver.result().is_none() && receiver.admission.terminal);
                drop(pair);
            }
            assert_eq!(a.ei.status().unwrap(), Status::Ready { remaining: 6 });
            assert_eq!(a.er.status().unwrap(), Status::Ready { remaining: 6 });
            a.release();
        }
    }

    #[test]
    fn local_rejection_sends_user_rejection_and_terminates_the_peer() {
        let a = Authorities::new("cancel-user-rejection");
        let mut pair = establish(&a);
        let id = pair.identity();
        // R saw a different SAS than I did (MISMATCH/REJECT) after I already approved.
        let i_mac = approve_and_emit(&mut pair.i, &id);
        pair.r.receive_bootstrap_mac(&i_mac).unwrap();
        let cancel = emitted_cancel(pair.r.reject_sas(&id));
        assert_eq!(cancel_parts(&cancel).2, CancelReason::UserRejection);
        assert_eq!(cancel_parts(&cancel).1, protocol::Role::Responder);
        assert_failed(&mut pair.r, &a.er, &id);
        assert_eq!(
            pair.i.receive_cancel(&cancel).map(|c| c.reason()),
            Ok(CancelReason::UserRejection)
        );
        assert_failed(&mut pair.i, &a.ei, &id);
        assert_eq!((remaining(&a.ei), remaining(&a.er)), (9, 9));
        drop(pair);
        a.release();
    }

    #[test]
    fn undelivered_local_cancel_needs_no_transport_and_leaves_the_peer_live() {
        let a = Authorities::new("cancel-undelivered");
        let mut pair = establish(&a);
        let id = pair.identity();
        let ops = crypto::mac_operations();
        let _never_sent = emitted_cancel(pair.i.cancel_sas(&id));
        // Already terminal: there is no send confirmation, retransmission, ack, or fourth step.
        assert_failed(&mut pair.i, &a.ei, &id);
        assert_eq!(pair.i.cancel_sas(&id), Err(CeremonyError::NoLiveSas));
        assert_eq!(crypto::mac_operations(), ops + 1);
        // The peer stays active until its own cancellation, disconnect, or (later) timeout.
        let r_mac = approve_and_emit(&mut pair.r, &id);
        assert_eq!(mac_fields(&r_mac).0, vector_request_id());
        assert!(pair.r.session().is_some() && pair.r.result().is_none());
        assert_eq!(a.er.status().unwrap(), Status::Busy);
        emitted_cancel(pair.r.cancel_sas(&id));
        assert_failed(&mut pair.r, &a.er, &id);
        drop(pair);
        a.release();
    }

    /// Delivers `mutate(valid I->R CANCEL)` to R and proves terminal protocol failure: never
    /// peer cancellation, MAC work only when the tag had to be checked, and no revival.
    fn assert_bad_cancel_is_terminal(
        scope: &str,
        mutate: impl Fn(&[u8]) -> Vec<u8>,
        expected: CeremonyError,
    ) {
        let a = Authorities::new(scope);
        let mut pair = establish(&a);
        let id = pair.identity();
        let valid = emitted_cancel(pair.i.cancel_sas(&id));
        let bad = mutate(&valid);
        assert_ne!(bad, valid);
        let checks_mac = matches!(expected, CeremonyError::Crypto(_));
        let ops = crypto::mac_operations();
        assert_eq!(pair.r.receive_cancel(&bad), Err(expected));
        assert_eq!(crypto::mac_operations(), ops + usize::from(checks_mac));
        assert_failed(&mut pair.r, &a.er, &id);
        // The genuine CANCEL can no longer be verified or change anything.
        assert_eq!(
            pair.r.receive_cancel(&valid),
            Err(CeremonyError::InvalidState)
        );
        assert_eq!(crypto::mac_operations(), ops + usize::from(checks_mac));
        assert_failed(&mut pair.r, &a.er, &id);
        drop(pair);
        a.release();
    }

    #[test]
    fn changed_reason_is_syntactically_valid_but_fails_verification() {
        for (index, reason) in [
            CancelReason::UserRejection,
            CancelReason::Timeout,
            CancelReason::LocalPolicyFailure,
        ]
        .into_iter()
        .enumerate()
        {
            assert_bad_cancel_is_terminal(
                &format!("cancel-reason-{index}"),
                |valid| {
                    let (rid, sender, original, mac) = cancel_parts(valid);
                    assert_eq!(original, CancelReason::UserCancellation);
                    let changed = cancel_wire(rid, sender, reason, mac);
                    // Still a canonical CANCEL; only the reason (and so the MAC input) differs.
                    assert_eq!(cancel_parts(&changed).2, reason);
                    changed
                },
                CeremonyError::Crypto(crypto::Error::MacMismatch),
            );
        }
        // An undefined reason code never reaches MAC work.
        assert_bad_cancel_is_terminal(
            "cancel-reason-undefined",
            |valid| {
                let mut bad = valid.to_vec();
                let at = bad.len() - 37;
                assert_eq!(bad[at], CancelReason::UserCancellation as u8);
                bad[at] = 0x05;
                bad
            },
            CeremonyError::Codec(protocol::CodecError::InvalidField("reason")),
        );
    }

    #[test]
    fn corrupted_short_or_misrouted_cancel_is_terminal_protocol_failure() {
        assert_bad_cancel_is_terminal(
            "cancel-bit-flip",
            |valid| {
                let (rid, sender, reason, mut mac) = cancel_parts(valid);
                mac[31] ^= 0x01;
                cancel_wire(rid, sender, reason, mac)
            },
            CeremonyError::Crypto(crypto::Error::MacMismatch),
        );
        assert_bad_cancel_is_terminal(
            "cancel-short-tag",
            |valid| {
                let mut short = valid[..valid.len() - 1].to_vec();
                let at = short.len() - 35;
                short[at..at + 4].copy_from_slice(&31u32.to_be_bytes());
                short
            },
            CeremonyError::Codec(protocol::CodecError::InvalidField("fixed_32")),
        );
        assert_bad_cancel_is_terminal(
            "cancel-request-id",
            |valid| {
                let (mut rid, sender, reason, mac) = cancel_parts(valid);
                rid[0] ^= 0x01;
                cancel_wire(rid, sender, reason, mac)
            },
            CeremonyError::RequestIdMismatch,
        );
        // The receiver's own role on the wire: rejected before any MAC work (R-WIRE-017).
        assert_bad_cancel_is_terminal(
            "cancel-wire-role",
            |valid| {
                let (rid, _, reason, mac) = cancel_parts(valid);
                cancel_wire(rid, protocol::Role::Responder, reason, mac)
            },
            CeremonyError::UnexpectedSenderRole,
        );
        // A different message type offered as CANCEL input.
        assert_bad_cancel_is_terminal(
            "cancel-other-type",
            |_| vector("RESPONDER_KEY"),
            CeremonyError::InvalidState,
        );
    }

    #[test]
    fn a_cancel_tag_for_the_opposite_direction_fails_verification() {
        let a = Authorities::new("cancel-direction");
        let mut pair = establish(&a);
        let id = pair.identity();
        // I's genuine I->R tag, without ending I, relabelled as R->I and offered back to I:
        // the wire role is the expected peer, so only the MAC can reject it.
        let i_to_r = own_cancel(pair.i.session().unwrap(), CancelReason::Timeout).unwrap();
        let (rid, sender, reason, mac) = cancel_parts(&i_to_r);
        assert_eq!(sender, protocol::Role::Initiator);
        let relabelled = cancel_wire(rid, protocol::Role::Responder, reason, mac);
        let ops = crypto::mac_operations();
        assert_eq!(
            pair.i.receive_cancel(&relabelled),
            Err(CeremonyError::Crypto(crypto::Error::MacMismatch))
        );
        assert_eq!(crypto::mac_operations(), ops + 1);
        assert_failed(&mut pair.i, &a.ei, &id);
        // The same tag as sent (I->R) still authenticates at R: direction alone decided it.
        assert_eq!(
            pair.r.receive_cancel(&i_to_r).map(|c| c.reason()),
            Ok(CancelReason::Timeout)
        );
        assert_failed(&mut pair.r, &a.er, &id);
        drop(pair);
        a.release();
    }

    #[test]
    fn cancel_from_another_ceremony_with_the_same_request_id_cannot_cancel() {
        let (first, second) = (
            Authorities::new("cancel-cross-a"),
            Authorities::new("cancel-cross-b"),
        );
        let mut a = establish(&first);
        let mut b = establish(&second);
        let (id_a, id_b) = (a.identity(), b.identity());
        assert_ne!(id_a, id_b);
        let foreign = emitted_cancel(a.i.cancel_sas(&id_a));
        let own = own_cancel(b.i.session().unwrap(), CancelReason::UserCancellation).unwrap();
        // Same request ID, reason, and roles; only the ceremony (and so the tag) differs.
        let (fa, fb) = (cancel_parts(&foreign), cancel_parts(&own));
        assert_eq!((&fa.0, fa.1, fa.2), (&fb.0, fb.1, fb.2));
        assert_ne!(fa.3, fb.3);

        let ops = crypto::mac_operations();
        assert_eq!(
            b.r.receive_cancel(&foreign),
            Err(CeremonyError::Crypto(crypto::Error::MacMismatch))
        );
        assert_eq!(crypto::mac_operations(), ops + 1);
        assert_failed(&mut b.r, &second.er, &id_b);
        // B's Initiator is a separate live endpoint and is unaffected by the replay.
        assert!(b.i.is_awaiting_approval());
        assert_eq!(second.ei.status().unwrap(), Status::Busy);
        // Ceremony A's own Responder authenticates its genuine CANCEL.
        assert_eq!(
            a.r.receive_cancel(&foreign).map(|c| c.reason()),
            Ok(CancelReason::UserCancellation)
        );
        assert_failed(&mut a.r, &first.er, &id_a);
        drop((a, b));
        first.release();
        second.release();
    }

    #[test]
    fn cancel_mac_binds_frozen_types_purpose_roles_identity_and_reason() {
        const CANCEL: &[u8] = b"sas-pairing-vodozemac-profile-draft-01/cancel/";
        const MAC: &[u8] = b"sas-pairing-vodozemac-profile-draft-01/mac/";
        use protocol::Role::{Initiator as I, Responder as R};
        let mismatch = Err(crypto::Error::MacMismatch);
        for sender in [I, R] {
            let a = Authorities::new(&format!("cancel-binding-{sender:?}"));
            let mut pair = establish(&a);
            let id = pair.identity();
            let receiver = other(sender);
            let reason = CancelReason::UserCancellation;
            let tag = cancel_parts(&emitted_cancel(
                endpoint(&mut pair, sender).cancel_locally(&id, reason),
            ))
            .3;
            let run = &*endpoint(&mut pair, receiver);
            let verify = |auth: u8,
                          context: u8,
                          prefix: &[u8],
                          inner: Option<&[u8]>,
                          s,
                          r,
                          id: &[u8; 32],
                          reason: u8| {
                let (input, info) = crypto::cancel_mac_strings_for_test(
                    auth, context, prefix, inner, s, r, id, reason,
                );
                run.session()
                    .unwrap()
                    .established
                    .verify_mac(&input, &info, &tag)
            };
            let good = reason as u8;
            assert_eq!(
                verify(0x34, 0x38, CANCEL, None, sender, receiver, &id, good),
                Ok(())
            );
            // Context type 0x38 -> approval, completion, or the auth-frame type.
            for context in [0x31, 0x32, 0x34] {
                assert_eq!(
                    verify(0x34, context, CANCEL, None, sender, receiver, &id, good),
                    mismatch
                );
            }
            // Auth-frame type 0x34 -> approval, completion, or the context type.
            for auth in [0x33, 0x35, 0x38] {
                assert_eq!(
                    verify(auth, 0x38, CANCEL, None, sender, receiver, &id, good),
                    mismatch
                );
            }
            // Outer purpose `mac`, an inner `cancel` field, and both together.
            assert_eq!(
                verify(0x34, 0x38, MAC, None, sender, receiver, &id, good),
                mismatch
            );
            let inner = Some(&b"cancel"[..]);
            assert_eq!(
                verify(0x34, 0x38, CANCEL, inner, sender, receiver, &id, good),
                mismatch
            );
            assert_eq!(
                verify(0x34, 0x38, MAC, inner, sender, receiver, &id, good),
                mismatch
            );
            // Sender role, receiver role, and the swapped direction.
            for (s, r) in [(receiver, receiver), (sender, sender), (receiver, sender)] {
                assert_eq!(verify(0x34, 0x38, CANCEL, None, s, r, &id, good), mismatch);
            }
            // Another ceremony identity.
            let mut other_id = id;
            other_id[9] ^= 0x02;
            assert_eq!(
                verify(0x34, 0x38, CANCEL, None, sender, receiver, &other_id, good),
                mismatch
            );
            // Every other reason byte, defined or not.
            for other_reason in [0x00, 0x01, 0x03, 0x04, 0x05, 0xff] {
                assert_eq!(
                    verify(
                        0x34,
                        0x38,
                        CANCEL,
                        None,
                        sender,
                        receiver,
                        &id,
                        other_reason
                    ),
                    mismatch
                );
            }
            drop(pair);
            a.release();
        }
    }

    #[test]
    fn cancel_before_sas_establishment_is_invalid_input_without_mac_work() {
        let a = Authorities::new("cancel-pre-sas");
        let early = |sender| {
            cancel_wire(
                vector_request_id(),
                sender,
                CancelReason::UserCancellation,
                [7; 32],
            )
        };
        let ops = crypto::mac_operations();

        // I before exposure, awaiting ACCEPT: terminal, nothing spent.
        let mut i = RemoteCeremony::initiator_with_fixed_start_for_test(
            a.ei.clone(),
            a.ei.begin(Role::Initiator).unwrap(),
            &vector("START"),
            bootstrap(&decoded("START"), true),
            None,
        )
        .unwrap();
        i.start().unwrap();
        assert_eq!(
            i.receive_cancel(&early(protocol::Role::Responder)),
            Err(CeremonyError::InvalidState)
        );
        assert!(i.admission.terminal && i.receive_accept(&vector("ACCEPT")).is_err());
        assert_eq!(a.ei.status().unwrap(), Status::Ready { remaining: 10 });
        drop(i);

        // A. R after START/ACCEPT, before any peer key: terminal, R spends nothing.
        let (mut r, _) = RemoteCeremony::responder(
            a.er.clone(),
            a.er.begin(Role::Responder).unwrap(),
            &vector("START"),
            bootstrap(&decoded("ACCEPT"), false),
            None,
        )
        .unwrap();
        assert_eq!(
            r.receive_cancel(&early(protocol::Role::Initiator)),
            Err(CeremonyError::InvalidState)
        );
        assert!(r.admission.terminal);
        assert!(r.receive_initiator_key(&vector("INITIATOR_KEY")).is_err());
        assert_eq!(a.er.status().unwrap(), Status::Ready { remaining: 10 });
        drop(r);

        // B. I exposed INITIATOR_KEY (opportunity consumed); R did DH but has not exposed.
        let start = vector("START");
        let mut i = RemoteCeremony::initiator_with_fixed_start_for_test(
            a.ei.clone(),
            a.ei.begin(Role::Initiator).unwrap(),
            &start,
            bootstrap(&decoded("START"), true),
            None,
        )
        .unwrap();
        i.start().unwrap();
        let (mut r, accept) = RemoteCeremony::responder(
            a.er.clone(),
            a.er.begin(Role::Responder).unwrap(),
            &start,
            bootstrap(&decoded("ACCEPT"), false),
            None,
        )
        .unwrap();
        i.receive_accept(&accept).unwrap();
        i.authorize(&a.i).unwrap();
        let ikey = i.expose_key().unwrap();
        assert_eq!(a.ei.status().unwrap(), Status::Busy);
        r.receive_initiator_key(&ikey).unwrap();
        // R holds a DH result but no transcript identity: still pre-SAS, nothing spent.
        assert_eq!(
            r.receive_cancel(&early(protocol::Role::Initiator)),
            Err(CeremonyError::InvalidState)
        );
        assert!(r.admission.terminal && r.authorize(&a.r).is_err() && r.expose_key().is_err());
        assert_eq!(a.er.status().unwrap(), Status::Ready { remaining: 10 });
        // I awaiting RESPONDER_KEY: terminal; its consumed opportunity stays consumed.
        assert_eq!(
            i.receive_cancel(&early(protocol::Role::Responder)),
            Err(CeremonyError::InvalidState)
        );
        assert!(i.admission.terminal && i.presentation().is_none());
        assert!(i.receive_responder_key(&vector("RESPONDER_KEY")).is_err());
        assert_eq!(a.ei.status().unwrap(), Status::Ready { remaining: 9 });

        assert_eq!(
            crypto::mac_operations(),
            ops,
            "no MAC work without a shared SAS"
        );
        drop((i, r));
        a.release();
    }

    #[test]
    fn duplicate_or_later_cancel_after_terminal_changes_nothing() {
        let a = Authorities::new("cancel-after-terminal");
        let mut pair = establish(&a);
        let id = pair.identity();
        let cancel = emitted_cancel(pair.i.cancel_sas(&id));
        pair.r.receive_cancel(&cancel).unwrap();
        assert_failed(&mut pair.r, &a.er, &id);
        let (rid, sender, _, mac) = cancel_parts(&cancel);
        let changed = cancel_wire(rid, sender, CancelReason::Timeout, mac);
        let ops = crypto::mac_operations();
        for later in [&cancel, &changed] {
            for run in [&mut pair.r, &mut pair.i] {
                assert_eq!(run.receive_cancel(later), Err(CeremonyError::InvalidState));
                assert!(matches!(run.state, State::Terminal) && run.result().is_none());
            }
        }
        assert_eq!(
            crypto::mac_operations(),
            ops,
            "no repeated MAC verification"
        );
        assert_failed(&mut pair.r, &a.er, &id);
        assert_failed(&mut pair.i, &a.ei, &id);

        // Nothing is released twice: a new ceremony's guard survives old-run input.
        let mut next = establish(&a);
        assert_eq!(
            (a.ei.status().unwrap(), a.er.status().unwrap()),
            (Status::Busy, Status::Busy)
        );
        assert!(pair.r.receive_cancel(&cancel).is_err());
        assert!(pair.i.receive_cancel(&cancel).is_err());
        assert_eq!(
            (a.ei.status().unwrap(), a.er.status().unwrap()),
            (Status::Busy, Status::Busy)
        );
        assert!(next.i.is_awaiting_approval() && next.r.is_awaiting_approval());
        let next_id = next.identity();
        emitted_cancel(next.i.cancel_sas(&next_id));
        drop((pair, next));
        a.release();
    }

    #[test]
    fn cancel_while_the_final_ack_send_is_pending_never_yields_a_result() {
        // Peer CANCEL arrives at I after it produced, but before it confirmed, the final ACK.
        let a = Authorities::new("cancel-pending-peer");
        let (mut pair, id) = approvals_authenticated(&a);
        let i_finish = finish(&mut pair.i);
        let r_ack = responder_ack(&mut pair.r, &i_finish);
        let i_ack = initiator_ack(&mut pair.i, &r_ack);
        assert_final_ack_pending(&pair.i, &a.ei, &i_ack);
        let cancel = emitted_cancel(pair.r.cancel_sas(&id));
        assert_failed(&mut pair.r, &a.er, &id);
        assert_eq!(
            pair.i.receive_cancel(&cancel).map(|c| c.reason()),
            Ok(CancelReason::UserCancellation)
        );
        assert_failed(&mut pair.i, &a.ei, &id);
        // The pending final ACK is gone and cannot win afterwards.
        assert_eq!(
            pair.i.confirm_initiator_finish_ack_sent(&i_ack),
            Err(CeremonyError::NoPendingFinalAck)
        );
        assert!(pair.i.receive_completion(&r_ack).is_err());
        assert_eq!((pair.i.result(), pair.r.result()), (None, None));
        assert_failed(&mut pair.i, &a.ei, &id);
        assert_eq!((remaining(&a.ei), remaining(&a.er)), (9, 9));
        drop(pair);
        a.release();

        // Local CANCEL at I in the same window; R then receives the CANCEL, not the ACK.
        let a = Authorities::new("cancel-pending-local");
        let (mut pair, id) = approvals_authenticated(&a);
        let i_finish = finish(&mut pair.i);
        let r_ack = responder_ack(&mut pair.r, &i_finish);
        let i_ack = initiator_ack(&mut pair.i, &r_ack);
        let cancel = emitted_cancel(pair.i.cancel_sas(&id));
        assert_failed(&mut pair.i, &a.ei, &id);
        assert_eq!(
            pair.i.confirm_initiator_finish_ack_sent(&i_ack),
            Err(CeremonyError::NoPendingFinalAck)
        );
        assert_eq!(pair.i.result(), None);
        assert!(pair.r.receive_cancel(&cancel).is_ok());
        assert_failed(&mut pair.r, &a.er, &id);
        assert!(pair.r.receive_completion(&i_ack).is_err());
        assert_eq!(pair.r.result(), None);
        drop(pair);
        a.release();
    }

    #[test]
    fn cancel_after_local_success_changes_nothing() {
        let a = Authorities::new("cancel-after-success");
        let (mut pair, id) = approvals_authenticated(&a);
        let i_finish = finish(&mut pair.i);
        let r_ack = responder_ack(&mut pair.r, &i_finish);
        let i_ack = initiator_ack(&mut pair.i, &r_ack);
        // Genuine CANCELs built (not sent, not ending either run) while both were still live.
        let i_cancel = own_cancel(pair.i.session().unwrap(), CancelReason::Timeout).unwrap();
        let r_cancel = own_cancel(pair.r.session().unwrap(), CancelReason::Timeout).unwrap();
        confirm_sent(&mut pair.i, &i_ack);
        assert_eq!(
            pair.r.receive_completion(&i_ack),
            Ok(CompletionReceipt::Succeeded)
        );
        for (run, executor, cancel) in [
            (&mut pair.i, &a.ei, &r_cancel),
            (&mut pair.r, &a.er, &i_cancel),
        ] {
            let result = run.result().cloned().unwrap();
            let ops = crypto::mac_operations();
            assert_eq!(run.receive_cancel(cancel), Err(CeremonyError::Completed));
            assert_eq!(
                run.receive_cancel(b"not a frame"),
                Err(CeremonyError::Completed)
            );
            // No live session: a stale local reject/cancel builds no CANCEL.
            assert_eq!(run.cancel_sas(&id), Err(CeremonyError::NoLiveSas));
            assert_eq!(run.reject_sas(&id), Err(CeremonyError::NoLiveSas));
            assert_eq!(
                run.cancel_locally(&id, CancelReason::Timeout),
                Err(CeremonyError::NoLiveSas)
            );
            assert_eq!(crypto::mac_operations(), ops);
            assert_eq!(run.result(), Some(&result));
            assert_succeeded(run, executor, &id);
        }
        drop(pair);
        a.release();
    }

    #[test]
    fn failed_cancel_construction_still_terminates_without_output() {
        for pending_final_ack in [false, true] {
            let a = Authorities::new(&format!("cancel-construction-failure-{pending_final_ack}"));
            let (mut pair, id) = approvals_authenticated(&a);
            let pending = pending_final_ack.then(|| {
                let f = finish(&mut pair.i);
                let ack = responder_ack(&mut pair.r, &f);
                initiator_ack(&mut pair.i, &ack)
            });
            crypto::fail_next_cancel_construction();
            let ops = crypto::mac_operations();
            assert_eq!(pair.i.cancel_sas(&id), Ok(LocalCancellation::NotEmitted));
            assert_eq!(crypto::mac_operations(), ops, "no tag was ever computed");
            // Terminal exactly as if the CANCEL had been built: nothing to send, no result.
            assert!(matches!(pair.i.state, State::Terminal) && pair.i.result().is_none());
            assert_stale(&mut pair.i, &id);
            assert!(pair.i.admission.terminal);
            if let Some(ack) = pending {
                assert_eq!(
                    pair.i.confirm_initiator_finish_ack_sent(&ack),
                    Err(CeremonyError::NoPendingFinalAck)
                );
            }
            assert_eq!(a.ei.status().unwrap(), Status::Ready { remaining: 9 });
            // With no notification, the peer simply remains live on its own.
            assert!(pair.r.session().is_some());
            assert_eq!(a.er.status().unwrap(), Status::Busy);
            emitted_cancel(pair.r.reject_sas(&id));
            assert_eq!(a.er.status().unwrap(), Status::Ready { remaining: 9 });
            drop(pair);
            a.release();
        }
    }

    #[test]
    fn uncertain_guard_release_withholds_local_cancel_and_fails_closed() {
        let a = Authorities::new("cancel-uncertain-local");
        let (mut pair, id) = approvals_authenticated(&a);
        let i_finish = finish(&mut pair.i);
        let r_ack = responder_ack(&mut pair.r, &i_finish);
        let i_ack = initiator_ack(&mut pair.i, &r_ack);
        poison(&a.ei);
        let ops = crypto::mac_operations();
        // The CANCEL is built while the session exists, then withheld: an uncertain cleanup
        // return releases no wire output.
        assert_eq!(
            pair.i.cancel_sas(&id),
            Err(CeremonyError::Owner(OwnerError::OwnershipUncertain))
        );
        assert_eq!(crypto::mac_operations(), ops + 1);
        assert!(matches!(pair.i.state, State::Terminal) && pair.i.result().is_none());
        assert_stale(&mut pair.i, &id);
        assert_eq!(
            pair.i.confirm_initiator_finish_ack_sent(&i_ack),
            Err(CeremonyError::NoPendingFinalAck)
        );
        assert_eq!(pair.i.result(), None);
        assert_guard_held_uncertainly(&a.ei);
        drop(pair);
        a.release();
    }

    #[test]
    fn uncertain_guard_release_after_a_verified_peer_cancel_fails_closed() {
        let a = Authorities::new("cancel-uncertain-peer");
        let mut pair = establish(&a);
        let id = pair.identity();
        let cancel = emitted_cancel(pair.r.cancel_sas(&id));
        poison(&a.ei);
        assert_eq!(
            pair.i.receive_cancel(&cancel),
            Err(CeremonyError::Owner(OwnerError::OwnershipUncertain))
        );
        assert!(matches!(pair.i.state, State::Terminal) && pair.i.result().is_none());
        assert_stale(&mut pair.i, &id);
        assert!(pair.i.receive_cancel(&cancel).is_err());
        assert_guard_held_uncertainly(&a.ei);
        drop(pair);
        a.release();
    }

    // P3 11.3 ceremony deadlines. Every clock is hand-advanced; no test sleeps.

    const NS: Duration = Duration::from_nanos(1);

    fn secs(value: u64) -> Duration {
        Duration::from_secs(value)
    }

    /// `establish` with one hand-advanced clock per endpoint, both starting at zero.
    fn establish_timed(a: &Authorities) -> (Pair, Arc<ManualClock>, Arc<ManualClock>) {
        let (ci, cr) = (ManualClock::new(), ManualClock::new());
        (establish_with(a, ci.clone(), cr.clone()), ci, cr)
    }

    /// Both approvals authenticated at clock zero on each side.
    fn approvals_timed(a: &Authorities) -> (Pair, [u8; 32], Arc<ManualClock>, Arc<ManualClock>) {
        let (mut pair, ci, cr) = establish_timed(a);
        let id = pair.identity();
        authenticate(&mut pair, &id);
        (pair, id, ci, cr)
    }

    /// A started Initiator awaiting ACCEPT, created at the clock's current value.
    fn timed_initiator(a: &Authorities, clock: &Arc<ManualClock>) -> RemoteCeremony {
        let mut run = RemoteCeremony::initiator_with_fixed_start_and_clock_for_test(
            clock.clone(),
            a.ei.clone(),
            a.ei.begin(Role::Initiator).unwrap(),
            &vector("START"),
            bootstrap(&decoded("START"), true),
            None,
        )
        .unwrap();
        run.start().unwrap();
        run
    }

    /// A Responder that accepted the vector START at the clock's current value.
    fn timed_responder(a: &Authorities, clock: &Arc<ManualClock>) -> RemoteCeremony {
        refill_start_limiters(a);
        RemoteCeremony::responder_with_clock(
            clock.clone(),
            a.er.clone(),
            a.er.begin(Role::Responder).unwrap(),
            &vector("START"),
            bootstrap(&decoded("ACCEPT"), false),
            None,
        )
        .unwrap()
        .0
    }

    fn active(run: &mut RemoteCeremony) {
        assert_eq!(run.poll_deadlines(), Ok(DeadlineOutcome::Active));
    }

    /// The poll found `expired`; the run is already terminal. Returns any CANCEL bytes.
    fn timed_out(
        outcome: Result<DeadlineOutcome, CeremonyError>,
        expired: Deadline,
    ) -> Option<Vec<u8>> {
        match outcome {
            Ok(DeadlineOutcome::TimedOut(timeout)) => {
                assert_eq!(timeout.expired(), expired);
                timeout.cancel().map(<[u8]>::to_vec)
            }
            other => panic!("expected a {expired:?} timeout, got {other:?}"),
        }
    }

    /// An operation met an expired deadline: its input was not applied and the run is
    /// already terminal. Returns any CANCEL bytes.
    fn refused_by_timeout<T: std::fmt::Debug>(
        result: Result<T, CeremonyError>,
        expired: Deadline,
    ) -> Option<Vec<u8>> {
        match result {
            Err(CeremonyError::TimedOut(timeout)) => {
                assert_eq!(timeout.expired(), expired);
                timeout.cancel().map(<[u8]>::to_vec)
            }
            other => panic!("expected a {expired:?} timeout, got {other:?}"),
        }
    }

    /// The exact frozen authenticated CANCEL with reason `0x03` timeout from `sender`.
    fn assert_timeout_cancel(cancel: &[u8], sender: protocol::Role) {
        assert_eq!(cancel[9], 0x09);
        let (request_id, from, reason, _) = cancel_parts(cancel);
        assert_eq!(
            (request_id, from, reason),
            (vector_request_id(), sender, CancelReason::Timeout)
        );
    }

    /// The peer verifies the CANCEL as authenticated timeout cancellation and fails too.
    fn deliver_timeout(
        peer: &mut RemoteCeremony,
        executor: &CeremonyExecutor,
        cancel: &[u8],
        id: &[u8; 32],
    ) {
        assert_eq!(
            peer.receive_cancel(cancel).map(|c| c.reason()),
            Ok(CancelReason::Timeout)
        );
        assert_failed(peer, executor, id);
    }

    /// Pre-SAS timeout: terminal, no result or SAS, guard released, `remaining` kept.
    fn assert_failed_pre_sas(run: &RemoteCeremony, executor: &CeremonyExecutor, remaining: u8) {
        assert!(matches!(run.state, State::Terminal) && run.result().is_none());
        assert!(run.session().is_none() && run.presentation().is_none());
        assert!(run.admission.terminal);
        assert_eq!(executor.status().unwrap(), Status::Ready { remaining });
    }

    fn state_name(state: &State) -> String {
        let name = match state {
            State::InitiatorCreated { .. } => "InitiatorCreated",
            State::InitiatorAwaitAccept { .. } => "InitiatorAwaitAccept",
            State::InitiatorAwaitAuthorization { .. } => "InitiatorAwaitAuthorization",
            State::InitiatorAwaitResponderKey { .. } => "InitiatorAwaitResponderKey",
            State::ResponderAcceptSentAwaitInitiatorKey { .. } => {
                "ResponderAcceptSentAwaitInitiatorKey"
            }
            State::ResponderAwaitAuthorization { .. } => "ResponderAwaitAuthorization",
            State::AwaitLocalApproval { .. } => "AwaitLocalApproval",
            State::LocallyApprovedAwaitingAuthentication { .. } => {
                "LocallyApprovedAwaitingAuthentication"
            }
            State::LocalMacSentAwaitingPeerMac { .. } => "LocalMacSentAwaitingPeerMac",
            State::ApprovalsAuthenticatedAwaitingCompletion { .. } => {
                "ApprovalsAuthenticatedAwaitingCompletion"
            }
            State::AwaitResponderFinish { .. } => "AwaitResponderFinish",
            State::AwaitInitiatorFinishAck { .. } => "AwaitInitiatorFinishAck",
            State::AwaitInitiatorFinishAckSend { .. } => "AwaitInitiatorFinishAckSend",
            State::Succeeded(_) => "Succeeded",
            State::Terminal => "Terminal",
        };
        let detail = match state {
            State::InitiatorAwaitAuthorization {
                authorization: Some(_),
                ..
            }
            | State::ResponderAwaitAuthorization {
                authorization: Some(_),
                ..
            } => "+authorized",
            State::AwaitLocalApproval {
                peer: PeerMac::Verified,
                ..
            }
            | State::LocallyApprovedAwaitingAuthentication {
                peer: PeerMac::Verified,
                ..
            } => "+peer-mac",
            _ => "",
        };
        format!("{name}{detail}")
    }

    #[test]
    fn every_state_has_its_intended_inactivity_mode() {
        use Inactivity::{Running, Suspended};
        let a = Authorities::new("deadline-state-table");
        let mut table = Vec::new();
        let mut note = |run: &RemoteCeremony| {
            table.push((state_name(&run.state), run.state.inactivity()));
        };
        let start = vector("START");
        let mut i = RemoteCeremony::initiator_with_fixed_start_for_test(
            a.ei.clone(),
            a.ei.begin(Role::Initiator).unwrap(),
            &start,
            bootstrap(&decoded("START"), true),
            None,
        )
        .unwrap();
        note(&i);
        i.start().unwrap();
        note(&i);
        let (mut r, accept) = RemoteCeremony::responder(
            a.er.clone(),
            a.er.begin(Role::Responder).unwrap(),
            &start,
            bootstrap(&decoded("ACCEPT"), false),
            None,
        )
        .unwrap();
        note(&r);
        i.receive_accept(&accept).unwrap();
        note(&i);
        i.authorize(&a.i).unwrap();
        note(&i);
        let ikey = i.expose_key().unwrap();
        note(&i);
        r.receive_initiator_key(&ikey).unwrap();
        note(&r);
        r.authorize(&a.r).unwrap();
        note(&r);
        let rkey = r.expose_key().unwrap();
        note(&r);
        i.receive_responder_key(&rkey).unwrap();
        let id = *i.presentation().unwrap().ceremony_identity();
        r.approve_sas(&id).unwrap();
        note(&r);
        let r_mac = emitted(&mut r);
        note(&r);
        i.receive_bootstrap_mac(&r_mac).unwrap();
        note(&i);
        i.approve_sas(&id).unwrap();
        note(&i);
        let i_mac = emitted(&mut i);
        note(&i);
        r.receive_bootstrap_mac(&i_mac).unwrap();
        let i_finish = finish(&mut i);
        note(&i);
        let r_ack = responder_ack(&mut r, &i_finish);
        note(&r);
        let i_ack = initiator_ack(&mut i, &r_ack);
        note(&i);
        confirm_sent(&mut i, &i_ack);
        note(&i);
        r.receive_completion(&i_ack).unwrap();
        let mut failed = establish(&a);
        failed.i.terminate().unwrap();
        note(&failed.i);
        assert_eq!(
            table,
            [
                ("InitiatorCreated", Some(Running)),
                ("InitiatorAwaitAccept", Some(Running)),
                ("ResponderAcceptSentAwaitInitiatorKey", Some(Running)),
                ("InitiatorAwaitAuthorization", Some(Running)),
                ("InitiatorAwaitAuthorization+authorized", Some(Running)),
                ("InitiatorAwaitResponderKey", Some(Running)),
                ("ResponderAwaitAuthorization", Some(Running)),
                ("ResponderAwaitAuthorization+authorized", Some(Running)),
                // Complete SAS displayed, awaiting a deliberate human decision.
                ("AwaitLocalApproval", Some(Suspended)),
                ("LocallyApprovedAwaitingAuthentication", Some(Running)),
                ("LocalMacSentAwaitingPeerMac", Some(Running)),
                // The peer's approval MAC does not end the human wait.
                ("AwaitLocalApproval+peer-mac", Some(Suspended)),
                (
                    "LocallyApprovedAwaitingAuthentication+peer-mac",
                    Some(Running)
                ),
                ("ApprovalsAuthenticatedAwaitingCompletion", Some(Running)),
                ("AwaitResponderFinish", Some(Running)),
                ("AwaitInitiatorFinishAck", Some(Running)),
                ("AwaitInitiatorFinishAckSend", Some(Running)),
                ("Succeeded", None),
                ("Terminal", None),
            ]
            .map(|(name, mode)| (name.to_string(), mode))
        );
        drop((i, r, failed));
        a.release();
    }

    #[test]
    fn absolute_deadline_starts_at_creation_and_no_transition_refreshes_it() {
        let a = Authorities::new("deadline-absolute-start");
        let (ci, cr) = (ManualClock::new(), ManualClock::new());
        // Clock values before each run's start point never count against it.
        ci.set(secs(1_000));
        cr.set(secs(5_000));
        let start = vector("START");
        let mut i = RemoteCeremony::initiator_with_fixed_start_and_clock_for_test(
            ci.clone(),
            a.ei.clone(),
            a.ei.begin(Role::Initiator).unwrap(),
            &start,
            bootstrap(&decoded("START"), true),
            None,
        )
        .unwrap(); // I absolute: 1_000 + 300.
        ci.advance(secs(50));
        i.start().unwrap();
        cr.advance(secs(20));
        let (mut r, accept) = RemoteCeremony::responder_with_clock(
            cr.clone(),
            a.er.clone(),
            a.er.begin(Role::Responder).unwrap(),
            &start,
            bootstrap(&decoded("ACCEPT"), false),
            None,
        )
        .unwrap(); // R absolute: START accepted at 5_020, + 300.
        ci.advance(secs(50));
        i.receive_accept(&accept).unwrap();
        i.receive_accept(&accept).unwrap();
        ci.advance(secs(50));
        i.authorize(&a.i).unwrap();
        ci.advance(secs(50));
        let ikey = i.expose_key().unwrap();
        // R must cross exposure within its fixed 60-second pending resource lifetime.
        cr.advance(secs(20));
        r.receive_initiator_key(&ikey).unwrap();
        cr.advance(secs(20));
        r.authorize(&a.r).unwrap();
        cr.advance(secs(15));
        let rkey = r.expose_key().unwrap(); // Exposed at 5_075.
        ci.advance(secs(50));
        i.receive_responder_key(&rkey).unwrap();
        let id = pair_identity(&i);
        ci.advance(secs(40));
        let i_mac = approve_and_emit(&mut i, &id);
        cr.advance(secs(225));
        let r_mac = approve_and_emit(&mut r, &id);
        ci.advance(secs(5));
        i.receive_bootstrap_mac(&r_mac).unwrap();
        cr.advance(secs(10));
        r.receive_bootstrap_mac(&i_mac).unwrap();

        // I made progress five seconds ago, so only the absolute deadline can expire.
        ci.advance(secs(5) - NS);
        active(&mut i);
        assert!(i.is_ready_for_completion());
        ci.advance(NS);
        let cancel = timed_out(i.poll_deadlines(), Deadline::Absolute).unwrap();
        assert_timeout_cancel(&cancel, protocol::Role::Initiator);
        assert_failed(&mut i, &a.ei, &id);

        // R's deadline counts from START acceptance at 5_020, not from its clock's earlier
        // values (which would already have expired at 5_300) and not from any later step.
        cr.advance(secs(10) - NS);
        active(&mut r);
        cr.advance(NS);
        let cancel = timed_out(r.poll_deadlines(), Deadline::Absolute).unwrap();
        assert_timeout_cancel(&cancel, protocol::Role::Responder);
        assert_failed(&mut r, &a.er, &id);
        drop((i, r));
        a.release();
    }

    fn pair_identity(run: &RemoteCeremony) -> [u8; 32] {
        *run.presentation().unwrap().ceremony_identity()
    }

    #[test]
    fn absolute_timeout_during_human_comparison_emits_an_authenticated_timeout_cancel() {
        let a = Authorities::new("deadline-absolute-sas");
        let (mut pair, ci, _cr) = establish_timed(&a);
        let id = pair.identity();
        ci.advance(ABSOLUTE_DEADLINE - NS);
        active(&mut pair.i);
        assert!(pair.i.is_awaiting_approval() && pair.i.presentation().is_some());
        ci.advance(NS);
        // Withdrawn read-only even before the poll makes the run terminal.
        assert_eq!(pair.i.presentation(), None);
        let ops = crypto::mac_operations();
        let cancel = timed_out(pair.i.poll_deadlines(), Deadline::Absolute).unwrap();
        assert_eq!(crypto::mac_operations(), ops + 1, "one calculate_mac");
        assert_timeout_cancel(&cancel, protocol::Role::Initiator);
        // Terminal before any delivery: no result, SAS, session, or callbacks; guard
        // released; the consumed opportunity kept.
        assert_failed(&mut pair.i, &a.ei, &id);
        assert!(pair.i.admission.authorization.is_none());
        assert_eq!(pair.i.poll_deadlines(), Ok(DeadlineOutcome::Finished));
        // The peer authenticates it as timeout cancellation.
        assert!(pair.r.is_awaiting_approval());
        deliver_timeout(&mut pair.r, &a.er, &cancel, &id);
        assert_eq!((remaining(&a.ei), remaining(&a.er)), (9, 9));
        drop(pair);
        a.release();
    }

    #[test]
    fn inactivity_is_suspended_during_human_comparison_and_restarts_at_approval() {
        let a = Authorities::new("deadline-human-wait");
        let (mut pair, ci, _cr) = establish_timed(&a);
        let id = pair.identity();
        for wait in [INACTIVITY_DEADLINE, secs(120)] {
            ci.advance(wait);
            active(&mut pair.i);
            assert!(pair.i.presentation().is_some());
        }
        // Three minutes of human wait cost nothing: approval opens a full fresh window.
        assert_eq!(pair.i.approve_sas(&id), Ok(SasApproval::Recorded));
        ci.advance(INACTIVITY_DEADLINE - NS);
        active(&mut pair.i);
        ci.advance(NS);
        let cancel = timed_out(pair.i.poll_deadlines(), Deadline::Inactivity).unwrap();
        assert_timeout_cancel(&cancel, protocol::Role::Initiator);
        assert_failed(&mut pair.i, &a.ei, &id);
        deliver_timeout(&mut pair.r, &a.er, &cancel, &id);
        drop(pair);
        a.release();
    }

    #[test]
    fn absolute_deadline_wins_over_a_fresh_inactivity_window() {
        let a = Authorities::new("deadline-absolute-first");
        let (mut pair, ci, _cr) = establish_timed(&a);
        let id = pair.identity();
        ci.advance(secs(290));
        assert_eq!(pair.i.approve_sas(&id), Ok(SasApproval::Recorded));
        // The nominal window would end at 350; the absolute deadline ends the run at 300.
        ci.advance(secs(10) - NS);
        active(&mut pair.i);
        ci.advance(NS);
        let cancel = timed_out(pair.i.poll_deadlines(), Deadline::Absolute).unwrap();
        assert_timeout_cancel(&cancel, protocol::Role::Initiator);
        assert_failed(&mut pair.i, &a.ei, &id);
        drop(pair);
        a.release();
    }

    #[test]
    fn peer_mac_before_local_approval_keeps_inactivity_suspended() {
        let a = Authorities::new("deadline-peer-mac-first");
        let (mut pair, ci, _cr) = establish_timed(&a);
        let id = pair.identity();
        let r_mac = approve_and_emit(&mut pair.r, &id);
        ci.advance(secs(10));
        assert_eq!(
            pair.i.receive_bootstrap_mac(&r_mac),
            Ok(PeerApproval::Authenticated)
        );
        assert!(pair.i.is_awaiting_approval() && pair.i.is_peer_approval_authenticated());
        // 180 seconds after the peer MAC, the SAS is still displayed and the run live.
        for wait in [INACTIVITY_DEADLINE, secs(120)] {
            ci.advance(wait);
            active(&mut pair.i);
            assert!(pair.i.presentation().is_some());
        }
        // Approval at 190 restarts the window there, not at the peer MAC time (10).
        assert_eq!(pair.i.approve_sas(&id), Ok(SasApproval::Recorded));
        ci.advance(INACTIVITY_DEADLINE - NS);
        active(&mut pair.i);
        ci.advance(NS);
        let cancel = timed_out(pair.i.poll_deadlines(), Deadline::Inactivity).unwrap();
        assert_timeout_cancel(&cancel, protocol::Role::Initiator);
        assert_failed(&mut pair.i, &a.ei, &id);
        // R awaits I's approval MAC; it authenticates I's timeout instead.
        deliver_timeout(&mut pair.r, &a.er, &cancel, &id);
        drop(pair);

        a.release();

        // The same human wait still ends at the absolute deadline.
        let a = Authorities::new("deadline-peer-mac-first-absolute");
        let (mut pair, ci, _cr) = establish_timed(&a);
        let id = pair.identity();
        let r_mac = approve_and_emit(&mut pair.r, &id);
        ci.advance(secs(10));
        pair.i.receive_bootstrap_mac(&r_mac).unwrap();
        ci.advance(ABSOLUTE_DEADLINE - secs(10) - NS);
        active(&mut pair.i);
        ci.advance(NS);
        let cancel = timed_out(pair.i.poll_deadlines(), Deadline::Absolute).unwrap();
        assert_failed(&mut pair.i, &a.ei, &id);
        deliver_timeout(&mut pair.r, &a.er, &cancel, &id);
        drop(pair);
        a.release();
    }

    #[test]
    fn valid_progress_refreshes_inactivity_but_polling_does_not() {
        let a = Authorities::new("deadline-progress");
        let ci = ManualClock::new();
        let mut i = timed_initiator(&a, &ci);
        ci.advance(secs(59));
        active(&mut i);
        i.receive_accept(&vector("ACCEPT")).unwrap();
        assert!(matches!(i.state, State::InitiatorAwaitAuthorization { .. }));
        ci.advance(secs(59));
        active(&mut i);
        ci.advance(secs(1));
        // Pre-SAS: local terminal failure, no authenticated CANCEL, nothing spent.
        assert_eq!(timed_out(i.poll_deadlines(), Deadline::Inactivity), None);
        assert_failed_pre_sas(&i, &a.ei, 10);
        drop(i);
        a.release();
    }

    #[test]
    fn exact_duplicates_do_not_refresh_inactivity() {
        let a = Authorities::new("deadline-duplicate");
        let ci = ManualClock::new();
        let mut i = timed_initiator(&a, &ci);
        i.receive_accept(&vector("ACCEPT")).unwrap();
        let seen = i.seen.len();
        ci.advance(secs(59));
        assert_eq!(i.receive_accept(&vector("ACCEPT")), Ok(()));
        assert_eq!(i.seen.len(), seen);
        ci.advance(secs(1));
        assert_eq!(timed_out(i.poll_deadlines(), Deadline::Inactivity), None);
        assert_failed_pre_sas(&i, &a.ei, 10);
        drop(i);

        // Post-SAS: an exact duplicate peer BOOTSTRAP_MAC is ignored without MAC work.
        let (mut pair, ci, _cr) = establish_timed(&a);
        let id = pair.identity();
        let r_mac = approve_and_emit(&mut pair.r, &id);
        approve_and_emit(&mut pair.i, &id);
        pair.i.receive_bootstrap_mac(&r_mac).unwrap();
        let (ops, seen) = (crypto::mac_operations(), pair.i.seen.len());
        ci.advance(secs(59));
        assert_eq!(
            pair.i.receive_bootstrap_mac(&r_mac),
            Ok(PeerApproval::AlreadyAuthenticated)
        );
        assert_eq!((crypto::mac_operations(), pair.i.seen.len()), (ops, seen));
        ci.advance(secs(1));
        let cancel = timed_out(pair.i.poll_deadlines(), Deadline::Inactivity).unwrap();
        assert_failed(&mut pair.i, &a.ei, &id);
        deliver_timeout(&mut pair.r, &a.er, &cancel, &id);
        drop(pair);
        a.release();
    }

    #[test]
    fn stale_callbacks_neither_refresh_nor_terminate() {
        let a = Authorities::new("deadline-stale-callback");
        let (mut pair, ci, _cr) = establish_timed(&a);
        let id = pair.identity();
        pair.i.approve_sas(&id).unwrap();
        let mut stale = id;
        stale[0] ^= 1;
        ci.advance(secs(59));
        let mismatch = CeremonyError::CeremonyIdentityMismatch;
        assert_eq!(pair.i.approve_sas(&stale), Err(mismatch.clone()));
        assert_eq!(pair.i.reject_sas(&stale), Err(mismatch.clone()));
        assert_eq!(pair.i.cancel_sas(&stale), Err(mismatch));
        // Rejected without effect: still live and locally approved, guard held.
        active(&mut pair.i);
        assert!(pair.i.is_locally_approved());
        assert_eq!(a.ei.status().unwrap(), Status::Busy);
        ci.advance(secs(1));
        let cancel = timed_out(pair.i.poll_deadlines(), Deadline::Inactivity).unwrap();
        assert_failed(&mut pair.i, &a.ei, &id);
        deliver_timeout(&mut pair.r, &a.er, &cancel, &id);
        drop(pair);
        a.release();
    }

    #[test]
    fn idempotent_local_repeats_do_not_refresh_inactivity() {
        let a = Authorities::new("deadline-idempotent");
        let (mut pair, ci, _cr) = establish_timed(&a);
        let id = pair.identity();
        approve_and_emit(&mut pair.i, &id);
        ci.advance(secs(59));
        let ops = crypto::mac_operations();
        assert_eq!(pair.i.approve_sas(&id), Ok(SasApproval::AlreadyRecorded));
        assert_eq!(
            pair.i.emit_bootstrap_mac(),
            Ok(BootstrapMacEmission::AlreadyEmitted)
        );
        assert_eq!(
            pair.i.emit_initiator_finish(),
            Err(CeremonyError::ApprovalsNotAuthenticated)
        );
        assert_eq!(crypto::mac_operations(), ops);
        ci.advance(secs(1));
        let cancel = timed_out(pair.i.poll_deadlines(), Deadline::Inactivity).unwrap();
        assert_failed(&mut pair.i, &a.ei, &id);
        deliver_timeout(&mut pair.r, &a.er, &cancel, &id);
        drop(pair);

        a.release();

        // A repeated INITIATOR_FINISH request is `AlreadyEmitted` and buys no time either.
        let a = Authorities::new("deadline-idempotent-finish");
        let (mut pair, id, ci, _cr) = approvals_timed(&a);
        finish(&mut pair.i);
        ci.advance(secs(59));
        assert_eq!(
            pair.i.emit_initiator_finish(),
            Ok(FinishEmission::AlreadyEmitted)
        );
        ci.advance(secs(1));
        timed_out(pair.i.poll_deadlines(), Deadline::Inactivity).unwrap();
        assert_failed(&mut pair.i, &a.ei, &id);
        drop(pair);
        a.release();
    }

    #[test]
    fn an_expired_ceremony_cannot_be_rescued_by_valid_input() {
        let a = Authorities::new("deadline-no-rescue");
        let ci = ManualClock::new();
        let mut i = timed_initiator(&a, &ci);
        ci.advance(INACTIVITY_DEADLINE);
        // The valid ACCEPT arrives too late: expiry is checked before it is applied.
        assert_eq!(
            refused_by_timeout(i.receive_accept(&vector("ACCEPT")), Deadline::Inactivity),
            None
        );
        assert!(i.seen.is_empty());
        assert_failed_pre_sas(&i, &a.ei, 10);
        assert!(i.receive_accept(&vector("ACCEPT")).is_err());
        assert!(matches!(i.state, State::Terminal));
        drop(i);

        a.release();

        // APPROVE after the absolute deadline cannot rescue the displayed SAS.
        let a = Authorities::new("deadline-no-rescue-approve");
        let (mut pair, ci, _cr) = establish_timed(&a);
        let id = pair.identity();
        ci.advance(ABSOLUTE_DEADLINE);
        let cancel = refused_by_timeout(pair.i.approve_sas(&id), Deadline::Absolute).unwrap();
        assert_timeout_cancel(&cancel, protocol::Role::Initiator);
        assert_failed(&mut pair.i, &a.ei, &id);
        deliver_timeout(&mut pair.r, &a.er, &cancel, &id);
        drop(pair);

        a.release();

        // A late REJECT ends in the timeout, not the user-rejection reason.
        let a = Authorities::new("deadline-no-rescue-reject");
        let (mut pair, _ci, cr) = establish_timed(&a);
        let id = pair.identity();
        cr.advance(ABSOLUTE_DEADLINE);
        let cancel = refused_by_timeout(pair.r.reject_sas(&id), Deadline::Absolute).unwrap();
        assert_timeout_cancel(&cancel, protocol::Role::Responder);
        assert_failed(&mut pair.r, &a.er, &id);
        deliver_timeout(&mut pair.i, &a.ei, &cancel, &id);
        drop(pair);
        a.release();
    }

    #[test]
    fn pre_sas_timeouts_are_local_only_and_keep_exact_accounting() {
        let a = Authorities::new("deadline-pre-sas");
        let clock = ManualClock::new();

        // I authorized but not exposed: nothing spent, the authorization is dropped.
        let mut i = timed_initiator(&a, &clock);
        i.receive_accept(&vector("ACCEPT")).unwrap();
        i.authorize(&a.i).unwrap();
        clock.advance(INACTIVITY_DEADLINE);
        assert_eq!(timed_out(i.poll_deadlines(), Deadline::Inactivity), None);
        assert_failed_pre_sas(&i, &a.ei, 10);
        assert!(i.expose_key().is_err());
        assert_eq!(a.ei.status().unwrap(), Status::Ready { remaining: 10 });
        drop(i);

        // I exposed INITIATOR_KEY but no shared SAS exists: no CANCEL, opportunity kept.
        let mut i = timed_initiator(&a, &clock);
        i.receive_accept(&vector("ACCEPT")).unwrap();
        i.authorize(&a.i).unwrap();
        i.expose_key().unwrap();
        assert_eq!(a.ei.status().unwrap(), Status::Busy);
        clock.advance(INACTIVITY_DEADLINE);
        assert_eq!(timed_out(i.poll_deadlines(), Deadline::Inactivity), None);
        assert_failed_pre_sas(&i, &a.ei, 9);
        assert!(i.receive_responder_key(&vector("RESPONDER_KEY")).is_err());
        assert_failed_pre_sas(&i, &a.ei, 9);
        drop(i);

        // R before any exposure, awaiting INITIATOR_KEY: nothing spent.
        let mut r = timed_responder(&a, &clock);
        clock.advance(INACTIVITY_DEADLINE);
        assert_eq!(timed_out(r.poll_deadlines(), Deadline::Inactivity), None);
        assert_failed_pre_sas(&r, &a.er, 10);
        drop(r);

        // R after DH and authorization, before revealing R_pub: nothing spent.
        let mut r = timed_responder(&a, &clock);
        r.receive_initiator_key(&vector("INITIATOR_KEY")).unwrap();
        r.authorize(&a.r).unwrap();
        clock.advance(INACTIVITY_DEADLINE);
        assert_eq!(timed_out(r.poll_deadlines(), Deadline::Inactivity), None);
        assert_failed_pre_sas(&r, &a.er, 10);
        assert!(r.expose_key().is_err());
        assert_eq!(a.er.status().unwrap(), Status::Ready { remaining: 10 });
        drop(r);

        a.release();

        // R after exposure (shared SAS exists): authenticated CANCEL, no refund.
        let a = Authorities::new("deadline-post-exposure-r");
        let (mut pair, _ci, cr) = establish_timed(&a);
        let id = pair.identity();
        pair.r.approve_sas(&id).unwrap();
        cr.advance(INACTIVITY_DEADLINE);
        let cancel = timed_out(pair.r.poll_deadlines(), Deadline::Inactivity).unwrap();
        assert_timeout_cancel(&cancel, protocol::Role::Responder);
        assert_failed(&mut pair.r, &a.er, &id);
        assert!(pair.r.admission.authorization.is_none());
        deliver_timeout(&mut pair.i, &a.ei, &cancel, &id);
        assert_eq!((remaining(&a.ei), remaining(&a.er)), (9, 9));
        drop(pair);
        a.release();
    }

    #[test]
    fn timeout_while_awaiting_the_peer_bootstrap_mac_is_authenticated() {
        let a = Authorities::new("deadline-await-peer-mac");
        let (mut pair, ci, _cr) = establish_timed(&a);
        let id = pair.identity();
        approve_and_emit(&mut pair.i, &id);
        assert!(matches!(
            pair.i.state,
            State::LocalMacSentAwaitingPeerMac { .. }
        ));
        ci.advance(INACTIVITY_DEADLINE - NS);
        active(&mut pair.i);
        ci.advance(NS);
        let cancel = timed_out(pair.i.poll_deadlines(), Deadline::Inactivity).unwrap();
        assert_timeout_cancel(&cancel, protocol::Role::Initiator);
        assert_failed(&mut pair.i, &a.ei, &id);
        deliver_timeout(&mut pair.r, &a.er, &cancel, &id);
        assert_eq!((remaining(&a.ei), remaining(&a.er)), (9, 9));
        drop(pair);
        a.release();
    }

    #[test]
    fn timeout_while_awaiting_completion_is_authenticated() {
        let a = Authorities::new("deadline-await-finish");
        // I awaits RESPONDER_FINISH_ACK.
        let (mut pair, id, ci, _cr) = approvals_timed(&a);
        finish(&mut pair.i);
        ci.advance(INACTIVITY_DEADLINE);
        let cancel = timed_out(pair.i.poll_deadlines(), Deadline::Inactivity).unwrap();
        assert_timeout_cancel(&cancel, protocol::Role::Initiator);
        assert_failed(&mut pair.i, &a.ei, &id);
        deliver_timeout(&mut pair.r, &a.er, &cancel, &id);
        drop(pair);

        a.release();

        // R awaits INITIATOR_FINISH_ACK.
        let a = Authorities::new("deadline-await-final-ack");
        let (mut pair, id, _ci, cr) = approvals_timed(&a);
        let i_finish = finish(&mut pair.i);
        let r_ack = responder_ack(&mut pair.r, &i_finish);
        cr.advance(INACTIVITY_DEADLINE - NS);
        active(&mut pair.r);
        cr.advance(NS);
        let cancel = timed_out(pair.r.poll_deadlines(), Deadline::Inactivity).unwrap();
        assert_timeout_cancel(&cancel, protocol::Role::Responder);
        assert_failed(&mut pair.r, &a.er, &id);
        // I never sees the ACK it was waiting for, only the authenticated timeout.
        deliver_timeout(&mut pair.i, &a.ei, &cancel, &id);
        assert!(pair.i.receive_completion(&r_ack).is_err());
        assert_eq!((pair.i.result(), pair.r.result()), (None, None));
        assert_eq!((remaining(&a.ei), remaining(&a.er)), (9, 9));
        drop(pair);
        a.release();
    }

    #[test]
    fn pending_final_ack_times_out_without_a_result() {
        let a = Authorities::new("deadline-pending-final-ack");
        let (mut pair, id, ci, _cr) = approvals_timed(&a);
        let i_finish = finish(&mut pair.i);
        let r_ack = responder_ack(&mut pair.r, &i_finish);
        let i_ack = initiator_ack(&mut pair.i, &r_ack);
        assert_final_ack_pending(&pair.i, &a.ei, &i_ack);
        ci.advance(secs(59));
        // A mismatched confirmation and an exact duplicate ACK neither succeed nor buy time.
        let ops = crypto::mac_operations();
        assert_eq!(
            pair.i.confirm_initiator_finish_ack_sent(&r_ack),
            Err(CeremonyError::FinalAckMismatch)
        );
        assert_eq!(
            pair.i.receive_completion(&r_ack),
            Ok(CompletionReceipt::AlreadyAccepted)
        );
        assert_eq!(crypto::mac_operations(), ops);
        assert_final_ack_pending(&pair.i, &a.ei, &i_ack);
        ci.advance(secs(1));
        let cancel = timed_out(pair.i.poll_deadlines(), Deadline::Inactivity).unwrap();
        assert_timeout_cancel(&cancel, protocol::Role::Initiator);
        assert_failed(&mut pair.i, &a.ei, &id);
        // The pending final ACK is gone; the stale confirmation cannot win.
        assert_eq!(
            pair.i.confirm_initiator_finish_ack_sent(&i_ack),
            Err(CeremonyError::NoPendingFinalAck)
        );
        assert_eq!(pair.i.result(), None);
        deliver_timeout(&mut pair.r, &a.er, &cancel, &id);
        assert!(pair.r.receive_completion(&i_ack).is_err());
        assert_eq!((pair.i.result(), pair.r.result()), (None, None));
        assert_eq!((remaining(&a.ei), remaining(&a.er)), (9, 9));
        drop(pair);
        a.release();
    }

    #[test]
    fn final_ack_confirmation_after_absolute_expiry_is_refused() {
        let a = Authorities::new("deadline-confirm-after-expiry");
        let (mut pair, ci, _cr) = establish_timed(&a);
        let id = pair.identity();
        ci.advance(secs(250));
        authenticate(&mut pair, &id);
        let i_finish = finish(&mut pair.i);
        let r_ack = responder_ack(&mut pair.r, &i_finish);
        let i_ack = initiator_ack(&mut pair.i, &r_ack);
        // Inactivity would allow until 310; the absolute deadline ends the run at 300.
        ci.advance(secs(50));
        let cancel = refused_by_timeout(
            pair.i.confirm_initiator_finish_ack_sent(&i_ack),
            Deadline::Absolute,
        )
        .unwrap();
        assert_timeout_cancel(&cancel, protocol::Role::Initiator);
        assert_eq!(pair.i.result(), None);
        assert_failed(&mut pair.i, &a.ei, &id);
        assert_eq!(
            pair.i.confirm_initiator_finish_ack_sent(&i_ack),
            Err(CeremonyError::NoPendingFinalAck)
        );
        deliver_timeout(&mut pair.r, &a.er, &cancel, &id);
        assert_eq!((pair.i.result(), pair.r.result()), (None, None));
        drop(pair);
        a.release();
    }

    #[test]
    fn failed_timeout_cancel_construction_still_times_out_without_output() {
        let a = Authorities::new("deadline-cancel-construction");
        let (mut pair, id, ci, _cr) = approvals_timed(&a);
        ci.advance(INACTIVITY_DEADLINE);
        crypto::fail_next_cancel_construction();
        let ops = crypto::mac_operations();
        assert_eq!(
            timed_out(pair.i.poll_deadlines(), Deadline::Inactivity),
            None
        );
        assert_eq!(crypto::mac_operations(), ops, "no tag was computed");
        assert_failed(&mut pair.i, &a.ei, &id);
        // Without a notification the peer simply remains live on its own.
        assert!(pair.r.session().is_some());
        assert_eq!(a.er.status().unwrap(), Status::Busy);
        drop(pair);
        a.release();
    }

    #[test]
    fn uncertain_guard_release_on_timeout_withholds_the_cancel_and_fails_closed() {
        let a = Authorities::new("deadline-uncertain-release");
        let (mut pair, id, ci, _cr) = approvals_timed(&a);
        ci.advance(INACTIVITY_DEADLINE);
        poison(&a.ei);
        let ops = crypto::mac_operations();
        assert_eq!(
            pair.i.poll_deadlines(),
            Err(CeremonyError::Owner(OwnerError::OwnershipUncertain))
        );
        // Built while the session existed, then withheld with the uncertain cleanup.
        assert_eq!(crypto::mac_operations(), ops + 1);
        assert!(matches!(pair.i.state, State::Terminal) && pair.i.result().is_none());
        assert_stale(&mut pair.i, &id);
        assert_eq!(pair.i.poll_deadlines(), Ok(DeadlineOutcome::Finished));
        assert_guard_held_uncertainly(&a.ei);
        drop(pair);
        a.release();
    }

    #[test]
    fn a_timed_out_run_stays_terminal_whatever_arrives_later() {
        let a = Authorities::new("deadline-terminal");
        let (mut pair, ci, _cr) = establish_timed(&a);
        let id = pair.identity();
        let r_mac = approve_and_emit(&mut pair.r, &id);
        let i_mac = approve_and_emit(&mut pair.i, &id);
        pair.i.receive_bootstrap_mac(&r_mac).unwrap();
        pair.r.receive_bootstrap_mac(&i_mac).unwrap();
        let i_finish = finish(&mut pair.i);
        let r_ack = responder_ack(&mut pair.r, &i_finish);
        ci.advance(INACTIVITY_DEADLINE);
        let cancel = timed_out(pair.i.poll_deadlines(), Deadline::Inactivity).unwrap();
        assert_failed(&mut pair.i, &a.ei, &id);
        let r_cancel = own_cancel(pair.r.session().unwrap(), CancelReason::Timeout).unwrap();

        let ops = crypto::mac_operations();
        ci.advance(ABSOLUTE_DEADLINE);
        let run = &mut pair.i;
        assert!(run.receive_completion(&r_ack).is_err());
        assert!(run.receive_bootstrap_mac(&r_mac).is_err());
        assert!(run.receive_cancel(&r_cancel).is_err());
        assert_eq!(run.emit_bootstrap_mac(), Err(CeremonyError::NoLiveSas));
        assert_eq!(run.emit_initiator_finish(), Err(CeremonyError::NoLiveSas));
        assert_eq!(
            run.confirm_initiator_finish_ack_sent(&r_ack),
            Err(CeremonyError::NoPendingFinalAck)
        );
        for _ in 0..2 {
            assert_eq!(run.poll_deadlines(), Ok(DeadlineOutcome::Finished));
        }
        // No MAC work, output, second CANCEL, second release, or result.
        assert_eq!(crypto::mac_operations(), ops);
        assert_failed(run, &a.ei, &id);
        assert_eq!(remaining(&a.ei), 9);
        deliver_timeout(&mut pair.r, &a.er, &cancel, &id);
        drop(pair);
        a.release();
    }

    #[test]
    fn local_success_is_immune_to_later_deadline_polls() {
        let a = Authorities::new("deadline-after-success");
        let (mut pair, id, ci, cr) = approvals_timed(&a);
        let i_finish = finish(&mut pair.i);
        let r_ack = responder_ack(&mut pair.r, &i_finish);
        let i_ack = initiator_ack(&mut pair.i, &r_ack);
        confirm_sent(&mut pair.i, &i_ack);
        assert_eq!(
            pair.r.receive_completion(&i_ack),
            Ok(CompletionReceipt::Succeeded)
        );
        let results = (pair.i.result().cloned(), pair.r.result().cloned());
        let ops = crypto::mac_operations();
        for clock in [&ci, &cr] {
            clock.advance(secs(600));
        }
        for (run, executor) in [(&mut pair.i, &a.ei), (&mut pair.r, &a.er)] {
            assert_eq!(run.poll_deadlines(), Ok(DeadlineOutcome::Finished));
            assert_succeeded(run, executor, &id);
        }
        assert_eq!(
            pair.i.confirm_initiator_finish_ack_sent(&i_ack),
            Err(CeremonyError::Completed)
        );
        // Even an unusable clock cannot touch a finished run.
        ci.fail();
        assert_eq!(pair.i.poll_deadlines(), Ok(DeadlineOutcome::Finished));
        assert_eq!(crypto::mac_operations(), ops);
        assert_eq!(
            (pair.i.result().cloned(), pair.r.result().cloned()),
            results
        );
        drop(pair);
        a.release();
    }

    #[test]
    fn an_unusable_clock_fails_closed_without_claiming_a_timeout() {
        let a = Authorities::new("deadline-unsafe-clock");
        // Backwards time with a live SAS: terminal, but no authenticated timeout claim.
        let (mut pair, ci, _cr) = establish_timed(&a);
        let id = pair.identity();
        ci.advance(secs(30));
        active(&mut pair.i);
        ci.set(secs(10));
        assert_eq!(pair.i.presentation(), None);
        let ops = crypto::mac_operations();
        assert_eq!(
            pair.i.poll_deadlines(),
            Err(CeremonyError::ClockUnavailable)
        );
        assert_eq!(crypto::mac_operations(), ops, "no CANCEL was built");
        assert_failed(&mut pair.i, &a.ei, &id);
        assert!(pair.r.is_awaiting_approval());
        drop(pair);

        // No value at all, before any exposure: terminal and nothing spent.
        let clock = ManualClock::new();
        let mut i = timed_initiator(&a, &clock);
        i.receive_accept(&vector("ACCEPT")).unwrap();
        clock.fail();
        assert_eq!(i.authorize(&a.i), Err(CeremonyError::ClockUnavailable));
        assert_failed_pre_sas(&i, &a.ei, 9);
        drop(i);

        // A run cannot even be created without a usable clock.
        assert!(matches!(
            RemoteCeremony::initiator_with_fixed_start_and_clock_for_test(
                clock.clone(),
                a.ei.clone(),
                a.ei.begin(Role::Initiator).unwrap(),
                &vector("START"),
                bootstrap(&decoded("START"), true),
                None,
            ),
            Err(CeremonyError::ClockUnavailable)
        ));
        assert!(matches!(
            RemoteCeremony::responder_with_clock(
                clock.clone(),
                a.er.clone(),
                a.er.begin(Role::Responder).unwrap(),
                &vector("START"),
                bootstrap(&decoded("ACCEPT"), false),
                None,
            ),
            Err(CeremonyError::ClockUnavailable)
        ));
        assert_eq!(a.ei.status().unwrap(), Status::Ready { remaining: 9 });
        assert_eq!(a.er.status().unwrap(), Status::Ready { remaining: 9 });
        a.release();
    }

    #[test]
    fn large_monotonic_jumps_never_extend_a_ceremony() {
        let a = Authorities::new("deadline-jumps");
        let clock = ManualClock::new();
        let mut i = timed_initiator(&a, &clock);
        clock.advance(secs(600));
        assert_eq!(timed_out(i.poll_deadlines(), Deadline::Absolute), None);
        assert_failed_pre_sas(&i, &a.ei, 10);
        drop(i);

        let (mut pair, ci, _cr) = establish_timed(&a);
        let id = pair.identity();
        ci.advance(secs(240));
        active(&mut pair.i);
        assert!(pair.i.presentation().is_some());
        ci.advance(secs(61));
        let cancel = timed_out(pair.i.poll_deadlines(), Deadline::Absolute).unwrap();
        assert_failed(&mut pair.i, &a.ei, &id);
        deliver_timeout(&mut pair.r, &a.er, &cancel, &id);
        drop(pair);
        a.release();
    }

    // Honest Initiator request IDs (P3 §4): OS CSPRNG generation, the authority-wide active
    // local Initiator reservation, and its lifecycle. The ID is routing/correlation data only.

    /// Scripted request-ID source: each entry is one candidate, or `None` for entropy failure.
    struct ScriptedIds(std::collections::VecDeque<Option<[u8; 16]>>);
    impl RequestIdGenerator for ScriptedIds {
        fn generate(&mut self) -> Option<[u8; 16]> {
            self.0.pop_front().expect("request-ID script exhausted")
        }
    }
    fn script(ids: &[Option<[u8; 16]>]) -> ScriptedIds {
        ScriptedIds(ids.iter().copied().collect())
    }

    /// Snapshot of the authority's active local Initiator request IDs.
    fn reserved_ids(executor: &CeremonyExecutor) -> HashSet<[u8; 16]> {
        executor
            .0
            .shared
            .lock()
            .unwrap()
            .initiator_request_ids
            .clone()
    }

    /// An honest Initiator on `a.ei` drawing its candidates from `ids`.
    fn honest(
        a: &Authorities,
        clock: Clock,
        ids: &mut ScriptedIds,
    ) -> Result<RemoteCeremony, CeremonyError> {
        RemoteCeremony::initiator_with(
            clock,
            ids,
            a.ei.clone(),
            a.ei.begin(Role::Initiator).unwrap(),
            bootstrap(&decoded("START"), true),
            None,
        )
    }

    fn wire_request_id(bytes: &[u8]) -> Vec<u8> {
        match protocol::decode(bytes).unwrap().message {
            Message::Start { request_id, .. }
            | Message::Accept { request_id, .. }
            | Message::InitiatorKey { request_id, .. }
            | Message::ResponderKey { request_id, .. }
            | Message::BootstrapMac { request_id, .. }
            | Message::InitiatorFinish { request_id, .. }
            | Message::ResponderFinishAck { request_id, .. }
            | Message::InitiatorFinishAck { request_id, .. }
            | Message::Cancel { request_id, .. } => request_id,
        }
    }

    /// The request ID inside a created, not yet started Initiator's retained START.
    fn created_request_id(run: &RemoteCeremony) -> [u8; 16] {
        match &run.state {
            State::InitiatorCreated { start, .. } => {
                request_id_of(start).unwrap().try_into().unwrap()
            }
            _ => panic!("expected InitiatorCreated"),
        }
    }

    #[test]
    fn honest_initiator_reserves_its_csprng_id_before_start_can_exist() {
        let a = Authorities::new("request-id-honest");
        let local = bootstrap(&decoded("START"), true);
        let mut runs: Vec<_> = (0..8)
            .map(|_| {
                RemoteCeremony::initiator(
                    a.ei.clone(),
                    a.ei.begin(Role::Initiator).unwrap(),
                    local.clone(),
                    None,
                )
                .unwrap()
            })
            .collect();
        // Before `start()` can return anything, each exact ID is already reserved by its run.
        for run in &runs {
            let id = created_request_id(run);
            assert_eq!(run.admission.request_id, Some(id));
            assert!(reserved_ids(&a.ei).contains(&id));
        }
        assert_eq!(
            reserved_ids(&a.ei).len(),
            runs.len(),
            "one live owner per ID"
        );
        assert_eq!(a.ei.status().unwrap(), Status::Ready { remaining: 10 });
        for run in &mut runs {
            let start = run.start().unwrap();
            let id = wire_request_id(&start);
            assert_eq!(id.len(), 16);
            assert_eq!(run.admission.request_id.map(Vec::from), Some(id.clone()));
            assert!(reserved_ids(&a.ei).contains(id.as_slice()));
            match protocol::decode(&start).unwrap().message {
                Message::Start { bootstrap, .. } => {
                    assert_eq!(bootstrap.canonical_bytes(), local.canonical_bytes());
                }
                _ => unreachable!(),
            }
        }
        // Reservation is routing state only: no opportunity, no exposed-ceremony guard.
        assert_eq!(a.ei.status().unwrap(), Status::Ready { remaining: 10 });
        runs[0].terminate().unwrap();
        assert_eq!(runs[0].admission.request_id, None);
        assert_eq!(reserved_ids(&a.ei).len(), runs.len() - 1);
        assert_eq!(
            runs[0].terminate(),
            Ok(()),
            "a repeat releases nothing twice"
        );
        drop(runs);
        assert!(reserved_ids(&a.ei).is_empty());
        a.release();
    }

    #[test]
    fn an_active_collision_regenerates_before_start_and_spends_nothing() {
        let a = Authorities::new("request-id-collision");
        let (id_a, id_b) = ([0xA1; 16], [0xB2; 16]);
        let mut ids = script(&[Some(id_a), Some(id_a), Some(id_b)]);
        let mut first = honest(&a, system_clock(), &mut ids).unwrap();
        let mut second = honest(&a, system_clock(), &mut ids).unwrap();
        assert!(
            ids.0.is_empty(),
            "the colliding candidate was discarded, not used"
        );
        assert_eq!(created_request_id(&second), id_b);
        assert_eq!(reserved_ids(&a.ei), HashSet::from([id_a, id_b]));
        assert_eq!(
            (first.admission.request_id, second.admission.request_id),
            (Some(id_a), Some(id_b))
        );
        assert_eq!(wire_request_id(&first.start().unwrap()), id_a);
        assert_eq!(wire_request_id(&second.start().unwrap()), id_b);
        assert!(matches!(second.state, State::InitiatorAwaitAccept { .. }));
        assert_eq!(a.ei.status().unwrap(), Status::Ready { remaining: 10 });
        first.terminate().unwrap();
        assert_eq!(reserved_ids(&a.ei), HashSet::from([id_b]));
        second.terminate().unwrap();
        assert!(reserved_ids(&a.ei).is_empty());
        assert_eq!(a.ei.status().unwrap(), Status::Ready { remaining: 10 });
        drop((first, second));
        a.release();
    }

    #[test]
    fn concurrent_reservation_of_one_candidate_has_exactly_one_owner() {
        const CONTENDERS: usize = 8;
        let a = Authorities::new("request-id-concurrent");
        let candidate = [0x5A; 16];
        for _ in 0..25 {
            let barrier = Arc::new(std::sync::Barrier::new(CONTENDERS));
            let contenders: Vec<_> = (0..CONTENDERS)
                .map(|_| {
                    let (executor, barrier) = (a.ei.clone(), barrier.clone());
                    std::thread::spawn(move || {
                        let mut ceremony = executor.begin(Role::Initiator).unwrap();
                        barrier.wait();
                        let outcome = executor.reserve_request_id(&mut ceremony, candidate);
                        (outcome.unwrap(), ceremony)
                    })
                })
                .collect();
            let (owners, losers): (Vec<_>, Vec<_>) = contenders
                .into_iter()
                .map(|thread| thread.join().unwrap())
                .partition(|(outcome, _)| *outcome == RequestIdReservation::Reserved);
            assert_eq!(owners.len(), 1, "never two owners of one active ID");
            assert_eq!(owners[0].1.request_id, Some(candidate));
            assert!(losers.iter().all(|(outcome, ceremony)| {
                *outcome == RequestIdReservation::Collision && ceremony.request_id.is_none()
            }));
            drop(losers);
            assert_eq!(reserved_ids(&a.ei), HashSet::from([candidate]));
            drop(owners);
            assert!(reserved_ids(&a.ei).is_empty());
        }
        assert_eq!(a.ei.status().unwrap(), Status::Ready { remaining: 10 });
        a.release();
    }

    #[test]
    fn request_id_reservation_is_initiator_only_single_and_authority_bound() {
        let (a, b) = (
            Authorities::new("request-id-eligibility-a"),
            Authorities::new("request-id-eligibility-b"),
        );
        let candidate = [0xE1; 16];
        let mut responder = a.ei.begin(Role::Responder).unwrap();
        assert_eq!(
            a.ei.reserve_request_id(&mut responder, candidate),
            Ok(RequestIdReservation::NotEligible)
        );
        let mut initiator = a.ei.begin(Role::Initiator).unwrap();
        assert_eq!(
            b.ei.reserve_request_id(&mut initiator, candidate),
            Err(OwnerError::StaleAuthorization)
        );
        assert_eq!(
            a.ei.reserve_request_id(&mut initiator, candidate),
            Ok(RequestIdReservation::Reserved)
        );
        assert_eq!(
            a.ei.reserve_request_id(&mut initiator, [0xE2; 16]),
            Ok(RequestIdReservation::NotEligible),
            "one reservation per ceremony"
        );
        assert_eq!(reserved_ids(&a.ei), HashSet::from([candidate]));
        assert!(reserved_ids(&b.ei).is_empty());
        a.ei.terminate(&mut initiator).unwrap();
        assert!(reserved_ids(&a.ei).is_empty());
        assert_eq!(
            a.ei.reserve_request_id(&mut initiator, candidate),
            Err(OwnerError::Terminated)
        );
        assert!(matches!(
            RemoteCeremony::initiator_with(
                system_clock(),
                &mut script(&[]),
                a.ei.clone(),
                a.ei.begin(Role::Responder).unwrap(),
                bootstrap(&decoded("START"), true),
                None,
            ),
            Err(CeremonyError::InvalidState)
        ));
        // Holding a reserved ID authorizes nothing: exposure still needs local authorization.
        let mut run = honest(&a, system_clock(), &mut script(&[Some(candidate)])).unwrap();
        run.start().unwrap();
        assert_eq!(
            a.ei.reserve(&mut run.admission, None),
            Err(OwnerError::MissingAuthorization)
        );
        assert_eq!(a.ei.status().unwrap(), Status::Ready { remaining: 10 });
        drop((responder, initiator, run));
        assert!(reserved_ids(&a.ei).is_empty());
        a.release();
        b.release();
    }

    #[test]
    fn different_authorities_may_hold_the_same_id_without_sharing_ceremony_identity() {
        let (first, second) = (
            Authorities::new("request-id-authority-a"),
            Authorities::new("request-id-authority-b"),
        );
        let same = [0xAA; 16];
        let i_a = honest(&first, system_clock(), &mut script(&[Some(same)])).unwrap();
        let i_b = honest(&second, system_clock(), &mut script(&[Some(same)])).unwrap();
        assert_eq!(reserved_ids(&first.ei), HashSet::from([same]));
        assert_eq!(reserved_ids(&second.ei), HashSet::from([same]));
        let mut a = establish_from(&first, i_a, system_clock());
        let mut b = establish_from(&second, i_b, system_clock());
        assert_eq!(wire_request_id(&a.wire[0]), wire_request_id(&b.wire[0]));
        assert!(reserved_ids(&first.er).is_empty() && reserved_ids(&second.er).is_empty());
        let (id_a, id_b) = (a.identity(), b.identity());
        assert_ne!(id_a, id_b, "equal request IDs are not equal ceremonies");
        for run in [&mut b.i, &mut b.r] {
            assert_eq!(
                run.approve_sas(&id_a),
                Err(CeremonyError::CeremonyIdentityMismatch)
            );
            assert!(run.is_awaiting_approval());
        }
        a.i.terminate().unwrap();
        assert!(reserved_ids(&first.ei).is_empty());
        assert_eq!(reserved_ids(&second.ei), HashSet::from([same]));
        assert_eq!(b.i.approve_sas(&id_b), Ok(SasApproval::Recorded));
        drop((a, b));
        assert!(reserved_ids(&second.ei).is_empty());
        first.release();
        second.release();
    }

    #[test]
    fn pre_sas_failure_releases_the_reservation() {
        let a = Authorities::new("request-id-pre-sas-failure");
        let id = [0x0E; 16];
        // An ACCEPT for another request ID (the vector's) is terminal before exposure.
        let mut run = honest(&a, system_clock(), &mut script(&[Some(id)])).unwrap();
        run.start().unwrap();
        assert_eq!(
            run.receive_accept(&vector("ACCEPT")),
            Err(CeremonyError::RequestIdMismatch)
        );
        assert_failed_pre_sas(&run, &a.ei, 10);
        assert!(reserved_ids(&a.ei).is_empty());
        drop(run);

        // Malformed input after exposure but before SAS: released, the opportunity stays spent.
        let mut run = honest(&a, system_clock(), &mut script(&[Some(id)])).unwrap();
        let start = run.start().unwrap();
        let (r, accept) = RemoteCeremony::responder(
            a.er.clone(),
            a.er.begin(Role::Responder).unwrap(),
            &start,
            bootstrap(&decoded("ACCEPT"), false),
            None,
        )
        .unwrap();
        assert_eq!(wire_request_id(&accept), id);
        run.receive_accept(&accept).unwrap();
        run.authorize(&a.i).unwrap();
        assert_eq!(wire_request_id(&run.expose_key().unwrap()), id);
        assert_eq!(a.ei.status().unwrap(), Status::Busy);
        assert_eq!(reserved_ids(&a.ei), HashSet::from([id]));
        assert!(run.receive_responder_key(&[0xFF; 3]).is_err());
        assert_failed_pre_sas(&run, &a.ei, 9);
        assert!(reserved_ids(&a.ei).is_empty());
        assert!(reserved_ids(&a.er).is_empty());
        drop((run, r));
        a.release();
    }

    #[test]
    fn pre_sas_timeout_releases_the_reservation_and_the_id_may_return() {
        let a = Authorities::new("request-id-pre-sas-timeout");
        let id = [0x7E; 16];
        let clock = ManualClock::new();
        let mut old = honest(&a, clock.clone(), &mut script(&[Some(id)])).unwrap();
        assert_eq!(reserved_ids(&a.ei), HashSet::from([id]));
        clock.advance(INACTIVITY_DEADLINE);
        assert_eq!(
            timed_out(old.poll_deadlines(), Deadline::Inactivity),
            None,
            "no authenticated CANCEL exists before SAS"
        );
        assert_failed_pre_sas(&old, &a.ei, 10);
        // Released at terminal cleanup, while the dead run object still exists.
        assert!(reserved_ids(&a.ei).is_empty());
        let mut fresh = honest(&a, clock.clone(), &mut script(&[Some(id)])).unwrap();
        assert_eq!(wire_request_id(&fresh.start().unwrap()), id);
        assert_eq!(reserved_ids(&a.ei), HashSet::from([id]));
        assert!(old.start().is_err());
        drop((old, fresh));
        assert!(reserved_ids(&a.ei).is_empty());
        a.release();
    }

    #[test]
    fn post_sas_timeout_releases_the_reservation_and_its_cancel_keeps_the_id() {
        let a = Authorities::new("request-id-post-sas-timeout");
        let id = [0x5E; 16];
        let (ci, cr) = (ManualClock::new(), ManualClock::new());
        let i = honest(&a, ci.clone(), &mut script(&[Some(id)])).unwrap();
        let mut pair = establish_from(&a, i, cr.clone());
        let ceremony = pair.identity();
        assert_eq!(reserved_ids(&a.ei), HashSet::from([id]));
        ci.advance(ABSOLUTE_DEADLINE);
        let cancel = timed_out(pair.i.poll_deadlines(), Deadline::Absolute).unwrap();
        let (request_id, sender, reason, _) = cancel_parts(&cancel);
        assert_eq!(
            (request_id, sender, reason),
            (
                id.to_vec(),
                protocol::Role::Initiator,
                CancelReason::Timeout
            )
        );
        assert_failed(&mut pair.i, &a.ei, &ceremony);
        assert!(
            reserved_ids(&a.ei).is_empty(),
            "historical output holds nothing"
        );
        deliver_timeout(&mut pair.r, &a.er, &cancel, &ceremony);
        drop(pair);
        a.release();
    }

    #[test]
    fn local_reject_or_cancel_releases_the_reservation() {
        let a = Authorities::new("request-id-local-cancel");
        let id = [0xCA; 16];
        for reason in [CancelReason::UserRejection, CancelReason::UserCancellation] {
            let i = honest(&a, system_clock(), &mut script(&[Some(id)])).unwrap();
            let mut pair = establish_from(&a, i, system_clock());
            let ceremony = pair.identity();
            let before = remaining(&a.ei);
            let outcome = match reason {
                CancelReason::UserRejection => pair.i.reject_sas(&ceremony),
                _ => pair.i.cancel_sas(&ceremony),
            };
            let cancel = emitted_cancel(outcome);
            let (request_id, sender, sent, _) = cancel_parts(&cancel);
            assert_eq!(
                (request_id, sender, sent),
                (id.to_vec(), protocol::Role::Initiator, reason)
            );
            assert!(pair.i.admission.terminal && pair.i.result().is_none());
            assert!(reserved_ids(&a.ei).is_empty());
            assert_eq!(remaining(&a.ei), before, "nothing refunded");
            assert_eq!(
                pair.r.receive_cancel(&cancel).map(|c| c.reason()),
                Ok(reason)
            );
            assert!(pair.r.admission.terminal && pair.r.result().is_none());
            drop(pair);
        }
        a.release();
    }

    #[test]
    fn success_releases_the_reservation_only_after_the_final_ack_send_boundary() {
        let a = Authorities::new("request-id-success");
        let id = [0x5C; 16];
        let i = honest(&a, system_clock(), &mut script(&[Some(id)])).unwrap();
        let mut pair = establish_from(&a, i, system_clock());
        let ceremony = pair.identity();
        let r_mac = approve_and_emit(&mut pair.r, &ceremony);
        let i_mac = approve_and_emit(&mut pair.i, &ceremony);
        pair.i.receive_bootstrap_mac(&r_mac).unwrap();
        pair.r.receive_bootstrap_mac(&i_mac).unwrap();
        let initiator_finish = finish(&mut pair.i);
        let responder_finish_ack = responder_ack(&mut pair.r, &initiator_finish);
        let final_ack = initiator_ack(&mut pair.i, &responder_finish_ack);
        let frames = [
            &r_mac,
            &i_mac,
            &initiator_finish,
            &responder_finish_ack,
            &final_ack,
        ];
        for frame in pair.wire.iter().chain(frames) {
            assert_eq!(
                wire_request_id(frame),
                id,
                "the generated ID flows unchanged"
            );
        }
        assert_final_ack_pending(&pair.i, &a.ei, &final_ack);
        assert_eq!(reserved_ids(&a.ei), HashSet::from([id]));
        confirm_sent(&mut pair.i, &final_ack);
        assert_succeeded(&mut pair.i, &a.ei, &ceremony);
        assert!(reserved_ids(&a.ei).is_empty());
        let result = pair.i.result().unwrap().clone();
        assert_eq!(result.request_id(), &id[..]);
        assert_eq!(result.ceremony_identity(), &ceremony);
        assert_eq!(
            pair.r.receive_completion(&final_ack),
            Ok(CompletionReceipt::Succeeded)
        );
        assert_succeeded(&mut pair.r, &a.er, &ceremony);
        assert_eq!(pair.r.result().unwrap().request_id(), &id[..]);
        assert!(reserved_ids(&a.er).is_empty());
        // The ID may be generated again while the old result keeps it as historical data.
        let mut again = honest(&a, system_clock(), &mut script(&[Some(id)])).unwrap();
        assert_eq!(wire_request_id(&again.start().unwrap()), id);
        assert_eq!(pair.i.result(), Some(&result));
        drop((again, pair));
        a.release();
    }

    #[test]
    fn dropping_a_live_initiator_releases_its_reservation() {
        let a = Authorities::new("request-id-drop");
        let id = [0xD0; 16];
        let mut run = honest(&a, system_clock(), &mut script(&[Some(id)])).unwrap();
        run.start().unwrap();
        assert_eq!(reserved_ids(&a.ei), HashSet::from([id]));
        drop(run);
        assert!(reserved_ids(&a.ei).is_empty());

        let i = honest(&a, system_clock(), &mut script(&[Some(id)])).unwrap();
        let pair = establish_from(&a, i, system_clock());
        assert_eq!(reserved_ids(&a.ei), HashSet::from([id]));
        drop(pair);
        assert!(reserved_ids(&a.ei).is_empty());
        assert_eq!(a.ei.status().unwrap(), Status::Ready { remaining: 9 });
        let reused = honest(&a, system_clock(), &mut script(&[Some(id)])).unwrap();
        assert_eq!(created_request_id(&reused), id);
        drop(reused);
        a.release();
    }

    #[test]
    fn generator_failure_emits_nothing_and_holds_nothing() {
        let a = Authorities::new("request-id-entropy-failure");
        assert!(matches!(
            honest(&a, system_clock(), &mut script(&[None])),
            Err(CeremonyError::RequestIdGenerationFailed)
        ));
        assert!(reserved_ids(&a.ei).is_empty());
        assert_eq!(a.ei.status().unwrap(), Status::Ready { remaining: 10 });

        // Failure while regenerating after a collision fails at once; the owner keeps its ID.
        let held = [0x4E; 16];
        let owner = honest(&a, system_clock(), &mut script(&[Some(held)])).unwrap();
        let mut ids = script(&[Some(held), None]);
        assert!(matches!(
            honest(&a, system_clock(), &mut ids),
            Err(CeremonyError::RequestIdGenerationFailed)
        ));
        assert!(ids.0.is_empty());
        assert_eq!(reserved_ids(&a.ei), HashSet::from([held]));
        assert_eq!(a.ei.status().unwrap(), Status::Ready { remaining: 10 });
        drop(owner);
        assert!(reserved_ids(&a.ei).is_empty());
        a.release();
    }

    #[test]
    fn construction_failure_after_reservation_releases_the_id() {
        let a = Authorities::new("request-id-post-reservation-failure");
        let id = [0x33; 16];
        let clock = ManualClock::new();
        clock.fail();
        assert!(matches!(
            honest(&a, clock.clone(), &mut script(&[Some(id)])),
            Err(CeremonyError::ClockUnavailable)
        ));
        assert!(reserved_ids(&a.ei).is_empty());
        assert_eq!(a.ei.status().unwrap(), Status::Ready { remaining: 10 });
        let run = honest(&a, system_clock(), &mut script(&[Some(id)])).unwrap();
        assert_eq!(created_request_id(&run), id);
        drop(run);
        a.release();
    }

    #[test]
    fn uncertain_shared_state_fails_closed_for_request_id_reservation() {
        let a = Authorities::new("request-id-uncertain");
        let id = [0x0C; 16];
        let mut live = honest(&a, system_clock(), &mut script(&[Some(id)])).unwrap();
        poison(&a.ei);
        // Acquisition cannot be determined: no run, so no START can exist.
        let mut ids = script(&[Some([0x0D; 16])]);
        assert!(matches!(
            honest(&a, system_clock(), &mut ids),
            Err(CeremonyError::Owner(OwnerError::OwnershipUncertain))
        ));
        // Release cannot be confirmed: the reservation stays conservatively held.
        assert_eq!(
            live.terminate(),
            Err(CeremonyError::Owner(OwnerError::OwnershipUncertain))
        );
        drop(live);
        match a.ei.0.shared.lock() {
            Err(poisoned) => {
                assert_eq!(
                    poisoned.into_inner().initiator_request_ids,
                    HashSet::from([id])
                )
            }
            Ok(_) => panic!("shared state unexpectedly recovered"),
        }
        a.release();
    }

    // P3 11.1.1 core pre-exposure resource controls: at most 4 pending Responders and 2
    // expensive preliminary operations per authority, and the fixed 60-second pending resource
    // lifetime from admission. Transport controls are not implemented. These tests refill the
    // separate START limiter before each Responder; its own tests follow below.

    /// Accepted but unexposed Responder runs currently counted by the authority.
    fn pending(executor: &CeremonyExecutor) -> usize {
        executor.0.shared.lock().unwrap().pending_responders
    }

    /// Expensive preliminary operations currently counted by the authority.
    fn operations(executor: &CeremonyExecutor) -> usize {
        executor.0.shared.lock().unwrap().preliminary_operations
    }

    /// A Responder on `a.er` for the vector START, admitted at `clock`'s current value, with
    /// a refilled START limiter.
    fn admit(a: &Authorities, clock: Clock) -> Result<(RemoteCeremony, Vec<u8>), CeremonyError> {
        refill_start_limiters(a);
        RemoteCeremony::responder_with_clock(
            clock,
            a.er.clone(),
            a.er.begin(Role::Responder).unwrap(),
            &vector("START"),
            bootstrap(&decoded("ACCEPT"), false),
            None,
        )
    }

    const RESOURCE_LIMITED: CeremonyError = CeremonyError::Owner(OwnerError::ResourceLimited);

    /// Pending expiry: terminal, no result, SAS, CANCEL, or authorization; nothing spent.
    fn assert_pending_expired(run: &RemoteCeremony, executor: &CeremonyExecutor) {
        assert_failed_pre_sas(run, executor, 10);
        assert_eq!(run.admission.pending_responder, None);
        assert!(run.admission.authorization.is_none());
    }

    #[test]
    fn four_pending_responders_hold_slots_but_no_guard_or_opportunity() {
        let (a, b) = (
            Authorities::new("resource-pending-cap-a"),
            Authorities::new("resource-pending-cap-b"),
        );
        let mut runs: Vec<_> = (0..4)
            .map(|_| admit(&a, system_clock()).unwrap().0)
            .collect();
        assert_eq!(pending(&a.er), 4);
        assert!(
            runs.iter()
                .all(|run| run.admission.pending_responder.is_some())
        );
        // Pending admission is not exposure: no guard, no opportunity, no request-ID entry.
        assert_eq!(a.er.status().unwrap(), Status::Ready { remaining: 10 });
        assert_eq!(
            operations(&a.er),
            0,
            "no permit outlives ACCEPT preparation"
        );
        assert!(
            reserved_ids(&a.er).is_empty(),
            "peer IDs are never reserved"
        );

        // A fifth otherwise-valid START is refused generically, with no ACCEPT or state.
        assert_eq!(admit(&a, system_clock()).err(), Some(RESOURCE_LIMITED));
        assert_eq!(pending(&a.er), 4);
        assert_eq!(operations(&a.er), 0);
        assert_eq!(a.er.status().unwrap(), Status::Ready { remaining: 10 });
        for run in &mut runs {
            active(run);
        }

        // Another authority's capacity is independent.
        let others: Vec<_> = (0..4)
            .map(|_| admit(&b, system_clock()).unwrap().0)
            .collect();
        assert_eq!((pending(&a.er), pending(&b.er)), (4, 4));

        // Explicit termination releases at once, exactly once; the dead object still exists.
        runs[0].terminate().unwrap();
        assert_eq!(runs[0].admission.pending_responder, None);
        assert_eq!(pending(&a.er), 3);
        runs[0].terminate().unwrap();
        assert_eq!(pending(&a.er), 3, "a repeat releases nothing twice");
        let (replacement, _) = admit(&a, system_clock()).unwrap();
        assert_eq!(pending(&a.er), 4);

        // Dropping a live pending Responder releases its slot.
        drop(runs.pop());
        assert_eq!(pending(&a.er), 3);
        drop((runs, replacement, others));
        assert_eq!((pending(&a.er), pending(&b.er)), (0, 0));
        assert_eq!(a.er.status().unwrap(), Status::Ready { remaining: 10 });
        a.release();
        b.release();
    }

    #[test]
    fn semantic_mismatch_and_clock_failure_take_no_pending_slot() {
        let a = Authorities::new("resource-pending-mismatch");
        let other_context = Bootstrap::new(
            bootstrap(&decoded("ACCEPT"), false)
                .application_identity()
                .to_vec(),
            bootstrap(&decoded("ACCEPT"), false)
                .key_algorithm()
                .to_vec(),
            bootstrap(&decoded("ACCEPT"), false).public_key().to_vec(),
            b"different context".to_vec(),
        )
        .unwrap();
        assert_eq!(
            RemoteCeremony::responder(
                a.er.clone(),
                a.er.begin(Role::Responder).unwrap(),
                &vector("START"),
                other_context,
                None,
            )
            .err(),
            Some(CeremonyError::SharedContextMismatch)
        );
        assert_eq!((pending(&a.er), operations(&a.er)), (0, 0));

        // The clock is read before admission: without a value nothing is acquired.
        let clock = ManualClock::new();
        clock.fail();
        assert_eq!(
            admit(&a, clock).err(),
            Some(CeremonyError::ClockUnavailable)
        );
        assert_eq!((pending(&a.er), operations(&a.er)), (0, 0));

        // An unusable clock while pending fails closed and releases the slot.
        let clock = ManualClock::new();
        let (mut run, _) = admit(&a, clock.clone()).unwrap();
        clock.fail();
        assert_eq!(run.poll_deadlines(), Err(CeremonyError::ClockUnavailable));
        assert_eq!((pending(&a.er), operations(&a.er)), (0, 0));
        assert_eq!(a.er.status().unwrap(), Status::Ready { remaining: 10 });
        drop(run);
        a.release();
    }

    #[test]
    fn pending_slot_is_single_responder_owned_and_authority_bound() {
        let (a, b) = (
            Authorities::new("resource-slot-owner-a"),
            Authorities::new("resource-slot-owner-b"),
        );
        let now = Duration::ZERO;
        let mut initiator = a.er.begin(Role::Initiator).unwrap();
        assert_eq!(
            a.er.admit_pending_responder(&mut initiator, now),
            Ok(PendingAdmission::NotEligible)
        );
        let mut responder = a.er.begin(Role::Responder).unwrap();
        assert_eq!(
            b.er.admit_pending_responder(&mut responder, now),
            Err(OwnerError::StaleAuthorization)
        );
        assert_eq!(
            a.er.admit_pending_responder(&mut responder, now),
            Ok(PendingAdmission::Admitted)
        );
        assert_eq!(
            a.er.admit_pending_responder(&mut responder, now),
            Ok(PendingAdmission::NotEligible),
            "one slot per ceremony"
        );
        assert_eq!((pending(&a.er), pending(&b.er)), (1, 0));
        assert_eq!(initiator.pending_responder, None);
        // Crossing exposure releases exactly once.
        a.er.release_pending_responder(&mut responder).unwrap();
        a.er.release_pending_responder(&mut responder).unwrap();
        assert_eq!(pending(&a.er), 0);

        // A constructor that fails after admission just drops its `Ceremony`: RAII releases.
        let mut constructing = a.er.begin(Role::Responder).unwrap();
        a.er.admit_pending_responder(&mut constructing, now)
            .unwrap();
        assert_eq!(pending(&a.er), 1);
        drop(constructing);
        assert_eq!(pending(&a.er), 0);

        // A terminal ceremony can never acquire one.
        a.er.terminate(&mut responder).unwrap();
        assert_eq!(
            a.er.admit_pending_responder(&mut responder, now),
            Err(OwnerError::Terminated)
        );
        assert_eq!(pending(&a.er), 0);
        assert_eq!(a.er.status().unwrap(), Status::Ready { remaining: 10 });
        drop((initiator, responder));
        a.release();
        b.release();
    }

    #[test]
    fn pending_deadline_is_fixed_from_admission_and_progress_does_not_extend_it() {
        let a = Authorities::new("resource-pending-fixed");
        let clock = ManualClock::new();
        let (mut r, _) = admit(&a, clock.clone()).unwrap();
        assert_eq!(r.admission.pending_responder, Some(Duration::ZERO));
        // Valid progress at 30 s restarts ceremony inactivity (until 90 s) but not this.
        clock.advance(secs(30));
        r.receive_initiator_key(&vector("INITIATOR_KEY")).unwrap();
        assert!(matches!(r.state, State::ResponderAwaitAuthorization { .. }));
        r.receive_initiator_key(&vector("INITIATOR_KEY")).unwrap();
        clock.advance(PENDING_PRE_EXPOSURE_DEADLINE - secs(30) - NS);
        active(&mut r);
        clock.advance(NS);
        // At 60 s from admission the ceremony deadlines alone would still be live.
        assert_eq!(
            r.deadlines
                .evaluate(Some(PENDING_PRE_EXPOSURE_DEADLINE), Inactivity::Running),
            Verdict::Live
        );
        let macs = crypto::mac_operations();
        assert_eq!(r.poll_deadlines(), Ok(DeadlineOutcome::PendingExpired));
        assert_eq!(
            crypto::mac_operations(),
            macs,
            "no CANCEL exists before exposure"
        );
        assert_pending_expired(&r, &a.er);
        assert_eq!((pending(&a.er), operations(&a.er)), (0, 0));

        // Nothing revives it.
        assert!(r.receive_initiator_key(&vector("INITIATOR_KEY")).is_err());
        assert!(r.authorize(&a.r).is_err());
        assert!(r.expose_key().is_err());
        assert_eq!(r.poll_deadlines(), Ok(DeadlineOutcome::Finished));
        assert_pending_expired(&r, &a.er);
        drop(r);
        a.release();
    }

    #[test]
    fn authorization_and_dh_success_do_not_extend_the_pending_deadline() {
        let a = Authorities::new("resource-pending-authorized");
        let clock = ManualClock::new();
        let (mut r, _) = admit(&a, clock.clone()).unwrap();
        clock.advance(secs(20));
        r.receive_initiator_key(&vector("INITIATOR_KEY")).unwrap();
        clock.advance(secs(20));
        r.authorize(&a.r).unwrap();
        assert!(r.admission.authorization.is_some());
        // Inactivity restarted at 40 s; the pending lifetime still ends at 60 s.
        clock.advance(secs(20) - NS);
        active(&mut r);
        assert!(r.session().is_none(), "DH success alone presents no SAS");
        clock.advance(NS);
        assert_eq!(r.expose_key(), Err(CeremonyError::PendingExpired));
        assert_pending_expired(&r, &a.er);
        assert_eq!(a.er.status().unwrap(), Status::Ready { remaining: 10 });
        assert_eq!((pending(&a.er), operations(&a.er)), (0, 0));
        drop(r);
        a.release();
    }

    #[test]
    fn exposure_ends_the_pending_slot_and_its_deadline() {
        let a = Authorities::new("resource-pending-exposed");
        let clock = ManualClock::new();
        let (mut r, _) = admit(&a, clock.clone()).unwrap();
        r.receive_initiator_key(&vector("INITIATOR_KEY")).unwrap();
        r.authorize(&a.r).unwrap();
        assert_eq!(pending(&a.er), 1, "authorization alone is not exposure");
        clock.advance(PENDING_PRE_EXPOSURE_DEADLINE - NS);
        let rkey = r.expose_key().unwrap();
        assert!(matches!(
            protocol::decode(&rkey).unwrap().message,
            Message::ResponderKey { .. }
        ));
        assert_eq!(r.admission.pending_responder, None);
        assert_eq!((pending(&a.er), operations(&a.er)), (0, 0));
        assert_eq!(a.er.status().unwrap(), Status::Busy);
        assert_eq!(remaining(&a.er), 9);

        // Long past the old pending lifetime, only the ceremony deadlines apply.
        clock.advance(secs(120));
        active(&mut r);
        assert!(r.presentation().is_some());
        clock.set(ABSOLUTE_DEADLINE);
        let cancel = timed_out(r.poll_deadlines(), Deadline::Absolute).unwrap();
        assert_timeout_cancel(&cancel, protocol::Role::Responder);
        assert_eq!(a.er.status().unwrap(), Status::Ready { remaining: 9 });
        assert_eq!(pending(&a.er), 0);
        drop(r);
        a.release();
    }

    #[test]
    fn a_fifth_responder_may_enter_after_one_pending_run_expires() {
        let a = Authorities::new("resource-pending-refill");
        let clocks: Vec<_> = (0..4).map(|_| ManualClock::new()).collect();
        let mut runs: Vec<_> = clocks
            .iter()
            .map(|clock| admit(&a, clock.clone()).unwrap().0)
            .collect();
        assert_eq!(admit(&a, system_clock()).err(), Some(RESOURCE_LIMITED));
        // Progress at 30 s keeps ceremony inactivity live, isolating the pending lifetime.
        clocks[0].advance(secs(30));
        runs[0]
            .receive_initiator_key(&vector("INITIATOR_KEY"))
            .unwrap();
        clocks[0].advance(PENDING_PRE_EXPOSURE_DEADLINE - secs(30));
        assert_eq!(
            runs[0].poll_deadlines(),
            Ok(DeadlineOutcome::PendingExpired)
        );
        assert_eq!(pending(&a.er), 3);
        for run in &mut runs[1..] {
            active(run);
        }
        let (fresh, _) = admit(&a, system_clock()).unwrap();
        assert_eq!(pending(&a.er), 4);
        assert_eq!(a.er.status().unwrap(), Status::Ready { remaining: 10 });
        drop((runs, fresh));
        assert_eq!(pending(&a.er), 0);
        a.release();
    }

    #[test]
    fn malformed_or_misrouted_initiator_key_releases_the_slot() {
        let a = Authorities::new("resource-pending-malformed");
        let (mut r, _) = admit(&a, system_clock()).unwrap();
        assert!(r.receive_initiator_key(&[0xFF; 3]).is_err());
        assert_failed_pre_sas(&r, &a.er, 10);
        assert_eq!((pending(&a.er), operations(&a.er)), (0, 0));
        drop(r);

        let (mut r, _) = admit(&a, system_clock()).unwrap();
        let misrouted = Message::InitiatorKey {
            request_id: vec![0x43; 16],
            public_key: [9; 32],
        }
        .encode()
        .unwrap();
        assert_eq!(
            r.receive_initiator_key(&misrouted),
            Err(CeremonyError::RequestIdMismatch)
        );
        assert_failed_pre_sas(&r, &a.er, 10);
        assert_eq!((pending(&a.er), operations(&a.er)), (0, 0));
        // The freed slot is usable again.
        let (again, _) = admit(&a, system_clock()).unwrap();
        assert_eq!(pending(&a.er), 1);
        drop((r, again));
        a.release();
    }

    #[test]
    fn noncontributory_dh_releases_the_slot_and_the_permit() {
        let a = Authorities::new("resource-pending-noncontributory");
        let (mut r, _) = admit(&a, system_clock()).unwrap();
        let zero = Message::InitiatorKey {
            request_id: vector_request_id(),
            public_key: [0; 32],
        }
        .encode()
        .unwrap();
        assert_eq!(
            r.receive_initiator_key(&zero),
            Err(CeremonyError::Crypto(crypto::Error::NonContributory))
        );
        assert_failed_pre_sas(&r, &a.er, 10);
        assert_eq!((pending(&a.er), operations(&a.er)), (0, 0));
        assert!(r.authorize(&a.r).is_err() && r.expose_key().is_err());
        assert_eq!(a.er.status().unwrap(), Status::Ready { remaining: 10 });
        drop(r);
        a.release();
    }

    #[test]
    fn busy_exposure_ends_the_pending_run_without_later_reveal() {
        let a = Authorities::new("resource-pending-busy");
        // Another ceremony of the same authority holds the exposed guard.
        let mut holder = RemoteCeremony::initiator_with_fixed_start_for_test(
            a.er.clone(),
            a.er.begin(Role::Initiator).unwrap(),
            &vector("START"),
            bootstrap(&decoded("START"), true),
            None,
        )
        .unwrap();
        holder.start().unwrap();
        holder.receive_accept(&vector("ACCEPT")).unwrap();
        holder.authorize(&a.r).unwrap();
        holder.expose_key().unwrap();
        assert_eq!(a.er.status().unwrap(), Status::Busy);

        let (mut r, _) = admit(&a, system_clock()).unwrap();
        r.receive_initiator_key(&vector("INITIATOR_KEY")).unwrap();
        r.authorize(&a.r).unwrap();
        assert_eq!(r.expose_key(), Err(CeremonyError::Owner(OwnerError::Busy)));
        assert!(matches!(r.state, State::Terminal) && r.admission.terminal);
        assert_eq!((pending(&a.er), operations(&a.er)), (0, 0));
        assert_eq!(
            remaining(&a.er),
            9,
            "only the holder's exposure was charged"
        );

        holder.terminate().unwrap();
        assert_eq!(a.er.status().unwrap(), Status::Ready { remaining: 9 });
        assert!(r.authorize(&a.r).is_err() && r.expose_key().is_err());
        assert_eq!(a.er.status().unwrap(), Status::Ready { remaining: 9 });
        drop((holder, r));
        a.release();
    }

    #[test]
    fn permits_are_never_held_across_waits() {
        let a = Authorities::new("resource-permit-transient");
        let mut i = RemoteCeremony::initiator_with_fixed_start_for_test(
            a.ei.clone(),
            a.ei.begin(Role::Initiator).unwrap(),
            &vector("START"),
            bootstrap(&decoded("START"), true),
            None,
        )
        .unwrap();
        let start = i.start().unwrap();
        let (mut r, accept) = RemoteCeremony::responder(
            a.er.clone(),
            a.er.begin(Role::Responder).unwrap(),
            &start,
            bootstrap(&decoded("ACCEPT"), false),
            None,
        )
        .unwrap();
        let idle = |a: &Authorities| (operations(&a.ei), operations(&a.er));
        assert_eq!((idle(&a), pending(&a.er)), ((0, 0), 1));
        i.receive_accept(&accept).unwrap();
        i.authorize(&a.i).unwrap();
        let ikey = i.expose_key().unwrap();
        assert_eq!(idle(&a), (0, 0));
        r.receive_initiator_key(&ikey).unwrap();
        assert_eq!((idle(&a), pending(&a.er)), ((0, 0), 1));
        r.authorize(&a.r).unwrap();
        let rkey = r.expose_key().unwrap();
        i.receive_responder_key(&rkey).unwrap();
        assert_eq!((idle(&a), pending(&a.er)), ((0, 0), 0));
        assert!(i.is_awaiting_approval() && r.is_awaiting_approval());
        drop((i, r));
        a.release();
    }

    #[test]
    fn preliminary_permits_are_bounded_immediate_and_authority_wide() {
        let (a, b) = (
            Authorities::new("resource-permit-cap-a"),
            Authorities::new("resource-permit-cap-b"),
        );
        // Two holders on other threads, coordinated explicitly: no reliance on slow work.
        let (held_tx, held_rx) = mpsc::channel();
        let holders: Vec<_> = (0..2)
            .map(|_| {
                let (executor, held) = (a.er.clone(), held_tx.clone());
                let (release_tx, release_rx) = mpsc::channel::<()>();
                let thread = std::thread::spawn(move || {
                    let permit = executor.preliminary_permit().unwrap();
                    held.send(()).unwrap();
                    release_rx.recv().unwrap();
                    drop(permit);
                });
                (release_tx, thread)
            })
            .collect();
        held_rx.recv().unwrap();
        held_rx.recv().unwrap();
        assert_eq!(operations(&a.er), 2);
        // The third is refused at once: no wait, no queue, nothing spent or guarded.
        assert!(matches!(
            a.er.preliminary_permit(),
            Err(OwnerError::ResourceLimited)
        ));
        assert_eq!(operations(&a.er), 2);
        assert_eq!(a.er.status().unwrap(), Status::Ready { remaining: 10 });
        // Another authority has its own two.
        let other = [
            b.er.preliminary_permit().unwrap(),
            b.er.preliminary_permit().unwrap(),
        ];
        assert!(b.er.preliminary_permit().is_err());
        assert_eq!((operations(&a.er), operations(&b.er)), (2, 2));
        // Releasing one makes exactly one available again.
        let mut holders = holders.into_iter();
        let (release, thread) = holders.next().unwrap();
        release.send(()).unwrap();
        thread.join().unwrap();
        assert_eq!(operations(&a.er), 1);
        let permit = a.er.preliminary_permit().unwrap();
        assert!(a.er.preliminary_permit().is_err());
        drop(permit);
        for (release, thread) in holders {
            release.send(()).unwrap();
            thread.join().unwrap();
        }
        drop(other);
        assert_eq!((operations(&a.er), operations(&b.er)), (0, 0));
        a.release();
        b.release();
    }

    #[test]
    fn simultaneous_permit_requests_admit_exactly_two() {
        const CONTENDERS: usize = 8;
        let a = Authorities::new("resource-permit-race");
        for _ in 0..50 {
            let (attempt, hold) = (
                Arc::new(Barrier::new(CONTENDERS)),
                Arc::new(Barrier::new(CONTENDERS)),
            );
            let granted = (0..CONTENDERS)
                .map(|_| {
                    let (executor, attempt, hold) = (a.ei.clone(), attempt.clone(), hold.clone());
                    std::thread::spawn(move || {
                        attempt.wait();
                        let permit = executor.preliminary_permit();
                        // Every request is made before any granted permit can be released.
                        hold.wait();
                        match permit {
                            Ok(_) => true,
                            Err(error) => {
                                assert_eq!(error, OwnerError::ResourceLimited);
                                false
                            }
                        }
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|thread| thread.join().unwrap())
                .filter(|granted| *granted)
                .count();
            assert_eq!(granted, 2);
            assert_eq!(operations(&a.ei), 0);
        }
        assert_eq!(a.ei.status().unwrap(), Status::Ready { remaining: 10 });
        a.release();
    }

    #[test]
    fn concurrent_starts_never_exceed_the_pending_cap() {
        const CONTENDERS: usize = 8;
        let a = Arc::new(Authorities::new("resource-pending-race"));
        for _ in 0..25 {
            let (attempt, hold) = (
                Arc::new(Barrier::new(CONTENDERS)),
                Arc::new(Barrier::new(CONTENDERS + 1)),
            );
            let threads: Vec<_> = (0..CONTENDERS)
                .map(|_| {
                    let (a, attempt, hold) = (a.clone(), attempt.clone(), hold.clone());
                    std::thread::spawn(move || {
                        attempt.wait();
                        let outcome = admit(&a, system_clock()).map(|(run, _)| run);
                        hold.wait();
                        outcome
                    })
                })
                .collect();
            hold.wait();
            let admitted = pending(&a.er);
            let outcomes: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
            let runs: Vec<_> = outcomes.iter().filter(|outcome| outcome.is_ok()).collect();
            assert!((1..=4).contains(&runs.len()));
            assert_eq!(admitted, runs.len());
            assert!(
                outcomes
                    .iter()
                    .filter_map(|outcome| outcome.as_ref().err())
                    .all(|error| *error == RESOURCE_LIMITED)
            );
            drop(outcomes);
            assert_eq!((pending(&a.er), operations(&a.er)), (0, 0));
        }
        assert_eq!(a.er.status().unwrap(), Status::Ready { remaining: 10 });
        Arc::into_inner(a).unwrap().release();
    }

    #[test]
    fn unavailable_permits_refuse_responder_admission_without_state() {
        let a = Authorities::new("resource-permit-start");
        let busy = [
            a.er.preliminary_permit().unwrap(),
            a.er.preliminary_permit().unwrap(),
        ];
        assert_eq!(admit(&a, system_clock()).err(), Some(RESOURCE_LIMITED));
        assert_eq!((pending(&a.er), operations(&a.er)), (0, 2));
        assert_eq!(a.er.status().unwrap(), Status::Ready { remaining: 10 });
        drop(busy);
        let (run, _) = admit(&a, system_clock()).unwrap();
        assert_eq!((pending(&a.er), operations(&a.er)), (1, 0));
        drop(run);
        a.release();
    }

    #[test]
    fn unavailable_permits_end_responder_dh_without_exposure() {
        let a = Authorities::new("resource-permit-dh");
        let (mut r, _) = admit(&a, system_clock()).unwrap();
        let busy = [
            a.er.preliminary_permit().unwrap(),
            a.er.preliminary_permit().unwrap(),
        ];
        assert_eq!(
            r.receive_initiator_key(&vector("INITIATOR_KEY")),
            Err(RESOURCE_LIMITED)
        );
        // Refused, not queued: the run is over unexposed and its slot is free.
        assert_failed_pre_sas(&r, &a.er, 10);
        assert_eq!((pending(&a.er), operations(&a.er)), (0, 2));
        drop(busy);
        assert!(r.receive_initiator_key(&vector("INITIATOR_KEY")).is_err());
        assert!(r.authorize(&a.r).is_err() && r.expose_key().is_err());
        assert_eq!((pending(&a.er), operations(&a.er)), (0, 0));
        assert_eq!(a.er.status().unwrap(), Status::Ready { remaining: 10 });
        drop(r);
        a.release();
    }

    #[test]
    fn unavailable_permits_end_initiator_exposure_with_nothing_spent() {
        let a = Authorities::new("resource-permit-initiator");
        let id = [0x1A; 16];
        let mut i = honest(&a, system_clock(), &mut script(&[Some(id)])).unwrap();
        let start = i.start().unwrap();
        let (r, accept) = RemoteCeremony::responder(
            a.er.clone(),
            a.er.begin(Role::Responder).unwrap(),
            &start,
            bootstrap(&decoded("ACCEPT"), false),
            None,
        )
        .unwrap();
        i.receive_accept(&accept).unwrap();
        i.authorize(&a.i).unwrap();
        let busy = [
            a.ei.preliminary_permit().unwrap(),
            a.ei.preliminary_permit().unwrap(),
        ];
        assert_eq!(i.expose_key(), Err(RESOURCE_LIMITED));
        assert_failed_pre_sas(&i, &a.ei, 10);
        assert!(i.admission.authorization.is_none());
        assert!(
            reserved_ids(&a.ei).is_empty(),
            "terminal cleanup released the ID"
        );
        assert_eq!(operations(&a.ei), 2);
        drop(busy);
        assert!(i.expose_key().is_err());
        assert_eq!(a.ei.status().unwrap(), Status::Ready { remaining: 10 });
        drop((i, r));

        // A Busy reservation after the permit was granted returns the permit.
        let fixed = |a: &Authorities| {
            let mut run = RemoteCeremony::initiator_with_fixed_start_for_test(
                a.ei.clone(),
                a.ei.begin(Role::Initiator).unwrap(),
                &vector("START"),
                bootstrap(&decoded("START"), true),
                None,
            )
            .unwrap();
            run.start().unwrap();
            run.receive_accept(&vector("ACCEPT")).unwrap();
            run.authorize(&a.i).unwrap();
            run
        };
        let mut holder = fixed(&a);
        let mut second = fixed(&a);
        holder.expose_key().unwrap();
        assert_eq!(
            second.expose_key(),
            Err(CeremonyError::Owner(OwnerError::Busy))
        );
        assert_eq!(operations(&a.ei), 0);
        assert_eq!(remaining(&a.ei), 9);
        drop((holder, second));
        a.release();
    }

    #[test]
    fn poisoned_shared_state_fails_closed_for_resources() {
        let a = Authorities::new("resource-uncertain");
        let (mut live, _) = admit(&a, system_clock()).unwrap();
        let permit = a.er.preliminary_permit().unwrap();
        poison(&a.er);
        assert_eq!(
            admit(&a, system_clock()).err(),
            Some(CeremonyError::Owner(OwnerError::OwnershipUncertain))
        );
        assert!(matches!(
            a.er.preliminary_permit(),
            Err(OwnerError::OwnershipUncertain)
        ));
        // Release cannot be confirmed: both stay conservatively counted.
        assert_eq!(
            live.terminate(),
            Err(CeremonyError::Owner(OwnerError::OwnershipUncertain))
        );
        drop((live, permit));
        match a.er.0.shared.lock() {
            Err(poisoned) => {
                let shared = poisoned.into_inner();
                assert_eq!(shared.pending_responders, 1);
                assert_eq!(shared.preliminary_operations, 1);
                assert_eq!(shared.remaining, 10);
                assert!(shared.active.is_none());
            }
            Ok(_) => panic!("shared state unexpectedly recovered"),
        }
        a.release();
    }

    // P3 11.1.1 authority-wide START admission limiter (R-OWNER-025, -027, -034 to -039). Each
    // test drives the authority's one injected limiter clock (`lr`) by hand; ceremony clocks are
    // separate. Source address, socket, connection, and listener rotation are transport-dependent
    // and not exercised: no transport exists.

    /// The Responder authority's START limiter.
    fn limiter(a: &Authorities) -> StartLimiterSnapshot {
        a.er.start_limiter_snapshot()
    }

    /// Asserts the limiter's whole tokens and live rolling records.
    #[track_caller]
    fn assert_limiter(a: &Authorities, tokens: u8, rolling: usize) {
        let state = limiter(a);
        assert_eq!(
            (state.tokens, state.rolling),
            (tokens, rolling),
            "{state:?}"
        );
    }

    /// No pending state, permit, guard, or opportunity effect.
    #[track_caller]
    fn assert_no_resources(a: &Authorities) {
        assert_eq!((pending(&a.er), operations(&a.er)), (0, 0));
        assert_eq!(a.er.status().unwrap(), Status::Ready { remaining: 10 });
    }

    /// A new Responder candidate on `a.er` with whatever limiter state exists.
    fn present(
        a: &Authorities,
        start: &[u8],
        local: Bootstrap,
        expected: Option<Bootstrap>,
    ) -> Result<(RemoteCeremony, Vec<u8>), CeremonyError> {
        RemoteCeremony::responder_with_clock(
            system_clock(),
            a.er.clone(),
            a.er.begin(Role::Responder).unwrap(),
            start,
            local,
            expected,
        )
    }

    fn responder_bootstrap() -> Bootstrap {
        bootstrap(&decoded("ACCEPT"), false)
    }

    /// A valid new START candidate for the vector Responder bootstrap; checks its ACCEPT.
    fn present_valid(a: &Authorities, start: &[u8]) -> Result<RemoteCeremony, CeremonyError> {
        present(a, start, responder_bootstrap(), None).map(|(run, accept)| {
            assert!(matches!(
                protocol::decode(&accept).unwrap().message,
                Message::Accept { .. }
            ));
            run
        })
    }

    /// A vector-START Responder whose ceremony clock is `clock`, with the current limiter.
    fn present_with_clock(
        a: &Authorities,
        clock: Arc<ManualClock>,
    ) -> Result<RemoteCeremony, CeremonyError> {
        RemoteCeremony::responder_with_clock(
            clock,
            a.er.clone(),
            a.er.begin(Role::Responder).unwrap(),
            &vector("START"),
            responder_bootstrap(),
            None,
        )
        .map(|(run, _)| run)
    }

    /// A canonical wire START whose third field is `field`, verbatim and unvalidated.
    fn raw_start(request_id: &[u8], field: &[u8]) -> Vec<u8> {
        let mut out = b"SASPAIR\x00\x01\x01".to_vec();
        for value in [protocol::PROFILE_ID, request_id, field] {
            out.extend_from_slice(&(value.len() as u32).to_be_bytes());
            out.extend_from_slice(value);
        }
        out
    }

    /// A valid START from the vector Initiator bootstrap with another `application_identity`.
    fn start_as(request_id: &[u8], identity: &[u8]) -> Vec<u8> {
        let b = bootstrap(&decoded("START"), true);
        Message::Start {
            request_id: request_id.to_vec(),
            bootstrap: Bootstrap::new(
                identity.to_vec(),
                b.key_algorithm().to_vec(),
                b.public_key().to_vec(),
                b.shared_context().to_vec(),
            )
            .unwrap(),
        }
        .encode()
        .unwrap()
    }

    /// One limiter decision through the authority primitive, for a fresh Responder ceremony.
    fn decide(executor: &CeremonyExecutor) -> StartLimit {
        executor
            .admit_start(&executor.begin(Role::Responder).unwrap())
            .unwrap()
    }

    // R-OWNER-034 and R-OWNER-027 through real Responder admission.
    #[test]
    fn burst_admits_four_same_instant_starts_then_refills_one_per_five_seconds() {
        let a = Authorities::new("start-limiter-burst");
        assert_eq!(
            limiter(&a),
            StartLimiterSnapshot {
                tokens: 4,
                remainder: Duration::ZERO,
                last: Duration::ZERO,
                rolling: 0,
            },
            "registration charges nothing"
        );
        // Ceremony clocks far apart in value never influence the limiter.
        for value in [0, 1_000, 7, 86_400] {
            let clock = ManualClock::new();
            clock.set(secs(value));
            drop(present_with_clock(&a, clock).unwrap());
        }
        assert_limiter(&a, 0, 4);
        assert_no_resources(&a);

        // The fifth at the same limiter instant is refused generically: no state of any kind.
        let before = limiter(&a);
        assert_eq!(
            present_valid(&a, &vector("START")).err(),
            Some(RESOURCE_LIMITED)
        );
        assert_eq!(limiter(&a), before);
        assert_no_resources(&a);

        // R-OWNER-027: a flood of refusals spends, refunds, and resets nothing.
        for _ in 0..1_000 {
            assert_eq!(
                present_valid(&a, &vector("START")).err(),
                Some(RESOURCE_LIMITED)
            );
        }
        assert_eq!(limiter(&a), before);
        assert_no_resources(&a);

        a.lr.set(secs(5) - NS);
        assert_eq!(
            present_valid(&a, &vector("START")).err(),
            Some(RESOURCE_LIMITED)
        );
        assert_limiter(&a, 0, 4);
        a.lr.set(secs(5));
        drop(present_valid(&a, &vector("START")).unwrap());
        assert_limiter(&a, 0, 5);
        assert_eq!(
            present_valid(&a, &vector("START")).err(),
            Some(RESOURCE_LIMITED)
        );

        // Ten seconds without an admission after that: exactly two.
        a.lr.set(secs(15));
        for _ in 0..2 {
            drop(present_valid(&a, &vector("START")).unwrap());
        }
        assert_eq!(
            present_valid(&a, &vector("START")).err(),
            Some(RESOURCE_LIMITED)
        );
        assert_limiter(&a, 0, 7);

        // Ten minutes idle: exactly four, never more.
        a.lr.set(secs(615));
        for _ in 0..4 {
            drop(present_valid(&a, &vector("START")).unwrap());
        }
        assert_eq!(
            present_valid(&a, &vector("START")).err(),
            Some(RESOURCE_LIMITED)
        );
        assert_limiter(&a, 0, 4);
        assert_no_resources(&a);
        a.release();
    }

    // R-OWNER-035 through the authority primitive and its one shared clock.
    #[test]
    fn rolling_cap_schedule_through_the_authority() {
        let a = Authorities::new("start-limiter-rolling");
        for _ in 0..4 {
            assert_eq!(decide(&a.er), StartLimit::Admitted);
        }
        for second in (5..=40).step_by(5) {
            a.lr.set(secs(second));
            assert_eq!(decide(&a.er), StartLimit::Admitted, "t={second}");
        }
        assert_limiter(&a, 0, 12);
        a.lr.set(secs(45));
        assert_eq!(decide(&a.er), StartLimit::Refused);
        assert_limiter(&a, 1, 12);
        a.lr.set(secs(60) - Duration::from_millis(1));
        assert_eq!(decide(&a.er), StartLimit::Refused);
        assert_limiter(&a, 3, 12);
        a.lr.set(secs(60));
        assert_eq!(decide(&a.er), StartLimit::Admitted);
        assert_limiter(&a, 3, 9);
        for _ in 0..3 {
            assert_eq!(decide(&a.er), StartLimit::Admitted);
        }
        assert_eq!(decide(&a.er), StartLimit::Refused);
        assert_limiter(&a, 0, 12);
        assert_no_resources(&a);
        a.release();
    }

    // R-OWNER-036 (a): semantic failures are charged first and never refunded.
    #[test]
    fn semantically_invalid_starts_are_charged_and_never_refunded() {
        let rid = vector_request_id();
        let peer = bootstrap(&decoded("START"), true);
        let nested = |key_algorithm: &[u8], shared_context: &[u8]| {
            let mut frame = b"SASPAIR\x00\x01\x20".to_vec();
            for value in [
                peer.application_identity(),
                key_algorithm,
                peer.public_key(),
                shared_context,
            ] {
                frame.extend_from_slice(&(value.len() as u32).to_be_bytes());
                frame.extend_from_slice(value);
            }
            frame
        };
        // A nested bootstrap above 16,384 bytes in an outer frame within 65,536.
        let oversized = nested(b"ed25519", &[0; 3 * protocol::MAX_BOOTSTRAP_FRAME / 2]);
        assert!(oversized.len() > protocol::MAX_BOOTSTRAP_FRAME);
        let other_context = Bootstrap::new(
            responder_bootstrap().application_identity().to_vec(),
            responder_bootstrap().key_algorithm().to_vec(),
            responder_bootstrap().public_key().to_vec(),
            b"another context".to_vec(),
        )
        .unwrap();
        let other_peer = Bootstrap::new(
            b"someone else".to_vec(),
            peer.key_algorithm().to_vec(),
            peer.public_key().to_vec(),
            peer.shared_context().to_vec(),
        )
        .unwrap();
        let codec = |error| CeremonyError::Codec(error);
        let cases = vec![
            (
                "malformed nested bootstrap",
                raw_start(&rid, &[0xFF; 3]),
                responder_bootstrap(),
                None,
                codec(protocol::CodecError::Truncated),
            ),
            (
                "nested bootstrap above 16,384 bytes",
                raw_start(&rid, &oversized),
                responder_bootstrap(),
                None,
                codec(protocol::CodecError::Oversized),
            ),
            (
                "key_algorithm grammar",
                raw_start(&rid, &nested(b"Ed25519", peer.shared_context())),
                responder_bootstrap(),
                None,
                codec(protocol::CodecError::InvalidField("key_algorithm")),
            ),
            (
                "shared-context mismatch",
                vector("START"),
                other_context,
                None,
                CeremonyError::SharedContextMismatch,
            ),
            (
                "expected-peer mismatch",
                vector("START"),
                responder_bootstrap(),
                Some(other_peer),
                CeremonyError::ExpectedPeerMismatch,
            ),
        ];
        for (index, (name, start, local, expected, error)) in cases.into_iter().enumerate() {
            assert!(start.len() <= protocol::MAX_FRAME, "{name}");
            let a = Authorities::new(&format!("start-limiter-semantic-{index}"));
            a.lr.set(secs(30));
            assert_limiter(&a, 4, 0);
            let macs = crypto::mac_operations();
            assert_eq!(
                present(&a, &start, local, expected).err(),
                Some(error),
                "{name}"
            );
            assert_limiter(&a, 3, 1);
            assert_no_resources(&a);
            assert_eq!(crypto::mac_operations(), macs, "{name}");
            // A valid START at the same instant observes the charge and proceeds normally.
            let run = present_valid(&a, &vector("START")).unwrap();
            assert_limiter(&a, 2, 2);
            assert_eq!((pending(&a.er), operations(&a.er)), (1, 0));
            assert_eq!(a.er.status().unwrap(), Status::Ready { remaining: 10 });
            drop(run);
            a.release();
        }
    }

    // R-OWNER-036 (b): not a START candidate, so nothing is charged.
    #[test]
    fn structurally_invalid_start_shaped_input_is_never_charged() {
        let valid = vector("START");
        let rid = vector_request_id();
        let field = bootstrap(&decoded("START"), true)
            .canonical_bytes()
            .to_vec();
        let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();
        let mut bytes = valid.clone();
        bytes[0] = b'X';
        cases.push(("magic", bytes));
        let mut bytes = valid.clone();
        bytes[8] = 2;
        cases.push(("header version", bytes));
        let mut bytes = valid.clone();
        bytes[9] = 0x7f;
        cases.push(("unknown outer type", bytes));
        cases.push(("another wire type", vector("ACCEPT")));
        let mut bytes = valid.clone();
        bytes[14] ^= 1;
        cases.push(("profile", bytes));
        cases.push(("request ID 0", raw_start(&[], &field)));
        cases.push(("request ID 65", raw_start(&[7; 65], &field)));
        cases.push(("truncated", valid[..valid.len() - 1].to_vec()));
        cases.push(("trailing byte", [valid.as_slice(), &[0]].concat()));
        cases.push(("four fields", [valid.as_slice(), &[0, 0, 0, 0]].concat()));
        let filler = protocol::MAX_FRAME - raw_start(&rid, &[]).len() + 1;
        let oversized = raw_start(&rid, &vec![0; filler]);
        assert_eq!(oversized.len(), protocol::MAX_FRAME + 1);
        cases.push(("frame above 65,536 bytes", oversized));

        let a = Authorities::new("start-limiter-structural");
        a.lr.set(secs(30));
        let fresh = limiter(&a);
        for (name, bytes) in &cases {
            assert!(
                matches!(present_valid(&a, bytes), Err(CeremonyError::Codec(_))),
                "{name}"
            );
            assert_eq!(limiter(&a), fresh, "{name}");
            assert_no_resources(&a);
        }
        // Still codec rejections, never limiter refusals, once the limiter is exhausted.
        for _ in 0..4 {
            drop(present_valid(&a, &valid).unwrap());
        }
        let exhausted = limiter(&a);
        assert_eq!(exhausted.tokens, 0);
        for (name, bytes) in &cases {
            assert!(
                matches!(present_valid(&a, bytes), Err(CeremonyError::Codec(_))),
                "{name}"
            );
            assert_eq!(limiter(&a), exhausted, "{name}");
        }
        assert_no_resources(&a);
        a.release();
    }

    // R-OWNER-025 / R-OWNER-036 (c): a permit refusal after admission keeps the charge.
    #[test]
    fn permit_refusal_after_limiter_admission_keeps_the_charge() {
        let a = Authorities::new("start-limiter-permit");
        let busy = [
            a.er.preliminary_permit().unwrap(),
            a.er.preliminary_permit().unwrap(),
        ];
        assert_eq!(
            present_valid(&a, &vector("START")).err(),
            Some(RESOURCE_LIMITED)
        );
        assert_limiter(&a, 3, 1);
        assert_eq!((pending(&a.er), operations(&a.er)), (0, 2));
        assert_eq!(a.er.status().unwrap(), Status::Ready { remaining: 10 });
        drop(busy);
        assert_no_resources(&a);
        let run = present_valid(&a, &vector("START")).unwrap();
        assert_limiter(&a, 2, 2);
        drop(run);
        a.release();
    }

    // R-OWNER-036 (c): a pending-capacity refusal after admission keeps the charge.
    #[test]
    fn pending_cap_refusal_after_limiter_admission_keeps_the_charge() {
        let a = Authorities::new("start-limiter-pending");
        let mut runs: Vec<_> = (0..4)
            .map(|_| present_valid(&a, &vector("START")).unwrap())
            .collect();
        assert_limiter(&a, 0, 4);
        a.lr.set(secs(5));
        // Admitted and charged by the limiter, validated, then refused for capacity.
        assert_eq!(
            present_valid(&a, &vector("START")).err(),
            Some(RESOURCE_LIMITED)
        );
        assert_limiter(&a, 0, 5);
        assert_eq!((pending(&a.er), operations(&a.er)), (4, 0));
        assert_eq!(a.er.status().unwrap(), Status::Ready { remaining: 10 });
        // A freed slot does not restore the spent token: now the limiter refuses.
        drop(runs.pop());
        assert_eq!(
            present_valid(&a, &vector("START")).err(),
            Some(RESOURCE_LIMITED)
        );
        assert_limiter(&a, 0, 5);
        assert_eq!(pending(&a.er), 3);
        drop(runs);
        assert_no_resources(&a);
        a.release();
    }

    // P3 10 order: candidate -> limiter -> permit -> semantics -> pending -> ephemeral/ACCEPT.
    #[test]
    fn responder_admission_order_is_exact() {
        let a = Authorities::new("start-limiter-order");
        let malformed = raw_start(&vector_request_id(), &[0xFF; 3]);
        let codec = |result: Result<RemoteCeremony, CeremonyError>| {
            matches!(result, Err(CeremonyError::Codec(_)))
        };

        // Limiter before permit: with no permit available the limiter is still charged.
        let busy = [
            a.er.preliminary_permit().unwrap(),
            a.er.preliminary_permit().unwrap(),
        ];
        assert_eq!(
            present_valid(&a, &vector("START")).err(),
            Some(RESOURCE_LIMITED)
        );
        assert_limiter(&a, 3, 1);
        // Permit before semantics: a malformed bootstrap is refused for the permit, unparsed.
        assert_eq!(present_valid(&a, &malformed).err(), Some(RESOURCE_LIMITED));
        assert_limiter(&a, 2, 2);
        drop(busy);

        // Semantics before pending capacity: with every slot held the bootstrap still fails.
        a.lr.set(secs(60));
        let runs: Vec<_> = (0..4)
            .map(|_| present_valid(&a, &vector("START")).unwrap())
            .collect();
        assert_eq!(pending(&a.er), 4);
        a.lr.set(secs(70));
        assert!(codec(present_valid(&a, &malformed)));
        assert_limiter(&a, 1, 5);
        // Pending capacity before ephemeral, commitment, and ACCEPT: refused, no ACCEPT.
        assert_eq!(
            present_valid(&a, &vector("START")).err(),
            Some(RESOURCE_LIMITED)
        );
        assert_limiter(&a, 0, 6);
        assert_eq!((pending(&a.er), operations(&a.er)), (4, 0));
        drop(runs);

        // Candidate structure before the limiter, and the limiter before semantics.
        let exhausted = limiter(&a);
        assert!(codec(present_valid(&a, &vector("START")[1..])));
        assert_eq!(present_valid(&a, &malformed).err(), Some(RESOURCE_LIMITED));
        assert_eq!(limiter(&a), exhausted);
        assert_no_resources(&a);
        a.release();
    }

    /// `CONTENDERS` threads present one candidate each to `a.er` at the same limiter instant.
    fn contend(a: &Arc<Authorities>) -> Vec<StartLimit> {
        const CONTENDERS: usize = 8;
        let attempt = Arc::new(Barrier::new(CONTENDERS));
        (0..CONTENDERS)
            .map(|_| {
                let (a, attempt) = (a.clone(), attempt.clone());
                std::thread::spawn(move || {
                    let ceremony = a.er.begin(Role::Responder).unwrap();
                    attempt.wait();
                    a.er.admit_start(&ceremony).unwrap()
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect()
    }

    fn admitted(outcomes: &[StartLimit]) -> usize {
        assert!(
            outcomes
                .iter()
                .all(|outcome| matches!(outcome, StartLimit::Admitted | StartLimit::Refused))
        );
        outcomes
            .iter()
            .filter(|outcome| **outcome == StartLimit::Admitted)
            .count()
    }

    // R-OWNER-037 (a): eight simultaneous candidates on one authority at one instant.
    #[test]
    fn simultaneous_candidates_admit_exactly_four() {
        let a = Arc::new(Authorities::new("start-limiter-burst-race"));
        for round in 0..50u64 {
            // A full rolling window later: full bucket, every earlier record expired.
            a.lr.set(secs(60 * round));
            assert_eq!(admitted(&contend(&a)), 4);
            assert_limiter(&a, 0, 4);
        }
        assert_no_resources(&a);
        Arc::into_inner(a).unwrap().release();
    }

    // R-OWNER-037 (b): contention near the rolling maximum never leaves more than 12 records.
    #[test]
    fn simultaneous_candidates_never_exceed_the_rolling_maximum() {
        for round in 0..10 {
            let a = Arc::new(Authorities::new(&format!(
                "start-limiter-rolling-race-{round}"
            )));
            // 10 live records, then a full bucket at 50 s: only 2 more fit in the window.
            for _ in 0..4 {
                assert_eq!(decide(&a.er), StartLimit::Admitted);
            }
            for second in (5..=30).step_by(5) {
                a.lr.set(secs(second));
                assert_eq!(decide(&a.er), StartLimit::Admitted);
            }
            a.lr.set(secs(50));
            assert_eq!(admitted(&contend(&a)), 2);
            assert_limiter(&a, 2, 12);
            Arc::into_inner(a).unwrap().release();
        }
    }

    // R-OWNER-037 (c), (d): one limiter per authority, shared by every label.
    #[test]
    fn authorities_are_independent_and_labels_share_one_limiter() {
        let (a, b) = (
            Authorities::new("start-limiter-scope-a"),
            Authorities::new("start-limiter-scope-b"),
        );
        // Both at the same numeric instant, five candidates each.
        let expected = [
            StartLimit::Admitted,
            StartLimit::Admitted,
            StartLimit::Admitted,
            StartLimit::Admitted,
            StartLimit::Refused,
        ];
        for authority in [&a, &b] {
            let outcomes: Vec<_> = (0..5).map(|_| decide(&authority.er)).collect();
            assert_eq!(outcomes, expected);
        }
        assert_eq!(limiter(&a), limiter(&b));

        // Rotating request IDs and application identities buys no extra capacity.
        b.lr.set(secs(60));
        for label in 0..4u8 {
            let start = start_as(&[label + 1; 16], &[b'p', label]);
            drop(present_valid(&b, &start).unwrap());
        }
        for (request_id, identity) in [(&[0xEE; 64][..], &b"rotated"[..]), (&[0x01], b"x")] {
            assert_eq!(
                present_valid(&b, &start_as(request_id, identity)).err(),
                Some(RESOURCE_LIMITED)
            );
        }
        assert_limiter(&b, 0, 4);
        assert_no_resources(&b);
        assert_limiter(&a, 0, 4);
        a.release();
        b.release();
    }

    // P3 4 / 10: an exact duplicate START for an existing run is not a new candidate.
    #[test]
    fn existing_run_duplicate_start_never_reaches_the_limiter() {
        let a = Authorities::new("start-limiter-duplicate");
        let start = vector("START");
        let mut run = present_valid(&a, &start).unwrap();
        assert_limiter(&a, 3, 1);
        for _ in 0..10 {
            run.receive_start_duplicate(&start).unwrap();
        }
        assert_limiter(&a, 3, 1);
        // Even with the limiter exhausted the duplicate is still handled by its run.
        for _ in 0..3 {
            drop(present_valid(&a, &start).unwrap());
        }
        assert_eq!(decide(&a.er), StartLimit::Refused);
        let exhausted = limiter(&a);
        run.receive_start_duplicate(&start).unwrap();
        assert_eq!(limiter(&a), exhausted);
        assert_eq!(pending(&a.er), 1, "no second pending run");
        drop(run);
        a.release();
    }

    // R-OWNER-038 (a): ceremony events never reset the limiter; only time changes it.
    #[test]
    fn ceremony_events_never_reset_the_limiter() {
        let a = Authorities::new("start-limiter-lifetime");
        let mut run = present_valid(&a, &vector("START")).unwrap();
        assert_limiter(&a, 3, 1);
        run.terminate().unwrap();
        drop(run);
        assert_limiter(&a, 3, 1);
        assert!(present_valid(&a, &raw_start(&vector_request_id(), &[0xFF; 3])).is_err());
        assert_limiter(&a, 2, 2);

        // A complete successful ceremony, then status queries.
        let i = RemoteCeremony::initiator_with_fixed_start_for_test(
            a.ei.clone(),
            a.ei.begin(Role::Initiator).unwrap(),
            &vector("START"),
            bootstrap(&decoded("START"), true),
            None,
        )
        .unwrap();
        let mut pair = exchange_keys(&a, i, system_clock());
        assert_limiter(&a, 1, 3);
        let id = pair.identity();
        authenticate(&mut pair, &id);
        let i_finish = finish(&mut pair.i);
        let r_ack = responder_ack(&mut pair.r, &i_finish);
        let i_ack = initiator_ack(&mut pair.i, &r_ack);
        confirm_sent(&mut pair.i, &i_ack);
        assert_eq!(
            pair.r.receive_completion(&i_ack),
            Ok(CompletionReceipt::Succeeded)
        );
        assert_eq!(a.er.status().unwrap(), Status::Ready { remaining: 9 });
        drop(pair);
        assert_limiter(&a, 1, 3);

        // Idle time only refills toward 4 and ages the t=0 records out at exactly 60 s.
        a.lr.set(secs(59));
        assert_eq!(decide(&a.er), StartLimit::Admitted);
        assert_limiter(&a, 3, 4);
        a.lr.set(secs(60));
        assert_eq!(decide(&a.er), StartLimit::Admitted);
        assert_limiter(&a, 2, 2);
        a.release();
    }

    // R-OWNER-038 (b), (c): only a safely established new owner starts fresh.
    #[test]
    fn a_safely_replaced_owner_starts_with_a_fresh_limiter() {
        let scope = b"start-limiter-owner";
        let clock = ManualClock::new();
        let owner = TrustedAuthority::register_with_limiter_clock(scope, clock.clone()).unwrap();
        let executor = owner.executor();
        for _ in 0..4 {
            assert_eq!(decide(&executor), StartLimit::Admitted);
        }
        assert_eq!(decide(&executor), StartLimit::Refused);
        clock.set(secs(3));
        // While the owner exists no second owner, and so no second limiter, can be created.
        assert_eq!(
            TrustedAuthority::register_with_limiter_clock(scope, clock.clone()).unwrap_err(),
            OwnerError::AlreadyRegistered
        );
        assert_eq!(decide(&executor), StartLimit::Refused);
        let state = executor.start_limiter_snapshot();
        assert_eq!((state.tokens, state.rolling), (0, 4));
        drop(executor);
        owner.release().unwrap();

        let replacement = TrustedAuthority::register_with_limiter_clock(scope, clock).unwrap();
        let executor = replacement.executor();
        assert_eq!(
            executor.start_limiter_snapshot(),
            StartLimiterSnapshot {
                tokens: 4,
                remainder: Duration::ZERO,
                last: Duration::ZERO,
                rolling: 0,
            }
        );
        for _ in 0..4 {
            assert_eq!(decide(&executor), StartLimit::Admitted);
        }
        assert_eq!(decide(&executor), StartLimit::Refused);
        drop(executor);
        replacement.release().unwrap();
    }

    // R-OWNER-039: an unusable limiter clock admits nothing and changes nothing.
    #[test]
    fn unsafe_limiter_clock_fails_closed_without_mutation() {
        let a = Authorities::new("start-limiter-clock");
        a.lr.set(secs(10));
        drop(present_valid(&a, &vector("START")).unwrap());
        let before = limiter(&a);
        assert_eq!(
            (before.tokens, before.rolling, before.last),
            (3, 1, secs(10))
        );

        a.lr.fail();
        assert_eq!(
            present_valid(&a, &vector("START")).err(),
            Some(CeremonyError::ClockUnavailable)
        );
        assert_eq!(limiter(&a), before);
        assert_no_resources(&a);

        // Backwards relative to the last evaluation: no refill, expiry, charge, or record.
        for value in [secs(10) - NS, secs(5), Duration::ZERO] {
            a.lr.set(value);
            assert_eq!(
                present_valid(&a, &vector("START")).err(),
                Some(CeremonyError::ClockUnavailable)
            );
            assert_eq!(decide(&a.er), StartLimit::UnsafeClock);
            assert_eq!(limiter(&a), before);
        }
        assert_no_resources(&a);

        // A safe reading continues from the unchanged state: no reset, no healing.
        a.lr.set(secs(10));
        drop(present_valid(&a, &vector("START")).unwrap());
        assert_limiter(&a, 2, 2);
        a.lr.set(secs(70));
        assert_eq!(decide(&a.er), StartLimit::Admitted);
        assert_limiter(&a, 3, 1);
        a.release();
    }

    /// Records whether each reading happens while the authority's shared state is locked.
    struct ProbeClock {
        state: std::sync::OnceLock<std::sync::Weak<crate::State>>,
        inside: AtomicUsize,
        outside: AtomicUsize,
    }

    impl crate::deadline::MonotonicClock for ProbeClock {
        fn now(&self) -> Option<Duration> {
            let state = self.state.get()?.upgrade()?;
            let counter = match state.shared.try_lock() {
                Err(std::sync::TryLockError::WouldBlock) => &self.inside,
                _ => &self.outside,
            };
            counter.fetch_add(1, AtomicOrdering::SeqCst);
            Some(Duration::ZERO)
        }
    }

    // R-OWNER-039: `now` is read inside the atomic decision, never as an earlier stale reading.
    #[test]
    fn the_limiter_clock_is_read_inside_the_shared_critical_section() {
        let probe = Arc::new(ProbeClock {
            state: std::sync::OnceLock::new(),
            inside: AtomicUsize::new(0),
            outside: AtomicUsize::new(0),
        });
        let authority =
            TrustedAuthority::register_with_limiter_clock(b"start-limiter-probe", probe.clone())
                .unwrap();
        probe.state.set(Arc::downgrade(&authority.0)).unwrap();
        let executor = authority.executor();
        for _ in 0..5 {
            decide(&executor);
        }
        let reads = (
            probe.inside.load(AtomicOrdering::SeqCst),
            probe.outside.load(AtomicOrdering::SeqCst),
        );
        assert_eq!(reads, (5, 0));
        drop(executor);
        authority.release().unwrap();
    }
}
