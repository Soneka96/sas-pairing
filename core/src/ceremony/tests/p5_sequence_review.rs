//! P5.2 review-only evidence (NOT part of the product; changes no production behavior):
//! bounded, deterministic, generated adversarial sequences over `RemoteCeremony`, explored for
//! each role independently. Families `SM-I-*`, `SM-R-*`, `DUP-*`, and `DEADLINE-*` in
//! `docs/p5-security-review/adversarial-sequences.md`.
//!
//! Method. A `World` holds the target run and an honest peer (a real `RemoteCeremony` of the
//! other role) that answers in lockstep: every frame the target produces is delivered to the
//! peer, which then takes its own legal local steps eagerly, and the peer's frames queue for
//! the target. Every honest prefix of one complete ceremony (one per reachable honest state) is
//! followed by every sequence of at most `depth` actions over a reduced alphabet (`Act`), then
//! by a fixed terminal postfix. Expansion stops at a terminal state. There is no randomness.
//!
//! Oracle. It tracks only high-level observations (terminality, result count, exposure count,
//! outputs by type, request-ID and pending-slot accounting, the guard, honest versus injected
//! input) and asserts relationships between them after every step. It does not re-implement
//! the protocol state machine.
use super::*;
use std::{collections::VecDeque, fmt::Write as _, sync::OnceLock};

/// Fixture values, parsed once (the vector file is large; re-parsing it per sequence would
/// dominate the run time).
struct Fixture {
    start: Vec<u8>,
    initiator: Bootstrap,
    responder: Bootstrap,
    request_id: [u8; 16],
}

fn fx() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| Fixture {
        start: vector("START"),
        initiator: bootstrap(&decoded("START"), true),
        responder: bootstrap(&decoded("ACCEPT"), false),
        request_id: vector_request_id().try_into().unwrap(),
    })
}

/// One abstract action applied to the target run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Act {
    // Network input.
    /// The honest peer's next frame.
    Next,
    /// Exact copy of the last honest frame the target accepted.
    DupLast,
    /// Exact copy of the first honest frame the target accepted (an older message).
    DupFirst,
    /// The last accepted frame with its final byte changed (a changed duplicate).
    ChangedLast,
    /// The honest next frame with its final byte changed (tag, key, or context corruption).
    CorruptNext,
    /// The honest next frame under another request ID.
    WrongIdNext,
    /// The honest next frame without its final byte (malformed).
    TruncNext,
    /// The same protocol step from an independent ceremony with the same request ID.
    Foreign,
    /// A later step of the independent ceremony (skips ahead).
    Future,
    /// The target's own last output delivered back to it (reflection).
    Reflect,
    /// The last accepted frame under another request ID (duplicate matrix only).
    WrongIdLast,
    /// The last accepted bidirectional frame with its sender flipped (duplicate matrix only).
    WrongRoleLast,
    /// The honest next bidirectional frame (BOOTSTRAP_MAC/CANCEL) with its sender role flipped.
    WrongRole,
    /// The honest peer's authenticated local CANCEL (only once the peer holds a live SAS).
    PeerCancel,
    // Trusted local actions.
    Authorize,
    Expose,
    /// MATCH for the live `ceremony_identity` (or a zero identity before one exists).
    Approve,
    /// MATCH for an identity that is not this run's.
    ApproveStale,
    Reject,
    Cancel,
    EmitMac,
    EmitFinish,
    /// Final-ACK send confirmation with the exact pending bytes.
    Confirm,
    /// Final-ACK send confirmation with other bytes.
    ConfirmWrong,
    // Lifecycle.
    /// Deadline poll without time passing.
    Poll,
    /// The absolute deadline passes, then a poll.
    Expire,
    /// Local termination (session or connection teardown).
    Close,
}
use Act::*;

/// The exploration alphabet, in a fixed order.
const ALPHABET: [Act; 25] = [
    Next,
    DupLast,
    DupFirst,
    ChangedLast,
    CorruptNext,
    WrongIdNext,
    TruncNext,
    Foreign,
    Future,
    Reflect,
    WrongRole,
    PeerCancel,
    Authorize,
    Expose,
    Approve,
    ApproveStale,
    Reject,
    Cancel,
    EmitMac,
    EmitFinish,
    Confirm,
    ConfirmWrong,
    Poll,
    Expire,
    Close,
];

/// One honest complete ceremony from the target's side, one action per honest state.
fn honest_path(role: Role) -> &'static [Act] {
    match role {
        Role::Initiator => &[
            Next, Authorize, Expose, Next, Approve, EmitMac, Next, EmitFinish, Next, Confirm,
        ],
        Role::Responder => &[Next, Authorize, Expose, Next, Approve, EmitMac, Next, Next],
    }
}

/// Post-terminal battery (P5.2 §12): nothing here may produce a result, an outbound security
/// frame, an exposure, or any state change.
const POSTFIX: [Act; 12] = [
    Next, DupLast, Approve, Cancel, Reject, Authorize, Expose, EmitMac, EmitFinish, Confirm, Poll,
    Close,
];

/// Local refusals that must leave the run exactly as it was.
fn refusal_without_effect(error: &CeremonyError) -> bool {
    matches!(
        error,
        CeremonyError::NoLiveSas
            | CeremonyError::CeremonyIdentityMismatch
            | CeremonyError::NotLocallyApproved
            | CeremonyError::ApprovalsNotAuthenticated
            | CeremonyError::NotInitiator
            | CeremonyError::NoPendingFinalAck
            | CeremonyError::FinalAckMismatch
            | CeremonyError::Completed
    )
}

fn is_network(act: Act) -> bool {
    matches!(
        act,
        Next | DupLast
            | DupFirst
            | ChangedLast
            | CorruptNext
            | WrongIdNext
            | TruncNext
            | Foreign
            | Future
            | Reflect
            | WrongIdLast
            | WrongRoleLast
            | WrongRole
            | PeerCancel
    )
}

fn flip_last(frame: &[u8]) -> Vec<u8> {
    let mut changed = frame.to_vec();
    *changed.last_mut().unwrap() ^= 0x01;
    changed
}

fn with_request_id(frame: &[u8], id: &[u8]) -> Vec<u8> {
    let mut message = protocol::decode(frame).unwrap().message;
    match &mut message {
        Message::Start { request_id, .. }
        | Message::Accept { request_id, .. }
        | Message::InitiatorKey { request_id, .. }
        | Message::ResponderKey { request_id, .. }
        | Message::BootstrapMac { request_id, .. }
        | Message::InitiatorFinish { request_id, .. }
        | Message::ResponderFinishAck { request_id, .. }
        | Message::InitiatorFinishAck { request_id, .. }
        | Message::Cancel { request_id, .. } => *request_id = id.to_vec(),
    }
    message.encode().unwrap()
}

fn with_flipped_sender(frame: &[u8]) -> Option<Vec<u8>> {
    let mut message = protocol::decode(frame).unwrap().message;
    match &mut message {
        Message::BootstrapMac { sender, .. } | Message::Cancel { sender, .. } => {
            *sender = other(*sender);
        }
        _ => return None,
    }
    Some(message.encode().unwrap())
}

fn kind(frame: &[u8]) -> u8 {
    frame[9]
}

/// Wire sender of a produced frame (both roles produce BOOTSTRAP_MAC and CANCEL).
fn sender_of(frame: &[u8]) -> protocol::Role {
    match protocol::decode(frame).unwrap().message {
        Message::Start { .. }
        | Message::InitiatorKey { .. }
        | Message::InitiatorFinish { .. }
        | Message::InitiatorFinishAck { .. } => protocol::Role::Initiator,
        Message::Accept { .. }
        | Message::ResponderKey { .. }
        | Message::ResponderFinishAck { .. } => protocol::Role::Responder,
        Message::BootstrapMac { sender, .. } | Message::Cancel { sender, .. } => sender,
    }
}

fn own(role: Role) -> protocol::Role {
    wire_role(role)
}

/// A request-ID source with exactly one scripted ID (a collision fails loudly, never loops).
struct OnceId(Option<[u8; 16]>);
impl RequestIdGenerator for OnceId {
    fn generate(&mut self) -> Option<[u8; 16]> {
        self.0.take()
    }
}

/// Resets the shared authorities between sequences: every earlier run is gone (asserted, so a
/// leaked guard, slot, permit, or reservation fails the sequence that leaked it), the budget is
/// full again, and both START limiters have credit.
fn reset(a: &Authorities) {
    for executor in [&a.ei, &a.er] {
        let mut shared = executor.0.shared.lock().unwrap();
        assert_eq!(shared.active, None, "leaked exposed-ceremony guard");
        assert_eq!(shared.pending_responders, 0, "leaked pending slot");
        assert_eq!(
            shared.preliminary_operations, 0,
            "leaked preliminary permit"
        );
        assert!(
            shared.initiator_request_ids.is_empty(),
            "leaked request-ID reservation"
        );
        shared.remaining = crate::MAX_OPPORTUNITIES;
    }
    refill_start_limiters(a);
}

/// The peer-role frames of one independent complete ceremony with the same START, in protocol
/// order: for an Initiator target `[ACCEPT, R_KEY, R_BMAC, R_FACK]`, for a Responder target
/// `[START, I_KEY, I_BMAC, I_FIN, I_FACK]`.
fn foreign_frames(a: &Authorities, role: Role) -> Vec<Vec<u8>> {
    reset(a);
    let mut i = RemoteCeremony::initiator_with(
        ManualClock::new(),
        &mut OnceId(Some(fx().request_id)),
        a.ei.clone(),
        a.ei.begin(Role::Initiator).unwrap(),
        fx().initiator.clone(),
        None,
    )
    .unwrap();
    let start = i.start().unwrap();
    let (mut r, accept) = RemoteCeremony::responder_with_clock(
        ManualClock::new(),
        a.er.clone(),
        a.er.begin(Role::Responder).unwrap(),
        &start,
        fx().responder.clone(),
        None,
    )
    .unwrap();
    i.receive_accept(&accept).unwrap();
    i.authorize(&a.i).unwrap();
    let ikey = i.expose_key().unwrap();
    r.receive_initiator_key(&ikey).unwrap();
    r.authorize(&a.r).unwrap();
    let rkey = r.expose_key().unwrap();
    i.receive_responder_key(&rkey).unwrap();
    let id = *i.presentation().unwrap().ceremony_identity();
    let i_mac = approve_and_emit(&mut i, &id);
    let r_mac = approve_and_emit(&mut r, &id);
    i.receive_bootstrap_mac(&r_mac).unwrap();
    r.receive_bootstrap_mac(&i_mac).unwrap();
    let i_fin = finish(&mut i);
    let r_fack = responder_ack(&mut r, &i_fin);
    let i_fack = initiator_ack(&mut i, &r_fack);
    confirm_sent(&mut i, &i_fack);
    assert_eq!(
        r.receive_completion(&i_fack),
        Ok(CompletionReceipt::Succeeded)
    );
    drop((i, r));
    reset(a);
    match role {
        Role::Initiator => vec![accept, rkey, r_mac, r_fack],
        Role::Responder => vec![start, ikey, i_mac, i_fin, i_fack],
    }
}

/// High-level observations of one sequence.
#[derive(Debug, Default)]
struct Obs {
    results: usize,
    exposures: usize,
    authorized: usize,
    approved: bool,
    own_mac: bool,
    peer_mac: bool,
    /// Honest completion frames the target verified (R: I_FIN and I_FACK; I: R_FACK).
    completions: usize,
    confirmed: bool,
    /// An injected (non-honest) frame was accepted without error.
    tainted: bool,
    /// The wire type of the first such frame.
    tainted_kind: Option<u8>,
}

/// Exploration totals, reported by each family.
#[derive(Debug, Default)]
struct Stats {
    sequences: usize,
    prefixes: usize,
    terminal_leaves: usize,
    results: usize,
    /// Injected frames accepted without error, by wire type: only unauthenticated
    /// pre-SAS contributions may appear here.
    tainted_by_kind: [usize; 10],
    max_suffix: usize,
    steps: usize,
    /// Nodes not expanded because their last action was a verified no-op (`reduce` only).
    pruned_noop: usize,
}

/// Everything about the target that a later action could depend on, compared before and
/// after an action. The deadline probe evaluates both deadlines at fixed instants, so it
/// reveals whether either origin moved (a refresh) without reading private deadline fields.
#[derive(Debug, PartialEq, Eq)]
struct Fingerprint {
    label: &'static str,
    seen: Vec<(u8, Vec<u8>)>,
    deadline_probe: [Verdict; 4],
    admission: (bool, bool, Option<[u8; 16]>, Option<Duration>),
    sas: Option<[u8; 6]>,
    result: Option<PairingResult>,
    world: (usize, usize, usize, Option<Vec<u8>>, &'static str),
}

struct World<'a> {
    a: &'a Authorities,
    role: Role,
    target: RemoteCeremony,
    peer: RemoteCeremony,
    clock: Arc<ManualClock>,
    /// Honest peer frames produced and not yet delivered to the target.
    inbox: VecDeque<Vec<u8>>,
    /// Honest peer frames the target accepted as new input, in order.
    accepted: Vec<Vec<u8>>,
    /// Every honest frame either side produced.
    honest: Vec<Vec<u8>>,
    /// The target's outputs, in order.
    outputs: Vec<Vec<u8>>,
    identity: Option<[u8; 32]>,
    peer_identity: Option<[u8; 32]>,
    final_ack: Option<Vec<u8>>,
    result: Option<PairingResult>,
    foreign: &'a [Vec<u8>],
    obs: Obs,
    trace: Vec<Act>,
    limiter: StartLimiterSnapshot,
    /// Suffix phase: one second passes before every action, so a wrongful deadline refresh
    /// would move an origin visibly.
    timed: bool,
    /// The last action left the fingerprint unchanged.
    last_noop: bool,
}

/// Before-step snapshot.
struct Snap {
    finished: bool,
    label: &'static str,
    outputs: usize,
    exposures: usize,
    sas: bool,
}

impl<'a> World<'a> {
    fn new(a: &'a Authorities, role: Role, foreign: &'a [Vec<u8>]) -> Self {
        reset(a);
        let clock = ManualClock::new();
        let (target, peer, start, accept) = match role {
            Role::Initiator => {
                let mut target = RemoteCeremony::initiator_with(
                    clock.clone(),
                    &mut OnceId(Some(fx().request_id)),
                    a.ei.clone(),
                    a.ei.begin(Role::Initiator).unwrap(),
                    fx().initiator.clone(),
                    None,
                )
                .unwrap();
                let start = target.start().unwrap();
                let (peer, accept) = RemoteCeremony::responder_with_clock(
                    ManualClock::new(),
                    a.er.clone(),
                    a.er.begin(Role::Responder).unwrap(),
                    &start,
                    fx().responder.clone(),
                    None,
                )
                .unwrap();
                (target, peer, start, accept)
            }
            Role::Responder => {
                let mut peer = RemoteCeremony::initiator_with(
                    ManualClock::new(),
                    &mut OnceId(Some(fx().request_id)),
                    a.ei.clone(),
                    a.ei.begin(Role::Initiator).unwrap(),
                    fx().initiator.clone(),
                    None,
                )
                .unwrap();
                let start = peer.start().unwrap();
                let (target, accept) = RemoteCeremony::responder_with_clock(
                    clock.clone(),
                    a.er.clone(),
                    a.er.begin(Role::Responder).unwrap(),
                    &start,
                    fx().responder.clone(),
                    None,
                )
                .unwrap();
                (target, peer, start, accept)
            }
        };
        assert_eq!(start, fx().start);
        let mut world = Self {
            a,
            role,
            target,
            peer,
            clock,
            inbox: VecDeque::new(),
            accepted: Vec::new(),
            honest: vec![start.clone(), accept.clone()],
            outputs: Vec::new(),
            identity: None,
            peer_identity: None,
            final_ack: None,
            result: None,
            foreign,
            obs: Obs::default(),
            trace: Vec::new(),
            limiter: a.er.start_limiter_snapshot(),
            timed: false,
            last_noop: false,
        };
        match role {
            Role::Initiator => {
                world.outputs.push(start);
                world.inbox.push_back(accept);
            }
            Role::Responder => {
                world.accepted.push(start);
                world.outputs.push(accept.clone());
                world.forward(&accept);
            }
        }
        world
    }

    fn target_executor(&self) -> &CeremonyExecutor {
        match self.role {
            Role::Initiator => &self.a.ei,
            Role::Responder => &self.a.er,
        }
    }
    fn target_authority(&self) -> &'a TrustedAuthority {
        match self.role {
            Role::Initiator => &self.a.i,
            Role::Responder => &self.a.r,
        }
    }
    fn peer_authority(&self) -> &'a TrustedAuthority {
        match self.role {
            Role::Initiator => &self.a.r,
            Role::Responder => &self.a.i,
        }
    }

    /// Delivers one target output to the honest peer, then lets the peer take every legal
    /// local step it can; its frames queue for the target.
    fn forward(&mut self, frame: &[u8]) {
        if self.peer.is_finished() {
            return;
        }
        let peer = &mut self.peer;
        let reply = match kind(frame) {
            1 => peer.receive_start_duplicate(frame).map(|()| None),
            2 => peer.receive_accept(frame).map(|()| None),
            3 => peer.receive_initiator_key(frame).map(|()| None),
            4 => peer.receive_responder_key(frame).map(|()| None),
            5 => peer.receive_bootstrap_mac(frame).map(|_| None),
            6..=8 => peer.receive_completion(frame).map(|receipt| match receipt {
                CompletionReceipt::SendResponderFinishAck(ack)
                | CompletionReceipt::SendInitiatorFinishAck(ack) => Some(ack),
                _ => None,
            }),
            _ => peer.receive_cancel(frame).map(|_| None),
        };
        if let Ok(Some(reply)) = reply {
            if kind(&reply) == 8 {
                // The honest peer Initiator's own send boundary.
                self.peer.confirm_initiator_finish_ack_sent(&reply).unwrap();
            }
            self.emit_peer(reply);
        }
        self.advance_peer();
    }

    fn emit_peer(&mut self, frame: Vec<u8>) {
        self.honest.push(frame.clone());
        self.inbox.push_back(frame);
    }

    fn advance_peer(&mut self) {
        loop {
            if self.peer.is_finished() {
                return;
            }
            let frame = match self.peer.state_label_for_test() {
                "InitiatorAwaitAuthorization" | "ResponderAwaitAuthorization" => {
                    let authority = self.peer_authority();
                    self.peer.authorize(authority).unwrap();
                    self.peer.expose_key().unwrap()
                }
                "AwaitLocalApproval" => {
                    let id = *self.peer.presentation().unwrap().ceremony_identity();
                    self.peer_identity = Some(id);
                    approve_and_emit(&mut self.peer, &id)
                }
                "ApprovalsAuthenticatedAwaitingCompletion" if self.role == Role::Responder => {
                    finish(&mut self.peer)
                }
                _ => return,
            };
            self.emit_peer(frame);
        }
    }

    /// One inbound frame through the target entrypoint the Router would choose for its type.
    fn deliver(&mut self, frame: &[u8]) -> Result<Option<Vec<u8>>, CeremonyError> {
        let target = &mut self.target;
        match kind(frame) {
            1 => target.receive_start_duplicate(frame).map(|()| None),
            2 => target.receive_accept(frame).map(|()| None),
            3 => target.receive_initiator_key(frame).map(|()| None),
            4 => target.receive_responder_key(frame).map(|()| None),
            5 => target.receive_bootstrap_mac(frame).map(|_| None),
            6..=8 => target
                .receive_completion(frame)
                .map(|receipt| match receipt {
                    CompletionReceipt::SendResponderFinishAck(ack)
                    | CompletionReceipt::SendInitiatorFinishAck(ack) => Some(ack),
                    CompletionReceipt::Succeeded | CompletionReceipt::AlreadyAccepted => None,
                }),
            _ => target.receive_cancel(frame).map(|_| None),
        }
    }

    fn identity_or_zero(&self) -> [u8; 32] {
        self.identity.unwrap_or([0; 32])
    }

    /// The frame `act` would inject, if it is applicable now.
    fn injected(&self, act: Act) -> Option<Vec<u8>> {
        let next = self.inbox.front();
        let position = self.accepted.len();
        match act {
            Next => next.cloned(),
            DupLast => self.accepted.last().cloned(),
            DupFirst => (self.accepted.len() >= 2).then(|| self.accepted[0].clone()),
            ChangedLast => self.accepted.last().map(|f| flip_last(f)),
            CorruptNext => next.map(|f| flip_last(f)),
            WrongIdNext => next.map(|f| with_request_id(f, &[0x5A; 16])),
            TruncNext => next.map(|f| f[..f.len() - 1].to_vec()),
            Foreign => self.foreign.get(position).cloned(),
            Future => self.foreign.get(position + 1).cloned(),
            Reflect => self.outputs.last().cloned(),
            WrongIdLast => self
                .accepted
                .last()
                .map(|f| with_request_id(f, &[0x5A; 16])),
            WrongRoleLast => self.accepted.last().and_then(|f| with_flipped_sender(f)),
            WrongRole => next.and_then(|f| with_flipped_sender(f)),
            _ => None,
        }
    }

    fn applicable(&self, act: Act) -> bool {
        match act {
            PeerCancel => !self.peer.is_finished() && self.peer.sas_bytes_for_test().is_some(),
            ConfirmWrong => self.final_ack.is_some(),
            act if is_network(act) => self.injected(act).is_some(),
            _ => true,
        }
    }

    fn snap(&self) -> Snap {
        Snap {
            finished: self.target.is_finished(),
            label: self.target.state_label_for_test(),
            outputs: self.outputs.len(),
            exposures: self.obs.exposures,
            sas: self.target.sas_bytes_for_test().is_some(),
        }
    }

    fn fingerprint(&self) -> Fingerprint {
        let t = &self.target;
        let probe = |at: Duration, mode| t.deadlines.evaluate(Some(at), mode);
        Fingerprint {
            label: t.state_label_for_test(),
            seen: t.seen.clone(),
            deadline_probe: [
                probe(INACTIVITY_DEADLINE - NS, Inactivity::Running),
                probe(INACTIVITY_DEADLINE, Inactivity::Running),
                probe(ABSOLUTE_DEADLINE - NS, Inactivity::Suspended),
                probe(ABSOLUTE_DEADLINE, Inactivity::Suspended),
            ],
            admission: (
                t.admission.terminal,
                t.admission.authorization.is_some(),
                t.admission.request_id,
                t.admission.pending_responder,
            ),
            sas: t.sas_bytes_for_test(),
            result: t.result().cloned(),
            world: (
                self.inbox.len(),
                self.accepted.len(),
                self.outputs.len(),
                self.final_ack.clone(),
                self.peer.state_label_for_test(),
            ),
        }
    }

    fn context(&self) -> String {
        format!("{:?} trace {:?}", self.role, self.trace)
    }

    /// Applies `act` (which must be applicable) and checks every invariant.
    fn apply(&mut self, act: Act) {
        self.trace.push(act);
        if self.timed {
            self.clock.advance(Duration::from_secs(1));
        }
        let fingerprint = self.fingerprint();
        let mut idempotent = false;
        let before = self.snap();
        let had_result = self.target.result().cloned();
        let mut frame_in: Option<Vec<u8>> = None;
        let outcome: Result<Option<Vec<u8>>, CeremonyError> = match act {
            Next => {
                let frame = self.inbox.pop_front().unwrap();
                let outcome = self.deliver(&frame);
                if outcome.is_ok() {
                    self.accepted.push(frame.clone());
                }
                frame_in = Some(frame);
                outcome
            }
            PeerCancel => {
                let id = self.peer_identity.unwrap();
                let frame = match self.peer.cancel_sas(&id).unwrap() {
                    LocalCancellation::Emitted(bytes) => bytes,
                    LocalCancellation::NotEmitted => panic!("honest peer built no CANCEL"),
                };
                self.honest.push(frame.clone());
                // The honest peer stops: nothing more of it is in flight.
                self.inbox.clear();
                let outcome = self.deliver(&frame);
                frame_in = Some(frame);
                outcome
            }
            act if is_network(act) => {
                let frame = self.injected(act).unwrap();
                let outcome = self.deliver(&frame);
                frame_in = Some(frame);
                outcome
            }
            Authorize => {
                let authority = self.target_authority();
                let outcome = self.target.authorize(authority).map(|()| None);
                if outcome.is_ok() {
                    self.obs.authorized += 1;
                }
                outcome
            }
            Expose => self.target.expose_key().map(Some),
            Approve => {
                let id = self.identity_or_zero();
                self.target.approve_sas(&id).map(|approval| {
                    match approval {
                        SasApproval::Recorded => self.obs.approved = true,
                        SasApproval::AlreadyRecorded => idempotent = true,
                    }
                    None
                })
            }
            ApproveStale => self.target.approve_sas(&[0xAB; 32]).map(|_| None),
            Reject | Cancel => {
                let id = self.identity_or_zero();
                let outcome = if act == Reject {
                    self.target.reject_sas(&id)
                } else {
                    self.target.cancel_sas(&id)
                };
                outcome.map(|cancel| match cancel {
                    LocalCancellation::Emitted(bytes) => Some(bytes),
                    LocalCancellation::NotEmitted => None,
                })
            }
            EmitMac => self
                .target
                .emit_bootstrap_mac()
                .map(|emission| match emission {
                    BootstrapMacEmission::Emitted(bytes) => {
                        self.obs.own_mac = true;
                        Some(bytes)
                    }
                    BootstrapMacEmission::AlreadyEmitted => {
                        idempotent = true;
                        None
                    }
                }),
            EmitFinish => self
                .target
                .emit_initiator_finish()
                .map(|emission| match emission {
                    FinishEmission::Emitted(bytes) => Some(bytes),
                    FinishEmission::AlreadyEmitted => {
                        idempotent = true;
                        None
                    }
                }),
            Confirm => {
                let sent = self
                    .final_ack
                    .clone()
                    .unwrap_or_else(|| b"no pending final ack".to_vec());
                self.target
                    .confirm_initiator_finish_ack_sent(&sent)
                    .map(|()| None)
            }
            ConfirmWrong => {
                let sent = flip_last(self.final_ack.as_ref().unwrap());
                self.target
                    .confirm_initiator_finish_ack_sent(&sent)
                    .map(|()| None)
            }
            Poll => self.poll(&before),
            Expire => {
                self.clock.advance(ABSOLUTE_DEADLINE);
                self.poll(&before)
            }
            Close => self.target.terminate().map(|()| None),
            _ => unreachable!(),
        };
        let output = outcome.as_ref().ok().cloned().flatten();
        if let Some(frame) = &output {
            self.outputs.push(frame.clone());
            if kind(frame) == 8 {
                self.final_ack = Some(frame.clone());
            }
        }
        let expect_noop = self.check(act, &before, had_result, frame_in.as_deref(), &outcome);
        if let Some(frame) = output {
            self.forward(&frame);
        }
        if let Some(shown) = self.target.presentation() {
            self.identity = Some(*shown.ceremony_identity());
        }
        self.last_noop = self.fingerprint() == fingerprint;
        if expect_noop || idempotent {
            // Duplicates, idempotent repeats, polls, and refusals change nothing at all: no
            // state, duplicate record, accounting, output, or deadline origin.
            assert_eq!(
                self.fingerprint(),
                fingerprint,
                "{}: expected no effect",
                self.context()
            );
        }
    }

    /// `poll_deadlines`, with its timeout CANCEL as the output.
    fn poll(&mut self, before: &Snap) -> Result<Option<Vec<u8>>, CeremonyError> {
        let polled = self.target.poll_deadlines();
        let context = self.context();
        match polled {
            Ok(DeadlineOutcome::Active) => {
                assert!(!before.finished, "{context}");
                Ok(None)
            }
            Ok(DeadlineOutcome::Finished) => {
                assert!(before.finished, "{context}");
                Ok(None)
            }
            Ok(DeadlineOutcome::TimedOut(timeout)) => {
                assert!(!before.finished, "{context}");
                assert_eq!(timeout.expired(), Deadline::Absolute, "{context}");
                // An authenticated timeout CANCEL exists exactly when a shared SAS did.
                assert_eq!(timeout.cancel().is_some(), before.sas, "{context}");
                Ok(timeout.cancel().map(<[u8]>::to_vec))
            }
            Ok(DeadlineOutcome::PendingExpired) => {
                panic!("{context}: absolute deadline is reported first")
            }
            Err(error) => Err(error),
        }
    }

    /// Checks every invariant for one step; returns whether the step must have had no effect.
    fn check(
        &mut self,
        act: Act,
        before: &Snap,
        had_result: Option<PairingResult>,
        frame_in: Option<&[u8]>,
        outcome: &Result<Option<Vec<u8>>, CeremonyError>,
    ) -> bool {
        let context = self.context();
        let was_tainted = self.obs.tainted;
        let after = self.snap();
        let produced = self.outputs.len() - before.outputs;
        let result = self.target.result().cloned();
        let new_result = had_result.is_none() && result.is_some();

        // Terminal irreversibility (I1/I2): a finished run never changes again.
        if before.finished {
            assert!(after.finished, "{context}: revived");
            assert_eq!(after.label, before.label, "{context}: state changed");
            assert_eq!(produced, 0, "{context}: output after terminal");
            assert_eq!(
                result, had_result,
                "{context}: result changed after terminal"
            );
            assert_eq!(self.obs.exposures, before.exposures, "{context}");
        }
        assert!(produced <= 1, "{context}");
        if act == Expose && outcome.is_ok() {
            self.obs.exposures += 1;
        }

        // Exposure accounting: at most one contribution per run, only after authorization.
        assert!(self.obs.exposures <= 1, "{context}: second exposure");
        if self.obs.exposures > before.exposures {
            assert!(
                self.obs.authorized >= 1,
                "{context}: exposure before authorization"
            );
        }
        let executor = self.target_executor();
        let remaining = executor.0.shared.lock().unwrap().remaining;
        assert_eq!(
            usize::from(remaining) + self.obs.exposures,
            usize::from(crate::MAX_OPPORTUNITIES),
            "{context}: budget changed other than by this run's one exposure"
        );
        // Guard: held exactly while this exposed run is live; never by an unexposed run.
        let busy = executor.status().unwrap() == Status::Busy;
        assert_eq!(
            busy,
            self.obs.exposures == 1 && !after.finished,
            "{context}: guard"
        );
        {
            let shared = executor.0.shared.lock().unwrap();
            match self.role {
                Role::Responder => assert_eq!(
                    shared.pending_responders,
                    usize::from(!after.finished && self.obs.exposures == 0),
                    "{context}: pending slot"
                ),
                Role::Initiator => assert_eq!(
                    shared.initiator_request_ids.len(),
                    usize::from(!after.finished),
                    "{context}: request-ID reservation"
                ),
            }
        }
        // No new START admission, limiter charge, or refund after the run exists.
        assert_eq!(
            self.a.er.start_limiter_snapshot(),
            self.limiter,
            "{context}: limiter changed"
        );

        // Outputs: only this role's own frame types, each at most once, never after terminal.
        if produced == 1 {
            let frame = self.outputs.last().unwrap();
            assert_eq!(
                sender_of(frame),
                own(self.role),
                "{context}: foreign output"
            );
            let same = self
                .outputs
                .iter()
                .filter(|f| kind(f) == kind(frame))
                .count();
            assert_eq!(same, 1, "{context}: repeated output type {}", kind(frame));
        }

        // Network input.
        if let Some(frame) = frame_in {
            let honest = self.honest.iter().any(|h| h == frame);
            match outcome {
                Err(_) => {
                    // A changed, injected, or wrong-state frame is terminal, never ignored.
                    assert!(
                        after.finished,
                        "{context}: rejected input left the run live"
                    );
                    assert!(!new_result, "{context}");
                }
                Ok(_) if !honest => {
                    // Only unauthenticated pre-SAS contributions can be accepted from an
                    // attacker; anything authenticated must be byte-identical honest input.
                    assert!(
                        matches!(kind(frame), 2 | 3) && !before.sas,
                        "{context}: injected frame type {} accepted",
                        kind(frame)
                    );
                    self.obs.tainted = true;
                    self.obs.tainted_kind.get_or_insert(kind(frame));
                }
                Ok(_) => {}
            }
            if matches!(act, DupLast | DupFirst) && outcome.is_ok() {
                assert_eq!(
                    after.label, before.label,
                    "{context}: duplicate changed state"
                );
                assert_eq!(produced, 0, "{context}: duplicate produced output");
            }
            if act == Next && !before.finished && !was_tainted {
                assert!(
                    outcome.is_ok(),
                    "{context}: honest progress refused on a live untainted run: {outcome:?}"
                );
            }
            if act == Next && outcome.is_ok() && !before.finished && kind(frame) == 5 && honest {
                self.obs.peer_mac = true;
            }
            if act == Next && outcome.is_ok() && honest && matches!(kind(frame), 6..=8) {
                self.obs.completions += 1;
            }
        } else if let Err(error) = outcome {
            // Local action.
            if refusal_without_effect(error) {
                assert_eq!(
                    after.label, before.label,
                    "{context}: refusal changed state"
                );
                assert_eq!(after.finished, before.finished, "{context}");
                assert_eq!(produced, 0, "{context}");
            } else {
                assert!(after.finished, "{context}: failed action left the run live");
            }
        }
        if act == Close {
            assert!(after.finished && produced == 0, "{context}");
        }
        if matches!(act, Confirm) && outcome.is_ok() {
            self.obs.confirmed = true;
        }

        // Result uniqueness and authentication ordering.
        if new_result {
            self.obs.results += 1;
            let result = result.as_ref().unwrap();
            assert!(self.obs.approved, "{context}: result without local MATCH");
            assert!(
                self.obs.own_mac,
                "{context}: result without own approval MAC"
            );
            assert!(
                self.obs.peer_mac,
                "{context}: result without verified peer MAC"
            );
            assert!(!self.obs.tainted, "{context}: result after injected input");
            match self.role {
                Role::Responder => {
                    assert_eq!(act, Next, "{context}");
                    assert_eq!(self.obs.completions, 2, "{context}: R result before I_FACK");
                }
                Role::Initiator => {
                    assert_eq!(act, Confirm, "{context}");
                    assert_eq!(self.obs.completions, 1, "{context}: I result before R_FACK");
                    assert!(self.final_ack.is_some(), "{context}");
                }
            }
            assert_eq!(
                Some(*result.ceremony_identity()),
                self.identity,
                "{context}"
            );
            let peer = match self.role {
                Role::Initiator => fx().responder.clone(),
                Role::Responder => fx().initiator.clone(),
            };
            assert_eq!(
                result.authenticated_peer_bootstrap(),
                peer.canonical_bytes(),
                "{context}"
            );
            assert_eq!(result.peer_role(), peer_of(self.role), "{context}");
            self.result = Some(result.clone());
        }
        assert!(self.obs.results <= 1, "{context}: second result");
        if let Some(kept) = &self.result {
            assert_eq!(result.as_ref(), Some(kept), "{context}: result changed");
        }
        let honest_duplicate = matches!(act, DupLast | DupFirst) && outcome.is_ok();
        let quiet_poll = act == Poll && !before.finished;
        let refused = frame_in.is_none() && outcome.as_ref().is_err_and(refusal_without_effect);
        let closed_again = act == Close && before.finished;
        honest_duplicate || quiet_poll || refused || closed_again
    }

    /// Runs the post-terminal battery (closing a still-live run first).
    fn postfix(&mut self) {
        if !self.target.is_finished() {
            self.apply(Close);
        }
        for act in POSTFIX {
            if self.applicable(act) {
                self.apply(act);
            }
        }
    }
}

/// Replays `prefix ++ suffix` on a fresh world and returns it, before any postfix.
fn replay<'a>(
    a: &'a Authorities,
    role: Role,
    foreign: &'a [Vec<u8>],
    prefix: &[Act],
    suffix: &[Act],
) -> World<'a> {
    let mut world = World::new(a, role, foreign);
    for &act in prefix {
        assert!(world.applicable(act), "{:?} not applicable", world.trace);
        world.apply(act);
    }
    world.timed = true;
    for &act in suffix {
        assert!(world.applicable(act), "{:?} not applicable", world.trace);
        world.apply(act);
    }
    world
}

/// Bounded DFS over adversarial suffixes after every honest prefix of `role`'s path, from
/// `prefixes`. Every node is one complete sequence (prefix, suffix, postfix) replayed from
/// scratch. With `reduce`, a node whose last action was a verified no-op (fingerprint
/// unchanged) is not expanded: its subtree equals its parent's, which is explored.
fn explore(
    a: &Authorities,
    role: Role,
    prefixes: std::ops::Range<usize>,
    depth: usize,
    reduce: bool,
) -> Stats {
    let foreign = foreign_frames(a, role);
    let path = honest_path(role);
    let mut stats = Stats::default();
    for k in prefixes {
        stats.prefixes += 1;
        let prefix = &path[..k];
        let mut stack: Vec<Vec<Act>> = vec![Vec::new()];
        while let Some(suffix) = stack.pop() {
            let mut world = replay(a, role, &foreign, prefix, &suffix);
            stats.sequences += 1;
            stats.steps += world.trace.len();
            stats.max_suffix = stats.max_suffix.max(suffix.len());
            let finished = world.target.is_finished();
            let pruned = reduce && !suffix.is_empty() && !finished && world.last_noop;
            if pruned && suffix.len() < depth {
                stats.pruned_noop += 1;
            }
            let children: Vec<Act> = if finished || pruned || suffix.len() == depth {
                Vec::new()
            } else {
                ALPHABET
                    .into_iter()
                    .filter(|&act| world.applicable(act))
                    .collect()
            };
            if finished {
                stats.terminal_leaves += 1;
            }
            stats.results += world.obs.results;
            if let Some(kind) = world.obs.tainted_kind {
                stats.tainted_by_kind[usize::from(kind)] += 1;
            }
            world.postfix();
            drop(world);
            for act in children.into_iter().rev() {
                let mut next = suffix.clone();
                next.push(act);
                stack.push(next);
            }
        }
    }
    reset(a);
    stats
}

fn report(family: &str, stats: &Stats) {
    let mut line = String::new();
    write!(
        line,
        "{family}: {} sequences over {} honest prefixes (suffix <= {}, {} steps), {} terminal \
         leaves, {} results, {} verified no-op subtrees not expanded, injected-accepted by \
         type {:?}",
        stats.sequences,
        stats.prefixes,
        stats.max_suffix,
        stats.steps,
        stats.terminal_leaves,
        stats.results,
        stats.pruned_noop,
        stats.tainted_by_kind
    )
    .unwrap();
    eprintln!("{line}");
}

/// The honest path itself reaches exactly one result for each role (harness self-check).
#[test]
fn p5_sm_honest_paths_reach_one_result_for_each_role() {
    let a = Authorities::new("p5-sm-honest");
    for role in [Role::Initiator, Role::Responder] {
        let foreign = foreign_frames(&a, role);
        let mut world = replay(&a, role, &foreign, honest_path(role), &[]);
        assert_eq!(world.obs.results, 1, "{role:?}");
        assert!(world.result.is_some());
        assert_eq!(world.target.state_label_for_test(), "Succeeded");
        world.postfix();
        drop(world);
        reset(&a);
    }
    a.release();
}

/// One CI exploration family: `role`, honest prefixes `prefixes`, suffix depth 2, verified
/// no-op subtrees reduced. Depth 3 without reduction is the manual deep run below.
fn ci_family(family: &str, role: Role, prefixes: std::ops::Range<usize>) {
    let a = Authorities::new(&format!("p5-{family}"));
    let stats = explore(&a, role, prefixes, 2, true);
    report(family, &stats);
    assert!(stats.sequences > 50, "{family}: {stats:?}");
    a.release();
}

/// SM-I-001a: Initiator target, honest prefixes 0..=4 (through SAS establishment).
#[test]
fn p5_sm_i_001a_generated_sequences_pre_sas() {
    ci_family("SM-I-001a", Role::Initiator, 0..5);
}

/// SM-I-001b: Initiator target, honest prefixes 5..=10 (approval, completion, success).
#[test]
fn p5_sm_i_001b_generated_sequences_post_sas() {
    ci_family(
        "SM-I-001b",
        Role::Initiator,
        5..honest_path(Role::Initiator).len() + 1,
    );
}

/// SM-R-001a: Responder target, honest prefixes 0..=3 (through exposure and SAS).
#[test]
fn p5_sm_r_001a_generated_sequences_pre_sas() {
    ci_family("SM-R-001a", Role::Responder, 0..4);
}

/// SM-R-001b: Responder target, honest prefixes 4..=8 (approval, completion, success).
#[test]
fn p5_sm_r_001b_generated_sequences_post_sas() {
    ci_family(
        "SM-R-001b",
        Role::Responder,
        4..honest_path(Role::Responder).len() + 1,
    );
}

/// SM-I-002 / SM-R-002 (deep, manual): suffix depth 3 with no reduction, one worker thread per
/// honest prefix (each with its own pair of authorities). Run with
/// `cargo test --manifest-path core/Cargo.toml --lib p5_sm_deep -- --ignored --nocapture`.
#[test]
#[ignore = "P5.2 deep review run (minutes of CPU); passing evidence, not a known-bug reproducer"]
fn p5_sm_deep_generated_sequences_depth_three_unreduced() {
    for (family, role) in [("SM-I-002", Role::Initiator), ("SM-R-002", Role::Responder)] {
        let path = honest_path(role);
        let parts: Vec<Stats> = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..=path.len())
                .map(|k| {
                    scope.spawn(move || {
                        let a = Authorities::new(&format!("p5-sm-deep-{family}-{k}"));
                        let stats = explore(&a, role, k..k + 1, 3, false);
                        a.release();
                        stats
                    })
                })
                .collect();
            workers.into_iter().map(|w| w.join().unwrap()).collect()
        });
        let mut total = Stats::default();
        for part in parts {
            total.sequences += part.sequences;
            total.prefixes += part.prefixes;
            total.terminal_leaves += part.terminal_leaves;
            total.results += part.results;
            total.steps += part.steps;
            total.max_suffix = total.max_suffix.max(part.max_suffix);
            for (sum, n) in total.tainted_by_kind.iter_mut().zip(part.tainted_by_kind) {
                *sum += n;
            }
        }
        report(family, &total);
        assert!(total.sequences > 10_000);
    }
}

// ---- DUP-001: duplicate / reorder matrix over every accepted inbound message ----

/// How one perturbation of the last accepted frame was handled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Handled {
    /// Accepted with no effect at all (fingerprint unchanged).
    Ignored,
    /// Rejected; the run is terminal without a result.
    Terminal,
    /// Rejected without effect because the run already succeeded (`Completed`).
    Completed,
}

/// DUP-001: for every honest prefix whose last network step accepted a peer frame M, each
/// perturbation of M (exact copy, changed copy, the older first frame again, a future frame
/// early, M under another request ID, M with its sender role flipped, and the target's own
/// frame reflected) is applied once, followed by the terminal postfix. P3 §6/§11.2: exact
/// duplicates are ignored; every other variant is terminal (after success: no effect).
#[test]
fn p5_dup_001_duplicate_and_reorder_matrix_matches_p3() {
    let a = Authorities::new("p5-dup-001");
    let mut table: Vec<String> = Vec::new();
    let mut cells = 0;
    for role in [Role::Initiator, Role::Responder] {
        let foreign = foreign_frames(&a, role);
        let path = honest_path(role);
        for k in 0..=path.len() {
            let probe = replay(&a, role, &foreign, &path[..k], &[]);
            let accepted = probe.accepted.len();
            let finished = probe.target.is_finished();
            drop(probe);
            // Only states where the last step accepted a new peer frame M (or success).
            if accepted == 0 || (k > 0 && path[k - 1] != Next && !finished) {
                continue;
            }
            for act in [
                DupLast,
                ChangedLast,
                DupFirst,
                Future,
                WrongIdLast,
                WrongRoleLast,
                Reflect,
            ] {
                let mut world = replay(&a, role, &foreign, &path[..k], &[]);
                if !world.applicable(act) {
                    continue;
                }
                let m = kind(world.accepted.last().unwrap());
                let before = world.fingerprint();
                let was_finished = world.target.is_finished();
                world.apply(act);
                let handled = if was_finished {
                    assert_eq!(world.fingerprint(), before);
                    Handled::Completed
                } else if world.fingerprint() == before {
                    Handled::Ignored
                } else {
                    assert!(world.target.is_finished() && world.target.result().is_none());
                    Handled::Terminal
                };
                let expected = match act {
                    _ if was_finished => Handled::Completed,
                    DupLast | DupFirst => Handled::Ignored,
                    _ => Handled::Terminal,
                };
                assert_eq!(handled, expected, "{role:?} prefix {k} M={m} {act:?}");
                table.push(format!("{role:?} k={k} M={m} {act:?} -> {handled:?}"));
                cells += 1;
                world.postfix();
            }
        }
    }
    eprintln!("DUP-001: {cells} cells");
    for row in &table {
        eprintln!("  {row}");
    }
    assert!(cells >= 50);
    a.release();
}

// ---- DEADLINE-001..004: ceremony deadline boundaries with a hand clock ----

/// How a run met one deadline probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Met {
    /// The input was processed (or the poll found the run live).
    Live,
    /// A P3 §11.3 timeout: which deadline, and whether an authenticated CANCEL was built.
    Timed(Deadline, bool),
    /// The fixed pending pre-exposure lifetime ended.
    Pending,
}

/// Probes used at each boundary instant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Probe {
    Poll,
    Next,
    DupLast,
    ApproveStale,
}

/// Probes at each boundary instant. A refused local action is probed in DEADLINE-004.
const PROBES: [Probe; 3] = [Probe::Poll, Probe::Next, Probe::DupLast];
const OFFSETS: [(i8, &str); 3] = [(-1, "-1ns"), (0, "exact"), (1, "+1ns")];

fn at(base: Duration, offset: i8) -> Duration {
    match offset {
        -1 => base - NS,
        0 => base,
        _ => base + NS,
    }
}

/// Moves the target clock to `instant` (never backwards) and applies `probe` directly to the
/// target, so the deadline outcome is observed exactly as the run reports it.
fn probe_at(world: &mut World<'_>, instant: Duration, probe: Probe) -> Option<Met> {
    let now = crate::deadline::MonotonicClock::now(&*world.clock).unwrap();
    assert!(instant >= now);
    let sas = world.target.sas_bytes_for_test().is_some();
    let frame = match probe {
        Probe::Next => Some(world.inbox.front()?.clone()),
        Probe::DupLast => Some(world.accepted.last()?.clone()),
        Probe::Poll | Probe::ApproveStale => None,
    };
    world.clock.advance(instant - now);
    let had_result = world.target.result().is_some();
    let met = match probe {
        Probe::Poll => match world.target.poll_deadlines().unwrap() {
            DeadlineOutcome::Active => Met::Live,
            DeadlineOutcome::TimedOut(t) => Met::Timed(t.expired(), t.cancel().is_some()),
            DeadlineOutcome::PendingExpired => Met::Pending,
            DeadlineOutcome::Finished => panic!("probe on a finished run"),
        },
        _ => {
            let outcome = match frame {
                Some(frame) => world.deliver(&frame).map(drop),
                None => world.target.approve_sas(&[0xAB; 32]).map(drop),
            };
            match outcome {
                Err(CeremonyError::TimedOut(t)) => Met::Timed(t.expired(), t.cancel().is_some()),
                Err(CeremonyError::PendingExpired) => Met::Pending,
                _ => Met::Live,
            }
        }
    };
    if met != Met::Live {
        // Expiry applies no input, ends the run, and never creates a result.
        assert!(world.target.is_finished() && world.target.result().is_none());
        assert!(!had_result);
        if let Met::Timed(_, cancel) = met {
            assert_eq!(
                cancel, sas,
                "a timeout CANCEL exists exactly when a shared SAS did"
            );
        }
    }
    Some(met)
}

/// DEADLINE-001: the 60 s inactivity boundary in every live honest state of both roles, at
/// −1 ns, exactly, and +1 ns, through a poll, honest input, and an exact duplicate. Expiry is `elapsed >= 60 s` while machine progress is awaited; inactivity is
/// suspended only while the SAS awaits the local decision. For a pending Responder the fixed
/// 60 s pending lifetime coincides and the ceremony deadline is reported first.
#[test]
fn p5_deadline_001_inactivity_boundary_in_every_state() {
    let a = Authorities::new("p5-deadline-001");
    let mut cases = 0;
    for role in [Role::Initiator, Role::Responder] {
        let foreign = foreign_frames(&a, role);
        let path = honest_path(role);
        for k in 0..path.len() {
            for probe in PROBES {
                for (offset, label) in OFFSETS {
                    let mut world = replay(&a, role, &foreign, &path[..k], &[]);
                    let state = world.target.state_label_for_test();
                    let suspended = world.target.state.inactivity() == Some(Inactivity::Suspended);
                    let sas = world.target.sas_bytes_for_test().is_some();
                    let Some(met) = probe_at(&mut world, at(INACTIVITY_DEADLINE, offset), probe)
                    else {
                        continue;
                    };
                    let expected = if offset < 0 || suspended {
                        Met::Live
                    } else {
                        Met::Timed(Deadline::Inactivity, sas)
                    };
                    assert_eq!(met, expected, "{role:?} {state} {probe:?} {label}");
                    cases += 1;
                    world.postfix();
                }
            }
        }
    }
    eprintln!("DEADLINE-001: {cases} boundary cases");
    a.release();
}

/// DEADLINE-002: the fixed 60 s pending pre-exposure lifetime, separated from inactivity by
/// making progress at t = 30 s: it expires at exactly 60 s from admission whatever progress
/// happened, and ends at exposure.
#[test]
fn p5_deadline_002_pending_lifetime_is_fixed_from_admission() {
    let a = Authorities::new("p5-deadline-002");
    let foreign = foreign_frames(&a, Role::Responder);
    let path = honest_path(Role::Responder);
    let mut cases = 0;
    // Prefix 1: I_KEY at 30 s. Prefix 2: I_KEY and authorization at 30 s. Prefix 3: exposure.
    for k in 1..=3 {
        for probe in PROBES {
            for (offset, label) in OFFSETS {
                let mut world = replay(&a, Role::Responder, &foreign, &[], &[]);
                world.timed = false;
                world.clock.advance(Duration::from_secs(30));
                for &act in &path[..k] {
                    world.apply(act);
                }
                let Some(met) =
                    probe_at(&mut world, at(PENDING_PRE_EXPOSURE_DEADLINE, offset), probe)
                else {
                    continue;
                };
                let expected = if offset < 0 || k == 3 {
                    Met::Live
                } else {
                    Met::Pending
                };
                assert_eq!(met, expected, "R prefix {k} {probe:?} {label}");
                cases += 1;
                world.postfix();
            }
        }
    }
    eprintln!("DEADLINE-002: {cases} boundary cases");
    a.release();
}

/// DEADLINE-003: the 5 min absolute deadline in every post-SAS state of both roles. The honest
/// path parks at the suspended SAS comparison until t = 250 s, then continues, so inactivity
/// cannot expire first. Expiry is exactly at 300 s from creation (I) or admission (R) however
/// recently the run progressed, and always carries the authenticated CANCEL.
#[test]
fn p5_deadline_003_absolute_boundary_never_refreshes() {
    let a = Authorities::new("p5-deadline-003");
    let mut cases = 0;
    for (role, sas_at) in [(Role::Initiator, 4), (Role::Responder, 3)] {
        let foreign = foreign_frames(&a, role);
        let path = honest_path(role);
        for k in sas_at..path.len() {
            for probe in PROBES {
                for (offset, label) in OFFSETS {
                    let mut world = replay(&a, role, &foreign, &path[..sas_at], &[]);
                    world.timed = false;
                    assert_eq!(world.target.state_label_for_test(), "AwaitLocalApproval");
                    world.clock.advance(Duration::from_secs(250));
                    for &act in &path[sas_at..k] {
                        world.apply(act);
                    }
                    let state = world.target.state_label_for_test();
                    let Some(met) = probe_at(&mut world, at(ABSOLUTE_DEADLINE, offset), probe)
                    else {
                        continue;
                    };
                    let expected = if offset < 0 {
                        Met::Live
                    } else {
                        Met::Timed(Deadline::Absolute, true)
                    };
                    assert_eq!(met, expected, "{role:?} {state} {probe:?} {label}");
                    cases += 1;
                    world.postfix();
                }
            }
        }
    }
    eprintln!("DEADLINE-003: {cases} boundary cases");
    a.release();
}

/// DEADLINE-004: what restarts the inactivity window. At t = 30 s one action is applied in a
/// state awaiting machine progress; the window then expires exactly at 60 s (no refresh) or
/// exactly at 90 s (refresh). Only protocol progress refreshes: a new state, a recorded
/// exposure authorization, or a verified peer approval MAC.
#[test]
fn p5_deadline_004_only_protocol_progress_refreshes_inactivity() {
    let a = Authorities::new("p5-deadline-004");
    let foreign = foreign_frames(&a, Role::Initiator);
    let path = honest_path(Role::Initiator);
    // (case, honest prefix, action at 30 s, refreshes)
    let cases: [(&str, usize, Act, bool); 8] = [
        ("exact duplicate", 6, DupLast, false),
        ("older exact duplicate", 6, DupFirst, false),
        ("refused stale MATCH", 6, ApproveStale, false),
        ("idempotent own MAC", 6, EmitMac, false),
        ("deadline poll", 6, Poll, false),
        ("new state (peer MAC completes approvals)", 6, Next, true),
        ("verified peer MAC after local MATCH", 5, Next, true),
        ("recorded exposure authorization", 1, Authorize, true),
    ];
    let mut checked = 0;
    // A read-only presentation of the live SAS moves no deadline origin (the fingerprint's
    // deadline probe would show it), so it cannot buy time after the decision either.
    let mut world = replay(&a, Role::Initiator, &foreign, &path[..4], &[]);
    world.timed = false;
    world.clock.advance(Duration::from_secs(30));
    let before = world.fingerprint();
    assert!(world.target.presentation().is_some());
    assert_eq!(world.fingerprint(), before);
    world.postfix();
    drop(world);
    checked += 1;
    for (case, k, act, refreshes) in cases {
        for (offset, label) in OFFSETS {
            for horizon in [
                INACTIVITY_DEADLINE,
                INACTIVITY_DEADLINE + Duration::from_secs(30),
            ] {
                let mut world = replay(&a, Role::Initiator, &foreign, &path[..k], &[]);
                world.timed = false;
                world.clock.advance(Duration::from_secs(30));
                world.apply(act);
                assert!(!world.target.is_finished(), "{case}");
                let met = probe_at(&mut world, at(horizon, offset), Probe::Poll).unwrap();
                let expires_at = if refreshes {
                    INACTIVITY_DEADLINE + Duration::from_secs(30)
                } else {
                    INACTIVITY_DEADLINE
                };
                let expired = at(horizon, offset) >= expires_at;
                assert_eq!(
                    met != Met::Live,
                    expired,
                    "{case} {label} at {:?}: {met:?}",
                    at(horizon, offset)
                );
                if expired {
                    assert!(matches!(met, Met::Timed(Deadline::Inactivity, _)), "{case}");
                }
                checked += 1;
                world.postfix();
            }
        }
    }
    eprintln!("DEADLINE-004: {checked} refresh cases");
    a.release();
}
