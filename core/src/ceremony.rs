//! Crate-private remote ceremony through SAS establishment, local human comparison, the
//! authenticated BOOTSTRAP_MAC approval exchange, and the three-message authenticated finish
//! handshake that yields a local, ceremony-scoped `PairingResult`.
//! Fixed request IDs are accepted only by this internal/test-scoped constructor;
//! production request-ID generation and active routing reservation remain pending.
//! Authenticated CANCEL, deadlines, and transport/resource admission are not implemented.
#![allow(dead_code)] // The protocol remains internal until later P4 work defines its complete API.
use crate::{
    Authorization, Ceremony, CeremonyExecutor, Error as OwnerError, Role, TrustedAuthority,
    crypto::{self, Completion, EphemeralSas, Established},
    protocol::{self, Bootstrap, DecodedMessage, Message},
};

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
    /// I verified RESPONDER_FINISH_ACK and reached LOCAL success: send this final
    /// INITIATOR_FINISH_ACK. Nothing will ever confirm that R receives it.
    SendInitiatorFinishAck(Vec<u8>),
    /// R verified INITIATOR_FINISH_ACK and reached local success. Nothing is sent.
    Succeeded,
    /// Exact duplicate of the accepted INITIATOR_FINISH, ignored without MAC work or output.
    AlreadyAccepted,
}

/// P3 9 local verified completion for exactly one ceremony. It is NOT bilateral success: it
/// does not mean the peer received the final message, returned its own result, or durably
/// stored trust, and no distributed commit or common knowledge exists. The Initiator's final
/// INITIATOR_FINISH_ACK may be lost after the Initiator holds this result.
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
}

impl RemoteCeremony {
    /// Internal/test-scoped fixed request ID constructor, not a production initiation API.
    pub(crate) fn initiator(
        executor: CeremonyExecutor,
        admission: Ceremony,
        start_bytes: &[u8],
        local: Bootstrap,
        expected: Option<Bootstrap>,
    ) -> Result<Self, CeremonyError> {
        let start = protocol::decode(start_bytes)?;
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
        Ok(Self {
            executor,
            admission,
            state: State::InitiatorCreated {
                start,
                local,
                expected,
            },
            seen: Vec::new(),
        })
    }

    /// Accept START after pre-exposure checks; ACCEPT carries commitment but never R_pub.
    pub(crate) fn responder(
        executor: CeremonyExecutor,
        admission: Ceremony,
        start_bytes: &[u8],
        local: Bootstrap,
        expected: Option<Bootstrap>,
    ) -> Result<(Self, Vec<u8>), CeremonyError> {
        let start = protocol::decode(start_bytes)?;
        let (request_id, peer) = match &start.message {
            Message::Start {
                request_id,
                bootstrap,
            } => (request_id.clone(), bootstrap),
            _ => return Err(CeremonyError::InvalidState),
        };
        if admission.role() != Role::Responder {
            return Err(CeremonyError::InvalidState);
        }
        validate_bootstraps(&local, peer, expected.as_ref())?;
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
        };
        Ok((run, accept_bytes))
    }

    pub(crate) fn start(&mut self) -> Result<Vec<u8>, CeremonyError> {
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
    /// is withdrawn by local approval or any terminal path.
    pub(crate) fn presentation(&self) -> Option<SasPresentation> {
        match &self.state {
            State::AwaitLocalApproval { session, .. } => Some(SasPresentation {
                ceremony_identity: session.ceremony_identity,
                decimal: session.decimal.clone(),
            }),
            _ => None,
        }
    }

    /// Local MATCH for exactly this transcript-derived identity. A request ID is never accepted.
    pub(crate) fn approve_sas(
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
        match &self.state {
            State::LocallyApprovedAwaitingAuthentication { .. } => {}
            State::LocalMacSentAwaitingPeerMac { .. }
            | State::ApprovalsAuthenticatedAwaitingCompletion { .. }
            | State::AwaitResponderFinish { .. }
            | State::AwaitInitiatorFinishAck { .. } => {
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
        if matches!(self.state, State::Succeeded(_)) {
            return Err(CeremonyError::Completed);
        }
        if self.admission.role() != Role::Initiator {
            return Err(CeremonyError::NotInitiator);
        }
        match &self.state {
            State::ApprovalsAuthenticatedAwaitingCompletion { .. } => {}
            State::AwaitResponderFinish { .. } => return Ok(FinishEmission::AlreadyEmitted),
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
                // I's success point: RESPONDER_FINISH_ACK verified and the final ACK produced.
                self.succeed(session)?;
                Ok(CompletionReceipt::SendInitiatorFinishAck(ack))
            }
            Completion::InitiatorFinishAck => {
                self.succeed(session)?;
                Ok(CompletionReceipt::Succeeded)
            }
        }
    }

    /// Success cleanup: build the immutable result, drop the session (vodozemac state, SAS
    /// bytes, approval) and duplicate-tracking state, and only then release the guard. The
    /// consumed opportunity stays consumed. An uncertain guard release fails closed: the run
    /// ends without a result and nothing further is emitted.
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

    /// Local MISMATCH/REJECT: terminal failure. Sends nothing and refunds nothing.
    pub(crate) fn reject_sas(&mut self, ceremony_identity: &[u8; 32]) -> Result<(), CeremonyError> {
        self.live_session(ceremony_identity)?;
        self.terminate()
    }

    /// Local CANCEL only; authenticated wire CANCEL is later work, so nothing is emitted.
    pub(crate) fn cancel_sas(&mut self, ceremony_identity: &[u8; 32]) -> Result<(), CeremonyError> {
        self.live_session(ceremony_identity)?;
        self.terminate()
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
            | State::AwaitInitiatorFinishAck { session } => Some(session),
            _ => None,
        }
    }

    #[cfg(test)]
    fn sas_bytes_for_test(&self) -> Option<[u8; 6]> {
        self.session().map(|session| session.sas_bytes)
    }

    pub(crate) fn receive_accept(&mut self, bytes: &[u8]) -> Result<(), CeremonyError> {
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
        let established = match ephemeral.establish(public_key) {
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
        let state = std::mem::replace(&mut self.state, State::Terminal);
        match state {
            State::InitiatorAwaitAuthorization {
                start,
                accept,
                authorization: Some(token),
            } => {
                if let Err(error) = self.executor.reserve(&mut self.admission, Some(token)) {
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
    use crate::{Status, protocol};
    use serde_json::Value;

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
        let mut initiator = RemoteCeremony::initiator(
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
            drop(responder);
            drop(exec);
            authority.release().unwrap();

            let (authority, exec) = executor(format!("initiator-request-id-{len}").as_bytes());
            let result = RemoteCeremony::initiator(
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
        let mut i = RemoteCeremony::initiator(
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
            RemoteCeremony::initiator(
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
        let mut peer_i = RemoteCeremony::initiator(
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
            RemoteCeremony::initiator(
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
        let mut first = RemoteCeremony::initiator(
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
        let mut second = RemoteCeremony::initiator(
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
        let mut run = RemoteCeremony::initiator(
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

        let mut run = RemoteCeremony::initiator(
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

        let mut run = RemoteCeremony::initiator(
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

        let mut run = RemoteCeremony::initiator(
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
        let mut initiator = RemoteCeremony::initiator(
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
    }
    impl Authorities {
        fn new(scope: &str) -> Self {
            let (i, ei) = executor(format!("{scope}-i").as_bytes());
            let (r, er) = executor(format!("{scope}-r").as_bytes());
            Self { i, ei, r, er }
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
        let start = vector("START");
        let mut i = RemoteCeremony::initiator(
            a.ei.clone(),
            a.ei.begin(Role::Initiator).unwrap(),
            &start,
            bootstrap(&decoded("START"), true),
            None,
        )
        .unwrap();
        assert_no_live_sas(&i);
        i.start().unwrap();
        let (mut r, accept) = RemoteCeremony::responder(
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

    #[test]
    fn local_reject_is_terminal_and_keeps_the_opportunity_consumed() {
        let a = Authorities::new("sas-reject");
        let mut pair = establish(&a);
        let id = pair.identity();
        assert_eq!(pair.i.reject_sas(&id), Ok(()));
        assert_stale(&mut pair.i, &id);
        assert_eq!(a.ei.status().unwrap(), Status::Ready { remaining: 9 });
        assert!(pair.i.admission.terminal);
        // The peer is a separate endpoint; this increment sends it nothing.
        assert!(pair.r.is_awaiting_approval());
        assert_eq!(a.er.status().unwrap(), Status::Busy);
        pair.r.approve_sas(&id).unwrap();
        assert_eq!(pair.r.reject_sas(&id), Ok(()));
        assert_stale(&mut pair.r, &id);
        assert_eq!(a.er.status().unwrap(), Status::Ready { remaining: 9 });
        drop(pair);
        a.release();
    }

    #[test]
    fn local_cancel_is_terminal_without_wire_output() {
        let a = Authorities::new("sas-cancel");
        let mut pair = establish(&a);
        let id = pair.identity();
        let seen = pair.i.seen.len();
        let () = pair.i.cancel_sas(&id).unwrap();
        assert_eq!(pair.i.seen.len(), seen);
        assert_stale(&mut pair.i, &id);
        assert_eq!(a.ei.status().unwrap(), Status::Ready { remaining: 9 });
        pair.r.approve_sas(&id).unwrap();
        let () = pair.r.cancel_sas(&id).unwrap();
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
        let mut pre = RemoteCeremony::initiator(
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
                let result = if reject {
                    pair.i.reject_sas(&id)
                } else {
                    pair.i.cancel_sas(&id)
                };
                assert_eq!(result, Ok(()), "stage {index}");
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
    /// its result by producing the final ACK; nothing acknowledges that ACK, so its loss leaves
    /// the Responder waiting with no result. There is no fourth message.
    #[test]
    fn lost_final_ack_leaves_only_the_initiator_with_a_local_result() {
        let a = Authorities::new("finish-lost-final-ack");
        let (mut pair, id) = approvals_authenticated(&a);
        let i_finish = finish(&mut pair.i);
        let r_ack = responder_ack(&mut pair.r, &i_finish);
        let _undelivered = initiator_ack(&mut pair.i, &r_ack);

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
        // R later ends locally (here: local CANCEL) with no result; I's result is unaffected.
        pair.r.cancel_sas(&id).unwrap();
        assert_failed(&mut pair.r, &a.er, &id);
        assert_eq!(pair.i.result().cloned(), result_i);
        drop(pair);
        a.release();
    }

    #[test]
    fn initiator_finish_requires_authenticated_approvals_and_the_initiator_role() {
        let a = Authorities::new("finish-preconditions");
        let mut pre = RemoteCeremony::initiator(
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

        // I moves from verifying RESPONDER_FINISH_ACK to Succeeded in one transition, so a
        // duplicate can only arrive after success: it is rejected and changes nothing.
        let i_ack = initiator_ack(&mut pair.i, &r_ack);
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
        let stages: [(protocol::Role, Setup); 3] = [
            // I awaiting RESPONDER_FINISH_ACK.
            (protocol::Role::Initiator, |p, id| {
                authenticate(p, id);
                finish(&mut p.i);
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
                let outcome = if reject {
                    run.reject_sas(&id)
                } else {
                    run.cancel_sas(&id)
                };
                assert_eq!(outcome, Ok(()), "stage {index}");
                assert_eq!(run.seen.len(), seen, "local-only: nothing sent");
                assert_failed(run, endpoint_executor(&a, role), &id);
                assert!(run.emit_initiator_finish().is_err());
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
        let poisoned = a.ei.clone();
        let _ = std::thread::spawn(move || {
            let _shared = poisoned.0.shared.lock().unwrap();
            panic!("simulate uncertain guard state");
        })
        .join();
        // No result and no final ACK are released; the SAS session is already dropped.
        assert_eq!(
            pair.i.receive_completion(&r_ack),
            Err(CeremonyError::Owner(OwnerError::OwnershipUncertain))
        );
        assert_eq!(pair.i.result(), None);
        assert!(matches!(pair.i.state, State::Terminal));
        assert_stale(&mut pair.i, &id);
        assert!(pair.i.receive_completion(&r_ack).is_err());
        assert_eq!(pair.i.result(), None);
        match a.ei.0.shared.lock() {
            Err(poisoned) => assert!(poisoned.into_inner().active.is_some()),
            Ok(_) => panic!("shared state unexpectedly recovered"),
        }
        drop(pair);
        a.release();
    }
}
