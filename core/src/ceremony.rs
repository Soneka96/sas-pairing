//! Crate-private remote ceremony through SAS establishment and local human comparison only.
//! Fixed request IDs are accepted only by this internal/test-scoped constructor;
//! production request-ID generation and active routing reservation remain pending.
//! BOOTSTRAP_MAC, authenticated CANCEL, completion, and PairingResult are not implemented.
#![allow(dead_code)] // The protocol remains internal until later P4 work defines its complete API.
use crate::{
    Authorization, Ceremony, CeremonyExecutor, Error as OwnerError, Role, TrustedAuthority,
    crypto::{self, EphemeralSas, Established},
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
    InvalidRequestId,
    RequestIdMismatch,
    SharedContextMismatch,
    ExpectedPeerMismatch,
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
    AwaitLocalApproval {
        session: SasSession,
    },
    /// Local human MATCH recorded for exactly this identity. Not protocol success: the
    /// authenticated BOOTSTRAP_MAC exchange and completion remain unimplemented.
    LocallyApprovedAwaitingAuthentication {
        session: SasSession,
    },
    Terminal,
}

/// Established-ceremony material, owned only by its state variant so every terminal
/// transition drops it. Retained for the later BOOTSTRAP_MAC increment; never exposed.
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
        )
    }

    /// Available only while this exact SAS awaits a local decision (I2). It never exists
    /// before `ceremony_identity` is fixed and is withdrawn by approval or any terminal path.
    pub(crate) fn presentation(&self) -> Option<SasPresentation> {
        match &self.state {
            State::AwaitLocalApproval { session } => Some(SasPresentation {
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
        let State::AwaitLocalApproval { session } =
            std::mem::replace(&mut self.state, State::Terminal)
        else {
            unreachable!()
        };
        self.state = State::LocallyApprovedAwaitingAuthentication { session };
        Ok(SasApproval::Recorded)
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
        let session = match &self.state {
            State::AwaitLocalApproval { session }
            | State::LocallyApprovedAwaitingAuthentication { session } => session,
            _ => return Err(CeremonyError::NoLiveSas),
        };
        if session.ceremony_identity != *ceremony_identity {
            return Err(CeremonyError::CeremonyIdentityMismatch);
        }
        Ok(session)
    }

    #[cfg(test)]
    fn sas_bytes_for_test(&self) -> Option<[u8; 6]> {
        match &self.state {
            State::AwaitLocalApproval { session }
            | State::LocallyApprovedAwaitingAuthentication { session } => Some(session.sas_bytes),
            _ => None,
        }
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
        self.state = State::AwaitLocalApproval { session };
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
                self.state = State::AwaitLocalApproval { session };
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
    pub(crate) fn terminate(&mut self) -> Result<(), CeremonyError> {
        if matches!(self.state, State::Terminal) {
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
                State::LocallyApprovedAwaitingAuthentication { session } => {
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
}
