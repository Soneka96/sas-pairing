//! Crate-private remote ceremony through internal SAS establishment only.
//! Fixed request IDs are accepted only by this internal/test-scoped constructor;
//! production request-ID generation and active routing reservation remain pending.
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
    AwaitingApproval {
        identity: [u8; 32],
        sas: Established,
        info: String,
    },
    Terminal,
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
        validate_request_id(&start)?;
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
        validate_request_id(&start)?;
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
        matches!(self.state, State::AwaitingApproval { .. })
    }

    #[cfg(test)]
    fn sas_for_test(&self) -> Option<(Vec<u8>, String)> {
        match &self.state {
            State::AwaitingApproval { sas, info, .. } => {
                let (bytes, decimal) = sas.sas(info);
                Some((bytes.as_bytes().to_vec(), decimal))
            }
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
        let (identity, _) = match crypto::transcript_identity(&start, &accept, &ikey, &msg) {
            Ok(value) => value,
            Err(error) => return self.fail(error.into()),
        };
        let (_, info) = match crypto::sas_info(&start, &accept, &ikey, &msg) {
            Ok(value) => value,
            Err(error) => return self.fail(error.into()),
        };
        self.state = State::AwaitingApproval {
            identity,
            sas: established,
            info,
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
                let (identity, _) = match crypto::transcript_identity(&start, &accept, &ikey, &rkey)
                {
                    Ok(value) => value,
                    Err(error) => return self.fail(error.into()),
                };
                let (_, info) = match crypto::sas_info(&start, &accept, &ikey, &rkey) {
                    Ok(value) => value,
                    Err(error) => return self.fail(error.into()),
                };
                self.state = State::AwaitingApproval {
                    identity,
                    sas: established,
                    info,
                };
                Ok(bytes)
            }
            other => {
                self.state = other;
                self.fail(OwnerError::MissingAuthorization.into())
            }
        }
    }

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
        // Drop ephemeral and SAS state before Ceremony's Drop releases the authority guard.
        self.state = State::Terminal;
    }
}

fn request_id_of(message: &DecodedMessage) -> Result<&[u8], CeremonyError> {
    match &message.message {
        Message::Start { request_id, .. } => Ok(request_id),
        _ => Err(CeremonyError::InvalidState),
    }
}
fn validate_request_id(message: &DecodedMessage) -> Result<(), CeremonyError> {
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
        assert_eq!(initiator.sas_for_test(), responder.sas_for_test());
        assert_eq!(executor_i.status().unwrap(), Status::Busy);
        assert_eq!(executor_r.status().unwrap(), Status::Busy);
        initiator.terminate().unwrap();
        responder.terminate().unwrap();
        assert_eq!(initiator.sas_for_test(), None);
        assert_eq!(responder.sas_for_test(), None);
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
}
