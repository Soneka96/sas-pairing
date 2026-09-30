//! Internal P3 cryptographic primitives. No ceremony or application API is exposed.

#![allow(dead_code)]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use vodozemac::{
    Curve25519PublicKey,
    sas::{EstablishedSas, Mac, Sas, SasBytes},
};

use crate::protocol::{
    Bootstrap, CancelReason, DecodedMessage, MAX_FRAME, Message, PROFILE_ID, Role,
};

const DOMAIN: &[u8] = b"org.sas-pairing";
const COMMIT_DOMAIN: &[u8] = b"sas-pairing-vodozemac-profile-draft-01/commit/v1";
const TRANSCRIPT_DOMAIN: &[u8] = b"sas-pairing-vodozemac-profile-draft-01/transcript/v1";
const SAS_PREFIX: &[u8] = b"sas-pairing-vodozemac-profile-draft-01/sas/";
const MAC_PREFIX: &[u8] = b"sas-pairing-vodozemac-profile-draft-01/mac/";
const CANCEL_PREFIX: &[u8] = b"sas-pairing-vodozemac-profile-draft-01/cancel/";
const APPROVAL_PURPOSE: &[u8] = b"match-approve-bootstrap";
const CRYPTO_INPUT_LIMIT: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Error {
    InvalidMessage,
    RequestIdMismatch,
    InvalidPeerKeyLength,
    NonContributory,
    Oversized,
    LengthOverflow,
    CommitmentMismatch,
    MacMismatch,
}

#[cfg(test)]
thread_local! {
    static MAC_OPERATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static FAIL_NEXT_CANCEL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Test-only count of vodozemac MAC calculations and verifications on this thread.
#[cfg(test)]
pub(super) fn mac_operations() -> usize {
    MAC_OPERATIONS.with(std::cell::Cell::get)
}

/// Test-only fault injection: the next `cancel_mac_strings` on this thread fails.
#[cfg(test)]
pub(super) fn fail_next_cancel_construction() {
    FAIL_NEXT_CANCEL.with(|fail| fail.set(true));
}

pub(super) struct EphemeralSas(Sas);

impl EphemeralSas {
    pub(super) fn new() -> Self {
        Self(Sas::new())
    }

    pub(super) fn public_key(&self) -> [u8; 32] {
        self.0.public_key().to_bytes()
    }

    pub(super) fn establish(self, peer: &[u8]) -> Result<Established, Error> {
        let peer: [u8; 32] = peer.try_into().map_err(|_| Error::InvalidPeerKeyLength)?;
        self.0
            .diffie_hellman(Curve25519PublicKey::from_bytes(peer))
            .map(Established)
            .map_err(|_| Error::NonContributory)
    }
}

#[derive(Debug)]
pub(super) struct Established(EstablishedSas);

impl Established {
    pub(super) fn sas(&self, info: &str) -> (SasBytes, String) {
        let bytes = self.0.bytes(info);
        let (first, second, third) = bytes.decimals();
        (bytes, format!("{first:04} {second:04} {third:04}"))
    }

    /// vodozemac HKDF/HMAC-SHA-256 over the exact Base64url `input` under `info`.
    pub(super) fn calculate_mac(&self, input: &str, info: &str) -> Result<[u8; 32], Error> {
        #[cfg(test)]
        MAC_OPERATIONS.with(|count| count.set(count.get() + 1));
        self.0
            .calculate_mac(input, info)
            .as_bytes()
            .try_into()
            .map_err(|_| Error::MacMismatch)
    }

    /// vodozemac's own tag comparison; no project-owned MAC or comparison code.
    pub(super) fn verify_mac(&self, input: &str, info: &str, tag: &[u8; 32]) -> Result<(), Error> {
        #[cfg(test)]
        MAC_OPERATIONS.with(|count| count.set(count.get() + 1));
        self.0
            .verify_mac(input, info, &Mac::from_slice(tag))
            .map_err(|_| Error::MacMismatch)
    }
}

fn checked_frame_len(field_lengths: &[usize]) -> Result<usize, Error> {
    let size = field_lengths.iter().try_fold(10usize, |size, length| {
        u32::try_from(*length).map_err(|_| Error::LengthOverflow)?;
        size.checked_add(4)
            .and_then(|size| size.checked_add(*length))
            .ok_or(Error::LengthOverflow)
    })?;
    if size > MAX_FRAME {
        Err(Error::Oversized)
    } else {
        Ok(size)
    }
}

fn frame(kind: u8, fields: &[&[u8]]) -> Result<Vec<u8>, Error> {
    let lengths: Vec<_> = fields.iter().map(|field| field.len()).collect();
    let size = checked_frame_len(&lengths)?;
    let mut bytes = Vec::with_capacity(size);
    bytes.extend_from_slice(b"SASPAIR\0\x01");
    bytes.push(kind);
    for field in fields {
        bytes.extend_from_slice(
            &u32::try_from(field.len())
                .map_err(|_| Error::LengthOverflow)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(field);
    }
    Ok(bytes)
}

fn append_length_prefixed(out: &mut Vec<u8>, value: &[u8]) -> Result<(), Error> {
    let length = u32::try_from(value.len()).map_err(|_| Error::LengthOverflow)?;
    out.try_reserve(
        4usize
            .checked_add(value.len())
            .ok_or(Error::LengthOverflow)?,
    )
    .map_err(|_| Error::LengthOverflow)?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn commitment_input(start: &DecodedMessage, responder_key: &[u8; 32]) -> Result<Vec<u8>, Error> {
    if !matches!(start.message, Message::Start { .. }) {
        return Err(Error::InvalidMessage);
    }
    let start_bytes = start.canonical_bytes();
    let size = COMMIT_DOMAIN
        .len()
        .checked_add(4)
        .and_then(|size| size.checked_add(start_bytes.len()))
        .and_then(|size| size.checked_add(responder_key.len()))
        .ok_or(Error::LengthOverflow)?;
    let mut input = Vec::with_capacity(size);
    input.extend_from_slice(COMMIT_DOMAIN);
    append_length_prefixed(&mut input, start_bytes)?;
    input.extend_from_slice(responder_key);
    Ok(input)
}

pub(super) fn commitment(
    start: &DecodedMessage,
    responder_key: &[u8; 32],
) -> Result<[u8; 32], Error> {
    Ok(Sha256::digest(commitment_input(start, responder_key)?).into())
}

pub(super) fn verify_commitment(
    start: &DecodedMessage,
    responder_key: &[u8; 32],
    expected: &[u8; 32],
) -> Result<(), Error> {
    if commitment(start, responder_key)? == *expected {
        Ok(())
    } else {
        Err(Error::CommitmentMismatch)
    }
}

fn transcript_bytes(
    domain: &[u8],
    start: &DecodedMessage,
    accept: &DecodedMessage,
    initiator_key: &DecodedMessage,
    responder_key: &DecodedMessage,
) -> Result<Vec<u8>, Error> {
    let messages = match (
        &start.message,
        &accept.message,
        &initiator_key.message,
        &responder_key.message,
    ) {
        (
            Message::Start { request_id, .. },
            Message::Accept {
                request_id: accept_id,
                ..
            },
            Message::InitiatorKey {
                request_id: initiator_id,
                ..
            },
            Message::ResponderKey {
                request_id: responder_id,
                ..
            },
        ) => {
            if request_id != accept_id || request_id != initiator_id || request_id != responder_id {
                return Err(Error::RequestIdMismatch);
            }
            [
                start.canonical_bytes(),
                accept.canonical_bytes(),
                initiator_key.canonical_bytes(),
                responder_key.canonical_bytes(),
            ]
        }
        _ => return Err(Error::InvalidMessage),
    };
    let total = messages.iter().try_fold(4usize, |size, bytes| {
        size.checked_add(4)
            .and_then(|size| size.checked_add(bytes.len()))
            .ok_or(Error::LengthOverflow)
    })?;
    let size = total
        .checked_add(domain.len())
        .ok_or(Error::LengthOverflow)?;
    let mut bytes = Vec::with_capacity(size);
    append_length_prefixed(&mut bytes, domain)?;
    for message in messages {
        append_length_prefixed(&mut bytes, message)?;
    }
    Ok(bytes)
}

pub(super) fn transcript_identity(
    start: &DecodedMessage,
    accept: &DecodedMessage,
    initiator_key: &DecodedMessage,
    responder_key: &DecodedMessage,
) -> Result<([u8; 32], Vec<u8>), Error> {
    let bytes = transcript_bytes(
        TRANSCRIPT_DOMAIN,
        start,
        accept,
        initiator_key,
        responder_key,
    )?;
    Ok((Sha256::digest(&bytes).into(), bytes))
}

/// `prefix || unpadded_Base64url(bytes)`, sized with checked arithmetic and capped as a
/// whole at the P3 3.1 65,536-byte generated cryptographic-input maximum.
fn capped_base64url(prefix: &[u8], bytes: &[u8]) -> Result<String, Error> {
    let encoded_len = bytes
        .len()
        .checked_div(3)
        .and_then(|len| len.checked_mul(4))
        .and_then(|len| {
            len.checked_add(match bytes.len() % 3 {
                0 => 0,
                1 => 2,
                _ => 3,
            })
        })
        .ok_or(Error::LengthOverflow)?;
    let total_len = prefix
        .len()
        .checked_add(encoded_len)
        .ok_or(Error::LengthOverflow)?;
    if total_len > CRYPTO_INPUT_LIMIT {
        return Err(Error::Oversized);
    }
    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(prefix);
    out.extend_from_slice(URL_SAFE_NO_PAD.encode(bytes).as_bytes());
    Ok(String::from_utf8(out).expect("ASCII prefix and Base64url"))
}

fn sas_info_from_context(context: &[u8]) -> Result<String, Error> {
    capped_base64url(SAS_PREFIX, context)
}

pub(super) fn sas_info(
    start: &DecodedMessage,
    accept: &DecodedMessage,
    initiator_key: &DecodedMessage,
    responder_key: &DecodedMessage,
) -> Result<(Vec<u8>, String), Error> {
    let request_id = match &start.message {
        Message::Start { request_id, .. } => request_id,
        _ => return Err(Error::InvalidMessage),
    };
    match &accept.message {
        Message::Accept {
            request_id: peer_id,
            ..
        } if peer_id == request_id => (),
        Message::Accept { .. } => return Err(Error::RequestIdMismatch),
        _ => return Err(Error::InvalidMessage),
    }
    let (initiator_id, initiator_public) = match &initiator_key.message {
        Message::InitiatorKey {
            request_id,
            public_key,
        } => (request_id, public_key),
        _ => return Err(Error::InvalidMessage),
    };
    let (responder_id, responder_public) = match &responder_key.message {
        Message::ResponderKey {
            request_id,
            public_key,
        } => (request_id, public_key),
        _ => return Err(Error::InvalidMessage),
    };
    if request_id != initiator_id || request_id != responder_id {
        return Err(Error::RequestIdMismatch);
    }
    let version = 1u16.to_be_bytes();
    let context = frame(
        0x30,
        &[
            DOMAIN,
            PROFILE_ID,
            &version,
            request_id,
            start.canonical_bytes(),
            accept.canonical_bytes(),
            initiator_public,
            responder_public,
        ],
    )?;
    let info = sas_info_from_context(&context)?;
    Ok((context, info))
}

fn peer_of(role: Role) -> Role {
    match role {
        Role::Initiator => Role::Responder,
        Role::Responder => Role::Initiator,
    }
}

/// Non-wire P3 8 approval frame `0x33`: the sender approves this full SAS for this exact
/// established transcript and authenticates the sender's own complete canonical bootstrap.
pub(super) fn approval_frame(
    sender: Role,
    ceremony_identity: &[u8; 32],
    sas_bytes: &[u8; 6],
    sender_bootstrap: &Bootstrap,
) -> Result<Vec<u8>, Error> {
    let version = 1u16.to_be_bytes();
    frame(
        0x33,
        &[
            DOMAIN,
            PROFILE_ID,
            &version,
            &[sender as u8],
            ceremony_identity,
            sas_bytes,
            sender_bootstrap.canonical_bytes(),
        ],
    )
}

/// P3 8 MAC context frame `0x31`; `purpose` is a parameter only so tests can prove its binding.
pub(super) fn approval_context(
    purpose: &[u8],
    sender: Role,
    receiver: Role,
    ceremony_identity: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    mac_context(0x31, purpose, sender, receiver, ceremony_identity)
}

/// The shared P3 8/9 MAC context layout: domain, profile, version, purpose, sender role,
/// receiver role, `ceremony_identity`. Only the context type distinguishes approval (`0x31`)
/// from completion (`0x32`).
fn mac_context(
    context_type: u8,
    purpose: &[u8],
    sender: Role,
    receiver: Role,
    ceremony_identity: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    let version = 1u16.to_be_bytes();
    frame(
        context_type,
        &[
            DOMAIN,
            PROFILE_ID,
            &version,
            purpose,
            &[sender as u8],
            &[receiver as u8],
            ceremony_identity,
        ],
    )
}

/// Exact vodozemac `(input, info)` strings for one authenticated statement: input is unpadded
/// Base64url of the complete non-wire frame; info is the P3 3.2 `mac` context string.
pub(super) fn mac_strings(frame: &[u8], context: &[u8]) -> Result<(String, String), Error> {
    Ok((
        capped_base64url(b"", frame)?,
        capped_base64url(MAC_PREFIX, context)?,
    ))
}

/// The BOOTSTRAP_MAC inputs for `sender` -> its peer. Senders pass their own bootstrap;
/// receivers pass the retained peer bootstrap and the peer's role.
pub(super) fn bootstrap_mac_strings(
    sender: Role,
    ceremony_identity: &[u8; 32],
    sas_bytes: &[u8; 6],
    sender_bootstrap: &Bootstrap,
) -> Result<(String, String), Error> {
    mac_strings(
        &approval_frame(sender, ceremony_identity, sas_bytes, sender_bootstrap)?,
        &approval_context(APPROVAL_PURPOSE, sender, peer_of(sender), ceremony_identity)?,
    )
}

/// The three P3 9 completion steps, in their only legal order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Completion {
    InitiatorFinish,
    ResponderFinishAck,
    InitiatorFinishAck,
}

impl Completion {
    /// Non-wire `CompletionAuthFrame` type byte; never a network message type.
    pub(super) fn auth_frame_type(self) -> u8 {
        match self {
            Self::InitiatorFinish => 0x35,
            Self::ResponderFinishAck => 0x36,
            Self::InitiatorFinishAck => 0x37,
        }
    }
    pub(super) fn purpose(self) -> &'static [u8] {
        match self {
            Self::InitiatorFinish => b"initiator-finish",
            Self::ResponderFinishAck => b"responder-finish-ack",
            Self::InitiatorFinishAck => b"initiator-finish-ack",
        }
    }
    pub(super) fn sender(self) -> Role {
        match self {
            Self::InitiatorFinish | Self::InitiatorFinishAck => Role::Initiator,
            Self::ResponderFinishAck => Role::Responder,
        }
    }
    pub(super) fn receiver(self) -> Role {
        peer_of(self.sender())
    }
}

/// Non-wire P3 9 `CompletionAuthFrame`: domain, profile, version, sender role, receiver role,
/// `ceremony_identity`, then the completion purpose LAST. It never contains a MAC.
fn completion_auth_frame(
    auth_frame_type: u8,
    sender: Role,
    receiver: Role,
    ceremony_identity: &[u8; 32],
    purpose: &[u8],
) -> Result<Vec<u8>, Error> {
    let version = 1u16.to_be_bytes();
    frame(
        auth_frame_type,
        &[
            DOMAIN,
            PROFILE_ID,
            &version,
            &[sender as u8],
            &[receiver as u8],
            ceremony_identity,
            purpose,
        ],
    )
}

/// The vodozemac `(input, info)` for `step` of this ceremony, from the fixed P3 9 mapping only.
pub(super) fn completion_mac_strings(
    step: Completion,
    ceremony_identity: &[u8; 32],
) -> Result<(String, String), Error> {
    let (purpose, sender, receiver) = (step.purpose(), step.sender(), step.receiver());
    mac_strings(
        &completion_auth_frame(
            step.auth_frame_type(),
            sender,
            receiver,
            ceremony_identity,
            purpose,
        )?,
        &mac_context(0x32, purpose, sender, receiver, ceremony_identity)?,
    )
}

/// Non-wire P3 11.3 cancellation structure: domain, profile, version, sender role, receiver
/// role, `ceremony_identity`, reason code. `CancelAuthFrame` (`0x34`) and `CancelMacContext`
/// (`0x38`) carry these identical fields in this order; only the type byte differs. There is no
/// inner purpose field, no request ID, and never a MAC.
fn cancel_frame(
    frame_type: u8,
    sender: Role,
    receiver: Role,
    ceremony_identity: &[u8; 32],
    reason: CancelReason,
) -> Result<Vec<u8>, Error> {
    let version = 1u16.to_be_bytes();
    frame(
        frame_type,
        &[
            DOMAIN,
            PROFILE_ID,
            &version,
            &[sender as u8],
            &[receiver as u8],
            ceremony_identity,
            &[reason as u8],
        ],
    )
}

/// Non-wire `CancelAuthFrame / 0x34`: the MAC input statement. Never a network message type.
pub(super) fn cancel_auth_frame(
    sender: Role,
    receiver: Role,
    ceremony_identity: &[u8; 32],
    reason: CancelReason,
) -> Result<Vec<u8>, Error> {
    cancel_frame(0x34, sender, receiver, ceremony_identity, reason)
}

/// Non-wire `CancelMacContext / 0x38`: the MAC `info` context under outer purpose `cancel`.
pub(super) fn cancel_context(
    sender: Role,
    receiver: Role,
    ceremony_identity: &[u8; 32],
    reason: CancelReason,
) -> Result<Vec<u8>, Error> {
    cancel_frame(0x38, sender, receiver, ceremony_identity, reason)
}

/// The vodozemac `(input, info)` for an authenticated CANCEL: input is unpadded Base64url of
/// the `0x34` frame; info is `.../cancel/` (never `.../mac/`) plus unpadded Base64url of the
/// `0x38` context. Callers derive both roles from local ceremony state, never from the wire.
pub(super) fn cancel_mac_strings(
    sender: Role,
    receiver: Role,
    ceremony_identity: &[u8; 32],
    reason: CancelReason,
) -> Result<(String, String), Error> {
    debug_assert_ne!(sender, receiver);
    #[cfg(test)]
    if FAIL_NEXT_CANCEL.with(|fail| fail.replace(false)) {
        return Err(Error::Oversized);
    }
    Ok((
        capped_base64url(
            b"",
            &cancel_auth_frame(sender, receiver, ceremony_identity, reason)?,
        )?,
        capped_base64url(
            CANCEL_PREFIX,
            &cancel_context(sender, receiver, ceremony_identity, reason)?,
        )?,
    ))
}

/// Test-only CANCEL reconstruction with every structural choice made by the caller (frame and
/// context types, outer prefix, an optional inner purpose field, roles, identity, and a raw
/// reason byte), so tests can prove each departure from the frozen encoding fails.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(super) fn cancel_mac_strings_for_test(
    auth_type: u8,
    context_type: u8,
    prefix: &[u8],
    inner_purpose: Option<&[u8]>,
    sender: Role,
    receiver: Role,
    ceremony_identity: &[u8; 32],
    reason: u8,
) -> (String, String) {
    let version = 1u16.to_be_bytes();
    let (sender, receiver, reason) = ([sender as u8], [receiver as u8], [reason]);
    let tail: [&[u8]; 4] = [&sender, &receiver, ceremony_identity, &reason];
    let auth: Vec<&[u8]> = [DOMAIN, PROFILE_ID, &version]
        .into_iter()
        .chain(tail)
        .collect();
    let context: Vec<&[u8]> = [DOMAIN, PROFILE_ID, &version]
        .into_iter()
        .chain(inner_purpose)
        .chain(tail)
        .collect();
    (
        capped_base64url(b"", &frame(auth_type, &auth).unwrap()).unwrap(),
        capped_base64url(prefix, &frame(context_type, &context).unwrap()).unwrap(),
    )
}

/// Test-only reconstruction with every bound completion field chosen by the caller, so tests
/// can prove that changing any one of them breaks verification. Production uses the fixed map.
#[cfg(test)]
pub(super) fn completion_mac_strings_for_test(
    auth_frame_type: u8,
    purpose: &[u8],
    sender: Role,
    receiver: Role,
    ceremony_identity: &[u8; 32],
) -> (String, String) {
    mac_strings(
        &completion_auth_frame(
            auth_frame_type,
            sender,
            receiver,
            ceremony_identity,
            purpose,
        )
        .unwrap(),
        &mac_context(0x32, purpose, sender, receiver, ceremony_identity).unwrap(),
    )
    .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol;
    use serde_json::Value;

    fn fixture() -> Value {
        serde_json::from_str(include_str!(
            "../../vectors/p3-remote-vodozemac-draft-01.json"
        ))
        .unwrap()
    }

    fn hex(input: &str) -> Vec<u8> {
        input
            .as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn vector_frame(name: &str) -> DecodedMessage {
        let json = fixture();
        let bytes = hex(json["wire_messages"][name]["hex"].as_str().unwrap());
        protocol::decode(&bytes).unwrap()
    }

    fn string<'a>(json: &'a Value, path: &[&str]) -> &'a str {
        path.iter().fold(json, |v, key| &v[*key]).as_str().unwrap()
    }

    #[test]
    fn deterministic_encoding_matches_authoritative_vector() {
        let json = fixture();
        let start = vector_frame("START");
        let accept = vector_frame("ACCEPT");
        let initiator = vector_frame("INITIATOR_KEY");
        let responder = vector_frame("RESPONDER_KEY");
        let responder_public = match responder.message {
            Message::ResponderKey { public_key, .. } => public_key,
            _ => unreachable!(),
        };

        let input = commitment_input(&start, &responder_public).unwrap();
        assert_eq!(
            input,
            hex(string(&json, &["commitment", "hash", "input_hex"]))
        );
        let digest = commitment(&start, &responder_public).unwrap();
        assert_eq!(
            digest.as_slice(),
            hex(string(&json, &["commitment", "hash", "output_hex"]))
        );
        verify_commitment(&start, &responder_public, &digest).unwrap();

        let (identity, transcript) =
            transcript_identity(&start, &accept, &initiator, &responder).unwrap();
        assert_eq!(
            transcript,
            hex(string(&json, &["transcript", "bytes", "hex"]))
        );
        assert_eq!(
            identity.as_slice(),
            hex(string(&json, &["ceremony_identity", "hex"]))
        );

        let (context, info) = sas_info(&start, &accept, &initiator, &responder).unwrap();
        assert_eq!(info, string(&json, &["sas", "info_string"]));
        assert_eq!(
            context,
            hex(string(&json, &["sas", "context_frame", "hex"]))
        );
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(
                    info.strip_prefix("sas-pairing-vodozemac-profile-draft-01/sas/")
                        .unwrap()
                )
                .unwrap(),
            hex(string(&json, &["sas", "context_frame", "hex"]))
        );
    }

    #[test]
    fn rejects_bad_commitments_order_and_mutated_canonical_frames() {
        let start = vector_frame("START");
        let accept = vector_frame("ACCEPT");
        let initiator = vector_frame("INITIATOR_KEY");
        let responder = vector_frame("RESPONDER_KEY");
        let responder_public = match responder.message {
            Message::ResponderKey { public_key, .. } => public_key,
            _ => unreachable!(),
        };
        let mut wrong = commitment(&start, &responder_public).unwrap();
        wrong[0] ^= 1;
        assert_eq!(
            verify_commitment(&start, &responder_public, &wrong),
            Err(Error::CommitmentMismatch)
        );

        let mut changed_start = start.canonical_bytes().to_vec();
        *changed_start.last_mut().unwrap() ^= 1;
        let changed_start = protocol::decode(&changed_start).unwrap();
        assert_eq!(
            verify_commitment(
                &changed_start,
                &responder_public,
                &commitment(&start, &responder_public).unwrap()
            ),
            Err(Error::CommitmentMismatch)
        );

        let mut changed_key = responder_public;
        changed_key[0] ^= 1;
        assert_eq!(
            verify_commitment(
                &start,
                &changed_key,
                &commitment(&start, &responder_public).unwrap()
            ),
            Err(Error::CommitmentMismatch)
        );
        assert_eq!(
            transcript_identity(&accept, &start, &initiator, &responder),
            Err(Error::InvalidMessage)
        );
        let wrong_domain: [u8; 32] = Sha256::digest(
            transcript_bytes(
                b"wrong transcript domain",
                &start,
                &accept,
                &initiator,
                &responder,
            )
            .unwrap(),
        )
        .into();
        assert_ne!(
            wrong_domain,
            transcript_identity(&start, &accept, &initiator, &responder)
                .unwrap()
                .0
        );

        let mut changed_start_bytes = start.canonical_bytes().to_vec();
        *changed_start_bytes.last_mut().unwrap() ^= 1;
        let changed_start = protocol::decode(&changed_start_bytes).unwrap();
        let changed_info = sas_info(&changed_start, &accept, &initiator, &responder)
            .unwrap()
            .1;
        let original_info = sas_info(&start, &accept, &initiator, &responder).unwrap().1;
        let initiator_state = EphemeralSas::new();
        let responder_state = EphemeralSas::new();
        let established = initiator_state
            .establish(&responder_state.public_key())
            .unwrap();
        assert_ne!(
            established.sas(&changed_info).0,
            established.sas(&original_info).0
        );
    }

    #[test]
    fn fresh_vodozemac_states_establish_contributory_sas() {
        let initiator = EphemeralSas::new();
        let responder = EphemeralSas::new();
        let initiator_public = initiator.public_key();
        let responder_public = responder.public_key();
        let info = "same canonical SAS context";
        let initiator_sas = initiator.establish(&responder_public).unwrap();
        let responder_sas = responder.establish(&initiator_public).unwrap();
        let (initiator_bytes, initiator_decimal) = initiator_sas.sas(info);
        let (responder_bytes, responder_decimal) = responder_sas.sas(info);
        assert_eq!(initiator_bytes, responder_bytes);
        assert_eq!(initiator_decimal, responder_decimal);
        assert_eq!(
            format!("{:04} {:04} {:04}", 4442, 5768, 1708),
            "4442 5768 1708"
        );
        assert_ne!(
            initiator_sas.sas(info).0,
            responder_sas.sas("different context").0
        );
    }

    #[test]
    fn rejects_bad_and_noncontributory_peer_keys() {
        let sas = EphemeralSas::new();
        assert_eq!(
            sas.establish(&[0; 31]).unwrap_err(),
            Error::InvalidPeerKeyLength
        );
        let sas = EphemeralSas::new();
        assert_eq!(sas.establish(&[0; 32]).unwrap_err(), Error::NonContributory);
    }

    fn vector_bootstraps() -> (Bootstrap, Bootstrap) {
        let initiator = match vector_frame("START").message {
            Message::Start { bootstrap, .. } => bootstrap,
            _ => unreachable!(),
        };
        let responder = match vector_frame("ACCEPT").message {
            Message::Accept { bootstrap, .. } => bootstrap,
            _ => unreachable!(),
        };
        (initiator, responder)
    }

    #[test]
    fn bootstrap_mac_encodings_match_authoritative_vector_in_both_directions() {
        let json = fixture();
        let identity: [u8; 32] = hex(string(&json, &["ceremony_identity", "hex"]))
            .try_into()
            .unwrap();
        let sas: [u8; 6] = hex(string(&json, &["sas", "raw_bytes", "hex"]))
            .try_into()
            .unwrap();
        let (initiator, responder) = vector_bootstraps();
        assert_eq!(
            initiator.canonical_bytes(),
            hex(string(&json, &["bootstraps", "initiator", "hex"]))
        );
        assert_eq!(
            responder.canonical_bytes(),
            hex(string(&json, &["bootstraps", "responder", "hex"]))
        );
        let request_id = hex(string(&json, &["inputs", "request_id", "hex"]));
        for (name, sender, receiver, own, other) in [
            (
                "initiator",
                Role::Initiator,
                Role::Responder,
                &initiator,
                &responder,
            ),
            (
                "responder",
                Role::Responder,
                Role::Initiator,
                &responder,
                &initiator,
            ),
        ] {
            let d = |path: &[&str]| {
                let mut full = vec!["bootstrap_macs", "directions", name];
                full.extend_from_slice(path);
                string(&json, &full).to_owned()
            };
            assert_eq!(hex(&d(&["sender_role_code"])), [sender as u8]);
            assert_eq!(hex(&d(&["receiver_role_code"])), [receiver as u8]);

            let approval = approval_frame(sender, &identity, &sas, own).unwrap();
            assert_eq!(approval, hex(&d(&["approval_frame", "hex"])));
            assert_eq!(
                approval,
                hex(string(
                    &json,
                    &["bootstrap_approval", "directions", name, "hex"]
                ))
            );
            // Directionality: the statement binds the sender's own bootstrap, never the peer's.
            assert!(approval.ends_with(own.canonical_bytes()));
            assert!(!approval.ends_with(other.canonical_bytes()));
            assert_ne!(
                approval,
                approval_frame(sender, &identity, &sas, other).unwrap()
            );

            let context = approval_context(APPROVAL_PURPOSE, sender, receiver, &identity).unwrap();
            assert_eq!(context, hex(&d(&["context_frame", "hex"])));
            assert_eq!(context, hex(&d(&["mac_context", "canonical_binary_hex"])));

            let (input, info) = bootstrap_mac_strings(sender, &identity, &sas, own).unwrap();
            assert_eq!(input, d(&["approval_input_base64url_unpadded"]));
            assert_eq!(input, d(&["mac_input", "base64url_unpadded"]));
            assert_eq!(input.as_bytes(), hex(&d(&["approval_input_hex"])));
            assert_eq!(input.as_bytes(), hex(&d(&["mac", "input_hex"])));
            assert_eq!(URL_SAFE_NO_PAD.decode(&input).unwrap(), approval);
            assert_eq!(info, d(&["info_string"]));
            assert_eq!(info, d(&["mac_context", "info_string"]));
            assert_eq!(
                info.strip_prefix("sas-pairing-vodozemac-profile-draft-01/mac/")
                    .unwrap(),
                d(&["mac_context", "base64url_unpadded"])
            );
            assert!(!input.contains('=') && !info.contains('='));

            // Wire framing of the fixture's fixed-secret tag; the tag itself is not recomputed.
            let tag: [u8; 32] = hex(&d(&["raw_mac", "hex"])).try_into().unwrap();
            assert_eq!(tag.as_slice(), hex(&d(&["mac", "output_hex"])));
            let wire = Message::BootstrapMac {
                request_id: request_id.clone(),
                sender,
                mac: tag,
            }
            .encode()
            .unwrap();
            assert_eq!(
                wire,
                hex(string(
                    &json,
                    &["wire_messages", "BOOTSTRAP_MAC", name, "hex"]
                ))
            );
        }
    }

    #[test]
    fn completion_encodings_match_authoritative_vector_for_all_three_steps() {
        let json = fixture();
        let identity: [u8; 32] = hex(string(&json, &["ceremony_identity", "hex"]))
            .try_into()
            .unwrap();
        assert_eq!(
            json["completion"]["transcript_digest_equals_ceremony_identity"],
            Value::Bool(true)
        );
        assert_eq!(
            identity.as_slice(),
            hex(string(&json, &["completion", "transcript_digest", "hex"]))
        );
        for (name, step, auth_type, sender, receiver) in [
            (
                "initiator_finish",
                Completion::InitiatorFinish,
                0x35,
                Role::Initiator,
                Role::Responder,
            ),
            (
                "responder_finish_ack",
                Completion::ResponderFinishAck,
                0x36,
                Role::Responder,
                Role::Initiator,
            ),
            (
                "initiator_finish_ack",
                Completion::InitiatorFinishAck,
                0x37,
                Role::Initiator,
                Role::Responder,
            ),
        ] {
            let d = |path: &[&str]| {
                let mut full = vec!["completion", "authentications", name];
                full.extend_from_slice(path);
                string(&json, &full).to_owned()
            };
            assert_eq!(step.purpose(), d(&["purpose"]).as_bytes());
            assert_eq!((step.sender(), step.receiver()), (sender, receiver));
            assert_eq!(hex(&d(&["sender_role_code"])), [sender as u8]);
            assert_eq!(hex(&d(&["receiver_role_code"])), [receiver as u8]);
            assert_eq!(step.auth_frame_type(), auth_type);

            let auth = hex(&d(&["auth_frame", "hex"]));
            assert_eq!(auth[9], auth_type);
            assert_eq!(auth, hex(&d(&["mac_input", "canonical_binary_hex"])));
            assert_eq!(
                completion_auth_frame(auth_type, sender, receiver, &identity, step.purpose())
                    .unwrap(),
                auth
            );
            // The purpose is the final field of the auth frame.
            assert!(auth.ends_with(step.purpose()));
            let context = hex(&d(&["context_frame", "hex"]));
            assert_eq!(context[9], 0x32);
            assert_eq!(context, hex(&d(&["mac_context", "canonical_binary_hex"])));
            assert_eq!(
                mac_context(0x32, step.purpose(), sender, receiver, &identity).unwrap(),
                context
            );
            assert!(context.ends_with(&identity));

            let (input, info) = completion_mac_strings(step, &identity).unwrap();
            assert_eq!(input, d(&["mac_input_base64url_unpadded"]));
            assert_eq!(input, d(&["mac_input", "base64url_unpadded"]));
            assert_eq!(input.as_bytes(), hex(&d(&["mac_input_hex"])));
            assert_eq!(input.as_bytes(), hex(&d(&["mac", "input_hex"])));
            assert_eq!(URL_SAFE_NO_PAD.decode(&input).unwrap(), auth);
            assert_eq!(info, d(&["info_string"]));
            assert_eq!(info, d(&["mac_context", "info_string"]));
            assert_eq!(
                info.strip_prefix("sas-pairing-vodozemac-profile-draft-01/mac/")
                    .unwrap(),
                d(&["mac_context", "base64url_unpadded"])
            );
            assert!(!input.contains('=') && !info.contains('='));
            assert_eq!(
                completion_mac_strings_for_test(
                    auth_type,
                    step.purpose(),
                    sender,
                    receiver,
                    &identity
                ),
                (input, info)
            );
            assert_eq!(
                hex(&d(&["raw_mac", "hex"])),
                hex(&d(&["mac", "output_hex"]))
            );
        }
    }

    #[test]
    fn cancel_encodings_match_authoritative_vector_in_both_directions() {
        let json = fixture();
        let c = &json["cancellation"];
        let identity: [u8; 32] = hex(string(&json, &["ceremony_identity", "hex"]))
            .try_into()
            .unwrap();
        assert_eq!(
            identity.as_slice(),
            hex(c["ceremony_identity"].as_str().unwrap())
        );
        assert_eq!(
            (
                c["auth_frame_type"].as_str(),
                c["mac_context_type"].as_str(),
                c["outer_purpose"].as_str()
            ),
            (Some("0x34"), Some("0x38"), Some("cancel"))
        );
        for (code, reason) in [
            ("01", CancelReason::UserRejection),
            ("02", CancelReason::UserCancellation),
            ("03", CancelReason::Timeout),
            ("04", CancelReason::LocalPolicyFailure),
        ] {
            assert_eq!(hex(code), [reason as u8]);
            assert!(c["reason_codes"][code].is_string());
        }
        let request_id = hex(string(&json, &["inputs", "request_id", "hex"]));
        for (name, sender, receiver, reason, expected_tag) in [
            (
                "initiator",
                Role::Initiator,
                Role::Responder,
                CancelReason::UserCancellation,
                "e4289b39d4ab4e17ef95398f926642bcdf203d21d3d93c33f16785838ebb7652",
            ),
            (
                "responder",
                Role::Responder,
                Role::Initiator,
                CancelReason::Timeout,
                "61c6ca7fa28eba2cd2fd3e3fdc262f9253ffadb8586b3f2fe96d5c9889a4ad42",
            ),
        ] {
            let d = |path: &[&str]| {
                let mut full = vec!["cancellation", "directions", name];
                full.extend_from_slice(path);
                string(&json, &full).to_owned()
            };
            assert_eq!(hex(&d(&["sender_role_code"])), [sender as u8]);
            assert_eq!(hex(&d(&["receiver_role_code"])), [receiver as u8]);
            assert_eq!(hex(&d(&["reason_code"])), [reason as u8]);

            let auth = cancel_auth_frame(sender, receiver, &identity, reason).unwrap();
            assert_eq!(auth, hex(&d(&["auth_frame", "hex"])));
            assert_eq!(auth, hex(&d(&["mac_input", "canonical_binary_hex"])));
            assert_eq!(auth[9], 0x34);
            let context = cancel_context(sender, receiver, &identity, reason).unwrap();
            assert_eq!(context, hex(&d(&["context_frame", "hex"])));
            assert_eq!(context, hex(&d(&["mac_context", "canonical_binary_hex"])));
            assert_eq!(context[9], 0x38);
            // Identical fields and order; only the type byte differs. The reason is last.
            assert_eq!((&auth[..9], &auth[10..]), (&context[..9], &context[10..]));
            assert!(auth.ends_with(&[0, 0, 0, 1, reason as u8]));
            assert!(!context.windows(6).any(|w| w == b"cancel"));

            let (input, info) = cancel_mac_strings(sender, receiver, &identity, reason).unwrap();
            assert_eq!(input, d(&["mac_input_base64url_unpadded"]));
            assert_eq!(input, d(&["mac_input", "base64url_unpadded"]));
            assert_eq!(input.as_bytes(), hex(&d(&["mac_input_hex"])));
            assert_eq!(input.as_bytes(), hex(&d(&["mac", "input_hex"])));
            assert_eq!(URL_SAFE_NO_PAD.decode(&input).unwrap(), auth);
            assert_eq!(info, d(&["info_string"]));
            assert_eq!(info, d(&["mac_context", "info_string"]));
            let encoded = info
                .strip_prefix("sas-pairing-vodozemac-profile-draft-01/cancel/")
                .unwrap();
            assert_eq!(encoded, d(&["mac_context", "base64url_unpadded"]));
            assert_eq!(URL_SAFE_NO_PAD.decode(encoded).unwrap(), context);
            assert!(!info.contains("/mac/"));
            assert!(!input.contains('=') && !info.contains('='));
            assert_eq!(
                cancel_mac_strings_for_test(
                    0x34,
                    0x38,
                    CANCEL_PREFIX,
                    None,
                    sender,
                    receiver,
                    &identity,
                    reason as u8
                ),
                (input, info)
            );

            // Wire framing of the fixture's fixed-secret tag; the tag itself is not recomputed.
            let tag: [u8; 32] = hex(&d(&["raw_mac", "hex"])).try_into().unwrap();
            assert_eq!(tag.as_slice(), hex(expected_tag));
            assert_eq!(tag.as_slice(), hex(&d(&["mac", "output_hex"])));
            let message = Message::Cancel {
                request_id: request_id.clone(),
                sender,
                reason,
                mac: tag,
            };
            let wire = message.encode().unwrap();
            let expected_wire = hex(string(&json, &["wire_messages", "CANCEL", name, "hex"]));
            assert_eq!(wire, expected_wire);
            assert_eq!(wire[9], 0x09);
            let decoded = protocol::decode(&expected_wire).unwrap();
            assert_eq!(decoded.message, message);
            assert_eq!(decoded.canonical_bytes(), expected_wire);
        }
    }

    #[test]
    fn live_bootstrap_mac_verifies_only_the_exact_bound_statement() {
        let (initiator_state, responder_state) = (EphemeralSas::new(), EphemeralSas::new());
        let (initiator_public, responder_public) =
            (initiator_state.public_key(), responder_state.public_key());
        let i = initiator_state.establish(&responder_public).unwrap();
        let r = responder_state.establish(&initiator_public).unwrap();
        let identity = [0x3c; 32];
        let sas = [1, 2, 3, 4, 5, 6];
        let (own, other) = vector_bootstraps();
        let (input, info) = bootstrap_mac_strings(Role::Initiator, &identity, &sas, &own).unwrap();
        let tag = i.calculate_mac(&input, &info).unwrap();
        assert_eq!(r.verify_mac(&input, &info, &tag), Ok(()));

        let reject = |frame: Vec<u8>, context: Vec<u8>| {
            let (input, info) = mac_strings(&frame, &context).unwrap();
            assert_eq!(r.verify_mac(&input, &info, &tag), Err(Error::MacMismatch));
        };
        let context = |purpose: &[u8], sender, receiver, id: &[u8; 32]| {
            approval_context(purpose, sender, receiver, id).unwrap()
        };
        let good_context = context(
            APPROVAL_PURPOSE,
            Role::Initiator,
            Role::Responder,
            &identity,
        );
        let mut other_identity = identity;
        other_identity[31] ^= 1;
        let mut other_sas = sas;
        other_sas[0] ^= 0x80;
        // ceremony_identity in the approval frame, in the context, and in both.
        reject(
            approval_frame(Role::Initiator, &other_identity, &sas, &own).unwrap(),
            good_context.clone(),
        );
        reject(
            approval_frame(Role::Initiator, &identity, &sas, &own).unwrap(),
            context(
                APPROVAL_PURPOSE,
                Role::Initiator,
                Role::Responder,
                &other_identity,
            ),
        );
        let (moved_input, moved_info) =
            bootstrap_mac_strings(Role::Initiator, &other_identity, &sas, &own).unwrap();
        assert_eq!(
            r.verify_mac(&moved_input, &moved_info, &tag),
            Err(Error::MacMismatch)
        );
        // Six raw SAS bytes.
        reject(
            approval_frame(Role::Initiator, &identity, &other_sas, &own).unwrap(),
            good_context.clone(),
        );
        // Sender bootstrap: the peer's bootstrap, or a one-byte change to the sender's.
        reject(
            approval_frame(Role::Initiator, &identity, &sas, &other).unwrap(),
            good_context.clone(),
        );
        let altered = Bootstrap::new(
            own.application_identity().to_vec(),
            own.key_algorithm().to_vec(),
            own.public_key().to_vec(),
            [own.shared_context(), b"!"].concat(),
        )
        .unwrap();
        reject(
            approval_frame(Role::Initiator, &identity, &sas, &altered).unwrap(),
            good_context.clone(),
        );
        // Sender role in the approval frame; sender and receiver roles in the context.
        reject(
            approval_frame(Role::Responder, &identity, &sas, &own).unwrap(),
            good_context.clone(),
        );
        let frame = approval_frame(Role::Initiator, &identity, &sas, &own).unwrap();
        reject(
            frame.clone(),
            context(
                APPROVAL_PURPOSE,
                Role::Responder,
                Role::Responder,
                &identity,
            ),
        );
        reject(
            frame.clone(),
            context(
                APPROVAL_PURPOSE,
                Role::Initiator,
                Role::Initiator,
                &identity,
            ),
        );
        // Opposite direction (swapped sender/receiver) and a different purpose.
        reject(
            frame.clone(),
            context(
                APPROVAL_PURPOSE,
                Role::Responder,
                Role::Initiator,
                &identity,
            ),
        );
        reject(
            frame.clone(),
            context(
                b"initiator-finish",
                Role::Initiator,
                Role::Responder,
                &identity,
            ),
        );
        // The MAC input is Base64url of the frame, not its hex or a lossy text rendering.
        let (_, info) = mac_strings(&frame, &good_context).unwrap();
        let hex_input: String = frame.iter().map(|b| format!("{b:02x}")).collect();
        let lossy_input = String::from_utf8_lossy(&frame).into_owned();
        for wrong in [hex_input, lossy_input] {
            assert_eq!(r.verify_mac(&wrong, &info, &tag), Err(Error::MacMismatch));
        }
        // One flipped tag bit.
        let mut flipped = tag;
        flipped[7] ^= 0x10;
        assert_eq!(
            r.verify_mac(&input, &info, &flipped),
            Err(Error::MacMismatch)
        );
        // Another live session cannot verify this session's tag.
        let (x, y) = (EphemeralSas::new(), EphemeralSas::new());
        let unrelated = x.establish(&y.public_key()).unwrap();
        assert_eq!(
            unrelated.verify_mac(&input, &info, &tag),
            Err(Error::MacMismatch)
        );
    }

    #[test]
    fn generated_mac_strings_are_capped_including_prefix() {
        let encoded = |n: usize| n / 3 * 4 + [0, 2, 3][n % 3];
        for prefix in [&b""[..], MAC_PREFIX, CANCEL_PREFIX] {
            let (mut accepted, mut rejected) = (false, false);
            for n in 49_100..49_160 {
                let fits = prefix.len() + encoded(n) <= CRYPTO_INPUT_LIMIT;
                match capped_base64url(prefix, &vec![0; n]) {
                    Ok(value) => {
                        assert!(fits);
                        assert_eq!(value.len(), prefix.len() + encoded(n));
                        accepted = true;
                    }
                    Err(error) => {
                        assert!(!fits);
                        assert_eq!(error, Error::Oversized);
                        rejected = true;
                    }
                }
            }
            assert!(accepted && rejected);
        }
        assert_eq!(
            capped_base64url(b"", &vec![0; 49_152]).unwrap().len(),
            CRYPTO_INPUT_LIMIT
        );
        assert_eq!(
            capped_base64url(b"", &vec![0; 49_153]),
            Err(Error::Oversized)
        );
        // The largest valid bootstrap still yields approval inputs well within the cap.
        let largest = Bootstrap::new(
            vec![b'a'; 1024],
            vec![b'a'; 64],
            vec![0; 4096],
            vec![0; 8192],
        )
        .unwrap();
        let (input, info) =
            bootstrap_mac_strings(Role::Responder, &[0; 32], &[0; 6], &largest).unwrap();
        assert!(input.len() <= CRYPTO_INPUT_LIMIT && info.len() <= CRYPTO_INPUT_LIMIT);
    }

    #[test]
    fn checked_frame_lengths_and_crypto_input_caps_fail_closed() {
        assert_eq!(checked_frame_len(&[usize::MAX]), Err(Error::LengthOverflow));
        assert_eq!(checked_frame_len(&[MAX_FRAME]), Err(Error::Oversized));
        assert_eq!(frame(0x30, &[&vec![0; MAX_FRAME]]), Err(Error::Oversized));
        let context = frame(0x30, &[&vec![0; 49_200]]).unwrap();
        assert!(context.len() <= MAX_FRAME);
        assert!(matches!(
            sas_info_from_context(&context),
            Err(Error::Oversized)
        ));
    }
}
