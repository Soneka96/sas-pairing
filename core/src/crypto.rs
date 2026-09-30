//! Internal P3 cryptographic primitives. No ceremony or application API is exposed.

#![allow(dead_code)]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use vodozemac::{
    Curve25519PublicKey,
    sas::{EstablishedSas, Sas, SasBytes},
};

use crate::protocol::{DecodedMessage, MAX_FRAME, Message, PROFILE_ID};

const COMMIT_DOMAIN: &[u8] = b"sas-pairing-vodozemac-profile-draft-01/commit/v1";
const TRANSCRIPT_DOMAIN: &[u8] = b"sas-pairing-vodozemac-profile-draft-01/transcript/v1";
const SAS_PREFIX: &[u8] = b"sas-pairing-vodozemac-profile-draft-01/sas/";
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

fn sas_info_from_context(context: &[u8]) -> Result<String, Error> {
    let encoded_len = context
        .len()
        .checked_div(3)
        .and_then(|len| len.checked_mul(4))
        .and_then(|len| {
            len.checked_add(match context.len() % 3 {
                0 => 0,
                1 => 2,
                _ => 3,
            })
        })
        .ok_or(Error::LengthOverflow)?;
    let total_len = SAS_PREFIX
        .len()
        .checked_add(encoded_len)
        .ok_or(Error::LengthOverflow)?;
    if total_len > CRYPTO_INPUT_LIMIT {
        return Err(Error::Oversized);
    }
    let mut info = Vec::with_capacity(total_len);
    info.extend_from_slice(SAS_PREFIX);
    info.extend_from_slice(URL_SAFE_NO_PAD.encode(context).as_bytes());
    Ok(String::from_utf8(info).expect("ASCII context"))
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
            b"org.sas-pairing",
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
