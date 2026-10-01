//! Canonical P3 remote wire codec. This validates syntax only; it performs no
//! authentication, cryptographic validation, or ceremony state transitions.

use std::fmt;

pub const PROFILE_ID: &[u8] = b"sas-pairing-vodozemac-profile-draft-01";
const MAGIC: &[u8; 7] = b"SASPAIR";
pub(crate) const VERSION: u16 = 1;
pub const MAX_FRAME: usize = 65_536;
pub const MAX_BOOTSTRAP_FRAME: usize = 16_384;
const START_TYPE: u8 = 0x01;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    Truncated,
    BadMagic,
    UnsupportedVersion(u16),
    UnknownType(u8),
    InvalidField(&'static str),
    Oversized,
    TrailingBytes,
    LengthOverflow,
}
impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for CodecError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Role {
    Initiator = 1,
    Responder = 2,
}
impl TryFrom<u8> for Role {
    type Error = CodecError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Initiator),
            2 => Ok(Self::Responder),
            _ => Err(CodecError::InvalidField("role")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bootstrap {
    application_identity: Vec<u8>,
    key_algorithm: Vec<u8>,
    public_key: Vec<u8>,
    shared_context: Vec<u8>,
    canonical: Vec<u8>,
}
impl Bootstrap {
    pub fn new(
        application_identity: Vec<u8>,
        key_algorithm: Vec<u8>,
        public_key: Vec<u8>,
        shared_context: Vec<u8>,
    ) -> Result<Self, CodecError> {
        let mut value = Self {
            application_identity,
            key_algorithm,
            public_key,
            shared_context,
            canonical: Vec::new(),
        };
        value.validate()?;
        value.canonical = encode_frame(
            0x20,
            &[
                &value.application_identity,
                &value.key_algorithm,
                &value.public_key,
                &value.shared_context,
            ],
            MAX_BOOTSTRAP_FRAME,
        )?;
        Ok(value)
    }
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
    pub fn application_identity(&self) -> &[u8] {
        &self.application_identity
    }
    pub fn key_algorithm(&self) -> &[u8] {
        &self.key_algorithm
    }
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
    pub fn shared_context(&self) -> &[u8] {
        &self.shared_context
    }
    fn validate(&self) -> Result<(), CodecError> {
        bounded(&self.application_identity, 1, 1024, "application_identity")?;
        bounded(&self.key_algorithm, 1, 64, "key_algorithm")?;
        if !self.key_algorithm.is_ascii()
            || !self.key_algorithm[0].is_ascii_lowercase()
                && !self.key_algorithm[0].is_ascii_digit()
            || !self
                .key_algorithm
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'.' || *b == b'-')
        {
            return Err(CodecError::InvalidField("key_algorithm"));
        }
        bounded(&self.public_key, 1, 4096, "public_key")?;
        bounded(&self.shared_context, 0, 8192, "shared_context")
    }
    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() > MAX_BOOTSTRAP_FRAME {
            return Err(CodecError::Oversized);
        }
        let (kind, fields) = parse(bytes)?;
        if kind != 0x20 || fields.len() != 4 {
            return Err(CodecError::InvalidField("bootstrap"));
        }
        let value = Self {
            application_identity: fields[0].to_vec(),
            key_algorithm: fields[1].to_vec(),
            public_key: fields[2].to_vec(),
            shared_context: fields[3].to_vec(),
            canonical: bytes.to_vec(),
        };
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Start {
        request_id: Vec<u8>,
        bootstrap: Bootstrap,
    },
    Accept {
        request_id: Vec<u8>,
        commitment: [u8; 32],
        bootstrap: Bootstrap,
    },
    InitiatorKey {
        request_id: Vec<u8>,
        public_key: [u8; 32],
    },
    ResponderKey {
        request_id: Vec<u8>,
        public_key: [u8; 32],
    },
    BootstrapMac {
        request_id: Vec<u8>,
        sender: Role,
        mac: [u8; 32],
    },
    InitiatorFinish {
        request_id: Vec<u8>,
        transcript: [u8; 32],
        mac: [u8; 32],
    },
    ResponderFinishAck {
        request_id: Vec<u8>,
        transcript: [u8; 32],
        mac: [u8; 32],
    },
    InitiatorFinishAck {
        request_id: Vec<u8>,
        transcript: [u8; 32],
        mac: [u8; 32],
    },
    Cancel {
        request_id: Vec<u8>,
        sender: Role,
        reason: CancelReason,
        mac: [u8; 32],
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CancelReason {
    UserRejection = 1,
    UserCancellation = 2,
    Timeout = 3,
    LocalPolicyFailure = 4,
}
impl TryFrom<u8> for CancelReason {
    type Error = CodecError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::UserRejection),
            2 => Ok(Self::UserCancellation),
            3 => Ok(Self::Timeout),
            4 => Ok(Self::LocalPolicyFailure),
            _ => Err(CodecError::InvalidField("reason")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedMessage {
    pub message: Message,
    canonical: Vec<u8>,
}
impl DecodedMessage {
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
}

impl Message {
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        let (kind, request_id, fields): (u8, &Vec<u8>, Vec<Vec<u8>>) = match self {
            Self::Start {
                request_id,
                bootstrap,
            } => (
                START_TYPE,
                request_id,
                vec![bootstrap.canonical_bytes().to_vec()],
            ),
            Self::Accept {
                request_id,
                commitment,
                bootstrap,
            } => (
                2,
                request_id,
                vec![commitment.to_vec(), bootstrap.canonical_bytes().to_vec()],
            ),
            Self::InitiatorKey {
                request_id,
                public_key,
            } => (3, request_id, vec![public_key.to_vec()]),
            Self::ResponderKey {
                request_id,
                public_key,
            } => (4, request_id, vec![public_key.to_vec()]),
            Self::BootstrapMac {
                request_id,
                sender,
                mac,
            } => (5, request_id, vec![vec![*sender as u8], mac.to_vec()]),
            Self::InitiatorFinish {
                request_id,
                transcript,
                mac,
            } => (6, request_id, vec![transcript.to_vec(), mac.to_vec()]),
            Self::ResponderFinishAck {
                request_id,
                transcript,
                mac,
            } => (7, request_id, vec![transcript.to_vec(), mac.to_vec()]),
            Self::InitiatorFinishAck {
                request_id,
                transcript,
                mac,
            } => (8, request_id, vec![transcript.to_vec(), mac.to_vec()]),
            Self::Cancel {
                request_id,
                sender,
                reason,
                mac,
            } => (
                9,
                request_id,
                vec![vec![*sender as u8], vec![*reason as u8], mac.to_vec()],
            ),
        };
        bounded(request_id, 1, 64, "request_id")?;
        let mut refs: Vec<&[u8]> = Vec::with_capacity(fields.len() + 2);
        refs.push(PROFILE_ID);
        refs.push(request_id);
        refs.extend(fields.iter().map(Vec::as_slice));
        encode_frame(kind, &refs, MAX_FRAME)
    }
}

pub fn decode(bytes: &[u8]) -> Result<DecodedMessage, CodecError> {
    let (kind, f) = parse_wire(bytes)?;
    if kind == START_TYPE {
        // The one START path: candidate structure first, then bootstrap semantics.
        return StartCandidate::from_wire(bytes, &f)?.decode();
    }
    if wire_field_count(kind) != Some(f.len()) {
        return Err(CodecError::InvalidField("field_count"));
    }
    let fixed = |i: usize| -> Result<[u8; 32], CodecError> {
        (*f.get(i).ok_or(CodecError::Truncated)?)
            .try_into()
            .map_err(|_| CodecError::InvalidField("fixed_32"))
    };
    let request_id = f[1].to_vec();
    let message = match kind {
        2 => Message::Accept {
            request_id,
            commitment: fixed(2)?,
            bootstrap: Bootstrap::decode(f[3])?,
        },
        3 => Message::InitiatorKey {
            request_id,
            public_key: fixed(2)?,
        },
        4 => Message::ResponderKey {
            request_id,
            public_key: fixed(2)?,
        },
        5 => Message::BootstrapMac {
            request_id,
            sender: Role::try_from(one(f[2], "role")?)?,
            mac: fixed(3)?,
        },
        6..=8 => {
            let transcript = fixed(2)?;
            let mac = fixed(3)?;
            match kind {
                6 => Message::InitiatorFinish {
                    request_id,
                    transcript,
                    mac,
                },
                7 => Message::ResponderFinishAck {
                    request_id,
                    transcript,
                    mac,
                },
                _ => Message::InitiatorFinishAck {
                    request_id,
                    transcript,
                    mac,
                },
            }
        }
        9 => Message::Cancel {
            request_id,
            sender: Role::try_from(one(f[2], "role")?)?,
            reason: CancelReason::try_from(one(f[3], "reason")?)?,
            mac: fixed(4)?,
        },
        _ => return Err(CodecError::UnknownType(kind)),
    };
    Ok(DecodedMessage {
        message,
        canonical: bytes.to_vec(),
    })
}

/// A complete syntactically framed START (P3 §11.1.1 START candidate boundary): one canonical
/// §3.1 wire frame within `MAX_FRAME` with exact magic, version, field boundaries, and no
/// trailing bytes; message type START with exactly its three fields; the exact profile ID; and
/// a 1–64-byte request ID. The bootstrap field is still opaque, unvalidated bytes: its nested
/// frame, size maxima, `key_algorithm` grammar, and every §8 check are START semantic
/// validation, run by `decode` only after the authority START limiter has charged. It carries
/// no authority, authentication, trust, ceremony identity, or limiter state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StartCandidate<'a> {
    request_id: &'a [u8],
    bootstrap: &'a [u8],
    canonical: &'a [u8],
}

impl<'a> StartCandidate<'a> {
    /// The START-specific structure on top of `parse_wire`; shared with `decode`.
    fn from_wire(canonical: &'a [u8], f: &[&'a [u8]]) -> Result<Self, CodecError> {
        if wire_field_count(START_TYPE) != Some(f.len()) {
            return Err(CodecError::InvalidField("field_count"));
        }
        Ok(Self {
            request_id: f[1],
            bootstrap: f[2],
            canonical,
        })
    }

    /// START semantic decoding of the opaque bootstrap field into the canonical message.
    pub(crate) fn decode(self) -> Result<DecodedMessage, CodecError> {
        Ok(DecodedMessage {
            message: Message::Start {
                request_id: self.request_id.to_vec(),
                bootstrap: Bootstrap::decode(self.bootstrap)?,
            },
            canonical: self.canonical.to_vec(),
        })
    }
}

/// Structural START classification only; see `StartCandidate`. Any other wire type, and every
/// frame/header/profile/request-ID failure, is a codec rejection and not a candidate.
pub(crate) fn start_candidate(bytes: &[u8]) -> Result<StartCandidate<'_>, CodecError> {
    let (kind, f) = parse_wire(bytes)?;
    if kind != START_TYPE {
        return Err(CodecError::InvalidField("message_type"));
    }
    StartCandidate::from_wire(bytes, &f)
}

/// The dispatch boundary of one complete received wire frame (P3 §3.1, §4, §11.1.1, §11.2): both
/// common fields are checked before dispatch, and only a START candidate may reach admission. No
/// field is decoded: the START bootstrap stays opaque for the limiter-first admission path, and
/// every other type's fields are left to the run the Router selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Routable<'a> {
    /// A START candidate (`start_candidate`): a new candidate for Router admission, or the
    /// duplicate/conflict rule of the run already routed under its key.
    Start { request_id: &'a [u8] },
    /// A structurally routable non-START frame (§11.2): another defined type with the exact
    /// profile ID and a 1–64-byte request ID, deliverable only to the run under its key.
    Run { request_id: &'a [u8] },
}

/// Classifies one complete frame by `Routable`. An error is structurally unroutable input: a
/// codec/transport rejection that must reach no run, admission, or limiter.
pub(crate) fn routable(bytes: &[u8]) -> Result<Routable<'_>, CodecError> {
    let (kind, f) = parse_wire(bytes)?;
    if kind != START_TYPE {
        return Ok(Routable::Run { request_id: f[1] });
    }
    let candidate = StartCandidate::from_wire(bytes, &f)?;
    Ok(Routable::Start {
        request_id: candidate.request_id,
    })
}

/// Routing fields only (P3 §4): the defined wire type and the canonical 1–64-byte request ID of
/// one structurally framed message (`parse_wire`). Nothing type-specific is decoded and the
/// result carries no authority: the run it is routed to still validates the complete message.
pub(crate) fn route_fields(bytes: &[u8]) -> Result<(u8, &[u8]), CodecError> {
    let (kind, f) = parse_wire(bytes)?;
    Ok((kind, f[1]))
}

/// The outer wire-message structure shared by `decode` and `start_candidate`: frame maximum,
/// §3.1 framing, a defined wire type, and both common fields. Nothing type-specific.
fn parse_wire(bytes: &[u8]) -> Result<(u8, Vec<&[u8]>), CodecError> {
    let (kind, f) = parse(bytes)?;
    if wire_field_count(kind).is_none() {
        return Err(CodecError::UnknownType(kind));
    }
    if f.len() < 2 || f[0] != PROFILE_ID {
        return Err(CodecError::InvalidField("profile_id"));
    }
    bounded(f[1], 1, 64, "request_id")?;
    Ok((kind, f))
}

fn one(field: &[u8], name: &'static str) -> Result<u8, CodecError> {
    if field.len() == 1 {
        Ok(field[0])
    } else {
        Err(CodecError::InvalidField(name))
    }
}
fn bounded(bytes: &[u8], min: usize, max: usize, name: &'static str) -> Result<(), CodecError> {
    if (min..=max).contains(&bytes.len()) {
        Ok(())
    } else {
        Err(CodecError::InvalidField(name))
    }
}
fn encode_frame(kind: u8, fields: &[&[u8]], max: usize) -> Result<Vec<u8>, CodecError> {
    let mut size = 10usize;
    for field in fields {
        size = size
            .checked_add(4)
            .and_then(|n| n.checked_add(field.len()))
            .ok_or(CodecError::LengthOverflow)?;
    }
    if size > max || size > MAX_FRAME {
        return Err(CodecError::Oversized);
    }
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_be_bytes());
    out.push(kind);
    for field in fields {
        let len = u32::try_from(field.len()).map_err(|_| CodecError::Oversized)?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(field);
    }
    Ok(out)
}

/// The outer field count of each defined wire message type (§6), including both common fields.
/// The one table shared by `decode`, the START candidate, and `wire_frame_extent`, so the codec
/// and the transport frame assembler cannot disagree about where a wire frame ends.
pub(crate) const fn wire_field_count(kind: u8) -> Option<usize> {
    match kind {
        START_TYPE | 3 | 4 => Some(3),
        2 | 5..=8 => Some(4),
        9 => Some(5),
        _ => None,
    }
}

/// How much of a wire frame a byte-stream prefix determines; see `wire_frame_extent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Extent {
    /// Nothing more is known until the prefix holds at least this many bytes (`<= MAX_FRAME`,
    /// always more than the prefix holds).
    Need(usize),
    /// Every field length is known: the complete frame is exactly this many bytes
    /// (`<= MAX_FRAME`), which the prefix may not hold yet.
    Frame(usize),
}

/// Outer extent of the wire frame at the start of `prefix`, a byte-stream prefix of any length
/// that begins at a frame boundary (P3 §3.1 fragmented input). It checks the §3.1 header (magic,
/// then version) and a defined wire type as soon as their bytes are present, then walks the type's
/// exact field count (`wire_field_count`), reading each `u32be` length. Each declaration is
/// checked when read, before its payload is needed and with checked arithmetic: the frame so far
/// plus the remaining fields' length prefixes must stay within `MAX_FRAME`, so no byte is ever
/// expected beyond the maximum. It reads only length prefixes, never payloads, and decodes
/// nothing: profile ID, request ID, and every field value are left to `decode`, `route_fields`,
/// and `start_candidate` on the complete frame.
pub(crate) fn wire_frame_extent(prefix: &[u8]) -> Result<Extent, CodecError> {
    let Some(kind) = header(prefix)? else {
        return Ok(Extent::Need(10));
    };
    let fields = wire_field_count(kind).ok_or(CodecError::UnknownType(kind))?;
    // Invariant: `pos` plus 4 bytes for each field still to come is at most MAX_FRAME.
    let mut pos = 10usize;
    for later in (0..fields).rev() {
        let end_len = pos + 4;
        let Some(len) = prefix.get(pos..end_len) else {
            return Ok(Extent::Need(end_len));
        };
        let len = u32::from_be_bytes(len.try_into().unwrap()) as usize;
        pos = end_len
            .checked_add(len)
            .filter(|end| {
                end.checked_add(4 * later)
                    .is_some_and(|min| min <= MAX_FRAME)
            })
            .ok_or(CodecError::Oversized)?;
    }
    Ok(Extent::Frame(pos))
}

/// The §3.1 header checks on however many header bytes `prefix` holds: magic, then version.
/// Returns the type byte once present.
fn header(prefix: &[u8]) -> Result<Option<u8>, CodecError> {
    let magic = prefix.len().min(MAGIC.len());
    if prefix[..magic] != MAGIC[..magic] {
        return Err(CodecError::BadMagic);
    }
    let [_, _, _, _, _, _, _, high, low, rest @ ..] = prefix else {
        return Ok(None);
    };
    let version = u16::from_be_bytes([*high, *low]);
    if version != VERSION {
        return Err(CodecError::UnsupportedVersion(version));
    }
    Ok(rest.first().copied())
}

fn parse(bytes: &[u8]) -> Result<(u8, Vec<&[u8]>), CodecError> {
    if bytes.len() < 10 {
        return Err(CodecError::Truncated);
    }
    if bytes.len() > MAX_FRAME {
        return Err(CodecError::Oversized);
    }
    let kind = header(bytes)?.ok_or(CodecError::Truncated)?;
    let mut pos = 10usize;
    let mut fields = Vec::new();
    while pos < bytes.len() {
        let end_len = pos.checked_add(4).ok_or(CodecError::LengthOverflow)?;
        if end_len > bytes.len() {
            return Err(CodecError::Truncated);
        }
        let len = u32::from_be_bytes(bytes[pos..end_len].try_into().unwrap()) as usize;
        let end = end_len.checked_add(len).ok_or(CodecError::LengthOverflow)?;
        if end > bytes.len() {
            return Err(CodecError::Truncated);
        }
        fields.push(&bytes[end_len..end]);
        pos = end;
    }
    Ok((kind, fields))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    fn boot(hex_frame: &str) -> Bootstrap {
        Bootstrap::decode(&hex(hex_frame)).unwrap()
    }
    const IBOOT: &str = "53415350414952000120000000227361732d70616972696e672074657374206669787475726520696e69746961746f7200000007656432353531390000002079b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad0496640000001b7361732d70616972696e672f636f6e746578742f746573742d7631";
    const RBOOT: &str = "53415350414952000120000000227361732d70616972696e672074657374206669787475726520726573706f6e646572000000076564323535313900000020e7f162a10bec559afea195e4dce84b69568d5d2cb0963eb446c0685e2b17f2f00000001b7361732d70616972696e672f636f6e746578742f746573742d7631";
    const RID: &str = "000102030405060708090a0b0c0d0e0f";
    const PROFILE: &str =
        "7361732d70616972696e672d766f646f7a656d61632d70726f66696c652d64726166742d3031";
    const START: &str = "53415350414952000101000000267361732d70616972696e672d766f646f7a656d61632d70726f66696c652d64726166742d303100000010000102030405060708090a0b0c0d0e0f0000007e53415350414952000120000000227361732d70616972696e672074657374206669787475726520696e69746961746f7200000007656432353531390000002079b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad0496640000001b7361732d70616972696e672f636f6e746578742f746573742d7631";
    const ACCEPT: &str = "53415350414952000102000000267361732d70616972696e672d766f646f7a656d61632d70726f66696c652d64726166742d303100000010000102030405060708090a0b0c0d0e0f000000203c8739ad0efadd2a0453a0b7513a441764cbf5acae216543ae6494c654a2b5710000007e53415350414952000120000000227361732d70616972696e672074657374206669787475726520726573706f6e646572000000076564323535313900000020e7f162a10bec559afea195e4dce84b69568d5d2cb0963eb446c0685e2b17f2f00000001b7361732d70616972696e672f636f6e746578742f746573742d7631";
    const IK: &str = "53415350414952000103000000267361732d70616972696e672d766f646f7a656d61632d70726f66696c652d64726166742d303100000010000102030405060708090a0b0c0d0e0f0000002007a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c";
    const RK: &str = "53415350414952000104000000267361732d70616972696e672d766f646f7a656d61632d70726f66696c652d64726166742d303100000010000102030405060708090a0b0c0d0e0f000000205869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b";
    const BM: &str = "53415350414952000105000000267361732d70616972696e672d766f646f7a656d61632d70726f66696c652d64726166742d303100000010000102030405060708090a0b0c0d0e0f00000001010000002083920d83a0c5c5fb2bff5a65f4723106ea253cb3102ba58e2e06d32f95e86853";
    const IF: &str = "53415350414952000106000000267361732d70616972696e672d766f646f7a656d61632d70726f66696c652d64726166742d303100000010000102030405060708090a0b0c0d0e0f000000203c9d1e03323ba12046fa2021391fdd22d6883a6e69a493801c0ab8703ad70c1c0000002024b6a87e3a885b2fe2fd798f3ebd917f87dbadc567974313483e55c67508c30e";
    const RFA: &str = "53415350414952000107000000267361732d70616972696e672d766f646f7a656d61632d70726f66696c652d64726166742d303100000010000102030405060708090a0b0c0d0e0f000000203c9d1e03323ba12046fa2021391fdd22d6883a6e69a493801c0ab8703ad70c1c00000020358d79b9fcbc73b57c6c8339fa644b018ee2f34ebe986e371042f59973d628c8";
    const IFA: &str = "53415350414952000108000000267361732d70616972696e672d766f646f7a656d61632d70726f66696c652d64726166742d303100000010000102030405060708090a0b0c0d0e0f000000203c9d1e03323ba12046fa2021391fdd22d6883a6e69a493801c0ab8703ad70c1c00000020f309fcd8da269c12a5d380ddfe626c9cee1c153d8bf5e6e90b24f78d2e6baec6";
    const CANCEL_I: &str = "53415350414952000109000000267361732d70616972696e672d766f646f7a656d61632d70726f66696c652d64726166742d303100000010000102030405060708090a0b0c0d0e0f0000000101000000010200000020e4289b39d4ab4e17ef95398f926642bcdf203d21d3d93c33f16785838ebb7652";
    const CANCEL_R: &str = "53415350414952000109000000267361732d70616972696e672d766f646f7a656d61632d70726f66696c652d64726166742d303100000010000102030405060708090a0b0c0d0e0f000000010200000001030000002061c6ca7fa28eba2cd2fd3e3fdc262f9253ffadb8586b3f2fe96d5c9889a4ad42";

    #[test]
    fn authoritative_vectors_and_all_nine_types_round_trip() {
        let cases = [START, ACCEPT, IK, RK, BM, IF, RFA, IFA, CANCEL_I, CANCEL_R];
        for expected in cases {
            let bytes = hex(expected);
            let parsed = decode(&bytes).unwrap();
            assert_eq!(parsed.canonical_bytes(), bytes);
            assert_eq!(parsed.message.encode().unwrap(), bytes);
        }
        assert_eq!(boot(IBOOT).canonical_bytes(), hex(IBOOT));
        assert_eq!(boot(RBOOT).canonical_bytes(), hex(RBOOT));

        let rid = hex(RID);
        let mac = [0x55; 32];
        let cancel = Message::Cancel {
            request_id: rid,
            sender: Role::Responder,
            reason: CancelReason::Timeout,
            mac,
        };
        let encoded = cancel.encode().unwrap();
        assert_eq!(decode(&encoded).unwrap().message, cancel);
        for (vector, sender, reason) in [
            (CANCEL_I, Role::Initiator, CancelReason::UserCancellation),
            (CANCEL_R, Role::Responder, CancelReason::Timeout),
        ] {
            assert!(matches!(
                decode(&hex(vector)).unwrap().message,
                Message::Cancel { sender: s, reason: r, .. } if s == sender && r == reason
            ));
        }
    }

    #[test]
    fn rejects_bad_headers_fields_truncation_and_trailing_data() {
        let valid = hex(IK);
        for (index, value, expected) in [
            (0, b'X', CodecError::BadMagic),
            (8, 2, CodecError::UnsupportedVersion(2)),
            (9, 0x7f, CodecError::UnknownType(0x7f)),
        ] {
            let mut bad = valid.clone();
            bad[index] = value;
            assert_eq!(decode(&bad).unwrap_err(), expected);
        }
        assert!(decode(&valid[..valid.len() - 1]).is_err());
        let mut extra = valid.clone();
        extra.extend_from_slice(&[0]);
        assert!(decode(&extra).is_err());
        let mut missing = valid.clone();
        missing.truncate(missing.len() - 36);
        assert!(decode(&missing).is_err());
        let mut bad_profile = valid.clone();
        let pos = 14;
        bad_profile[pos] ^= 1;
        assert!(decode(&bad_profile).is_err());
        let mut extra_field = valid.clone();
        extra_field.extend_from_slice(&[0, 0, 0, 0]);
        assert!(decode(&extra_field).is_err());
        let mut bad_role = hex(BM);
        bad_role[76] = 3;
        assert!(decode(&bad_role).is_err());
        let mut bad_reason = Message::Cancel {
            request_id: hex(RID),
            sender: Role::Initiator,
            reason: CancelReason::UserRejection,
            mac: [0; 32],
        }
        .encode()
        .unwrap();
        bad_reason[81] = 5;
        assert!(decode(&bad_reason).is_err());
    }

    #[test]
    fn exact_resource_boundaries_and_untrusted_lengths() {
        let boot_ok = Bootstrap::new(
            vec![b'a'; 1024],
            b"ed25519".to_vec(),
            vec![0; 4096],
            vec![0; 8192],
        )
        .unwrap();
        assert!(boot_ok.canonical_bytes().len() <= MAX_BOOTSTRAP_FRAME);
        assert!(
            Bootstrap::new(vec![b'a'; 1025], b"ed25519".to_vec(), vec![0; 32], vec![]).is_err()
        );
        assert!(Bootstrap::new(vec![b'a'], b"Ed25519".to_vec(), vec![0; 32], vec![]).is_err());
        let mut giant = hex(IK);
        giant[10..14].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode(&giant).is_err());
        let payload_len = (MAX_FRAME - 14) as u32;
        let at_limit = [
            &b"SASPAIR\0\x01\x7f"[..],
            &payload_len.to_be_bytes(),
            &vec![0; MAX_FRAME - 14],
        ]
        .concat();
        assert!(parse(&at_limit).is_ok());
        assert_eq!(
            parse(&[at_limit.as_slice(), &[0]].concat()).unwrap_err(),
            CodecError::Oversized
        );
        assert_eq!(
            Bootstrap::decode(&vec![0; MAX_BOOTSTRAP_FRAME + 1]).unwrap_err(),
            CodecError::Oversized
        );
        assert_eq!(
            decode(&vec![0; MAX_FRAME + 1]).unwrap_err(),
            CodecError::Oversized
        );
        assert_eq!(hex(PROFILE), PROFILE_ID);
        let key = [0; 32];
        let id64 = Message::InitiatorKey {
            request_id: vec![7; 64],
            public_key: key,
        };
        assert!(decode(&id64.encode().unwrap()).is_ok());
        let id65 = Message::InitiatorKey {
            request_id: vec![7; 65],
            public_key: key,
        };
        assert!(id65.encode().is_err());

        let mut empty_start = hex(START);
        let profile_len = u32::from_be_bytes(empty_start[10..14].try_into().unwrap()) as usize;
        let request_id_len_at = 18 + profile_len;
        let request_id_at = request_id_len_at + 4;
        empty_start.drain(request_id_at..request_id_at + 16);
        empty_start[request_id_len_at..request_id_at].copy_from_slice(&0u32.to_be_bytes());
        assert!(decode(&empty_start).is_err());

        let mut oversized_start = hex(START);
        let request_id_len_at =
            18 + u32::from_be_bytes(oversized_start[10..14].try_into().unwrap()) as usize;
        let request_id_at = request_id_len_at + 4;
        oversized_start.splice(request_id_at..request_id_at + 16, vec![7; 65]);
        oversized_start[request_id_len_at..request_id_at].copy_from_slice(&65u32.to_be_bytes());
        assert!(decode(&oversized_start).is_err());
        assert!(Bootstrap::new(vec![b'a'], vec![b'a'; 64], vec![0], vec![0; 8192]).is_ok());
        assert!(Bootstrap::new(vec![b'a'], b"a".to_vec(), vec![0], vec![0; 8193]).is_err());
    }

    #[test]
    fn stream_extent_and_the_codec_share_one_frame_layout() {
        let vectors = [START, ACCEPT, IK, RK, BM, IF, RFA, IFA, CANCEL_I, CANCEL_R];
        for kind in 0..=u8::MAX {
            let defined = (1..=9).contains(&kind);
            assert_eq!(wire_field_count(kind).is_some(), defined, "{kind}");
        }
        for vector in vectors {
            let bytes = hex(vector);
            let (kind, fields) = parse_wire(&bytes).unwrap();
            assert_eq!(wire_field_count(kind), Some(fields.len()));
            // Every prefix either needs strictly more bytes or names exactly this frame, and
            // trailing stream bytes never change the extent.
            let mut last_need = 0;
            for end in 0..=bytes.len() {
                match wire_frame_extent(&bytes[..end]).unwrap() {
                    Extent::Need(n) => {
                        assert!(n > end && n <= bytes.len() && n >= last_need);
                        last_need = n;
                    }
                    Extent::Frame(total) => assert_eq!(total, bytes.len()),
                }
            }
            let stream = [bytes.as_slice(), &bytes].concat();
            assert_eq!(
                wire_frame_extent(&stream).unwrap(),
                Extent::Frame(bytes.len())
            );
        }
        assert_eq!(wire_frame_extent(&[]).unwrap(), Extent::Need(10));
        assert_eq!(wire_frame_extent(b"SASP").unwrap(), Extent::Need(10));
        assert_eq!(wire_frame_extent(b"X").unwrap_err(), CodecError::BadMagic);
        assert_eq!(wire_frame_extent(b"SAX").unwrap_err(), CodecError::BadMagic);
        assert_eq!(
            wire_frame_extent(b"SASPAIR\0\x02").unwrap_err(),
            CodecError::UnsupportedVersion(2)
        );
        for kind in [0, 0x0a, 0x20, 0x7f] {
            assert_eq!(
                wire_frame_extent(&[b"SASPAIR\0\x01".as_slice(), &[kind]].concat()).unwrap_err(),
                CodecError::UnknownType(kind)
            );
        }
        // A declaration is checked as soon as it is read, before its payload is needed: the
        // frame so far plus the remaining fields' 4-byte length prefixes must fit. INITIATOR_KEY
        // has three fields, so its first may declare at most MAX_FRAME - 22 bytes.
        let first = |len: usize| [&b"SASPAIR\0\x01\x03"[..], &(len as u32).to_be_bytes()].concat();
        assert_eq!(
            wire_frame_extent(&first(MAX_FRAME - 22)).unwrap(),
            Extent::Need(MAX_FRAME - 4)
        );
        for len in [MAX_FRAME - 21, MAX_FRAME, u32::MAX as usize] {
            assert_eq!(
                wire_frame_extent(&first(len)).unwrap_err(),
                CodecError::Oversized
            );
        }
        let at_max = [first(MAX_FRAME - 22), vec![0; MAX_FRAME - 22], vec![0; 8]].concat();
        assert_eq!(at_max.len(), MAX_FRAME);
        assert_eq!(
            wire_frame_extent(&at_max[..MAX_FRAME - 4]).unwrap(),
            Extent::Need(MAX_FRAME)
        );
        assert_eq!(
            wire_frame_extent(&at_max).unwrap(),
            Extent::Frame(MAX_FRAME)
        );
        assert!(parse(&at_max).is_ok());
        let mut over = at_max.clone();
        over[MAX_FRAME - 1] = 1;
        assert_eq!(wire_frame_extent(&over).unwrap_err(), CodecError::Oversized);
    }

    // R-WIRE-002 to R-WIRE-008, R-WIRE-011, and the codec half of R-WIRE-017: every class of
    // structural mutation, applied to every authoritative wire vector, is rejected before any
    // message exists. A swap of two adjacent fields of equal width (a completion digest and its
    // MAC; a CANCEL role and reason that are both defined) is the only mutation that can stay
    // structurally valid: it decodes to a different message, which its run then rejects through
    // the transcript-digest, sender-role, and MAC checks.
    #[test]
    fn every_structural_mutation_class_is_rejected_for_every_wire_type() {
        for vector in [START, ACCEPT, IK, RK, BM, IF, RFA, IFA, CANCEL_I, CANCEL_R] {
            let bytes = hex(vector);
            let original = decode(&bytes).unwrap();
            let (kind, fields) = parse(&bytes).unwrap();
            let rebuild = |fields: &[&[u8]]| encode_frame(kind, fields, MAX_FRAME).unwrap();
            assert_eq!(rebuild(&fields), bytes);
            // Truncation at every byte boundary: header, length prefixes, and field contents.
            for end in 0..bytes.len() {
                assert!(decode(&bytes[..end]).is_err(), "{kind}: truncated at {end}");
            }
            let tails: [&[u8]; 4] = [&[0], &[0; 3], &[0; 4], &[0, 0, 0, 1, 0]];
            for tail in tails {
                assert!(
                    decode(&[bytes.as_slice(), tail].concat()).is_err(),
                    "{kind}"
                );
            }
            for index in 0..7 {
                let mut bad = bytes.clone();
                bad[index] ^= 0x20;
                assert_eq!(decode(&bad).unwrap_err(), CodecError::BadMagic, "{kind}");
            }
            for version in [0, 2, 0x0100, u16::MAX] {
                let mut bad = bytes.clone();
                bad[7..9].copy_from_slice(&version.to_be_bytes());
                let expected = CodecError::UnsupportedVersion(version);
                assert_eq!(decode(&bad).unwrap_err(), expected, "{kind}");
            }
            for unknown in [0, 0x0a, 0x20, 0x33, 0x38, 0xff] {
                let mut bad = bytes.clone();
                bad[9] = unknown;
                let expected = CodecError::UnknownType(unknown);
                assert_eq!(decode(&bad).unwrap_err(), expected, "{kind}");
            }
            for index in 0..fields.len() {
                let mut missing = fields.clone();
                missing.remove(index);
                assert!(decode(&rebuild(&missing)).is_err(), "{kind}: omit {index}");
                let mut duplicated = fields.clone();
                duplicated.insert(index, fields[index]);
                assert!(
                    decode(&rebuild(&duplicated)).is_err(),
                    "{kind}: repeat {index}"
                );
            }
            for index in 0..fields.len() - 1 {
                let mut swapped = fields.clone();
                swapped.swap(index, index + 1);
                match decode(&rebuild(&swapped)) {
                    Err(_) => {}
                    Ok(other) => {
                        assert!(matches!(kind, 6..=9), "{kind}: swap {index}");
                        assert_eq!(fields[index].len(), fields[index + 1].len());
                        assert_ne!(other.message, original.message, "{kind}: swap {index}");
                    }
                }
            }
            let request_ids: [&[u8]; 2] = [&[], &[7; 65]];
            for request_id in request_ids {
                let mut bad = fields.clone();
                bad[1] = request_id;
                let expected = CodecError::InvalidField("request_id");
                assert_eq!(decode(&rebuild(&bad)).unwrap_err(), expected, "{kind}");
            }
            let profiles: [&[u8]; 3] = [
                &[],
                &PROFILE_ID[..PROFILE_ID.len() - 1],
                b"sas-pairing-vodozemac-profile-draft-02",
            ];
            for profile in profiles {
                let mut bad = fields.clone();
                bad[0] = profile;
                let expected = CodecError::InvalidField("profile_id");
                assert_eq!(decode(&rebuild(&bad)).unwrap_err(), expected, "{kind}");
            }
        }
        // Undefined role and reason codes in the two bidirectional messages.
        for (vector, at) in [(BM, 2), (CANCEL_I, 2), (CANCEL_R, 2)] {
            let bytes = hex(vector);
            let (kind, fields) = parse(&bytes).unwrap();
            for role in [0, 3, 0xff] {
                let mut bad = fields.clone();
                bad[at] = std::slice::from_ref(&role);
                let encoded = encode_frame(kind, &bad, MAX_FRAME).unwrap();
                let expected = CodecError::InvalidField("role");
                assert_eq!(decode(&encoded).unwrap_err(), expected);
            }
        }
        for vector in [CANCEL_I, CANCEL_R] {
            let bytes = hex(vector);
            let (kind, fields) = parse(&bytes).unwrap();
            for reason in [0, 5, 0xff] {
                let mut bad = fields.clone();
                bad[3] = std::slice::from_ref(&reason);
                let encoded = encode_frame(kind, &bad, MAX_FRAME).unwrap();
                let expected = CodecError::InvalidField("reason");
                assert_eq!(decode(&encoded).unwrap_err(), expected);
            }
        }
        // `key_algorithm` outside `[a-z0-9][a-z0-9.-]*`, including non-ASCII, in both the START
        // and ACCEPT bootstraps and at construction.
        let valid = boot(IBOOT);
        let key_algorithms: [&[u8]; 8] = [
            b"ed25519\xc3\xa9",
            b"\x80",
            b"\xffed25519",
            b"Ed25519",
            b"ed 25519",
            b"ed_25519",
            b"-ed25519",
            b".ed25519",
        ];
        for key_algorithm in key_algorithms {
            let fields = [
                valid.application_identity(),
                key_algorithm,
                valid.public_key(),
                valid.shared_context(),
            ];
            let nested = encode_frame(0x20, &fields, MAX_FRAME).unwrap();
            let expected = CodecError::InvalidField("key_algorithm");
            let rid = hex(RID);
            let start = start_with_field(&rid, &nested);
            assert_eq!(decode(&start).unwrap_err(), expected);
            let accept = encode_frame(2, &[PROFILE_ID, &rid, &[0; 32], &nested], MAX_FRAME);
            assert_eq!(decode(&accept.unwrap()).unwrap_err(), expected);
            let built = Bootstrap::new(
                fields[0].to_vec(),
                fields[1].to_vec(),
                fields[2].to_vec(),
                fields[3].to_vec(),
            );
            assert_eq!(built.unwrap_err(), expected);
        }
    }

    /// A wire START carrying `bootstrap` verbatim as its opaque third field.
    fn start_with_field(request_id: &[u8], bootstrap: &[u8]) -> Vec<u8> {
        encode_frame(START_TYPE, &[PROFILE_ID, request_id, bootstrap], MAX_FRAME).unwrap()
    }

    #[test]
    fn start_candidates_and_full_decode_share_one_structure() {
        // Every authoritative vector: only START is a candidate, and its semantic decode is
        // exactly the full decoder's result. No other type is reinterpreted.
        for vector in [START, ACCEPT, IK, RK, BM, IF, RFA, IFA, CANCEL_I, CANCEL_R] {
            let bytes = hex(vector);
            match start_candidate(&bytes) {
                Ok(candidate) => {
                    assert_eq!(bytes[9], START_TYPE);
                    assert_eq!(candidate.canonical, bytes.as_slice());
                    assert_eq!(candidate.request_id, hex(RID).as_slice());
                    assert_eq!(candidate.bootstrap, hex(IBOOT).as_slice());
                    assert_eq!(candidate.decode().unwrap(), decode(&bytes).unwrap());
                }
                Err(error) => {
                    assert_ne!(bytes[9], START_TYPE);
                    assert_eq!(error, CodecError::InvalidField("message_type"));
                }
            }
        }
    }

    #[test]
    fn structural_start_failures_are_not_candidates_and_match_decode() {
        let valid = hex(START);
        let profile_len_at = 10;
        let request_id_len_at = 14 + PROFILE_ID.len();
        let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();
        let mut bytes = valid.clone();
        bytes[0] = b'X';
        cases.push(("magic", bytes));
        let mut bytes = valid.clone();
        bytes[8] = 2;
        cases.push(("version", bytes));
        let mut bytes = valid.clone();
        bytes[9] = 0x7f;
        cases.push(("unknown type", bytes));
        let mut bytes = valid.clone();
        bytes[profile_len_at + 4] ^= 1;
        cases.push(("profile", bytes));
        cases.push(("request ID 0", start_with_field(&[], &hex(IBOOT))));
        cases.push((
            "request ID 65",
            encode_frame(START_TYPE, &[PROFILE_ID, &[7; 65], &hex(IBOOT)], MAX_FRAME).unwrap(),
        ));
        cases.push(("truncated", valid[..valid.len() - 1].to_vec()));
        cases.push(("trailing", [valid.as_slice(), &[0]].concat()));
        cases.push(("extra field", [valid.as_slice(), &[0, 0, 0, 0]].concat()));
        cases.push((
            "missing field",
            encode_frame(START_TYPE, &[PROFILE_ID, &hex(RID)], MAX_FRAME).unwrap(),
        ));
        let mut bytes = valid.clone();
        bytes[request_id_len_at..request_id_len_at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        cases.push(("length overflow", bytes));
        let field = MAX_FRAME + 1 - (10 + 4 + PROFILE_ID.len() + 4 + 16 + 4);
        let oversized = [
            &valid[..10],
            &(PROFILE_ID.len() as u32).to_be_bytes(),
            PROFILE_ID,
            &16u32.to_be_bytes(),
            &hex(RID),
            &(field as u32).to_be_bytes(),
            &vec![0; field],
        ]
        .concat();
        assert_eq!(oversized.len(), MAX_FRAME + 1);
        cases.push(("oversized", oversized));
        for (name, bytes) in cases {
            let candidate = start_candidate(&bytes).expect_err(name);
            assert_eq!(decode(&bytes).unwrap_err(), candidate, "{name}");
            assert_eq!(routable(&bytes).unwrap_err(), candidate, "{name}");
        }
    }

    #[test]
    fn dispatch_classification_uses_the_shared_structure_only() {
        let rid = hex(RID);
        for vector in [START, ACCEPT, IK, RK, BM, IF, RFA, IFA, CANCEL_I, CANCEL_R] {
            let bytes = hex(vector);
            let expected = match start_candidate(&bytes) {
                Ok(_) => Routable::Start {
                    request_id: rid.as_slice(),
                },
                Err(_) => Routable::Run {
                    request_id: rid.as_slice(),
                },
            };
            assert_eq!(routable(&bytes).unwrap(), expected);
            assert_eq!(route_fields(&bytes).unwrap().1, rid.as_slice());
        }
        // A START candidate whose bootstrap is semantically invalid is still dispatched to
        // admission: the bootstrap is not decoded here.
        let garbage = start_with_field(&rid, &[0xFF; 3]);
        assert_eq!(
            routable(&garbage).unwrap(),
            Routable::Start {
                request_id: rid.as_slice()
            }
        );
        assert_eq!(decode(&garbage).unwrap_err(), CodecError::Truncated);
        // Common-field failures of a non-START frame are unroutable, exactly as `route_fields`.
        let mut bad_profile = hex(IK);
        bad_profile[14] ^= 1;
        let long_id = encode_frame(3, &[PROFILE_ID, &[7; 65], &[0; 32]], MAX_FRAME).unwrap();
        let empty_id = encode_frame(3, &[PROFILE_ID, &[], &[0; 32]], MAX_FRAME).unwrap();
        for bytes in [bad_profile, long_id, empty_id] {
            assert_eq!(
                routable(&bytes).unwrap_err(),
                route_fields(&bytes).unwrap_err()
            );
        }
        // A non-START frame's own fields are its run's concern, not dispatch's.
        let short_key = encode_frame(3, &[PROFILE_ID, &rid, &[0; 31]], MAX_FRAME).unwrap();
        assert!(matches!(routable(&short_key), Ok(Routable::Run { .. })));
        assert!(decode(&short_key).is_err());
    }

    #[test]
    fn bootstrap_contents_are_start_semantics_after_the_candidate_boundary() {
        let rid = hex(RID);
        let valid = Bootstrap::decode(&hex(IBOOT)).unwrap();
        let mut wrong_type = hex(IBOOT);
        wrong_type[9] = 0x21;
        let with = |key_algorithm: &[u8]| {
            encode_frame(
                0x20,
                &[
                    valid.application_identity(),
                    key_algorithm,
                    valid.public_key(),
                    valid.shared_context(),
                ],
                MAX_FRAME,
            )
            .unwrap()
        };
        // A complete nested bootstrap above 16,384 bytes inside an outer frame within 65,536.
        let over_cap = encode_frame(
            0x20,
            &[
                &[b'a'; 1024],
                b"ed25519",
                &[0; 4096],
                &[0; 3 * MAX_BOOTSTRAP_FRAME / 2],
            ],
            MAX_FRAME,
        )
        .unwrap();
        assert!(over_cap.len() > MAX_BOOTSTRAP_FRAME);
        for (name, bootstrap, expected) in [
            ("garbage", vec![0xFF; 3], CodecError::Truncated),
            ("empty", Vec::new(), CodecError::Truncated),
            (
                "nested type",
                wrong_type,
                CodecError::InvalidField("bootstrap"),
            ),
            (
                "trailing",
                [hex(IBOOT), vec![0]].concat(),
                CodecError::Truncated,
            ),
            (
                "key_algorithm grammar",
                with(b"Ed25519"),
                CodecError::InvalidField("key_algorithm"),
            ),
            (
                "key_algorithm leading dot",
                with(b".ed25519"),
                CodecError::InvalidField("key_algorithm"),
            ),
            ("bootstrap maximum", over_cap, CodecError::Oversized),
            (
                "field maximum",
                encode_frame(0x20, &[b"a", b"a", b"k", &[0; 8193]], MAX_FRAME).unwrap(),
                CodecError::InvalidField("shared_context"),
            ),
        ] {
            let bytes = start_with_field(&rid, &bootstrap);
            assert!(bytes.len() <= MAX_FRAME, "{name}");
            let candidate = start_candidate(&bytes).expect(name);
            assert_eq!(candidate.bootstrap, bootstrap.as_slice(), "{name}");
            assert_eq!(candidate.decode().unwrap_err(), expected, "{name}");
            assert_eq!(decode(&bytes).unwrap_err(), expected, "{name}");
        }
    }
}
