//! `PairingResult` ownership and foreign access (P7-D-010).
//!
//! A result handle owns exactly one immutable core `PairingResult` that a drive surfaced: the
//! one-shot local verified completion of one ceremony (P6-D-005). It is not bilateral success:
//! it does not mean the peer received the final message, holds its own result, or stored trust.
//! The runtime owns every result, so connection close, listener detach, host destroy, and
//! authority release never touch one; only result destroy and runtime destroy end it.
//!
//! Reading or destroying a result is ABI-owned data access, never core work: it is admitted
//! after fatal through its own admission path ([`Admission::Data`]) and creates no result,
//! resumes no run, and changes no accounting. Fields are fixed-width integers and caller-buffer
//! byte copies; no Rust allocation or pointer crosses the ABI.

use std::num::NonZeroU64;

use super::{
    runtime::{AbiState, Admission},
    status::{SAS_PAIRING_FATAL, SAS_PAIRING_INVALID_HANDLE, SAS_PAIRING_OK},
};
use crate::{Role, ceremony::PairingResult};

/// `sas_pairing_result_t`: an opaque process-local handle; `0` is never valid.
pub(super) type ResultHandle = u64;

/// `sas_pairing_role_t`: the PEER's role in the ceremony, as the core reports it.
pub(super) const SAS_PAIRING_ROLE_INVALID: u32 = 0;
pub(super) const SAS_PAIRING_ROLE_INITIATOR: u32 = 1;
pub(super) const SAS_PAIRING_ROLE_RESPONDER: u32 = 2;

/// `sas_pairing_result_field_t`: the variable-length result fields `sas_pairing_result_copy`
/// copies. `0` is no field.
pub(super) const SAS_PAIRING_RESULT_FIELD_REQUEST_ID: u32 = 1;
pub(super) const SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_PEER_BOOTSTRAP: u32 = 2;
pub(super) const SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_SHARED_CONTEXT: u32 = 3;
pub(super) const SAS_PAIRING_RESULT_FIELD_PROFILE_IDENTIFIER: u32 = 4;

/// `sas_pairing_result_info_t`: the fixed fields and the lengths of the variable ones. A
/// padding-free `repr(C)` record of integers and bytes, with no pointer.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResultInfo {
    /// Exactly the core's 32-byte transcript-derived `ceremony_identity`: not the request ID, a
    /// connection or run handle, or peer identity.
    pub(super) ceremony_identity: [u8; 32],
    pub(super) peer_role: u32,
    pub(super) profile_version: u32,
    pub(super) request_id_len: u32,
    pub(super) peer_bootstrap_len: u32,
    pub(super) shared_context_len: u32,
    pub(super) profile_identifier_len: u32,
}

const _: () = {
    assert!(size_of::<ResultInfo>() == 56);
    assert!(align_of::<ResultInfo>() == 4);
    assert!(std::mem::offset_of!(ResultInfo, peer_role) == 32);
    assert!(std::mem::offset_of!(ResultInfo, profile_identifier_len) == 52);
};

impl ResultInfo {
    pub(super) const ZERO: Self = Self {
        ceremony_identity: [0; 32],
        peer_role: SAS_PAIRING_ROLE_INVALID,
        profile_version: 0,
        request_id_len: 0,
        peer_bootstrap_len: 0,
        shared_context_len: 0,
        profile_identifier_len: 0,
    };

    /// The info of `result`, copied from its own fields; `None` only if a length could not fit
    /// `uint32_t`, which the core's frame bounds make impossible.
    fn of(result: &PairingResult) -> Option<Self> {
        let len = |bytes: &[u8]| u32::try_from(bytes.len()).ok();
        Some(Self {
            ceremony_identity: *result.ceremony_identity(),
            peer_role: role(result.peer_role()),
            profile_version: u32::from(result.profile_version()),
            request_id_len: len(result.request_id())?,
            peer_bootstrap_len: len(result.authenticated_peer_bootstrap())?,
            shared_context_len: len(result.authenticated_shared_context())?,
            profile_identifier_len: len(result.profile_identifier())?,
        })
    }
}

fn role(role: Role) -> u32 {
    match role {
        Role::Initiator => SAS_PAIRING_ROLE_INITIATOR,
        Role::Responder => SAS_PAIRING_ROLE_RESPONDER,
    }
}

/// One variable-length result field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ResultField {
    RequestId,
    AuthenticatedPeerBootstrap,
    AuthenticatedSharedContext,
    ProfileIdentifier,
}

impl ResultField {
    /// The field a `sas_pairing_result_field_t` names; `None` for any other value.
    pub(super) fn from_raw(field: u32) -> Option<Self> {
        match field {
            SAS_PAIRING_RESULT_FIELD_REQUEST_ID => Some(Self::RequestId),
            SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_PEER_BOOTSTRAP => {
                Some(Self::AuthenticatedPeerBootstrap)
            }
            SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_SHARED_CONTEXT => {
                Some(Self::AuthenticatedSharedContext)
            }
            SAS_PAIRING_RESULT_FIELD_PROFILE_IDENTIFIER => Some(Self::ProfileIdentifier),
            _ => None,
        }
    }

    /// Exactly the core result's bytes for this field.
    fn bytes(self, result: &PairingResult) -> &[u8] {
        match self {
            Self::RequestId => result.request_id(),
            Self::AuthenticatedPeerBootstrap => result.authenticated_peer_bootstrap(),
            Self::AuthenticatedSharedContext => result.authenticated_shared_context(),
            Self::ProfileIdentifier => result.profile_identifier(),
        }
    }
}

fn owned(handle: ResultHandle) -> Result<NonZeroU64, i32> {
    NonZeroU64::new(handle).ok_or(SAS_PAIRING_INVALID_HANDLE)
}

impl AbiState {
    /// The info of `result` under the live runtime `runtime`. Data access: admitted after
    /// fatal, never entering the core.
    pub(super) fn result_info(
        &self,
        runtime: u64,
        result: ResultHandle,
    ) -> Result<ResultInfo, i32> {
        self.with_runtime(runtime, Admission::Data, |live| {
            let stored = live
                .results
                .get(&owned(result)?)
                .ok_or(SAS_PAIRING_INVALID_HANDLE)?;
            ResultInfo::of(stored).ok_or_else(|| {
                self.fatal.mark();
                SAS_PAIRING_FATAL
            })
        })
    }

    /// Runs `op` on exactly the bytes of `field` of `result`, under the runtime slot. Data
    /// access: admitted after fatal, never entering the core.
    pub(super) fn with_result_field<T>(
        &self,
        runtime: u64,
        result: ResultHandle,
        field: ResultField,
        op: impl FnOnce(&[u8]) -> T,
    ) -> Result<T, i32> {
        self.with_runtime(runtime, Admission::Data, |live| {
            let stored = live
                .results
                .get(&owned(result)?)
                .ok_or(SAS_PAIRING_INVALID_HANDLE)?;
            Ok(op(field.bytes(stored)))
        })
    }

    /// Destroys `result`: its handle leaves the runtime first (invalid forever), then the
    /// immutable result is dropped. Data cleanup: admitted after fatal, never entering the core.
    pub(super) fn destroy_result(&self, runtime: u64, result: ResultHandle) -> i32 {
        let destroyed = self.with_runtime(runtime, Admission::Data, |live| {
            live.results
                .remove(&owned(result)?)
                .ok_or(SAS_PAIRING_INVALID_HANDLE)
        });
        match destroyed {
            Ok(result) => {
                drop(result);
                SAS_PAIRING_OK
            }
            Err(status) => status,
        }
    }
}
