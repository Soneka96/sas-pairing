//! Trusted local ceremony control through the native ABI (P7-D-011, P7-D-012).
//!
//! Nine explicit exports expose the reviewed trusted-local action chain of the Windows owner loop
//! (`WindowsOwnerLoop::start_initiator`, `authorize_exposure`, `expose_key`, `presentation`,
//! `approve_sas`, `emit_bootstrap_mac`, `reject_sas`, `cancel_sas`, `emit_initiator_finish`), one
//! reviewed call per export. Nothing here chains actions, encodes or returns protocol bytes, or
//! decides ceremony state: the TCP adapter keeps any frame an action produced and writes it on a
//! later drive, and the core alone decides authorization, exposure, SAS, and completion.
//!
//! An action names its connection by handle and its run by an exact run handle of THAT
//! connection (P7-D-009): the core's `RunRef`, never a request ID. The outcome is a fixed
//! [`Action`] record (the local event, a deadline kind, the write-pending flag, and the run
//! handle that is still live), or a status: a refusal before the core (handles, write pending,
//! run cap, handle space), a run-local ceremony refusal (P7-D-012), `RUN_ENDED` for a stale exact
//! run, or a connection or owner-loop ending. Presentation is read-only and fills a fixed
//! [`Presentation`] record: the 32-byte ceremony identity and the 14-byte decimal SAS, never the
//! raw SAS bytes.
#![cfg_attr(
    not(windows),
    allow(
        dead_code,
        reason = "the records and constants are shared, but only Windows runs local actions"
    )
)]

use std::mem;
#[cfg(windows)]
use std::num::NonZeroU64;

#[cfg(not(windows))]
use super::status::SAS_PAIRING_UNSUPPORTED_PLATFORM;
use super::{
    BootstrapInput, BootstrapView, byte_range, caller_bytes,
    network::{ConnectionHandle, RunHandle, SAS_PAIRING_DEADLINE_NONE, element_range, overlaps},
    runtime::AbiState,
    status::{SAS_PAIRING_INVALID_ARGUMENT, SAS_PAIRING_OK},
};
#[cfg(windows)]
use super::{
    hosting::HostContext,
    network::{MAX_RUNS_PER_CONNECTION, deadline_kind, issue},
    runtime::{Admission, Runtime},
    status::{
        SAS_PAIRING_CONNECTION_ENDED, SAS_PAIRING_FATAL, SAS_PAIRING_HANDLES_EXHAUSTED,
        SAS_PAIRING_INVALID_BOOTSTRAP, SAS_PAIRING_INVALID_HANDLE,
        SAS_PAIRING_LISTENER_NOT_ATTACHED, SAS_PAIRING_OWNER_LOOP_CLOSED,
        SAS_PAIRING_OWNERSHIP_UNCERTAIN, SAS_PAIRING_RESOURCE_LIMITED, SAS_PAIRING_RUN_ENDED,
        SAS_PAIRING_WRITE_PENDING, map_ceremony_error, map_run_refusal,
    },
};
#[cfg(windows)]
use crate::{
    ceremony::{SasApproval, SasPresentation},
    host::LocalEvent,
    router::{RouteError, RunRef},
    windows_owner_loop::OwnerLoopError,
    windows_tcp::{Acted, Refused},
};

/// `sas_pairing_local_event_t`: what one trusted local action did.
pub(super) const SAS_PAIRING_LOCAL_EVENT_INVALID: u32 = 0;
pub(super) const SAS_PAIRING_LOCAL_EVENT_INITIATOR_STARTED: u32 = 1;
pub(super) const SAS_PAIRING_LOCAL_EVENT_EXPOSURE_AUTHORIZED: u32 = 2;
pub(super) const SAS_PAIRING_LOCAL_EVENT_KEY_EXPOSED: u32 = 3;
pub(super) const SAS_PAIRING_LOCAL_EVENT_SAS_APPROVED: u32 = 4;
pub(super) const SAS_PAIRING_LOCAL_EVENT_SAS_ALREADY_APPROVED: u32 = 5;
pub(super) const SAS_PAIRING_LOCAL_EVENT_BOOTSTRAP_MAC_EMITTED: u32 = 6;
pub(super) const SAS_PAIRING_LOCAL_EVENT_BOOTSTRAP_MAC_ALREADY_EMITTED: u32 = 7;
pub(super) const SAS_PAIRING_LOCAL_EVENT_INITIATOR_FINISH_EMITTED: u32 = 8;
pub(super) const SAS_PAIRING_LOCAL_EVENT_INITIATOR_FINISH_ALREADY_EMITTED: u32 = 9;
pub(super) const SAS_PAIRING_LOCAL_EVENT_SAS_REJECTED: u32 = 10;
pub(super) const SAS_PAIRING_LOCAL_EVENT_SAS_CANCELLED: u32 = 11;
pub(super) const SAS_PAIRING_LOCAL_EVENT_DEADLINE: u32 = 12;

/// `sas_pairing_action_flags_t` bits. `WRITE_PENDING`: the connection's adapter now retains one
/// outbound frame (this action's, or a timeout CANCEL) and writes it on a later drive. There is no
/// untracked-run flag: a trusted local action never creates a run without a handle.
pub(super) const SAS_PAIRING_ACTION_FLAG_WRITE_PENDING: u32 = 0x1;

/// The core's `ceremony_identity` length: the only accepted target of a local SAS decision.
pub(super) const CEREMONY_IDENTITY_LEN: usize = 32;
/// `SAS_PAIRING_SAS_DECIMAL_LEN`: the core's decimal SAS display, `NNNN NNNN NNNN` (three
/// four-digit groups, `{first:04} {second:04} {third:04}`, each 1000–9191), as ASCII.
pub(super) const SAS_DECIMAL_LEN: usize = 14;

/// `sas_pairing_action_t`: the outcome of one trusted local action, a fixed C record of integers
/// with no padding (every byte is a field, so no uninitialized byte can reach the caller). It
/// owns nothing and carries no protocol byte.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Action {
    pub(super) event: u32,
    pub(super) deadline_kind: u32,
    pub(super) flags: u32,
    /// Always zero; makes the record padding-free.
    pub(super) reserved: u32,
    /// The run handle still live after the action (the same handle the action named, or a new
    /// one for a started Initiator); `0` once the run is terminal.
    pub(super) run: RunHandle,
}

const _: () = {
    assert!(size_of::<Action>() == 24);
    assert!(align_of::<Action>() == 8);
    assert!(mem::offset_of!(Action, reserved) == 12);
    assert!(mem::offset_of!(Action, run) == 16);
};

impl Action {
    /// Every field zero: every output starts here.
    pub(super) const ZERO: Self = Self {
        event: SAS_PAIRING_LOCAL_EVENT_INVALID,
        deadline_kind: SAS_PAIRING_DEADLINE_NONE,
        flags: 0,
        reserved: 0,
        run: 0,
    };
}

/// `sas_pairing_sas_presentation_t`: one live SAS for local comparison, a fixed C record with no
/// padding. Display data only: it authorizes, approves, and proves nothing.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Presentation {
    /// `1` when the core presented a live SAS; `0` (and every other byte zero) otherwise.
    pub(super) available: u32,
    /// Always zero.
    pub(super) reserved: u32,
    pub(super) ceremony_identity: [u8; CEREMONY_IDENTITY_LEN],
    /// Exactly `NNNN NNNN NNNN` in ASCII, no terminator.
    pub(super) decimal: [u8; SAS_DECIMAL_LEN],
    /// Always zero.
    pub(super) reserved_tail: [u8; 2],
}

const _: () = {
    assert!(size_of::<Presentation>() == 56);
    assert!(align_of::<Presentation>() == 4);
    assert!(mem::offset_of!(Presentation, ceremony_identity) == 8);
    assert!(mem::offset_of!(Presentation, decimal) == 40);
    assert!(mem::offset_of!(Presentation, reserved_tail) == 54);
};

impl Presentation {
    /// Every byte zero: every output starts here, and it is the "no SAS presented" answer.
    pub(super) const ZERO: Self = Self {
        available: 0,
        reserved: 0,
        ceremony_identity: [0; CEREMONY_IDENTITY_LEN],
        decimal: [0; SAS_DECIMAL_LEN],
        reserved_tail: [0; 2],
    };
}

/// A local SAS decision, always for one exact `ceremony_identity`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Decision {
    /// Local MATCH (`approve_sas`).
    Approve,
    /// Local MISMATCH (`reject_sas`, CANCEL reason `0x01`).
    Reject,
    /// Local CANCEL (`cancel_sas`, CANCEL reason `0x02`).
    Cancel,
}

/// One trusted local action on an existing exact run: exactly one reviewed owner-loop call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Request {
    AuthorizeExposure,
    ExposeKey,
    EmitBootstrapMac,
    EmitInitiatorFinish,
    Decide(Decision, [u8; CEREMONY_IDENTITY_LEN]),
}

/// The handles one run action names: its run must be a run handle of exactly `connection`, of
/// exactly `host`, of exactly `runtime`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RunTarget {
    pub(super) runtime: u64,
    pub(super) host: u64,
    pub(super) connection: ConnectionHandle,
    pub(super) run: RunHandle,
}

// --- Stable translations ---------------------------------------------------------------------

/// `(event, deadline kind)` of one local event. Exhaustive and wildcard-free; a deadline found
/// during the action reuses the frozen P7.5 deadline kinds.
#[cfg(windows)]
pub(super) fn local_event(event: LocalEvent) -> (u32, u32) {
    let plain = |value| (value, SAS_PAIRING_DEADLINE_NONE);
    match event {
        LocalEvent::InitiatorStarted => plain(SAS_PAIRING_LOCAL_EVENT_INITIATOR_STARTED),
        LocalEvent::ExposureAuthorized => plain(SAS_PAIRING_LOCAL_EVENT_EXPOSURE_AUTHORIZED),
        LocalEvent::KeyExposed => plain(SAS_PAIRING_LOCAL_EVENT_KEY_EXPOSED),
        LocalEvent::SasApproved(SasApproval::Recorded) => {
            plain(SAS_PAIRING_LOCAL_EVENT_SAS_APPROVED)
        }
        LocalEvent::SasApproved(SasApproval::AlreadyRecorded) => {
            plain(SAS_PAIRING_LOCAL_EVENT_SAS_ALREADY_APPROVED)
        }
        LocalEvent::BootstrapMacEmitted => plain(SAS_PAIRING_LOCAL_EVENT_BOOTSTRAP_MAC_EMITTED),
        LocalEvent::BootstrapMacAlreadyEmitted => {
            plain(SAS_PAIRING_LOCAL_EVENT_BOOTSTRAP_MAC_ALREADY_EMITTED)
        }
        LocalEvent::InitiatorFinishEmitted => {
            plain(SAS_PAIRING_LOCAL_EVENT_INITIATOR_FINISH_EMITTED)
        }
        LocalEvent::InitiatorFinishAlreadyEmitted => {
            plain(SAS_PAIRING_LOCAL_EVENT_INITIATOR_FINISH_ALREADY_EMITTED)
        }
        LocalEvent::SasRejected => plain(SAS_PAIRING_LOCAL_EVENT_SAS_REJECTED),
        LocalEvent::SasCancelled => plain(SAS_PAIRING_LOCAL_EVENT_SAS_CANCELLED),
        LocalEvent::Deadline(kind) => (SAS_PAIRING_LOCAL_EVENT_DEADLINE, deadline_kind(kind)),
    }
}

fn action_flags(write_pending: bool) -> u32 {
    if write_pending {
        SAS_PAIRING_ACTION_FLAG_WRITE_PENDING
    } else {
        0
    }
}

/// Whether `display` is exactly the core's decimal SAS shape: `NNNN NNNN NNNN`.
pub(super) fn is_decimal_display(display: &[u8; SAS_DECIMAL_LEN]) -> bool {
    display.iter().enumerate().all(|(index, byte)| {
        if index == 4 || index == 9 {
            *byte == b' '
        } else {
            byte.is_ascii_digit()
        }
    })
}

/// The record of one core presentation: the zero record for `None`, otherwise exactly the
/// core's identity and decimal display. `None` if the display is not the 14-byte shape the core
/// builds (a broken core invariant).
#[cfg(windows)]
pub(super) fn presentation_record(presented: Option<SasPresentation>) -> Option<Presentation> {
    let Some(presented) = presented else {
        return Some(Presentation::ZERO);
    };
    let decimal: [u8; SAS_DECIMAL_LEN] = presented.decimal().as_bytes().try_into().ok()?;
    if !is_decimal_display(&decimal) {
        return None;
    }
    Some(Presentation {
        available: 1,
        reserved: 0,
        ceremony_identity: *presented.ceremony_identity(),
        decimal,
        reserved_tail: [0; 2],
    })
}

/// Marks a broken invariant: the process becomes fatal, as for a caught panic.
#[cfg(windows)]
fn fatal(state: &AbiState) -> i32 {
    state.fatal.mark();
    SAS_PAIRING_FATAL
}

/// Settles the owner loop's own refusal of one local call, keeping the host's references
/// exact. `Connection`: that connection ended during the call (its handle and every run handle
/// of it end). `OwnershipUncertain`: the loop failed closed (every reference of the host ends).
/// `Closed`: it had already failed closed. The rest cannot follow a valid binding lookup and
/// break an invariant (fatal).
#[cfg(windows)]
fn settle<T>(
    state: &AbiState,
    context: &mut HostContext,
    connection: ConnectionHandle,
    outcome: Result<T, OwnerLoopError>,
) -> Result<T, i32> {
    match outcome {
        Ok(value) => Ok(value),
        Err(OwnerLoopError::Connection(_)) => {
            context.bindings_mut().unbind_handle(connection);
            Err(SAS_PAIRING_CONNECTION_ENDED)
        }
        Err(OwnerLoopError::OwnershipUncertain) => {
            context.bindings_mut().clear();
            Err(SAS_PAIRING_OWNERSHIP_UNCERTAIN)
        }
        Err(OwnerLoopError::Closed) => {
            context.bindings_mut().clear();
            Err(SAS_PAIRING_OWNER_LOOP_CLOSED)
        }
        Err(
            OwnerLoopError::UnknownConnection
            | OwnerLoopError::Poll(_)
            | OwnerLoopError::ListenerIo(_),
        ) => {
            context.bindings_mut().clear();
            Err(fatal(state))
        }
    }
}

/// The run-local refusal of an action on an existing exact run (P7-D-012). `UnknownRoute`: the
/// exact run is no longer routed, so its now-stale reference is removed (`RUN_ENDED`). A
/// ceremony refusal keeps the reference: the core alone knows whether it ended the run, and a
/// stale exact reference never reaches another run (P7-D-009).
#[cfg(windows)]
fn run_refusal(
    state: &AbiState,
    context: &mut HostContext,
    target: RunTarget,
    error: &RouteError,
) -> i32 {
    let Some(status) = map_run_refusal(error) else {
        return fatal(state);
    };
    if status == SAS_PAIRING_RUN_ENDED {
        context
            .bindings_mut()
            .remove_run(target.connection, target.run);
    }
    status
}

/// The run-local refusal of a local Initiator start, which names no existing run: only a
/// ceremony refusal is possible; anything else breaks the start path's invariant.
#[cfg(windows)]
fn start_refusal(state: &AbiState, error: &RouteError) -> i32 {
    match error {
        RouteError::Ceremony(error) => map_ceremony_error(error),
        RouteError::UnknownRoute
        | RouteError::UnknownSession
        | RouteError::SessionProtocolFailure => fatal(state),
    }
}

/// Converts one applied action on the existing exact run `input` (P7-D-011). A live run must be
/// exactly `input` and keeps its handle; a terminal run's handle ends here. A start event, or a
/// different live run, breaks the core's invariant.
#[cfg(windows)]
fn action_record(
    state: &AbiState,
    context: &mut HostContext,
    target: RunTarget,
    input: &RunRef,
    acted: Acted,
) -> Result<Action, i32> {
    let Acted {
        run,
        event,
        write_pending,
    } = acted;
    if event == LocalEvent::InitiatorStarted {
        return Err(fatal(state));
    }
    let (event, deadline_kind) = local_event(event);
    let run = match run {
        Some(live) if live == *input => target.run,
        Some(_) => return Err(fatal(state)),
        None => {
            context
                .bindings_mut()
                .remove_run(target.connection, target.run);
            0
        }
    };
    Ok(Action {
        event,
        deadline_kind,
        flags: action_flags(write_pending),
        reserved: 0,
        run,
    })
}

/// The live host `host` of `live` with an attached network context.
#[cfg(windows)]
fn network_host(live: &mut Runtime, host: u64) -> Result<&mut HostContext, i32> {
    let handle = NonZeroU64::new(host).ok_or(SAS_PAIRING_INVALID_HANDLE)?;
    let context = live
        .hosts
        .get_mut(&handle)
        .ok_or(SAS_PAIRING_INVALID_HANDLE)?;
    if !context.has_network() {
        return Err(SAS_PAIRING_LISTENER_NOT_ATTACHED);
    }
    Ok(context)
}

// --- State operations ------------------------------------------------------------------------

impl AbiState {
    /// One trusted local Initiator start on `connection` (P7-D-011). Order: the Bootstrap
    /// configuration (copied, then `Bootstrap::new`), then (through `with_runtime`) the fatal
    /// state and the runtime, the host, an attached listener, the connection, the connection's
    /// run cap, and one handle of space; only then the owner loop. A started run always gets an
    /// exact run handle: there is no untracked local Initiator.
    #[cfg(windows)]
    pub(super) fn start_initiator(
        &self,
        runtime: u64,
        host: u64,
        connection: ConnectionHandle,
        local: &BootstrapInput<'_>,
        expected: Option<&BootstrapInput<'_>>,
    ) -> Result<Action, i32> {
        let local = local.to_bootstrap().ok_or(SAS_PAIRING_INVALID_BOOTSTRAP)?;
        let expected = match expected.map(BootstrapInput::to_bootstrap) {
            None => None,
            Some(Some(expected)) => Some(expected),
            Some(None) => return Err(SAS_PAIRING_INVALID_BOOTSTRAP),
        };
        self.with_runtime(runtime, Admission::Normal, |live| {
            let context = network_host(live, host)?;
            let target = context
                .bindings()
                .connection(connection)
                .ok_or(SAS_PAIRING_INVALID_HANDLE)?;
            if context
                .bindings()
                .run_count(connection)
                .is_none_or(|runs| runs >= MAX_RUNS_PER_CONNECTION)
            {
                return Err(SAS_PAIRING_RESOURCE_LIMITED);
            }
            // Non-consuming, and it stays true until `issue` below: every handle allocation runs
            // under the runtime slot this call holds.
            if !self.can_allocate_handles(1) {
                return Err(SAS_PAIRING_HANDLES_EXHAUSTED);
            }
            let outcome = context
                .start_initiator(target, local, expected)
                .ok_or(SAS_PAIRING_LISTENER_NOT_ATTACHED)?;
            let acted = match settle(self, context, connection, outcome)? {
                Ok(acted) => acted,
                Err(Refused::WritePending) => return Err(SAS_PAIRING_WRITE_PENDING),
                Err(Refused::Run(error)) => return Err(start_refusal(self, &error)),
            };
            let Acted {
                run: Some(run),
                event: LocalEvent::InitiatorStarted,
                write_pending,
            } = acted
            else {
                return Err(fatal(self));
            };
            let handle = issue(self)?;
            if !context
                .bindings_mut()
                .bind_local_run(connection, run, handle)
            {
                return Err(fatal(self));
            }
            Ok(Action {
                event: SAS_PAIRING_LOCAL_EVENT_INITIATOR_STARTED,
                deadline_kind: SAS_PAIRING_DEADLINE_NONE,
                flags: action_flags(write_pending),
                reserved: 0,
                run: handle.get(),
            })
        })
    }

    /// Off Windows no connection can exist: nothing is copied or created.
    #[cfg(not(windows))]
    pub(super) fn start_initiator(
        &self,
        runtime: u64,
        host: u64,
        connection: ConnectionHandle,
        local: &BootstrapInput<'_>,
        expected: Option<&BootstrapInput<'_>>,
    ) -> Result<Action, i32> {
        let _ = (self, runtime, host, connection, local, expected);
        Err(SAS_PAIRING_UNSUPPORTED_PLATFORM)
    }

    /// One trusted local action on the exact run `target` names (P7-D-011). Order: (through
    /// `with_runtime`) the fatal state and the runtime, the host, an attached listener, the run
    /// as a run of exactly that connection; then exactly one reviewed owner-loop call. Exposure
    /// authorization uses the host's own parent authority, borrowed only for this call.
    #[cfg(windows)]
    pub(super) fn act(&self, target: RunTarget, request: Request) -> Result<Action, i32> {
        self.with_runtime(target.runtime, Admission::Normal, |live| {
            let handle = NonZeroU64::new(target.host).ok_or(SAS_PAIRING_INVALID_HANDLE)?;
            let context = live
                .hosts
                .get_mut(&handle)
                .ok_or(SAS_PAIRING_INVALID_HANDLE)?;
            if !context.has_network() {
                return Err(SAS_PAIRING_LISTENER_NOT_ATTACHED);
            }
            let (connection, run) = context
                .bindings()
                .run(target.connection, target.run)
                .ok_or(SAS_PAIRING_INVALID_HANDLE)?;
            // A host's parent authority outlives it (release and destroy remove hosts first).
            let Some(authority) = live.authorities.get(&context.authority) else {
                return Err(fatal(self));
            };
            let outcome = context
                .act_on_run(connection, &run, request, authority)
                .ok_or(SAS_PAIRING_LISTENER_NOT_ATTACHED)?;
            match settle(self, context, target.connection, outcome)? {
                Ok(acted) => action_record(self, context, target, &run, acted),
                Err(Refused::WritePending) => Err(SAS_PAIRING_WRITE_PENDING),
                Err(Refused::Run(error)) => Err(run_refusal(self, context, target, &error)),
            }
        })
    }

    /// Off Windows no run can exist.
    #[cfg(not(windows))]
    pub(super) fn act(&self, target: RunTarget, request: Request) -> Result<Action, i32> {
        let _ = (self, target, request);
        Err(SAS_PAIRING_UNSUPPORTED_PLATFORM)
    }

    /// The live SAS of the exact run `target` names, read-only (P7-D-012): it changes no state,
    /// refreshes no deadline, and runs also while a write is pending. A live run without a
    /// presented SAS gives the zero record; a stale exact run gives `RUN_ENDED`.
    #[cfg(windows)]
    pub(super) fn presentation(&self, target: RunTarget) -> Result<Presentation, i32> {
        self.with_runtime(target.runtime, Admission::Normal, |live| {
            let context = network_host(live, target.host)?;
            let (connection, run) = context
                .bindings()
                .run(target.connection, target.run)
                .ok_or(SAS_PAIRING_INVALID_HANDLE)?;
            let outcome = context
                .presentation(connection, &run)
                .ok_or(SAS_PAIRING_LISTENER_NOT_ATTACHED)?;
            match settle(self, context, target.connection, outcome)? {
                Ok(presented) => presentation_record(presented).ok_or_else(|| fatal(self)),
                Err(error) => Err(run_refusal(self, context, target, &error)),
            }
        })
    }

    /// Off Windows no run can exist.
    #[cfg(not(windows))]
    pub(super) fn presentation(&self, target: RunTarget) -> Result<Presentation, i32> {
        let _ = (self, target);
        Err(SAS_PAIRING_UNSUPPORTED_PLATFORM)
    }
}

// --- Caller memory and export bodies ---------------------------------------------------------

/// The address range of one output record at `out`, when it is non-null and aligned.
fn record_range<T>(out: *mut T) -> Option<(usize, usize)> {
    if out.is_null() || !out.is_aligned() {
        return None;
    }
    element_range(out.cast_const(), 1)
}

/// Writes `outcome` to the caller's zeroed action record: the record on `OK`, nothing else
/// otherwise (it stays zero).
///
/// # Safety
///
/// `out_action` passed [`record_range`] and is the caller's writable, unaliased record for the
/// call.
unsafe fn deliver(out_action: *mut Action, outcome: Result<Action, i32>) -> i32 {
    match outcome {
        Ok(action) => {
            // SAFETY: the precondition; `Action` is a padding-free `repr(C)` record of integers,
            // written whole.
            unsafe { out_action.write(action) };
            SAS_PAIRING_OK
        }
        Err(status) => status,
    }
}

/// The shared body of the four run actions without a decision (authorize, expose, emit
/// BOOTSTRAP_MAC, emit INITIATOR_FINISH). Order: `out_action` (non-null, aligned) before any
/// write, then the record is zeroed, then the platform and the state checks, then the action.
///
/// # Safety
///
/// A non-null, aligned `out_action` must address one caller-owned writable `sas_pairing_action_t`,
/// not accessed concurrently for the duration of the call.
pub(super) unsafe fn act_through(
    state: &AbiState,
    target: RunTarget,
    out_action: *mut Action,
    request: Request,
) -> i32 {
    if record_range(out_action).is_none() {
        return SAS_PAIRING_INVALID_ARGUMENT;
    }
    // SAFETY: non-null and aligned (checked above); the caller guarantees one writable record it
    // owns, unaliased, for this call. A padding-free record of integers, written whole.
    unsafe { out_action.write(Action::ZERO) };
    // SAFETY: as above.
    unsafe { deliver(out_action, state.act(target, request)) }
}

/// The shared body of the three SAS decisions (MATCH, MISMATCH, CANCEL). Order: `out_action`
/// (non-null, aligned) and `ceremony_identity` (non-null, 32 bytes that do not wrap the address
/// space and do not overlap `out_action`) before any write; then the record is zeroed; then the
/// 32 bytes are copied; then the platform and the state checks, then the decision.
///
/// # Safety
///
/// A non-null, aligned `out_action` must address one caller-owned writable `sas_pairing_action_t`,
/// and a non-null `ceremony_identity` 32 readable bytes not mutated during the call, neither
/// accessed concurrently for the duration of the call.
pub(super) unsafe fn decide_through(
    state: &AbiState,
    target: RunTarget,
    ceremony_identity: *const u8,
    out_action: *mut Action,
    decision: Decision,
) -> i32 {
    let (Some(out_range), Some(identity_range)) = (
        record_range(out_action),
        byte_range(ceremony_identity, CEREMONY_IDENTITY_LEN),
    ) else {
        return SAS_PAIRING_INVALID_ARGUMENT;
    };
    if overlaps(identity_range, out_range) {
        return SAS_PAIRING_INVALID_ARGUMENT;
    }
    // SAFETY: non-null and aligned (checked above), disjoint from the identity bytes; the caller
    // guarantees one writable record it owns, unaliased, for this call.
    unsafe { out_action.write(Action::ZERO) };
    let mut identity = [0; CEREMONY_IDENTITY_LEN];
    // SAFETY: the identity range is non-null, 32 bytes, and does not wrap (checked above); the
    // caller guarantees 32 readable bytes left unmutated for this call. They are copied at once
    // and the borrow ends here; no pointer is kept.
    identity.copy_from_slice(unsafe { caller_bytes(ceremony_identity, CEREMONY_IDENTITY_LEN) });
    // SAFETY: as for the zeroing write.
    unsafe {
        deliver(
            out_action,
            state.act(target, Request::Decide(decision, identity)),
        )
    }
}

/// Whether any input of a local start overlaps the output record: the two view records and every
/// non-empty byte string they name. Addresses are compared as integers; nothing is dereferenced.
fn start_inputs_overlap(
    out: (usize, usize),
    views: &[(*const BootstrapView, Option<BootstrapView>)],
) -> bool {
    views.iter().any(|(pointer, view)| {
        let Some(view) = view else {
            return false;
        };
        let record = element_range(*pointer, 1).is_none_or(|range| overlaps(range, out));
        record
            || view.fields().into_iter().any(|field| {
                byte_range(field.data, field.len).is_none_or(|range| overlaps(range, out))
            })
    })
}

/// The body of the local Initiator start export (P7-D-011). Order: `out_action` (non-null,
/// aligned), `local` (non-null, aligned), `expected` (aligned when non-null), every byte view well
/// formed, and no input overlapping `out_action`, all before any write; then the record is zeroed;
/// then the platform; then the Bootstrap configuration (`INVALID_BOOTSTRAP`); then the state
/// checks and the start. The views and their bytes are copied during the call; nothing is kept.
///
/// # Safety
///
/// A non-null, aligned `out_action` must address one caller-owned writable `sas_pairing_action_t`;
/// non-null, aligned `local` and `expected` one readable `sas_pairing_bootstrap_view_t` each, every
/// non-empty byte view `len` readable bytes; none mutated or accessed concurrently for the
/// duration of the call.
pub(super) unsafe fn start_through(
    state: &AbiState,
    runtime: u64,
    host: u64,
    connection: ConnectionHandle,
    local: *const BootstrapView,
    expected: *const BootstrapView,
    out_action: *mut Action,
) -> i32 {
    let Some(out_range) = record_range(out_action) else {
        return SAS_PAIRING_INVALID_ARGUMENT;
    };
    if local.is_null() || !local.is_aligned() || !expected.is_aligned() {
        return SAS_PAIRING_INVALID_ARGUMENT;
    }
    // SAFETY: `local` and a non-null `expected` are non-null and aligned (checked above), and the
    // caller guarantees each addresses one readable view for this call. Views are integers and
    // raw pointers, so every bit pattern is valid and nothing is dropped; they are copied out.
    let (local_view, expected_view) =
        unsafe { (local.read(), (!expected.is_null()).then(|| expected.read())) };
    if !local_view.is_well_formed()
        || !expected_view.is_none_or(BootstrapView::is_well_formed)
        || start_inputs_overlap(
            out_range,
            &[(local, Some(local_view)), (expected, expected_view)],
        )
    {
        return SAS_PAIRING_INVALID_ARGUMENT;
    }
    // SAFETY: non-null and aligned (checked above), disjoint from every input; the caller
    // guarantees one writable record it owns, unaliased, for this call.
    unsafe { out_action.write(Action::ZERO) };
    // SAFETY: every byte view is well formed (checked above), and the caller guarantees their
    // bytes readable and unmutated for this call; the inputs do not outlive it.
    let local = unsafe { BootstrapInput::new(local_view) };
    // SAFETY: as for `local`.
    let expected = expected_view.map(|view| unsafe { BootstrapInput::new(view) });
    let started = state.start_initiator(runtime, host, connection, &local, expected.as_ref());
    // SAFETY: as for the zeroing write.
    unsafe { deliver(out_action, started) }
}

/// The body of the presentation export (P7-D-012). Order: `out_presentation` (non-null,
/// aligned) before any write, then it is zeroed, then the platform and the state checks, then
/// the read.
///
/// # Safety
///
/// A non-null, aligned `out_presentation` must address one caller-owned writable
/// `sas_pairing_sas_presentation_t`, not accessed concurrently for the duration of the call.
pub(super) unsafe fn present_through(
    state: &AbiState,
    target: RunTarget,
    out_presentation: *mut Presentation,
) -> i32 {
    if record_range(out_presentation).is_none() {
        return SAS_PAIRING_INVALID_ARGUMENT;
    }
    // SAFETY: non-null and aligned (checked above); the caller guarantees one writable record it
    // owns, unaliased, for this call. A padding-free record of integers and bytes, written whole.
    let write_out = |value: Presentation| unsafe { out_presentation.write(value) };
    write_out(Presentation::ZERO);
    match state.presentation(target) {
        Ok(presentation) => {
            write_out(presentation);
            SAS_PAIRING_OK
        }
        Err(status) => status,
    }
}
