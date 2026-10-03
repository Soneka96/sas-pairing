//! Bounded network drive, connection and run references, and drive events (P7-D-008, P7-D-009).
//!
//! The drive exports call the reviewed `WindowsOwnerLoop::drive_once` and
//! `recheck_after_resume` exactly once each and translate the returned `OwnerStep` into a fixed
//! array of language-neutral [`Event`] records. Nothing here performs transport work: the TCP
//! adapter keeps and writes its own outbound frame, and no outbound byte, socket, or Rust object
//! crosses the ABI.
//!
//! Everything that can refuse a call is checked before the owner loop runs: the caller's memory,
//! the event capacity (at least [`MAX_DRIVE_EVENTS`]), the fatal state, the handles, an attached
//! listener, and enough handle space for the worst possible drive ([`DRIVE_HANDLE_BOUND`]). The
//! check and the conversion run under the one runtime slot that serializes every handle
//! allocation, so after the loop has made progress the conversion cannot fail: one-shot outcomes
//! such as a `PairingResult` are always delivered.
//!
//! A connection handle names one live `ConnectionRef` of the host's current owner loop and a run
//! handle one exact `RunRef` (never a request ID). Both come from the shared handle counter and
//! are never reused. [`Bindings`] keeps them per host, with at most
//! [`MAX_RUNS_PER_CONNECTION`] run references per connection.
#![cfg_attr(
    not(windows),
    allow(
        dead_code,
        reason = "the event layout and constants are shared, but only Windows drives a loop"
    )
)]

use std::mem;
#[cfg(windows)]
use std::{collections::BTreeMap, num::NonZeroU64};

#[cfg(not(windows))]
use super::status::SAS_PAIRING_UNSUPPORTED_PLATFORM;
#[cfg(windows)]
use super::{
    hosting::HostHandle,
    runtime::Admission,
    status::{
        SAS_PAIRING_FATAL, SAS_PAIRING_HANDLES_EXHAUSTED, SAS_PAIRING_INVALID_HANDLE,
        SAS_PAIRING_LISTENER_NOT_ATTACHED, SAS_PAIRING_NETWORK_POLL_FAILED,
        SAS_PAIRING_OWNER_LOOP_CLOSED, SAS_PAIRING_OWNERSHIP_UNCERTAIN,
    },
};
use super::{
    runtime::AbiState,
    status::{SAS_PAIRING_BUFFER_TOO_SMALL, SAS_PAIRING_INVALID_ARGUMENT, SAS_PAIRING_OK},
};
use crate::transport::MAX_LIVE_UNAUTHENTICATED_CONNECTIONS;
#[cfg(windows)]
use crate::{
    Error,
    ceremony::{CeremonyError, PairingResult, PeerApproval},
    deadline::Deadline,
    host::{CeremonyDeadline, HostError, HostEvent},
    protocol::CancelReason,
    router::{RouteError, RunRef},
    transport::TransportError,
    windows_owner_loop::{
        ConnectionEnd, ConnectionRef, ListenerFailure, OwnerEvent, OwnerLoopError, OwnerStep,
    },
    windows_tcp::{TcpError, TcpEvent, TcpStep, TimeoutCancel},
};

/// `sas_pairing_connection_t`: an opaque process-local handle; `0` is never valid.
pub(super) type ConnectionHandle = u64;
/// `sas_pairing_run_t`: an opaque process-local handle; `0` is never valid.
pub(super) type RunHandle = u64;

/// `SAS_PAIRING_MAX_DRIVE_EVENTS`: the most events one drive or recheck reports, exactly the
/// owner loop's `MAX_STEP_EVENTS` (the listener plus one event per live connection).
#[cfg(windows)]
pub(super) const MAX_DRIVE_EVENTS: usize = crate::windows_owner_loop::MAX_STEP_EVENTS;
/// Off Windows no owner loop exists; the value is the same derivation (the listener plus the
/// authority-wide live-connection cap), and the header test pins it to 17 everywhere.
#[cfg(not(windows))]
pub(super) const MAX_DRIVE_EVENTS: usize = 1 + MAX_LIVE_UNAUTHENTICATED_CONNECTIONS;
const _: () = assert!(MAX_DRIVE_EVENTS == 1 + MAX_LIVE_UNAUTHENTICATED_CONNECTIONS);

/// Handles one drive can issue at most, checked before the owner loop runs. Every event issues
/// at most one: `CONNECTION_ACCEPTED` its connection handle, and a `CONNECTION_STEP` either the
/// handle of its `PairingResult` or, without a result, at most one new run handle; no other
/// event issues any. A drive reports at most `MAX_DRIVE_EVENTS` events.
pub(super) const DRIVE_HANDLE_BOUND: u64 = MAX_DRIVE_EVENTS as u64;

/// `SAS_PAIRING_MAX_REQUEST_ID_LEN`: the frozen P3 request-ID bound (1–64 bytes) the codec
/// enforces on every frame, and the size of an event's request-ID array.
pub(super) const MAX_REQUEST_ID_LEN: usize = 64;

/// `SAS_PAIRING_MAX_RUNS_PER_CONNECTION`: run references one connection keeps (P7-D-009). A new
/// exact run beyond it is reported with no handle and `SAS_PAIRING_EVENT_FLAG_RUN_UNTRACKED`;
/// nothing is ever evicted.
pub(super) const MAX_RUNS_PER_CONNECTION: usize = 32;

/// `sas_pairing_event_kind_t`.
pub(super) const SAS_PAIRING_EVENT_INVALID: u32 = 0;
pub(super) const SAS_PAIRING_EVENT_CONNECTION_ACCEPTED: u32 = 1;
pub(super) const SAS_PAIRING_EVENT_ACCEPT_REFUSED: u32 = 2;
pub(super) const SAS_PAIRING_EVENT_LISTENER_DISABLED: u32 = 3;
pub(super) const SAS_PAIRING_EVENT_CONNECTION_STEP: u32 = 4;
pub(super) const SAS_PAIRING_EVENT_CONNECTION_CLOSED: u32 = 5;

/// `sas_pairing_step_kind_t`: the adapter outcome of a `CONNECTION_STEP`.
pub(super) const SAS_PAIRING_STEP_NONE: u32 = 0;
pub(super) const SAS_PAIRING_STEP_INBOUND: u32 = 1;
pub(super) const SAS_PAIRING_STEP_REFUSED: u32 = 2;
pub(super) const SAS_PAIRING_STEP_DEADLINE: u32 = 3;
pub(super) const SAS_PAIRING_STEP_WRITTEN: u32 = 4;
pub(super) const SAS_PAIRING_STEP_CONFIRMED: u32 = 5;
pub(super) const SAS_PAIRING_STEP_UNCONFIRMED: u32 = 6;
pub(super) const SAS_PAIRING_STEP_DISCARDED: u32 = 7;

/// `sas_pairing_protocol_event_t`: what one dispatched inbound frame did.
pub(super) const SAS_PAIRING_PROTOCOL_EVENT_NONE: u32 = 0;
pub(super) const SAS_PAIRING_PROTOCOL_EVENT_START_ACCEPTED: u32 = 1;
pub(super) const SAS_PAIRING_PROTOCOL_EVENT_START_DUPLICATE: u32 = 2;
pub(super) const SAS_PAIRING_PROTOCOL_EVENT_ACCEPT: u32 = 3;
pub(super) const SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_KEY: u32 = 4;
pub(super) const SAS_PAIRING_PROTOCOL_EVENT_RESPONDER_KEY: u32 = 5;
pub(super) const SAS_PAIRING_PROTOCOL_EVENT_BOOTSTRAP_MAC_AUTHENTICATED: u32 = 6;
pub(super) const SAS_PAIRING_PROTOCOL_EVENT_BOOTSTRAP_MAC_DUPLICATE: u32 = 7;
pub(super) const SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH: u32 = 8;
pub(super) const SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH_DUPLICATE: u32 = 9;
pub(super) const SAS_PAIRING_PROTOCOL_EVENT_RESPONDER_FINISH_ACK: u32 = 10;
pub(super) const SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH_ACK: u32 = 11;
pub(super) const SAS_PAIRING_PROTOCOL_EVENT_PEER_CANCEL: u32 = 12;

/// `sas_pairing_event_reason_t`: an operational reason, never evidence about the peer,
/// authentication, an SAS, or compromise.
pub(super) const SAS_PAIRING_EVENT_REASON_NONE: u32 = 0;
pub(super) const SAS_PAIRING_EVENT_REASON_RESOURCE_LIMITED: u32 = 1;
pub(super) const SAS_PAIRING_EVENT_REASON_PEER_CLOSED: u32 = 2;
pub(super) const SAS_PAIRING_EVENT_REASON_SOCKET_IO: u32 = 3;
pub(super) const SAS_PAIRING_EVENT_REASON_ABANDONED_PARTIAL_FRAME: u32 = 4;
pub(super) const SAS_PAIRING_EVENT_REASON_READINESS_FAILURE: u32 = 5;
pub(super) const SAS_PAIRING_EVENT_REASON_LISTENER_IO: u32 = 6;
pub(super) const SAS_PAIRING_EVENT_REASON_LISTENER_READINESS: u32 = 7;
pub(super) const SAS_PAIRING_EVENT_REASON_ROUTE_REFUSED: u32 = 8;
pub(super) const SAS_PAIRING_EVENT_REASON_OWNERSHIP_UNCERTAIN: u32 = 9;
pub(super) const SAS_PAIRING_EVENT_REASON_OTHER_HOST_FAILURE: u32 = 10;
pub(super) const SAS_PAIRING_EVENT_REASON_INVALID_FRAME: u32 = 11;
pub(super) const SAS_PAIRING_EVENT_REASON_TRANSPORT_DEADLINE: u32 = 12;
pub(super) const SAS_PAIRING_EVENT_REASON_CLOCK_UNAVAILABLE: u32 = 13;
pub(super) const SAS_PAIRING_EVENT_REASON_SESSION_PROTOCOL_FAILURE: u32 = 14;
pub(super) const SAS_PAIRING_EVENT_REASON_ALREADY_CLOSED: u32 = 15;

/// `sas_pairing_deadline_kind_t`: how a run ended by its own deadline processing. A timeout,
/// the pending-resource expiry, and an unusable clock are three different outcomes.
pub(super) const SAS_PAIRING_DEADLINE_NONE: u32 = 0;
pub(super) const SAS_PAIRING_DEADLINE_ABSOLUTE_TIMEOUT: u32 = 1;
pub(super) const SAS_PAIRING_DEADLINE_INACTIVITY_TIMEOUT: u32 = 2;
pub(super) const SAS_PAIRING_DEADLINE_PENDING_EXPIRED: u32 = 3;
pub(super) const SAS_PAIRING_DEADLINE_CLOCK_UNAVAILABLE: u32 = 4;

/// `sas_pairing_cancel_state_t`: what became of a deadline's best-effort authenticated CANCEL
/// locally. Never whether the peer received it.
pub(super) const SAS_PAIRING_CANCEL_STATE_NONE: u32 = 0;
pub(super) const SAS_PAIRING_CANCEL_STATE_NOT_BUILT: u32 = 1;
pub(super) const SAS_PAIRING_CANCEL_STATE_PENDING: u32 = 2;
pub(super) const SAS_PAIRING_CANCEL_STATE_DROPPED: u32 = 3;

/// `sas_pairing_cancel_reason_t`: the reason a verified peer CANCEL carried.
pub(super) const SAS_PAIRING_CANCEL_REASON_NONE: u32 = 0;
pub(super) const SAS_PAIRING_CANCEL_REASON_USER_REJECTION: u32 = 1;
pub(super) const SAS_PAIRING_CANCEL_REASON_USER_CANCELLATION: u32 = 2;
pub(super) const SAS_PAIRING_CANCEL_REASON_TIMEOUT: u32 = 3;
pub(super) const SAS_PAIRING_CANCEL_REASON_LOCAL_POLICY_FAILURE: u32 = 4;

/// `sas_pairing_event_flags_t` bits.
pub(super) const SAS_PAIRING_EVENT_FLAG_WRITE_PENDING: u32 = 0x1;
pub(super) const SAS_PAIRING_EVENT_FLAG_RUN_UNTRACKED: u32 = 0x2;

/// `sas_pairing_event_t`: one drive event, a fixed C record with no padding (every byte is a
/// field, so no uninitialized byte can reach the caller). Fields that do not apply to an event
/// are zero.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Event {
    pub(super) kind: u32,
    pub(super) step_kind: u32,
    pub(super) protocol_event: u32,
    pub(super) reason: u32,
    pub(super) deadline_kind: u32,
    pub(super) cancel_state: u32,
    pub(super) cancel_reason: u32,
    pub(super) flags: u32,
    pub(super) connection: ConnectionHandle,
    pub(super) run: u64,
    pub(super) result: u64,
    pub(super) request_id_len: u32,
    /// Always zero; makes the record padding-free.
    pub(super) reserved: u32,
    pub(super) request_id: [u8; MAX_REQUEST_ID_LEN],
}

const _: () = {
    assert!(size_of::<Event>() == 128);
    assert!(align_of::<Event>() == 8);
    assert!(mem::offset_of!(Event, connection) == 32);
    assert!(mem::offset_of!(Event, request_id_len) == 56);
    assert!(mem::offset_of!(Event, request_id) == 64);
};
impl Event {
    /// Every field zero: the start of every produced record.
    pub(super) const ZERO: Self = Self {
        kind: SAS_PAIRING_EVENT_INVALID,
        step_kind: SAS_PAIRING_STEP_NONE,
        protocol_event: SAS_PAIRING_PROTOCOL_EVENT_NONE,
        reason: SAS_PAIRING_EVENT_REASON_NONE,
        deadline_kind: SAS_PAIRING_DEADLINE_NONE,
        cancel_state: SAS_PAIRING_CANCEL_STATE_NONE,
        cancel_reason: SAS_PAIRING_CANCEL_REASON_NONE,
        flags: 0,
        connection: 0,
        run: 0,
        result: 0,
        request_id_len: 0,
        reserved: 0,
        request_id: [0; MAX_REQUEST_ID_LEN],
    };

    /// Copies a request ID the step validation already bounded by `MAX_REQUEST_ID_LEN`.
    #[cfg(windows)]
    fn set_request_id(&mut self, request_id: &[u8]) {
        self.request_id = [0; MAX_REQUEST_ID_LEN];
        self.request_id[..request_id.len()].copy_from_slice(request_id);
        // Bounded by 64 above (a longer ID would have panicked into the fatal path instead).
        self.request_id_len = request_id.len() as u32;
    }

    /// The request ID bytes (tests only).
    #[cfg(test)]
    pub(super) fn request_id(&self) -> &[u8] {
        &self.request_id[..self.request_id_len as usize]
    }
}

/// Which bounded owner-loop call a drive export makes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DriveMode {
    /// `drive_once`.
    Drive,
    /// `recheck_after_resume`: one deadline sweep, no socket operation, no wait, no accept.
    Resume,
}

/// What one admitted drive produced: `count` converted events, and the owner loop's own failure
/// status for that call (`SAS_PAIRING_OK` when none).
#[derive(Clone, Copy, Debug)]
pub(super) struct DriveOutput {
    pub(super) events: [Event; MAX_DRIVE_EVENTS],
    pub(super) count: usize,
    pub(super) failure: i32,
}

impl DriveOutput {
    #[cfg(windows)]
    fn empty() -> Self {
        Self {
            events: [Event::ZERO; MAX_DRIVE_EVENTS],
            count: 0,
            failure: SAS_PAIRING_OK,
        }
    }

    /// The converted events (tests only).
    #[cfg(test)]
    pub(super) fn events(&self) -> &[Event] {
        &self.events[..self.count]
    }
}

/// One host's connection and run references (P7-D-009). Each connection keeps its own runs, so
/// removing a connection removes every run reference parented to it.
#[cfg(windows)]
pub(super) struct Bindings {
    /// At most the authority-wide live-connection cap: a binding exists only for a live
    /// connection of the current owner loop.
    connections: Vec<ConnectionBinding>,
}

#[cfg(windows)]
struct ConnectionBinding {
    handle: NonZeroU64,
    connection: ConnectionRef,
    /// At most `MAX_RUNS_PER_CONNECTION`, allocated once.
    runs: Vec<RunBinding>,
}

#[cfg(windows)]
struct RunBinding {
    handle: NonZeroU64,
    /// The exact run instance: never matched by request ID alone.
    run: RunRef,
}

#[cfg(windows)]
impl Bindings {
    pub(super) fn new() -> Self {
        Self {
            connections: Vec::with_capacity(MAX_LIVE_UNAUTHENTICATED_CONNECTIONS),
        }
    }

    /// Invalidates every connection and run reference (detach, failure, teardown).
    pub(super) fn clear(&mut self) {
        self.connections.clear();
    }

    fn index_of(&self, connection: &ConnectionRef) -> Option<usize> {
        self.connections
            .iter()
            .position(|binding| binding.connection == *connection)
    }

    fn get_mut(&mut self, connection: &ConnectionRef) -> Option<&mut ConnectionBinding> {
        self.connections
            .iter_mut()
            .find(|binding| binding.connection == *connection)
    }

    /// Records a newly accepted connection under its new handle.
    fn bind(&mut self, connection: ConnectionRef, handle: NonZeroU64) {
        self.connections.push(ConnectionBinding {
            handle,
            connection,
            runs: Vec::with_capacity(MAX_RUNS_PER_CONNECTION),
        });
    }

    /// Removes the connection named by `connection` and every run parented to it; returns its
    /// handle.
    fn unbind(&mut self, connection: &ConnectionRef) -> Option<NonZeroU64> {
        let index = self.index_of(connection)?;
        Some(self.connections.remove(index).handle)
    }

    /// Removes the connection whose ABI handle is `handle` and every run parented to it;
    /// returns the core reference it named. Any other value (zero, stale, another kind) names
    /// nothing.
    pub(super) fn unbind_handle(&mut self, handle: ConnectionHandle) -> Option<ConnectionRef> {
        let index = self
            .connections
            .iter()
            .position(|binding| binding.handle.get() == handle)?;
        Some(self.connections.remove(index).connection)
    }

    /// The binding of the live connection whose ABI handle is `handle`. Any other value (zero,
    /// stale, another kind, another loop's) names nothing.
    fn binding(&self, handle: ConnectionHandle) -> Option<&ConnectionBinding> {
        self.connections
            .iter()
            .find(|binding| binding.handle.get() == handle)
    }

    fn binding_mut(&mut self, handle: ConnectionHandle) -> Option<&mut ConnectionBinding> {
        self.connections
            .iter_mut()
            .find(|binding| binding.handle.get() == handle)
    }

    /// The core connection behind the connection handle `connection` (P7-D-011).
    pub(super) fn connection(&self, connection: ConnectionHandle) -> Option<ConnectionRef> {
        self.binding(connection).map(|binding| binding.connection)
    }

    /// The core connection and the exact run behind `run`, which must be a run handle of exactly
    /// the connection `connection` names: a run of another connection, host, or loop, or a
    /// handle of another kind, names nothing. Never matched by request ID.
    pub(super) fn run(
        &self,
        connection: ConnectionHandle,
        run: RunHandle,
    ) -> Option<(ConnectionRef, RunRef)> {
        let binding = self.binding(connection)?;
        let exact = binding
            .runs
            .iter()
            .find(|bound| bound.handle.get() == run)?;
        Some((binding.connection, exact.run.clone()))
    }

    /// Run references `connection` holds; `None` when it names no live connection.
    pub(super) fn run_count(&self, connection: ConnectionHandle) -> Option<usize> {
        self.binding(connection).map(|binding| binding.runs.len())
    }

    /// Removes the run reference `run` of `connection` (the exact run ended, or was found
    /// stale). Removing an absent reference changes nothing.
    pub(super) fn remove_run(&mut self, connection: ConnectionHandle, run: RunHandle) {
        if let Some(binding) = self.binding_mut(connection) {
            binding.runs.retain(|bound| bound.handle.get() != run);
        }
    }

    /// Records the exact run a trusted local Initiator start just routed on `connection`, under
    /// its already-preflighted `handle`. References under the same request ID are retired first
    /// (the core routes one run per key, so they ended), exactly as for a run an event reports.
    /// The caller checked under the same runtime slot that the connection is bound and holds
    /// fewer than `MAX_RUNS_PER_CONNECTION` references; `false` if that no longer holds (a
    /// broken invariant: nothing is recorded).
    pub(super) fn bind_local_run(
        &mut self,
        connection: ConnectionHandle,
        run: RunRef,
        handle: NonZeroU64,
    ) -> bool {
        let Some(binding) = self.binding_mut(connection) else {
            return false;
        };
        binding.retire(run.request_id());
        if binding.runs.len() >= MAX_RUNS_PER_CONNECTION {
            return false;
        }
        binding.runs.push(RunBinding { handle, run });
        true
    }

    /// The core connection behind a connection handle (tests only).
    #[cfg(test)]
    pub(super) fn connection_for_test(&self, handle: ConnectionHandle) -> Option<ConnectionRef> {
        self.connections
            .iter()
            .find(|binding| binding.handle.get() == handle)
            .map(|binding| binding.connection)
    }

    /// The parent connection handle and exact run behind a run handle (tests only).
    #[cfg(test)]
    pub(super) fn run_for_test(&self, handle: RunHandle) -> Option<(ConnectionHandle, RunRef)> {
        self.connections.iter().find_map(|binding| {
            binding
                .runs
                .iter()
                .find(|run| run.handle.get() == handle)
                .map(|run| (binding.handle.get(), run.run.clone()))
        })
    }

    /// `(connections, run references)` held (tests only).
    #[cfg(test)]
    pub(super) fn counts_for_test(&self) -> (usize, usize) {
        let runs = self
            .connections
            .iter()
            .map(|binding| binding.runs.len())
            .sum();
        (self.connections.len(), runs)
    }

    /// Run references of the connection behind `handle` (tests only).
    #[cfg(test)]
    pub(super) fn runs_of_for_test(&self, handle: ConnectionHandle) -> usize {
        self.connections
            .iter()
            .find(|binding| binding.handle.get() == handle)
            .map_or(0, |binding| binding.runs.len())
    }
}

#[cfg(windows)]
impl ConnectionBinding {
    /// The handle of exactly `run`: the existing one if this exact run is already referenced,
    /// otherwise a new one. Before a new one is issued, references under the same request ID
    /// are removed: the core routes one run per (session, request ID), so a live `run` proves
    /// every other run under its key ended. `None` when the connection already holds
    /// `MAX_RUNS_PER_CONNECTION` references: nothing is evicted.
    fn run_handle(
        &mut self,
        run: RunRef,
        issue: impl FnOnce() -> Result<NonZeroU64, i32>,
    ) -> Result<Option<NonZeroU64>, i32> {
        if let Some(existing) = self.runs.iter().find(|binding| binding.run == run) {
            return Ok(Some(existing.handle));
        }
        self.retire(run.request_id());
        if self.runs.len() >= MAX_RUNS_PER_CONNECTION {
            return Ok(None);
        }
        let handle = issue()?;
        self.runs.push(RunBinding { handle, run });
        Ok(Some(handle))
    }

    /// Removes every run reference under `request_id`: the event just reported that the run
    /// routed under it ended, and no other run can be live under that key.
    fn retire(&mut self, request_id: &[u8]) {
        self.runs
            .retain(|binding| binding.run.request_id() != request_id);
    }
}

// --- Stable translations ---------------------------------------------------------------------

/// The protocol event and, for a peer CANCEL, its reason. Exhaustive.
#[cfg(windows)]
pub(super) fn protocol_event(event: HostEvent) -> (u32, u32) {
    let plain = |value| (value, SAS_PAIRING_CANCEL_REASON_NONE);
    match event {
        HostEvent::StartAccepted => plain(SAS_PAIRING_PROTOCOL_EVENT_START_ACCEPTED),
        HostEvent::StartDuplicate => plain(SAS_PAIRING_PROTOCOL_EVENT_START_DUPLICATE),
        HostEvent::Accept => plain(SAS_PAIRING_PROTOCOL_EVENT_ACCEPT),
        HostEvent::InitiatorKey => plain(SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_KEY),
        HostEvent::ResponderKey => plain(SAS_PAIRING_PROTOCOL_EVENT_RESPONDER_KEY),
        HostEvent::BootstrapMac(PeerApproval::Authenticated) => {
            plain(SAS_PAIRING_PROTOCOL_EVENT_BOOTSTRAP_MAC_AUTHENTICATED)
        }
        HostEvent::BootstrapMac(PeerApproval::AlreadyAuthenticated) => {
            plain(SAS_PAIRING_PROTOCOL_EVENT_BOOTSTRAP_MAC_DUPLICATE)
        }
        HostEvent::InitiatorFinish => plain(SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH),
        HostEvent::InitiatorFinishDuplicate => {
            plain(SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH_DUPLICATE)
        }
        HostEvent::ResponderFinishAck => plain(SAS_PAIRING_PROTOCOL_EVENT_RESPONDER_FINISH_ACK),
        HostEvent::InitiatorFinishAck => plain(SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH_ACK),
        HostEvent::Cancel(cancel) => (
            SAS_PAIRING_PROTOCOL_EVENT_PEER_CANCEL,
            cancel_reason(cancel.reason()),
        ),
    }
}

#[cfg(windows)]
pub(super) fn cancel_reason(reason: CancelReason) -> u32 {
    match reason {
        CancelReason::UserRejection => SAS_PAIRING_CANCEL_REASON_USER_REJECTION,
        CancelReason::UserCancellation => SAS_PAIRING_CANCEL_REASON_USER_CANCELLATION,
        CancelReason::Timeout => SAS_PAIRING_CANCEL_REASON_TIMEOUT,
        CancelReason::LocalPolicyFailure => SAS_PAIRING_CANCEL_REASON_LOCAL_POLICY_FAILURE,
    }
}

#[cfg(windows)]
pub(super) fn deadline_kind(kind: CeremonyDeadline) -> u32 {
    match kind {
        CeremonyDeadline::TimedOut(Deadline::Absolute) => SAS_PAIRING_DEADLINE_ABSOLUTE_TIMEOUT,
        CeremonyDeadline::TimedOut(Deadline::Inactivity) => SAS_PAIRING_DEADLINE_INACTIVITY_TIMEOUT,
        CeremonyDeadline::PendingExpired => SAS_PAIRING_DEADLINE_PENDING_EXPIRED,
        CeremonyDeadline::ClockUnavailable => SAS_PAIRING_DEADLINE_CLOCK_UNAVAILABLE,
    }
}

#[cfg(windows)]
pub(super) fn cancel_state(cancel: TimeoutCancel) -> u32 {
    match cancel {
        TimeoutCancel::NotBuilt => SAS_PAIRING_CANCEL_STATE_NOT_BUILT,
        TimeoutCancel::Pending => SAS_PAIRING_CANCEL_STATE_PENDING,
        TimeoutCancel::Dropped => SAS_PAIRING_CANCEL_STATE_DROPPED,
    }
}

/// Why an adapter ended a connection or refused an accepted socket.
#[cfg(windows)]
pub(super) fn tcp_reason(error: &TcpError) -> u32 {
    match error {
        TcpError::Closed => SAS_PAIRING_EVENT_REASON_ALREADY_CLOSED,
        TcpError::PeerClosed => SAS_PAIRING_EVENT_REASON_PEER_CLOSED,
        TcpError::Io(_) => SAS_PAIRING_EVENT_REASON_SOCKET_IO,
        TcpError::Host(error) => host_reason(error),
        TcpError::AbandonedPartialFrame => SAS_PAIRING_EVENT_REASON_ABANDONED_PARTIAL_FRAME,
    }
}

#[cfg(windows)]
pub(super) fn host_reason(error: &HostError) -> u32 {
    match error {
        HostError::Transport(error) => transport_reason(*error),
        HostError::Unroutable(_) => SAS_PAIRING_EVENT_REASON_INVALID_FRAME,
        HostError::Routing(error) => route_reason(error),
    }
}

#[cfg(windows)]
pub(super) fn transport_reason(error: TransportError) -> u32 {
    match error {
        TransportError::ResourceLimited => SAS_PAIRING_EVENT_REASON_RESOURCE_LIMITED,
        TransportError::InvalidFrame | TransportError::FrameTooLarge => {
            SAS_PAIRING_EVENT_REASON_INVALID_FRAME
        }
        TransportError::WholeFrameTimeout
        | TransportError::IdleTimeout
        | TransportError::FirstFrameTimeout
        | TransportError::QuiescentTimeout
        | TransportError::RetainedOutputTimeout
        | TransportError::RetainedOutputIdleTimeout => SAS_PAIRING_EVENT_REASON_TRANSPORT_DEADLINE,
        TransportError::ClockUnavailable => SAS_PAIRING_EVENT_REASON_CLOCK_UNAVAILABLE,
        TransportError::Closed => SAS_PAIRING_EVENT_REASON_ALREADY_CLOSED,
        TransportError::OwnershipUncertain => SAS_PAIRING_EVENT_REASON_OWNERSHIP_UNCERTAIN,
    }
}

/// A routing outcome: a run-local refusal of one frame or confirmation, or the routing reason a
/// host ended its connection.
#[cfg(windows)]
pub(super) fn route_reason(error: &RouteError) -> u32 {
    match error {
        RouteError::UnknownSession => SAS_PAIRING_EVENT_REASON_OTHER_HOST_FAILURE,
        RouteError::UnknownRoute => SAS_PAIRING_EVENT_REASON_ROUTE_REFUSED,
        RouteError::SessionProtocolFailure => SAS_PAIRING_EVENT_REASON_SESSION_PROTOCOL_FAILURE,
        RouteError::Ceremony(error) => ceremony_reason(error),
    }
}

/// Collapses ceremony detail into the operational reasons; P7.6 owns precise local-action
/// statuses. Exhaustive, so a new ceremony error is a conscious ABI decision.
#[cfg(windows)]
pub(super) fn ceremony_reason(error: &CeremonyError) -> u32 {
    match error {
        CeremonyError::Owner(Error::ResourceLimited) => SAS_PAIRING_EVENT_REASON_RESOURCE_LIMITED,
        CeremonyError::Owner(Error::OwnershipUncertain) => {
            SAS_PAIRING_EVENT_REASON_OWNERSHIP_UNCERTAIN
        }
        CeremonyError::Owner(
            Error::InvalidScope
            | Error::AlreadyRegistered
            | Error::OwnershipUnavailable
            | Error::UnsupportedPlatform
            | Error::Busy
            | Error::MissingAuthorization
            | Error::StaleAuthorization
            | Error::Exhausted
            | Error::Terminated,
        ) => SAS_PAIRING_EVENT_REASON_ROUTE_REFUSED,
        CeremonyError::ClockUnavailable => SAS_PAIRING_EVENT_REASON_CLOCK_UNAVAILABLE,
        CeremonyError::Codec(_)
        | CeremonyError::Crypto(_)
        | CeremonyError::InvalidState
        | CeremonyError::NoLiveSas
        | CeremonyError::CeremonyIdentityMismatch
        | CeremonyError::NotLocallyApproved
        | CeremonyError::UnexpectedSenderRole
        | CeremonyError::InvalidRequestId
        | CeremonyError::RequestIdGenerationFailed
        | CeremonyError::RequestIdMismatch
        | CeremonyError::SharedContextMismatch
        | CeremonyError::ExpectedPeerMismatch
        | CeremonyError::ApprovalsNotAuthenticated
        | CeremonyError::NotInitiator
        | CeremonyError::TranscriptMismatch
        | CeremonyError::Completed
        | CeremonyError::NoPendingFinalAck
        | CeremonyError::FinalAckMismatch
        | CeremonyError::TimedOut(_)
        | CeremonyError::PendingExpired => SAS_PAIRING_EVENT_REASON_ROUTE_REFUSED,
    }
}

#[cfg(windows)]
pub(super) fn listener_reason(failure: ListenerFailure) -> u32 {
    match failure {
        ListenerFailure::Io(_) => SAS_PAIRING_EVENT_REASON_LISTENER_IO,
        ListenerFailure::Readiness(_) => SAS_PAIRING_EVENT_REASON_LISTENER_READINESS,
    }
}

#[cfg(windows)]
pub(super) fn end_reason(end: &ConnectionEnd) -> u32 {
    match end {
        ConnectionEnd::Adapter(error) => tcp_reason(error),
        ConnectionEnd::Readiness(_) => SAS_PAIRING_EVENT_REASON_READINESS_FAILURE,
    }
}

/// The owner loop's own failure of one call, as the drive's `out_failure`. `OwnershipUncertain`
/// and `Poll` are the only failures the loop reports in a step (it fails closed for nothing
/// else); any other value breaks that invariant and is fatal (`None`: the caller marks it).
#[cfg(windows)]
pub(super) fn owner_failure_status(failure: &OwnerLoopError) -> Option<i32> {
    match failure {
        OwnerLoopError::OwnershipUncertain => Some(SAS_PAIRING_OWNERSHIP_UNCERTAIN),
        OwnerLoopError::Poll(_) => Some(SAS_PAIRING_NETWORK_POLL_FAILED),
        OwnerLoopError::Closed
        | OwnerLoopError::UnknownConnection
        | OwnerLoopError::ListenerIo(_)
        | OwnerLoopError::Connection(_) => None,
    }
}

// --- Conversion ------------------------------------------------------------------------------

/// Whether `events` can be converted without any failure: at most `MAX_DRIVE_EVENTS`, each
/// connection named at most once, an accepted connection not yet bound and every other
/// connection bound, and every request ID within `MAX_REQUEST_ID_LEN`. The owner loop
/// guarantees all of this; a violation is a broken invariant, never an ordinary error.
#[cfg(windows)]
fn well_formed(events: &[OwnerEvent], bindings: &Bindings) -> bool {
    if events.len() > MAX_DRIVE_EVENTS {
        return false;
    }
    let mut named: Vec<ConnectionRef> = Vec::with_capacity(MAX_DRIVE_EVENTS);
    let fits = |id: &[u8]| id.len() <= MAX_REQUEST_ID_LEN;
    for event in events {
        let (connection, bound) = match event {
            OwnerEvent::AcceptRefused(_) | OwnerEvent::ListenerDisabled(_) => continue,
            OwnerEvent::Accepted(connection) => (connection, false),
            OwnerEvent::Closed(connection, _) => (connection, true),
            OwnerEvent::Step(connection, step) => {
                let ids_fit = match &step.event {
                    Some(TcpEvent::Inbound { request_id, .. }) => fits(request_id),
                    Some(TcpEvent::Deadline { request_id, .. }) => {
                        request_id.as_deref().is_none_or(fits)
                    }
                    Some(
                        TcpEvent::Refused(_)
                        | TcpEvent::Written
                        | TcpEvent::Confirmed
                        | TcpEvent::Unconfirmed(_)
                        | TcpEvent::Discarded,
                    )
                    | None => true,
                };
                let result_fits = step
                    .result
                    .as_ref()
                    .is_none_or(|result| fits(result.request_id()));
                if !ids_fit || !result_fits {
                    return false;
                }
                (connection, true)
            }
        };
        if named.contains(connection) || bindings.index_of(connection).is_some() != bound {
            return false;
        }
        named.push(*connection);
    }
    true
}

/// Issues one handle the preflight already guaranteed; running out here breaks that guarantee
/// and is fatal.
#[cfg(windows)]
pub(super) fn issue(state: &AbiState) -> Result<NonZeroU64, i32> {
    state.allocate_handle().map_err(|_| {
        state.fatal.mark();
        SAS_PAIRING_FATAL
    })
}

/// Converts one owner-loop call into drive output, updating the host's references and storing
/// every surfaced `PairingResult` in the runtime. Runs under the runtime slot after the
/// preflight, so it allocates at most `DRIVE_HANDLE_BOUND` handles that are known to exist.
/// After a validated step nothing here fails normally; a broken invariant marks the process
/// fatal (never a silently dropped event).
#[cfg(windows)]
pub(super) fn convert(
    state: &AbiState,
    bindings: &mut Bindings,
    results: &mut BTreeMap<NonZeroU64, PairingResult>,
    stepped: Result<OwnerStep, OwnerLoopError>,
) -> Result<DriveOutput, i32> {
    let mut output = DriveOutput::empty();
    let OwnerStep { events, failure } = match stepped {
        Ok(step) => step,
        // Closed earlier: nothing was done, and no connection of that loop is left.
        Err(OwnerLoopError::Closed) => {
            bindings.clear();
            output.failure = SAS_PAIRING_OWNER_LOOP_CLOSED;
            return Ok(output);
        }
        // `drive_once` and `recheck_after_resume` refuse only with `Closed`.
        Err(
            OwnerLoopError::UnknownConnection
            | OwnerLoopError::ListenerIo(_)
            | OwnerLoopError::Poll(_)
            | OwnerLoopError::OwnershipUncertain
            | OwnerLoopError::Connection(_),
        ) => {
            bindings.clear();
            state.fatal.mark();
            output.failure = SAS_PAIRING_FATAL;
            return Ok(output);
        }
    };
    if !well_formed(&events, bindings) {
        bindings.clear();
        state.fatal.mark();
        return Err(SAS_PAIRING_FATAL);
    }
    for (slot, event) in output.events.iter_mut().zip(events) {
        *slot = convert_event(state, bindings, results, event)?;
        output.count += 1;
    }
    if let Some(failure) = failure {
        // The loop failed closed: its listener and every connection are gone, without CLOSED
        // events, so every reference of this loop ends with this call.
        bindings.clear();
        output.failure = owner_failure_status(&failure).unwrap_or_else(|| {
            state.fatal.mark();
            SAS_PAIRING_FATAL
        });
    }
    Ok(output)
}

#[cfg(windows)]
fn convert_event(
    state: &AbiState,
    bindings: &mut Bindings,
    results: &mut BTreeMap<NonZeroU64, PairingResult>,
    event: OwnerEvent,
) -> Result<Event, i32> {
    let mut out = Event::ZERO;
    // Validated: an accepted connection is unbound, every other connection is bound.
    let broken = || {
        state.fatal.mark();
        SAS_PAIRING_FATAL
    };
    match event {
        OwnerEvent::Accepted(connection) => {
            out.kind = SAS_PAIRING_EVENT_CONNECTION_ACCEPTED;
            let handle = issue(state)?;
            bindings.bind(connection, handle);
            out.connection = handle.get();
        }
        OwnerEvent::AcceptRefused(error) => {
            out.kind = SAS_PAIRING_EVENT_ACCEPT_REFUSED;
            out.reason = tcp_reason(&error);
        }
        OwnerEvent::ListenerDisabled(failure) => {
            out.kind = SAS_PAIRING_EVENT_LISTENER_DISABLED;
            out.reason = listener_reason(failure);
        }
        OwnerEvent::Step(connection, step) => {
            out.kind = SAS_PAIRING_EVENT_CONNECTION_STEP;
            let binding = bindings.get_mut(&connection).ok_or_else(broken)?;
            out.connection = binding.handle.get();
            convert_step(state, binding, results, step, &mut out)?;
        }
        OwnerEvent::Closed(connection, end) => {
            out.kind = SAS_PAIRING_EVENT_CONNECTION_CLOSED;
            out.reason = end_reason(&end);
            // The handle of the connection that just ended; it is invalid once this returns.
            out.connection = bindings.unbind(&connection).ok_or_else(broken)?.get();
        }
    }
    Ok(out)
}

#[cfg(windows)]
fn convert_step(
    state: &AbiState,
    binding: &mut ConnectionBinding,
    results: &mut BTreeMap<NonZeroU64, PairingResult>,
    step: TcpStep,
    out: &mut Event,
) -> Result<(), i32> {
    let TcpStep {
        event,
        result,
        write_pending,
    } = step;
    if write_pending {
        out.flags |= SAS_PAIRING_EVENT_FLAG_WRITE_PENDING;
    }
    let mut live = None;
    match event {
        None => {}
        Some(TcpEvent::Inbound {
            request_id,
            run,
            event,
        }) => {
            out.step_kind = SAS_PAIRING_STEP_INBOUND;
            (out.protocol_event, out.cancel_reason) = protocol_event(event);
            out.set_request_id(&request_id);
            match run {
                Some(run) => live = Some(run),
                // A duplicate START reports no run only while the original is still being
                // admitted; every other frame without a live run ended the run under its key.
                None if matches!(event, HostEvent::StartDuplicate) => {}
                None => binding.retire(&request_id),
            }
        }
        Some(TcpEvent::Refused(error)) => {
            out.step_kind = SAS_PAIRING_STEP_REFUSED;
            out.reason = route_reason(&error);
        }
        Some(TcpEvent::Deadline {
            request_id,
            kind,
            cancel,
        }) => {
            out.step_kind = SAS_PAIRING_STEP_DEADLINE;
            out.deadline_kind = deadline_kind(kind);
            out.cancel_state = cancel_state(cancel);
            if let Some(request_id) = request_id {
                out.set_request_id(&request_id);
                binding.retire(&request_id);
            }
        }
        Some(TcpEvent::Written) => out.step_kind = SAS_PAIRING_STEP_WRITTEN,
        Some(TcpEvent::Confirmed) => out.step_kind = SAS_PAIRING_STEP_CONFIRMED,
        Some(TcpEvent::Unconfirmed(error)) => {
            out.step_kind = SAS_PAIRING_STEP_UNCONFIRMED;
            out.reason = route_reason(&error);
        }
        Some(TcpEvent::Discarded) => out.step_kind = SAS_PAIRING_STEP_DISCARDED,
    }
    match result {
        // Local verified completion: the run is terminal, so no run handle is reported, and
        // the one result moves into runtime storage under its own handle.
        Some(result) => {
            binding.retire(result.request_id());
            if out.request_id_len == 0 {
                out.set_request_id(result.request_id());
            }
            let handle = issue(state)?;
            results.insert(handle, result);
            out.result = handle.get();
        }
        None => {
            if let Some(run) = live {
                match binding.run_handle(run, || issue(state))? {
                    Some(handle) => out.run = handle.get(),
                    None => out.flags |= SAS_PAIRING_EVENT_FLAG_RUN_UNTRACKED,
                }
            }
        }
    }
    Ok(())
}

// --- State operations ------------------------------------------------------------------------

impl AbiState {
    /// One bounded drive or resume recheck of `host`'s owner loop (P7-D-008). Order: the event
    /// capacity, then (through `with_runtime`) the fatal state and the runtime, then the host,
    /// an attached listener, and the handle preflight; only then the owner loop, then the
    /// conversion, all under the runtime slot.
    #[cfg(windows)]
    pub(super) fn drive_host(
        &self,
        runtime: u64,
        host: HostHandle,
        mode: DriveMode,
        capacity: usize,
    ) -> Result<DriveOutput, i32> {
        if capacity < MAX_DRIVE_EVENTS {
            return Err(SAS_PAIRING_BUFFER_TOO_SMALL);
        }
        self.with_runtime(runtime, Admission::Normal, |live| {
            let handle = NonZeroU64::new(host).ok_or(SAS_PAIRING_INVALID_HANDLE)?;
            let context = live
                .hosts
                .get_mut(&handle)
                .ok_or(SAS_PAIRING_INVALID_HANDLE)?;
            if !context.has_network() {
                return Err(SAS_PAIRING_LISTENER_NOT_ATTACHED);
            }
            if !self.can_allocate_handles(DRIVE_HANDLE_BOUND) {
                return Err(SAS_PAIRING_HANDLES_EXHAUSTED);
            }
            let stepped = context
                .step_network(mode)
                .ok_or(SAS_PAIRING_LISTENER_NOT_ATTACHED)?;
            convert(self, context.bindings_mut(), &mut live.results, stepped)
        })
    }

    /// Off Windows no owner loop exists: nothing is driven.
    #[cfg(not(windows))]
    pub(super) fn drive_host(
        &self,
        runtime: u64,
        host: u64,
        mode: DriveMode,
        capacity: usize,
    ) -> Result<DriveOutput, i32> {
        let _ = (self, runtime, host, mode, capacity);
        Err(SAS_PAIRING_UNSUPPORTED_PLATFORM)
    }

    /// Explicitly closes one connection (cleanup, P7-D-009): its connection reference and every
    /// run reference parented to it are removed first, then the owner loop's own close of that
    /// connection runs. Admitted in the fatal state; never clears it.
    #[cfg(windows)]
    pub(super) fn close_connection(
        &self,
        runtime: u64,
        host: HostHandle,
        connection: ConnectionHandle,
    ) -> i32 {
        let closed = self.with_runtime(runtime, Admission::Cleanup, |live| {
            let handle = NonZeroU64::new(host).ok_or(SAS_PAIRING_INVALID_HANDLE)?;
            let context = live
                .hosts
                .get_mut(&handle)
                .ok_or(SAS_PAIRING_INVALID_HANDLE)?;
            if !context.has_network() {
                return Err(SAS_PAIRING_LISTENER_NOT_ATTACHED);
            }
            let target = context
                .bindings_mut()
                .unbind_handle(connection)
                .ok_or(SAS_PAIRING_INVALID_HANDLE)?;
            let closed = context
                .close_network_connection(target)
                .ok_or(SAS_PAIRING_LISTENER_NOT_ATTACHED)?;
            if closed.is_err() {
                // An uncertain cleanup fails the whole loop closed: no connection is left.
                context.bindings_mut().clear();
            }
            Ok(closed)
        });
        match closed {
            Ok(Ok(())) => SAS_PAIRING_OK,
            Ok(Err(OwnerLoopError::OwnershipUncertain)) => SAS_PAIRING_OWNERSHIP_UNCERTAIN,
            // A bound connection is always a live connection of a live loop.
            Ok(Err(
                OwnerLoopError::Closed
                | OwnerLoopError::UnknownConnection
                | OwnerLoopError::ListenerIo(_)
                | OwnerLoopError::Poll(_)
                | OwnerLoopError::Connection(_),
            )) => {
                self.fatal.mark();
                SAS_PAIRING_FATAL
            }
            Err(status) => status,
        }
    }

    /// Off Windows no connection can exist.
    #[cfg(not(windows))]
    pub(super) fn close_connection(&self, runtime: u64, host: u64, connection: u64) -> i32 {
        let _ = (self, runtime, host, connection);
        SAS_PAIRING_UNSUPPORTED_PLATFORM
    }
}

// --- Caller memory ---------------------------------------------------------------------------

/// The address range of `count` values of `T` at `data`, when a Rust slice could describe it:
/// `data` is non-null unless `count` is `0`, the byte size fits `isize`, and the range does not
/// wrap. Addresses are compared as integers; nothing is dereferenced.
pub(super) fn element_range<T>(data: *const T, count: usize) -> Option<(usize, usize)> {
    if count == 0 {
        return Some((data.addr(), data.addr()));
    }
    if data.is_null() {
        return None;
    }
    let bytes = count.checked_mul(size_of::<T>())?;
    isize::try_from(bytes).ok()?;
    Some((data.addr(), data.addr().checked_add(bytes)?))
}

/// Whether two address ranges share a byte; an empty range overlaps nothing.
pub(super) fn overlaps(a: (usize, usize), b: (usize, usize)) -> bool {
    a.0 < a.1 && b.0 < b.1 && a.0 < b.1 && b.0 < a.1
}

/// The shared body of the drive and recheck exports (P7-D-008).
///
/// Order: `out_count` and `out_failure` (non-null, aligned, disjoint), the event array (null only
/// with capacity `0`, aligned, a describable range, disjoint from both outputs), all before any
/// write; then both outputs are set to `0` and `SAS_PAIRING_OK`; then the platform; then the
/// capacity (`SAS_PAIRING_BUFFER_TOO_SMALL` with `*out_count` = the required capacity); then the
/// state checks and the drive. Only the converted events are written, each one whole record.
///
/// # Safety
///
/// Non-null, aligned `out_count` and `out_failure` must each address one writable value of
/// their type, and a non-null `events` must address `capacity` writable `sas_pairing_event_t`
/// records, all caller-owned and not accessed concurrently for the duration of the call.
#[expect(
    clippy::too_many_arguments,
    reason = "the two drive exports' C parameters, plus the state and the drive mode"
)]
pub(super) unsafe fn drive_through(
    state: &AbiState,
    runtime: u64,
    host: u64,
    mode: DriveMode,
    events: *mut Event,
    capacity: usize,
    out_count: *mut usize,
    out_failure: *mut i32,
) -> i32 {
    if out_count.is_null()
        || !out_count.is_aligned()
        || out_failure.is_null()
        || !out_failure.is_aligned()
        || (!events.is_null() && !events.is_aligned())
    {
        return SAS_PAIRING_INVALID_ARGUMENT;
    }
    let (Some(count_range), Some(failure_range), Some(events_range)) = (
        element_range(out_count.cast_const(), 1),
        element_range(out_failure.cast_const(), 1),
        element_range(events.cast_const(), capacity),
    ) else {
        return SAS_PAIRING_INVALID_ARGUMENT;
    };
    if overlaps(count_range, failure_range)
        || overlaps(events_range, count_range)
        || overlaps(events_range, failure_range)
    {
        return SAS_PAIRING_INVALID_ARGUMENT;
    }
    // SAFETY: both pointers are non-null and aligned and their ranges are disjoint from each
    // other and from the event array (checked above); the caller guarantees each addresses one
    // writable value of its type that it owns, unaliased, for this call. `usize` and `i32` have
    // no invalid bit patterns and no destructor.
    let write_count = |value: usize| unsafe { out_count.write(value) };
    // SAFETY: as for `write_count`.
    let write_failure = |value: i32| unsafe { out_failure.write(value) };
    write_count(0);
    write_failure(SAS_PAIRING_OK);
    match state.drive_host(runtime, host, mode, capacity) {
        Ok(output) => {
            for (index, event) in output.events[..output.count].iter().enumerate() {
                // SAFETY: `index < output.count <= MAX_DRIVE_EVENTS <= capacity` (a smaller
                // capacity never reaches the drive), so the record lies inside the validated,
                // aligned, writable caller array, disjoint from both outputs. `Event` is a
                // padding-free `repr(C)` record of integers, written whole.
                unsafe { events.add(index).write(*event) };
            }
            write_count(output.count);
            write_failure(output.failure);
            SAS_PAIRING_OK
        }
        Err(SAS_PAIRING_BUFFER_TOO_SMALL) => {
            write_count(MAX_DRIVE_EVENTS);
            SAS_PAIRING_BUFFER_TOO_SMALL
        }
        Err(status) => status,
    }
}
