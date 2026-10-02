//! Crate-private, experimental Windows adapter that drives one `HostConnection` over one
//! ALREADY-CONNECTED `std::net::TcpStream`. TCP here is one P4 adapter implementation, not a P3
//! carrier requirement: nothing about TCP (addresses, ports, the socket) reaches any wire frame,
//! transcript, MAC input, authorization, accounting, or authority identity, and no peer address
//! is retained or used as a key. There is no listener, bind, port, interface, discovery,
//! `connect`, TLS, reconnect, or resume: trusted outer code obtains the connected stream and,
//! before any other work, an `AcceptPermit` of the authority's bounded accept-work queue, and
//! hands both over. That outer code also decides when the socket is readable or writable and
//! when deadlines are polled; this module spawns, sleeps, waits, and schedules nothing.
//!
//! One adapter is one TCP connection, one `TransportConnection` (one live count), and one Router
//! session for its whole life. Every call does bounded synchronous work and returns:
//! - `on_readable`: at most one nonblocking OS read of at most `SOCKET_READ_CHUNK` bytes, and at
//!   most one complete frame dispatched through the host. Bytes of that read the host did not
//!   take stay in a fixed retained suffix (never more than one read chunk) and are fed before
//!   the socket is read again; no receive queue exists. Framing, `MAX_FRAME`, the incomplete-
//!   frame caps, and the 10 s / 2 s frame deadlines stay the transport's: this module only
//!   moves chunks.
//! - `on_writable`: at most one nonblocking OS write of the one retained outbound frame, resuming
//!   at its exact offset, after one exact deadline check of the live run that owns the frame (one
//!   run, no scan), so no frame of a run that has ended is written further, wherever the fair
//!   deadline cursor stands. A frame leaves the slot only once its last byte was written locally;
//!   ordinary frames are never confirmed, and the Initiator's `FinalAck` goes to
//!   `HostConnection::confirm_sent` only then, so its `PairingResult` exists only after the
//!   complete local write. Written locally is never peer receipt.
//! - `poll_frame_deadlines` and `poll_ceremony_deadlines`: exactly one host poll each.
//!
//! Backpressure: at most ONE outbound frame is ever retained (one `Option`). While it is, the
//! socket is not read, no inbound frame is dispatched, and every mutating local action is refused
//! (`Refused::WritePending`) before the host is called, so no second output can be produced; the
//! peer's TCP flow control holds back further input. Read-only presentation and both deadline
//! polls still run, so a peer that stops reading cannot extend any deadline. A run-local timeout
//! CANCEL takes the slot only if it is free; otherwise it is dropped as best effort (the run is
//! terminal either way). A run whose own frame is retained and that ends (by deadline, found by
//! either deadline poll or by the write's own owner check) loses that frame: unsent, it is
//! discarded (its timeout CANCEL may replace it); partially written, the byte stream holds a
//! truncated canonical frame that can be neither retracted nor followed, so the whole
//! connection is closed with nothing appended.
//!
//! WouldBlock and Interrupted are not failures: the call changes nothing (no host call, no
//! deadline refresh, no confirmation) and is never retried inside the call; the next readiness
//! call retries. EOF, any other socket error, a write of zero bytes, an orphaned partial frame,
//! a host error, and an explicit close or drop all take one path: stop I/O and shut the socket
//! down, discard the retained suffix and outbound frame (a `FinalAck` is never confirmed), then
//! close the host, whose transport teardown settles the Router session (every run terminal, no
//! result, no CANCEL, no refund, consumed opportunities kept) before releasing the live count,
//! which stays held if that cleanup is uncertain. None of these is authentication, SAS-mismatch,
//! compromise, or opportunity-exhaustion evidence.
#![allow(dead_code)] // Used by tests and the crate-private owner loop until a consumer API exists.
use crate::{
    TrustedAuthority,
    ceremony::{CeremonyError, PairingResult, SasPresentation, Timeout},
    host::{
        self, CeremonyDeadline, CeremonyDeadlineEvent, CeremonyPoll, Dispatched, HostConnection,
        HostError, HostEvent, HostFed, HostResult, LocalAction, LocalEvent, Outbound,
    },
    protocol::Bootstrap,
    router::{DeadlineEnded, RouteError, RunRef, SessionHandle},
    transport::{AcceptPermit, TransportConnection, TransportError},
};
#[cfg(test)]
use crate::{deadline::Clock, request_id::RequestIdGenerator};
use std::{
    io::{self, ErrorKind, Read, Write},
    net::{Shutdown, TcpStream},
    os::windows::io::AsRawSocket,
};
use windows_sys::Win32::Networking::WinSock::SOCKET;

/// Bytes taken from the socket by one read, and so the most ever retained unconsumed. Local
/// I/O plumbing only: not a protocol limit and not `MAX_FRAME`, which the transport enforces.
pub(crate) const SOCKET_READ_CHUNK: usize = 8192;

/// The few nonblocking socket operations the adapter makes. Production uses the real
/// `TcpStream`; tests script partial writes, WouldBlock, EOF, and errors deterministically.
pub(crate) trait SocketIo {
    fn configure_nonblocking(&mut self) -> io::Result<()>;
    /// One nonblocking read into `buf`.
    fn read_some(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    /// One nonblocking write of a prefix of `bytes`.
    fn write_some(&mut self, bytes: &[u8]) -> io::Result<usize>;
    /// Best-effort shutdown of both directions; the OS handle closes when the adapter drops.
    fn shut_down(&mut self);
}

/// The OS socket handle a readiness wait (`WSAPoll`) needs. Only a readiness handle: never a
/// connection, routing, authorization, or accounting identity, and never compared or retained.
pub(crate) trait RawSocket {
    fn raw_socket(&self) -> SOCKET;
}

impl RawSocket for TcpStream {
    fn raw_socket(&self) -> SOCKET {
        // A Windows SOCKET value, which always fits the platform's pointer-sized SOCKET.
        self.as_raw_socket() as SOCKET
    }
}

impl SocketIo for TcpStream {
    fn configure_nonblocking(&mut self) -> io::Result<()> {
        self.set_nonblocking(true)
    }
    fn read_some(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read(buf)
    }
    fn write_some(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.write(bytes)
    }
    fn shut_down(&mut self) {
        let _ = self.shutdown(Shutdown::Both);
    }
}

/// Why the adapter's connection ended. Every `Err` from an adapter method means it is closed
/// (`Closed`: it already was, and nothing was done); outcomes that leave it live are inside
/// `Ok`. None of these says anything about the peer, authentication, an SAS, compromise, or
/// the opportunity budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TcpError {
    /// The adapter had already closed; nothing was done.
    Closed,
    /// The socket read reached end of stream.
    PeerClosed,
    /// A local socket failure (the kind is diagnostic only): nonblocking setup, a read or write
    /// error other than WouldBlock/Interrupted, `WriteZero` for a write that took nothing, or
    /// `InvalidData` for an OS count larger than the buffer offered.
    Io(ErrorKind),
    /// The host ended (or could not establish teardown of) the connection: transport failure
    /// or refusal, an unroutable frame, session-fatal routing, or `OwnershipUncertain`.
    Host(HostError),
    /// The run owning a partially written frame ended, leaving a truncated frame on the stream.
    AbandonedPartialFrame,
}

/// A trusted local action that was not applied, with the connection still live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Refused {
    /// One outbound frame is still retained: nothing reached the host; retry once it is written.
    WritePending,
    /// The run's or Router's own run-local refusal.
    Run(RouteError),
}

/// What became of a timeout's authenticated CANCEL. The run is terminal in every case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TimeoutCancel {
    /// None exists (no shared SAS yet, or not a timeout).
    NotBuilt,
    /// It is now the one retained outbound frame (best effort; never confirmed or retried).
    Pending,
    /// Another run's frame occupied the one slot: dropped as best effort, never queued.
    Dropped,
}

/// The one semantic outcome of an adapter call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TcpEvent {
    /// One inbound frame was dispatched. Any frame it produced is now the retained write and
    /// is not copied here; `run` is present while that run is still live.
    Inbound {
        request_id: Vec<u8>,
        run: Option<RunRef>,
        event: HostEvent,
    },
    /// The one dispatched frame was refused by its START attempt or run (run-local).
    Refused(RouteError),
    /// A run ended by its own deadline processing, found by a poll (request ID present), an
    /// inbound frame, or a final-ACK send confirmation.
    Deadline {
        request_id: Option<Vec<u8>>,
        kind: CeremonyDeadline,
        cancel: TimeoutCancel,
    },
    /// The retained ordinary frame's last byte was written locally.
    Written,
    /// The final ACK's last byte was written locally and confirmed: the result is attached.
    Confirmed,
    /// The final ACK was written completely but its run refused confirmation: no result.
    Unconfirmed(RouteError),
    /// The retained frame's owner run was no longer live before any of its bytes were written:
    /// the frame was dropped unwritten. Nothing else changed.
    Discarded,
}

/// One bounded adapter call: at most one event and one `PairingResult`. Outbound bytes are
/// never returned: the adapter owns and writes them.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct TcpStep {
    pub(crate) event: Option<TcpEvent>,
    pub(crate) result: Option<PairingResult>,
    /// One outbound frame is retained: wait for writable readiness.
    pub(crate) write_pending: bool,
}

/// One applied trusted local action. Any frame it produced is the retained write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Acted {
    /// The run, present only while it is still live after this action.
    pub(crate) run: Option<RunRef>,
    pub(crate) event: LocalEvent,
    pub(crate) write_pending: bool,
}

/// The one outbound frame being written: the exact host output (a `FinalAck` stays itself
/// until its last byte is written), how much was written, and the live run that produced it.
/// Local plumbing only; the owner never reaches the wire.
#[derive(Debug)]
struct PendingWrite {
    outbound: Outbound,
    /// Bytes already written locally; always less than the frame length while retained.
    offset: usize,
    /// `None` for a frame of an already-terminal run (a best-effort CANCEL).
    owner: Option<RunRef>,
}

/// Unconsumed bytes of the last socket read, fed to the host before the socket is read again.
/// Structurally bounded by one read chunk.
struct ReadSuffix {
    buf: Box<[u8; SOCKET_READ_CHUNK]>,
    start: usize,
    end: usize,
}

impl ReadSuffix {
    fn unread(&self) -> &[u8] {
        &self.buf[self.start..self.end]
    }
    fn is_empty(&self) -> bool {
        self.start == self.end
    }
    fn clear(&mut self) {
        (self.start, self.end) = (0, 0);
    }
}

type Outcome<T> = Result<Result<T, Refused>, TcpError>;

/// One already-connected TCP stream driving one admitted host connection. See the module docs.
pub(crate) struct WindowsTcpConnection<'r, S: SocketIo = TcpStream> {
    io: S,
    /// `None` once closed: no further I/O or host call is made.
    host: Option<HostConnection<'r>>,
    suffix: ReadSuffix,
    pending: Option<PendingWrite>,
}

impl<'r> WindowsTcpConnection<'r> {
    /// Takes an already-connected stream and the `AcceptPermit` trusted outer code acquired for
    /// it immediately after the OS accept (a refused permit means: close the socket and create
    /// nothing). The stream is made nonblocking first; if that fails, the socket and permit are
    /// dropped and nothing becomes live. Otherwise the permit's own activation takes the live
    /// count and opens the one Router session (refused at 16 live: the socket is dropped and
    /// nothing else exists), and the host wraps that connection with the local Responder
    /// configuration for new STARTs.
    pub(crate) fn from_accepted(
        stream: TcpStream,
        permit: AcceptPermit<'r>,
        local: Bootstrap,
        expected: Option<Bootstrap>,
    ) -> Result<Self, TcpError> {
        Self::admit(stream, permit, AcceptPermit::activate, |transport| {
            HostConnection::new(transport, local, expected)
        })
    }
}

impl<'r, S: SocketIo> WindowsTcpConnection<'r, S> {
    /// `from_accepted` over any socket, with hand transport and new-Responder ceremony clocks.
    #[cfg(test)]
    pub(crate) fn from_accepted_with(
        io: S,
        permit: AcceptPermit<'r>,
        local: Bootstrap,
        expected: Option<Bootstrap>,
        transport: Clock,
        ceremony: Clock,
    ) -> Result<Self, TcpError> {
        Self::admit(
            io,
            permit,
            |permit| permit.activate_with_clock(transport),
            |connection| HostConnection::with_ceremony_clock(connection, local, expected, ceremony),
        )
    }

    fn admit(
        mut io: S,
        permit: AcceptPermit<'r>,
        activate: impl FnOnce(AcceptPermit<'r>) -> Result<TransportConnection<'r>, TransportError>,
        wrap: impl FnOnce(TransportConnection<'r>) -> HostConnection<'r>,
    ) -> Result<Self, TcpError> {
        if let Err(error) = io.configure_nonblocking() {
            drop(io);
            drop(permit);
            return Err(TcpError::Io(error.kind()));
        }
        let transport = match activate(permit) {
            Ok(transport) => transport,
            Err(error) => {
                drop(io);
                return Err(TcpError::Host(HostError::Transport(error)));
            }
        };
        Ok(Self {
            io,
            host: Some(wrap(transport)),
            suffix: ReadSuffix {
                buf: Box::new([0; SOCKET_READ_CHUNK]),
                start: 0,
                end: 0,
            },
            pending: None,
        })
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.host.is_none()
    }

    /// This connection's one Router session while it is live. Local and volatile; an owner
    /// may use it to name this adapter, never as peer identity or authentication.
    pub(crate) fn session(&self) -> Option<SessionHandle> {
        self.host.as_ref().map(HostConnection::session)
    }

    /// Whether one outbound frame is retained (wait for writable readiness, not readable).
    pub(crate) fn write_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// Whether unconsumed bytes of an earlier read are retained: `on_readable` then has work
    /// that no new socket readiness will announce.
    pub(crate) fn input_buffered(&self) -> bool {
        !self.suffix.is_empty()
    }

    /// The socket's readiness handle, for an owner's `WSAPoll` interest only.
    pub(crate) fn raw_socket(&self) -> SOCKET
    where
        S: RawSocket,
    {
        self.io.raw_socket()
    }

    /// Socket readable: dispatches at most one complete frame, from the retained suffix if any
    /// is left, otherwise from at most one OS read. Nothing is read or dispatched while a frame
    /// is retained for writing. Returns that frame's event; its output becomes the retained
    /// write. A deadline the frame's run found expired surfaces its timeout CANCEL.
    pub(crate) fn on_readable(&mut self) -> Result<TcpStep, TcpError> {
        if self.host.is_none() {
            return Err(TcpError::Closed);
        }
        if self.pending.is_some() {
            return Ok(self.step(None, None));
        }
        if self.suffix.is_empty() {
            match self.io.read_some(&mut self.suffix.buf[..]) {
                Ok(0) => return Err(self.end(TcpError::PeerClosed)),
                Ok(read) if read <= SOCKET_READ_CHUNK => {
                    (self.suffix.start, self.suffix.end) = (0, read)
                }
                Ok(_) => return Err(self.end(TcpError::Io(ErrorKind::InvalidData))),
                Err(error) if retry_later(&error) => return Ok(self.step(None, None)),
                Err(error) => return Err(self.end(TcpError::Io(error.kind()))),
            }
        }
        let Some(host) = self.host.as_mut() else {
            return Err(TcpError::Closed);
        };
        let HostFed { consumed, frame } = match host.receive(self.suffix.unread()) {
            Ok(fed) => fed,
            Err(error) => return Err(self.end(TcpError::Host(error))),
        };
        self.suffix.start += consumed;
        let event = match frame {
            None => None,
            Some(Ok(Dispatched {
                request_id,
                run,
                event,
                outbound,
                result,
            })) => {
                self.retain(outbound, run.clone());
                let event = TcpEvent::Inbound {
                    request_id,
                    run,
                    event,
                };
                return Ok(self.step(Some(event), result));
            }
            Some(Err(RouteError::Ceremony(CeremonyError::TimedOut(timeout)))) => {
                Some(self.timed_out(None, timeout))
            }
            Some(Err(error)) => Some(TcpEvent::Refused(error)),
        };
        Ok(self.step(event, None))
    }

    /// Socket writable: one OS write of the retained frame from its offset. Only once its last
    /// byte is written does it leave the slot; a `FinalAck` is then confirmed through the host,
    /// which alone creates the Initiator's result (or ends the run if its deadline passed,
    /// surfacing the timeout CANCEL into the now-free slot).
    ///
    /// Before that write, a frame a live run owns gets an exact deadline check of that one run
    /// (`HostConnection::poll_run_deadline`), so whether stale bytes are written never depends on
    /// where the fair deadline cursor stands. If the owner ended (deadline, or a stale
    /// reference), nothing is written by this call: unsent, the frame is discarded (a timeout
    /// CANCEL may take the slot); partially written, the connection closes with nothing appended.
    pub(crate) fn on_writable(&mut self) -> Result<TcpStep, TcpError> {
        let Some(host) = self.host.as_mut() else {
            return Err(TcpError::Closed);
        };
        let Some(pending) = self.pending.as_ref() else {
            return Ok(self.step(None, None));
        };
        if let Some(owner) = pending.owner.clone() {
            match host.poll_run_deadline(&owner) {
                Ok(Ok(None)) => {}
                Ok(Ok(Some(ended))) => return self.abandon(owner, Some(ended)),
                // No longer live (a stale reference): its frame must not continue either.
                Ok(Err(_)) => return self.abandon(owner, None),
                Err(error) => return Err(self.end(TcpError::Host(error))),
            }
        }
        let Some(pending) = self.pending.as_mut() else {
            return Ok(self.step(None, None));
        };
        let rest = &pending.outbound.bytes()[pending.offset..];
        let remaining = rest.len();
        match self.io.write_some(rest) {
            Ok(0) => Err(self.end(TcpError::Io(ErrorKind::WriteZero))),
            Ok(written) if written > remaining => {
                Err(self.end(TcpError::Io(ErrorKind::InvalidData)))
            }
            Ok(written) if written < remaining => {
                pending.offset += written;
                Ok(self.step(None, None))
            }
            Ok(_) => match self.pending.take() {
                Some(PendingWrite {
                    outbound: Outbound::FinalAck(ack),
                    owner,
                    ..
                }) => self.confirm(ack, owner),
                _ => Ok(self.step(Some(TcpEvent::Written), None)),
            },
            Err(error) if retry_later(&error) => Ok(self.step(None, None)),
            Err(error) => Err(self.end(TcpError::Io(error.kind()))),
        }
    }

    /// The transport frame-deadline poll, also while a write is retained; expiry ends the
    /// connection and discards the retained frame.
    pub(crate) fn poll_frame_deadlines(&mut self) -> Result<TcpStep, TcpError> {
        let Some(host) = self.host.as_mut() else {
            return Err(TcpError::Closed);
        };
        match host.poll_frame_deadlines() {
            Ok(()) => Ok(self.step(None, None)),
            Err(error) => Err(self.end(TcpError::Host(error))),
        }
    }

    /// Exactly one bounded `HostConnection::poll_ceremony_deadlines`, also while a write is
    /// retained. If the run that ended owns the retained frame, that frame is never continued:
    /// unsent, it is discarded; partially written, the connection is closed with nothing
    /// appended. The run's timeout CANCEL takes the slot only if it is then free.
    pub(crate) fn poll_ceremony_deadlines(&mut self) -> Result<TcpStep, TcpError> {
        let Some(host) = self.host.as_mut() else {
            return Err(TcpError::Closed);
        };
        let CeremonyPoll {
            event, outbound, ..
        } = match host.poll_ceremony_deadlines() {
            Ok(poll) => poll,
            Err(error) => return Err(self.end(TcpError::Host(error))),
        };
        let Some(CeremonyDeadlineEvent { request_id, kind }) = event else {
            return Ok(self.step(None, None));
        };
        // While a frame is retained nothing else can end or replace its live owner, so the run
        // under the owner's key on this session is that owner.
        if let Some(pending) = &self.pending
            && pending
                .owner
                .as_ref()
                .is_some_and(|owner| owner.request_id() == request_id.as_slice())
        {
            if pending.offset > 0 {
                return Err(self.end(TcpError::AbandonedPartialFrame));
            }
            self.pending = None;
        }
        let cancel = self.offer(outbound);
        let event = TcpEvent::Deadline {
            request_id: Some(request_id),
            kind,
            cancel,
        };
        Ok(self.step(Some(event), None))
    }

    /// `HostConnection::start_initiator`; START becomes the retained write.
    pub(crate) fn start_initiator(
        &mut self,
        local: Bootstrap,
        expected: Option<Bootstrap>,
    ) -> Outcome<Acted> {
        self.act(|host| host.start_initiator(local, expected))
    }

    /// `start_initiator` with a hand ceremony clock and scripted request IDs.
    #[cfg(test)]
    pub(crate) fn start_initiator_with(
        &mut self,
        clock: Clock,
        ids: &mut dyn RequestIdGenerator,
        local: Bootstrap,
        expected: Option<Bootstrap>,
    ) -> Outcome<Acted> {
        self.act(|host| host.start_initiator_with(clock, ids, local, expected))
    }

    pub(crate) fn authorize_exposure(
        &mut self,
        run: &RunRef,
        authority: &TrustedAuthority,
    ) -> Outcome<Acted> {
        self.act(|host| host.authorize_exposure(run, authority))
    }

    pub(crate) fn expose_key(&mut self, run: &RunRef) -> Outcome<Acted> {
        self.act(|host| host.expose_key(run))
    }

    /// Read-only, so also available while a write is retained.
    pub(crate) fn presentation(
        &mut self,
        run: &RunRef,
    ) -> Result<Result<Option<SasPresentation>, RouteError>, TcpError> {
        let Some(host) = self.host.as_mut() else {
            return Err(TcpError::Closed);
        };
        host.presentation(run)
            .map_err(|error| self.end(TcpError::Host(error)))
    }

    pub(crate) fn approve_sas(
        &mut self,
        run: &RunRef,
        ceremony_identity: &[u8; 32],
    ) -> Outcome<Acted> {
        self.act(|host| host.approve_sas(run, ceremony_identity))
    }

    pub(crate) fn emit_bootstrap_mac(&mut self, run: &RunRef) -> Outcome<Acted> {
        self.act(|host| host.emit_bootstrap_mac(run))
    }

    pub(crate) fn reject_sas(
        &mut self,
        run: &RunRef,
        ceremony_identity: &[u8; 32],
    ) -> Outcome<Acted> {
        self.act(|host| host.reject_sas(run, ceremony_identity))
    }

    pub(crate) fn cancel_sas(
        &mut self,
        run: &RunRef,
        ceremony_identity: &[u8; 32],
    ) -> Outcome<Acted> {
        self.act(|host| host.cancel_sas(run, ceremony_identity))
    }

    pub(crate) fn emit_initiator_finish(&mut self, run: &RunRef) -> Outcome<Acted> {
        self.act(|host| host.emit_initiator_finish(run))
    }

    /// Explicit local close: the one teardown. No CANCEL, no result, nothing retried; a second
    /// close reports `Closed`.
    pub(crate) fn close(&mut self) -> Result<(), TcpError> {
        if self.host.is_none() {
            return Err(TcpError::Closed);
        }
        self.teardown().map_err(TcpError::Host)
    }

    /// One mutating local action: refused before the host while a frame is retained; otherwise
    /// one host call, whose one output becomes the retained write.
    fn act(
        &mut self,
        op: impl FnOnce(&mut HostConnection<'r>) -> HostResult<LocalAction>,
    ) -> Outcome<Acted> {
        let Some(host) = self.host.as_mut() else {
            return Err(TcpError::Closed);
        };
        if self.pending.is_some() {
            return Ok(Err(Refused::WritePending));
        }
        match op(host) {
            Ok(Ok(LocalAction {
                run,
                event,
                outbound,
            })) => {
                self.retain(outbound, run.clone());
                Ok(Ok(Acted {
                    run,
                    event,
                    write_pending: self.pending.is_some(),
                }))
            }
            Ok(Err(error)) => Ok(Err(Refused::Run(error))),
            Err(error) => Err(self.end(TcpError::Host(error))),
        }
    }

    /// The retained frame's owner is no longer live (`ended`: by its own deadline, or `None`
    /// for a stale reference). Unsent, the frame is discarded (a `FinalAck` with its token,
    /// never confirmed) and any timeout CANCEL offered to the now-free slot; partially written,
    /// the stream holds a truncated frame, so the connection closes with nothing appended.
    fn abandon(
        &mut self,
        owner: RunRef,
        ended: Option<(CeremonyDeadline, Option<Outbound>)>,
    ) -> Result<TcpStep, TcpError> {
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| pending.offset > 0)
        {
            return Err(self.end(TcpError::AbandonedPartialFrame));
        }
        self.pending = None;
        let event = match ended {
            Some((kind, outbound)) => TcpEvent::Deadline {
                request_id: Some(owner.request_id().to_vec()),
                kind,
                cancel: self.offer(outbound),
            },
            None => TcpEvent::Discarded,
        };
        Ok(self.step(Some(event), None))
    }

    /// Confirms a final ACK whose last byte was just written; the slot is already empty.
    fn confirm(&mut self, ack: host::FinalAck, owner: Option<RunRef>) -> Result<TcpStep, TcpError> {
        let Some(host) = self.host.as_mut() else {
            return Err(TcpError::Closed);
        };
        match host.confirm_sent(ack) {
            Ok(Ok(result)) => Ok(self.step(Some(TcpEvent::Confirmed), Some(result))),
            Ok(Err(RouteError::Ceremony(CeremonyError::TimedOut(timeout)))) => {
                let request_id = owner.map(|run| run.request_id().to_vec());
                let event = self.timed_out(request_id, timeout);
                Ok(self.step(Some(event), None))
            }
            Ok(Err(error)) => Ok(self.step(Some(TcpEvent::Unconfirmed(error)), None)),
            Err(error) => Err(self.end(TcpError::Host(error))),
        }
    }

    /// A run's own timeout found outside the deadline driver, reported as the driver reports
    /// it, with exactly the CANCEL the run built.
    fn timed_out(&mut self, request_id: Option<Vec<u8>>, timeout: Timeout) -> TcpEvent {
        let (kind, outbound) = host::deadline(DeadlineEnded::TimedOut(timeout));
        TcpEvent::Deadline {
            request_id,
            kind,
            cancel: self.offer(outbound),
        }
    }

    /// A terminal run's best-effort CANCEL: into the slot only if it is free.
    fn offer(&mut self, cancel: Option<Outbound>) -> TimeoutCancel {
        match cancel {
            None => TimeoutCancel::NotBuilt,
            Some(_) if self.pending.is_some() => TimeoutCancel::Dropped,
            cancel => {
                self.retain(cancel, None);
                TimeoutCancel::Pending
            }
        }
    }

    /// Callers guarantee the slot is free: reads and actions never run while it is occupied.
    fn retain(&mut self, outbound: Option<Outbound>, owner: Option<RunRef>) {
        if let Some(outbound) = outbound {
            debug_assert!(self.pending.is_none());
            self.pending = Some(PendingWrite {
                outbound,
                offset: 0,
                owner,
            });
        }
    }

    fn step(&self, event: Option<TcpEvent>, result: Option<PairingResult>) -> TcpStep {
        TcpStep {
            event,
            result,
            write_pending: self.pending.is_some(),
        }
    }

    /// Ends the connection and reports `cause`, or the host's error if its teardown could not
    /// be established (the live count then stays held).
    fn end(&mut self, cause: TcpError) -> TcpError {
        match self.teardown() {
            Ok(()) => cause,
            Err(error) => TcpError::Host(error),
        }
    }

    /// The one teardown: no more I/O, socket shut down, suffix and retained frame (and any
    /// `FinalAck`) discarded, then the host closed unless it already ended itself.
    fn teardown(&mut self) -> Result<(), HostError> {
        let host = self.host.take();
        self.io.shut_down();
        self.suffix.clear();
        self.pending = None;
        match host {
            Some(host) if !host.is_closed() => host.close(),
            _ => Ok(()),
        }
    }
}

impl<S: SocketIo> Drop for WindowsTcpConnection<'_, S> {
    /// The same one teardown for an adapter that was never closed. Never panics; uncertain
    /// cleanup keeps the live count held.
    fn drop(&mut self) {
        if self.host.is_some() {
            let _ = self.teardown();
        }
    }
}

/// WouldBlock: no readiness after all. Interrupted: deliberately not retried inside the call
/// (no loop); the next readiness call retries.
fn retry_later(error: &io::Error) -> bool {
    matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        CeremonyExecutor, Status,
        ceremony::{PeerApproval, RemoteCeremony, SasApproval},
        deadline::{ABSOLUTE_DEADLINE, Deadline, INACTIVITY_DEADLINE, ManualClock},
        protocol::{self, CancelReason, MAX_FRAME, Message, PROFILE_ID},
        request_id::RequestIdGenerator,
        router::Router,
        transport::{
            IDLE_READ_DEADLINE, MAX_LIVE_UNAUTHENTICATED_CONNECTIONS, MAX_PENDING_ACCEPTS,
        },
    };
    use ErrorKind::{BrokenPipe, ConnectionAborted, ConnectionReset, Interrupted, WouldBlock};
    use serde_json::Value;
    use std::{
        cell::RefCell,
        collections::VecDeque,
        net::TcpListener,
        rc::Rc,
        sync::{Arc, PoisonError},
        thread,
        time::{Duration, Instant},
    };

    pub(crate) const NS: Duration = Duration::from_nanos(1);
    pub(crate) const ABSOLUTE: CeremonyDeadline = CeremonyDeadline::TimedOut(Deadline::Absolute);
    pub(crate) const INACTIVITY: CeremonyDeadline =
        CeremonyDeadline::TimedOut(Deadline::Inactivity);
    pub(crate) const UNKNOWN: RouteError = RouteError::UnknownRoute;
    /// No progress, with one frame still retained.
    pub(crate) const BUSY: TcpStep = TcpStep {
        event: None,
        result: None,
        write_pending: true,
    };

    pub(crate) fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
    pub(crate) fn vector(name: &str) -> Vec<u8> {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../vectors/p3-remote-vodozemac-draft-01.json"
        ))
        .unwrap();
        hex(fixture["wire_messages"][name]["hex"].as_str().unwrap())
    }
    pub(crate) fn initiator_bootstrap() -> Bootstrap {
        match protocol::decode(&vector("START")).unwrap().message {
            Message::Start { bootstrap, .. } => bootstrap,
            _ => unreachable!(),
        }
    }
    pub(crate) fn responder_bootstrap() -> Bootstrap {
        match protocol::decode(&vector("ACCEPT")).unwrap().message {
            Message::Accept { bootstrap, .. } => bootstrap,
            _ => unreachable!(),
        }
    }
    pub(crate) fn start_with(request_id: &[u8], bootstrap: Bootstrap) -> Vec<u8> {
        Message::Start {
            request_id: request_id.to_vec(),
            bootstrap,
        }
        .encode()
        .unwrap()
    }
    pub(crate) fn start(request_id: &[u8]) -> Vec<u8> {
        start_with(request_id, initiator_bootstrap())
    }
    pub(crate) fn initiator_key(request_id: &[u8]) -> Vec<u8> {
        Message::InitiatorKey {
            request_id: request_id.to_vec(),
            public_key: [9; 32],
        }
        .encode()
        .unwrap()
    }
    /// A wire-shaped frame with arbitrary fields and no semantic validation.
    pub(crate) fn frame(kind: u8, fields: &[&[u8]]) -> Vec<u8> {
        let mut out = b"SASPAIR\0\x01".to_vec();
        out.push(kind);
        for field in fields {
            out.extend_from_slice(&(field.len() as u32).to_be_bytes());
            out.extend_from_slice(field);
        }
        out
    }
    /// A produced frame's message; outputs must be canonical.
    pub(crate) fn message(bytes: &[u8]) -> Message {
        let decoded = protocol::decode(bytes).unwrap();
        assert_eq!(decoded.canonical_bytes(), bytes);
        decoded.message
    }
    pub(crate) fn cancel_of(bytes: &[u8]) -> (protocol::Role, CancelReason) {
        match message(bytes) {
            Message::Cancel { sender, reason, .. } => (sender, reason),
            other => panic!("not a CANCEL: {other:?}"),
        }
    }

    /// One scripted socket read.
    pub(crate) enum ReadStep {
        /// Offered bytes; what does not fit the caller's buffer stays for the next read.
        Data(Vec<u8>),
        Eof,
        Fail(ErrorKind),
    }
    /// One scripted socket write: take at most `n` offered bytes (`0` is a zero write), or fail.
    pub(crate) enum WriteStep {
        Take(usize),
        Fail(ErrorKind),
    }
    use WriteStep::{Fail, Take};

    #[derive(Default)]
    pub(crate) struct Script {
        pub(crate) refuse_nonblocking: bool,
        pub(crate) nonblocking: bool,
        /// Scripted reads in order; none left is WouldBlock.
        pub(crate) reads: VecDeque<ReadStep>,
        /// Scripted writes in order; none left takes everything offered, or is WouldBlock
        /// while `hold` is set.
        pub(crate) writes: VecDeque<WriteStep>,
        pub(crate) hold: bool,
        /// Bytes writes accepted and not yet taken by the test.
        pub(crate) wire: Vec<u8>,
        pub(crate) read_calls: usize,
        pub(crate) write_calls: usize,
        pub(crate) shutdowns: usize,
    }

    /// A deterministic socket; the test keeps a handle to the script the adapter drives.
    #[derive(Clone, Default)]
    pub(crate) struct Scripted(pub(crate) Rc<RefCell<Script>>);
    impl Scripted {
        pub(crate) fn with<T>(&self, op: impl FnOnce(&mut Script) -> T) -> T {
            op(&mut self.0.borrow_mut())
        }
        pub(crate) fn data(&self, bytes: &[u8]) {
            self.read(ReadStep::Data(bytes.to_vec()));
        }
        pub(crate) fn read(&self, step: ReadStep) {
            self.with(|s| s.reads.push_back(step));
        }
        pub(crate) fn write(&self, step: WriteStep) {
            self.with(|s| s.writes.push_back(step));
        }
        pub(crate) fn hold(&self, hold: bool) {
            self.with(|s| s.hold = hold);
        }
        pub(crate) fn wire(&self) -> Vec<u8> {
            self.with(|s| s.wire.clone())
        }
        pub(crate) fn take_wire(&self) -> Vec<u8> {
            self.with(|s| std::mem::take(&mut s.wire))
        }
        pub(crate) fn reads(&self) -> usize {
            self.with(|s| s.read_calls)
        }
        pub(crate) fn writes(&self) -> usize {
            self.with(|s| s.write_calls)
        }
        pub(crate) fn shutdowns(&self) -> usize {
            self.with(|s| s.shutdowns)
        }
    }
    impl SocketIo for Scripted {
        fn configure_nonblocking(&mut self) -> io::Result<()> {
            self.with(|s| {
                if s.refuse_nonblocking {
                    return Err(ErrorKind::InvalidInput.into());
                }
                s.nonblocking = true;
                Ok(())
            })
        }
        fn read_some(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.with(|s| {
                s.read_calls += 1;
                match s.reads.pop_front() {
                    None => Err(WouldBlock.into()),
                    Some(ReadStep::Eof) => Ok(0),
                    Some(ReadStep::Fail(kind)) => Err(kind.into()),
                    Some(ReadStep::Data(mut data)) => {
                        let n = data.len().min(buf.len());
                        buf[..n].copy_from_slice(&data[..n]);
                        if n < data.len() {
                            s.reads.push_front(ReadStep::Data(data.split_off(n)));
                        }
                        Ok(n)
                    }
                }
            })
        }
        fn write_some(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.with(|s| {
                s.write_calls += 1;
                let n = match s.writes.pop_front() {
                    None if s.hold => return Err(WouldBlock.into()),
                    None => bytes.len(),
                    Some(Take(n)) => n.min(bytes.len()),
                    Some(Fail(kind)) => return Err(kind.into()),
                };
                s.wire.extend_from_slice(&bytes[..n]);
                Ok(n)
            })
        }
        fn shut_down(&mut self) {
            self.with(|s| s.shutdowns += 1);
        }
    }

    impl RawSocket for Scripted {
        /// Distinct for every live scripted socket; only scripted readiness ever reads it.
        fn raw_socket(&self) -> SOCKET {
            Rc::as_ptr(&self.0).addr()
        }
    }

    pub(crate) type Tcp<'r> = WindowsTcpConnection<'r, Scripted>;

    /// One authority (START limiter on a hand clock never advanced) and its router.
    pub(crate) struct Node {
        pub(crate) trusted: TrustedAuthority,
        pub(crate) executor: CeremonyExecutor,
        pub(crate) router: Router,
    }
    impl Node {
        pub(crate) fn new(scope: &str) -> Self {
            let trusted =
                TrustedAuthority::register_with_limiter_clock(scope.as_bytes(), ManualClock::new())
                    .unwrap();
            let executor = trusted.executor();
            let router = Router::new(executor.clone()).unwrap();
            Self {
                trusted,
                executor,
                router,
            }
        }
        pub(crate) fn release(self) {
            drop(self.router);
            drop(self.executor);
            self.trusted.release().unwrap();
        }
        /// A scripted connection admitted through a fresh permit of this node's router.
        pub(crate) fn connect(
            &self,
            transport: &Arc<ManualClock>,
            ceremony: &Arc<ManualClock>,
        ) -> (Tcp<'_>, Scripted) {
            let io = Scripted::default();
            let permit = AcceptPermit::begin(&self.router).unwrap();
            let tcp = Tcp::from_accepted_with(
                io.clone(),
                permit,
                responder_bootstrap(),
                None,
                transport.clone(),
                ceremony.clone(),
            )
            .unwrap();
            (tcp, io)
        }
        /// `(pending accepts, live connections, incomplete frames, pending Responders)`, read
        /// even if poisoned.
        pub(crate) fn counts(&self) -> (usize, usize, usize, usize) {
            let shared = self
                .executor
                .0
                .shared
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            (
                shared.pending_accepts,
                shared.live_connections,
                shared.incomplete_frames,
                shared.pending_responders,
            )
        }
        pub(crate) fn reserved(&self) -> usize {
            let shared = self.executor.0.shared.lock().unwrap();
            shared.initiator_request_ids.len()
        }
        pub(crate) fn remaining(&self) -> u8 {
            self.executor.0.shared.lock().unwrap().remaining
        }
        pub(crate) fn status(&self) -> Status {
            self.executor.status().unwrap()
        }
        /// `(burst tokens, rolling records)` of the START limiter.
        pub(crate) fn charged(&self) -> (u8, usize) {
            let limiter = self.executor.start_limiter_snapshot();
            (limiter.tokens, limiter.rolling)
        }
        pub(crate) fn routes(&self) -> usize {
            self.router.routes_for_test()
        }
        pub(crate) fn sessions(&self) -> usize {
            self.router.sessions_for_test()
        }
    }
    pub(crate) fn clocks() -> (Arc<ManualClock>, Arc<ManualClock>, Arc<ManualClock>) {
        (ManualClock::new(), ManualClock::new(), ManualClock::new())
    }

    /// A request-ID source that yields exactly one scripted ID.
    pub(crate) struct OneId(pub(crate) Option<[u8; 16]>);
    impl RequestIdGenerator for OneId {
        fn generate(&mut self) -> Option<[u8; 16]> {
            self.0.take()
        }
    }

    pub(crate) fn acted(outcome: Outcome<Acted>) -> Acted {
        outcome.expect("connection ended").expect("action refused")
    }
    /// `(bytes, offset, is the final ACK)` of the retained frame.
    fn pending<S: SocketIo>(tcp: &WindowsTcpConnection<'_, S>) -> Option<(Vec<u8>, usize, bool)> {
        tcp.pending.as_ref().map(|p| {
            let fin = matches!(p.outbound, Outbound::FinalAck(_));
            (p.outbound.bytes().to_vec(), p.offset, fin)
        })
    }
    fn pending_bytes<S: SocketIo>(tcp: &WindowsTcpConnection<'_, S>) -> Vec<u8> {
        pending(tcp).expect("retained frame").0
    }
    /// The inbound event of a step that produced no result.
    pub(crate) fn inbound(step: TcpStep) -> (HostEvent, Option<RunRef>) {
        assert_eq!(step.result, None);
        match step.event {
            Some(TcpEvent::Inbound { event, run, .. }) => (event, run),
            other => panic!("no inbound event: {other:?}"),
        }
    }
    pub(crate) fn written() -> TcpStep {
        TcpStep {
            event: Some(TcpEvent::Written),
            ..TcpStep::default()
        }
    }
    pub(crate) fn deadline(
        request_id: Option<&[u8]>,
        kind: CeremonyDeadline,
        cancel: TimeoutCancel,
    ) -> TcpStep {
        TcpStep {
            event: Some(TcpEvent::Deadline {
                request_id: request_id.map(<[u8]>::to_vec),
                kind,
                cancel,
            }),
            result: None,
            write_pending: cancel == TimeoutCancel::Pending,
        }
    }
    /// Moves every byte `from` wrote onto `to`'s socket as one read.
    pub(crate) fn relay(from: &Scripted, to: &Scripted) {
        let bytes = from.take_wire();
        assert!(!bytes.is_empty());
        to.data(&bytes);
    }
    /// Writes `a`'s retained ordinary frame in one call, relays it, and lets `b` dispatch it.
    pub(crate) fn cross(
        a: &mut Tcp<'_>,
        aio: &Scripted,
        b: &mut Tcp<'_>,
        bio: &Scripted,
    ) -> TcpStep {
        assert_eq!(a.on_writable(), Ok(written()));
        relay(aio, bio);
        b.on_readable().unwrap()
    }
    /// Admits a new START on `tcp`, writes its ACCEPT, and returns the live Responder run.
    pub(crate) fn admit(tcp: &mut Tcp<'_>, io: &Scripted, start: &[u8]) -> RunRef {
        io.data(start);
        let (event, run) = inbound(tcp.on_readable().unwrap());
        assert_eq!(event, HostEvent::StartAccepted);
        assert_eq!(tcp.on_writable(), Ok(written()));
        io.take_wire();
        run.expect("live Responder")
    }
    /// Poisons the run under `id` on `tcp`'s session by panicking inside an operation on it.
    fn poison_run(tcp: &Tcp<'_>, router: &Router, id: &[u8]) {
        let session = tcp.host.as_ref().unwrap().session();
        thread::scope(|scope| {
            let op = scope.spawn(|| {
                router.with_run(session, id, |_| -> Result<(), CeremonyError> {
                    panic!("simulate uncertain run state")
                })
            });
            assert!(op.join().is_err());
        });
    }
    pub(crate) fn results_agree(initiator: &PairingResult, responder: &PairingResult, id: &[u8]) {
        assert_eq!(initiator.ceremony_identity(), responder.ceremony_identity());
        for (result, peer, role) in [
            (initiator, responder_bootstrap(), crate::Role::Responder),
            (responder, initiator_bootstrap(), crate::Role::Initiator),
        ] {
            assert_eq!(result.request_id(), id);
            assert_eq!(
                result.authenticated_peer_bootstrap(),
                peer.canonical_bytes()
            );
            assert_eq!(result.peer_role(), role);
        }
    }

    /// Both ends of one scripted connection: I's adapter on one node, R's on another.
    struct Sides<'r> {
        i: Tcp<'r>,
        iio: Scripted,
        r: Tcp<'r>,
        rio: Scripted,
    }
    /// One ceremony's run references on both sides.
    struct Run {
        id: Vec<u8>,
        i: RunRef,
        r: RunRef,
    }
    impl<'r> Sides<'r> {
        fn new(
            i: &'r Node,
            r: &'r Node,
            transport: &Arc<ManualClock>,
            ci: &Arc<ManualClock>,
            cr: &Arc<ManualClock>,
        ) -> Self {
            let (ia, iio) = i.connect(transport, ci);
            let (ra, rio) = r.connect(transport, cr);
            Self {
                i: ia,
                iio,
                r: ra,
                rio,
            }
        }
        fn i_to_r(&mut self) -> TcpStep {
            cross(&mut self.i, &self.iio, &mut self.r, &self.rio)
        }
        fn r_to_i(&mut self) -> TcpStep {
            cross(&mut self.r, &self.rio, &mut self.i, &self.iio)
        }
        /// A local Initiator under `id` (ceremony clock `ci`); START and ACCEPT cross.
        fn open(&mut self, ci: &Arc<ManualClock>, id: [u8; 16]) -> Run {
            let started = acted(self.i.start_initiator_with(
                ci.clone(),
                &mut OneId(Some(id)),
                initiator_bootstrap(),
                None,
            ));
            assert_eq!(
                (started.event, started.write_pending),
                (LocalEvent::InitiatorStarted, true)
            );
            let (event, r) = inbound(self.i_to_r());
            assert_eq!(event, HostEvent::StartAccepted);
            assert_eq!(inbound(self.r_to_i()).0, HostEvent::Accept);
            Run {
                id: id.to_vec(),
                i: started.run.unwrap(),
                r: r.unwrap(),
            }
        }
        /// I authorizes, then exposes; INITIATOR_KEY crosses.
        fn initiator_key(&mut self, i: &Node, run: &Run) {
            assert!(!acted(self.i.authorize_exposure(&run.i, &i.trusted)).write_pending);
            let exposed = acted(self.i.expose_key(&run.i));
            assert_eq!(
                (exposed.event, exposed.write_pending),
                (LocalEvent::KeyExposed, true)
            );
            assert_eq!(inbound(self.i_to_r()).0, HostEvent::InitiatorKey);
        }
        /// R authorizes, then exposes; RESPONDER_KEY is retained, not yet written.
        fn responder_key(&mut self, r: &Node, run: &Run) -> Vec<u8> {
            assert!(!acted(self.r.authorize_exposure(&run.r, &r.trusted)).write_pending);
            let exposed = acted(self.r.expose_key(&run.r));
            assert_eq!(
                (exposed.event, exposed.write_pending),
                (LocalEvent::KeyExposed, true)
            );
            pending_bytes(&self.r)
        }
        /// Up to both live SAS presentations; returns the run and the shared identity.
        fn sas(
            &mut self,
            i: &Node,
            r: &Node,
            ci: &Arc<ManualClock>,
            id: [u8; 16],
        ) -> (Run, [u8; 32]) {
            let run = self.open(ci, id);
            self.initiator_key(i, &run);
            self.responder_key(r, &run);
            assert_eq!(inbound(self.r_to_i()).0, HostEvent::ResponderKey);
            let shown = self.i.presentation(&run.i).unwrap().unwrap().expect("SAS");
            assert_eq!(self.r.presentation(&run.r), Ok(Ok(Some(shown.clone()))));
            (run, *shown.ceremony_identity())
        }
        /// From the SAS through both approvals and MACs, INITIATOR_FINISH, and
        /// RESPONDER_FINISH_ACK, to I's retained final ACK, whose bytes are returned.
        fn final_ack(&mut self, run: &Run, identity: &[u8; 32]) -> Vec<u8> {
            assert!(!acted(self.i.approve_sas(&run.i, identity)).write_pending);
            assert!(acted(self.i.emit_bootstrap_mac(&run.i)).write_pending);
            assert_eq!(
                inbound(self.i_to_r()).0,
                HostEvent::BootstrapMac(PeerApproval::Authenticated)
            );
            assert!(!acted(self.r.approve_sas(&run.r, identity)).write_pending);
            assert!(acted(self.r.emit_bootstrap_mac(&run.r)).write_pending);
            assert_eq!(
                inbound(self.r_to_i()).0,
                HostEvent::BootstrapMac(PeerApproval::Authenticated)
            );
            let finished = acted(self.i.emit_initiator_finish(&run.i));
            assert_eq!(
                (finished.event, finished.write_pending),
                (LocalEvent::InitiatorFinishEmitted, true)
            );
            assert_eq!(inbound(self.i_to_r()).0, HostEvent::InitiatorFinish);
            assert_eq!(inbound(self.r_to_i()).0, HostEvent::ResponderFinishAck);
            let (bytes, offset, fin) = pending(&self.i).expect("final ACK");
            assert_eq!((offset, fin), (0, true));
            assert!(matches!(
                message(&bytes),
                Message::InitiatorFinishAck { .. }
            ));
            bytes
        }
    }

    #[test]
    fn frozen_adapter_bounds() {
        assert_eq!(SOCKET_READ_CHUNK, 8192);
        const { assert!(SOCKET_READ_CHUNK < MAX_FRAME) };
    }

    #[test]
    fn an_accepted_stream_and_its_permit_become_exactly_one_live_session() {
        let r = Node::new("tcp-construct");
        let (tc, cc, _) = clocks();
        // Nonblocking setup fails: socket and permit dropped, nothing becomes live.
        let io = Scripted::default();
        io.with(|s| s.refuse_nonblocking = true);
        let permit = AcceptPermit::begin(&r.router).unwrap();
        assert_eq!(r.counts(), (1, 0, 0, 0));
        let refused = Tcp::from_accepted_with(
            io.clone(),
            permit,
            responder_bootstrap(),
            None,
            tc.clone(),
            cc.clone(),
        );
        assert_eq!(refused.err(), Some(TcpError::Io(ErrorKind::InvalidInput)));
        assert_eq!(
            (r.counts(), r.sessions(), Rc::strong_count(&io.0)),
            ((0, 0, 0, 0), 0, 1)
        );
        // Success: nonblocking first, then the permit's own activation (one live count, one
        // session), and no I/O until the caller drives it.
        let (tcp, io) = r.connect(&tc, &cc);
        assert!(io.with(|s| s.nonblocking) && !tcp.is_closed());
        assert_eq!((r.counts(), r.sessions()), ((0, 1, 0, 0), 1));
        assert_eq!((io.reads(), io.writes(), io.shutdowns()), (0, 0, 0));
        drop(tcp);
        assert_eq!(
            (r.counts(), r.sessions(), io.shutdowns()),
            ((0, 0, 0, 0), 0, 1)
        );
        r.release();
    }

    #[test]
    fn uncertain_activation_creates_no_adapter_and_keeps_its_count_held() {
        let r = Node::new("tcp-construct-uncertain");
        let (tc, cc, _) = clocks();
        let permit = AcceptPermit::begin(&r.router).unwrap();
        let executor = r.executor.clone();
        let _ = thread::spawn(move || {
            let _shared = executor.0.shared.lock().unwrap();
            panic!("simulate ambiguous transport accounting");
        })
        .join();
        let io = Scripted::default();
        let refused = Tcp::from_accepted_with(
            io.clone(),
            permit,
            responder_bootstrap(),
            None,
            tc.clone(),
            cc.clone(),
        );
        assert_eq!(
            refused.err(),
            Some(TcpError::Host(HostError::Transport(
                TransportError::OwnershipUncertain
            )))
        );
        // The existing transport semantics: no session, the socket dropped, the permit's
        // count kept because the shared state is ambiguous.
        assert_eq!(
            (r.counts(), r.sessions(), Rc::strong_count(&io.0)),
            ((1, 0, 0, 0), 0, 1)
        );
        r.release();
    }

    #[test]
    fn accept_and_live_caps_stay_authority_wide_across_adapters_and_routers() {
        let a = Node::new("tcp-caps-a");
        let b = Node::new("tcp-caps-b");
        let other = Router::new(a.executor.clone()).unwrap();
        let (tc, cc, _) = clocks();
        let router = |n: usize| {
            if n.is_multiple_of(2) {
                &a.router
            } else {
                &other
            }
        };
        // Accept work: four permits across both routers of one authority, the fifth refused
        // on either; another authority is independent.
        let permits: Vec<_> = (0..MAX_PENDING_ACCEPTS)
            .map(|n| AcceptPermit::begin(router(n)).unwrap())
            .collect();
        for refused in [&a.router, &other] {
            assert_eq!(
                AcceptPermit::begin(refused).err(),
                Some(TransportError::ResourceLimited)
            );
        }
        let (independent, _) = b.connect(&tc, &cc);
        assert_eq!((a.counts(), b.counts()), ((4, 0, 0, 0), (0, 1, 0, 0)));
        drop(permits);
        // Sixteen live adapters across both routers; the seventeenth is refused on either:
        // its socket dropped, its permit released, no session.
        let live: Vec<_> = (0..MAX_LIVE_UNAUTHENTICATED_CONNECTIONS)
            .map(|n| {
                let permit = AcceptPermit::begin(router(n)).unwrap();
                Tcp::from_accepted_with(
                    Scripted::default(),
                    permit,
                    responder_bootstrap(),
                    None,
                    tc.clone(),
                    cc.clone(),
                )
                .unwrap()
            })
            .collect();
        for refused in [&a.router, &other] {
            let io = Scripted::default();
            let permit = AcceptPermit::begin(refused).unwrap();
            let result = Tcp::from_accepted_with(
                io.clone(),
                permit,
                responder_bootstrap(),
                None,
                tc.clone(),
                cc.clone(),
            );
            assert_eq!(
                result.err(),
                Some(TcpError::Host(HostError::Transport(
                    TransportError::ResourceLimited
                )))
            );
            assert_eq!(Rc::strong_count(&io.0), 1);
            assert_eq!(a.counts(), (0, 16, 0, 0));
        }
        assert_eq!(a.sessions() + other.sessions_for_test(), 16);
        assert_eq!(b.counts(), (0, 1, 0, 0));
        drop((live, independent));
        assert_eq!((a.counts(), b.counts()), ((0, 0, 0, 0), (0, 0, 0, 0)));
        drop(other);
        a.release();
        b.release();
    }

    #[test]
    fn one_read_of_several_frames_dispatches_one_frame_per_call_without_reading_again() {
        let r = Node::new("tcp-suffix");
        let (tc, cc, _) = clocks();
        let (mut ra, io) = r.connect(&tc, &cc);
        let (a, b, c) = (start(&[1; 16]), start(&[2; 16]), start(&[3; 16]));
        // One OS read returns A || B || a prefix of C; the rest of C arrives later.
        io.data(&[a.as_slice(), &b, &c[..10]].concat());
        io.data(&c[10..]);
        io.hold(true);
        let (event, _) = inbound(ra.on_readable().unwrap());
        assert_eq!(
            (event, io.reads(), r.routes()),
            (HostEvent::StartAccepted, 1, 1)
        );
        assert_eq!(ra.suffix.unread(), [b.as_slice(), &c[..10]].concat());
        let accept_a = pending_bytes(&ra);
        // While ACCEPT A is retained: no read and no dispatch, however often driven.
        for _ in 0..3 {
            assert_eq!(ra.on_readable(), Ok(BUSY));
        }
        assert_eq!((io.reads(), r.routes()), (1, 1));
        io.hold(false);
        assert_eq!(ra.on_writable(), Ok(written()));
        // B comes from the retained suffix, not from the socket.
        let step = ra.on_readable().unwrap();
        assert!(matches!(
            step.event,
            Some(TcpEvent::Inbound { ref request_id, event: HostEvent::StartAccepted, .. })
                if *request_id == [2; 16]
        ));
        assert_eq!((io.reads(), ra.suffix.unread()), (1, &c[..10]));
        let accept_b = pending_bytes(&ra);
        assert_eq!(ra.on_writable(), Ok(written()));
        // C's prefix goes to the transport's one incomplete frame, still without a read.
        assert_eq!(ra.on_readable(), Ok(TcpStep::default()));
        assert_eq!((io.reads(), ra.suffix.is_empty()), (1, true));
        assert_eq!(r.counts(), (0, 1, 1, 2));
        // Only now is the socket read again, completing C.
        assert_eq!(
            inbound(ra.on_readable().unwrap()).0,
            HostEvent::StartAccepted
        );
        assert_eq!((io.reads(), r.counts()), (2, (0, 1, 0, 3)));
        let accept_c = pending_bytes(&ra);
        assert_eq!(ra.on_writable(), Ok(written()));
        // Each ACCEPT exactly once, in order, for its own request: nothing lost or reordered.
        assert_eq!(
            io.take_wire(),
            [accept_a.as_slice(), &accept_b, &accept_c].concat()
        );
        for (accept, id) in [
            (&accept_a, [1; 16]),
            (&accept_b, [2; 16]),
            (&accept_c, [3; 16]),
        ] {
            assert!(
                matches!(message(accept), Message::Accept { ref request_id, .. } if *request_id == id)
            );
        }
        assert_eq!(r.charged(), (1, 3));
        // A frame longer than one read chunk: the socket offers all of it, the adapter takes
        // one chunk per read, and the transport assembles it (MAX_FRAME stays its limit).
        let large = start_with(
            &[4; 16],
            Bootstrap::new(
                vec![7; 1024],
                initiator_bootstrap().key_algorithm().to_vec(),
                initiator_bootstrap().public_key().to_vec(),
                vec![8; 8192],
            )
            .unwrap(),
        );
        assert!(large.len() > SOCKET_READ_CHUNK);
        io.data(&large);
        assert_eq!(ra.on_readable(), Ok(TcpStep::default()));
        assert_eq!((io.reads(), r.counts().2), (3, 1));
        // Complete on the next read; its foreign shared context is a charged, run-local
        // semantic rejection, and the connection stays live.
        assert_eq!(
            ra.on_readable(),
            Ok(TcpStep {
                event: Some(TcpEvent::Refused(RouteError::Ceremony(
                    CeremonyError::SharedContextMismatch
                ))),
                ..TcpStep::default()
            })
        );
        assert_eq!(
            (io.reads(), r.counts(), r.charged()),
            (4, (0, 1, 0, 3), (0, 4))
        );
        assert!(!ra.is_closed());
        drop(ra);
        r.release();
    }

    #[test]
    fn would_block_and_interrupted_reads_make_no_progress_and_refresh_nothing() {
        let r = Node::new("tcp-would-block");
        let (tc, cc, _) = clocks();
        let (mut ra, io) = r.connect(&tc, &cc);
        io.read(ReadStep::Fail(Interrupted));
        assert_eq!(ra.on_readable(), Ok(TcpStep::default()));
        assert_eq!(ra.on_readable(), Ok(TcpStep::default()));
        assert_eq!((io.reads(), r.routes(), r.charged()), (2, 0, (4, 0)));
        // A retained partial frame's idle deadline keeps running across them: neither is
        // progress, and neither reaches the host.
        io.data(&start(&[1; 16])[..20]);
        assert_eq!(ra.on_readable(), Ok(TcpStep::default()));
        assert_eq!(r.counts(), (0, 1, 1, 0));
        tc.advance(IDLE_READ_DEADLINE - NS);
        io.read(ReadStep::Fail(Interrupted));
        assert_eq!(ra.on_readable(), Ok(TcpStep::default()));
        assert_eq!(ra.on_readable(), Ok(TcpStep::default()));
        assert_eq!(ra.poll_frame_deadlines(), Ok(TcpStep::default()));
        tc.advance(NS);
        assert_eq!(
            ra.poll_frame_deadlines(),
            Err(TcpError::Host(HostError::Transport(
                TransportError::IdleTimeout
            )))
        );
        assert_eq!(
            (r.counts(), r.charged(), io.shutdowns()),
            ((0, 0, 0, 0), (4, 0), 1)
        );
        let reads = io.reads();
        assert_eq!(ra.on_readable(), Err(TcpError::Closed));
        assert_eq!(io.reads(), reads);
        drop(ra);
        r.release();
    }

    #[test]
    fn eof_and_read_failures_end_every_run_of_only_their_connection() {
        let r = Node::new("tcp-eof-pre-exposure");
        let (tc, cc, ci) = clocks();
        let (mut a, aio) = r.connect(&tc, &cc);
        let (mut b, bio) = r.connect(&tc, &cc);
        let (x, y, z) = ([1; 16], [2; 16], [3; 16]);
        // On A: Responders X and Y and a local Initiator Z; on B: a Responder under X's ID.
        let xa = admit(&mut a, &aio, &start(&x));
        let ya = admit(&mut a, &aio, &start(&y));
        let za = acted(a.start_initiator_with(
            ci.clone(),
            &mut OneId(Some(z)),
            initiator_bootstrap(),
            None,
        ))
        .run
        .unwrap();
        assert_eq!(a.on_writable(), Ok(written()));
        let xb = admit(&mut b, &bio, &start(&x));
        assert_eq!((r.routes(), r.reserved(), r.counts()), (4, 1, (0, 2, 0, 3)));
        let charged = r.charged();
        // EOF on A: one teardown ends X, Y, and Z, releasing their slots and reservation,
        // with no result, no limiter refund, and no opportunity spent; B is untouched.
        aio.read(ReadStep::Eof);
        assert_eq!(a.on_readable(), Err(TcpError::PeerClosed));
        assert_eq!((r.routes(), r.reserved(), r.counts()), (1, 0, (0, 1, 0, 1)));
        assert_eq!(
            (r.charged(), r.status(), aio.shutdowns()),
            (charged, Status::Ready { remaining: 10 }, 1)
        );
        // A is final, and its runs' references reach nothing anywhere.
        assert_eq!(a.on_readable(), Err(TcpError::Closed));
        assert_eq!(a.on_writable(), Err(TcpError::Closed));
        assert_eq!(a.expose_key(&xa), Err(TcpError::Closed));
        assert_eq!(a.presentation(&xa), Err(TcpError::Closed));
        for stale in [&xa, &ya, &za] {
            assert_eq!(b.presentation(stale), Ok(Err(UNKNOWN)));
        }
        // B's own run under the equal request ID continues.
        bio.data(&initiator_key(&x));
        assert_eq!(
            inbound(b.on_readable().unwrap()),
            (HostEvent::InitiatorKey, Some(xb))
        );
        // A hard read failure ends B the same way.
        bio.read(ReadStep::Fail(ConnectionReset));
        assert_eq!(b.on_readable(), Err(TcpError::Io(ConnectionReset)));
        assert_eq!((r.routes(), r.counts(), r.sessions()), (0, (0, 0, 0, 0), 0));
        assert_eq!(r.status(), Status::Ready { remaining: 10 });
        drop((a, b));
        r.release();
    }

    #[test]
    fn eof_after_exposure_keeps_the_opportunity_and_releases_the_guard() {
        let (i, r) = (
            Node::new("tcp-eof-exposed-i"),
            Node::new("tcp-eof-exposed-r"),
        );
        let (tc, ci, cr) = clocks();
        let mut s = Sides::new(&i, &r, &tc, &ci, &cr);
        s.sas(&i, &r, &ci, [5; 16]);
        assert_eq!((i.status(), r.status()), (Status::Busy, Status::Busy));
        assert_eq!((i.remaining(), r.remaining()), (9, 9));
        s.rio.read(ReadStep::Eof);
        assert_eq!(s.r.on_readable(), Err(TcpError::PeerClosed));
        // R's run is terminal (SAS invalidated first), the guard released, the opportunity
        // kept; no CANCEL is needed or sent.
        assert_eq!(
            (r.routes(), r.status(), r.counts()),
            (0, Status::Ready { remaining: 9 }, (0, 0, 0, 0))
        );
        assert_eq!(s.rio.wire(), b"");
        s.iio.read(ReadStep::Fail(ConnectionAborted));
        assert_eq!(s.i.on_readable(), Err(TcpError::Io(ConnectionAborted)));
        assert_eq!(
            (i.routes(), i.reserved(), i.status(), i.counts()),
            (0, 0, Status::Ready { remaining: 9 }, (0, 0, 0, 0))
        );
        drop(s);
        i.release();
        r.release();
    }

    #[test]
    fn partial_writes_resume_at_the_exact_offset_and_never_repeat_bytes() {
        let r = Node::new("tcp-partial-write");
        let (tc, cc, _) = clocks();
        let (mut ra, io) = r.connect(&tc, &cc);
        io.data(&start(&[1; 16]));
        let run = inbound(ra.on_readable().unwrap()).1.unwrap();
        let accept = pending_bytes(&ra);
        for step in [
            Take(3),
            Fail(WouldBlock),
            Take(5),
            Fail(Interrupted),
            Take(1),
        ] {
            io.write(step);
        }
        for offset in [3, 3, 8, 8, 9] {
            assert_eq!(ra.on_writable(), Ok(BUSY));
            assert_eq!(pending(&ra), Some((accept.clone(), offset, false)));
            assert_eq!(io.wire(), accept[..offset]);
        }
        // The rest in one write: each byte exactly once, then the slot is empty. Ordinary
        // frames are never confirmed.
        assert_eq!(ra.on_writable(), Ok(written()));
        assert_eq!((io.take_wire(), io.writes()), (accept, 6));
        assert_eq!(ra.on_writable(), Ok(TcpStep::default()));
        assert_eq!(io.writes(), 6);
        assert_eq!(ra.presentation(&run), Ok(Ok(None)));
        assert_eq!((r.routes(), r.counts()), (1, (0, 1, 0, 1)));
        drop(ra);
        r.release();
    }

    #[test]
    fn zero_and_failed_writes_close_the_connection_without_retry() {
        let r = Node::new("tcp-write-failure");
        let (tc, cc, _) = clocks();
        for (n, failure, error) in [
            (1, Take(0), TcpError::Io(ErrorKind::WriteZero)),
            (2, Fail(BrokenPipe), TcpError::Io(BrokenPipe)),
        ] {
            let (mut ra, io) = r.connect(&tc, &cc);
            io.data(&start(&[n; 16]));
            inbound(ra.on_readable().unwrap());
            let accept = pending_bytes(&ra);
            io.write(Take(2));
            io.write(failure);
            assert_eq!(ra.on_writable(), Ok(BUSY));
            assert_eq!(ra.on_writable(), Err(error));
            // Not retried and not considered sent: only the prefix ever left.
            assert_eq!(ra.on_writable(), Err(TcpError::Closed));
            assert_eq!(
                (io.writes(), io.take_wire(), io.shutdowns()),
                (2, accept[..2].to_vec(), 1)
            );
            assert_eq!((r.routes(), r.counts(), r.sessions()), (0, (0, 0, 0, 0), 0));
        }
        r.release();
    }

    #[test]
    fn a_retained_write_backpressures_input_and_mutating_actions_but_not_presentation_or_deadlines()
    {
        let (i, r) = (
            Node::new("tcp-backpressure-i"),
            Node::new("tcp-backpressure-r"),
        );
        let (tc, ci, cr) = clocks();
        let mut s = Sides::new(&i, &r, &tc, &ci, &cr);
        let run = s.open(&ci, [6; 16]);
        s.initiator_key(&i, &run);
        let rkey = s.responder_key(&r, &run);
        s.rio.hold(true);
        assert_eq!(s.r.on_writable(), Ok(BUSY));
        assert_eq!(pending(&s.r), Some((rkey.clone(), 0, false)));
        // Input waiting in the socket (bytes that would end the connection) is neither read
        // nor dispatched.
        s.rio.data(b"not a frame");
        let reads = s.rio.reads();
        for _ in 0..3 {
            assert_eq!(s.r.on_readable(), Ok(BUSY));
        }
        assert_eq!(s.rio.reads(), reads);
        // Read-only presentation still shows the live SAS.
        let shown =
            s.r.presentation(&run.r)
                .unwrap()
                .unwrap()
                .expect("live SAS");
        let identity = *shown.ceremony_identity();
        // Every mutating action is refused before the host: nothing applied or produced, and
        // in particular no second outbound frame.
        let refusals = [
            s.r.approve_sas(&run.r, &identity),
            s.r.reject_sas(&run.r, &identity),
            s.r.cancel_sas(&run.r, &identity),
            s.r.emit_bootstrap_mac(&run.r),
            s.r.emit_initiator_finish(&run.r),
            s.r.authorize_exposure(&run.r, &r.trusted),
            s.r.expose_key(&run.r),
            s.r.start_initiator_with(
                ci.clone(),
                &mut OneId(Some([7; 16])),
                initiator_bootstrap(),
                None,
            ),
        ];
        for refusal in refusals {
            assert_eq!(refusal, Ok(Err(Refused::WritePending)));
        }
        assert_eq!((r.routes(), r.reserved()), (1, 0));
        assert_eq!(pending(&s.r), Some((rkey.clone(), 0, false)));
        assert_eq!(s.r.presentation(&run.r), Ok(Ok(Some(shown))));
        // Both deadline polls still run.
        assert_eq!(s.r.poll_frame_deadlines(), Ok(BUSY));
        assert_eq!(s.r.poll_ceremony_deadlines(), Ok(BUSY));
        // Once the frame is written, actions and input resume.
        s.rio.with(|script| script.reads.clear());
        s.rio.hold(false);
        assert_eq!(s.r.on_writable(), Ok(written()));
        assert_eq!(s.rio.wire(), rkey);
        assert_eq!(
            acted(s.r.approve_sas(&run.r, &identity)).event,
            LocalEvent::SasApproved(SasApproval::Recorded)
        );
        relay(&s.rio, &s.iio);
        assert_eq!(
            inbound(s.i.on_readable().unwrap()).0,
            HostEvent::ResponderKey
        );
        drop(s);
        i.release();
        r.release();
    }

    #[test]
    fn a_scripted_ceremony_confirms_the_final_ack_only_after_its_last_byte_is_written() {
        let (i, r) = (Node::new("tcp-final-ack-i"), Node::new("tcp-final-ack-r"));
        let (tc, ci, cr) = clocks();
        let mut s = Sides::new(&i, &r, &tc, &ci, &cr);
        let (run, identity) = s.sas(&i, &r, &ci, [8; 16]);
        let fin = s.final_ack(&run, &identity);
        for step in [
            Take(3),
            Fail(WouldBlock),
            Take(5),
            Fail(Interrupted),
            Take(1),
        ] {
            s.iio.write(step);
        }
        for offset in [3, 3, 8, 8, 9] {
            assert_eq!(s.i.on_writable(), Ok(BUSY));
            // No Initiator result yet: routed, pending, guard held, the same FinalAck retained.
            assert_eq!(pending(&s.i), Some((fin.clone(), offset, true)));
            assert_eq!(
                (i.routes(), i.status(), i.remaining()),
                (1, Status::Busy, 9)
            );
            assert_eq!(s.iio.wire(), fin[..offset]);
        }
        // The call that writes the last byte confirms it, once.
        let step = s.i.on_writable().unwrap();
        assert_eq!(
            (&step.event, step.write_pending),
            (&Some(TcpEvent::Confirmed), false)
        );
        let initiator = step.result.expect("Initiator result");
        assert_eq!(
            (i.routes(), i.reserved(), i.status()),
            (0, 0, Status::Ready { remaining: 9 })
        );
        assert!(!s.i.is_closed());
        assert_eq!(s.iio.wire(), fin);
        // R succeeds on exactly those bytes.
        relay(&s.iio, &s.rio);
        let step = s.r.on_readable().unwrap();
        assert!(matches!(
            step.event,
            Some(TcpEvent::Inbound {
                event: HostEvent::InitiatorFinishAck,
                run: None,
                ..
            })
        ));
        let responder = step.result.expect("Responder result");
        results_agree(&initiator, &responder, &run.id);
        assert_eq!(initiator.ceremony_identity(), &identity);
        // Both connections stay live; the ended runs' references reach nothing.
        assert_eq!((i.counts(), r.counts()), ((0, 1, 0, 0), (0, 1, 0, 0)));
        assert_eq!(s.i.presentation(&run.i), Ok(Err(UNKNOWN)));
        assert_eq!(
            s.r.approve_sas(&run.r, &identity),
            Ok(Err(Refused::Run(UNKNOWN)))
        );
        assert_eq!(s.i.on_writable(), Ok(TcpStep::default()));
        drop(s);
        i.release();
        r.release();
    }

    #[test]
    fn a_failed_final_ack_write_creates_no_result_and_keeps_the_opportunity() {
        let (i, r) = (Node::new("tcp-final-fail-i"), Node::new("tcp-final-fail-r"));
        let (tc, ci, cr) = clocks();
        let mut s = Sides::new(&i, &r, &tc, &ci, &cr);
        let (run, identity) = s.sas(&i, &r, &ci, [8; 16]);
        let fin = s.final_ack(&run, &identity);
        let writes = s.iio.writes();
        s.iio.write(Take(4));
        s.iio.write(Fail(ConnectionReset));
        assert_eq!(s.i.on_writable(), Ok(BUSY));
        assert_eq!(s.i.on_writable(), Err(TcpError::Io(ConnectionReset)));
        // Never confirmed, never retried: no result, the run ended with its connection, its
        // guard released after invalidation, its opportunity still spent.
        assert_eq!(
            (i.routes(), i.status(), i.counts()),
            (0, Status::Ready { remaining: 9 }, (0, 0, 0, 0))
        );
        assert_eq!(s.i.on_writable(), Err(TcpError::Closed));
        assert_eq!(s.iio.writes(), writes + 2);
        // R sees only the truncated prefix, then the end of the stream: no result there.
        let wire = s.iio.take_wire();
        assert_eq!(wire, fin[..4]);
        s.rio.data(&wire);
        s.rio.read(ReadStep::Eof);
        assert_eq!(s.r.on_readable(), Ok(TcpStep::default()));
        assert_eq!(r.counts().2, 1);
        assert_eq!(s.r.on_readable(), Err(TcpError::PeerClosed));
        assert_eq!(
            (r.routes(), r.status(), r.counts()),
            (0, Status::Ready { remaining: 9 }, (0, 0, 0, 0))
        );
        drop(s);
        i.release();
        r.release();
    }

    #[test]
    fn a_failed_contribution_write_keeps_its_opportunity_consumed() {
        let (i, r) = (Node::new("tcp-key-fail-i"), Node::new("tcp-key-fail-r"));
        let (tc, ci, cr) = clocks();
        let mut s = Sides::new(&i, &r, &tc, &ci, &cr);
        let run = s.open(&ci, [9; 16]);
        acted(s.i.authorize_exposure(&run.i, &i.trusted));
        assert_eq!(acted(s.i.expose_key(&run.i)).event, LocalEvent::KeyExposed);
        let ikey = pending_bytes(&s.i);
        assert_eq!((i.status(), i.remaining()), (Status::Busy, 9));
        let writes = s.iio.writes();
        s.iio.write(Take(10));
        s.iio.write(Fail(BrokenPipe));
        assert_eq!(s.i.on_writable(), Ok(BUSY));
        assert_eq!(s.i.on_writable(), Err(TcpError::Io(BrokenPipe)));
        // Reserved before the write, so never refunded; no retry and no resend.
        assert_eq!(
            (
                i.status(),
                i.remaining(),
                i.reserved(),
                i.routes(),
                i.counts()
            ),
            (Status::Ready { remaining: 9 }, 9, 0, 0, (0, 0, 0, 0))
        );
        assert_eq!(s.iio.writes(), writes + 2);
        // The peer got a truncated INITIATOR_KEY and then the end of the stream: that
        // connection carries no further frame, and R's unexposed run ends spending nothing.
        let wire = s.iio.take_wire();
        assert_eq!(wire, ikey[..10]);
        s.rio.data(&wire);
        s.rio.read(ReadStep::Eof);
        assert_eq!(s.r.on_readable(), Ok(TcpStep::default()));
        assert_eq!(s.r.on_readable(), Err(TcpError::PeerClosed));
        assert_eq!(
            (r.status(), r.routes(), r.counts()),
            (Status::Ready { remaining: 10 }, 0, (0, 0, 0, 0))
        );
        drop(s);
        i.release();
        r.release();
    }

    #[test]
    fn a_timed_out_runs_unsent_frame_is_discarded_and_replaced_by_its_cancel() {
        // (a) R's unsent RESPONDER_KEY after SAS establishment: replaced by R's timeout CANCEL.
        let (i, r) = (
            Node::new("tcp-owner-timeout-i"),
            Node::new("tcp-owner-timeout-r"),
        );
        let (tc, ci, cr) = clocks();
        let mut s = Sides::new(&i, &r, &tc, &ci, &cr);
        let run = s.open(&ci, [0x11; 16]);
        s.initiator_key(&i, &run);
        let rkey = s.responder_key(&r, &run);
        s.rio.hold(true);
        assert_eq!(s.r.on_writable(), Ok(BUSY));
        cr.advance(ABSOLUTE_DEADLINE);
        assert_eq!(
            s.r.poll_ceremony_deadlines(),
            Ok(deadline(Some(&run.id), ABSOLUTE, TimeoutCancel::Pending))
        );
        let (cancel, offset, fin) = pending(&s.r).unwrap();
        assert_eq!((offset, fin), (0, false));
        assert!(s.r.pending.as_ref().unwrap().owner.is_none());
        assert_eq!(
            cancel_of(&cancel),
            (protocol::Role::Responder, CancelReason::Timeout)
        );
        assert_eq!(
            (r.routes(), r.status()),
            (0, Status::Ready { remaining: 9 })
        );
        s.rio.hold(false);
        assert_eq!(s.r.on_writable(), Ok(written()));
        // Not one byte of the stale RESPONDER_KEY was ever written.
        assert_eq!(s.rio.take_wire(), cancel);
        assert_ne!(cancel, rkey);
        assert!(!s.r.is_closed());
        assert_eq!(r.counts(), (0, 1, 0, 0));
        drop(s);

        // (b) A local Initiator's unsent START before any SAS: discarded, nothing to send.
        let cl = ManualClock::new();
        let (mut lone, lio) = i.connect(&tc, &cl);
        acted(lone.start_initiator_with(
            cl.clone(),
            &mut OneId(Some([0x12; 16])),
            initiator_bootstrap(),
            None,
        ));
        lio.hold(true);
        assert_eq!(lone.on_writable(), Ok(BUSY));
        assert_eq!(i.reserved(), 1);
        cl.advance(INACTIVITY_DEADLINE);
        assert_eq!(
            lone.poll_ceremony_deadlines(),
            Ok(deadline(
                Some(&[0x12; 16]),
                INACTIVITY,
                TimeoutCancel::NotBuilt
            ))
        );
        assert_eq!(
            (pending(&lone), lio.wire(), i.reserved()),
            (None, vec![], 0)
        );
        assert!(!lone.is_closed());
        drop(lone);
        i.release();
        r.release();

        // (c) I's unsent final ACK: discarded with its token, replaced by I's CANCEL; no result.
        let (i, r) = (
            Node::new("tcp-owner-timeout-i2"),
            Node::new("tcp-owner-timeout-r2"),
        );
        let (tc, ci, cr) = clocks();
        let mut s = Sides::new(&i, &r, &tc, &ci, &cr);
        let (run, identity) = s.sas(&i, &r, &ci, [0x13; 16]);
        let fin = s.final_ack(&run, &identity);
        s.iio.hold(true);
        assert_eq!(s.i.on_writable(), Ok(BUSY));
        ci.advance(ABSOLUTE_DEADLINE);
        assert_eq!(
            s.i.poll_ceremony_deadlines(),
            Ok(deadline(Some(&run.id), ABSOLUTE, TimeoutCancel::Pending))
        );
        let (cancel, _, fin_retained) = pending(&s.i).unwrap();
        assert!(!fin_retained);
        assert_eq!(
            cancel_of(&cancel),
            (protocol::Role::Initiator, CancelReason::Timeout)
        );
        assert_eq!(
            (i.routes(), i.status()),
            (0, Status::Ready { remaining: 9 })
        );
        s.iio.hold(false);
        assert_eq!(s.iio.wire(), b"");
        assert!(matches!(inbound(s.i_to_r()).0, HostEvent::Cancel(_)));
        assert_eq!(
            (r.routes(), r.status()),
            (0, Status::Ready { remaining: 9 })
        );
        assert_ne!(cancel, fin);
        drop(s);
        i.release();
        r.release();
    }

    #[test]
    fn a_timed_out_runs_partially_written_frame_closes_the_whole_connection() {
        let (i, r) = (
            Node::new("tcp-partial-timeout-i"),
            Node::new("tcp-partial-timeout-r"),
        );
        let (tc, ci, cr) = clocks();
        let mut s = Sides::new(&i, &r, &tc, &ci, &cr);
        let run = s.open(&ci, [0x10; 16]);
        // A sibling Responder Y on the same connection, and X's request ID on another one.
        let y = admit(&mut s.r, &s.rio, &start(&[0x20; 16]));
        let cb = ManualClock::new();
        let (mut other, oio) = r.connect(&tc, &cb);
        let x_other = admit(&mut other, &oio, &start(&run.id));
        s.initiator_key(&i, &run);
        let rkey = s.responder_key(&r, &run);
        s.rio.write(Take(7));
        s.rio.hold(true);
        assert_eq!(s.r.on_writable(), Ok(BUSY));
        assert_eq!(s.r.on_writable(), Ok(BUSY));
        assert_eq!(pending(&s.r), Some((rkey.clone(), 7, false)));
        assert_eq!(
            (r.status(), r.routes(), r.counts()),
            (Status::Busy, 3, (0, 2, 0, 2))
        );
        cr.advance(ABSOLUTE_DEADLINE);
        assert_eq!(
            s.r.poll_ceremony_deadlines(),
            Err(TcpError::AbandonedPartialFrame)
        );
        // Only the 7-byte prefix ever left: the stale frame is not continued and no CANCEL
        // follows it on the stream.
        assert_eq!(
            (s.rio.take_wire(), s.rio.shutdowns()),
            (rkey[..7].to_vec(), 1)
        );
        assert_eq!(s.r.on_writable(), Err(TcpError::Closed));
        // Every run of this connection ended; X's opportunity stays spent, the guard is free,
        // and the other connection with the equal request ID is unaffected.
        assert_eq!(
            (r.routes(), r.status(), r.counts()),
            (1, Status::Ready { remaining: 9 }, (0, 1, 0, 1))
        );
        assert_eq!(other.presentation(&y), Ok(Err(UNKNOWN)));
        oio.data(&initiator_key(&run.id));
        assert_eq!(
            inbound(other.on_readable().unwrap()),
            (HostEvent::InitiatorKey, Some(x_other))
        );
        drop((s, other));
        i.release();
        r.release();
    }

    #[test]
    fn a_sibling_timeout_never_displaces_another_runs_retained_frame() {
        let (i, r) = (
            Node::new("tcp-sibling-timeout-i"),
            Node::new("tcp-sibling-timeout-r"),
        );
        let (tc, ci, cr) = clocks();
        let mut s = Sides::new(&i, &r, &tc, &ci, &cr);
        let (y, _) = s.sas(&i, &r, &ci, [0x10; 16]);
        cr.advance(ABSOLUTE_DEADLINE - Duration::from_secs(30));
        // X: a new START on the same connection; its ACCEPT is partly written, then blocked.
        s.rio.data(&start(&[0x20; 16]));
        let x = inbound(s.r.on_readable().unwrap()).1.unwrap();
        let accept = pending_bytes(&s.r);
        s.rio.write(Take(5));
        s.rio.hold(true);
        assert_eq!(s.r.on_writable(), Ok(BUSY));
        // Y reaches its absolute deadline: it ends, and its CANCEL is dropped rather than
        // queued behind X's frame.
        cr.advance(Duration::from_secs(30));
        assert_eq!(
            s.r.poll_ceremony_deadlines(),
            Ok(TcpStep {
                write_pending: true,
                ..deadline(Some(&y.id), ABSOLUTE, TimeoutCancel::Dropped)
            })
        );
        assert_eq!(pending(&s.r), Some((accept.clone(), 5, false)));
        assert_eq!(
            (r.routes(), r.status(), r.remaining()),
            (1, Status::Ready { remaining: 9 }, 9)
        );
        // X's frame continues exactly where it stopped; the connection stays live.
        s.rio.hold(false);
        assert_eq!(s.r.on_writable(), Ok(written()));
        assert_eq!(s.rio.take_wire(), accept);
        assert_eq!(s.r.presentation(&x), Ok(Ok(None)));
        assert!(!s.r.is_closed());
        drop(s);
        i.release();
        r.release();
    }

    #[test]
    fn the_writes_owner_check_stops_an_expired_frame_the_fair_cursor_has_not_reached() {
        for prefix in [0, 5] {
            let i = Node::new(&format!("tcp-owner-check-cursor-{prefix}"));
            let (tc, cc, others) = clocks();
            let (mut tcp, io) = i.connect(&tc, &cc);
            // Sixteen live Initiators after X in request-ID order, so the fair driver's second
            // call (eight routes after its first eight) cannot reach X.
            for n in 0..16 {
                acted(tcp.start_initiator_with(
                    others.clone(),
                    &mut OneId(Some([0x20 + n; 16])),
                    initiator_bootstrap(),
                    None,
                ));
                assert_eq!(tcp.on_writable(), Ok(written()));
            }
            io.take_wire();
            let (x, cx) = ([0x10; 16], ManualClock::new());
            acted(tcp.start_initiator_with(
                cx.clone(),
                &mut OneId(Some(x)),
                initiator_bootstrap(),
                None,
            ));
            let start_x = pending_bytes(&tcp);
            io.hold(true);
            if prefix > 0 {
                io.write(Take(prefix));
                assert_eq!(tcp.on_writable(), Ok(BUSY));
            }
            assert_eq!(pending(&tcp), Some((start_x.clone(), prefix, false)));
            // The first fair call reaches X (live) and seven others; X then expires, and the
            // next fair call inspects eight other routes and does not reach it.
            assert_eq!(tcp.poll_ceremony_deadlines(), Ok(BUSY));
            cx.advance(INACTIVITY_DEADLINE);
            assert_eq!(tcp.poll_ceremony_deadlines(), Ok(BUSY));
            assert_eq!((i.routes(), i.reserved()), (17, 17));
            // Writable readiness: the write's own exact check of X ends X before any byte.
            io.hold(false);
            let writes = io.writes();
            if prefix == 0 {
                assert_eq!(
                    tcp.on_writable(),
                    Ok(deadline(Some(&x), INACTIVITY, TimeoutCancel::NotBuilt))
                );
                assert_eq!((io.wire(), pending(&tcp)), (vec![], None));
                assert_eq!((i.routes(), i.reserved()), (16, 16));
                assert!(!tcp.is_closed());
            } else {
                assert_eq!(tcp.on_writable(), Err(TcpError::AbandonedPartialFrame));
                assert_eq!(io.wire(), start_x[..prefix]);
                assert_eq!((i.routes(), i.reserved(), i.counts()), (0, 0, (0, 0, 0, 0)));
            }
            assert_eq!(io.writes(), writes);
            drop(tcp);
            i.release();
        }
    }

    #[test]
    fn a_final_ack_whose_run_expired_before_writable_readiness_is_never_written_further() {
        for prefix in [0, 4] {
            let (i, r) = (
                Node::new(&format!("tcp-final-expired-i-{prefix}")),
                Node::new(&format!("tcp-final-expired-r-{prefix}")),
            );
            let (tc, ci, cr) = clocks();
            let mut s = Sides::new(&i, &r, &tc, &ci, &cr);
            let (run, identity) = s.sas(&i, &r, &ci, [0x24; 16]);
            let fin = s.final_ack(&run, &identity);
            if prefix > 0 {
                s.iio.write(Take(prefix));
                assert_eq!(s.i.on_writable(), Ok(BUSY));
            }
            // The deadline passes before the next writable readiness; no deadline poll runs.
            ci.advance(ABSOLUTE_DEADLINE);
            let writes = s.iio.writes();
            if prefix == 0 {
                // Zero FinalAck bytes, no result; the timeout CANCEL takes the slot instead.
                assert_eq!(
                    s.i.on_writable(),
                    Ok(deadline(Some(&run.id), ABSOLUTE, TimeoutCancel::Pending))
                );
                assert_eq!((s.iio.writes(), s.iio.wire()), (writes, vec![]));
                let cancel = pending_bytes(&s.i);
                assert_eq!(
                    cancel_of(&cancel),
                    (protocol::Role::Initiator, CancelReason::Timeout)
                );
                assert_eq!(
                    (i.routes(), i.status(), i.counts()),
                    (0, Status::Ready { remaining: 9 }, (0, 1, 0, 0))
                );
                assert!(matches!(inbound(s.i_to_r()).0, HostEvent::Cancel(_)));
                assert_eq!(r.status(), Status::Ready { remaining: 9 });
            } else {
                // A prefix already left: the connection closes with nothing appended.
                assert_eq!(s.i.on_writable(), Err(TcpError::AbandonedPartialFrame));
                assert_eq!(
                    (s.iio.writes(), s.iio.take_wire()),
                    (writes, fin[..prefix].to_vec())
                );
                assert_eq!(
                    (i.routes(), i.status(), i.counts()),
                    (0, Status::Ready { remaining: 9 }, (0, 0, 0, 0))
                );
            }
            drop(s);
            i.release();
            r.release();
        }
    }

    #[test]
    fn a_frame_whose_owner_is_no_longer_live_is_never_written_further() {
        let r = Node::new("tcp-stale-owner");
        let (tc, cc, ci) = clocks();
        for (n, prefix) in [(1, 0), (2, 6)] {
            let (mut tcp, io) = r.connect(&tc, &cc);
            let id = [n; 16];
            acted(tcp.start_initiator_with(
                ci.clone(),
                &mut OneId(Some(id)),
                initiator_bootstrap(),
                None,
            ));
            let start = pending_bytes(&tcp);
            io.hold(true);
            if prefix > 0 {
                io.write(Take(prefix));
                assert_eq!(tcp.on_writable(), Ok(BUSY));
            }
            // The owner ends outside this adapter (directly on the Router), so the retained
            // frame's reference is stale.
            let session = tcp.session().unwrap();
            r.router
                .with_run(session, &id, RemoteCeremony::terminate)
                .unwrap();
            assert_eq!((r.routes(), r.reserved()), (0, 0));
            io.hold(false);
            let writes = io.writes();
            if prefix == 0 {
                assert_eq!(
                    tcp.on_writable(),
                    Ok(TcpStep {
                        event: Some(TcpEvent::Discarded),
                        ..TcpStep::default()
                    })
                );
                assert_eq!((io.wire(), pending(&tcp)), (vec![], None));
                assert!(!tcp.is_closed());
                assert_eq!(tcp.on_writable(), Ok(TcpStep::default()));
            } else {
                assert_eq!(tcp.on_writable(), Err(TcpError::AbandonedPartialFrame));
                assert_eq!(io.wire(), start[..prefix]);
                assert!(tcp.is_closed());
            }
            assert_eq!(io.writes(), writes);
        }
        // An owner whose run state is uncertain: the check fails the connection closed through
        // the one teardown before any byte is written, and the live count stays held.
        let (mut tcp, io) = r.connect(&tc, &cc);
        acted(tcp.start_initiator_with(
            ci.clone(),
            &mut OneId(Some([3; 16])),
            initiator_bootstrap(),
            None,
        ));
        poison_run(&tcp, &r.router, &[3; 16]);
        assert_eq!(
            tcp.on_writable(),
            Err(TcpError::Host(HostError::Transport(
                TransportError::OwnershipUncertain
            )))
        );
        assert_eq!((io.writes(), io.wire(), io.shutdowns()), (0, vec![], 1));
        assert!(tcp.is_closed());
        assert_eq!(r.counts().1, 1);
        drop(tcp);
        r.release();
    }

    #[test]
    fn deadlines_found_by_input_actions_or_confirmation_keep_their_cancel() {
        // (a) An inbound frame finds R's absolute deadline passed.
        let (i, r) = (
            Node::new("tcp-found-input-i"),
            Node::new("tcp-found-input-r"),
        );
        let (tc, ci, cr) = clocks();
        let mut s = Sides::new(&i, &r, &tc, &ci, &cr);
        let (run, identity) = s.sas(&i, &r, &ci, [0x21; 16]);
        acted(s.i.approve_sas(&run.i, &identity));
        acted(s.i.emit_bootstrap_mac(&run.i));
        assert_eq!(s.i.on_writable(), Ok(written()));
        relay(&s.iio, &s.rio);
        cr.advance(ABSOLUTE_DEADLINE);
        assert_eq!(
            s.r.on_readable(),
            Ok(deadline(None, ABSOLUTE, TimeoutCancel::Pending))
        );
        let cancel = pending_bytes(&s.r);
        assert_eq!(
            cancel_of(&cancel),
            (protocol::Role::Responder, CancelReason::Timeout)
        );
        assert_eq!(
            (r.routes(), r.status()),
            (0, Status::Ready { remaining: 9 })
        );
        // The peer's host verifies exactly that CANCEL.
        assert!(matches!(inbound(s.r_to_i()).0, HostEvent::Cancel(_)));
        assert_eq!(
            (i.routes(), i.status()),
            (0, Status::Ready { remaining: 9 })
        );
        drop(s);
        i.release();
        r.release();

        // (b) A local action finds it.
        let (i, r) = (
            Node::new("tcp-found-action-i"),
            Node::new("tcp-found-action-r"),
        );
        let (tc, ci, cr) = clocks();
        let mut s = Sides::new(&i, &r, &tc, &ci, &cr);
        let (run, identity) = s.sas(&i, &r, &ci, [0x22; 16]);
        cr.advance(ABSOLUTE_DEADLINE);
        assert_eq!(
            acted(s.r.approve_sas(&run.r, &identity)),
            Acted {
                run: None,
                event: LocalEvent::Deadline(ABSOLUTE),
                write_pending: true,
            }
        );
        assert_eq!(
            cancel_of(&pending_bytes(&s.r)),
            (protocol::Role::Responder, CancelReason::Timeout)
        );
        drop(s);
        i.release();
        r.release();

        // (c) The final ACK's send confirmation finds I's deadline passed: the deadline passes
        // after the write's own owner check (one clock reading) and before the confirmation.
        let (i, r) = (
            Node::new("tcp-found-confirm-i"),
            Node::new("tcp-found-confirm-r"),
        );
        let (tc, ci, cr) = clocks();
        let mut s = Sides::new(&i, &r, &tc, &ci, &cr);
        let (run, identity) = s.sas(&i, &r, &ci, [0x23; 16]);
        let fin = s.final_ack(&run, &identity);
        s.iio.hold(true);
        assert_eq!(s.i.on_writable(), Ok(BUSY));
        ci.advance_after(1, ABSOLUTE_DEADLINE);
        s.iio.hold(false);
        assert_eq!(
            s.i.on_writable(),
            Ok(deadline(Some(&run.id), ABSOLUTE, TimeoutCancel::Pending))
        );
        let cancel = pending_bytes(&s.i);
        assert_eq!(
            cancel_of(&cancel),
            (protocol::Role::Initiator, CancelReason::Timeout)
        );
        assert_eq!(
            (i.routes(), i.status()),
            (0, Status::Ready { remaining: 9 })
        );
        // The final ACK's bytes did leave, but no result exists; the CANCEL follows them.
        assert_eq!(s.i.on_writable(), Ok(written()));
        assert_eq!(s.iio.take_wire(), [fin, cancel].concat());
        drop(s);
        i.release();
        r.release();
    }

    #[test]
    fn the_frame_deadline_still_ends_a_connection_whose_write_is_blocked() {
        let r = Node::new("tcp-frame-deadline");
        let (tc, cc, ci) = clocks();
        let (mut ra, io) = r.connect(&tc, &cc);
        io.data(&start(&[1; 16])[..30]);
        assert_eq!(ra.on_readable(), Ok(TcpStep::default()));
        acted(ra.start_initiator_with(
            ci.clone(),
            &mut OneId(Some([2; 16])),
            initiator_bootstrap(),
            None,
        ));
        io.hold(true);
        tc.advance(IDLE_READ_DEADLINE - NS);
        // A blocked write is not input progress.
        assert_eq!(ra.on_writable(), Ok(BUSY));
        assert_eq!(ra.poll_frame_deadlines(), Ok(BUSY));
        tc.advance(NS);
        assert_eq!(
            ra.poll_frame_deadlines(),
            Err(TcpError::Host(HostError::Transport(
                TransportError::IdleTimeout
            )))
        );
        assert_eq!((io.wire(), io.shutdowns()), (vec![], 1));
        assert_eq!(
            (r.routes(), r.reserved(), r.counts(), r.charged()),
            (0, 0, (0, 0, 0, 0), (4, 0))
        );
        drop(ra);
        r.release();
    }

    #[test]
    fn malformed_frames_and_unknown_routes_close_only_their_connection() {
        let r = Node::new("tcp-malformed");
        let (tc, cc, _) = clocks();
        let (mut keep, kio) = r.connect(&tc, &cc);
        let kept = admit(&mut keep, &kio, &start(&[0x77; 16]));
        let charged = r.charged();
        let mut bad_magic = start(&[1; 16]);
        bad_magic[0] ^= 0xFF;
        let oversized = [
            b"SASPAIR\0\x01\x01".as_slice(),
            &u32::try_from(MAX_FRAME).unwrap().to_be_bytes(),
        ]
        .concat();
        let unroutable = frame(3, &[b"another-profile", &[1; 16], &[9; 32]]);
        let unroutable_error = HostError::Unroutable(protocol::routable(&unroutable).unwrap_err());
        for (bytes, error) in [
            (
                bad_magic,
                HostError::Transport(TransportError::InvalidFrame),
            ),
            (
                frame(0x20, &[PROFILE_ID, &[1; 16]]),
                HostError::Transport(TransportError::InvalidFrame),
            ),
            (
                oversized,
                HostError::Transport(TransportError::FrameTooLarge),
            ),
            (unroutable, unroutable_error),
        ] {
            let (mut tcp, io) = r.connect(&tc, &cc);
            io.data(&bytes);
            assert_eq!(tcp.on_readable(), Err(TcpError::Host(error)));
            assert!(tcp.is_closed());
            assert_eq!(io.shutdowns(), 1);
            // No limiter charge and no state; only `keep` remains.
            assert_eq!(
                (r.counts(), r.charged(), r.sessions()),
                ((0, 1, 0, 1), charged, 1)
            );
        }
        // A canonical non-START frame naming no run here: the whole session ends, with its
        // own run; the equal request ID on `keep` is unaffected.
        let (mut fatal, fio) = r.connect(&tc, &cc);
        let own = admit(&mut fatal, &fio, &start(&[0x66; 16]));
        fio.data(&initiator_key(&[0x77; 16]));
        assert_eq!(
            fatal.on_readable(),
            Err(TcpError::Host(HostError::Routing(
                RouteError::SessionProtocolFailure
            )))
        );
        assert_eq!(
            (fio.shutdowns(), r.routes(), r.counts()),
            (1, 1, (0, 1, 0, 1))
        );
        assert_eq!(fatal.close(), Err(TcpError::Closed));
        assert_eq!(keep.presentation(&own), Ok(Err(UNKNOWN)));
        kio.data(&initiator_key(&[0x77; 16]));
        assert_eq!(
            inbound(keep.on_readable().unwrap()),
            (HostEvent::InitiatorKey, Some(kept))
        );
        drop((keep, fatal));
        r.release();
    }

    #[test]
    fn explicit_close_and_drop_tear_down_exactly_once() {
        let r = Node::new("tcp-close");
        let (tc, cc, ci) = clocks();
        let (mut a, aio) = r.connect(&tc, &cc);
        let run = acted(a.start_initiator_with(
            ci.clone(),
            &mut OneId(Some([1; 16])),
            initiator_bootstrap(),
            None,
        ))
        .run
        .unwrap();
        assert_eq!((r.reserved(), r.counts()), (1, (0, 1, 0, 0)));
        assert_eq!(a.close(), Ok(()));
        // Nothing written, no CANCEL, nothing retried; the retained START went with its run.
        assert_eq!((aio.wire(), aio.writes(), aio.shutdowns()), (vec![], 0, 1));
        assert_eq!(
            (r.routes(), r.reserved(), r.counts(), r.sessions()),
            (0, 0, (0, 0, 0, 0), 0)
        );
        // Closed is final.
        assert_eq!(a.close(), Err(TcpError::Closed));
        assert_eq!(a.on_readable(), Err(TcpError::Closed));
        assert_eq!(a.on_writable(), Err(TcpError::Closed));
        assert_eq!(a.poll_frame_deadlines(), Err(TcpError::Closed));
        assert_eq!(a.poll_ceremony_deadlines(), Err(TcpError::Closed));
        assert_eq!(a.presentation(&run), Err(TcpError::Closed));
        assert_eq!(a.emit_initiator_finish(&run), Err(TcpError::Closed));
        assert_eq!((aio.reads(), aio.shutdowns()), (0, 1));
        drop(a);
        assert_eq!((r.counts(), aio.shutdowns()), ((0, 0, 0, 0), 1));
        // Drop without close: the same teardown, once.
        let (b, bio) = r.connect(&tc, &cc);
        assert_eq!(r.counts(), (0, 1, 0, 0));
        drop(b);
        assert_eq!(
            (r.counts(), r.sessions(), bio.shutdowns()),
            ((0, 0, 0, 0), 0, 1)
        );
        // Uncertain Router cleanup on EOF: the adapter is closed, but the live count stays
        // held for good, also after drop.
        let (mut c, cio) = r.connect(&tc, &cc);
        admit(&mut c, &cio, &start(&[3; 16]));
        poison_run(&c, &r.router, &[3; 16]);
        cio.read(ReadStep::Eof);
        assert_eq!(
            c.on_readable(),
            Err(TcpError::Host(HostError::Transport(
                TransportError::OwnershipUncertain
            )))
        );
        assert!(c.is_closed());
        assert_eq!((r.counts().1, cio.shutdowns()), (1, 1));
        assert_eq!(c.close(), Err(TcpError::Closed));
        drop(c);
        assert_eq!(r.counts().1, 1);
        r.release();
    }

    /// Retries one nonblocking adapter call until it yields, for real sockets only. No sleep:
    /// it yields the thread between attempts and gives up after 10 s instead of hanging.
    pub(crate) fn until<T>(mut attempt: impl FnMut() -> Option<T>) -> T {
        let give_up = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(value) = attempt() {
                return value;
            }
            assert!(Instant::now() < give_up, "no socket readiness in 10 s");
            thread::yield_now();
        }
    }
    pub(crate) fn sent(tcp: &mut WindowsTcpConnection<'_>) -> TcpStep {
        until(|| {
            let step = tcp.on_writable().unwrap();
            assert_eq!(step.result, None);
            step.event.is_some().then_some(step)
        })
    }
    pub(crate) fn received(tcp: &mut WindowsTcpConnection<'_>) -> TcpStep {
        until(|| {
            let step = tcp.on_readable().unwrap();
            step.event.is_some().then_some(step)
        })
    }
    /// A connected loopback pair on an OS-assigned port: test plumbing only, never policy.
    fn loopback() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    #[test]
    fn real_loopback_start_gets_its_exact_accept_and_an_unknown_route_closes_the_socket() {
        let r = Node::new("tcp-real-start");
        let (mut peer, server) = loopback();
        peer.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let permit = AcceptPermit::begin(&r.router).unwrap();
        let mut ra =
            WindowsTcpConnection::from_accepted(server, permit, responder_bootstrap(), None)
                .unwrap();
        assert_eq!((r.counts(), r.sessions()), ((0, 1, 0, 0), 1));
        // Nonblocking: with nothing sent yet the read returns at once, with no progress.
        assert_eq!(ra.on_readable(), Ok(TcpStep::default()));
        let id = [0x42; 16];
        peer.write_all(&start(&id)).unwrap();
        let (event, run) = inbound(received(&mut ra));
        assert_eq!(event, HostEvent::StartAccepted);
        let accept = pending_bytes(&ra);
        assert_eq!(sent(&mut ra), written());
        // The peer receives exactly the host's canonical ACCEPT bytes.
        let mut got = vec![0; accept.len()];
        peer.read_exact(&mut got).unwrap();
        assert_eq!(got, accept);
        assert!(matches!(message(&got), Message::Accept { request_id, .. } if request_id == id));
        assert_eq!(ra.presentation(&run.unwrap()), Ok(Ok(None)));
        // A canonical frame for an unknown route ends the session and shuts the real socket.
        peer.write_all(&initiator_key(&[0x77; 16])).unwrap();
        let error = until(|| ra.on_readable().err());
        assert_eq!(
            error,
            TcpError::Host(HostError::Routing(RouteError::SessionProtocolFailure))
        );
        assert_eq!(peer.read(&mut [0; 1]).unwrap(), 0);
        assert_eq!((r.routes(), r.counts(), r.sessions()), (0, (0, 0, 0, 0), 0));
        drop(ra);
        r.release();
    }

    #[test]
    fn real_loopback_ceremony_confirms_the_final_ack_only_after_its_socket_write() {
        let (i, r) = (
            Node::new("tcp-real-ceremony-i"),
            Node::new("tcp-real-ceremony-r"),
        );
        let (tc, ci, cr) = clocks();
        let (client, server) = loopback();
        fn adapter<'r>(
            node: &'r Node,
            stream: TcpStream,
            transport: &Arc<ManualClock>,
            ceremony: &Arc<ManualClock>,
        ) -> WindowsTcpConnection<'r> {
            let permit = AcceptPermit::begin(&node.router).unwrap();
            WindowsTcpConnection::from_accepted_with(
                stream,
                permit,
                responder_bootstrap(),
                None,
                transport.clone(),
                ceremony.clone(),
            )
            .unwrap()
        }
        let mut ia = adapter(&i, client, &tc, &ci);
        let mut ra = adapter(&r, server, &tc, &cr);
        let started = acted(ia.start_initiator_with(
            ci.clone(),
            &mut OneId(Some([0x31; 16])),
            initiator_bootstrap(),
            None,
        ));
        let iref = started.run.unwrap();
        assert_eq!(sent(&mut ia), written());
        let (event, rref) = inbound(received(&mut ra));
        assert_eq!(event, HostEvent::StartAccepted);
        let rref = rref.unwrap();
        assert_eq!(sent(&mut ra), written());
        assert_eq!(inbound(received(&mut ia)).0, HostEvent::Accept);
        acted(ia.authorize_exposure(&iref, &i.trusted));
        acted(ia.expose_key(&iref));
        assert_eq!(sent(&mut ia), written());
        assert_eq!(inbound(received(&mut ra)).0, HostEvent::InitiatorKey);
        acted(ra.authorize_exposure(&rref, &r.trusted));
        acted(ra.expose_key(&rref));
        assert_eq!(sent(&mut ra), written());
        assert_eq!(inbound(received(&mut ia)).0, HostEvent::ResponderKey);
        let shown = ia.presentation(&iref).unwrap().unwrap().unwrap();
        assert_eq!(ra.presentation(&rref), Ok(Ok(Some(shown.clone()))));
        let identity = *shown.ceremony_identity();
        acted(ia.approve_sas(&iref, &identity));
        acted(ia.emit_bootstrap_mac(&iref));
        assert_eq!(sent(&mut ia), written());
        assert_eq!(
            inbound(received(&mut ra)).0,
            HostEvent::BootstrapMac(PeerApproval::Authenticated)
        );
        acted(ra.approve_sas(&rref, &identity));
        acted(ra.emit_bootstrap_mac(&rref));
        assert_eq!(sent(&mut ra), written());
        assert_eq!(
            inbound(received(&mut ia)).0,
            HostEvent::BootstrapMac(PeerApproval::Authenticated)
        );
        acted(ia.emit_initiator_finish(&iref));
        assert_eq!(sent(&mut ia), written());
        assert_eq!(inbound(received(&mut ra)).0, HostEvent::InitiatorFinish);
        assert_eq!(sent(&mut ra), written());
        assert_eq!(inbound(received(&mut ia)).0, HostEvent::ResponderFinishAck);
        assert!(pending(&ia).unwrap().2);
        assert_eq!((i.routes(), i.status()), (1, Status::Busy));
        // The result appears only on the call whose real socket write completes the frame.
        let step = until(|| {
            let step = ia.on_writable().unwrap();
            if step.event.is_none() {
                assert_eq!((step.result.as_ref(), i.routes()), (None, 1));
                return None;
            }
            Some(step)
        });
        assert_eq!(step.event, Some(TcpEvent::Confirmed));
        let initiator = step.result.unwrap();
        assert_eq!(
            (i.routes(), i.status()),
            (0, Status::Ready { remaining: 9 })
        );
        let step = received(&mut ra);
        assert!(matches!(
            step.event,
            Some(TcpEvent::Inbound {
                event: HostEvent::InitiatorFinishAck,
                ..
            })
        ));
        let responder = step.result.unwrap();
        results_agree(&initiator, &responder, &[0x31; 16]);
        assert_eq!(initiator.ceremony_identity(), &identity);
        assert_eq!(r.status(), Status::Ready { remaining: 9 });
        // Real EOF: dropping I's adapter closes its socket; R's next read ends R's connection.
        drop(ia);
        assert_eq!(until(|| ra.on_readable().err()), TcpError::PeerClosed);
        assert_eq!((i.counts(), r.counts()), ((0, 0, 0, 0), (0, 0, 0, 0)));
        drop(ra);
        i.release();
        r.release();
    }

    /// P5.2 review-only transport sequence evidence (not part of the product); see
    /// `docs/p5-security-review/adversarial-sequences.md`.
    mod p5_transport_review;

    /// P5.3 review-only entropy-panic unwind evidence (not part of the product); see
    /// `docs/p5-security-review/dependency-unsafe-deep-review.md`.
    mod p5_entropy_panic_review;
}
