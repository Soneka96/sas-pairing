//! Crate-private, experimental, synchronous Windows owner loop: the one cooperative driver of an
//! ALREADY-BOUND `std::net::TcpListener` and of the `WindowsTcpConnection`s it accepts for ONE
//! `Router` (one authority hosting context). Trusted outer code binds the listener and owns every
//! exposure decision (address, interface, loopback or LAN, port, discovery, firewall); this module
//! never binds, connects, inspects a local or peer address, or selects a destination. TCP stays an
//! experimental P4 carrier only, and no socket handle, address, or port enters any protocol,
//! authorization, routing, limiter, or accounting decision.
//!
//! One `drive_once` is bounded synchronous work, with no thread, timer, sleep, or queue:
//! 1. a deadline sweep: per live connection at most one transport connection-deadline poll
//!    (frame deadlines, or the P6-D-001 connection lifetime) and one bounded ceremony-deadline
//!    poll (itself at most `MAX_CEREMONY_POLLS_PER_CALL` routes);
//! 2. at most one `WSAPoll` over at most `MAX_POLL_SOCKETS` (1 listener + 16 connections) sockets,
//!    waiting at most `OWNER_LOOP_MAX_WAIT` (not at all if step 1 produced an event). That wait is
//!    scheduling plumbing only: not a protocol deadline, and a wake (or a zero return) is not
//!    progress, activity, keepalive, or timeout of anything;
//! 3. the same deadline sweep again, so no socket I/O follows a wait (or a long pause between
//!    calls) before deadlines were re-evaluated;
//! 4. per existing connection at most ONE socket operation: error or invalid-handle readiness
//!    closes it without any read or write; otherwise one `on_writable` while a frame is retained
//!    and the socket is writable, else one `on_readable` if the socket is readable or hung up or
//!    the adapter still retains unconsumed input of an earlier read (which also makes the wait
//!    zero). Hang-up (P6-D-003) is a peer's graceful FIN, which ends only its sending direction:
//!    it closes nothing by itself, its earlier bytes are still read and a retained frame is
//!    still written, and the connection ends at the read that returns EOF. Draining is one
//!    operation per drive, never a loop; the transport's frame and P6-D-001 connection
//!    deadlines and the ceremony deadlines bound a half-closed peer that never reaches EOF;
//! 5. at most ONE OS accept, after every existing connection was served, so a continuously
//!    readable listener never starves established connections.
//!
//! A connection whose sweep produced an event does no socket I/O in that drive: deadline
//! resolution comes before further network progress, and each connection reports at most one
//! event per drive (so a step holds at most 17). Admission is unchanged: right after the OS
//! accept, before anything else touches the socket, `AcceptPermit::begin` (refused: the socket is
//! dropped and nothing exists), then `WindowsTcpConnection::from_accepted`, whose activation
//! enforces the authority-wide live cap of 16. This loop holds at most one permit at a time, a
//! stronger implementation bound than the authority's 4, which is unchanged. The OS backlog is
//! the listener's and stays unclaimed and unbounded here.
//!
//! Failure scope. Connection-local endings (EOF, socket error, error or invalid-handle readiness,
//! transport or routing failure, an abandoned partial frame) remove only that connection. A
//! listener accept error, or error, hang-up, or invalid-handle readiness on the listener, drops
//! only the listener; live connections continue and nothing rebinds. An interrupted `WSAPoll`
//! makes no progress. A failed `WSAPoll` (readiness, and so deadline driving, can no longer be
//! trusted) or any `OwnershipUncertain` (shared authority state or cleanup uncertain) fails the
//! whole hosting context closed: listener dropped, every connection's close attempted, nothing
//! admitted again, uncertain capacity held as the existing teardown leaves it.
//!
//! The loop is a hosting layer, not the authority: closing, dropping, or replacing it (a frontend
//! or listener restart) releases no ownership lease and resets no opportunity budget, guard, START
//! limiter, or pending control; a new loop over the same Router gets fresh sessions only. Trusted
//! local actions name a connection by an opaque `ConnectionRef` and a run by its `RunRef`; the
//! adapter and host checks stay authoritative. `recheck_after_resume` is the explicit hook outer
//! code may call after an OS resume notification (not subscribed to here): a deadline sweep and
//! nothing else, against the existing monotonic clocks.
#![allow(dead_code)] // Used only by tests until a consumer API exists.
use crate::{
    Error as AuthorityError, TrustedAuthority,
    ceremony::{CeremonyError, SasPresentation},
    host::HostError,
    protocol::Bootstrap,
    router::{RouteError, Router, RunRef, SessionHandle},
    transport::{AcceptPermit, MAX_LIVE_UNAUTHENTICATED_CONNECTIONS, TransportError},
    windows_tcp::{Acted, RawSocket, Refused, SocketIo, TcpError, TcpStep, WindowsTcpConnection},
};
#[cfg(test)]
use crate::{deadline::Clock, request_id::RequestIdGenerator};
use std::{
    io::{self, ErrorKind},
    net::{TcpListener, TcpStream},
    os::windows::io::AsRawSocket,
    time::Duration,
};
use windows_sys::Win32::Networking::WinSock::{
    POLLERR, POLLHUP, POLLIN, POLLNVAL, POLLOUT, SOCKET, SOCKET_ERROR, WSAEINTR, WSAGetLastError,
    WSAPOLLFD, WSAPoll,
};

/// Longest one readiness wait may last, so a quiet loop still drives deadlines. Scheduling
/// plumbing only: not a protocol deadline or security constant, and added to no deadline.
pub(crate) const OWNER_LOOP_MAX_WAIT: Duration = Duration::from_millis(250);
const WAIT_MS: i32 = 250;
const _: () = assert!(OWNER_LOOP_MAX_WAIT.as_millis() == WAIT_MS as u128);
/// The listener plus the authority-wide live-connection cap: the most sockets one wait covers.
pub(crate) const MAX_POLL_SOCKETS: usize = 1 + MAX_LIVE_UNAUTHENTICATED_CONNECTIONS;
/// At most one listener event plus one event per live connection.
pub(crate) const MAX_STEP_EVENTS: usize = MAX_POLL_SOCKETS;
/// Readiness that ends a connection's use before any read or write, whatever else is reported
/// with it (P6-D-003). Hang-up is not among them: see `READABLE`.
const CONNECTION_FAILED: i16 = POLLERR | POLLNVAL;
/// Readiness that makes one read worthwhile for a connection with no retained frame: data, or a
/// peer's graceful hang-up (P6-D-003), which ends only the peer's sending direction. The read
/// then returns the bytes the peer sent before it, or EOF, the one graceful-close boundary.
const READABLE: i16 = POLLIN | POLLHUP;
/// Readiness that ends the listener's use, whatever else is reported with it.
const LISTENER_FAILED: i16 = POLLERR | POLLHUP | POLLNVAL;

/// The already-bound listener the loop accepts from. Production is `std::net::TcpListener`;
/// tests script accepts and failures.
pub(crate) trait Listen {
    type Stream: SocketIo + RawSocket;
    fn configure_nonblocking(&mut self) -> io::Result<()>;
    /// One nonblocking OS accept. The peer address is never returned.
    fn accept_one(&mut self) -> io::Result<Self::Stream>;
    fn raw_socket(&self) -> SOCKET;
    /// The adapter's admission of an accepted stream with its permit.
    fn admit<'r>(
        &self,
        stream: Self::Stream,
        permit: AcceptPermit<'r>,
        local: Bootstrap,
        expected: Option<Bootstrap>,
    ) -> Result<WindowsTcpConnection<'r, Self::Stream>, TcpError>;
}

impl Listen for TcpListener {
    type Stream = TcpStream;
    fn configure_nonblocking(&mut self) -> io::Result<()> {
        self.set_nonblocking(true)
    }
    fn accept_one(&mut self) -> io::Result<TcpStream> {
        // The peer address is dropped unread: it reaches no decision and is never retained.
        self.accept().map(|(stream, _)| stream)
    }
    fn raw_socket(&self) -> SOCKET {
        // A Windows SOCKET value, which always fits the platform's pointer-sized SOCKET.
        self.as_raw_socket() as SOCKET
    }
    fn admit<'r>(
        &self,
        stream: TcpStream,
        permit: AcceptPermit<'r>,
        local: Bootstrap,
        expected: Option<Bootstrap>,
    ) -> Result<WindowsTcpConnection<'r>, TcpError> {
        WindowsTcpConnection::from_accepted(stream, permit, local, expected)
    }
}

/// Opaque, volatile, local name of one live connection of this loop: its Router session, which
/// is never reissued, so a reference kept after its connection closed never names a later one,
/// whatever storage it occupies. Not peer identity, an address, a socket, authentication, trust,
/// authorization, or ceremony identity; never sent, persisted, or peer-controlled. It selects one
/// adapter only: a `RunRef` still selects the run, and `ceremony_identity` still authorizes SAS
/// decisions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ConnectionRef(SessionHandle);

/// Why the hosting context refused a call or failed. Connection-local endings are events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OwnerLoopError {
    /// The loop was closed or failed closed earlier; nothing was done.
    Closed,
    /// No live connection of this loop has that reference; nothing was done.
    UnknownConnection,
    /// The listener could not be made nonblocking (diagnostic kind); nothing was created.
    ListenerIo(ErrorKind),
    /// `WSAPoll` failed (WinSock code, diagnostic only): the loop failed closed.
    Poll(i32),
    /// Shared authority state or a connection's cleanup is uncertain: the loop failed closed.
    OwnershipUncertain,
    /// The addressed connection ended during the call and was removed; nothing else changed.
    Connection(TcpError),
}

/// Why the listener was dropped. Live connections continue; nothing rebinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ListenerFailure {
    /// An accept error other than WouldBlock/Interrupted (diagnostic kind).
    Io(ErrorKind),
    /// Error, hang-up, or invalid-handle readiness (the reported flags, diagnostic only).
    Readiness(i16),
}

/// Why a connection ended. Never authentication, SAS-mismatch, or compromise evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ConnectionEnd {
    /// The adapter ended it (EOF, socket or host failure, abandoned partial frame).
    Adapter(TcpError),
    /// Error or invalid-handle readiness (the reported flags, diagnostic only): closed before any
    /// read or write. A peer's graceful hang-up ends through the adapter's EOF instead.
    Readiness(i16),
}

/// One semantic outcome of a drive. Outbound bytes are never copied here: adapters own them.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum OwnerEvent {
    /// One accepted socket became a live connection; its I/O starts on a later drive.
    Accepted(ConnectionRef),
    /// One accepted socket was dropped without becoming live: a generic local admission refusal
    /// (accept-work or live cap, or adapter setup), never a claim about the peer.
    AcceptRefused(TcpError),
    ListenerDisabled(ListenerFailure),
    /// One connection's adapter step with an event or a result.
    Step(ConnectionRef, TcpStep),
    /// One connection ended and was removed; its siblings and the listener are unaffected.
    Closed(ConnectionRef, ConnectionEnd),
}

/// One bounded drive. Nothing is retained after it returns.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct OwnerStep {
    /// At most `MAX_STEP_EVENTS`.
    pub(crate) events: Vec<OwnerEvent>,
    /// Set when the loop failed closed during this call (listener dropped, every connection's
    /// close attempted); events produced earlier in the call are kept.
    pub(crate) failure: Option<OwnerLoopError>,
}

impl OwnerStep {
    fn new() -> Self {
        Self {
            events: Vec::with_capacity(MAX_STEP_EVENTS),
            failure: None,
        }
    }
    fn push(&mut self, event: OwnerEvent) {
        debug_assert!(self.events.len() < MAX_STEP_EVENTS);
        self.events.push(event);
    }
}

/// One live connection of this loop.
struct Live<'r, S: SocketIo> {
    connection: ConnectionRef,
    tcp: WindowsTcpConnection<'r, S>,
    /// This drive already reported this connection's one event, or admitted it: no further
    /// deadline or socket work for it until the next drive.
    served: bool,
}

type Outcome<T> = Result<Result<T, Refused>, OwnerLoopError>;

/// The owner loop over one already-bound listener for one Router. See the module docs.
pub(crate) struct WindowsOwnerLoop<'r, L: Listen = TcpListener> {
    /// `None` once disabled or closed: never replaced.
    listener: Option<L>,
    router: &'r Router,
    /// Local Responder configuration for new STARTs on accepted connections.
    local: Bootstrap,
    expected: Option<Bootstrap>,
    /// At most the authority-wide live cap (16), allocated once.
    connections: Vec<Live<'r, L::Stream>>,
    /// Closed or failed closed: every call refuses.
    closed: bool,
}

impl<'r, L: Listen> WindowsOwnerLoop<'r, L> {
    /// Takes an already-bound listener from trusted outer code and makes it nonblocking; if that
    /// fails the listener is dropped and nothing is created. No address, interface, or port is
    /// inspected or chosen. Starts with no connection.
    pub(crate) fn from_bound_listener(
        mut listener: L,
        router: &'r Router,
        local: Bootstrap,
        expected: Option<Bootstrap>,
    ) -> Result<Self, OwnerLoopError> {
        if let Err(error) = listener.configure_nonblocking() {
            return Err(OwnerLoopError::ListenerIo(error.kind()));
        }
        Ok(Self {
            listener: Some(listener),
            router,
            local,
            expected,
            connections: Vec::with_capacity(MAX_LIVE_UNAUTHENTICATED_CONNECTIONS),
            closed: false,
        })
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed
    }

    pub(crate) fn is_listening(&self) -> bool {
        self.listener.is_some()
    }

    pub(crate) fn live_connections(&self) -> usize {
        self.connections.len()
    }

    /// One bounded drive: sweep, one readiness wait of at most `OWNER_LOOP_MAX_WAIT`, sweep
    /// again, one socket operation per ready connection, at most one accept.
    pub(crate) fn drive_once(&mut self) -> Result<OwnerStep, OwnerLoopError> {
        self.drive_with(wsa_poll)
    }

    /// `drive_once` with the one readiness wait `poll` (production: `wsa_poll`), which gets the
    /// interest set and the wait in milliseconds and fills in `revents`, or returns a WinSock
    /// error code.
    fn drive_with(
        &mut self,
        poll: impl FnOnce(&mut [WSAPOLLFD], i32) -> Result<usize, i32>,
    ) -> Result<OwnerStep, OwnerLoopError> {
        if self.closed {
            return Err(OwnerLoopError::Closed);
        }
        let mut step = OwnerStep::new();
        for live in &mut self.connections {
            live.served = false;
        }
        self.drive_into(&mut step, poll);
        self.connections.retain(|live| !live.tcp.is_closed());
        Ok(step)
    }

    fn drive_into(
        &mut self,
        step: &mut OwnerStep,
        poll: impl FnOnce(&mut [WSAPOLLFD], i32) -> Result<usize, i32>,
    ) {
        self.sweep(step);
        if self.closed {
            return;
        }
        // Interest: the listener, then every connection without an event yet, for writable
        // readiness while it retains a frame and readable readiness otherwise.
        let mut fds = Vec::with_capacity(MAX_POLL_SOCKETS);
        if let Some(listener) = &self.listener {
            fds.push(interest(listener.raw_socket(), POLLIN));
        }
        let listening = !fds.is_empty();
        let mut polled = Vec::with_capacity(MAX_LIVE_UNAUTHENTICATED_CONNECTIONS);
        let mut buffered = false;
        for (index, live) in self.connections.iter().enumerate() {
            if !live.served {
                let events = if live.tcp.write_pending() {
                    POLLOUT
                } else {
                    buffered |= live.tcp.input_buffered();
                    POLLIN
                };
                fds.push(interest(live.tcp.raw_socket(), events));
                polled.push(index);
            }
        }
        debug_assert!(fds.len() <= MAX_POLL_SOCKETS);
        if fds.is_empty() {
            return;
        }
        // Events found already, or retained input that no readiness will announce, are handled
        // without waiting.
        let wait = if step.events.is_empty() && !buffered {
            WAIT_MS
        } else {
            0
        };
        match poll(&mut fds, wait) {
            Ok(_) => {}
            Err(WSAEINTR) => return,
            Err(code) => return self.fail(step, OwnerLoopError::Poll(code)),
        }
        // Time may have passed: deadlines again before any socket I/O.
        self.sweep(step);
        if self.closed {
            return;
        }
        let first = usize::from(listening);
        for (slot, index) in polled.into_iter().enumerate() {
            let revents = fds[first + slot].revents;
            let live = &mut self.connections[index];
            if live.served {
                continue;
            }
            let connection = live.connection;
            // Hang-up alone closes nothing: a half-closed peer still receives (the retained frame
            // is written on writable readiness) and its earlier bytes are still read, until EOF.
            let outcome = if revents & CONNECTION_FAILED != 0 {
                match live.tcp.close() {
                    Ok(()) => Err(Some(ConnectionEnd::Readiness(revents))),
                    Err(error) => Ok(Err(error)),
                }
            } else if live.tcp.write_pending() && revents & POLLOUT != 0 {
                Ok(live.tcp.on_writable())
            } else if !live.tcp.write_pending()
                && (revents & READABLE != 0 || live.tcp.input_buffered())
            {
                Ok(live.tcp.on_readable())
            } else {
                Err(None)
            };
            match outcome {
                Ok(result) => self.report(step, connection, result),
                Err(Some(end)) => step.push(OwnerEvent::Closed(connection, end)),
                Err(None) => {}
            }
            if self.closed {
                return;
            }
        }
        // Ended connections leave before admission, so only live ones occupy storage.
        self.connections.retain(|live| !live.tcp.is_closed());
        if listening {
            self.listen(fds[0].revents, step);
        }
    }

    /// For trusted outer code after an OS resume notification: one deadline sweep over every
    /// live connection and nothing else (no socket I/O, no accept), against the existing
    /// monotonic clocks; an unusable clock fails closed as it always does.
    pub(crate) fn recheck_after_resume(&mut self) -> Result<OwnerStep, OwnerLoopError> {
        if self.closed {
            return Err(OwnerLoopError::Closed);
        }
        let mut step = OwnerStep::new();
        for live in &mut self.connections {
            live.served = false;
        }
        self.sweep(&mut step);
        self.connections.retain(|live| !live.tcp.is_closed());
        Ok(step)
    }

    /// `WindowsTcpConnection::start_initiator` on exactly `connection`; nothing is opened.
    pub(crate) fn start_initiator(
        &mut self,
        connection: ConnectionRef,
        local: Bootstrap,
        expected: Option<Bootstrap>,
    ) -> Outcome<Acted> {
        self.on(connection, |tcp| tcp.start_initiator(local, expected))
    }

    /// `start_initiator` with a hand ceremony clock and scripted request IDs.
    #[cfg(test)]
    pub(crate) fn start_initiator_with(
        &mut self,
        connection: ConnectionRef,
        clock: Clock,
        ids: &mut dyn RequestIdGenerator,
        local: Bootstrap,
        expected: Option<Bootstrap>,
    ) -> Outcome<Acted> {
        self.on(connection, |tcp| {
            tcp.start_initiator_with(clock, ids, local, expected)
        })
    }

    pub(crate) fn authorize_exposure(
        &mut self,
        connection: ConnectionRef,
        run: &RunRef,
        authority: &TrustedAuthority,
    ) -> Outcome<Acted> {
        self.on(connection, |tcp| tcp.authorize_exposure(run, authority))
    }

    pub(crate) fn expose_key(&mut self, connection: ConnectionRef, run: &RunRef) -> Outcome<Acted> {
        self.on(connection, |tcp| tcp.expose_key(run))
    }

    pub(crate) fn presentation(
        &mut self,
        connection: ConnectionRef,
        run: &RunRef,
    ) -> Result<Result<Option<SasPresentation>, RouteError>, OwnerLoopError> {
        self.on(connection, |tcp| tcp.presentation(run))
    }

    pub(crate) fn approve_sas(
        &mut self,
        connection: ConnectionRef,
        run: &RunRef,
        ceremony_identity: &[u8; 32],
    ) -> Outcome<Acted> {
        self.on(connection, |tcp| tcp.approve_sas(run, ceremony_identity))
    }

    pub(crate) fn emit_bootstrap_mac(
        &mut self,
        connection: ConnectionRef,
        run: &RunRef,
    ) -> Outcome<Acted> {
        self.on(connection, |tcp| tcp.emit_bootstrap_mac(run))
    }

    pub(crate) fn reject_sas(
        &mut self,
        connection: ConnectionRef,
        run: &RunRef,
        ceremony_identity: &[u8; 32],
    ) -> Outcome<Acted> {
        self.on(connection, |tcp| tcp.reject_sas(run, ceremony_identity))
    }

    pub(crate) fn cancel_sas(
        &mut self,
        connection: ConnectionRef,
        run: &RunRef,
        ceremony_identity: &[u8; 32],
    ) -> Outcome<Acted> {
        self.on(connection, |tcp| tcp.cancel_sas(run, ceremony_identity))
    }

    pub(crate) fn emit_initiator_finish(
        &mut self,
        connection: ConnectionRef,
        run: &RunRef,
    ) -> Outcome<Acted> {
        self.on(connection, |tcp| tcp.emit_initiator_finish(run))
    }

    /// Closes exactly `connection` through its adapter's one teardown (no CANCEL, nothing
    /// retried) and removes it; the listener and the other connections are unaffected unless
    /// that cleanup is uncertain, which fails the loop closed.
    pub(crate) fn close_connection(
        &mut self,
        connection: ConnectionRef,
    ) -> Result<(), OwnerLoopError> {
        let index = self.find(connection)?;
        let mut live = self.connections.remove(index);
        match live.tcp.close() {
            Ok(()) => Ok(()),
            Err(_) => {
                let _ = self.shut_all();
                Err(OwnerLoopError::OwnershipUncertain)
            }
        }
    }

    /// Drops the listener and attempts to close EVERY live connection, even after one close is
    /// uncertain; nothing is admitted again. `OwnershipUncertain` if any cleanup was uncertain.
    /// A second call is `Closed`.
    pub(crate) fn close(&mut self) -> Result<(), OwnerLoopError> {
        if self.closed {
            return Err(OwnerLoopError::Closed);
        }
        self.shut_all()
    }

    /// One local call on exactly the connection `connection` names, found by its exact
    /// reference among at most 16 (never by position, run, or request ID). An ending the call
    /// reports removes that connection; an uncertain one fails the loop closed.
    fn on<T>(
        &mut self,
        connection: ConnectionRef,
        op: impl FnOnce(&mut WindowsTcpConnection<'r, L::Stream>) -> Result<T, TcpError>,
    ) -> Result<T, OwnerLoopError> {
        let index = self.find(connection)?;
        match op(&mut self.connections[index].tcp) {
            Ok(value) => Ok(value),
            Err(error) => {
                self.connections.remove(index);
                if uncertain(&error) {
                    let _ = self.shut_all();
                    return Err(OwnerLoopError::OwnershipUncertain);
                }
                Err(OwnerLoopError::Connection(error))
            }
        }
    }

    fn find(&self, connection: ConnectionRef) -> Result<usize, OwnerLoopError> {
        if self.closed {
            return Err(OwnerLoopError::Closed);
        }
        self.connections
            .iter()
            .position(|live| live.connection == connection)
            .ok_or(OwnerLoopError::UnknownConnection)
    }

    /// One bounded deadline pass: per connection without an event yet, one connection-deadline
    /// poll and one ceremony-deadline poll. An event marks the connection served for this drive.
    fn sweep(&mut self, step: &mut OwnerStep) {
        for index in 0..self.connections.len() {
            let live = &mut self.connections[index];
            if live.served || live.tcp.is_closed() {
                continue;
            }
            let outcome = live
                .tcp
                .poll_connection_deadlines()
                .and_then(|_| live.tcp.poll_ceremony_deadlines());
            if matches!(&outcome, Ok(polled) if polled.event.is_none() && polled.result.is_none()) {
                continue;
            }
            live.served = true;
            let connection = live.connection;
            self.report(step, connection, outcome);
            if self.closed {
                return;
            }
        }
    }

    /// Records one adapter outcome: a step with an event or result, or the connection's end;
    /// an uncertain end fails the loop closed.
    fn report(
        &mut self,
        step: &mut OwnerStep,
        connection: ConnectionRef,
        outcome: Result<TcpStep, TcpError>,
    ) {
        match outcome {
            Ok(polled) if polled.event.is_none() && polled.result.is_none() => {}
            Ok(polled) => step.push(OwnerEvent::Step(connection, polled)),
            Err(error) if uncertain(&error) => {
                self.fail(step, OwnerLoopError::OwnershipUncertain);
            }
            Err(error) => step.push(OwnerEvent::Closed(
                connection,
                ConnectionEnd::Adapter(error),
            )),
        }
    }

    /// The listener's readiness: error flags drop it; otherwise at most one accept, admitted at
    /// once through a permit and the adapter, or dropped.
    fn listen(&mut self, revents: i16, step: &mut OwnerStep) {
        if revents & LISTENER_FAILED != 0 {
            self.listener = None;
            step.push(OwnerEvent::ListenerDisabled(ListenerFailure::Readiness(
                revents,
            )));
            return;
        }
        if revents & POLLIN == 0 {
            return;
        }
        let Some(listener) = self.listener.as_mut() else {
            return;
        };
        let stream = match listener.accept_one() {
            Ok(stream) => stream,
            Err(error)
                if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) =>
            {
                return;
            }
            Err(error) => {
                self.listener = None;
                step.push(OwnerEvent::ListenerDisabled(ListenerFailure::Io(
                    error.kind(),
                )));
                return;
            }
        };
        // Admission first: nothing else touches the socket before the permit.
        let permit = match AcceptPermit::begin(self.router) {
            Ok(permit) => permit,
            Err(TransportError::ResourceLimited) => {
                drop(stream);
                step.push(OwnerEvent::AcceptRefused(TcpError::Host(
                    HostError::Transport(TransportError::ResourceLimited),
                )));
                return;
            }
            Err(_) => {
                drop(stream);
                self.fail(step, OwnerLoopError::OwnershipUncertain);
                return;
            }
        };
        let Some(listener) = self.listener.as_ref() else {
            return;
        };
        let admitted = listener.admit(stream, permit, self.local.clone(), self.expected.clone());
        match admitted {
            // The authority-wide cap bounds this loop's connections too; more would mean its
            // accounting is broken.
            Ok(tcp) if self.connections.len() < MAX_LIVE_UNAUTHENTICATED_CONNECTIONS => {
                let Some(session) = tcp.session() else {
                    self.fail(step, OwnerLoopError::OwnershipUncertain);
                    return;
                };
                let connection = ConnectionRef(session);
                self.connections.push(Live {
                    connection,
                    tcp,
                    served: true,
                });
                step.push(OwnerEvent::Accepted(connection));
            }
            Ok(tcp) => {
                drop(tcp);
                self.fail(step, OwnerLoopError::OwnershipUncertain);
            }
            Err(error) if uncertain(&error) => self.fail(step, OwnerLoopError::OwnershipUncertain),
            Err(error) => step.push(OwnerEvent::AcceptRefused(error)),
        }
    }

    /// Fails the loop closed for `error`; an uncertain cleanup during that shutdown dominates
    /// any trigger, so the surfaced failure is then `OwnershipUncertain`.
    fn fail(&mut self, step: &mut OwnerStep, error: OwnerLoopError) {
        step.failure = Some(match self.shut_all() {
            Ok(()) => error,
            Err(uncertain) => uncertain,
        });
    }

    /// Closed for good: listener dropped, then every live connection's close attempted.
    fn shut_all(&mut self) -> Result<(), OwnerLoopError> {
        self.closed = true;
        self.listener = None;
        let mut outcome = Ok(());
        for mut live in self.connections.drain(..) {
            if !live.tcp.is_closed() && live.tcp.close().is_err() {
                outcome = Err(OwnerLoopError::OwnershipUncertain);
            }
        }
        outcome
    }
}

/// Shared authority state or Router cleanup could not be established. Distinct from every
/// connection-local ending (EOF, reset, broken pipe, run-local protocol failure).
fn uncertain(error: &TcpError) -> bool {
    matches!(
        error,
        TcpError::Host(
            HostError::Transport(TransportError::OwnershipUncertain)
                | HostError::Routing(RouteError::Ceremony(CeremonyError::Owner(
                    AuthorityError::OwnershipUncertain
                )))
        )
    )
}

fn interest(fd: SOCKET, events: i16) -> WSAPOLLFD {
    WSAPOLLFD {
        fd,
        events,
        revents: 0,
    }
}

/// One `WSAPoll` over `fds` (at most `MAX_POLL_SOCKETS`), waiting at most `wait` milliseconds.
fn wsa_poll(fds: &mut [WSAPOLLFD], wait: i32) -> Result<usize, i32> {
    debug_assert!(fds.len() <= MAX_POLL_SOCKETS && (0..=WAIT_MS).contains(&wait));
    // SAFETY: `fds` is an exclusively borrowed, initialized array of exactly `fds.len()` (at most
    // 17) `WSAPOLLFD`s for the whole synchronous call; WSAPoll writes only their `revents` and
    // keeps no pointer after it returns.
    let ready = unsafe { WSAPoll(fds.as_mut_ptr(), fds.len() as u32, wait) };
    if ready == SOCKET_ERROR {
        // SAFETY: no arguments; reads the calling thread's last WinSock error.
        return Err(unsafe { WSAGetLastError() });
    }
    Ok(usize::try_from(ready).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Error, Status,
        ceremony::PeerApproval,
        deadline::{
            ABSOLUTE_DEADLINE, INACTIVITY_DEADLINE, ManualClock, PENDING_PRE_EXPOSURE_DEADLINE,
        },
        host::{CeremonyDeadline, HostEvent, LocalEvent},
        protocol::{self, CancelReason, Message, Role},
        router::MAX_CEREMONY_POLLS_PER_CALL,
        transport::{IDLE_READ_DEADLINE, MAX_PENDING_ACCEPTS, WHOLE_FRAME_DEADLINE},
        windows_tcp::{
            TcpEvent, TimeoutCancel,
            tests::{
                ABSOLUTE, INACTIVITY, Node, OneId, ReadStep, Scripted, Tcp, UNKNOWN,
                WriteStep::{Fail, Take},
                acted, cancel_of, clocks, deadline, inbound, initiator_bootstrap, initiator_key,
                message, received, relay, responder_bootstrap, results_agree, sent, start, until,
                written,
            },
        },
    };
    use ErrorKind::{BrokenPipe, Interrupted, PermissionDenied, WouldBlock};
    use std::{
        cell::RefCell,
        collections::VecDeque,
        io::{Read, Write},
        net::SocketAddr,
        rc::Rc,
        sync::Arc,
        thread,
        time::Instant,
    };
    use windows_sys::Win32::Networking::WinSock::{POLLRDNORM, POLLWRNORM};

    /// WSAENETDOWN: a readiness wait that failed for good.
    const NET_DOWN: i32 = 10050;

    /// A scripted already-bound listener's backlog; the test keeps a handle to it.
    #[derive(Default)]
    struct Backlog {
        queued: VecDeque<Result<Scripted, ErrorKind>>,
        /// Every socket the loop took, so scripted readiness can find it.
        accepted: Vec<Scripted>,
        accepts: usize,
        refuse_nonblocking: bool,
        nonblocking: bool,
    }

    /// Accepts scripted sockets, admitted with hand transport and new-Responder clocks.
    #[derive(Clone)]
    struct FakeListener {
        backlog: Rc<RefCell<Backlog>>,
        transport: Arc<ManualClock>,
        ceremony: Arc<ManualClock>,
    }

    impl Listen for FakeListener {
        type Stream = Scripted;
        fn configure_nonblocking(&mut self) -> io::Result<()> {
            let mut backlog = self.backlog.borrow_mut();
            if backlog.refuse_nonblocking {
                return Err(ErrorKind::InvalidInput.into());
            }
            backlog.nonblocking = true;
            Ok(())
        }
        fn accept_one(&mut self) -> io::Result<Scripted> {
            let mut backlog = self.backlog.borrow_mut();
            backlog.accepts += 1;
            match backlog.queued.pop_front() {
                None => Err(WouldBlock.into()),
                Some(Err(kind)) => Err(kind.into()),
                Some(Ok(socket)) => {
                    backlog.accepted.push(socket.clone());
                    Ok(socket)
                }
            }
        }
        fn raw_socket(&self) -> SOCKET {
            Rc::as_ptr(&self.backlog).addr()
        }
        fn admit<'r>(
            &self,
            stream: Scripted,
            permit: AcceptPermit<'r>,
            local: Bootstrap,
            expected: Option<Bootstrap>,
        ) -> Result<WindowsTcpConnection<'r, Scripted>, TcpError> {
            WindowsTcpConnection::from_accepted_with(
                stream,
                permit,
                local,
                expected,
                self.transport.clone(),
                self.ceremony.clone(),
            )
        }
    }

    type Loop<'r> = WindowsOwnerLoop<'r, FakeListener>;

    /// Scripted readiness: what `WSAPoll` would report for the scripted sockets, unless
    /// overridden, and a record of every wait.
    struct Net {
        listener: FakeListener,
        overrides: RefCell<Vec<(SOCKET, i16)>>,
        /// `(sockets, wait in ms)` of every readiness wait.
        waits: RefCell<Vec<(usize, i32)>>,
        /// Runs inside the next wait: time passing while the loop is blocked.
        during: RefCell<Option<Box<dyn FnOnce()>>>,
        fail: RefCell<Option<i32>>,
    }

    impl Net {
        fn ready(&self, fds: &mut [WSAPOLLFD], wait: i32) -> Result<usize, i32> {
            self.waits.borrow_mut().push((fds.len(), wait));
            if let Some(during) = self.during.borrow_mut().take() {
                during();
            }
            if let Some(code) = self.fail.borrow_mut().take() {
                return Err(code);
            }
            let mut ready = 0;
            for fd in fds.iter_mut() {
                fd.revents = self.revents(fd.fd, fd.events);
                ready += usize::from(fd.revents != 0);
            }
            Ok(ready)
        }
        fn revents(&self, fd: SOCKET, events: i16) -> i16 {
            let overrides = self.overrides.borrow();
            if let Some(&(_, revents)) = overrides.iter().find(|(socket, _)| *socket == fd) {
                return revents;
            }
            let backlog = self.listener.backlog.borrow();
            if fd == self.listener.raw_socket() {
                return if backlog.queued.is_empty() {
                    0
                } else {
                    POLLRDNORM & events
                };
            }
            let Some(socket) = backlog.accepted.iter().find(|s| s.raw_socket() == fd) else {
                return POLLNVAL;
            };
            socket.with(|s| {
                let readable = if s.reads.is_empty() { 0 } else { POLLRDNORM };
                let writable = if s.hold && s.writes.is_empty() {
                    0
                } else {
                    POLLWRNORM
                };
                (readable | writable) & events
            })
        }
        /// Queues one connecting peer.
        fn connect(&self) -> Scripted {
            let socket = Scripted::default();
            let mut backlog = self.listener.backlog.borrow_mut();
            backlog.queued.push_back(Ok(socket.clone()));
            socket
        }
        fn queue_error(&self, kind: ErrorKind) {
            let mut backlog = self.listener.backlog.borrow_mut();
            backlog.queued.push_back(Err(kind));
        }
        fn accepts(&self) -> usize {
            self.listener.backlog.borrow().accepts
        }
        fn polls(&self) -> usize {
            self.waits.borrow().len()
        }
        fn last_wait(&self) -> (usize, i32) {
            *self.waits.borrow().last().unwrap()
        }
        /// Reports `revents` for `fd` from now on, replacing any earlier override for it.
        fn set(&self, fd: SOCKET, revents: i16) {
            let mut overrides = self.overrides.borrow_mut();
            overrides.retain(|(socket, _)| *socket != fd);
            overrides.push((fd, revents));
        }
        fn during(&self, op: impl FnOnce() + 'static) {
            *self.during.borrow_mut() = Some(Box::new(op));
        }
    }

    fn hosting<'r>(
        node: &'r Node,
        transport: &Arc<ManualClock>,
        ceremony: &Arc<ManualClock>,
    ) -> (Loop<'r>, Net) {
        let listener = FakeListener {
            backlog: Rc::default(),
            transport: transport.clone(),
            ceremony: ceremony.clone(),
        };
        let net = Net {
            listener: listener.clone(),
            overrides: RefCell::default(),
            waits: RefCell::default(),
            during: RefCell::default(),
            fail: RefCell::default(),
        };
        let owner = WindowsOwnerLoop::from_bound_listener(
            listener,
            &node.router,
            responder_bootstrap(),
            None,
        )
        .unwrap();
        (owner, net)
    }
    fn try_drive(owner: &mut Loop<'_>, net: &Net) -> Result<OwnerStep, OwnerLoopError> {
        owner.drive_with(|fds, wait| net.ready(fds, wait))
    }
    fn drive(owner: &mut Loop<'_>, net: &Net) -> OwnerStep {
        let step = try_drive(owner, net).unwrap();
        assert!(step.events.len() <= MAX_STEP_EVENTS);
        step
    }
    /// The one event of a drive, which must be `connection`'s adapter step.
    fn step_of(step: OwnerStep, connection: ConnectionRef) -> TcpStep {
        assert_eq!(step.failure, None);
        match <[_; 1]>::try_from(step.events) {
            Ok([OwnerEvent::Step(c, step)]) if c == connection => step,
            other => panic!("not one step of {connection:?}: {other:?}"),
        }
    }
    fn accepted(step: &OwnerStep) -> ConnectionRef {
        match step.events.as_slice() {
            [OwnerEvent::Accepted(connection)] => *connection,
            other => panic!("not one acceptance: {other:?}"),
        }
    }
    /// Queues a peer and drives once: exactly that peer becomes live.
    fn accept(owner: &mut Loop<'_>, net: &Net) -> (ConnectionRef, Scripted) {
        let socket = net.connect();
        let step = drive(owner, net);
        (accepted(&step), socket)
    }
    fn acted_loop(outcome: Outcome<Acted>) -> Acted {
        outcome.expect("loop refused").expect("action refused")
    }
    /// A START admitted on `connection` and its ACCEPT written; the Responder run.
    fn admit(
        owner: &mut Loop<'_>,
        net: &Net,
        connection: ConnectionRef,
        socket: &Scripted,
        id: [u8; 16],
    ) -> RunRef {
        socket.data(&start(&id));
        let (event, run) = inbound(step_of(drive(owner, net), connection));
        assert_eq!(event, HostEvent::StartAccepted);
        assert_eq!(step_of(drive(owner, net), connection), written());
        socket.take_wire();
        run.unwrap()
    }
    /// Poisons the run under `id` on `connection`'s session.
    fn poison(router: &Router, connection: ConnectionRef, id: &[u8]) {
        thread::scope(|scope| {
            let op = scope.spawn(|| {
                router.with_run(connection.0, id, |_| -> Result<(), CeremonyError> {
                    panic!("simulate uncertain run state")
                })
            });
            assert!(op.join().is_err());
        });
    }
    fn refused() -> OwnerEvent {
        OwnerEvent::AcceptRefused(TcpError::Host(HostError::Transport(
            TransportError::ResourceLimited,
        )))
    }
    fn closed_by(connection: ConnectionRef, error: TransportError) -> OwnerEvent {
        OwnerEvent::Closed(
            connection,
            ConnectionEnd::Adapter(TcpError::Host(HostError::Transport(error))),
        )
    }

    /// One loop-hosted connection and its peer: a direct scripted adapter of another node.
    struct Pair<'r> {
        conn: ConnectionRef,
        sock: Scripted,
        peer: Tcp<'r>,
        pio: Scripted,
    }
    impl<'r> Pair<'r> {
        fn accept(owner: &mut Loop<'_>, net: &Net, peer: &'r Node) -> Self {
            let (conn, sock) = accept(owner, net);
            let (peer, pio) = peer.connect(&ManualClock::new(), &ManualClock::new());
            Self {
                conn,
                sock,
                peer,
                pio,
            }
        }
        /// The loop writes its retained frame in one drive and the peer dispatches it.
        fn loop_to_peer(&mut self, owner: &mut Loop<'_>, net: &Net) -> TcpStep {
            assert_eq!(step_of(drive(owner, net), self.conn), written());
            relay(&self.sock, &self.pio);
            self.peer.on_readable().unwrap()
        }
        /// The peer writes its retained frame and the loop dispatches it in one drive.
        fn peer_to_loop(&mut self, owner: &mut Loop<'_>, net: &Net) -> TcpStep {
            assert_eq!(self.peer.on_writable(), Ok(written()));
            relay(&self.pio, &self.sock);
            step_of(drive(owner, net), self.conn)
        }
        /// A peer Initiator starts; the loop's new Responder accepts. `(peer run, loop run)`.
        fn open(
            &mut self,
            owner: &mut Loop<'_>,
            net: &Net,
            clock: &Arc<ManualClock>,
            id: [u8; 16],
        ) -> (RunRef, RunRef) {
            let started = acted(self.peer.start_initiator_with(
                clock.clone(),
                &mut OneId(Some(id)),
                initiator_bootstrap(),
                None,
            ));
            let (event, run) = inbound(self.peer_to_loop(owner, net));
            assert_eq!(event, HostEvent::StartAccepted);
            assert_eq!(inbound(self.loop_to_peer(owner, net)).0, HostEvent::Accept);
            (started.run.unwrap(), run.unwrap())
        }
        /// Both sides authorize and expose, the loop's side through the loop.
        fn keys(
            &mut self,
            owner: &mut Loop<'_>,
            net: &Net,
            peer: &Node,
            host: &Node,
            runs: &(RunRef, RunRef),
        ) {
            let (theirs, ours) = runs;
            acted(self.peer.authorize_exposure(theirs, &peer.trusted));
            acted(self.peer.expose_key(theirs));
            assert_eq!(
                inbound(self.peer_to_loop(owner, net)).0,
                HostEvent::InitiatorKey
            );
            acted_loop(owner.authorize_exposure(self.conn, ours, &host.trusted));
            acted_loop(owner.expose_key(self.conn, ours));
            assert_eq!(
                inbound(self.loop_to_peer(owner, net)).0,
                HostEvent::ResponderKey
            );
            let shown = self.peer.presentation(theirs).unwrap().unwrap().unwrap();
            assert_eq!(owner.presentation(self.conn, ours), Ok(Ok(Some(shown))));
        }
    }

    /// A loop-hosted Initiator (request ID `id`, ceremony clock `ci`) driven to its retained
    /// final ACK through drives and loop actions only, after `siblings` other live Initiators
    /// on the same connection; the peer is a Responder adapter of `r`.
    struct Fin<'r> {
        pair: Pair<'r>,
        run: RunRef,
        id: Vec<u8>,
    }
    fn final_ack<'r>(
        owner: &mut Loop<'_>,
        net: &Net,
        (i, r): (&Node, &'r Node),
        ci: &Arc<ManualClock>,
        id: [u8; 16],
        siblings: u8,
    ) -> Fin<'r> {
        let mut p = Pair::accept(owner, net, r);
        let others = ManualClock::new();
        for n in 0..siblings {
            acted_loop(owner.start_initiator_with(
                p.conn,
                others.clone(),
                &mut OneId(Some([0x20 + n; 16])),
                initiator_bootstrap(),
                None,
            ));
            assert_eq!(step_of(drive(owner, net), p.conn), written());
        }
        p.sock.take_wire();
        let run = acted_loop(owner.start_initiator_with(
            p.conn,
            ci.clone(),
            &mut OneId(Some(id)),
            initiator_bootstrap(),
            None,
        ))
        .run
        .unwrap();
        let (event, theirs) = inbound(p.loop_to_peer(owner, net));
        assert_eq!(event, HostEvent::StartAccepted);
        let theirs = theirs.unwrap();
        assert_eq!(inbound(p.peer_to_loop(owner, net)).0, HostEvent::Accept);
        acted_loop(owner.authorize_exposure(p.conn, &run, &i.trusted));
        acted_loop(owner.expose_key(p.conn, &run));
        assert_eq!(
            inbound(p.loop_to_peer(owner, net)).0,
            HostEvent::InitiatorKey
        );
        acted(p.peer.authorize_exposure(&theirs, &r.trusted));
        acted(p.peer.expose_key(&theirs));
        assert_eq!(
            inbound(p.peer_to_loop(owner, net)).0,
            HostEvent::ResponderKey
        );
        let shown = owner.presentation(p.conn, &run).unwrap().unwrap().unwrap();
        let identity = *shown.ceremony_identity();
        acted_loop(owner.approve_sas(p.conn, &run, &identity));
        acted_loop(owner.emit_bootstrap_mac(p.conn, &run));
        assert_eq!(
            inbound(p.loop_to_peer(owner, net)).0,
            HostEvent::BootstrapMac(PeerApproval::Authenticated)
        );
        acted(p.peer.approve_sas(&theirs, &identity));
        acted(p.peer.emit_bootstrap_mac(&theirs));
        assert_eq!(
            inbound(p.peer_to_loop(owner, net)).0,
            HostEvent::BootstrapMac(PeerApproval::Authenticated)
        );
        acted_loop(owner.emit_initiator_finish(p.conn, &run));
        assert_eq!(
            inbound(p.loop_to_peer(owner, net)).0,
            HostEvent::InitiatorFinish
        );
        let step = p.peer_to_loop(owner, net);
        assert!(step.write_pending);
        assert_eq!(inbound(step).0, HostEvent::ResponderFinishAck);
        assert_eq!(i.status(), Status::Busy);
        Fin {
            pair: p,
            run,
            id: id.to_vec(),
        }
    }

    #[test]
    fn frozen_owner_loop_bounds() {
        assert_eq!(OWNER_LOOP_MAX_WAIT, Duration::from_millis(250));
        assert_eq!((MAX_POLL_SOCKETS, MAX_STEP_EVENTS, WAIT_MS), (17, 17, 250));
        assert_eq!(
            (
                MAX_LIVE_UNAUTHENTICATED_CONNECTIONS,
                MAX_PENDING_ACCEPTS,
                MAX_CEREMONY_POLLS_PER_CALL
            ),
            (16, 4, 8)
        );
        // The wait is scheduling plumbing: every protocol and resource deadline is unchanged.
        assert_eq!(
            [
                WHOLE_FRAME_DEADLINE,
                IDLE_READ_DEADLINE,
                INACTIVITY_DEADLINE,
                ABSOLUTE_DEADLINE,
                PENDING_PRE_EXPOSURE_DEADLINE
            ],
            [10, 2, 60, 300, 60].map(Duration::from_secs)
        );
    }

    /// Code lines (comments dropped) before a source file's test module.
    fn production(source: &str) -> String {
        let end = source.find("mod tests {").unwrap();
        source[..end]
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn production_code_binds_connects_spawns_and_keys_nothing_by_address() {
        for source in [
            include_str!("windows_owner_loop.rs"),
            include_str!("windows_tcp.rs"),
        ] {
            let code = production(source);
            for forbidden in [
                "::bind(",
                "connect(",
                "SocketAddr",
                "IpAddr",
                "peer_addr",
                "local_addr",
                "127.0.0.1",
                "0.0.0.0",
                "thread::",
                "sleep(",
                "HashMap",
                "BTreeMap",
            ] {
                assert!(
                    !code.contains(forbidden),
                    "production code uses {forbidden}"
                );
            }
        }
        let code = production(include_str!("windows_owner_loop.rs"));
        // No route enumeration and no bypass of the adapter or of accept admission.
        for forbidden in [
            "poll_session_deadlines",
            "with_run",
            "with_exact_run",
            "HostConnection",
            "TransportConnection",
            "from_accepted_with",
            "activate",
            "receive_start",
            "deliver(",
        ] {
            assert!(!code.contains(forbidden), "owner loop uses {forbidden}");
        }
        assert!(code.contains("AcceptPermit::begin(self.router)"));
        assert!(
            code.contains("WindowsTcpConnection::from_accepted(stream, permit, local, expected)")
        );
    }

    #[test]
    fn a_bound_listener_is_made_nonblocking_first_or_nothing_is_created() {
        let r = Node::new("loop-construct");
        let (tc, cc, _) = clocks();
        let (owner, net) = hosting(&r, &tc, &cc);
        assert!(net.listener.backlog.borrow().nonblocking);
        assert_eq!(
            (
                owner.live_connections(),
                owner.is_listening(),
                owner.is_closed()
            ),
            (0, true, false)
        );
        assert_eq!((net.accepts(), net.polls(), r.sessions()), (0, 0, 0));
        drop((owner, net));
        let listener = FakeListener {
            backlog: Rc::default(),
            transport: tc.clone(),
            ceremony: cc.clone(),
        };
        listener.backlog.borrow_mut().refuse_nonblocking = true;
        let refused =
            Loop::from_bound_listener(listener.clone(), &r.router, responder_bootstrap(), None);
        assert_eq!(
            refused.err(),
            Some(OwnerLoopError::ListenerIo(ErrorKind::InvalidInput))
        );
        // The listener was dropped and nothing exists.
        assert_eq!(Rc::strong_count(&listener.backlog), 1);
        assert_eq!(
            (r.counts(), r.sessions(), listener.backlog.borrow().accepts),
            ((0, 0, 0, 0), 0, 0)
        );
        r.release();
    }

    #[test]
    fn one_drive_waits_once_on_at_most_17_sockets_and_accepts_at_most_one() {
        let r = Node::new("loop-one-accept");
        let (tc, cc, _) = clocks();
        let (mut owner, net) = hosting(&r, &tc, &cc);
        let queued: Vec<_> = (0..3).map(|_| net.connect()).collect();
        for n in 1..=3 {
            accepted(&drive(&mut owner, &net));
            // One wait (on the listener and the earlier connections), one accept.
            assert_eq!((net.polls(), net.accepts()), (n, n));
            assert_eq!(net.last_wait(), (n, 250));
            assert_eq!((r.counts(), r.sessions()), ((0, n, 0, 0), n));
        }
        // An admitted connection does no socket I/O in the drive that admitted it.
        for socket in &queued {
            assert_eq!((socket.reads(), socket.writes()), (0, 0));
        }
        // Nothing queued: the listener is not readable and is not accepted from.
        assert_eq!(drive(&mut owner, &net), OwnerStep::default());
        assert_eq!((net.accepts(), net.last_wait()), (3, (4, 250)));
        // Up to the cap the interest set grows to 1 + 16 sockets and no further.
        for _ in 3..MAX_LIVE_UNAUTHENTICATED_CONNECTIONS {
            accept(&mut owner, &net);
        }
        net.connect();
        assert_eq!(drive(&mut owner, &net).events, vec![refused()]);
        assert_eq!(net.last_wait(), (17, 250));
        let waits = net.waits.take();
        assert!(
            waits
                .iter()
                .all(|&(n, wait)| n <= 17 && (0..=250).contains(&wait))
        );
        assert_eq!(waits.len(), 18);
        drop(owner);
        r.release();
    }

    #[test]
    fn a_refused_accept_drops_its_socket_and_charges_nothing() {
        let r = Node::new("loop-accept-refused");
        let (tc, cc, _) = clocks();
        let (mut owner, net) = hosting(&r, &tc, &cc);
        let (a, sa) = accept(&mut owner, &net);
        let x = [1; 16];
        admit(&mut owner, &net, a, &sa, x);
        let charged = r.charged();
        // (a) The authority's accept-work queue is full (four permits held elsewhere): the
        // socket is dropped before anything else touches it.
        let permits: Vec<_> = (0..MAX_PENDING_ACCEPTS)
            .map(|_| AcceptPermit::begin(&r.router).unwrap())
            .collect();
        let y = net.connect();
        assert_eq!(drive(&mut owner, &net).events, vec![refused()]);
        assert_eq!(
            y.with(|s| (s.nonblocking, s.read_calls, s.write_calls, s.shutdowns)),
            (false, 0, 0, 0)
        );
        // Only the test's and the scripted backlog's handles remain.
        assert_eq!(Rc::strong_count(&y.0), 2);
        assert_eq!((r.counts(), r.sessions()), ((4, 1, 0, 1), 1));
        drop(permits);
        // (b) Sixteen live: the seventeenth is accepted by the OS, refused at activation, and
        // dropped, with no session, host, or protocol state.
        for _ in 1..MAX_LIVE_UNAUTHENTICATED_CONNECTIONS {
            accept(&mut owner, &net);
        }
        assert_eq!(r.counts(), (0, 16, 0, 1));
        let z = net.connect();
        assert_eq!(drive(&mut owner, &net).events, vec![refused()]);
        assert_eq!(z.with(|s| (s.read_calls, s.write_calls)), (0, 0));
        assert_eq!(Rc::strong_count(&z.0), 2);
        assert_eq!(
            (r.counts(), r.sessions(), owner.live_connections()),
            ((0, 16, 0, 1), 16, 16)
        );
        // Neither refusal charged the START limiter, spent an opportunity, reserved a request
        // ID, or made a pending Responder; established connections are unaffected.
        assert_eq!((r.charged(), r.remaining(), r.reserved()), (charged, 10, 0));
        sa.data(&initiator_key(&x));
        assert_eq!(
            inbound(step_of(drive(&mut owner, &net), a)).0,
            HostEvent::InitiatorKey
        );
        drop(owner);
        r.release();
    }

    #[test]
    fn uncertain_accept_admission_fails_the_whole_hosting_context_closed() {
        let r = Node::new("loop-accept-uncertain");
        let (tc, cc, _) = clocks();
        let (mut owner, net) = hosting(&r, &tc, &cc);
        let (a, sa) = accept(&mut owner, &net);
        let x = net.connect();
        let executor = r.executor.clone();
        let _ = thread::spawn(move || {
            let _shared = executor.0.shared.lock().unwrap();
            panic!("simulate ambiguous authority accounting");
        })
        .join();
        let step = drive(&mut owner, &net);
        assert_eq!(
            (step.events, step.failure),
            (vec![], Some(OwnerLoopError::OwnershipUncertain))
        );
        // Listener dropped, the accepted socket dropped untouched, the live connection closed
        // (its count stays held: its release cannot be established), nothing admitted again.
        assert!(owner.is_closed() && !owner.is_listening());
        assert_eq!((owner.live_connections(), sa.shutdowns()), (0, 1));
        assert_eq!(x.with(|s| (s.nonblocking, s.read_calls)), (false, 0));
        assert_eq!(r.counts().1, 1);
        net.connect();
        assert_eq!(try_drive(&mut owner, &net), Err(OwnerLoopError::Closed));
        assert_eq!(
            owner.start_initiator(a, initiator_bootstrap(), None),
            Err(OwnerLoopError::Closed)
        );
        assert_eq!(owner.close_connection(a), Err(OwnerLoopError::Closed));
        assert_eq!(owner.recheck_after_resume(), Err(OwnerLoopError::Closed));
        assert_eq!(owner.close(), Err(OwnerLoopError::Closed));
        assert_eq!(net.accepts(), 2);
        drop(owner);
        r.release();
    }

    #[test]
    fn listener_failures_disable_only_the_listener() {
        let r = Node::new("loop-listener-failure");
        let (tc, cc, _) = clocks();
        let (mut owner, net) = hosting(&r, &tc, &cc);
        let (a, sa) = accept(&mut owner, &net);
        // WouldBlock (readiness that no longer holds) and Interrupted: no work and no event.
        for kind in [WouldBlock, Interrupted] {
            net.queue_error(kind);
            assert_eq!(drive(&mut owner, &net), OwnerStep::default());
            assert!(owner.is_listening());
        }
        assert_eq!(net.accepts(), 3);
        // Another accept error drops the listener; the live connection continues.
        net.queue_error(PermissionDenied);
        assert_eq!(
            drive(&mut owner, &net).events,
            vec![OwnerEvent::ListenerDisabled(ListenerFailure::Io(
                PermissionDenied
            ))]
        );
        assert!(!owner.is_listening() && !owner.is_closed());
        let ignored = net.connect();
        admit(&mut owner, &net, a, &sa, [1; 16]);
        // No rebind and no further accept: only the connection is waited on.
        assert_eq!(
            (net.accepts(), net.last_wait().0, ignored.reads()),
            (4, 1, 0)
        );
        assert_eq!(owner.live_connections(), 1);
        drop((owner, net));
        // Error or hang-up readiness drops the listener without an accept, even while a peer
        // is queued.
        let (mut owner, net) = hosting(&r, &tc, &cc);
        let (b, sb) = accept(&mut owner, &net);
        net.connect();
        net.set(net.listener.raw_socket(), POLLHUP | POLLRDNORM);
        assert_eq!(
            drive(&mut owner, &net).events,
            vec![OwnerEvent::ListenerDisabled(ListenerFailure::Readiness(
                POLLHUP | POLLRDNORM
            ))]
        );
        assert_eq!((net.accepts(), owner.is_listening()), (1, false));
        admit(&mut owner, &net, b, &sb, [2; 16]);
        assert_eq!(owner.live_connections(), 1);
        drop(owner);
        r.release();
    }

    /// Error and invalid-handle readiness close a connection before any read or write; hang-up
    /// does not. P6.2 intentionally corrected the P4 reading of this test (formerly
    /// `error_or_hang_up_readiness_closes_a_connection_before_any_read_or_write`), under which
    /// `POLLHUP | POLLRDNORM` also closed A unread and discarded the START its peer sent before a
    /// graceful close (P5-F-001). Under P6-D-003 hang-up is read toward EOF and does not stop a
    /// retained frame from being written; the hard-failure half is unchanged.
    #[test]
    fn error_or_invalid_handle_readiness_closes_a_connection_before_any_read_or_write() {
        let r = Node::new("loop-readiness-error");
        let (tc, cc, _) = clocks();
        let (mut owner, net) = hosting(&r, &tc, &cc);
        let (a, sa) = accept(&mut owner, &net);
        let (b, sb) = accept(&mut owner, &net);
        let (c, sc) = accept(&mut owner, &net);
        // B retains its ACCEPT.
        sb.data(&start(&[2; 16]));
        inbound(step_of(drive(&mut owner, &net), b));
        // A: readable input with a hang-up. B: writable with an error. C: ordinary input.
        sa.data(&start(&[1; 16]));
        sa.read(ReadStep::Eof);
        sc.data(&start(&[3; 16]));
        net.set(sa.raw_socket(), POLLHUP | POLLRDNORM);
        net.set(sb.raw_socket(), POLLERR | POLLWRNORM);
        let events = drive(&mut owner, &net).events;
        let [
            OwnerEvent::Step(ca, sta),
            OwnerEvent::Closed(cb, end),
            OwnerEvent::Step(cx, stc),
        ] = <[_; 3]>::try_from(events).unwrap()
        else {
            panic!("not A's step, B's close, C's step");
        };
        assert_eq!((ca, cb, cx), (a, b, c));
        assert_eq!(end, ConnectionEnd::Readiness(POLLERR | POLLWRNORM));
        assert_eq!(inbound(sta).0, HostEvent::StartAccepted);
        assert_eq!(inbound(stc).0, HostEvent::StartAccepted);
        // A was read once and stays live; B was neither read nor written and is shut down.
        assert_eq!((sa.reads(), sb.writes(), sb.wire()), (1, 0, vec![]));
        assert_eq!((sa.shutdowns(), sb.shutdowns(), sc.shutdowns()), (0, 1, 0));
        assert_eq!((r.routes(), r.counts()), (2, (0, 2, 0, 2)));
        assert!(owner.is_listening());
        // A's ACCEPT still goes out to its half-closed peer; then its EOF ends A normally.
        sc.hold(true);
        net.set(sa.raw_socket(), POLLHUP | POLLWRNORM);
        assert_eq!(step_of(drive(&mut owner, &net), a), written());
        assert!(matches!(message(&sa.take_wire()), Message::Accept { .. }));
        net.set(sa.raw_socket(), POLLHUP);
        assert_eq!(
            drive(&mut owner, &net).events,
            vec![OwnerEvent::Closed(
                a,
                ConnectionEnd::Adapter(TcpError::PeerClosed)
            )]
        );
        assert_eq!((sa.reads(), sa.shutdowns()), (2, 1));
        // An invalid handle closes like an error, while C retains its ACCEPT.
        net.set(sc.raw_socket(), POLLNVAL);
        assert_eq!(
            drive(&mut owner, &net).events,
            vec![OwnerEvent::Closed(c, ConnectionEnd::Readiness(POLLNVAL))]
        );
        assert_eq!((sc.writes(), r.counts()), (0, (0, 0, 0, 0)));
        drop(owner);
        r.release();
    }

    #[test]
    fn connection_local_endings_remove_only_their_connection() {
        let r = Node::new("loop-local-endings");
        let (tc, cc, _) = clocks();
        let (mut owner, net) = hosting(&r, &tc, &cc);
        let (healthy, sh) = accept(&mut owner, &net);
        let (eof, se) = accept(&mut owner, &net);
        let (bad, sbad) = accept(&mut owner, &net);
        let (pipe, sp) = accept(&mut owner, &net);
        admit(&mut owner, &net, healthy, &sh, [1; 16]);
        sp.data(&start(&[2; 16]));
        inbound(step_of(drive(&mut owner, &net), pipe));
        sp.write(Fail(BrokenPipe));
        se.read(ReadStep::Eof);
        sbad.data(b"not a frame at all");
        let (charged, remaining) = (r.charged(), r.remaining());
        let step = drive(&mut owner, &net);
        assert_eq!(
            step.events,
            vec![
                OwnerEvent::Closed(eof, ConnectionEnd::Adapter(TcpError::PeerClosed)),
                closed_by(bad, TransportError::InvalidFrame),
                OwnerEvent::Closed(pipe, ConnectionEnd::Adapter(TcpError::Io(BrokenPipe))),
            ]
        );
        assert_eq!(step.failure, None);
        // The healthy connection, the listener, and every authority control are unaffected.
        assert_eq!((owner.live_connections(), owner.is_listening()), (1, true));
        assert_eq!(
            (r.charged(), r.remaining(), r.counts()),
            (charged, remaining, (0, 1, 0, 1))
        );
        sh.data(&initiator_key(&[1; 16]));
        assert_eq!(
            inbound(step_of(drive(&mut owner, &net), healthy)).0,
            HostEvent::InitiatorKey
        );
        drop(owner);
        r.release();
    }

    #[test]
    fn a_continuously_readable_listener_never_starves_an_established_connection() {
        let r = Node::new("loop-accept-flood");
        let (tc, cc, _) = clocks();
        let (mut owner, net) = hosting(&r, &tc, &cc);
        let (a, sa) = accept(&mut owner, &net);
        sa.data(&start(&[1; 16]));
        inbound(step_of(drive(&mut owner, &net), a));
        // A's ACCEPT goes out five bytes per write while peers keep connecting.
        for _ in 0..1000 {
            sa.write(Take(5));
            net.connect();
        }
        let accepts = net.accepts();
        let mut drives = 0;
        let step = loop {
            let step = drive(&mut owner, &net);
            drives += 1;
            // One accept per drive, every drive, and exactly one listener event.
            assert_eq!(net.accepts(), accepts + drives);
            let listener_events = step
                .events
                .iter()
                .filter(|e| matches!(e, OwnerEvent::Accepted(_) | OwnerEvent::AcceptRefused(_)))
                .count();
            assert_eq!(listener_events, 1);
            if step
                .events
                .iter()
                .any(|e| matches!(e, OwnerEvent::Step(c, _) if *c == a))
            {
                break step;
            }
            assert!(drives < 1000);
        };
        assert!(step.events.contains(&OwnerEvent::Step(a, written())));
        // One write syscall per drive: the frame completed exactly when five bytes per drive
        // complete it.
        let frame = sa.take_wire();
        assert!(matches!(message(&frame), Message::Accept { .. }));
        assert_eq!(drives, frame.len().div_ceil(5));
        assert_eq!(sa.writes(), drives);
        assert_eq!(
            owner.live_connections(),
            MAX_LIVE_UNAUTHENTICATED_CONNECTIONS.min(1 + drives)
        );
        drop(owner);
        r.release();
    }

    #[test]
    fn every_ready_connection_gets_one_socket_operation_per_drive() {
        let r = Node::new("loop-fairness");
        let (tc, cc, _) = clocks();
        let (mut owner, net) = hosting(&r, &tc, &cc);
        let (a, sa) = accept(&mut owner, &net);
        let (b, sb) = accept(&mut owner, &net);
        let (_, sc) = accept(&mut owner, &net);
        // A and B each get two complete STARTs in one OS read; C a prefix of one.
        sa.data(&[start(&[1; 16]), start(&[2; 16])].concat());
        sb.data(&[start(&[3; 16]), start(&[4; 16])].concat());
        sc.data(&start(&[5; 16])[..20]);
        let step = drive(&mut owner, &net);
        // One read each and at most one dispatched frame each: nobody drains a second frame.
        let started = |step: OwnerStep| -> Vec<ConnectionRef> {
            step.events
                .into_iter()
                .map(|event| match event {
                    OwnerEvent::Step(conn, step) => {
                        assert!(step.write_pending);
                        assert_eq!(inbound(step).0, HostEvent::StartAccepted);
                        conn
                    }
                    other => panic!("unexpected {other:?}"),
                })
                .collect()
        };
        assert_eq!(started(step), [a, b]);
        assert_eq!((sa.reads(), sb.reads(), sc.reads()), (1, 1, 1));
        assert_eq!((r.routes(), r.counts()), (2, (0, 3, 1, 2)));
        // Then one write syscall each per drive, however much is left, and no read meanwhile.
        sa.write(Take(3));
        sb.write(Take(3));
        assert_eq!(drive(&mut owner, &net), OwnerStep::default());
        assert_eq!(
            (sa.writes(), sb.writes(), sa.wire().len(), sb.wire().len()),
            (1, 1, 3, 3)
        );
        assert_eq!(
            drive(&mut owner, &net).events,
            vec![
                OwnerEvent::Step(a, written()),
                OwnerEvent::Step(b, written())
            ]
        );
        assert_eq!(
            (sa.writes(), sb.writes(), sa.reads(), sb.reads()),
            (2, 2, 1, 1)
        );
        // The second STARTs are retained input no socket readiness announces: the next drive
        // does not wait and dispatches one per connection, without reading the socket again.
        assert_eq!(started(drive(&mut owner, &net)), [a, b]);
        assert_eq!(net.last_wait(), (4, 0));
        assert_eq!((sa.reads(), sb.reads(), r.routes()), (1, 1, 4));
        drop(owner);
        r.release();
    }

    #[test]
    fn a_failed_readiness_wait_fails_closed_and_an_interrupted_one_changes_nothing() {
        let r = Node::new("loop-poll-failure");
        let (tc, cc, _) = clocks();
        let (mut owner, net) = hosting(&r, &tc, &cc);
        let (a, sa) = accept(&mut owner, &net);
        sa.data(&start(&[1; 16]));
        *net.fail.borrow_mut() = Some(WSAEINTR);
        assert_eq!(drive(&mut owner, &net), OwnerStep::default());
        assert_eq!((sa.reads(), owner.is_closed()), (0, false));
        inbound(step_of(drive(&mut owner, &net), a));
        // Readiness can no longer be trusted: no fallback, the loop fails closed.
        *net.fail.borrow_mut() = Some(NET_DOWN);
        let step = drive(&mut owner, &net);
        assert_eq!(
            (step.events, step.failure),
            (vec![], Some(OwnerLoopError::Poll(NET_DOWN)))
        );
        assert!(owner.is_closed() && !owner.is_listening());
        assert_eq!(
            (sa.shutdowns(), sa.writes(), r.counts(), r.routes()),
            (1, 0, (0, 0, 0, 0), 0)
        );
        assert_eq!(try_drive(&mut owner, &net), Err(OwnerLoopError::Closed));
        drop(owner);
        r.release();
    }

    #[test]
    fn an_uncertain_cleanup_after_a_failed_readiness_wait_surfaces_as_ownership_uncertain() {
        let r = Node::new("loop-poll-failure-uncertain");
        let (tc, cc, _) = clocks();
        let (mut owner, net) = hosting(&r, &tc, &cc);
        let (a, sa) = accept(&mut owner, &net);
        admit(&mut owner, &net, a, &sa, [1; 16]);
        let (b, sb) = accept(&mut owner, &net);
        let rb = admit(&mut owner, &net, b, &sb, [2; 16]);
        assert_eq!((r.counts(), r.sessions(), r.routes()), ((0, 2, 0, 2), 2, 2));
        let queued = net.connect();
        let (accepts, writes) = (net.accepts(), (sa.writes(), sb.writes()));
        // The deadline sweep passes; A's run turns uncertain only while the loop waits, and the
        // wait then fails for good: the fail-closed shutdown is what finds A uncertain.
        *net.fail.borrow_mut() = Some(NET_DOWN);
        let step = owner
            .drive_with(|fds, wait| {
                poison(&r.router, a, &[1; 16]);
                net.ready(fds, wait)
            })
            .unwrap();
        assert_eq!(net.last_wait(), (3, 250));
        // Cleanup uncertainty dominates the readiness failure that triggered the shutdown.
        assert_eq!(
            (step.events, step.failure),
            (vec![], Some(OwnerLoopError::OwnershipUncertain))
        );
        assert!(owner.is_closed() && !owner.is_listening());
        assert_eq!(owner.live_connections(), 0);
        // A's uncertain close did not stop B's: both were attempted, neither wrote anything.
        assert_eq!((sa.shutdowns(), sb.shutdowns()), (1, 1));
        assert_eq!((sa.writes(), sb.writes()), writes);
        // Only A's live count and session (CLOSING for good) stay held; B's are released and
        // every route is gone.
        assert_eq!((r.counts(), r.sessions(), r.routes()), ((0, 1, 0, 0), 1, 0));
        assert_eq!(
            r.router.with_run(b.0, &[2; 16], |_| Ok(())).err(),
            Some(RouteError::UnknownSession)
        );
        // Nothing is admitted again and every call refuses.
        assert_eq!((net.accepts(), queued.reads()), (accepts, 0));
        net.connect();
        assert_eq!(try_drive(&mut owner, &net), Err(OwnerLoopError::Closed));
        assert_eq!(owner.presentation(b, &rb), Err(OwnerLoopError::Closed));
        assert_eq!(owner.close(), Err(OwnerLoopError::Closed));
        assert_eq!(net.accepts(), accepts);
        drop(owner);
        r.release();
    }

    #[test]
    fn quiet_drives_still_drive_deadlines_and_an_empty_wait_is_not_a_timeout() {
        let r = Node::new("loop-quiet");
        let (tc, cc, _) = clocks();
        let (mut owner, net) = hosting(&r, &tc, &cc);
        let (a, sa) = accept(&mut owner, &net);
        let (b, sb) = accept(&mut owner, &net);
        let x = [1; 16];
        admit(&mut owner, &net, a, &sa, x);
        sb.data(&start(&[2; 16])[..20]);
        assert_eq!(drive(&mut owner, &net), OwnerStep::default());
        let reads = (sa.reads(), sb.reads());
        // Nothing is ready: each drive waits once, reports nothing, and stays live.
        for _ in 0..3 {
            assert_eq!(drive(&mut owner, &net), OwnerStep::default());
            assert_eq!(net.last_wait(), (3, 250));
        }
        assert_eq!((r.routes(), r.counts()), (1, (0, 2, 1, 1)));
        // B's partial frame idles out with no input: the drive closes B without reading.
        tc.advance(IDLE_READ_DEADLINE);
        assert_eq!(
            drive(&mut owner, &net).events,
            vec![closed_by(b, TransportError::IdleTimeout)]
        );
        // Found before the wait, so this drive did not wait.
        assert_eq!(net.last_wait(), (2, 0));
        // A's run reaches its 60 s deadline, also with no input.
        cc.advance(INACTIVITY_DEADLINE);
        assert_eq!(
            step_of(drive(&mut owner, &net), a),
            deadline(Some(&x), INACTIVITY, TimeoutCancel::NotBuilt)
        );
        assert_eq!((sa.reads(), sb.reads()), reads);
        assert_eq!(
            (r.routes(), r.counts(), owner.live_connections()),
            (0, (0, 1, 0, 0), 1)
        );
        drop(owner);
        r.release();
    }

    #[test]
    fn time_passing_during_the_wait_is_resolved_before_any_socket_io() {
        let r = Node::new("loop-post-wait");
        let (tc, cc, _) = clocks();
        let (mut owner, net) = hosting(&r, &tc, &cc);
        // (a) A's local Initiator START is retained; A's Responder Y expires during the wait.
        let (a, sa) = accept(&mut owner, &net);
        let y = [2; 16];
        admit(&mut owner, &net, a, &sa, y);
        let x = [1; 16];
        acted_loop(owner.start_initiator_with(
            a,
            ManualClock::new(),
            &mut OneId(Some(x)),
            initiator_bootstrap(),
            None,
        ));
        let writes = sa.writes();
        let clock = cc.clone();
        net.during(move || clock.advance(INACTIVITY_DEADLINE));
        assert_eq!(
            step_of(drive(&mut owner, &net), a),
            TcpStep {
                write_pending: true,
                ..deadline(Some(&y), INACTIVITY, TimeoutCancel::NotBuilt)
            }
        );
        // The full wait happened, and still no write followed it in that drive.
        assert_eq!(net.last_wait(), (2, 250));
        assert_eq!((sa.writes(), sa.wire()), (writes, vec![]));
        assert_eq!(step_of(drive(&mut owner, &net), a), written());
        assert!(
            matches!(message(&sa.take_wire()), Message::Start { request_id, .. } if request_id == x)
        );
        // (b) A partial inbound frame idles out during the wait while its completing bytes are
        // readable: the connection closes with no read.
        let (b, sb) = accept(&mut owner, &net);
        let frame = start(&[3; 16]);
        sb.data(&frame[..20]);
        assert_eq!(drive(&mut owner, &net), OwnerStep::default());
        sb.data(&frame[20..]);
        let reads = sb.reads();
        let clock = tc.clone();
        net.during(move || clock.advance(IDLE_READ_DEADLINE));
        assert_eq!(
            drive(&mut owner, &net).events,
            vec![closed_by(b, TransportError::IdleTimeout)]
        );
        assert_eq!((sb.reads(), r.routes()), (reads, 1));
        drop(owner);
        r.release();
    }

    #[test]
    fn resume_recheck_ends_expired_state_before_any_socket_progress() {
        let (i, r) = (Node::new("loop-resume-i"), Node::new("loop-resume-r"));
        let (tc, cc, ci) = clocks();
        let (mut owner, net) = hosting(&r, &tc, &cc);
        // A: a ceremony past SAS awaiting the human decision (inactivity suspended).
        let mut pa = Pair::accept(&mut owner, &net, &i);
        let runs = pa.open(&mut owner, &net, &ci, [1; 16]);
        pa.keys(&mut owner, &net, &i, &r, &runs);
        // B: a pre-exposure Responder. C: a partial transport frame.
        let (b, sb) = accept(&mut owner, &net);
        admit(&mut owner, &net, b, &sb, [2; 16]);
        let (c, sc) = accept(&mut owner, &net);
        sc.data(&start(&[3; 16])[..20]);
        assert_eq!(drive(&mut owner, &net), OwnerStep::default());
        assert_eq!(
            (r.routes(), r.status(), r.remaining()),
            (2, Status::Busy, 9)
        );
        // A suspension longer than every deadline; then input everywhere and a queued peer.
        tc.advance(ABSOLUTE_DEADLINE);
        cc.advance(ABSOLUTE_DEADLINE);
        pa.sock.data(b"late input");
        sb.data(&initiator_key(&[2; 16]));
        sc.data(&start(&[3; 16])[20..]);
        let queued = net.connect();
        let io = |s: &Scripted| (s.reads(), s.writes());
        let before = [io(&pa.sock), io(&sb), io(&sc)];
        let (polls, accepts) = (net.polls(), net.accepts());
        let step = owner.recheck_after_resume().unwrap();
        assert_eq!(step.failure, None);
        assert_eq!(
            step.events,
            vec![
                OwnerEvent::Step(
                    pa.conn,
                    deadline(Some(&[1; 16]), ABSOLUTE, TimeoutCancel::Pending)
                ),
                OwnerEvent::Step(
                    b,
                    deadline(Some(&[2; 16]), ABSOLUTE, TimeoutCancel::NotBuilt)
                ),
                closed_by(c, TransportError::WholeFrameTimeout),
            ]
        );
        // Deadlines only: no read, write, wait, or accept.
        assert_eq!([io(&pa.sock), io(&sb), io(&sc)], before);
        assert_eq!(
            (net.polls(), net.accepts(), queued.reads()),
            (polls, accepts, 0)
        );
        assert_eq!(
            (r.routes(), r.status(), r.remaining()),
            (0, Status::Ready { remaining: 9 }, 9)
        );
        // Nothing was extended: only surviving state proceeds. A writes its timeout CANCEL (the
        // late input stays unread behind it), B's late frame meets no run and ends B's session,
        // and the queued peer is admitted.
        let step = drive(&mut owner, &net);
        assert_eq!(step.events.len(), 3);
        assert_eq!(
            step.events[..2],
            [
                OwnerEvent::Step(pa.conn, written()),
                OwnerEvent::Closed(
                    b,
                    ConnectionEnd::Adapter(TcpError::Host(HostError::Routing(
                        RouteError::SessionProtocolFailure
                    )))
                ),
            ]
        );
        assert!(matches!(step.events[2], OwnerEvent::Accepted(_)));
        relay(&pa.sock, &pa.pio);
        assert!(matches!(
            inbound(pa.peer.on_readable().unwrap()).0,
            HostEvent::Cancel(_)
        ));
        assert_eq!(i.status(), Status::Ready { remaining: 9 });
        drop((owner, pa));
        i.release();
        r.release();
    }

    #[test]
    fn an_unusable_clock_found_by_the_resume_recheck_fails_closed() {
        let r = Node::new("loop-resume-clock");
        let (tc, cc, _) = clocks();
        let (mut owner, net) = hosting(&r, &tc, &cc);
        let (a, sa) = accept(&mut owner, &net);
        let x = [1; 16];
        admit(&mut owner, &net, a, &sa, x);
        let (b, sb) = accept(&mut owner, &net);
        sb.data(&start(&[2; 16])[..20]);
        assert_eq!(drive(&mut owner, &net), OwnerStep::default());
        cc.advance(Duration::from_secs(5));
        tc.advance(Duration::from_secs(1));
        assert_eq!(drive(&mut owner, &net), OwnerStep::default());
        // After resume the ceremony clock reads earlier than before and the transport clock
        // has no value: elapsed time is never invented and no deadline is extended.
        cc.set(Duration::from_secs(1));
        tc.fail();
        assert_eq!(
            owner.recheck_after_resume().unwrap().events,
            vec![
                OwnerEvent::Step(
                    a,
                    deadline(
                        Some(&x),
                        CeremonyDeadline::ClockUnavailable,
                        TimeoutCancel::NotBuilt
                    )
                ),
                closed_by(b, TransportError::ClockUnavailable),
            ]
        );
        assert_eq!(
            (r.routes(), r.counts(), owner.live_connections()),
            (0, (0, 1, 0, 0), 1)
        );
        drop(owner);
        r.release();
    }

    #[test]
    fn a_connection_ref_names_one_live_connection_and_never_its_replacement() {
        let r = Node::new("loop-connection-ref");
        let (tc, cc, _) = clocks();
        let (mut owner, net) = hosting(&r, &tc, &cc);
        let x = [1; 16];
        let (a, sa) = accept(&mut owner, &net);
        let ra = admit(&mut owner, &net, a, &sa, x);
        assert_eq!(owner.close_connection(a), Ok(()));
        // B takes the storage A had, and a run under A's request ID.
        let (b, sb) = accept(&mut owner, &net);
        let rb = admit(&mut owner, &net, b, &sb, x);
        assert_ne!(a, b);
        let unknown = OwnerLoopError::UnknownConnection;
        assert_eq!(owner.close_connection(a), Err(unknown.clone()));
        assert_eq!(owner.presentation(a, &rb), Err(unknown.clone()));
        assert_eq!(owner.expose_key(a, &rb), Err(unknown.clone()));
        assert_eq!(
            owner.start_initiator(a, initiator_bootstrap(), None),
            Err(unknown)
        );
        // A run reference of another connection is refused by the exact run check, never
        // rerouted to the connection that has it.
        let (c, sc) = accept(&mut owner, &net);
        let id = [0; 32];
        assert_eq!(owner.presentation(b, &ra), Ok(Err(UNKNOWN)));
        assert_eq!(owner.presentation(c, &rb), Ok(Err(UNKNOWN)));
        let refused = Ok(Err(Refused::Run(UNKNOWN)));
        assert_eq!(owner.authorize_exposure(c, &rb, &r.trusted), refused);
        assert_eq!(owner.expose_key(c, &rb), refused);
        assert_eq!(owner.approve_sas(c, &rb, &id), refused);
        assert_eq!(owner.reject_sas(c, &rb, &id), refused);
        assert_eq!(owner.cancel_sas(c, &rb, &id), refused);
        assert_eq!(owner.emit_bootstrap_mac(c, &rb), refused);
        assert_eq!(owner.emit_initiator_finish(c, &rb), refused);
        // B and C are untouched: both live, nothing written, B's run where it was.
        assert_eq!(
            (owner.live_connections(), sb.wire(), sc.wire()),
            (2, vec![], vec![])
        );
        assert_eq!((sa.shutdowns(), sb.shutdowns(), sc.shutdowns()), (1, 0, 0));
        sb.data(&initiator_key(&x));
        assert_eq!(
            inbound(step_of(drive(&mut owner, &net), b)),
            (HostEvent::InitiatorKey, Some(rb.clone()))
        );
        assert_eq!(
            acted_loop(owner.authorize_exposure(b, &rb, &r.trusted)).event,
            LocalEvent::ExposureAuthorized
        );
        assert_eq!(r.status(), Status::Ready { remaining: 10 });
        drop(owner);
        r.release();
    }

    #[test]
    fn local_actions_reach_only_their_exact_connection_and_never_queue() {
        let r = Node::new("loop-local-actions");
        let (tc, cc, ci) = clocks();
        let (mut owner, net) = hosting(&r, &tc, &cc);
        let (a, sa) = accept(&mut owner, &net);
        let (b, sb) = accept(&mut owner, &net);
        let (x, y) = ([1; 16], [2; 16]);
        let started = acted_loop(owner.start_initiator_with(
            a,
            ci.clone(),
            &mut OneId(Some(x)),
            initiator_bootstrap(),
            None,
        ));
        assert_eq!(
            (started.event, started.write_pending),
            (LocalEvent::InitiatorStarted, true)
        );
        let run = started.run.unwrap();
        // While A's START is retained, mutating actions on A are refused and never queued;
        // presentation still answers.
        let pending = Ok(Err(Refused::WritePending));
        assert_eq!(
            owner.start_initiator_with(
                a,
                ci.clone(),
                &mut OneId(Some(y)),
                initiator_bootstrap(),
                None
            ),
            pending
        );
        assert_eq!(owner.authorize_exposure(a, &run, &r.trusted), pending);
        assert_eq!(owner.emit_initiator_finish(a, &run), pending);
        assert_eq!(owner.presentation(a, &run), Ok(Ok(None)));
        // B acts independently.
        let rb = acted_loop(owner.start_initiator_with(
            b,
            ci.clone(),
            &mut OneId(Some(y)),
            initiator_bootstrap(),
            None,
        ))
        .run
        .unwrap();
        assert_eq!((r.reserved(), r.routes()), (2, 2));
        assert_eq!(
            drive(&mut owner, &net).events,
            vec![
                OwnerEvent::Step(a, written()),
                OwnerEvent::Step(b, written())
            ]
        );
        // Nothing refused earlier happens by itself once the write completed.
        assert_eq!(drive(&mut owner, &net), OwnerStep::default());
        assert!(
            matches!(message(&sa.wire()), Message::Start { request_id, .. } if request_id == x)
        );
        assert_eq!((r.reserved(), r.routes()), (2, 2));
        assert_eq!(owner.presentation(a, &run), Ok(Ok(None)));
        // Closing A ends only A: no CANCEL, B and the listener stay; a repeat is refused.
        let wire = sa.wire();
        assert_eq!(owner.close_connection(a), Ok(()));
        assert_eq!((sa.wire(), sa.shutdowns(), sb.shutdowns()), (wire, 1, 0));
        assert_eq!((owner.live_connections(), owner.is_listening()), (1, true));
        assert_eq!((r.reserved(), r.routes()), (1, 1));
        assert_eq!(
            owner.close_connection(a),
            Err(OwnerLoopError::UnknownConnection)
        );
        // A connection whose session ended underneath an action is removed by that action.
        r.router.close_session(b.0).unwrap();
        assert_eq!(
            owner.presentation(b, &rb),
            Err(OwnerLoopError::Connection(TcpError::Host(
                HostError::Routing(RouteError::UnknownSession)
            )))
        );
        assert_eq!(
            (owner.live_connections(), owner.is_closed(), r.counts()),
            (0, false, (0, 0, 0, 0))
        );
        drop(owner);
        r.release();
    }

    #[test]
    fn shutdown_closes_every_connection_and_settles_its_state() {
        let (i, r) = (Node::new("loop-shutdown-i"), Node::new("loop-shutdown-r"));
        let (tc, cc, ci) = clocks();
        let (mut owner, net) = hosting(&r, &tc, &cc);
        // A: exposed past SAS (guard held, opportunity spent). B: a pre-exposure Responder.
        // C: a local Initiator's reservation with its START retained.
        let mut pa = Pair::accept(&mut owner, &net, &i);
        let runs = pa.open(&mut owner, &net, &ci, [1; 16]);
        pa.keys(&mut owner, &net, &i, &r, &runs);
        let (b, sb) = accept(&mut owner, &net);
        admit(&mut owner, &net, b, &sb, [2; 16]);
        let (c, sc) = accept(&mut owner, &net);
        sc.hold(true);
        acted_loop(owner.start_initiator_with(
            c,
            ManualClock::new(),
            &mut OneId(Some([3; 16])),
            initiator_bootstrap(),
            None,
        ));
        assert_eq!(drive(&mut owner, &net), OwnerStep::default());
        assert_eq!(
            (
                r.routes(),
                r.reserved(),
                r.counts(),
                r.status(),
                r.remaining()
            ),
            (3, 1, (0, 3, 0, 1), Status::Busy, 9)
        );
        assert_eq!(owner.close(), Ok(()));
        assert!(owner.is_closed() && !owner.is_listening());
        assert_eq!(
            (
                pa.sock.shutdowns(),
                sb.shutdowns(),
                sc.shutdowns(),
                sc.wire()
            ),
            (1, 1, 1, vec![])
        );
        // Every session settled: slots, reservations, and the guard released, the spent
        // opportunity kept, no result.
        assert_eq!(
            (
                r.routes(),
                r.reserved(),
                r.counts(),
                r.sessions(),
                r.status()
            ),
            (0, 0, (0, 0, 0, 0), 0, Status::Ready { remaining: 9 })
        );
        net.connect();
        assert_eq!(try_drive(&mut owner, &net), Err(OwnerLoopError::Closed));
        assert_eq!(owner.close(), Err(OwnerLoopError::Closed));
        assert_eq!(net.accepts(), 3);
        // The peer sees only the end of the stream.
        pa.pio.read(ReadStep::Eof);
        assert_eq!(pa.peer.on_readable(), Err(TcpError::PeerClosed));
        assert_eq!(i.status(), Status::Ready { remaining: 9 });
        drop((owner, pa));
        i.release();
        r.release();
    }

    #[test]
    fn an_uncertain_close_never_stops_the_others_from_closing() {
        let r = Node::new("loop-shutdown-uncertain");
        let (tc, cc, _) = clocks();
        let (mut owner, net) = hosting(&r, &tc, &cc);
        let live: Vec<_> = (1..=3)
            .map(|n| {
                let (conn, socket) = accept(&mut owner, &net);
                admit(&mut owner, &net, conn, &socket, [n; 16]);
                (conn, socket)
            })
            .collect();
        poison(&r.router, live[1].0, &[2; 16]);
        assert_eq!(owner.close(), Err(OwnerLoopError::OwnershipUncertain));
        // All three were closed; only the uncertain one keeps its live count (and its session,
        // CLOSING for good) held.
        for (_, socket) in &live {
            assert_eq!(socket.shutdowns(), 1);
        }
        assert_eq!((r.counts(), r.sessions(), r.routes()), ((0, 1, 0, 0), 1, 0));
        assert!(owner.is_closed() && !owner.is_listening());
        assert_eq!(owner.close(), Err(OwnerLoopError::Closed));
        assert_eq!(try_drive(&mut owner, &net), Err(OwnerLoopError::Closed));
        drop(owner);
        r.release();
    }

    #[test]
    fn an_uncertain_connection_fails_the_whole_hosting_context_closed() {
        let r = Node::new("loop-connection-uncertain");
        let (tc, cc, _) = clocks();
        let (mut owner, net) = hosting(&r, &tc, &cc);
        let (a, sa) = accept(&mut owner, &net);
        admit(&mut owner, &net, a, &sa, [1; 16]);
        let (b, sb) = accept(&mut owner, &net);
        let rb = admit(&mut owner, &net, b, &sb, [2; 16]);
        poison(&r.router, a, &[1; 16]);
        sb.data(&initiator_key(&[2; 16]));
        let queued = net.connect();
        let accepts = net.accepts();
        // The sweep finds A's run state uncertain: not a connection-local ending.
        let step = drive(&mut owner, &net);
        assert_eq!(
            (step.events, step.failure),
            (vec![], Some(OwnerLoopError::OwnershipUncertain))
        );
        assert!(owner.is_closed() && !owner.is_listening());
        // B was closed too, before its input was read; nothing new was admitted.
        assert_eq!((sa.shutdowns(), sb.shutdowns(), sb.reads()), (1, 1, 1));
        assert_eq!((net.accepts(), queued.reads()), (accepts, 0));
        assert_eq!((r.counts(), r.sessions()), ((0, 1, 0, 0), 1));
        assert_eq!(owner.presentation(b, &rb), Err(OwnerLoopError::Closed));
        drop(owner);
        r.release();
    }

    #[test]
    fn dropping_the_loop_tears_everything_down_without_panicking() {
        let r = Node::new("loop-drop");
        let (tc, cc, ci) = clocks();
        let (mut owner, net) = hosting(&r, &tc, &cc);
        let (a, sa) = accept(&mut owner, &net);
        admit(&mut owner, &net, a, &sa, [1; 16]);
        let (b, sb) = accept(&mut owner, &net);
        sb.hold(true);
        acted_loop(owner.start_initiator_with(
            b,
            ci,
            &mut OneId(Some([2; 16])),
            initiator_bootstrap(),
            None,
        ));
        assert_eq!((r.routes(), r.reserved(), r.counts().1), (2, 1, 2));
        drop(owner);
        assert_eq!(
            (r.routes(), r.reserved(), r.counts(), r.sessions()),
            (0, 0, (0, 0, 0, 0), 0)
        );
        assert_eq!((sa.shutdowns(), sb.shutdowns(), sb.wire()), (1, 1, vec![]));
        // Dropping a closed loop is a no-op.
        let (mut owner, _net) = hosting(&r, &tc, &cc);
        owner.close().unwrap();
        drop(owner);
        r.release();
    }

    #[test]
    fn restarting_the_hosting_loop_resets_no_authority_state() {
        let (i, r) = (Node::new("loop-restart-i"), Node::new("loop-restart-r"));
        let (tc, cc, ci) = clocks();
        let (mut owner, net) = hosting(&r, &tc, &cc);
        // A peer START (charged to the START limiter) and R's exposure (one opportunity).
        let mut pa = Pair::accept(&mut owner, &net, &i);
        let runs = pa.open(&mut owner, &net, &ci, [1; 16]);
        pa.keys(&mut owner, &net, &i, &r, &runs);
        let (old, ours) = (pa.conn, runs.1.clone());
        let limiter = r.executor.start_limiter_snapshot();
        assert_eq!(
            (r.remaining(), r.status(), limiter.tokens),
            (9, Status::Busy, 3)
        );
        // The frontend's network loop and its listener go away.
        drop((owner, net));
        assert_eq!(
            (r.remaining(), r.status(), r.routes(), r.sessions()),
            (9, Status::Ready { remaining: 9 }, 0, 0)
        );
        assert_eq!(r.executor.start_limiter_snapshot(), limiter);
        // Ownership was neither released nor reacquired: the authority is still registered.
        let again =
            TrustedAuthority::register_with_limiter_clock(b"loop-restart-r", ManualClock::new());
        assert_eq!(again.err(), Some(Error::AlreadyRegistered));
        // A new already-bound listener and a new loop over the same Router.
        let (mut owner, net) = hosting(&r, &tc, &cc);
        let (fresh, socket) = accept(&mut owner, &net);
        assert_ne!(fresh, old);
        assert_eq!(
            owner.presentation(old, &ours),
            Err(OwnerLoopError::UnknownConnection)
        );
        assert_eq!(owner.presentation(fresh, &ours), Ok(Err(UNKNOWN)));
        assert_eq!(
            owner.expose_key(fresh, &ours),
            Ok(Err(Refused::Run(UNKNOWN)))
        );
        // The START limiter continues from its state, and the budget stays spent.
        admit(&mut owner, &net, fresh, &socket, [9; 16]);
        let after = r.executor.start_limiter_snapshot();
        assert_eq!(
            (after.tokens, after.rolling),
            (limiter.tokens - 1, limiter.rolling + 1)
        );
        assert_eq!(r.status(), Status::Ready { remaining: 9 });
        drop((owner, pa));
        i.release();
        r.release();
    }

    #[test]
    fn the_loops_final_ack_result_appears_only_in_the_drive_that_writes_its_last_byte() {
        let (i, r) = (Node::new("loop-final-ack-i"), Node::new("loop-final-ack-r"));
        let (tc, cc, ci) = clocks();
        let (mut owner, net) = hosting(&i, &tc, &cc);
        let mut f = final_ack(&mut owner, &net, (&i, &r), &ci, [0x10; 16], 0);
        let conn = f.pair.conn;
        f.pair.sock.write(Take(3));
        f.pair.sock.write(Fail(WouldBlock));
        // A partial write, then a blocked one: no result, run and guard still held.
        for _ in 0..2 {
            assert_eq!(drive(&mut owner, &net), OwnerStep::default());
            assert_eq!(f.pair.sock.wire().len(), 3);
            assert_eq!((i.routes(), i.status()), (1, Status::Busy));
        }
        // The drive whose write completes the frame confirms it, once.
        let step = step_of(drive(&mut owner, &net), conn);
        assert_eq!(
            (&step.event, step.write_pending),
            (&Some(TcpEvent::Confirmed), false)
        );
        let initiator = step.result.expect("Initiator result");
        assert_eq!(drive(&mut owner, &net), OwnerStep::default());
        assert_eq!(
            (i.routes(), i.status()),
            (0, Status::Ready { remaining: 9 })
        );
        assert!(matches!(
            message(&f.pair.sock.wire()),
            Message::InitiatorFinishAck { .. }
        ));
        relay(&f.pair.sock, &f.pair.pio);
        let step = f.pair.peer.on_readable().unwrap();
        assert!(matches!(
            step.event,
            Some(TcpEvent::Inbound {
                event: HostEvent::InitiatorFinishAck,
                ..
            })
        ));
        results_agree(&initiator, &step.result.unwrap(), &f.id);
        // Success closes no connection.
        assert_eq!(
            (owner.live_connections(), i.counts().1, r.counts().1),
            (1, 1, 1)
        );
        assert!(!f.pair.peer.is_closed());
        assert_eq!(owner.presentation(conn, &f.run), Ok(Err(UNKNOWN)));
        drop((owner, f));
        i.release();
        r.release();
    }

    #[test]
    fn a_final_ack_whose_run_expires_before_the_loop_writes_it_is_never_written_further() {
        for prefix in [0, 4] {
            let (i, r) = (
                Node::new(&format!("loop-final-expired-i-{prefix}")),
                Node::new(&format!("loop-final-expired-r-{prefix}")),
            );
            let (tc, cc, ci) = clocks();
            let (mut owner, net) = hosting(&i, &tc, &cc);
            // More live sibling routes on X's connection than one fair sweep inspects.
            let f = final_ack(&mut owner, &net, (&i, &r), &ci, [0x10; 16], 16);
            let conn = f.pair.conn;
            if prefix > 0 {
                f.pair.sock.write(Take(prefix));
                assert_eq!(drive(&mut owner, &net), OwnerStep::default());
            }
            let fin = f.pair.sock.wire();
            assert_eq!(fin.len(), prefix);
            // X's deadline passes during the next readiness wait, which reports writable.
            let writes = f.pair.sock.writes();
            let clock = ci.clone();
            net.during(move || clock.advance(ABSOLUTE_DEADLINE));
            let step = drive(&mut owner, &net);
            // No further final-ACK byte and no result: the timeout wins.
            assert_eq!((f.pair.sock.writes(), f.pair.sock.wire()), (writes, fin));
            assert_eq!(i.status(), Status::Ready { remaining: 9 });
            if prefix == 0 {
                assert_eq!(
                    step_of(step, conn),
                    deadline(Some(&f.id), ABSOLUTE, TimeoutCancel::Pending)
                );
                assert_eq!(i.routes(), 16);
                assert_eq!(step_of(drive(&mut owner, &net), conn), written());
                assert_eq!(
                    cancel_of(&f.pair.sock.wire()),
                    (Role::Initiator, CancelReason::Timeout)
                );
            } else {
                assert_eq!(
                    step.events,
                    vec![OwnerEvent::Closed(
                        conn,
                        ConnectionEnd::Adapter(TcpError::AbandonedPartialFrame)
                    )]
                );
                assert_eq!(
                    (i.routes(), i.counts().1, owner.live_connections()),
                    (0, 0, 0)
                );
            }
            drop((owner, f));
            i.release();
            r.release();
        }
    }

    /// Drives the real loop until `connection` reports a step; no other event may occur.
    fn until_step(owner: &mut WindowsOwnerLoop<'_>, connection: ConnectionRef) -> TcpStep {
        until(|| {
            let step = owner.drive_once().unwrap();
            assert_eq!(step.failure, None);
            let mut events = step.events.into_iter();
            let event = events.next()?;
            assert!(events.next().is_none());
            match event {
                OwnerEvent::Step(c, step) if c == connection => Some(step),
                other => panic!("unexpected {other:?}"),
            }
        })
    }
    /// Drives the real loop until its listener admits or refuses one connection.
    fn until_accepted(owner: &mut WindowsOwnerLoop<'_>) -> Result<ConnectionRef, TcpError> {
        until(|| {
            let step = owner.drive_once().unwrap();
            assert!(step.events.len() <= 1);
            match step.events.into_iter().next()? {
                OwnerEvent::Accepted(connection) => Some(Ok(connection)),
                OwnerEvent::AcceptRefused(error) => Some(Err(error)),
                other => panic!("unexpected {other:?}"),
            }
        })
    }
    /// Test plumbing only: loopback on an OS-assigned port, never policy.
    fn real_listener() -> (TcpListener, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        (listener, address)
    }
    /// Reads from a blocking client until one complete canonical frame arrived.
    fn read_frame(client: &mut TcpStream) -> Vec<u8> {
        client
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut frame = Vec::new();
        loop {
            let mut chunk = [0; 4096];
            let n = client.read(&mut chunk).unwrap();
            assert!(n > 0, "connection ended");
            frame.extend_from_slice(&chunk[..n]);
            if protocol::decode(&frame).is_ok() {
                return frame;
            }
        }
    }

    #[test]
    fn real_loopback_accepts_one_queued_connection_per_drive_through_wsapoll() {
        let r = Node::new("loop-real-accept");
        let (listener, address) = real_listener();
        let mut owner =
            WindowsOwnerLoop::from_bound_listener(listener, &r.router, responder_bootstrap(), None)
                .unwrap();
        let mut clients: Vec<_> = (0..3)
            .map(|_| TcpStream::connect(address).unwrap())
            .collect();
        let mut live = Vec::new();
        for n in 1..=3 {
            live.push(until_accepted(&mut owner).unwrap());
            assert_eq!((r.counts(), r.sessions()), ((0, n, 0, 0), n));
        }
        // Nothing ready: one bounded wait, no event, still live.
        let started = Instant::now();
        assert_eq!(owner.drive_once().unwrap(), OwnerStep::default());
        assert!(started.elapsed() < Duration::from_secs(5));
        // A real START gets its exact ACCEPT, read and written on WSAPoll readiness.
        let id = [0x42; 16];
        clients[0].write_all(&start(&id)).unwrap();
        let (event, run) = inbound(until_step(&mut owner, live[0]));
        assert_eq!(event, HostEvent::StartAccepted);
        assert_eq!(until_step(&mut owner, live[0]), written());
        let accept = read_frame(&mut clients[0]);
        assert!(matches!(message(&accept), Message::Accept { request_id, .. } if request_id == id));
        assert_eq!(owner.presentation(live[0], &run.unwrap()), Ok(Ok(None)));
        // Peers on distinct source ports share the one authority START limiter.
        clients[1].write_all(&start(&[0x43; 16])).unwrap();
        inbound(until_step(&mut owner, live[1]));
        assert_eq!(r.charged(), (2, 2));
        drop(owner);
        drop(clients);
        r.release();
    }

    #[test]
    fn real_loopback_refuses_the_seventeenth_connection_without_touching_the_others() {
        let r = Node::new("loop-real-cap");
        let (listener, address) = real_listener();
        let mut owner =
            WindowsOwnerLoop::from_bound_listener(listener, &r.router, responder_bootstrap(), None)
                .unwrap();
        let clients: Vec<_> = (0..17)
            .map(|_| TcpStream::connect(address).unwrap())
            .collect();
        for _ in 0..16 {
            until_accepted(&mut owner).unwrap();
        }
        assert_eq!(
            until_accepted(&mut owner),
            Err(TcpError::Host(HostError::Transport(
                TransportError::ResourceLimited
            )))
        );
        assert_eq!(
            (r.counts(), r.sessions(), owner.live_connections()),
            ((0, 16, 0, 0), 16, 16)
        );
        // Exactly one client sees its connection end; the other sixteen stay open.
        for client in &clients {
            client.set_nonblocking(true).unwrap();
        }
        let ended = |mut client: &TcpStream| match client.read(&mut [0; 1]) {
            Ok(0) => true,
            Ok(_) => panic!("unexpected bytes"),
            Err(error) => error.kind() != WouldBlock,
        };
        let refused = until(|| clients.iter().position(&ended));
        let open = clients
            .iter()
            .enumerate()
            .filter(|(n, _)| *n != refused)
            .filter(|(_, client)| !ended(client))
            .count();
        assert_eq!(open, 16);
        assert_eq!(r.counts(), (0, 16, 0, 0));
        drop(owner);
        drop(clients);
        r.release();
    }

    #[test]
    fn real_loopback_owner_loop_completes_a_ceremony_as_the_initiator() {
        let (i, r) = (
            Node::new("loop-real-ceremony-i"),
            Node::new("loop-real-ceremony-r"),
        );
        let (listener, address) = real_listener();
        let mut owner =
            WindowsOwnerLoop::from_bound_listener(listener, &i.router, responder_bootstrap(), None)
                .unwrap();
        let client = TcpStream::connect(address).unwrap();
        let conn = until_accepted(&mut owner).unwrap();
        // The peer: a direct adapter of another authority over the client end.
        let permit = AcceptPermit::begin(&r.router).unwrap();
        let mut peer =
            WindowsTcpConnection::from_accepted(client, permit, responder_bootstrap(), None)
                .unwrap();
        // Every loop-side transition is a drive; every loop-side action goes through the loop.
        let run = acted_loop(owner.start_initiator(conn, initiator_bootstrap(), None))
            .run
            .unwrap();
        let id = run.request_id().to_vec();
        assert_eq!(until_step(&mut owner, conn), written());
        let (event, theirs) = inbound(received(&mut peer));
        assert_eq!(event, HostEvent::StartAccepted);
        let theirs = theirs.unwrap();
        assert_eq!(sent(&mut peer), written());
        assert_eq!(inbound(until_step(&mut owner, conn)).0, HostEvent::Accept);
        acted_loop(owner.authorize_exposure(conn, &run, &i.trusted));
        acted_loop(owner.expose_key(conn, &run));
        assert_eq!(until_step(&mut owner, conn), written());
        assert_eq!(inbound(received(&mut peer)).0, HostEvent::InitiatorKey);
        acted(peer.authorize_exposure(&theirs, &r.trusted));
        acted(peer.expose_key(&theirs));
        assert_eq!(sent(&mut peer), written());
        assert_eq!(
            inbound(until_step(&mut owner, conn)).0,
            HostEvent::ResponderKey
        );
        let shown = owner.presentation(conn, &run).unwrap().unwrap().unwrap();
        assert_eq!(peer.presentation(&theirs), Ok(Ok(Some(shown.clone()))));
        let identity = *shown.ceremony_identity();
        acted_loop(owner.approve_sas(conn, &run, &identity));
        acted_loop(owner.emit_bootstrap_mac(conn, &run));
        assert_eq!(until_step(&mut owner, conn), written());
        assert_eq!(
            inbound(received(&mut peer)).0,
            HostEvent::BootstrapMac(PeerApproval::Authenticated)
        );
        acted(peer.approve_sas(&theirs, &identity));
        acted(peer.emit_bootstrap_mac(&theirs));
        assert_eq!(sent(&mut peer), written());
        assert_eq!(
            inbound(until_step(&mut owner, conn)).0,
            HostEvent::BootstrapMac(PeerApproval::Authenticated)
        );
        acted_loop(owner.emit_initiator_finish(conn, &run));
        assert_eq!(until_step(&mut owner, conn), written());
        assert_eq!(inbound(received(&mut peer)).0, HostEvent::InitiatorFinish);
        assert_eq!(sent(&mut peer), written());
        let step = until_step(&mut owner, conn);
        assert!(step.write_pending);
        assert_eq!(inbound(step).0, HostEvent::ResponderFinishAck);
        assert_eq!((i.routes(), i.status()), (1, Status::Busy));
        // The result appears only in the drive whose real socket write completes the frame.
        let step = until_step(&mut owner, conn);
        assert_eq!(step.event, Some(TcpEvent::Confirmed));
        let initiator = step.result.unwrap();
        assert_eq!(
            (i.routes(), i.status()),
            (0, Status::Ready { remaining: 9 })
        );
        let step = received(&mut peer);
        assert!(matches!(
            step.event,
            Some(TcpEvent::Inbound {
                event: HostEvent::InitiatorFinishAck,
                ..
            })
        ));
        results_agree(&initiator, &step.result.unwrap(), &id);
        assert_eq!(initiator.ceremony_identity(), &identity);
        // Both connections stay live after success, until explicitly closed.
        assert_eq!(
            (owner.live_connections(), i.counts(), r.counts()),
            (1, (0, 1, 0, 0), (0, 1, 0, 0))
        );
        assert_eq!(owner.close_connection(conn), Ok(()));
        assert_eq!(until(|| peer.on_readable().err()), TcpError::PeerClosed);
        assert_eq!((i.counts(), r.counts()), ((0, 0, 0, 0), (0, 0, 0, 0)));
        drop((owner, peer));
        i.release();
        r.release();
    }

    #[test]
    fn real_loopback_peer_hang_up_closes_its_connection_and_no_other() {
        let r = Node::new("loop-real-hang-up");
        let (listener, address) = real_listener();
        let mut owner =
            WindowsOwnerLoop::from_bound_listener(listener, &r.router, responder_bootstrap(), None)
                .unwrap();
        let first = TcpStream::connect(address).unwrap();
        let a = until_accepted(&mut owner).unwrap();
        let mut second = TcpStream::connect(address).unwrap();
        let b = until_accepted(&mut owner).unwrap();
        drop(first);
        let step = until(|| {
            let step = owner.drive_once().unwrap();
            (!step.events.is_empty()).then_some(step)
        });
        // A graceful close with nothing in flight ends at the read that returns EOF, not on the
        // hang-up readiness itself (P6-D-003).
        assert!(matches!(
            step.events.as_slice(),
            [OwnerEvent::Closed(c, ConnectionEnd::Adapter(TcpError::PeerClosed))] if *c == a
        ));
        assert_eq!((owner.live_connections(), r.counts()), (1, (0, 1, 0, 0)));
        second.write_all(&start(&[7; 16])).unwrap();
        assert_eq!(
            inbound(until_step(&mut owner, b)).0,
            HostEvent::StartAccepted
        );
        drop(owner);
        r.release();
    }

    /// P6-D-001 connection-lifetime regressions (P5-F-002 remediation).
    mod connection_lifetime;

    /// P6-D-003 graceful hang-up regressions (P5-F-001 remediation).
    mod graceful_hang_up;

    /// P5.2 review-only owner-loop evidence (not part of the product); see
    /// `docs/p5-security-review/adversarial-sequences.md`.
    mod p5_owner_loop_review;

    /// P5.3 review-only entropy-panic unwind evidence (not part of the product); see
    /// `docs/p5-security-review/dependency-unsafe-deep-review.md`.
    mod p5_entropy_panic_loop;
}
