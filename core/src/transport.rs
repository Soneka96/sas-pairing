//! Crate-private, socket-free P3 §11.1.1 transport admission and bounded frame assembly for one
//! pairing authority: the model a future socket adapter drives. Nothing here opens, binds,
//! listens on, accepts from, reads from, or writes to any OS object, and nothing schedules,
//! sleeps, or spawns; the adapter supplies events (an accepted connection, received bytes, a poll,
//! a close) and receives at most one complete frame per call.
//!
//! Admission. Every count lives in the authority's existing shared state, beside the START
//! limiter and the pending/preliminary caps, so every router, listener, and adapter object of
//! one authority shares it and different authorities are independent; nothing is per router,
//! per listener, or keyed by peer address. An `AcceptPermit` is one of at most 4 accept-work tasks
//! the adapter has taken on but not yet turned into a live connection; it models the adapter's
//! bounded application work queue, not an OS listener backlog, which this module cannot
//! configure or bound. `activate` turns a permit into a live `TransportConnection` in one
//! critical section (pending -1, live +1, refused at 16 live) and only then opens that
//! connection's one fresh `Router` session. A connection counts against the cap of 16 from
//! activation until its teardown has established that session CLOSED, whether or not it ever
//! sent a frame; there is no authenticated transport state that would release it earlier.
//!
//! Frames. Each connection assembles at most one incomplete frame at a time (structurally: one
//! `Option`) and the authority at most 4. Boundaries come only from
//! `protocol::wire_frame_extent`, the codec's own header checks and wire-type field-count table,
//! so the assembler cannot drift from `decode`. It checks magic, version, defined type, every
//! declared length, and the complete-frame maximum, and nothing else: complete frames are exact
//! received bytes for `Router::receive_start`/`deliver`, which this module never calls. A frame
//! found complete inside one input is returned without retaining anything; otherwise one
//! authority incomplete-frame slot is acquired before the first byte is retained. A retained
//! frame has a 10-second whole-frame deadline from its first byte that nothing extends, and a
//! 2-second deadline without byte progress; both expire at `elapsed >= deadline`, are checked
//! before any new byte is accepted, and are evaluated against one injected monotonic clock that
//! is never a ceremony or START-limiter clock.
//!
//! Teardown. A framing error, frame or idle deadline, unusable clock, incomplete-slot refusal,
//! or explicit close or drop all take one path: stop accepting input, destroy the partial frame
//! and release its slot, close the Router session through `Router::close_session_settled`
//! (synchronous; every run ends through the existing session teardown, with no CANCEL, no
//! result, no limiter refund, and consumed opportunities kept), and only once that session is
//! established CLOSED release the live-connection count. If Router cleanup is uncertain the
//! count is never released, so uncertain work can never be replaced by new connections.
//! Transport failure never touches the START limiter, the opportunity budget, the guard, the
//! ownership lease, or another connection.
//!
//! Lock order: run mutex -> router table mutex -> session lifecycle mutex (leaf), with the
//! authority shared mutex taken by ceremony work under a run mutex or with nothing held. This
//! module adds no mutex (a connection is used through `&mut self`) and takes the authority shared
//! mutex only for its counts, with no other lock held and never across a Router call. A
//! connection must not be closed or dropped from inside a `Router::with_run` closure on its own
//! session: that operation's lease would never drain.
#![allow(dead_code)] // Used only by tests until a socket adapter exists.
#[cfg(test)]
use crate::test_hook::{self, Point};
use crate::{
    Shared,
    deadline::{Clock, system_clock},
    protocol::{self, CodecError, Extent},
    router::{Router, SessionHandle},
};
use std::{sync::MutexGuard, time::Duration};

/// P3 §11.1.1: live unauthenticated connections per authority, counted with or without frames.
pub(crate) const MAX_LIVE_UNAUTHENTICATED_CONNECTIONS: usize = 16;
/// P3 §11.1.1: adapter accept-work tasks per authority not yet turned into live connections.
pub(crate) const MAX_PENDING_ACCEPTS: usize = 4;
/// P3 §11.1.1: retained incomplete frames per authority.
pub(crate) const MAX_INCOMPLETE_FRAMES_PER_AUTHORITY: usize = 4;
/// P3 §11.1.1: retained incomplete frames per connection; one `Option<Partial>` enforces it.
pub(crate) const MAX_INCOMPLETE_FRAMES_PER_CONNECTION: usize = 1;
const _: () = assert!(MAX_INCOMPLETE_FRAMES_PER_CONNECTION == 1);
/// From the first retained byte of a frame to its last; never extended.
pub(crate) const WHOLE_FRAME_DEADLINE: Duration = Duration::from_secs(10);
/// Longest wait for the next byte of a retained incomplete frame.
pub(crate) const IDLE_READ_DEADLINE: Duration = Duration::from_secs(2);

/// Narrow local transport outcomes. None says anything about peer authentication, an SAS,
/// compromise, or the opportunity budget, and none is a protocol message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransportError {
    /// Generic transport admission refusal (accept queue, live connections, incomplete frames).
    ResourceLimited,
    /// Bad magic, unsupported version, or an undefined wire type.
    InvalidFrame,
    /// A declared length makes the complete frame larger than `MAX_FRAME`.
    FrameTooLarge,
    WholeFrameTimeout,
    IdleTimeout,
    /// The transport clock gave no value or went backwards.
    ClockUnavailable,
    /// The connection already ended; nothing was done.
    Closed,
    /// Authority shared state or Router cleanup could not be established; capacity stays held.
    OwnershipUncertain,
}

impl From<CodecError> for TransportError {
    fn from(error: CodecError) -> Self {
        match error {
            CodecError::Oversized | CodecError::LengthOverflow => Self::FrameTooLarge,
            _ => Self::InvalidFrame,
        }
    }
}

/// The authority's shared counts. A poisoned lock fails closed.
fn accounts(router: &Router) -> Result<MutexGuard<'_, Shared>, TransportError> {
    router
        .authority()
        .0
        .shared
        .lock()
        .map_err(|_| TransportError::OwnershipUncertain)
}

/// One of the authority's at most 4 adapter accept-work tasks: a connection notification the
/// adapter has accepted into bounded application work and not yet made live. Dropping an unused
/// permit releases its count exactly once; with poisoned shared state it stays counted.
pub(crate) struct AcceptPermit<'r> {
    router: &'r Router,
    /// Whether this permit still holds its pending-accept count.
    held: bool,
}

impl<'r> AcceptPermit<'r> {
    /// Immediately takes one pending-accept slot of `router`'s authority, or refuses with
    /// `ResourceLimited`; it never waits or queues.
    pub(crate) fn begin(router: &'r Router) -> Result<Self, TransportError> {
        let mut shared = accounts(router)?;
        if shared.pending_accepts >= MAX_PENDING_ACCEPTS {
            return Err(TransportError::ResourceLimited);
        }
        shared.pending_accepts += 1;
        Ok(Self { router, held: true })
    }

    /// `activate_with_clock` with a fresh production monotonic clock.
    pub(crate) fn activate(self) -> Result<TransportConnection<'r>, TransportError> {
        self.activate_with_clock(system_clock())
    }

    /// Turns this permit into a live connection with its own fresh Router session. In one
    /// critical section the pending count is released and, unless 16 connections are already
    /// live (`ResourceLimited`: no session, protocol state, limiter charge, or opportunity
    /// change), the live count is taken; the cap is checked here, never at `begin`. Only then is
    /// the session opened; if that fails the live count is released again, since no session
    /// exists to clean up.
    pub(crate) fn activate_with_clock(
        mut self,
        clock: Clock,
    ) -> Result<TransportConnection<'r>, TransportError> {
        {
            let mut shared = accounts(self.router)?;
            shared.pending_accepts -= 1;
            self.held = false;
            if shared.live_connections >= MAX_LIVE_UNAUTHENTICATED_CONNECTIONS {
                return Err(TransportError::ResourceLimited);
            }
            shared.live_connections += 1;
        }
        match self.router.open_session() {
            Ok(session) => Ok(TransportConnection {
                router: self.router,
                session,
                clock,
                observed: Duration::ZERO,
                partial: None,
                ended: false,
            }),
            Err(_) => {
                if let Ok(mut shared) = accounts(self.router) {
                    shared.live_connections -= 1;
                }
                Err(TransportError::OwnershipUncertain)
            }
        }
    }
}

impl Drop for AcceptPermit<'_> {
    fn drop(&mut self) {
        if self.held
            && let Ok(mut shared) = accounts(self.router)
        {
            shared.pending_accepts -= 1;
        }
    }
}

/// One authority incomplete-frame slot, owned by the one partial frame it was taken for and
/// released exactly once when that frame completes or is destroyed. With poisoned shared state
/// it stays counted.
struct IncompleteSlot<'r>(&'r Router);

impl<'r> IncompleteSlot<'r> {
    fn acquire(router: &'r Router) -> Result<Self, TransportError> {
        let mut shared = accounts(router)?;
        if shared.incomplete_frames >= MAX_INCOMPLETE_FRAMES_PER_AUTHORITY {
            return Err(TransportError::ResourceLimited);
        }
        shared.incomplete_frames += 1;
        Ok(Self(router))
    }
}

impl Drop for IncompleteSlot<'_> {
    fn drop(&mut self) {
        if let Ok(mut shared) = accounts(self.0) {
            shared.incomplete_frames -= 1;
        }
    }
}

/// The connection's one retained incomplete frame and its two transport timers.
struct Partial<'r> {
    /// Exact received bytes from the frame's first byte; never beyond its end or `MAX_FRAME`.
    bytes: Vec<u8>,
    /// Monotonic instant its first byte was retained; the whole-frame deadline's origin.
    started: Duration,
    /// Monotonic instant of the last call that retained at least one new byte.
    progress: Duration,
    slot: IncompleteSlot<'r>,
}

impl Partial<'_> {
    /// Retains bytes of `input` up to the frame's end and no further, one bounded step at a
    /// time: each step reaches at most the next point `wire_frame_extent` names, so a declared
    /// length is validated before any byte (or capacity) for its payload is retained. Returns
    /// the bytes taken and whether the frame is complete.
    fn extend(&mut self, input: &[u8]) -> Result<(usize, bool), CodecError> {
        let mut taken = 0;
        loop {
            let target = match protocol::wire_frame_extent(&self.bytes)? {
                Extent::Frame(total) if total == self.bytes.len() => return Ok((taken, true)),
                Extent::Frame(target) | Extent::Need(target) => target,
            };
            let rest = &input[taken..];
            if rest.is_empty() {
                return Ok((taken, false));
            }
            let missing = target - self.bytes.len();
            let take = missing.min(rest.len());
            self.bytes.reserve_exact(missing);
            self.bytes.extend_from_slice(&rest[..take]);
            taken += take;
        }
    }
}

/// The result of one `feed`: `consumed` leading input bytes were taken (the caller feeds the
/// rest again), and `frame` is the one complete frame finished by this call, if any.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Fed {
    pub(crate) consumed: usize,
    pub(crate) frame: Option<Vec<u8>>,
}

/// One live unauthenticated transport connection: exactly one Router session for its whole
/// life, one live-connection count, and at most one incomplete frame. It never switches or
/// reuses a session. Ending it (any failure, `close`, or drop) is one synchronous teardown.
pub(crate) struct TransportConnection<'r> {
    router: &'r Router,
    session: SessionHandle,
    clock: Clock,
    /// Latest clock reading accepted; an earlier one is a backwards clock.
    observed: Duration,
    partial: Option<Partial<'r>>,
    /// Teardown has begun: no input, poll, or second teardown is accepted.
    ended: bool,
}

impl TransportConnection<'_> {
    /// This connection's one Router session, for the adapter's `receive_start`/`deliver` calls.
    pub(crate) fn session(&self) -> SessionHandle {
        self.session
    }

    /// Takes received bytes and returns at most one complete frame, exactly as received. An
    /// empty input takes nothing and refreshes nothing. With a frame in progress its deadlines
    /// are checked first, so a late byte cannot rescue it. Any failure tears the connection down
    /// before it is returned; the connection then only reports `Closed`.
    pub(crate) fn feed(&mut self, input: &[u8]) -> Result<Fed, TransportError> {
        if self.ended {
            return Err(TransportError::Closed);
        }
        self.step(input).map_err(|error| self.fail(error))
    }

    /// Enforces the frame deadlines without input, for a host that must expire an idle frame
    /// when no bytes arrive. It never refreshes anything. With no frame in progress it does
    /// nothing and reads no clock.
    pub(crate) fn poll_frame_deadlines(&mut self) -> Result<(), TransportError> {
        if self.ended {
            return Err(TransportError::Closed);
        }
        if self.partial.is_none() {
            return Ok(());
        }
        self.now().map(drop).map_err(|error| self.fail(error))
    }

    /// Explicit local close: the same synchronous teardown as a failure. `Ok(())` means the
    /// Router session is CLOSED and every resource of this connection is released.
    pub(crate) fn close(mut self) -> Result<(), TransportError> {
        self.teardown()
    }

    fn step(&mut self, input: &[u8]) -> Result<Fed, TransportError> {
        let now = if self.partial.is_some() {
            self.now()?
        } else {
            if input.is_empty() {
                return Ok(Fed::default());
            }
            if let Extent::Frame(total) = protocol::wire_frame_extent(input)?
                && total <= input.len()
            {
                // Complete within this input: nothing is retained, so no slot or timer.
                return Ok(Fed {
                    consumed: total,
                    frame: Some(input[..total].to_vec()),
                });
            }
            let now = self.now()?;
            let slot = IncompleteSlot::acquire(self.router)?;
            self.partial = Some(Partial {
                bytes: Vec::new(),
                started: now,
                progress: now,
                slot,
            });
            now
        };
        let Some(partial) = self.partial.as_mut() else {
            return Err(TransportError::OwnershipUncertain);
        };
        let (consumed, complete) = partial.extend(input)?;
        if consumed > 0 {
            partial.progress = now;
        }
        let frame = match self.partial.take_if(|_| complete) {
            // The slot is released and both timers are gone with the partial frame.
            Some(Partial { bytes, slot, .. }) => {
                drop(slot);
                Some(bytes)
            }
            None => None,
        };
        Ok(Fed { consumed, frame })
    }

    /// One monotonic reading, checked first against the frame in progress: a missing or
    /// backwards reading is `ClockUnavailable`, then `WholeFrameTimeout` (reported first when
    /// both have expired; the effect is identical), then `IdleTimeout`.
    fn now(&mut self) -> Result<Duration, TransportError> {
        let now = self
            .clock
            .now()
            .filter(|now| *now >= self.observed)
            .ok_or(TransportError::ClockUnavailable)?;
        if let Some(partial) = &self.partial {
            let (Some(whole), Some(idle)) = (
                now.checked_sub(partial.started),
                now.checked_sub(partial.progress),
            ) else {
                return Err(TransportError::ClockUnavailable);
            };
            if whole >= WHOLE_FRAME_DEADLINE {
                return Err(TransportError::WholeFrameTimeout);
            }
            if idle >= IDLE_READ_DEADLINE {
                return Err(TransportError::IdleTimeout);
            }
        }
        self.observed = now;
        Ok(now)
    }

    /// The one failure path: tear down, then report `error`, or `OwnershipUncertain` if the
    /// teardown could not be established.
    fn fail(&mut self, error: TransportError) -> TransportError {
        match self.teardown() {
            Ok(()) => error,
            Err(uncertain) => uncertain,
        }
    }

    fn teardown(&mut self) -> Result<(), TransportError> {
        if self.ended {
            return Err(TransportError::Closed);
        }
        self.ended = true;
        // Local transport state no Router work can use: destroyed and its slot released first.
        self.partial = None;
        if self.router.close_session_settled(self.session).is_err() {
            // Router cleanup is not established: the live count stays held for good.
            return Err(TransportError::OwnershipUncertain);
        }
        #[cfg(test)]
        test_hook::fire(Point::TransportSessionClosed);
        accounts(self.router)?.live_connections -= 1;
        Ok(())
    }
}

impl Drop for TransportConnection<'_> {
    /// Best-effort synchronous teardown for a connection that was never closed. It never
    /// panics; uncertain cleanup keeps the live count held.
    fn drop(&mut self) {
        if !self.ended {
            let _ = self.teardown();
        }
    }
}

#[cfg(test)]
mod limits {
    use super::*;

    #[test]
    fn frozen_transport_limits_are_exact() {
        assert_eq!(MAX_LIVE_UNAUTHENTICATED_CONNECTIONS, 16);
        assert_eq!(MAX_PENDING_ACCEPTS, 4);
        assert_eq!(MAX_INCOMPLETE_FRAMES_PER_AUTHORITY, 4);
        assert_eq!(MAX_INCOMPLETE_FRAMES_PER_CONNECTION, 1);
        assert_eq!(WHOLE_FRAME_DEADLINE, Duration::from_secs(10));
        assert_eq!(IDLE_READ_DEADLINE, Duration::from_secs(2));
        assert_eq!(protocol::MAX_FRAME, 65_536);
        assert_eq!(
            TransportError::from(CodecError::Oversized),
            TransportError::FrameTooLarge
        );
        for error in [
            CodecError::BadMagic,
            CodecError::UnsupportedVersion(2),
            CodecError::UnknownType(0x20),
        ] {
            assert_eq!(TransportError::from(error), TransportError::InvalidFrame);
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::{
        CeremonyExecutor, Error as OwnerError, Status, TrustedAuthority,
        ceremony::CeremonyError,
        deadline::ManualClock,
        protocol::{Bootstrap, MAX_FRAME, Message, PROFILE_ID},
        router::{Inbound, RouteError, StartRouting},
        start_limiter::StartLimiterSnapshot,
    };
    use TransportError::*;
    use serde_json::Value;
    use std::{
        sync::{Arc, Barrier, PoisonError, mpsc},
        thread,
    };

    const NS: Duration = Duration::from_nanos(1);
    const MS: Duration = Duration::from_millis(1);
    const UNCERTAIN: RouteError =
        RouteError::Ceremony(CeremonyError::Owner(OwnerError::OwnershipUncertain));

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
    /// A fixture wire frame by its path under `wire_messages`.
    fn wire(path: &[&str]) -> Vec<u8> {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../vectors/p3-remote-vodozemac-draft-01.json"
        ))
        .unwrap();
        let mut value = &fixture["wire_messages"];
        for name in path {
            value = &value[name];
        }
        hex(value["hex"].as_str().unwrap())
    }
    /// Every authoritative fixture wire frame: all nine wire types, both directions where two.
    fn frames() -> Vec<Vec<u8>> {
        let frames: Vec<_> = [
            &["START"][..],
            &["ACCEPT"],
            &["INITIATOR_KEY"],
            &["RESPONDER_KEY"],
            &["BOOTSTRAP_MAC", "initiator"],
            &["BOOTSTRAP_MAC", "responder"],
            &["INITIATOR_FINISH"],
            &["RESPONDER_FINISH_ACK"],
            &["INITIATOR_FINISH_ACK"],
            &["CANCEL", "initiator"],
            &["CANCEL", "responder"],
        ]
        .into_iter()
        .map(wire)
        .collect();
        let mut kinds: Vec<u8> = frames.iter().map(|frame| frame[9]).collect();
        kinds.dedup();
        assert_eq!(kinds, (1..=9).collect::<Vec<u8>>());
        frames
    }
    fn initiator_bootstrap() -> Bootstrap {
        match protocol::decode(&wire(&["START"])).unwrap().message {
            Message::Start { bootstrap, .. } => bootstrap,
            _ => unreachable!(),
        }
    }
    fn responder_bootstrap() -> Bootstrap {
        match protocol::decode(&wire(&["ACCEPT"])).unwrap().message {
            Message::Accept { bootstrap, .. } => bootstrap,
            _ => unreachable!(),
        }
    }
    fn start(id: u8) -> Vec<u8> {
        Message::Start {
            request_id: vec![id; 16],
            bootstrap: initiator_bootstrap(),
        }
        .encode()
        .unwrap()
    }
    fn initiator_key(request_id: &[u8]) -> Vec<u8> {
        Message::InitiatorKey {
            request_id: request_id.to_vec(),
            public_key: [9; 32],
        }
        .encode()
        .unwrap()
    }
    /// A wire-shaped frame with arbitrary fields and no semantic validation.
    fn frame(kind: u8, fields: &[&[u8]]) -> Vec<u8> {
        let mut out = b"SASPAIR\0\x01".to_vec();
        out.push(kind);
        for field in fields {
            out.extend_from_slice(&(field.len() as u32).to_be_bytes());
            out.extend_from_slice(field);
        }
        out
    }

    /// One authority whose START limiter runs on a hand clock that the tests never advance.
    struct Authority {
        trusted: TrustedAuthority,
        executor: CeremonyExecutor,
    }
    impl Authority {
        fn new(scope: &str) -> Self {
            let trusted =
                TrustedAuthority::register_with_limiter_clock(scope.as_bytes(), ManualClock::new())
                    .unwrap();
            let executor = trusted.executor();
            Self { trusted, executor }
        }
        fn router(&self) -> Router {
            Router::new(self.executor.clone()).unwrap()
        }
        /// `(pending accepts, live connections, incomplete frames)`, read even if poisoned.
        fn counts(&self) -> (usize, usize, usize) {
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
            )
        }
        fn pending_responders(&self) -> usize {
            self.executor.0.shared.lock().unwrap().pending_responders
        }
        fn permits(&self) -> usize {
            self.executor
                .0
                .shared
                .lock()
                .unwrap()
                .preliminary_operations
        }
        fn limiter(&self) -> StartLimiterSnapshot {
            self.executor.start_limiter_snapshot()
        }
        /// `(burst tokens, rolling records)`.
        fn charged(&self) -> (u8, usize) {
            let limiter = self.limiter();
            (limiter.tokens, limiter.rolling)
        }
        fn status(&self) -> Status {
            self.executor.status().unwrap()
        }
        fn release(self) {
            drop(self.executor);
            self.trusted.release().unwrap();
        }
    }

    fn connect<'r>(router: &'r Router, clock: &Arc<ManualClock>) -> TransportConnection<'r> {
        AcceptPermit::begin(router)
            .unwrap()
            .activate_with_clock(clock.clone())
            .unwrap()
    }
    fn assert_open(router: &Router, session: SessionHandle) {
        let probe = router.with_run(session, &[0xEE], |_| Ok(()));
        assert_eq!(probe.unwrap_err(), RouteError::UnknownRoute);
    }
    fn assert_closed(router: &Router, session: SessionHandle) {
        let probe = router.with_run(session, &[0xEE], |_| Ok(()));
        assert_eq!(probe.unwrap_err(), RouteError::UnknownSession);
    }
    fn admit(router: &Router, session: SessionHandle, start: &[u8]) {
        assert!(matches!(
            router.receive_start(session, start, responder_bootstrap(), None),
            Ok(StartRouting::Accepted(_))
        ));
    }
    /// Feeds `bytes` in `chunk`-byte reads; only the last completes the frame, returned.
    fn reassemble(conn: &mut TransportConnection<'_>, bytes: &[u8], chunk: usize) -> Vec<u8> {
        let mut reads = bytes.chunks(chunk).peekable();
        while let Some(read) = reads.next() {
            let fed = conn.feed(read).unwrap();
            assert_eq!(fed.consumed, read.len());
            if reads.peek().is_none() {
                return fed.frame.expect("frame complete");
            }
            assert_eq!(fed.frame, None);
        }
        unreachable!("empty frame")
    }
    /// `(buffered bytes, buffer capacity, started, last progress)` of the retained frame.
    fn retained(conn: &TransportConnection<'_>) -> Option<(usize, usize, Duration, Duration)> {
        conn.partial
            .as_ref()
            .map(|p| (p.bytes.len(), p.bytes.capacity(), p.started, p.progress))
    }
    /// Poisons the run under `(session, id)` by panicking inside an operation on it.
    fn poison_run(router: &Router, session: SessionHandle, id: &[u8]) {
        thread::scope(|scope| {
            let op = scope.spawn(|| {
                router.with_run(session, id, |_| -> Result<(), CeremonyError> {
                    panic!("simulate uncertain run state")
                })
            });
            assert!(op.join().is_err());
        });
    }

    #[test]
    fn the_accept_queue_holds_four_permits_and_refuses_the_fifth_immediately() {
        let a = Authority::new("transport-accept-queue");
        let router = a.router();
        let mut permits: Vec<_> = (0..4)
            .map(|_| AcceptPermit::begin(&router).unwrap())
            .collect();
        assert_eq!(a.counts(), (4, 0, 0));
        assert_eq!(AcceptPermit::begin(&router).err(), Some(ResourceLimited));
        assert_eq!(a.counts(), (4, 0, 0));
        assert_eq!(router.sessions_for_test(), 0);
        // Dropping an unused permit releases exactly its slot.
        drop(permits.pop());
        assert_eq!(a.counts(), (3, 0, 0));
        permits.push(AcceptPermit::begin(&router).unwrap());
        assert_eq!(a.counts(), (4, 0, 0));
        drop(permits);
        assert_eq!(a.counts(), (0, 0, 0));
        assert_eq!(router.sessions_for_test(), 0);
        assert_eq!(a.charged(), (4, 0));
        assert_eq!(a.status(), Status::Ready { remaining: 10 });
        drop(router);
        a.release();
    }

    #[test]
    fn sixteen_frameless_connections_fill_the_cap_and_the_seventeenth_is_refused() {
        let a = Authority::new("transport-live-cap");
        let router = a.router();
        let clock = ManualClock::new();
        let mut conns: Vec<_> = (0..16).map(|_| connect(&router, &clock)).collect();
        assert_eq!(a.counts(), (0, 16, 0));
        assert_eq!(router.sessions_for_test(), 16);
        let permit = AcceptPermit::begin(&router).unwrap();
        assert_eq!(a.counts(), (1, 16, 0));
        assert_eq!(
            permit.activate_with_clock(clock.clone()).err(),
            Some(ResourceLimited)
        );
        // The pending slot is released; no session, state, or charge was created.
        assert_eq!(a.counts(), (0, 16, 0));
        assert_eq!(router.sessions_for_test(), 16);
        assert_eq!((a.charged(), a.pending_responders()), ((4, 0), 0));
        assert_eq!(a.status(), Status::Ready { remaining: 10 });
        conns.pop().unwrap().close().unwrap();
        assert_eq!(a.counts(), (0, 15, 0));
        assert_eq!(router.sessions_for_test(), 15);
        conns.push(connect(&router, &clock));
        assert_eq!(a.counts(), (0, 16, 0));
        drop(conns);
        assert_eq!(a.counts(), (0, 0, 0));
        assert_eq!(router.sessions_for_test(), 0);
        drop(router);
        a.release();
    }

    #[test]
    fn concurrent_activations_at_fifteen_live_admit_exactly_one() {
        let a = Authority::new("transport-activation-race");
        let router = a.router();
        let clock = ManualClock::new();
        for _ in 0..25 {
            let conns: Vec<_> = (0..15).map(|_| connect(&router, &clock)).collect();
            let permits: Vec<_> = (0..4)
                .map(|_| AcceptPermit::begin(&router).unwrap())
                .collect();
            assert_eq!(a.counts(), (4, 15, 0));
            let barrier = Barrier::new(permits.len());
            let outcomes: Vec<_> = thread::scope(|scope| {
                let racers: Vec<_> = permits
                    .into_iter()
                    .map(|permit| {
                        let (barrier, clock) = (&barrier, clock.clone());
                        scope.spawn(move || {
                            barrier.wait();
                            permit.activate_with_clock(clock)
                        })
                    })
                    .collect();
                racers.into_iter().map(|h| h.join().unwrap()).collect()
            });
            assert_eq!(outcomes.iter().filter(|o| o.is_ok()).count(), 1);
            assert!(
                outcomes
                    .iter()
                    .filter_map(|o| o.as_ref().err())
                    .all(|e| *e == ResourceLimited)
            );
            assert_eq!(a.counts(), (0, 16, 0));
            assert_eq!(router.sessions_for_test(), 16);
            drop(outcomes);
            drop(conns);
            assert_eq!(a.counts(), (0, 0, 0));
            assert_eq!(router.sessions_for_test(), 0);
        }
        drop(router);
        a.release();
    }

    #[test]
    fn transport_caps_are_shared_by_every_router_of_one_authority_only() {
        let a = Authority::new("transport-routers-a");
        let b = Authority::new("transport-routers-b");
        let (r1, r2, rb) = (a.router(), a.router(), b.router());
        let clock = ManualClock::new();
        let mut conns: Vec<_> = (0..16)
            .map(|n| connect(if n % 2 == 0 { &r1 } else { &r2 }, &clock))
            .collect();
        assert_eq!(a.counts(), (0, 16, 0));
        assert_eq!((r1.sessions_for_test(), r2.sessions_for_test()), (8, 8));
        for router in [&r1, &r2] {
            let permit = AcceptPermit::begin(router).unwrap();
            assert_eq!(
                permit.activate_with_clock(clock.clone()).err(),
                Some(ResourceLimited)
            );
        }
        // The accept queue is authority-wide too.
        let held = [&r1, &r2, &r1, &r2].map(|router| AcceptPermit::begin(router).unwrap());
        assert_eq!(AcceptPermit::begin(&r1).err(), Some(ResourceLimited));
        assert_eq!(AcceptPermit::begin(&r2).err(), Some(ResourceLimited));
        // Another authority is independent.
        let others: Vec<_> = (0..16).map(|_| connect(&rb, &clock)).collect();
        assert_eq!(b.counts(), (0, 16, 0));
        assert_eq!(a.counts(), (4, 16, 0));
        drop(held);
        // Capacity freed under one router is usable under the other.
        conns.pop().unwrap().close().unwrap();
        assert_eq!(r2.sessions_for_test(), 7);
        conns.push(connect(&r1, &clock));
        assert_eq!(a.counts(), (0, 16, 0));
        assert_eq!(r1.sessions_for_test(), 9);
        drop((conns, others));
        assert_eq!((a.counts(), b.counts()), ((0, 0, 0), (0, 0, 0)));
        drop((r1, r2, rb));
        a.release();
        b.release();
    }

    #[test]
    fn each_connection_owns_one_fresh_router_session_that_is_never_reissued() {
        let a = Authority::new("transport-session-map");
        let (router, other) = (a.router(), a.router());
        let clock = ManualClock::new();
        let (c1, c2) = (connect(&router, &clock), connect(&router, &clock));
        let (s1, s2) = (c1.session(), c2.session());
        assert_ne!(s1, s2);
        assert_open(&router, s1);
        assert_open(&router, s2);
        assert_eq!(
            other.close_session_settled(s1),
            Err(RouteError::UnknownSession)
        );
        // The handle is the adapter's routing context for this connection's frames.
        admit(&router, s1, &start(1));
        assert_eq!(a.pending_responders(), 1);
        c1.close().unwrap();
        assert_closed(&router, s1);
        assert_open(&router, s2);
        assert_eq!(a.pending_responders(), 0);
        let c3 = connect(&router, &clock);
        assert!(c3.session() != s1 && c3.session() != s2);
        drop((c2, c3));
        drop((router, other));
        a.release();
    }

    #[test]
    fn explicit_close_establishes_the_router_session_closed_before_releasing_the_live_count() {
        let a = Authority::new("transport-close-order");
        let router = Arc::new(a.router());
        let clock = ManualClock::new();
        let mut conn = connect(&router, &clock);
        let session = conn.session();
        admit(&router, session, &start(1));
        conn.feed(&initiator_key(&[1; 16])[..5]).unwrap();
        assert_eq!((a.counts(), a.pending_responders()), ((0, 1, 1), 1));
        let (seen_tx, seen) = mpsc::channel();
        {
            let (router, executor) = (router.clone(), a.executor.clone());
            test_hook::install(move |point| {
                if point == Point::TransportSessionClosed {
                    let shared = executor.0.shared.lock().unwrap();
                    let counts = (
                        shared.live_connections,
                        shared.incomplete_frames,
                        shared.pending_responders,
                    );
                    drop(shared);
                    let probe = router.with_run(session, &[0], |_| Ok(())).unwrap_err();
                    seen_tx
                        .send((counts, probe, router.sessions_for_test()))
                        .unwrap();
                }
            });
        }
        conn.close().unwrap();
        test_hook::install(|_| {});
        // By then the partial frame was gone, the run terminated (its pending slot released),
        // and the session CLOSED, while the live count was still held.
        assert_eq!(
            seen.try_recv().unwrap(),
            ((1, 0, 0), RouteError::UnknownSession, 0)
        );
        assert_eq!(a.counts(), (0, 0, 0));
        drop(router);
        a.release();
    }

    #[test]
    fn closing_a_connection_mid_ceremony_keeps_the_opportunity_and_yields_no_result() {
        let i = Authority::new("transport-ceremony-i");
        let r = Authority::new("transport-ceremony-r");
        let (ir, rr) = (i.router(), r.router());
        let clock = ManualClock::new();
        let si = ir.open_session().unwrap();
        let mut conn = connect(&rr, &clock);
        let sr = conn.session();
        // Every frame reaches the Responder through the transport, fragmented.
        let (id, start) = ir.start_initiator(si, initiator_bootstrap(), None).unwrap();
        let start = reassemble(&mut conn, &start, 7);
        let Ok(StartRouting::Accepted(accept)) =
            rr.receive_start(sr, &start, responder_bootstrap(), None)
        else {
            panic!("START not admitted");
        };
        assert_eq!(ir.deliver(si, &accept).unwrap().output, Inbound::Accept);
        ir.with_run(si, &id, |run| run.authorize(&i.trusted))
            .unwrap();
        let ikey = ir.with_run(si, &id, |run| run.expose_key()).unwrap().output;
        let ikey = reassemble(&mut conn, &ikey, 5);
        assert_eq!(rr.deliver(sr, &ikey).unwrap().output, Inbound::InitiatorKey);
        rr.with_run(sr, &id, |run| run.authorize(&r.trusted))
            .unwrap();
        let rkey = rr.with_run(sr, &id, |run| run.expose_key()).unwrap().output;
        assert_eq!(ir.deliver(si, &rkey).unwrap().output, Inbound::ResponderKey);
        assert!(
            rr.with_run(sr, &id, |run| Ok(run.presentation()))
                .unwrap()
                .output
                .is_some()
        );
        assert_eq!(r.status(), Status::Busy);
        conn.feed(&wire(&["BOOTSTRAP_MAC", "responder"])[..9])
            .unwrap();
        assert_eq!(r.counts(), (0, 1, 1));
        let charged = r.charged();
        // Transport close is local terminal failure only: SAS and approval dropped before the
        // guard, the consumed opportunity kept, no result, no CANCEL, no limiter refund.
        assert_eq!(conn.close(), Ok(()));
        assert_eq!(r.status(), Status::Ready { remaining: 9 });
        assert_eq!((r.counts(), r.pending_responders()), ((0, 0, 0), 0));
        assert_eq!(r.charged(), charged);
        assert_closed(&rr, sr);
        // The peer was not notified.
        assert_eq!(
            ir.with_run(si, &id, |run| Ok(run.state_label_for_test()))
                .unwrap()
                .output,
            "AwaitLocalApproval"
        );
        drop((ir, rr));
        i.release();
        r.release();
    }

    #[test]
    fn transport_failure_resets_no_authority_control_and_spares_other_connections() {
        let r = Authority::new("transport-no-reset");
        let router = r.router();
        let clock = ManualClock::new();
        let (mut a, mut b) = (connect(&router, &clock), connect(&router, &clock));
        let (sa, sb) = (a.session(), b.session());
        let first = reassemble(&mut b, &start(9), 64);
        admit(&router, sb, &first);
        for id in 1..=3 {
            let frame = reassemble(&mut a, &start(id), 64);
            admit(&router, sa, &frame);
        }
        let exhausted = r.limiter();
        assert_eq!(r.charged(), (0, 4));
        assert_eq!(r.pending_responders(), 4);
        a.feed(&start(4)[..20]).unwrap();
        // The transport clock is not the limiter clock: advancing it refills nothing.
        clock.advance(IDLE_READ_DEADLINE);
        assert_eq!(a.poll_frame_deadlines(), Err(IdleTimeout));
        assert_closed(&router, sa);
        assert_eq!((r.counts(), r.pending_responders()), ((0, 1, 0), 1));
        assert_eq!((r.limiter(), r.permits()), (exhausted, 0));
        assert_eq!(r.status(), Status::Ready { remaining: 10 });
        // B and its run are untouched, and the limiter was not reset.
        assert_eq!(
            router
                .with_run(sb, &[9; 16], |run| Ok(run.state_label_for_test()))
                .unwrap()
                .output,
            "ResponderAcceptSentAwaitInitiatorKey"
        );
        let next = reassemble(&mut b, &start(5), 64);
        assert_eq!(
            router.receive_start(sb, &next, responder_bootstrap(), None),
            Err(RouteError::Ceremony(CeremonyError::Owner(
                OwnerError::ResourceLimited
            )))
        );
        assert_eq!(r.limiter(), exhausted);
        drop((a, b));
        drop(router);
        r.release();
    }

    #[test]
    fn four_incomplete_frames_fill_the_authority_and_a_fifth_closes_only_its_connection() {
        let a = Authority::new("transport-incomplete-a");
        let other = Authority::new("transport-incomplete-b");
        let (r1, r2, ro) = (a.router(), a.router(), other.router());
        let clock = ManualClock::new();
        let start = wire(&["START"]);
        // Spread over two routers of one authority: one shared cap.
        let mut held: Vec<_> = [&r1, &r1, &r2, &r2]
            .map(|router| connect(router, &clock))
            .into_iter()
            .collect();
        for conn in &mut held {
            assert_eq!(
                conn.feed(&start[..5]).unwrap(),
                Fed {
                    consumed: 5,
                    frame: None
                }
            );
        }
        assert_eq!(a.counts(), (0, 4, 4));
        let mut e = connect(&r2, &clock);
        let se = e.session();
        // A frame complete within one input retains nothing, so it passes while the cap is full.
        assert_eq!(e.feed(&start).unwrap().frame, Some(start.clone()));
        assert_eq!(e.feed(&start[..5]), Err(ResourceLimited));
        assert!(e.partial.is_none());
        assert_closed(&r2, se);
        assert_eq!(a.counts(), (0, 4, 4));
        assert_eq!(e.feed(&start[5..]), Err(Closed));
        assert_eq!(e.poll_frame_deadlines(), Err(Closed));
        drop(e);
        assert_eq!(a.counts(), (0, 4, 4));
        for conn in &held {
            assert_eq!(retained(conn).unwrap().0, 5);
            assert_eq!(conn.partial.as_ref().unwrap().bytes, start[..5]);
            assert_open(conn.router, conn.session());
        }
        // Another authority has its own four.
        let mut others: Vec<_> = (0..4).map(|_| connect(&ro, &clock)).collect();
        for conn in &mut others {
            conn.feed(&start[..5]).unwrap();
        }
        assert_eq!(other.counts(), (0, 4, 4));
        // Completing or closing a held frame frees a slot for a later connection.
        assert_eq!(
            held[0].feed(&start[5..]).unwrap(),
            Fed {
                consumed: start.len() - 5,
                frame: Some(start.clone())
            }
        );
        assert_eq!(a.counts(), (0, 4, 3));
        let mut f = connect(&r1, &clock);
        f.feed(&start[..5]).unwrap();
        assert_eq!(a.counts(), (0, 5, 4));
        held.remove(1).close().unwrap();
        assert_eq!(a.counts(), (0, 4, 3));
        drop((held, others, f));
        assert_eq!((a.counts(), other.counts()), ((0, 0, 0), (0, 0, 0)));
        drop((r1, r2, ro));
        a.release();
        other.release();
    }

    #[test]
    fn one_connection_grows_its_one_frame_and_releases_its_slot_on_completion_or_close() {
        let a = Authority::new("transport-one-frame");
        let router = a.router();
        let clock = ManualClock::new();
        let mut conn = connect(&router, &clock);
        let ik = wire(&["INITIATOR_KEY"]);
        assert_eq!(conn.feed(&ik[..3]).unwrap().consumed, 3);
        clock.advance(MS);
        assert_eq!(conn.feed(&ik[3..6]).unwrap().consumed, 3);
        // More bytes extend the same frame: still one slot, one buffer, one start time.
        assert_eq!(a.counts(), (0, 1, 1));
        let (len, _, started, progress) = retained(&conn).unwrap();
        assert_eq!((len, started, progress), (6, Duration::ZERO, MS));
        assert_eq!(conn.feed(&ik[6..]).unwrap().frame, Some(ik.clone()));
        // Completion releases the slot and the timers but not the connection or its session.
        assert_eq!(a.counts(), (0, 1, 0));
        assert!(conn.partial.is_none());
        assert_open(&router, conn.session());
        clock.advance(MS);
        conn.feed(&ik[..20]).unwrap();
        assert_eq!(retained(&conn).unwrap().2, 2 * MS);
        assert_eq!(a.counts(), (0, 1, 1));
        let session = conn.session();
        conn.close().unwrap();
        assert_closed(&router, session);
        assert_eq!(a.counts(), (0, 0, 0));
        drop(router);
        a.release();
    }

    #[test]
    fn every_wire_type_reassembles_byte_by_byte_exactly() {
        let a = Authority::new("transport-byte-by-byte");
        let router = a.router();
        let clock = ManualClock::new();
        let mut conn = connect(&router, &clock);
        for original in frames() {
            for (i, byte) in original.iter().enumerate() {
                let fed = conn.feed(std::slice::from_ref(byte)).unwrap();
                assert_eq!(fed.consumed, 1);
                if i + 1 < original.len() {
                    assert_eq!(fed.frame, None, "premature completion");
                    assert_eq!(retained(&conn).unwrap().0, i + 1);
                    assert_eq!(a.counts(), (0, 1, 1));
                    clock.advance(MS);
                } else {
                    let rebuilt = fed.frame.unwrap();
                    assert_eq!(rebuilt, original);
                    // One layout: the full codec decodes the reconstruction identically.
                    assert_eq!(
                        protocol::decode(&rebuilt).unwrap(),
                        protocol::decode(&original).unwrap()
                    );
                }
            }
            assert_eq!(a.counts(), (0, 1, 0));
            assert!(conn.partial.is_none());
        }
        drop(conn);
        drop(router);
        a.release();
    }

    #[test]
    fn every_split_point_of_every_wire_type_reconstructs_the_original() {
        // Exhaustive two-read splits cover splits inside the header, between and inside
        // length-prefix bytes, between a prefix and its payload, inside the request ID, inside
        // key, MAC, transcript, and bootstrap fields, and before the final byte.
        let a = Authority::new("transport-splits");
        let router = a.router();
        let clock = ManualClock::new();
        let mut conn = connect(&router, &clock);
        for original in frames() {
            for at in 1..original.len() {
                assert_eq!(
                    conn.feed(&original[..at]).unwrap(),
                    Fed {
                        consumed: at,
                        frame: None
                    }
                );
                assert_eq!(a.counts(), (0, 1, 1));
                assert_eq!(
                    conn.feed(&original[at..]).unwrap(),
                    Fed {
                        consumed: original.len() - at,
                        frame: Some(original.clone())
                    }
                );
                assert_eq!(a.counts(), (0, 1, 0));
            }
        }
        drop(conn);
        drop(router);
        a.release();
    }

    #[test]
    fn frames_in_one_input_come_back_one_per_call_without_loss_or_duplication() {
        let a = Authority::new("transport-many-frames");
        let router = a.router();
        let clock = ManualClock::new();
        let mut conn = connect(&router, &clock);
        let (s, ik) = (wire(&["START"]), wire(&["INITIATOR_KEY"]));
        let both = [s.as_slice(), &ik].concat();
        let first = conn.feed(&both).unwrap();
        assert_eq!(first.consumed, s.len());
        assert_eq!(first.frame, Some(s.clone()));
        assert_eq!(a.counts(), (0, 1, 0));
        assert_eq!(
            conn.feed(&both[first.consumed..]).unwrap(),
            Fed {
                consumed: ik.len(),
                frame: Some(ik.clone())
            }
        );
        // A complete frame followed by the start of the next: the suffix begins one frame.
        let mixed = [s.as_slice(), &ik[..9]].concat();
        assert_eq!(conn.feed(&mixed).unwrap().frame, Some(s.clone()));
        assert_eq!(a.counts(), (0, 1, 0));
        assert_eq!(
            conn.feed(&mixed[s.len()..]).unwrap(),
            Fed {
                consumed: 9,
                frame: None
            }
        );
        assert_eq!(a.counts(), (0, 1, 1));
        assert_eq!(conn.feed(&ik[9..]).unwrap().frame, Some(ik.clone()));
        // A long caller buffer yields one frame per call and is never queued internally.
        let stream: Vec<u8> = frames()
            .iter()
            .cycle()
            .take(100)
            .flatten()
            .copied()
            .collect();
        let mut rest = stream.as_slice();
        let mut out = Vec::new();
        while !rest.is_empty() {
            let fed = conn.feed(rest).unwrap();
            assert!(conn.partial.is_none());
            out.push(fed.frame.unwrap());
            rest = &rest[fed.consumed..];
        }
        assert_eq!((out.len(), out.concat()), (100, stream.clone()));
        // The same stream in arbitrary reads, each unconsumed suffix fed again.
        let mut out = Vec::new();
        for read in stream.chunks(50) {
            let mut rest = read;
            while !rest.is_empty() {
                let fed = conn.feed(rest).unwrap();
                assert!(fed.consumed > 0);
                out.extend(fed.frame);
                rest = &rest[fed.consumed..];
            }
        }
        assert_eq!((out.len(), out.concat()), (100, stream));
        assert_eq!(a.counts(), (0, 1, 0));
        drop(conn);
        drop(router);
        a.release();
    }

    #[test]
    fn empty_input_and_polls_never_start_or_refresh_a_frame() {
        let a = Authority::new("transport-empty-input");
        let router = a.router();
        let clock = ManualClock::new();
        let mut conn = connect(&router, &clock);
        let session = conn.session();
        assert_eq!(conn.feed(&[]).unwrap(), Fed::default());
        assert_eq!(conn.poll_frame_deadlines(), Ok(()));
        assert!(conn.partial.is_none());
        assert_eq!(a.counts(), (0, 1, 0));
        let ik = wire(&["INITIATOR_KEY"]);
        conn.feed(&ik[..4]).unwrap();
        clock.advance(Duration::from_secs(1));
        assert_eq!(conn.feed(&[]).unwrap(), Fed::default());
        assert_eq!(conn.poll_frame_deadlines(), Ok(()));
        clock.advance(Duration::from_secs(1) - NS);
        assert_eq!(conn.feed(&[]).unwrap(), Fed::default());
        assert_eq!(retained(&conn).unwrap().3, Duration::ZERO);
        clock.advance(NS);
        // Empty input enforces the deadline too.
        assert_eq!(conn.feed(&[]), Err(IdleTimeout));
        assert_closed(&router, session);
        assert_eq!(a.counts(), (0, 0, 0));
        assert_eq!(conn.feed(&ik), Err(Closed));
        drop(conn);
        drop(router);
        a.release();
    }

    #[test]
    fn the_idle_deadline_expires_at_exactly_two_seconds_without_progress() {
        let a = Authority::new("transport-idle");
        let router = a.router();
        let ik = wire(&["INITIATOR_KEY"]);
        let clock = ManualClock::new();
        let mut conn = connect(&router, &clock);
        conn.feed(&ik[..1]).unwrap();
        clock.advance(IDLE_READ_DEADLINE - NS);
        assert_eq!(conn.poll_frame_deadlines(), Ok(()));
        assert_eq!(conn.feed(&ik[1..2]).unwrap().consumed, 1);
        // Progress restarts only the idle deadline.
        let (_, _, started, progress) = retained(&conn).unwrap();
        assert_eq!(
            (started, progress),
            (Duration::ZERO, IDLE_READ_DEADLINE - NS)
        );
        clock.advance(IDLE_READ_DEADLINE - NS);
        assert_eq!(conn.poll_frame_deadlines(), Ok(()));
        clock.advance(NS);
        assert_eq!(conn.poll_frame_deadlines(), Err(IdleTimeout));
        assert_closed(&router, conn.session());
        assert_eq!(a.counts(), (0, 0, 0));
        // A byte arriving at exactly two seconds is too late and is not taken.
        let clock = ManualClock::new();
        drop(conn);

        let mut conn = connect(&router, &clock);
        conn.feed(&ik[..1]).unwrap();
        clock.advance(IDLE_READ_DEADLINE);
        assert_eq!(conn.feed(&ik[1..]), Err(IdleTimeout));
        assert!(conn.partial.is_none());
        assert_closed(&router, conn.session());
        assert_eq!(a.counts(), (0, 0, 0));
        drop(conn);
        drop(router);
        a.release();
    }

    #[test]
    fn the_whole_frame_deadline_is_fixed_at_ten_seconds_whatever_the_progress() {
        let a = Authority::new("transport-whole-frame");
        let router = a.router();
        let ik = wire(&["INITIATOR_KEY"]);
        // First byte at 0, progress every 1.9 s so idle never expires, then the rest at `at`.
        let finish_at = |at: Duration| {
            let clock = ManualClock::new();
            let mut conn = connect(&router, &clock);
            conn.feed(&ik[..1]).unwrap();
            for n in 1..=5 {
                clock.set(Duration::from_millis(1900 * n as u64));
                assert_eq!(conn.feed(&ik[n..n + 1]).unwrap().consumed, 1);
            }
            assert_eq!(retained(&conn).unwrap().2, Duration::ZERO);
            clock.set(at);
            let outcome = conn.feed(&ik[6..]);
            (outcome, conn.partial.is_none(), conn.ended)
        };
        let (completed, _, ended) = finish_at(WHOLE_FRAME_DEADLINE - NS);
        assert_eq!(completed.unwrap().frame, Some(ik.clone()));
        assert!(!ended);
        assert_eq!(
            finish_at(WHOLE_FRAME_DEADLINE),
            (Err(WholeFrameTimeout), true, true)
        );
        assert_eq!(a.counts(), (0, 0, 0));
        // With both deadlines expired at one poll the whole-frame diagnostic is reported; the
        // cleanup is the same.
        let clock = ManualClock::new();
        let mut conn = connect(&router, &clock);
        conn.feed(&ik[..1]).unwrap();
        clock.set(WHOLE_FRAME_DEADLINE);
        assert_eq!(conn.poll_frame_deadlines(), Err(WholeFrameTimeout));
        assert_closed(&router, conn.session());
        assert_eq!(a.counts(), (0, 0, 0));
        drop(conn);
        drop(router);
        a.release();
    }

    #[test]
    fn an_unusable_or_backwards_transport_clock_fails_the_connection_closed() {
        let a = Authority::new("transport-clock");
        let router = a.router();
        let ik = wire(&["INITIATOR_KEY"]);
        let five = Duration::from_secs(5);
        // Backwards while a frame is retained.
        let clock = ManualClock::new();
        clock.set(five);
        let mut conn = connect(&router, &clock);
        conn.feed(&ik[..3]).unwrap();
        clock.set(five - NS);
        assert_eq!(conn.feed(&ik[3..4]), Err(ClockUnavailable));
        assert_closed(&router, conn.session());
        assert_eq!(a.counts(), (0, 0, 0));
        // Unavailable at a poll.
        let clock = ManualClock::new();
        drop(conn);

        let mut conn = connect(&router, &clock);
        conn.feed(&ik[..3]).unwrap();
        clock.fail();
        assert_eq!(conn.poll_frame_deadlines(), Err(ClockUnavailable));
        assert_eq!(a.counts(), (0, 0, 0));
        // Unavailable when a frame would begin: nothing is retained and no slot is taken.
        let clock = ManualClock::new();
        drop(conn);

        let mut conn = connect(&router, &clock);
        clock.fail();
        assert_eq!(conn.feed(&ik[..3]), Err(ClockUnavailable));
        assert_eq!(a.counts(), (0, 0, 0));
        // A later frame cannot begin before a reading already taken for an earlier one.
        let clock = ManualClock::new();
        drop(conn);

        let mut conn = connect(&router, &clock);
        clock.set(five);
        conn.feed(&ik[..3]).unwrap();
        clock.set(five + MS);
        assert_eq!(conn.feed(&ik[3..]).unwrap().frame, Some(ik.clone()));
        clock.set(five - MS);
        assert_eq!(conn.feed(&ik[..3]), Err(ClockUnavailable));
        assert_eq!(a.counts(), (0, 0, 0));
        // A frame complete within one input has no timer and reads no clock.
        let clock = ManualClock::new();
        drop(conn);

        let mut conn = connect(&router, &clock);
        clock.fail();
        assert_eq!(conn.feed(&ik).unwrap().frame, Some(ik.clone()));
        assert_eq!(a.counts(), (0, 1, 0));
        drop(conn);
        drop(router);
        a.release();
    }

    #[test]
    fn a_declared_length_beyond_the_maximum_fails_before_its_payload_is_retained() {
        let a = Authority::new("transport-oversized");
        let router = a.router();
        let clock = ManualClock::new();
        let mut huge = b"SASPAIR\0\x01\x03".to_vec();
        huge.extend_from_slice(&u32::MAX.to_be_bytes());
        let mut conn = connect(&router, &clock);
        assert_eq!(conn.feed(&huge[..13]).unwrap().consumed, 13);
        let (len, capacity, ..) = retained(&conn).unwrap();
        assert!(len == 13 && capacity <= 14, "{len} {capacity}");
        assert_eq!(conn.feed(&huge[13..]), Err(FrameTooLarge));
        assert!(conn.partial.is_none());
        assert_closed(&router, conn.session());
        assert_eq!(a.counts(), (0, 0, 0));
        // The same declaration with plenty of payload in one caller buffer: nothing is copied.
        drop(conn);

        let mut conn = connect(&router, &clock);
        let claimed = [huge.as_slice(), &vec![0; 70_000]].concat();
        assert_eq!(conn.feed(&claimed), Err(FrameTooLarge));
        assert_eq!(a.counts(), (0, 0, 0));
        // A last declared length making the frame 65,537 bytes fails once that prefix is read.
        let over = frame(3, &[PROFILE_ID, &[7; 16], &vec![0; MAX_FRAME - 75]]);
        assert_eq!(over.len(), MAX_FRAME + 1);
        drop(conn);

        let mut conn = connect(&router, &clock);
        assert_eq!(conn.feed(&over[..75]).unwrap().consumed, 75);
        let (len, capacity, ..) = retained(&conn).unwrap();
        assert!(len == 75 && capacity <= 76, "{len} {capacity}");
        assert_eq!(conn.feed(&over[75..]), Err(FrameTooLarge));
        assert!(conn.partial.is_none());
        assert_eq!(a.counts(), (0, 0, 0));
        drop(conn);
        drop(router);
        a.release();
    }

    #[test]
    fn an_exact_maximum_frame_is_assembled_whole_or_in_pieces() {
        let a = Authority::new("transport-exact-max");
        let router = a.router();
        let clock = ManualClock::new();
        let at_max = frame(3, &[PROFILE_ID, &[7; 16], &vec![0xAB; MAX_FRAME - 76]]);
        assert_eq!(at_max.len(), MAX_FRAME);
        let mut conn = connect(&router, &clock);
        assert_eq!(
            conn.feed(&at_max).unwrap(),
            Fed {
                consumed: MAX_FRAME,
                frame: Some(at_max.clone())
            }
        );
        assert_eq!(a.counts(), (0, 1, 0));
        assert_eq!(conn.feed(&at_max[..100]).unwrap().consumed, 100);
        let (len, capacity, ..) = retained(&conn).unwrap();
        assert!(len == 100 && capacity <= MAX_FRAME, "{len} {capacity}");
        assert_eq!(
            conn.feed(&at_max[100..]).unwrap().frame,
            Some(at_max.clone())
        );
        assert_eq!(a.counts(), (0, 1, 0));
        // The outer frame is the assembler's concern; its fields are the codec's, later.
        assert!(protocol::route_fields(&at_max).is_ok());
        assert_eq!(
            protocol::decode(&at_max).unwrap_err(),
            CodecError::InvalidField("fixed_32")
        );
        drop(conn);
        drop(router);
        a.release();
    }

    #[test]
    fn a_bad_magic_version_or_type_closes_the_connection_as_soon_as_it_is_known() {
        let a = Authority::new("transport-bad-header");
        let router = a.router();
        let clock = ManualClock::new();
        let cases: [(&str, &[&[u8]]); 7] = [
            ("magic first byte", &[b"X"]),
            ("magic later byte", &[b"SAS", b"Q"]),
            ("version", &[b"SASPAIR\0", b"\x02"]),
            ("type 0", &[b"SASPAIR\0\x01\x00"]),
            ("type 10", &[b"SASPAIR\0\x01\x0a"]),
            ("bootstrap type", &[b"SASPAIR\0\x01", b"\x20"]),
            ("type 0xff", &[b"SASPAIR\0\x01\xff"]),
        ];
        for (name, reads) in cases {
            let mut conn = connect(&router, &clock);
            let (last, first) = reads.split_last().unwrap();
            for read in first {
                assert_eq!(conn.feed(read).unwrap().consumed, read.len(), "{name}");
            }
            assert_eq!(conn.feed(last), Err(InvalidFrame), "{name}");
            assert!(conn.partial.is_none(), "{name}");
            assert_closed(&router, conn.session());
            assert_eq!(a.counts(), (0, 0, 0), "{name}");
            assert_eq!(conn.feed(b"SASPAIR"), Err(Closed), "{name}");
        }
        assert_eq!((a.charged(), a.pending_responders()), ((4, 0), 0));
        assert_eq!(a.status(), Status::Ready { remaining: 10 });
        drop(router);
        a.release();
    }

    #[test]
    fn frames_reach_no_router_state_or_limiter_until_the_router_start_path() {
        let a = Authority::new("transport-no-router-state");
        let router = a.router();
        let clock = ManualClock::new();
        let mut conn = connect(&router, &clock);
        let session = conn.session();
        let start = wire(&["START"]);
        let request_id = protocol::route_fields(&start).unwrap().1.to_vec();
        conn.feed(&start[..start.len() - 1]).unwrap();
        // Partial bytes: no run, pending slot, permit, ephemeral, charge, or opportunity.
        assert_eq!(
            router
                .with_run(session, &request_id, |_| Ok(()))
                .unwrap_err(),
            RouteError::UnknownRoute
        );
        assert_eq!(
            (a.charged(), a.pending_responders(), a.permits()),
            ((4, 0), 0, 0)
        );
        // Completion alone changes nothing either; only the Router START path charges.
        let complete = conn.feed(&start[start.len() - 1..]).unwrap().frame.unwrap();
        assert_eq!(complete, start);
        assert_eq!((a.charged(), a.pending_responders()), ((4, 0), 0));
        admit(&router, session, &complete);
        assert_eq!((a.charged(), a.pending_responders()), ((3, 1), 1));
        // An outer-canonical START with a semantically invalid bootstrap is still one exact
        // complete frame; the unchanged Router path charges it, then rejects it semantically.
        let bad = frame(1, &[PROFILE_ID, &[5; 16], &[0xFF; 3]]);
        assert_eq!(reassemble(&mut conn, &bad, 4), bad);
        assert_eq!(a.charged(), (3, 1));
        assert_eq!(
            router.receive_start(session, &bad, responder_bootstrap(), None),
            Err(RouteError::Ceremony(CeremonyError::Codec(
                CodecError::Truncated
            )))
        );
        assert_eq!((a.charged(), a.pending_responders()), ((2, 2), 1));
        // A transport failure charges and refunds nothing.
        conn.feed(&start[..30]).unwrap();
        clock.advance(IDLE_READ_DEADLINE);
        assert_eq!(conn.poll_frame_deadlines(), Err(IdleTimeout));
        assert_eq!((a.charged(), a.pending_responders()), ((2, 2), 0));
        assert_eq!(a.status(), Status::Ready { remaining: 10 });
        drop(conn);
        drop(router);
        a.release();
    }

    #[test]
    fn poisoned_transport_accounting_fails_closed_and_keeps_every_count() {
        let a = Authority::new("transport-poison");
        let router = a.router();
        let clock = ManualClock::new();
        let ik = wire(&["INITIATOR_KEY"]);
        let mut partial = connect(&router, &clock);
        partial.feed(&ik[..5]).unwrap();
        let mut idle = connect(&router, &clock);
        let permit = AcceptPermit::begin(&router).unwrap();
        assert_eq!(a.counts(), (1, 2, 1));
        let executor = a.executor.clone();
        let _ = thread::spawn(move || {
            let _shared = executor.0.shared.lock().unwrap();
            panic!("simulate ambiguous transport accounting");
        })
        .join();
        assert_eq!(AcceptPermit::begin(&router).err(), Some(OwnershipUncertain));
        assert_eq!(
            permit.activate_with_clock(clock.clone()).err(),
            Some(OwnershipUncertain)
        );
        // No incomplete frame can start, and the failed connection's capacity stays held.
        assert_eq!(idle.feed(&ik[..5]), Err(OwnershipUncertain));
        assert_closed(&router, idle.session());
        assert_eq!(partial.close(), Err(OwnershipUncertain));
        assert_eq!(a.counts(), (1, 2, 1));
        assert_eq!(router.sessions_for_test(), 0);
        drop(idle);
        assert_eq!(a.counts(), (1, 2, 1));
        drop(router);
        a.release();
    }

    #[test]
    fn uncertain_router_teardown_keeps_the_live_count_held_for_good() {
        let a = Authority::new("transport-uncertain");
        let router = a.router();
        let clock = ManualClock::new();
        // Explicit close.
        let closed = connect(&router, &clock);
        admit(&router, closed.session(), &start(1));
        poison_run(&router, closed.session(), &[1; 16]);
        assert_eq!(closed.close(), Err(OwnershipUncertain));
        // Drop, which must not panic.
        let dropped = connect(&router, &clock);
        admit(&router, dropped.session(), &start(2));
        poison_run(&router, dropped.session(), &[2; 16]);
        drop(dropped);
        // A session-fatal routing failure whose own teardown was uncertain is not mistaken for
        // CLOSED by the transport.
        let mut fatal = connect(&router, &clock);
        let session = fatal.session();
        admit(&router, session, &start(3));
        poison_run(&router, session, &[3; 16]);
        assert_eq!(
            router
                .deliver(session, &initiator_key(&[0x77; 16]))
                .unwrap_err(),
            UNCERTAIN
        );
        assert_eq!(fatal.feed(&[]), Ok(Fed::default()));
        assert_eq!(fatal.close(), Err(OwnershipUncertain));
        assert_eq!(a.counts(), (0, 3, 0));
        // The authority's capacity is now 13 for the rest of this owner session.
        let rest: Vec<_> = (0..13).map(|_| connect(&router, &clock)).collect();
        let permit = AcceptPermit::begin(&router).unwrap();
        assert_eq!(
            permit.activate_with_clock(clock.clone()).err(),
            Some(ResourceLimited)
        );
        drop(rest);
        assert_eq!(a.counts(), (0, 3, 0));
        drop(router);
        a.release();
    }

    #[test]
    fn transport_close_waits_for_a_session_teardown_another_caller_began() {
        let a = Authority::new("transport-settled");
        let router = a.router();
        let clock = ManualClock::new();
        // Already CLOSED by a completed session-fatal routing failure: released at once.
        let first = connect(&router, &clock);
        admit(&router, first.session(), &start(1));
        assert_eq!(
            router
                .deliver(first.session(), &initiator_key(&[0x77; 16]))
                .unwrap_err(),
            RouteError::SessionProtocolFailure
        );
        assert_eq!(a.counts(), (0, 1, 0));
        assert_eq!(first.close(), Ok(()));
        assert_eq!((a.counts(), a.pending_responders()), ((0, 0, 0), 0));
        // In progress: the routing failure's teardown waits on an operation inside a run, and
        // the transport close waits for that teardown to end.
        let conn = connect(&router, &clock);
        let session = conn.session();
        admit(&router, session, &start(2));
        let (arrived_tx, arrived) = mpsc::channel();
        let (resume_tx, resume) = mpsc::channel::<()>();
        let (waiting_tx, waiting) = mpsc::channel();
        let (closed_tx, closed) = mpsc::channel();
        let shared_router = &router;
        thread::scope(|scope| {
            let router = shared_router;
            let op = scope.spawn(move || {
                router.with_run(session, &[2; 16], move |run| {
                    arrived_tx.send(()).unwrap();
                    resume.recv().unwrap();
                    Ok(run.state_label_for_test())
                })
            });
            arrived.recv().unwrap();
            let fatal = scope.spawn(move || {
                test_hook::install(move |point| {
                    if let Point::CloseWaiting { .. } = point {
                        waiting_tx.send(()).unwrap();
                    }
                });
                router.deliver(session, &initiator_key(&[0x77; 16]))
            });
            waiting.recv().unwrap();
            let close = scope.spawn(move || {
                test_hook::install(move |point| {
                    if point == Point::TransportSessionClosed {
                        closed_tx.send(()).unwrap();
                    }
                });
                conn.close()
            });
            // The teardown cannot end while the operation is inside the run.
            assert!(closed.try_recv().is_err());
            assert_eq!(a.counts(), (0, 1, 0));
            resume_tx.send(()).unwrap();
            assert!(op.join().unwrap().is_ok());
            assert_eq!(
                fatal.join().unwrap().unwrap_err(),
                RouteError::SessionProtocolFailure
            );
            assert_eq!(close.join().unwrap(), Ok(()));
            assert!(closed.try_recv().is_ok());
        });
        assert_eq!((a.counts(), a.pending_responders()), ((0, 0, 0), 0));
        assert_eq!(router.sessions_for_test(), 0);
        drop(router);
        a.release();
    }
}
