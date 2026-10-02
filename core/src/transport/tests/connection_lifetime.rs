//! P6-D-001 connection lifetime (remediation of P5-F-002): the transition table, the first-frame
//! and quiescent deadlines at their exact boundaries, the hand-over to the frame deadlines, the
//! live-slot release, and the activity that must never extend a connection. Hand clocks only.
use super::*;
use crate::deadline::{ManualClock, PENDING_PRE_EXPOSURE_DEADLINE};

const S: Duration = Duration::from_secs(1);

/// An authority whose four START tokens are spent, so every later START is a cheap, uncharged,
/// run-local refusal: a complete frame that creates no live run.
fn drained(scope: &str) -> Authority {
    let a = Authority::new(scope);
    let router = a.router();
    let clock = ManualClock::new();
    let conn = connect(&router, &clock);
    for id in 0..4 {
        admit(&router, conn.session(), &start(0xD0 + id));
    }
    drop(conn);
    drop(router);
    assert_eq!((a.charged(), a.counts()), ((0, 4), (0, 0, 0)));
    a
}

fn refused_start(router: &Router, session: SessionHandle, id: u8) {
    assert_eq!(
        router.receive_start(session, &start(id), responder_bootstrap(), None),
        Err(RouteError::Ceremony(CeremonyError::Owner(
            OwnerError::ResourceLimited
        )))
    );
}

#[test]
fn lifetime_transitions_move_an_origin_only_when_what_is_held_changes() {
    use Lifetime::*;
    use OutboundState::{Empty, Retained};
    let (t0, t1) = (3 * S, 7 * S);
    let first = FirstFrame { since: t0 };
    let quiet = Quiescent { since: t0 };
    let output = OwnerlessOutput {
        since: t0,
        progress: t0,
    };
    // (from, live run, outbound) -> state at t1.
    let table = [
        (first, false, Empty, first),
        (quiet, false, Empty, quiet),
        (LiveRun, false, Empty, Quiescent { since: t1 }),
        (output, false, Empty, Quiescent { since: t1 }),
        (output, false, Retained, output),
        (
            first,
            false,
            Retained,
            OwnerlessOutput {
                since: t1,
                progress: t1,
            },
        ),
        (
            LiveRun,
            false,
            Retained,
            OwnerlessOutput {
                since: t1,
                progress: t1,
            },
        ),
    ];
    for (from, live_run, outbound, to) in table {
        assert_eq!(from.settle(t1, live_run, outbound), to, "{from:?}");
    }
    for from in [first, quiet, LiveRun, output] {
        for outbound in [Empty, Retained] {
            assert_eq!(
                from.settle(t1, true, outbound),
                LiveRun,
                "a live run governs"
            );
        }
    }
    // The first frame changes the name, never the origin.
    assert_eq!(first.frame_begun(), quiet);
    for other in [quiet, LiveRun, output] {
        assert_eq!(other.frame_begun(), other);
    }
    // Expiry is `elapsed >= deadline`; a live run has no connection deadline at all.
    for (state, deadline, error) in [
        (first, FIRST_FRAME_DEADLINE, FirstFrameTimeout),
        (quiet, QUIESCENT_DEADLINE, QuiescentTimeout),
        (
            output,
            RETAINED_OUTPUT_IDLE_DEADLINE,
            RetainedOutputIdleTimeout,
        ),
    ] {
        assert_eq!(state.check(t0 + deadline - NS), Ok(()));
        assert_eq!(state.check(t0 + deadline), Err(error));
        assert_eq!(state.check(t0 + deadline + NS), Err(error));
    }
    let progressed = OwnerlessOutput {
        since: t0,
        progress: t0 + 9 * S,
    };
    assert_eq!(progressed.check(t0 + RETAINED_OUTPUT_DEADLINE - NS), Ok(()));
    assert_eq!(
        progressed.check(t0 + RETAINED_OUTPUT_DEADLINE),
        Err(RetainedOutputTimeout)
    );
    assert_eq!(LiveRun.check(Duration::MAX), Ok(()));
    assert_eq!(quiet.check(t0 - NS), Err(ClockUnavailable));
}

#[test]
fn frameless_connection_expires_at_the_first_frame_deadline() {
    let a = Authority::new("lifetime-first-frame");
    let router = a.router();
    for (offset, via_feed) in [(-1i8, false), (0, false), (1, false), (0, true)] {
        let clock = ManualClock::new();
        clock.set(5 * S);
        let mut conn = connect(&router, &clock);
        let session = conn.session();
        // Polls before the boundary observe and refresh nothing.
        for at in [5 * S, 9 * S, 14 * S] {
            clock.set(at);
            assert_eq!(conn.poll_connection_deadlines(OutboundState::Empty), Ok(()));
            assert_eq!(conn.feed(&[]), Ok(Fed::default()));
        }
        let deadline = 5 * S + FIRST_FRAME_DEADLINE;
        clock.set(match offset {
            -1 => deadline - NS,
            0 => deadline,
            _ => deadline + NS,
        });
        let outcome = if via_feed {
            conn.feed(&start(1)).map(drop)
        } else {
            conn.poll_connection_deadlines(OutboundState::Empty)
        };
        if offset < 0 {
            assert_eq!(outcome, Ok(()));
            assert_open(&router, session);
            assert_eq!(a.counts(), (0, 1, 0));
        } else {
            // At the deadline even a complete frame is not taken: teardown wins.
            assert_eq!(outcome, Err(FirstFrameTimeout), "{offset} {via_feed}");
            assert!(conn.is_closed());
            assert_closed(&router, session);
            assert_eq!(a.counts(), (0, 0, 0));
            // Released exactly once: nothing more is done, dropping changes nothing.
            assert_eq!(
                conn.poll_connection_deadlines(OutboundState::Empty),
                Err(Closed)
            );
            assert_eq!(conn.feed(&start(1)), Err(Closed));
        }
        drop(conn);
        assert_eq!(a.counts(), (0, 0, 0));
    }
    assert_eq!(
        (a.charged(), a.status()),
        ((4, 0), Status::Ready { remaining: 10 })
    );
    drop(router);
    a.release();
}

#[test]
fn a_first_byte_before_the_deadline_hands_over_to_the_unchanged_frame_deadlines() {
    let a = Authority::new("lifetime-first-byte");
    let router = a.router();
    let frame = start(2);
    let first = FIRST_FRAME_DEADLINE - NS;
    // Whole frame: progress every 1.5 s keeps the 2 s deadline away; 10 s from the first byte.
    for offset in [-1i8, 0] {
        let clock = ManualClock::new();
        let mut conn = connect(&router, &clock);
        clock.set(first);
        assert_eq!(conn.feed(&frame[..10]).unwrap().consumed, 10);
        assert_eq!(retained(&conn).map(|r| (r.2, r.3)), Some((first, first)));
        for n in 1..=6usize {
            let at = first + MS * (1500 * n as u32);
            clock.set(at);
            assert_eq!(conn.feed(&frame[n * 10..n * 10 + 10]).unwrap().consumed, 10);
            // Long past the first-frame deadline: the frame's own deadlines govern.
            assert_eq!(conn.poll_connection_deadlines(OutboundState::Empty), Ok(()));
        }
        clock.set(first + WHOLE_FRAME_DEADLINE - NS + NS * u32::from(offset == 0));
        let outcome = conn.poll_connection_deadlines(OutboundState::Empty);
        if offset < 0 {
            assert_eq!(outcome, Ok(()));
            assert_eq!(conn.feed(&frame[70..]).unwrap().frame, Some(frame.clone()));
        } else {
            assert_eq!(outcome, Err(WholeFrameTimeout));
        }
        drop(conn);
    }
    // No progress: 2 s from the first byte, exactly as before P6.
    for offset in [-1i8, 0] {
        let clock = ManualClock::new();
        let mut conn = connect(&router, &clock);
        clock.set(first);
        conn.feed(&frame[..10]).unwrap();
        clock.set(first + IDLE_READ_DEADLINE - NS + NS * u32::from(offset == 0));
        let outcome = conn.poll_connection_deadlines(OutboundState::Empty);
        assert_eq!(outcome, if offset < 0 { Ok(()) } else { Err(IdleTimeout) });
        drop(conn);
    }
    assert_eq!(a.counts(), (0, 0, 0));
    drop(router);
    a.release();
}

/// The P5-F-002 known-bug scenario as a regression: 16 silent peers hold the cap only until
/// the first-frame deadline, after which a new connection is admitted.
#[test]
fn sixteen_frameless_connections_release_the_live_cap_at_the_first_frame_deadline() {
    let a = Authority::new("lifetime-sixteen");
    let router = a.router();
    let clock = ManualClock::new();
    let mut conns: Vec<_> = (0..16).map(|_| connect(&router, &clock)).collect();
    let refused = |a: &Authority| {
        let permit = AcceptPermit::begin(&router).unwrap();
        assert_eq!(
            permit.activate_with_clock(clock.clone()).err(),
            Some(ResourceLimited)
        );
        assert_eq!(a.counts(), (0, 16, 0));
    };
    refused(&a);
    clock.set(FIRST_FRAME_DEADLINE - NS);
    for conn in &mut conns {
        assert_eq!(conn.poll_connection_deadlines(OutboundState::Empty), Ok(()));
    }
    refused(&a);
    clock.set(FIRST_FRAME_DEADLINE);
    for conn in &mut conns {
        assert_eq!(
            conn.poll_connection_deadlines(OutboundState::Empty),
            Err(FirstFrameTimeout)
        );
    }
    assert_eq!(a.counts(), (0, 0, 0));
    assert_eq!(router.sessions_for_test(), 0);
    let next = connect(&router, &clock);
    assert_eq!(a.counts(), (0, 1, 0));
    drop((next, conns));
    assert_eq!(a.counts(), (0, 0, 0));
    assert_eq!(
        (a.charged(), a.status()),
        ((4, 0), Status::Ready { remaining: 10 })
    );
    drop(router);
    a.release();
}

#[test]
fn quiescent_connection_releases_its_live_slot_at_the_deadline() {
    let a = Authority::new("lifetime-quiescent");
    let router = a.router();
    let (clock, ceremony) = (ManualClock::new(), ManualClock::new());
    let mut conn = connect(&router, &clock);
    let session = conn.session();
    let admitted = |id: u8| {
        let routed = router.receive_start_with_clock(
            ceremony.clone(),
            session,
            &start(id),
            responder_bootstrap(),
            None,
        );
        assert!(matches!(routed, Ok(StartRouting::Accepted(_))));
    };
    admitted(1);
    // A live run governs: no connection timer, however long the transport clock runs.
    clock.set(Duration::from_secs(3600));
    assert_eq!(conn.poll_connection_deadlines(OutboundState::Empty), Ok(()));
    // The run ends by its own pending lifetime; the next evaluation starts the quiescent wait.
    ceremony.advance(PENDING_PRE_EXPOSURE_DEADLINE);
    let mut cursor = Default::default();
    let ended = router.poll_session_deadlines(session, &mut cursor).unwrap();
    assert!(ended.event.is_some());
    let quiet = Duration::from_secs(4000);
    clock.set(quiet);
    assert_eq!(conn.poll_connection_deadlines(OutboundState::Empty), Ok(()));
    // Reuse before expiry: a new run governs again, past the old deadline.
    clock.set(quiet + QUIESCENT_DEADLINE - NS);
    admitted(2);
    clock.set(quiet + 5 * QUIESCENT_DEADLINE);
    assert_eq!(conn.poll_connection_deadlines(OutboundState::Empty), Ok(()));
    assert_open(&router, session);
    // That run ends too: a fresh quiescent wait from its observation, exact at the boundary.
    ceremony.advance(PENDING_PRE_EXPOSURE_DEADLINE);
    assert!(
        router
            .poll_session_deadlines(session, &mut cursor)
            .unwrap()
            .event
            .is_some()
    );
    let quiet = quiet + 6 * QUIESCENT_DEADLINE;
    clock.set(quiet);
    assert_eq!(conn.poll_connection_deadlines(OutboundState::Empty), Ok(()));
    clock.set(quiet + QUIESCENT_DEADLINE - NS);
    assert_eq!(conn.poll_connection_deadlines(OutboundState::Empty), Ok(()));
    assert_eq!(a.counts(), (0, 1, 0));
    clock.set(quiet + QUIESCENT_DEADLINE);
    assert_eq!(
        conn.poll_connection_deadlines(OutboundState::Empty),
        Err(QuiescentTimeout)
    );
    assert_closed(&router, session);
    assert_eq!((a.counts(), a.pending_responders()), ((0, 0, 0), 0));
    drop(conn);
    assert_eq!(a.counts(), (0, 0, 0));
    assert_eq!(a.status(), Status::Ready { remaining: 10 });
    drop(router);
    a.release();
}

/// Frames that create no live run, partial frames in between, polls, and empty input never
/// move the no-run origin: the connection ends at activation + 10 s whatever the peer sends.
#[test]
fn frames_that_create_no_live_run_never_extend_the_connection() {
    let a = drained("lifetime-no-live-work");
    let router = a.router();
    let clock = ManualClock::new();
    let mut conn = connect(&router, &clock);
    let session = conn.session();
    // Cycle complete refused STARTs and partial frames, each well inside its own deadlines.
    for (n, at) in (0..6u8).map(|n| (n, u32::from(n) * 1500 * MS)) {
        clock.set(at);
        if n % 2 == 0 {
            let frame = conn.feed(&start(n)).unwrap().frame.unwrap();
            assert_eq!(frame, start(n));
            refused_start(&router, session, n);
        } else {
            let frame = start(n);
            conn.feed(&frame[..20]).unwrap();
            clock.set(at + 1000 * MS);
            let done = conn.feed(&frame[20..]).unwrap().frame.unwrap();
            assert_eq!(done, frame);
            refused_start(&router, session, n);
        }
        assert_eq!(conn.feed(&[]), Ok(Fed::default()));
        assert_eq!(conn.poll_connection_deadlines(OutboundState::Empty), Ok(()));
    }
    // A partial frame begun before the deadline keeps its own window past it ...
    clock.set(QUIESCENT_DEADLINE - NS);
    let frame = start(9);
    conn.feed(&frame[..20]).unwrap();
    clock.set(QUIESCENT_DEADLINE + S);
    assert_eq!(conn.poll_connection_deadlines(OutboundState::Empty), Ok(()));
    assert_eq!(conn.feed(&frame[20..]).unwrap().frame, Some(frame));
    refused_start(&router, session, 9);
    // ... but once it created no live run the earlier origin applies at once.
    assert_eq!(
        conn.poll_connection_deadlines(OutboundState::Empty),
        Err(QuiescentTimeout)
    );
    assert_closed(&router, session);
    assert_eq!(a.counts(), (0, 0, 0));
    assert_eq!(
        (a.charged(), a.status()),
        ((0, 4), Status::Ready { remaining: 10 })
    );
    drop(conn);
    drop(router);
    a.release();
}

#[test]
fn a_no_run_connection_with_a_backwards_or_failed_clock_fails_closed() {
    let a = Authority::new("lifetime-clock");
    let router = a.router();
    for fault in ["backwards", "failed"] {
        let clock = ManualClock::new();
        clock.set(5 * S);
        let mut conn = connect(&router, &clock);
        assert_eq!(conn.poll_connection_deadlines(OutboundState::Empty), Ok(()));
        match fault {
            "backwards" => clock.set(5 * S - NS),
            _ => clock.fail(),
        }
        assert_eq!(
            conn.poll_connection_deadlines(OutboundState::Empty),
            Err(ClockUnavailable),
            "{fault}"
        );
        assert_closed(&router, conn.session());
        assert_eq!(a.counts(), (0, 0, 0));
    }
    // With no usable clock at activation nothing becomes live.
    let clock = ManualClock::new();
    clock.fail();
    let permit = AcceptPermit::begin(&router).unwrap();
    assert_eq!(
        permit.activate_with_clock(clock).err(),
        Some(ClockUnavailable)
    );
    assert_eq!((a.counts(), router.sessions_for_test()), ((0, 0, 0), 0));
    drop(router);
    a.release();
}
