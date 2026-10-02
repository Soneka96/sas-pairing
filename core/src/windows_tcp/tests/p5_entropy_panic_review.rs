//! P5.3 review-only evidence (NOT part of the product; changes no production behavior):
//! P5-F-005, an OS entropy failure inside vodozemac `Sas::new()` (rand `ThreadRng` seeding or
//! reseeding panics) unwinding through the Router and the Windows TCP adapter. Families
//! `F005-001..003` in `docs/p5-security-review/dependency-unsafe-deep-review.md`.
//!
//! The panic is injected with the existing P4 test pause points, which fire immediately before
//! `EphemeralSas::new()` with nothing in between (`ceremony.rs`, `ResponderAdmitted` and
//! `InitiatorReserved`), so the unwind starts exactly where the real one would. Each test
//! catches the unwind the way a careless caller could, then records the surviving state and
//! what the next operation does. These are PASSING EVIDENCE TESTS: they characterize current
//! behavior, assert the security properties that must hold (no output, no result, no refund,
//! no reuse), and record the availability effects without asserting them as desirable.
use super::*;
use crate::{
    router::StartRouting,
    test_hook::{self, Point},
};
use std::panic::{AssertUnwindSafe, catch_unwind};

/// The next ephemeral generation at `target` on this thread panics like a failed entropy seed.
fn fail_at(target: Point) {
    test_hook::install(move |point| {
        if point == target {
            panic!("P5-F-005 simulated OS entropy failure inside Sas::new()");
        }
    });
}
fn no_fault() {
    test_hook::install(|_| {});
}
/// The adapter's report when its Router session cannot be torn down with certainty.
fn uncertain<T>() -> Result<T, TcpError> {
    Err(TcpError::Host(HostError::Transport(
        TransportError::OwnershipUncertain,
    )))
}

/// `F005-001`. Responder admission through the Router. The START claimed its key, was charged
/// by the limiter, took a permit and a pending slot, and then generation panicked.
#[test]
fn p5_f005_001_router_responder_admission_panic_leaves_only_an_orphan_claim() {
    let r = Node::new("p5-f005-001");
    let s = r.router.open_session().unwrap();
    let id = [0x51; 16];
    fail_at(Point::ResponderAdmitted);
    let caught = catch_unwind(AssertUnwindSafe(|| {
        r.router
            .receive_start(s, &start(&id), responder_bootstrap(), None)
    }));
    no_fault();
    assert!(caught.is_err(), "the panic escapes Router::receive_start");
    // Security state: no ACCEPT, no contribution, no opportunity, no guard; the permit and the
    // pending slot unwound with the admission; the limiter charge is kept (never refunded).
    assert_eq!(r.counts(), (0, 0, 0, 0));
    assert_eq!(r.status(), Status::Ready { remaining: 10 });
    assert_eq!(r.charged(), (3, 1));
    // Router state: the `Admitting` claim for (session, request ID) survives the unwind.
    assert_eq!((r.routes(), r.sessions()), (1, 1));
    // An exact copy of the START is an ignored duplicate: no admission, charge, or output.
    assert_eq!(
        r.router
            .receive_start(s, &start(&id), responder_bootstrap(), None),
        Ok(StartRouting::Duplicate)
    );
    assert_eq!(r.charged(), (3, 1));
    // A later frame for that key is out of order for that key only (run-local); it marks the
    // claim conflicted, after which the same START is refused too. Nothing is ever accepted.
    let bad = RouteError::Ceremony(CeremonyError::InvalidState);
    assert_eq!(r.router.deliver(s, &initiator_key(&id)).unwrap_err(), bad);
    assert_eq!(
        r.router
            .receive_start(s, &start(&id), responder_bootstrap(), None),
        Err(bad)
    );
    // Other keys on the same session are unaffected.
    assert!(matches!(
        r.router
            .receive_start(s, &start(&[0x52; 16]), responder_bootstrap(), None),
        Ok(StartRouting::Accepted(_))
    ));
    assert_eq!(r.routes(), 2);
    // Session teardown removes the orphan claim with everything else: nothing persists.
    assert_eq!(r.router.close_session(s), Ok(()));
    assert_eq!((r.routes(), r.sessions()), (0, 0));
    assert_eq!(r.counts(), (0, 0, 0, 0));
    assert_eq!(r.status(), Status::Ready { remaining: 10 });
    r.release();
}

/// `F005-002`. The same panic reached from a socket read through the TCP adapter. The adapter
/// had not yet advanced its retained input past the START, so the next `on_readable` feeds the
/// same bytes again; the orphan claim turns that into an ignored duplicate. Closing releases
/// everything.
#[test]
fn p5_f005_002_adapter_responder_admission_panic_replays_as_a_duplicate() {
    let r = Node::new("p5-f005-002");
    let (tc, cc, _) = clocks();
    let (mut tcp, io) = r.connect(&tc, &cc);
    let id = [0x53; 16];
    io.data(&start(&id));
    fail_at(Point::ResponderAdmitted);
    let caught = catch_unwind(AssertUnwindSafe(|| tcp.on_readable()));
    no_fault();
    assert!(caught.is_err(), "the panic escapes on_readable");
    assert!(!tcp.is_closed() && !tcp.write_pending() && io.wire().is_empty());
    assert!(
        tcp.input_buffered(),
        "the START is still retained as unread input"
    );
    assert_eq!(r.counts(), (0, 1, 0, 0));
    assert_eq!(r.status(), Status::Ready { remaining: 10 });
    assert_eq!((r.charged(), r.routes()), ((3, 1), 1));
    let (event, run) = inbound(tcp.on_readable().unwrap());
    assert_eq!((event, run), (HostEvent::StartDuplicate, None));
    assert!(!tcp.input_buffered() && io.wire().is_empty());
    assert_eq!(r.charged(), (3, 1));
    assert_eq!(tcp.close(), Ok(()));
    assert_eq!(r.counts(), (0, 0, 0, 0));
    assert_eq!((r.routes(), r.sessions()), (0, 0));
    drop(tcp);
    r.release();
}

/// What the owner does after catching the Initiator's exposure panic.
#[derive(Clone, Copy, Debug)]
enum Next {
    Presentation,
    DeadlinePoll,
    InboundFrame,
    Close,
}

/// `F005-003`. Initiator exposure through the TCP adapter: authorized, guard and opportunity
/// reserved, then generation panicked while the Router held the run's lock, poisoning it.
/// Whatever the owner does next, the poisoned run is uncertain: the adapter ends, the run is
/// detached and dropped (so its guard and request-ID reservation are released by `Drop`), the
/// consumed opportunity stays consumed, but the Router session stays CLOSING and the
/// authority-wide live-connection count stays held.
#[test]
fn p5_f005_003_adapter_initiator_exposure_panic_poisons_the_run() {
    for next in [
        Next::Presentation,
        Next::DeadlinePoll,
        Next::InboundFrame,
        Next::Close,
    ] {
        let (i, r) = (Node::new("p5-f005-003-i"), Node::new("p5-f005-003-r"));
        let (tc, ci, cr) = clocks();
        let mut x = Sides::new(&i, &r, &tc, &ci, &cr);
        let run = x.open(&ci, [0x61; 16]);
        acted(x.i.authorize_exposure(&run.i, &i.trusted));
        fail_at(Point::InitiatorReserved);
        let caught = catch_unwind(AssertUnwindSafe(|| x.i.expose_key(&run.i)));
        no_fault();
        assert!(caught.is_err(), "{next:?}: the panic escapes expose_key");
        // Immediately after: nothing exposed or written, the opportunity consumed (no refund),
        // the guard and request-ID reservation still held by the poisoned run, adapter open.
        assert!(!x.i.is_closed() && !x.i.write_pending() && x.iio.wire().is_empty());
        assert_eq!((i.status(), i.remaining()), (Status::Busy, 9), "{next:?}");
        assert_eq!((i.routes(), i.sessions(), i.reserved()), (1, 1, 1));
        assert_eq!(i.counts(), (0, 1, 0, 0));
        match next {
            Next::Presentation => assert_eq!(x.i.presentation(&run.i), uncertain()),
            Next::DeadlinePoll => assert_eq!(x.i.poll_ceremony_deadlines(), uncertain()),
            Next::InboundFrame => {
                // Any routable frame for that key reaches the poisoned run.
                x.iio.data(&initiator_key(&run.id));
                assert_eq!(x.i.on_readable(), uncertain());
            }
            Next::Close => assert_eq!(x.i.close(), uncertain()),
        }
        // After the next operation: the adapter ended; the run was detached and dropped, which
        // released the guard and reservation; no refund; no result or output ever existed.
        assert!(x.i.is_closed() && x.iio.wire().is_empty(), "{next:?}");
        assert_eq!(i.status(), Status::Ready { remaining: 9 }, "{next:?}");
        assert_eq!((i.routes(), i.reserved()), (0, 0), "{next:?}");
        // Availability residue: the session stays CLOSING and the live slot stays held.
        assert_eq!(i.sessions(), 1, "{next:?}");
        assert_eq!(i.counts(), (0, 1, 0, 0), "{next:?}");
        assert_eq!(x.i.presentation(&run.i), Err(TcpError::Closed));
        // The peer Responder is untouched: still pending, bounded by its own deadlines.
        assert_eq!(r.counts(), (0, 1, 0, 1));
        assert_eq!(r.status(), Status::Ready { remaining: 10 });
        drop(x);
        assert_eq!(
            i.counts(),
            (0, 1, 0, 0),
            "{next:?}: held past the adapter's drop"
        );
        assert_eq!(i.status(), Status::Ready { remaining: 9 });
    }
}
