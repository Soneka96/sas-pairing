//! P5.3 review-only evidence (NOT part of the product; changes no production behavior):
//! P5-F-005, an OS entropy failure inside vodozemac `Sas::new()` escaping the experimental
//! owner loop's `drive_once` and local actions, and what the loop does next. Families
//! `F005-004..005` in `docs/p5-security-review/dependency-unsafe-deep-review.md`.
//!
//! The panic is injected with the existing P4 pause points immediately before
//! `EphemeralSas::new()`. PASSING EVIDENCE TESTS: they assert the security properties that
//! must hold and record the availability effects without asserting them as desirable.
use super::*;
use crate::test_hook::{self, Point};
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

/// `F005-004`. A loop-hosted Responder admission panics inside `drive_once`. The panic escapes
/// the loop, which stays open with its connection live. The next drive feeds the START the
/// adapter still retains again, which is an ignored duplicate of the orphan claim. Closing the
/// loop releases everything.
#[test]
fn p5_f005_004_owner_loop_responder_panic_escapes_drive_once_and_replays_as_duplicate() {
    let r = Node::new("p5-f005-004");
    let (tc, cc, _) = clocks();
    let (mut owner, net) = hosting(&r, &tc, &cc);
    let (conn, sock) = accept(&mut owner, &net);
    let id = [0x71; 16];
    sock.data(&start(&id));
    fail_at(Point::ResponderAdmitted);
    let caught = catch_unwind(AssertUnwindSafe(|| try_drive(&mut owner, &net)));
    no_fault();
    assert!(caught.is_err(), "the panic escapes drive_once");
    assert!(!owner.is_closed() && owner.is_listening());
    assert_eq!(owner.live_connections(), 1);
    assert_eq!(r.counts(), (0, 1, 0, 0));
    assert_eq!((r.charged(), r.routes()), ((3, 1), 1));
    assert_eq!(r.status(), Status::Ready { remaining: 10 });
    let (event, run) = inbound(step_of(drive(&mut owner, &net), conn));
    assert_eq!((event, run), (HostEvent::StartDuplicate, None));
    assert!(sock.wire().is_empty(), "no ACCEPT was ever written");
    assert_eq!(r.charged(), (3, 1));
    assert_eq!(owner.close(), Ok(()));
    assert_eq!(r.counts(), (0, 0, 0, 0));
    assert_eq!((r.routes(), r.sessions()), (0, 0));
}

/// `F005-005`. A loop-hosted Initiator's exposure panics inside `WindowsOwnerLoop::expose_key`.
/// The panic escapes the local action with the run poisoned. The next `drive_once` sweep finds
/// the poisoned run uncertain, and the loop fails its whole hosting context closed (listener
/// dropped, every connection closed). The guard is released when the detached run drops, and
/// the opportunity stays consumed, but the connection's live slot and its CLOSING Router
/// session remain held after the loop is gone.
#[test]
fn p5_f005_005_owner_loop_initiator_panic_then_the_loop_fails_closed() {
    let (i, r) = (Node::new("p5-f005-005-i"), Node::new("p5-f005-005-r"));
    let (tc, cc, _) = clocks();
    let (mut owner, net) = hosting(&i, &tc, &cc);
    let mut p = Pair::accept(&mut owner, &net, &r);
    let run = acted_loop(owner.start_initiator_with(
        p.conn,
        ManualClock::new(),
        &mut OneId(Some([0x72; 16])),
        initiator_bootstrap(),
        None,
    ))
    .run
    .unwrap();
    assert_eq!(
        inbound(p.loop_to_peer(&mut owner, &net)).0,
        HostEvent::StartAccepted
    );
    assert_eq!(
        inbound(p.peer_to_loop(&mut owner, &net)).0,
        HostEvent::Accept
    );
    acted_loop(owner.authorize_exposure(p.conn, &run, &i.trusted));
    fail_at(Point::InitiatorReserved);
    let caught = catch_unwind(AssertUnwindSafe(|| owner.expose_key(p.conn, &run)));
    no_fault();
    assert!(caught.is_err(), "the panic escapes the loop's expose_key");
    assert!(!owner.is_closed());
    assert_eq!((i.status(), i.remaining()), (Status::Busy, 9));
    assert_eq!((i.routes(), i.sessions(), i.reserved()), (1, 1, 1));
    let step = try_drive(&mut owner, &net).unwrap();
    assert!(step.events.is_empty());
    assert_eq!(step.failure, Some(OwnerLoopError::OwnershipUncertain));
    assert!(owner.is_closed() && !owner.is_listening());
    assert_eq!(owner.live_connections(), 0);
    assert!(p.sock.wire().is_empty(), "INITIATOR_KEY never existed");
    assert_eq!(
        try_drive(&mut owner, &net).unwrap_err(),
        OwnerLoopError::Closed
    );
    // Accounting: consumed opportunity, guard and reservation released by the run's drop.
    assert_eq!(i.status(), Status::Ready { remaining: 9 });
    assert_eq!((i.routes(), i.reserved()), (0, 0));
    // Availability residue: one live slot and one CLOSING session stay held.
    assert_eq!(i.counts(), (0, 1, 0, 0));
    assert_eq!(i.sessions(), 1);
    drop(owner);
    assert_eq!(i.counts(), (0, 1, 0, 0), "held past the loop's drop");
    // The peer Responder is untouched: still pending, bounded by its own deadlines.
    assert_eq!(r.counts(), (0, 1, 0, 1));
    assert_eq!(r.status(), Status::Ready { remaining: 10 });
}
