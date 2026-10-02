//! P5.2 review-only evidence (NOT part of the product; changes no production behavior):
//! bounded deterministic Router concurrency stress. Families `ROUTER-RACE-001..008` in
//! `docs/p5-security-review/adversarial-sequences.md`.
//!
//! Each scenario runs repeatedly in two ways: forced interleavings (the existing per-thread
//! test pause points, channel hand-offs, and exact-state waits; never a sleep), and barrier-
//! released races whose interleaving varies but whose invariants must hold for every outcome.
//! Every hand-off waits at most `HANG` and fails the test instead of hanging.
use super::*;
use std::sync::mpsc::RecvTimeoutError;

/// Forced-order and barrier-race iterations of scenarios without key generation.
const ITERATIONS: usize = 100;
/// Iterations of scenarios that generate keys (each costs milliseconds in the unoptimized
/// test profile).
const CRYPTO_ITERATIONS: usize = 25;

/// `default` iterations, or `P5_RACE_ITERATIONS` for a deeper manual run, e.g.
/// `P5_RACE_ITERATIONS=1000 cargo test --manifest-path core/Cargo.toml --lib p5_router_race`.
fn iterations(default: usize) -> usize {
    std::env::var("P5_RACE_ITERATIONS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}
/// A hand-off that takes longer than this is a deadlock.
const HANG: Duration = Duration::from_secs(10);

fn arrive(arrival: &Receiver<()>, what: &str) {
    match arrival.recv_timeout(HANG) {
        Ok(()) => {}
        Err(RecvTimeoutError::Timeout) => panic!("deadlock: {what} never arrived"),
        Err(RecvTimeoutError::Disconnected) => panic!("{what}: thread ended early"),
    }
}

/// `(routes, pending Responders, preliminary permits, Initiator reservations)` all zero.
fn assert_released(node: &Node, what: &str) {
    assert_eq!(node.resources(), (0, 0, 0, 0), "{what}: leaked resources");
}

/// The run's `Arc` count as held by the table plus every other holder.
fn holders(node: &Node, session: SessionHandle, id: &[u8]) -> Option<usize> {
    let key = RoutingKey {
        session,
        request_id: id.to_vec(),
    };
    match node.router.table.lock().unwrap().routes.get(&key) {
        Some(Route::Active(run)) => Some(Arc::strong_count(run)),
        _ => None,
    }
}

/// Waits (yielding, never sleeping) until `ready()` holds, failing after `HANG`.
fn wait_until(what: &str, mut ready: impl FnMut() -> bool) {
    let give_up = std::time::Instant::now() + HANG;
    while !ready() {
        assert!(std::time::Instant::now() < give_up, "deadlock: {what}");
        thread::yield_now();
    }
}

/// A local Initiator on `session` (no key generation: it is pre-exposure) with the ceremony
/// clock `clock`; returns its exact run reference.
fn initiator(
    node: &Node,
    session: SessionHandle,
    clock: &Arc<ManualClock>,
    id: [u8; 16],
) -> RunRef {
    node.router
        .start_initiator_run(
            clock.clone(),
            &mut script([id]),
            session,
            initiator_bootstrap(),
            None,
        )
        .unwrap()
        .0
}

/// ROUTER-RACE-001: session close versus inbound delivery to an installed run. Forced: the
/// delivery's run operation is in progress when close begins (close waits, the operation keeps
/// its outcome, then the run is terminated). Race: deliver and close released together; the
/// delivery either entered first (its outcome stands, then close terminates the run) or is
/// refused as `UnknownSession`; nothing leaks either way.
#[test]
fn p5_router_race_001_close_versus_deliver() {
    let r = Node::new("p5-race-001");
    let mut orders = [0usize; 2];
    let rounds = iterations(CRYPTO_ITERATIONS);
    for n in 0..rounds {
        r.refill();
        let a = r.session();
        let id = [0x10; 16];
        r.accept(a, &start_frame(&id));
        let frame = initiator_key(&id);
        // Forced: the run operation holds the run when close begins.
        let (arrived, arrival) = mpsc::channel();
        let (resume, resumed) = mpsc::channel::<()>();
        thread::scope(|scope| {
            let op = scope.spawn(|| {
                r.router.with_run(a, &id, move |run| {
                    arrived.send(()).unwrap();
                    resumed.recv().unwrap();
                    run.receive_initiator_key(&frame)
                })
            });
            arrive(&arrival, "run operation");
            let (close, waits) = close_on(scope, &r, a);
            assert_eq!(waits.recv_timeout(HANG).unwrap(), 1, "iteration {n}");
            assert_eq!(
                r.router.deliver(a, &initiator_key(&id)).unwrap_err(),
                CLOSED
            );
            resume.send(()).unwrap();
            // The entered operation kept its outcome (DH with the base-point test key).
            let done = op.join().unwrap().unwrap();
            assert!(done.result.is_none() && done.run.is_some());
            assert_eq!(close.join().unwrap(), (Ok(()), (0, 0, 0, 0)));
        });
        assert_released(&r, "forced");
        // Race.
        r.refill();
        let b = r.session();
        r.accept(b, &start_frame(&id));
        let barrier = Barrier::new(2);
        let (delivered, closed) = thread::scope(|scope| {
            let deliver = scope.spawn(|| {
                barrier.wait();
                r.router.deliver(b, &initiator_key(&id))
            });
            let close = scope.spawn(|| {
                barrier.wait();
                // Alternate who is more likely to win; correctness never depends on it.
                if n % 2 == 0 {
                    thread::yield_now();
                }
                r.router.close_session(b)
            });
            (deliver.join().unwrap(), close.join().unwrap())
        });
        assert_eq!(closed, Ok(()));
        match delivered {
            // Entered first: the run applied the frame, then close ended it.
            Ok(routed) if routed.output == Inbound::InitiatorKey => orders[0] += 1,
            Err(RouteError::UnknownSession) => orders[1] += 1,
            other => panic!("unexpected delivery outcome {other:?}"),
        }
        assert_released(&r, "race");
        assert_eq!(r.status(), Status::Ready { remaining: 10 });
    }
    eprintln!(
        "ROUTER-RACE-001: {rounds} forced + {rounds} races; race orders (delivered first, closed first) = {orders:?}"
    );
    r.release();
}

/// ROUTER-RACE-002: session close versus START admission. Forced: admission holds its permit
/// and pending slot (paused after limiter admission) when close begins; it observes the closing
/// session, installs nothing, returns no ACCEPT, and releases both before close returns; the
/// limiter charge stays. Race: either admitted then terminated, or refused at entry with no
/// charge.
#[test]
fn p5_router_race_002_close_versus_start_admission() {
    let r = Node::new("p5-race-002");
    let mut orders = [0usize; 3];
    let rounds = iterations(CRYPTO_ITERATIONS);
    for n in 0..rounds {
        r.refill();
        let a = r.session();
        let (arrived, arrival) = mpsc::channel();
        let (resume, resumed) = mpsc::channel();
        thread::scope(|scope| {
            let admit = scope.spawn(|| {
                pause_at(Point::ResponderAdmitted, arrived, resumed);
                r.receive(a, &start_frame(&[0x20; 16]))
            });
            arrive(&arrival, "admission");
            let charged = r.limiter();
            assert_eq!(r.resources(), (1, 1, 1, 0), "iteration {n}");
            let (close, waits) = close_on(scope, &r, a);
            assert_eq!(waits.recv_timeout(HANG).unwrap(), 1);
            resume.send(()).unwrap();
            assert_eq!(admit.join().unwrap(), Err(CLOSED));
            assert_eq!(close.join().unwrap(), (Ok(()), (0, 0, 0, 0)));
            assert_eq!(r.limiter(), charged, "START admission is never refunded");
        });
        // Race.
        r.refill();
        let b = r.session();
        let before = r.limiter().rolling;
        let barrier = Barrier::new(2);
        let (admitted, closed) = thread::scope(|scope| {
            let admit = scope.spawn(|| {
                barrier.wait();
                r.receive(b, &start_frame(&[0x21; 16]))
            });
            let close = scope.spawn(|| {
                barrier.wait();
                // Alternate who is more likely to win; correctness never depends on it.
                if n % 2 == 0 {
                    thread::yield_now();
                }
                r.router.close_session(b)
            });
            (admit.join().unwrap(), close.join().unwrap())
        });
        assert_eq!(closed, Ok(()));
        let charged = r.limiter().rolling - before;
        match admitted {
            Ok(StartRouting::Accepted(_)) => {
                assert_eq!(charged, 1);
                orders[0] += 1;
            }
            // Refused at entry: nothing charged. Or closed during admission: charged.
            Err(RouteError::UnknownSession) if charged == 0 => orders[1] += 1,
            Err(RouteError::UnknownSession) if charged == 1 => orders[2] += 1,
            other => panic!("unexpected admission outcome {other:?} (charged {charged})"),
        }
        assert_released(&r, "race");
    }
    eprintln!(
        "ROUTER-RACE-002: {rounds} forced + {rounds} races; race orders (admitted, refused at entry, closed during admission) = {orders:?}"
    );
    assert_eq!(r.status(), Status::Ready { remaining: 10 });
    r.release();
}

/// ROUTER-RACE-003: session close versus local Initiator creation. Forced: the Initiator holds
/// its reserved request ID and built START when close begins; START is suppressed and the
/// reservation released before close returns. Race: either routed then terminated, or refused.
#[test]
fn p5_router_race_003_close_versus_initiator_creation() {
    let node = Node::new("p5-race-003");
    let mut orders = [0usize; 2];
    let rounds = iterations(ITERATIONS);
    for n in 0..rounds {
        let a = node.session();
        let (arrived, arrival) = mpsc::channel();
        let (resume, resumed) = mpsc::channel();
        thread::scope(|scope| {
            let create = scope.spawn(|| {
                pause_at(Point::InitiatorStarted, arrived, resumed);
                node.router.start_initiator(a, initiator_bootstrap(), None)
            });
            arrive(&arrival, "Initiator creation");
            assert_eq!(node.resources(), (0, 0, 0, 1), "iteration {n}");
            let (close, waits) = close_on(scope, &node, a);
            assert_eq!(waits.recv_timeout(HANG).unwrap(), 1);
            resume.send(()).unwrap();
            assert_eq!(create.join().unwrap(), Err(CLOSED));
            assert_eq!(close.join().unwrap(), (Ok(()), (0, 0, 0, 0)));
        });
        let b = node.session();
        let barrier = Barrier::new(2);
        let (created, closed) = thread::scope(|scope| {
            let create = scope.spawn(|| {
                barrier.wait();
                node.router.start_initiator(b, initiator_bootstrap(), None)
            });
            let close = scope.spawn(|| {
                barrier.wait();
                if n % 2 == 0 {
                    thread::yield_now();
                }
                node.router.close_session(b)
            });
            (create.join().unwrap(), close.join().unwrap())
        });
        assert_eq!(closed, Ok(()));
        match created {
            Ok(_) => orders[0] += 1,
            Err(RouteError::UnknownSession) => orders[1] += 1,
            other => panic!("unexpected creation outcome {other:?}"),
        }
        assert_released(&node, "race");
    }
    eprintln!(
        "ROUTER-RACE-003: {rounds} forced + {rounds} races; race orders (routed then closed, refused) = {orders:?}"
    );
    node.release();
}

/// ROUTER-RACE-004: two STARTs for one key. Forced: while the first is being admitted, an
/// identical copy is a duplicate (no charge, slot, or output) and the first is installed; a
/// changed copy conflicts and the first admission is discarded. Race: identical copies released
/// together create exactly one run and one charge.
#[test]
fn p5_router_race_004_duplicate_and_conflicting_starts() {
    let r = Node::new("p5-race-004");
    let id = [0x40; 16];
    let rounds = iterations(CRYPTO_ITERATIONS);
    for n in 0..rounds {
        for changed in [false, true] {
            r.refill();
            let a = r.session();
            let (arrived, arrival) = mpsc::channel();
            let (resume, resumed) = mpsc::channel();
            thread::scope(|scope| {
                let first = scope.spawn(|| {
                    pause_at(Point::ResponderAdmitted, arrived, resumed);
                    r.receive(a, &start_frame(&id))
                });
                arrive(&arrival, "first admission");
                let charged = r.limiter();
                let second = if changed {
                    changed_start(&id)
                } else {
                    start_frame(&id)
                };
                let outcome = r.receive(a, &second);
                assert_eq!(r.limiter(), charged, "the copy was charged");
                resume.send(()).unwrap();
                let first = first.join().unwrap();
                if changed {
                    assert_eq!((outcome, first), (Err(BAD), Err(BAD)), "iteration {n}");
                    assert_eq!(r.resources(), (0, 0, 0, 0));
                } else {
                    assert_eq!(outcome, Ok(StartRouting::Duplicate));
                    assert!(matches!(first, Ok(StartRouting::Accepted(_))));
                    assert_eq!(r.resources(), (1, 1, 0, 0));
                }
            });
            r.router.close_session(a).unwrap();
            assert_released(&r, "forced");
        }
        r.refill();
        let b = r.session();
        let outcomes = race(&r, &vec![(b, start_frame(&id)); 4]);
        let accepted = outcomes
            .iter()
            .filter(|o| matches!(o, Ok(StartRouting::Accepted(_))))
            .count();
        assert_eq!(accepted, 1, "{outcomes:?}");
        assert!(outcomes.iter().all(|o| matches!(
            o,
            Ok(StartRouting::Accepted(_)) | Ok(StartRouting::Duplicate)
        )));
        let limiter = r.limiter();
        assert_eq!((limiter.tokens, limiter.rolling), (3, 1));
        assert_eq!(r.resources(), (1, 1, 0, 0));
        r.router.close_session(b).unwrap();
        assert_released(&r, "race");
    }
    eprintln!("ROUTER-RACE-004: {rounds} x 2 forced + {rounds} four-way races");
    r.release();
}

/// ROUTER-RACE-005: a local callback versus the deadline driver on an expired run. Forced (a):
/// the callback holds the run first; the driver skips it as busy; the callback's own deadline
/// check ends the run (the callback did not happen) and removes the route; the driver later
/// finds nothing. Forced (b): the driver holds the run first; the callback has taken the same
/// run and waits for its lock; the driver ends the run; the callback then acts on a terminal
/// run and changes nothing. Exactly one deadline outcome either way.
#[test]
fn p5_router_race_005_callback_versus_deadline_driver() {
    let node = Node::new("p5-race-005");
    let rounds = iterations(ITERATIONS);
    for n in 0..rounds {
        for callback_first in [true, false] {
            let a = node.session();
            let clock = ManualClock::new();
            let id = [0x50; 16];
            let run = initiator(&node, a, &clock, id);
            clock.advance(INACTIVITY_DEADLINE);
            let (arrived, arrival) = mpsc::channel();
            let (resume, resumed) = mpsc::channel();
            let (callback, polled) = thread::scope(|scope| {
                if callback_first {
                    let callback = scope.spawn(|| {
                        pause_at(Point::LocalRunLocked, arrived, resumed);
                        node.router
                            .with_exact_run(a, &run, |ceremony| ceremony.approve_sas(&[0; 32]))
                    });
                    arrive(&arrival, "callback");
                    let busy = node
                        .router
                        .poll_session_deadlines(a, &mut DeadlineCursor::default())
                        .unwrap();
                    assert_eq!(busy.trace, vec![(id.to_vec(), Inspected::Busy)]);
                    assert!(busy.event.is_none());
                    resume.send(()).unwrap();
                    let callback = callback.join().unwrap();
                    let later = node
                        .router
                        .poll_session_deadlines(a, &mut DeadlineCursor::default())
                        .unwrap();
                    (callback, later)
                } else {
                    let driver = scope.spawn(|| {
                        pause_at(Point::DeadlineRunLocked, arrived, resumed);
                        node.router
                            .poll_session_deadlines(a, &mut DeadlineCursor::default())
                    });
                    arrive(&arrival, "driver");
                    // Table and driver hold the run; the callback's lookup adds a third holder.
                    assert_eq!(holders(&node, a, &id), Some(2));
                    let callback = scope.spawn(|| {
                        node.router
                            .with_exact_run(a, &run, |ceremony| ceremony.approve_sas(&[0; 32]))
                    });
                    wait_until("callback lookup", || holders(&node, a, &id) == Some(3));
                    resume.send(()).unwrap();
                    let polled = driver.join().unwrap().unwrap();
                    (callback.join().unwrap(), polled)
                }
            });
            if callback_first {
                assert!(
                    matches!(
                        callback,
                        Err(RouteError::Ceremony(CeremonyError::TimedOut(ref t)))
                            if t.expired() == Deadline::Inactivity && t.cancel().is_none()
                    ),
                    "iteration {n}: {callback:?}"
                );
                assert!(polled.event.is_none() && polled.inspected == 0);
            } else {
                assert!(matches!(
                    polled.event,
                    Some(DeadlineEvent {
                        ended: DeadlineEnded::TimedOut(_),
                        ..
                    })
                ));
                assert_eq!(
                    callback.unwrap_err(),
                    RouteError::Ceremony(CeremonyError::NoLiveSas),
                    "iteration {n}"
                );
            }
            // The stale reference now reaches nothing; nothing leaked.
            assert_eq!(
                node.router
                    .with_exact_run(a, &run, |c| c.approve_sas(&[0; 32]))
                    .unwrap_err(),
                RouteError::UnknownRoute
            );
            node.router.close_session(a).unwrap();
            assert_released(&node, "callback versus driver");
        }
    }
    eprintln!("ROUTER-RACE-005: {rounds} x 2 forced orders");
    node.release();
}

/// ROUTER-RACE-006: post-SAS timeout versus a local MATCH. The same two forced orders as
/// ROUTER-RACE-005 after a real key exchange: exactly one authenticated timeout CANCEL, the
/// guard released once, the opportunity kept, and no result.
#[test]
fn p5_router_race_006_post_sas_callback_versus_timeout() {
    let rounds = iterations(CRYPTO_ITERATIONS);
    for n in 0..rounds {
        for callback_first in [true, false] {
            let (i, si, r, sr, id, start) = initiated(&format!("p5-race-006-{n}-{callback_first}"));
            let clock = ManualClock::new();
            let accept = match r.receive_at(&clock, sr, &start) {
                Ok(StartRouting::Accepted(accept)) => accept,
                other => panic!("{other:?}"),
            };
            let identity = exchange(&i, si, &r, sr, &id, &accept);
            assert_eq!(r.status(), Status::Busy);
            let run = r.router.with_run(sr, &id, |_| Ok(())).unwrap().run.unwrap();
            // Approve, then let the inactivity window lapse while awaiting machine progress.
            r.router
                .with_exact_run(sr, &run, |c| c.approve_sas(&identity))
                .unwrap();
            clock.advance(INACTIVITY_DEADLINE);
            let (arrived, arrival) = mpsc::channel();
            let (resume, resumed) = mpsc::channel();
            let rid = id.clone();
            let (callback, polled) = thread::scope(|scope| {
                if callback_first {
                    let callback = scope.spawn(|| {
                        pause_at(Point::LocalRunLocked, arrived, resumed);
                        r.router
                            .with_exact_run(sr, &run, |c| c.emit_bootstrap_mac())
                    });
                    arrive(&arrival, "callback");
                    let busy = r
                        .router
                        .poll_session_deadlines(sr, &mut DeadlineCursor::default())
                        .unwrap();
                    assert!(busy.event.is_none());
                    resume.send(()).unwrap();
                    (callback.join().unwrap().map(drop), None)
                } else {
                    let driver = scope.spawn(|| {
                        pause_at(Point::DeadlineRunLocked, arrived, resumed);
                        r.router
                            .poll_session_deadlines(sr, &mut DeadlineCursor::default())
                    });
                    arrive(&arrival, "driver");
                    let callback = scope.spawn(|| {
                        r.router
                            .with_exact_run(sr, &run, |c| c.emit_bootstrap_mac())
                    });
                    wait_until("callback lookup", || holders(&r, sr, &rid) == Some(3));
                    resume.send(()).unwrap();
                    let polled = driver.join().unwrap().unwrap();
                    (callback.join().unwrap().map(drop), Some(polled))
                }
            });
            let cancel = match (callback, polled) {
                (Err(RouteError::Ceremony(CeremonyError::TimedOut(t))), None) => {
                    t.cancel().map(<[u8]>::to_vec)
                }
                (
                    Err(RouteError::Ceremony(CeremonyError::NoLiveSas)),
                    Some(DeadlinePoll {
                        event:
                            Some(DeadlineEvent {
                                ended: DeadlineEnded::TimedOut(t),
                                ..
                            }),
                        ..
                    }),
                ) => t.cancel().map(<[u8]>::to_vec),
                other => panic!("iteration {n}: unexpected {other:?}"),
            };
            // One authenticated timeout CANCEL, the guard released once, the opportunity kept.
            let cancel = cancel.expect("timeout CANCEL");
            assert!(matches!(
                protocol::decode(&cancel).unwrap().message,
                Message::Cancel {
                    reason: CancelReason::Timeout,
                    ..
                }
            ));
            assert_eq!(r.status(), Status::Ready { remaining: 9 });
            assert_eq!(r.resources(), (0, 0, 0, 0));
            // The peer verifies it and also ends without a result.
            assert!(matches!(
                i.router.deliver(si, &cancel).unwrap().output,
                Inbound::Cancel(_)
            ));
            assert_eq!(i.status(), Status::Ready { remaining: 9 });
            i.release();
            r.release();
        }
    }
    eprintln!("ROUTER-RACE-006: {rounds} x 2 forced orders after a real key exchange");
}

/// ROUTER-RACE-007: a local callback versus session close. Forced (a): the callback holds the
/// run when close begins; close waits, the callback completes with its own outcome, then the
/// run is terminated. (b): close completes first; the callback is refused. Race: either
/// outcome, never a deadlock or a leak.
#[test]
fn p5_router_race_007_callback_versus_close() {
    let node = Node::new("p5-race-007");
    let mut orders = [0usize; 2];
    let rounds = iterations(ITERATIONS);
    for n in 0..rounds {
        let clock = ManualClock::new();
        let a = node.session();
        let run = initiator(&node, a, &clock, [0x70; 16]);
        let (arrived, arrival) = mpsc::channel();
        let (resume, resumed) = mpsc::channel();
        thread::scope(|scope| {
            let callback = scope.spawn(|| {
                pause_at(Point::LocalRunLocked, arrived, resumed);
                node.router
                    .with_exact_run(a, &run, |c| c.approve_sas(&[0; 32]))
            });
            arrive(&arrival, "callback");
            let (close, waits) = close_on(scope, &node, a);
            assert_eq!(waits.recv_timeout(HANG).unwrap(), 1, "iteration {n}");
            resume.send(()).unwrap();
            // Entered before close: its refusal stands (no live SAS yet), nothing changed.
            assert_eq!(
                callback.join().unwrap().unwrap_err(),
                RouteError::Ceremony(CeremonyError::NoLiveSas)
            );
            assert_eq!(close.join().unwrap(), (Ok(()), (0, 0, 0, 0)));
        });
        assert_eq!(
            node.router
                .with_exact_run(a, &run, |c| c.approve_sas(&[0; 32]))
                .unwrap_err(),
            CLOSED
        );
        // Race.
        let b = node.session();
        let run = initiator(&node, b, &clock, [0x71; 16]);
        let barrier = Barrier::new(2);
        let (acted, closed) = thread::scope(|scope| {
            let callback = scope.spawn(|| {
                barrier.wait();
                node.router
                    .with_exact_run(b, &run, |c| c.approve_sas(&[0; 32]))
            });
            let close = scope.spawn(|| {
                barrier.wait();
                if n % 2 == 0 {
                    thread::yield_now();
                }
                node.router.close_session(b)
            });
            (callback.join().unwrap(), close.join().unwrap())
        });
        assert_eq!(closed, Ok(()));
        match acted.unwrap_err() {
            RouteError::Ceremony(CeremonyError::NoLiveSas) => orders[0] += 1,
            RouteError::UnknownSession => orders[1] += 1,
            other => panic!("unexpected callback outcome {other:?}"),
        }
        assert_released(&node, "race");
    }
    eprintln!(
        "ROUTER-RACE-007: {rounds} forced + {rounds} races; race orders (acted first, closed first) = {orders:?}"
    );
    node.release();
}

/// ROUTER-RACE-008: the deadline driver versus session close, with the polled run expired or
/// live. The driver holds the run when close begins; close waits; the driver finishes that one
/// run (reporting its timeout if expired) and stops; close then terminates the rest. Every
/// resource is released once.
#[test]
fn p5_router_race_008_deadline_driver_versus_close() {
    let node = Node::new("p5-race-008");
    let rounds = iterations(ITERATIONS);
    for n in 0..rounds {
        for expired in [false, true] {
            let clock = ManualClock::new();
            let a = node.session();
            initiator(&node, a, &clock, ordered(1));
            initiator(&node, a, &clock, ordered(2));
            if expired {
                clock.advance(INACTIVITY_DEADLINE);
            }
            let (arrived, arrival) = mpsc::channel();
            let (resume, resumed) = mpsc::channel();
            thread::scope(|scope| {
                let driver = scope.spawn(|| {
                    pause_at(Point::DeadlineRunLocked, arrived, resumed);
                    node.router
                        .poll_session_deadlines(a, &mut DeadlineCursor::default())
                });
                arrive(&arrival, "driver");
                let (close, waits) = close_on(scope, &node, a);
                assert_eq!(waits.recv_timeout(HANG).unwrap(), 1, "iteration {n}");
                resume.send(()).unwrap();
                let polled = driver.join().unwrap().unwrap();
                assert_eq!(polled.inspected, 1);
                assert_eq!(polled.event.is_some(), expired);
                assert_eq!(close.join().unwrap(), (Ok(()), (0, 0, 0, 0)));
            });
            assert_released(&node, "driver versus close");
        }
    }
    eprintln!("ROUTER-RACE-008: {rounds} x 2 forced orders");
    node.release();
}

/// ROUTER-RACE-009 (P5.2 §16 "unrelated traffic"): progress of one run never refreshes another
/// run on the same session. Two Responders share a session and a ceremony clock; B makes
/// protocol progress at 30 s; A still expires at exactly 60 s and B survives.
#[test]
fn p5_router_race_009_sibling_progress_buys_no_time() {
    let r = Node::new("p5-race-009");
    let clock = ManualClock::new();
    let a = r.session();
    let (x, y) = ([0x91; 16], [0x92; 16]);
    for id in [x, y] {
        assert!(matches!(
            r.receive_at(&clock, a, &start_frame(&id)),
            Ok(StartRouting::Accepted(_))
        ));
    }
    clock.advance(Duration::from_secs(30));
    // Y makes protocol progress: a contributory INITIATOR_KEY (pre-authorization DH).
    let ikey = Message::InitiatorKey {
        request_id: y.to_vec(),
        public_key: x25519_point(),
    }
    .encode()
    .unwrap();
    assert_eq!(
        r.router.deliver(a, &ikey).unwrap().output,
        Inbound::InitiatorKey
    );
    clock.advance(Duration::from_secs(30) - Duration::from_nanos(1));
    assert_eq!(
        r.local(a, &x, |run| run.poll_deadlines()).output,
        DeadlineOutcome::Active
    );
    clock.advance(Duration::from_nanos(1));
    assert!(matches!(
        r.router.with_run(a, &x, |run| run.poll_deadlines()).unwrap().output,
        DeadlineOutcome::TimedOut(ref t) if t.expired() == Deadline::Inactivity
    ));
    // Y's own fixed pending lifetime (from its admission at 0) is what ends it now, not
    // inactivity: its progress at 30 s moved only its own inactivity origin.
    assert!(matches!(
        r.router
            .with_run(a, &y, |run| run.poll_deadlines())
            .unwrap()
            .output,
        DeadlineOutcome::PendingExpired
    ));
    r.release();
}

/// A valid, contributory X25519 public key (the fixture Initiator's) for DH success.
fn x25519_point() -> [u8; 32] {
    match protocol::decode(&vector("INITIATOR_KEY")).unwrap().message {
        Message::InitiatorKey { public_key, .. } => public_key,
        _ => unreachable!(),
    }
}
