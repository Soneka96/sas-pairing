//! P6-D-001 connection lifetime through the Windows TCP adapter (remediation of P5-F-002):
//! owner-less retained output (10 s absolute, 2 s without write progress), the quiescent
//! deadline after a completed ceremony and immediate reuse before it, live-ceremony
//! precedence, and the socket activity that must never extend a connection. Scripted sockets
//! and hand clocks only.
use super::*;
use crate::{
    deadline::PENDING_PRE_EXPOSURE_DEADLINE,
    transport::{
        FIRST_FRAME_DEADLINE, QUIESCENT_DEADLINE, RETAINED_OUTPUT_DEADLINE,
        RETAINED_OUTPUT_IDLE_DEADLINE,
    },
};

const S: Duration = Duration::from_secs(1);
const MS: Duration = Duration::from_millis(1);

fn ended(error: TransportError) -> Result<TcpStep, TcpError> {
    Err(TcpError::Host(HostError::Transport(error)))
}

/// One owner-loop sweep of `tcp`: its connection-deadline poll, then its ceremony poll.
fn sweep(tcp: &mut Tcp<'_>) -> Result<Vec<TcpEvent>, TcpError> {
    let mut events = Vec::new();
    for step in [
        tcp.poll_connection_deadlines()?,
        tcp.poll_ceremony_deadlines()?,
    ] {
        assert_eq!(step.result, None);
        events.extend(step.event);
    }
    Ok(events)
}

/// R's run ends by its absolute deadline after the SAS; its authenticated timeout CANCEL is
/// retained with no owner for a peer that never reads. Returns its bytes; the transport clock
/// then reads `at`, the instant the owner-less output is first observed.
fn ownerless_cancel(
    s: &mut Sides<'_>,
    run: &Run,
    cr: &ManualClock,
    tc: &ManualClock,
    at: Duration,
) -> Vec<u8> {
    s.rio.hold(true);
    cr.advance(ABSOLUTE_DEADLINE);
    assert_eq!(
        s.r.poll_ceremony_deadlines(),
        Ok(deadline(Some(&run.id), ABSOLUTE, TimeoutCancel::Pending))
    );
    assert!(s.r.pending.as_ref().unwrap().owner.is_none());
    tc.set(at);
    assert_eq!(s.r.poll_connection_deadlines(), Ok(BUSY));
    pending_bytes(&s.r)
}

#[derive(Clone, Copy, Debug)]
enum Out {
    /// C1/C2: no write progress at all.
    Idle(i8),
    /// WouldBlock and Interrupted writes are no progress.
    Refused,
    /// C3: one byte at 1.5 s restarts only the no-progress deadline.
    OneByte(i8),
    /// C4/C5: a byte every 1.5 s never passes the 10 s absolute deadline.
    Trickle(i8),
}

#[test]
fn ownerless_output_has_absolute_and_no_progress_deadlines() {
    let t0 = Duration::from_secs(100);
    for case in [
        Out::Idle(-1),
        Out::Idle(0),
        Out::Idle(1),
        Out::Refused,
        Out::OneByte(-1),
        Out::OneByte(0),
        Out::Trickle(-1),
        Out::Trickle(0),
    ] {
        // One authority pair per case: budgets persist per process session (P6.3).
        let (i, r) = (
            Node::new(&format!("p6-out-i-{case:?}")),
            Node::new(&format!("p6-out-r-{case:?}")),
        );
        let (tc, ci, cr) = clocks();
        let mut s = Sides::new(&i, &r, &tc, &ci, &cr);
        let (run, _) = s.sas(&i, &r, &ci, [0x60; 16]);
        let cancel = ownerless_cancel(&mut s, &run, &cr, &tc, t0);
        let at = |d: Duration, offset: i8| match offset {
            -1 => t0 + d - NS,
            0 => t0 + d,
            _ => t0 + d + NS,
        };
        let (probe, expected) = match case {
            Out::Idle(offset) => (
                at(RETAINED_OUTPUT_IDLE_DEADLINE, offset),
                TransportError::RetainedOutputIdleTimeout,
            ),
            Out::Refused => {
                for (n, kind) in [(1, WouldBlock), (2, Interrupted)] {
                    tc.set(t0 + 500 * MS * n);
                    if kind == Interrupted {
                        s.rio.write(Fail(kind));
                    }
                    assert_eq!(s.r.on_writable(), Ok(BUSY), "{kind:?}");
                }
                (
                    at(RETAINED_OUTPUT_IDLE_DEADLINE, 0),
                    TransportError::RetainedOutputIdleTimeout,
                )
            }
            Out::OneByte(offset) => {
                tc.set(t0 + 1500 * MS);
                s.rio.write(Take(1));
                assert_eq!(s.r.on_writable(), Ok(BUSY));
                (
                    at(1500 * MS + RETAINED_OUTPUT_IDLE_DEADLINE, offset),
                    TransportError::RetainedOutputIdleTimeout,
                )
            }
            Out::Trickle(offset) => {
                for n in 1..=6 {
                    tc.set(t0 + 1500 * MS * n);
                    s.rio.write(Take(1));
                    assert_eq!(s.r.on_writable(), Ok(BUSY));
                    assert_eq!(s.r.poll_connection_deadlines(), Ok(BUSY));
                }
                (
                    at(RETAINED_OUTPUT_DEADLINE, offset),
                    TransportError::RetainedOutputTimeout,
                )
            }
        };
        tc.set(probe);
        let live = matches!(case, Out::Idle(-1) | Out::OneByte(-1) | Out::Trickle(-1));
        if live {
            assert_eq!(s.r.poll_connection_deadlines(), Ok(BUSY), "{case:?}");
            assert_eq!(r.counts(), (0, 1, 0, 0));
        } else {
            // Exact boundary through the write preflight: nothing more is written.
            let writes = s.rio.writes();
            assert_eq!(s.r.on_writable(), ended(expected), "{case:?}");
            assert_eq!(s.rio.writes(), writes, "no write after expiry");
            assert!(s.r.is_closed());
            assert_eq!(r.counts(), (0, 0, 0, 0));
            assert_eq!(r.sessions(), 0);
            assert_eq!(s.r.poll_connection_deadlines(), Err(TcpError::Closed));
        }
        // C6: never a result, never a refund; the wire holds a strict prefix of the CANCEL.
        let wire = s.rio.wire();
        assert!(
            wire.len() < cancel.len() && cancel.starts_with(&wire),
            "{case:?}"
        );
        // I's own run is still live at its SAS; only R's connection was touched.
        assert_eq!(
            (i.status(), i.remaining(), r.status()),
            (Status::Busy, 9, Status::Ready { remaining: 9 })
        );
        drop(s);
        assert_eq!(r.counts(), (0, 0, 0, 0));
        i.release();
        r.release();
    }
}

/// The local REJECT's CANCEL is owner-less output too.
#[test]
fn a_local_rejects_cancel_is_bounded_like_any_ownerless_output() {
    let (i, r) = (Node::new("p6-reject-i"), Node::new("p6-reject-r"));
    let (tc, ci, cr) = clocks();
    let mut s = Sides::new(&i, &r, &tc, &ci, &cr);
    let (run, identity) = s.sas(&i, &r, &ci, [0x61; 16]);
    s.rio.hold(true);
    tc.set(7 * S);
    let rejected = acted(s.r.reject_sas(&run.r, &identity));
    assert_eq!(
        (rejected.event, rejected.run),
        (LocalEvent::SasRejected, None)
    );
    assert_eq!(s.r.poll_connection_deadlines(), Ok(BUSY));
    tc.set(7 * S + RETAINED_OUTPUT_IDLE_DEADLINE - NS);
    assert_eq!(s.r.poll_connection_deadlines(), Ok(BUSY));
    tc.set(7 * S + RETAINED_OUTPUT_IDLE_DEADLINE);
    assert_eq!(
        s.r.poll_connection_deadlines(),
        ended(TransportError::RetainedOutputIdleTimeout)
    );
    assert_eq!(
        (r.counts(), r.status()),
        ((0, 0, 0, 0), Status::Ready { remaining: 9 })
    );
    drop(s);
    i.release();
    r.release();
}

#[test]
fn quiescent_connection_after_a_completed_ceremony_releases_its_live_slot() {
    for reuse in [false, true] {
        let (i, r) = (
            Node::new(&format!("p6-quiet-i-{reuse}")),
            Node::new(&format!("p6-quiet-r-{reuse}")),
        );
        let (tc, ci, cr) = clocks();
        let mut s = Sides::new(&i, &r, &tc, &ci, &cr);
        let (run, identity) = s.sas(&i, &r, &ci, [0x62; 16]);
        s.final_ack(&run, &identity);
        let confirmed = s.i.on_writable().unwrap();
        assert_eq!(confirmed.event, Some(TcpEvent::Confirmed));
        relay(&s.iio, &s.rio);
        let finished = s.r.on_readable().unwrap();
        results_agree(
            confirmed.result.as_ref().unwrap(),
            finished.result.as_ref().unwrap(),
            &run.id,
        );
        assert_eq!((i.routes(), r.routes()), (0, 0));
        // No live run, no frame, no output: both connections are quiescent from here.
        let quiet = Duration::from_secs(30);
        tc.set(quiet);
        assert_eq!(sweep(&mut s.i), Ok(vec![]));
        assert_eq!(sweep(&mut s.r), Ok(vec![]));
        tc.set(quiet + QUIESCENT_DEADLINE - NS);
        assert_eq!(sweep(&mut s.i), Ok(vec![]));
        assert_eq!(sweep(&mut s.r), Ok(vec![]));
        if reuse {
            // Immediate reuse just before expiry: the new run governs both connections.
            let again = s.open(&ci, [0x63; 16]);
            tc.set(quiet + Duration::from_secs(3600));
            assert_eq!(sweep(&mut s.i), Ok(vec![]));
            assert_eq!(sweep(&mut s.r), Ok(vec![]));
            assert!(s.r.presentation(&again.r).is_ok() && !s.r.is_closed());
            assert_eq!((i.counts().1, r.counts().1), (1, 1));
        } else {
            tc.set(quiet + QUIESCENT_DEADLINE);
            let expected = Err(TcpError::Host(HostError::Transport(
                TransportError::QuiescentTimeout,
            )));
            assert_eq!(s.i.poll_connection_deadlines(), expected);
            assert_eq!(s.r.poll_connection_deadlines(), expected);
            assert_eq!((i.counts(), r.counts()), ((0, 0, 0, 0), (0, 0, 0, 0)));
            assert_eq!((i.sessions(), r.sessions()), (0, 0));
        }
        assert_eq!(
            (i.status(), r.status()),
            (
                Status::Ready { remaining: 9 },
                Status::Ready { remaining: 9 }
            )
        );
        drop(s);
        i.release();
        r.release();
    }
}

/// Live-ceremony precedence: a SAS awaiting human comparison with no socket traffic for minutes
/// is untouched by every 10 s connection timer, then still completes; and only the existing
/// ceremony deadlines (5 min absolute; 60 s inactivity or pending) end a live run.
#[test]
fn active_ceremony_is_not_subject_to_the_connection_timers() {
    // (a) Four silent minutes at the SAS, swept every 5 s, then success.
    {
        let (i, r) = (Node::new("p6-active-i"), Node::new("p6-active-r"));
        let (tc, ci, cr) = clocks();
        let mut s = Sides::new(&i, &r, &tc, &ci, &cr);
        let (run, identity) = s.sas(&i, &r, &ci, [0x64; 16]);
        for _ in 0..48 {
            for clock in [&tc, &ci, &cr] {
                clock.advance(5 * S);
            }
            assert_eq!(sweep(&mut s.i), Ok(vec![]));
            assert_eq!(sweep(&mut s.r), Ok(vec![]));
        }
        assert!(s.i.presentation(&run.i).unwrap().unwrap().is_some());
        assert!(s.r.presentation(&run.r).unwrap().unwrap().is_some());
        s.final_ack(&run, &identity);
        let confirmed = s.i.on_writable().unwrap();
        relay(&s.iio, &s.rio);
        let finished = s.r.on_readable().unwrap();
        results_agree(
            confirmed.result.as_ref().unwrap(),
            finished.result.as_ref().unwrap(),
            &run.id,
        );
        drop(s);
        i.release();
        r.release();
    }
    // (b) The 5 min absolute deadline still decides, exactly; then the 10 s quiescent wait.
    {
        let (i, r) = (Node::new("p6-absolute-i"), Node::new("p6-absolute-r"));
        let (tc, ci, cr) = clocks();
        let mut s = Sides::new(&i, &r, &tc, &ci, &cr);
        let (run, _) = s.sas(&i, &r, &ci, [0x65; 16]);
        for clock in [&tc, &ci] {
            clock.set(ABSOLUTE_DEADLINE - NS);
        }
        assert_eq!(sweep(&mut s.i), Ok(vec![]));
        for clock in [&tc, &ci] {
            clock.set(ABSOLUTE_DEADLINE);
        }
        assert_eq!(
            s.i.poll_ceremony_deadlines(),
            Ok(deadline(Some(&run.id), ABSOLUTE, TimeoutCancel::Pending))
        );
        // Its CANCEL is written; the connection is then quiescent for 10 s.
        assert_eq!(s.i.on_writable(), Ok(written()));
        assert_eq!(sweep(&mut s.i), Ok(vec![]));
        tc.set(ABSOLUTE_DEADLINE + QUIESCENT_DEADLINE - NS);
        assert_eq!(sweep(&mut s.i), Ok(vec![]));
        tc.set(ABSOLUTE_DEADLINE + QUIESCENT_DEADLINE);
        assert_eq!(
            s.i.poll_connection_deadlines(),
            ended(TransportError::QuiescentTimeout)
        );
        assert_eq!(i.counts(), (0, 0, 0, 0));
        drop(s);
        i.release();
        r.release();
    }
    // (c) While waiting for machine progress, the 60 s inactivity and pending deadlines decide.
    {
        let (i, r) = (Node::new("p6-inactive-i"), Node::new("p6-inactive-r"));
        let (tc, ci, cr) = clocks();
        let mut s = Sides::new(&i, &r, &tc, &ci, &cr);
        let run = s.open(&ci, [0x66; 16]);
        for clock in [&tc, &ci, &cr] {
            clock.set(INACTIVITY_DEADLINE - NS);
        }
        assert_eq!(sweep(&mut s.i), Ok(vec![]));
        assert_eq!(sweep(&mut s.r), Ok(vec![]));
        for clock in [&tc, &ci, &cr] {
            clock.set(INACTIVITY_DEADLINE);
        }
        assert_eq!(INACTIVITY_DEADLINE, PENDING_PRE_EXPOSURE_DEADLINE);
        assert_eq!(
            sweep(&mut s.i),
            Ok(vec![
                deadline(Some(&run.id), INACTIVITY, TimeoutCancel::NotBuilt)
                    .event
                    .unwrap()
            ])
        );
        assert_eq!(
            sweep(&mut s.r),
            Ok(vec![
                // Pending and inactivity expire together; the ceremony reports inactivity.
                deadline(Some(&run.id), INACTIVITY, TimeoutCancel::NotBuilt)
                    .event
                    .unwrap()
            ])
        );
        drop(s);
        i.release();
        r.release();
    }
}

/// Meaningless socket activity and noise on a connection with no live run: none of it moves
/// the first-frame origin, and frames that would need a run end the connection at once.
#[test]
fn meaningless_socket_activity_never_extends_a_connection() {
    let r = Node::new("p6-noise");
    let (tc, cc, _) = clocks();
    let (mut tcp, io) = r.connect(&tc, &cc);
    for n in 0..20u32 {
        tc.set(n * 450 * MS);
        io.read(ReadStep::Fail(if n % 2 == 0 {
            WouldBlock
        } else {
            Interrupted
        }));
        assert_eq!(tcp.on_readable(), Ok(TcpStep::default()));
        assert_eq!(tcp.on_readable(), Ok(TcpStep::default()), "WouldBlock");
        assert_eq!(tcp.on_writable(), Ok(TcpStep::default()));
        assert_eq!(sweep(&mut tcp), Ok(vec![]));
    }
    tc.set(FIRST_FRAME_DEADLINE - NS);
    assert_eq!(sweep(&mut tcp), Ok(vec![]));
    tc.set(FIRST_FRAME_DEADLINE);
    // Readable data at the deadline is read but not taken: teardown wins.
    io.data(&start(&[0x67; 16]));
    assert_eq!(tcp.on_readable(), ended(TransportError::FirstFrameTimeout));
    assert_eq!((r.counts(), r.charged()), ((0, 0, 0, 0), (4, 0)));
    drop(tcp);
    // A frame for a run that does not exist, and a malformed one, end a quiet connection now.
    for frame in [initiator_key(&[0x68; 16]), b"SASPAIR\0\x02\x01".to_vec()] {
        let (mut tcp, io) = r.connect(&tc, &cc);
        io.data(&frame);
        assert!(tcp.on_readable().is_err());
        assert!(tcp.is_closed());
        assert_eq!(r.counts(), (0, 0, 0, 0));
    }
    r.release();
}
