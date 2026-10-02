//! P6-D-003 graceful hang-up handling through the owner loop (remediation of P5-F-001): a peer's
//! `POLLHUP` is drained toward EOF one operation per drive and does not suppress a retained
//! frame's write, while `POLLERR` and `POLLNVAL` still close before any I/O. Scripted readiness
//! rows are precedence tests of the loop's classification, not claims that Windows reports each
//! combination; the real-loopback tests pin what Windows does report.
use super::*;
use crate::{
    transport::{FIRST_FRAME_DEADLINE, QUIESCENT_DEADLINE, RETAINED_OUTPUT_IDLE_DEADLINE},
    windows_tcp::tests::NS,
};
use ErrorKind::{ConnectionAborted, ConnectionReset};
use std::net::Shutdown;

/// What one drive did to the connection under test.
#[derive(Debug, PartialEq, Eq)]
struct Did {
    reads: usize,
    writes: usize,
    shut_down: bool,
    seen: Seen,
    /// The connection still retains an outbound frame after the drive.
    pending: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum Seen {
    Nothing,
    Dispatched(HostEvent),
    Written,
    Ended(ConnectionEnd),
}

/// The connection's adapter state when its readiness is reported. Both have one complete START
/// readable on the socket, so a read that should not happen is visible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    NoPendingOutput,
    /// A local Initiator's START is retained, unwritten.
    PendingOutput,
}

/// What the precedence rules require of one row.
#[derive(Clone, Copy, Debug)]
enum Want {
    Nothing,
    Read,
    Write,
    Close,
}

fn drive_once_with(
    owner: &mut Loop<'_>,
    net: &Net,
    conn: ConnectionRef,
    socket: &Scripted,
    revents: i16,
) -> Did {
    let (reads, writes, shutdowns) = (socket.reads(), socket.writes(), socket.shutdowns());
    net.set(socket.raw_socket(), revents);
    let step = drive(owner, net);
    assert_eq!(step.failure, None);
    let seen = match <[_; 1]>::try_from(step.events) {
        Err(events) if events.is_empty() => Seen::Nothing,
        Ok([OwnerEvent::Step(c, step)]) if c == conn => {
            assert_eq!(step.result, None);
            match step.event {
                Some(TcpEvent::Inbound { event, .. }) => Seen::Dispatched(event),
                Some(TcpEvent::Written) => Seen::Written,
                other => panic!("unexpected step {other:?}"),
            }
        }
        Ok([OwnerEvent::Closed(c, end)]) if c == conn => Seen::Ended(end),
        other => panic!("unexpected events {other:?}"),
    };
    Did {
        reads: socket.reads() - reads,
        writes: socket.writes() - writes,
        shut_down: socket.shutdowns() > shutdowns,
        seen,
        pending: owner
            .connections
            .iter()
            .any(|live| live.connection == conn && live.tcp.write_pending()),
    }
}

/// The connection-readiness precedence table (P6-D-003), every row on a fresh authority:
/// error or invalid-handle readiness closes before any I/O whatever else is set; with a retained
/// frame only writable readiness writes (hang-up neither closes nor lets input bypass write
/// backpressure); without one, readable or hang-up readiness makes exactly one read.
#[test]
fn connection_readiness_precedence_matrix() {
    // N: no socket I/O. R: one read. W: one write. C: closed before any I/O.
    use Want::{Close as C, Nothing as N, Read as R, Write as W};
    #[rustfmt::skip]
    let rows: [(&str, i16, Want, Want); 14] = [
        // name                         revents                          no output  pending output
        ("0",                           0,                               N,         N),
        ("POLLIN",                      POLLIN,                          R,         N),
        ("POLLOUT",                     POLLOUT,                         N,         W),
        ("POLLHUP",                     POLLHUP,                         R,         N),
        ("POLLHUP|POLLIN",              POLLHUP | POLLIN,                R,         N),
        ("POLLHUP|POLLRDNORM",          POLLHUP | POLLRDNORM,            R,         N),
        ("POLLHUP|POLLOUT",             POLLHUP | POLLOUT,               R,         W),
        ("POLLERR",                     POLLERR,                         C,         C),
        ("POLLERR|POLLIN",              POLLERR | POLLIN,                C,         C),
        ("POLLERR|POLLOUT",             POLLERR | POLLOUT,               C,         C),
        ("POLLERR|POLLHUP|POLLRDNORM",  POLLERR | POLLHUP | POLLRDNORM,  C,         C),
        ("POLLNVAL",                    POLLNVAL,                        C,         C),
        ("POLLNVAL|POLLIN",             POLLNVAL | POLLIN,               C,         C),
        ("POLLNVAL|POLLOUT",            POLLNVAL | POLLOUT,              C,         C),
    ];
    for (n, (name, revents, without, with)) in rows.into_iter().enumerate() {
        for (shape, want) in [
            (Shape::NoPendingOutput, without),
            (Shape::PendingOutput, with),
        ] {
            let r = Node::new(&format!("p6-hup-matrix-{n}-{shape:?}"));
            let (tc, cc, _) = clocks();
            let (mut owner, net) = hosting(&r, &tc, &cc);
            let (conn, socket) = accept(&mut owner, &net);
            socket.data(&start(&[1; 16]));
            if shape == Shape::PendingOutput {
                acted_loop(owner.start_initiator_with(
                    conn,
                    ManualClock::new(),
                    &mut OneId(Some([0x61; 16])),
                    initiator_bootstrap(),
                    None,
                ));
            }
            let did = drive_once_with(&mut owner, &net, conn, &socket, revents);
            let pending = shape == Shape::PendingOutput;
            let expected = match want {
                Want::Nothing => Did {
                    reads: 0,
                    writes: 0,
                    shut_down: false,
                    seen: Seen::Nothing,
                    pending,
                },
                Want::Read => Did {
                    reads: 1,
                    writes: 0,
                    shut_down: false,
                    seen: Seen::Dispatched(HostEvent::StartAccepted),
                    pending: true,
                },
                Want::Write => Did {
                    reads: 0,
                    writes: 1,
                    shut_down: false,
                    seen: Seen::Written,
                    pending: false,
                },
                Want::Close => Did {
                    reads: 0,
                    writes: 0,
                    shut_down: true,
                    seen: Seen::Ended(ConnectionEnd::Readiness(revents)),
                    pending: false,
                },
            };
            assert_eq!(did, expected, "{shape:?} {name}");
            // Accounting: only a dispatched START charges the limiter and installs a pending
            // Responder; a close releases everything; nothing touches the budget.
            let read = matches!(want, Want::Read);
            let live = !matches!(want, Want::Close);
            assert_eq!(
                (
                    owner.live_connections(),
                    r.counts(),
                    r.charged(),
                    r.routes(),
                    r.reserved(),
                    r.remaining()
                ),
                (
                    usize::from(live),
                    (0, usize::from(live), 0, usize::from(read)),
                    if read { (3, 1) } else { (4, 0) },
                    usize::from(read) + usize::from(live && pending),
                    usize::from(live && pending),
                    10
                ),
                "{shape:?} {name}"
            );
            drop(owner);
            assert_eq!(r.counts(), (0, 0, 0, 0));
            r.release();
        }
    }
}

/// Bytes already read into the adapter's suffix are served one frame per drive under hang-up,
/// each answer is still written to the half-closed peer, and only the read that returns EOF ends
/// the connection. A retained frame with hang-up and no writable readiness waits; nothing is
/// discarded and nothing is drained in one drive.
#[test]
fn retained_input_is_served_frame_by_frame_under_hang_up_before_eof() {
    let r = Node::new("p6-hup-retained");
    let (tc, cc, _) = clocks();
    let (mut owner, net) = hosting(&r, &tc, &cc);
    let (a, sa) = accept(&mut owner, &net);
    let ids = [[0x11; 16], [0x12; 16], [0x13; 16]];
    // One OS read delivers three complete STARTs; the peer's FIN follows them.
    sa.data(&ids.map(|id| start(&id)).concat());
    sa.read(ReadStep::Eof);
    let mut did = |revents| drive_once_with(&mut owner, &net, a, &sa, revents);
    // The first is dispatched on ordinary readability; two complete STARTs stay retained.
    assert_eq!(
        did(POLLRDNORM).seen,
        Seen::Dispatched(HostEvent::StartAccepted)
    );
    for (n, id) in ids.iter().enumerate() {
        if n > 0 {
            // Hang-up alone serves the retained suffix: no OS read, one frame.
            let served = did(POLLHUP);
            assert_eq!(
                (served.reads, served.seen, served.pending),
                (0, Seen::Dispatched(HostEvent::StartAccepted), true)
            );
        }
        // Hang-up without writable readiness: the answer waits, nothing else happens.
        let waited = did(POLLHUP);
        assert_eq!(
            (waited.reads, waited.writes, waited.seen, waited.pending),
            (0, 0, Seen::Nothing, true)
        );
        // Hang-up with writable readiness: the answer goes out.
        assert_eq!(did(POLLHUP | POLLWRNORM).seen, Seen::Written);
        assert!(
            matches!(message(&sa.take_wire()), Message::Accept { request_id, .. } if request_id == *id)
        );
    }
    // Only now does the next read reach the peer's EOF.
    let end = did(POLLHUP);
    assert_eq!(
        (end.reads, end.seen),
        (1, Seen::Ended(ConnectionEnd::Adapter(TcpError::PeerClosed)))
    );
    assert_eq!((sa.reads(), sa.writes(), sa.shutdowns()), (2, 3, 1));
    // Each START was admitted once; the teardown released every pending Responder and slot.
    assert_eq!(
        (r.charged(), r.routes(), r.counts(), r.remaining()),
        ((1, 3), 0, (0, 0, 0, 0), 10)
    );
    drop(owner);
    r.release();
}

/// Hang-up with nothing left to read ends at once through the adapter's EOF, not by readiness:
/// one read in one drive, with a live run torn down exactly as any EOF tears it down.
#[test]
fn a_hang_up_with_nothing_left_ends_at_eof_in_one_drive() {
    let r = Node::new("p6-hup-eof");
    let (tc, cc, _) = clocks();
    let (mut owner, net) = hosting(&r, &tc, &cc);
    let (a, sa) = accept(&mut owner, &net);
    let (b, sb) = accept(&mut owner, &net);
    admit(&mut owner, &net, b, &sb, [0x21; 16]);
    sa.read(ReadStep::Eof);
    sb.read(ReadStep::Eof);
    net.set(sa.raw_socket(), POLLHUP);
    net.set(sb.raw_socket(), POLLHUP);
    let peer_closed = ConnectionEnd::Adapter(TcpError::PeerClosed);
    assert_eq!(
        drive(&mut owner, &net).events,
        vec![
            OwnerEvent::Closed(a, peer_closed.clone()),
            OwnerEvent::Closed(b, peer_closed)
        ]
    );
    assert_eq!(
        (
            sa.reads(),
            sb.reads() > 0,
            sa.writes(),
            sa.shutdowns(),
            sb.shutdowns()
        ),
        (1, true, 0, 1, 1)
    );
    // B's live Responder ended with the connection: no result, no refund, budget unchanged.
    assert_eq!(
        (
            owner.live_connections(),
            r.routes(),
            r.counts(),
            r.charged()
        ),
        (0, 0, (0, 0, 0, 0), (3, 1))
    );
    assert_eq!(r.status(), Status::Ready { remaining: 10 });
    drop(owner);
    r.release();
}

/// A hung-up peer that never reaches EOF (every read WouldBlock) is not closed by hang-up and
/// not refreshed by it: each drive makes exactly one read, and the existing P6-D-001 first-frame,
/// quiescent, and incomplete-frame deadlines close it at their exact boundaries without a read
/// in the expiry drive. No hang-up timer exists.
#[test]
fn a_hang_up_that_never_reaches_eof_is_bounded_by_the_existing_deadlines() {
    let r = Node::new("p6-hup-bounded");
    // First frame: admitted, hung up, nothing ever readable.
    let (tc, cc, _) = clocks();
    let (mut owner, net) = hosting(&r, &tc, &cc);
    let (a, sa) = accept(&mut owner, &net);
    net.set(sa.raw_socket(), POLLHUP);
    for n in 1..=3 {
        assert_eq!(drive(&mut owner, &net), OwnerStep::default());
        assert_eq!(sa.reads(), n);
    }
    tc.set(FIRST_FRAME_DEADLINE - NS);
    assert_eq!(drive(&mut owner, &net), OwnerStep::default());
    tc.set(FIRST_FRAME_DEADLINE);
    assert_eq!(
        drive(&mut owner, &net).events,
        vec![closed_by(a, TransportError::FirstFrameTimeout)]
    );
    assert_eq!(sa.reads(), 4);
    drop((owner, net));
    // Quiescent: a run that ended leaves a hung-up connection that never reaches EOF.
    let (tc, cc, _) = clocks();
    let (mut owner, net) = hosting(&r, &tc, &cc);
    let (b, sb) = accept(&mut owner, &net);
    let x = [0x31; 16];
    admit(&mut owner, &net, b, &sb, x);
    cc.advance(INACTIVITY_DEADLINE);
    assert_eq!(
        step_of(drive(&mut owner, &net), b),
        deadline(Some(&x), INACTIVITY, TimeoutCancel::NotBuilt)
    );
    net.set(sb.raw_socket(), POLLHUP);
    assert_eq!(drive(&mut owner, &net), OwnerStep::default());
    tc.set(QUIESCENT_DEADLINE - NS);
    assert_eq!(drive(&mut owner, &net), OwnerStep::default());
    let reads = sb.reads();
    tc.set(QUIESCENT_DEADLINE);
    assert_eq!(
        drive(&mut owner, &net).events,
        vec![closed_by(b, TransportError::QuiescentTimeout)]
    );
    assert_eq!(sb.reads(), reads);
    drop((owner, net));
    // Incomplete inbound frame: a prefix, then hang-up and nothing more.
    let (tc, cc, _) = clocks();
    let (mut owner, net) = hosting(&r, &tc, &cc);
    let (c, sc) = accept(&mut owner, &net);
    sc.data(&start(&[0x32; 16])[..20]);
    net.set(sc.raw_socket(), POLLHUP | POLLRDNORM);
    assert_eq!(drive(&mut owner, &net), OwnerStep::default());
    assert_eq!(r.counts(), (0, 1, 1, 0));
    tc.set(IDLE_READ_DEADLINE - NS);
    assert_eq!(drive(&mut owner, &net), OwnerStep::default());
    tc.set(IDLE_READ_DEADLINE);
    assert_eq!(
        drive(&mut owner, &net).events,
        vec![closed_by(c, TransportError::IdleTimeout)]
    );
    // Nothing was dispatched or charged, and every slot came back once.
    assert_eq!(
        (r.counts(), r.charged(), r.routes()),
        ((0, 0, 0, 0), (3, 1), 0)
    );
    assert_eq!(r.status(), Status::Ready { remaining: 10 });
    drop(owner);
    r.release();
}

/// A retained frame to a hung-up peer that never accepts a byte is bounded by its governing
/// deadline, never by hang-up: owner-less output by the P6-D-001 2 s no-progress deadline
/// (hang-up alone writes nothing; hang-up with writable readiness tries one write, and
/// WouldBlock is no progress), and output a live run owns by that run's ceremony deadline.
#[test]
fn retained_output_to_a_hung_up_peer_is_bounded_by_its_governing_deadline() {
    // Owner-less: the loop Responder's timeout CANCEL after the SAS.
    let (i, r) = (Node::new("p6-hup-output-i"), Node::new("p6-hup-output-r"));
    let (tc, cc, ci) = clocks();
    let (mut owner, net) = hosting(&r, &tc, &cc);
    let mut p = Pair::accept(&mut owner, &net, &i);
    let id = [0x41; 16];
    let runs = p.open(&mut owner, &net, &ci, id);
    p.keys(&mut owner, &net, &i, &r, &runs);
    p.sock.hold(true);
    cc.advance(ABSOLUTE_DEADLINE);
    assert_eq!(
        step_of(drive(&mut owner, &net), p.conn),
        deadline(Some(&id), ABSOLUTE, TimeoutCancel::Pending)
    );
    let t0 = Duration::from_secs(100);
    tc.set(t0);
    let mut did = |revents| drive_once_with(&mut owner, &net, p.conn, &p.sock, revents);
    let none = |writes| Did {
        reads: 0,
        writes,
        shut_down: false,
        seen: Seen::Nothing,
        pending: true,
    };
    assert_eq!(did(POLLHUP), none(0));
    assert_eq!(did(POLLHUP | POLLWRNORM), none(1));
    tc.set(t0 + RETAINED_OUTPUT_IDLE_DEADLINE - NS);
    assert_eq!(did(POLLHUP | POLLWRNORM), none(1));
    tc.set(t0 + RETAINED_OUTPUT_IDLE_DEADLINE);
    let end = did(POLLHUP | POLLWRNORM);
    assert_eq!(
        (end.writes, end.seen),
        (
            0,
            Seen::Ended(ConnectionEnd::Adapter(TcpError::Host(
                HostError::Transport(TransportError::RetainedOutputIdleTimeout)
            )))
        )
    );
    // The CANCEL never reached the wire; no result, no refund, everything released.
    assert!(p.sock.wire().is_empty());
    assert_eq!(
        (r.routes(), r.counts(), r.status()),
        (0, (0, 0, 0, 0), Status::Ready { remaining: 9 })
    );
    drop((owner, net, p));
    i.release();
    r.release();
    // Owned: a loop Initiator's unwritten START waits behind hang-up for its run's deadline.
    let r = Node::new("p6-hup-owned");
    let (tc, cc, ci) = clocks();
    let (mut owner, net) = hosting(&r, &tc, &cc);
    let (a, sa) = accept(&mut owner, &net);
    let x = [0x42; 16];
    acted_loop(owner.start_initiator_with(
        a,
        ci.clone(),
        &mut OneId(Some(x)),
        initiator_bootstrap(),
        None,
    ));
    net.set(sa.raw_socket(), POLLHUP);
    // A live run suspends every connection timer: an hour of transport time changes nothing.
    tc.set(Duration::from_secs(3600));
    for _ in 0..3 {
        assert_eq!(drive(&mut owner, &net), OwnerStep::default());
    }
    ci.advance(INACTIVITY_DEADLINE);
    assert_eq!(
        step_of(drive(&mut owner, &net), a),
        deadline(Some(&x), INACTIVITY, TimeoutCancel::NotBuilt)
    );
    assert_eq!((sa.writes(), sa.wire()), (0, vec![]));
    // Then the quiescent deadline governs the hung-up connection.
    let quiet = Duration::from_secs(3600);
    assert_eq!(drive(&mut owner, &net), OwnerStep::default());
    tc.set(quiet + QUIESCENT_DEADLINE);
    assert_eq!(
        drive(&mut owner, &net).events,
        vec![closed_by(a, TransportError::QuiescentTimeout)]
    );
    assert_eq!((r.counts(), r.reserved(), r.routes()), ((0, 0, 0, 0), 0, 0));
    drop(owner);
    r.release();
}

/// P6-D-003 changes graceful hang-up only: error or invalid-handle readiness still wins over a
/// complete frame already retained in the adapter, with or without hang-up, before any read or
/// dispatch.
#[test]
fn hard_failure_readiness_wins_over_retained_input() {
    for (n, revents) in [
        POLLERR | POLLIN,
        POLLNVAL | POLLIN,
        POLLERR | POLLHUP | POLLRDNORM,
        POLLNVAL | POLLHUP,
    ]
    .into_iter()
    .enumerate()
    {
        let r = Node::new(&format!("p6-hup-hard-{n}"));
        let (tc, cc, _) = clocks();
        let (mut owner, net) = hosting(&r, &tc, &cc);
        let (a, sa) = accept(&mut owner, &net);
        sa.data(&[start(&[0x51; 16]), start(&[0x52; 16])].concat());
        let mut did = |revents| drive_once_with(&mut owner, &net, a, &sa, revents);
        assert_eq!(
            did(POLLRDNORM).seen,
            Seen::Dispatched(HostEvent::StartAccepted)
        );
        assert_eq!(did(POLLWRNORM).seen, Seen::Written);
        sa.take_wire();
        let end = did(revents);
        assert_eq!(
            (end.reads, end.writes, end.shut_down, end.seen),
            (0, 0, true, Seen::Ended(ConnectionEnd::Readiness(revents))),
            "{revents:#06x}"
        );
        // The retained second START was never dispatched or charged.
        assert_eq!(
            (r.charged(), r.routes(), r.counts()),
            ((3, 1), 0, (0, 0, 0, 0))
        );
        drop(owner);
        r.release();
    }
}

/// Deadline precedence is unchanged: a governing deadline that expires in the same drive as
/// hang-up with readable data wins before any read, and the late frame rescues nothing.
#[test]
fn an_expired_deadline_wins_over_hang_up_with_readable_data() {
    // A valid ACCEPT arrives with the peer's FIN, but the loop Initiator's inactivity deadline
    // passes during the wait.
    let (i, r) = (Node::new("p6-hup-late-i"), Node::new("p6-hup-late-r"));
    let (tc, cc, ci) = clocks();
    let (mut owner, net) = hosting(&i, &tc, &cc);
    let mut p = Pair::accept(&mut owner, &net, &r);
    let x = [0x61; 16];
    acted_loop(owner.start_initiator_with(
        p.conn,
        ci.clone(),
        &mut OneId(Some(x)),
        initiator_bootstrap(),
        None,
    ));
    assert_eq!(
        inbound(p.loop_to_peer(&mut owner, &net)).0,
        HostEvent::StartAccepted
    );
    assert_eq!(p.peer.on_writable(), Ok(written()));
    relay(&p.pio, &p.sock);
    p.sock.read(ReadStep::Eof);
    net.set(p.sock.raw_socket(), POLLHUP | POLLRDNORM);
    let reads = p.sock.reads();
    let clock = ci.clone();
    net.during(move || clock.advance(INACTIVITY_DEADLINE));
    assert_eq!(
        step_of(drive(&mut owner, &net), p.conn),
        deadline(Some(&x), INACTIVITY, TimeoutCancel::NotBuilt)
    );
    assert_eq!(
        p.sock.reads(),
        reads,
        "the late ACCEPT was read in the expiry drive"
    );
    // The next drive reads it: its route is gone, which P3 §11.2 makes session-fatal.
    assert_eq!(
        drive(&mut owner, &net).events,
        vec![OwnerEvent::Closed(
            p.conn,
            ConnectionEnd::Adapter(TcpError::Host(HostError::Routing(
                RouteError::SessionProtocolFailure
            )))
        )]
    );
    assert_eq!(
        (i.routes(), i.counts(), i.reserved(), i.status()),
        (0, (0, 0, 0, 0), 0, Status::Ready { remaining: 10 })
    );
    drop((owner, net, p));
    i.release();
    r.release();
    // The first-frame deadline expires while a complete START and hang-up are reported.
    let r = Node::new("p6-hup-late-first");
    let (tc, cc, _) = clocks();
    let (mut owner, net) = hosting(&r, &tc, &cc);
    let (a, sa) = accept(&mut owner, &net);
    sa.data(&start(&[0x62; 16]));
    net.set(sa.raw_socket(), POLLHUP | POLLRDNORM);
    let clock = tc.clone();
    net.during(move || clock.set(FIRST_FRAME_DEADLINE));
    assert_eq!(
        drive(&mut owner, &net).events,
        vec![closed_by(a, TransportError::FirstFrameTimeout)]
    );
    assert_eq!(
        (sa.reads(), r.charged(), r.counts()),
        (0, (4, 0), (0, 0, 0, 0))
    );
    drop(owner);
    r.release();
}

/// The central case (scripted): the loop is the Responder; the Initiator writes its final ACK,
/// has its result, and closes at once, so the ACK is readable together with hang-up. The loop
/// verifies it and returns the Responder's one result, compatible with the Initiator's; only
/// the next read's EOF ends the connection.
#[test]
fn a_final_ack_delivered_with_hang_up_gives_the_responder_its_result_once() {
    let (i, r) = (Node::new("p6-hup-final-i"), Node::new("p6-hup-final-r"));
    let (tc, cc, ci) = clocks();
    let (mut owner, net) = hosting(&r, &tc, &cc);
    let mut p = Pair::accept(&mut owner, &net, &i);
    let id = [0x71; 16];
    let runs = p.open(&mut owner, &net, &ci, id);
    p.keys(&mut owner, &net, &i, &r, &runs);
    let (theirs, ours) = &runs;
    let identity = *owner
        .presentation(p.conn, ours)
        .unwrap()
        .unwrap()
        .unwrap()
        .ceremony_identity();
    acted(p.peer.approve_sas(theirs, &identity));
    acted(p.peer.emit_bootstrap_mac(theirs));
    assert_eq!(
        inbound(p.peer_to_loop(&mut owner, &net)).0,
        HostEvent::BootstrapMac(PeerApproval::Authenticated)
    );
    acted_loop(owner.approve_sas(p.conn, ours, &identity));
    acted_loop(owner.emit_bootstrap_mac(p.conn, ours));
    assert_eq!(
        inbound(p.loop_to_peer(&mut owner, &net)).0,
        HostEvent::BootstrapMac(PeerApproval::Authenticated)
    );
    acted(p.peer.emit_initiator_finish(theirs));
    assert_eq!(
        inbound(p.peer_to_loop(&mut owner, &net)).0,
        HostEvent::InitiatorFinish
    );
    assert_eq!(
        inbound(p.loop_to_peer(&mut owner, &net)).0,
        HostEvent::ResponderFinishAck
    );
    let step = p.peer.on_writable().unwrap();
    assert_eq!(step.event, Some(TcpEvent::Confirmed));
    let initiator = step.result.expect("Initiator result");
    // The final ACK and the FIN reach the loop's socket together.
    relay(&p.pio, &p.sock);
    p.sock.read(ReadStep::Eof);
    net.set(p.sock.raw_socket(), POLLHUP | POLLRDNORM);
    let step = step_of(drive(&mut owner, &net), p.conn);
    assert!(matches!(
        step.event,
        Some(TcpEvent::Inbound {
            event: HostEvent::InitiatorFinishAck,
            ..
        })
    ));
    assert!(!step.write_pending);
    let responder = step
        .result
        .expect("the delivered final ACK gives the Responder's result");
    results_agree(&initiator, &responder, &id);
    assert_eq!(responder.ceremony_identity(), &identity);
    assert_eq!(
        (r.routes(), r.status()),
        (0, Status::Ready { remaining: 9 })
    );
    // Then EOF: an ordinary teardown, no second result.
    assert_eq!(
        drive(&mut owner, &net).events,
        vec![OwnerEvent::Closed(
            p.conn,
            ConnectionEnd::Adapter(TcpError::PeerClosed)
        )]
    );
    assert_eq!(drive(&mut owner, &net), OwnerStep::default());
    assert_eq!(
        (r.counts(), r.status()),
        ((0, 0, 0, 0), Status::Ready { remaining: 9 })
    );
    drop((owner, net, p));
    i.release();
    r.release();
}

/// EOF never completes a frame: a prefix followed by the peer's FIN is retained, then torn down
/// at EOF with nothing dispatched or charged and the incomplete-frame slot released once.
#[test]
fn a_partial_frame_then_eof_dispatches_nothing() {
    let r = Node::new("p6-hup-partial");
    let (tc, cc, _) = clocks();
    let (mut owner, net) = hosting(&r, &tc, &cc);
    let (a, sa) = accept(&mut owner, &net);
    sa.data(&start(&[0x81; 16])[..20]);
    sa.read(ReadStep::Eof);
    let mut did = |revents| drive_once_with(&mut owner, &net, a, &sa, revents);
    let first = did(POLLHUP | POLLRDNORM);
    assert_eq!((first.reads, first.seen), (1, Seen::Nothing));
    assert_eq!(r.counts(), (0, 1, 1, 0));
    let end = did(POLLHUP);
    assert_eq!(
        (end.reads, end.seen),
        (1, Seen::Ended(ConnectionEnd::Adapter(TcpError::PeerClosed)))
    );
    assert_eq!(
        (r.counts(), r.charged(), r.routes(), r.remaining()),
        ((0, 0, 0, 0), (4, 0), 0, 10)
    );
    drop(owner);
    r.release();
}

// ---- Real Windows loopback through the production loop and `WSAPoll` ----

/// Waits (bounded, never sleeping) until `WSAPoll` reports hang-up on `socket` for readable
/// interest, without reading; returns the reported flags.
fn await_hang_up(socket: SOCKET) -> i16 {
    until(|| {
        let mut fds = [interest(socket, POLLIN)];
        assert!(wsa_poll(&mut fds, 100).is_ok());
        (fds[0].revents & POLLHUP != 0).then_some(fds[0].revents)
    })
}

/// Drives until the loop's only connection `conn` ended; returns how it ended. Nothing else
/// may happen in between, and no step carries a result.
fn until_closed(owner: &mut WindowsOwnerLoop<'_>, conn: ConnectionRef) -> ConnectionEnd {
    until(|| {
        let step = owner.drive_once().unwrap();
        assert_eq!(step.failure, None);
        let mut end = None;
        for event in step.events {
            match event {
                OwnerEvent::Step(c, step) if c == conn => assert_eq!(step.result, None),
                OwnerEvent::Closed(c, ended) if c == conn => end = Some(ended),
                other => panic!("unexpected {other:?}"),
            }
        }
        end
    })
}

/// A complete START written just before a full close is dispatched; the loop's ACCEPT may then
/// meet the closed peer's reset, which ends the connection as a hard error or an I/O reset,
/// never as a hang-up.
#[test]
fn real_complete_start_then_close_is_dispatched() {
    let r = Node::new("p6-hup-real-close");
    let (listener, address) = real_listener();
    let mut owner =
        WindowsOwnerLoop::from_bound_listener(listener, &r.router, responder_bootstrap(), None)
            .unwrap();
    let mut client = TcpStream::connect(address).unwrap();
    let conn = until_accepted(&mut owner).unwrap();
    let id = [0x91; 16];
    client.write_all(&start(&id)).unwrap();
    drop(client);
    let revents = await_hang_up(owner.connections[0].tcp.raw_socket());
    assert_eq!(revents & (POLLHUP | POLLRDNORM), POLLHUP | POLLRDNORM);
    // The START reached admission: the authority's limiter was charged once for it.
    let (event, run) = inbound(until_step(&mut owner, conn));
    assert_eq!(event, HostEvent::StartAccepted);
    assert_eq!(run.unwrap().request_id(), id);
    assert_eq!((r.charged(), r.counts()), ((3, 1), (0, 1, 0, 1)));
    let end = until_closed(&mut owner, conn);
    assert!(
        match &end {
            ConnectionEnd::Adapter(TcpError::PeerClosed) => true,
            ConnectionEnd::Adapter(TcpError::Io(kind)) => {
                matches!(kind, ConnectionReset | ConnectionAborted)
            }
            ConnectionEnd::Readiness(flags) => flags & CONNECTION_FAILED != 0,
            ConnectionEnd::Adapter(_) => false,
        },
        "{end:?}"
    );
    assert_eq!((r.routes(), r.counts(), r.sessions()), (0, (0, 0, 0, 0), 0));
    assert_eq!(r.status(), Status::Ready { remaining: 10 });
    drop(owner);
    r.release();
}

/// `shutdown(Send)` closes only the peer's sending direction: after it, the loop reads the
/// START, answers, and the half-closed peer reads that ACCEPT. Then EOF ends the connection.
#[test]
fn real_start_then_shutdown_send_still_receives_the_accept() {
    let r = Node::new("p6-hup-real-half-close");
    let (listener, address) = real_listener();
    let mut owner =
        WindowsOwnerLoop::from_bound_listener(listener, &r.router, responder_bootstrap(), None)
            .unwrap();
    let mut client = TcpStream::connect(address).unwrap();
    let conn = until_accepted(&mut owner).unwrap();
    let id = [0x92; 16];
    client.write_all(&start(&id)).unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let revents = await_hang_up(owner.connections[0].tcp.raw_socket());
    assert_eq!(revents & (POLLHUP | POLLRDNORM), POLLHUP | POLLRDNORM);
    assert_eq!(
        inbound(until_step(&mut owner, conn)).0,
        HostEvent::StartAccepted
    );
    assert_eq!(until_step(&mut owner, conn), written());
    let accept = read_frame(&mut client);
    assert!(matches!(message(&accept), Message::Accept { request_id, .. } if request_id == id));
    assert_eq!(
        until_closed(&mut owner, conn),
        ConnectionEnd::Adapter(TcpError::PeerClosed)
    );
    assert_eq!(
        (r.routes(), r.counts(), r.charged()),
        (0, (0, 0, 0, 0), (3, 1))
    );
    drop(owner);
    drop(client);
    r.release();
}

/// Two complete STARTs delivered before the peer's `shutdown(Send)` are each dispatched exactly
/// once, one per drive, each answered to the half-closed peer, before EOF ends the connection.
#[test]
fn real_two_frames_before_shutdown_send_are_each_dispatched_once() {
    let r = Node::new("p6-hup-real-two");
    let (listener, address) = real_listener();
    let mut owner =
        WindowsOwnerLoop::from_bound_listener(listener, &r.router, responder_bootstrap(), None)
            .unwrap();
    let mut client = TcpStream::connect(address).unwrap();
    let conn = until_accepted(&mut owner).unwrap();
    let ids = [[0x93; 16], [0x94; 16]];
    client
        .write_all(&ids.map(|id| start(&id)).concat())
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    await_hang_up(owner.connections[0].tcp.raw_socket());
    for id in ids {
        let (event, run) = inbound(until_step(&mut owner, conn));
        assert_eq!(event, HostEvent::StartAccepted);
        assert_eq!(run.unwrap().request_id(), id);
        assert_eq!(until_step(&mut owner, conn), written());
        let accept = read_frame(&mut client);
        assert!(matches!(message(&accept), Message::Accept { request_id, .. } if request_id == id));
    }
    assert_eq!((r.charged(), r.counts()), ((2, 2), (0, 1, 0, 2)));
    assert_eq!(
        until_closed(&mut owner, conn),
        ConnectionEnd::Adapter(TcpError::PeerClosed)
    );
    assert_eq!(
        (r.routes(), r.counts(), r.remaining()),
        (0, (0, 0, 0, 0), 10)
    );
    drop(owner);
    drop(client);
    r.release();
}
