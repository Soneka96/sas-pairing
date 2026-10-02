//! P5.2 review-only evidence (NOT part of the product; changes no production behavior): the
//! owner loop's readiness classification and precedence (scripted readiness), deadline-versus-
//! socket precedence, and real Windows graceful-close behavior for P5-F-001. Families
//! `LOOP-READY-*`, `LOOP-DEADLINE-*`, `LOOP-HUP-*`, and `F001-*` in
//! `docs/p5-security-review/adversarial-sequences.md`. Ignored tests here are EXPECTED-FAIL
//! known-bug reproducers: they state the desired future behavior and fail until P6.
use super::*;
use crate::{ceremony::PairingResult, windows_tcp::tests::admit as admit_on};
use windows_sys::Win32::Networking::WinSock::{POLLHUP, POLLRDNORM};

/// A refused START: dispatched (a run-local refusal) without key generation, once `node`'s
/// START limiter is drained.
fn drain_limiter(node: &Node) {
    let (tc, cc, _) = clocks();
    let (mut tcp, io) = node.connect(&tc, &cc);
    for n in 0..4u8 {
        admit_on(&mut tcp, &io, &start(&[0xD0 + n; 16]));
    }
    drop(tcp);
    assert_eq!(node.charged(), (0, 4));
}

const LIMITED: TcpEvent = TcpEvent::Refused(RouteError::Ceremony(CeremonyError::Owner(
    crate::Error::ResourceLimited,
)));

/// The connection's adapter state when its readiness is reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    /// No retained output or input; one complete frame is readable on the socket.
    Idle,
    /// One retained outbound frame (a local Initiator's START); nothing readable.
    WritePending,
    /// A complete frame retained in the read suffix; nothing new on the socket.
    Buffered,
}

/// What one drive did to the connection.
#[derive(Debug, PartialEq, Eq)]
struct Did {
    read: bool,
    write: bool,
    closed: bool,
    event: String,
    failure: bool,
}

fn did(
    owner: &mut Loop<'_>,
    net: &Net,
    conn: ConnectionRef,
    socket: &Scripted,
    revents: i16,
) -> Did {
    let (reads, writes, shutdowns) = (socket.reads(), socket.writes(), socket.shutdowns());
    net.set(socket.raw_socket(), revents);
    let step = try_drive(owner, net).unwrap();
    let event = match step.events.as_slice() {
        [] => "none".to_string(),
        [OwnerEvent::Step(c, step)] if *c == conn => match &step.event {
            Some(TcpEvent::Inbound { event, .. }) => format!("dispatch {event:?}"),
            Some(event) => format!("{event:?}"),
            None => "step without event".to_string(),
        },
        [OwnerEvent::Closed(c, end)] if *c == conn => format!("closed {end:?}"),
        other => format!("{other:?}"),
    };
    Did {
        read: socket.reads() > reads,
        write: socket.writes() > writes,
        closed: socket.shutdowns() > shutdowns,
        event,
        failure: step.failure.is_some(),
    }
}

/// LOOP-READY-001: every representative `revents` combination against each adapter shape,
/// through scripted readiness. Durable precedence (asserted): error or invalid-handle readiness
/// closes the connection before any read or write; with a retained frame only writable
/// readiness writes; otherwise readable readiness (or retained input, with no wait) reads; no
/// readiness does nothing; no combination fails the whole loop. Hang-up rows are recorded, not
/// asserted: P5-F-001 challenges their current close-before-read handling.
#[test]
fn p5_loop_ready_001_readiness_combinations_and_precedence() {
    let r = Node::new("p5-loop-ready");
    drain_limiter(&r);
    let combos: [(&str, i16); 11] = [
        ("0", 0),
        ("POLLIN", POLLIN),
        ("POLLRDNORM", POLLRDNORM),
        ("POLLOUT", POLLOUT),
        ("POLLHUP", POLLHUP),
        ("POLLHUP|POLLIN", POLLHUP | POLLIN),
        ("POLLHUP|POLLRDNORM", POLLHUP | POLLRDNORM),
        ("POLLERR", POLLERR),
        ("POLLERR|POLLIN", POLLERR | POLLIN),
        ("POLLNVAL", POLLNVAL),
        ("POLLOUT|POLLHUP", POLLOUT | POLLHUP),
    ];
    let mut table = Vec::new();
    for shape in [Shape::Idle, Shape::WritePending, Shape::Buffered] {
        for (name, revents) in combos {
            let (tc, cc, _) = clocks();
            let (mut owner, net) = hosting(&r, &tc, &cc);
            let (conn, socket) = accept(&mut owner, &net);
            match shape {
                Shape::Idle => socket.data(&start(&[1; 16])),
                Shape::WritePending => {
                    acted_loop(owner.start_initiator_with(
                        conn,
                        ManualClock::new(),
                        &mut OneId(Some([0x61; 16])),
                        initiator_bootstrap(),
                        None,
                    ));
                }
                Shape::Buffered => {
                    socket.data(&[start(&[1; 16]), start(&[2; 16])].concat());
                    assert_eq!(step_of(drive(&mut owner, &net), conn).event, Some(LIMITED));
                }
            }
            let result = did(&mut owner, &net, conn, &socket, revents);
            let failed = revents & (POLLERR | POLLNVAL) != 0;
            let hang_up = revents & POLLHUP != 0;
            assert!(!result.failure, "{shape:?} {name}: whole loop failed");
            if failed {
                assert!(
                    result.closed && !result.read && !result.write,
                    "{shape:?} {name}"
                );
            } else if !hang_up {
                let expect_read = match shape {
                    Shape::Idle => revents & POLLIN != 0,
                    Shape::WritePending => false,
                    Shape::Buffered => true,
                };
                let expect_write = shape == Shape::WritePending && revents & POLLOUT != 0;
                assert_eq!(
                    (
                        result.read
                            || (shape == Shape::Buffered && result.event.starts_with("Refused")),
                        result.write,
                        result.closed
                    ),
                    (expect_read, expect_write, false),
                    "{shape:?} {name}: {result:?}"
                );
                if shape == Shape::Buffered {
                    // The retained frame was served from the suffix with no wait and no read.
                    assert_eq!(net.last_wait().1, 0);
                    assert!(!result.read);
                }
            }
            table.push(format!(
                "{shape:?} | {name} | read {} | write {} | close {} | event {} | loop failure {}",
                result.read, result.write, result.closed, result.event, result.failure
            ));
            drop(owner);
            assert_eq!(r.counts(), (0, 0, 0, 0));
        }
    }
    eprintln!("LOOP-READY-001:\n  {}", table.join("\n  "));
    r.release();
}

/// LOOP-DEADLINE-001: a deadline that passes during the readiness wait while the socket is
/// readable or writable. The post-wait sweep wins: no expired run's frame is read or written in
/// that drive. Read: the expired run's next frame stays unread (a later drive finds its route
/// gone, which P3 §11.2 makes session-fatal). Write: an expired run's unsent frame is
/// discarded. An owner-less CANCEL of an already terminal run has no deadline and is written.
#[test]
fn p5_loop_deadline_001_deadline_wins_over_readiness() {
    let r = Node::new("p5-loop-deadline");
    let (tc, cc, _) = clocks();
    let (mut owner, net) = hosting(&r, &tc, &cc);
    // Read: a local Initiator awaits ACCEPT; a frame for it is readable; its 60 s inactivity
    // passes during the wait.
    let (a, sa) = accept(&mut owner, &net);
    let ci = ManualClock::new();
    let x = [0x71; 16];
    acted_loop(owner.start_initiator_with(
        a,
        ci.clone(),
        &mut OneId(Some(x)),
        initiator_bootstrap(),
        None,
    ));
    assert_eq!(step_of(drive(&mut owner, &net), a), written());
    sa.take_wire();
    // Any frame for that run will do; it must not be read in the drive that expires the run.
    sa.data(&initiator_key(&x));
    let reads = sa.reads();
    let clock = ci.clone();
    net.during(move || clock.advance(INACTIVITY_DEADLINE));
    let step = step_of(drive(&mut owner, &net), a);
    assert_eq!(
        step,
        deadline(Some(&x), INACTIVITY, TimeoutCancel::NotBuilt)
    );
    assert_eq!(
        sa.reads(),
        reads,
        "the expired run's frame was read in the expiry drive"
    );
    // The next drive reads it: its route is gone, so the session ends (P3 §11.2).
    assert!(matches!(
        drive(&mut owner, &net).events.as_slice(),
        [OwnerEvent::Closed(c, ConnectionEnd::Adapter(TcpError::Host(HostError::Routing(RouteError::SessionProtocolFailure))))] if *c == a
    ));
    // Write: a retained START of a run that expires during the wait is never written.
    let (b, sb) = accept(&mut owner, &net);
    let ci = ManualClock::new();
    let y = [0x72; 16];
    acted_loop(owner.start_initiator_with(
        b,
        ci.clone(),
        &mut OneId(Some(y)),
        initiator_bootstrap(),
        None,
    ));
    let clock = ci.clone();
    net.during(move || clock.advance(INACTIVITY_DEADLINE));
    assert_eq!(
        step_of(drive(&mut owner, &net), b),
        deadline(Some(&y), INACTIVITY, TimeoutCancel::NotBuilt)
    );
    assert_eq!((sb.writes(), sb.wire()), (0, vec![]));
    drop(owner);
    r.release();

    // An owner-less CANCEL (the loop Responder's timeout after SAS) is written after any wait.
    let (i, r) = (
        Node::new("p5-loop-deadline-ci"),
        Node::new("p5-loop-deadline-cr"),
    );
    let (tc, cc, ci) = clocks();
    let (mut owner, net) = hosting(&r, &tc, &cc);
    let mut p = Pair::accept(&mut owner, &net, &i);
    let runs = p.open(&mut owner, &net, &ci, [0x73; 16]);
    p.keys(&mut owner, &net, &i, &r, &runs);
    let clock = cc.clone();
    net.during(move || clock.advance(ABSOLUTE_DEADLINE));
    let step = step_of(drive(&mut owner, &net), p.conn);
    assert_eq!(
        step,
        deadline(Some(&[0x73; 16]), ABSOLUTE, TimeoutCancel::Pending)
    );
    let clock = cc.clone();
    net.during(move || clock.advance(ABSOLUTE_DEADLINE));
    assert_eq!(step_of(drive(&mut owner, &net), p.conn), written());
    assert_eq!(
        cancel_of(&p.sock.wire()),
        (Role::Responder, CancelReason::Timeout)
    );
    drop((owner, p));
    i.release();
    r.release();
}

/// F001-001 (scripted, PASSING EVIDENCE): the loop as Responder with its peer's complete final
/// ACK readable together with hang-up readiness (`POLLHUP | POLLRDNORM`, as Windows reports a
/// graceful close). Durable safety assertions only: the Responder never gets a result from an
/// incomplete or unread frame, never a second result, and every resource is released; the
/// Initiator's result is unaffected. Whether the Responder got its result is recorded (today it
/// does not: P5-F-001).
#[test]
fn p5_f001_001_scripted_final_ack_with_hang_up_fails_closed_safely() {
    let (i, r) = (
        Node::new("p5-f001-scripted-i"),
        Node::new("p5-f001-scripted-r"),
    );
    let (tc, cc, ci) = clocks();
    let (mut owner, net) = hosting(&r, &tc, &cc);
    let mut p = Pair::accept(&mut owner, &net, &i);
    let runs = p.open(&mut owner, &net, &ci, [0x81; 16]);
    p.keys(&mut owner, &net, &i, &r, &runs);
    let (theirs, ours) = &runs;
    let identity = *p
        .peer
        .presentation(theirs)
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
    // The Initiator writes its final ACK completely and has its result.
    let step = p.peer.on_writable().unwrap();
    assert_eq!(step.event, Some(TcpEvent::Confirmed));
    assert!(step.result.is_some());
    // The ACK reaches the loop's socket, reported readable together with hang-up.
    relay(&p.pio, &p.sock);
    p.sock.read(ReadStep::Eof);
    net.set(p.sock.raw_socket(), POLLHUP | POLLRDNORM);
    let events = drive(&mut owner, &net).events;
    let r_result = events.iter().find_map(|e| match e {
        OwnerEvent::Step(_, step) => step.result.clone(),
        _ => None,
    });
    if let Some(result) = &r_result {
        assert_eq!(result.ceremony_identity(), &identity);
    }
    // Drive until the connection is gone; at most one Responder result in total.
    let mut later = 0;
    for _ in 0..4 {
        for e in drive(&mut owner, &net).events {
            if matches!(&e, OwnerEvent::Step(_, s) if s.result.is_some()) {
                later += 1;
            }
        }
    }
    assert!(
        later + usize::from(r_result.is_some()) <= 1,
        "second Responder result"
    );
    assert_eq!(owner.live_connections(), 0);
    assert_eq!((r.routes(), r.counts()), (0, (0, 0, 0, 0)));
    assert_eq!(r.status(), Status::Ready { remaining: 9 });
    eprintln!(
        "F001-001: drive events {events:?}; Responder result: {}",
        if r_result.is_some() {
            "yes"
        } else {
            "NO (P5-F-001)"
        }
    );
    drop((owner, p));
    i.release();
    r.release();
}

// ---- Real Windows sockets: LOOP-HUP-001 and the F-001 owner-loop reproducers ----

/// Waits (bounded, never sleeping) until `WSAPoll` on `socket` reports hang-up for readable
/// interest, without reading. Returns the reported `revents`.
fn await_hang_up(socket: SOCKET) -> i16 {
    await_hang_up_for(socket, POLLIN)
}

/// `await_hang_up` for the given interest (`POLLIN` or `POLLOUT`, as the loop would ask).
fn await_hang_up_for(socket: SOCKET, events: i16) -> i16 {
    let give_up = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let mut fds = [WSAPOLLFD {
            fd: socket,
            events,
            revents: 0,
        }];
        assert!(wsa_poll(&mut fds, 100).is_ok());
        if fds[0].revents & POLLHUP != 0 {
            return fds[0].revents;
        }
        assert!(
            std::time::Instant::now() < give_up,
            "no hang-up readiness in 10 s"
        );
    }
}

/// How a client ends its side in one LOOP-HUP case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClientEnd {
    Close,
    ShutdownSend,
}

struct HupCase {
    name: &'static str,
    bytes: Vec<u8>,
    complete: usize,
    end: ClientEnd,
}

fn hup_cases() -> Vec<HupCase> {
    let (a, b) = (start(&[0xA1; 16]), start(&[0xA2; 16]));
    vec![
        HupCase {
            name: "A full frame, close",
            bytes: a.clone(),
            complete: 1,
            end: ClientEnd::Close,
        },
        HupCase {
            name: "B full frame, shutdown(Send), socket kept",
            bytes: a.clone(),
            complete: 1,
            end: ClientEnd::ShutdownSend,
        },
        HupCase {
            name: "C partial frame, close",
            bytes: a[..20].to_vec(),
            complete: 0,
            end: ClientEnd::Close,
        },
        HupCase {
            name: "D two frames, close",
            bytes: [a, b].concat(),
            complete: 2,
            end: ClientEnd::Close,
        },
    ]
}

/// One real graceful-close case against the production owner loop (real listener, real
/// `WSAPoll`). Returns `(revents, events until the connection ended, frames dispatched)`.
fn run_hup_case(case: &HupCase) -> (i16, Vec<String>, usize) {
    let r = Node::new(&format!("p5-loop-hup-{}", &case.name[..1]));
    let (listener, address) = real_listener();
    let mut owner =
        WindowsOwnerLoop::from_bound_listener(listener, &r.router, responder_bootstrap(), None)
            .unwrap();
    let mut client = TcpStream::connect(address).unwrap();
    let conn = until_accepted(&mut owner).unwrap();
    client.write_all(&case.bytes).unwrap();
    let kept = match case.end {
        ClientEnd::Close => {
            drop(client);
            None
        }
        ClientEnd::ShutdownSend => {
            client.shutdown(std::net::Shutdown::Write).unwrap();
            Some(client)
        }
    };
    // Deterministic, no sleep: the hang-up is reported before the loop's next readiness wait.
    let revents = await_hang_up(owner.connections[0].tcp.raw_socket());
    let mut events = Vec::new();
    let mut dispatched = 0;
    let give_up = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while owner.live_connections() > 0 {
        assert!(
            std::time::Instant::now() < give_up,
            "connection never ended"
        );
        let step = owner.drive_once().unwrap();
        assert_eq!(step.failure, None);
        for event in step.events {
            match &event {
                OwnerEvent::Step(c, step) if *c == conn => {
                    assert!(step.result.is_none());
                    if matches!(step.event, Some(TcpEvent::Inbound { .. })) {
                        dispatched += 1;
                    }
                }
                OwnerEvent::Closed(c, _) => assert_eq!(*c, conn),
                other => panic!("unexpected {other:?}"),
            }
            events.push(format!("{event:?}"));
        }
    }
    // Cleanup is exact whatever was dispatched.
    assert_eq!((r.routes(), r.counts(), r.sessions()), (0, (0, 0, 0, 0), 0));
    assert_eq!(r.status(), Status::Ready { remaining: 10 });
    drop(kept);
    drop(owner);
    r.release();
    (revents, events, dispatched)
}

/// LOOP-HUP-001 (real Windows, PASSING EVIDENCE): a peer writes then closes or half-closes.
/// Durable OS facts and safety asserted: `WSAPoll` reports `POLLHUP` together with readable
/// data; no incomplete frame is ever dispatched; nothing is dispatched twice; the connection
/// ends and everything is released. How many complete frames the loop dispatched before closing
/// is recorded, not asserted (today none: P5-F-001).
#[test]
fn p5_loop_hup_001_real_graceful_close_matrix() {
    let mut rows = Vec::new();
    for case in hup_cases() {
        let (revents, events, dispatched) = run_hup_case(&case);
        assert_ne!(revents & POLLHUP, 0, "{}", case.name);
        assert_ne!(
            revents & POLLRDNORM,
            0,
            "{}: hang-up without readable data",
            case.name
        );
        assert!(dispatched <= case.complete, "{}", case.name);
        rows.push(format!(
            "{} | revents 0x{revents:04x} | dispatched {dispatched}/{} complete | events {events:?}",
            case.name, case.complete
        ));
    }
    eprintln!("LOOP-HUP-001:\n  {}", rows.join("\n  "));
}

/// P5-F-001 EXPECTED-FAIL KNOWN-BUG REPRODUCER (desired behavior; fails until P6): every
/// complete frame a peer wrote before its graceful close or half-close is dispatched before the
/// loop ends the connection. Run with
/// `cargo test --manifest-path core/Cargo.toml --lib p5_f_001_owner_loop -- --ignored --nocapture`.
#[test]
#[ignore = "P5-F-001 known bug: the owner loop closes on POLLHUP before reading; enable after P6"]
fn p5_f_001_owner_loop_dispatches_complete_frames_before_graceful_close() {
    let mut lost = Vec::new();
    for case in hup_cases() {
        let (revents, events, dispatched) = run_hup_case(&case);
        if dispatched != case.complete {
            lost.push(format!(
                "{}: revents 0x{revents:04x}, dispatched {dispatched}/{}, events {events:?}",
                case.name, case.complete
            ));
        }
    }
    assert!(
        lost.is_empty(),
        "frames lost before close:\n  {}",
        lost.join("\n  ")
    );
}

/// Drives a real ceremony with the production owner loop as Responder and a direct adapter as
/// Initiator up to the Initiator's confirmed final ACK, then the Initiator closes at once.
/// Returns `(Initiator result, revents at the loop, Responder results, loop events after)`.
fn final_ack_then_close() -> (PairingResult, i16, Vec<PairingResult>, Vec<String>) {
    let (i, r) = (Node::new("p5-f001-real-i"), Node::new("p5-f001-real-r"));
    let (listener, address) = real_listener();
    let mut owner =
        WindowsOwnerLoop::from_bound_listener(listener, &r.router, responder_bootstrap(), None)
            .unwrap();
    let client = TcpStream::connect(address).unwrap();
    let conn = until_accepted(&mut owner).unwrap();
    let permit = AcceptPermit::begin(&i.router).unwrap();
    let mut peer =
        WindowsTcpConnection::from_accepted(client, permit, responder_bootstrap(), None).unwrap();
    let theirs = acted(peer.start_initiator(initiator_bootstrap(), None))
        .run
        .unwrap();
    assert_eq!(sent(&mut peer), written());
    let (event, ours) = inbound(until_step(&mut owner, conn));
    assert_eq!(event, HostEvent::StartAccepted);
    let ours = ours.unwrap();
    assert_eq!(until_step(&mut owner, conn), written());
    assert_eq!(inbound(received(&mut peer)).0, HostEvent::Accept);
    acted(peer.authorize_exposure(&theirs, &i.trusted));
    acted(peer.expose_key(&theirs));
    assert_eq!(sent(&mut peer), written());
    assert_eq!(
        inbound(until_step(&mut owner, conn)).0,
        HostEvent::InitiatorKey
    );
    acted_loop(owner.authorize_exposure(conn, &ours, &r.trusted));
    acted_loop(owner.expose_key(conn, &ours));
    assert_eq!(until_step(&mut owner, conn), written());
    assert_eq!(inbound(received(&mut peer)).0, HostEvent::ResponderKey);
    let shown = peer.presentation(&theirs).unwrap().unwrap().unwrap();
    let identity = *shown.ceremony_identity();
    acted(peer.approve_sas(&theirs, &identity));
    acted(peer.emit_bootstrap_mac(&theirs));
    assert_eq!(sent(&mut peer), written());
    assert_eq!(
        inbound(until_step(&mut owner, conn)).0,
        HostEvent::BootstrapMac(PeerApproval::Authenticated)
    );
    acted_loop(owner.approve_sas(conn, &ours, &identity));
    acted_loop(owner.emit_bootstrap_mac(conn, &ours));
    assert_eq!(until_step(&mut owner, conn), written());
    assert_eq!(
        inbound(received(&mut peer)).0,
        HostEvent::BootstrapMac(PeerApproval::Authenticated)
    );
    acted(peer.emit_initiator_finish(&theirs));
    assert_eq!(sent(&mut peer), written());
    assert_eq!(
        inbound(until_step(&mut owner, conn)).0,
        HostEvent::InitiatorFinish
    );
    assert_eq!(until_step(&mut owner, conn), written());
    assert_eq!(
        inbound(received(&mut peer)).0,
        HostEvent::ResponderFinishAck
    );
    // The Initiator's final ACK leaves completely: its result exists.
    let step = until(|| {
        let step = peer.on_writable().unwrap();
        step.event.is_some().then_some(step)
    });
    assert_eq!(step.event, Some(TcpEvent::Confirmed));
    let initiator = step.result.unwrap();
    // A natural application pattern: close right after success.
    drop(peer);
    let revents = await_hang_up(owner.connections[0].tcp.raw_socket());
    let mut results = Vec::new();
    let mut events = Vec::new();
    let give_up = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while owner.live_connections() > 0 {
        assert!(
            std::time::Instant::now() < give_up,
            "connection never ended"
        );
        let step = owner.drive_once().unwrap();
        assert_eq!(step.failure, None);
        for event in step.events {
            if let OwnerEvent::Step(_, step) = &event
                && let Some(result) = &step.result
            {
                results.push(result.clone());
            }
            events.push(format!("{event:?}"));
        }
    }
    assert_eq!((r.routes(), r.counts()), (0, (0, 0, 0, 0)));
    assert_eq!(r.status(), Status::Ready { remaining: 9 });
    assert_eq!(i.status(), Status::Ready { remaining: 9 });
    drop(owner);
    i.release();
    r.release();
    (initiator, revents, results, events)
}

/// LOOP-HUP-002 (real Windows, PASSING EVIDENCE): the Initiator's final ACK followed at once by
/// its graceful close, against the production owner loop as Responder. Durable safety asserted:
/// at most one Responder result, and any result is authentic for the same ceremony; everything
/// is released. Whether the Responder got its result is recorded (today: no, P5-F-001).
#[test]
fn p5_loop_hup_002_real_final_ack_then_close_is_safe() {
    let (initiator, revents, results, events) = final_ack_then_close();
    assert!(results.len() <= 1, "second Responder result");
    if let Some(responder) = results.first() {
        results_agree(&initiator, responder, initiator.request_id());
    }
    eprintln!(
        "LOOP-HUP-002: revents 0x{revents:04x}; Responder results {}; events {events:?}",
        results.len()
    );
}

/// P5-F-001 EXPECTED-FAIL KNOWN-BUG REPRODUCER (desired behavior; fails until P6): with the
/// owner loop as Responder, an Initiator that writes its final INITIATOR_FINISH_ACK and closes
/// immediately leaves the ACK readable while Windows reports `POLLHUP | POLLRDNORM`; the loop
/// should verify it and return the Responder's result. Today it closes without reading. Run with
/// `cargo test --manifest-path core/Cargo.toml --lib p5_f_001_owner_loop -- --ignored --nocapture`.
#[test]
#[ignore = "P5-F-001 known bug: the owner loop drops a final ACK that arrives with hang-up; enable after P6"]
fn p5_f_001_owner_loop_responder_loses_final_ack_before_graceful_close() {
    let (initiator, revents, results, events) = final_ack_then_close();
    eprintln!("revents 0x{revents:04x}; events {events:?}");
    let responder = results
        .first()
        .expect("the Responder's result: its final ACK was delivered before the close");
    results_agree(&initiator, responder, initiator.request_id());
}

/// The loop's own retained output when the peer half-closes (`shutdown(Send)`), as a peer with
/// nothing more to send may do (for example a Responder after RESPONDER_FINISH_ACK, which then
/// only awaits the final ACK). Returns `(revents for writable interest, loop events until the
/// connection ended or the frame was written, bytes the peer received)`.
fn half_close_with_output_pending() -> (i16, Vec<String>, Vec<u8>) {
    let r = Node::new("p5-loop-hup-output");
    let (listener, address) = real_listener();
    let mut owner =
        WindowsOwnerLoop::from_bound_listener(listener, &r.router, responder_bootstrap(), None)
            .unwrap();
    let mut client = TcpStream::connect(address).unwrap();
    let conn = until_accepted(&mut owner).unwrap();
    // The loop's local Initiator: START is retained and not yet written.
    let started = acted_loop(owner.start_initiator(conn, initiator_bootstrap(), None));
    assert!(started.write_pending);
    client.shutdown(std::net::Shutdown::Write).unwrap();
    let revents = await_hang_up_for(owner.connections[0].tcp.raw_socket(), POLLOUT);
    let mut events = Vec::new();
    let give_up = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut written_out = false;
    while owner.live_connections() > 0 && !written_out {
        assert!(
            std::time::Instant::now() < give_up,
            "neither written nor closed"
        );
        let step = owner.drive_once().unwrap();
        assert_eq!(step.failure, None);
        for event in step.events {
            written_out |=
                matches!(&event, OwnerEvent::Step(_, s) if s.event == Some(TcpEvent::Written));
            events.push(format!("{event:?}"));
        }
    }
    client
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let mut received = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match client.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                received.extend_from_slice(&buf[..n]);
                if protocol::decode(&received).is_ok() {
                    break;
                }
            }
        }
    }
    drop(owner);
    drop(client);
    assert_eq!((r.routes(), r.counts()), (0, (0, 0, 0, 0)));
    r.release();
    (revents, events, received)
}

/// LOOP-HUP-003 (real Windows, PASSING EVIDENCE): the peer half-closes while the loop holds an
/// unwritten frame. Durable facts asserted: `WSAPoll` reports `POLLHUP` for writable interest
/// too; whatever reaches the peer is a prefix of one canonical frame (never a different or
/// repeated frame); everything is released. Whether the frame was written is recorded (today:
/// the loop closes without writing, a write-side facet of P5-F-001).
#[test]
fn p5_loop_hup_003_real_half_close_while_output_pending() {
    let (revents, events, received) = half_close_with_output_pending();
    assert_ne!(revents & POLLHUP, 0);
    if !received.is_empty() {
        assert!(matches!(
            protocol::decode(&received).map(|m| m.message),
            Ok(Message::Start { .. })
        ));
    }
    eprintln!(
        "LOOP-HUP-003: revents 0x{revents:04x}; peer received {} bytes; events {events:?}",
        received.len()
    );
}

/// P5-F-001 EXPECTED-FAIL KNOWN-BUG REPRODUCER (write side; desired behavior; fails until P6):
/// a peer's half-close ends only its sending direction, so the loop should still write the
/// frame it holds. Today `POLLHUP` closes the connection first. Run with
/// `cargo test --manifest-path core/Cargo.toml --lib p5_f_001_owner_loop -- --ignored --nocapture`.
#[test]
#[ignore = "P5-F-001 known bug: POLLHUP after a peer half-close drops the loop's pending output; enable after P6"]
fn p5_f_001_owner_loop_writes_pending_output_after_peer_half_close() {
    let (revents, events, received) = half_close_with_output_pending();
    assert!(
        matches!(
            protocol::decode(&received).map(|m| m.message),
            Ok(Message::Start { .. })
        ),
        "the retained START never reached the half-closed peer: revents 0x{revents:04x}, events {events:?}"
    );
}
