//! P5.2 review-only evidence (NOT part of the product; changes no production behavior):
//! deterministic stream, socket-script, deadline, and retained-output sequences over the
//! experimental Windows TCP adapter, with scripted sockets and hand clocks. Families
//! `F007-*`, `TCP-STREAM-*`, `TCP-RD-*`, `TCP-W-*`, `TCP-DEADLINE-*`, `F002-*`, and `TCP-OUT-*` in
//! `docs/p5-security-review/adversarial-sequences.md`. Ignored tests here are EXPECTED-FAIL
//! known-bug reproducers: they state the desired future invariant and fail until P6. The
//! P5-F-002 reproducer failed through P5 and became a normal regression test in P6.1.
use super::*;
use crate::start_limiter::ROLLING_WINDOW;
use std::fmt::Write as _;

const ONE_DAY: Duration = Duration::from_secs(24 * 60 * 60);

/// An authority whose START limiter clock the test can advance, and its router.
fn node(scope: &str) -> (Node, Arc<ManualClock>) {
    let limiter = ManualClock::new();
    let trusted =
        TrustedAuthority::register_with_limiter_clock(scope.as_bytes(), limiter.clone()).unwrap();
    let executor = trusted.executor();
    let router = Router::new(executor.clone()).unwrap();
    (
        Node {
            trusted,
            executor,
            router,
        },
        limiter,
    )
}

/// A node whose START limiter is exhausted (and never advanced), so every later START is a
/// cheap, uncharged, run-local `ResourceLimited` refusal: a probe frame whose dispatch is
/// observable without key generation.
fn drained(scope: &str) -> Node {
    let (r, _) = node(scope);
    let (tc, cc, _) = clocks();
    let (mut tcp, io) = r.connect(&tc, &cc);
    for n in 0..4u8 {
        admit(&mut tcp, &io, &start(&[0xD0 + n; 16]));
    }
    drop(tcp);
    assert_eq!(r.charged(), (0, 4));
    assert_eq!(r.counts(), (0, 0, 0, 0));
    r
}

const LIMITED: TcpEvent = TcpEvent::Refused(RouteError::Ceremony(CeremonyError::Owner(
    crate::Error::ResourceLimited,
)));

/// A START larger than one socket read chunk (two reads), structurally valid.
fn big_start(id: u8) -> Vec<u8> {
    let frame = start_with(
        &[id; 16],
        Bootstrap::new(
            vec![7; 1024],
            initiator_bootstrap().key_algorithm().to_vec(),
            vec![6; 4096],
            vec![8; 8192],
        )
        .unwrap(),
    );
    assert!(frame.len() > SOCKET_READ_CHUNK);
    frame
}

/// Drives `tcp` until its script is used up and no retained input or output remains, writing
/// any retained frame at once. Returns every event in order and the error that ended the
/// connection, if any. Each adapter call performs at most one socket operation.
fn drain(tcp: &mut Tcp<'_>, io: &Scripted) -> (Vec<TcpEvent>, Option<TcpError>) {
    let mut events = Vec::new();
    for _ in 0..200_000 {
        let (reads, writes) = (io.reads(), io.writes());
        let step = if tcp.write_pending() {
            tcp.on_writable()
        } else {
            tcp.on_readable()
        };
        assert!(
            io.reads() + io.writes() <= reads + writes + 1,
            "more than one socket operation in one call"
        );
        match step {
            Err(error) => return (events, Some(error)),
            Ok(step) => {
                assert_eq!(step.result, None);
                match step.event {
                    Some(event) => events.push(event),
                    None if !tcp.write_pending()
                        && !tcp.input_buffered()
                        && io.with(|s| s.reads.is_empty()) =>
                    {
                        return (events, None);
                    }
                    None => {}
                }
            }
        }
    }
    panic!("adapter never settled (busy loop)")
}

/// The request ID of an inbound dispatch event.
fn dispatched(event: &TcpEvent) -> Option<(HostEvent, Vec<u8>)> {
    match event {
        TcpEvent::Inbound {
            request_id, event, ..
        } => Some((*event, request_id.clone())),
        _ => None,
    }
}

// ---- F007-001..002: the Initiator's final-ACK deadline boundary, end to end ----

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum F007 {
    /// Owner check at D − 2 ns, send confirmation at D − 1 ns.
    BothLive,
    /// Owner check at D − 1 ns (live), last byte written, confirmation at exactly D.
    CrossesBeforeConfirm,
    /// Owner check at exactly D.
    ExpiredAtCheck,
    /// Owner check at D + 1 ns.
    ExpiredAfterCheck,
    /// Four bytes written at D − 1 ns, the next write attempted at exactly D.
    PartialThenCrosses,
}

/// One end-to-end F-007 case over two scripted adapters. Returns a table row.
fn f007_case(deadline: Deadline, case: F007) -> String {
    let tag = format!("{deadline:?}-{case:?}");
    let (i, r) = (
        Node::new(&format!("p5-f007-i-{tag}")),
        Node::new(&format!("p5-f007-r-{tag}")),
    );
    let (tc, ci, cr) = clocks();
    let mut s = Sides::new(&i, &r, &tc, &ci, &cr);
    let (run, identity) = s.sas(&i, &r, &ci, [0x70; 16]);
    // Absolute: park at the suspended SAS comparison until 250 s, so the last progress (the
    // RESPONDER_FINISH_ACK) is recent and only the absolute deadline (300 s) can fire.
    // Inactivity: the last progress is at 0, so the deadline is 60 s.
    let (now, d) = match deadline {
        Deadline::Absolute => {
            ci.advance(Duration::from_secs(250));
            (Duration::from_secs(250), ABSOLUTE_DEADLINE)
        }
        Deadline::Inactivity => (Duration::ZERO, INACTIVITY_DEADLINE),
    };
    let fin = s.final_ack(&run, &identity);
    let (check, confirm) = match case {
        F007::BothLive => (d - 2 * NS, d - NS),
        F007::CrossesBeforeConfirm | F007::PartialThenCrosses => (d - NS, d),
        F007::ExpiredAtCheck => (d, d),
        F007::ExpiredAfterCheck => (d + NS, d + NS),
    };
    ci.advance(check - now);
    let kind = CeremonyDeadline::TimedOut(deadline);
    let (i_outcome, i_result) = if case == F007::PartialThenCrosses {
        s.iio.write(Take(4));
        assert_eq!(s.i.on_writable(), Ok(BUSY));
        ci.advance(confirm - check);
        assert_eq!(s.i.on_writable(), Err(TcpError::AbandonedPartialFrame));
        assert_eq!(s.iio.wire(), fin[..4]);
        ("closed: AbandonedPartialFrame".to_string(), None)
    } else {
        if confirm > check {
            // Exactly one reading (the owner check) happens before the confirmation's.
            ci.advance_after(1, confirm - check);
        }
        let step = s.i.on_writable().unwrap();
        match (&step.event, case) {
            (Some(TcpEvent::Confirmed), F007::BothLive) => {
                assert_eq!(s.iio.wire(), fin);
                ("Confirmed (result)".to_string(), step.result)
            }
            (Some(TcpEvent::Deadline { cancel, .. }), F007::CrossesBeforeConfirm) => {
                // The complete final ACK left; the run then expired: no result, CANCEL next.
                assert_eq!(step, deadline_step(&run.id, kind, *cancel));
                assert_eq!(*cancel, TimeoutCancel::Pending);
                assert_eq!(s.iio.wire(), fin);
                assert_eq!(s.i.on_writable(), Ok(written()));
                (
                    "timeout after the full write, CANCEL follows".to_string(),
                    None,
                )
            }
            (Some(TcpEvent::Deadline { cancel, .. }), _) => {
                assert_eq!(*cancel, TimeoutCancel::Pending);
                assert_eq!(s.iio.wire(), b"", "no final-ACK byte after expiry");
                assert_eq!(s.i.on_writable(), Ok(written()));
                ("timeout before any byte, CANCEL instead".to_string(), None)
            }
            other => panic!("{tag}: unexpected {other:?}"),
        }
    };
    assert_eq!(i.status(), Status::Ready { remaining: 9 });
    assert_eq!(i.routes(), 0);
    // The Responder receives exactly what left I's socket, then (if I closed) the end.
    let wire = s.iio.take_wire();
    s.rio.data(&wire);
    if s.i.is_closed() {
        s.rio.read(ReadStep::Eof);
    }
    let mut r_events = Vec::new();
    let mut r_result = None;
    let mut r_end = None;
    loop {
        match s.r.on_readable() {
            Ok(step)
                if step.event.is_none()
                    && !s.r.input_buffered()
                    && s.rio.with(|x| x.reads.is_empty()) =>
            {
                break;
            }
            Ok(step) => {
                if step.result.is_some() {
                    assert!(r_result.is_none(), "second Responder result");
                    r_result = step.result;
                }
                if let Some(event) = step.event {
                    r_events.push(event);
                }
            }
            Err(error) => {
                r_end = Some(error);
                break;
            }
        }
    }
    if let Some(result) = &r_result {
        // Fully authenticated: the same ceremony identity and peer as the Initiator's SAS.
        assert_eq!(result.ceremony_identity(), &identity);
        assert_eq!(
            result.authenticated_peer_bootstrap(),
            initiator_bootstrap().canonical_bytes()
        );
    }
    if let (Some(i), Some(r)) = (&i_result, &r_result) {
        results_agree(i, r, &run.id);
    }
    let row = format!(
        "{deadline:?} | {case:?} | check {check:?} / confirm {confirm:?} | wire {} B (final ACK {} B) | I: {i_outcome} | R: {} result, events {:?}, end {:?}",
        wire.len(),
        fin.len(),
        if r_result.is_some() { "HAS" } else { "no" },
        r_events
            .iter()
            .map(|e| match e {
                TcpEvent::Inbound { event, .. } => format!("{event:?}"),
                other => format!("{other:?}"),
            })
            .collect::<Vec<_>>(),
        r_end
    );
    // The reverse asymmetric outcome is exactly the crossing case.
    let reverse = i_result.is_none() && r_result.is_some();
    assert_eq!(reverse, case == F007::CrossesBeforeConfirm, "{row}");
    drop(s);
    i.release();
    r.release();
    row
}

fn deadline_step(id: &[u8], kind: CeremonyDeadline, cancel: TimeoutCancel) -> TcpStep {
    super::deadline(Some(id), kind, cancel)
}

/// F007-001/002: the Initiator's final-ACK send-confirmation boundary for both deadlines, at
/// D − 2 ns / D − 1 ns / D / D + 1 ns and with a partial write, end to end through both adapters.
/// Only `CrossesBeforeConfirm` yields the reverse asymmetric outcome: the complete final ACK
/// left I's socket, I has no result (timeout, CANCEL follows), and R verifies the ACK and holds
/// the only result; I's following CANCEL is then an unknown route on R's session, which ends
/// R's connection after its result (P3 §11.2).
#[test]
fn p5_f007_final_ack_deadline_boundary_end_to_end() {
    let mut table = String::new();
    for deadline in [Deadline::Inactivity, Deadline::Absolute] {
        for case in [
            F007::BothLive,
            F007::CrossesBeforeConfirm,
            F007::ExpiredAtCheck,
            F007::ExpiredAfterCheck,
            F007::PartialThenCrosses,
        ] {
            writeln!(table, "  {}", f007_case(deadline, case)).unwrap();
        }
    }
    eprintln!("F007-001/002 boundary table:\n{table}");
}

// ---- TCP-STREAM-001..003: chunking, concatenation, truncation ----

/// Read chunkings of a stream whose frame boundaries are `ends`: whole, 1 + rest, rest + 1,
/// byte by byte, header / length-prefix / payload splits, splits at and around every frame
/// boundary, and several fixed medium chunk sizes.
fn chunkings(len: usize, ends: &[usize]) -> Vec<(String, Vec<usize>)> {
    let mut out: Vec<(String, Vec<usize>)> = vec![
        ("whole".into(), vec![len]),
        ("1+rest".into(), vec![1, len - 1]),
        ("rest+1".into(), vec![len - 1, 1]),
        ("byte-by-byte".into(), vec![1; len]),
    ];
    for (name, at) in [
        ("magic split", 5),
        ("header split", 9),
        ("after header", 10),
        ("length-prefix split", 12),
        ("request-ID length split", 54),
        ("request-ID split", 60),
        ("bootstrap split", 100),
    ] {
        if at < len {
            out.push((name.into(), vec![at, len - at]));
        }
    }
    for &end in &ends[..ends.len() - 1] {
        for (name, at) in [
            ("frame boundary", end),
            ("boundary - 1", end - 1),
            ("next header partial", end + 3),
            ("next length partial", end + 12),
        ] {
            out.push((format!("{name} @{end}"), vec![at, len - at]));
        }
    }
    for size in [7, 64, 1000, SOCKET_READ_CHUNK] {
        let mut sizes = vec![size; len / size];
        if !len.is_multiple_of(size) {
            sizes.push(len % size);
        }
        out.push((format!("chunks of {size}"), sizes));
    }
    out
}

fn script_reads(io: &Scripted, bytes: &[u8], sizes: &[usize]) {
    let mut at = 0;
    for &size in sizes {
        io.data(&bytes[at..at + size]);
        at += size;
    }
    assert_eq!(at, bytes.len());
}

/// TCP-STREAM-001/002: every chunking of single and concatenated frames (A || B, A || B || C,
/// a larger-than-one-read frame then another, and an exact duplicate) dispatches each frame
/// exactly once, in order, with no lost, duplicated, or reordered byte, no dispatch from an
/// incomplete frame, the retained suffix fully consumed, and no timeout (no transport time
/// passes, and a retained complete frame is dispatched without new readiness).
#[test]
fn p5_tcp_stream_001_chunkings_and_concatenations_dispatch_each_frame_once() {
    let (r, limiter) = node("p5-tcp-stream");
    let (tc, cc, _) = clocks();
    // (name, frames, expected dispatch per frame: `None` for a run-local refusal)
    type Stream<'a> = (&'a str, Vec<Vec<u8>>, Vec<Option<HostEvent>>);
    let streams: Vec<Stream> = vec![
        (
            "A",
            vec![start(&[1; 16])],
            vec![Some(HostEvent::StartAccepted)],
        ),
        (
            "A||B",
            vec![start(&[1; 16]), start(&[2; 16])],
            vec![Some(HostEvent::StartAccepted); 2],
        ),
        (
            "A||B||C",
            vec![start(&[1; 16]), start(&[2; 16]), start(&[3; 16])],
            vec![Some(HostEvent::StartAccepted); 3],
        ),
        (
            "BIG||B",
            vec![big_start(1), start(&[2; 16])],
            // BIG's foreign shared context: a run-local refusal (no event request ID).
            vec![None, Some(HostEvent::StartAccepted)],
        ),
        (
            "A||A",
            vec![start(&[1; 16]), start(&[1; 16])],
            vec![
                Some(HostEvent::StartAccepted),
                Some(HostEvent::StartDuplicate),
            ],
        ),
    ];
    let mut patterns = 0;
    for (name, frames, expected) in &streams {
        let bytes = frames.concat();
        let mut ends = Vec::new();
        let mut end = 0;
        for frame in frames {
            end += frame.len();
            ends.push(end);
        }
        for (split, sizes) in chunkings(bytes.len(), &ends) {
            limiter.advance(ROLLING_WINDOW);
            let (mut tcp, io) = r.connect(&tc, &cc);
            script_reads(&io, &bytes, &sizes);
            let (events, end) = drain(&mut tcp, &io);
            assert_eq!(end, None, "{name} {split}");
            // Frame dispatches and the ACCEPT writes they caused, in order.
            let inbound: Vec<_> = events
                .iter()
                .filter(|e| !matches!(e, TcpEvent::Written))
                .collect();
            assert_eq!(inbound.len(), frames.len(), "{name} {split}: {events:?}");
            for ((event, expect), frame) in inbound.iter().zip(expected).zip(frames) {
                match expect {
                    Some(kind) => {
                        let (got, id) = dispatched(event).expect("dispatch");
                        assert_eq!(got, *kind, "{name} {split}");
                        let expected_id = protocol::route_fields(frame).unwrap().1;
                        assert_eq!(id, expected_id, "{name} {split}: wrong frame");
                    }
                    None => assert!(matches!(event, TcpEvent::Refused(_)), "{name} {split}"),
                }
            }
            let accepts = expected
                .iter()
                .filter(|e| **e == Some(HostEvent::StartAccepted))
                .count();
            assert_eq!(
                events.iter().filter(|e| **e == TcpEvent::Written).count(),
                accepts
            );
            // Nothing left over anywhere; the connection is live.
            assert!(!tcp.input_buffered() && !tcp.write_pending() && !tcp.is_closed());
            assert_eq!(r.counts().2, 0, "{name} {split}: incomplete frame retained");
            drop(tcp);
            assert_eq!(r.counts(), (0, 0, 0, 0));
            patterns += 1;
        }
    }
    eprintln!("TCP-STREAM-001/002: {patterns} stream/chunking patterns");
    r.release();
}

/// TCP-STREAM-003: truncation then EOF (header prefix, length prefix, payload prefix, and a
/// complete frame followed by a partial one), in one read and byte by byte. Complete frames are
/// dispatched; incomplete bytes never reach the host as a frame; EOF tears the connection down
/// once, with every run ended and every count released.
#[test]
fn p5_tcp_stream_003_truncation_then_eof_fails_closed_exactly_once() {
    let (r, limiter) = node("p5-tcp-eof");
    let (tc, cc, _) = clocks();
    let a = start(&[1; 16]);
    let b = start(&[2; 16]);
    let cases: Vec<(&str, Vec<u8>, usize)> = vec![
        ("magic prefix", a[..5].to_vec(), 0),
        ("length prefix", a[..12].to_vec(), 0),
        ("payload prefix", a[..a.len() - 1].to_vec(), 0),
        (
            "complete + partial next",
            [a.as_slice(), &b[..20]].concat(),
            1,
        ),
        ("complete (control)", a.clone(), 1),
    ];
    let mut rows = Vec::new();
    for (name, bytes, complete) in &cases {
        for (split, sizes) in [
            ("one read", vec![bytes.len()]),
            ("byte-by-byte", vec![1; bytes.len()]),
        ] {
            limiter.advance(ROLLING_WINDOW);
            let (mut tcp, io) = r.connect(&tc, &cc);
            script_reads(&io, bytes, &sizes);
            io.read(ReadStep::Eof);
            let (events, end) = drain(&mut tcp, &io);
            let dispatches = events
                .iter()
                .filter(|e| matches!(e, TcpEvent::Inbound { .. }))
                .count();
            assert_eq!(dispatches, *complete, "{name} {split}");
            assert_eq!(end, Some(TcpError::PeerClosed), "{name} {split}");
            assert_eq!(io.shutdowns(), 1, "teardown exactly once");
            assert_eq!(tcp.on_readable(), Err(TcpError::Closed));
            assert_eq!(io.shutdowns(), 1);
            assert_eq!(
                (r.counts(), r.routes()),
                ((0, 0, 0, 0), 0),
                "{name} {split}"
            );
            assert_eq!(r.status(), Status::Ready { remaining: 10 });
            rows.push(format!(
                "{name} / {split}: {dispatches} dispatched, then {end:?}"
            ));
        }
    }
    eprintln!("TCP-STREAM-003:\n  {}", rows.join("\n  "));
    r.release();
}

// ---- TCP-RD-001: generated read-result sequences ----

#[derive(Clone, Copy, Debug)]
enum Rd {
    WouldBlock,
    Interrupted,
    One,
    Seven,
    RestOfFrame,
    All,
    Eof,
    Error,
}

/// TCP-RD-001: every sequence of at most three scripted read results over a two-frame stream,
/// then draining. Each call makes at most one socket operation; WouldBlock and Interrupted
/// change nothing; exactly the frames whose last byte arrived before the end are dispatched, in
/// order, each once; EOF or an error tears down exactly once and releases everything.
#[test]
fn p5_tcp_rd_001_generated_read_sequences() {
    read_sequences("TCP-RD-001", 3);
}

/// TCP-RD-002 (deep, manual): the same with at most four read results. Run with
/// `cargo test --manifest-path core/Cargo.toml --lib p5_tcp_rd_deep -- --ignored --nocapture`.
#[test]
#[ignore = "P5.2 deep review run; passing evidence, not a known-bug reproducer"]
fn p5_tcp_rd_deep_read_sequences_length_four() {
    read_sequences("TCP-RD-002", 4);
}

fn read_sequences(family: &str, max_len: usize) {
    let r = drained(&format!("p5-{family}"));
    let (tc, cc, _) = clocks();
    let frames = [start(&[1; 16]), start(&[2; 16])];
    let stream = frames.concat();
    let ends = [frames[0].len(), stream.len()];
    let alphabet = [
        Rd::WouldBlock,
        Rd::Interrupted,
        Rd::One,
        Rd::Seven,
        Rd::RestOfFrame,
        Rd::All,
        Rd::Eof,
        Rd::Error,
    ];
    let mut sequences = 0;
    let mut stack: Vec<Vec<Rd>> = alphabet.iter().map(|&a| vec![a]).collect();
    while let Some(seq) = stack.pop() {
        if seq.len() < max_len {
            for &a in &alphabet {
                let mut next = seq.clone();
                next.push(a);
                stack.push(next);
            }
        }
        let (mut tcp, io) = r.connect(&tc, &cc);
        let mut at = 0;
        let mut ended = None;
        for step in &seq {
            let take = |n: usize| (stream.len() - at).min(n);
            let n = match step {
                Rd::One => take(1),
                Rd::Seven => take(7),
                Rd::RestOfFrame => {
                    let end = *ends.iter().find(|&&e| e > at).unwrap_or(&stream.len());
                    end - at
                }
                Rd::All => stream.len() - at,
                Rd::WouldBlock => {
                    io.read(ReadStep::Fail(WouldBlock));
                    continue;
                }
                Rd::Interrupted => {
                    io.read(ReadStep::Fail(Interrupted));
                    continue;
                }
                Rd::Eof => {
                    io.read(ReadStep::Eof);
                    ended.get_or_insert(TcpError::PeerClosed);
                    break;
                }
                Rd::Error => {
                    io.read(ReadStep::Fail(ConnectionReset));
                    ended.get_or_insert(TcpError::Io(ConnectionReset));
                    break;
                }
            };
            if n == 0 {
                // Nothing left to deliver: an empty read would be EOF, so offer WouldBlock.
                io.read(ReadStep::Fail(WouldBlock));
            } else {
                io.data(&stream[at..at + n]);
                at += n;
            }
        }
        let complete = ends.iter().filter(|&&e| e <= at).count();
        let (events, end) = drain(&mut tcp, &io);
        assert_eq!(events, vec![LIMITED; complete], "{seq:?}");
        assert_eq!(end, ended, "{seq:?}");
        if end.is_some() {
            assert_eq!(io.shutdowns(), 1, "{seq:?}");
            assert_eq!(r.counts(), (0, 0, 0, 0), "{seq:?}");
        } else {
            // A partial second frame stays with the transport, nowhere else.
            assert_eq!(
                r.counts(),
                (0, 1, usize::from(at % ends[0] != 0 && at < stream.len()), 0)
            );
        }
        drop(tcp);
        assert_eq!(r.counts(), (0, 0, 0, 0));
        sequences += 1;
    }
    eprintln!("{family}: {sequences} read sequences");
    r.release();
}

// ---- TCP-W-001..002: generated write-result sequences ----

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Wr {
    WouldBlock,
    Interrupted,
    One,
    Seven,
    Zero,
    Error,
    /// The owner run's deadline passes before this write attempt.
    Expire,
}

const WRITES: [Wr; 7] = [
    Wr::WouldBlock,
    Wr::Interrupted,
    Wr::One,
    Wr::Seven,
    Wr::Zero,
    Wr::Error,
    Wr::Expire,
];

fn sequences(depth: usize) -> Vec<Vec<Wr>> {
    let mut out = Vec::new();
    let mut frontier: Vec<Vec<Wr>> = vec![Vec::new()];
    for _ in 0..depth {
        let mut next = Vec::new();
        for seq in &frontier {
            for &w in &WRITES {
                let mut s = seq.clone();
                s.push(w);
                next.push(s);
            }
        }
        out.extend(next.iter().cloned());
        frontier = next;
    }
    out
}

/// What the adapter should do for one write attempt, from the frame length and the offset.
#[derive(Debug, PartialEq, Eq)]
enum Expect {
    Busy,
    Done,
    Closed(TcpError),
    Expired { offset: usize },
}

/// Applies one scripted write step to a retained frame owned by a live run whose deadline
/// `expire` passes; returns what happened.
fn write_step(
    tcp: &mut Tcp<'_>,
    io: &Scripted,
    w: Wr,
    expire: &dyn Fn(),
) -> Result<TcpStep, TcpError> {
    match w {
        Wr::WouldBlock => io.write(Fail(WouldBlock)),
        Wr::Interrupted => io.write(Fail(Interrupted)),
        Wr::One => io.write(Take(1)),
        Wr::Seven => io.write(Take(7)),
        Wr::Zero => io.write(Take(0)),
        Wr::Error => io.write(Fail(ConnectionReset)),
        Wr::Expire => expire(),
    }
    tcp.on_writable()
}

/// TCP-W-001: every sequence of at most three write results for a retained START of a live
/// local Initiator (no key generation), then an unblocked write. Offsets only grow; the wire
/// holds exactly a prefix of the frame (never a repeated byte); `Written` appears exactly when
/// the last byte is written; WouldBlock/Interrupted change nothing; a zero write or an error
/// closes; an expired owner discards an unsent frame and closes on a partly sent one, with
/// nothing appended.
#[test]
fn p5_tcp_w_001_generated_write_sequences() {
    let i = Node::new("p5-tcp-w-001");
    let (tc, cc, _) = clocks();
    let mut count = 0;
    for seq in sequences(3) {
        let ci = ManualClock::new();
        let (mut tcp, io) = i.connect(&tc, &cc);
        acted(tcp.start_initiator_with(
            ci.clone(),
            &mut OneId(Some([0x33; 16])),
            initiator_bootstrap(),
            None,
        ));
        let frame = pending_bytes(&tcp);
        io.hold(true);
        let mut offset = 0;
        let mut open = true;
        let mut done = false;
        for &w in &seq {
            if !open || done {
                break;
            }
            let writes = io.writes();
            let expect = match w {
                Wr::WouldBlock | Wr::Interrupted => Expect::Busy,
                Wr::One | Wr::Seven => {
                    let n = if w == Wr::One { 1 } else { 7 };
                    if offset + n >= frame.len() {
                        Expect::Done
                    } else {
                        Expect::Busy
                    }
                }
                Wr::Zero => Expect::Closed(TcpError::Io(ErrorKind::WriteZero)),
                Wr::Error => Expect::Closed(TcpError::Io(ConnectionReset)),
                Wr::Expire => Expect::Expired { offset },
            };
            let got = write_step(&mut tcp, &io, w, &|| ci.advance(INACTIVITY_DEADLINE));
            match (&expect, got) {
                (Expect::Busy, Ok(step)) => {
                    assert_eq!(step, BUSY, "{seq:?}");
                    if matches!(w, Wr::One | Wr::Seven) {
                        offset += if w == Wr::One { 1 } else { 7 };
                    }
                }
                (Expect::Done, Ok(step)) => {
                    assert_eq!(step, written(), "{seq:?}");
                    offset = frame.len();
                    done = true;
                }
                (Expect::Closed(error), Err(got)) => {
                    assert_eq!(&got, error, "{seq:?}");
                    open = false;
                }
                (Expect::Expired { offset: 0 }, Ok(step)) => {
                    // Unsent: discarded, no CANCEL before any SAS, connection live.
                    assert_eq!(
                        step,
                        super::deadline(Some(&[0x33; 16]), INACTIVITY, TimeoutCancel::NotBuilt),
                        "{seq:?}"
                    );
                    assert_eq!(io.writes(), writes, "an expired frame was written");
                    done = true;
                }
                (Expect::Expired { .. }, Err(got)) => {
                    assert_eq!(got, TcpError::AbandonedPartialFrame, "{seq:?}");
                    assert_eq!(io.writes(), writes, "an expired frame was written");
                    open = false;
                }
                (expect, got) => panic!("{seq:?}: expected {expect:?}, got {got:?}"),
            }
            assert_eq!(
                io.wire(),
                frame[..offset],
                "{seq:?}: wire is not a frame prefix"
            );
        }
        if open && !done {
            io.hold(false);
            assert_eq!(tcp.on_writable(), Ok(written()), "{seq:?}");
            assert_eq!(io.wire(), frame, "{seq:?}");
        }
        if !open {
            assert_eq!(tcp.on_writable(), Err(TcpError::Closed));
            assert_eq!(io.shutdowns(), 1);
        }
        drop(tcp);
        assert_eq!((i.counts(), i.routes(), i.reserved()), ((0, 0, 0, 0), 0, 0));
        count += 1;
    }
    eprintln!("TCP-W-001: {count} write sequences");
    i.release();
}

/// TCP-W-002: every sequence of at most two write results for the Initiator's retained final
/// ACK, then an unblocked write. The Initiator's result appears only on the call that writes
/// the last byte; never after a zero write, an error, or an abandoned partial write; and the
/// Responder succeeds only from the complete frame.
#[test]
fn p5_tcp_w_002_final_ack_write_sequences_confirm_only_the_last_byte() {
    let mut count = 0;
    for (n, seq) in sequences(2).into_iter().enumerate() {
        let (i, r) = (
            Node::new(&format!("p5-tcp-w-002-i-{n}")),
            Node::new(&format!("p5-tcp-w-002-r-{n}")),
        );
        let (tc, ci, cr) = clocks();
        let mut s = Sides::new(&i, &r, &tc, &ci, &cr);
        let (run, identity) = s.sas(&i, &r, &ci, [0x44; 16]);
        let fin = s.final_ack(&run, &identity);
        s.iio.hold(true);
        let mut offset = 0;
        let mut i_result = None;
        let mut open = true;
        for &w in &seq {
            if !open || i_result.is_some() {
                break;
            }
            let got = write_step(&mut s.i, &s.iio, w, &|| ci.advance(INACTIVITY_DEADLINE));
            match (w, got) {
                (Wr::WouldBlock | Wr::Interrupted, Ok(step)) => assert_eq!(step, BUSY),
                (Wr::One | Wr::Seven, Ok(step)) => {
                    let k = if w == Wr::One { 1 } else { 7 };
                    if offset + k >= fin.len() {
                        assert_eq!(step.event, Some(TcpEvent::Confirmed));
                        i_result = step.result;
                        offset = fin.len();
                    } else {
                        assert_eq!((step, i.status()), (BUSY, Status::Busy), "no early result");
                        offset += k;
                    }
                }
                (Wr::Zero | Wr::Error, Err(_)) => open = false,
                (Wr::Expire, Ok(step)) => {
                    assert_eq!(offset, 0, "{seq:?}");
                    assert_eq!(
                        step,
                        super::deadline(Some(&run.id), INACTIVITY, TimeoutCancel::Pending)
                    );
                    // The CANCEL replaced the unsent final ACK.
                    assert!(!pending(&s.i).unwrap().2);
                    break;
                }
                (Wr::Expire, Err(TcpError::AbandonedPartialFrame)) => {
                    assert!(offset > 0);
                    open = false;
                }
                (w, got) => panic!("{seq:?}: {w:?} -> {got:?}"),
            }
            assert_eq!(s.iio.wire(), fin[..offset], "{seq:?}");
        }
        let expired = seq.contains(&Wr::Expire);
        if open && i_result.is_none() && !expired {
            s.iio.hold(false);
            let step = s.i.on_writable().unwrap();
            assert_eq!(step.event, Some(TcpEvent::Confirmed), "{seq:?}");
            i_result = step.result;
            offset = fin.len();
        }
        assert_eq!(s.iio.wire(), fin[..offset], "{seq:?}");
        // The Responder sees exactly the bytes that left, then EOF if I closed.
        let wire = s.iio.take_wire();
        let complete = wire.len() >= fin.len() && wire[..fin.len()] == fin[..];
        if !wire.is_empty() {
            s.rio.data(&wire);
        }
        if !open {
            s.rio.read(ReadStep::Eof);
        }
        let mut r_result = None;
        while let Ok(step) = s.r.on_readable() {
            if let Some(result) = step.result {
                r_result = Some(result);
            }
            if step.event.is_none() && !s.r.input_buffered() && s.rio.with(|x| x.reads.is_empty()) {
                break;
            }
        }
        assert_eq!(
            i_result.is_some(),
            complete && !expired,
            "{seq:?}: Initiator result"
        );
        assert_eq!(r_result.is_some(), complete, "{seq:?}: Responder result");
        if let (Some(a), Some(b)) = (&i_result, &r_result) {
            results_agree(a, b, &run.id);
        }
        drop(s);
        i.release();
        r.release();
        count += 1;
    }
    eprintln!("TCP-W-002: {count} final-ACK write sequences");
}

// ---- TCP-DEADLINE-001: transport frame deadlines at the exact boundary ----

/// TCP-DEADLINE-001: the 2 s no-progress and 10 s whole-frame deadlines of an incomplete
/// frame, at −1 ns / exactly / +1 ns, with retained-byte progress, a WouldBlock read, and a
/// poll before the boundary (neither refreshes). Expiry is `elapsed >= deadline`. Without an
/// incomplete frame no transport deadline existed at all in P5 (P5-F-002; P6-D-001 adds the
/// connection lifetime).
#[test]
fn p5_tcp_deadline_001_frame_deadlines_at_the_exact_boundary() {
    let r = drained("p5-tcp-deadline");
    let cc = ManualClock::new();
    let a = start(&[1; 16]);
    let ms = |n: u64| Duration::from_millis(n);
    // (case, chunk times before the probe, probe time, error at or after the boundary)
    let cases: [(&str, &[Duration], Duration, TransportError); 4] = [
        (
            "idle",
            &[Duration::ZERO],
            IDLE_READ_DEADLINE,
            TransportError::IdleTimeout,
        ),
        (
            "idle after progress",
            &[Duration::ZERO, ms(1500)],
            ms(1500) + IDLE_READ_DEADLINE,
            TransportError::IdleTimeout,
        ),
        (
            "whole frame despite progress",
            &[
                Duration::ZERO,
                ms(1500),
                ms(3000),
                ms(4500),
                ms(6000),
                ms(7500),
                ms(9000),
            ],
            crate::transport::WHOLE_FRAME_DEADLINE,
            TransportError::WholeFrameTimeout,
        ),
        (
            "would-block read and poll do not refresh",
            &[Duration::ZERO],
            IDLE_READ_DEADLINE,
            TransportError::IdleTimeout,
        ),
    ];
    let mut checked = 0;
    for (case, chunks, probe, error) in cases {
        for (offset, label) in [(-1i8, "-1ns"), (0, "exact"), (1, "+1ns")] {
            for via_poll in [false, true] {
                let tc = ManualClock::new();
                let (mut tcp, io) = r.connect(&tc, &cc);
                // Chunks of 10 bytes each: never the whole frame before the probe.
                for (n, at) in chunks.iter().enumerate() {
                    tc.set(*at);
                    io.data(&a[n * 10..n * 10 + 10]);
                    assert_eq!(tcp.on_readable(), Ok(TcpStep::default()), "{case}");
                }
                if case.starts_with("would-block") {
                    tc.set(ms(1900));
                    assert_eq!(tcp.on_readable(), Ok(TcpStep::default()));
                    assert_eq!(tcp.poll_connection_deadlines(), Ok(TcpStep::default()));
                }
                let instant = match offset {
                    -1 => probe - NS,
                    0 => probe,
                    _ => probe + NS,
                };
                tc.set(instant);
                let outcome = if via_poll {
                    tcp.poll_connection_deadlines()
                } else {
                    io.data(&a[chunks.len() * 10..]);
                    tcp.on_readable()
                };
                if offset < 0 {
                    // Live: a poll changes nothing; the rest of the frame completes it.
                    let step = outcome.unwrap();
                    if !via_poll {
                        assert_eq!(step.event, Some(LIMITED), "{case} {label}");
                    }
                    assert!(!tcp.is_closed());
                } else {
                    assert_eq!(
                        outcome,
                        Err(TcpError::Host(HostError::Transport(error))),
                        "{case} {label} poll={via_poll}"
                    );
                    assert_eq!(r.counts(), (0, 0, 0, 0));
                }
                drop(tcp);
                assert_eq!(r.counts(), (0, 0, 0, 0));
                checked += 1;
            }
        }
    }
    eprintln!("TCP-DEADLINE-001: {checked} boundary cases");
    r.release();
}

// ---- F002-001..002 and TCP-OUT-001: connection and retained-output lifetime ----

/// One owner-loop sweep's worth of polling for one connection, as the loop does it.
fn sweep(tcp: &mut Tcp<'_>) -> Result<Vec<TcpEvent>, TcpError> {
    let mut events = Vec::new();
    for step in [
        tcp.poll_connection_deadlines()?,
        tcp.poll_ceremony_deadlines()?,
    ] {
        events.extend(step.event);
    }
    Ok(events)
}

/// Advances every clock by one day in steps, sweeping after each, and reports whether the
/// connection ended and what the sweeps reported.
fn idle_a_day(
    tcp: &mut Tcp<'_>,
    clocks: &[&Arc<ManualClock>],
) -> (bool, Vec<TcpEvent>, Option<TcpError>) {
    let mut events = Vec::new();
    for _ in 0..24 {
        for clock in clocks {
            clock.advance(ONE_DAY / 24);
        }
        match sweep(tcp) {
            Ok(found) => events.extend(found),
            Err(error) => return (true, events, Some(error)),
        }
    }
    (tcp.is_closed(), events, None)
}

/// The P5-F-002 connection-lifetime cases, built on `r` (Responder side) with peer node `i`.
/// Returns, per case, whether a day of sweeps released the connection.
fn f002_cases(tag: &str, mut record: impl FnMut(&str, bool, String)) {
    // (a) Admitted, never a byte.
    {
        let r = Node::new(&format!("p5-f002-a-{tag}"));
        let (tc, cc, _) = clocks();
        let (mut tcp, _io) = r.connect(&tc, &cc);
        let (released, events, end) = idle_a_day(&mut tcp, &[&tc, &cc]);
        record(
            "A: admitted, zero bytes, 24 h",
            released,
            format!("events {events:?}, end {end:?}, live {}", r.counts().1),
        );
        drop(tcp);
        r.release();
    }
    // (b) A complete START admitted, its run ended by its own pending lifetime, then idle.
    {
        let r = Node::new(&format!("p5-f002-b-{tag}"));
        let (tc, cc, _) = clocks();
        let (mut tcp, io) = r.connect(&tc, &cc);
        admit(&mut tcp, &io, &start(&[0xB0; 16]));
        let (released, events, end) = idle_a_day(&mut tcp, &[&tc, &cc]);
        assert!(
            events.iter().any(|e| matches!(
                e,
                TcpEvent::Deadline {
                    kind: CeremonyDeadline::TimedOut(_) | CeremonyDeadline::PendingExpired,
                    ..
                }
            )),
            "the run itself ends: {events:?}"
        );
        assert_eq!(r.routes(), 0);
        record(
            "B: frame, run ended, then idle 24 h",
            released,
            format!("events {events:?}, end {end:?}, live {}", r.counts().1),
        );
        drop(tcp);
        r.release();
    }
    // (c) An incomplete frame: the 2 s idle deadline releases it.
    {
        let r = Node::new(&format!("p5-f002-c-{tag}"));
        let (tc, cc, _) = clocks();
        let (mut tcp, io) = r.connect(&tc, &cc);
        io.data(&start(&[0xC0; 16])[..20]);
        assert_eq!(tcp.on_readable(), Ok(TcpStep::default()));
        let (released, events, end) = idle_a_day(&mut tcp, &[&tc, &cc]);
        record(
            "C: partial frame",
            released,
            format!("events {events:?}, end {end:?}, live {}", r.counts().1),
        );
        drop(tcp);
        r.release();
    }
    // (d) A complete unroutable frame: closed at once.
    {
        let r = Node::new(&format!("p5-f002-d-{tag}"));
        let (tc, cc, _) = clocks();
        let (mut tcp, io) = r.connect(&tc, &cc);
        io.data(&frame(3, &[b"wrong profile", &[1; 16], &[9; 32]]));
        let end = tcp.on_readable().err();
        record(
            "D: complete invalid frame",
            tcp.is_closed(),
            format!("end {end:?}, live {}", r.counts().1),
        );
        drop(tcp);
        r.release();
    }
    // (e) A retained owner-less CANCEL (the Responder's timeout after SAS) to a peer that never
    // reads: the run is over, only the output remains.
    {
        let (i, r) = (
            Node::new(&format!("p5-f002-e-i-{tag}")),
            Node::new(&format!("p5-f002-e-r-{tag}")),
        );
        let (tc, ci, cr) = clocks();
        let mut s = Sides::new(&i, &r, &tc, &ci, &cr);
        let (run, _) = s.sas(&i, &r, &ci, [0xE0; 16]);
        s.rio.hold(true);
        cr.advance(ABSOLUTE_DEADLINE);
        assert_eq!(
            s.r.poll_ceremony_deadlines(),
            Ok(super::deadline(
                Some(&run.id),
                ABSOLUTE,
                TimeoutCancel::Pending
            ))
        );
        assert!(s.r.pending.as_ref().unwrap().owner.is_none());
        let (released, events, end) = idle_a_day(&mut s.r, &[&tc, &cr]);
        let retained = s.r.write_pending();
        record(
            "E: owner-less CANCEL, peer never reads, 24 h",
            released,
            format!(
                "events {events:?}, end {end:?}, live {}, CANCEL still retained {retained}",
                r.counts().1
            ),
        );
        drop(s);
        i.release();
        r.release();
    }
}

/// F002-001 (PASSING EVIDENCE): which connection states have a finite release today. Durable
/// assertions only: an incomplete frame (C) and a complete unroutable frame (D) are released;
/// no case creates a result or touches the budget. The unbounded cases (A, B, E) are recorded,
/// not asserted here; `p5_f_002_idle_connections_eventually_release_their_live_slot` asserts
/// their release since P6.1.
#[test]
fn p5_f002_001_connection_lifetime_cases() {
    let mut rows = Vec::new();
    f002_cases("evidence", |case, released, detail| {
        if case.starts_with("C:") || case.starts_with("D:") {
            assert!(released, "{case}: {detail}");
        }
        rows.push(format!("{case}: released={released}; {detail}"));
    });
    eprintln!("F002-001:\n  {}", rows.join("\n  "));
}

/// P5-F-002 REGRESSION (P6.1, decision P6-D-001): every admitted connection, idle before its
/// first frame (A), idle after its run ended (B), or holding only an owner-less retained frame
/// for a peer that never reads (E), is released by the owner's ordinary sweep. In P5 this was
/// the `#[ignore]`d EXPECTED-FAIL reproducer of the gap and failed on A, B, and E; it runs
/// normally since the P6.1 remediation.
#[test]
fn p5_f_002_idle_connections_eventually_release_their_live_slot() {
    let mut unreleased = Vec::new();
    f002_cases("desired", |case, released, detail| {
        if !released {
            unreleased.push(format!("{case}: {detail}"));
        }
    });
    assert!(
        unreleased.is_empty(),
        "connections held for a day:\n  {}",
        unreleased.join("\n  ")
    );
}

/// TCP-OUT-001 (P5.2 §29): retained output after its run ended, for a peer that never reads.
/// Output lifetime is separate from ceremony lifetime: a frame a live run owns never outlives
/// that run (at its deadline an unsent frame is discarded, a partly sent one closes the
/// connection), but whatever replaces it, the run's own timeout CANCEL, and a local REJECT or
/// CANCEL frame, have no owner, and in P5 no deadline. Durable assertions: no owned frame
/// outlives its run, and no result or refund ever appears; the owner-less retention is
/// recorded. Since P6-D-001 (P5-F-002 remediation) the owner-less CANCEL is released too.
#[test]
fn p5_tcp_out_001_retained_output_lifetime_versus_ceremony_lifetime() {
    let mut rows = Vec::new();
    // (1) Owned final ACK, unsent, peer never reads.
    for partial in [false, true] {
        let tag = if partial { "partial" } else { "unsent" };
        let (i, r) = (
            Node::new(&format!("p5-out-fin-i-{tag}")),
            Node::new(&format!("p5-out-fin-r-{tag}")),
        );
        let (tc, ci, cr) = clocks();
        let mut s = Sides::new(&i, &r, &tc, &ci, &cr);
        let (run, identity) = s.sas(&i, &r, &ci, [0x51; 16]);
        s.final_ack(&run, &identity);
        if partial {
            s.iio.write(Take(5));
            assert_eq!(s.i.on_writable(), Ok(BUSY));
        }
        s.iio.hold(true);
        let (released, events, end) = idle_a_day(&mut s.i, &[&tc, &ci]);
        let owner_less = s.i.pending.as_ref().map(|p| p.owner.is_none());
        assert_eq!(
            i.status(),
            Status::Ready { remaining: 9 },
            "no result, no refund"
        );
        if partial {
            assert!(
                released,
                "a partly sent owned frame closes at its run's deadline"
            );
        } else {
            // P5 found the owned frame replaced by its owner-less CANCEL, retained for good.
            // Since P6-D-001 (P5-F-002 remediation) that CANCEL has its own retained-output
            // deadlines, so the connection is released.
            assert!(
                events.iter().any(|event| matches!(
                    event,
                    TcpEvent::Deadline {
                        cancel: TimeoutCancel::Pending,
                        ..
                    }
                )),
                "the owned frame was replaced by its CANCEL: {events:?}"
            );
            assert!(released, "the owner-less CANCEL is bounded (P6-D-001)");
        }
        rows.push(format!(
            "final ACK {tag}: released={released}, retained owner-less frame={owner_less:?}, events {events:?}, end {end:?}"
        ));
        drop(s);
        i.release();
        r.release();
    }
    // (2) Local REJECT's CANCEL, peer never reads.
    {
        let (i, r) = (Node::new("p5-out-reject-i"), Node::new("p5-out-reject-r"));
        let (tc, ci, cr) = clocks();
        let mut s = Sides::new(&i, &r, &tc, &ci, &cr);
        let (run, identity) = s.sas(&i, &r, &ci, [0x52; 16]);
        let rejected = acted(s.r.reject_sas(&run.r, &identity));
        assert_eq!(
            (rejected.event, rejected.run),
            (LocalEvent::SasRejected, None)
        );
        assert!(s.r.pending.as_ref().unwrap().owner.is_none());
        s.rio.hold(true);
        let (released, events, end) = idle_a_day(&mut s.r, &[&tc, &cr]);
        rows.push(format!(
            "local REJECT CANCEL: released={released}, still retained={}, events {events:?}, end {end:?}",
            s.r.write_pending()
        ));
        assert_eq!(r.status(), Status::Ready { remaining: 9 });
        drop(s);
        i.release();
        r.release();
    }
    eprintln!("TCP-OUT-001:\n  {}", rows.join("\n  "));
}
