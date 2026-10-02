//! P6-D-001 connection lifetime through the owner loop (remediation of P5-F-002): the ordinary
//! drive releases idle connections and their live slots, with the deadline sweep before any
//! socket I/O. Scripted listener and sockets, hand clocks.
use super::*;
use crate::{
    transport::{FIRST_FRAME_DEADLINE, QUIESCENT_DEADLINE},
    windows_tcp::tests::NS,
};

/// The P5-F-002 known-bug scenario through the owner loop: 16 silent peers fill the cap and a
/// 17th is refused; at the first-frame deadline the drive closes all 16, and the same drive
/// admits the next peer.
#[test]
fn sixteen_idle_peers_release_the_live_cap_and_the_next_peer_is_admitted() {
    let r = Node::new("p6-loop-sixteen");
    let (tc, cc, _) = clocks();
    let (mut owner, net) = hosting(&r, &tc, &cc);
    let idle: Vec<_> = (0..16).map(|_| accept(&mut owner, &net)).collect();
    assert_eq!(r.counts(), (0, 16, 0, 0));
    net.connect();
    assert_eq!(drive(&mut owner, &net).events, vec![refused()]);
    tc.set(FIRST_FRAME_DEADLINE - NS);
    net.connect();
    assert_eq!(drive(&mut owner, &net).events, vec![refused()]);
    assert_eq!((owner.live_connections(), r.counts()), (16, (0, 16, 0, 0)));
    tc.set(FIRST_FRAME_DEADLINE);
    let socket = net.connect();
    let step = drive(&mut owner, &net);
    assert_eq!(step.failure, None);
    let (closed, admitted) = step.events.split_at(16);
    let expected: Vec<_> = idle
        .iter()
        .map(|(connection, _)| closed_by(*connection, TransportError::FirstFrameTimeout))
        .collect();
    assert_eq!(closed, expected.as_slice());
    let [OwnerEvent::Accepted(next)] = admitted else {
        panic!("the next peer is admitted: {admitted:?}");
    };
    assert_eq!((owner.live_connections(), r.counts()), (1, (0, 1, 0, 0)));
    assert!(idle.iter().all(|(_, socket)| socket.reads() == 0));
    assert_eq!(r.sessions(), 1);
    // The newcomer has its own fresh first-frame wait and is served normally.
    let run = admit(&mut owner, &net, *next, &socket, [1; 16]);
    tc.set(FIRST_FRAME_DEADLINE * 10);
    assert_eq!(drive(&mut owner, &net), OwnerStep::default());
    assert_eq!(owner.presentation(*next, &run), Ok(Ok(None)));
    assert_eq!(
        (r.charged(), r.status()),
        ((3, 1), Status::Ready { remaining: 10 })
    );
    drop(owner);
    assert_eq!(r.counts(), (0, 0, 0, 0));
    r.release();
}

/// An expired connection deadline wins before socket I/O: readable bytes waiting at the
/// boundary are never read, and a run that ended leaves a connection the drive closes after
/// its quiescent wait with no input.
#[test]
fn the_sweep_ends_expired_connections_before_any_socket_io() {
    let r = Node::new("p6-loop-sweep");
    let (tc, cc, _) = clocks();
    let (mut owner, net) = hosting(&r, &tc, &cc);
    let (a, sa) = accept(&mut owner, &net);
    let (b, sb) = accept(&mut owner, &net);
    let x = [2; 16];
    admit(&mut owner, &net, b, &sb, x);
    tc.set(FIRST_FRAME_DEADLINE);
    sa.data(&start(&[3; 16]));
    assert_eq!(
        drive(&mut owner, &net).events,
        vec![closed_by(a, TransportError::FirstFrameTimeout)]
    );
    assert_eq!(sa.reads(), 0, "the readable START was never read");
    // B's run ends by its own deadline; the next drives observe it quiescent, then close it.
    cc.advance(INACTIVITY_DEADLINE);
    assert_eq!(
        step_of(drive(&mut owner, &net), b),
        deadline(Some(&x), INACTIVITY, TimeoutCancel::NotBuilt)
    );
    // The transport clock has not moved since the first-frame boundary.
    let quiet = FIRST_FRAME_DEADLINE;
    assert_eq!(drive(&mut owner, &net), OwnerStep::default());
    tc.set(quiet + QUIESCENT_DEADLINE - NS);
    assert_eq!(drive(&mut owner, &net), OwnerStep::default());
    let reads = sb.reads();
    tc.set(quiet + QUIESCENT_DEADLINE);
    sb.data(&start(&[4; 16]));
    assert_eq!(
        drive(&mut owner, &net).events,
        vec![closed_by(b, TransportError::QuiescentTimeout)]
    );
    assert_eq!(sb.reads(), reads);
    assert_eq!((owner.live_connections(), r.counts()), (0, (0, 0, 0, 0)));
    assert_eq!(r.status(), Status::Ready { remaining: 10 });
    drop(owner);
    r.release();
}
