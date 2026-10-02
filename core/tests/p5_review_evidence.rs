//! P5 security-review evidence (review infrastructure only). Nothing here exercises or changes
//! production behavior; each test pins an external fact a P5 finding depends on, so CI keeps
//! that fact visible on `windows-latest`. See `docs/p5-security-review/findings.md`.
#![cfg(windows)]

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    os::windows::io::AsRawSocket,
    time::{Duration, Instant},
};
use windows_sys::Win32::Networking::WinSock::{POLLHUP, POLLIN, POLLRDNORM, WSAPOLLFD, WSAPoll};

/// P5-F-001 precondition. After a peer writes bytes and closes its socket gracefully, `WSAPoll`
/// reports `POLLHUP` together with `POLLRDNORM`, and the bytes the peer wrote are still readable.
/// The experimental owner loop treats any `POLLHUP` as "close without reading", so such bytes
/// (for example a final INITIATOR_FINISH_ACK) are discarded. This test records only the OS fact.
#[test]
fn p5_f_001_wsapoll_reports_hang_up_while_written_bytes_remain_readable() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut local, _) = listener.accept().unwrap();
    peer.write_all(b"frame-bytes").unwrap();
    drop(peer);

    let give_up = Instant::now() + Duration::from_secs(10);
    let revents = loop {
        let mut fd = WSAPOLLFD {
            fd: local.as_raw_socket() as _,
            events: POLLIN,
            revents: 0,
        };
        // SAFETY: one initialized, exclusively borrowed WSAPOLLFD for this synchronous call;
        // WSAPoll writes only its `revents` and keeps no pointer after returning.
        let ready = unsafe { WSAPoll(&mut fd, 1, 100) };
        assert!(ready >= 0, "WSAPoll failed");
        if fd.revents & POLLHUP != 0 {
            break fd.revents;
        }
        assert!(Instant::now() < give_up, "no hang-up readiness in 10 s");
    };
    assert_ne!(
        revents & POLLRDNORM,
        0,
        "hang-up reported without readable data"
    );

    let mut buf = [0u8; 32];
    let read = local.read(&mut buf).unwrap();
    assert_eq!(&buf[..read], b"frame-bytes");
    assert_eq!(
        local.read(&mut buf).unwrap(),
        0,
        "end of stream follows the data"
    );
}
