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
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE},
    Networking::WinSock::{POLLHUP, POLLIN, POLLRDNORM, WSAPOLLFD, WSAPoll},
    Security::{GetLengthSid, GetTokenInformation, IsValidSid, TOKEN_QUERY, TOKEN_USER, TokenUser},
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

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

/// One `GetTokenInformation(TokenUser)` into `buffer`: the returned length, or the Win32 error.
fn token_user_into(token: HANDLE, buffer: &mut [u8]) -> Result<usize, i32> {
    let mut returned = 0u32;
    // SAFETY: `buffer` is an exclusively borrowed, writable byte slice of exactly the length
    // passed, alive for this synchronous call; Windows writes at most that many bytes.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
            &mut returned,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
    }
    Ok(returned as usize)
}

/// Where Windows put the SID of one successful TokenUser result, proven with address
/// arithmetic BEFORE any dereference of the OS-written pointer: `(sid offset, SID length)`.
fn sid_layout(buffer: &[u8], returned: usize) -> (usize, usize) {
    let header = std::mem::size_of::<TOKEN_USER>();
    assert!(returned <= buffer.len() && returned >= header);
    // SAFETY: at least `size_of::<TOKEN_USER>()` initialized bytes; unaligned copy of plain data.
    let user = unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast::<TOKEN_USER>()) };
    let (base, sid) = (buffer.as_ptr() as usize, user.User.Sid as usize);
    // Range checks by number only: nothing outside `buffer` is ever read.
    assert!(
        sid >= base + header,
        "SID starts before the end of the header"
    );
    assert!(
        sid + 8 <= base + returned,
        "SID header outside the returned bytes"
    );
    let offset = sid - base;
    // Read the SID's revision and sub-authority count from our own slice, not via the pointer.
    assert_eq!(buffer[offset], 1, "SID revision");
    let len = 8 + 4 * usize::from(buffer[offset + 1]);
    assert!(
        offset + len <= returned,
        "SID extends past the returned bytes"
    );
    // Only now, with [sid, sid + len) proven inside the live buffer, ask Windows about it.
    // SAFETY: `sid` points into `buffer` (checked above), which is borrowed for this call.
    unsafe {
        assert_ne!(IsValidSid(user.User.Sid), 0);
        assert_eq!(GetLengthSid(user.User.Sid) as usize, len);
    }
    (offset, len)
}

/// P5-F-004 empirical evidence (an OS observation, NOT a statement of the Windows API
/// contract). On this Windows build, the SID that `GetTokenInformation(TokenUser)` points to
/// lies entirely inside the caller's buffer, directly after the header, and inside the
/// returned length. This holds for exact-size and oversized buffers, for 8- and 4-aligned
/// buffer starts, and across repeated calls. Unaligned starts are only recorded: Windows may
/// refuse them. The OS-written pointer is never dereferenced before its range is proven.
#[test]
fn p5_f_004_token_user_sid_lies_inside_the_returned_buffer_on_this_windows() {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: pseudo-handle of the current process; valid out-pointer.
    assert_ne!(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) },
        0
    );
    let mut required = 0u32;
    // SAFETY: size query with a null buffer of length zero.
    unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut required) };
    let required = required as usize;
    assert!(required > std::mem::size_of::<TOKEN_USER>());

    let mut first = None;
    let mut misaligned = Vec::new();
    for round in 0..100 {
        for extra in [0usize, 64] {
            for start in [0usize, 1, 2, 3, 4, 8] {
                // u64 storage gives an 8-aligned base; `start` shifts the buffer within it.
                let mut storage = vec![0u64; (required + extra + start).div_ceil(8) + 1];
                // SAFETY: a byte view of the whole `storage` allocation, which outlives `bytes`.
                let bytes = unsafe {
                    std::slice::from_raw_parts_mut(
                        storage.as_mut_ptr().cast::<u8>(),
                        storage.len() * 8,
                    )
                };
                let buffer = &mut bytes[start..start + required + extra];
                let returned = match token_user_into(token, buffer) {
                    Ok(returned) => returned,
                    Err(code) => {
                        assert!(start % 4 != 0, "an aligned buffer was refused: {code}");
                        if round == 0 {
                            misaligned.push((start, extra, format!("refused, error {code}")));
                        }
                        continue;
                    }
                };
                assert_eq!(returned, required, "returned length is the required length");
                let layout = sid_layout(buffer, returned);
                assert_eq!(
                    layout.0,
                    std::mem::size_of::<TOKEN_USER>(),
                    "SID follows the header"
                );
                assert_eq!(
                    layout.0 + layout.1,
                    returned,
                    "returned length is header plus SID"
                );
                assert_eq!(*first.get_or_insert(layout), layout, "stable across calls");
                if round == 0 && start % 4 != 0 {
                    misaligned.push((start, extra, "accepted, SID inside".to_string()));
                }
            }
        }
    }
    // SAFETY: the token handle from OpenProcessToken above, closed once.
    unsafe { CloseHandle(token) };
    eprintln!(
        "P5-F-004: required {required} bytes, SID (offset, length) {:?}, unaligned starts {misaligned:?}",
        first.unwrap()
    );
}
