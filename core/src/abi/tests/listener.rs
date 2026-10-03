//! P7.4 Windows listener ownership and owner-loop lifetime tests (P7-D-006, P7-D-007).
//!
//! The argument-order and Bootstrap tests run everywhere. Attaching needs a registered authority
//! and a Windows owner loop, so the rest is Windows-only; off Windows a child shows that attach
//! fails closed with `UNSUPPORTED_PLATFORM` and leaves the socket slot alone. In-process tests
//! drive a test-local `AbiState` and never probe socket numbers (other tests open sockets in
//! parallel, so a closed number may be reused at once); the children run the real exports in a
//! fresh process, where these tests open every socket themselves, and check whether a socket
//! number is open, still listening, or closed with `getsockopt`.

use std::ptr;
#[cfg(windows)]
use std::{
    io::{ErrorKind, Read},
    net::{SocketAddr, TcpListener, TcpStream},
    num::NonZeroU64,
    os::windows::io::{FromRawSocket, IntoRawSocket},
    panic::panic_any,
    sync::{
        Arc, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{
    SO_ACCEPTCONN, SO_TYPE, SOL_SOCKET, WSAENOTSOCK, WSAGetLastError, getsockopt,
};

#[cfg(windows)]
use super::{
    super::{
        BootstrapInput, PROCESS,
        authority::{CORE_ENTRIES, SAS_PAIRING_AUTHORITY_BUSY, SAS_PAIRING_AUTHORITY_EXHAUSTED},
        authority::{SAS_PAIRING_AUTHORITY_READY, SAS_PAIRING_AUTHORITY_STATE_INVALID},
        dispatch,
        hosting::{NETWORK_DROPS, OWNER_LOOP_CONSTRUCTIONS, OWNER_LOOP_FAULT},
        listener::{
            ADOPTION_FAULT, ListenerSlot, network_close_status, owner_loop_creation_status,
        },
        panic_boundary::contain,
        runtime::{AbiState, Admission},
    },
    PanicOnDrop,
    authority::{NO_STATUS, READY_10, race_pair, registration, session, spend, with_authority},
    authority_status, create, destroy, host_create, host_destroy, is_child, register, release,
    run_child,
};
use super::{
    super::{
        BootstrapView, BytesView, sas_pairing_host_attach_windows_listener,
        sas_pairing_host_detach_listener, status::*,
    },
    SAS_PAIRING_SOCKET_INVALID,
};
#[cfg(not(windows))]
use super::{create, destroy, is_child, run_child};
use crate::protocol::{Bootstrap, MAX_BOOTSTRAP_FRAME};
#[cfg(windows)]
use crate::{
    Registration, Role, windows_owner_loop::OwnerEvent, windows_owner_loop::OwnerLoopError,
};

const APPLICATION: &[u8] = b"p7-listener-application";
const ALGORITHM: &[u8] = b"x25519";
const KEY: &[u8] = &[7; 32];

fn bytes(value: &[u8]) -> BytesView {
    BytesView {
        data: value.as_ptr(),
        len: value.len(),
    }
}

fn view(application: &[u8], algorithm: &[u8], key: &[u8], context: &[u8]) -> BootstrapView {
    BootstrapView {
        application_identity: bytes(application),
        key_algorithm: bytes(algorithm),
        public_key: bytes(key),
        shared_context: bytes(context),
    }
}

/// A Bootstrap the core accepts; the empty shared context is a null pointer with length 0.
fn local_view() -> BootstrapView {
    let mut local = view(APPLICATION, ALGORITHM, KEY, b"");
    local.shared_context = BytesView {
        data: ptr::null(),
        len: 0,
    };
    local
}

/// Structurally fine, but the core's Bootstrap rules refuse it (uppercase key algorithm).
fn invalid_view() -> BootstrapView {
    view(APPLICATION, b"X25519", KEY, b"")
}

/// Attaches through the export; `expected` null when `None`.
fn attach_with(
    runtime: u64,
    host: u64,
    slot: &mut usize,
    local: &BootstrapView,
    expected: Option<&BootstrapView>,
) -> i32 {
    let expected = expected.map_or(ptr::null(), ptr::from_ref);
    // SAFETY: `slot` is a live, aligned, exclusive `usize`, holding either a socket this test
    // owns (bound and listening) or a value the export rejects or never adopts; `local` and
    // `expected` are live views over live byte slices for the whole call.
    unsafe { sas_pairing_host_attach_windows_listener(runtime, host, slot, local, expected) }
}

fn detach(runtime: u64, host: u64) -> i32 {
    sas_pairing_host_detach_listener(runtime, host)
}

// --- Platform-neutral -------------------------------------------------------------------------

/// Structural argument errors come first and never touch the slot. The socket value is a fake:
/// no call below gets as far as adoption (the last one fails on its handles or its platform).
#[test]
fn attach_rejects_bad_arguments_before_anything_else() {
    const FAKE: usize = 0x5A5A;
    let local = local_view();
    let rejected = |slot: *mut usize, local: *const BootstrapView, expected| {
        // SAFETY: every pointer is either live and aligned, or rejected before any access.
        unsafe { sas_pairing_host_attach_windows_listener(0, 0, slot, local, expected) }
    };
    let mut slot = FAKE;
    assert_eq!(
        rejected(ptr::null_mut(), &local, ptr::null()),
        SAS_PAIRING_INVALID_ARGUMENT
    );
    let mut words = [FAKE; 2];
    let misaligned = words
        .as_mut_ptr()
        .cast::<u8>()
        .wrapping_add(1)
        .cast::<usize>();
    assert_eq!(
        rejected(misaligned, &local, ptr::null()),
        SAS_PAIRING_INVALID_ARGUMENT
    );
    assert_eq!(words, [FAKE; 2], "nothing written");
    assert_eq!(
        rejected(&mut slot, ptr::null(), ptr::null()),
        SAS_PAIRING_INVALID_ARGUMENT
    );
    let views = [local; 2];
    let misaligned_view = views
        .as_ptr()
        .cast::<u8>()
        .wrapping_add(1)
        .cast::<BootstrapView>();
    assert_eq!(
        rejected(&mut slot, misaligned_view, ptr::null()),
        SAS_PAIRING_INVALID_ARGUMENT
    );
    assert_eq!(
        rejected(&mut slot, &local, misaligned_view),
        SAS_PAIRING_INVALID_ARGUMENT
    );
    assert_eq!(slot, FAKE);

    // A slot that holds no socket.
    let mut empty = SAS_PAIRING_SOCKET_INVALID;
    assert_eq!(
        rejected(&mut empty, &local, ptr::null()),
        SAS_PAIRING_INVALID_ARGUMENT
    );
    assert_eq!(empty, SAS_PAIRING_SOCKET_INVALID);

    // Byte views no Rust slice can describe, in every field of `local` and of `expected`.
    let malformed = [
        BytesView {
            data: ptr::null(),
            len: 1,
        },
        BytesView {
            data: KEY.as_ptr(),
            len: isize::MAX as usize + 1,
        },
        BytesView {
            data: ptr::without_provenance(usize::MAX - 2),
            len: 4,
        },
    ];
    for bad in malformed {
        for field in 0..4 {
            let mut broken = local;
            match field {
                0 => broken.application_identity = bad,
                1 => broken.key_algorithm = bad,
                2 => broken.public_key = bad,
                _ => broken.shared_context = bad,
            }
            assert_eq!(
                rejected(&mut slot, &broken, ptr::null()),
                SAS_PAIRING_INVALID_ARGUMENT
            );
            assert_eq!(
                rejected(&mut slot, &local, &broken),
                SAS_PAIRING_INVALID_ARGUMENT
            );
        }
    }
    assert_eq!(slot, FAKE, "nothing written");

    // Structurally valid: the handles (runtime 0) or the platform refuse it; never adopted.
    let status = rejected(&mut slot, &local, ptr::null());
    if cfg!(windows) {
        assert_eq!(status, SAS_PAIRING_INVALID_HANDLE);
    } else {
        assert_eq!(status, SAS_PAIRING_UNSUPPORTED_PLATFORM);
    }
    assert_eq!(slot, FAKE);
    assert_eq!(detach(0, 0), SAS_PAIRING_INVALID_HANDLE);
}

/// The copy bound (`MAX_BOOTSTRAP_FRAME` per field) never changes an outcome: `Bootstrap::new`
/// refuses any such field itself.
#[test]
fn the_bootstrap_copy_bound_never_changes_the_outcome() {
    let valid = || {
        [
            APPLICATION.to_vec(),
            ALGORITHM.to_vec(),
            KEY.to_vec(),
            Vec::new(),
        ]
    };
    let [a, b, c, d] = valid();
    assert!(Bootstrap::new(a, b, c, d).is_ok());
    for field in 0..4 {
        let mut fields = valid();
        fields[field] = vec![b'a'; MAX_BOOTSTRAP_FRAME + 1];
        let [a, b, c, d] = fields;
        assert!(Bootstrap::new(a, b, c, d).is_err(), "field {field}");
    }
}

// --- Unsupported platforms --------------------------------------------------------------------

#[cfg(not(windows))]
#[test]
#[ignore = "subprocess child; run by attach_fails_closed_on_unsupported_platforms"]
fn child_unsupported_platform() {
    if !is_child("listener::child_unsupported_platform") {
        return;
    }
    // No real socket exists here: the value is never read as one, because nothing is adopted.
    const FAKE: usize = 0x5A5A;
    let (status, runtime) = create();
    assert_eq!(status, SAS_PAIRING_OK);
    let mut slot = FAKE;
    for (runtime, host) in [(runtime, runtime + 1), (runtime, 0), (0, 0)] {
        for local in [local_view(), invalid_view()] {
            assert_eq!(
                attach_with(runtime, host, &mut slot, &local, None),
                SAS_PAIRING_UNSUPPORTED_PLATFORM
            );
            assert_eq!(
                attach_with(runtime, host, &mut slot, &local, Some(&invalid_view())),
                SAS_PAIRING_UNSUPPORTED_PLATFORM
            );
        }
    }
    assert_eq!(slot, FAKE, "the slot is never touched");
    // No host can exist off Windows (no authority registers), so detach names nothing.
    assert_eq!(detach(runtime, runtime + 1), SAS_PAIRING_INVALID_HANDLE);
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
}

#[cfg(not(windows))]
#[test]
fn attach_fails_closed_on_unsupported_platforms() {
    run_child("listener::child_unsupported_platform");
}

// --- Windows helpers --------------------------------------------------------------------------

/// A loopback listener on an OS-assigned port, bound by the test (the caller), as a raw SOCKET
/// the test owns. Test plumbing only, never policy.
#[cfg(windows)]
fn bound() -> (usize, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    (listener.into_raw_socket() as usize, address)
}

/// Takes a socket the caller still owns back into a `TcpListener` (which closes it on drop).
#[cfg(windows)]
fn reclaim(raw: usize) -> TcpListener {
    // SAFETY: only called for sockets the test bound and the ABI did not adopt (the slot still
    // holds them), so the test is their one owner.
    unsafe { TcpListener::from_raw_socket(raw as u64) }
}

/// Whether `raw` names a listening socket of this process (children only: see the module docs).
#[cfg(windows)]
fn listening(raw: usize) -> bool {
    let (mut value, mut len) = (0_i32, size_of::<i32>() as i32);
    // SAFETY: `value` and `len` are live, writable locals of the sizes passed; getsockopt keeps
    // no pointer. An invalid socket number only makes it fail.
    let status = unsafe {
        getsockopt(
            raw,
            SOL_SOCKET,
            SO_ACCEPTCONN,
            ptr::from_mut(&mut value).cast(),
            &mut len,
        )
    };
    status == 0 && value != 0
}

/// Whether `raw` names no socket of this process any more (children only).
#[cfg(windows)]
fn closed(raw: usize) -> bool {
    let (mut value, mut len) = (0_i32, size_of::<i32>() as i32);
    // SAFETY: as in `listening`.
    let status = unsafe {
        getsockopt(
            raw,
            SOL_SOCKET,
            SO_TYPE,
            ptr::from_mut(&mut value).cast(),
            &mut len,
        )
    };
    // SAFETY: no arguments; reads this thread's last WinSock error.
    status != 0 && unsafe { WSAGetLastError() } == WSAENOTSOCK
}

/// The caller still owns `raw`: it is still a listening socket, which the test then closes.
#[cfg(windows)]
fn still_the_callers(raw: usize) {
    assert!(
        listening(raw),
        "the ABI closed or changed a socket it never adopted"
    );
    drop(reclaim(raw));
    assert!(closed(raw));
}

#[cfg(windows)]
fn attach(runtime: u64, host: u64, slot: &mut usize) -> i32 {
    attach_with(runtime, host, slot, &local_view(), None)
}

/// Attaches through the state method directly (local-state tests).
#[cfg(windows)]
fn attach_local(
    state: &AbiState,
    runtime: u64,
    host: u64,
    slot: &mut usize,
    local: &BootstrapView,
    expected: Option<&BootstrapView>,
) -> i32 {
    let socket = *slot;
    // SAFETY: `slot` is live, aligned, and exclusive for the call and holds a socket the test
    // bound and owns; the views are live over live slices for the call.
    unsafe {
        let slot = ListenerSlot::new(slot, socket);
        let local = BootstrapInput::new(*local);
        let expected = expected.map(|view| BootstrapInput::new(*view));
        state.attach_listener(runtime, host, slot, &local, expected.as_ref())
    }
}

#[cfg(windows)]
fn has_network(state: &AbiState, runtime: u64, host: u64) -> Option<bool> {
    state
        .with_runtime(runtime, Admission::Cleanup, |live| {
            Ok(live
                .hosts
                .get(&NonZeroU64::new(host).unwrap())
                .map(|context| context.has_network()))
        })
        .ok()
        .flatten()
}

/// Holders of the authority's shared state: the authority itself plus one per live router.
#[cfg(windows)]
fn holders(state: &AbiState, runtime: u64, authority: u64) -> usize {
    with_authority(state, runtime, authority, |authority| {
        Arc::strong_count(&authority.0)
    })
}

/// Live connections the authority counts (across all its routers).
#[cfg(windows)]
fn live_connections(state: &AbiState, runtime: u64, authority: u64) -> usize {
    with_authority(state, runtime, authority, |authority| {
        authority
            .0
            .shared
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .live_connections
    })
}

/// Drives `host`'s owner loop internally (no ABI export) until it accepts one connection.
#[cfg(windows)]
fn accept_one(state: &AbiState, runtime: u64, host: u64) {
    let give_up = Instant::now() + Duration::from_secs(10);
    loop {
        let events = state
            .with_runtime(runtime, Admission::Cleanup, |live| {
                let context = live.hosts.get_mut(&NonZeroU64::new(host).unwrap()).unwrap();
                let owner_loop = context.owner_loop_for_test().expect("attached");
                Ok(owner_loop.drive_once().expect("drive").events)
            })
            .unwrap();
        match events.as_slice() {
            [] => assert!(Instant::now() < give_up, "no accept in 10 s"),
            [OwnerEvent::Accepted(_)] => return,
            other => panic!("unexpected {other:?}"),
        }
    }
}

/// `(owner-loop connections, router sessions)` of `host`, read in place.
#[cfg(windows)]
fn host_connections(state: &AbiState, runtime: u64, host: u64) -> (Option<usize>, usize) {
    state
        .with_runtime(runtime, Admission::Cleanup, |live| {
            let context = live.hosts.get_mut(&NonZeroU64::new(host).unwrap()).unwrap();
            let sessions = context.router().sessions_for_test();
            let connections = context
                .owner_loop_for_test()
                .map(|owner_loop| owner_loop.live_connections());
            Ok((connections, sessions))
        })
        .unwrap()
}

/// The peer saw its connection end (EOF or reset), not a timeout.
#[cfg(windows)]
fn ended(client: &mut TcpStream) -> bool {
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    match client.read(&mut [0; 1]) {
        Ok(0) => true,
        Ok(_) => false,
        Err(error) => !matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut),
    }
}

// --- Error boundaries (Windows) ---------------------------------------------------------------

/// The owner-loop constructor's one documented failure is `LISTENER_SETUP_FAILED`; a close
/// report is `OK` (also `Closed`: nothing left to close) or `OWNERSHIP_UNCERTAIN`; anything
/// else breaks an invariant and is fatal.
#[cfg(windows)]
#[test]
fn owner_loop_errors_map_narrowly() {
    for kind in [
        ErrorKind::Other,
        ErrorKind::InvalidInput,
        ErrorKind::PermissionDenied,
    ] {
        assert_eq!(
            owner_loop_creation_status(&OwnerLoopError::ListenerIo(kind)),
            SAS_PAIRING_LISTENER_SETUP_FAILED
        );
    }
    let unexpected = [
        OwnerLoopError::Closed,
        OwnerLoopError::UnknownConnection,
        OwnerLoopError::Poll(10_050),
        OwnerLoopError::OwnershipUncertain,
        OwnerLoopError::Connection(crate::windows_tcp::TcpError::Closed),
    ];
    for error in &unexpected {
        assert_eq!(
            owner_loop_creation_status(error),
            SAS_PAIRING_FATAL,
            "{error:?}"
        );
    }
    assert_eq!(network_close_status(&Ok(())), SAS_PAIRING_OK);
    assert_eq!(
        network_close_status(&Err(OwnerLoopError::Closed)),
        SAS_PAIRING_OK
    );
    assert_eq!(
        network_close_status(&Err(OwnerLoopError::OwnershipUncertain)),
        SAS_PAIRING_OWNERSHIP_UNCERTAIN
    );
    for error in [
        OwnerLoopError::UnknownConnection,
        OwnerLoopError::ListenerIo(ErrorKind::Other),
        OwnerLoopError::Poll(10_050),
        OwnerLoopError::Connection(crate::windows_tcp::TcpError::Closed),
    ] {
        assert_eq!(
            network_close_status(&Err(error.clone())),
            SAS_PAIRING_FATAL,
            "{error:?}"
        );
    }
}

/// The Bootstrap a view yields is exactly the one `Bootstrap::new` builds from the same bytes.
#[cfg(windows)]
#[test]
fn bootstrap_views_are_copied_into_bootstrap_new() {
    let context = b"shared-context".to_vec();
    let with_context = view(APPLICATION, ALGORITHM, KEY, &context);
    // SAFETY: views over live slices.
    let built = unsafe { BootstrapInput::new(with_context) }.to_bootstrap();
    let direct = Bootstrap::new(
        APPLICATION.to_vec(),
        ALGORITHM.to_vec(),
        KEY.to_vec(),
        context.clone(),
    )
    .unwrap();
    assert_eq!(built, Some(direct));
    // SAFETY: as above (the null shared context has length 0).
    let empty = unsafe { BootstrapInput::new(local_view()) }.to_bootstrap();
    assert_eq!(empty.unwrap().shared_context(), b"");
    // SAFETY: as above.
    assert_eq!(
        unsafe { BootstrapInput::new(invalid_view()) }.to_bootstrap(),
        None
    );
    let empty_identity = view(b"", ALGORITHM, KEY, b"");
    // SAFETY: as above.
    assert_eq!(
        unsafe { BootstrapInput::new(empty_identity) }.to_bootstrap(),
        None
    );
    let oversized = vec![0; MAX_BOOTSTRAP_FRAME + 1];
    // SAFETY: as above.
    assert_eq!(
        unsafe { BootstrapInput::new(view(APPLICATION, ALGORITHM, &oversized, b"")) }
            .to_bootstrap(),
        None
    );
}

// --- Local state with real authorities and sockets (Windows) ----------------------------------

/// Every failure before adoption leaves the socket with the caller and the slot unchanged; the
/// order is Bootstrap, then fatal and handles, then an existing listener; replacement is detach
/// then attach; nothing changes the authority.
#[cfg(windows)]
#[test]
fn every_failure_before_adoption_leaves_the_socket_with_the_caller() {
    let scope = b"p7-listener-local-order";
    let state = AbiState::new();
    let runtime = state.create().unwrap().get();
    let authority = state.register_authority(runtime, scope).unwrap().get();
    let host = state.create_host(runtime, authority).unwrap().get();
    let stale = state.create_host(runtime, authority).unwrap().get();
    assert_eq!(state.destroy_host(runtime, stale), SAS_PAIRING_OK);
    let (raw, _) = bound();
    let mut slot = raw;
    let loops = OWNER_LOOP_CONSTRUCTIONS.get();
    let (local, invalid) = (local_view(), invalid_view());

    // An invalid Bootstrap (local or expected) wins over bad handles.
    for (local, expected) in [(&invalid, None), (&local, Some(&invalid))] {
        for target in [host, 0, stale] {
            assert_eq!(
                attach_local(&state, runtime, target, &mut slot, local, expected),
                SAS_PAIRING_INVALID_BOOTSTRAP
            );
        }
    }
    // Handles: zero, random, stale, and every other kind of handle.
    for (runtime, host) in [
        (runtime, 0),
        (runtime, u64::MAX),
        (runtime, stale),
        (runtime, authority),
        (runtime, runtime),
        (0, host),
        (runtime + 1_000, host),
        (host, host),
    ] {
        assert_eq!(
            attach_local(&state, runtime, host, &mut slot, &local, None),
            SAS_PAIRING_INVALID_HANDLE
        );
    }
    assert_eq!(slot, raw, "the slot is untouched before adoption");
    assert_eq!(OWNER_LOOP_CONSTRUCTIONS.get(), loops, "no owner loop built");
    assert_eq!(has_network(&state, runtime, host), Some(false));

    // Attach, with an expected peer Bootstrap: the slot is cleared, one loop is built.
    let peer = view(b"p7-listener-peer", ALGORITHM, &[9; 32], b"");
    assert_eq!(
        attach_local(&state, runtime, host, &mut slot, &local, Some(&peer)),
        SAS_PAIRING_OK
    );
    assert_eq!(slot, SAS_PAIRING_SOCKET_INVALID);
    assert_eq!(OWNER_LOOP_CONSTRUCTIONS.get(), loops + 1);
    assert_eq!(has_network(&state, runtime, host), Some(true));

    // A second listener is refused before adoption: the caller keeps it and it still listens.
    let (second, second_address) = bound();
    let mut second_slot = second;
    assert_eq!(
        attach_local(&state, runtime, host, &mut second_slot, &local, None),
        SAS_PAIRING_LISTENER_ALREADY_ATTACHED
    );
    assert_eq!(second_slot, second);
    assert_eq!(OWNER_LOOP_CONSTRUCTIONS.get(), loops + 1);
    let second_listener = reclaim(second);
    let _client = TcpStream::connect(second_address).unwrap();
    second_listener
        .accept()
        .expect("the caller's socket still listens");

    // Detach is idempotent; replacement is detach, then attach.
    assert_eq!(state.detach_listener(runtime, host), SAS_PAIRING_OK);
    assert_eq!(has_network(&state, runtime, host), Some(false));
    assert_eq!(state.detach_listener(runtime, host), SAS_PAIRING_OK);
    let (third, _) = bound();
    let mut third_slot = third;
    assert_eq!(
        attach_local(&state, runtime, host, &mut third_slot, &local, None),
        SAS_PAIRING_OK
    );
    assert_eq!(third_slot, SAS_PAIRING_SOCKET_INVALID);
    assert_eq!(
        state.authority_status(runtime, authority),
        Ok((SAS_PAIRING_AUTHORITY_READY, 10))
    );

    // Fatal precedes the handles and the existing listener; detach stays cleanup.
    let status = contain(&state.fatal, SAS_PAIRING_FATAL, || -> i32 {
        panic!("injected panic")
    });
    assert_eq!(status, SAS_PAIRING_FATAL);
    let (fourth, fourth_address) = bound();
    let mut fourth_slot = fourth;
    let loops = OWNER_LOOP_CONSTRUCTIONS.get();
    for (runtime, host) in [(runtime, host), (runtime, stale), (0, 0)] {
        assert_eq!(
            attach_local(&state, runtime, host, &mut fourth_slot, &local, None),
            SAS_PAIRING_FATAL
        );
    }
    assert_eq!(fourth_slot, fourth);
    assert_eq!(OWNER_LOOP_CONSTRUCTIONS.get(), loops);
    let fourth_listener = reclaim(fourth);
    let _client = TcpStream::connect(fourth_address).unwrap();
    fourth_listener
        .accept()
        .expect("the caller's socket still listens");
    assert_eq!(state.detach_listener(runtime, host), SAS_PAIRING_OK);
    assert_eq!(has_network(&state, runtime, host), Some(false));
    assert_eq!(state.destroy(runtime), SAS_PAIRING_OK);
    assert_eq!(registration(scope), Some(Registration::Inactive));
}

/// The deepest borrow chain (owner loop → accepted `WindowsTcpConnection` → `HostConnection` →
/// `TransportConnection` → router) is gone before the router on every teardown path: a probe
/// that drops right after the owner loop sees no live connection and still counts the router
/// among the authority's holders, and the router (and its holder count) goes only afterwards.
#[cfg(windows)]
#[test]
fn the_owner_loop_and_its_connections_drop_before_the_router() {
    let (a, b) = (b"p7-listener-local-drop-a", b"p7-listener-local-drop-b");
    let state = AbiState::new();
    let runtime = state.create().unwrap().get();
    let first = state.register_authority(runtime, a).unwrap().get();
    let without_hosts = holders(&state, runtime, first);
    NETWORK_DROPS.take();

    // Attaches a listener to a new host of `authority` and has its loop accept one client.
    let connected = |state: &AbiState, runtime: u64, authority: u64| {
        let host = state.create_host(runtime, authority).unwrap().get();
        let (raw, address) = bound();
        let mut slot = raw;
        assert_eq!(
            attach_local(state, runtime, host, &mut slot, &local_view(), None),
            SAS_PAIRING_OK
        );
        let client = TcpStream::connect(address).unwrap();
        accept_one(state, runtime, host);
        assert_eq!(host_connections(state, runtime, host), (Some(1), 1));
        (host, client)
    };

    // Detach: the loop and its connection go; the router stays and its session is closed.
    let (host, mut client) = connected(&state, runtime, first);
    assert_eq!(live_connections(&state, runtime, first), 1);
    let with_router = holders(&state, runtime, first);
    assert_eq!(with_router, without_hosts + 1);
    assert_eq!(state.detach_listener(runtime, host), SAS_PAIRING_OK);
    assert_eq!(NETWORK_DROPS.take(), [Some((with_router, 0))]);
    assert_eq!(host_connections(&state, runtime, host), (None, 0));
    assert_eq!(holders(&state, runtime, first), with_router, "router alive");
    assert!(ended(&mut client), "the accepted connection was closed");

    // Host destroy: loop and connection first, then the router.
    let (destroyed, mut client) = connected(&state, runtime, first);
    let with_routers = holders(&state, runtime, first);
    assert_eq!(with_routers, without_hosts + 2);
    assert_eq!(state.destroy_host(runtime, destroyed), SAS_PAIRING_OK);
    assert_eq!(NETWORK_DROPS.take(), [Some((with_routers, 0))]);
    assert_eq!(
        holders(&state, runtime, first),
        with_routers - 1,
        "router gone"
    );
    assert!(ended(&mut client));

    // Authority release: every child loop, then every child router, then the core release
    // (which would be BUSY if a router were left).
    let (_, mut client) = connected(&state, runtime, first);
    let with_routers = holders(&state, runtime, first);
    assert_eq!(with_routers, without_hosts + 2);
    assert_eq!(state.release_authority(runtime, first), SAS_PAIRING_OK);
    assert_eq!(NETWORK_DROPS.take(), [Some((with_routers, 0))]);
    assert!(ended(&mut client));
    assert_eq!(registration(a), Some(Registration::Inactive));

    // Runtime destroy over two authorities: both loops (with their connections) before any
    // router, every router before any authority.
    let first = state.register_authority(runtime, a).unwrap().get();
    let second = state.register_authority(runtime, b).unwrap().get();
    let (_, mut first_client) = connected(&state, runtime, first);
    let (_, mut second_client) = connected(&state, runtime, second);
    let expected = [
        Some((holders(&state, runtime, first), 0)),
        Some((holders(&state, runtime, second), 0)),
    ];
    assert_eq!(state.destroy(runtime), SAS_PAIRING_OK);
    assert_eq!(NETWORK_DROPS.take(), expected);
    assert!(ended(&mut first_client) && ended(&mut second_client));
    assert_eq!(registration(a), Some(Registration::Inactive));
    assert_eq!(registration(b), Some(Registration::Inactive));
}

// --- Real exports, isolated processes (Windows) ----------------------------------------------

/// Basic lifecycle, invalid hosts and Bootstraps, a second attach, replacement, and stale hosts
/// through the real exports, with every socket's owner checked.
#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by listener_lifecycle_through_the_exports"]
fn child_listener_lifecycle() {
    if !is_child("listener::child_listener_lifecycle") {
        return;
    }
    let scope = b"p7-listener-lifecycle";
    let (_, runtime) = create();
    let (_, authority) = register(runtime, scope);
    let (_, host) = host_create(runtime, authority);
    let (_, _, accounting) = session(scope).unwrap();
    let (first, _) = bound();
    let mut slot = first;
    let (entries, loops) = (
        CORE_ENTRIES.load(Ordering::SeqCst),
        OWNER_LOOP_CONSTRUCTIONS.get(),
    );

    // Invalid hosts: no transfer.
    for (runtime, host) in [
        (runtime, 0),
        (runtime, u64::MAX),
        (runtime, authority),
        (runtime, runtime),
        (0, host),
        (runtime + 1_000, host),
        (authority, host),
        (host, host),
    ] {
        assert_eq!(attach(runtime, host, &mut slot), SAS_PAIRING_INVALID_HANDLE);
    }
    // Invalid Bootstraps: no transfer.
    let empty_identity = view(b"", ALGORITHM, KEY, b"");
    for (local, expected) in [
        (invalid_view(), None),
        (empty_identity, None),
        (local_view(), Some(invalid_view())),
    ] {
        assert_eq!(
            attach_with(runtime, host, &mut slot, &local, expected.as_ref()),
            SAS_PAIRING_INVALID_BOOTSTRAP
        );
    }
    assert_eq!(slot, first);
    assert!(listening(first), "the caller's socket is untouched");
    assert_eq!(CORE_ENTRIES.load(Ordering::SeqCst), entries, "core entered");
    assert_eq!(OWNER_LOOP_CONSTRUCTIONS.get(), loops, "owner loop built");

    // Attach: the slot is cleared, the ABI owns the still-listening socket.
    assert_eq!(attach(runtime, host, &mut slot), SAS_PAIRING_OK);
    assert_eq!(slot, SAS_PAIRING_SOCKET_INVALID);
    assert_eq!(OWNER_LOOP_CONSTRUCTIONS.get(), loops + 1);
    assert!(listening(first), "adopted, not closed");
    assert_eq!(authority_status(runtime, authority), READY_10);

    // A second attach is refused before adoption: the caller keeps the second socket.
    let (second, _) = bound();
    let mut second_slot = second;
    assert_eq!(
        attach(runtime, host, &mut second_slot),
        SAS_PAIRING_LISTENER_ALREADY_ATTACHED
    );
    assert_eq!(second_slot, second);
    assert!(listening(second) && listening(first));

    // Detach: the first socket is closed by the ABI; idempotent; host and authority stay.
    assert_eq!(detach(runtime, host), SAS_PAIRING_OK);
    assert!(closed(first));
    assert_eq!(detach(runtime, host), SAS_PAIRING_OK);
    assert_eq!(authority_status(runtime, authority), READY_10);

    // Replacement: attach the second socket to the same host.
    assert_eq!(attach(runtime, host, &mut second_slot), SAS_PAIRING_OK);
    assert_eq!(second_slot, SAS_PAIRING_SOCKET_INVALID);
    assert!(listening(second));

    // Host destroy without detach: the socket closes with the host.
    assert_eq!(host_destroy(runtime, host), SAS_PAIRING_OK);
    assert!(closed(second));
    let (third, _) = bound();
    let mut third_slot = third;
    assert_eq!(
        attach(runtime, host, &mut third_slot),
        SAS_PAIRING_INVALID_HANDLE,
        "stale host"
    );
    assert_eq!(detach(runtime, host), SAS_PAIRING_INVALID_HANDLE);
    assert_eq!(third_slot, third);

    // A new host on the same authority accepts a new listener; release closes it.
    let (_, again) = host_create(runtime, authority);
    assert_eq!(attach(runtime, again, &mut third_slot), SAS_PAIRING_OK);
    assert_eq!(release(runtime, authority), SAS_PAIRING_OK);
    assert!(closed(third));
    assert_eq!(detach(runtime, again), SAS_PAIRING_INVALID_HANDLE);
    assert_eq!(
        session(scope),
        Some((Registration::Inactive, 10, accounting))
    );
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
    assert_eq!(detach(runtime, again), SAS_PAIRING_INVALID_HANDLE);
    assert!(!PROCESS.fatal.is_set());
}

#[cfg(windows)]
#[test]
fn listener_lifecycle_through_the_exports() {
    run_child("listener::child_listener_lifecycle");
}

/// Host destroy, authority release, and runtime destroy with attached listeners (no detach):
/// every network context goes first, while its router is alive, then the routers, then the
/// authorities; every adopted socket is closed.
#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by parent_destruction_closes_listeners_before_routers"]
fn child_listener_cascades() {
    if !is_child("listener::child_listener_cascades") {
        return;
    }
    let (a, b) = (b"p7-listener-cascade-a", b"p7-listener-cascade-b");
    let (_, runtime) = create();
    let (_, first) = register(runtime, a);
    let (_, second) = register(runtime, b);
    let alone = holders(&PROCESS, runtime, first);
    let hosts: Vec<u64> = [first, first, second]
        .into_iter()
        .map(|authority| host_create(runtime, authority).1)
        .collect();
    let sockets: Vec<usize> = hosts
        .iter()
        .map(|&host| {
            let (raw, _) = bound();
            let mut slot = raw;
            assert_eq!(attach(runtime, host, &mut slot), SAS_PAIRING_OK);
            raw
        })
        .collect();
    assert_eq!(holders(&PROCESS, runtime, first), alone + 2);
    NETWORK_DROPS.take();

    // Host destroy: its loop goes while its router is alive (both routers counted), then the
    // router (one fewer holder afterwards).
    assert_eq!(host_destroy(runtime, hosts[0]), SAS_PAIRING_OK);
    assert_eq!(NETWORK_DROPS.take(), [Some((alone + 2, 0))]);
    assert_eq!(holders(&PROCESS, runtime, first), alone + 1);
    assert!(closed(sockets[0]) && listening(sockets[1]) && listening(sockets[2]));
    assert_eq!(registration(a), Some(Registration::Active));
    assert_eq!(authority_status(runtime, first), READY_10);

    // Authority release: the remaining child loop (router still counted), then the router,
    // then the core release, which returns OK only because no router is left.
    assert_eq!(release(runtime, first), SAS_PAIRING_OK);
    assert_eq!(NETWORK_DROPS.take(), [Some((alone + 1, 0))]);
    assert!(closed(sockets[1]) && listening(sockets[2]));
    assert_eq!(detach(runtime, hosts[1]), SAS_PAIRING_INVALID_HANDLE);
    assert_eq!(authority_status(runtime, first), NO_STATUS);
    assert_eq!(registration(a), Some(Registration::Inactive));

    // Runtime destroy with listeners on hosts of two authorities.
    let (_, again) = register(runtime, a);
    let (_, fourth) = host_create(runtime, again);
    let (raw, _) = bound();
    let mut slot = raw;
    assert_eq!(attach(runtime, fourth, &mut slot), SAS_PAIRING_OK);
    let expected = [
        Some((holders(&PROCESS, runtime, second), 0)),
        Some((holders(&PROCESS, runtime, again), 0)),
    ];
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
    assert_eq!(NETWORK_DROPS.take(), expected);
    assert!(closed(sockets[2]) && closed(raw));
    for host in [hosts[2], fourth] {
        assert_eq!(detach(runtime, host), SAS_PAIRING_INVALID_HANDLE);
        assert_eq!(host_destroy(runtime, host), SAS_PAIRING_INVALID_HANDLE);
    }
    assert_eq!(registration(a), Some(Registration::Inactive));
    assert_eq!(registration(b), Some(Registration::Inactive));
    let (_, next) = create();
    for host in [hosts[2], fourth] {
        assert_eq!(detach(next, host), SAS_PAIRING_INVALID_HANDLE);
    }
    assert_eq!(destroy(next), SAS_PAIRING_OK);
}

#[cfg(windows)]
#[test]
fn parent_destruction_closes_listeners_before_routers() {
    run_child("listener::child_listener_cascades");
}

/// After fatal: attach refuses before adoption (the caller keeps the socket) without entering
/// the core; detach still cleans up and never clears fatal.
#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by attach_is_fatal_gated_and_detach_is_cleanup"]
fn child_listener_fatal() {
    if !is_child("listener::child_listener_fatal") {
        return;
    }
    let scope = b"p7-listener-fatal";
    let (_, runtime) = create();
    let (_, authority) = register(runtime, scope);
    let (_, host) = host_create(runtime, authority);
    let (_, sibling) = host_create(runtime, authority);
    let (first, _) = bound();
    let mut slot = first;
    assert_eq!(attach(runtime, host, &mut slot), SAS_PAIRING_OK);
    let (_, _, accounting) = session(scope).unwrap();

    assert_eq!(
        dispatch(SAS_PAIRING_FATAL, |_| -> i32 { panic!("injected panic") }),
        SAS_PAIRING_FATAL
    );
    assert!(PROCESS.fatal.is_set());
    let (second, _) = bound();
    let mut second_slot = second;
    let (entries, loops) = (
        CORE_ENTRIES.load(Ordering::SeqCst),
        OWNER_LOOP_CONSTRUCTIONS.get(),
    );
    for (runtime, host) in [
        (runtime, sibling),
        (runtime, host),
        (0, 0),
        (runtime + 1_000, sibling),
    ] {
        assert_eq!(attach(runtime, host, &mut second_slot), SAS_PAIRING_FATAL);
    }
    // The Bootstrap check (a stateless value check) comes before the fatal state.
    assert_eq!(
        attach_with(runtime, sibling, &mut second_slot, &invalid_view(), None),
        SAS_PAIRING_INVALID_BOOTSTRAP
    );
    assert_eq!(second_slot, second);
    assert!(listening(second) && listening(first));
    assert_eq!(CORE_ENTRIES.load(Ordering::SeqCst), entries, "core entered");
    assert_eq!(OWNER_LOOP_CONSTRUCTIONS.get(), loops, "owner loop built");

    // Detach is cleanup: it closes the adopted socket, is idempotent, and keeps fatal.
    assert_eq!(detach(runtime, host), SAS_PAIRING_OK);
    assert!(closed(first));
    assert_eq!(detach(runtime, host), SAS_PAIRING_OK);
    assert_eq!(detach(runtime, sibling), SAS_PAIRING_OK);
    assert!(PROCESS.fatal.is_set());
    assert_eq!(attach(runtime, host, &mut second_slot), SAS_PAIRING_FATAL);
    assert_eq!(second_slot, second);
    assert_eq!(session(scope), Some((Registration::Active, 10, accounting)));
    assert_eq!(host_destroy(runtime, host), SAS_PAIRING_OK);
    assert_eq!(release(runtime, authority), SAS_PAIRING_OK);
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
    assert_eq!(create(), (SAS_PAIRING_FATAL, 0));
    still_the_callers(second);
    assert_eq!(
        session(scope),
        Some((Registration::Inactive, 10, accounting))
    );
}

#[cfg(windows)]
#[test]
fn attach_is_fatal_gated_and_detach_is_cleanup() {
    run_child("listener::child_listener_fatal");
}

#[cfg(windows)]
static ADOPTION_PAYLOAD_DROPS: AtomicUsize = AtomicUsize::new(0);

#[cfg(windows)]
fn ordinary_adoption_panic() {
    panic!("injected panic right after socket adoption");
}

#[cfg(windows)]
fn drop_panicking_adoption_panic() {
    panic_any(PanicOnDrop(&ADOPTION_PAYLOAD_DROPS));
}

/// A panic right after adoption and before the owner loop exists, through the real export:
/// exactly one owner (Rust, whose unwinding closes the socket), the caller's slot `INVALID`,
/// nothing installed, fatal, and cleanup still works.
#[cfg(windows)]
fn assert_adoption_panic_is_contained(fault: fn()) {
    let scope = b"p7-listener-adoption-panic";
    let (_, runtime) = create();
    let (_, authority) = register(runtime, scope);
    let (_, host) = host_create(runtime, authority);
    let (_, _, accounting) = session(scope).unwrap();
    let (raw, _) = bound();
    let mut slot = raw;
    let loops = OWNER_LOOP_CONSTRUCTIONS.get();

    ADOPTION_FAULT.set(Some(fault));
    assert_eq!(attach(runtime, host, &mut slot), SAS_PAIRING_FATAL);
    assert_eq!(
        slot, SAS_PAIRING_SOCKET_INVALID,
        "ownership had transferred"
    );
    assert!(closed(raw), "the unwinding Rust owner closed the socket");
    assert_eq!(OWNER_LOOP_CONSTRUCTIONS.get(), loops, "no owner loop built");
    assert!(PROCESS.fatal.is_set());
    assert_eq!(
        ADOPTION_PAYLOAD_DROPS.load(Ordering::SeqCst),
        0,
        "payload destructor ran"
    );
    assert_eq!(has_network(&PROCESS, runtime, host), Some(false));

    // Later normal operations are fatal and adopt nothing.
    let (other, _) = bound();
    let mut other_slot = other;
    assert_eq!(attach(runtime, host, &mut other_slot), SAS_PAIRING_FATAL);
    assert_eq!(other_slot, other);
    assert_eq!(host_create(runtime, authority), (SAS_PAIRING_FATAL, 0));
    assert_eq!(
        authority_status(runtime, authority),
        (SAS_PAIRING_FATAL, SAS_PAIRING_AUTHORITY_STATE_INVALID, 0)
    );
    assert_eq!(session(scope), Some((Registration::Active, 10, accounting)));

    // Cleanup still works.
    assert_eq!(detach(runtime, host), SAS_PAIRING_OK);
    assert_eq!(host_destroy(runtime, host), SAS_PAIRING_OK);
    assert_eq!(release(runtime, authority), SAS_PAIRING_OK);
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
    assert_eq!(create(), (SAS_PAIRING_FATAL, 0));
    still_the_callers(other);
    assert_eq!(
        session(scope),
        Some((Registration::Inactive, 10, accounting))
    );
    assert_eq!(ADOPTION_PAYLOAD_DROPS.load(Ordering::SeqCst), 0);
}

#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by a_panic_after_socket_adoption_leaves_one_owner"]
fn child_adoption_panic_ordinary() {
    if !is_child("listener::child_adoption_panic_ordinary") {
        return;
    }
    assert_adoption_panic_is_contained(ordinary_adoption_panic);
}

#[cfg(windows)]
#[test]
fn a_panic_after_socket_adoption_leaves_one_owner() {
    run_child("listener::child_adoption_panic_ordinary");
}

#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by a_drop_panicking_payload_after_socket_adoption_is_never_dropped"]
fn child_adoption_panic_on_drop() {
    if !is_child("listener::child_adoption_panic_on_drop") {
        return;
    }
    assert_adoption_panic_is_contained(drop_panicking_adoption_panic);
}

/// The child aborts if the payload destructor runs (its panic would cross `extern "C"`).
#[cfg(windows)]
#[test]
fn a_drop_panicking_payload_after_socket_adoption_is_never_dropped() {
    run_child("listener::child_adoption_panic_on_drop");
}

/// Owner-loop setup failures after adoption: the documented one is `LISTENER_SETUP_FAILED`
/// (not fatal), any other is `FATAL`; either way the slot is `INVALID` and Rust closed the
/// socket, and nothing is installed.
#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by an_owner_loop_setup_failure_closes_the_adopted_socket"]
fn child_listener_setup_failure() {
    if !is_child("listener::child_listener_setup_failure") {
        return;
    }
    let scope = b"p7-listener-setup-failure";
    let (_, runtime) = create();
    let (_, authority) = register(runtime, scope);
    let (_, host) = host_create(runtime, authority);
    let loops = OWNER_LOOP_CONSTRUCTIONS.get();

    let (first, _) = bound();
    let mut slot = first;
    OWNER_LOOP_FAULT.set(Some(|| OwnerLoopError::ListenerIo(ErrorKind::Other)));
    assert_eq!(
        attach(runtime, host, &mut slot),
        SAS_PAIRING_LISTENER_SETUP_FAILED
    );
    assert_eq!(slot, SAS_PAIRING_SOCKET_INVALID);
    assert!(closed(first), "Rust closed the adopted socket");
    assert_eq!(
        OWNER_LOOP_CONSTRUCTIONS.get(),
        loops + 1,
        "the real constructor ran"
    );
    assert_eq!(has_network(&PROCESS, runtime, host), Some(false));
    assert!(!PROCESS.fatal.is_set());

    // The host stays attachable.
    let (second, _) = bound();
    let mut slot = second;
    assert_eq!(attach(runtime, host, &mut slot), SAS_PAIRING_OK);
    assert_eq!(detach(runtime, host), SAS_PAIRING_OK);
    assert!(closed(second));
    assert_eq!(authority_status(runtime, authority), READY_10);

    // Any other constructor error breaks its invariant: fatal, and still one owner.
    let (third, _) = bound();
    let mut slot = third;
    OWNER_LOOP_FAULT.set(Some(|| OwnerLoopError::Poll(10_050)));
    assert_eq!(attach(runtime, host, &mut slot), SAS_PAIRING_FATAL);
    assert_eq!(slot, SAS_PAIRING_SOCKET_INVALID);
    assert!(closed(third));
    assert!(PROCESS.fatal.is_set());
    assert_eq!(has_network(&PROCESS, runtime, host), Some(false));
    assert_eq!(host_destroy(runtime, host), SAS_PAIRING_OK);
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
    assert_eq!(registration(scope), Some(Registration::Inactive));
}

#[cfg(windows)]
#[test]
fn an_owner_loop_setup_failure_closes_the_adopted_socket() {
    run_child("listener::child_listener_setup_failure");
}

/// P6-D-002 across listener churn: attach, detach, replacement, host destroy, and a new host
/// never change the budget, the START limiter, the guard, or the session.
#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by listener_churn_never_changes_process_session_accounting"]
fn child_listener_accounting() {
    if !is_child("listener::child_listener_accounting") {
        return;
    }
    let scope = b"p7-listener-accounting";
    let (_, runtime) = create();
    let (_, authority) = register(runtime, scope);
    let (_, _, accounting) = session(scope).unwrap();
    assert_eq!(with_authority(&PROCESS, runtime, authority, spend), Ok(9));
    let limiter = |authority: u64| {
        with_authority(&PROCESS, runtime, authority, |authority| {
            authority.executor().start_limiter_snapshot()
        })
    };
    let before = limiter(authority);
    let ready_9 = (SAS_PAIRING_OK, SAS_PAIRING_AUTHORITY_READY, 9);
    let churn = |authority: u64, expected: (i32, u32, u32)| {
        let (_, host) = host_create(runtime, authority);
        for _ in 0..2 {
            let (raw, _) = bound();
            let mut slot = raw;
            assert_eq!(attach(runtime, host, &mut slot), SAS_PAIRING_OK);
            assert_eq!(authority_status(runtime, authority), expected);
            assert_eq!(detach(runtime, host), SAS_PAIRING_OK);
            assert_eq!(authority_status(runtime, authority), expected);
        }
        let (raw, _) = bound();
        let mut slot = raw;
        assert_eq!(attach(runtime, host, &mut slot), SAS_PAIRING_OK);
        assert_eq!(host_destroy(runtime, host), SAS_PAIRING_OK);
        assert_eq!(authority_status(runtime, authority), expected);
        let (_, host) = host_create(runtime, authority);
        let (raw, _) = bound();
        let mut slot = raw;
        assert_eq!(attach(runtime, host, &mut slot), SAS_PAIRING_OK);
        assert_eq!(authority_status(runtime, authority), expected);
        host
    };
    let live = churn(authority, ready_9);
    assert_eq!(limiter(authority), before, "START limiter untouched");
    assert_eq!(session(scope), Some((Registration::Active, 9, accounting)));

    // An exposed ceremony holds the guard: listener churn neither waits for nor clears it.
    let (executor, mut ceremony) = with_authority(&PROCESS, runtime, authority, |authority| {
        let executor = authority.executor();
        let mut ceremony = executor.begin(Role::Initiator).unwrap();
        let token = authority.authorize(&mut ceremony).unwrap();
        assert_eq!(executor.reserve(&mut ceremony, Some(token)), Ok(8));
        (executor, ceremony)
    });
    let busy = (SAS_PAIRING_OK, SAS_PAIRING_AUTHORITY_BUSY, 0);
    churn(authority, busy);
    executor.terminate(&mut ceremony).unwrap();
    drop((executor, ceremony));
    let ready_8 = (SAS_PAIRING_OK, SAS_PAIRING_AUTHORITY_READY, 8);
    assert_eq!(authority_status(runtime, authority), ready_8);
    assert_eq!(detach(runtime, live), SAS_PAIRING_OK);

    // An exhausted authority stays exhausted through listener churn and re-registration.
    let spent = b"p7-listener-accounting-exhausted";
    let (_, exhausted_authority) = register(runtime, spent);
    for expected in (0..10).rev() {
        assert_eq!(
            with_authority(&PROCESS, runtime, exhausted_authority, spend),
            Ok(expected)
        );
    }
    let exhausted = (SAS_PAIRING_OK, SAS_PAIRING_AUTHORITY_EXHAUSTED, 0);
    churn(exhausted_authority, exhausted);
    assert_eq!(release(runtime, exhausted_authority), SAS_PAIRING_OK);
    let (_, exhausted_authority) = register(runtime, spent);
    churn(exhausted_authority, exhausted);
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
    assert_eq!(
        session(scope),
        Some((Registration::Inactive, 8, accounting))
    );
}

#[cfg(windows)]
#[test]
fn listener_churn_never_changes_process_session_accounting() {
    run_child("listener::child_listener_accounting");
}

// --- Concurrency (Windows) -------------------------------------------------------------------

#[cfg(windows)]
const ROUNDS: usize = 24;

/// Attach copies and validates its Bootstrap before it takes the runtime slot, so an unstaggered
/// race almost always admits the other call first. Raced rounds therefore delay one side by
/// 0-1 ms (the first side on even rounds, the second on odd ones).
#[cfg(windows)]
fn stagger(round: usize) -> [Duration; 2] {
    let delay = Duration::from_micros(200 * (round as u64 / 2 % 6));
    if round.is_multiple_of(2) {
        [delay, Duration::ZERO]
    } else {
        [Duration::ZERO, delay]
    }
}

#[cfg(windows)]
fn pause(delay: Duration) {
    let until = Instant::now() + delay;
    while Instant::now() < until {
        std::hint::spin_loop();
    }
}

/// Runs `first` and `second` for one round. Rounds 0 and 1 run them one after the other
/// (first then second, then second then first), so each admission order and its outcome is
/// checked whatever the scheduler does; every later round races them, staggered.
#[cfg(windows)]
fn contend<T: Send + 'static>(
    round: usize,
    first: impl Fn() -> T + Send + Sync + 'static,
    second: impl Fn() -> T + Send + Sync + 'static,
) -> [T; 2] {
    match round {
        0 => {
            let first = first();
            [first, second()]
        }
        1 => {
            let second = second();
            [first(), second]
        }
        _ => {
            let [early, late] = stagger(round);
            race_pair(
                round,
                move || {
                    pause(early);
                    first()
                },
                move || {
                    pause(late);
                    second()
                },
            )
        }
    }
}

/// Both admission orders occurred (rounds 0 and 1 force them; raced rounds add to the counts),
/// so both outcomes were checked.
#[cfg(windows)]
fn report_orders(first: &str, second: &str, orders: [usize; 2]) {
    println!(
        "{first} admitted first: {}, {second} admitted first: {}",
        orders[0], orders[1]
    );
    assert!(
        orders[0] > 0 && orders[1] > 0,
        "one admission order never occurred"
    );
}

/// One attach of a fresh socket racing `other`: `((attach status, slot after), other's status,
/// the socket)`.
#[cfg(windows)]
fn attach_race(
    round: usize,
    runtime: u64,
    host: u64,
    other: impl Fn() -> i32 + Send + Sync + 'static,
) -> ((i32, usize), i32, usize) {
    let (raw, _) = bound();
    let [attached, raced] = contend(
        round,
        move || {
            let mut slot = raw;
            (attach(runtime, host, &mut slot), slot)
        },
        move || (other(), 0),
    );
    (attached, raced.0, raw)
}

/// Exactly one owner holds the socket after an attach: on `OK` the slot is `INVALID` and the ABI
/// owns it (returns `true`); on `INVALID_HANDLE` the slot is unchanged and the socket still
/// listens, and the test, its owner, closes it (returns `false`).
#[cfg(windows)]
fn check_attach_outcome((status, slot): (i32, usize), raw: usize) -> bool {
    match status {
        SAS_PAIRING_OK => {
            assert_eq!(slot, SAS_PAIRING_SOCKET_INVALID);
            true
        }
        SAS_PAIRING_INVALID_HANDLE => {
            assert_eq!(slot, raw);
            still_the_callers(raw);
            false
        }
        other => panic!("unexpected attach outcome {other}"),
    }
}

/// Attach vs detach of the same host: both always succeed; exactly one listener (or none) is
/// left, and its socket closes with the host.
#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by attach_racing_detach_never_leaves_two_owners"]
fn child_attach_detach_race() {
    if !is_child("listener::child_attach_detach_race") {
        return;
    }
    let (_, runtime) = create();
    let (_, authority) = register(runtime, b"p7-listener-race-attach-detach");
    let mut orders = [0; 2];
    for round in 0..ROUNDS {
        let (_, host) = host_create(runtime, authority);
        let (attached, detached, raw) =
            attach_race(round, runtime, host, move || detach(runtime, host));
        assert_eq!(detached, SAS_PAIRING_OK);
        assert!(check_attach_outcome(attached, raw));
        // Detach admitted first leaves the new listener; attach first lets detach close it.
        match has_network(&PROCESS, runtime, host) {
            Some(true) => {
                orders[1] += 1;
                assert!(listening(raw));
            }
            Some(false) => {
                orders[0] += 1;
                assert!(closed(raw));
            }
            None => panic!("host vanished"),
        }
        assert_eq!(host_destroy(runtime, host), SAS_PAIRING_OK);
        assert!(closed(raw));
    }
    assert_eq!(authority_status(runtime, authority), READY_10);
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
    report_orders("attach", "detach", orders);
}

#[cfg(windows)]
#[test]
fn attach_racing_detach_never_leaves_two_owners() {
    run_child("listener::child_attach_detach_race");
}

/// Attach vs host destroy: attach first adopts (destroy then closes it); destroy first refuses
/// attach before adoption (the caller keeps the socket).
#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by attach_racing_host_destroy_has_one_owner"]
fn child_attach_host_destroy_race() {
    if !is_child("listener::child_attach_host_destroy_race") {
        return;
    }
    let (_, runtime) = create();
    let (_, authority) = register(runtime, b"p7-listener-race-attach-host");
    let mut orders = [0; 2];
    for round in 0..ROUNDS {
        let (_, host) = host_create(runtime, authority);
        let (attached, destroyed, raw) =
            attach_race(round, runtime, host, move || host_destroy(runtime, host));
        assert_eq!(destroyed, SAS_PAIRING_OK);
        if check_attach_outcome(attached, raw) {
            orders[0] += 1;
        } else {
            orders[1] += 1;
        }
        assert!(closed(raw));
        assert_eq!(detach(runtime, host), SAS_PAIRING_INVALID_HANDLE);
    }
    assert_eq!(authority_status(runtime, authority), READY_10);
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
    report_orders("attach", "host destroy", orders);
}

#[cfg(windows)]
#[test]
fn attach_racing_host_destroy_has_one_owner() {
    run_child("listener::child_attach_host_destroy_race");
}

/// Attach vs authority release: release always succeeds (never BUSY because of a host or its
/// loop); attach first adopts and release closes it, release first leaves the caller owner.
#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by attach_racing_authority_release_has_one_owner"]
fn child_attach_release_race() {
    if !is_child("listener::child_attach_release_race") {
        return;
    }
    let scope: &'static [u8] = b"p7-listener-race-attach-release";
    let (_, runtime) = create();
    let mut orders = [0; 2];
    for round in 0..ROUNDS {
        let (_, authority) = register(runtime, scope);
        let (_, host) = host_create(runtime, authority);
        let (attached, released, raw) =
            attach_race(round, runtime, host, move || release(runtime, authority));
        assert_eq!(released, SAS_PAIRING_OK);
        if check_attach_outcome(attached, raw) {
            orders[0] += 1;
        } else {
            orders[1] += 1;
        }
        assert!(closed(raw));
        assert_eq!(registration(scope), Some(Registration::Inactive));
    }
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
    report_orders("attach", "release", orders);
}

#[cfg(windows)]
#[test]
fn attach_racing_authority_release_has_one_owner() {
    run_child("listener::child_attach_release_race");
}

/// Attach vs runtime destroy: the same, for the whole runtime.
#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by attach_racing_runtime_destroy_has_one_owner"]
fn child_attach_runtime_destroy_race() {
    if !is_child("listener::child_attach_runtime_destroy_race") {
        return;
    }
    let scope: &'static [u8] = b"p7-listener-race-attach-runtime";
    let mut orders = [0; 2];
    for round in 0..ROUNDS {
        let (_, runtime) = create();
        let (_, authority) = register(runtime, scope);
        let (_, host) = host_create(runtime, authority);
        let (attached, destroyed, raw) =
            attach_race(round, runtime, host, move || destroy(runtime));
        assert_eq!(destroyed, SAS_PAIRING_OK);
        if check_attach_outcome(attached, raw) {
            orders[0] += 1;
        } else {
            orders[1] += 1;
        }
        assert!(closed(raw));
        assert_eq!(registration(scope), Some(Registration::Inactive));
    }
    report_orders("attach", "runtime destroy", orders);
}

#[cfg(windows)]
#[test]
fn attach_racing_runtime_destroy_has_one_owner() {
    run_child("listener::child_attach_runtime_destroy_race");
}

/// Detach racing a parent destruction: exactly one path ends the network context and closes the
/// socket; a detach admitted second names no host.
#[cfg(windows)]
fn detach_race(
    round: usize,
    runtime: u64,
    host: u64,
    parent: impl Fn() -> i32 + Send + Sync + 'static,
) -> usize {
    let (raw, _) = bound();
    let mut slot = raw;
    assert_eq!(attach(runtime, host, &mut slot), SAS_PAIRING_OK);
    let [detached, destroyed] = contend(round, move || detach(runtime, host), parent);
    assert_eq!(destroyed, SAS_PAIRING_OK);
    assert!(closed(raw), "closed by exactly one path");
    match detached {
        SAS_PAIRING_OK => 0,
        SAS_PAIRING_INVALID_HANDLE => 1,
        other => panic!("unexpected detach outcome {other}"),
    }
}

#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by detach_racing_host_destroy_closes_once"]
fn child_detach_host_destroy_race() {
    if !is_child("listener::child_detach_host_destroy_race") {
        return;
    }
    let (_, runtime) = create();
    let (_, authority) = register(runtime, b"p7-listener-race-detach-host");
    let mut orders = [0; 2];
    for round in 0..ROUNDS {
        let (_, host) = host_create(runtime, authority);
        orders[detach_race(round, runtime, host, move || host_destroy(runtime, host))] += 1;
        assert_eq!(host_destroy(runtime, host), SAS_PAIRING_INVALID_HANDLE);
    }
    assert_eq!(authority_status(runtime, authority), READY_10);
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
    report_orders("detach", "host destroy", orders);
}

#[cfg(windows)]
#[test]
fn detach_racing_host_destroy_closes_once() {
    run_child("listener::child_detach_host_destroy_race");
}

#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by detach_racing_authority_release_closes_once"]
fn child_detach_release_race() {
    if !is_child("listener::child_detach_release_race") {
        return;
    }
    let scope: &'static [u8] = b"p7-listener-race-detach-release";
    let (_, runtime) = create();
    let mut orders = [0; 2];
    for round in 0..ROUNDS {
        let (_, authority) = register(runtime, scope);
        let (_, host) = host_create(runtime, authority);
        orders[detach_race(round, runtime, host, move || release(runtime, authority))] += 1;
        assert_eq!(host_destroy(runtime, host), SAS_PAIRING_INVALID_HANDLE);
        assert_eq!(registration(scope), Some(Registration::Inactive));
    }
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
    report_orders("detach", "release", orders);
}

#[cfg(windows)]
#[test]
fn detach_racing_authority_release_closes_once() {
    run_child("listener::child_detach_release_race");
}

#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by detach_racing_runtime_destroy_closes_once"]
fn child_detach_runtime_destroy_race() {
    if !is_child("listener::child_detach_runtime_destroy_race") {
        return;
    }
    let scope: &'static [u8] = b"p7-listener-race-detach-runtime";
    let mut orders = [0; 2];
    for round in 0..ROUNDS {
        let (_, runtime) = create();
        let (_, authority) = register(runtime, scope);
        let (_, host) = host_create(runtime, authority);
        orders[detach_race(round, runtime, host, move || destroy(runtime))] += 1;
        assert_eq!(registration(scope), Some(Registration::Inactive));
    }
    report_orders("detach", "runtime destroy", orders);
}

#[cfg(windows)]
#[test]
fn detach_racing_runtime_destroy_closes_once() {
    run_child("listener::child_detach_runtime_destroy_race");
}
