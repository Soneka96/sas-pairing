//! P7.5 bounded network drive, connection and run references, drive events, and results
//! (P7-D-008, P7-D-009, P7-D-010).
//!
//! Argument validation, the result-access paths, the handle preflight, and the request-ID bound
//! are tested everywhere; off Windows a child shows that driving and closing fail closed. The
//! rest needs a Windows owner loop: exhaustive translation tables, conversion of synthetic owner
//! steps built from real core references, real loopback flows on test-local states (including
//! complete ceremonies that surface a real `PairingResult` in either role), and children that use
//! the real exports and the process state (fatal after a result, a contained panic in the middle
//! of a drive, and races with every teardown path). Local ceremony actions are test-side calls of
//! the reviewed owner loop (no ceremony export exists before P7.6).

use std::ptr;
#[cfg(windows)]
use std::{
    collections::BTreeMap,
    io::{ErrorKind, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    num::NonZeroU64,
    os::windows::io::IntoRawSocket,
    thread,
    time::{Duration, Instant},
};

use super::super::{
    network::{DRIVE_HANDLE_BOUND, Event, MAX_DRIVE_EVENTS, MAX_REQUEST_ID_LEN},
    result::{ResultInfo, SAS_PAIRING_RESULT_FIELD_REQUEST_ID},
    runtime::HandleCounter,
    sas_pairing_host_drive, sas_pairing_host_recheck_after_resume, sas_pairing_result_copy,
    sas_pairing_result_destroy, sas_pairing_result_info,
    status::*,
};
#[cfg(windows)]
use super::{
    super::{
        BootstrapInput, BootstrapView, BytesView, PROCESS, dispatch,
        hosting::{DRIVE_FAULT, NETWORK_STEPS},
        listener::ListenerSlot,
        network::*,
        panic_boundary::contain,
        result::*,
        runtime::{AbiState, Admission},
        sas_pairing_connection_close, sas_pairing_host_attach_windows_listener,
        sas_pairing_host_detach_listener,
    },
    authority::{race_pair, session},
    create, destroy, host_create, host_destroy, is_child, register, release, run_child,
};
#[cfg(not(windows))]
use super::{create, destroy, is_child, run_child};
use crate::protocol::{Bootstrap, Message, decode};
#[cfg(windows)]
use crate::{
    Error, TrustedAuthority,
    ceremony::{CeremonyError, PairingResult, PeerApproval},
    crypto,
    deadline::{Deadline, system_clock},
    host::{CeremonyDeadline, HostError, HostEvent},
    protocol::{CancelReason, CodecError, PROFILE_ID},
    router::{RouteError, RunRef},
    transport::{AcceptPermit, FIRST_FRAME_DEADLINE, TransportError},
    windows_owner_loop::{
        ConnectionEnd, ConnectionRef, ListenerFailure, OwnerEvent, OwnerLoopError, OwnerStep,
        WindowsOwnerLoop,
    },
    windows_tcp::{
        Acted, Refused, TcpError, TcpEvent, TcpStep, TimeoutCancel, WindowsTcpConnection,
        tests::{
            Node, OneId, acted, inbound, initiator_bootstrap, received, responder_bootstrap, sent,
            start, start_with, until, written,
        },
    },
};

type DriveExport = unsafe extern "C" fn(u64, u64, *mut Event, usize, *mut usize, *mut i32) -> i32;
const DRIVE_EXPORTS: [DriveExport; 2] = [
    sas_pairing_host_drive,
    sas_pairing_host_recheck_after_resume,
];

/// A record no conversion produces, to show which caller records were written.
const UNTOUCHED: Event = Event {
    kind: 0xDEAD,
    ..Event::ZERO
};

// --- Platform-neutral -------------------------------------------------------------------------

/// Every structural error of the drive exports is decided before any write, and the outputs
/// are never touched by a rejected call; then the platform, then the capacity.
#[test]
fn drive_arguments_are_checked_before_anything_else() {
    for drive in DRIVE_EXPORTS {
        let call = |events: *mut Event, capacity: usize, count: *mut usize, failure: *mut i32| {
            // SAFETY: every pointer is either live, aligned, and exclusive for the call, or
            // rejected by the export before any access.
            unsafe { drive(0, 0, events, capacity, count, failure) }
        };
        let mut events = [UNTOUCHED; MAX_DRIVE_EVENTS];
        let base = events.as_mut_ptr();
        let (mut count, mut failure) = (usize::MAX, i32::MAX);
        let (count_ptr, failure_ptr) = (ptr::from_mut(&mut count), ptr::from_mut(&mut failure));
        let mut words = [usize::MAX; 3];
        let misaligned_count = words
            .as_mut_ptr()
            .cast::<u8>()
            .wrapping_add(1)
            .cast::<usize>();
        let mut ints = [i32::MAX; 3];
        let misaligned_failure = ints.as_mut_ptr().cast::<u8>().wrapping_add(1).cast::<i32>();
        // `out_failure` inside `out_count`, and either output inside the event array.
        let mut pair = [u64::MAX; 2];
        let shared_count = pair.as_mut_ptr().cast::<usize>();
        let shared_failure = pair.as_mut_ptr().cast::<i32>().wrapping_add(1);
        let inner_count = base.cast::<u8>().wrapping_add(128).cast::<usize>();
        let inner_failure = base.cast::<u8>().wrapping_add(256 + 60).cast::<i32>();
        let misaligned_events = base.cast::<u8>().wrapping_add(4).cast::<Event>();
        let high = ptr::without_provenance_mut::<Event>((usize::MAX - 1023) & !7);
        for (events, capacity, count, failure) in [
            (base, MAX_DRIVE_EVENTS, ptr::null_mut(), failure_ptr),
            (base, MAX_DRIVE_EVENTS, count_ptr, ptr::null_mut()),
            (base, MAX_DRIVE_EVENTS, misaligned_count, failure_ptr),
            (base, MAX_DRIVE_EVENTS, count_ptr, misaligned_failure),
            (base, MAX_DRIVE_EVENTS, shared_count, shared_failure),
            (ptr::null_mut(), MAX_DRIVE_EVENTS, count_ptr, failure_ptr),
            (ptr::null_mut(), 1, count_ptr, failure_ptr),
            (misaligned_events, 1, count_ptr, failure_ptr),
            (base, usize::MAX, count_ptr, failure_ptr),
            (base, isize::MAX as usize / 128 + 1, count_ptr, failure_ptr),
            (high, MAX_DRIVE_EVENTS, count_ptr, failure_ptr),
            (base, MAX_DRIVE_EVENTS, inner_count, failure_ptr),
            (base, MAX_DRIVE_EVENTS, count_ptr, inner_failure),
        ] {
            assert_eq!(
                call(events, capacity, count, failure),
                SAS_PAIRING_INVALID_ARGUMENT
            );
        }
        assert_eq!((count, failure), (usize::MAX, i32::MAX), "nothing written");
        assert_eq!(words, [usize::MAX; 3]);
        assert_eq!(ints, [i32::MAX; 3]);
        assert_eq!(pair, [u64::MAX; 2]);
        assert!(events.iter().all(|event| *event == UNTOUCHED));

        // The size query and too-small arrays: the required capacity, nothing driven.
        let base = events.as_mut_ptr();
        for (events, capacity) in [
            (ptr::null_mut(), 0),
            (base, 0),
            (base, 1),
            (base, MAX_DRIVE_EVENTS - 1),
        ] {
            let status = call(events, capacity, &mut count, &mut failure);
            if cfg!(windows) {
                assert_eq!(
                    (status, count, failure),
                    (
                        SAS_PAIRING_BUFFER_TOO_SMALL,
                        MAX_DRIVE_EVENTS,
                        SAS_PAIRING_OK
                    )
                );
            } else {
                assert_eq!(
                    (status, count, failure),
                    (SAS_PAIRING_UNSUPPORTED_PLATFORM, 0, SAS_PAIRING_OK)
                );
            }
        }
        // Full capacity: the handles (or the platform) refuse it; nothing is written.
        let status = call(base, MAX_DRIVE_EVENTS, &mut count, &mut failure);
        let expected = if cfg!(windows) {
            SAS_PAIRING_INVALID_HANDLE
        } else {
            SAS_PAIRING_UNSUPPORTED_PLATFORM
        };
        assert_eq!((status, count, failure), (expected, 0, SAS_PAIRING_OK));
        assert!(events.iter().all(|event| *event == UNTOUCHED));
    }
}

/// Result access validates its memory and field before anything else and never reads the
/// caller's buffer; result handles that name nothing are `INVALID_HANDLE`.
#[test]
fn result_access_arguments_are_checked_before_anything_else() {
    let mut info = ResultInfo {
        peer_role: 77,
        ..ResultInfo::ZERO
    };
    // SAFETY: a null pointer is rejected before any access.
    let status = unsafe { sas_pairing_result_info(0, 1, ptr::null_mut()) };
    assert_eq!(status, SAS_PAIRING_INVALID_ARGUMENT);
    let mut raw = [0xA5_u32; 20];
    let misaligned = raw
        .as_mut_ptr()
        .cast::<u8>()
        .wrapping_add(1)
        .cast::<ResultInfo>();
    // SAFETY: a misaligned pointer is rejected before any access.
    let status = unsafe { sas_pairing_result_info(0, 1, misaligned) };
    assert_eq!(status, SAS_PAIRING_INVALID_ARGUMENT);
    assert!(raw.iter().all(|word| *word == 0xA5), "nothing written");
    // SAFETY: `info` is live, aligned, and exclusive for the call.
    let status = unsafe { sas_pairing_result_info(0, 1, &mut info) };
    assert_eq!(status, SAS_PAIRING_INVALID_HANDLE);
    assert_eq!(info, ResultInfo::ZERO, "zeroed on entry");

    const FILL: u64 = 0x5A5A_5A5A_5A5A_5A5A;
    let mut buffer = [FILL; 8];
    let mut required = usize::MAX;
    let copy = |field: u32, buffer: *mut u8, capacity: usize, required: *mut usize| {
        // SAFETY: every pointer is live, aligned, and exclusive for the call, or rejected
        // before any access.
        unsafe { sas_pairing_result_copy(0, 1, field, buffer, capacity, required) }
    };
    let base = buffer.as_mut_ptr().cast::<u8>();
    let mut words = [usize::MAX; 3];
    let misaligned_required = words
        .as_mut_ptr()
        .cast::<u8>()
        .wrapping_add(1)
        .cast::<usize>();
    let inner_required = base.wrapping_add(8).cast::<usize>();
    let field = SAS_PAIRING_RESULT_FIELD_REQUEST_ID;
    for (field, buffer, capacity, required) in [
        (field, base, 64, ptr::null_mut()),
        (field, base, 64, misaligned_required),
        (field, ptr::null_mut(), 4, ptr::from_mut(&mut required)),
        (field, base, usize::MAX, ptr::from_mut(&mut required)),
        (
            field,
            ptr::without_provenance_mut(usize::MAX - 3),
            8,
            ptr::from_mut(&mut required),
        ),
        (field, base, 64, inner_required),
        (0, base, 64, ptr::from_mut(&mut required)),
        (5, base, 64, ptr::from_mut(&mut required)),
        (u32::MAX, base, 64, ptr::from_mut(&mut required)),
    ] {
        assert_eq!(
            copy(field, buffer, capacity, required),
            SAS_PAIRING_INVALID_ARGUMENT
        );
    }
    assert_eq!(required, usize::MAX, "nothing written");
    assert_eq!(words, [usize::MAX; 3]);
    assert!(buffer.iter().all(|word| *word == FILL));
    // Well-formed: `*out_required` is set to 0, then the handle names nothing.
    for (buffer, capacity) in [(ptr::null_mut(), 0), (base, 64)] {
        required = usize::MAX;
        assert_eq!(
            copy(field, buffer, capacity, &mut required),
            SAS_PAIRING_INVALID_HANDLE
        );
        assert_eq!(required, 0);
    }
    assert!(buffer.iter().all(|word| *word == FILL));
    for result in [0, 1, u64::MAX] {
        assert_eq!(
            sas_pairing_result_destroy(0, result),
            SAS_PAIRING_INVALID_HANDLE
        );
    }
}

/// The drive preflight issues nothing: it only asks whether the next `count` values exist.
#[test]
fn the_handle_preflight_is_non_consuming_and_exact() {
    assert_eq!(DRIVE_HANDLE_BOUND, 17);
    assert_eq!(MAX_DRIVE_EVENTS, 17);
    let counter = HandleCounter::starting_at(u64::MAX - 16);
    for _ in 0..3 {
        assert!(counter.can_allocate(17), "exactly 17 values are left");
        assert!(!counter.can_allocate(18));
        assert!(counter.can_allocate(0));
    }
    assert_eq!(
        counter.allocate().map(std::num::NonZeroU64::get),
        Some(u64::MAX - 16)
    );
    assert!(counter.can_allocate(16) && !counter.can_allocate(17));
    for _ in 0..16 {
        assert!(counter.allocate().is_some());
    }
    assert!(!counter.can_allocate(1) && counter.can_allocate(0));
    assert_eq!(counter.allocate(), None);
    assert!(HandleCounter::new().can_allocate(u64::MAX));
}

/// The event's request-ID array is exactly the codec's frozen bound: 64 bytes encode and decode,
/// 65 are refused.
#[test]
fn the_request_id_array_is_the_codec_bound() {
    assert_eq!(MAX_REQUEST_ID_LEN, 64);
    let bootstrap = Bootstrap::new(
        b"p7-net-app".to_vec(),
        b"x25519".to_vec(),
        vec![7; 32],
        vec![],
    )
    .unwrap();
    let start = |len: usize| {
        Message::Start {
            request_id: vec![7; len],
            bootstrap: bootstrap.clone(),
        }
        .encode()
    };
    assert!(decode(&start(MAX_REQUEST_ID_LEN).unwrap()).is_ok());
    assert!(start(MAX_REQUEST_ID_LEN + 1).is_err());
}

// --- Unsupported platforms --------------------------------------------------------------------

#[cfg(not(windows))]
#[test]
#[ignore = "subprocess child; run by driving_fails_closed_on_unsupported_platforms"]
fn child_unsupported_drive() {
    use super::super::sas_pairing_connection_close;
    if !is_child("network::child_unsupported_drive") {
        return;
    }
    let (status, runtime) = create();
    assert_eq!(status, SAS_PAIRING_OK);
    for drive in DRIVE_EXPORTS {
        let mut events = [UNTOUCHED; MAX_DRIVE_EVENTS];
        let (mut count, mut failure) = (usize::MAX, i32::MAX);
        for host in [runtime + 1, 0] {
            // SAFETY: live, aligned, exclusive outputs and array for the call.
            let status = unsafe {
                drive(
                    runtime,
                    host,
                    events.as_mut_ptr(),
                    MAX_DRIVE_EVENTS,
                    &mut count,
                    &mut failure,
                )
            };
            assert_eq!(
                (status, count, failure),
                (SAS_PAIRING_UNSUPPORTED_PLATFORM, 0, SAS_PAIRING_OK)
            );
        }
        assert!(events.iter().all(|event| *event == UNTOUCHED));
    }
    for (host, connection) in [(runtime + 1, runtime + 2), (0, 0)] {
        assert_eq!(
            sas_pairing_connection_close(runtime, host, connection),
            SAS_PAIRING_UNSUPPORTED_PLATFORM
        );
    }
    // Result access is ABI-owned data and works on every platform: no result exists here.
    let mut info = ResultInfo::ZERO;
    // SAFETY: `info` is live, aligned, and exclusive for the call.
    let status = unsafe { sas_pairing_result_info(runtime, runtime + 1, &mut info) };
    assert_eq!(status, SAS_PAIRING_INVALID_HANDLE);
    assert_eq!(
        sas_pairing_result_destroy(runtime, runtime + 1),
        SAS_PAIRING_INVALID_HANDLE
    );
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
}

#[cfg(not(windows))]
#[test]
fn driving_fails_closed_on_unsupported_platforms() {
    run_child("network::child_unsupported_drive");
}

// --- Translation tables (Windows) -------------------------------------------------------------

/// Every core outcome a drive can report has exactly one frozen event value, and diagnostic
/// detail collapses only where the contract says so. (`PeerCancellation` and `Timeout` cannot
/// be built outside the core: the peer CANCEL flow below covers the first, and the second is
/// matched explicitly in `ceremony_reason`.)
#[cfg(windows)]
#[test]
fn every_core_outcome_maps_to_one_frozen_event_value() {
    use HostEvent as H;
    for (event, value) in [
        (H::StartAccepted, SAS_PAIRING_PROTOCOL_EVENT_START_ACCEPTED),
        (
            H::StartDuplicate,
            SAS_PAIRING_PROTOCOL_EVENT_START_DUPLICATE,
        ),
        (H::Accept, SAS_PAIRING_PROTOCOL_EVENT_ACCEPT),
        (H::InitiatorKey, SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_KEY),
        (H::ResponderKey, SAS_PAIRING_PROTOCOL_EVENT_RESPONDER_KEY),
        (
            H::BootstrapMac(PeerApproval::Authenticated),
            SAS_PAIRING_PROTOCOL_EVENT_BOOTSTRAP_MAC_AUTHENTICATED,
        ),
        (
            H::BootstrapMac(PeerApproval::AlreadyAuthenticated),
            SAS_PAIRING_PROTOCOL_EVENT_BOOTSTRAP_MAC_DUPLICATE,
        ),
        (
            H::InitiatorFinish,
            SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH,
        ),
        (
            H::InitiatorFinishDuplicate,
            SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH_DUPLICATE,
        ),
        (
            H::ResponderFinishAck,
            SAS_PAIRING_PROTOCOL_EVENT_RESPONDER_FINISH_ACK,
        ),
        (
            H::InitiatorFinishAck,
            SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH_ACK,
        ),
    ] {
        assert_eq!(
            protocol_event(event),
            (value, SAS_PAIRING_CANCEL_REASON_NONE),
            "{event:?}"
        );
    }
    for (reason, value) in [
        (
            CancelReason::UserRejection,
            SAS_PAIRING_CANCEL_REASON_USER_REJECTION,
        ),
        (
            CancelReason::UserCancellation,
            SAS_PAIRING_CANCEL_REASON_USER_CANCELLATION,
        ),
        (CancelReason::Timeout, SAS_PAIRING_CANCEL_REASON_TIMEOUT),
        (
            CancelReason::LocalPolicyFailure,
            SAS_PAIRING_CANCEL_REASON_LOCAL_POLICY_FAILURE,
        ),
    ] {
        assert_eq!(cancel_reason(reason), value);
    }
    for (kind, value) in [
        (
            CeremonyDeadline::TimedOut(Deadline::Absolute),
            SAS_PAIRING_DEADLINE_ABSOLUTE_TIMEOUT,
        ),
        (
            CeremonyDeadline::TimedOut(Deadline::Inactivity),
            SAS_PAIRING_DEADLINE_INACTIVITY_TIMEOUT,
        ),
        (
            CeremonyDeadline::PendingExpired,
            SAS_PAIRING_DEADLINE_PENDING_EXPIRED,
        ),
        (
            CeremonyDeadline::ClockUnavailable,
            SAS_PAIRING_DEADLINE_CLOCK_UNAVAILABLE,
        ),
    ] {
        assert_eq!(deadline_kind(kind), value);
    }
    for (cancel, value) in [
        (TimeoutCancel::NotBuilt, SAS_PAIRING_CANCEL_STATE_NOT_BUILT),
        (TimeoutCancel::Pending, SAS_PAIRING_CANCEL_STATE_PENDING),
        (TimeoutCancel::Dropped, SAS_PAIRING_CANCEL_STATE_DROPPED),
    ] {
        assert_eq!(cancel_state(cancel), value);
    }

    use TransportError as T;
    let transports = [
        (
            T::ResourceLimited,
            SAS_PAIRING_EVENT_REASON_RESOURCE_LIMITED,
        ),
        (T::InvalidFrame, SAS_PAIRING_EVENT_REASON_INVALID_FRAME),
        (T::FrameTooLarge, SAS_PAIRING_EVENT_REASON_INVALID_FRAME),
        (
            T::WholeFrameTimeout,
            SAS_PAIRING_EVENT_REASON_TRANSPORT_DEADLINE,
        ),
        (T::IdleTimeout, SAS_PAIRING_EVENT_REASON_TRANSPORT_DEADLINE),
        (
            T::FirstFrameTimeout,
            SAS_PAIRING_EVENT_REASON_TRANSPORT_DEADLINE,
        ),
        (
            T::QuiescentTimeout,
            SAS_PAIRING_EVENT_REASON_TRANSPORT_DEADLINE,
        ),
        (
            T::RetainedOutputTimeout,
            SAS_PAIRING_EVENT_REASON_TRANSPORT_DEADLINE,
        ),
        (
            T::RetainedOutputIdleTimeout,
            SAS_PAIRING_EVENT_REASON_TRANSPORT_DEADLINE,
        ),
        (
            T::ClockUnavailable,
            SAS_PAIRING_EVENT_REASON_CLOCK_UNAVAILABLE,
        ),
        (T::Closed, SAS_PAIRING_EVENT_REASON_ALREADY_CLOSED),
        (
            T::OwnershipUncertain,
            SAS_PAIRING_EVENT_REASON_OWNERSHIP_UNCERTAIN,
        ),
    ];
    for (error, value) in transports {
        assert_eq!(transport_reason(error), value, "{error:?}");
        assert_eq!(host_reason(&HostError::Transport(error)), value);
        assert_eq!(
            tcp_reason(&TcpError::Host(HostError::Transport(error))),
            value
        );
    }
    assert_eq!(
        host_reason(&HostError::Unroutable(CodecError::BadMagic)),
        SAS_PAIRING_EVENT_REASON_INVALID_FRAME
    );
    for (error, value) in [
        (TcpError::Closed, SAS_PAIRING_EVENT_REASON_ALREADY_CLOSED),
        (TcpError::PeerClosed, SAS_PAIRING_EVENT_REASON_PEER_CLOSED),
        (
            TcpError::Io(ErrorKind::ConnectionReset),
            SAS_PAIRING_EVENT_REASON_SOCKET_IO,
        ),
        (
            TcpError::AbandonedPartialFrame,
            SAS_PAIRING_EVENT_REASON_ABANDONED_PARTIAL_FRAME,
        ),
    ] {
        assert_eq!(tcp_reason(&error), value);
        assert_eq!(end_reason(&ConnectionEnd::Adapter(error)), value);
    }
    assert_eq!(
        end_reason(&ConnectionEnd::Readiness(8)),
        SAS_PAIRING_EVENT_REASON_READINESS_FAILURE
    );
    assert_eq!(
        listener_reason(ListenerFailure::Io(ErrorKind::Other)),
        SAS_PAIRING_EVENT_REASON_LISTENER_IO
    );
    assert_eq!(
        listener_reason(ListenerFailure::Readiness(1)),
        SAS_PAIRING_EVENT_REASON_LISTENER_READINESS
    );

    // Routing and ceremony detail collapses into the operational reasons.
    let refused = SAS_PAIRING_EVENT_REASON_ROUTE_REFUSED;
    for (error, value) in [
        (
            RouteError::UnknownSession,
            SAS_PAIRING_EVENT_REASON_OTHER_HOST_FAILURE,
        ),
        (RouteError::UnknownRoute, refused),
        (
            RouteError::SessionProtocolFailure,
            SAS_PAIRING_EVENT_REASON_SESSION_PROTOCOL_FAILURE,
        ),
    ] {
        assert_eq!(route_reason(&error), value);
        assert_eq!(host_reason(&HostError::Routing(error)), value);
    }
    let owner = [
        (Error::InvalidScope, refused),
        (Error::AlreadyRegistered, refused),
        (Error::OwnershipUnavailable, refused),
        (Error::UnsupportedPlatform, refused),
        (
            Error::OwnershipUncertain,
            SAS_PAIRING_EVENT_REASON_OWNERSHIP_UNCERTAIN,
        ),
        (Error::Busy, refused),
        (Error::MissingAuthorization, refused),
        (Error::StaleAuthorization, refused),
        (Error::Exhausted, refused),
        (Error::Terminated, refused),
        (
            Error::ResourceLimited,
            SAS_PAIRING_EVENT_REASON_RESOURCE_LIMITED,
        ),
    ];
    for (error, value) in owner {
        let error = CeremonyError::Owner(error);
        assert_eq!(ceremony_reason(&error), value);
        assert_eq!(route_reason(&RouteError::Ceremony(error)), value);
    }
    use CeremonyError as C;
    for error in [
        C::Codec(CodecError::Truncated),
        C::Crypto(crypto::Error::MacMismatch),
        C::InvalidState,
        C::NoLiveSas,
        C::CeremonyIdentityMismatch,
        C::NotLocallyApproved,
        C::UnexpectedSenderRole,
        C::InvalidRequestId,
        C::RequestIdGenerationFailed,
        C::RequestIdMismatch,
        C::SharedContextMismatch,
        C::ExpectedPeerMismatch,
        C::ApprovalsNotAuthenticated,
        C::NotInitiator,
        C::TranscriptMismatch,
        C::Completed,
        C::NoPendingFinalAck,
        C::FinalAckMismatch,
        C::PendingExpired,
    ] {
        assert_eq!(ceremony_reason(&error), refused, "{error:?}");
    }
    assert_eq!(
        ceremony_reason(&C::ClockUnavailable),
        SAS_PAIRING_EVENT_REASON_CLOCK_UNAVAILABLE
    );

    // The owner loop's own failures: only the two it reports in a step map; the rest are fatal.
    assert_eq!(
        owner_failure_status(&OwnerLoopError::OwnershipUncertain),
        Some(SAS_PAIRING_OWNERSHIP_UNCERTAIN)
    );
    assert_eq!(
        owner_failure_status(&OwnerLoopError::Poll(10_038)),
        Some(SAS_PAIRING_NETWORK_POLL_FAILED)
    );
    for failure in [
        OwnerLoopError::Closed,
        OwnerLoopError::UnknownConnection,
        OwnerLoopError::ListenerIo(ErrorKind::Other),
        OwnerLoopError::Connection(TcpError::PeerClosed),
    ] {
        assert_eq!(owner_failure_status(&failure), None);
    }
}

// --- Conversion of synthetic steps over real core references (Windows) ------------------------

/// `n` real `ConnectionRef`s of a real owner loop over `node`'s router (the loop and its
/// connections are dropped afterwards: the references stay distinct values, never reissued).
#[cfg(windows)]
fn connection_refs(node: &Node, n: usize) -> Vec<ConnectionRef> {
    let (listener, address) = loopback();
    let mut owner =
        WindowsOwnerLoop::from_bound_listener(listener, &node.router, responder_bootstrap(), None)
            .unwrap();
    let clients: Vec<TcpStream> = (0..n)
        .map(|_| TcpStream::connect(address).unwrap())
        .collect();
    let mut refs = Vec::new();
    while refs.len() < n {
        let step = owner.drive_once().unwrap();
        for event in step.events {
            match event {
                OwnerEvent::Accepted(connection) => refs.push(connection),
                other => panic!("unexpected {other:?}"),
            }
        }
    }
    drop(owner);
    drop(clients);
    refs
}

/// Real exact runs on `node`'s router: one local Initiator run per ID on a fresh session each.
#[cfg(windows)]
fn run_refs(node: &Node, ids: &[[u8; 16]]) -> Vec<RunRef> {
    ids.iter()
        .map(|id| {
            let session = node.router.open_session().unwrap();
            let (run, _) = node
                .router
                .start_initiator_run(
                    system_clock(),
                    &mut OneId(Some(*id)),
                    session,
                    initiator_bootstrap(),
                    None,
                )
                .unwrap();
            node.router.close_session(session).unwrap();
            run
        })
        .collect()
}

/// A test-local conversion target: its own handle counter and fatal state, one host's bindings,
/// and the runtime's result store.
#[cfg(windows)]
struct Converter {
    state: AbiState,
    bindings: Bindings,
    results: BTreeMap<std::num::NonZeroU64, PairingResult>,
}

#[cfg(windows)]
impl Converter {
    fn new() -> Self {
        Self {
            state: AbiState::new(),
            bindings: Bindings::new(),
            results: BTreeMap::new(),
        }
    }

    fn step(
        &mut self,
        events: Vec<OwnerEvent>,
        failure: Option<OwnerLoopError>,
    ) -> Result<DriveOutput, i32> {
        convert(
            &self.state,
            &mut self.bindings,
            &mut self.results,
            Ok(OwnerStep { events, failure }),
        )
    }

    /// One converted step that must succeed with no owner failure.
    fn events(&mut self, events: Vec<OwnerEvent>) -> Vec<Event> {
        let output = self.step(events, None).expect("converted");
        assert_eq!(output.failure, SAS_PAIRING_OK);
        for event in output.events() {
            assert_canonical(event);
        }
        output.events().to_vec()
    }

    /// The next handle the counter would issue (by issuing it: tests only).
    fn next_handle(&self) -> u64 {
        self.state.allocate_handle().unwrap().get()
    }
}

#[cfg(windows)]
fn inbound_step(request_id: &[u8], run: Option<RunRef>, event: HostEvent) -> TcpStep {
    TcpStep {
        event: Some(TcpEvent::Inbound {
            request_id: request_id.to_vec(),
            run,
            event,
        }),
        result: None,
        write_pending: false,
    }
}

#[cfg(windows)]
fn step_of(event: TcpEvent, write_pending: bool) -> TcpStep {
    TcpStep {
        event: Some(event),
        result: None,
        write_pending,
    }
}

/// Fields that do not apply to an event's kind are zero, the reserved word and the unused tail
/// of the request ID are zero, and a terminal result never comes with a run handle.
#[cfg(windows)]
fn assert_canonical(event: &Event) {
    assert_eq!(event.reserved, 0);
    let len = event.request_id_len as usize;
    assert!(len <= MAX_REQUEST_ID_LEN);
    assert!(event.request_id[len..].iter().all(|byte| *byte == 0));
    assert!(event.run == 0 || event.result == 0, "{event:?}");
    let step_fields = (
        event.step_kind,
        event.protocol_event,
        event.deadline_kind,
        event.cancel_state,
        event.cancel_reason,
        event.flags,
        event.run,
        event.result,
        event.request_id_len,
    );
    let quiet = (0, 0, 0, 0, 0, 0, 0, 0, 0);
    match event.kind {
        SAS_PAIRING_EVENT_CONNECTION_ACCEPTED => {
            assert_ne!(event.connection, 0);
            assert_eq!((step_fields, event.reason), (quiet, 0), "{event:?}");
        }
        SAS_PAIRING_EVENT_ACCEPT_REFUSED | SAS_PAIRING_EVENT_LISTENER_DISABLED => {
            assert_eq!((event.connection, step_fields), (0, quiet), "{event:?}");
            assert_ne!(event.reason, 0);
        }
        SAS_PAIRING_EVENT_CONNECTION_CLOSED => {
            assert_ne!(event.connection, 0);
            assert_ne!(event.reason, 0);
            assert_eq!(step_fields, quiet, "{event:?}");
        }
        SAS_PAIRING_EVENT_CONNECTION_STEP => {
            assert_ne!(event.connection, 0);
            let inbound = event.step_kind == SAS_PAIRING_STEP_INBOUND;
            assert_eq!(event.protocol_event != 0, inbound, "{event:?}");
            assert_eq!(
                event.cancel_reason != 0,
                event.protocol_event == SAS_PAIRING_PROTOCOL_EVENT_PEER_CANCEL,
                "{event:?}"
            );
            let deadline = event.step_kind == SAS_PAIRING_STEP_DEADLINE;
            assert_eq!(event.deadline_kind != 0, deadline, "{event:?}");
            assert_eq!(event.cancel_state != 0, deadline, "{event:?}");
            let reasoned = matches!(
                event.step_kind,
                SAS_PAIRING_STEP_REFUSED | SAS_PAIRING_STEP_UNCONFIRMED
            );
            assert_eq!(event.reason != 0, reasoned, "{event:?}");
            assert!(event.run == 0 || inbound, "{event:?}");
            assert_eq!(
                event.flags
                    & !(SAS_PAIRING_EVENT_FLAG_WRITE_PENDING
                        | SAS_PAIRING_EVENT_FLAG_RUN_UNTRACKED),
                0
            );
        }
        other => panic!("unknown event kind {other}"),
    }
}

/// One connection keeps one handle across steps; its CLOSED event names that handle, which is
/// invalid afterwards; a later connection gets a new one. Accept refusals and listener failures
/// name no connection. The write-pending flag and request IDs are copied exactly.
#[cfg(windows)]
#[test]
fn a_connection_keeps_one_handle_until_its_closed_event() {
    let node = Node::new("p7-net-conv-connection");
    let [first, second] = connection_refs(&node, 2)[..] else {
        unreachable!()
    };
    let mut conv = Converter::new();
    let accepted = conv.events(vec![OwnerEvent::Accepted(first)]);
    let handle = accepted[0].connection;
    assert_eq!(accepted[0].kind, SAS_PAIRING_EVENT_CONNECTION_ACCEPTED);
    let id = [0x31; 64];
    let steps = conv.events(vec![
        OwnerEvent::Step(first, inbound_step(&id, None, HostEvent::StartDuplicate)),
        OwnerEvent::AcceptRefused(TcpError::Host(HostError::Transport(
            TransportError::ResourceLimited,
        ))),
        OwnerEvent::ListenerDisabled(ListenerFailure::Readiness(1)),
    ]);
    assert_eq!(steps[0].connection, handle);
    assert_eq!(steps[0].request_id(), id);
    assert_eq!(steps[0].request_id_len, 64);
    assert_eq!(
        (steps[1].kind, steps[1].reason),
        (
            SAS_PAIRING_EVENT_ACCEPT_REFUSED,
            SAS_PAIRING_EVENT_REASON_RESOURCE_LIMITED
        )
    );
    assert_eq!(steps[2].kind, SAS_PAIRING_EVENT_LISTENER_DISABLED);
    let written = conv.events(vec![OwnerEvent::Step(
        first,
        step_of(TcpEvent::Written, true),
    )]);
    assert_eq!(
        (
            written[0].connection,
            written[0].step_kind,
            written[0].flags
        ),
        (
            handle,
            SAS_PAIRING_STEP_WRITTEN,
            SAS_PAIRING_EVENT_FLAG_WRITE_PENDING
        )
    );
    let closed = conv.events(vec![OwnerEvent::Closed(
        first,
        ConnectionEnd::Adapter(TcpError::PeerClosed),
    )]);
    assert_eq!(
        (closed[0].kind, closed[0].connection, closed[0].reason),
        (
            SAS_PAIRING_EVENT_CONNECTION_CLOSED,
            handle,
            SAS_PAIRING_EVENT_REASON_PEER_CLOSED
        )
    );
    assert_eq!(
        conv.bindings.connection_for_test(handle),
        None,
        "invalid afterwards"
    );
    assert_eq!(conv.bindings.counts_for_test(), (0, 0));
    let again = conv.events(vec![OwnerEvent::Accepted(second)]);
    assert!(again[0].connection > handle, "never reused");
    // A step for a connection that is not bound breaks the owner loop's invariant: fatal.
    assert_eq!(
        conv.step(
            vec![OwnerEvent::Step(first, step_of(TcpEvent::Written, false))],
            None
        )
        .err(),
        Some(SAS_PAIRING_FATAL)
    );
    assert!(conv.state.fatal.is_set());
    node.release();
}

/// The same exact run keeps one run handle; a new run under a reused request ID gets a new
/// handle and the old reference is retired (the core routes one run per key); an event that
/// shows a run under a key ended retires it; nothing else is guessed.
#[cfg(windows)]
#[test]
fn an_exact_run_keeps_one_handle_and_a_reused_request_id_gets_a_new_one() {
    let node = Node::new("p7-net-conv-run");
    let [connection] = connection_refs(&node, 1)[..] else {
        unreachable!()
    };
    let (x, y) = ([0x41; 16], [0x42; 16]);
    let runs = run_refs(&node, &[x, x, y]);
    let (r1, r2, other) = (runs[0].clone(), runs[1].clone(), runs[2].clone());
    assert_eq!(r1.request_id(), r2.request_id());
    assert_ne!(r1, r2, "distinct instances under one request ID");
    let mut conv = Converter::new();
    let handle = conv.events(vec![OwnerEvent::Accepted(connection)])[0].connection;
    let on = |event: TcpStep| vec![OwnerEvent::Step(connection, event)];

    let first = conv.events(on(inbound_step(
        &x,
        Some(r1.clone()),
        HostEvent::StartAccepted,
    )))[0];
    assert_ne!(first.run, 0);
    for event in [
        HostEvent::InitiatorKey,
        HostEvent::BootstrapMac(PeerApproval::Authenticated),
    ] {
        let again = conv.events(on(inbound_step(&x, Some(r1.clone()), event)))[0];
        assert_eq!(again.run, first.run, "same exact run, same handle");
    }
    let unrelated = conv.events(on(inbound_step(&y, Some(other.clone()), HostEvent::Accept)))[0];
    assert!(unrelated.run > first.run);
    assert_eq!(conv.bindings.runs_of_for_test(handle), 2);

    // A replacement run under the reused request ID: a new handle; the old one is retired.
    let replaced = conv.events(on(inbound_step(
        &x,
        Some(r2.clone()),
        HostEvent::StartAccepted,
    )))[0];
    assert!(replaced.run > unrelated.run, "never the old handle");
    assert_eq!(conv.bindings.run_for_test(first.run), None);
    assert_eq!(
        conv.bindings.run_for_test(replaced.run),
        Some((handle, r2.clone()))
    );
    assert_eq!(
        conv.bindings.run_for_test(unrelated.run),
        Some((handle, other.clone()))
    );

    // A duplicate START without a run claims nothing; a deadline without a request ID cannot
    // name its run (the reference may stay stale); one with a request ID retires it.
    conv.events(on(inbound_step(&x, None, HostEvent::StartDuplicate)));
    conv.events(on(step_of(
        TcpEvent::Deadline {
            request_id: None,
            kind: CeremonyDeadline::PendingExpired,
            cancel: TimeoutCancel::NotBuilt,
        },
        false,
    )));
    conv.events(on(step_of(
        TcpEvent::Refused(RouteError::UnknownRoute),
        false,
    )));
    assert_eq!(conv.bindings.runs_of_for_test(handle), 2);
    let expired = conv.events(on(step_of(
        TcpEvent::Deadline {
            request_id: Some(x.to_vec()),
            kind: CeremonyDeadline::TimedOut(Deadline::Inactivity),
            cancel: TimeoutCancel::Pending,
        },
        true,
    )))[0];
    assert_eq!(
        (expired.deadline_kind, expired.cancel_state, expired.run),
        (
            SAS_PAIRING_DEADLINE_INACTIVITY_TIMEOUT,
            SAS_PAIRING_CANCEL_STATE_PENDING,
            0
        )
    );
    assert_eq!(expired.request_id(), x);
    assert_eq!(conv.bindings.run_for_test(replaced.run), None, "retired");

    // A frame whose run is no longer live afterwards (here a peer CANCEL-like ending) retires
    // the run under its key and reports no run.
    let ended = conv.events(on(inbound_step(&y, None, HostEvent::InitiatorFinishAck)))[0];
    assert_eq!(ended.run, 0);
    assert_eq!(conv.bindings.runs_of_for_test(handle), 0);

    // Closing the connection removes every run parented to it.
    let late = conv.events(on(inbound_step(&y, Some(other.clone()), HostEvent::Accept)))[0];
    assert!(
        late.run > replaced.run,
        "a retired exact run is never given its old handle"
    );
    conv.events(vec![OwnerEvent::Closed(
        connection,
        ConnectionEnd::Readiness(8),
    )]);
    assert_eq!(conv.bindings.run_for_test(late.run), None);
    assert_eq!(conv.bindings.counts_for_test(), (0, 0));
    node.release();
}

/// At most `MAX_RUNS_PER_CONNECTION` run references per connection: a new exact run beyond it
/// gets no handle and the RUN_UNTRACKED flag; nothing is evicted and existing handles stay.
#[cfg(windows)]
#[test]
fn a_full_connection_reports_new_runs_untracked_and_evicts_nothing() {
    let node = Node::new("p7-net-conv-cap");
    let [connection] = connection_refs(&node, 1)[..] else {
        unreachable!()
    };
    let ids: Vec<[u8; 16]> = (0..=MAX_RUNS_PER_CONNECTION as u8)
        .map(|n| [n; 16])
        .collect();
    let runs = run_refs(&node, &ids);
    let mut conv = Converter::new();
    let handle = conv.events(vec![OwnerEvent::Accepted(connection)])[0].connection;
    let mut handles = Vec::new();
    for (id, run) in ids.iter().zip(&runs).take(MAX_RUNS_PER_CONNECTION) {
        let event = conv.events(vec![OwnerEvent::Step(
            connection,
            inbound_step(id, Some(run.clone()), HostEvent::StartAccepted),
        )])[0];
        assert_ne!(event.run, 0);
        assert_eq!(event.flags & SAS_PAIRING_EVENT_FLAG_RUN_UNTRACKED, 0);
        handles.push(event.run);
    }
    let before = conv.next_handle();
    let overflow = conv.events(vec![OwnerEvent::Step(
        connection,
        inbound_step(
            &ids[MAX_RUNS_PER_CONNECTION],
            Some(runs[MAX_RUNS_PER_CONNECTION].clone()),
            HostEvent::StartAccepted,
        ),
    )])[0];
    assert_eq!(overflow.run, 0);
    assert_eq!(overflow.flags, SAS_PAIRING_EVENT_FLAG_RUN_UNTRACKED);
    assert_eq!(
        conv.next_handle(),
        before + 1,
        "no handle was issued for it"
    );
    assert_eq!(
        conv.bindings.runs_of_for_test(handle),
        MAX_RUNS_PER_CONNECTION
    );
    for (index, run) in runs.iter().take(MAX_RUNS_PER_CONNECTION).enumerate() {
        let again = conv.events(vec![OwnerEvent::Step(
            connection,
            inbound_step(&ids[index], Some(run.clone()), HostEvent::InitiatorKey),
        )])[0];
        assert_eq!(again.run, handles[index], "nothing was evicted");
    }
    node.release();
}

/// Events produced before the owner loop failed closed in the same call are all converted and
/// returned with the loop's failure; every reference of that loop ends. A failure the loop
/// never reports, an already closed loop, and malformed steps are handled as specified.
#[cfg(windows)]
#[test]
fn an_owner_failure_never_discards_the_events_before_it() {
    let node = Node::new("p7-net-conv-failure");
    let refs = connection_refs(&node, 3);
    for (failure, status, fatal) in [
        (
            OwnerLoopError::Poll(10_038),
            SAS_PAIRING_NETWORK_POLL_FAILED,
            false,
        ),
        (
            OwnerLoopError::OwnershipUncertain,
            SAS_PAIRING_OWNERSHIP_UNCERTAIN,
            false,
        ),
        (
            OwnerLoopError::ListenerIo(ErrorKind::Other),
            SAS_PAIRING_FATAL,
            true,
        ),
    ] {
        let mut conv = Converter::new();
        conv.events(vec![OwnerEvent::Accepted(refs[0])]);
        let output = conv
            .step(
                vec![
                    OwnerEvent::Step(refs[0], step_of(TcpEvent::Written, false)),
                    OwnerEvent::Accepted(refs[1]),
                ],
                Some(failure),
            )
            .expect("converted");
        assert_eq!(output.count, 2, "earlier events kept");
        assert_eq!(output.events()[0].step_kind, SAS_PAIRING_STEP_WRITTEN);
        assert_eq!(
            output.events()[1].kind,
            SAS_PAIRING_EVENT_CONNECTION_ACCEPTED
        );
        assert_eq!(output.failure, status);
        assert_eq!(
            conv.bindings.counts_for_test(),
            (0, 0),
            "every reference ended"
        );
        assert_eq!(conv.state.fatal.is_set(), fatal);
    }

    // An owner loop that had already failed closed: nothing converted, nothing fatal.
    let mut conv = Converter::new();
    conv.events(vec![OwnerEvent::Accepted(refs[0])]);
    let closed = convert(
        &conv.state,
        &mut conv.bindings,
        &mut conv.results,
        Err(OwnerLoopError::Closed),
    )
    .unwrap();
    assert_eq!(
        (closed.count, closed.failure),
        (0, SAS_PAIRING_OWNER_LOOP_CLOSED)
    );
    assert_eq!(conv.bindings.counts_for_test(), (0, 0));
    assert!(!conv.state.fatal.is_set());
    // A refusal `drive_once` never returns is fatal.
    let broken = convert(
        &conv.state,
        &mut conv.bindings,
        &mut conv.results,
        Err(OwnerLoopError::UnknownConnection),
    )
    .unwrap();
    assert_eq!((broken.count, broken.failure), (0, SAS_PAIRING_FATAL));
    assert!(conv.state.fatal.is_set());

    // Malformed steps (impossible for the owner loop) are fatal and convert nothing.
    let too_many: Vec<OwnerEvent> = (0..=MAX_DRIVE_EVENTS)
        .map(|_| OwnerEvent::ListenerDisabled(ListenerFailure::Readiness(1)))
        .collect();
    let twice = vec![
        OwnerEvent::Accepted(refs[2]),
        OwnerEvent::Step(refs[2], step_of(TcpEvent::Written, false)),
    ];
    let long_id = vec![OwnerEvent::Accepted(refs[2])];
    for events in [too_many, twice] {
        let mut conv = Converter::new();
        let before = conv.next_handle();
        assert_eq!(conv.step(events, None).err(), Some(SAS_PAIRING_FATAL));
        assert!(conv.state.fatal.is_set());
        assert_eq!(conv.next_handle(), before + 1, "no handle issued");
    }
    let mut conv = Converter::new();
    conv.events(long_id);
    let oversized = vec![OwnerEvent::Step(
        refs[2],
        inbound_step(&[1; MAX_REQUEST_ID_LEN + 1], None, HostEvent::Accept),
    )];
    assert_eq!(conv.step(oversized, None).err(), Some(SAS_PAIRING_FATAL));
    assert!(conv.state.fatal.is_set());
    node.release();
}

/// Each event issues at most one handle, so a drive never needs more than
/// `DRIVE_HANDLE_BOUND` (17): an accepted connection one, a step at most one, every other event
/// none, and repeated events of known runs none.
#[cfg(windows)]
#[test]
fn every_event_issues_at_most_one_handle() {
    let node = Node::new("p7-net-conv-bound");
    let refs = connection_refs(&node, 4);
    let runs = run_refs(&node, &[[1; 16], [2; 16], [3; 16]]);
    let mut conv = Converter::new();
    let before = conv.next_handle();
    let events = conv.events(vec![
        OwnerEvent::Accepted(refs[0]),
        OwnerEvent::Accepted(refs[1]),
        OwnerEvent::Accepted(refs[2]),
    ]);
    assert_eq!(events.len(), 3);
    let issued = conv.next_handle() - before - 1;
    assert_eq!(issued, 3);
    let before = conv.next_handle();
    conv.events(vec![
        OwnerEvent::Step(
            refs[0],
            inbound_step(&[1; 16], Some(runs[0].clone()), HostEvent::StartAccepted),
        ),
        OwnerEvent::Step(
            refs[1],
            inbound_step(&[2; 16], Some(runs[1].clone()), HostEvent::StartAccepted),
        ),
        OwnerEvent::Step(refs[2], step_of(TcpEvent::Discarded, false)),
        OwnerEvent::Accepted(refs[3]),
        OwnerEvent::AcceptRefused(TcpError::Io(ErrorKind::Other)),
    ]);
    assert_eq!(
        conv.next_handle() - before - 1,
        3,
        "two runs and one connection"
    );
    let before = conv.next_handle();
    conv.events(vec![
        OwnerEvent::Step(
            refs[0],
            inbound_step(&[1; 16], Some(runs[0].clone()), HostEvent::InitiatorKey),
        ),
        OwnerEvent::Step(
            refs[1],
            inbound_step(&[2; 16], Some(runs[1].clone()), HostEvent::InitiatorKey),
        ),
        OwnerEvent::Closed(refs[2], ConnectionEnd::Readiness(8)),
    ]);
    assert_eq!(
        conv.next_handle() - before - 1,
        0,
        "known runs issue nothing"
    );
    node.release();
}

// --- Real loopback harness (Windows) ----------------------------------------------------------

/// Test plumbing only: a loopback listener on an OS-assigned port, bound by the test.
#[cfg(windows)]
fn loopback() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    (listener, address)
}

#[cfg(windows)]
fn bytes(value: &[u8]) -> BytesView {
    BytesView {
        data: value.as_ptr(),
        len: value.len(),
    }
}

/// A view over `bootstrap`'s own fields (borrowed for as long as `bootstrap` lives).
#[cfg(windows)]
fn view_of(bootstrap: &Bootstrap) -> BootstrapView {
    BootstrapView {
        application_identity: bytes(bootstrap.application_identity()),
        key_algorithm: bytes(bootstrap.key_algorithm()),
        public_key: bytes(bootstrap.public_key()),
        shared_context: bytes(bootstrap.shared_context()),
    }
}

/// `outcome` of an owner-loop local action that must apply.
#[cfg(windows)]
fn applied(outcome: Result<Result<Acted, Refused>, OwnerLoopError>) -> Acted {
    outcome.expect("hosting context").expect("action applied")
}

/// One ABI host with an attached loopback listener (the host is the Responder for STARTs),
/// driven through the real exports and the process state (`exports`), or through a test-local
/// state's own methods.
#[cfg(windows)]
struct Harness<'s> {
    state: &'s AbiState,
    exports: bool,
    runtime: u64,
    authority: u64,
    host: u64,
    address: SocketAddr,
}

#[cfg(windows)]
impl<'s> Harness<'s> {
    /// A new runtime (local) or the given one (exports), an authority for `scope`, a host, and
    /// an attached listener.
    fn new(state: &'s AbiState, exports: bool, runtime: u64, scope: &[u8]) -> Self {
        let authority = if exports {
            let (status, authority) = register(runtime, scope);
            assert_eq!(status, SAS_PAIRING_OK);
            authority
        } else {
            state.register_authority(runtime, scope).unwrap().get()
        };
        let mut harness = Self {
            state,
            exports,
            runtime,
            authority,
            host: 0,
            address: "127.0.0.1:0".parse().unwrap(),
        };
        harness.host = harness.new_host();
        harness.address = harness.attach();
        harness
    }

    fn local(state: &'s AbiState, scope: &[u8]) -> Self {
        let runtime = state.create().unwrap().get();
        Self::new(state, false, runtime, scope)
    }

    fn new_host(&self) -> u64 {
        if self.exports {
            let (status, host) = host_create(self.runtime, self.authority);
            assert_eq!(status, SAS_PAIRING_OK);
            host
        } else {
            self.state
                .create_host(self.runtime, self.authority)
                .unwrap()
                .get()
        }
    }

    /// Binds a new loopback listener (the caller's job) and attaches it to the host.
    fn attach(&self) -> SocketAddr {
        let (listener, address) = loopback();
        let mut slot = listener.into_raw_socket() as usize;
        let socket = slot;
        let local = responder_bootstrap();
        let view = view_of(&local);
        let status = if self.exports {
            // SAFETY: `slot` holds a bound listening socket this test owns; `view` borrows
            // `local`, alive for the call.
            unsafe {
                sas_pairing_host_attach_windows_listener(
                    self.runtime,
                    self.host,
                    &mut slot,
                    &view,
                    ptr::null(),
                )
            }
        } else {
            // SAFETY: as above; the slot and the views are live for the call.
            unsafe {
                let slot = ListenerSlot::new(&mut slot, socket);
                let local = BootstrapInput::new(view);
                self.state
                    .attach_listener(self.runtime, self.host, slot, &local, None)
            }
        };
        assert_eq!(status, SAS_PAIRING_OK);
        address
    }

    fn detach(&self) -> i32 {
        if self.exports {
            sas_pairing_host_detach_listener(self.runtime, self.host)
        } else {
            self.state.detach_listener(self.runtime, self.host)
        }
    }

    /// One raw drive or recheck: `(status, written records, *out_count, *out_failure)`.
    fn call(&self, mode: DriveMode, capacity: usize) -> (i32, Vec<Event>, usize, i32) {
        if self.exports {
            let export = match mode {
                DriveMode::Drive => DRIVE_EXPORTS[0],
                DriveMode::Resume => DRIVE_EXPORTS[1],
            };
            let mut events = vec![UNTOUCHED; capacity];
            let (mut count, mut failure) = (usize::MAX, i32::MAX);
            let array = if capacity == 0 {
                ptr::null_mut()
            } else {
                events.as_mut_ptr()
            };
            // SAFETY: `events` holds `capacity` live records; both outputs are live, aligned,
            // and distinct, all exclusive for the call.
            let status = unsafe {
                export(
                    self.runtime,
                    self.host,
                    array,
                    capacity,
                    &mut count,
                    &mut failure,
                )
            };
            let written = events
                .iter()
                .take_while(|event| **event != UNTOUCHED)
                .count();
            if status == SAS_PAIRING_OK {
                assert_eq!(written, count, "exactly the counted records were written");
            } else {
                assert_eq!(written, 0);
            }
            events.truncate(written);
            (status, events, count, failure)
        } else {
            match self
                .state
                .drive_host(self.runtime, self.host, mode, capacity)
            {
                Ok(output) => (
                    SAS_PAIRING_OK,
                    output.events().to_vec(),
                    output.count,
                    output.failure,
                ),
                Err(SAS_PAIRING_BUFFER_TOO_SMALL) => (
                    SAS_PAIRING_BUFFER_TOO_SMALL,
                    Vec::new(),
                    MAX_DRIVE_EVENTS,
                    SAS_PAIRING_OK,
                ),
                Err(status) => (status, Vec::new(), 0, SAS_PAIRING_OK),
            }
        }
    }

    /// One successful drive or recheck without an owner failure; every event is canonical.
    fn events(&self, mode: DriveMode) -> Vec<Event> {
        let (status, events, _, failure) = self.call(mode, MAX_DRIVE_EVENTS);
        assert_eq!((status, failure), (SAS_PAIRING_OK, SAS_PAIRING_OK));
        events.iter().for_each(assert_canonical);
        events
    }

    /// Drives until one event appears; exactly one must.
    fn next_event(&self) -> Event {
        let give_up = Instant::now() + Duration::from_secs(10);
        loop {
            let events = self.events(DriveMode::Drive);
            match events.as_slice() {
                [] => assert!(Instant::now() < give_up, "no event in 10 s"),
                [event] => return *event,
                more => panic!("one event expected: {more:?}"),
            }
        }
    }

    fn close(&self, connection: u64) -> i32 {
        if self.exports {
            sas_pairing_connection_close(self.runtime, self.host, connection)
        } else {
            self.state
                .close_connection(self.runtime, self.host, connection)
        }
    }

    /// Reads the host context in place (test-side, under the runtime slot like an export).
    fn with_host<T>(&self, op: impl FnOnce(&mut super::super::hosting::HostContext) -> T) -> T {
        self.state
            .with_runtime(self.runtime, Admission::Cleanup, |live| {
                let host = live
                    .hosts
                    .get_mut(&NonZeroU64::new(self.host).unwrap())
                    .expect("live host");
                Ok(op(host))
            })
            .unwrap()
    }

    fn connection_ref(&self, handle: u64) -> ConnectionRef {
        self.with_host(|host| host.bindings().connection_for_test(handle))
            .expect("a live connection handle")
    }

    fn run_ref(&self, handle: u64) -> Option<RunRef> {
        self.with_host(|host| host.bindings().run_for_test(handle))
            .map(|(_, run)| run)
    }

    fn counts(&self) -> (usize, usize) {
        self.with_host(|host| host.bindings().counts_for_test())
    }

    /// A trusted local action on the owner loop (test-side: no ceremony export before P7.6).
    fn with_loop<T>(
        &self,
        op: impl FnOnce(&mut WindowsOwnerLoop<'static>, &TrustedAuthority) -> T,
    ) -> T {
        self.state
            .with_runtime(self.runtime, Admission::Cleanup, |live| {
                let authority = &live.authorities[&NonZeroU64::new(self.authority).unwrap()];
                let host = live
                    .hosts
                    .get_mut(&NonZeroU64::new(self.host).unwrap())
                    .expect("live host");
                Ok(op(host.owner_loop_for_test().expect("attached"), authority))
            })
            .unwrap()
    }

    fn live_connections(&self) -> usize {
        self.with_loop(|owner, _| owner.live_connections())
    }

    fn result_info(&self, result: u64) -> Result<ResultInfo, i32> {
        if self.exports {
            let mut info = ResultInfo {
                peer_role: 99,
                ..ResultInfo::ZERO
            };
            // SAFETY: `info` is live, aligned, and exclusive for the call.
            match unsafe { sas_pairing_result_info(self.runtime, result, &mut info) } {
                SAS_PAIRING_OK => Ok(info),
                status => {
                    assert_eq!(info, ResultInfo::ZERO);
                    Err(status)
                }
            }
        } else {
            self.state.result_info(self.runtime, result)
        }
    }

    /// One field copy with `capacity` bytes: `(status, copied bytes, *out_required)`.
    fn copy(&self, result: u64, field: u32, capacity: usize) -> (i32, Vec<u8>, usize) {
        if self.exports {
            let mut buffer = vec![0xEE; capacity];
            let mut required = usize::MAX;
            let array = if capacity == 0 {
                ptr::null_mut()
            } else {
                buffer.as_mut_ptr()
            };
            // SAFETY: `buffer` holds `capacity` live bytes and `required` is live and aligned,
            // both exclusive for the call.
            let status = unsafe {
                sas_pairing_result_copy(self.runtime, result, field, array, capacity, &mut required)
            };
            if status == SAS_PAIRING_OK {
                assert!(
                    buffer[required..].iter().all(|byte| *byte == 0xEE),
                    "no NUL, no more"
                );
                buffer.truncate(required);
            } else {
                assert!(buffer.iter().all(|byte| *byte == 0xEE), "nothing copied");
                buffer.clear();
            }
            (status, buffer, required)
        } else {
            let field = ResultField::from_raw(field).expect("known field");
            match self
                .state
                .with_result_field(self.runtime, result, field, <[u8]>::to_vec)
            {
                Ok(bytes) if bytes.len() <= capacity => {
                    (SAS_PAIRING_OK, bytes.clone(), bytes.len())
                }
                Ok(bytes) => (SAS_PAIRING_BUFFER_TOO_SMALL, Vec::new(), bytes.len()),
                Err(status) => (status, Vec::new(), 0),
            }
        }
    }

    fn destroy_result(&self, result: u64) -> i32 {
        if self.exports {
            sas_pairing_result_destroy(self.runtime, result)
        } else {
            self.state.destroy_result(self.runtime, result)
        }
    }

    /// The exact core result the runtime stores under `result` (test-side data read).
    fn stored(&self, result: u64) -> PairingResult {
        self.state
            .with_runtime(self.runtime, Admission::Data, |live| {
                Ok(live.results[&NonZeroU64::new(result).unwrap()].clone())
            })
            .unwrap()
    }
}

#[cfg(windows)]
fn is_step(event: &Event, step_kind: u32, protocol_event: u32) -> bool {
    event.kind == SAS_PAIRING_EVENT_CONNECTION_STEP
        && event.step_kind == step_kind
        && event.protocol_event == protocol_event
}

/// Every foreign-facing field of `result` equals the stored core `PairingResult` byte for byte,
/// and copies obey the buffer contract (exact length, never truncated or terminated).
#[cfg(windows)]
fn assert_result_matches_core(harness: &Harness<'_>, result: u64) -> PairingResult {
    let core = harness.stored(result);
    let info = harness.result_info(result).expect("readable");
    assert_eq!(&info.ceremony_identity, core.ceremony_identity());
    let role = match core.peer_role() {
        crate::Role::Initiator => SAS_PAIRING_ROLE_INITIATOR,
        crate::Role::Responder => SAS_PAIRING_ROLE_RESPONDER,
    };
    assert_eq!(info.peer_role, role);
    assert_eq!(info.profile_version, u32::from(core.profile_version()));
    for (field, bytes, len) in [
        (
            SAS_PAIRING_RESULT_FIELD_REQUEST_ID,
            core.request_id(),
            info.request_id_len,
        ),
        (
            SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_PEER_BOOTSTRAP,
            core.authenticated_peer_bootstrap(),
            info.peer_bootstrap_len,
        ),
        (
            SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_SHARED_CONTEXT,
            core.authenticated_shared_context(),
            info.shared_context_len,
        ),
        (
            SAS_PAIRING_RESULT_FIELD_PROFILE_IDENTIFIER,
            core.profile_identifier(),
            info.profile_identifier_len,
        ),
    ] {
        assert_eq!(len as usize, bytes.len());
        assert_eq!(
            harness.copy(result, field, bytes.len()),
            (SAS_PAIRING_OK, bytes.to_vec(), bytes.len())
        );
        assert_eq!(
            harness.copy(result, field, bytes.len() + 7),
            (SAS_PAIRING_OK, bytes.to_vec(), bytes.len())
        );
        if !bytes.is_empty() {
            assert_eq!(
                harness.copy(result, field, bytes.len() - 1),
                (SAS_PAIRING_BUFFER_TOO_SMALL, Vec::new(), bytes.len())
            );
            assert_eq!(
                harness.copy(result, field, 0),
                (SAS_PAIRING_BUFFER_TOO_SMALL, Vec::new(), bytes.len())
            );
        }
    }
    assert_eq!(core.profile_identifier(), PROFILE_ID);
    assert_eq!(core.profile_version(), 1);
    core
}

/// A complete ceremony with the ABI host as the RESPONDER: the peer is a direct adapter of
/// another authority acting as the Initiator over a loopback client. Returns
/// `(connection handle, run handle seen during the ceremony, result handle, request ID,
/// ceremony identity)`. The peer connection is returned live.
#[cfg(windows)]
fn responder_ceremony<'n>(
    harness: &Harness<'_>,
    peer: &'n Node,
) -> (u64, u64, u64, Vec<u8>, [u8; 32], WindowsTcpConnection<'n>) {
    let client = TcpStream::connect(harness.address).unwrap();
    let accepted = harness.next_event();
    assert_eq!(accepted.kind, SAS_PAIRING_EVENT_CONNECTION_ACCEPTED);
    let connection = accepted.connection;
    let permit = AcceptPermit::begin(&peer.router).unwrap();
    let mut theirs =
        WindowsTcpConnection::from_accepted(client, permit, responder_bootstrap(), None).unwrap();
    let initiator = acted(theirs.start_initiator(initiator_bootstrap(), None))
        .run
        .unwrap();
    let id = initiator.request_id().to_vec();
    assert_eq!(sent(&mut theirs), written());

    let started = harness.next_event();
    assert!(is_step(
        &started,
        SAS_PAIRING_STEP_INBOUND,
        SAS_PAIRING_PROTOCOL_EVENT_START_ACCEPTED
    ));
    assert_eq!(started.connection, connection);
    assert_eq!(started.request_id(), id.as_slice());
    assert_eq!(started.flags, SAS_PAIRING_EVENT_FLAG_WRITE_PENDING);
    let run = started.run;
    assert_ne!(run, 0);
    let wrote = |harness: &Harness<'_>| {
        let event = harness.next_event();
        assert!(is_step(&event, SAS_PAIRING_STEP_WRITTEN, 0), "{event:?}");
        assert_eq!(
            (event.connection, event.run, event.flags),
            (connection, 0, 0)
        );
    };
    wrote(harness);
    assert_eq!(inbound(received(&mut theirs)).0, HostEvent::Accept);
    acted(theirs.authorize_exposure(&initiator, &peer.trusted));
    acted(theirs.expose_key(&initiator));
    assert_eq!(sent(&mut theirs), written());

    let key = harness.next_event();
    assert!(is_step(
        &key,
        SAS_PAIRING_STEP_INBOUND,
        SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_KEY
    ));
    assert_eq!(
        (key.connection, key.run),
        (connection, run),
        "one handle per exact run"
    );
    let (conn, ours) = (
        harness.connection_ref(connection),
        harness.run_ref(run).unwrap(),
    );
    harness.with_loop(|owner, authority| {
        applied(owner.authorize_exposure(conn, &ours, authority));
        applied(owner.expose_key(conn, &ours));
    });
    wrote(harness);
    assert_eq!(inbound(received(&mut theirs)).0, HostEvent::ResponderKey);
    let shown = theirs.presentation(&initiator).unwrap().unwrap().unwrap();
    let identity = *shown.ceremony_identity();
    let ours_shown = harness.with_loop(|owner, _| owner.presentation(conn, &ours));
    assert_eq!(ours_shown, Ok(Ok(Some(shown))));
    acted(theirs.approve_sas(&initiator, &identity));
    acted(theirs.emit_bootstrap_mac(&initiator));
    assert_eq!(sent(&mut theirs), written());

    let mac = harness.next_event();
    assert!(is_step(
        &mac,
        SAS_PAIRING_STEP_INBOUND,
        SAS_PAIRING_PROTOCOL_EVENT_BOOTSTRAP_MAC_AUTHENTICATED
    ));
    assert_eq!(mac.run, run);
    harness.with_loop(|owner, _| {
        applied(owner.approve_sas(conn, &ours, &identity));
        applied(owner.emit_bootstrap_mac(conn, &ours));
    });
    wrote(harness);
    assert_eq!(
        inbound(received(&mut theirs)).0,
        HostEvent::BootstrapMac(PeerApproval::Authenticated)
    );
    acted(theirs.emit_initiator_finish(&initiator));
    assert_eq!(sent(&mut theirs), written());

    let finish = harness.next_event();
    assert!(is_step(
        &finish,
        SAS_PAIRING_STEP_INBOUND,
        SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH
    ));
    assert_eq!((finish.run, finish.result), (run, 0), "no result yet");
    assert_eq!(finish.flags, SAS_PAIRING_EVENT_FLAG_WRITE_PENDING);
    wrote(harness);
    let step = received(&mut theirs);
    assert!(step.write_pending);
    assert_eq!(inbound(step).0, HostEvent::ResponderFinishAck);
    let confirmed = until(|| {
        let step = theirs.on_writable().unwrap();
        step.event.is_some().then_some(step)
    });
    assert_eq!(confirmed.event, Some(TcpEvent::Confirmed));
    assert!(
        confirmed.result.is_some(),
        "the peer Initiator's own result"
    );

    let done = harness.next_event();
    assert!(is_step(
        &done,
        SAS_PAIRING_STEP_INBOUND,
        SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH_ACK
    ));
    assert_eq!(done.run, 0, "terminal: no run handle");
    assert_ne!(done.result, 0);
    assert_eq!(done.request_id(), id.as_slice());
    assert_eq!(harness.run_ref(run), None, "the run reference was retired");
    (connection, run, done.result, id, identity, theirs)
}

/// The same ceremony with the ABI host as the INITIATOR (its START is a test-side local action).
/// Returns at the drive that confirmed the final ACK, before the peer has read it:
/// `(connection, run, result, request ID, identity, peer connection)`.
#[cfg(windows)]
fn initiator_ceremony<'n>(
    harness: &Harness<'_>,
    peer: &'n Node,
) -> (u64, u64, u64, Vec<u8>, [u8; 32], WindowsTcpConnection<'n>) {
    let client = TcpStream::connect(harness.address).unwrap();
    let connection = harness.next_event().connection;
    let permit = AcceptPermit::begin(&peer.router).unwrap();
    let mut theirs =
        WindowsTcpConnection::from_accepted(client, permit, responder_bootstrap(), None).unwrap();
    let conn = harness.connection_ref(connection);
    let ours = harness.with_loop(|owner, _| {
        applied(owner.start_initiator(conn, initiator_bootstrap(), None))
            .run
            .unwrap()
    });
    let id = ours.request_id().to_vec();
    let wrote = |harness: &Harness<'_>| {
        let event = harness.next_event();
        assert!(is_step(&event, SAS_PAIRING_STEP_WRITTEN, 0), "{event:?}");
    };
    wrote(harness);
    let (event, responder) = inbound(received(&mut theirs));
    assert_eq!(event, HostEvent::StartAccepted);
    let responder = responder.unwrap();
    assert_eq!(sent(&mut theirs), written());
    let accept = harness.next_event();
    assert!(is_step(
        &accept,
        SAS_PAIRING_STEP_INBOUND,
        SAS_PAIRING_PROTOCOL_EVENT_ACCEPT
    ));
    let run = accept.run;
    assert_eq!(
        harness.run_ref(run),
        Some(ours.clone()),
        "the exact local run"
    );
    harness.with_loop(|owner, authority| {
        applied(owner.authorize_exposure(conn, &ours, authority));
        applied(owner.expose_key(conn, &ours));
    });
    wrote(harness);
    assert_eq!(inbound(received(&mut theirs)).0, HostEvent::InitiatorKey);
    acted(theirs.authorize_exposure(&responder, &peer.trusted));
    acted(theirs.expose_key(&responder));
    assert_eq!(sent(&mut theirs), written());
    let key = harness.next_event();
    assert!(is_step(
        &key,
        SAS_PAIRING_STEP_INBOUND,
        SAS_PAIRING_PROTOCOL_EVENT_RESPONDER_KEY
    ));
    assert_eq!(key.run, run);
    let shown = harness
        .with_loop(|owner, _| owner.presentation(conn, &ours))
        .unwrap()
        .unwrap()
        .unwrap();
    let identity = *shown.ceremony_identity();
    harness.with_loop(|owner, _| {
        applied(owner.approve_sas(conn, &ours, &identity));
        applied(owner.emit_bootstrap_mac(conn, &ours));
    });
    wrote(harness);
    assert_eq!(
        inbound(received(&mut theirs)).0,
        HostEvent::BootstrapMac(PeerApproval::Authenticated)
    );
    acted(theirs.approve_sas(&responder, &identity));
    acted(theirs.emit_bootstrap_mac(&responder));
    assert_eq!(sent(&mut theirs), written());
    let mac = harness.next_event();
    assert!(is_step(
        &mac,
        SAS_PAIRING_STEP_INBOUND,
        SAS_PAIRING_PROTOCOL_EVENT_BOOTSTRAP_MAC_AUTHENTICATED
    ));
    assert_eq!(mac.run, run);
    harness.with_loop(|owner, _| applied(owner.emit_initiator_finish(conn, &ours)));
    wrote(harness);
    assert_eq!(inbound(received(&mut theirs)).0, HostEvent::InitiatorFinish);
    assert_eq!(sent(&mut theirs), written());
    let ack = harness.next_event();
    assert!(is_step(
        &ack,
        SAS_PAIRING_STEP_INBOUND,
        SAS_PAIRING_PROTOCOL_EVENT_RESPONDER_FINISH_ACK
    ));
    assert_eq!(
        (ack.run, ack.result, ack.flags),
        (run, 0, SAS_PAIRING_EVENT_FLAG_WRITE_PENDING)
    );
    // The result exists only in the drive whose own write completed the final ACK.
    let confirmed = harness.next_event();
    assert!(is_step(&confirmed, SAS_PAIRING_STEP_CONFIRMED, 0));
    assert_eq!(confirmed.run, 0);
    assert_ne!(confirmed.result, 0);
    assert_eq!(
        confirmed.request_id(),
        id.as_slice(),
        "from the result itself"
    );
    assert_eq!(harness.run_ref(run), None);
    (connection, run, confirmed.result, id, identity, theirs)
}

// --- Real loopback flows (Windows, test-local states) -----------------------------------------

/// A too-small event array and an exhausted handle space refuse the call before the owner loop
/// runs: no accept, no read, no deadline work, no handle. The pending work is all still there
/// for the next admitted drive.
#[cfg(windows)]
#[test]
fn a_refused_drive_makes_no_network_progress() {
    let state = AbiState::new();
    let harness = Harness::local(&state, b"p7-net-refused-drive");
    let mut client = TcpStream::connect(harness.address).unwrap();
    // Let the connection reach the backlog; nothing is accepted without a drive.
    thread::sleep(Duration::from_millis(50));
    let steps = NETWORK_STEPS.get();
    for mode in [DriveMode::Drive, DriveMode::Resume] {
        for capacity in [0, 1, MAX_DRIVE_EVENTS - 1] {
            assert_eq!(
                harness.call(mode, capacity),
                (
                    SAS_PAIRING_BUFFER_TOO_SMALL,
                    Vec::new(),
                    MAX_DRIVE_EVENTS,
                    SAS_PAIRING_OK
                )
            );
        }
    }
    assert_eq!(NETWORK_STEPS.get(), steps, "the owner loop never ran");
    assert_eq!(harness.live_connections(), 0, "nothing accepted");
    let accepted = harness.next_event();
    assert_eq!(accepted.kind, SAS_PAIRING_EVENT_CONNECTION_ACCEPTED);

    // Readable input waits too.
    client.write_all(&start(&[0x51; 16])).unwrap();
    thread::sleep(Duration::from_millis(50));
    let steps = NETWORK_STEPS.get();
    assert_eq!(
        harness.call(DriveMode::Drive, MAX_DRIVE_EVENTS - 1).0,
        SAS_PAIRING_BUFFER_TOO_SMALL
    );
    assert_eq!(NETWORK_STEPS.get(), steps);
    let started = harness.next_event();
    assert!(is_step(
        &started,
        SAS_PAIRING_STEP_INBOUND,
        SAS_PAIRING_PROTOCOL_EVENT_START_ACCEPTED
    ));
    assert_eq!(started.connection, accepted.connection);
    // A larger array is fine; only the produced records count.
    assert_eq!(harness.call(DriveMode::Drive, 64).0, SAS_PAIRING_OK);
    assert_eq!(state.destroy(harness.runtime), SAS_PAIRING_OK);
}

/// Handle space for the worst drive (17) is required before the owner loop runs; with 16 left
/// nothing is driven and the pending connection is still pending; with exactly 17 left the
/// drive runs.
#[cfg(windows)]
#[test]
fn the_handle_preflight_precedes_every_network_step() {
    for (left, admitted) in [(16_u64, false), (17, true)] {
        // runtime, authority, and host take three values; then `left` remain.
        let state = AbiState::with_handles(HandleCounter::starting_at(u64::MAX - left - 2));
        let scope = format!("p7-net-preflight-{left}");
        let harness = Harness::local(&state, scope.as_bytes());
        assert_eq!(harness.host, u64::MAX - left);
        let _client = TcpStream::connect(harness.address).unwrap();
        thread::sleep(Duration::from_millis(50));
        let steps = NETWORK_STEPS.get();
        if admitted {
            assert_eq!(
                harness.next_event().kind,
                SAS_PAIRING_EVENT_CONNECTION_ACCEPTED
            );
            assert!(NETWORK_STEPS.get() > steps);
        } else {
            for mode in [DriveMode::Drive, DriveMode::Resume] {
                assert_eq!(
                    harness.call(mode, MAX_DRIVE_EVENTS),
                    (SAS_PAIRING_HANDLES_EXHAUSTED, Vec::new(), 0, SAS_PAIRING_OK)
                );
            }
            assert_eq!(NETWORK_STEPS.get(), steps, "the owner loop never ran");
            assert_eq!(harness.live_connections(), 0);
            // The connection is still pending: the loop itself (no ABI drive) accepts it.
            let accepted = until(|| {
                harness.with_loop(|owner, _| {
                    let step = owner.drive_once().unwrap();
                    (!step.events.is_empty()).then_some(step)
                })
            });
            assert!(matches!(accepted.events[..], [OwnerEvent::Accepted(_)]));
            assert_eq!(harness.counts(), (0, 0), "no ABI handle exists for it");
        }
        assert!(!state.fatal.is_set());
        assert_eq!(state.destroy(harness.runtime), SAS_PAIRING_OK);
    }
}

/// Connection handles: one per accepted connection, stable across its steps, named by its
/// CLOSED event and invalid afterwards; explicit close invalidates the connection and its runs
/// first; other handle kinds and stale values name nothing; detach invalidates everything and a
/// replacement listener's connections get new handles.
#[cfg(windows)]
#[test]
fn connection_handles_are_stable_until_closed_and_never_reused() {
    let state = AbiState::new();
    let harness = Harness::local(&state, b"p7-net-connections");
    let mut first = TcpStream::connect(harness.address).unwrap();
    let c1 = harness.next_event().connection;
    first.write_all(&start(&[0x61; 16])).unwrap();
    let started = harness.next_event();
    assert_eq!(started.connection, c1);
    let r1 = started.run;
    assert_eq!(harness.next_event().connection, c1, "WRITTEN, same handle");
    assert_eq!(harness.counts(), (1, 1));

    // The peer reads its ACCEPT and closes gracefully: CLOSED names c1, then c1 and its run
    // are invalid. (Closing with unread input would reset the connection instead.)
    first
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    assert!(first.read(&mut [0; 4096]).unwrap() > 0);
    drop(first);
    let closed = harness.next_event();
    assert_eq!(
        (closed.kind, closed.connection, closed.reason),
        (
            SAS_PAIRING_EVENT_CONNECTION_CLOSED,
            c1,
            SAS_PAIRING_EVENT_REASON_PEER_CLOSED
        )
    );
    assert_eq!(harness.counts(), (0, 0));
    assert_eq!(harness.run_ref(r1), None);
    assert_eq!(harness.close(c1), SAS_PAIRING_INVALID_HANDLE);

    // Explicit close: the connection and its runs go first; the peer sees the end.
    let mut second = TcpStream::connect(harness.address).unwrap();
    let c2 = harness.next_event().connection;
    assert!(c2 > c1);
    second.write_all(&start(&[0x62; 16])).unwrap();
    let r2 = harness.next_event().run;
    assert_ne!(r2, 0);
    for wrong in [
        0,
        harness.runtime,
        harness.authority,
        harness.host,
        r2,
        c1,
        c2 + 1_000,
        u64::MAX,
    ] {
        assert_eq!(harness.close(wrong), SAS_PAIRING_INVALID_HANDLE, "{wrong}");
    }
    assert_eq!(harness.close(c2), SAS_PAIRING_OK);
    assert_eq!(harness.counts(), (0, 0));
    assert_eq!(harness.live_connections(), 0);
    assert_eq!(harness.close(c2), SAS_PAIRING_INVALID_HANDLE);
    second
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut accept = [0; 4096];
    let ended = loop {
        match second.read(&mut accept) {
            Ok(0) => break true,
            Ok(_) => continue,
            Err(error) => break error.kind() != ErrorKind::TimedOut,
        }
    };
    assert!(ended, "the peer saw its connection end");

    // Detach invalidates every handle of that loop; the replacement issues new ones.
    let _third = TcpStream::connect(harness.address).unwrap();
    let c3 = harness.next_event().connection;
    assert_eq!(harness.detach(), SAS_PAIRING_OK);
    assert_eq!(harness.close(c3), SAS_PAIRING_LISTENER_NOT_ATTACHED);
    for mode in [DriveMode::Drive, DriveMode::Resume] {
        assert_eq!(
            harness.call(mode, MAX_DRIVE_EVENTS).0,
            SAS_PAIRING_LISTENER_NOT_ATTACHED
        );
    }
    let mut replaced = harness;
    replaced.address = replaced.attach();
    assert_eq!(replaced.counts(), (0, 0));
    assert_eq!(
        replaced.close(c3),
        SAS_PAIRING_INVALID_HANDLE,
        "old handle, new loop"
    );
    let _fourth = TcpStream::connect(replaced.address).unwrap();
    let c4 = replaced.next_event().connection;
    assert!(c4 > c3, "never an old handle");
    assert_eq!(state.destroy(replaced.runtime), SAS_PAIRING_OK);
}

/// A run ended by a conflicting START leaves its reference stale (the event names no request
/// ID); the next START under the same request ID on the same connection is a new run with a new
/// handle, the stale reference is retired, and the old exact run cannot reach the new one.
#[cfg(windows)]
#[test]
fn a_reused_request_id_never_reaches_the_replacement_run() {
    let state = AbiState::new();
    let harness = Harness::local(&state, b"p7-net-reuse");
    let mut client = TcpStream::connect(harness.address).unwrap();
    let connection = harness.next_event().connection;
    let id = [0x71; 16];
    client.write_all(&start(&id)).unwrap();
    let first = harness.next_event();
    let r1 = first.run;
    let old = harness.run_ref(r1).unwrap();
    assert!(is_step(&harness.next_event(), SAS_PAIRING_STEP_WRITTEN, 0));

    // A changed START for the live key terminally fails that run (run-local, charged).
    let changed = Bootstrap::new(
        b"p7-net-other-application".to_vec(),
        initiator_bootstrap().key_algorithm().to_vec(),
        initiator_bootstrap().public_key().to_vec(),
        initiator_bootstrap().shared_context().to_vec(),
    )
    .unwrap();
    client.write_all(&start_with(&id, changed)).unwrap();
    let refused = harness.next_event();
    assert!(is_step(&refused, SAS_PAIRING_STEP_REFUSED, 0));
    assert_eq!(
        (refused.reason, refused.run, refused.request_id_len),
        (SAS_PAIRING_EVENT_REASON_ROUTE_REFUSED, 0, 0)
    );
    // Honest contract: the reference may stay, but the core refuses it.
    assert_eq!(harness.run_ref(r1), Some(old.clone()));
    let conn = harness.connection_ref(connection);
    assert_eq!(
        harness.with_loop(|owner, _| owner.presentation(conn, &old)),
        Ok(Err(RouteError::UnknownRoute))
    );

    client.write_all(&start(&id)).unwrap();
    let second = harness.next_event();
    assert!(is_step(
        &second,
        SAS_PAIRING_STEP_INBOUND,
        SAS_PAIRING_PROTOCOL_EVENT_START_ACCEPTED
    ));
    assert_eq!(second.request_id(), id);
    assert_ne!(second.run, 0);
    assert_ne!(second.run, r1, "a new handle for the replacement");
    let new = harness.run_ref(second.run).unwrap();
    assert_ne!(new, old, "a new exact run");
    assert_eq!(new.request_id(), old.request_id());
    assert_eq!(harness.run_ref(r1), None, "the stale reference was retired");
    assert_eq!(
        harness.with_loop(|owner, _| owner.presentation(conn, &old)),
        Ok(Err(RouteError::UnknownRoute)),
        "the old exact run never reaches the replacement"
    );
    assert_eq!(
        harness.with_loop(|owner, _| owner.presentation(conn, &new)),
        Ok(Ok(None))
    );
    assert_eq!(state.destroy(harness.runtime), SAS_PAIRING_OK);
}

/// A real PairingResult with the ABI host as the Responder: delivered once, byte for byte, and
/// it survives connection close, listener detach, host destroy, and authority release; result
/// destroy ends it. The ceremony consumed this authority's opportunity, and nothing refunded it.
#[cfg(windows)]
#[test]
fn a_responder_result_is_delivered_once_and_outlives_its_frontend() {
    let state = AbiState::new();
    let harness = Harness::local(&state, b"p7-net-result-r");
    let peer = Node::new("p7-net-result-r-peer");
    let (connection, run, result, id, identity, theirs) = responder_ceremony(&harness, &peer);
    let core = assert_result_matches_core(&harness, result);
    assert_eq!(core.request_id(), id.as_slice());
    assert_eq!(core.ceremony_identity(), &identity);
    assert_eq!(core.peer_role(), crate::Role::Initiator);
    assert_eq!(
        core.authenticated_peer_bootstrap(),
        initiator_bootstrap().canonical_bytes()
    );
    assert_eq!(
        core.authenticated_shared_context(),
        initiator_bootstrap().shared_context()
    );
    let (_, remaining, _) = session(b"p7-net-result-r").unwrap();
    assert_eq!(remaining, 9, "one opportunity consumed, never refunded");
    // Delivered once: later drives report nothing more for it.
    assert!(harness.events(DriveMode::Drive).is_empty());
    assert_eq!(
        state.with_runtime(harness.runtime, Admission::Data, |live| Ok(live
            .results
            .len())),
        Ok(1)
    );

    assert_eq!(harness.close(connection), SAS_PAIRING_OK);
    assert_eq!(harness.run_ref(run), None);
    assert_eq!(
        harness
            .result_info(result)
            .map(|info| info.ceremony_identity),
        Ok(identity)
    );
    assert_eq!(harness.detach(), SAS_PAIRING_OK);
    assert_eq!(
        state.destroy_host(harness.runtime, harness.host),
        SAS_PAIRING_OK
    );
    assert_eq!(
        state.release_authority(harness.runtime, harness.authority),
        SAS_PAIRING_OK
    );
    assert_eq!(
        assert_result_matches_core(&harness, result),
        core,
        "unchanged"
    );
    assert_eq!(session(b"p7-net-result-r").unwrap().1, 9);

    assert_eq!(harness.destroy_result(result), SAS_PAIRING_OK);
    assert_eq!(harness.result_info(result), Err(SAS_PAIRING_INVALID_HANDLE));
    assert_eq!(
        harness
            .copy(result, SAS_PAIRING_RESULT_FIELD_REQUEST_ID, 64)
            .0,
        SAS_PAIRING_INVALID_HANDLE
    );
    assert_eq!(harness.destroy_result(result), SAS_PAIRING_INVALID_HANDLE);
    assert_eq!(state.destroy(harness.runtime), SAS_PAIRING_OK);
    drop(theirs);
    peer.release();
}

/// A real PairingResult with the ABI host as the Initiator, delivered by the drive whose own
/// write completed the final ACK while the peer has no result yet (local completion is not
/// bilateral); the peer then never reads the ACK, and the host result is unaffected. Runtime
/// destroy invalidates the result.
#[cfg(windows)]
#[test]
fn an_initiator_result_is_local_completion_only_and_dies_with_its_runtime() {
    let state = AbiState::new();
    let harness = Harness::local(&state, b"p7-net-result-i");
    let peer = Node::new("p7-net-result-i-peer");
    let (connection, _, result, id, identity, theirs) = initiator_ceremony(&harness, &peer);
    // The peer Responder has not read the final ACK: its run is still routed, no result.
    assert_eq!(peer.routes(), 1, "the peer has no result yet");
    let core = assert_result_matches_core(&harness, result);
    assert_eq!(core.request_id(), id.as_slice());
    assert_eq!(core.ceremony_identity(), &identity);
    assert_eq!(core.peer_role(), crate::Role::Responder);
    assert_eq!(
        core.authenticated_peer_bootstrap(),
        responder_bootstrap().canonical_bytes()
    );
    // The peer goes away without ever reading the ACK.
    drop(theirs);
    peer.release();
    let closed = harness.next_event();
    assert_eq!(
        (closed.kind, closed.connection),
        (SAS_PAIRING_EVENT_CONNECTION_CLOSED, connection)
    );
    assert_eq!(assert_result_matches_core(&harness, result), core);

    let runtime = harness.runtime;
    assert_eq!(state.destroy(runtime), SAS_PAIRING_OK);
    assert_eq!(
        state.result_info(runtime, result),
        Err(SAS_PAIRING_INVALID_HANDLE)
    );
    assert_eq!(
        state.destroy_result(runtime, result),
        SAS_PAIRING_INVALID_HANDLE
    );
    let next = state.create().unwrap().get();
    assert_eq!(
        state.result_info(next, result),
        Err(SAS_PAIRING_INVALID_HANDLE)
    );
    assert_eq!(state.destroy(next), SAS_PAIRING_OK);
}

/// A verified peer CANCEL ends the run visibly: the event carries its reason and request ID, no
/// run and no result, and the run reference is retired at once.
#[cfg(windows)]
#[test]
fn a_peer_cancel_retires_its_run_at_once() {
    let state = AbiState::new();
    let harness = Harness::local(&state, b"p7-net-cancel");
    let peer = Node::new("p7-net-cancel-peer");
    let client = TcpStream::connect(harness.address).unwrap();
    let connection = harness.next_event().connection;
    let permit = AcceptPermit::begin(&peer.router).unwrap();
    let mut theirs =
        WindowsTcpConnection::from_accepted(client, permit, responder_bootstrap(), None).unwrap();
    let initiator = acted(theirs.start_initiator(initiator_bootstrap(), None))
        .run
        .unwrap();
    assert_eq!(sent(&mut theirs), written());
    let run = harness.next_event().run;
    harness.next_event();
    received(&mut theirs);
    acted(theirs.authorize_exposure(&initiator, &peer.trusted));
    acted(theirs.expose_key(&initiator));
    assert_eq!(sent(&mut theirs), written());
    assert_eq!(harness.next_event().run, run);
    let (conn, ours) = (
        harness.connection_ref(connection),
        harness.run_ref(run).unwrap(),
    );
    harness.with_loop(|owner, authority| {
        applied(owner.authorize_exposure(conn, &ours, authority));
        applied(owner.expose_key(conn, &ours));
    });
    harness.next_event();
    received(&mut theirs);
    let identity = *theirs
        .presentation(&initiator)
        .unwrap()
        .unwrap()
        .unwrap()
        .ceremony_identity();
    acted(theirs.reject_sas(&initiator, &identity));
    assert_eq!(sent(&mut theirs), written());
    let cancel = harness.next_event();
    assert!(is_step(
        &cancel,
        SAS_PAIRING_STEP_INBOUND,
        SAS_PAIRING_PROTOCOL_EVENT_PEER_CANCEL
    ));
    assert_eq!(
        cancel.cancel_reason,
        SAS_PAIRING_CANCEL_REASON_USER_REJECTION
    );
    assert_eq!((cancel.run, cancel.result), (0, 0));
    assert_eq!(cancel.request_id(), initiator.request_id());
    assert_eq!(harness.run_ref(run), None, "retired by the visible ending");
    assert_eq!(harness.counts(), (1, 0));
    assert_eq!(state.destroy(harness.runtime), SAS_PAIRING_OK);
    drop(theirs);
    peer.release();
}

/// Events produced in a drive before the owner loop failed closed are returned with
/// `OK` and the loop's failure; every connection handle of that loop is then invalid, and the
/// next drive reports `OWNER_LOOP_CLOSED` without events. The test seam closes the real loop
/// right after it produced a real event, as the loop's own failure path does.
#[cfg(windows)]
#[test]
fn a_drive_that_fails_closed_still_delivers_its_events() {
    fn fail_after_events(
        owner: &mut WindowsOwnerLoop<'static>,
        stepped: &mut Result<OwnerStep, OwnerLoopError>,
    ) {
        match stepped {
            Ok(step) if !step.events.is_empty() => {
                assert_eq!(owner.close(), Ok(()));
                step.failure = Some(OwnerLoopError::Poll(10_038));
            }
            _ => DRIVE_FAULT.set(Some(fail_after_events)),
        }
    }
    let state = AbiState::new();
    let harness = Harness::local(&state, b"p7-net-fail-closed");
    let _client = TcpStream::connect(harness.address).unwrap();
    DRIVE_FAULT.set(Some(fail_after_events));
    let give_up = Instant::now() + Duration::from_secs(10);
    let (status, events, count, failure) = loop {
        let outcome = harness.call(DriveMode::Drive, MAX_DRIVE_EVENTS);
        if outcome.2 > 0 || outcome.3 != SAS_PAIRING_OK {
            break outcome;
        }
        assert!(Instant::now() < give_up);
    };
    DRIVE_FAULT.take();
    assert_eq!(
        (status, count, failure),
        (SAS_PAIRING_OK, 1, SAS_PAIRING_NETWORK_POLL_FAILED)
    );
    assert_eq!(events[0].kind, SAS_PAIRING_EVENT_CONNECTION_ACCEPTED);
    assert_eq!(harness.counts(), (0, 0));
    assert_eq!(
        harness.close(events[0].connection),
        SAS_PAIRING_INVALID_HANDLE
    );
    assert_eq!(
        harness.call(DriveMode::Drive, MAX_DRIVE_EVENTS),
        (SAS_PAIRING_OK, Vec::new(), 0, SAS_PAIRING_OWNER_LOOP_CLOSED)
    );
    assert_eq!(
        harness.call(DriveMode::Resume, MAX_DRIVE_EVENTS),
        (SAS_PAIRING_OK, Vec::new(), 0, SAS_PAIRING_OWNER_LOOP_CLOSED)
    );
    assert!(!state.fatal.is_set());
    assert_eq!(harness.detach(), SAS_PAIRING_OK, "detach then cleans up");
    assert_eq!(state.destroy(harness.runtime), SAS_PAIRING_OK);
}

/// The resume recheck is a deadline sweep only: a pending accept stays pending and readable
/// input stays unread until a drive.
#[cfg(windows)]
#[test]
fn the_resume_recheck_accepts_reads_and_writes_nothing() {
    let state = AbiState::new();
    let harness = Harness::local(&state, b"p7-net-recheck");
    let mut first = TcpStream::connect(harness.address).unwrap();
    let connection = harness.next_event().connection;
    first.write_all(&start(&[0x81; 16])).unwrap();
    let _second = TcpStream::connect(harness.address).unwrap();
    thread::sleep(Duration::from_millis(100));
    let steps = NETWORK_STEPS.get();
    for _ in 0..3 {
        assert!(harness.events(DriveMode::Resume).is_empty());
    }
    assert_eq!(NETWORK_STEPS.get(), steps + 3, "one owner-loop call each");
    assert_eq!(harness.live_connections(), 1, "no accept");
    // The drive then finds both: the input of the existing connection and the pending accept.
    let events = harness.events(DriveMode::Drive);
    assert_eq!(events.len(), 2, "{events:?}");
    assert!(is_step(
        &events[0],
        SAS_PAIRING_STEP_INBOUND,
        SAS_PAIRING_PROTOCOL_EVENT_START_ACCEPTED
    ));
    assert_eq!(events[0].connection, connection);
    assert_eq!(events[1].kind, SAS_PAIRING_EVENT_CONNECTION_ACCEPTED);
    // The retained ACCEPT is not written by a recheck either.
    assert!(harness.events(DriveMode::Resume).is_empty());
    assert!(is_step(&harness.next_event(), SAS_PAIRING_STEP_WRITTEN, 0));
    assert_eq!(state.destroy(harness.runtime), SAS_PAIRING_OK);
}

/// A deadline found by the resume recheck surfaces as an event: a connection that never sent
/// its first frame ends at the transport's first-frame deadline. Its unread bytes on another
/// connection show that the recheck never read: that connection ends by the same deadline.
#[cfg(windows)]
#[test]
fn the_resume_recheck_surfaces_deadline_endings() {
    let state = AbiState::new();
    let harness = Harness::local(&state, b"p7-net-recheck-deadline");
    let _silent = TcpStream::connect(harness.address).unwrap();
    let quiet = harness.next_event().connection;
    let mut unread = TcpStream::connect(harness.address).unwrap();
    let other = harness.next_event().connection;
    unread.write_all(&start(&[0x82; 16])).unwrap();
    thread::sleep(FIRST_FRAME_DEADLINE + Duration::from_millis(200));
    let events = harness.events(DriveMode::Resume);
    let mut closed: Vec<(u64, u32)> = events
        .iter()
        .map(|event| {
            assert_eq!(event.kind, SAS_PAIRING_EVENT_CONNECTION_CLOSED);
            (event.connection, event.reason)
        })
        .collect();
    closed.sort_unstable();
    assert_eq!(
        closed,
        [
            (quiet, SAS_PAIRING_EVENT_REASON_TRANSPORT_DEADLINE),
            (other, SAS_PAIRING_EVENT_REASON_TRANSPORT_DEADLINE)
        ]
    );
    assert_eq!(harness.counts(), (0, 0));
    assert_eq!(state.destroy(harness.runtime), SAS_PAIRING_OK);
}

/// The seventeenth connection is refused without a connection handle; the sixteen others keep
/// theirs.
#[cfg(windows)]
#[test]
fn an_accept_refusal_names_no_connection() {
    let state = AbiState::new();
    let harness = Harness::local(&state, b"p7-net-refusal");
    let mut clients = Vec::new();
    let mut handles = Vec::new();
    for _ in 0..16 {
        clients.push(TcpStream::connect(harness.address).unwrap());
        let event = harness.next_event();
        assert_eq!(event.kind, SAS_PAIRING_EVENT_CONNECTION_ACCEPTED);
        handles.push(event.connection);
    }
    clients.push(TcpStream::connect(harness.address).unwrap());
    let refused = harness.next_event();
    assert_eq!(
        (refused.kind, refused.connection, refused.reason),
        (
            SAS_PAIRING_EVENT_ACCEPT_REFUSED,
            0,
            SAS_PAIRING_EVENT_REASON_RESOURCE_LIMITED
        )
    );
    assert_eq!(harness.counts(), (16, 0));
    handles.dedup();
    assert_eq!(handles.len(), 16);
    assert_eq!(state.destroy(harness.runtime), SAS_PAIRING_OK);
}

/// After fatal, drive and recheck are refused before any network or core work; connection close
/// stays cleanup; existing results stay readable and destroyable (data access, no core entry).
#[cfg(windows)]
#[test]
fn after_fatal_only_cleanup_and_result_data_remain() {
    let state = AbiState::new();
    let harness = Harness::local(&state, b"p7-net-fatal-local");
    let peer = Node::new("p7-net-fatal-local-peer");
    let (connection, _, result, _, identity, theirs) = responder_ceremony(&harness, &peer);
    let core = assert_result_matches_core(&harness, result);
    let status = contain(&state.fatal, SAS_PAIRING_FATAL, || -> i32 {
        panic!("injected panic")
    });
    assert_eq!(status, SAS_PAIRING_FATAL);
    let steps = NETWORK_STEPS.get();
    for mode in [DriveMode::Drive, DriveMode::Resume] {
        assert_eq!(
            harness.call(mode, MAX_DRIVE_EVENTS),
            (SAS_PAIRING_FATAL, Vec::new(), 0, SAS_PAIRING_OK)
        );
    }
    assert_eq!(NETWORK_STEPS.get(), steps, "no owner-loop work");
    assert_eq!(assert_result_matches_core(&harness, result), core);
    assert_eq!(
        harness.result_info(result).unwrap().ceremony_identity,
        identity
    );
    assert_eq!(harness.close(connection), SAS_PAIRING_OK, "cleanup");
    assert_eq!(harness.destroy_result(result), SAS_PAIRING_OK);
    assert_eq!(harness.destroy_result(result), SAS_PAIRING_INVALID_HANDLE);
    assert!(state.fatal.is_set(), "nothing clears fatal");
    assert_eq!(state.destroy(harness.runtime), SAS_PAIRING_OK);
    drop(theirs);
    peer.release();
}

// --- Real exports, isolated processes (Windows) ----------------------------------------------

/// Through the real exports: a size query, a too-small array, a real ceremony whose result is
/// read and copied through the result exports, then fatal: drive and recheck refuse without
/// network work, connection close and every result export still work, and runtime destroy
/// invalidates the remaining result.
#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by the_drive_and_result_exports_work_end_to_end"]
fn child_drive_and_result_exports() {
    if !is_child("network::child_drive_and_result_exports") {
        return;
    }
    let scope = b"p7-net-exports";
    let (_, runtime) = create();
    let harness = Harness::new(&PROCESS, true, runtime, scope);
    let mut count = usize::MAX;
    let mut failure = i32::MAX;
    // SAFETY: the size-query form: no array, capacity 0; live, aligned outputs.
    let status = unsafe {
        sas_pairing_host_drive(
            runtime,
            harness.host,
            ptr::null_mut(),
            0,
            &mut count,
            &mut failure,
        )
    };
    assert_eq!(
        (status, count, failure),
        (SAS_PAIRING_BUFFER_TOO_SMALL, 17, SAS_PAIRING_OK)
    );
    let peer = Node::new("p7-net-exports-peer");
    let (connection, _, result, id, identity, theirs) = responder_ceremony(&harness, &peer);
    let core = assert_result_matches_core(&harness, result);
    assert_eq!(core.request_id(), id.as_slice());
    // A second ceremony on a second connection gives a second result handle.
    let (second_connection, _, second, ..) = initiator_ceremony(&harness, &peer);
    assert_ne!(second, result);
    assert_ne!(second_connection, connection);
    assert_eq!(session(scope).unwrap().1, 8);

    assert_eq!(
        dispatch(SAS_PAIRING_FATAL, |_| -> i32 { panic!("injected panic") }),
        SAS_PAIRING_FATAL
    );
    let steps = NETWORK_STEPS.get();
    for mode in [DriveMode::Drive, DriveMode::Resume] {
        assert_eq!(
            harness.call(mode, MAX_DRIVE_EVENTS),
            (SAS_PAIRING_FATAL, Vec::new(), 0, SAS_PAIRING_OK)
        );
        // The capacity check is a stateless value check before the fatal state.
        assert_eq!(harness.call(mode, 1).0, SAS_PAIRING_BUFFER_TOO_SMALL);
    }
    assert_eq!(NETWORK_STEPS.get(), steps);
    assert_eq!(assert_result_matches_core(&harness, result), core);
    assert_eq!(
        harness.result_info(result).unwrap().ceremony_identity,
        identity
    );
    assert_eq!(harness.close(connection), SAS_PAIRING_OK);
    assert_eq!(harness.close(connection), SAS_PAIRING_INVALID_HANDLE);
    assert_eq!(harness.destroy_result(result), SAS_PAIRING_OK);
    assert_eq!(harness.result_info(result), Err(SAS_PAIRING_INVALID_HANDLE));
    assert_eq!(harness.detach(), SAS_PAIRING_OK);
    assert_eq!(host_destroy(runtime, harness.host), SAS_PAIRING_OK);
    assert_eq!(release(runtime, harness.authority), SAS_PAIRING_OK);
    assert!(
        harness.result_info(second).is_ok(),
        "survives every parent but the runtime"
    );
    assert_eq!(session(scope).unwrap().1, 8, "no refund, no reset");
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
    assert_eq!(harness.result_info(second), Err(SAS_PAIRING_INVALID_HANDLE));
    assert_eq!(
        sas_pairing_result_destroy(runtime, second),
        SAS_PAIRING_INVALID_HANDLE
    );
    assert!(PROCESS.fatal.is_set());
    drop(theirs);
    peer.release();
}

#[cfg(windows)]
#[test]
fn the_drive_and_result_exports_work_end_to_end() {
    run_child("network::child_drive_and_result_exports");
}

/// A panic in the middle of a real drive (after the owner loop produced a real event): the call
/// returns FATAL with nothing reported as success, the process is fatal, later drives never run
/// the loop, cleanup still works, and the authority's accounting is unchanged.
#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by a_panic_during_a_drive_is_contained_without_false_success"]
fn child_drive_panic() {
    fn panic_after_events(
        _: &mut WindowsOwnerLoop<'static>,
        stepped: &mut Result<OwnerStep, OwnerLoopError>,
    ) {
        match stepped {
            Ok(step) if !step.events.is_empty() => panic!("injected panic during a drive"),
            _ => DRIVE_FAULT.set(Some(panic_after_events)),
        }
    }
    if !is_child("network::child_drive_panic") {
        return;
    }
    let scope = b"p7-net-drive-panic";
    let (_, runtime) = create();
    let harness = Harness::new(&PROCESS, true, runtime, scope);
    let accounting = session(scope).unwrap();
    let _client = TcpStream::connect(harness.address).unwrap();
    DRIVE_FAULT.set(Some(panic_after_events));
    let give_up = Instant::now() + Duration::from_secs(10);
    let outcome = loop {
        let outcome = harness.call(DriveMode::Drive, MAX_DRIVE_EVENTS);
        if outcome.0 != SAS_PAIRING_OK {
            break outcome;
        }
        assert_eq!(outcome.2, 0, "no event before the panic");
        assert!(Instant::now() < give_up);
    };
    assert_eq!(outcome, (SAS_PAIRING_FATAL, Vec::new(), 0, SAS_PAIRING_OK));
    assert!(PROCESS.fatal.is_set());
    let steps = NETWORK_STEPS.get();
    assert_eq!(
        harness.call(DriveMode::Drive, MAX_DRIVE_EVENTS).0,
        SAS_PAIRING_FATAL
    );
    assert_eq!(NETWORK_STEPS.get(), steps);
    assert_eq!(harness.detach(), SAS_PAIRING_OK);
    assert_eq!(host_destroy(runtime, harness.host), SAS_PAIRING_OK);
    assert_eq!(release(runtime, harness.authority), SAS_PAIRING_OK);
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
    let after = session(scope).unwrap();
    assert_eq!(
        (after.1, after.2),
        (accounting.1, accounting.2),
        "accounting unchanged"
    );
    assert_eq!(create(), (SAS_PAIRING_FATAL, 0));
}

#[cfg(windows)]
#[test]
fn a_panic_during_a_drive_is_contained_without_false_success() {
    run_child("network::child_drive_panic");
}

/// Drive races detach, host destroy, authority release, and runtime destroy. Every pair
/// serializes on the runtime slot: a drive admitted first finishes, then the teardown runs; a
/// teardown admitted first makes the drive refuse; no event of a detached loop appears later.
#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by drive_serializes_with_every_teardown"]
fn child_drive_races() {
    fn drive(runtime: u64, host: u64) -> i32 {
        let mut events = [Event::ZERO; MAX_DRIVE_EVENTS];
        let (mut count, mut failure) = (0, 0);
        // SAFETY: live, aligned, exclusive array and outputs for the call.
        let status = unsafe {
            sas_pairing_host_drive(
                runtime,
                host,
                events.as_mut_ptr(),
                events.len(),
                &mut count,
                &mut failure,
            )
        };
        assert_eq!(failure, SAS_PAIRING_OK);
        status
    }
    if !is_child("network::child_drive_races") {
        return;
    }
    let (_, mut runtime) = create();
    for round in 0..8 {
        for teardown in 0..4 {
            let scope = format!("p7-net-race-{round}-{teardown}");
            let harness = Harness::new(&PROCESS, true, runtime, scope.as_bytes());
            let _client = TcpStream::connect(harness.address).unwrap();
            let (host, authority) = (harness.host, harness.authority);
            let [driven, torn] = race_pair(
                round,
                move || drive(runtime, host),
                move || match teardown {
                    0 => sas_pairing_host_detach_listener(runtime, host),
                    1 => host_destroy(runtime, host),
                    2 => release(runtime, authority),
                    _ => destroy(runtime),
                },
            );
            assert_eq!(torn, SAS_PAIRING_OK, "teardown {teardown}");
            let refused = if teardown == 0 {
                SAS_PAIRING_LISTENER_NOT_ATTACHED
            } else {
                SAS_PAIRING_INVALID_HANDLE
            };
            assert!(
                driven == SAS_PAIRING_OK || driven == refused,
                "teardown {teardown}: drive {driven}"
            );
            // Nothing of the old loop is ever reported again.
            assert_eq!(drive(runtime, host), refused);
            match teardown {
                0 => {
                    assert_eq!(host_destroy(runtime, host), SAS_PAIRING_OK);
                    assert_eq!(release(runtime, authority), SAS_PAIRING_OK);
                }
                1 => assert_eq!(release(runtime, authority), SAS_PAIRING_OK),
                2 => {}
                _ => runtime = create().1,
            }
        }
    }
    assert!(!PROCESS.fatal.is_set());
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
}

#[cfg(windows)]
#[test]
fn drive_serializes_with_every_teardown() {
    run_child("network::child_drive_races");
}
