//! P7.6 trusted local ceremony actions, SAS presentation, and local-action statuses (P7-D-011,
//! P7-D-012). The P6-D-004 consumed-opportunity panic evidence is in `consumed_panic`.
//!
//! The status mapping and the argument checks are tested everywhere; off Windows a child shows
//! that every action fails closed. The rest needs a Windows owner loop: real loopback ceremonies
//! on test-local states whose local side uses only the P7.6 operations (the peer is a direct
//! adapter of another authority), test seams that rewrite a real action's outcome to reach the
//! connection-ending and invariant paths, and children that use the real exports and the process
//! state (complete Initiator and Responder ceremonies on the public ABI, and races).

use std::ptr;

use super::super::{
    BootstrapView, BytesView,
    control::{Action, Presentation},
    sas_pairing_connection_start_initiator, sas_pairing_run_approve_sas,
    sas_pairing_run_authorize_exposure, sas_pairing_run_cancel_sas,
    sas_pairing_run_emit_bootstrap_mac, sas_pairing_run_emit_initiator_finish,
    sas_pairing_run_expose_key, sas_pairing_run_presentation, sas_pairing_run_reject_sas,
    status::*,
};
use super::{create, destroy, is_child, run_child};
use crate::{Error, ceremony::CeremonyError, crypto, protocol::CodecError, router::RouteError};
#[cfg(windows)]
use std::{io::Write, net::TcpStream, thread, time::Duration};

#[cfg(windows)]
use super::{
    super::{
        BootstrapInput, PROCESS,
        authority::{
            SAS_PAIRING_AUTHORITY_BUSY, SAS_PAIRING_AUTHORITY_EXHAUSTED,
            SAS_PAIRING_AUTHORITY_READY,
        },
        control::*,
        hosting::{ACTION_FAULT, LOCAL_ACTIONS, PRESENTATION_FAULT, START_CLOCK},
        network::*,
        panic_boundary::contain,
        runtime::{AbiState, Admission, HandleCounter},
        sas_pairing_connection_close, sas_pairing_host_detach_listener, sas_pairing_host_drive,
    },
    authority::{race_pair, session, spend, with_authority},
    authority_status, host_destroy,
    network::{Harness, assert_result_matches_core, is_step, view_of},
    release,
};
#[cfg(windows)]
use crate::{
    deadline::{ABSOLUTE_DEADLINE, Clock, INACTIVITY_DEADLINE, ManualClock},
    host::{CeremonyDeadline, HostEvent, LocalEvent},
    protocol::{Bootstrap, CancelReason},
    router::RunRef,
    transport::{AcceptPermit, FIRST_FRAME_DEADLINE},
    windows_owner_loop::{OwnerLoopError, WindowsOwnerLoop},
    windows_tcp::{
        Acted, Refused, TcpError, WindowsTcpConnection,
        tests::{
            Node, OneId, acted, inbound, initiator_bootstrap, received, responder_bootstrap, sent,
            start as start_frame, start_with as start_frame_with, written,
        },
    },
};

/// A record no action produces, to show which outputs were written.
pub(super) const SENTINEL: Action = Action {
    event: 0xDEAD,
    ..Action::ZERO
};
const SENTINEL_PRESENTATION: Presentation = Presentation {
    available: 0xDEAD,
    ..Presentation::ZERO
};

// --- Status mapping (all platforms) -----------------------------------------------------------

/// Every `CeremonyError` variant other than `TimedOut` (whose value the core alone builds; the
/// Windows test below gets a real one), with its frozen status.
fn ceremony_errors() -> Vec<(CeremonyError, i32)> {
    use CeremonyError as C;
    let mut errors = vec![
        (C::Codec(CodecError::Truncated), 225),
        (C::Crypto(crypto::Error::MacMismatch), 226),
        (C::InvalidState, 206),
        (C::NoLiveSas, 207),
        (C::CeremonyIdentityMismatch, 208),
        (C::NotLocallyApproved, 209),
        (C::UnexpectedSenderRole, 210),
        (C::InvalidRequestId, 211),
        (C::RequestIdGenerationFailed, 212),
        (C::RequestIdMismatch, 213),
        (C::SharedContextMismatch, 214),
        (C::ExpectedPeerMismatch, 215),
        (C::ApprovalsNotAuthenticated, 216),
        (C::NotInitiator, 217),
        (C::TranscriptMismatch, 218),
        (C::Completed, 219),
        (C::NoPendingFinalAck, 220),
        (C::FinalAckMismatch, 221),
        (C::ClockUnavailable, 223),
        (C::PendingExpired, 224),
    ];
    // `Owner` keeps the P7-D-004 value of its core error: nothing is duplicated.
    for (error, value) in [
        (Error::InvalidScope, 100),
        (Error::AlreadyRegistered, 101),
        (Error::OwnershipUnavailable, 102),
        (Error::UnsupportedPlatform, 103),
        (Error::OwnershipUncertain, 104),
        (Error::Busy, 105),
        (Error::Exhausted, 106),
        (Error::ResourceLimited, 107),
        (Error::MissingAuthorization, 200),
        (Error::StaleAuthorization, 201),
        (Error::Terminated, 202),
    ] {
        errors.push((C::Owner(error), value));
    }
    errors
}

/// Does not compile when the core gains a `CeremonyError` variant, so the table above (and the
/// production mapping, which is wildcard-free too) cannot fall behind.
fn listed_in_ceremony_errors(error: &CeremonyError) -> bool {
    match error {
        CeremonyError::TimedOut(_) => false,
        CeremonyError::Owner(_)
        | CeremonyError::Codec(_)
        | CeremonyError::Crypto(_)
        | CeremonyError::InvalidState
        | CeremonyError::NoLiveSas
        | CeremonyError::CeremonyIdentityMismatch
        | CeremonyError::NotLocallyApproved
        | CeremonyError::UnexpectedSenderRole
        | CeremonyError::InvalidRequestId
        | CeremonyError::RequestIdGenerationFailed
        | CeremonyError::RequestIdMismatch
        | CeremonyError::SharedContextMismatch
        | CeremonyError::ExpectedPeerMismatch
        | CeremonyError::ApprovalsNotAuthenticated
        | CeremonyError::NotInitiator
        | CeremonyError::TranscriptMismatch
        | CeremonyError::Completed
        | CeremonyError::NoPendingFinalAck
        | CeremonyError::FinalAckMismatch
        | CeremonyError::ClockUnavailable
        | CeremonyError::PendingExpired => true,
    }
}

/// Every ceremony refusal of a local action has exactly one frozen status; `Owner` keeps its
/// P7-D-004 value; `UnknownRoute` is `RUN_ENDED`; the session-ending route errors are an
/// invariant failure of a run-local refusal (`None`: the caller makes it fatal).
#[test]
fn every_ceremony_error_maps_to_one_frozen_status() {
    let errors = ceremony_errors();
    assert_eq!(
        errors.len(),
        20 + 11,
        "every variant but TimedOut, every core error"
    );
    let mut seen = std::collections::BTreeSet::new();
    for (error, value) in &errors {
        assert!(listed_in_ceremony_errors(error));
        assert_eq!(map_ceremony_error(error), *value, "{error:?}");
        assert_eq!(
            map_run_refusal(&RouteError::Ceremony(error.clone())),
            Some(*value)
        );
        if !matches!(error, CeremonyError::Owner(_)) {
            assert!((206..=226).contains(value), "{error:?}");
            assert!(seen.insert(*value), "{error:?} collides");
        }
    }
    assert_eq!(seen.len(), 20);
    assert!(!seen.contains(&222), "only TimedOut maps to 222");
    assert_eq!(
        map_run_refusal(&RouteError::UnknownRoute),
        Some(SAS_PAIRING_RUN_ENDED)
    );
    assert_eq!(map_run_refusal(&RouteError::UnknownSession), None);
    assert_eq!(map_run_refusal(&RouteError::SessionProtocolFailure), None);
}

// --- Arguments (all platforms) ----------------------------------------------------------------

type RunAction = unsafe extern "C" fn(u64, u64, u64, u64, *mut Action) -> i32;
type RunDecision = unsafe extern "C" fn(u64, u64, u64, u64, *const u8, *mut Action) -> i32;
const RUN_ACTIONS: [RunAction; 4] = [
    sas_pairing_run_authorize_exposure,
    sas_pairing_run_expose_key,
    sas_pairing_run_emit_bootstrap_mac,
    sas_pairing_run_emit_initiator_finish,
];
const RUN_DECISIONS: [RunDecision; 3] = [
    sas_pairing_run_approve_sas,
    sas_pairing_run_reject_sas,
    sas_pairing_run_cancel_sas,
];

fn bytes_of(value: &[u8]) -> BytesView {
    BytesView {
        data: value.as_ptr(),
        len: value.len(),
    }
}

/// A Bootstrap view over constant test bytes.
fn test_view() -> BootstrapView {
    BootstrapView {
        application_identity: bytes_of(b"p7-control-app"),
        key_algorithm: bytes_of(b"x25519"),
        public_key: bytes_of(&[7; 32]),
        shared_context: bytes_of(b""),
    }
}

/// Every pointer error of the nine exports is decided before any write, and nothing is written
/// through a rejected call; a well-formed call zeroes its record before anything else and then
/// refuses the handles (or, off Windows, the platform).
#[test]
fn local_action_arguments_are_checked_before_anything_else() {
    let refused = if cfg!(windows) {
        SAS_PAIRING_INVALID_HANDLE
    } else {
        SAS_PAIRING_UNSUPPORTED_PLATFORM
    };
    let mut words = [SENTINEL; 3];
    let misaligned = words
        .as_mut_ptr()
        .cast::<u8>()
        .wrapping_add(4)
        .cast::<Action>();
    let identity = [0x42_u8; 32];
    for action in RUN_ACTIONS {
        // SAFETY: rejected before any access.
        assert_eq!(
            unsafe { action(1, 2, 3, 4, ptr::null_mut()) },
            SAS_PAIRING_INVALID_ARGUMENT
        );
        // SAFETY: rejected before any access.
        assert_eq!(
            unsafe { action(1, 2, 3, 4, misaligned) },
            SAS_PAIRING_INVALID_ARGUMENT
        );
        let mut out = SENTINEL;
        // SAFETY: a live, aligned, exclusive record.
        assert_eq!(unsafe { action(0, 0, 0, 0, &mut out) }, refused);
        assert_eq!(out, Action::ZERO, "zeroed on entry");
    }
    for decision in RUN_DECISIONS {
        let mut out = SENTINEL;
        // The identity inside the output record, wrapping the address space, or null.
        let inside = ptr::from_mut(&mut out).cast::<u8>().cast_const();
        let high = ptr::without_provenance::<u8>(usize::MAX - 15);
        for (identity, out) in [
            (identity.as_ptr(), ptr::null_mut()),
            (identity.as_ptr(), misaligned),
            (ptr::null(), ptr::from_mut(&mut out)),
            (high, ptr::from_mut(&mut out)),
            (inside, ptr::from_mut(&mut out)),
            (inside.wrapping_add(20), ptr::from_mut(&mut out)),
        ] {
            // SAFETY: every pointer is rejected before any access.
            assert_eq!(
                unsafe { decision(1, 2, 3, 4, identity, out) },
                SAS_PAIRING_INVALID_ARGUMENT
            );
        }
        assert_eq!(out, SENTINEL, "nothing written");
        let mut pair = [SENTINEL; 2];
        // SAFETY: a live, aligned, exclusive record and 32 live readable identity bytes.
        assert_eq!(
            unsafe { decision(0, 0, 0, 0, identity.as_ptr(), &mut pair[0]) },
            refused
        );
        assert_eq!(pair[0], Action::ZERO);
        assert_eq!(pair[1], SENTINEL);
    }
    assert!(words.iter().all(|word| *word == SENTINEL));

    // Local start: the record, both views, every byte string, and no overlap with the record.
    let view = test_view();
    let mut out = SENTINEL;
    let out_ptr = ptr::from_mut(&mut out);
    let mut views = [view; 2];
    let misaligned_view = views
        .as_mut_ptr()
        .cast::<u8>()
        .wrapping_add(1)
        .cast::<BootstrapView>()
        .cast_const();
    let malformed = BootstrapView {
        public_key: BytesView {
            data: ptr::null(),
            len: 3,
        },
        ..view
    };
    let overlapping_bytes = BootstrapView {
        shared_context: BytesView {
            data: out_ptr.cast::<u8>().cast_const(),
            len: 8,
        },
        ..view
    };
    // A view record that shares memory with the output record.
    #[repr(C, align(8))]
    struct Shared([u8; 128]);
    let mut shared = Shared([0; 128]);
    let shared_view = shared.0.as_mut_ptr().cast::<BootstrapView>();
    // SAFETY: `shared` is live, aligned to 8, and holds one view.
    unsafe { shared_view.write(view) };
    let shared_out = shared
        .0
        .as_mut_ptr()
        .wrapping_add(size_of::<BootstrapView>() - 8)
        .cast::<Action>();
    let start = |local: *const BootstrapView, expected: *const BootstrapView, out: *mut Action| {
        // SAFETY: every pointer is live, aligned, and exclusive for the call, or rejected
        // before any access.
        unsafe { sas_pairing_connection_start_initiator(1, 2, 3, local, expected, out) }
    };
    for (local, expected, out) in [
        (ptr::from_ref(&view), ptr::null(), ptr::null_mut()),
        (ptr::from_ref(&view), ptr::null(), misaligned),
        (ptr::null(), ptr::null(), out_ptr),
        (misaligned_view, ptr::null(), out_ptr),
        (ptr::from_ref(&view), misaligned_view, out_ptr),
        (ptr::from_ref(&malformed), ptr::null(), out_ptr),
        (ptr::from_ref(&view), ptr::from_ref(&malformed), out_ptr),
        (ptr::from_ref(&overlapping_bytes), ptr::null(), out_ptr),
        (
            ptr::from_ref(&view),
            ptr::from_ref(&overlapping_bytes),
            out_ptr,
        ),
        (shared_view.cast_const(), ptr::null(), shared_out),
    ] {
        assert_eq!(start(local, expected, out), SAS_PAIRING_INVALID_ARGUMENT);
    }
    assert_eq!(out, SENTINEL, "nothing written");
    // SAFETY: `shared` still holds the view written above.
    assert_eq!(unsafe { shared_view.read().key_algorithm.len }, 6);
    // Well formed: zeroed, then the platform; on Windows an invalid Bootstrap is refused before
    // the state checks, a valid one by the handles.
    let invalid = BootstrapView {
        key_algorithm: bytes_of(b"NOT VALID"),
        ..view
    };
    for (local, expected, status) in [
        (
            ptr::from_ref(&invalid),
            ptr::null(),
            if cfg!(windows) {
                SAS_PAIRING_INVALID_BOOTSTRAP
            } else {
                SAS_PAIRING_UNSUPPORTED_PLATFORM
            },
        ),
        (
            ptr::from_ref(&view),
            ptr::from_ref(&invalid),
            if cfg!(windows) {
                SAS_PAIRING_INVALID_BOOTSTRAP
            } else {
                SAS_PAIRING_UNSUPPORTED_PLATFORM
            },
        ),
        (ptr::from_ref(&view), ptr::null(), refused),
        (ptr::from_ref(&view), ptr::from_ref(&view), refused),
    ] {
        out = SENTINEL;
        assert_eq!(start(local, expected, &mut out), status);
        assert_eq!(out, Action::ZERO);
    }

    // Presentation.
    let mut raw = [SENTINEL_PRESENTATION; 2];
    let misaligned_presentation = raw
        .as_mut_ptr()
        .cast::<u8>()
        .wrapping_add(2)
        .cast::<Presentation>();
    for out in [ptr::null_mut(), misaligned_presentation] {
        // SAFETY: rejected before any access.
        assert_eq!(
            unsafe { sas_pairing_run_presentation(1, 2, 3, 4, out) },
            SAS_PAIRING_INVALID_ARGUMENT
        );
    }
    assert!(raw.iter().all(|record| *record == SENTINEL_PRESENTATION));
    let mut presented = SENTINEL_PRESENTATION;
    // SAFETY: a live, aligned, exclusive record.
    assert_eq!(
        unsafe { sas_pairing_run_presentation(0, 0, 0, 0, &mut presented) },
        refused
    );
    assert_eq!(presented, Presentation::ZERO);
}

// --- Unsupported platforms --------------------------------------------------------------------

#[cfg(not(windows))]
#[test]
#[ignore = "subprocess child; run by local_actions_fail_closed_on_unsupported_platforms"]
fn child_unsupported_actions() {
    if !is_child("control::child_unsupported_actions") {
        return;
    }
    let (status, runtime) = create();
    assert_eq!(status, SAS_PAIRING_OK);
    let identity = [9_u8; 32];
    let view = test_view();
    for (host, connection, run) in [(runtime + 1, runtime + 2, runtime + 3), (0, 0, 0)] {
        for action in RUN_ACTIONS {
            let mut out = SENTINEL;
            // SAFETY: a live, aligned, exclusive record.
            let status = unsafe { action(runtime, host, connection, run, &mut out) };
            assert_eq!(
                (status, out),
                (SAS_PAIRING_UNSUPPORTED_PLATFORM, Action::ZERO)
            );
        }
        for decision in RUN_DECISIONS {
            let mut out = SENTINEL;
            // SAFETY: a live record and 32 live identity bytes.
            let status =
                unsafe { decision(runtime, host, connection, run, identity.as_ptr(), &mut out) };
            assert_eq!(
                (status, out),
                (SAS_PAIRING_UNSUPPORTED_PLATFORM, Action::ZERO)
            );
        }
        let mut out = SENTINEL;
        // SAFETY: a live record and a live view whose bytes are constants.
        let status = unsafe {
            sas_pairing_connection_start_initiator(
                runtime,
                host,
                connection,
                &view,
                ptr::null(),
                &mut out,
            )
        };
        assert_eq!(
            (status, out),
            (SAS_PAIRING_UNSUPPORTED_PLATFORM, Action::ZERO)
        );
        let mut presented = SENTINEL_PRESENTATION;
        // SAFETY: a live, aligned, exclusive record.
        let status =
            unsafe { sas_pairing_run_presentation(runtime, host, connection, run, &mut presented) };
        assert_eq!(
            (status, presented),
            (SAS_PAIRING_UNSUPPORTED_PLATFORM, Presentation::ZERO)
        );
    }
    // No handle was issued or burned, and the runtime is intact.
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
    let (status, next) = create();
    assert_eq!((status, next), (SAS_PAIRING_OK, runtime + 1));
    assert_eq!(destroy(next), SAS_PAIRING_OK);
}

#[cfg(not(windows))]
#[test]
fn local_actions_fail_closed_on_unsupported_platforms() {
    run_child("control::child_unsupported_actions");
}

// --- Translation (Windows) --------------------------------------------------------------------

/// Every `LocalEvent` has exactly one frozen event value; deadlines reuse the P7.5 kinds.
#[cfg(windows)]
#[test]
fn every_local_event_maps_to_one_frozen_action_value() {
    use crate::{ceremony::SasApproval, deadline::Deadline};
    use LocalEvent as L;
    let none = SAS_PAIRING_DEADLINE_NONE;
    for (event, value) in [
        (
            L::InitiatorStarted,
            (SAS_PAIRING_LOCAL_EVENT_INITIATOR_STARTED, none),
        ),
        (
            L::ExposureAuthorized,
            (SAS_PAIRING_LOCAL_EVENT_EXPOSURE_AUTHORIZED, none),
        ),
        (L::KeyExposed, (SAS_PAIRING_LOCAL_EVENT_KEY_EXPOSED, none)),
        (
            L::SasApproved(SasApproval::Recorded),
            (SAS_PAIRING_LOCAL_EVENT_SAS_APPROVED, none),
        ),
        (
            L::SasApproved(SasApproval::AlreadyRecorded),
            (SAS_PAIRING_LOCAL_EVENT_SAS_ALREADY_APPROVED, none),
        ),
        (
            L::BootstrapMacEmitted,
            (SAS_PAIRING_LOCAL_EVENT_BOOTSTRAP_MAC_EMITTED, none),
        ),
        (
            L::BootstrapMacAlreadyEmitted,
            (SAS_PAIRING_LOCAL_EVENT_BOOTSTRAP_MAC_ALREADY_EMITTED, none),
        ),
        (
            L::InitiatorFinishEmitted,
            (SAS_PAIRING_LOCAL_EVENT_INITIATOR_FINISH_EMITTED, none),
        ),
        (
            L::InitiatorFinishAlreadyEmitted,
            (
                SAS_PAIRING_LOCAL_EVENT_INITIATOR_FINISH_ALREADY_EMITTED,
                none,
            ),
        ),
        (L::SasRejected, (SAS_PAIRING_LOCAL_EVENT_SAS_REJECTED, none)),
        (
            L::SasCancelled,
            (SAS_PAIRING_LOCAL_EVENT_SAS_CANCELLED, none),
        ),
        (
            L::Deadline(CeremonyDeadline::TimedOut(Deadline::Absolute)),
            (
                SAS_PAIRING_LOCAL_EVENT_DEADLINE,
                SAS_PAIRING_DEADLINE_ABSOLUTE_TIMEOUT,
            ),
        ),
        (
            L::Deadline(CeremonyDeadline::TimedOut(Deadline::Inactivity)),
            (
                SAS_PAIRING_LOCAL_EVENT_DEADLINE,
                SAS_PAIRING_DEADLINE_INACTIVITY_TIMEOUT,
            ),
        ),
        (
            L::Deadline(CeremonyDeadline::PendingExpired),
            (
                SAS_PAIRING_LOCAL_EVENT_DEADLINE,
                SAS_PAIRING_DEADLINE_PENDING_EXPIRED,
            ),
        ),
        (
            L::Deadline(CeremonyDeadline::ClockUnavailable),
            (
                SAS_PAIRING_LOCAL_EVENT_DEADLINE,
                SAS_PAIRING_DEADLINE_CLOCK_UNAVAILABLE,
            ),
        ),
    ] {
        assert_eq!(local_event(event), value, "{event:?}");
    }
}

/// A real `CeremonyError::TimedOut` (built by the core for an expired run) maps to 222.
#[cfg(windows)]
#[test]
fn a_real_ceremony_timeout_maps_to_its_frozen_status() {
    let node = Node::new("p7-control-timeout-map");
    let clock = ManualClock::new();
    let session = node.router.open_session().unwrap();
    let (run, _) = node
        .router
        .start_initiator_run(
            clock.clone(),
            &mut OneId(Some([0x5C; 16])),
            session,
            initiator_bootstrap(),
            None,
        )
        .unwrap();
    clock.advance(ABSOLUTE_DEADLINE + Duration::from_secs(1));
    let error = node
        .router
        .with_exact_run(session, &run, |ceremony| ceremony.authorize(&node.trusted))
        .unwrap_err();
    let RouteError::Ceremony(timeout @ CeremonyError::TimedOut(_)) = &error else {
        panic!("a timeout: {error:?}");
    };
    assert!(!listed_in_ceremony_errors(timeout));
    assert_eq!(map_ceremony_error(timeout), SAS_PAIRING_CEREMONY_TIMED_OUT);
    assert_eq!(
        map_run_refusal(&error),
        Some(SAS_PAIRING_CEREMONY_TIMED_OUT)
    );
    node.router.close_session(session).unwrap();
    node.release();
}

// --- Harness actions (Windows) ----------------------------------------------------------------

#[cfg(windows)]
pub(super) fn done(event: u32, deadline_kind: u32, flags: u32, run: u64) -> Action {
    Action {
        event,
        deadline_kind,
        flags,
        reserved: 0,
        run,
    }
}

#[cfg(windows)]
const WP: u32 = SAS_PAIRING_ACTION_FLAG_WRITE_PENDING;

/// The outcome of one export call: the record on `OK`; otherwise the record must be the zero
/// record the export wrote on entry.
#[cfg(windows)]
fn exported(status: i32, out: Action) -> Result<Action, i32> {
    if status == SAS_PAIRING_OK {
        assert_eq!(out.reserved, 0);
        Ok(out)
    } else {
        assert_eq!(out, Action::ZERO, "zeroed, never a fabricated record");
        Err(status)
    }
}

/// A local Initiator start on `connection` (through the export, or the test-local state).
#[cfg(windows)]
fn start_on(
    h: &Harness<'_>,
    connection: u64,
    local: &Bootstrap,
    expected: Option<&Bootstrap>,
) -> Result<Action, i32> {
    let local_view = view_of(local);
    let expected_view = expected.map(view_of);
    if h.exports {
        let mut out = SENTINEL;
        let expected = expected_view.as_ref().map_or(ptr::null(), ptr::from_ref);
        // SAFETY: both views borrow live Bootstraps for the call; `out` is a live record.
        let status = unsafe {
            sas_pairing_connection_start_initiator(
                h.runtime,
                h.host,
                connection,
                &local_view,
                expected,
                &mut out,
            )
        };
        exported(status, out)
    } else {
        // SAFETY: the views borrow live Bootstraps for the call.
        let (local, expected) = unsafe {
            (
                BootstrapInput::new(local_view),
                expected_view.map(|view| BootstrapInput::new(view)),
            )
        };
        h.state
            .start_initiator(h.runtime, h.host, connection, &local, expected.as_ref())
    }
}

#[cfg(windows)]
pub(super) fn local_start(h: &Harness<'_>, connection: u64) -> Result<Action, i32> {
    start_on(h, connection, &initiator_bootstrap(), None)
}

/// One run action (through the export, or the test-local state).
#[cfg(windows)]
pub(super) fn act(
    h: &Harness<'_>,
    connection: u64,
    run: u64,
    request: Request,
) -> Result<Action, i32> {
    if !h.exports {
        let target = RunTarget {
            runtime: h.runtime,
            host: h.host,
            connection,
            run,
        };
        return h.state.act(target, request);
    }
    let (runtime, host) = (h.runtime, h.host);
    let mut out = SENTINEL;
    // SAFETY: `out` is a live record and every identity is a live 32-byte array.
    let status = unsafe {
        match request {
            Request::AuthorizeExposure => {
                sas_pairing_run_authorize_exposure(runtime, host, connection, run, &mut out)
            }
            Request::ExposeKey => {
                sas_pairing_run_expose_key(runtime, host, connection, run, &mut out)
            }
            Request::EmitBootstrapMac => {
                sas_pairing_run_emit_bootstrap_mac(runtime, host, connection, run, &mut out)
            }
            Request::EmitInitiatorFinish => {
                sas_pairing_run_emit_initiator_finish(runtime, host, connection, run, &mut out)
            }
            Request::Decide(decision, identity) => {
                let export = match decision {
                    Decision::Approve => sas_pairing_run_approve_sas,
                    Decision::Reject => sas_pairing_run_reject_sas,
                    Decision::Cancel => sas_pairing_run_cancel_sas,
                };
                export(runtime, host, connection, run, identity.as_ptr(), &mut out)
            }
        }
    };
    exported(status, out)
}

#[cfg(windows)]
pub(super) fn authorize(h: &Harness<'_>, connection: u64, run: u64) -> Result<Action, i32> {
    act(h, connection, run, Request::AuthorizeExposure)
}
#[cfg(windows)]
pub(super) fn expose(h: &Harness<'_>, connection: u64, run: u64) -> Result<Action, i32> {
    act(h, connection, run, Request::ExposeKey)
}
#[cfg(windows)]
pub(super) fn decide(
    h: &Harness<'_>,
    connection: u64,
    run: u64,
    decision: Decision,
    identity: &[u8; 32],
) -> Result<Action, i32> {
    act(h, connection, run, Request::Decide(decision, *identity))
}
#[cfg(windows)]
pub(super) fn emit_mac(h: &Harness<'_>, connection: u64, run: u64) -> Result<Action, i32> {
    act(h, connection, run, Request::EmitBootstrapMac)
}
#[cfg(windows)]
pub(super) fn emit_finish(h: &Harness<'_>, connection: u64, run: u64) -> Result<Action, i32> {
    act(h, connection, run, Request::EmitInitiatorFinish)
}

/// The presentation of `run` (through the export, or the test-local state).
#[cfg(windows)]
pub(super) fn present(h: &Harness<'_>, connection: u64, run: u64) -> Result<Presentation, i32> {
    if !h.exports {
        let target = RunTarget {
            runtime: h.runtime,
            host: h.host,
            connection,
            run,
        };
        return h.state.presentation(target);
    }
    let mut out = SENTINEL_PRESENTATION;
    // SAFETY: `out` is a live, aligned, exclusive record.
    let status =
        unsafe { sas_pairing_run_presentation(h.runtime, h.host, connection, run, &mut out) };
    if status == SAS_PAIRING_OK {
        Ok(out)
    } else {
        assert_eq!(out, Presentation::ZERO);
        Err(status)
    }
}

/// The authority's `(state, remaining)` through the ABI's own status path.
#[cfg(windows)]
fn status_of(h: &Harness<'_>) -> (u32, u32) {
    if h.exports {
        let (status, state, remaining) = authority_status(h.runtime, h.authority);
        assert_eq!(status, SAS_PAIRING_OK);
        (state, remaining)
    } else {
        h.state.authority_status(h.runtime, h.authority).unwrap()
    }
}

/// The remaining opportunities of `scope`'s process session (test-side registry read).
#[cfg(windows)]
fn remaining(scope: &[u8]) -> u8 {
    session(scope).expect("a process session").1
}

/// Runs `op` on the host's router (test-side read, under the runtime slot).
#[cfg(windows)]
fn with_router<T>(h: &Harness<'_>, op: impl FnOnce(&crate::router::Router) -> T) -> T {
    h.with_host(|host| op(host.router()))
}

/// The next drive event is the WRITTEN step of `connection`.
#[cfg(windows)]
fn wrote(h: &Harness<'_>, connection: u64) {
    let event = h.next_event();
    assert!(is_step(&event, SAS_PAIRING_STEP_WRITTEN, 0), "{event:?}");
    assert_eq!(
        (event.connection, event.run, event.flags),
        (connection, 0, 0)
    );
}

/// The peer adapter received nothing (polled for a while without an event).
#[cfg(windows)]
fn quiet(theirs: &mut WindowsTcpConnection<'_>) {
    for _ in 0..5 {
        thread::sleep(Duration::from_millis(20));
        let step = theirs.on_readable().unwrap();
        assert_eq!(step.event, None, "nothing was sent to the peer");
    }
}

/// A connection accepted by the ABI host, with the peer's direct adapter on the other end.
#[cfg(windows)]
fn connect_peer<'n>(h: &Harness<'_>, peer: &'n Node) -> (u64, WindowsTcpConnection<'n>) {
    let client = TcpStream::connect(h.address).unwrap();
    let accepted = h.next_event();
    assert_eq!(accepted.kind, SAS_PAIRING_EVENT_CONNECTION_ACCEPTED);
    let permit = AcceptPermit::begin(&peer.router).unwrap();
    let theirs =
        WindowsTcpConnection::from_accepted(client, permit, responder_bootstrap(), None).unwrap();
    (accepted.connection, theirs)
}

/// One ceremony between the ABI host and a peer adapter.
#[cfg(windows)]
pub(super) struct Flow<'n> {
    pub(super) connection: u64,
    /// The ABI run handle.
    pub(super) run: u64,
    pub(super) theirs: WindowsTcpConnection<'n>,
    /// The peer's own exact run.
    pub(super) peer_run: RunRef,
}

/// The ABI host starts a local Initiator through the P7.6 start and drives it until the peer's
/// ACCEPT arrived: the run awaits exposure authorization.
#[cfg(windows)]
pub(super) fn initiator_to_authorization<'n>(h: &Harness<'_>, peer: &'n Node) -> Flow<'n> {
    let (connection, mut theirs) = connect_peer(h, peer);
    let started = local_start(h, connection).unwrap();
    assert_eq!(
        started,
        done(
            SAS_PAIRING_LOCAL_EVENT_INITIATOR_STARTED,
            0,
            WP,
            started.run
        )
    );
    let run = started.run;
    assert!(run > connection, "a new handle");
    wrote(h, connection);
    let (event, peer_run) = inbound(received(&mut theirs));
    assert_eq!(event, HostEvent::StartAccepted);
    assert_eq!(sent(&mut theirs), written());
    let accept = h.next_event();
    assert!(is_step(
        &accept,
        SAS_PAIRING_STEP_INBOUND,
        SAS_PAIRING_PROTOCOL_EVENT_ACCEPT
    ));
    assert_eq!((accept.connection, accept.run), (connection, run));
    Flow {
        connection,
        run,
        theirs,
        peer_run: peer_run.unwrap(),
    }
}

/// From exposure authorization to the live SAS on the ABI Initiator: authorize, expose, the
/// peer's key. Returns the ABI presentation.
#[cfg(windows)]
fn initiator_to_sas(h: &Harness<'_>, peer: &Node, flow: &mut Flow<'_>) -> Presentation {
    let (connection, run) = (flow.connection, flow.run);
    assert_eq!(
        authorize(h, connection, run),
        Ok(done(SAS_PAIRING_LOCAL_EVENT_EXPOSURE_AUTHORIZED, 0, 0, run))
    );
    assert_eq!(
        expose(h, connection, run),
        Ok(done(SAS_PAIRING_LOCAL_EVENT_KEY_EXPOSED, 0, WP, run))
    );
    wrote(h, connection);
    assert_eq!(
        inbound(received(&mut flow.theirs)).0,
        HostEvent::InitiatorKey
    );
    acted(
        flow.theirs
            .authorize_exposure(&flow.peer_run, &peer.trusted),
    );
    acted(flow.theirs.expose_key(&flow.peer_run));
    assert_eq!(sent(&mut flow.theirs), written());
    let key = h.next_event();
    assert!(is_step(
        &key,
        SAS_PAIRING_STEP_INBOUND,
        SAS_PAIRING_PROTOCOL_EVENT_RESPONDER_KEY
    ));
    assert_eq!(key.run, run);
    let presented = present(h, connection, run).unwrap();
    assert_eq!(presented.available, 1);
    presented
}

/// The peer starts an Initiator toward the ABI host (the Responder) and exposes its key; the ABI
/// run awaits exposure authorization.
#[cfg(windows)]
fn responder_to_authorization<'n>(h: &Harness<'_>, peer: &'n Node) -> Flow<'n> {
    let (connection, mut theirs) = connect_peer(h, peer);
    let peer_run = acted(theirs.start_initiator(initiator_bootstrap(), None))
        .run
        .unwrap();
    assert_eq!(sent(&mut theirs), written());
    let started = h.next_event();
    assert!(is_step(
        &started,
        SAS_PAIRING_STEP_INBOUND,
        SAS_PAIRING_PROTOCOL_EVENT_START_ACCEPTED
    ));
    let run = started.run;
    wrote(h, connection);
    assert_eq!(inbound(received(&mut theirs)).0, HostEvent::Accept);
    acted(theirs.authorize_exposure(&peer_run, &peer.trusted));
    acted(theirs.expose_key(&peer_run));
    assert_eq!(sent(&mut theirs), written());
    let key = h.next_event();
    assert!(is_step(
        &key,
        SAS_PAIRING_STEP_INBOUND,
        SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_KEY
    ));
    assert_eq!(key.run, run);
    Flow {
        connection,
        run,
        theirs,
        peer_run,
    }
}

/// The record shape of a live presentation, and that it equals the core's own presentation and
/// the peer's view of the same ceremony byte for byte.
#[cfg(windows)]
fn assert_presentation_is_exact(h: &Harness<'_>, flow: &mut Flow<'_>, presented: &Presentation) {
    assert_eq!(
        (
            presented.available,
            presented.reserved,
            presented.reserved_tail
        ),
        (1, 0, [0, 0])
    );
    assert!(is_decimal_display(&presented.decimal));
    let (connection, run) = (
        h.connection_ref(flow.connection),
        h.run_ref(flow.run).unwrap(),
    );
    let core = h
        .with_loop(|owner, _| owner.presentation(connection, &run))
        .unwrap()
        .unwrap()
        .expect("the core presents it");
    assert_eq!(&presented.ceremony_identity, core.ceremony_identity());
    assert_eq!(presented.decimal.as_slice(), core.decimal().as_bytes());
    let theirs = flow
        .theirs
        .presentation(&flow.peer_run)
        .unwrap()
        .unwrap()
        .expect("the peer presents it too");
    assert_eq!(theirs, core, "both sides compare the same value");
}

// --- Local start and backpressure (Windows) ---------------------------------------------------

/// A local start creates one exact run with a new handle and retains START; until it is written
/// every mutating action is refused before the host (`WRITE_PENDING`, zero record, nothing
/// changes), while the read-only presentation still answers. The Responder START limiter is not
/// touched. After the write the run continues normally, proving the refused calls did nothing.
#[cfg(windows)]
#[test]
fn a_local_start_issues_one_exact_run_and_backpressures_every_mutation() {
    let state = AbiState::new();
    let scope = b"p7-control-start";
    let h = Harness::local(&state, scope);
    let peer = Node::new("p7-control-start-peer");
    let (connection, mut theirs) = connect_peer(&h, &peer);
    let limiter = with_router(&h, |router| router.authority().start_limiter_snapshot());
    let started = local_start(&h, connection).unwrap();
    let run = started.run;
    assert_eq!(
        started,
        done(SAS_PAIRING_LOCAL_EVENT_INITIATOR_STARTED, 0, WP, run)
    );
    assert!(run > connection);
    let exact = h.run_ref(run).expect("an exact run reference");
    assert_eq!(exact.request_id().len(), 16, "a core-generated request ID");
    assert_eq!(h.counts(), (1, 1));
    assert_eq!(with_router(&h, |router| router.routes_for_test()), 1);
    assert_eq!(
        with_router(&h, |router| router.authority().start_limiter_snapshot()),
        limiter,
        "a local Initiator never uses the Responder START limiter"
    );
    assert_eq!(remaining(scope), 10, "starting spends nothing");

    // START is retained: every mutating action is refused before the host.
    let wrong = [0x13; 32];
    assert_eq!(local_start(&h, connection), Err(SAS_PAIRING_WRITE_PENDING));
    for request in [
        Request::AuthorizeExposure,
        Request::ExposeKey,
        Request::EmitBootstrapMac,
        Request::EmitInitiatorFinish,
        Request::Decide(Decision::Approve, wrong),
        Request::Decide(Decision::Reject, wrong),
        Request::Decide(Decision::Cancel, wrong),
    ] {
        assert_eq!(
            act(&h, connection, run, request),
            Err(SAS_PAIRING_WRITE_PENDING),
            "{request:?}"
        );
    }
    // The read-only presentation still answers (no SAS yet).
    assert_eq!(present(&h, connection, run), Ok(Presentation::ZERO));
    assert_eq!(h.counts(), (1, 1), "the mapping is unchanged");
    assert_eq!(with_router(&h, |router| router.routes_for_test()), 1);

    // Exactly one START reaches the peer, and the run continues normally.
    wrote(&h, connection);
    let (event, peer_run) = inbound(received(&mut theirs));
    assert_eq!(event, HostEvent::StartAccepted);
    assert_eq!(peer_run.unwrap().request_id(), exact.request_id());
    assert_eq!(sent(&mut theirs), written());
    let accept = h.next_event();
    assert_eq!(accept.run, run, "the same handle");
    assert_eq!(
        authorize(&h, connection, run),
        Ok(done(SAS_PAIRING_LOCAL_EVENT_EXPOSURE_AUTHORIZED, 0, 0, run))
    );
    assert_eq!(remaining(scope), 10);
    assert_eq!(state.destroy(h.runtime), SAS_PAIRING_OK);
    drop(theirs);
    peer.release();
}

/// A connection holding `SAS_PAIRING_MAX_RUNS_PER_CONNECTION` run handles refuses a local start
/// before the owner loop: no run, START, request-ID reservation, or handle, and never an
/// untracked local run. A stale reference still counts until an action finds it ended.
#[cfg(windows)]
#[test]
fn a_full_connection_refuses_a_local_start_before_the_core() {
    let state = AbiState::new();
    let h = Harness::local(&state, b"p7-control-cap");
    let _client = TcpStream::connect(h.address).unwrap();
    let connection = h.next_event().connection;
    let mut runs = Vec::new();
    for _ in 0..MAX_RUNS_PER_CONNECTION {
        let started = local_start(&h, connection).unwrap();
        assert_eq!(started.event, SAS_PAIRING_LOCAL_EVENT_INITIATOR_STARTED);
        runs.push(started.run);
        wrote(&h, connection);
    }
    runs.dedup();
    assert_eq!(runs.len(), 32, "32 distinct handles");
    assert_eq!(h.counts(), (1, 32));
    let reserved = || {
        with_router(&h, |router| {
            let shared = router.authority().0.shared.lock().unwrap();
            shared.initiator_request_ids.len()
        })
    };
    assert_eq!(reserved(), 32);
    let (actions, next) = (LOCAL_ACTIONS.get(), state.next_handle_for_test());
    assert_eq!(
        local_start(&h, connection),
        Err(SAS_PAIRING_RESOURCE_LIMITED)
    );
    assert_eq!(LOCAL_ACTIONS.get(), actions, "the owner loop never ran");
    assert_eq!(state.next_handle_for_test(), next, "no handle issued");
    assert_eq!(with_router(&h, |router| router.routes_for_test()), 32);
    assert_eq!(reserved(), 32, "no request ID reserved");
    assert_eq!(h.counts(), (1, 32));

    // Authorizing a run that awaits ACCEPT ends it in the core (an ordinary refusal): its
    // reference is kept, honestly stale, and still counts.
    assert_eq!(
        authorize(&h, connection, runs[0]),
        Err(SAS_PAIRING_CEREMONY_INVALID_STATE)
    );
    assert_eq!(h.counts(), (1, 32));
    assert_eq!(
        local_start(&h, connection),
        Err(SAS_PAIRING_RESOURCE_LIMITED)
    );
    // The next action finds it ended and removes it; then one local start fits again.
    assert_eq!(present(&h, connection, runs[0]), Err(SAS_PAIRING_RUN_ENDED));
    assert_eq!(h.counts(), (1, 31));
    let started = local_start(&h, connection).unwrap();
    assert_eq!(
        started.run, next,
        "the first handle issued since the refusal"
    );
    assert_eq!(h.counts(), (1, 32));
    assert_eq!(state.destroy(h.runtime), SAS_PAIRING_OK);
}

/// A local start needs exactly one handle value and checks it before the owner loop: with none
/// left nothing starts and nothing is sent; with exactly one left the start takes it.
#[cfg(windows)]
#[test]
fn a_local_start_checks_its_handle_before_the_core() {
    // Runtime, authority, and host take three values, leaving the 17 the accepting drive needs.
    let state = AbiState::with_handles(HandleCounter::starting_at(u64::MAX - 19));
    let h = Harness::local(&state, b"p7-control-handles");
    let peer = Node::new("p7-control-handles-peer");
    let (connection, mut theirs) = connect_peer(&h, &peer);
    assert_eq!(state.next_handle_for_test(), u64::MAX - 15);
    for _ in 0..15 {
        state.allocate_handle().unwrap();
    }
    assert_eq!(state.next_handle_for_test(), u64::MAX, "exactly one left");
    let started = local_start(&h, connection).unwrap();
    assert_eq!(started.run, u64::MAX);
    assert_eq!(state.next_handle_for_test(), 0, "none left");
    let actions = LOCAL_ACTIONS.get();
    // Refused before the owner loop (which would have answered WRITE_PENDING).
    assert_eq!(
        local_start(&h, connection),
        Err(SAS_PAIRING_HANDLES_EXHAUSTED)
    );
    assert_eq!(LOCAL_ACTIONS.get(), actions);
    assert_eq!(with_router(&h, |router| router.routes_for_test()), 1);
    // Actions on the existing run need no handle.
    assert_eq!(present(&h, connection, u64::MAX), Ok(Presentation::ZERO));
    assert!(!state.fatal.is_set());
    // Only the first START was produced (the drive itself now needs 17 handles).
    assert_eq!(
        h.call(DriveMode::Drive, MAX_DRIVE_EVENTS).0,
        SAS_PAIRING_HANDLES_EXHAUSTED
    );
    quiet(&mut theirs);
    assert_eq!(state.destroy(h.runtime), SAS_PAIRING_OK);
    drop(theirs);
    peer.release();
}

// --- Authorization and exposure (Windows) -----------------------------------------------------

/// Authorization records consent and spends nothing; exposure consumes it and exactly one
/// opportunity, holds the guard, and retains the key frame. Nothing is merged or chained.
#[cfg(windows)]
#[test]
fn authorization_spends_nothing_and_exposure_spends_exactly_one() {
    let state = AbiState::new();
    let scope = b"p7-control-spend";
    let h = Harness::local(&state, scope);
    let peer = Node::new("p7-control-spend-peer");
    let mut flow = initiator_to_authorization(&h, &peer);
    let (connection, run) = (flow.connection, flow.run);
    assert_eq!(status_of(&h), (SAS_PAIRING_AUTHORITY_READY, 10));
    assert_eq!(
        authorize(&h, connection, run),
        Ok(done(SAS_PAIRING_LOCAL_EVENT_EXPOSURE_AUTHORIZED, 0, 0, run))
    );
    assert_eq!(status_of(&h), (SAS_PAIRING_AUTHORITY_READY, 10));
    assert_eq!(remaining(scope), 10, "authorization spends nothing");
    assert!(h.events(DriveMode::Drive).is_empty(), "nothing to write");
    quiet(&mut flow.theirs);
    assert_eq!(
        expose(&h, connection, run),
        Ok(done(SAS_PAIRING_LOCAL_EVENT_KEY_EXPOSED, 0, WP, run))
    );
    assert_eq!(remaining(scope), 9, "exposure spent exactly one");
    assert_eq!(status_of(&h), (SAS_PAIRING_AUTHORITY_BUSY, 0), "guard held");
    wrote(&h, connection);
    assert_eq!(
        inbound(received(&mut flow.theirs)).0,
        HostEvent::InitiatorKey
    );
    // The authorization was consumed: a second exposure has none.
    assert_eq!(
        expose(&h, connection, run),
        Err(SAS_PAIRING_MISSING_AUTHORIZATION),
        "the core refuses (and ends) a second exposure"
    );
    assert_eq!(remaining(scope), 9);
    assert_eq!(
        status_of(&h),
        (SAS_PAIRING_AUTHORITY_READY, 9),
        "guard released"
    );
    assert_eq!(state.destroy(h.runtime), SAS_PAIRING_OK);
    assert_eq!(remaining(scope), 9, "never refunded");
    drop(flow);
    peer.release();
}

/// Exposure without a fresh authorization of exactly this run is refused by the core
/// (`MISSING_AUTHORIZATION`), with no output and nothing spent; one run's authorization never
/// authorizes another; a second authorization is the core's invalid-state refusal. The run's
/// fate is the core's: a refusal that ended it leaves a stale reference that reports
/// `RUN_ENDED`, then names nothing. No ABI path can name another authority; the core's own
/// refusal of a foreign authority maps to `STALE_AUTHORIZATION`.
#[cfg(windows)]
#[test]
fn exposure_needs_a_fresh_authorization_of_exactly_that_run() {
    let state = AbiState::new();
    let scope = b"p7-control-fresh";
    let h = Harness::local(&state, scope);
    let peer = Node::new("p7-control-fresh-peer");
    let a = initiator_to_authorization(&h, &peer);
    let b = initiator_to_authorization(&h, &peer);
    let c = initiator_to_authorization(&h, &peer);
    // Without any authorization.
    assert_eq!(
        expose(&h, a.connection, a.run),
        Err(SAS_PAIRING_MISSING_AUTHORIZATION)
    );
    assert_eq!(remaining(scope), 10);
    assert!(h.events(DriveMode::Drive).is_empty(), "no key frame");
    assert!(h.run_ref(a.run).is_some(), "the reference is kept");
    assert_eq!(
        authorize(&h, a.connection, a.run),
        Err(SAS_PAIRING_RUN_ENDED),
        "the core ended that run"
    );
    assert_eq!(
        authorize(&h, a.connection, a.run),
        Err(SAS_PAIRING_INVALID_HANDLE)
    );
    // B's authorization does not authorize C.
    assert_eq!(
        authorize(&h, b.connection, b.run).map(|action| action.event),
        Ok(SAS_PAIRING_LOCAL_EVENT_EXPOSURE_AUTHORIZED)
    );
    assert_eq!(
        expose(&h, c.connection, c.run),
        Err(SAS_PAIRING_MISSING_AUTHORIZATION)
    );
    assert_eq!(remaining(scope), 10);
    // A second authorization of B is refused by the core.
    assert_eq!(
        authorize(&h, b.connection, b.run),
        Err(SAS_PAIRING_CEREMONY_INVALID_STATE)
    );
    assert_eq!(expose(&h, b.connection, b.run), Err(SAS_PAIRING_RUN_ENDED));
    assert_eq!(remaining(scope), 10, "nothing was ever spent");

    // A foreign authority, test-side only (the ABI takes no authority parameter).
    let d = initiator_to_authorization(&h, &peer);
    let (connection, run) = (h.connection_ref(d.connection), h.run_ref(d.run).unwrap());
    let refused = h.with_loop(|owner, _| owner.authorize_exposure(connection, &run, &peer.trusted));
    let Ok(Err(Refused::Run(error))) = refused else {
        panic!("a run-local refusal: {refused:?}");
    };
    assert_eq!(
        map_run_refusal(&error),
        Some(SAS_PAIRING_STALE_AUTHORIZATION)
    );
    assert_eq!(state.destroy(h.runtime), SAS_PAIRING_OK);
    drop([a, b, c, d]);
    peer.release();
}

/// While one exposed ceremony holds the authority's guard, another exposure is `BUSY`: no
/// queueing, waiting, or reset; the busy run is ended by the core and its reference reports
/// `RUN_ENDED` next.
#[cfg(windows)]
#[test]
fn a_second_exposure_while_the_guard_is_held_is_busy() {
    let state = AbiState::new();
    let scope = b"p7-control-busy";
    let h = Harness::local(&state, scope);
    let peer = Node::new("p7-control-busy-peer");
    let a = initiator_to_authorization(&h, &peer);
    let b = initiator_to_authorization(&h, &peer);
    for flow in [&a, &b] {
        assert_eq!(
            authorize(&h, flow.connection, flow.run).map(|action| action.event),
            Ok(SAS_PAIRING_LOCAL_EVENT_EXPOSURE_AUTHORIZED)
        );
    }
    assert_eq!(
        expose(&h, a.connection, a.run),
        Ok(done(SAS_PAIRING_LOCAL_EVENT_KEY_EXPOSED, 0, WP, a.run))
    );
    assert_eq!(expose(&h, b.connection, b.run), Err(SAS_PAIRING_BUSY));
    assert_eq!(remaining(scope), 9);
    assert_eq!(status_of(&h), (SAS_PAIRING_AUTHORITY_BUSY, 0));
    assert_eq!(present(&h, b.connection, b.run), Err(SAS_PAIRING_RUN_ENDED));
    assert_eq!(
        present(&h, a.connection, a.run),
        Ok(Presentation::ZERO),
        "the first run is live"
    );
    assert_eq!(state.destroy(h.runtime), SAS_PAIRING_OK);
    drop((a, b));
    peer.release();
}

/// With the budget spent, exposure is `EXHAUSTED`: no key frame, nothing refunded, and the
/// exhaustion survives every teardown.
#[cfg(windows)]
#[test]
fn an_exhausted_budget_refuses_exposure_without_output() {
    let state = AbiState::new();
    let scope = b"p7-control-exhausted";
    let h = Harness::local(&state, scope);
    let peer = Node::new("p7-control-exhausted-peer");
    for left in (0..10).rev() {
        let spent = with_authority(&state, h.runtime, h.authority, spend);
        assert_eq!(spent, Ok(left));
    }
    assert_eq!(status_of(&h), (SAS_PAIRING_AUTHORITY_EXHAUSTED, 0));
    let mut flow = initiator_to_authorization(&h, &peer);
    assert_eq!(
        authorize(&h, flow.connection, flow.run).map(|action| action.event),
        Ok(SAS_PAIRING_LOCAL_EVENT_EXPOSURE_AUTHORIZED)
    );
    assert_eq!(
        expose(&h, flow.connection, flow.run),
        Err(SAS_PAIRING_EXHAUSTED)
    );
    assert!(h.events(DriveMode::Drive).is_empty(), "no key frame");
    quiet(&mut flow.theirs);
    assert_eq!(h.close(flow.connection), SAS_PAIRING_OK);
    assert_eq!(
        state.release_authority(h.runtime, h.authority),
        SAS_PAIRING_OK
    );
    assert_eq!(state.destroy(h.runtime), SAS_PAIRING_OK);
    assert_eq!(remaining(scope), 0, "nothing refunded");
    drop(flow);
    peer.release();
}

/// Each host authorizes with its own parent authority: there is no foreign-authority parameter,
/// spending on one authority leaves the other untouched, and a run of one host (or connection)
/// is never reachable through another host (or connection).
#[cfg(windows)]
#[test]
fn every_host_authorizes_with_its_own_authority_and_parents_are_exact() {
    let state = AbiState::new();
    let runtime = state.create().unwrap().get();
    let (scope_a, scope_b) = (b"p7-control-parent-a", b"p7-control-parent-b");
    let ha = Harness::new(&state, false, runtime, scope_a);
    let hb = Harness::new(&state, false, runtime, scope_b);
    let peer = Node::new("p7-control-parent-peer");
    let a = initiator_to_authorization(&ha, &peer);
    let b = initiator_to_authorization(&hb, &peer);
    let a2 = initiator_to_authorization(&ha, &peer);
    // Cross-parent and wrong-kind handles name nothing.
    let cross = |h: &Harness<'_>, connection: u64, run: u64| present(h, connection, run);
    for (h, connection, run) in [
        (&hb, a.connection, a.run),
        (&ha, b.connection, b.run),
        (&ha, a2.connection, a.run),
        (&ha, a.connection, a2.run),
        (&ha, a.connection, a.connection),
        (&ha, a.run, a.run),
        (&ha, a.connection, runtime),
        (&ha, a.connection, ha.authority),
        (&ha, a.connection, ha.host),
        (&ha, ha.host, a.run),
        (&ha, a.connection, 0),
        (&ha, 0, a.run),
    ] {
        assert_eq!(
            cross(h, connection, run),
            Err(SAS_PAIRING_INVALID_HANDLE),
            "{connection} {run}"
        );
    }
    let foreign_host = Harness {
        state: &state,
        exports: false,
        runtime,
        authority: ha.authority,
        host: ha.authority,
        address: ha.address,
    };
    assert_eq!(
        authorize(&foreign_host, a.connection, a.run),
        Err(SAS_PAIRING_INVALID_HANDLE)
    );
    assert_eq!(
        local_start(&hb, a.connection),
        Err(SAS_PAIRING_INVALID_HANDLE)
    );

    assert_eq!(
        authorize(&ha, a.connection, a.run).map(|action| action.event),
        Ok(SAS_PAIRING_LOCAL_EVENT_EXPOSURE_AUTHORIZED)
    );
    assert_eq!(
        expose(&ha, a.connection, a.run).map(|action| action.event),
        Ok(SAS_PAIRING_LOCAL_EVENT_KEY_EXPOSED)
    );
    assert_eq!((remaining(scope_a), remaining(scope_b)), (9, 10));
    assert_eq!(
        authorize(&hb, b.connection, b.run).map(|action| action.event),
        Ok(SAS_PAIRING_LOCAL_EVENT_EXPOSURE_AUTHORIZED)
    );
    assert_eq!(
        expose(&hb, b.connection, b.run).map(|action| action.event),
        Ok(SAS_PAIRING_LOCAL_EVENT_KEY_EXPOSED)
    );
    assert_eq!((remaining(scope_a), remaining(scope_b)), (9, 9));

    // A connection of a detached listener names nothing after a new listener is attached.
    assert_eq!(ha.detach(), SAS_PAIRING_OK);
    assert_eq!(
        present(&ha, a2.connection, a2.run),
        Err(SAS_PAIRING_LISTENER_NOT_ATTACHED)
    );
    ha.attach();
    assert_eq!(
        present(&ha, a2.connection, a2.run),
        Err(SAS_PAIRING_INVALID_HANDLE)
    );
    assert_eq!(
        local_start(&ha, a2.connection),
        Err(SAS_PAIRING_INVALID_HANDLE)
    );
    assert_eq!(state.destroy(runtime), SAS_PAIRING_OK);
    drop((a, b, a2));
    peer.release();
}

// --- SAS presentation and decisions (Windows) -------------------------------------------------

/// The Responder's key is retained right after exposure while its SAS is already live: the
/// read-only presentation answers with the exact identity and decimal value (equal to the core's
/// and the peer's), repeatedly and unchanged, while every mutating action is `WRITE_PENDING`.
#[cfg(windows)]
#[test]
fn presentation_is_exact_and_read_only_also_while_a_write_is_pending() {
    let state = AbiState::new();
    let h = Harness::local(&state, b"p7-control-present");
    let peer = Node::new("p7-control-present-peer");
    let mut flow = responder_to_authorization(&h, &peer);
    let (connection, run) = (flow.connection, flow.run);
    assert_eq!(
        present(&h, connection, run),
        Ok(Presentation::ZERO),
        "no SAS before exposure"
    );
    assert_eq!(
        authorize(&h, connection, run).map(|action| action.event),
        Ok(SAS_PAIRING_LOCAL_EVENT_EXPOSURE_AUTHORIZED)
    );
    assert_eq!(
        expose(&h, connection, run),
        Ok(done(SAS_PAIRING_LOCAL_EVENT_KEY_EXPOSED, 0, WP, run))
    );
    // RESPONDER_KEY is retained, and the SAS is live.
    let presented = present(&h, connection, run).unwrap();
    // The peer has no SAS until it receives our key; compare with the core first.
    let (conn, exact) = (h.connection_ref(connection), h.run_ref(run).unwrap());
    let core = h
        .with_loop(|owner, _| owner.presentation(conn, &exact))
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(&presented.ceremony_identity, core.ceremony_identity());
    assert_eq!(presented.decimal.as_slice(), core.decimal().as_bytes());
    assert_eq!(presented.decimal.len(), SAS_DECIMAL_LEN);
    assert_eq!(present(&h, connection, run), Ok(presented), "unchanged");
    assert_eq!(
        decide(
            &h,
            connection,
            run,
            Decision::Approve,
            &presented.ceremony_identity
        ),
        Err(SAS_PAIRING_WRITE_PENDING)
    );
    wrote(&h, connection);
    assert_eq!(
        inbound(received(&mut flow.theirs)).0,
        HostEvent::ResponderKey
    );
    assert_presentation_is_exact(&h, &mut flow, &presented);
    assert_eq!(present(&h, connection, run), Ok(presented));
    assert_eq!(state.destroy(h.runtime), SAS_PAIRING_OK);
    drop(flow);
    peer.release();
}

/// A decision must name the exact presented `ceremony_identity`: another identity (one bit off,
/// the request ID, a handle's bytes, zeros) is `CEREMONY_IDENTITY_MISMATCH` and changes nothing;
/// the ABI substitutes nothing for it.
#[cfg(windows)]
#[test]
fn a_decision_must_name_the_exact_ceremony_identity() {
    let state = AbiState::new();
    let h = Harness::local(&state, b"p7-control-identity");
    let peer = Node::new("p7-control-identity-peer");
    let mut flow = initiator_to_authorization(&h, &peer);
    let presented = initiator_to_sas(&h, &peer, &mut flow);
    let (connection, run) = (flow.connection, flow.run);
    let identity = presented.ceremony_identity;
    let padded = |bytes: &[u8]| {
        let mut wrong = [0; 32];
        wrong[..bytes.len()].copy_from_slice(bytes);
        wrong
    };
    let mut flipped = identity;
    flipped[31] ^= 1;
    let request_id = h.run_ref(run).unwrap().request_id().to_vec();
    for wrong in [
        flipped,
        padded(&request_id),
        padded(&run.to_le_bytes()),
        padded(&connection.to_le_bytes()),
        [0; 32],
    ] {
        for decision in [Decision::Approve, Decision::Reject, Decision::Cancel] {
            assert_eq!(
                decide(&h, connection, run, decision, &wrong),
                Err(SAS_PAIRING_CEREMONY_IDENTITY_MISMATCH),
                "{decision:?}"
            );
        }
    }
    assert_eq!(
        present(&h, connection, run),
        Ok(presented),
        "nothing changed"
    );
    assert!(h.events(DriveMode::Drive).is_empty());
    assert_eq!(
        decide(&h, connection, run, Decision::Approve, &identity),
        Ok(done(SAS_PAIRING_LOCAL_EVENT_SAS_APPROVED, 0, 0, run))
    );
    assert_eq!(state.destroy(h.runtime), SAS_PAIRING_OK);
    drop(flow);
    peer.release();
}

/// Local MISMATCH and CANCEL end the run at once: `SAS_REJECTED`/`SAS_CANCELLED`, run `0`, the
/// handle invalid afterwards, the authenticated CANCEL (reason `0x01`/`0x02`) retained and
/// received by the peer, no result, and the spent opportunity never refunded by any teardown.
#[cfg(windows)]
#[test]
fn reject_and_cancel_end_the_run_without_a_refund() {
    for (decision, event, reason) in [
        (
            Decision::Reject,
            SAS_PAIRING_LOCAL_EVENT_SAS_REJECTED,
            CancelReason::UserRejection,
        ),
        (
            Decision::Cancel,
            SAS_PAIRING_LOCAL_EVENT_SAS_CANCELLED,
            CancelReason::UserCancellation,
        ),
    ] {
        let state = AbiState::new();
        let scope = format!("p7-control-end-{reason:?}");
        let h = Harness::local(&state, scope.as_bytes());
        let peer = Node::new(&format!("p7-control-end-{reason:?}-peer"));
        let mut flow = initiator_to_authorization(&h, &peer);
        let presented = initiator_to_sas(&h, &peer, &mut flow);
        let (connection, run) = (flow.connection, flow.run);
        assert_eq!(remaining(scope.as_bytes()), 9);
        assert_eq!(
            decide(&h, connection, run, decision, &presented.ceremony_identity),
            Ok(done(event, 0, WP, 0))
        );
        assert_eq!(h.run_ref(run), None, "the handle ended with the run");
        assert_eq!(
            present(&h, connection, run),
            Err(SAS_PAIRING_INVALID_HANDLE)
        );
        assert_eq!(
            decide(&h, connection, run, decision, &presented.ceremony_identity),
            Err(SAS_PAIRING_INVALID_HANDLE)
        );
        wrote(&h, connection);
        let (event, peer_run) = inbound(received(&mut flow.theirs));
        let HostEvent::Cancel(cancel) = event else {
            panic!("a CANCEL: {event:?}");
        };
        assert_eq!(cancel.reason(), reason);
        assert_eq!(peer_run, None);
        assert_eq!(status_of(&h), (SAS_PAIRING_AUTHORITY_READY, 9));
        assert_eq!(
            state.with_runtime(h.runtime, Admission::Data, |live| Ok(live.results.len())),
            Ok(0),
            "no result"
        );
        assert_eq!(h.close(connection), SAS_PAIRING_OK);
        assert_eq!(h.detach(), SAS_PAIRING_OK);
        assert_eq!(state.destroy_host(h.runtime, h.host), SAS_PAIRING_OK);
        assert_eq!(
            state.release_authority(h.runtime, h.authority),
            SAS_PAIRING_OK
        );
        assert_eq!(state.destroy(h.runtime), SAS_PAIRING_OK);
        assert_eq!(remaining(scope.as_bytes()), 9, "never refunded");
        let runtime = state.create().unwrap().get();
        let authority = state.register_authority(runtime, scope.as_bytes()).unwrap();
        assert_eq!(
            state.authority_status(runtime, authority.get()),
            Ok((SAS_PAIRING_AUTHORITY_READY, 9)),
            "the same process session"
        );
        assert_eq!(state.destroy(runtime), SAS_PAIRING_OK);
        drop(flow);
        peer.release();
    }
}

/// A local Responder run refuses the Initiator-only finish (`NOT_INITIATOR`) with no output; its
/// handle stays valid and the run continues.
#[cfg(windows)]
#[test]
fn a_responder_cannot_emit_the_initiator_finish() {
    let state = AbiState::new();
    let h = Harness::local(&state, b"p7-control-not-initiator");
    let peer = Node::new("p7-control-not-initiator-peer");
    let flow = responder_to_authorization(&h, &peer);
    let (connection, run) = (flow.connection, flow.run);
    assert_eq!(
        emit_finish(&h, connection, run),
        Err(SAS_PAIRING_NOT_INITIATOR)
    );
    assert!(h.run_ref(run).is_some());
    assert_eq!(
        authorize(&h, connection, run).map(|action| action.run),
        Ok(run),
        "still live"
    );
    assert_eq!(state.destroy(h.runtime), SAS_PAIRING_OK);
    drop(flow);
    peer.release();
}

// --- Deadlines found by an action (Windows) ---------------------------------------------------

/// A run whose own deadline expired before an action is ended by the core's deadline
/// processing, reported as a successfully executed call: `DEADLINE` with the exact kind, run
/// `0`, and `WRITE_PENDING` only when a timeout CANCEL was retained. The requested action did not
/// happen; the ABI computes no deadline itself. The run's ceremony clock is a test clock set at
/// the start (test seam).
#[cfg(windows)]
#[test]
fn a_deadline_found_by_an_action_is_a_deadline_event() {
    let state = AbiState::new();
    let scope = b"p7-control-deadline";
    let h = Harness::local(&state, scope);
    let peer = Node::new("p7-control-deadline-peer");
    fn clocked<'n>(h: &Harness<'_>, peer: &'n Node) -> (std::sync::Arc<ManualClock>, Flow<'n>) {
        let clock = ManualClock::new();
        let shared: Clock = clock.clone();
        START_CLOCK.set(Some(shared));
        let flow = initiator_to_authorization(h, peer);
        assert!(START_CLOCK.take().is_none(), "the seam was used");
        (clock, flow)
    }

    // Inactivity before exposure: nothing to cancel.
    let (clock, inactive) = clocked(&h, &peer);
    clock.advance(INACTIVITY_DEADLINE + Duration::from_secs(1));
    assert_eq!(
        authorize(&h, inactive.connection, inactive.run),
        Ok(done(
            SAS_PAIRING_LOCAL_EVENT_DEADLINE,
            SAS_PAIRING_DEADLINE_INACTIVITY_TIMEOUT,
            0,
            0
        ))
    );
    assert_eq!(h.run_ref(inactive.run), None);
    assert_eq!(remaining(scope), 10, "the authorization never happened");

    // An unusable clock.
    let (clock, unclocked) = clocked(&h, &peer);
    clock.fail();
    assert_eq!(
        authorize(&h, unclocked.connection, unclocked.run),
        Ok(done(
            SAS_PAIRING_LOCAL_EVENT_DEADLINE,
            SAS_PAIRING_DEADLINE_CLOCK_UNAVAILABLE,
            0,
            0
        ))
    );

    // The absolute deadline during the SAS comparison: the authenticated timeout CANCEL is
    // retained and reaches the peer.
    let (clock, mut absolute) = clocked(&h, &peer);
    let presented = initiator_to_sas(&h, &peer, &mut absolute);
    clock.advance(ABSOLUTE_DEADLINE + Duration::from_secs(1));
    assert_eq!(
        decide(
            &h,
            absolute.connection,
            absolute.run,
            Decision::Approve,
            &presented.ceremony_identity
        ),
        Ok(done(
            SAS_PAIRING_LOCAL_EVENT_DEADLINE,
            SAS_PAIRING_DEADLINE_ABSOLUTE_TIMEOUT,
            WP,
            0
        ))
    );
    assert_eq!(h.run_ref(absolute.run), None);
    wrote(&h, absolute.connection);
    let (event, _) = inbound(received(&mut absolute.theirs));
    let HostEvent::Cancel(cancel) = event else {
        panic!("a timeout CANCEL: {event:?}");
    };
    assert_eq!(cancel.reason(), CancelReason::Timeout);
    assert_eq!(remaining(scope), 9, "the exposed opportunity stays spent");
    assert_eq!(state.destroy(h.runtime), SAS_PAIRING_OK);
    drop((inactive, unclocked, absolute));
    peer.release();
}

// --- Stale runs and request-ID reuse (Windows) ------------------------------------------------

/// A run that ended without an event naming it keeps an honestly stale reference: the next
/// action reports `RUN_ENDED` and removes it, after which the handle names nothing. A
/// replacement run under the same request ID is never reachable through the old handle: the
/// exact run, not the request ID, is the target.
#[cfg(windows)]
#[test]
fn a_stale_run_reports_run_ended_and_never_reaches_a_replacement() {
    let state = AbiState::new();
    let h = Harness::local(&state, b"p7-control-stale");
    let mut client = TcpStream::connect(h.address).unwrap();
    let connection = h.next_event().connection;
    let changed = Bootstrap::new(
        b"p7-control-other-application".to_vec(),
        initiator_bootstrap().key_algorithm().to_vec(),
        initiator_bootstrap().public_key().to_vec(),
        initiator_bootstrap().shared_context().to_vec(),
    )
    .unwrap();

    // R1 ends by a run-local refusal (no event names it); its reference stays.
    let id = [0x91; 16];
    client.write_all(&start_frame(&id)).unwrap();
    let r1 = h.next_event().run;
    wrote(&h, connection);
    client
        .write_all(&start_frame_with(&id, changed.clone()))
        .unwrap();
    assert!(is_step(&h.next_event(), SAS_PAIRING_STEP_REFUSED, 0));
    assert!(h.run_ref(r1).is_some(), "honestly stale");
    assert_eq!(
        authorize(&h, connection, r1),
        Err(SAS_PAIRING_RUN_ENDED),
        "the exact run is gone"
    );
    assert_eq!(h.run_ref(r1), None, "removed by that call");
    assert_eq!(
        authorize(&h, connection, r1),
        Err(SAS_PAIRING_INVALID_HANDLE)
    );
    assert_eq!(present(&h, connection, r1), Err(SAS_PAIRING_INVALID_HANDLE));

    // R2 ends the same way, and its replacement R3 under the same request ID is admitted by a
    // test-side drive the ABI does not convert, so R2's reference is still mapped while R3 is
    // live: the old handle still reaches nothing.
    let id = [0x92; 16];
    client.write_all(&start_frame(&id)).unwrap();
    let r2 = h.next_event().run;
    let old = h.run_ref(r2).unwrap();
    wrote(&h, connection);
    client.write_all(&start_frame_with(&id, changed)).unwrap();
    assert!(is_step(&h.next_event(), SAS_PAIRING_STEP_REFUSED, 0));
    client.write_all(&start_frame(&id)).unwrap();
    let conn = h.connection_ref(connection);
    let replacement = crate::windows_tcp::tests::until(|| {
        let step = h.with_loop(|owner, _| owner.drive_once()).unwrap();
        step.events.into_iter().next().map(|event| match event {
            crate::windows_owner_loop::OwnerEvent::Step(_, step) => match step.event {
                Some(crate::windows_tcp::TcpEvent::Inbound {
                    run: Some(run),
                    event: HostEvent::StartAccepted,
                    ..
                }) => run,
                other => panic!("unexpected {other:?}"),
            },
            other => panic!("unexpected {other:?}"),
        })
    });
    assert_eq!(replacement.request_id(), old.request_id());
    assert_ne!(replacement, old);
    // The replacement's ACCEPT is written by an ABI drive (a WRITTEN step names no run).
    wrote(&h, connection);
    assert_eq!(h.run_ref(r2), Some(old), "still mapped, stale");
    assert_eq!(
        authorize(&h, connection, r2),
        Err(SAS_PAIRING_RUN_ENDED),
        "never the replacement"
    );
    assert_eq!(
        h.with_loop(|owner, _| owner.presentation(conn, &replacement)),
        Ok(Ok(None)),
        "the replacement is live and untouched"
    );
    assert_eq!(state.destroy(h.runtime), SAS_PAIRING_OK);
}

// --- Connection and owner-loop endings (Windows) ----------------------------------------------

/// A local start on a connection whose transport lifetime already expired ends that connection
/// in the host: `CONNECTION_ENDED`, its handle invalid, its sibling untouched.
#[cfg(windows)]
#[test]
fn a_local_action_that_ends_its_connection_invalidates_its_handles() {
    let state = AbiState::new();
    let h = Harness::local(&state, b"p7-control-connection-ended");
    let _silent = TcpStream::connect(h.address).unwrap();
    let silent = h.next_event().connection;
    let mut sibling_client = TcpStream::connect(h.address).unwrap();
    let sibling = h.next_event().connection;
    sibling_client.write_all(&start_frame(&[0xA1; 16])).unwrap();
    let sibling_run = h.next_event().run;
    wrote(&h, sibling);
    // The silent connection never sent its first frame; no drive runs while it expires.
    thread::sleep(FIRST_FRAME_DEADLINE + Duration::from_millis(200));
    assert_eq!(local_start(&h, silent), Err(SAS_PAIRING_CONNECTION_ENDED));
    assert_eq!(local_start(&h, silent), Err(SAS_PAIRING_INVALID_HANDLE));
    assert_eq!(h.close(silent), SAS_PAIRING_INVALID_HANDLE);
    assert_eq!(h.counts(), (1, 1), "the sibling and its run are untouched");
    assert!(h.run_ref(sibling_run).is_some());
    assert!(!state.fatal.is_set());
    assert_eq!(state.destroy(h.runtime), SAS_PAIRING_OK);
}

/// Seams rewrite a real action's outcome after it ran, with the real owner loop: a connection
/// ending removes exactly that connection and every run of it; an uncertain cleanup or a loop
/// that had failed closed removes every reference of the host; outcomes the core never
/// produces (an impossible loop refusal, a different live run, a start without a run, a
/// session-ending refusal reported as run-local, an unusable presentation) are fatal.
#[cfg(windows)]
#[test]
fn owner_loop_endings_and_broken_invariants_are_reported_exactly() {
    fn end_connection(
        owner: &mut WindowsOwnerLoop<'static>,
        connection: crate::windows_owner_loop::ConnectionRef,
        outcome: &mut Result<Result<Acted, Refused>, OwnerLoopError>,
    ) {
        assert!(outcome.is_ok());
        assert_eq!(owner.close_connection(connection), Ok(()));
        *outcome = Err(OwnerLoopError::Connection(TcpError::PeerClosed));
    }
    fn fail_uncertain(
        owner: &mut WindowsOwnerLoop<'static>,
        _: crate::windows_owner_loop::ConnectionRef,
        outcome: &mut Result<Result<Acted, Refused>, OwnerLoopError>,
    ) {
        assert_eq!(owner.close(), Ok(()));
        *outcome = Err(OwnerLoopError::OwnershipUncertain);
    }
    fn fail_closed(
        owner: &mut WindowsOwnerLoop<'static>,
        _: crate::windows_owner_loop::ConnectionRef,
        outcome: &mut Result<Result<Acted, Refused>, OwnerLoopError>,
    ) {
        assert_eq!(owner.close(), Ok(()));
        *outcome = Err(OwnerLoopError::Closed);
    }
    // Each scenario: two connections, the first with two runs.
    fn scenario<'s>(state: &'s AbiState, scope: &str) -> (Harness<'s>, Vec<TcpStream>, [u64; 4]) {
        let h = Harness::local(state, scope.as_bytes());
        let mut clients = Vec::new();
        clients.push(TcpStream::connect(h.address).unwrap());
        let first = h.next_event().connection;
        clients.push(TcpStream::connect(h.address).unwrap());
        let second = h.next_event().connection;
        let mut runs = Vec::new();
        for id in [[0xB1; 16], [0xB2; 16]] {
            clients[0].write_all(&start_frame(&id)).unwrap();
            runs.push(h.next_event().run);
            wrote(&h, first);
        }
        (h, clients, [first, second, runs[0], runs[1]])
    }

    // A terminal decision whose best-effort CANCEL could not be built: the core reports it
    // with no output, and the record says so (no flag) while the run handle ends. The core's
    // CANCEL construction cannot fail on demand, so the seam presents that outcome after a real
    // action ended the run in the core.
    fn rejected_without_cancel(
        _: &mut WindowsOwnerLoop<'static>,
        _: crate::windows_owner_loop::ConnectionRef,
        outcome: &mut Result<Result<Acted, Refused>, OwnerLoopError>,
    ) {
        assert!(matches!(outcome, Ok(Err(Refused::Run(_)))), "{outcome:?}");
        *outcome = Ok(Ok(Acted {
            run: None,
            event: LocalEvent::SasRejected,
            write_pending: false,
        }));
    }
    let state = AbiState::new();
    let (h, _clients, [first, _, r1, r2]) = scenario(&state, "p7-control-seam-not-emitted");
    ACTION_FAULT.set(Some(rejected_without_cancel));
    assert_eq!(
        authorize(&h, first, r1),
        Ok(done(SAS_PAIRING_LOCAL_EVENT_SAS_REJECTED, 0, 0, 0))
    );
    assert_eq!(h.run_ref(r1), None, "the run handle ended");
    assert!(h.run_ref(r2).is_some());
    assert_eq!(state.destroy(h.runtime), SAS_PAIRING_OK);

    let state = AbiState::new();
    let (h, _clients, [first, second, r1, r2]) = scenario(&state, "p7-control-seam-end");
    ACTION_FAULT.set(Some(end_connection));
    assert_eq!(local_start(&h, first), Err(SAS_PAIRING_CONNECTION_ENDED));
    for run in [r1, r2] {
        assert_eq!(present(&h, first, run), Err(SAS_PAIRING_INVALID_HANDLE));
    }
    assert_eq!(
        h.counts(),
        (1, 0),
        "only that connection and its runs ended"
    );
    assert_eq!(local_start(&h, second).map(|action| action.event), Ok(1));
    assert!(!state.fatal.is_set());
    assert_eq!(state.destroy(h.runtime), SAS_PAIRING_OK);

    for (fault, status, scope) in [
        (
            fail_uncertain as hosting_fault::Action,
            SAS_PAIRING_OWNERSHIP_UNCERTAIN,
            "p7-control-seam-uncertain",
        ),
        (
            fail_closed,
            SAS_PAIRING_OWNER_LOOP_CLOSED,
            "p7-control-seam-closed",
        ),
    ] {
        let state = AbiState::new();
        let (h, _clients, [first, second, r1, _]) = scenario(&state, scope);
        ACTION_FAULT.set(Some(fault));
        assert_eq!(authorize(&h, first, r1), Err(status));
        assert_eq!(h.counts(), (0, 0), "every reference of the host ended");
        assert_eq!(present(&h, second, 0), Err(SAS_PAIRING_INVALID_HANDLE));
        assert_eq!(
            h.call(DriveMode::Drive, MAX_DRIVE_EVENTS),
            (SAS_PAIRING_OK, Vec::new(), 0, SAS_PAIRING_OWNER_LOOP_CLOSED)
        );
        assert!(!state.fatal.is_set());
        assert_eq!(h.detach(), SAS_PAIRING_OK);
        assert_eq!(state.destroy(h.runtime), SAS_PAIRING_OK);
    }

    // Outcomes the core never produces are fatal, never an ordinary status.
    fn impossible(error: OwnerLoopError) -> hosting_fault::Action {
        match error {
            OwnerLoopError::UnknownConnection => |_, _, outcome| {
                *outcome = Err(OwnerLoopError::UnknownConnection);
            },
            OwnerLoopError::Poll(_) => |_, _, outcome| *outcome = Err(OwnerLoopError::Poll(1)),
            _ => |_, _, outcome| {
                *outcome = Err(OwnerLoopError::ListenerIo(std::io::ErrorKind::Other));
            },
        }
    }
    fn other_run(
        _: &mut WindowsOwnerLoop<'static>,
        _: crate::windows_owner_loop::ConnectionRef,
        outcome: &mut Result<Result<Acted, Refused>, OwnerLoopError>,
    ) {
        *outcome = Ok(Ok(Acted {
            run: OTHER_RUN.with(|other| other.borrow().clone()),
            event: LocalEvent::ExposureAuthorized,
            write_pending: false,
        }));
    }
    fn no_run(
        _: &mut WindowsOwnerLoop<'static>,
        _: crate::windows_owner_loop::ConnectionRef,
        outcome: &mut Result<Result<Acted, Refused>, OwnerLoopError>,
    ) {
        let Ok(Ok(acted)) = outcome else {
            panic!("an applied start")
        };
        acted.run = None;
    }
    fn session_refusal(
        _: &mut WindowsOwnerLoop<'static>,
        _: crate::windows_owner_loop::ConnectionRef,
        outcome: &mut Result<Result<Acted, Refused>, OwnerLoopError>,
    ) {
        *outcome = Ok(Err(Refused::Run(RouteError::UnknownSession)));
    }
    fn start_event(
        _: &mut WindowsOwnerLoop<'static>,
        _: crate::windows_owner_loop::ConnectionRef,
        outcome: &mut Result<Result<Acted, Refused>, OwnerLoopError>,
    ) {
        *outcome = Ok(Ok(Acted {
            run: None,
            event: LocalEvent::InitiatorStarted,
            write_pending: false,
        }));
    }
    thread_local! {
        static OTHER_RUN: std::cell::RefCell<Option<RunRef>> =
            const { std::cell::RefCell::new(None) };
    }
    enum Call {
        Start,
        Authorize,
        Present,
    }
    let cases: Vec<(&str, Call, Option<hosting_fault::Action>)> = vec![
        (
            "unknown",
            Call::Authorize,
            Some(impossible(OwnerLoopError::UnknownConnection)),
        ),
        (
            "poll",
            Call::Authorize,
            Some(impossible(OwnerLoopError::Poll(1))),
        ),
        (
            "listener",
            Call::Start,
            Some(impossible(OwnerLoopError::ListenerIo(
                std::io::ErrorKind::Other,
            ))),
        ),
        ("other-run", Call::Authorize, Some(other_run)),
        ("start-event", Call::Authorize, Some(start_event)),
        ("no-run", Call::Start, Some(no_run)),
        ("session", Call::Authorize, Some(session_refusal)),
        ("session-start", Call::Start, Some(session_refusal)),
        ("present-session", Call::Present, None),
    ];
    for (name, call, fault) in cases {
        let state = AbiState::new();
        let (h, _clients, [first, _, r1, r2]) = scenario(&state, &format!("p7-control-bad-{name}"));
        OTHER_RUN.with(|other| *other.borrow_mut() = h.run_ref(r2));
        if let Some(fault) = fault {
            ACTION_FAULT.set(Some(fault));
        } else {
            PRESENTATION_FAULT.set(Some(|_, _, outcome| {
                *outcome = Ok(Err(RouteError::SessionProtocolFailure));
            }));
        }
        let status = match call {
            Call::Start => local_start(&h, first).map(|_| ()),
            Call::Authorize => authorize(&h, first, r1).map(|_| ()),
            Call::Present => present(&h, first, r1).map(|_| ()),
        };
        assert_eq!(status, Err(SAS_PAIRING_FATAL), "{name}");
        assert!(state.fatal.is_set(), "{name}");
        assert_eq!(state.destroy(h.runtime), SAS_PAIRING_OK, "cleanup");
    }
}

/// Short names for the seam function types.
#[cfg(windows)]
mod hosting_fault {
    pub(super) type Action = super::super::super::hosting::ActionFault;
}

// --- Fatal (Windows, test-local state) --------------------------------------------------------

/// After fatal every trusted local action and presentation is refused before any handle check
/// or owner-loop call; connection close and the rest of cleanup still work.
#[cfg(windows)]
#[test]
fn after_fatal_no_local_action_enters_the_core() {
    let state = AbiState::new();
    let h = Harness::local(&state, b"p7-control-fatal-local");
    let _client = TcpStream::connect(h.address).unwrap();
    let connection = h.next_event().connection;
    let run = local_start(&h, connection).unwrap().run;
    assert_eq!(
        contain(&state.fatal, SAS_PAIRING_FATAL, || -> i32 {
            panic!("injected panic")
        }),
        SAS_PAIRING_FATAL
    );
    let actions = LOCAL_ACTIONS.get();
    for (connection, run) in [(connection, run), (0, 0), (connection + 99, run + 99)] {
        assert_eq!(local_start(&h, connection), Err(SAS_PAIRING_FATAL));
        for request in [
            Request::AuthorizeExposure,
            Request::ExposeKey,
            Request::EmitBootstrapMac,
            Request::EmitInitiatorFinish,
            Request::Decide(Decision::Approve, [1; 32]),
            Request::Decide(Decision::Reject, [1; 32]),
            Request::Decide(Decision::Cancel, [1; 32]),
        ] {
            assert_eq!(act(&h, connection, run, request), Err(SAS_PAIRING_FATAL));
        }
        assert_eq!(present(&h, connection, run), Err(SAS_PAIRING_FATAL));
    }
    assert_eq!(
        LOCAL_ACTIONS.get(),
        actions,
        "the owner loop was never entered"
    );
    assert_eq!(h.close(connection), SAS_PAIRING_OK, "cleanup");
    assert_eq!(h.detach(), SAS_PAIRING_OK);
    assert_eq!(state.destroy(h.runtime), SAS_PAIRING_OK);
    assert!(state.fatal.is_set());
}

// --- Complete ceremonies on the public ABI (Windows, children) --------------------------------

/// A complete Initiator ceremony whose local side uses only the real exports: one explicit call
/// per step, nothing chained (MATCH sends nothing, BOOTSTRAP_MAC does not emit the finish),
/// idempotent repeats produce nothing new, one run handle throughout, one opportunity spent,
/// and the result appears only in the drive whose own write completed the final ACK. The peer
/// then has no result yet (local completion only).
#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by the_initiator_ceremony_runs_on_the_public_abi"]
fn child_initiator_flow() {
    if !is_child("control::child_initiator_flow") {
        return;
    }
    let scope = b"p7-control-initiator-flow";
    let (_, runtime) = create();
    let h = Harness::new(&PROCESS, true, runtime, scope);
    let peer = Node::new("p7-control-initiator-flow-peer");
    let mut flow = initiator_to_authorization(&h, &peer);
    let presented = initiator_to_sas(&h, &peer, &mut flow);
    let (connection, run) = (flow.connection, flow.run);
    assert_eq!(remaining(scope), 9);
    assert_presentation_is_exact(&h, &mut flow, &presented);
    let identity = presented.ceremony_identity;

    // MATCH sends nothing and never emits BOOTSTRAP_MAC.
    assert_eq!(
        decide(&h, connection, run, Decision::Approve, &identity),
        Ok(done(SAS_PAIRING_LOCAL_EVENT_SAS_APPROVED, 0, 0, run))
    );
    assert!(h.events(DriveMode::Drive).is_empty());
    quiet(&mut flow.theirs);
    assert_eq!(
        decide(&h, connection, run, Decision::Approve, &identity),
        Ok(done(
            SAS_PAIRING_LOCAL_EVENT_SAS_ALREADY_APPROVED,
            0,
            0,
            run
        ))
    );
    assert_eq!(
        present(&h, connection, run),
        Ok(Presentation::ZERO),
        "withdrawn by the local approval"
    );
    // Own BOOTSTRAP_MAC once.
    assert_eq!(
        emit_mac(&h, connection, run),
        Ok(done(
            SAS_PAIRING_LOCAL_EVENT_BOOTSTRAP_MAC_EMITTED,
            0,
            WP,
            run
        ))
    );
    assert_eq!(
        emit_mac(&h, connection, run),
        Err(SAS_PAIRING_WRITE_PENDING)
    );
    wrote(&h, connection);
    assert_eq!(
        emit_mac(&h, connection, run),
        Ok(done(
            SAS_PAIRING_LOCAL_EVENT_BOOTSTRAP_MAC_ALREADY_EMITTED,
            0,
            0,
            run
        ))
    );
    assert!(h.events(DriveMode::Drive).is_empty(), "no second MAC");
    assert_eq!(
        inbound(received(&mut flow.theirs)).0,
        HostEvent::BootstrapMac(crate::ceremony::PeerApproval::Authenticated)
    );
    quiet(&mut flow.theirs);
    // The peer approves; its MAC arrives. Nothing emits the finish on its own.
    acted(flow.theirs.approve_sas(&flow.peer_run, &identity));
    acted(flow.theirs.emit_bootstrap_mac(&flow.peer_run));
    assert_eq!(sent(&mut flow.theirs), written());
    let mac = h.next_event();
    assert!(is_step(
        &mac,
        SAS_PAIRING_STEP_INBOUND,
        SAS_PAIRING_PROTOCOL_EVENT_BOOTSTRAP_MAC_AUTHENTICATED
    ));
    assert_eq!(mac.run, run);
    assert!(h.events(DriveMode::Drive).is_empty(), "no automatic finish");
    quiet(&mut flow.theirs);
    // INITIATOR_FINISH once.
    assert_eq!(
        emit_finish(&h, connection, run),
        Ok(done(
            SAS_PAIRING_LOCAL_EVENT_INITIATOR_FINISH_EMITTED,
            0,
            WP,
            run
        ))
    );
    assert_eq!(
        emit_finish(&h, connection, run),
        Err(SAS_PAIRING_WRITE_PENDING)
    );
    wrote(&h, connection);
    assert_eq!(
        emit_finish(&h, connection, run),
        Ok(done(
            SAS_PAIRING_LOCAL_EVENT_INITIATOR_FINISH_ALREADY_EMITTED,
            0,
            0,
            run
        ))
    );
    assert_eq!(
        inbound(received(&mut flow.theirs)).0,
        HostEvent::InitiatorFinish
    );
    assert_eq!(sent(&mut flow.theirs), written());
    // RESPONDER_FINISH_ACK: the final ACK is retained; no result yet.
    let ack = h.next_event();
    assert!(is_step(
        &ack,
        SAS_PAIRING_STEP_INBOUND,
        SAS_PAIRING_PROTOCOL_EVENT_RESPONDER_FINISH_ACK
    ));
    assert_eq!(
        (ack.run, ack.result, ack.flags),
        (run, 0, SAS_PAIRING_EVENT_FLAG_WRITE_PENDING)
    );
    assert_eq!(
        emit_finish(&h, connection, run),
        Err(SAS_PAIRING_WRITE_PENDING),
        "nothing can act while the final ACK is retained"
    );
    // The adapter confirms the final ACK itself, after writing all of it.
    let confirmed = h.next_event();
    assert!(is_step(&confirmed, SAS_PAIRING_STEP_CONFIRMED, 0));
    assert_eq!(confirmed.run, 0);
    assert_ne!(confirmed.result, 0);
    let core = assert_result_matches_core(&h, confirmed.result);
    assert_eq!(core.ceremony_identity(), &identity);
    assert_eq!(core.peer_role(), crate::Role::Responder);
    assert_eq!(
        emit_finish(&h, connection, run),
        Err(SAS_PAIRING_INVALID_HANDLE),
        "the completed run's handle ended"
    );
    assert_eq!(peer.routes(), 1, "the peer has no result yet");
    assert_eq!(remaining(scope), 9, "exactly one opportunity");
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
    assert_eq!(remaining(scope), 9);
    assert!(!PROCESS.fatal.is_set());
    drop(flow);
    peer.release();
}

#[cfg(windows)]
#[test]
fn the_initiator_ceremony_runs_on_the_public_abi() {
    run_child("control::child_initiator_flow");
}

/// A complete Responder ceremony whose local side uses only the real exports: the run handle
/// from START_ACCEPTED, authorization, exposure (the presentation answers while the key is
/// retained), MATCH, own BOOTSTRAP_MAC; the Initiator-only finish is refused; the completion
/// messages are handled by the drive alone, and the result appears with the verified final ACK.
#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by the_responder_ceremony_runs_on_the_public_abi"]
fn child_responder_flow() {
    if !is_child("control::child_responder_flow") {
        return;
    }
    let scope = b"p7-control-responder-flow";
    let (_, runtime) = create();
    let h = Harness::new(&PROCESS, true, runtime, scope);
    let peer = Node::new("p7-control-responder-flow-peer");
    let mut flow = responder_to_authorization(&h, &peer);
    let (connection, run) = (flow.connection, flow.run);
    assert_eq!(
        authorize(&h, connection, run),
        Ok(done(SAS_PAIRING_LOCAL_EVENT_EXPOSURE_AUTHORIZED, 0, 0, run))
    );
    assert_eq!(remaining(scope), 10);
    assert_eq!(
        expose(&h, connection, run),
        Ok(done(SAS_PAIRING_LOCAL_EVENT_KEY_EXPOSED, 0, WP, run))
    );
    assert_eq!(remaining(scope), 9);
    let presented = present(&h, connection, run).unwrap();
    assert_eq!(presented.available, 1, "readable while the key is retained");
    wrote(&h, connection);
    assert_eq!(
        inbound(received(&mut flow.theirs)).0,
        HostEvent::ResponderKey
    );
    assert_presentation_is_exact(&h, &mut flow, &presented);
    let identity = presented.ceremony_identity;
    acted(flow.theirs.approve_sas(&flow.peer_run, &identity));
    acted(flow.theirs.emit_bootstrap_mac(&flow.peer_run));
    assert_eq!(sent(&mut flow.theirs), written());
    let mac = h.next_event();
    assert!(is_step(
        &mac,
        SAS_PAIRING_STEP_INBOUND,
        SAS_PAIRING_PROTOCOL_EVENT_BOOTSTRAP_MAC_AUTHENTICATED
    ));
    assert_eq!(
        decide(&h, connection, run, Decision::Approve, &identity),
        Ok(done(SAS_PAIRING_LOCAL_EVENT_SAS_APPROVED, 0, 0, run))
    );
    assert_eq!(
        emit_finish(&h, connection, run),
        Err(SAS_PAIRING_NOT_INITIATOR)
    );
    assert_eq!(
        emit_mac(&h, connection, run),
        Ok(done(
            SAS_PAIRING_LOCAL_EVENT_BOOTSTRAP_MAC_EMITTED,
            0,
            WP,
            run
        ))
    );
    wrote(&h, connection);
    assert_eq!(
        inbound(received(&mut flow.theirs)).0,
        HostEvent::BootstrapMac(crate::ceremony::PeerApproval::Authenticated)
    );
    acted(flow.theirs.emit_initiator_finish(&flow.peer_run));
    assert_eq!(sent(&mut flow.theirs), written());
    let finish = h.next_event();
    assert!(is_step(
        &finish,
        SAS_PAIRING_STEP_INBOUND,
        SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH
    ));
    assert_eq!(
        (finish.run, finish.result, finish.flags),
        (run, 0, SAS_PAIRING_EVENT_FLAG_WRITE_PENDING),
        "RESPONDER_FINISH_ACK is retained; no result yet"
    );
    wrote(&h, connection);
    let step = received(&mut flow.theirs);
    assert!(step.write_pending);
    assert_eq!(inbound(step).0, HostEvent::ResponderFinishAck);
    let confirmed = crate::windows_tcp::tests::until(|| {
        let step = flow.theirs.on_writable().unwrap();
        step.event.is_some().then_some(step)
    });
    assert!(confirmed.result.is_some(), "the peer's own result");
    let done_event = h.next_event();
    assert!(is_step(
        &done_event,
        SAS_PAIRING_STEP_INBOUND,
        SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH_ACK
    ));
    assert_eq!(done_event.run, 0);
    assert_ne!(done_event.result, 0);
    let core = assert_result_matches_core(&h, done_event.result);
    assert_eq!(core.ceremony_identity(), &identity);
    assert_eq!(core.peer_role(), crate::Role::Initiator);
    assert_eq!(
        present(&h, connection, run),
        Err(SAS_PAIRING_INVALID_HANDLE)
    );
    assert_eq!(remaining(scope), 9);
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
    assert!(!PROCESS.fatal.is_set());
    drop(flow);
    peer.release();
}

#[cfg(windows)]
#[test]
fn the_responder_ceremony_runs_on_the_public_abi() {
    run_child("control::child_responder_flow");
}

// --- Races (Windows, child) -------------------------------------------------------------------

/// Local actions serialize with the drive and every teardown on the runtime slot, and two
/// actions on one run or connection serialize with each other: one runs first and the other
/// sees its result. No use-after-free, deadlock, or fatal.
#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by local_actions_serialize_with_drives_and_teardowns"]
fn child_local_action_races() {
    fn start(runtime: u64, host: u64, connection: u64) -> (i32, Action) {
        let local = initiator_bootstrap();
        let view = view_of(&local);
        let mut out = SENTINEL;
        // SAFETY: `view` borrows `local`, alive for the call; `out` is a live record.
        let status = unsafe {
            sas_pairing_connection_start_initiator(
                runtime,
                host,
                connection,
                &view,
                ptr::null(),
                &mut out,
            )
        };
        (status, out)
    }
    fn drive(runtime: u64, host: u64) -> i32 {
        let mut events = [Event::ZERO; MAX_DRIVE_EVENTS];
        let (mut count, mut failure) = (0, 0);
        // SAFETY: live, aligned, exclusive array and outputs.
        unsafe {
            sas_pairing_host_drive(
                runtime,
                host,
                events.as_mut_ptr(),
                events.len(),
                &mut count,
                &mut failure,
            )
        }
    }
    if !is_child("control::child_local_action_races") {
        return;
    }
    let (_, mut runtime) = create();
    for round in 0..6 {
        for teardown in 0..6 {
            let scope = format!("p7-control-race-{round}-{teardown}");
            let h = Harness::new(&PROCESS, true, runtime, scope.as_bytes());
            let _client = TcpStream::connect(h.address).unwrap();
            let connection = h.next_event().connection;
            let (host, authority) = (h.host, h.authority);
            let [(started, action), torn] = race_pair(
                round,
                move || start(runtime, host, connection),
                move || {
                    let status = match teardown {
                        0 => drive(runtime, host),
                        1 => sas_pairing_host_detach_listener(runtime, host),
                        2 => sas_pairing_connection_close(runtime, host, connection),
                        3 => host_destroy(runtime, host),
                        4 => release(runtime, authority),
                        _ => destroy(runtime),
                    };
                    (status, Action::ZERO)
                },
            );
            assert_eq!(torn.0, SAS_PAIRING_OK, "teardown {teardown}");
            let refused = match teardown {
                1 => SAS_PAIRING_LISTENER_NOT_ATTACHED,
                _ => SAS_PAIRING_INVALID_HANDLE,
            };
            if started == SAS_PAIRING_OK {
                assert_eq!(action.event, SAS_PAIRING_LOCAL_EVENT_INITIATOR_STARTED);
            } else {
                assert_ne!(teardown, 0, "a drive never refuses an action");
                assert_eq!(
                    (started, action),
                    (refused, Action::ZERO),
                    "teardown {teardown}"
                );
            }
            // Afterwards the teardown's state is what every later action sees.
            if teardown != 0 {
                assert_eq!(start(runtime, host, connection).0, refused);
            }
            match teardown {
                0..=2 => {
                    assert_eq!(host_destroy(runtime, host), SAS_PAIRING_OK);
                    assert_eq!(release(runtime, authority), SAS_PAIRING_OK);
                }
                3 => assert_eq!(release(runtime, authority), SAS_PAIRING_OK),
                4 => {}
                _ => runtime = create().1,
            }
        }
    }

    // Two actions on one connection or run: one first, the other sees its result.
    for round in 0..6 {
        let scope = format!("p7-control-race-pair-{round}");
        let h = Harness::new(&PROCESS, true, runtime, scope.as_bytes());
        let peer = Node::new(&format!("p7-control-race-pair-{round}-peer"));
        let (connection, theirs) = connect_peer(&h, &peer);
        let host = h.host;
        let both = race_pair(
            round,
            move || start(runtime, host, connection),
            move || start(runtime, host, connection),
        );
        let started: Vec<&(i32, Action)> = both.iter().filter(|(status, _)| *status == 0).collect();
        assert_eq!(started.len(), 1, "{both:?}");
        assert!(
            both.contains(&(SAS_PAIRING_WRITE_PENDING, Action::ZERO)),
            "{both:?}"
        );
        let run = started[0].1.run;
        assert_eq!(h.counts(), (1, 1), "one run, one handle");
        assert_eq!(
            h.run_ref(run).map(|exact| exact.request_id().len()),
            Some(16)
        );
        assert_eq!(
            sas_pairing_connection_close(runtime, host, connection),
            SAS_PAIRING_OK
        );
        drop(theirs);
        // Two authorizations of one run: the first records it, the second is refused.
        let flow = initiator_to_authorization(&h, &peer);
        let (c, r) = (flow.connection, flow.run);
        let pair = race_pair(
            round,
            move || {
                let mut out = SENTINEL;
                // SAFETY: a live record.
                let status =
                    unsafe { sas_pairing_run_authorize_exposure(runtime, host, c, r, &mut out) };
                (status, out.event)
            },
            move || {
                let mut out = SENTINEL;
                // SAFETY: a live record.
                let status =
                    unsafe { sas_pairing_run_authorize_exposure(runtime, host, c, r, &mut out) };
                (status, out.event)
            },
        );
        let mut outcomes = pair.to_vec();
        outcomes.sort_unstable();
        assert_eq!(
            outcomes,
            [
                (SAS_PAIRING_OK, SAS_PAIRING_LOCAL_EVENT_EXPOSURE_AUTHORIZED),
                (
                    SAS_PAIRING_CEREMONY_INVALID_STATE,
                    SAS_PAIRING_LOCAL_EVENT_INVALID
                ),
            ]
        );
        assert_eq!(remaining(scope.as_bytes()), 10);
        assert_eq!(host_destroy(runtime, host), SAS_PAIRING_OK);
        assert_eq!(release(runtime, h.authority), SAS_PAIRING_OK);
        drop(flow);
        peer.release();
    }
    assert!(!PROCESS.fatal.is_set());
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
}

#[cfg(windows)]
#[test]
fn local_actions_serialize_with_drives_and_teardowns() {
    run_child("control::child_local_action_races");
}
