//! Native ABI tests (P7.1 foundation; the P7.2 authority lifecycle is in `authority`, the P7.3
//! hosting contexts in `host`, the P7.4 listener ownership and owner-loop lifetime in
//! `listener`, the P7.5 network drive, connection, run, event, and result ABI in `network`, the
//! P7.6 trusted local ceremony actions and SAS presentation in `control`).
//!
//! Logic tests use test-local `AbiState`/`FatalState` instances. Tests of the real exports and
//! the process-global state run in isolated child processes (this test binary re-run with one
//! exact `#[ignore]`d child test), because the production fatal state can never be reset.

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    env, fs,
    mem::{align_of, offset_of},
    panic::panic_any,
    process::Command,
    ptr,
    sync::{
        Arc, Barrier,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use super::{
    ABI_VERSION, BootstrapView, BytesView, INVALID_ABI_VERSION, PROCESS, RuntimeHandle,
    authority::{
        AuthorityHandle, CORE_ENTRIES, SAS_PAIRING_AUTHORITY_BUSY, SAS_PAIRING_AUTHORITY_EXHAUSTED,
        SAS_PAIRING_AUTHORITY_READY, SAS_PAIRING_AUTHORITY_STATE_INVALID,
    },
    control::{self as control_abi, Action, Presentation},
    dispatch,
    hosting::{HostHandle, ROUTER_CONSTRUCTIONS},
    listener::{SAS_PAIRING_SOCKET_INVALID, SocketHandle},
    network::{self as drive_abi, ConnectionHandle, Event, RunHandle},
    panic_boundary::{FatalState, contain},
    result::{self as result_abi, ResultHandle, ResultInfo},
    runtime::{AbiState, HandleCounter},
    sas_pairing_abi_version, sas_pairing_authority_register, sas_pairing_authority_release,
    sas_pairing_authority_status, sas_pairing_connection_close,
    sas_pairing_connection_start_initiator, sas_pairing_host_attach_windows_listener,
    sas_pairing_host_create, sas_pairing_host_destroy, sas_pairing_host_detach_listener,
    sas_pairing_host_drive, sas_pairing_host_recheck_after_resume, sas_pairing_result_copy,
    sas_pairing_result_destroy, sas_pairing_result_info, sas_pairing_run_approve_sas,
    sas_pairing_run_authorize_exposure, sas_pairing_run_cancel_sas,
    sas_pairing_run_emit_bootstrap_mac, sas_pairing_run_emit_initiator_finish,
    sas_pairing_run_expose_key, sas_pairing_run_presentation, sas_pairing_run_reject_sas,
    sas_pairing_runtime_create, sas_pairing_runtime_destroy,
    status::*,
};

/// P7.2 authority lifecycle, error mapping, concurrency, and real-core panic tests.
mod authority;
/// P7.6 trusted local ceremony actions, SAS presentation, local-action statuses, races.
mod control;
/// P7.3 hosting contexts: host lifecycle, cascades, accounting neutrality, races.
mod host;
/// P7.4 Windows listener ownership, socket adoption, owner-loop lifetime bridge, races.
mod listener;
/// P7.5 bounded drive, connection and run references, events, results, races.
mod network;

const HEADER: &str = include_str!("../../include/sas_pairing.h");
const MANIFEST: &str = include_str!("../../Cargo.toml");
const ABI_SOURCES: [(&str, &str); 10] = [
    ("mod.rs", include_str!("mod.rs")),
    ("authority.rs", include_str!("authority.rs")),
    ("control.rs", include_str!("control.rs")),
    ("hosting.rs", include_str!("hosting.rs")),
    ("listener.rs", include_str!("listener.rs")),
    ("network.rs", include_str!("network.rs")),
    ("panic_boundary.rs", include_str!("panic_boundary.rs")),
    ("result.rs", include_str!("result.rs")),
    ("runtime.rs", include_str!("runtime.rs")),
    ("status.rs", include_str!("status.rs")),
];
const STATUSES: [(&str, i32); 48] = [
    ("SAS_PAIRING_OK", SAS_PAIRING_OK),
    ("SAS_PAIRING_INVALID_ARGUMENT", SAS_PAIRING_INVALID_ARGUMENT),
    ("SAS_PAIRING_INVALID_HANDLE", SAS_PAIRING_INVALID_HANDLE),
    (
        "SAS_PAIRING_ALREADY_INITIALIZED",
        SAS_PAIRING_ALREADY_INITIALIZED,
    ),
    (
        "SAS_PAIRING_HANDLES_EXHAUSTED",
        SAS_PAIRING_HANDLES_EXHAUSTED,
    ),
    ("SAS_PAIRING_INVALID_SCOPE", SAS_PAIRING_INVALID_SCOPE),
    (
        "SAS_PAIRING_ALREADY_REGISTERED",
        SAS_PAIRING_ALREADY_REGISTERED,
    ),
    (
        "SAS_PAIRING_OWNERSHIP_UNAVAILABLE",
        SAS_PAIRING_OWNERSHIP_UNAVAILABLE,
    ),
    (
        "SAS_PAIRING_UNSUPPORTED_PLATFORM",
        SAS_PAIRING_UNSUPPORTED_PLATFORM,
    ),
    (
        "SAS_PAIRING_OWNERSHIP_UNCERTAIN",
        SAS_PAIRING_OWNERSHIP_UNCERTAIN,
    ),
    ("SAS_PAIRING_BUSY", SAS_PAIRING_BUSY),
    ("SAS_PAIRING_EXHAUSTED", SAS_PAIRING_EXHAUSTED),
    ("SAS_PAIRING_RESOURCE_LIMITED", SAS_PAIRING_RESOURCE_LIMITED),
    (
        "SAS_PAIRING_MISSING_AUTHORIZATION",
        SAS_PAIRING_MISSING_AUTHORIZATION,
    ),
    (
        "SAS_PAIRING_STALE_AUTHORIZATION",
        SAS_PAIRING_STALE_AUTHORIZATION,
    ),
    ("SAS_PAIRING_TERMINATED", SAS_PAIRING_TERMINATED),
    (
        "SAS_PAIRING_INVALID_BOOTSTRAP",
        SAS_PAIRING_INVALID_BOOTSTRAP,
    ),
    ("SAS_PAIRING_RUN_ENDED", SAS_PAIRING_RUN_ENDED),
    ("SAS_PAIRING_WRITE_PENDING", SAS_PAIRING_WRITE_PENDING),
    (
        "SAS_PAIRING_CEREMONY_INVALID_STATE",
        SAS_PAIRING_CEREMONY_INVALID_STATE,
    ),
    ("SAS_PAIRING_NO_LIVE_SAS", SAS_PAIRING_NO_LIVE_SAS),
    (
        "SAS_PAIRING_CEREMONY_IDENTITY_MISMATCH",
        SAS_PAIRING_CEREMONY_IDENTITY_MISMATCH,
    ),
    (
        "SAS_PAIRING_NOT_LOCALLY_APPROVED",
        SAS_PAIRING_NOT_LOCALLY_APPROVED,
    ),
    (
        "SAS_PAIRING_UNEXPECTED_SENDER_ROLE",
        SAS_PAIRING_UNEXPECTED_SENDER_ROLE,
    ),
    (
        "SAS_PAIRING_INVALID_REQUEST_ID",
        SAS_PAIRING_INVALID_REQUEST_ID,
    ),
    (
        "SAS_PAIRING_REQUEST_ID_GENERATION_FAILED",
        SAS_PAIRING_REQUEST_ID_GENERATION_FAILED,
    ),
    (
        "SAS_PAIRING_REQUEST_ID_MISMATCH",
        SAS_PAIRING_REQUEST_ID_MISMATCH,
    ),
    (
        "SAS_PAIRING_SHARED_CONTEXT_MISMATCH",
        SAS_PAIRING_SHARED_CONTEXT_MISMATCH,
    ),
    (
        "SAS_PAIRING_EXPECTED_PEER_MISMATCH",
        SAS_PAIRING_EXPECTED_PEER_MISMATCH,
    ),
    (
        "SAS_PAIRING_APPROVALS_NOT_AUTHENTICATED",
        SAS_PAIRING_APPROVALS_NOT_AUTHENTICATED,
    ),
    ("SAS_PAIRING_NOT_INITIATOR", SAS_PAIRING_NOT_INITIATOR),
    (
        "SAS_PAIRING_TRANSCRIPT_MISMATCH",
        SAS_PAIRING_TRANSCRIPT_MISMATCH,
    ),
    ("SAS_PAIRING_COMPLETED", SAS_PAIRING_COMPLETED),
    (
        "SAS_PAIRING_NO_PENDING_FINAL_ACK",
        SAS_PAIRING_NO_PENDING_FINAL_ACK,
    ),
    (
        "SAS_PAIRING_FINAL_ACK_MISMATCH",
        SAS_PAIRING_FINAL_ACK_MISMATCH,
    ),
    (
        "SAS_PAIRING_CEREMONY_TIMED_OUT",
        SAS_PAIRING_CEREMONY_TIMED_OUT,
    ),
    (
        "SAS_PAIRING_CEREMONY_CLOCK_UNAVAILABLE",
        SAS_PAIRING_CEREMONY_CLOCK_UNAVAILABLE,
    ),
    ("SAS_PAIRING_PENDING_EXPIRED", SAS_PAIRING_PENDING_EXPIRED),
    (
        "SAS_PAIRING_CEREMONY_CODEC_ERROR",
        SAS_PAIRING_CEREMONY_CODEC_ERROR,
    ),
    (
        "SAS_PAIRING_CEREMONY_CRYPTO_ERROR",
        SAS_PAIRING_CEREMONY_CRYPTO_ERROR,
    ),
    ("SAS_PAIRING_BUFFER_TOO_SMALL", SAS_PAIRING_BUFFER_TOO_SMALL),
    (
        "SAS_PAIRING_LISTENER_ALREADY_ATTACHED",
        SAS_PAIRING_LISTENER_ALREADY_ATTACHED,
    ),
    (
        "SAS_PAIRING_LISTENER_SETUP_FAILED",
        SAS_PAIRING_LISTENER_SETUP_FAILED,
    ),
    (
        "SAS_PAIRING_LISTENER_NOT_ATTACHED",
        SAS_PAIRING_LISTENER_NOT_ATTACHED,
    ),
    (
        "SAS_PAIRING_OWNER_LOOP_CLOSED",
        SAS_PAIRING_OWNER_LOOP_CLOSED,
    ),
    (
        "SAS_PAIRING_NETWORK_POLL_FAILED",
        SAS_PAIRING_NETWORK_POLL_FAILED,
    ),
    ("SAS_PAIRING_CONNECTION_ENDED", SAS_PAIRING_CONNECTION_ENDED),
    ("SAS_PAIRING_FATAL", SAS_PAIRING_FATAL),
];
const AUTHORITY_STATES: [(&str, u32); 4] = [
    (
        "SAS_PAIRING_AUTHORITY_STATE_INVALID",
        SAS_PAIRING_AUTHORITY_STATE_INVALID,
    ),
    ("SAS_PAIRING_AUTHORITY_READY", SAS_PAIRING_AUTHORITY_READY),
    ("SAS_PAIRING_AUTHORITY_BUSY", SAS_PAIRING_AUTHORITY_BUSY),
    (
        "SAS_PAIRING_AUTHORITY_EXHAUSTED",
        SAS_PAIRING_AUTHORITY_EXHAUSTED,
    ),
];

/// Every typed event, result, and local-action constant (P7.5, P7.6): `(header name, C typedef,
/// Rust value)`.
fn typed_constants() -> Vec<(&'static str, &'static str, u32)> {
    use control_abi::*;
    use drive_abi::*;
    use result_abi::*;
    let kinds = [
        ("SAS_PAIRING_EVENT_INVALID", SAS_PAIRING_EVENT_INVALID),
        (
            "SAS_PAIRING_EVENT_CONNECTION_ACCEPTED",
            SAS_PAIRING_EVENT_CONNECTION_ACCEPTED,
        ),
        (
            "SAS_PAIRING_EVENT_ACCEPT_REFUSED",
            SAS_PAIRING_EVENT_ACCEPT_REFUSED,
        ),
        (
            "SAS_PAIRING_EVENT_LISTENER_DISABLED",
            SAS_PAIRING_EVENT_LISTENER_DISABLED,
        ),
        (
            "SAS_PAIRING_EVENT_CONNECTION_STEP",
            SAS_PAIRING_EVENT_CONNECTION_STEP,
        ),
        (
            "SAS_PAIRING_EVENT_CONNECTION_CLOSED",
            SAS_PAIRING_EVENT_CONNECTION_CLOSED,
        ),
    ];
    let steps = [
        ("SAS_PAIRING_STEP_NONE", SAS_PAIRING_STEP_NONE),
        ("SAS_PAIRING_STEP_INBOUND", SAS_PAIRING_STEP_INBOUND),
        ("SAS_PAIRING_STEP_REFUSED", SAS_PAIRING_STEP_REFUSED),
        ("SAS_PAIRING_STEP_DEADLINE", SAS_PAIRING_STEP_DEADLINE),
        ("SAS_PAIRING_STEP_WRITTEN", SAS_PAIRING_STEP_WRITTEN),
        ("SAS_PAIRING_STEP_CONFIRMED", SAS_PAIRING_STEP_CONFIRMED),
        ("SAS_PAIRING_STEP_UNCONFIRMED", SAS_PAIRING_STEP_UNCONFIRMED),
        ("SAS_PAIRING_STEP_DISCARDED", SAS_PAIRING_STEP_DISCARDED),
    ];
    let protocol = [
        (
            "SAS_PAIRING_PROTOCOL_EVENT_NONE",
            SAS_PAIRING_PROTOCOL_EVENT_NONE,
        ),
        (
            "SAS_PAIRING_PROTOCOL_EVENT_START_ACCEPTED",
            SAS_PAIRING_PROTOCOL_EVENT_START_ACCEPTED,
        ),
        (
            "SAS_PAIRING_PROTOCOL_EVENT_START_DUPLICATE",
            SAS_PAIRING_PROTOCOL_EVENT_START_DUPLICATE,
        ),
        (
            "SAS_PAIRING_PROTOCOL_EVENT_ACCEPT",
            SAS_PAIRING_PROTOCOL_EVENT_ACCEPT,
        ),
        (
            "SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_KEY",
            SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_KEY,
        ),
        (
            "SAS_PAIRING_PROTOCOL_EVENT_RESPONDER_KEY",
            SAS_PAIRING_PROTOCOL_EVENT_RESPONDER_KEY,
        ),
        (
            "SAS_PAIRING_PROTOCOL_EVENT_BOOTSTRAP_MAC_AUTHENTICATED",
            SAS_PAIRING_PROTOCOL_EVENT_BOOTSTRAP_MAC_AUTHENTICATED,
        ),
        (
            "SAS_PAIRING_PROTOCOL_EVENT_BOOTSTRAP_MAC_DUPLICATE",
            SAS_PAIRING_PROTOCOL_EVENT_BOOTSTRAP_MAC_DUPLICATE,
        ),
        (
            "SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH",
            SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH,
        ),
        (
            "SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH_DUPLICATE",
            SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH_DUPLICATE,
        ),
        (
            "SAS_PAIRING_PROTOCOL_EVENT_RESPONDER_FINISH_ACK",
            SAS_PAIRING_PROTOCOL_EVENT_RESPONDER_FINISH_ACK,
        ),
        (
            "SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH_ACK",
            SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH_ACK,
        ),
        (
            "SAS_PAIRING_PROTOCOL_EVENT_PEER_CANCEL",
            SAS_PAIRING_PROTOCOL_EVENT_PEER_CANCEL,
        ),
    ];
    let reasons = [
        (
            "SAS_PAIRING_EVENT_REASON_NONE",
            SAS_PAIRING_EVENT_REASON_NONE,
        ),
        (
            "SAS_PAIRING_EVENT_REASON_RESOURCE_LIMITED",
            SAS_PAIRING_EVENT_REASON_RESOURCE_LIMITED,
        ),
        (
            "SAS_PAIRING_EVENT_REASON_PEER_CLOSED",
            SAS_PAIRING_EVENT_REASON_PEER_CLOSED,
        ),
        (
            "SAS_PAIRING_EVENT_REASON_SOCKET_IO",
            SAS_PAIRING_EVENT_REASON_SOCKET_IO,
        ),
        (
            "SAS_PAIRING_EVENT_REASON_ABANDONED_PARTIAL_FRAME",
            SAS_PAIRING_EVENT_REASON_ABANDONED_PARTIAL_FRAME,
        ),
        (
            "SAS_PAIRING_EVENT_REASON_READINESS_FAILURE",
            SAS_PAIRING_EVENT_REASON_READINESS_FAILURE,
        ),
        (
            "SAS_PAIRING_EVENT_REASON_LISTENER_IO",
            SAS_PAIRING_EVENT_REASON_LISTENER_IO,
        ),
        (
            "SAS_PAIRING_EVENT_REASON_LISTENER_READINESS",
            SAS_PAIRING_EVENT_REASON_LISTENER_READINESS,
        ),
        (
            "SAS_PAIRING_EVENT_REASON_ROUTE_REFUSED",
            SAS_PAIRING_EVENT_REASON_ROUTE_REFUSED,
        ),
        (
            "SAS_PAIRING_EVENT_REASON_OWNERSHIP_UNCERTAIN",
            SAS_PAIRING_EVENT_REASON_OWNERSHIP_UNCERTAIN,
        ),
        (
            "SAS_PAIRING_EVENT_REASON_OTHER_HOST_FAILURE",
            SAS_PAIRING_EVENT_REASON_OTHER_HOST_FAILURE,
        ),
        (
            "SAS_PAIRING_EVENT_REASON_INVALID_FRAME",
            SAS_PAIRING_EVENT_REASON_INVALID_FRAME,
        ),
        (
            "SAS_PAIRING_EVENT_REASON_TRANSPORT_DEADLINE",
            SAS_PAIRING_EVENT_REASON_TRANSPORT_DEADLINE,
        ),
        (
            "SAS_PAIRING_EVENT_REASON_CLOCK_UNAVAILABLE",
            SAS_PAIRING_EVENT_REASON_CLOCK_UNAVAILABLE,
        ),
        (
            "SAS_PAIRING_EVENT_REASON_SESSION_PROTOCOL_FAILURE",
            SAS_PAIRING_EVENT_REASON_SESSION_PROTOCOL_FAILURE,
        ),
        (
            "SAS_PAIRING_EVENT_REASON_ALREADY_CLOSED",
            SAS_PAIRING_EVENT_REASON_ALREADY_CLOSED,
        ),
    ];
    let deadlines = [
        ("SAS_PAIRING_DEADLINE_NONE", SAS_PAIRING_DEADLINE_NONE),
        (
            "SAS_PAIRING_DEADLINE_ABSOLUTE_TIMEOUT",
            SAS_PAIRING_DEADLINE_ABSOLUTE_TIMEOUT,
        ),
        (
            "SAS_PAIRING_DEADLINE_INACTIVITY_TIMEOUT",
            SAS_PAIRING_DEADLINE_INACTIVITY_TIMEOUT,
        ),
        (
            "SAS_PAIRING_DEADLINE_PENDING_EXPIRED",
            SAS_PAIRING_DEADLINE_PENDING_EXPIRED,
        ),
        (
            "SAS_PAIRING_DEADLINE_CLOCK_UNAVAILABLE",
            SAS_PAIRING_DEADLINE_CLOCK_UNAVAILABLE,
        ),
    ];
    let cancel_states = [
        (
            "SAS_PAIRING_CANCEL_STATE_NONE",
            SAS_PAIRING_CANCEL_STATE_NONE,
        ),
        (
            "SAS_PAIRING_CANCEL_STATE_NOT_BUILT",
            SAS_PAIRING_CANCEL_STATE_NOT_BUILT,
        ),
        (
            "SAS_PAIRING_CANCEL_STATE_PENDING",
            SAS_PAIRING_CANCEL_STATE_PENDING,
        ),
        (
            "SAS_PAIRING_CANCEL_STATE_DROPPED",
            SAS_PAIRING_CANCEL_STATE_DROPPED,
        ),
    ];
    let cancel_reasons = [
        (
            "SAS_PAIRING_CANCEL_REASON_NONE",
            SAS_PAIRING_CANCEL_REASON_NONE,
        ),
        (
            "SAS_PAIRING_CANCEL_REASON_USER_REJECTION",
            SAS_PAIRING_CANCEL_REASON_USER_REJECTION,
        ),
        (
            "SAS_PAIRING_CANCEL_REASON_USER_CANCELLATION",
            SAS_PAIRING_CANCEL_REASON_USER_CANCELLATION,
        ),
        (
            "SAS_PAIRING_CANCEL_REASON_TIMEOUT",
            SAS_PAIRING_CANCEL_REASON_TIMEOUT,
        ),
        (
            "SAS_PAIRING_CANCEL_REASON_LOCAL_POLICY_FAILURE",
            SAS_PAIRING_CANCEL_REASON_LOCAL_POLICY_FAILURE,
        ),
    ];
    let flags = [
        (
            "SAS_PAIRING_EVENT_FLAG_WRITE_PENDING",
            SAS_PAIRING_EVENT_FLAG_WRITE_PENDING,
        ),
        (
            "SAS_PAIRING_EVENT_FLAG_RUN_UNTRACKED",
            SAS_PAIRING_EVENT_FLAG_RUN_UNTRACKED,
        ),
    ];
    let roles = [
        ("SAS_PAIRING_ROLE_INVALID", SAS_PAIRING_ROLE_INVALID),
        ("SAS_PAIRING_ROLE_INITIATOR", SAS_PAIRING_ROLE_INITIATOR),
        ("SAS_PAIRING_ROLE_RESPONDER", SAS_PAIRING_ROLE_RESPONDER),
    ];
    let fields = [
        (
            "SAS_PAIRING_RESULT_FIELD_REQUEST_ID",
            SAS_PAIRING_RESULT_FIELD_REQUEST_ID,
        ),
        (
            "SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_PEER_BOOTSTRAP",
            SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_PEER_BOOTSTRAP,
        ),
        (
            "SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_SHARED_CONTEXT",
            SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_SHARED_CONTEXT,
        ),
        (
            "SAS_PAIRING_RESULT_FIELD_PROFILE_IDENTIFIER",
            SAS_PAIRING_RESULT_FIELD_PROFILE_IDENTIFIER,
        ),
    ];
    let local_events = [
        (
            "SAS_PAIRING_LOCAL_EVENT_INVALID",
            SAS_PAIRING_LOCAL_EVENT_INVALID,
        ),
        (
            "SAS_PAIRING_LOCAL_EVENT_INITIATOR_STARTED",
            SAS_PAIRING_LOCAL_EVENT_INITIATOR_STARTED,
        ),
        (
            "SAS_PAIRING_LOCAL_EVENT_EXPOSURE_AUTHORIZED",
            SAS_PAIRING_LOCAL_EVENT_EXPOSURE_AUTHORIZED,
        ),
        (
            "SAS_PAIRING_LOCAL_EVENT_KEY_EXPOSED",
            SAS_PAIRING_LOCAL_EVENT_KEY_EXPOSED,
        ),
        (
            "SAS_PAIRING_LOCAL_EVENT_SAS_APPROVED",
            SAS_PAIRING_LOCAL_EVENT_SAS_APPROVED,
        ),
        (
            "SAS_PAIRING_LOCAL_EVENT_SAS_ALREADY_APPROVED",
            SAS_PAIRING_LOCAL_EVENT_SAS_ALREADY_APPROVED,
        ),
        (
            "SAS_PAIRING_LOCAL_EVENT_BOOTSTRAP_MAC_EMITTED",
            SAS_PAIRING_LOCAL_EVENT_BOOTSTRAP_MAC_EMITTED,
        ),
        (
            "SAS_PAIRING_LOCAL_EVENT_BOOTSTRAP_MAC_ALREADY_EMITTED",
            SAS_PAIRING_LOCAL_EVENT_BOOTSTRAP_MAC_ALREADY_EMITTED,
        ),
        (
            "SAS_PAIRING_LOCAL_EVENT_INITIATOR_FINISH_EMITTED",
            SAS_PAIRING_LOCAL_EVENT_INITIATOR_FINISH_EMITTED,
        ),
        (
            "SAS_PAIRING_LOCAL_EVENT_INITIATOR_FINISH_ALREADY_EMITTED",
            SAS_PAIRING_LOCAL_EVENT_INITIATOR_FINISH_ALREADY_EMITTED,
        ),
        (
            "SAS_PAIRING_LOCAL_EVENT_SAS_REJECTED",
            SAS_PAIRING_LOCAL_EVENT_SAS_REJECTED,
        ),
        (
            "SAS_PAIRING_LOCAL_EVENT_SAS_CANCELLED",
            SAS_PAIRING_LOCAL_EVENT_SAS_CANCELLED,
        ),
        (
            "SAS_PAIRING_LOCAL_EVENT_DEADLINE",
            SAS_PAIRING_LOCAL_EVENT_DEADLINE,
        ),
    ];
    let action_flags = [(
        "SAS_PAIRING_ACTION_FLAG_WRITE_PENDING",
        SAS_PAIRING_ACTION_FLAG_WRITE_PENDING,
    )];
    let mut all = Vec::new();
    for (typedef, table) in [
        ("sas_pairing_event_kind_t", &kinds[..]),
        ("sas_pairing_step_kind_t", &steps[..]),
        ("sas_pairing_protocol_event_t", &protocol[..]),
        ("sas_pairing_event_reason_t", &reasons[..]),
        ("sas_pairing_deadline_kind_t", &deadlines[..]),
        ("sas_pairing_cancel_state_t", &cancel_states[..]),
        ("sas_pairing_cancel_reason_t", &cancel_reasons[..]),
        ("sas_pairing_event_flags_t", &flags[..]),
        ("sas_pairing_role_t", &roles[..]),
        ("sas_pairing_result_field_t", &fields[..]),
        ("sas_pairing_local_event_t", &local_events[..]),
        ("sas_pairing_action_flags_t", &action_flags[..]),
    ] {
        // Each enumeration is dense from its first value and has no duplicate.
        let values: Vec<u32> = table.iter().map(|(_, value)| *value).collect();
        if typedef == "sas_pairing_event_flags_t" {
            assert_eq!(values, [0x1, 0x2]);
        } else if typedef == "sas_pairing_action_flags_t" {
            assert_eq!(values, [0x1], "no untracked-run flag for local actions");
        } else {
            let first = values[0];
            assert!(first <= 1, "{typedef}");
            assert!(
                values
                    .iter()
                    .zip(first..)
                    .all(|(value, expected)| *value == expected),
                "{typedef} values are frozen and dense: {values:?}"
            );
        }
        all.extend(table.iter().map(|(name, value)| (*name, typedef, *value)));
    }
    all
}

/// A panic payload whose destructor counts itself and then panics again (P6.4.1).
struct PanicOnDrop(&'static AtomicUsize);

impl Drop for PanicOnDrop {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
        panic!("PanicOnDrop destructor must never run");
    }
}

fn create_local(state: &AbiState) -> u64 {
    state.create().expect("create").get()
}

// --- ABI constants and header ---------------------------------------------------------------

#[test]
fn abi_constants_are_frozen() {
    assert_eq!(ABI_VERSION, 1);
    assert_eq!(INVALID_ABI_VERSION, 0);
    assert_eq!(
        STATUSES,
        [
            ("SAS_PAIRING_OK", 0),
            ("SAS_PAIRING_INVALID_ARGUMENT", 1),
            ("SAS_PAIRING_INVALID_HANDLE", 2),
            ("SAS_PAIRING_ALREADY_INITIALIZED", 3),
            ("SAS_PAIRING_HANDLES_EXHAUSTED", 4),
            ("SAS_PAIRING_INVALID_SCOPE", 100),
            ("SAS_PAIRING_ALREADY_REGISTERED", 101),
            ("SAS_PAIRING_OWNERSHIP_UNAVAILABLE", 102),
            ("SAS_PAIRING_UNSUPPORTED_PLATFORM", 103),
            ("SAS_PAIRING_OWNERSHIP_UNCERTAIN", 104),
            ("SAS_PAIRING_BUSY", 105),
            ("SAS_PAIRING_EXHAUSTED", 106),
            ("SAS_PAIRING_RESOURCE_LIMITED", 107),
            ("SAS_PAIRING_MISSING_AUTHORIZATION", 200),
            ("SAS_PAIRING_STALE_AUTHORIZATION", 201),
            ("SAS_PAIRING_TERMINATED", 202),
            ("SAS_PAIRING_INVALID_BOOTSTRAP", 203),
            ("SAS_PAIRING_RUN_ENDED", 204),
            ("SAS_PAIRING_WRITE_PENDING", 205),
            ("SAS_PAIRING_CEREMONY_INVALID_STATE", 206),
            ("SAS_PAIRING_NO_LIVE_SAS", 207),
            ("SAS_PAIRING_CEREMONY_IDENTITY_MISMATCH", 208),
            ("SAS_PAIRING_NOT_LOCALLY_APPROVED", 209),
            ("SAS_PAIRING_UNEXPECTED_SENDER_ROLE", 210),
            ("SAS_PAIRING_INVALID_REQUEST_ID", 211),
            ("SAS_PAIRING_REQUEST_ID_GENERATION_FAILED", 212),
            ("SAS_PAIRING_REQUEST_ID_MISMATCH", 213),
            ("SAS_PAIRING_SHARED_CONTEXT_MISMATCH", 214),
            ("SAS_PAIRING_EXPECTED_PEER_MISMATCH", 215),
            ("SAS_PAIRING_APPROVALS_NOT_AUTHENTICATED", 216),
            ("SAS_PAIRING_NOT_INITIATOR", 217),
            ("SAS_PAIRING_TRANSCRIPT_MISMATCH", 218),
            ("SAS_PAIRING_COMPLETED", 219),
            ("SAS_PAIRING_NO_PENDING_FINAL_ACK", 220),
            ("SAS_PAIRING_FINAL_ACK_MISMATCH", 221),
            ("SAS_PAIRING_CEREMONY_TIMED_OUT", 222),
            ("SAS_PAIRING_CEREMONY_CLOCK_UNAVAILABLE", 223),
            ("SAS_PAIRING_PENDING_EXPIRED", 224),
            ("SAS_PAIRING_CEREMONY_CODEC_ERROR", 225),
            ("SAS_PAIRING_CEREMONY_CRYPTO_ERROR", 226),
            ("SAS_PAIRING_BUFFER_TOO_SMALL", 300),
            ("SAS_PAIRING_LISTENER_ALREADY_ATTACHED", 400),
            ("SAS_PAIRING_LISTENER_SETUP_FAILED", 401),
            ("SAS_PAIRING_LISTENER_NOT_ATTACHED", 402),
            ("SAS_PAIRING_OWNER_LOOP_CLOSED", 403),
            ("SAS_PAIRING_NETWORK_POLL_FAILED", 404),
            ("SAS_PAIRING_CONNECTION_ENDED", 405),
            ("SAS_PAIRING_FATAL", 900),
        ]
    );
    let values: BTreeSet<i32> = STATUSES.iter().map(|(_, value)| *value).collect();
    assert_eq!(values.len(), STATUSES.len(), "no two statuses collide");
    assert_eq!(
        AUTHORITY_STATES,
        [
            ("SAS_PAIRING_AUTHORITY_STATE_INVALID", 0),
            ("SAS_PAIRING_AUTHORITY_READY", 1),
            ("SAS_PAIRING_AUTHORITY_BUSY", 2),
            ("SAS_PAIRING_AUTHORITY_EXHAUSTED", 3),
        ]
    );
    assert_eq!(size_of::<RuntimeHandle>(), 8);
    assert_eq!(size_of::<AuthorityHandle>(), 8);
    assert_eq!(size_of::<HostHandle>(), 8);
    assert_eq!(size_of::<ConnectionHandle>(), 8);
    assert_eq!(size_of::<RunHandle>(), 8);
    assert_eq!(size_of::<ResultHandle>(), 8);
    assert_eq!(size_of::<i32>(), 4);
    // `sas_pairing_socket_t` is `uintptr_t`; its invalid value is `UINTPTR_MAX` (Windows
    // `INVALID_SOCKET`, also checked at compile time on Windows).
    assert_eq!(size_of::<SocketHandle>(), size_of::<*const ()>());
    assert_eq!(SAS_PAIRING_SOCKET_INVALID, usize::MAX);
    // Zero is never a valid handle: destroy rejects it, and the counter never issues it.
    assert_eq!(
        AbiState::new().destroy(0),
        SAS_PAIRING_INVALID_HANDLE,
        "handle 0 must be invalid"
    );
}

/// The C layouts of the two input views: `{const uint8_t *data; size_t len;}` and four of them,
/// in declaration order, with no padding, aligned like a pointer.
#[test]
fn input_view_layouts_are_pinned() {
    let word = size_of::<usize>();
    assert_eq!(size_of::<*const u8>(), word);
    assert_eq!(size_of::<BytesView>(), 2 * word);
    assert_eq!(align_of::<BytesView>(), align_of::<usize>());
    assert_eq!(offset_of!(BytesView, data), 0);
    assert_eq!(offset_of!(BytesView, len), word);
    assert_eq!(size_of::<BootstrapView>(), 8 * word);
    assert_eq!(align_of::<BootstrapView>(), align_of::<usize>());
    assert_eq!(offset_of!(BootstrapView, application_identity), 0);
    assert_eq!(offset_of!(BootstrapView, key_algorithm), 2 * word);
    assert_eq!(offset_of!(BootstrapView, public_key), 4 * word);
    assert_eq!(offset_of!(BootstrapView, shared_context), 6 * word);
}

/// The event and result-info records foreign callers read as raw memory: fixed sizes, alignment,
/// and offsets on every supported target, and no padding (the fields fill each record exactly,
/// so no uninitialized byte can be observed).
#[test]
fn event_and_result_info_layouts_are_pinned() {
    assert_eq!(size_of::<Event>(), 128);
    assert_eq!(align_of::<Event>(), 8);
    let event_fields = [
        (offset_of!(Event, kind), 4),
        (offset_of!(Event, step_kind), 4),
        (offset_of!(Event, protocol_event), 4),
        (offset_of!(Event, reason), 4),
        (offset_of!(Event, deadline_kind), 4),
        (offset_of!(Event, cancel_state), 4),
        (offset_of!(Event, cancel_reason), 4),
        (offset_of!(Event, flags), 4),
        (offset_of!(Event, connection), 8),
        (offset_of!(Event, run), 8),
        (offset_of!(Event, result), 8),
        (offset_of!(Event, request_id_len), 4),
        (offset_of!(Event, reserved), 4),
        (offset_of!(Event, request_id), 64),
    ];
    let mut next = 0;
    for (offset, size) in event_fields {
        assert_eq!(offset, next, "fields are contiguous in declaration order");
        next += size;
    }
    assert_eq!(next, size_of::<Event>(), "no trailing padding");
    assert_eq!(offset_of!(Event, connection), 32);
    assert_eq!(offset_of!(Event, request_id), 64);

    assert_eq!(size_of::<ResultInfo>(), 56);
    assert_eq!(align_of::<ResultInfo>(), 4);
    let info_fields = [
        (offset_of!(ResultInfo, ceremony_identity), 32),
        (offset_of!(ResultInfo, peer_role), 4),
        (offset_of!(ResultInfo, profile_version), 4),
        (offset_of!(ResultInfo, request_id_len), 4),
        (offset_of!(ResultInfo, peer_bootstrap_len), 4),
        (offset_of!(ResultInfo, shared_context_len), 4),
        (offset_of!(ResultInfo, profile_identifier_len), 4),
    ];
    let mut next = 0;
    for (offset, size) in info_fields {
        assert_eq!(offset, next);
        next += size;
    }
    assert_eq!(next, size_of::<ResultInfo>());

    // The zero records are all zero bytes.
    // SAFETY: both are padding-free `repr(C)` records of integers and byte arrays, so every
    // byte is an initialized field byte.
    let (event, info) = unsafe {
        (
            std::slice::from_raw_parts(ptr::from_ref(&Event::ZERO).cast::<u8>(), 128),
            std::slice::from_raw_parts(ptr::from_ref(&ResultInfo::ZERO).cast::<u8>(), 56),
        )
    };
    assert!(event.iter().chain(info).all(|byte| *byte == 0));
}

/// The local-action and SAS-presentation records (P7-D-011, P7-D-012): fixed sizes, alignment,
/// and offsets, no padding, all-zero zero records, and the 14-byte decimal display.
#[test]
fn action_and_presentation_layouts_are_pinned() {
    assert_eq!(size_of::<Action>(), 24);
    assert_eq!(align_of::<Action>(), 8);
    let action_fields = [
        (offset_of!(Action, event), 4),
        (offset_of!(Action, deadline_kind), 4),
        (offset_of!(Action, flags), 4),
        (offset_of!(Action, reserved), 4),
        (offset_of!(Action, run), 8),
    ];
    let mut next = 0;
    for (offset, size) in action_fields {
        assert_eq!(offset, next, "fields are contiguous in declaration order");
        next += size;
    }
    assert_eq!(next, size_of::<Action>(), "no trailing padding");

    assert_eq!(control_abi::SAS_DECIMAL_LEN, 14);
    assert_eq!(control_abi::CEREMONY_IDENTITY_LEN, 32);
    assert_eq!(size_of::<Presentation>(), 56);
    assert_eq!(align_of::<Presentation>(), 4);
    let presentation_fields = [
        (offset_of!(Presentation, available), 4),
        (offset_of!(Presentation, reserved), 4),
        (offset_of!(Presentation, ceremony_identity), 32),
        (offset_of!(Presentation, decimal), 14),
        (offset_of!(Presentation, reserved_tail), 2),
    ];
    let mut next = 0;
    for (offset, size) in presentation_fields {
        assert_eq!(offset, next);
        next += size;
    }
    assert_eq!(next, size_of::<Presentation>());

    // SAFETY: both are padding-free `repr(C)` records of integers and byte arrays, so every
    // byte is an initialized field byte.
    let (action, presentation) = unsafe {
        (
            std::slice::from_raw_parts(ptr::from_ref(&Action::ZERO).cast::<u8>(), 24),
            std::slice::from_raw_parts(ptr::from_ref(&Presentation::ZERO).cast::<u8>(), 56),
        )
    };
    assert!(action.iter().chain(presentation).all(|byte| *byte == 0));

    // The display shape the core builds (`{first:04} {second:04} {third:04}`, each 1000-9191).
    let shape = |text: &str| control_abi::is_decimal_display(text.as_bytes().try_into().unwrap());
    for valid in ["1000 1000 1000", "9191 9191 9191", "4442 5768 1708"] {
        assert!(shape(valid), "{valid}");
    }
    for invalid in [
        "4442-5768-1708",
        "4442 5768 170x",
        " 4442 5768 170",
        "44425 768 1708",
    ] {
        assert!(!shape(invalid), "{invalid}");
    }
    assert_eq!(format!("{:04} {:04} {:04}", 1000, 9191, 4442).len(), 14);
}

/// The ABI production sources keep exactly the one P7-D-007 router lifetime extension, transmute
/// and leak nothing, start no thread, and expose no outbound-byte or send path.
#[test]
fn abi_sources_keep_one_lifetime_extension_and_no_thread_or_send_path() {
    let mut extensions = 0;
    let mut static_routers = 0;
    for (file, source) in ABI_SOURCES {
        let code = source;
        extensions += code.matches("unsafe fn router_for_owner_loop").count();
        static_routers += code.matches("&'static Router").count();
        for forbidden in [
            "transmute",
            "Box::leak",
            "ManuallyDrop",
            "thread::spawn",
            "std::thread",
            "Arc<Router>",
            "fn send",
            "outbound_bytes",
        ] {
            assert!(!code.contains(forbidden), "{file} contains {forbidden}");
        }
        let calls = code.matches("router_for_owner_loop(&").count();
        assert_eq!(calls, usize::from(file == "hosting.rs"), "{file} calls");
    }
    assert_eq!(extensions, 1, "exactly one lifetime-extension function");
    assert_eq!(
        static_routers, 2,
        "its signature and the one owner-loop constructor it feeds"
    );
}

#[test]
fn version_export_reports_abi_version_one() {
    assert_eq!(sas_pairing_abi_version(), 1);
}

#[test]
fn export_signatures_are_pinned() {
    let _: extern "C" fn() -> u32 = sas_pairing_abi_version;
    let _: unsafe extern "C" fn(*mut u64) -> i32 = sas_pairing_runtime_create;
    let _: extern "C" fn(u64) -> i32 = sas_pairing_runtime_destroy;
    let _: unsafe extern "C" fn(u64, *const u8, usize, *mut u64) -> i32 =
        sas_pairing_authority_register;
    let _: extern "C" fn(u64, u64) -> i32 = sas_pairing_authority_release;
    let _: unsafe extern "C" fn(u64, u64, *mut u32, *mut u32) -> i32 = sas_pairing_authority_status;
    let _: unsafe extern "C" fn(u64, u64, *mut u64) -> i32 = sas_pairing_host_create;
    let _: extern "C" fn(u64, u64) -> i32 = sas_pairing_host_destroy;
    let _: unsafe extern "C" fn(
        u64,
        u64,
        *mut usize,
        *const BootstrapView,
        *const BootstrapView,
    ) -> i32 = sas_pairing_host_attach_windows_listener;
    let _: extern "C" fn(u64, u64) -> i32 = sas_pairing_host_detach_listener;
    let _: unsafe extern "C" fn(u64, u64, *mut Event, usize, *mut usize, *mut i32) -> i32 =
        sas_pairing_host_drive;
    let _: unsafe extern "C" fn(u64, u64, *mut Event, usize, *mut usize, *mut i32) -> i32 =
        sas_pairing_host_recheck_after_resume;
    let _: extern "C" fn(u64, u64, u64) -> i32 = sas_pairing_connection_close;
    let _: unsafe extern "C" fn(u64, u64, *mut ResultInfo) -> i32 = sas_pairing_result_info;
    let _: unsafe extern "C" fn(u64, u64, u32, *mut u8, usize, *mut usize) -> i32 =
        sas_pairing_result_copy;
    let _: extern "C" fn(u64, u64) -> i32 = sas_pairing_result_destroy;
    let _: unsafe extern "C" fn(
        u64,
        u64,
        u64,
        *const BootstrapView,
        *const BootstrapView,
        *mut Action,
    ) -> i32 = sas_pairing_connection_start_initiator;
    type RunAction = unsafe extern "C" fn(u64, u64, u64, u64, *mut Action) -> i32;
    type RunDecision = unsafe extern "C" fn(u64, u64, u64, u64, *const u8, *mut Action) -> i32;
    let _: [RunAction; 4] = [
        sas_pairing_run_authorize_exposure,
        sas_pairing_run_expose_key,
        sas_pairing_run_emit_bootstrap_mac,
        sas_pairing_run_emit_initiator_finish,
    ];
    let _: [RunDecision; 3] = [
        sas_pairing_run_approve_sas,
        sas_pairing_run_reject_sas,
        sas_pairing_run_cancel_sas,
    ];
    let _: unsafe extern "C" fn(u64, u64, u64, u64, *mut Presentation) -> i32 =
        sas_pairing_run_presentation;
}

/// The checked-in header and the Rust ABI agree on the version, status values, type widths,
/// and the exact set of exported functions and their declarations.
#[test]
fn header_matches_the_rust_abi() {
    let defines: BTreeMap<&str, &str> = HEADER
        .lines()
        .filter_map(|line| line.strip_prefix("#define "))
        .filter_map(|rest| rest.split_once(' '))
        .map(|(name, value)| (name, value.trim()))
        .collect();
    assert_eq!(
        defines.get("SAS_PAIRING_ABI_VERSION"),
        Some(&format!("{ABI_VERSION}u").as_str())
    );
    assert_eq!(
        defines.get("SAS_PAIRING_ABI_VERSION_INVALID"),
        Some(&format!("{INVALID_ABI_VERSION}u").as_str())
    );
    assert_eq!(
        defines.get("SAS_PAIRING_RUNTIME_INVALID"),
        Some(&"((sas_pairing_runtime_t)0)")
    );
    assert_eq!(
        defines.get("SAS_PAIRING_AUTHORITY_INVALID"),
        Some(&"((sas_pairing_authority_t)0)")
    );
    assert_eq!(
        defines.get("SAS_PAIRING_HOST_INVALID"),
        Some(&"((sas_pairing_host_t)0)")
    );
    assert_eq!(
        defines.get("SAS_PAIRING_SOCKET_INVALID"),
        Some(&"((sas_pairing_socket_t)UINTPTR_MAX)")
    );
    for (name, value) in AUTHORITY_STATES {
        assert_eq!(
            defines.get(name),
            Some(&format!("((sas_pairing_authority_state_t){value})").as_str()),
            "{name}"
        );
    }
    for (name, typedef) in [
        ("SAS_PAIRING_CONNECTION_INVALID", "sas_pairing_connection_t"),
        ("SAS_PAIRING_RUN_INVALID", "sas_pairing_run_t"),
        ("SAS_PAIRING_RESULT_INVALID", "sas_pairing_result_t"),
    ] {
        assert_eq!(
            defines.get(name),
            Some(&format!("(({typedef})0)").as_str()),
            "{name}"
        );
    }
    for (name, value) in [
        ("SAS_PAIRING_MAX_DRIVE_EVENTS", drive_abi::MAX_DRIVE_EVENTS),
        (
            "SAS_PAIRING_MAX_REQUEST_ID_LEN",
            drive_abi::MAX_REQUEST_ID_LEN,
        ),
        (
            "SAS_PAIRING_MAX_RUNS_PER_CONNECTION",
            drive_abi::MAX_RUNS_PER_CONNECTION,
        ),
        ("SAS_PAIRING_SAS_DECIMAL_LEN", control_abi::SAS_DECIMAL_LEN),
    ] {
        assert_eq!(
            defines.get(name),
            Some(&format!("((size_t){value})").as_str()),
            "{name}"
        );
    }
    for (name, typedef, value) in typed_constants() {
        let rendered = if typedef.ends_with("_flags_t") {
            format!("(({typedef})0x{value:x})")
        } else {
            format!("(({typedef}){value})")
        };
        assert_eq!(defines.get(name), Some(&rendered.as_str()), "{name}");
    }
    let typed_names: BTreeSet<&str> = typed_constants().iter().map(|(name, ..)| *name).collect();
    let header_typed: BTreeSet<&str> = defines
        .iter()
        .filter(|(_, value)| {
            [
                "((sas_pairing_event_kind_t)",
                "((sas_pairing_step_kind_t)",
                "((sas_pairing_protocol_event_t)",
                "((sas_pairing_event_reason_t)",
                "((sas_pairing_deadline_kind_t)",
                "((sas_pairing_cancel_state_t)",
                "((sas_pairing_cancel_reason_t)",
                "((sas_pairing_event_flags_t)",
                "((sas_pairing_role_t)",
                "((sas_pairing_result_field_t)",
                "((sas_pairing_local_event_t)",
                "((sas_pairing_action_flags_t)",
            ]
            .iter()
            .any(|prefix| value.starts_with(prefix))
        })
        .map(|(name, _)| *name)
        .collect();
    assert_eq!(
        header_typed, typed_names,
        "every typed event, result, and local-action constant"
    );
    let header_statuses: BTreeMap<&str, i32> = defines
        .iter()
        .filter_map(|(name, value)| Some((*name, value.parse::<i32>().ok()?)))
        .collect();
    assert_eq!(header_statuses, BTreeMap::from(STATUSES));

    let typedefs: BTreeSet<&str> = HEADER
        .lines()
        .filter(|line| line.starts_with("typedef "))
        .collect();
    assert_eq!(
        typedefs,
        BTreeSet::from([
            "typedef int32_t sas_pairing_status_t;",
            "typedef uint64_t sas_pairing_runtime_t;",
            "typedef uint64_t sas_pairing_authority_t;",
            "typedef uint64_t sas_pairing_host_t;",
            "typedef uint32_t sas_pairing_authority_state_t;",
            "typedef uintptr_t sas_pairing_socket_t;",
            "typedef struct sas_pairing_bytes_view {",
            "typedef struct sas_pairing_bootstrap_view {",
            "typedef uint64_t sas_pairing_connection_t;",
            "typedef uint64_t sas_pairing_run_t;",
            "typedef uint64_t sas_pairing_result_t;",
            "typedef uint32_t sas_pairing_event_kind_t;",
            "typedef uint32_t sas_pairing_step_kind_t;",
            "typedef uint32_t sas_pairing_protocol_event_t;",
            "typedef uint32_t sas_pairing_event_reason_t;",
            "typedef uint32_t sas_pairing_deadline_kind_t;",
            "typedef uint32_t sas_pairing_cancel_state_t;",
            "typedef uint32_t sas_pairing_cancel_reason_t;",
            "typedef uint32_t sas_pairing_event_flags_t;",
            "typedef struct sas_pairing_event {",
            "typedef uint32_t sas_pairing_role_t;",
            "typedef uint32_t sas_pairing_result_field_t;",
            "typedef struct sas_pairing_result_info {",
            "typedef uint32_t sas_pairing_local_event_t;",
            "typedef uint32_t sas_pairing_action_flags_t;",
            "typedef struct sas_pairing_action {",
            "typedef struct sas_pairing_sas_presentation {",
        ])
    );
    // The local-action and presentation records, field for field (layout test above).
    assert!(HEADER.contains(
        "typedef struct sas_pairing_action {\n    \
         sas_pairing_local_event_t event;\n    \
         sas_pairing_deadline_kind_t deadline_kind;\n    \
         sas_pairing_action_flags_t flags;\n    \
         uint32_t reserved;\n    \
         sas_pairing_run_t run;\n} sas_pairing_action_t;"
    ));
    assert!(HEADER.contains(
        "typedef struct sas_pairing_sas_presentation {\n    \
         uint32_t available;\n    \
         uint32_t reserved;\n    \
         uint8_t ceremony_identity[32];\n    \
         uint8_t decimal[SAS_PAIRING_SAS_DECIMAL_LEN];\n    \
         uint8_t reserved_tail[2];\n} sas_pairing_sas_presentation_t;"
    ));
    // The event and result-info records, field for field, in the order `Event` and
    // `ResultInfo` pin (layout test below).
    assert!(HEADER.contains(
        "typedef struct sas_pairing_event {\n    \
         sas_pairing_event_kind_t kind;\n    \
         sas_pairing_step_kind_t step_kind;\n    \
         sas_pairing_protocol_event_t protocol_event;\n    \
         sas_pairing_event_reason_t reason;\n    \
         sas_pairing_deadline_kind_t deadline_kind;\n    \
         sas_pairing_cancel_state_t cancel_state;\n    \
         sas_pairing_cancel_reason_t cancel_reason;\n    \
         sas_pairing_event_flags_t flags;\n    \
         sas_pairing_connection_t connection;\n    \
         sas_pairing_run_t run;\n    \
         sas_pairing_result_t result;\n    \
         uint32_t request_id_len;\n    \
         uint32_t reserved;\n    \
         uint8_t request_id[SAS_PAIRING_MAX_REQUEST_ID_LEN];\n} sas_pairing_event_t;"
    ));
    assert!(HEADER.contains(
        "typedef struct sas_pairing_result_info {\n    \
         uint8_t ceremony_identity[32];\n    \
         sas_pairing_role_t peer_role;\n    \
         uint32_t profile_version;\n    \
         uint32_t request_id_len;\n    \
         uint32_t peer_bootstrap_len;\n    \
         uint32_t shared_context_len;\n    \
         uint32_t profile_identifier_len;\n} sas_pairing_result_info_t;"
    ));
    // The two input views, field for field, in the order `BytesView` and `BootstrapView` pin.
    assert!(HEADER.contains(
        "typedef struct sas_pairing_bytes_view {\n    const uint8_t *data;\n    size_t len;\n} \
         sas_pairing_bytes_view_t;"
    ));
    assert!(HEADER.contains(
        "typedef struct sas_pairing_bootstrap_view {\n    \
         sas_pairing_bytes_view_t application_identity;\n    \
         sas_pairing_bytes_view_t key_algorithm;\n    \
         sas_pairing_bytes_view_t public_key;\n    \
         sas_pairing_bytes_view_t shared_context;\n} sas_pairing_bootstrap_view_t;"
    ));
    assert!(HEADER.contains("#include <stddef.h>"));
    assert!(HEADER.contains("#include <stdint.h>"));

    let declarations: BTreeSet<&str> = HEADER
        .lines()
        .filter(|line| line.ends_with(");") && line.contains("sas_pairing_") && line.contains('('))
        .collect();
    assert_eq!(
        declarations,
        BTreeSet::from([
            "uint32_t sas_pairing_abi_version(void);",
            "sas_pairing_status_t sas_pairing_runtime_create(sas_pairing_runtime_t *out_runtime);",
            "sas_pairing_status_t sas_pairing_runtime_destroy(sas_pairing_runtime_t runtime);",
            "sas_pairing_status_t sas_pairing_authority_register(sas_pairing_runtime_t runtime, \
             const uint8_t *scope, size_t scope_len, sas_pairing_authority_t *out_authority);",
            "sas_pairing_status_t sas_pairing_authority_release(sas_pairing_runtime_t runtime, \
             sas_pairing_authority_t authority);",
            "sas_pairing_status_t sas_pairing_authority_status(sas_pairing_runtime_t runtime, \
             sas_pairing_authority_t authority, sas_pairing_authority_state_t *out_state, \
             uint32_t *out_remaining);",
            "sas_pairing_status_t sas_pairing_host_create(sas_pairing_runtime_t runtime, \
             sas_pairing_authority_t authority, sas_pairing_host_t *out_host);",
            "sas_pairing_status_t sas_pairing_host_destroy(sas_pairing_runtime_t runtime, \
             sas_pairing_host_t host);",
            "sas_pairing_status_t sas_pairing_host_attach_windows_listener(\
             sas_pairing_runtime_t runtime, sas_pairing_host_t host, \
             sas_pairing_socket_t *inout_listener, const sas_pairing_bootstrap_view_t *local, \
             const sas_pairing_bootstrap_view_t *expected);",
            "sas_pairing_status_t sas_pairing_host_detach_listener(sas_pairing_runtime_t runtime, \
             sas_pairing_host_t host);",
            "sas_pairing_status_t sas_pairing_host_drive(sas_pairing_runtime_t runtime, \
             sas_pairing_host_t host, sas_pairing_event_t *events, size_t event_capacity, \
             size_t *out_count, sas_pairing_status_t *out_failure);",
            "sas_pairing_status_t sas_pairing_host_recheck_after_resume(\
             sas_pairing_runtime_t runtime, sas_pairing_host_t host, sas_pairing_event_t *events, \
             size_t event_capacity, size_t *out_count, sas_pairing_status_t *out_failure);",
            "sas_pairing_status_t sas_pairing_connection_close(sas_pairing_runtime_t runtime, \
             sas_pairing_host_t host, sas_pairing_connection_t connection);",
            "sas_pairing_status_t sas_pairing_result_info(sas_pairing_runtime_t runtime, \
             sas_pairing_result_t result, sas_pairing_result_info_t *out_info);",
            "sas_pairing_status_t sas_pairing_result_copy(sas_pairing_runtime_t runtime, \
             sas_pairing_result_t result, sas_pairing_result_field_t field, uint8_t *buffer, \
             size_t capacity, size_t *out_required);",
            "sas_pairing_status_t sas_pairing_result_destroy(sas_pairing_runtime_t runtime, \
             sas_pairing_result_t result);",
            "sas_pairing_status_t sas_pairing_connection_start_initiator(\
             sas_pairing_runtime_t runtime, sas_pairing_host_t host, \
             sas_pairing_connection_t connection, const sas_pairing_bootstrap_view_t *local, \
             const sas_pairing_bootstrap_view_t *expected, sas_pairing_action_t *out_action);",
            "sas_pairing_status_t sas_pairing_run_authorize_exposure(sas_pairing_runtime_t runtime, \
             sas_pairing_host_t host, sas_pairing_connection_t connection, sas_pairing_run_t run, \
             sas_pairing_action_t *out_action);",
            "sas_pairing_status_t sas_pairing_run_expose_key(sas_pairing_runtime_t runtime, \
             sas_pairing_host_t host, sas_pairing_connection_t connection, sas_pairing_run_t run, \
             sas_pairing_action_t *out_action);",
            "sas_pairing_status_t sas_pairing_run_presentation(sas_pairing_runtime_t runtime, \
             sas_pairing_host_t host, sas_pairing_connection_t connection, sas_pairing_run_t run, \
             sas_pairing_sas_presentation_t *out_presentation);",
            "sas_pairing_status_t sas_pairing_run_approve_sas(sas_pairing_runtime_t runtime, \
             sas_pairing_host_t host, sas_pairing_connection_t connection, sas_pairing_run_t run, \
             const uint8_t *ceremony_identity, sas_pairing_action_t *out_action);",
            "sas_pairing_status_t sas_pairing_run_emit_bootstrap_mac(sas_pairing_runtime_t runtime, \
             sas_pairing_host_t host, sas_pairing_connection_t connection, sas_pairing_run_t run, \
             sas_pairing_action_t *out_action);",
            "sas_pairing_status_t sas_pairing_run_reject_sas(sas_pairing_runtime_t runtime, \
             sas_pairing_host_t host, sas_pairing_connection_t connection, sas_pairing_run_t run, \
             const uint8_t *ceremony_identity, sas_pairing_action_t *out_action);",
            "sas_pairing_status_t sas_pairing_run_cancel_sas(sas_pairing_runtime_t runtime, \
             sas_pairing_host_t host, sas_pairing_connection_t connection, sas_pairing_run_t run, \
             const uint8_t *ceremony_identity, sas_pairing_action_t *out_action);",
            "sas_pairing_status_t sas_pairing_run_emit_initiator_finish(\
             sas_pairing_runtime_t runtime, sas_pairing_host_t host, \
             sas_pairing_connection_t connection, sas_pairing_run_t run, \
             sas_pairing_action_t *out_action);",
        ])
    );
    let declared: BTreeSet<&str> = declarations
        .iter()
        .filter_map(|line| line.split('(').next()?.rsplit(' ').next())
        .collect();
    assert_eq!(declared, exported_functions().into_keys().collect());
}

/// Every `#[unsafe(no_mangle)]` function in the ABI sources, with the first line of its body.
fn exported_functions() -> BTreeMap<&'static str, &'static str> {
    let mut exports = BTreeMap::new();
    for (file, source) in ABI_SOURCES {
        let lines: Vec<&str> = source.lines().collect();
        for (index, _) in lines
            .iter()
            .enumerate()
            .filter(|(_, line)| line.trim() == "#[unsafe(no_mangle)]")
        {
            let signature = lines[index + 1];
            let name = signature
                .split("fn ")
                .nth(1)
                .and_then(|rest| rest.split('(').next())
                .unwrap_or_else(|| panic!("{file}: no fn after no_mangle"));
            let body_start = lines[index + 1..]
                .iter()
                .position(|line| line.trim_end().ends_with('{'))
                .expect("export body");
            exports.insert(name, lines[index + 2 + body_start].trim());
        }
    }
    exports
}

/// Every export enters its Rust work through the one containment dispatcher, and no other
/// ABI source catches panics on its own.
#[test]
fn every_export_runs_inside_the_central_panic_boundary() {
    let exports = exported_functions();
    assert_eq!(
        exports.keys().copied().collect::<Vec<_>>(),
        [
            "sas_pairing_abi_version",
            "sas_pairing_authority_register",
            "sas_pairing_authority_release",
            "sas_pairing_authority_status",
            "sas_pairing_connection_close",
            "sas_pairing_connection_start_initiator",
            "sas_pairing_host_attach_windows_listener",
            "sas_pairing_host_create",
            "sas_pairing_host_destroy",
            "sas_pairing_host_detach_listener",
            "sas_pairing_host_drive",
            "sas_pairing_host_recheck_after_resume",
            "sas_pairing_result_copy",
            "sas_pairing_result_destroy",
            "sas_pairing_result_info",
            "sas_pairing_run_approve_sas",
            "sas_pairing_run_authorize_exposure",
            "sas_pairing_run_cancel_sas",
            "sas_pairing_run_emit_bootstrap_mac",
            "sas_pairing_run_emit_initiator_finish",
            "sas_pairing_run_expose_key",
            "sas_pairing_run_presentation",
            "sas_pairing_run_reject_sas",
            "sas_pairing_runtime_create",
            "sas_pairing_runtime_destroy",
        ]
    );
    for (name, first_statement) in exports {
        assert!(
            first_statement.starts_with("dispatch("),
            "{name} must start with dispatch(..), found `{first_statement}`"
        );
    }
    for (file, source) in ABI_SOURCES {
        let catches = source.matches("catch_unwind(").count();
        let expected = usize::from(file == "panic_boundary.rs");
        assert_eq!(catches, expected, "{file} catch_unwind count");
        assert!(!source.contains("set_hook"), "{file} installs a panic hook");
        assert!(!source.contains("C-unwind"), "{file} uses C-unwind");
    }
}

#[test]
fn manifest_pins_the_supported_native_artifact() {
    let release = MANIFEST
        .split("[profile.release]")
        .nth(1)
        .expect("[profile.release] section")
        .split("\n[")
        .next()
        .unwrap();
    assert!(release.contains("panic = \"unwind\""), "{release}");
    assert!(MANIFEST.contains("crate-type = [\"rlib\", \"cdylib\"]"));
    assert!(MANIFEST.contains("native-abi = []"));
}

// --- Handles ---------------------------------------------------------------------------------

#[test]
fn handles_start_at_one_and_are_never_repeated() {
    let counter = HandleCounter::new();
    let issued: Vec<u64> = (0..10_000)
        .map(|_| counter.allocate().expect("handle").get())
        .collect();
    assert_eq!(issued[0], 1);
    assert!(issued.windows(2).all(|pair| pair[1] > pair[0]));
}

#[test]
fn the_handle_counter_fails_closed_instead_of_wrapping() {
    let counter = HandleCounter::starting_at(u64::MAX - 1);
    assert_eq!(counter.allocate().map(|h| h.get()), Some(u64::MAX - 1));
    assert_eq!(counter.allocate().map(|h| h.get()), Some(u64::MAX));
    for _ in 0..3 {
        assert_eq!(counter.allocate(), None, "never wraps to 0 or 1");
    }
}

#[test]
fn create_after_handle_exhaustion_fails_closed_without_a_runtime() {
    let state = AbiState::with_handles(HandleCounter::starting_at(u64::MAX));
    let last = create_local(&state);
    assert_eq!(last, u64::MAX);
    assert_eq!(state.destroy(last), SAS_PAIRING_OK);
    for _ in 0..2 {
        assert_eq!(state.create(), Err(SAS_PAIRING_HANDLES_EXHAUSTED));
        assert_eq!(state.destroy(last), SAS_PAIRING_INVALID_HANDLE);
    }
    assert!(!state.fatal.is_set(), "exhaustion is not a panic");
}

#[test]
fn a_destroyed_handle_never_aliases_a_later_runtime() {
    let state = AbiState::new();
    let first = create_local(&state);
    assert_eq!(state.create(), Err(SAS_PAIRING_ALREADY_INITIALIZED));
    assert_eq!(state.destroy(first), SAS_PAIRING_OK);
    assert_eq!(state.destroy(first), SAS_PAIRING_INVALID_HANDLE);
    let second = create_local(&state);
    assert_ne!(first, second);
    assert_eq!(state.destroy(first), SAS_PAIRING_INVALID_HANDLE);
    assert_eq!(state.create(), Err(SAS_PAIRING_ALREADY_INITIALIZED));
    assert_eq!(state.destroy(second), SAS_PAIRING_OK);
}

// --- Panic containment primitive -------------------------------------------------------------

#[test]
fn contain_returns_the_value_and_stays_healthy_without_a_panic() {
    let fatal = FatalState::new();
    assert_eq!(contain(&fatal, SAS_PAIRING_FATAL, || SAS_PAIRING_OK), 0);
    assert_eq!(contain(&fatal, INVALID_ABI_VERSION, || ABI_VERSION), 1);
    assert!(!fatal.is_set());
}

/// Test A: an ordinary panic is caught, marks the state fatal, and yields the fallback; this
/// test (the host) keeps running afterwards.
#[test]
fn contain_catches_an_ordinary_panic_and_marks_fatal() {
    let fatal = FatalState::new();
    let entered = AtomicUsize::new(0);
    let status = contain(&fatal, SAS_PAIRING_FATAL, || -> i32 {
        entered.fetch_add(1, Ordering::SeqCst);
        panic!("injected ordinary panic");
    });
    assert_eq!(status, SAS_PAIRING_FATAL);
    assert_eq!(entered.load(Ordering::SeqCst), 1);
    assert!(fatal.is_set());

    let version_fatal = FatalState::new();
    let version = contain(&version_fatal, INVALID_ABI_VERSION, || -> u32 {
        panic!("injected version-query panic");
    });
    assert_eq!(version, 0);
    assert!(version_fatal.is_set());
}

/// Test B: a payload whose destructor panics is caught, the state becomes fatal, the fallback is
/// returned, and the destructor never runs.
#[test]
fn contain_never_runs_a_drop_panicking_payload_destructor() {
    static DROPS: AtomicUsize = AtomicUsize::new(0);
    let fatal = FatalState::new();
    let status = contain(&fatal, SAS_PAIRING_FATAL, || -> i32 {
        panic_any(PanicOnDrop(&DROPS));
    });
    assert_eq!(status, SAS_PAIRING_FATAL);
    assert!(fatal.is_set());
    assert_eq!(DROPS.load(Ordering::SeqCst), 0);
}

#[test]
fn a_fatal_state_blocks_create_but_not_destroy() {
    let state = AbiState::new();
    let handle = create_local(&state);
    let status = contain(&state.fatal, SAS_PAIRING_FATAL, || -> i32 {
        panic!("injected panic");
    });
    assert_eq!(status, SAS_PAIRING_FATAL);
    assert_eq!(state.create(), Err(SAS_PAIRING_FATAL));
    assert_eq!(state.destroy(handle), SAS_PAIRING_OK);
    assert_eq!(state.destroy(handle), SAS_PAIRING_INVALID_HANDLE);
    assert!(state.fatal.is_set(), "destroy never clears fatal");
    assert_eq!(state.create(), Err(SAS_PAIRING_FATAL));
}

#[test]
fn a_panic_that_poisons_the_runtime_slot_still_allows_destroy() {
    let state = AbiState::new();
    let handle = create_local(&state);
    let status = contain(&state.fatal, SAS_PAIRING_FATAL, || {
        state.panic_while_holding_runtime_slot()
    });
    assert_eq!(status, SAS_PAIRING_FATAL);
    assert_eq!(state.create(), Err(SAS_PAIRING_FATAL));
    assert_eq!(state.destroy(handle), SAS_PAIRING_OK);
    assert_eq!(state.destroy(handle), SAS_PAIRING_INVALID_HANDLE);
    assert_eq!(state.create(), Err(SAS_PAIRING_FATAL));
}

// --- Process-isolated tests of the real exports ----------------------------------------------

const CHILD_ENV: &str = "SAS_PAIRING_ABI_TEST_CHILD";
const CHILD_TIMEOUT: Duration = Duration::from_secs(120);

/// Whether this process was spawned to run exactly the child test `name`.
fn is_child(name: &str) -> bool {
    env::var(CHILD_ENV).is_ok_and(|child| child == name)
}

/// Runs the `#[ignore]`d child test `name` alone in a fresh process and requires that it ran,
/// passed, and finished (a hang counts as a deadlock).
fn run_child(name: &str) {
    static SPAWNED: AtomicUsize = AtomicUsize::new(0);
    let spawn = SPAWNED.fetch_add(1, Ordering::SeqCst);
    let stem = env::temp_dir().join(format!(
        "sas-pairing-abi-{}-{spawn}-{}",
        std::process::id(),
        name.replace("::", "-")
    ));
    let (out_path, err_path) = (stem.with_extension("out"), stem.with_extension("err"));
    let mut child = Command::new(env::current_exe().expect("test binary"))
        .args([
            &format!("abi::tests::{name}"),
            "--exact",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
        ])
        .env(CHILD_ENV, name)
        .stdout(fs::File::create(&out_path).expect("child stdout"))
        .stderr(fs::File::create(&err_path).expect("child stderr"))
        .spawn()
        .expect("spawn child");
    let deadline = Instant::now() + CHILD_TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait().expect("child status") {
            break Some(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        thread::sleep(Duration::from_millis(10));
    };
    let stdout = fs::read_to_string(&out_path).unwrap_or_default();
    let stderr = fs::read_to_string(&err_path).unwrap_or_default();
    let _ = fs::remove_file(&out_path);
    let _ = fs::remove_file(&err_path);
    let status = status.unwrap_or_else(|| {
        panic!("child {name} did not finish in {CHILD_TIMEOUT:?}\n{stdout}\n{stderr}")
    });
    assert!(
        status.success(),
        "child {name} failed: {status}\n{stdout}\n{stderr}"
    );
    assert!(
        stdout.contains("test result: ok. 1 passed"),
        "child {name} did not run exactly its test\n{stdout}\n{stderr}"
    );
}

fn create() -> (i32, u64) {
    let mut out = u64::MAX;
    // SAFETY: `out` is a live, aligned, exclusively borrowed `u64` for the whole call.
    let status = unsafe { sas_pairing_runtime_create(&mut out) };
    (status, out)
}

fn destroy(handle: u64) -> i32 {
    sas_pairing_runtime_destroy(handle)
}

/// Registers `scope` through the export; the output slot starts as a sentinel.
fn register(runtime: u64, scope: &[u8]) -> (i32, u64) {
    let mut out = u64::MAX;
    // SAFETY: `scope` is a live slice for the whole call, and `out` is a live, aligned,
    // exclusively borrowed `u64` that does not overlap it.
    let status =
        unsafe { sas_pairing_authority_register(runtime, scope.as_ptr(), scope.len(), &mut out) };
    (status, out)
}

fn release(runtime: u64, authority: u64) -> i32 {
    sas_pairing_authority_release(runtime, authority)
}

/// Creates a host through the export; the output slot starts as a sentinel.
fn host_create(runtime: u64, authority: u64) -> (i32, u64) {
    let mut out = u64::MAX;
    // SAFETY: `out` is a live, aligned, exclusively borrowed `u64` for the whole call.
    let status = unsafe { sas_pairing_host_create(runtime, authority, &mut out) };
    (status, out)
}

fn host_destroy(runtime: u64, host: u64) -> i32 {
    sas_pairing_host_destroy(runtime, host)
}

/// Reads an authority's status through the export; the output slots start as sentinels.
fn authority_status(runtime: u64, authority: u64) -> (i32, u32, u32) {
    let (mut state, mut remaining) = (u32::MAX, u32::MAX);
    // SAFETY: two distinct live, aligned, exclusively borrowed `u32` slots.
    let status =
        unsafe { sas_pairing_authority_status(runtime, authority, &mut state, &mut remaining) };
    (status, state, remaining)
}

/// After a panic that left the runtime slot unpoisoned, normal authority and host operations are
/// refused by the fatal state alone, before the runtime handle is checked and without entering
/// the core or building a router; release and host destroy stay admitted as cleanup.
fn assert_authority_calls_are_fatal(runtime: u64) {
    let entries = CORE_ENTRIES.load(Ordering::SeqCst);
    let routers = ROUTER_CONSTRUCTIONS.get();
    for runtime in [runtime, 0, runtime.wrapping_add(1_000)] {
        assert_eq!(
            host_create(runtime, runtime.wrapping_add(1)),
            (SAS_PAIRING_FATAL, 0)
        );
        assert_eq!(
            register(runtime, b"p7-abi-after-fatal"),
            (SAS_PAIRING_FATAL, 0)
        );
        assert_eq!(
            authority_status(runtime, runtime.wrapping_add(1)),
            (SAS_PAIRING_FATAL, SAS_PAIRING_AUTHORITY_STATE_INVALID, 0)
        );
    }
    assert_eq!(CORE_ENTRIES.load(Ordering::SeqCst), entries, "core entered");
    assert_eq!(ROUTER_CONSTRUCTIONS.get(), routers, "router built");
    assert_eq!(
        release(runtime, runtime.wrapping_add(1)),
        SAS_PAIRING_INVALID_HANDLE,
        "cleanup is admitted and still validates its handles"
    );
    assert_eq!(
        host_destroy(runtime, runtime.wrapping_add(1)),
        SAS_PAIRING_INVALID_HANDLE,
        "host destroy is cleanup too"
    );
}

/// Export-shaped test seam: an `extern "C"` function whose Rust work panics inside the real
/// `dispatch`, as a production export's would. Not `no_mangle`; never in the artifact. If the
/// boundary let a second panic escape, crossing `extern "C"` would abort the child process.
extern "C" fn injected_panic_export(drop_panicking_payload: u32) -> i32 {
    static CHILD_PAYLOAD_DROPS: AtomicUsize = AtomicUsize::new(0);
    dispatch(SAS_PAIRING_FATAL, |_| -> i32 {
        if drop_panicking_payload != 0 {
            panic_any(PanicOnDrop(&CHILD_PAYLOAD_DROPS));
        }
        panic!("injected ordinary panic");
    })
}

/// The whole fatal lifecycle against the real process state, after one injected panic.
fn assert_fatal_lifecycle(drop_panicking_payload: u32) {
    let (status, handle) = create();
    assert_eq!(status, SAS_PAIRING_OK);
    assert!(!PROCESS.fatal.is_set());

    assert_eq!(
        injected_panic_export(drop_panicking_payload),
        SAS_PAIRING_FATAL
    );
    assert!(PROCESS.fatal.is_set(), "fatal is recorded");
    assert_authority_calls_are_fatal(handle);

    // Fatal cannot be left: no create succeeds, and the live runtime is not replaced.
    assert_eq!(create(), (SAS_PAIRING_FATAL, 0));
    assert_eq!(sas_pairing_abi_version(), 1, "version query still answers");
    // The fatal runtime stays destroyable, exactly once, without clearing fatal.
    assert_eq!(destroy(handle), SAS_PAIRING_OK);
    assert_eq!(destroy(handle), SAS_PAIRING_INVALID_HANDLE);
    assert!(PROCESS.fatal.is_set());
    for _ in 0..3 {
        assert_eq!(create(), (SAS_PAIRING_FATAL, 0));
    }
    // A panic on the version-query path yields the reserved invalid version 0.
    assert_eq!(
        dispatch(INVALID_ABI_VERSION, |_| -> u32 { panic!("version") }),
        0
    );
}

#[test]
#[ignore = "subprocess child; run by runtime_lifecycle_through_the_exports"]
fn child_lifecycle() {
    if !is_child("child_lifecycle") {
        return;
    }
    assert_eq!(sas_pairing_abi_version(), 1);
    // SAFETY: a null pointer is part of the contract and is never written through.
    let status = unsafe { sas_pairing_runtime_create(ptr::null_mut()) };
    assert_eq!(status, SAS_PAIRING_INVALID_ARGUMENT);
    let mut words = [u64::MAX; 2];
    let misaligned = words
        .as_mut_ptr()
        .cast::<u8>()
        .wrapping_add(1)
        .cast::<u64>();
    assert!(!misaligned.is_aligned());
    // SAFETY: the misaligned pointer is rejected before any write.
    let status = unsafe { sas_pairing_runtime_create(misaligned) };
    assert_eq!(status, SAS_PAIRING_INVALID_ARGUMENT);
    assert_eq!(words, [u64::MAX; 2], "nothing written");

    let (status, first) = create();
    assert_eq!(
        status, SAS_PAIRING_OK,
        "rejected pointers created no runtime"
    );
    assert_ne!(first, 0);
    assert_eq!(create(), (SAS_PAIRING_ALREADY_INITIALIZED, 0));
    for unknown in [0, first + 1, u64::MAX] {
        assert_eq!(destroy(unknown), SAS_PAIRING_INVALID_HANDLE);
    }
    assert_eq!(destroy(first), SAS_PAIRING_OK);
    assert_eq!(destroy(first), SAS_PAIRING_INVALID_HANDLE);

    let (status, second) = create();
    assert_eq!(status, SAS_PAIRING_OK);
    assert_ne!(second, 0);
    assert_ne!(second, first, "a new runtime gets a new handle");
    assert_eq!(
        destroy(first),
        SAS_PAIRING_INVALID_HANDLE,
        "stale stays invalid"
    );
    assert_eq!(
        create(),
        (SAS_PAIRING_ALREADY_INITIALIZED, 0),
        "second is live"
    );
    assert_eq!(destroy(second), SAS_PAIRING_OK);
    assert!(!PROCESS.fatal.is_set());
}

#[test]
fn runtime_lifecycle_through_the_exports() {
    run_child("child_lifecycle");
}

#[test]
#[ignore = "subprocess child; run by concurrent_creates_admit_exactly_one_runtime"]
fn child_concurrent_create() {
    if !is_child("child_concurrent_create") {
        return;
    }
    const THREADS: usize = 16;
    const ROUNDS: usize = 32;
    let mut issued = HashSet::new();
    let mut stale = 0;
    for _ in 0..ROUNDS {
        let barrier = Arc::new(Barrier::new(THREADS));
        let results: Vec<(i32, u64)> = (0..THREADS)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    create()
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|thread| thread.join().expect("no panic"))
            .collect();
        let winners: Vec<u64> = results
            .iter()
            .filter(|(status, _)| *status == SAS_PAIRING_OK)
            .map(|(_, handle)| *handle)
            .collect();
        assert_eq!(winners.len(), 1, "exactly one create succeeds: {results:?}");
        assert!(
            results
                .iter()
                .all(|r| r.0 == SAS_PAIRING_OK || *r == (SAS_PAIRING_ALREADY_INITIALIZED, 0)),
            "{results:?}"
        );
        let live = winners[0];
        assert_ne!(live, 0);
        assert!(issued.insert(live), "handle {live} issued twice");

        // Concurrent destroys: half name the live handle, half stale or unknown ones.
        let barrier = Arc::new(Barrier::new(THREADS));
        let outcomes: Vec<(bool, i32)> = (0..THREADS)
            .map(|index| {
                let barrier = Arc::clone(&barrier);
                let target = match index % 4 {
                    0 | 1 => live,
                    2 => stale,
                    _ => live.wrapping_add(1_000_000),
                };
                thread::spawn(move || {
                    barrier.wait();
                    (target == live, destroy(target))
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|thread| thread.join().expect("no panic"))
            .collect();
        let successes: Vec<&(bool, i32)> = outcomes
            .iter()
            .filter(|(_, status)| *status == SAS_PAIRING_OK)
            .collect();
        assert_eq!(successes.len(), 1, "{outcomes:?}");
        assert!(successes[0].0, "only the live handle destroys");
        assert!(
            outcomes
                .iter()
                .all(|(_, s)| *s == SAS_PAIRING_OK || *s == SAS_PAIRING_INVALID_HANDLE)
        );
        stale = live;
    }
    assert_eq!(issued.len(), ROUNDS);
    assert!(!PROCESS.fatal.is_set());
}

#[test]
fn concurrent_creates_admit_exactly_one_runtime() {
    run_child("child_concurrent_create");
}

#[test]
#[ignore = "subprocess child; run by an_ordinary_panic_makes_the_process_permanently_fatal"]
fn child_fatal_after_ordinary_panic() {
    if !is_child("child_fatal_after_ordinary_panic") {
        return;
    }
    assert_fatal_lifecycle(0);
}

#[test]
fn an_ordinary_panic_makes_the_process_permanently_fatal() {
    run_child("child_fatal_after_ordinary_panic");
}

#[test]
#[ignore = "subprocess child; run by a_drop_panicking_payload_is_contained_at_an_export"]
fn child_fatal_after_drop_panicking_payload() {
    if !is_child("child_fatal_after_drop_panicking_payload") {
        return;
    }
    assert_fatal_lifecycle(1);
}

/// The child aborts if the payload destructor runs (its panic would cross `extern "C"`).
#[test]
fn a_drop_panicking_payload_is_contained_at_an_export() {
    run_child("child_fatal_after_drop_panicking_payload");
}

#[test]
#[ignore = "subprocess child; run by only_a_new_process_has_a_clean_abi_state"]
fn child_clean_state() {
    if !is_child("child_clean_state") {
        return;
    }
    assert!(!PROCESS.fatal.is_set());
    let (status, handle) = create();
    assert_eq!(status, SAS_PAIRING_OK);
    assert_eq!(destroy(handle), SAS_PAIRING_OK);
}

#[test]
fn only_a_new_process_has_a_clean_abi_state() {
    run_child("child_fatal_after_ordinary_panic");
    run_child("child_clean_state");
}
