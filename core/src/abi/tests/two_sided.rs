//! P7.7 two-sided public-ABI ceremonies: two independent native ABI consumers, each in its own OS
//! process with its own runtime and authority, pair with each other (or fail to) through ONLY the
//! 25 public exports.
//!
//! The parent test is the harness. It spawns both endpoint processes (this test binary re-run as
//! the one `#[ignore]`d child `child_endpoint`), connects to both endpoints' listeners, and relays
//! bytes between the two connections without reading them: a byte-transparent relay. It
//! synchronizes the processes only through their own report lines and compares what each endpoint
//! reported through the public ABI. It never parses, builds, or changes a protocol frame, and it
//! never calls into the crate.
//!
//! The endpoint code is written as a foreign consumer writes it: it declares the C ABI itself
//! (its own `#[repr(C)]` records, constants, and `extern "C"` declarations mirrored from
//! `core/include/sas_pairing.h`) and uses nothing of the crate. The checks after the marker at the
//! end pin both properties: the consumer section names no crate item, its declarations are
//! exactly the 25 exports, and its mirrored constants equal the header.
//!
//! Endpoint A is the TCP-accepting Initiator (its local start runs on the connection its listener
//! accepted from the relay); endpoint B is the Responder. TCP direction is not protocol role.
#![cfg_attr(
    not(windows),
    allow(
        dead_code,
        reason = "the consumer's records and constants are pinned everywhere; only Windows pairs"
    )
)]

#[cfg(windows)]
use std::{
    collections::VecDeque,
    env,
    io::{BufRead, BufReader, Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    os::windows::io::IntoRawSocket,
    process::{Child, ChildStdin, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

#[cfg(windows)]
use super::{CHILD_ENV, is_child};

// --- The consumer's own C ABI declarations (mirrored from sas_pairing.h) ----------------------

const SAS_PAIRING_ABI_VERSION: u32 = 1;

const SAS_PAIRING_OK: i32 = 0;
const SAS_PAIRING_INVALID_HANDLE: i32 = 2;
const SAS_PAIRING_WRITE_PENDING: i32 = 205;
const SAS_PAIRING_CEREMONY_IDENTITY_MISMATCH: i32 = 208;
const SAS_PAIRING_BUFFER_TOO_SMALL: i32 = 300;
const SAS_PAIRING_LISTENER_NOT_ATTACHED: i32 = 402;

const SAS_PAIRING_AUTHORITY_READY: u32 = 1;
const SAS_PAIRING_AUTHORITY_BUSY: u32 = 2;

const SAS_PAIRING_SOCKET_INVALID: usize = usize::MAX;
const SAS_PAIRING_MAX_DRIVE_EVENTS: usize = 17;
const SAS_PAIRING_MAX_REQUEST_ID_LEN: usize = 64;
const SAS_PAIRING_SAS_DECIMAL_LEN: usize = 14;

const SAS_PAIRING_EVENT_CONNECTION_ACCEPTED: u32 = 1;
const SAS_PAIRING_EVENT_CONNECTION_STEP: u32 = 4;
const SAS_PAIRING_EVENT_CONNECTION_CLOSED: u32 = 5;

const SAS_PAIRING_STEP_INBOUND: u32 = 1;
const SAS_PAIRING_STEP_WRITTEN: u32 = 4;
const SAS_PAIRING_STEP_CONFIRMED: u32 = 5;

const SAS_PAIRING_PROTOCOL_EVENT_START_ACCEPTED: u32 = 1;
const SAS_PAIRING_PROTOCOL_EVENT_ACCEPT: u32 = 3;
const SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_KEY: u32 = 4;
const SAS_PAIRING_PROTOCOL_EVENT_RESPONDER_KEY: u32 = 5;
const SAS_PAIRING_PROTOCOL_EVENT_BOOTSTRAP_MAC_AUTHENTICATED: u32 = 6;
const SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH: u32 = 8;
const SAS_PAIRING_PROTOCOL_EVENT_RESPONDER_FINISH_ACK: u32 = 10;
const SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH_ACK: u32 = 11;
const SAS_PAIRING_PROTOCOL_EVENT_PEER_CANCEL: u32 = 12;

const SAS_PAIRING_EVENT_REASON_PEER_CLOSED: u32 = 2;
const SAS_PAIRING_EVENT_REASON_READINESS_FAILURE: u32 = 5;
const SAS_PAIRING_EVENT_REASON_TRANSPORT_DEADLINE: u32 = 12;

const SAS_PAIRING_CANCEL_REASON_USER_REJECTION: u32 = 1;
const SAS_PAIRING_CANCEL_REASON_USER_CANCELLATION: u32 = 2;

const SAS_PAIRING_EVENT_FLAG_WRITE_PENDING: u32 = 0x1;

const SAS_PAIRING_ROLE_INITIATOR: u32 = 1;
const SAS_PAIRING_ROLE_RESPONDER: u32 = 2;

const SAS_PAIRING_RESULT_FIELD_REQUEST_ID: u32 = 1;
const SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_PEER_BOOTSTRAP: u32 = 2;
const SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_SHARED_CONTEXT: u32 = 3;
const SAS_PAIRING_RESULT_FIELD_PROFILE_IDENTIFIER: u32 = 4;

const SAS_PAIRING_LOCAL_EVENT_INITIATOR_STARTED: u32 = 1;
const SAS_PAIRING_LOCAL_EVENT_EXPOSURE_AUTHORIZED: u32 = 2;
const SAS_PAIRING_LOCAL_EVENT_KEY_EXPOSED: u32 = 3;
const SAS_PAIRING_LOCAL_EVENT_SAS_APPROVED: u32 = 4;
const SAS_PAIRING_LOCAL_EVENT_BOOTSTRAP_MAC_EMITTED: u32 = 6;
const SAS_PAIRING_LOCAL_EVENT_INITIATOR_FINISH_EMITTED: u32 = 8;
const SAS_PAIRING_LOCAL_EVENT_SAS_REJECTED: u32 = 10;
const SAS_PAIRING_LOCAL_EVENT_SAS_CANCELLED: u32 = 11;

const SAS_PAIRING_ACTION_FLAG_WRITE_PENDING: u32 = 0x1;

/// `sas_pairing_bytes_view_t`.
#[repr(C)]
#[derive(Clone, Copy)]
struct BytesView {
    data: *const u8,
    len: usize,
}

/// `sas_pairing_bootstrap_view_t`.
#[repr(C)]
#[derive(Clone, Copy)]
struct BootstrapView {
    application_identity: BytesView,
    key_algorithm: BytesView,
    public_key: BytesView,
    shared_context: BytesView,
}

/// `sas_pairing_event_t`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Event {
    kind: u32,
    step_kind: u32,
    protocol_event: u32,
    reason: u32,
    deadline_kind: u32,
    cancel_state: u32,
    cancel_reason: u32,
    flags: u32,
    connection: u64,
    run: u64,
    result: u64,
    request_id_len: u32,
    reserved: u32,
    request_id: [u8; SAS_PAIRING_MAX_REQUEST_ID_LEN],
}

/// `sas_pairing_result_info_t`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ResultInfo {
    ceremony_identity: [u8; 32],
    peer_role: u32,
    profile_version: u32,
    request_id_len: u32,
    peer_bootstrap_len: u32,
    shared_context_len: u32,
    profile_identifier_len: u32,
}

/// `sas_pairing_action_t`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Action {
    event: u32,
    deadline_kind: u32,
    flags: u32,
    reserved: u32,
    run: u64,
}

/// `sas_pairing_sas_presentation_t`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Presentation {
    available: u32,
    reserved: u32,
    ceremony_identity: [u8; 32],
    decimal: [u8; SAS_PAIRING_SAS_DECIMAL_LEN],
    reserved_tail: [u8; 2],
}

// The consumer's records have the frozen ABI v1 layouts (abi-v1-manifest.md).
const _: () = {
    assert!(size_of::<Event>() == 128 && align_of::<Event>() == 8);
    assert!(std::mem::offset_of!(Event, connection) == 32);
    assert!(std::mem::offset_of!(Event, request_id_len) == 56);
    assert!(std::mem::offset_of!(Event, request_id) == 64);
    assert!(size_of::<ResultInfo>() == 56 && align_of::<ResultInfo>() == 4);
    assert!(std::mem::offset_of!(ResultInfo, peer_role) == 32);
    assert!(size_of::<Action>() == 24 && align_of::<Action>() == 8);
    assert!(std::mem::offset_of!(Action, run) == 16);
    assert!(size_of::<Presentation>() == 56 && align_of::<Presentation>() == 4);
    assert!(std::mem::offset_of!(Presentation, decimal) == 40);
    assert!(size_of::<BootstrapView>() == size_of::<[usize; 8]>());
};

#[cfg(windows)]
unsafe extern "C" {
    fn sas_pairing_abi_version() -> u32;
    fn sas_pairing_runtime_create(out_runtime: *mut u64) -> i32;
    fn sas_pairing_runtime_destroy(runtime: u64) -> i32;
    fn sas_pairing_authority_register(
        runtime: u64,
        scope: *const u8,
        scope_len: usize,
        out_authority: *mut u64,
    ) -> i32;
    fn sas_pairing_authority_release(runtime: u64, authority: u64) -> i32;
    fn sas_pairing_authority_status(
        runtime: u64,
        authority: u64,
        out_state: *mut u32,
        out_remaining: *mut u32,
    ) -> i32;
    fn sas_pairing_host_create(runtime: u64, authority: u64, out_host: *mut u64) -> i32;
    fn sas_pairing_host_destroy(runtime: u64, host: u64) -> i32;
    fn sas_pairing_host_attach_windows_listener(
        runtime: u64,
        host: u64,
        inout_listener: *mut usize,
        local: *const BootstrapView,
        expected: *const BootstrapView,
    ) -> i32;
    fn sas_pairing_host_detach_listener(runtime: u64, host: u64) -> i32;
    fn sas_pairing_host_drive(
        runtime: u64,
        host: u64,
        events: *mut Event,
        event_capacity: usize,
        out_count: *mut usize,
        out_failure: *mut i32,
    ) -> i32;
    fn sas_pairing_host_recheck_after_resume(
        runtime: u64,
        host: u64,
        events: *mut Event,
        event_capacity: usize,
        out_count: *mut usize,
        out_failure: *mut i32,
    ) -> i32;
    fn sas_pairing_connection_close(runtime: u64, host: u64, connection: u64) -> i32;
    fn sas_pairing_result_info(runtime: u64, result: u64, out_info: *mut ResultInfo) -> i32;
    fn sas_pairing_result_copy(
        runtime: u64,
        result: u64,
        field: u32,
        buffer: *mut u8,
        capacity: usize,
        out_required: *mut usize,
    ) -> i32;
    fn sas_pairing_result_destroy(runtime: u64, result: u64) -> i32;
    fn sas_pairing_connection_start_initiator(
        runtime: u64,
        host: u64,
        connection: u64,
        local: *const BootstrapView,
        expected: *const BootstrapView,
        out_action: *mut Action,
    ) -> i32;
    fn sas_pairing_run_authorize_exposure(
        runtime: u64,
        host: u64,
        connection: u64,
        run: u64,
        out_action: *mut Action,
    ) -> i32;
    fn sas_pairing_run_expose_key(
        runtime: u64,
        host: u64,
        connection: u64,
        run: u64,
        out_action: *mut Action,
    ) -> i32;
    fn sas_pairing_run_presentation(
        runtime: u64,
        host: u64,
        connection: u64,
        run: u64,
        out_presentation: *mut Presentation,
    ) -> i32;
    fn sas_pairing_run_approve_sas(
        runtime: u64,
        host: u64,
        connection: u64,
        run: u64,
        ceremony_identity: *const u8,
        out_action: *mut Action,
    ) -> i32;
    fn sas_pairing_run_emit_bootstrap_mac(
        runtime: u64,
        host: u64,
        connection: u64,
        run: u64,
        out_action: *mut Action,
    ) -> i32;
    fn sas_pairing_run_reject_sas(
        runtime: u64,
        host: u64,
        connection: u64,
        run: u64,
        ceremony_identity: *const u8,
        out_action: *mut Action,
    ) -> i32;
    fn sas_pairing_run_cancel_sas(
        runtime: u64,
        host: u64,
        connection: u64,
        run: u64,
        ceremony_identity: *const u8,
        out_action: *mut Action,
    ) -> i32;
    fn sas_pairing_run_emit_initiator_finish(
        runtime: u64,
        host: u64,
        connection: u64,
        run: u64,
        out_action: *mut Action,
    ) -> i32;
}

// --- Shared configuration ---------------------------------------------------------------------

/// The trusted local configuration each endpoint was given out of band (its own Bootstrap and
/// the exact expected peer Bootstrap). Both share one context.
const SHARED_CONTEXT: &[u8] = b"p7.7 two-sided shared context";
const A_IDENTITY: &[u8] = b"p7.7 two-sided endpoint A (Initiator)";
const A_PUBLIC_KEY: &[u8] = &[0xA7; 32];
const B_IDENTITY: &[u8] = b"p7.7 two-sided endpoint B (Responder)";
const B_PUBLIC_KEY: &[u8] = &[0xB7; 32];
const KEY_ALGORITHM: &[u8] = b"p77.test-key";
/// What every result's profile identifier must be (the frozen P6 candidate).
const PROFILE_IDENTIFIER: &[u8] = b"sas-pairing-vodozemac-profile-draft-01";
/// The one line prefix of every report line the harness reads.
const REPORT: &str = "SASPAIR ";
#[cfg(windows)]
const ROLE_ENV: &str = "SAS_PAIRING_TWO_SIDED_ROLE";
#[cfg(windows)]
const SCENARIO_ENV: &str = "SAS_PAIRING_TWO_SIDED_SCENARIO";
#[cfg(windows)]
const CHILD_NAME: &str = "two_sided::child_endpoint";

/// How a two-sided run goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scenario {
    /// Both endpoints MATCH (each first tries a wrong identity) and both reach a result.
    Success,
    /// B rejects its presented SAS; A, still undecided, receives the authenticated CANCEL.
    Reject,
    /// A cancels; B, still undecided, receives the authenticated CANCEL.
    Cancel,
    /// A closes its connection after the SAS was shown on both sides.
    Close,
    /// B detaches its listener after the SAS was shown.
    Detach,
    /// Neither starts a ceremony: both connections reach their first-frame deadline.
    Deadline,
    /// The A→B link fails after A received the Responder's FINISH_ACK: A completes locally and
    /// B never receives the final ACK (P6-D-005: either side may be the only result holder).
    LostFinalAck,
}

impl Scenario {
    const ALL: [Self; 7] = [
        Self::Success,
        Self::Reject,
        Self::Cancel,
        Self::Close,
        Self::Detach,
        Self::Deadline,
        Self::LostFinalAck,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Reject => "reject",
            Self::Cancel => "cancel",
            Self::Close => "close",
            Self::Detach => "detach",
            Self::Deadline => "deadline",
            Self::LostFinalAck => "lost-final-ack",
        }
    }

    fn from_name(name: &str) -> Self {
        *Self::ALL
            .iter()
            .find(|scenario| scenario.name() == name)
            .unwrap_or_else(|| panic!("unknown scenario {name}"))
    }

    /// Whether both endpoints MATCH and run the whole ceremony.
    fn completes(self) -> bool {
        matches!(self, Self::Success | Self::LostFinalAck)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Initiator,
    Responder,
}

impl Role {
    fn name(self) -> &'static str {
        match self {
            Self::Initiator => "initiator",
            Self::Responder => "responder",
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

// --- The endpoint: one public-ABI consumer process --------------------------------------------

#[cfg(windows)]
fn bytes(value: &'static [u8]) -> BytesView {
    BytesView {
        data: value.as_ptr(),
        len: value.len(),
    }
}

#[cfg(windows)]
fn bootstrap(role: Role) -> BootstrapView {
    let (identity, key) = match role {
        Role::Initiator => (A_IDENTITY, A_PUBLIC_KEY),
        Role::Responder => (B_IDENTITY, B_PUBLIC_KEY),
    };
    BootstrapView {
        application_identity: bytes(identity),
        key_algorithm: bytes(KEY_ALGORITHM),
        public_key: bytes(key),
        shared_context: bytes(SHARED_CONTEXT),
    }
}

#[cfg(windows)]
const ZERO_EVENT: Event = Event {
    kind: 0,
    step_kind: 0,
    protocol_event: 0,
    reason: 0,
    deadline_kind: 0,
    cancel_state: 0,
    cancel_reason: 0,
    flags: 0,
    connection: 0,
    run: 0,
    result: 0,
    request_id_len: 0,
    reserved: 0,
    request_id: [0; SAS_PAIRING_MAX_REQUEST_ID_LEN],
};
#[cfg(windows)]
const ZERO_ACTION: Action = Action {
    event: 0,
    deadline_kind: 0,
    flags: 0,
    reserved: 0,
    run: 0,
};
#[cfg(windows)]
const ZERO_PRESENTATION: Presentation = Presentation {
    available: 0,
    reserved: 0,
    ceremony_identity: [0; 32],
    decimal: [0; SAS_PAIRING_SAS_DECIMAL_LEN],
    reserved_tail: [0; 2],
};

/// One trusted local step the endpoint wants, retried after a drive while it is backpressured.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Start,
    Authorize,
    Expose,
    /// MATCH naming an identity that differs from the presented one in one bit.
    ApproveWrong,
    Approve,
    EmitMac,
    Finish,
    Reject,
    Cancel,
}

/// The frame this endpoint's adapter retains, as the endpoint's own actions and events say.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Retained {
    Frame,
    Decision,
    ResponderKey,
}

/// One endpoint: its public-ABI objects and what it has observed through them.
#[cfg(windows)]
struct Endpoint {
    role: Role,
    scenario: Scenario,
    runtime: u64,
    authority: u64,
    host: u64,
    connection: u64,
    run: u64,
    accepted_at: Option<Instant>,
    identity: Option<[u8; 32]>,
    queue: VecDeque<Step>,
    retained: Option<Retained>,
    own_mac: bool,
    peer_mac: bool,
    finish_queued: bool,
    saw_initiator_finish: bool,
    result: u64,
    backpressured: usize,
    done: Option<String>,
}

#[cfg(windows)]
type RunAction = unsafe extern "C" fn(u64, u64, u64, u64, *mut Action) -> i32;
#[cfg(windows)]
type RunDecision = unsafe extern "C" fn(u64, u64, u64, u64, *const u8, *mut Action) -> i32;

#[cfg(windows)]
fn report(key: &str, value: impl std::fmt::Display) {
    println!("{REPORT}{key} {value}");
}

#[cfg(windows)]
impl Endpoint {
    /// Runtime, authority, host, and a listener the endpoint bound itself on loopback (the
    /// caller's job), attached with its own Responder Bootstrap and the exact expected peer.
    fn open(role: Role, scenario: Scenario) -> (Self, u16) {
        // SAFETY (every call in this function): each pointer is a live, aligned, exclusively
        // borrowed local of the declared type, valid for the whole call; the scope and the views'
        // bytes are `'static`.
        unsafe {
            assert_eq!(sas_pairing_abi_version(), SAS_PAIRING_ABI_VERSION);
            let mut runtime = u64::MAX;
            assert_eq!(sas_pairing_runtime_create(&mut runtime), SAS_PAIRING_OK);
            let scope = format!(
                "p7.7-two-sided-{}-{}-{}",
                scenario.name(),
                role.name(),
                std::process::id()
            );
            let mut authority = u64::MAX;
            assert_eq!(
                sas_pairing_authority_register(
                    runtime,
                    scope.as_ptr(),
                    scope.len(),
                    &mut authority
                ),
                SAS_PAIRING_OK
            );
            let mut host = u64::MAX;
            assert_eq!(
                sas_pairing_host_create(runtime, authority, &mut host),
                SAS_PAIRING_OK
            );
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
            let port = listener.local_addr().expect("address").port();
            let mut slot = listener.into_raw_socket() as usize;
            let (local, expected) = match role {
                Role::Initiator => (bootstrap(Role::Initiator), bootstrap(Role::Responder)),
                Role::Responder => (bootstrap(Role::Responder), bootstrap(Role::Initiator)),
            };
            assert_eq!(
                sas_pairing_host_attach_windows_listener(
                    runtime, host, &mut slot, &local, &expected
                ),
                SAS_PAIRING_OK
            );
            assert_eq!(
                slot, SAS_PAIRING_SOCKET_INVALID,
                "the library owns the socket"
            );
            let endpoint = Self {
                role,
                scenario,
                runtime,
                authority,
                host,
                connection: 0,
                run: 0,
                accepted_at: None,
                identity: None,
                queue: VecDeque::new(),
                retained: None,
                own_mac: false,
                peer_mac: false,
                finish_queued: false,
                saw_initiator_finish: false,
                result: 0,
                backpressured: 0,
                done: None,
            };
            assert_eq!(endpoint.status(), (SAS_PAIRING_AUTHORITY_READY, 10));
            (endpoint, port)
        }
    }

    fn status(&self) -> (u32, u32) {
        let (mut state, mut remaining) = (u32::MAX, u32::MAX);
        // SAFETY: two distinct live, aligned, exclusive `u32` slots.
        let status = unsafe {
            sas_pairing_authority_status(self.runtime, self.authority, &mut state, &mut remaining)
        };
        assert_eq!(status, SAS_PAIRING_OK);
        (state, remaining)
    }

    /// One drive; every event it wrote is returned (and must be consumed).
    fn drive(&self) -> Vec<Event> {
        let mut events = [ZERO_EVENT; SAS_PAIRING_MAX_DRIVE_EVENTS];
        let (mut count, mut failure) = (usize::MAX, i32::MAX);
        // SAFETY: `events` holds the capacity passed; both outputs are live, aligned, distinct.
        let status = unsafe {
            sas_pairing_host_drive(
                self.runtime,
                self.host,
                events.as_mut_ptr(),
                events.len(),
                &mut count,
                &mut failure,
            )
        };
        assert_eq!((status, failure), (SAS_PAIRING_OK, SAS_PAIRING_OK));
        events[..count].to_vec()
    }

    fn present(&self, run: u64) -> (i32, Presentation) {
        let mut out = ZERO_PRESENTATION;
        out.available = 0xEE;
        // SAFETY: `out` is a live, aligned, exclusive record.
        let status = unsafe {
            sas_pairing_run_presentation(self.runtime, self.host, self.connection, run, &mut out)
        };
        if status != SAS_PAIRING_OK {
            assert_eq!(out, ZERO_PRESENTATION, "a refused presentation is zero");
        }
        (status, out)
    }

    fn run_action(&self, export: RunAction) -> (i32, Action) {
        let mut out = ZERO_ACTION;
        out.event = 0xEE;
        // SAFETY: `out` is a live, aligned, exclusive record.
        let status =
            unsafe { export(self.runtime, self.host, self.connection, self.run, &mut out) };
        (status, out)
    }

    fn decide(&self, export: RunDecision, identity: &[u8; 32]) -> (i32, Action) {
        let mut out = ZERO_ACTION;
        out.event = 0xEE;
        // SAFETY: `identity` is 32 live bytes disjoint from the live, aligned, exclusive `out`.
        let status = unsafe {
            export(
                self.runtime,
                self.host,
                self.connection,
                self.run,
                identity.as_ptr(),
                &mut out,
            )
        };
        (status, out)
    }

    fn call(&self, step: Step) -> (i32, Action) {
        let identity = || self.identity.expect("a presented SAS");
        match step {
            Step::Start => {
                let (local, expected) = (bootstrap(Role::Initiator), bootstrap(Role::Responder));
                let mut out = ZERO_ACTION;
                out.event = 0xEE;
                // SAFETY: both views and their `'static` bytes are live for the call; `out` is a
                // live, aligned, exclusive record disjoint from them.
                let status = unsafe {
                    sas_pairing_connection_start_initiator(
                        self.runtime,
                        self.host,
                        self.connection,
                        &local,
                        &expected,
                        &mut out,
                    )
                };
                (status, out)
            }
            Step::Authorize => self.run_action(sas_pairing_run_authorize_exposure),
            Step::Expose => self.run_action(sas_pairing_run_expose_key),
            Step::EmitMac => self.run_action(sas_pairing_run_emit_bootstrap_mac),
            Step::Finish => self.run_action(sas_pairing_run_emit_initiator_finish),
            Step::ApproveWrong => {
                let mut wrong = identity();
                wrong[7] ^= 0x10;
                self.decide(sas_pairing_run_approve_sas, &wrong)
            }
            Step::Approve => self.decide(sas_pairing_run_approve_sas, &identity()),
            Step::Reject => self.decide(sas_pairing_run_reject_sas, &identity()),
            Step::Cancel => self.decide(sas_pairing_run_cancel_sas, &identity()),
        }
    }

    /// Runs queued steps in order until one is backpressured (`WRITE_PENDING`: nothing ran, the
    /// record stayed zero; it is retried after the next drive) or none is left.
    fn run_queue(&mut self) {
        while let Some(step) = self.queue.front().copied() {
            let (status, action) = self.call(step);
            if status == SAS_PAIRING_WRITE_PENDING {
                assert_eq!(
                    action, ZERO_ACTION,
                    "{step:?}: a backpressured record is zero"
                );
                assert!(
                    self.retained.is_some(),
                    "{step:?}: backpressure without a frame"
                );
                self.backpressured += 1;
                return;
            }
            self.queue.pop_front();
            self.on_action(step, status, action);
            if self.done.is_some() {
                return;
            }
        }
    }

    fn expect_action(&self, step: Step, (status, action): (i32, Action), event: u32, flags: u32) {
        assert_eq!(status, SAS_PAIRING_OK, "{step:?}");
        assert_eq!(
            (
                action.event,
                action.flags,
                action.reserved,
                action.deadline_kind
            ),
            (event, flags, 0, 0),
            "{step:?}"
        );
    }

    fn on_action(&mut self, step: Step, status: i32, action: Action) {
        let pending = SAS_PAIRING_ACTION_FLAG_WRITE_PENDING;
        match step {
            Step::Start => {
                self.expect_action(
                    step,
                    (status, action),
                    SAS_PAIRING_LOCAL_EVENT_INITIATOR_STARTED,
                    pending,
                );
                assert_ne!(action.run, 0);
                self.run = action.run;
                self.retained = Some(Retained::Frame);
                // Backpressure: while START is retained, a mutating action does nothing and
                // keeps a zero record; the read-only presentation still answers.
                let (refused, record) = self.call(Step::Authorize);
                assert_eq!((refused, record), (SAS_PAIRING_WRITE_PENDING, ZERO_ACTION));
                self.backpressured += 1;
                assert_eq!(self.present(self.run), (SAS_PAIRING_OK, ZERO_PRESENTATION));
            }
            Step::Authorize => {
                self.expect_action(
                    step,
                    (status, action),
                    SAS_PAIRING_LOCAL_EVENT_EXPOSURE_AUTHORIZED,
                    0,
                );
                assert_eq!(action.run, self.run);
                assert_eq!(
                    self.status(),
                    (SAS_PAIRING_AUTHORITY_READY, 10),
                    "authorization spends nothing"
                );
            }
            Step::Expose => {
                self.expect_action(
                    step,
                    (status, action),
                    SAS_PAIRING_LOCAL_EVENT_KEY_EXPOSED,
                    pending,
                );
                assert_eq!(action.run, self.run);
                assert_eq!(self.status(), (SAS_PAIRING_AUTHORITY_BUSY, 0), "guard held");
                self.retained = Some(match self.role {
                    Role::Initiator => Retained::Frame,
                    Role::Responder => Retained::ResponderKey,
                });
                if self.role == Role::Responder {
                    // The Responder holds both keys now: its SAS is presented while its key is
                    // still retained (presentation is read-only and never backpressured).
                    self.on_sas();
                }
            }
            Step::ApproveWrong => {
                assert_eq!(
                    (status, action),
                    (SAS_PAIRING_CEREMONY_IDENTITY_MISMATCH, ZERO_ACTION),
                    "a decision must name the exact presented identity"
                );
            }
            Step::Approve => {
                self.expect_action(
                    step,
                    (status, action),
                    SAS_PAIRING_LOCAL_EVENT_SAS_APPROVED,
                    0,
                );
                assert_eq!(action.run, self.run);
                assert_eq!(
                    self.present(self.run),
                    (SAS_PAIRING_OK, ZERO_PRESENTATION),
                    "a decided SAS is no longer presented"
                );
            }
            Step::EmitMac => {
                self.expect_action(
                    step,
                    (status, action),
                    SAS_PAIRING_LOCAL_EVENT_BOOTSTRAP_MAC_EMITTED,
                    pending,
                );
                assert_eq!(action.run, self.run);
                self.retained = Some(Retained::Frame);
                self.own_mac = true;
                self.maybe_finish();
            }
            Step::Finish => {
                self.expect_action(
                    step,
                    (status, action),
                    SAS_PAIRING_LOCAL_EVENT_INITIATOR_FINISH_EMITTED,
                    pending,
                );
                assert_eq!(action.run, self.run);
                self.retained = Some(Retained::Frame);
            }
            Step::Reject | Step::Cancel => {
                let event = if step == Step::Reject {
                    SAS_PAIRING_LOCAL_EVENT_SAS_REJECTED
                } else {
                    SAS_PAIRING_LOCAL_EVENT_SAS_CANCELLED
                };
                self.expect_action(step, (status, action), event, pending);
                assert_eq!(action.run, 0, "the decision ended the run");
                let stale = self.run;
                assert_eq!(
                    self.present(stale).0,
                    SAS_PAIRING_INVALID_HANDLE,
                    "the ended run's handle names nothing"
                );
                assert_eq!(
                    self.status(),
                    (SAS_PAIRING_AUTHORITY_READY, 9),
                    "the spent opportunity is not refunded"
                );
                self.run = 0;
                self.retained = Some(Retained::Decision);
                report(
                    "DECIDED",
                    if step == Step::Reject {
                        "reject"
                    } else {
                        "cancel"
                    },
                );
            }
        }
    }

    /// The initiator emits INITIATOR_FINISH only once its own MAC was produced and the peer's
    /// was authenticated: an explicit step, never chained to either.
    fn maybe_finish(&mut self) {
        if self.role == Role::Initiator && self.own_mac && self.peer_mac && !self.finish_queued {
            self.finish_queued = true;
            self.queue.push_back(Step::Finish);
        }
    }

    /// The SAS is live on this side: read it, report it, and decide as the scenario says.
    fn on_sas(&mut self) {
        let (status, shown) = self.present(self.run);
        assert_eq!(status, SAS_PAIRING_OK);
        assert_eq!(shown.available, 1, "a live SAS is presented");
        assert_eq!((shown.reserved, shown.reserved_tail), (0, [0, 0]));
        let decimal = std::str::from_utf8(&shown.decimal).expect("ASCII display");
        assert_eq!(self.present(self.run), (SAS_PAIRING_OK, shown), "read-only");
        report("SAS", decimal);
        report("IDENTITY", hex(&shown.ceremony_identity));
        self.identity = Some(shown.ceremony_identity);
        let mine = match (self.scenario, self.role) {
            (scenario, _) if scenario.completes() => {
                self.queue
                    .extend([Step::ApproveWrong, Step::Approve, Step::EmitMac]);
                return;
            }
            (Scenario::Reject, Role::Responder) => Step::Reject,
            (Scenario::Cancel, Role::Initiator) => Step::Cancel,
            (Scenario::Close, Role::Initiator) => {
                self.close_connection();
                return;
            }
            // Undecided: this side waits for the peer's decision or teardown.
            _ => return,
        };
        self.queue.push_back(mine);
    }

    /// Explicit connection close (cleanup): the handle and its run handle end at once.
    fn close_connection(&mut self) {
        // SAFETY: integer arguments only.
        let status =
            unsafe { sas_pairing_connection_close(self.runtime, self.host, self.connection) };
        assert_eq!(status, SAS_PAIRING_OK);
        assert_eq!(self.present(self.run).0, SAS_PAIRING_INVALID_HANDLE);
        self.connection_ended("closed locally");
    }

    fn connection_ended(&mut self, why: &str) {
        self.connection = 0;
        self.run = 0;
        self.done = Some(why.to_owned());
    }

    fn on_event(&mut self, event: &Event) {
        assert_eq!(event.reserved, 0);
        assert!(
            event.request_id[event.request_id_len as usize..]
                .iter()
                .all(|byte| *byte == 0),
            "request-ID tail bytes are zero"
        );
        match event.kind {
            SAS_PAIRING_EVENT_CONNECTION_ACCEPTED => {
                assert_eq!(self.connection, 0, "the relay makes one connection");
                assert_ne!(event.connection, 0);
                self.connection = event.connection;
                self.accepted_at = Some(Instant::now());
                if self.role == Role::Initiator && self.scenario != Scenario::Deadline {
                    self.queue.push_back(Step::Start);
                }
            }
            SAS_PAIRING_EVENT_CONNECTION_STEP => {
                assert_eq!(event.connection, self.connection);
                match event.step_kind {
                    SAS_PAIRING_STEP_INBOUND => self.on_inbound(event),
                    SAS_PAIRING_STEP_WRITTEN => {
                        assert_eq!((event.run, event.result), (0, 0));
                        let written = self.retained.take().expect("a retained frame");
                        if written == Retained::Decision {
                            self.done = Some("decision written".into());
                        }
                        if written == Retained::ResponderKey && self.scenario == Scenario::Detach {
                            self.detach();
                        }
                    }
                    SAS_PAIRING_STEP_CONFIRMED => {
                        assert_eq!(self.role, Role::Initiator);
                        assert_eq!(event.run, 0, "terminal: no run handle");
                        assert_ne!(
                            event.result, 0,
                            "the final ACK's confirmation is the result"
                        );
                        self.retained = None;
                        self.complete(event.result);
                    }
                    other => panic!("{:?}: unexpected step kind {other}: {event:?}", self.role),
                }
            }
            SAS_PAIRING_EVENT_CONNECTION_CLOSED => {
                assert_eq!(event.connection, self.connection);
                report("CLOSED", event.reason);
                if self.scenario == Scenario::Deadline {
                    let waited = self.accepted_at.expect("accepted").elapsed();
                    report("CLOSED_AFTER_MS", waited.as_millis());
                }
                if self.run != 0 {
                    assert_eq!(
                        self.present(self.run).0,
                        SAS_PAIRING_INVALID_HANDLE,
                        "a closed connection's run handle names nothing"
                    );
                }
                self.connection_ended("connection closed");
            }
            other => panic!("{:?}: unexpected event kind {other}: {event:?}", self.role),
        }
    }

    fn on_inbound(&mut self, event: &Event) {
        let pending = event.flags & SAS_PAIRING_EVENT_FLAG_WRITE_PENDING != 0;
        match (self.role, event.protocol_event) {
            (Role::Responder, SAS_PAIRING_PROTOCOL_EVENT_START_ACCEPTED) => {
                assert_eq!(self.run, 0);
                assert_ne!(event.run, 0);
                assert_eq!(event.request_id_len, 16, "the Initiator's core request ID");
                assert!(pending, "ACCEPT is retained");
                self.run = event.run;
                self.retained = Some(Retained::Frame);
            }
            (Role::Initiator, SAS_PAIRING_PROTOCOL_EVENT_ACCEPT)
            | (Role::Responder, SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_KEY) => {
                assert_eq!(event.run, self.run, "one handle per exact run");
                self.queue.extend([Step::Authorize, Step::Expose]);
            }
            (Role::Initiator, SAS_PAIRING_PROTOCOL_EVENT_RESPONDER_KEY) => {
                assert_eq!(event.run, self.run);
                self.on_sas();
            }
            (_, SAS_PAIRING_PROTOCOL_EVENT_BOOTSTRAP_MAC_AUTHENTICATED) => {
                assert_eq!(event.run, self.run);
                self.peer_mac = true;
                self.maybe_finish();
            }
            (Role::Responder, SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH) => {
                assert_eq!((event.run, event.result), (self.run, 0), "no result yet");
                assert!(pending, "the drive retained RESPONDER_FINISH_ACK");
                self.saw_initiator_finish = true;
                self.retained = Some(Retained::Frame);
            }
            (Role::Initiator, SAS_PAIRING_PROTOCOL_EVENT_RESPONDER_FINISH_ACK) => {
                assert_eq!((event.run, event.result), (self.run, 0), "no result yet");
                assert!(pending, "the final ACK is retained, unconfirmed");
                self.retained = Some(Retained::Frame);
                if self.scenario == Scenario::LostFinalAck {
                    // The harness cuts the A→B link now; the final ACK this endpoint writes next
                    // never reaches B.
                    report("FINAL_ACK_PENDING", self.run);
                    let mut go = String::new();
                    std::io::stdin().read_line(&mut go).expect("harness go");
                    assert_eq!(go.trim(), "GO");
                }
            }
            (Role::Responder, SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH_ACK) => {
                assert_eq!(event.run, 0, "terminal: no run handle");
                assert_ne!(event.result, 0);
                self.complete(event.result);
            }
            (_, SAS_PAIRING_PROTOCOL_EVENT_PEER_CANCEL) => {
                assert_eq!(event.run, 0, "a verified peer CANCEL ends the run");
                report("PEER_CANCEL", event.cancel_reason);
                let stale = self.run;
                assert_eq!(self.present(stale).0, SAS_PAIRING_INVALID_HANDLE);
                self.run = 0;
                self.done = Some("peer cancel".into());
            }
            (role, other) => panic!("{role:?}: unexpected protocol event {other}: {event:?}"),
        }
    }

    fn detach(&mut self) {
        let run = self.run;
        // SAFETY: integer arguments only.
        assert_eq!(
            unsafe { sas_pairing_host_detach_listener(self.runtime, self.host) },
            SAS_PAIRING_OK
        );
        assert_eq!(self.present(run).0, SAS_PAIRING_LISTENER_NOT_ATTACHED);
        let mut events = [ZERO_EVENT; SAS_PAIRING_MAX_DRIVE_EVENTS];
        let (mut count, mut failure) = (usize::MAX, i32::MAX);
        // SAFETY: as in `drive`.
        let status = unsafe {
            sas_pairing_host_recheck_after_resume(
                self.runtime,
                self.host,
                events.as_mut_ptr(),
                events.len(),
                &mut count,
                &mut failure,
            )
        };
        assert_eq!(
            (status, count, failure),
            (SAS_PAIRING_LISTENER_NOT_ATTACHED, 0, SAS_PAIRING_OK)
        );
        self.connection_ended("listener detached");
    }

    /// A local verified completion surfaced: read it through the public ABI and report it.
    fn complete(&mut self, result: u64) {
        let stale = self.run;
        assert_eq!(
            self.present(stale).0,
            SAS_PAIRING_INVALID_HANDLE,
            "run retired"
        );
        self.run = 0;
        self.result = result;
        let fields = self.result_fields();
        report("RESULT_IDENTITY", hex(&fields.0.ceremony_identity));
        report("RESULT_PEER_ROLE", fields.0.peer_role);
        report("RESULT_PROFILE_VERSION", fields.0.profile_version);
        for (name, value) in &fields.1 {
            report(&format!("RESULT_{name}"), hex(value));
        }
        assert_eq!(
            self.status(),
            (SAS_PAIRING_AUTHORITY_READY, 9),
            "one opportunity spent"
        );
        self.done = Some("local completion".into());
    }

    /// The result's info and its four variable fields, each copied with an exact buffer after a
    /// size query.
    fn result_fields(&self) -> (ResultInfo, Vec<(&'static str, Vec<u8>)>) {
        let mut info = ResultInfo {
            ceremony_identity: [0xEE; 32],
            peer_role: 99,
            profile_version: 99,
            request_id_len: 99,
            peer_bootstrap_len: 99,
            shared_context_len: 99,
            profile_identifier_len: 99,
        };
        // SAFETY: `info` is a live, aligned, exclusive record.
        let status = unsafe { sas_pairing_result_info(self.runtime, self.result, &mut info) };
        assert_eq!(status, SAS_PAIRING_OK);
        let mut fields = Vec::new();
        for (name, field, len) in [
            (
                "REQUEST_ID",
                SAS_PAIRING_RESULT_FIELD_REQUEST_ID,
                info.request_id_len,
            ),
            (
                "PEER_BOOTSTRAP",
                SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_PEER_BOOTSTRAP,
                info.peer_bootstrap_len,
            ),
            (
                "SHARED_CONTEXT",
                SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_SHARED_CONTEXT,
                info.shared_context_len,
            ),
            (
                "PROFILE",
                SAS_PAIRING_RESULT_FIELD_PROFILE_IDENTIFIER,
                info.profile_identifier_len,
            ),
        ] {
            let mut required = usize::MAX;
            // SAFETY: a null buffer with capacity 0 (the size query); `required` is live.
            let query = unsafe {
                sas_pairing_result_copy(
                    self.runtime,
                    self.result,
                    field,
                    std::ptr::null_mut(),
                    0,
                    &mut required,
                )
            };
            assert_eq!(required, len as usize);
            assert_eq!(
                query,
                if len == 0 {
                    SAS_PAIRING_OK
                } else {
                    SAS_PAIRING_BUFFER_TOO_SMALL
                }
            );
            let mut buffer = vec![0xEE; required];
            // SAFETY: `buffer` holds `required` live bytes; `required` is a live `size_t`.
            let copied = unsafe {
                sas_pairing_result_copy(
                    self.runtime,
                    self.result,
                    field,
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &mut required,
                )
            };
            assert_eq!((copied, required), (SAS_PAIRING_OK, buffer.len()));
            fields.push((name, buffer));
        }
        (info, fields)
    }

    /// Every frontend object ends; an existing result survives all of it until its own destroy,
    /// and the runtime goes last.
    fn teardown(self) {
        let before = (self.result != 0).then(|| self.result_fields());
        // SAFETY (every call below): integer arguments only.
        unsafe {
            if self.connection != 0 {
                assert_eq!(
                    sas_pairing_connection_close(self.runtime, self.host, self.connection),
                    SAS_PAIRING_OK
                );
            }
            assert_eq!(
                sas_pairing_host_detach_listener(self.runtime, self.host),
                SAS_PAIRING_OK
            );
            assert_eq!(
                sas_pairing_host_destroy(self.runtime, self.host),
                SAS_PAIRING_OK
            );
            assert_eq!(
                sas_pairing_authority_release(self.runtime, self.authority),
                SAS_PAIRING_OK
            );
            if let Some(before) = before {
                assert_eq!(
                    self.result_fields(),
                    before,
                    "the result survives connection, listener, host, and authority teardown"
                );
                assert_eq!(
                    sas_pairing_result_destroy(self.runtime, self.result),
                    SAS_PAIRING_OK
                );
                assert_eq!(
                    sas_pairing_result_destroy(self.runtime, self.result),
                    SAS_PAIRING_INVALID_HANDLE
                );
                report("RESULT_SURVIVED_TEARDOWN", 1);
            }
            assert_eq!(sas_pairing_runtime_destroy(self.runtime), SAS_PAIRING_OK);
            assert_eq!(
                sas_pairing_runtime_destroy(self.runtime),
                SAS_PAIRING_INVALID_HANDLE
            );
        }
    }
}

/// The endpoint process body: role and scenario come from the harness's environment.
#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by the two_sided_* tests"]
fn child_endpoint() {
    if !is_child(CHILD_NAME) {
        return;
    }
    let role = match env::var(ROLE_ENV).expect("role").as_str() {
        "initiator" => Role::Initiator,
        "responder" => Role::Responder,
        other => panic!("unknown role {other}"),
    };
    let scenario = Scenario::from_name(&env::var(SCENARIO_ENV).expect("scenario"));
    let (mut endpoint, port) = Endpoint::open(role, scenario);
    report("PORT", port);
    let give_up = Instant::now() + Duration::from_secs(60);
    while endpoint.done.is_none() {
        assert!(
            Instant::now() < give_up,
            "{role:?} in {scenario:?} made no progress"
        );
        endpoint.run_queue();
        if endpoint.done.is_some() {
            break;
        }
        for event in endpoint.drive() {
            endpoint.on_event(&event);
        }
    }
    report("DONE", endpoint.done.as_deref().unwrap_or_default());
    report("BACKPRESSURED", endpoint.backpressured);
    if scenario == Scenario::LostFinalAck && role == Role::Responder {
        assert!(
            endpoint.saw_initiator_finish,
            "B was awaiting the final ACK"
        );
    }
    let spent = if scenario == Scenario::Deadline {
        10
    } else {
        9
    };
    assert_eq!(endpoint.status(), (SAS_PAIRING_AUTHORITY_READY, spent));
    report("REMAINING", spent);
    endpoint.teardown();
    report("END", scenario.name());
}

// --- The harness: two endpoint processes and a byte-transparent relay --------------------------

/// A report line starts at its prefix: the first one shares its line with libtest's
/// `test ... ` banner.
#[cfg(windows)]
fn report_of(line: String) -> String {
    match line.find(REPORT) {
        Some(start) => line[start..].to_owned(),
        None => line,
    }
}

/// One endpoint process and its report lines.
#[cfg(windows)]
struct Process {
    role: Role,
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
    seen: Vec<String>,
    stderr: Arc<Mutex<String>>,
}

#[cfg(windows)]
impl Process {
    fn spawn(role: Role, scenario: Scenario) -> Self {
        let mut child = Command::new(env::current_exe().expect("test binary"))
            .args([
                &format!("abi::tests::{CHILD_NAME}"),
                "--exact",
                "--ignored",
                "--test-threads=1",
                "--nocapture",
            ])
            .env(CHILD_ENV, CHILD_NAME)
            .env(ROLE_ENV, role.name())
            .env(SCENARIO_ENV, scenario.name())
            .stdin(if scenario == Scenario::LostFinalAck {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn endpoint");
        let (send, lines) = mpsc::channel();
        let stdout = child.stdout.take().expect("stdout");
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if send.send(line).is_err() {
                    break;
                }
            }
        });
        let stderr = Arc::new(Mutex::new(String::new()));
        let sink = Arc::clone(&stderr);
        let mut pipe = child.stderr.take().expect("stderr");
        thread::spawn(move || {
            let mut text = String::new();
            let _ = pipe.read_to_string(&mut text);
            sink.lock().unwrap().push_str(&text);
        });
        let stdin = child.stdin.take();
        Self {
            role,
            child,
            stdin,
            lines,
            seen: Vec::new(),
            stderr,
        }
    }

    /// Waits for the report `key` and returns its value.
    fn expect(&mut self, key: &str) -> String {
        let give_up = Instant::now() + Duration::from_secs(90);
        loop {
            if let Some(value) = self.value(key) {
                return value;
            }
            let left = give_up.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) => self.seen.push(report_of(line)),
                Err(_) => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    thread::sleep(Duration::from_millis(100));
                    panic!(
                        "{:?} never reported {key}\n{}\n{}",
                        self.role,
                        self.seen.join("\n"),
                        self.stderr.lock().unwrap()
                    );
                }
            }
        }
    }

    fn value(&self, key: &str) -> Option<String> {
        let prefix = format!("{REPORT}{key} ");
        self.seen
            .iter()
            .find_map(|line| line.strip_prefix(&prefix))
            .map(str::to_owned)
    }

    fn send(&mut self, line: &str) {
        let stdin = self.stdin.as_mut().expect("piped stdin");
        writeln!(stdin, "{line}").expect("write to endpoint");
        stdin.flush().expect("flush");
    }

    /// Waits for the endpoint to finish its child test successfully; returns its reports.
    fn finish(mut self) -> Vec<String> {
        let _ = self.expect("END");
        let give_up = Instant::now() + Duration::from_secs(60);
        let status = loop {
            if let Some(status) = self.child.try_wait().expect("child status") {
                break status;
            }
            assert!(Instant::now() < give_up, "{:?} did not exit", self.role);
            thread::sleep(Duration::from_millis(10));
        };
        while let Ok(line) = self.lines.recv_timeout(Duration::from_secs(5)) {
            self.seen.push(report_of(line));
        }
        let all = self.seen.join("\n");
        assert!(
            status.success(),
            "{:?} failed: {status}\n{all}\n{}",
            self.role,
            self.stderr.lock().unwrap()
        );
        assert!(
            all.contains("test result: ok. 1 passed"),
            "{:?} did not run its endpoint\n{all}",
            self.role
        );
        self.seen
    }
}

/// The byte-transparent relay: two connections, one to each endpoint's listener, and one pump
/// per direction that copies whatever bytes arrive, never reading, building, or changing them.
/// `cut` simulates a link failure from A to B: from then on, bytes from A are lost.
#[cfg(windows)]
struct Relay {
    to_a: TcpStream,
    to_b: TcpStream,
    cut: Arc<AtomicBool>,
    pumps: Vec<JoinHandle<u64>>,
}

#[cfg(windows)]
impl Relay {
    fn connect(port_a: u16, port_b: u16, propagate_close: bool) -> Self {
        let to_a = TcpStream::connect(("127.0.0.1", port_a)).expect("connect to A");
        let to_b = TcpStream::connect(("127.0.0.1", port_b)).expect("connect to B");
        let cut = Arc::new(AtomicBool::new(false));
        let pumps = vec![
            Self::pump(&to_a, &to_b, Some(Arc::clone(&cut)), propagate_close),
            Self::pump(&to_b, &to_a, None, propagate_close),
        ];
        Self {
            to_a,
            to_b,
            cut,
            pumps,
        }
    }

    /// Copies `from` to `to` until `from` ends; returns the bytes forwarded.
    fn pump(
        from: &TcpStream,
        to: &TcpStream,
        cut: Option<Arc<AtomicBool>>,
        propagate_close: bool,
    ) -> JoinHandle<u64> {
        let (mut from, mut to) = (from.try_clone().unwrap(), to.try_clone().unwrap());
        thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            let mut forwarded = 0;
            loop {
                let read = match from.read(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => read,
                };
                if cut.as_ref().is_some_and(|cut| cut.load(Ordering::SeqCst)) {
                    continue;
                }
                if to.write_all(&buffer[..read]).is_err() {
                    break;
                }
                forwarded += read as u64;
            }
            if propagate_close {
                let _ = to.shutdown(Shutdown::Write);
            }
            forwarded
        })
    }

    fn stop(self) -> (u64, u64) {
        let _ = self.to_a.shutdown(Shutdown::Both);
        let _ = self.to_b.shutdown(Shutdown::Both);
        let mut pumps = self.pumps.into_iter().map(|pump| pump.join().unwrap());
        (pumps.next().unwrap(), pumps.next().unwrap())
    }
}

/// The two endpoints' reports after one two-sided run.
#[cfg(windows)]
struct Pair {
    a: Vec<String>,
    b: Vec<String>,
    forwarded: (u64, u64),
}

#[cfg(windows)]
fn value(lines: &[String], key: &str) -> Option<String> {
    let prefix = format!("{REPORT}{key} ");
    lines
        .iter()
        .find_map(|line| line.strip_prefix(&prefix))
        .map(str::to_owned)
}

#[cfg(windows)]
fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

#[cfg(windows)]
fn run_pair(scenario: Scenario) -> Pair {
    let mut a = Process::spawn(Role::Initiator, scenario);
    let mut b = Process::spawn(Role::Responder, scenario);
    let port_a: u16 = a.expect("PORT").parse().unwrap();
    let port_b: u16 = b.expect("PORT").parse().unwrap();
    // A deadline run keeps each side's own deadline observable: a close is not forwarded.
    let relay = Relay::connect(port_a, port_b, scenario != Scenario::Deadline);
    if scenario == Scenario::LostFinalAck {
        a.expect("FINAL_ACK_PENDING");
        relay.cut.store(true, Ordering::SeqCst);
        a.send("GO");
        a.expect("END");
        // Only now does B's side of the network go away: B never received the final ACK.
        let _ = relay.to_b.shutdown(Shutdown::Both);
    }
    let a = a.finish();
    let b = b.finish();
    let forwarded = relay.stop();
    Pair { a, b, forwarded }
}

#[cfg(windows)]
impl Pair {
    fn a(&self, key: &str) -> Option<String> {
        value(&self.a, key)
    }

    fn b(&self, key: &str) -> Option<String> {
        value(&self.b, key)
    }

    /// Both endpoints presented the same SAS and the same ceremony identity.
    fn assert_same_sas(&self) -> Vec<u8> {
        let (sas_a, sas_b) = (self.a("SAS").expect("A SAS"), self.b("SAS").expect("B SAS"));
        assert_eq!(sas_a.len(), 14);
        assert_eq!(sas_a, sas_b, "both sides show the same comparison value");
        let identity = self.a("IDENTITY").expect("A identity");
        assert_eq!(Some(&identity), self.b("IDENTITY").as_ref());
        unhex(&identity)
    }

    fn assert_no_results(&self) {
        for lines in [&self.a, &self.b] {
            assert!(value(lines, "RESULT_IDENTITY").is_none());
        }
    }
}

#[cfg(windows)]
#[test]
fn two_sided_public_abi_ceremony_completes_on_both_endpoints() {
    let pair = run_pair(Scenario::Success);
    let identity = pair.assert_same_sas();
    let field = |lines: &[String], key: &str| unhex(&value(lines, key).expect(key));
    for (lines, peer_role, peer_identity, peer_key) in [
        (
            &pair.a,
            SAS_PAIRING_ROLE_RESPONDER,
            B_IDENTITY,
            B_PUBLIC_KEY,
        ),
        (
            &pair.b,
            SAS_PAIRING_ROLE_INITIATOR,
            A_IDENTITY,
            A_PUBLIC_KEY,
        ),
    ] {
        assert_eq!(field(lines, "RESULT_IDENTITY"), identity);
        assert_eq!(
            value(lines, "RESULT_PEER_ROLE"),
            Some(peer_role.to_string())
        );
        assert_eq!(value(lines, "RESULT_PROFILE_VERSION").as_deref(), Some("1"));
        assert_eq!(field(lines, "RESULT_PROFILE"), PROFILE_IDENTIFIER);
        assert_eq!(field(lines, "RESULT_SHARED_CONTEXT"), SHARED_CONTEXT);
        let peer = field(lines, "RESULT_PEER_BOOTSTRAP");
        assert!(contains(&peer, peer_identity) && contains(&peer, peer_key));
        assert_eq!(
            value(lines, "RESULT_SURVIVED_TEARDOWN").as_deref(),
            Some("1")
        );
        assert_eq!(value(lines, "REMAINING").as_deref(), Some("9"));
        let backpressured: usize = value(lines, "BACKPRESSURED").unwrap().parse().unwrap();
        assert!(backpressured >= 1, "WRITE_PENDING was exercised");
    }
    let request_id = field(&pair.a, "RESULT_REQUEST_ID");
    assert_eq!(request_id.len(), 16);
    assert_eq!(field(&pair.b, "RESULT_REQUEST_ID"), request_id);
    assert_ne!(
        field(&pair.a, "RESULT_PEER_BOOTSTRAP"),
        field(&pair.b, "RESULT_PEER_BOOTSTRAP")
    );
    assert!(pair.forwarded.0 > 0 && pair.forwarded.1 > 0);
}

#[cfg(windows)]
#[test]
fn two_sided_reject_reaches_the_undecided_peer_as_a_verified_cancel() {
    let pair = run_pair(Scenario::Reject);
    pair.assert_same_sas();
    assert_eq!(pair.b("DECIDED").as_deref(), Some("reject"));
    assert_eq!(
        pair.a("PEER_CANCEL"),
        Some(SAS_PAIRING_CANCEL_REASON_USER_REJECTION.to_string())
    );
    pair.assert_no_results();
}

#[cfg(windows)]
#[test]
fn two_sided_cancel_reaches_the_undecided_peer_as_a_verified_cancel() {
    let pair = run_pair(Scenario::Cancel);
    pair.assert_same_sas();
    assert_eq!(pair.a("DECIDED").as_deref(), Some("cancel"));
    assert_eq!(
        pair.b("PEER_CANCEL"),
        Some(SAS_PAIRING_CANCEL_REASON_USER_CANCELLATION.to_string())
    );
    pair.assert_no_results();
}

#[cfg(windows)]
#[test]
fn two_sided_connection_close_ends_the_ceremony_on_both_sides() {
    let pair = run_pair(Scenario::Close);
    pair.assert_same_sas();
    assert_eq!(pair.a("DONE").as_deref(), Some("closed locally"));
    let reason: u32 = pair.b("CLOSED").expect("B closed").parse().unwrap();
    assert!(
        [
            SAS_PAIRING_EVENT_REASON_PEER_CLOSED,
            SAS_PAIRING_EVENT_REASON_READINESS_FAILURE
        ]
        .contains(&reason)
    );
    pair.assert_no_results();
}

#[cfg(windows)]
#[test]
fn two_sided_listener_detach_ends_the_ceremony_on_both_sides() {
    let pair = run_pair(Scenario::Detach);
    pair.assert_same_sas();
    assert_eq!(pair.b("DONE").as_deref(), Some("listener detached"));
    let reason: u32 = pair.a("CLOSED").expect("A closed").parse().unwrap();
    assert!(
        [
            SAS_PAIRING_EVENT_REASON_PEER_CLOSED,
            SAS_PAIRING_EVENT_REASON_READINESS_FAILURE
        ]
        .contains(&reason)
    );
    pair.assert_no_results();
}

#[cfg(windows)]
#[test]
fn two_sided_idle_connections_reach_their_own_first_frame_deadline() {
    let pair = run_pair(Scenario::Deadline);
    for lines in [&pair.a, &pair.b] {
        assert_eq!(
            value(lines, "CLOSED"),
            Some(SAS_PAIRING_EVENT_REASON_TRANSPORT_DEADLINE.to_string())
        );
        let waited: u64 = value(lines, "CLOSED_AFTER_MS").unwrap().parse().unwrap();
        assert!((9_000..40_000).contains(&waited), "{waited} ms");
        assert!(value(lines, "SAS").is_none(), "no ceremony started");
        assert_eq!(value(lines, "REMAINING").as_deref(), Some("10"));
    }
    pair.assert_no_results();
    assert_eq!(pair.forwarded, (0, 0), "no byte was sent either way");
}

#[cfg(windows)]
#[test]
fn two_sided_lost_final_ack_leaves_the_initiator_the_only_result_holder() {
    let pair = run_pair(Scenario::LostFinalAck);
    let identity = pair.assert_same_sas();
    assert_eq!(
        value(&pair.a, "RESULT_IDENTITY").map(|text| unhex(&text)),
        Some(identity)
    );
    assert_eq!(
        pair.a("RESULT_PEER_ROLE"),
        Some(SAS_PAIRING_ROLE_RESPONDER.to_string())
    );
    assert!(pair.b("RESULT_IDENTITY").is_none(), "B never completed");
    assert!(
        pair.b("CLOSED").is_some(),
        "B's connection ended without a result"
    );
}

// --- Consumer checks (platform-neutral) --------------------------------------------------------
// MARKER: everything above this line is the public-ABI consumer and its harness.

/// The consumer section above names nothing of the crate: no `crate::` or `super::super` path,
/// no core type, and no protocol code; its `extern "C"` declarations are exactly the 25 exports.
#[test]
fn the_two_sided_consumer_uses_only_the_public_abi() {
    const SOURCE: &str = include_str!("two_sided.rs");
    let consumer = SOURCE
        .split("// MARKER: everything above this line")
        .next()
        .unwrap();
    let code: String = consumer
        .lines()
        .map(|line| line.split("//").next().unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in [
        "crate::",
        "super::super",
        "Router",
        "RemoteCeremony",
        "HostConnection",
        "WindowsOwnerLoop",
        "WindowsTcpConnection",
        "TrustedAuthority",
        "PairingResult",
        "Bootstrap::",
        "Message",
        "decode(",
        "encode(",
        "AbiState",
        "PROCESS",
        "dispatch",
        "Harness",
        "with_loop",
        "test_hook",
    ] {
        assert!(!code.contains(forbidden), "the consumer uses {forbidden}");
    }
    let imports: Vec<&str> = code
        .lines()
        .filter(|line| line.trim_start().starts_with("use super::"))
        .collect();
    assert_eq!(
        imports,
        ["use super::{CHILD_ENV, is_child};"],
        "test plumbing only"
    );
    let declared: std::collections::BTreeSet<&str> = code
        .split("unsafe extern \"C\" {")
        .nth(1)
        .expect("extern block")
        .split("\n}")
        .next()
        .unwrap()
        .split("fn ")
        .skip(1)
        .map(|rest| rest.split('(').next().unwrap())
        .collect();
    assert_eq!(declared, super::exported_functions().into_keys().collect());
}

/// Every constant the consumer mirrors equals the header's `#define` of the same name.
#[test]
fn the_two_sided_consumer_mirrors_the_header() {
    const SOURCE: &str = include_str!("two_sided.rs");
    let defines: std::collections::BTreeMap<&str, &str> = super::HEADER
        .lines()
        .filter_map(|line| line.strip_prefix("#define "))
        .filter_map(|rest| rest.split_once(' '))
        .collect();
    let mut mirrored = 0;
    for line in SOURCE
        .lines()
        .filter(|line| line.starts_with("const SAS_PAIRING_"))
    {
        let (name, rest) = line["const ".len()..].split_once(':').unwrap();
        let value = rest.split('=').nth(1).unwrap().trim().trim_end_matches(';');
        let header = defines
            .get(name)
            .unwrap_or_else(|| panic!("{name} is not in the header"));
        let header = header
            .trim_start_matches("((")
            .split_once(')')
            .map_or(*header, |(_, value)| value.trim_end_matches(')'))
            .trim_end_matches('u');
        let parse = |text: &str| -> u128 {
            match text {
                "UINTPTR_MAX" | "usize::MAX" => u128::from(u64::MAX),
                hex if hex.starts_with("0x") => u128::from_str_radix(&hex[2..], 16).unwrap(),
                decimal => decimal.parse().unwrap(),
            }
        };
        assert_eq!(parse(value), parse(header), "{name}");
        mirrored += 1;
    }
    assert!(mirrored >= 40, "{mirrored} constants mirrored");
}
