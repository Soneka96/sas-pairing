//! Native ABI tests (P7.1 foundation; the P7.2 authority lifecycle is in `authority`, the P7.3
//! hosting contexts in `host`).
//!
//! Logic tests use test-local `AbiState`/`FatalState` instances. Tests of the real exports and
//! the process-global state run in isolated child processes (this test binary re-run with one
//! exact `#[ignore]`d child test), because the production fatal state can never be reset.

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    env, fs,
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
    ABI_VERSION, INVALID_ABI_VERSION, PROCESS, RuntimeHandle,
    authority::{
        AuthorityHandle, CORE_ENTRIES, SAS_PAIRING_AUTHORITY_BUSY, SAS_PAIRING_AUTHORITY_EXHAUSTED,
        SAS_PAIRING_AUTHORITY_READY, SAS_PAIRING_AUTHORITY_STATE_INVALID,
    },
    dispatch,
    hosting::{HostHandle, ROUTER_CONSTRUCTIONS},
    panic_boundary::{FatalState, contain},
    runtime::{AbiState, HandleCounter},
    sas_pairing_abi_version, sas_pairing_authority_register, sas_pairing_authority_release,
    sas_pairing_authority_status, sas_pairing_host_create, sas_pairing_host_destroy,
    sas_pairing_runtime_create, sas_pairing_runtime_destroy,
    status::*,
};

/// P7.2 authority lifecycle, error mapping, concurrency, and real-core panic tests.
mod authority;
/// P7.3 hosting contexts: host lifecycle, cascades, accounting neutrality, races.
mod host;

const HEADER: &str = include_str!("../../include/sas_pairing.h");
const MANIFEST: &str = include_str!("../../Cargo.toml");
const ABI_SOURCES: [(&str, &str); 6] = [
    ("mod.rs", include_str!("mod.rs")),
    ("authority.rs", include_str!("authority.rs")),
    ("hosting.rs", include_str!("hosting.rs")),
    ("panic_boundary.rs", include_str!("panic_boundary.rs")),
    ("runtime.rs", include_str!("runtime.rs")),
    ("status.rs", include_str!("status.rs")),
];
const STATUSES: [(&str, i32); 17] = [
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
    assert_eq!(size_of::<i32>(), 4);
    // Zero is never a valid handle: destroy rejects it, and the counter never issues it.
    assert_eq!(
        AbiState::new().destroy(0),
        SAS_PAIRING_INVALID_HANDLE,
        "handle 0 must be invalid"
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
    for (name, value) in AUTHORITY_STATES {
        assert_eq!(
            defines.get(name),
            Some(&format!("((sas_pairing_authority_state_t){value})").as_str()),
            "{name}"
        );
    }
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
        ])
    );
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
            "sas_pairing_host_create",
            "sas_pairing_host_destroy",
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
