//! P7.7 ABI v1 freeze checks: the compact manifest (`docs/p7-native-abi/abi-v1-manifest.md`)
//! against the Rust implementation and the C header, the fatal class of every export, and the
//! drive bounds the contract states.
//!
//! The manifest is parsed only as simple Markdown table rows: a row whose first cell names a
//! `SAS_PAIRING_` constant, an export (after its number), a type, or a record is a freeze entry.
//! Any accidental change of a status, enumeration value, constant, export, type, or record layout
//! in one of the three places fails here (or in `header_matches_the_rust_abi` for Rust ↔ header).

use std::{
    collections::{BTreeMap, BTreeSet},
    mem::{align_of, offset_of, size_of},
    sync::atomic::Ordering,
};

use super::super::{
    PROCESS, sas_pairing_abi_version, sas_pairing_authority_register,
    sas_pairing_authority_release, sas_pairing_authority_status, sas_pairing_connection_close,
    sas_pairing_connection_start_initiator, sas_pairing_host_attach_windows_listener,
    sas_pairing_host_create, sas_pairing_host_destroy, sas_pairing_host_detach_listener,
    sas_pairing_host_drive, sas_pairing_host_recheck_after_resume, sas_pairing_result_copy,
    sas_pairing_result_destroy, sas_pairing_result_info, sas_pairing_run_approve_sas,
    sas_pairing_run_authorize_exposure, sas_pairing_run_cancel_sas,
    sas_pairing_run_emit_bootstrap_mac, sas_pairing_run_emit_initiator_finish,
    sas_pairing_run_expose_key, sas_pairing_run_presentation, sas_pairing_run_reject_sas,
    sas_pairing_runtime_create, sas_pairing_runtime_destroy, status::*,
};
use super::{
    super::{
        BootstrapView, BytesView, control::Action, control::Presentation, network::Event,
        result::ResultInfo,
    },
    AUTHORITY_STATES, CORE_ENTRIES, HEADER, STATUSES, exported_functions, injected_panic_export,
    is_child, run_child, typed_constants,
};

const MANIFEST: &str = include_str!("../../../../docs/p7-native-abi/abi-v1-manifest.md");

/// The frozen fatal class of every export (P7-D-013): `normal` operations are refused with
/// `FATAL` after a contained panic without entering the core; `cleanup` and `data` stay admitted
/// and never clear fatal; `constant` reads a constant.
const FATAL_CLASSES: [(&str, &str); 25] = [
    ("sas_pairing_abi_version", "constant"),
    ("sas_pairing_runtime_create", "normal"),
    ("sas_pairing_runtime_destroy", "cleanup"),
    ("sas_pairing_authority_register", "normal"),
    ("sas_pairing_authority_release", "cleanup"),
    ("sas_pairing_authority_status", "normal"),
    ("sas_pairing_host_create", "normal"),
    ("sas_pairing_host_destroy", "cleanup"),
    ("sas_pairing_host_attach_windows_listener", "normal"),
    ("sas_pairing_host_detach_listener", "cleanup"),
    ("sas_pairing_host_drive", "normal"),
    ("sas_pairing_host_recheck_after_resume", "normal"),
    ("sas_pairing_connection_close", "cleanup"),
    ("sas_pairing_result_info", "data"),
    ("sas_pairing_result_copy", "data"),
    ("sas_pairing_result_destroy", "data"),
    ("sas_pairing_connection_start_initiator", "normal"),
    ("sas_pairing_run_authorize_exposure", "normal"),
    ("sas_pairing_run_expose_key", "normal"),
    ("sas_pairing_run_presentation", "normal"),
    ("sas_pairing_run_approve_sas", "normal"),
    ("sas_pairing_run_emit_bootstrap_mac", "normal"),
    ("sas_pairing_run_reject_sas", "normal"),
    ("sas_pairing_run_cancel_sas", "normal"),
    ("sas_pairing_run_emit_initiator_finish", "normal"),
];

/// The cells of every Markdown table row of the manifest, backticks removed.
fn manifest_rows() -> Vec<Vec<String>> {
    MANIFEST
        .lines()
        .filter(|line| line.starts_with('|') && !line.starts_with("|---"))
        .map(|line| {
            line.trim_matches('|')
                .split('|')
                .map(|cell| cell.trim().replace('`', ""))
                .collect()
        })
        .collect()
}

/// A header or manifest value as an integer: `1u`, `0x2`, `((type)17)`, `UINTPTR_MAX`.
fn numeric(text: &str) -> u128 {
    let text = text.trim();
    let text = match text.strip_prefix("((") {
        Some(cast) => cast.split_once(')').unwrap().1.trim_end_matches(')'),
        None => text,
    };
    let text = text.trim_end_matches('u');
    match text {
        "UINTPTR_MAX" => usize::MAX as u128,
        hex if hex.starts_with("0x") => u128::from_str_radix(&hex[2..], 16).unwrap(),
        decimal => decimal
            .parse()
            .unwrap_or_else(|_| panic!("not a number: {text}")),
    }
}

/// The C type a header define casts to (`None` for a plain integer).
fn cast_of(value: &str) -> Option<&str> {
    value
        .strip_prefix("((")?
        .split_once(')')
        .map(|(cast, _)| cast)
}

/// The size of the field `field` projects from a `T`.
fn field_size<T, F>(_: fn(&T) -> &F) -> usize {
    size_of::<F>()
}

/// `(record, field) → (offset, size)` of every field of every public record, from the Rust
/// types the ABI writes and reads.
fn rust_fields() -> BTreeMap<(&'static str, &'static str), (usize, usize)> {
    macro_rules! fields {
        ($record:literal, $type:ty, [$($field:ident),* $(,)?]) => {
            [$((
                ($record, stringify!($field)),
                (offset_of!($type, $field), field_size(|value: &$type| &value.$field)),
            )),*]
        };
    }
    let mut all = BTreeMap::new();
    all.extend(fields!("sas_pairing_bytes_view_t", BytesView, [data, len]));
    all.extend(fields!(
        "sas_pairing_bootstrap_view_t",
        BootstrapView,
        [
            application_identity,
            key_algorithm,
            public_key,
            shared_context
        ]
    ));
    all.extend(fields!(
        "sas_pairing_event_t",
        Event,
        [
            kind,
            step_kind,
            protocol_event,
            reason,
            deadline_kind,
            cancel_state,
            cancel_reason,
            flags,
            connection,
            run,
            result,
            request_id_len,
            reserved,
            request_id,
        ]
    ));
    all.extend(fields!(
        "sas_pairing_result_info_t",
        ResultInfo,
        [
            ceremony_identity,
            peer_role,
            profile_version,
            request_id_len,
            peer_bootstrap_len,
            shared_context_len,
            profile_identifier_len,
        ]
    ));
    all.extend(fields!(
        "sas_pairing_action_t",
        Action,
        [event, deadline_kind, flags, reserved, run]
    ));
    all.extend(fields!(
        "sas_pairing_sas_presentation_t",
        Presentation,
        [
            available,
            reserved,
            ceremony_identity,
            decimal,
            reserved_tail
        ]
    ));
    all
}

/// `record → (size, align)` of every public record.
fn rust_records() -> BTreeMap<&'static str, (usize, usize)> {
    BTreeMap::from([
        (
            "sas_pairing_bytes_view_t",
            (size_of::<BytesView>(), align_of::<BytesView>()),
        ),
        (
            "sas_pairing_bootstrap_view_t",
            (size_of::<BootstrapView>(), align_of::<BootstrapView>()),
        ),
        (
            "sas_pairing_event_t",
            (size_of::<Event>(), align_of::<Event>()),
        ),
        (
            "sas_pairing_result_info_t",
            (size_of::<ResultInfo>(), align_of::<ResultInfo>()),
        ),
        (
            "sas_pairing_action_t",
            (size_of::<Action>(), align_of::<Action>()),
        ),
        (
            "sas_pairing_sas_presentation_t",
            (size_of::<Presentation>(), align_of::<Presentation>()),
        ),
    ])
}

/// The manifest equals the Rust ABI and the header: the version, the exact export list (in its
/// frozen order, with its fatal class), every status and integer-namespace value with its type,
/// every scalar constant, every typedef, and every record's size, alignment, and field offsets.
/// Nothing in the header is missing from the manifest, and nothing is extra.
#[test]
fn the_abi_v1_manifest_matches_the_rust_abi_and_the_header() {
    assert!(
        size_of::<usize>() == 8,
        "the manifest records 64-bit layouts"
    );
    let rows = manifest_rows();
    let defines: BTreeMap<&str, &str> = HEADER
        .lines()
        .filter_map(|line| line.strip_prefix("#define SAS_PAIRING_"))
        .filter_map(|rest| rest.split_once(' '))
        .map(|(name, value)| (name, value.trim()))
        .collect();

    // Constants: every `SAS_PAIRING_*` define of the header, with the same value and type.
    let mut constants = BTreeMap::new();
    for row in rows.iter().filter(|row| row[0].starts_with("SAS_PAIRING_")) {
        let name = &row[0]["SAS_PAIRING_".len()..];
        let header = defines
            .get(name)
            .unwrap_or_else(|| panic!("{name}: in the manifest, not the header"));
        let value = row.last().unwrap();
        assert_eq!(numeric(value), numeric(header), "{name}");
        if row.len() == 3 {
            assert_eq!(Some(row[1].as_str()), cast_of(header), "{name} type");
        }
        assert!(
            constants.insert(name.to_owned(), numeric(value)).is_none(),
            "{name} twice"
        );
    }
    let header_names: BTreeSet<String> = defines.keys().map(|name| (*name).to_owned()).collect();
    assert_eq!(
        constants.keys().cloned().collect::<BTreeSet<_>>(),
        header_names,
        "every header constant is in the manifest"
    );
    // And the Rust values directly (statuses, authority states, typed namespaces, version).
    for (name, value) in STATUSES {
        assert_eq!(
            constants[&name["SAS_PAIRING_".len()..]],
            u128::from(value.unsigned_abs())
        );
    }
    for (name, value) in AUTHORITY_STATES {
        assert_eq!(constants[&name["SAS_PAIRING_".len()..]], u128::from(value));
    }
    for (name, _, value) in typed_constants() {
        assert_eq!(constants[&name["SAS_PAIRING_".len()..]], u128::from(value));
    }
    assert_eq!(
        constants["ABI_VERSION"],
        u128::from(super::super::ABI_VERSION)
    );
    assert_eq!(
        constants["ABI_VERSION"],
        u128::from(sas_pairing_abi_version())
    );

    // Exports: numbered 1..=25, exactly the `no_mangle` set, each with its fatal class.
    let exports: Vec<(usize, &str, &str)> = rows
        .iter()
        .filter(|row| row.len() == 3 && row[1].starts_with("sas_pairing_"))
        .filter_map(|row| Some((row[0].parse().ok()?, row[1].as_str(), row[2].as_str())))
        .collect();
    assert_eq!(
        exports.iter().map(|export| export.0).collect::<Vec<_>>(),
        (1..=25).collect::<Vec<_>>()
    );
    assert_eq!(
        exports
            .iter()
            .map(|export| export.1)
            .collect::<BTreeSet<_>>(),
        exported_functions().into_keys().collect()
    );
    assert_eq!(
        exports
            .iter()
            .map(|export| (export.1, export.2))
            .collect::<Vec<_>>(),
        FATAL_CLASSES
    );

    // Types: every scalar typedef of the header, nothing else.
    let typedefs: BTreeSet<(String, String)> = HEADER
        .lines()
        .filter_map(|line| line.strip_prefix("typedef "))
        .filter_map(|rest| rest.strip_suffix(';'))
        .filter_map(|rest| rest.split_once(' '))
        .filter(|(c_type, _)| !c_type.starts_with("struct"))
        .map(|(c_type, name)| (name.to_owned(), c_type.to_owned()))
        .collect();
    let manifest_types: BTreeSet<(String, String)> = rows
        .iter()
        .filter(|row| row.len() == 2 && row[0].starts_with("sas_pairing_"))
        .map(|row| (row[0].clone(), row[1].clone()))
        .collect();
    assert_eq!(manifest_types, typedefs);

    // Records: size and alignment, and every field's offset and size, equal the Rust types; the
    // fields are contiguous and fill the record (no padding).
    let records: BTreeMap<&str, (usize, usize)> = rows
        .iter()
        .filter(|row| row.len() == 3 && row[0].starts_with("sas_pairing_"))
        .map(|row| {
            (
                row[0].as_str(),
                (row[1].parse().unwrap(), row[2].parse().unwrap()),
            )
        })
        .collect();
    assert_eq!(records, rust_records());
    let fields: BTreeMap<(&str, &str), (usize, usize)> = rows
        .iter()
        .filter(|row| row.len() == 4 && row[0].starts_with("sas_pairing_"))
        .map(|row| {
            (
                (row[0].as_str(), row[1].as_str()),
                (row[2].parse().unwrap(), row[3].parse().unwrap()),
            )
        })
        .collect();
    assert_eq!(fields, rust_fields());
    for (record, (size, _)) in rust_records() {
        let mut next = 0;
        let mut ordered: Vec<(usize, usize)> = fields
            .iter()
            .filter(|((name, _), _)| *name == record)
            .map(|(_, layout)| *layout)
            .collect();
        ordered.sort_unstable();
        for (offset, field) in ordered {
            assert_eq!(offset, next, "{record}: no padding before offset {offset}");
            next += field;
        }
        assert_eq!(next, size, "{record}: no trailing padding");
    }
}

/// The drive and local-start bounds of the contract (§18, §20) are the implementation's.
#[test]
fn drive_bounds_are_frozen() {
    use super::super::network::{
        DRIVE_HANDLE_BOUND, MAX_DRIVE_EVENTS, MAX_REQUEST_ID_LEN, MAX_RUNS_PER_CONNECTION,
    };
    assert_eq!(MAX_DRIVE_EVENTS, 17);
    assert_eq!(DRIVE_HANDLE_BOUND, 17);
    assert_eq!(MAX_RUNS_PER_CONNECTION, 32);
    assert_eq!(MAX_REQUEST_ID_LEN, 64);
    assert_eq!(crate::transport::MAX_LIVE_UNAUTHENTICATED_CONNECTIONS, 16);
    #[cfg(windows)]
    {
        use crate::windows_owner_loop::{MAX_POLL_SOCKETS, MAX_STEP_EVENTS, OWNER_LOOP_MAX_WAIT};
        assert_eq!(OWNER_LOOP_MAX_WAIT, std::time::Duration::from_millis(250));
        assert_eq!((MAX_POLL_SOCKETS, MAX_STEP_EVENTS), (17, 17));
    }
}

/// After a contained panic, every one of the 25 exports behaves as its frozen fatal class says,
/// and no normal operation enters the core. Runs against the real process state in a child.
#[test]
#[ignore = "subprocess child; run by every_export_has_its_frozen_fatal_class"]
fn child_fatal_classes() {
    if !is_child("freeze::child_fatal_classes") {
        return;
    }
    let mut runtime = 0;
    // SAFETY: a live, aligned, exclusive `u64`.
    assert_eq!(
        unsafe { sas_pairing_runtime_create(&mut runtime) },
        SAS_PAIRING_OK
    );
    assert_eq!(injected_panic_export(0), SAS_PAIRING_FATAL);
    assert!(PROCESS.fatal.is_set());
    let entries = CORE_ENTRIES.load(Ordering::SeqCst);
    // A handle naming nothing, and an unplatformed refusal for Windows-only normal operations.
    let none = runtime + 1_000;
    let windows_only = if cfg!(windows) {
        SAS_PAIRING_FATAL
    } else {
        SAS_PAIRING_UNSUPPORTED_PLATFORM
    };
    // A structurally valid Bootstrap view (its validity is checked before the fatal state).
    let field = |bytes: &'static [u8]| BytesView {
        data: bytes.as_ptr(),
        len: bytes.len(),
    };
    let view = BootstrapView {
        application_identity: field(b"p7.7 fatal classes"),
        key_algorithm: field(b"p77.test-key"),
        public_key: field(&[7; 32]),
        shared_context: field(b""),
    };
    #[cfg(windows)]
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    #[cfg(windows)]
    let mut socket = {
        use std::os::windows::io::AsRawSocket;
        listener.as_raw_socket() as usize
    };
    #[cfg(not(windows))]
    let mut socket = 3usize;
    let before = socket;
    let identity = [0u8; 32];
    let mut observed = BTreeMap::new();
    // SAFETY (every call below): each pointer is a live, aligned, exclusive local of its type,
    // valid for the call; no input overlaps an output.
    unsafe {
        let mut handle = u64::MAX;
        let (mut state, mut remaining) = (u32::MAX, u32::MAX);
        let mut events = [Event::ZERO; 17];
        let (mut count, mut failure) = (usize::MAX, i32::MAX);
        let mut action = Action::ZERO;
        let mut presentation = Presentation::ZERO;
        let mut info = ResultInfo::ZERO;
        let mut required = usize::MAX;
        let scope = b"p7.7-fatal-classes";
        let version = sas_pairing_abi_version();
        observed.insert("sas_pairing_abi_version", i32::try_from(version).unwrap());
        for (name, status) in [
            (
                "sas_pairing_runtime_create",
                sas_pairing_runtime_create(&mut handle),
            ),
            (
                "sas_pairing_authority_register",
                sas_pairing_authority_register(runtime, scope.as_ptr(), scope.len(), &mut handle),
            ),
            (
                "sas_pairing_authority_release",
                sas_pairing_authority_release(runtime, none),
            ),
            (
                "sas_pairing_authority_status",
                sas_pairing_authority_status(runtime, none, &mut state, &mut remaining),
            ),
            (
                "sas_pairing_host_create",
                sas_pairing_host_create(runtime, none, &mut handle),
            ),
            (
                "sas_pairing_host_destroy",
                sas_pairing_host_destroy(runtime, none),
            ),
            (
                "sas_pairing_host_attach_windows_listener",
                sas_pairing_host_attach_windows_listener(
                    runtime,
                    none,
                    &mut socket,
                    &view,
                    std::ptr::null(),
                ),
            ),
            (
                "sas_pairing_host_detach_listener",
                sas_pairing_host_detach_listener(runtime, none),
            ),
            (
                "sas_pairing_host_drive",
                sas_pairing_host_drive(
                    runtime,
                    none,
                    events.as_mut_ptr(),
                    events.len(),
                    &mut count,
                    &mut failure,
                ),
            ),
            (
                "sas_pairing_host_recheck_after_resume",
                sas_pairing_host_recheck_after_resume(
                    runtime,
                    none,
                    events.as_mut_ptr(),
                    events.len(),
                    &mut count,
                    &mut failure,
                ),
            ),
            (
                "sas_pairing_connection_close",
                sas_pairing_connection_close(runtime, none, none),
            ),
            (
                "sas_pairing_result_info",
                sas_pairing_result_info(runtime, none, &mut info),
            ),
            (
                "sas_pairing_result_copy",
                sas_pairing_result_copy(runtime, none, 1, std::ptr::null_mut(), 0, &mut required),
            ),
            (
                "sas_pairing_result_destroy",
                sas_pairing_result_destroy(runtime, none),
            ),
            (
                "sas_pairing_connection_start_initiator",
                sas_pairing_connection_start_initiator(
                    runtime,
                    none,
                    none,
                    &view,
                    std::ptr::null(),
                    &mut action,
                ),
            ),
            (
                "sas_pairing_run_authorize_exposure",
                sas_pairing_run_authorize_exposure(runtime, none, none, none, &mut action),
            ),
            (
                "sas_pairing_run_expose_key",
                sas_pairing_run_expose_key(runtime, none, none, none, &mut action),
            ),
            (
                "sas_pairing_run_presentation",
                sas_pairing_run_presentation(runtime, none, none, none, &mut presentation),
            ),
            (
                "sas_pairing_run_approve_sas",
                sas_pairing_run_approve_sas(
                    runtime,
                    none,
                    none,
                    none,
                    identity.as_ptr(),
                    &mut action,
                ),
            ),
            (
                "sas_pairing_run_emit_bootstrap_mac",
                sas_pairing_run_emit_bootstrap_mac(runtime, none, none, none, &mut action),
            ),
            (
                "sas_pairing_run_reject_sas",
                sas_pairing_run_reject_sas(
                    runtime,
                    none,
                    none,
                    none,
                    identity.as_ptr(),
                    &mut action,
                ),
            ),
            (
                "sas_pairing_run_cancel_sas",
                sas_pairing_run_cancel_sas(
                    runtime,
                    none,
                    none,
                    none,
                    identity.as_ptr(),
                    &mut action,
                ),
            ),
            (
                "sas_pairing_run_emit_initiator_finish",
                sas_pairing_run_emit_initiator_finish(runtime, none, none, none, &mut action),
            ),
        ] {
            observed.insert(name, status);
        }
        // Cleanup of the live runtime itself is still admitted.
        observed.insert(
            "sas_pairing_runtime_destroy",
            sas_pairing_runtime_destroy(runtime),
        );
        assert_eq!(handle, 0, "no handle was issued");
    }
    assert_eq!(socket, before, "the socket was never adopted");
    assert_eq!(
        CORE_ENTRIES.load(Ordering::SeqCst),
        entries,
        "no normal operation entered the core"
    );
    let windows_only_exports = [
        "sas_pairing_host_attach_windows_listener",
        "sas_pairing_host_drive",
        "sas_pairing_host_recheck_after_resume",
        "sas_pairing_connection_start_initiator",
        "sas_pairing_run_authorize_exposure",
        "sas_pairing_run_expose_key",
        "sas_pairing_run_presentation",
        "sas_pairing_run_approve_sas",
        "sas_pairing_run_emit_bootstrap_mac",
        "sas_pairing_run_reject_sas",
        "sas_pairing_run_cancel_sas",
        "sas_pairing_run_emit_initiator_finish",
    ];
    for (name, class) in FATAL_CLASSES {
        let expected = match (class, name) {
            ("constant", _) => 1,
            ("normal", name) if windows_only_exports.contains(&name) => windows_only,
            ("normal", _) => SAS_PAIRING_FATAL,
            ("cleanup", "sas_pairing_runtime_destroy") => SAS_PAIRING_OK,
            // Off Windows, connection close is refused for the platform before its handles.
            ("cleanup", "sas_pairing_connection_close") if !cfg!(windows) => {
                SAS_PAIRING_UNSUPPORTED_PLATFORM
            }
            ("cleanup" | "data", _) => SAS_PAIRING_INVALID_HANDLE,
            other => panic!("unknown class {other:?}"),
        };
        assert_eq!(observed[name], expected, "{name} ({class})");
    }
    assert_eq!(observed.len(), 25);
    assert!(PROCESS.fatal.is_set(), "cleanup never clears fatal");
    let mut again = u64::MAX;
    // SAFETY: a live, aligned, exclusive `u64`.
    assert_eq!(
        unsafe { sas_pairing_runtime_create(&mut again) },
        SAS_PAIRING_FATAL
    );
    #[cfg(windows)]
    drop(listener);
}

#[test]
fn every_export_has_its_frozen_fatal_class() {
    assert_eq!(
        FATAL_CLASSES
            .iter()
            .map(|(name, _)| *name)
            .collect::<BTreeSet<_>>(),
        exported_functions().into_keys().collect(),
        "every export is classified"
    );
    run_child("freeze::child_fatal_classes");
}
