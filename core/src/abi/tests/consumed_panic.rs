//! P6-D-004 consumed-accounting panic evidence through the P7.6 key-exposure export.
//!
//! The first native ABI operation that consumes an opportunity is `sas_pairing_run_expose_key`.
//! These children drive a real local Initiator through the P7.6 exports to its exposure, then
//! panic inside the core at the existing test-only hook `Point::InitiatorReserved` (after the
//! guard was reserved and one opportunity burned, before any key exists), with an ordinary and
//! a `PanicOnDrop` payload, each in its own process and with its own authority scopes.
#![cfg(windows)]

use std::{
    panic::panic_any,
    sync::atomic::{AtomicUsize, Ordering},
};

use super::super::control::SAS_PAIRING_LOCAL_EVENT_EXPOSURE_AUTHORIZED;
use super::{
    super::{
        PROCESS,
        authority::{CORE_ENTRIES, SAS_PAIRING_AUTHORITY_READY},
        control::{Action, Decision},
        hosting::LOCAL_ACTIONS,
        network::{DriveMode, MAX_DRIVE_EVENTS},
        sas_pairing_abi_version, sas_pairing_connection_close, sas_pairing_host_detach_listener,
        sas_pairing_run_expose_key,
        status::*,
    },
    PanicOnDrop,
    authority::session,
    authority_status,
    control::{
        SENTINEL, authorize, decide, done, emit_finish, emit_mac, expose,
        initiator_to_authorization, local_start, present,
    },
    create, destroy, host_create, host_destroy, is_child,
    network::Harness,
    register, release, run_child,
};
use crate::{
    Error, TrustedAuthority,
    test_hook::{self, Point},
    windows_tcp::tests::Node,
};

/// The P6-D-004 exit evidence through a core-entering export that consumes an opportunity: a
/// real panic inside `RemoteCeremony::expose_key`, at the existing test hook
/// `Point::InitiatorReserved` (after the core reserved the guard and burned one opportunity,
/// before any key exists), reached through `sas_pairing_run_expose_key`. The panic is contained
/// in Rust (FATAL, the process fatal, the payload never dropped), the opportunity stays spent
/// (9, never restored to 10), no later normal ABI call re-enters the core, and cleanup works.
fn consumed_opportunity_panic(drop_panicking_payload: bool, scope: &[u8], peer_scope: &str) {
    static FIRED: AtomicUsize = AtomicUsize::new(0);
    static DROPS: AtomicUsize = AtomicUsize::new(0);
    let (status, runtime) = create();
    assert_eq!(status, SAS_PAIRING_OK);
    let h = Harness::new(&PROCESS, true, runtime, scope);
    let peer = Node::new(peer_scope);
    let flow = initiator_to_authorization(&h, &peer);
    let (connection, run) = (flow.connection, flow.run);
    assert_eq!(
        authorize(&h, connection, run),
        Ok(done(SAS_PAIRING_LOCAL_EVENT_EXPOSURE_AUTHORIZED, 0, 0, run))
    );
    assert_eq!(
        authority_status(runtime, h.authority),
        (SAS_PAIRING_OK, SAS_PAIRING_AUTHORITY_READY, 10)
    );
    let accounting = session(scope).unwrap();
    assert_eq!(accounting.1, 10);
    let (entries, actions) = (CORE_ENTRIES.load(Ordering::SeqCst), LOCAL_ACTIONS.get());

    test_hook::install(move |point| {
        if point == Point::InitiatorReserved {
            FIRED.fetch_add(1, Ordering::SeqCst);
            if drop_panicking_payload {
                panic_any(PanicOnDrop(&DROPS));
            }
            panic!("injected panic after the opportunity was reserved");
        }
    });
    let mut out = SENTINEL;
    // SAFETY: `out` is a live, aligned, exclusive record.
    let status = unsafe { sas_pairing_run_expose_key(runtime, h.host, connection, run, &mut out) };
    test_hook::install(|_| {});
    assert_eq!(status, SAS_PAIRING_FATAL);
    assert_eq!(out, Action::ZERO, "zeroed on entry, never a success record");
    assert_eq!(FIRED.load(Ordering::SeqCst), 1, "a real core panic");
    assert!(PROCESS.fatal.is_set());
    assert_eq!(
        DROPS.load(Ordering::SeqCst),
        0,
        "the payload was never dropped"
    );
    assert_eq!(CORE_ENTRIES.load(Ordering::SeqCst), entries + 1);
    assert_eq!(LOCAL_ACTIONS.get(), actions + 1);
    let (_, left, allocation) = session(scope).unwrap();
    assert_eq!(left, 9, "consumed by the reserve, never restored to 10");
    assert_eq!(allocation, accounting.2, "the same process session");

    // No normal operation re-enters the core.
    let identity = [7; 32];
    for (connection, run) in [(connection, run), (0, 0)] {
        assert_eq!(expose(&h, connection, run), Err(SAS_PAIRING_FATAL));
        assert_eq!(authorize(&h, connection, run), Err(SAS_PAIRING_FATAL));
        assert_eq!(
            decide(&h, connection, run, Decision::Approve, &identity),
            Err(SAS_PAIRING_FATAL)
        );
        assert_eq!(emit_mac(&h, connection, run), Err(SAS_PAIRING_FATAL));
        assert_eq!(emit_finish(&h, connection, run), Err(SAS_PAIRING_FATAL));
        assert_eq!(present(&h, connection, run), Err(SAS_PAIRING_FATAL));
        assert_eq!(local_start(&h, connection), Err(SAS_PAIRING_FATAL));
    }
    assert_eq!(
        h.call(DriveMode::Drive, MAX_DRIVE_EVENTS).0,
        SAS_PAIRING_FATAL
    );
    assert_eq!(authority_status(runtime, h.authority).0, SAS_PAIRING_FATAL);
    assert_eq!(
        register(runtime, b"p7-control-after-fatal"),
        (SAS_PAIRING_FATAL, 0)
    );
    assert_eq!(host_create(runtime, h.authority), (SAS_PAIRING_FATAL, 0));
    assert_eq!(create(), (SAS_PAIRING_FATAL, 0));
    assert_eq!(
        CORE_ENTRIES.load(Ordering::SeqCst),
        entries + 1,
        "no core re-entry"
    );
    assert_eq!(LOCAL_ACTIONS.get(), actions + 1, "no owner-loop re-entry");
    assert_eq!(FIRED.load(Ordering::SeqCst), 1);
    assert_eq!(sas_pairing_abi_version(), 1);
    assert_eq!(session(scope).unwrap().1, 9);

    // Cleanup stays available. The panic poisoned the run's own lock, so that connection's
    // session teardown cannot establish its cleanup: the core reports it as uncertain and keeps
    // its capacity held (the owner loop fails closed), which the ABI reports honestly. Detach
    // then finds the loop already closed; host destroy, release, and runtime destroy succeed.
    assert_eq!(
        sas_pairing_connection_close(runtime, h.host, connection),
        SAS_PAIRING_OWNERSHIP_UNCERTAIN
    );
    assert_eq!(
        sas_pairing_host_detach_listener(runtime, h.host),
        SAS_PAIRING_OK
    );
    assert_eq!(host_destroy(runtime, h.host), SAS_PAIRING_OK);
    assert_eq!(release(runtime, h.authority), SAS_PAIRING_OK);
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
    assert!(PROCESS.fatal.is_set(), "cleanup never clears fatal");
    assert_eq!(create(), (SAS_PAIRING_FATAL, 0));
    assert_eq!(
        session(scope).unwrap(),
        (crate::Registration::Inactive, 9, accounting.2),
        "released, and the opportunity still spent"
    );
    // Same-process re-registration (test-side: the ABI itself is fatal) fails closed while the
    // uncertain cleanup holds its capacity (P6-D-002): it can never reach fresh accounting.
    assert_eq!(
        TrustedAuthority::register(scope).map(|_| ()),
        Err(Error::OwnershipUncertain)
    );
    assert_eq!(session(scope).unwrap().1, 9, "never refunded");
    drop(flow);
    peer.release();
}

#[test]
#[ignore = "subprocess child; run by a_consumed_opportunity_panic_is_contained"]
fn child_consumed_opportunity_panic() {
    if !is_child("consumed_panic::child_consumed_opportunity_panic") {
        return;
    }
    consumed_opportunity_panic(
        false,
        b"p7-control-consumed-panic",
        "p7-control-consumed-panic-peer",
    );
}

#[test]
fn a_consumed_opportunity_panic_is_contained() {
    run_child("consumed_panic::child_consumed_opportunity_panic");
}

/// As above with a `PanicOnDrop` payload: the child would abort (`0xc0000409`) if the payload
/// destructor ran, because its panic would cross `extern "C"`.
#[test]
#[ignore = "subprocess child; run by a_consumed_opportunity_panic_on_drop_is_contained"]
fn child_consumed_opportunity_panic_on_drop() {
    if !is_child("consumed_panic::child_consumed_opportunity_panic_on_drop") {
        return;
    }
    consumed_opportunity_panic(
        true,
        b"p7-control-consumed-drop",
        "p7-control-consumed-drop-peer",
    );
}

#[test]
fn a_consumed_opportunity_panic_on_drop_is_contained() {
    run_child("consumed_panic::child_consumed_opportunity_panic_on_drop");
}
