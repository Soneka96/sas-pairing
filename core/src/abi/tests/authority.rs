//! P7.2 authority lifecycle tests (P7-D-003, P7-D-004).
//!
//! Local-state tests drive a test-local `AbiState` against the real core, whose registry is
//! process-global, so every test uses its own scopes. Tests of the real exports run in child
//! processes, like the P7.1 ones. A successful registration needs the Windows OS ownership
//! lease, so those tests are Windows-only; elsewhere the core fails closed, which is tested too.

use std::sync::{Arc, atomic::Ordering};
#[cfg(windows)]
use std::{
    collections::{BTreeSet, HashSet},
    num::NonZeroU64,
    panic::panic_any,
    ptr,
    sync::{Barrier, atomic::AtomicUsize},
    thread,
};

use super::{
    super::{
        PROCESS,
        authority::{
            CORE_ENTRIES, SAS_PAIRING_AUTHORITY_EXHAUSTED, SAS_PAIRING_AUTHORITY_READY,
            SAS_PAIRING_AUTHORITY_STATE_INVALID, authority_state,
        },
        panic_boundary::contain,
        runtime::{AbiState, HandleCounter},
        status::*,
    },
    authority_status, create, destroy, is_child, register, run_child,
};
#[cfg(windows)]
use super::{
    super::{
        authority::SAS_PAIRING_AUTHORITY_BUSY, runtime::Admission, sas_pairing_authority_register,
        sas_pairing_authority_status,
    },
    PanicOnDrop, release, sas_pairing_abi_version,
};
use crate::{DOMAIN, Error, Registration, Status, registry};
#[cfg(windows)]
use crate::{Role, TrustedAuthority, test_hook};

fn identity(scope: &[u8]) -> Vec<u8> {
    let mut identity = DOMAIN.to_vec();
    identity.extend_from_slice(&(scope.len() as u32).to_be_bytes());
    identity.extend_from_slice(scope);
    identity
}

/// The core registry's view of `scope`, read without registering: the registration state, the
/// remaining budget, and the address of the process session's accounting (equal addresses mean
/// the same session, which the registry keeps alive). `None` when the core never owned it.
fn session(scope: &[u8]) -> Option<(Registration, u8, usize)> {
    let sessions = registry().lock().unwrap();
    let session = sessions.get(&identity(scope))?;
    let remaining = session.shared.lock().unwrap().remaining;
    Some((
        session.registration,
        remaining,
        Arc::as_ptr(&session.shared).addr(),
    ))
}

#[cfg(windows)]
fn registration(scope: &[u8]) -> Option<Registration> {
    session(scope).map(|(registration, _, _)| registration)
}

/// Runs `op` on the real core authority behind an ABI handle (test-side access, under the
/// runtime slot like an export). Never call an export from `op`: the slot is held.
#[cfg(windows)]
fn with_authority<T>(
    state: &AbiState,
    runtime: u64,
    authority: u64,
    op: impl FnOnce(&TrustedAuthority) -> T,
) -> T {
    state
        .with_runtime(runtime, Admission::Normal, |live| {
            Ok(op(&live.authorities[&NonZeroU64::new(authority).unwrap()]))
        })
        .expect("a live authority")
}

/// Spends one opportunity through the core's own authorize/reserve path, then terminates. No
/// ceremony ABI exists yet; this is test-side use of the reviewed core API.
#[cfg(windows)]
fn spend(authority: &TrustedAuthority) -> Result<u8, Error> {
    let executor = authority.executor();
    let mut ceremony = executor.begin(Role::Initiator).unwrap();
    let token = authority.authorize(&mut ceremony).unwrap();
    let result = executor.reserve(&mut ceremony, Some(token));
    executor.terminate(&mut ceremony).unwrap();
    result
}

/// Runs `op(index)` on `threads` threads released together by a barrier.
#[cfg(windows)]
fn race<T: Send + 'static>(
    threads: usize,
    op: impl Fn(usize) -> T + Send + Sync + 'static,
) -> Vec<T> {
    let barrier = Arc::new(Barrier::new(threads));
    let op = Arc::new(op);
    (0..threads)
        .map(|index| {
            let (barrier, op) = (Arc::clone(&barrier), Arc::clone(&op));
            thread::spawn(move || {
                barrier.wait();
                op(index)
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|thread| thread.join().expect("no panic"))
        .collect()
}

#[cfg(windows)]
/// Races `first` against `second`, returning `[first's result, second's result]`. The thread
/// that reaches the barrier last usually proceeds first, so the roles swap threads every other
/// round to exercise both admission orders.
#[cfg(windows)]
fn race_pair<T: Send + 'static>(
    round: usize,
    first: impl Fn() -> T + Send + Sync + 'static,
    second: impl Fn() -> T + Send + Sync + 'static,
) -> [T; 2] {
    let swapped = round % 2 == 1;
    let mut results = race(2, move |index| {
        if (index == 1) == swapped {
            first()
        } else {
            second()
        }
    });
    let (last, before) = (results.pop().unwrap(), results.pop().unwrap());
    if swapped {
        [last, before]
    } else {
        [before, last]
    }
}

#[cfg(windows)]
const READY_10: (i32, u32, u32) = (SAS_PAIRING_OK, SAS_PAIRING_AUTHORITY_READY, 10);
const NO_STATUS: (i32, u32, u32) = (
    SAS_PAIRING_INVALID_HANDLE,
    SAS_PAIRING_AUTHORITY_STATE_INVALID,
    0,
);

// --- Stable translations (P7-D-004) -----------------------------------------------------------

/// Every core `Error` variant, with its frozen ABI value.
const CORE_ERRORS: [(Error, i32); 11] = [
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
];

/// Does not compile when the core gains an `Error` variant, so `CORE_ERRORS` cannot fall behind.
fn listed_in_core_errors(error: &Error) {
    match error {
        Error::InvalidScope
        | Error::AlreadyRegistered
        | Error::OwnershipUnavailable
        | Error::UnsupportedPlatform
        | Error::OwnershipUncertain
        | Error::Busy
        | Error::Exhausted
        | Error::ResourceLimited
        | Error::MissingAuthorization
        | Error::StaleAuthorization
        | Error::Terminated => {}
    }
}

#[test]
fn every_core_error_maps_to_its_frozen_abi_value() {
    for (error, value) in CORE_ERRORS {
        listed_in_core_errors(&error);
        assert_eq!(map_core_error(error.clone()), value, "{error:?}");
        assert!(
            (100..=107).contains(&value) || (200..=202).contains(&value),
            "{error:?} outside its reserved range"
        );
    }
    let distinct: std::collections::BTreeSet<i32> =
        CORE_ERRORS.iter().map(|(_, value)| *value).collect();
    assert_eq!(distinct.len(), CORE_ERRORS.len(), "one value per variant");
}

#[test]
fn core_status_translates_to_fixed_authority_states() {
    assert_eq!(
        authority_state(Status::Ready { remaining: 10 }),
        (SAS_PAIRING_AUTHORITY_READY, 10)
    );
    assert_eq!(
        authority_state(Status::Ready { remaining: 1 }),
        (SAS_PAIRING_AUTHORITY_READY, 1)
    );
    assert_eq!(authority_state(Status::Busy), (2, 0));
    assert_eq!(
        authority_state(Status::Exhausted),
        (SAS_PAIRING_AUTHORITY_EXHAUSTED, 0)
    );
}

// --- Local state: validation order, fatal, exhaustion -----------------------------------------

#[test]
fn authority_operations_reject_unknown_and_foreign_handles() {
    let scope = b"p7-abi-local-handles";
    let state = AbiState::new();
    let runtime = state.create().unwrap().get();
    for bad in [0, runtime + 1, u64::MAX] {
        assert_eq!(
            state.register_authority(bad, scope),
            Err(SAS_PAIRING_INVALID_HANDLE)
        );
        assert_eq!(
            state.authority_status(bad, runtime),
            Err(SAS_PAIRING_INVALID_HANDLE)
        );
        assert_eq!(
            state.release_authority(bad, runtime),
            SAS_PAIRING_INVALID_HANDLE
        );
    }
    // The runtime's own handle is no authority handle.
    for bad in [0, runtime, runtime + 1, u64::MAX] {
        assert_eq!(
            state.authority_status(runtime, bad),
            Err(SAS_PAIRING_INVALID_HANDLE)
        );
        assert_eq!(
            state.release_authority(runtime, bad),
            SAS_PAIRING_INVALID_HANDLE
        );
    }
    assert_eq!(
        session(scope),
        None,
        "a rejected handle never enters the core"
    );
    assert_eq!(state.destroy(runtime), SAS_PAIRING_OK);
    assert_eq!(
        state.register_authority(runtime, scope),
        Err(SAS_PAIRING_INVALID_HANDLE)
    );
}

#[test]
fn a_fatal_state_refuses_normal_authority_operations_before_any_handle_check() {
    let scope = b"p7-abi-local-fatal";
    let state = AbiState::new();
    let runtime = state.create().unwrap().get();
    let status = contain(&state.fatal, SAS_PAIRING_FATAL, || -> i32 {
        panic!("injected panic");
    });
    assert_eq!(status, SAS_PAIRING_FATAL);
    for runtime in [runtime, 0, runtime + 7] {
        assert_eq!(
            state.register_authority(runtime, scope),
            Err(SAS_PAIRING_FATAL)
        );
        assert_eq!(
            state.authority_status(runtime, runtime + 1),
            Err(SAS_PAIRING_FATAL)
        );
    }
    // Release is cleanup: admitted, and it still validates its handles.
    assert_eq!(
        state.release_authority(runtime, runtime + 1),
        SAS_PAIRING_INVALID_HANDLE
    );
    assert_eq!(state.release_authority(0, 1), SAS_PAIRING_INVALID_HANDLE);
    assert_eq!(session(scope), None);
    assert_eq!(state.destroy(runtime), SAS_PAIRING_OK);
    assert!(state.fatal.is_set());
}

#[test]
fn a_poisoned_runtime_slot_makes_normal_operations_fatal_but_admits_cleanup() {
    let state = AbiState::new();
    let runtime = state.create().unwrap().get();
    // Poison the slot without the containment boundary, so only the poisoning is observed.
    let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        state.panic_while_holding_runtime_slot()
    }));
    assert!(poisoned.is_err());
    assert!(!state.fatal.is_set());
    assert_eq!(
        state.authority_status(runtime, runtime + 1),
        Err(SAS_PAIRING_FATAL)
    );
    assert!(state.fatal.is_set(), "a poisoned slot is recorded as fatal");
    assert_eq!(
        state.release_authority(runtime, runtime + 1),
        SAS_PAIRING_INVALID_HANDLE
    );
    assert_eq!(state.destroy(runtime), SAS_PAIRING_OK);
}

/// Handles are reserved before the core is entered, so exhaustion can never leave a core
/// registration without a handle.
#[test]
fn handle_exhaustion_fails_before_the_core_is_entered() {
    let scope = b"p7-abi-local-exhausted";
    let state = AbiState::with_handles(HandleCounter::starting_at(u64::MAX));
    let runtime = state.create().unwrap().get();
    assert_eq!(runtime, u64::MAX);
    for _ in 0..2 {
        assert_eq!(
            state.register_authority(runtime, scope),
            Err(SAS_PAIRING_HANDLES_EXHAUSTED)
        );
    }
    assert_eq!(session(scope), None, "no core registration was made");
    assert!(!state.fatal.is_set(), "exhaustion is not a panic");
    // The scope was never left registered: the core accepts it directly.
    #[cfg(windows)]
    TrustedAuthority::register(scope)
        .unwrap()
        .release()
        .unwrap();
    assert_eq!(state.destroy(runtime), SAS_PAIRING_OK);
}

/// One counter for every handle kind; a failed registration burns its reserved value.
#[cfg(windows)]
#[test]
fn authority_handles_share_the_runtime_counter_and_failures_burn_a_value() {
    let (a, b) = (b"p7-abi-local-burn-a", b"p7-abi-local-burn-b");
    let state = AbiState::new();
    let runtime = state.create().unwrap().get();
    assert_eq!(runtime, 1);
    // 2 is burned by the empty scope, 4 by the duplicate; neither is ever issued.
    assert_eq!(
        state.register_authority(runtime, b""),
        Err(SAS_PAIRING_INVALID_SCOPE)
    );
    assert_eq!(state.register_authority(runtime, a).unwrap().get(), 3);
    assert_eq!(
        state.register_authority(runtime, a),
        Err(SAS_PAIRING_ALREADY_REGISTERED)
    );
    assert_eq!(state.register_authority(runtime, b).unwrap().get(), 5);
    for burned in [2, 4] {
        assert_eq!(
            state.authority_status(runtime, burned),
            Err(SAS_PAIRING_INVALID_HANDLE)
        );
    }
    assert_eq!(state.release_authority(runtime, 3), SAS_PAIRING_OK);
    assert_eq!(state.register_authority(runtime, a).unwrap().get(), 6);
    assert_eq!(state.destroy(runtime), SAS_PAIRING_OK);
    assert_eq!(registration(a), Some(Registration::Inactive));
    assert_eq!(registration(b), Some(Registration::Inactive));
    assert_eq!(
        state.create().unwrap().get(),
        7,
        "runtimes continue the count"
    );
}

#[cfg(windows)]
#[test]
fn the_last_handle_value_can_name_an_authority_then_registration_fails_closed() {
    let (last, refused) = (b"p7-abi-local-last", b"p7-abi-local-last-refused");
    let state = AbiState::with_handles(HandleCounter::starting_at(u64::MAX - 1));
    let runtime = state.create().unwrap().get();
    let authority = state.register_authority(runtime, last).unwrap().get();
    assert_eq!(authority, u64::MAX);
    assert_eq!(
        state.register_authority(runtime, refused),
        Err(SAS_PAIRING_HANDLES_EXHAUSTED)
    );
    assert_eq!(session(refused), None);
    assert_eq!(
        state.authority_status(runtime, authority),
        Ok((SAS_PAIRING_AUTHORITY_READY, 10))
    );
    assert_eq!(state.destroy(runtime), SAS_PAIRING_OK);
    assert_eq!(registration(last), Some(Registration::Inactive));
}

// --- Real exports, isolated processes (Windows: real OS ownership) ---------------------------

#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by authority_lifecycle_through_the_exports"]
fn child_authority_lifecycle() {
    if !is_child("authority::child_authority_lifecycle") {
        return;
    }
    let (a, b) = (
        b"p7-abi-lifecycle-a".as_slice(),
        b"p7-abi-lifecycle-b".as_slice(),
    );
    let (status, runtime) = create();
    assert_eq!(status, SAS_PAIRING_OK);

    // Raw arguments are validated first: nothing written, the core not entered.
    let entries = CORE_ENTRIES.load(Ordering::SeqCst);
    let register_raw = |scope: *const u8, len: usize, out: *mut u64| {
        // SAFETY: every pointer passed here is either valid for the call or one the export
        // rejects before dereferencing it (null, misaligned, impossible length, wrapping or
        // overlapping range).
        unsafe { sas_pairing_authority_register(runtime, scope, len, out) }
    };
    assert_eq!(
        register_raw(a.as_ptr(), a.len(), ptr::null_mut()),
        SAS_PAIRING_INVALID_ARGUMENT
    );
    let mut words = [u64::MAX; 2];
    let misaligned = words
        .as_mut_ptr()
        .cast::<u8>()
        .wrapping_add(1)
        .cast::<u64>();
    assert_eq!(
        register_raw(a.as_ptr(), a.len(), misaligned),
        SAS_PAIRING_INVALID_ARGUMENT
    );
    assert_eq!(words, [u64::MAX; 2]);
    let mut out = u64::MAX;
    let out_ptr = &raw mut out;
    let near_top = ptr::without_provenance::<u8>(usize::MAX - 3);
    for (scope, len) in [
        (ptr::null(), 1),                       // null scope, non-zero length
        (a.as_ptr(), isize::MAX as usize + 1),  // no Rust slice can be this long
        (near_top, 8),                          // the range wraps the address space
        (out_ptr.cast::<u8>().cast_const(), 8), // the scope is the output slot
        (out_ptr.cast::<u8>().wrapping_sub(4).cast_const(), 8), // partly overlapping
    ] {
        assert_eq!(
            register_raw(scope, len, out_ptr),
            SAS_PAIRING_INVALID_ARGUMENT
        );
        assert_eq!(out, u64::MAX, "nothing written");
    }
    assert_eq!(CORE_ENTRIES.load(Ordering::SeqCst), entries);

    // An empty scope reaches the core, which rejects it.
    assert_eq!(
        register_raw(ptr::null(), 0, out_ptr),
        SAS_PAIRING_INVALID_SCOPE
    );
    assert_eq!(out, 0, "cleared on entry");
    assert_eq!(register(runtime, b""), (SAS_PAIRING_INVALID_SCOPE, 0));

    // Registration; one active registration per scope; scopes coexist.
    let (status, first) = register(runtime, a);
    assert_eq!(status, SAS_PAIRING_OK);
    assert!(first != 0 && first != runtime);
    assert_eq!(register(runtime, a), (SAS_PAIRING_ALREADY_REGISTERED, 0));
    let (status, other) = register(runtime, b);
    assert_eq!(status, SAS_PAIRING_OK);
    assert!(other != first && other != runtime);
    assert_eq!(authority_status(runtime, first), READY_10);
    assert_eq!(authority_status(runtime, other), READY_10);

    // Status outputs: null, misaligned, or one slot for both → nothing written.
    let (mut state, mut remaining) = (u32::MAX, u32::MAX);
    let mut halves = [u32::MAX; 2];
    let misaligned = halves
        .as_mut_ptr()
        .cast::<u8>()
        .wrapping_add(1)
        .cast::<u32>();
    for (out_state, out_remaining) in [
        (ptr::null_mut(), &raw mut remaining),
        (&raw mut state, ptr::null_mut()),
        (misaligned, &raw mut remaining),
        (&raw mut state, misaligned),
        (&raw mut state, &raw mut state),
    ] {
        // SAFETY: each case is rejected before any write.
        let status =
            unsafe { sas_pairing_authority_status(runtime, first, out_state, out_remaining) };
        assert_eq!(status, SAS_PAIRING_INVALID_ARGUMENT);
        assert_eq!(
            (state, remaining, halves),
            (u32::MAX, u32::MAX, [u32::MAX; 2])
        );
    }

    // Unknown runtimes, unknown authorities, and handles of the wrong kind.
    for (runtime, authority) in [
        (0, first),
        (runtime + 1_000, first),
        (first, first),
        (runtime, 0),
        (runtime, runtime),
        (runtime, u64::MAX),
    ] {
        assert_eq!(authority_status(runtime, authority), NO_STATUS);
        assert_eq!(release(runtime, authority), SAS_PAIRING_INVALID_HANDLE);
    }
    assert_eq!(destroy(first), SAS_PAIRING_INVALID_HANDLE);
    assert_eq!(authority_status(runtime, first), READY_10);

    // Release invalidates the handle at once; the scope's process session stays.
    let (registered, _, accounting) = session(a).unwrap();
    assert_eq!(registered, Registration::Active);
    assert_eq!(release(runtime, first), SAS_PAIRING_OK);
    assert_eq!(authority_status(runtime, first), NO_STATUS);
    assert_eq!(release(runtime, first), SAS_PAIRING_INVALID_HANDLE);
    assert_eq!(
        authority_status(runtime, other),
        READY_10,
        "the other stays"
    );
    assert_eq!(session(a), Some((Registration::Inactive, 10, accounting)));

    // Re-registration: a new handle for the same process session.
    let (status, again) = register(runtime, a);
    assert_eq!(status, SAS_PAIRING_OK);
    assert!(again > other, "{again} is newer than every earlier handle");
    assert_eq!(session(a), Some((Registration::Active, 10, accounting)));
    assert_eq!(authority_status(runtime, again), READY_10);
    assert_eq!(
        authority_status(runtime, first),
        NO_STATUS,
        "stale stays stale"
    );

    // Destroy cascades to every authority the runtime owns.
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
    for authority in [first, other, again] {
        assert_eq!(authority_status(runtime, authority), NO_STATUS);
        assert_eq!(release(runtime, authority), SAS_PAIRING_INVALID_HANDLE);
    }
    assert_eq!(registration(a), Some(Registration::Inactive));
    assert_eq!(registration(b), Some(Registration::Inactive));

    // A new runtime: the old handles name nothing, and the scopes register anew.
    let (status, next) = create();
    assert_eq!(status, SAS_PAIRING_OK);
    let old = BTreeSet::from([runtime, first, other, again]);
    assert!(!old.contains(&next));
    for authority in [first, other, again, runtime] {
        assert_eq!(authority_status(next, authority), NO_STATUS);
        assert_eq!(release(next, authority), SAS_PAIRING_INVALID_HANDLE);
    }
    let (status, newest) = register(next, a);
    assert_eq!(status, SAS_PAIRING_OK);
    assert!(newest > next && !old.contains(&newest));
    assert_eq!(session(a), Some((Registration::Active, 10, accounting)));
    assert_eq!(destroy(next), SAS_PAIRING_OK);

    // A runtime that never owned an authority destroys normally.
    let (status, empty) = create();
    assert_eq!(status, SAS_PAIRING_OK);
    assert_eq!(destroy(empty), SAS_PAIRING_OK);
    assert!(!PROCESS.fatal.is_set());
}

#[cfg(windows)]
#[test]
fn authority_lifecycle_through_the_exports() {
    run_child("authority::child_authority_lifecycle");
}

/// P6-D-002 across the ABI: release, re-registration, and runtime destroy never refresh the
/// process session's budget. Opportunities are spent through the core's own reserve path.
#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by abi_lifecycle_never_refreshes_process_session_accounting"]
fn child_session_accounting() {
    if !is_child("authority::child_session_accounting") {
        return;
    }
    let scope = b"p7-abi-session";
    let (_, runtime) = create();
    let (status, first) = register(runtime, scope);
    assert_eq!(status, SAS_PAIRING_OK);
    let (_, _, accounting) = session(scope).unwrap();
    assert_eq!(with_authority(&PROCESS, runtime, first, spend), Ok(9));
    assert_eq!(
        authority_status(runtime, first),
        (SAS_PAIRING_OK, SAS_PAIRING_AUTHORITY_READY, 9)
    );

    // An exposed ceremony holds the guard: the ABI reports BUSY with no count.
    let (executor, mut ceremony) = with_authority(&PROCESS, runtime, first, |authority| {
        let executor = authority.executor();
        let mut ceremony = executor.begin(Role::Initiator).unwrap();
        let token = authority.authorize(&mut ceremony).unwrap();
        assert_eq!(executor.reserve(&mut ceremony, Some(token)), Ok(8));
        (executor, ceremony)
    });
    assert_eq!(
        authority_status(runtime, first),
        (SAS_PAIRING_OK, SAS_PAIRING_AUTHORITY_BUSY, 0)
    );
    executor.terminate(&mut ceremony).unwrap();
    drop((executor, ceremony));
    let ready_8 = (SAS_PAIRING_OK, SAS_PAIRING_AUTHORITY_READY, 8);
    assert_eq!(authority_status(runtime, first), ready_8);

    // Release and register again: a new handle, the same session and budget.
    assert_eq!(release(runtime, first), SAS_PAIRING_OK);
    let (status, second) = register(runtime, scope);
    assert_eq!(status, SAS_PAIRING_OK);
    assert_ne!(second, first);
    assert_eq!(authority_status(runtime, second), ready_8);

    // Destroy the runtime and create another: still the same session and budget.
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
    let (_, runtime) = create();
    let (status, third) = register(runtime, scope);
    assert_eq!(status, SAS_PAIRING_OK);
    assert_eq!(authority_status(runtime, third), ready_8);
    assert_eq!(session(scope), Some((Registration::Active, 8, accounting)));

    // An exhausted budget stays exhausted across release and re-registration.
    let spent = b"p7-abi-session-exhausted";
    let (_, authority) = register(runtime, spent);
    for expected in (0..10).rev() {
        assert_eq!(
            with_authority(&PROCESS, runtime, authority, spend),
            Ok(expected)
        );
    }
    assert_eq!(
        with_authority(&PROCESS, runtime, authority, spend),
        Err(Error::Exhausted)
    );
    let exhausted = (SAS_PAIRING_OK, SAS_PAIRING_AUTHORITY_EXHAUSTED, 0);
    assert_eq!(authority_status(runtime, authority), exhausted);
    assert_eq!(release(runtime, authority), SAS_PAIRING_OK);
    let (_, authority) = register(runtime, spent);
    assert_eq!(authority_status(runtime, authority), exhausted);
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
}

#[cfg(windows)]
#[test]
fn abi_lifecycle_never_refreshes_process_session_accounting() {
    run_child("authority::child_session_accounting");
}

/// A core release error is mapped, and the handle stays invalid regardless.
#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by a_failed_release_never_restores_the_handle"]
fn child_release_errors() {
    if !is_child("authority::child_release_errors") {
        return;
    }
    let (_, runtime) = create();

    // Busy: something still shares the registration, so the core cannot release it yet.
    let busy = b"p7-abi-release-busy";
    let (_, authority) = register(runtime, busy);
    let executor = with_authority(&PROCESS, runtime, authority, TrustedAuthority::executor);
    assert_eq!(release(runtime, authority), SAS_PAIRING_BUSY);
    assert_eq!(authority_status(runtime, authority), NO_STATUS);
    assert_eq!(release(runtime, authority), SAS_PAIRING_INVALID_HANDLE);
    assert_eq!(registration(busy), Some(Registration::Active));
    assert_eq!(register(runtime, busy), (SAS_PAIRING_ALREADY_REGISTERED, 0));
    drop(executor); // The last holder ends the registration through the core's `Drop`.
    assert_eq!(registration(busy), Some(Registration::Inactive));
    let (status, again) = register(runtime, busy);
    assert_eq!(status, SAS_PAIRING_OK);
    assert_ne!(again, authority);
    assert_eq!(release(runtime, again), SAS_PAIRING_OK);

    // Uncertain: the unlock could not be confirmed. P6-D-002 keeps the scope closed.
    let uncertain = b"p7-abi-release-uncertain";
    let (_, authority) = register(runtime, uncertain);
    crate::os_lock::FAIL_NEXT_RELEASE.set(true);
    assert_eq!(release(runtime, authority), SAS_PAIRING_OWNERSHIP_UNCERTAIN);
    assert!(!crate::os_lock::FAIL_NEXT_RELEASE.get());
    assert_eq!(authority_status(runtime, authority), NO_STATUS);
    assert_eq!(release(runtime, authority), SAS_PAIRING_INVALID_HANDLE);
    for _ in 0..2 {
        assert_eq!(
            register(runtime, uncertain),
            (SAS_PAIRING_OWNERSHIP_UNCERTAIN, 0)
        );
    }
    assert_eq!(registration(uncertain), Some(Registration::Uncertain));
    // Destroying and re-creating the runtime is no reset.
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
    let (_, runtime) = create();
    assert_eq!(
        register(runtime, uncertain),
        (SAS_PAIRING_OWNERSHIP_UNCERTAIN, 0)
    );
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
}

#[cfg(windows)]
#[test]
fn a_failed_release_never_restores_the_handle() {
    run_child("authority::child_release_errors");
}

// --- Cross-process ownership -----------------------------------------------------------------

#[cfg(windows)]
const CROSS_PROCESS_SCOPE: &[u8] = b"p7-abi-cross-process";

#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by another_process_cannot_register_a_held_authority"]
fn child_cross_process_owner() {
    if !is_child("authority::child_cross_process_owner") {
        return;
    }
    let (_, runtime) = create();
    let (status, authority) = register(runtime, CROSS_PROCESS_SCOPE);
    assert_eq!(status, SAS_PAIRING_OK);
    run_child("authority::child_cross_process_contender");
    assert_eq!(release(runtime, authority), SAS_PAIRING_OK);
    run_child("authority::child_cross_process_acquirer");
    // After the other process released and exited, this process acquires again.
    let (status, again) = register(runtime, CROSS_PROCESS_SCOPE);
    assert_eq!(status, SAS_PAIRING_OK);
    assert_ne!(again, authority);
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
}

#[cfg(windows)]
#[test]
#[ignore = "grandchild; run by child_cross_process_owner"]
fn child_cross_process_contender() {
    if !is_child("authority::child_cross_process_contender") {
        return;
    }
    let (_, runtime) = create();
    assert_eq!(
        register(runtime, CROSS_PROCESS_SCOPE),
        (SAS_PAIRING_OWNERSHIP_UNAVAILABLE, 0)
    );
    assert_eq!(
        session(CROSS_PROCESS_SCOPE),
        None,
        "a failed first acquisition creates no session"
    );
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
}

#[cfg(windows)]
#[test]
#[ignore = "grandchild; run by child_cross_process_owner"]
fn child_cross_process_acquirer() {
    if !is_child("authority::child_cross_process_acquirer") {
        return;
    }
    let (_, runtime) = create();
    let (status, authority) = register(runtime, CROSS_PROCESS_SCOPE);
    assert_eq!(status, SAS_PAIRING_OK);
    assert_eq!(authority_status(runtime, authority), READY_10);
    assert_eq!(release(runtime, authority), SAS_PAIRING_OK);
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
}

#[cfg(windows)]
#[test]
fn another_process_cannot_register_a_held_authority() {
    run_child("authority::child_cross_process_owner");
}

// --- Concurrency -----------------------------------------------------------------------------

#[cfg(windows)]
const ROUNDS: usize = 24;

#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by concurrent_registrations_of_one_scope_admit_exactly_one"]
fn child_same_scope_race() {
    if !is_child("authority::child_same_scope_race") {
        return;
    }
    const THREADS: usize = 16;
    let scope: &'static [u8] = b"p7-abi-race-same-scope";
    let (_, runtime) = create();
    let mut issued = HashSet::new();
    for _ in 0..ROUNDS {
        let results = race(THREADS, move |_| register(runtime, scope));
        let winners: Vec<u64> = results
            .iter()
            .filter(|(status, _)| *status == SAS_PAIRING_OK)
            .map(|(_, handle)| *handle)
            .collect();
        assert_eq!(winners.len(), 1, "exactly one registration: {results:?}");
        assert!(
            results
                .iter()
                .all(|r| r.0 == SAS_PAIRING_OK || *r == (SAS_PAIRING_ALREADY_REGISTERED, 0)),
            "{results:?}"
        );
        assert!(issued.insert(winners[0]));
        assert_eq!(registration(scope), Some(Registration::Active));
        assert_eq!(release(runtime, winners[0]), SAS_PAIRING_OK);
    }
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
}

#[cfg(windows)]
#[test]
fn concurrent_registrations_of_one_scope_admit_exactly_one() {
    run_child("authority::child_same_scope_race");
}

#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by different_scopes_coexist_under_one_runtime"]
fn child_different_scopes() {
    if !is_child("authority::child_different_scopes") {
        return;
    }
    const SCOPES: [&[u8]; 8] = [
        b"p7-abi-scope-0",
        b"p7-abi-scope-1",
        b"p7-abi-scope-2",
        b"p7-abi-scope-3",
        b"p7-abi-scope-4",
        b"p7-abi-scope-5",
        b"p7-abi-scope-6",
        b"p7-abi-scope-7",
    ];
    let (_, runtime) = create();
    let results = race(SCOPES.len(), move |index| register(runtime, SCOPES[index]));
    assert!(results.iter().all(|(status, _)| *status == SAS_PAIRING_OK));
    let handles: Vec<u64> = results.iter().map(|(_, handle)| *handle).collect();
    let distinct: BTreeSet<u64> = handles.iter().copied().collect();
    assert_eq!(distinct.len(), SCOPES.len());
    assert!(!distinct.contains(&runtime) && !distinct.contains(&0));
    assert_eq!(release(runtime, handles[0]), SAS_PAIRING_OK);
    assert_eq!(authority_status(runtime, handles[0]), NO_STATUS);
    for handle in &handles[1..] {
        assert_eq!(authority_status(runtime, *handle), READY_10);
    }
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
    for (scope, handle) in SCOPES.iter().zip(&handles) {
        assert_eq!(authority_status(runtime, *handle), NO_STATUS);
        assert_eq!(registration(scope), Some(Registration::Inactive));
    }
}

#[cfg(windows)]
#[test]
fn different_scopes_coexist_under_one_runtime() {
    run_child("authority::child_different_scopes");
}

/// Register vs runtime destroy: register admitted first → `OK` and destroy then releases it;
/// destroy admitted first → `INVALID_HANDLE`. Either way nothing outlives the runtime.
#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by register_racing_runtime_destroy_never_outlives_the_runtime"]
fn child_register_destroy_race() {
    if !is_child("authority::child_register_destroy_race") {
        return;
    }
    let scope: &'static [u8] = b"p7-abi-race-register-destroy";
    let mut orders = [0; 2];
    for round in 0..ROUNDS {
        let (_, runtime) = create();
        let results = race_pair(
            round,
            move || register(runtime, scope),
            move || (destroy(runtime), 0),
        );
        assert_eq!(results[1].0, SAS_PAIRING_OK, "{results:?}");
        match results[0] {
            (SAS_PAIRING_OK, authority) => {
                orders[0] += 1;
                assert_ne!(authority, 0);
                assert_eq!(authority_status(runtime, authority), NO_STATUS);
            }
            (SAS_PAIRING_INVALID_HANDLE, 0) => orders[1] += 1,
            other => panic!("unexpected register outcome {other:?}"),
        }
        assert_ne!(registration(scope), Some(Registration::Active));
    }
    println!(
        "register admitted first: {}, destroy admitted first: {}",
        orders[0], orders[1]
    );
}

#[cfg(windows)]
#[test]
fn register_racing_runtime_destroy_never_outlives_the_runtime() {
    run_child("authority::child_register_destroy_race");
}

/// Release vs runtime destroy: exactly one path takes the authority out of the runtime and
/// ends it; both handles are invalid afterwards.
#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by release_racing_runtime_destroy_releases_exactly_once"]
fn child_release_destroy_race() {
    if !is_child("authority::child_release_destroy_race") {
        return;
    }
    let scope: &'static [u8] = b"p7-abi-race-release-destroy";
    let mut orders = [0; 2];
    for round in 0..ROUNDS {
        let (_, runtime) = create();
        let (status, authority) = register(runtime, scope);
        assert_eq!(status, SAS_PAIRING_OK);
        let results = race_pair(
            round,
            move || release(runtime, authority),
            move || destroy(runtime),
        );
        assert_eq!(results[1], SAS_PAIRING_OK, "{results:?}");
        match results[0] {
            SAS_PAIRING_OK => orders[0] += 1,
            SAS_PAIRING_INVALID_HANDLE => orders[1] += 1,
            other => panic!("unexpected release outcome {other}"),
        }
        assert_eq!(registration(scope), Some(Registration::Inactive));
        assert_eq!(authority_status(runtime, authority), NO_STATUS);
        assert_eq!(release(runtime, authority), SAS_PAIRING_INVALID_HANDLE);
        assert_eq!(destroy(runtime), SAS_PAIRING_INVALID_HANDLE);
    }
    println!(
        "release admitted first: {}, destroy admitted first: {}",
        orders[0], orders[1]
    );
}

#[cfg(windows)]
#[test]
fn release_racing_runtime_destroy_releases_exactly_once() {
    run_child("authority::child_release_destroy_race");
}

/// Status vs release: status sees the live authority, or release won and status sees none.
#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by status_racing_release_sees_a_live_or_no_authority"]
fn child_status_release_race() {
    if !is_child("authority::child_status_release_race") {
        return;
    }
    let scope: &'static [u8] = b"p7-abi-race-status-release";
    let (_, runtime) = create();
    let mut orders = [0; 2];
    for round in 0..ROUNDS {
        let (_, authority) = register(runtime, scope);
        let results = race_pair(
            round,
            move || authority_status(runtime, authority),
            move || (release(runtime, authority), 0, 0),
        );
        assert_eq!(results[1].0, SAS_PAIRING_OK, "{results:?}");
        match results[0] {
            READY_10 => orders[0] += 1,
            NO_STATUS => orders[1] += 1,
            other => panic!("unexpected status outcome {other:?}"),
        }
        assert_eq!(release(runtime, authority), SAS_PAIRING_INVALID_HANDLE);
    }
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
    println!(
        "status admitted first: {}, release admitted first: {}",
        orders[0], orders[1]
    );
}

#[cfg(windows)]
#[test]
fn status_racing_release_sees_a_live_or_no_authority() {
    run_child("authority::child_status_release_race");
}

// --- Real core panic (P6-D-004 exit test through a core-entering export) ---------------------

/// A panic raised inside `TrustedAuthority::register`, after the registration is complete, at
/// the test-only `AuthorityRegistered` point, reached through `sas_pairing_authority_register`.
#[cfg(windows)]
fn assert_real_core_panic_is_contained(drop_panicking_payload: bool) {
    static HOOK_FIRES: AtomicUsize = AtomicUsize::new(0);
    static PAYLOAD_DROPS: AtomicUsize = AtomicUsize::new(0);
    let held = b"p7-abi-core-panic-held";
    let panicking = b"p7-abi-core-panic-registering";
    let (_, runtime) = create();
    let (status, authority) = register(runtime, held);
    assert_eq!(status, SAS_PAIRING_OK);
    assert_eq!(with_authority(&PROCESS, runtime, authority, spend), Ok(9));

    test_hook::install(move |point| {
        if point == test_hook::Point::AuthorityRegistered {
            HOOK_FIRES.fetch_add(1, Ordering::SeqCst);
            if drop_panicking_payload {
                panic_any(PanicOnDrop(&PAYLOAD_DROPS));
            }
            panic!("injected core panic after a completed registration");
        }
    });
    let entries = CORE_ENTRIES.load(Ordering::SeqCst);
    assert_eq!(register(runtime, panicking), (SAS_PAIRING_FATAL, 0));
    assert_eq!(
        HOOK_FIRES.load(Ordering::SeqCst),
        1,
        "panicked inside the core"
    );
    assert_eq!(CORE_ENTRIES.load(Ordering::SeqCst), entries + 1);
    assert!(PROCESS.fatal.is_set());
    assert_eq!(
        PAYLOAD_DROPS.load(Ordering::SeqCst),
        0,
        "payload destructor ran"
    );
    // The registration really happened, and its own `Drop` released it during the unwind.
    let (registered, remaining, _) = session(panicking).unwrap();
    assert_eq!((registered, remaining), (Registration::Inactive, 10));

    // No normal operation enters the core again.
    for _ in 0..3 {
        assert_eq!(
            authority_status(runtime, authority),
            (SAS_PAIRING_FATAL, SAS_PAIRING_AUTHORITY_STATE_INVALID, 0)
        );
        assert_eq!(register(runtime, panicking), (SAS_PAIRING_FATAL, 0));
        assert_eq!(register(runtime, held), (SAS_PAIRING_FATAL, 0));
        assert_eq!(create(), (SAS_PAIRING_FATAL, 0));
    }
    assert_eq!(
        CORE_ENTRIES.load(Ordering::SeqCst),
        entries + 1,
        "re-entered"
    );
    assert_eq!(HOOK_FIRES.load(Ordering::SeqCst), 1);
    assert_eq!(sas_pairing_abi_version(), 1);
    let (registered, remaining, accounting) = session(held).unwrap();
    assert_eq!((registered, remaining), (Registration::Active, 9));

    // Cleanup stays possible and changes nothing else.
    assert_eq!(release(runtime, authority), SAS_PAIRING_OK);
    assert_eq!(release(runtime, authority), SAS_PAIRING_INVALID_HANDLE);
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
    assert_eq!(destroy(runtime), SAS_PAIRING_INVALID_HANDLE);
    assert!(PROCESS.fatal.is_set(), "cleanup never clears fatal");
    assert_eq!(create(), (SAS_PAIRING_FATAL, 0));
    assert_eq!(register(runtime, held), (SAS_PAIRING_FATAL, 0));
    assert_eq!(
        session(held),
        Some((Registration::Inactive, 9, accounting)),
        "the spent opportunity stays spent; no fresh accounting"
    );
    assert_eq!(HOOK_FIRES.load(Ordering::SeqCst), 1);
    assert_eq!(PAYLOAD_DROPS.load(Ordering::SeqCst), 0);
    test_hook::install(|_| {});
}

#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by a_real_core_panic_is_contained_and_fatal"]
fn child_core_panic_ordinary() {
    if !is_child("authority::child_core_panic_ordinary") {
        return;
    }
    assert_real_core_panic_is_contained(false);
}

#[cfg(windows)]
#[test]
fn a_real_core_panic_is_contained_and_fatal() {
    run_child("authority::child_core_panic_ordinary");
}

#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by a_real_core_drop_panicking_payload_is_never_dropped"]
fn child_core_panic_on_drop() {
    if !is_child("authority::child_core_panic_on_drop") {
        return;
    }
    assert_real_core_panic_is_contained(true);
}

/// The child aborts if the payload destructor runs (its panic would cross `extern "C"`).
#[cfg(windows)]
#[test]
fn a_real_core_drop_panicking_payload_is_never_dropped() {
    run_child("authority::child_core_panic_on_drop");
}

// --- Unsupported platforms -------------------------------------------------------------------

#[cfg(not(windows))]
#[test]
#[ignore = "subprocess child; run by authority_registration_fails_closed_on_unsupported_platforms"]
fn child_unsupported_platform() {
    if !is_child("authority::child_unsupported_platform") {
        return;
    }
    let scope = b"p7-abi-unsupported";
    let (status, runtime) = create();
    assert_eq!(status, SAS_PAIRING_OK, "the runtime is infrastructure only");
    let entries = CORE_ENTRIES.load(Ordering::SeqCst);
    for _ in 0..2 {
        assert_eq!(
            register(runtime, scope),
            (SAS_PAIRING_UNSUPPORTED_PLATFORM, 0)
        );
    }
    assert_eq!(
        CORE_ENTRIES.load(Ordering::SeqCst),
        entries + 2,
        "the core decided"
    );
    assert_eq!(register(runtime, b""), (SAS_PAIRING_INVALID_SCOPE, 0));
    assert_eq!(session(scope), None, "nothing was registered");
    for authority in [runtime + 1, runtime + 2, runtime + 3] {
        assert_eq!(authority_status(runtime, authority), NO_STATUS);
    }
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
    assert!(!PROCESS.fatal.is_set());
}

#[cfg(not(windows))]
#[test]
fn authority_registration_fails_closed_on_unsupported_platforms() {
    run_child("authority::child_unsupported_platform");
}
