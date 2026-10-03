//! P7.3 hosting-context tests (P7-D-005).
//!
//! Local-state tests drive a test-local `AbiState`; the router-construction counter and fault
//! seam are per thread, so they are exact even while other tests run. A host needs a registered
//! authority, which needs the Windows OS ownership lease, so most tests are Windows-only; the
//! validation, fatal, and error-mapping tests run everywhere. Tests of the real exports run in
//! child processes, like the P7.1 and P7.2 ones.

#[cfg(windows)]
use std::{
    collections::BTreeSet,
    mem,
    panic::panic_any,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use std::{num::NonZeroU64, ptr};

#[cfg(windows)]
use super::{
    super::{
        PROCESS,
        authority::{CORE_ENTRIES, SAS_PAIRING_AUTHORITY_BUSY, SAS_PAIRING_AUTHORITY_EXHAUSTED},
        authority::{SAS_PAIRING_AUTHORITY_READY, SAS_PAIRING_AUTHORITY_STATE_INVALID},
        dispatch,
        hosting::ROUTER_FAULT,
        runtime::HandleCounter,
    },
    PanicOnDrop,
    authority::{NO_STATUS, READY_10, race_pair, registration, session, spend, with_authority},
    authority_status, create, destroy, host_destroy, is_child, register, release, run_child,
};
use super::{
    super::{
        hosting::{ROUTER_CONSTRUCTIONS, router_creation_status},
        panic_boundary::contain,
        runtime::{AbiState, Admission},
        status::*,
    },
    host_create,
};
use crate::{Error, ceremony::CeremonyError, router::RouteError};
#[cfg(windows)]
use crate::{Registration, Role};

/// The hosts of `runtime` as `(handle, parent authority, router address)`, read under the
/// runtime slot as cleanup (so also after fatal); empty when the runtime is gone. The address is
/// test evidence only, never ABI data.
fn hosts(state: &AbiState, runtime: u64) -> Vec<(u64, u64, usize)> {
    state
        .with_runtime(runtime, Admission::Cleanup, |live| {
            Ok(live
                .hosts
                .iter()
                .map(|(handle, host)| {
                    (
                        handle.get(),
                        host.authority.get(),
                        ptr::from_ref(host.router()).addr(),
                    )
                })
                .collect())
        })
        .unwrap_or_default()
}

/// The hosts of `runtime` as `(handle, parent authority)`.
#[cfg(windows)]
fn parents(state: &AbiState, runtime: u64) -> Vec<(u64, u64)> {
    hosts(state, runtime)
        .into_iter()
        .map(|(handle, parent, _)| (handle, parent))
        .collect()
}

// --- Platform-neutral -------------------------------------------------------------------------

/// `Router::new`'s one documented failure is `OWNERSHIP_UNCERTAIN`; anything else is a broken
/// constructor invariant and fatal, never an ordinary host-creation failure.
#[test]
fn router_constructor_errors_map_narrowly() {
    assert_eq!(
        router_creation_status(&RouteError::Ceremony(CeremonyError::Owner(
            Error::OwnershipUncertain
        ))),
        SAS_PAIRING_OWNERSHIP_UNCERTAIN
    );
    for unexpected in [
        RouteError::UnknownSession,
        RouteError::UnknownRoute,
        RouteError::SessionProtocolFailure,
        RouteError::Ceremony(CeremonyError::InvalidState),
        RouteError::Ceremony(CeremonyError::Owner(Error::Busy)),
        RouteError::Ceremony(CeremonyError::Owner(Error::ResourceLimited)),
        RouteError::Ceremony(CeremonyError::Owner(Error::OwnershipUnavailable)),
    ] {
        assert_eq!(
            router_creation_status(&unexpected),
            SAS_PAIRING_FATAL,
            "{unexpected:?}"
        );
    }
}

#[test]
fn host_operations_reject_unknown_and_foreign_handles() {
    let state = AbiState::new();
    let runtime = state.create().unwrap().get();
    let routers = ROUTER_CONSTRUCTIONS.get();
    for bad in [0, runtime + 1, u64::MAX] {
        assert_eq!(
            state.create_host(bad, runtime + 1),
            Err(SAS_PAIRING_INVALID_HANDLE)
        );
        assert_eq!(
            state.destroy_host(bad, runtime + 1),
            SAS_PAIRING_INVALID_HANDLE
        );
    }
    // No authority exists, so neither the runtime's own handle nor any other value names a
    // parent authority or a host.
    for bad in [0, runtime, runtime + 1, u64::MAX] {
        assert_eq!(
            state.create_host(runtime, bad),
            Err(SAS_PAIRING_INVALID_HANDLE)
        );
        assert_eq!(state.destroy_host(runtime, bad), SAS_PAIRING_INVALID_HANDLE);
    }
    assert_eq!(ROUTER_CONSTRUCTIONS.get(), routers, "no router was built");
    assert!(hosts(&state, runtime).is_empty());
    assert_eq!(
        state.allocate_handle(),
        Ok(NonZeroU64::new(runtime + 1).unwrap()),
        "a rejected handle reserves no value"
    );
    assert_eq!(state.destroy(runtime), SAS_PAIRING_OK);
    assert_eq!(
        state.create_host(runtime, runtime + 1),
        Err(SAS_PAIRING_INVALID_HANDLE)
    );
}

#[test]
fn a_fatal_state_refuses_host_creation_before_any_handle_check() {
    let state = AbiState::new();
    let runtime = state.create().unwrap().get();
    let status = contain(&state.fatal, SAS_PAIRING_FATAL, || -> i32 {
        panic!("injected panic");
    });
    assert_eq!(status, SAS_PAIRING_FATAL);
    let routers = ROUTER_CONSTRUCTIONS.get();
    for runtime in [runtime, 0, runtime + 7] {
        for authority in [runtime + 1, 0] {
            assert_eq!(
                state.create_host(runtime, authority),
                Err(SAS_PAIRING_FATAL)
            );
        }
    }
    assert_eq!(ROUTER_CONSTRUCTIONS.get(), routers);
    // Host destroy is cleanup: admitted, and it still validates its handles.
    assert_eq!(
        state.destroy_host(runtime, runtime + 1),
        SAS_PAIRING_INVALID_HANDLE
    );
    assert_eq!(state.destroy_host(0, 1), SAS_PAIRING_INVALID_HANDLE);
    assert_eq!(state.destroy(runtime), SAS_PAIRING_OK);
    assert!(state.fatal.is_set());
}

#[test]
fn a_poisoned_runtime_slot_refuses_host_creation_but_admits_host_destroy() {
    let state = AbiState::new();
    let runtime = state.create().unwrap().get();
    let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        state.panic_while_holding_runtime_slot()
    }));
    assert!(poisoned.is_err());
    assert!(!state.fatal.is_set());
    let routers = ROUTER_CONSTRUCTIONS.get();
    assert_eq!(
        state.create_host(runtime, runtime + 1),
        Err(SAS_PAIRING_FATAL)
    );
    assert!(state.fatal.is_set(), "a poisoned slot is recorded as fatal");
    assert_eq!(ROUTER_CONSTRUCTIONS.get(), routers);
    assert_eq!(
        state.destroy_host(runtime, runtime + 1),
        SAS_PAIRING_INVALID_HANDLE
    );
    assert_eq!(state.destroy(runtime), SAS_PAIRING_OK);
}

/// Through the export: a bad output pointer is rejected before anything else.
#[test]
fn host_create_rejects_bad_output_pointers_before_anything_else() {
    // SAFETY: null is part of the contract and never written through.
    let status = unsafe { super::super::sas_pairing_host_create(0, 0, ptr::null_mut()) };
    assert_eq!(status, SAS_PAIRING_INVALID_ARGUMENT);
    let mut words = [u64::MAX; 2];
    let misaligned = words
        .as_mut_ptr()
        .cast::<u8>()
        .wrapping_add(1)
        .cast::<u64>();
    // SAFETY: the misaligned pointer is rejected before any write.
    let status = unsafe { super::super::sas_pairing_host_create(0, 0, misaligned) };
    assert_eq!(status, SAS_PAIRING_INVALID_ARGUMENT);
    assert_eq!(words, [u64::MAX; 2], "nothing written");
    // A valid slot is cleared even when the handles are wrong (here: no runtime 0).
    assert_eq!(host_create(0, 0), (SAS_PAIRING_INVALID_HANDLE, 0));
}

// --- Local state with real authorities (Windows) ---------------------------------------------

/// One counter for every kind; no value of one kind names an object of another.
#[cfg(windows)]
#[test]
fn hosts_share_the_handle_counter_and_never_alias_another_kind() {
    let scope = b"p7-host-local-counter";
    let state = AbiState::new();
    let runtime = state.create().unwrap().get();
    let authority = state.register_authority(runtime, scope).unwrap().get();
    let first = state.create_host(runtime, authority).unwrap().get();
    let second = state.create_host(runtime, authority).unwrap().get();
    assert_eq!([runtime, authority, first, second], [1, 2, 3, 4]);
    assert_eq!(state.destroy_host(runtime, first), SAS_PAIRING_OK);
    let third = state.create_host(runtime, authority).unwrap().get();
    assert_eq!(third, 5, "a destroyed host's value is never reissued");

    assert_eq!(
        state.create_host(runtime, second),
        Err(SAS_PAIRING_INVALID_HANDLE),
        "host as authority"
    );
    assert_eq!(
        state.create_host(runtime, runtime),
        Err(SAS_PAIRING_INVALID_HANDLE),
        "runtime as authority"
    );
    assert_eq!(
        state.create_host(second, authority),
        Err(SAS_PAIRING_INVALID_HANDLE),
        "host as runtime"
    );
    for bad in [authority, runtime, first] {
        assert_eq!(state.destroy_host(runtime, bad), SAS_PAIRING_INVALID_HANDLE);
    }
    assert_eq!(
        state.destroy_host(second, second),
        SAS_PAIRING_INVALID_HANDLE
    );
    assert_eq!(
        state.authority_status(runtime, second),
        Err(SAS_PAIRING_INVALID_HANDLE)
    );
    assert_eq!(
        state.release_authority(runtime, second),
        SAS_PAIRING_INVALID_HANDLE
    );
    assert_eq!(state.destroy(second), SAS_PAIRING_INVALID_HANDLE);
    assert_eq!(
        parents(&state, runtime),
        [(second, authority), (third, authority)],
        "nothing changed"
    );

    // Release cascades; re-registration and new hosts continue the one count.
    assert_eq!(state.release_authority(runtime, authority), SAS_PAIRING_OK);
    assert!(hosts(&state, runtime).is_empty());
    let again = state.register_authority(runtime, scope).unwrap().get();
    assert_eq!(again, 6);
    assert_eq!(state.create_host(runtime, again).unwrap().get(), 7);
    assert_eq!(
        state.create_host(runtime, authority),
        Err(SAS_PAIRING_INVALID_HANDLE),
        "the released authority stays stale"
    );
    assert_eq!(state.destroy(runtime), SAS_PAIRING_OK);
    assert_eq!(
        state.create().unwrap().get(),
        8,
        "runtimes continue the count"
    );
}

/// The handle is reserved before the router is built, so exhaustion never builds one.
#[cfg(windows)]
#[test]
fn host_handle_exhaustion_builds_no_router() {
    let scope = b"p7-host-local-exhausted";
    let state = AbiState::with_handles(HandleCounter::starting_at(u64::MAX - 1));
    let runtime = state.create().unwrap().get();
    let authority = state.register_authority(runtime, scope).unwrap().get();
    assert_eq!(authority, u64::MAX);
    let routers = ROUTER_CONSTRUCTIONS.get();
    for _ in 0..2 {
        assert_eq!(
            state.create_host(runtime, authority),
            Err(SAS_PAIRING_HANDLES_EXHAUSTED)
        );
    }
    assert_eq!(ROUTER_CONSTRUCTIONS.get(), routers, "no router was built");
    assert!(hosts(&state, runtime).is_empty());
    assert!(!state.fatal.is_set(), "exhaustion is not a panic");
    assert_eq!(
        state.authority_status(runtime, authority),
        Ok((SAS_PAIRING_AUTHORITY_READY, 10))
    );
    assert_eq!(state.destroy(runtime), SAS_PAIRING_OK);
    assert_eq!(registration(scope), Some(Registration::Inactive));
}

/// A constructor failure burns the reserved value and installs nothing. Its documented failure
/// is ordinary; any other error is fatal.
#[cfg(windows)]
#[test]
fn a_router_constructor_failure_burns_the_handle_and_installs_nothing() {
    let scope = b"p7-host-local-constructor";
    let state = AbiState::new();
    let runtime = state.create().unwrap().get();
    let authority = state.register_authority(runtime, scope).unwrap().get();
    let routers = ROUTER_CONSTRUCTIONS.get();

    ROUTER_FAULT.set(Some(|| {
        RouteError::Ceremony(CeremonyError::Owner(Error::OwnershipUncertain))
    }));
    assert_eq!(
        state.create_host(runtime, authority),
        Err(SAS_PAIRING_OWNERSHIP_UNCERTAIN)
    );
    assert_eq!(
        ROUTER_CONSTRUCTIONS.get(),
        routers + 1,
        "the real constructor ran"
    );
    assert!(ROUTER_FAULT.get().is_none());
    assert!(hosts(&state, runtime).is_empty(), "nothing installed");
    assert!(!state.fatal.is_set());
    assert_eq!(
        state.destroy_host(runtime, authority + 1),
        SAS_PAIRING_INVALID_HANDLE,
        "the burned value names nothing"
    );
    let host = state.create_host(runtime, authority).unwrap().get();
    assert_eq!(host, authority + 2, "the burned value is never issued");
    assert_eq!(
        state.authority_status(runtime, authority),
        Ok((SAS_PAIRING_AUTHORITY_READY, 10))
    );

    // Any other constructor error breaks its invariant: fatal, never an ordinary failure.
    ROUTER_FAULT.set(Some(|| RouteError::UnknownSession));
    assert_eq!(
        state.create_host(runtime, authority),
        Err(SAS_PAIRING_FATAL)
    );
    assert!(state.fatal.is_set());
    assert_eq!(parents(&state, runtime), [(host, authority)]);
    let routers = ROUTER_CONSTRUCTIONS.get();
    assert_eq!(
        state.create_host(runtime, authority),
        Err(SAS_PAIRING_FATAL)
    );
    assert_eq!(ROUTER_CONSTRUCTIONS.get(), routers, "no router after fatal");
    assert_eq!(
        state.destroy_host(runtime, host + 1),
        SAS_PAIRING_INVALID_HANDLE
    );
    assert_eq!(state.destroy_host(runtime, host), SAS_PAIRING_OK);
    assert_eq!(state.release_authority(runtime, authority), SAS_PAIRING_OK);
    assert_eq!(state.destroy(runtime), SAS_PAIRING_OK);
    assert_eq!(
        session(scope).map(|(r, n, _)| (r, n)),
        Some((Registration::Inactive, 10))
    );
}

/// Implementation evidence for P7.4: each router stays at one heap address while the runtime's
/// host map grows, shrinks, and moves, and each is built over its own parent's authority state.
#[cfg(windows)]
#[test]
fn every_router_keeps_one_heap_address_while_the_maps_change() {
    let (a, b) = (b"p7-host-local-address-a", b"p7-host-local-address-b");
    let state = AbiState::new();
    let runtime = state.create().unwrap().get();
    let first_parent = state.register_authority(runtime, a).unwrap().get();
    let second_parent = state.register_authority(runtime, b).unwrap().get();
    let first = state.create_host(runtime, first_parent).unwrap().get();
    let address = |state: &AbiState| {
        hosts(state, runtime)
            .into_iter()
            .find(|(handle, _, _)| *handle == first)
            .map(|(_, _, address)| address)
            .unwrap()
    };
    let before = address(&state);

    let created: Vec<u64> = (0..64)
        .map(|index| {
            let parent = if index % 2 == 0 {
                first_parent
            } else {
                second_parent
            };
            state.create_host(runtime, parent).unwrap().get()
        })
        .collect();
    for host in created.iter().step_by(2) {
        assert_eq!(state.destroy_host(runtime, *host), SAS_PAIRING_OK);
    }
    assert_eq!(address(&state), before, "map growth and removal");

    // Move the whole host map out of the runtime, through a box and a vector, and back.
    state
        .with_runtime(runtime, Admission::Normal, |live| {
            let boxed = Box::new(mem::take(&mut live.hosts));
            let moved = vec![*boxed];
            let router = moved[0][&NonZeroU64::new(first).unwrap()].router();
            assert_eq!(ptr::from_ref(router).addr(), before, "map moved");
            live.hosts = moved.into_iter().next().unwrap();
            Ok(())
        })
        .unwrap();
    assert_eq!(address(&state), before);

    let all = hosts(&state, runtime);
    let distinct: BTreeSet<usize> = all.iter().map(|(_, _, address)| *address).collect();
    assert_eq!(distinct.len(), all.len(), "every host owns its own router");
    state
        .with_runtime(runtime, Admission::Normal, |live| {
            for host in live.hosts.values() {
                let parent = &live.authorities[&host.authority];
                assert!(Arc::ptr_eq(&host.router().authority().0, &parent.0));
                for (handle, other) in &live.authorities {
                    let shared = Arc::ptr_eq(&host.router().authority().0, &other.0);
                    assert_eq!(shared, *handle == host.authority);
                }
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(state.destroy(runtime), SAS_PAIRING_OK);
    assert_eq!(registration(a), Some(Registration::Inactive));
    assert_eq!(registration(b), Some(Registration::Inactive));
}

// --- Real exports, isolated processes (Windows) ----------------------------------------------

#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by host_lifecycle_through_the_exports"]
fn child_host_lifecycle() {
    if !is_child("host::child_host_lifecycle") {
        return;
    }
    let (a, b) = (
        b"p7-host-lifecycle-a".as_slice(),
        b"p7-host-lifecycle-b".as_slice(),
    );
    let (_, runtime) = create();
    let (status, authority) = register(runtime, a);
    assert_eq!(status, SAS_PAIRING_OK);
    let (_, _, accounting) = session(a).unwrap();

    // Raw output, then handles: nothing built, nothing entered.
    let (entries, routers) = (
        CORE_ENTRIES.load(Ordering::SeqCst),
        ROUTER_CONSTRUCTIONS.get(),
    );
    // SAFETY: null is rejected before any write.
    let status =
        unsafe { super::super::sas_pairing_host_create(runtime, authority, ptr::null_mut()) };
    assert_eq!(status, SAS_PAIRING_INVALID_ARGUMENT);
    for (runtime, authority) in [
        (0, authority),
        (runtime + 1_000, authority),
        (authority, authority),
        (runtime, 0),
        (runtime, runtime),
        (runtime, u64::MAX),
    ] {
        assert_eq!(
            host_create(runtime, authority),
            (SAS_PAIRING_INVALID_HANDLE, 0)
        );
    }
    assert_eq!(CORE_ENTRIES.load(Ordering::SeqCst), entries);
    assert_eq!(ROUTER_CONSTRUCTIONS.get(), routers);

    // Two hosts of one authority: two routers, unchanged authority status and session.
    let (status, first) = host_create(runtime, authority);
    assert_eq!(status, SAS_PAIRING_OK);
    assert!(![0, runtime, authority].contains(&first));
    let (status, second) = host_create(runtime, authority);
    assert_eq!(status, SAS_PAIRING_OK);
    assert_ne!(second, first);
    assert_eq!(ROUTER_CONSTRUCTIONS.get(), routers + 2);
    assert_eq!(
        parents(&PROCESS, runtime),
        [(first, authority), (second, authority)]
    );
    assert_eq!(authority_status(runtime, authority), READY_10);
    assert_eq!(session(a), Some((Registration::Active, 10, accounting)));

    // Wrong kinds through the exports.
    assert_eq!(host_destroy(runtime, authority), SAS_PAIRING_INVALID_HANDLE);
    assert_eq!(host_destroy(runtime, runtime), SAS_PAIRING_INVALID_HANDLE);
    assert_eq!(host_destroy(first, first), SAS_PAIRING_INVALID_HANDLE);
    assert_eq!(host_create(runtime, first), (SAS_PAIRING_INVALID_HANDLE, 0));
    assert_eq!(authority_status(runtime, first), NO_STATUS);
    assert_eq!(release(runtime, first), SAS_PAIRING_INVALID_HANDLE);
    assert_eq!(destroy(first), SAS_PAIRING_INVALID_HANDLE);
    assert_eq!(
        parents(&PROCESS, runtime),
        [(first, authority), (second, authority)]
    );

    // Destroying one host leaves its sibling and its authority alone.
    assert_eq!(host_destroy(runtime, first), SAS_PAIRING_OK);
    assert_eq!(host_destroy(runtime, first), SAS_PAIRING_INVALID_HANDLE);
    assert_eq!(parents(&PROCESS, runtime), [(second, authority)]);
    assert_eq!(authority_status(runtime, authority), READY_10);
    assert_eq!(host_destroy(runtime, second), SAS_PAIRING_OK);
    assert!(hosts(&PROCESS, runtime).is_empty());
    assert_eq!(authority_status(runtime, authority), READY_10);
    assert_eq!(session(a), Some((Registration::Active, 10, accounting)));

    // A new host never reuses a value.
    let (_, third) = host_create(runtime, authority);
    assert!(third > second);

    // Release with live hosts: normal release, never BUSY because of them; hosts cascade.
    let (_, fourth) = host_create(runtime, authority);
    assert_eq!(
        release(runtime, authority),
        SAS_PAIRING_OK,
        "live ABI hosts never make release BUSY"
    );
    for host in [third, fourth] {
        assert_eq!(host_destroy(runtime, host), SAS_PAIRING_INVALID_HANDLE);
    }
    assert!(hosts(&PROCESS, runtime).is_empty());
    assert_eq!(session(a), Some((Registration::Inactive, 10, accounting)));

    // Re-registration: new handles for the same process session.
    let (status, again) = register(runtime, a);
    assert_eq!(status, SAS_PAIRING_OK);
    assert!(again > fourth);
    assert_eq!(session(a), Some((Registration::Active, 10, accounting)));
    assert_eq!(
        host_create(runtime, authority),
        (SAS_PAIRING_INVALID_HANDLE, 0)
    );
    let (_, fifth) = host_create(runtime, again);
    assert!(fifth > again);

    // Runtime destroy cascades over hosts of two authorities.
    let (_, other) = register(runtime, b);
    let (_, sixth) = host_create(runtime, other);
    let (_, seventh) = host_create(runtime, other);
    assert_eq!(hosts(&PROCESS, runtime).len(), 3);
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
    let old = [
        runtime, authority, first, second, third, fourth, again, fifth, other, sixth, seventh,
    ];
    assert_eq!(
        old.iter().collect::<BTreeSet<_>>().len(),
        old.len(),
        "never reused"
    );
    for host in [fifth, sixth, seventh] {
        assert_eq!(host_destroy(runtime, host), SAS_PAIRING_INVALID_HANDLE);
    }
    assert_eq!(session(a), Some((Registration::Inactive, 10, accounting)));
    assert_eq!(registration(b), Some(Registration::Inactive));

    // A new runtime: no old value names anything.
    let (_, next) = create();
    assert!(!old.contains(&next));
    for value in old {
        assert_eq!(host_destroy(next, value), SAS_PAIRING_INVALID_HANDLE);
        assert_eq!(host_create(next, value), (SAS_PAIRING_INVALID_HANDLE, 0));
    }
    let (_, newest) = register(next, a);
    let (status, host) = host_create(next, newest);
    assert_eq!(status, SAS_PAIRING_OK);
    assert!(host > newest && !old.contains(&host));
    assert_eq!(destroy(next), SAS_PAIRING_OK);
    assert!(!PROCESS.fatal.is_set());
}

#[cfg(windows)]
#[test]
fn host_lifecycle_through_the_exports() {
    run_child("host::child_host_lifecycle");
}

/// P6-D-002 across host churn: hosts never change the budget, the guard, or the session.
#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by host_churn_never_changes_process_session_accounting"]
fn child_host_accounting() {
    if !is_child("host::child_host_accounting") {
        return;
    }
    let scope = b"p7-host-accounting";
    let (_, runtime) = create();
    let (_, authority) = register(runtime, scope);
    let (_, _, accounting) = session(scope).unwrap();
    assert_eq!(with_authority(&PROCESS, runtime, authority, spend), Ok(9));
    let ready_9 = (SAS_PAIRING_OK, SAS_PAIRING_AUTHORITY_READY, 9);
    let mut issued = BTreeSet::new();
    let mut churn = |runtime: u64, authority: u64, expected: (i32, u32, u32)| {
        for _ in 0..4 {
            let (_, first) = host_create(runtime, authority);
            let (_, second) = host_create(runtime, authority);
            assert_eq!(authority_status(runtime, authority), expected);
            assert_eq!(host_destroy(runtime, first), SAS_PAIRING_OK);
            assert_eq!(host_destroy(runtime, second), SAS_PAIRING_OK);
            assert_eq!(authority_status(runtime, authority), expected);
            assert!(
                issued.insert(first) && issued.insert(second),
                "a value was reused"
            );
        }
    };
    churn(runtime, authority, ready_9);
    assert_eq!(session(scope), Some((Registration::Active, 9, accounting)));

    // An exposed ceremony holds the guard: host churn neither waits for nor clears it.
    let (executor, mut ceremony) = with_authority(&PROCESS, runtime, authority, |authority| {
        let executor = authority.executor();
        let mut ceremony = executor.begin(Role::Initiator).unwrap();
        let token = authority.authorize(&mut ceremony).unwrap();
        assert_eq!(executor.reserve(&mut ceremony, Some(token)), Ok(8));
        (executor, ceremony)
    });
    churn(
        runtime,
        authority,
        (SAS_PAIRING_OK, SAS_PAIRING_AUTHORITY_BUSY, 0),
    );
    executor.terminate(&mut ceremony).unwrap();
    drop((executor, ceremony));
    let ready_8 = (SAS_PAIRING_OK, SAS_PAIRING_AUTHORITY_READY, 8);
    assert_eq!(authority_status(runtime, authority), ready_8);

    // Release with a live host, register again: the same session and budget.
    let (_, live) = host_create(runtime, authority);
    assert_eq!(release(runtime, authority), SAS_PAIRING_OK);
    assert_eq!(host_destroy(runtime, live), SAS_PAIRING_INVALID_HANDLE);
    let (_, authority) = register(runtime, scope);
    assert_eq!(authority_status(runtime, authority), ready_8);
    churn(runtime, authority, ready_8);

    // Runtime destroy with live hosts, a new runtime: still the same session and budget.
    assert_eq!(host_create(runtime, authority).0, SAS_PAIRING_OK);
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
    let (_, runtime) = create();
    let (_, authority) = register(runtime, scope);
    assert_eq!(authority_status(runtime, authority), ready_8);
    assert_eq!(session(scope), Some((Registration::Active, 8, accounting)));

    // An exhausted authority stays exhausted across host churn, release, and re-registration.
    let spent = b"p7-host-accounting-exhausted";
    let (_, exhausted_authority) = register(runtime, spent);
    for expected in (0..10).rev() {
        assert_eq!(
            with_authority(&PROCESS, runtime, exhausted_authority, spend),
            Ok(expected)
        );
    }
    let exhausted = (SAS_PAIRING_OK, SAS_PAIRING_AUTHORITY_EXHAUSTED, 0);
    churn(runtime, exhausted_authority, exhausted);
    let (status, _) = host_create(runtime, exhausted_authority);
    assert_eq!(status, SAS_PAIRING_OK, "a host is not an opportunity");
    assert_eq!(release(runtime, exhausted_authority), SAS_PAIRING_OK);
    let (_, exhausted_authority) = register(runtime, spent);
    assert_eq!(authority_status(runtime, exhausted_authority), exhausted);
    churn(runtime, exhausted_authority, exhausted);
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
    assert_eq!(
        session(scope),
        Some((Registration::Inactive, 8, accounting))
    );
}

#[cfg(windows)]
#[test]
fn host_churn_never_changes_process_session_accounting() {
    run_child("host::child_host_accounting");
}

/// After fatal: host create is refused without entering the core; host destroy still cleans.
#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by host_create_is_fatal_gated_and_host_destroy_is_cleanup"]
fn child_host_fatal() {
    if !is_child("host::child_host_fatal") {
        return;
    }
    let scope = b"p7-host-fatal";
    let (_, runtime) = create();
    let (_, authority) = register(runtime, scope);
    let (_, host) = host_create(runtime, authority);
    let (_, sibling) = host_create(runtime, authority);
    let (_, _, accounting) = session(scope).unwrap();

    assert_eq!(
        dispatch(SAS_PAIRING_FATAL, |_| -> i32 { panic!("injected panic") }),
        SAS_PAIRING_FATAL
    );
    assert!(PROCESS.fatal.is_set());
    let (entries, routers) = (
        CORE_ENTRIES.load(Ordering::SeqCst),
        ROUTER_CONSTRUCTIONS.get(),
    );
    for runtime in [runtime, 0, runtime + 1_000] {
        for parent in [authority, 0, host] {
            assert_eq!(host_create(runtime, parent), (SAS_PAIRING_FATAL, 0));
        }
    }
    assert_eq!(CORE_ENTRIES.load(Ordering::SeqCst), entries, "core entered");
    assert_eq!(ROUTER_CONSTRUCTIONS.get(), routers, "router built");

    // Cleanup stays possible and changes nothing else.
    assert_eq!(host_destroy(runtime, host), SAS_PAIRING_OK);
    assert_eq!(host_destroy(runtime, host), SAS_PAIRING_INVALID_HANDLE);
    assert_eq!(parents(&PROCESS, runtime), [(sibling, authority)]);
    assert_eq!(host_create(runtime, authority), (SAS_PAIRING_FATAL, 0));
    assert_eq!(session(scope), Some((Registration::Active, 10, accounting)));
    assert_eq!(release(runtime, authority), SAS_PAIRING_OK);
    assert_eq!(
        host_destroy(runtime, sibling),
        SAS_PAIRING_INVALID_HANDLE,
        "cascaded"
    );
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
    assert!(PROCESS.fatal.is_set(), "cleanup never clears fatal");
    assert_eq!(create(), (SAS_PAIRING_FATAL, 0));
    assert_eq!(host_create(runtime, authority), (SAS_PAIRING_FATAL, 0));
    assert_eq!(ROUTER_CONSTRUCTIONS.get(), routers);
    assert_eq!(
        session(scope),
        Some((Registration::Inactive, 10, accounting))
    );
}

#[cfg(windows)]
#[test]
fn host_create_is_fatal_gated_and_host_destroy_is_cleanup() {
    run_child("host::child_host_fatal");
}

#[cfg(windows)]
static ROUTER_PAYLOAD_DROPS: AtomicUsize = AtomicUsize::new(0);

#[cfg(windows)]
fn ordinary_router_panic() -> RouteError {
    panic!("injected panic right after Router::new");
}

#[cfg(windows)]
fn drop_panicking_router_panic() -> RouteError {
    panic_any(PanicOnDrop(&ROUTER_PAYLOAD_DROPS));
}

/// A panic right after the real `Router::new`, with the new router still alive, reached through
/// `sas_pairing_host_create`: contained, fatal, nothing installed, cleanup still works.
///
/// The two payload kinds run in parallel child processes; the OS ownership lease excludes a scope
/// across processes, so each passes its own `scope`.
#[cfg(windows)]
fn assert_router_panic_is_contained(scope: &[u8], fault: fn() -> RouteError) {
    let (_, runtime) = create();
    let (_, authority) = register(runtime, scope);
    let (_, earlier) = host_create(runtime, authority);
    let (_, _, accounting) = session(scope).unwrap();
    let routers = ROUTER_CONSTRUCTIONS.get();

    ROUTER_FAULT.set(Some(fault));
    assert_eq!(host_create(runtime, authority), (SAS_PAIRING_FATAL, 0));
    assert_eq!(
        ROUTER_CONSTRUCTIONS.get(),
        routers + 1,
        "panicked after Router::new"
    );
    assert!(PROCESS.fatal.is_set());
    assert_eq!(
        ROUTER_PAYLOAD_DROPS.load(Ordering::SeqCst),
        0,
        "payload destructor ran"
    );
    assert_eq!(
        parents(&PROCESS, runtime),
        [(earlier, authority)],
        "nothing installed"
    );

    for _ in 0..3 {
        assert_eq!(host_create(runtime, authority), (SAS_PAIRING_FATAL, 0));
        assert_eq!(
            authority_status(runtime, authority),
            (SAS_PAIRING_FATAL, SAS_PAIRING_AUTHORITY_STATE_INVALID, 0)
        );
    }
    assert_eq!(
        ROUTER_CONSTRUCTIONS.get(),
        routers + 1,
        "no router after fatal"
    );
    assert_eq!(session(scope), Some((Registration::Active, 10, accounting)));

    assert_eq!(host_destroy(runtime, earlier), SAS_PAIRING_OK);
    assert_eq!(release(runtime, authority), SAS_PAIRING_OK);
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
    assert_eq!(create(), (SAS_PAIRING_FATAL, 0));
    assert_eq!(
        session(scope),
        Some((Registration::Inactive, 10, accounting))
    );
    assert_eq!(ROUTER_PAYLOAD_DROPS.load(Ordering::SeqCst), 0);
}

#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by a_panic_around_router_construction_is_contained"]
fn child_router_panic_ordinary() {
    if !is_child("host::child_router_panic_ordinary") {
        return;
    }
    assert_router_panic_is_contained(b"p7-host-router-panic", ordinary_router_panic);
}

#[cfg(windows)]
#[test]
fn a_panic_around_router_construction_is_contained() {
    run_child("host::child_router_panic_ordinary");
}

#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by a_drop_panicking_payload_around_router_construction_is_never_dropped"]
fn child_router_panic_on_drop() {
    if !is_child("host::child_router_panic_on_drop") {
        return;
    }
    assert_router_panic_is_contained(b"p7-host-router-panic-on-drop", drop_panicking_router_panic);
}

/// The child aborts if the payload destructor runs (its panic would cross `extern "C"`).
#[cfg(windows)]
#[test]
fn a_drop_panicking_payload_around_router_construction_is_never_dropped() {
    run_child("host::child_router_panic_on_drop");
}

// --- Concurrency (Windows) -------------------------------------------------------------------

#[cfg(windows)]
const ROUNDS: usize = 24;

/// Host create vs destroying a sibling host: both succeed; the sibling is gone, the new one live.
#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by host_create_racing_sibling_destroy_both_succeed"]
fn child_create_destroy_race() {
    if !is_child("host::child_create_destroy_race") {
        return;
    }
    let (_, runtime) = create();
    let (_, authority) = register(runtime, b"p7-host-race-create-destroy");
    for round in 0..ROUNDS {
        let (_, sibling) = host_create(runtime, authority);
        let [created, destroyed] = race_pair(
            round,
            move || host_create(runtime, authority),
            move || (host_destroy(runtime, sibling), 0),
        );
        assert_eq!(destroyed.0, SAS_PAIRING_OK);
        assert_eq!(created.0, SAS_PAIRING_OK);
        assert_eq!(parents(&PROCESS, runtime), [(created.1, authority)]);
        assert_eq!(host_destroy(runtime, created.1), SAS_PAIRING_OK);
    }
    assert_eq!(authority_status(runtime, authority), READY_10);
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
}

#[cfg(windows)]
#[test]
fn host_create_racing_sibling_destroy_both_succeed() {
    run_child("host::child_create_destroy_race");
}

/// Host create vs authority release: no host survives its authority.
#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by host_create_racing_authority_release_never_outlives_it"]
fn child_create_release_race() {
    if !is_child("host::child_create_release_race") {
        return;
    }
    let scope: &'static [u8] = b"p7-host-race-create-release";
    let (_, runtime) = create();
    let mut orders = [0; 2];
    for round in 0..ROUNDS {
        let (_, authority) = register(runtime, scope);
        let (_, existing) = host_create(runtime, authority);
        let [created, released] = race_pair(
            round,
            move || host_create(runtime, authority),
            move || (release(runtime, authority), 0),
        );
        assert_eq!(
            released.0, SAS_PAIRING_OK,
            "never BUSY because of ABI hosts"
        );
        match created {
            (SAS_PAIRING_OK, host) => {
                orders[0] += 1;
                assert_eq!(host_destroy(runtime, host), SAS_PAIRING_INVALID_HANDLE);
            }
            (SAS_PAIRING_INVALID_HANDLE, 0) => orders[1] += 1,
            other => panic!("unexpected host create outcome {other:?}"),
        }
        assert_eq!(host_destroy(runtime, existing), SAS_PAIRING_INVALID_HANDLE);
        assert!(hosts(&PROCESS, runtime).is_empty());
        assert_eq!(registration(scope), Some(Registration::Inactive));
    }
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
    println!(
        "host create admitted first: {}, release admitted first: {}",
        orders[0], orders[1]
    );
}

#[cfg(windows)]
#[test]
fn host_create_racing_authority_release_never_outlives_it() {
    run_child("host::child_create_release_race");
}

/// Host destroy vs authority release: exactly one path removes and drops the host.
#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by host_destroy_racing_authority_release_drops_once"]
fn child_destroy_release_race() {
    if !is_child("host::child_destroy_release_race") {
        return;
    }
    let scope: &'static [u8] = b"p7-host-race-destroy-release";
    let (_, runtime) = create();
    let mut orders = [0; 2];
    for round in 0..ROUNDS {
        let (_, authority) = register(runtime, scope);
        let (_, host) = host_create(runtime, authority);
        let [destroyed, released] = race_pair(
            round,
            move || host_destroy(runtime, host),
            move || release(runtime, authority),
        );
        assert_eq!(released, SAS_PAIRING_OK);
        match destroyed {
            SAS_PAIRING_OK => orders[0] += 1,
            SAS_PAIRING_INVALID_HANDLE => orders[1] += 1,
            other => panic!("unexpected host destroy outcome {other}"),
        }
        assert_eq!(host_destroy(runtime, host), SAS_PAIRING_INVALID_HANDLE);
        assert!(hosts(&PROCESS, runtime).is_empty());
        assert_eq!(registration(scope), Some(Registration::Inactive));
    }
    assert_eq!(destroy(runtime), SAS_PAIRING_OK);
    println!(
        "host destroy admitted first: {}, release admitted first: {}",
        orders[0], orders[1]
    );
}

#[cfg(windows)]
#[test]
fn host_destroy_racing_authority_release_drops_once() {
    run_child("host::child_destroy_release_race");
}

/// Host create vs runtime destroy: no host survives its runtime.
#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by host_create_racing_runtime_destroy_never_outlives_it"]
fn child_create_runtime_destroy_race() {
    if !is_child("host::child_create_runtime_destroy_race") {
        return;
    }
    let scope: &'static [u8] = b"p7-host-race-create-runtime";
    let mut orders = [0; 2];
    for round in 0..ROUNDS {
        let (_, runtime) = create();
        let (_, authority) = register(runtime, scope);
        let [created, destroyed] = race_pair(
            round,
            move || host_create(runtime, authority),
            move || (destroy(runtime), 0),
        );
        assert_eq!(destroyed.0, SAS_PAIRING_OK);
        match created {
            (SAS_PAIRING_OK, host) => {
                orders[0] += 1;
                assert_eq!(host_destroy(runtime, host), SAS_PAIRING_INVALID_HANDLE);
            }
            (SAS_PAIRING_INVALID_HANDLE, 0) => orders[1] += 1,
            other => panic!("unexpected host create outcome {other:?}"),
        }
        assert_eq!(registration(scope), Some(Registration::Inactive));
    }
    println!(
        "host create admitted first: {}, runtime destroy admitted first: {}",
        orders[0], orders[1]
    );
}

#[cfg(windows)]
#[test]
fn host_create_racing_runtime_destroy_never_outlives_it() {
    run_child("host::child_create_runtime_destroy_race");
}

/// Host destroy vs runtime destroy: exactly one path removes and drops the host.
#[cfg(windows)]
#[test]
#[ignore = "subprocess child; run by host_destroy_racing_runtime_destroy_drops_once"]
fn child_destroy_runtime_destroy_race() {
    if !is_child("host::child_destroy_runtime_destroy_race") {
        return;
    }
    let scope: &'static [u8] = b"p7-host-race-destroy-runtime";
    let mut orders = [0; 2];
    for round in 0..ROUNDS {
        let (_, runtime) = create();
        let (_, authority) = register(runtime, scope);
        let (_, host) = host_create(runtime, authority);
        let [destroyed, runtime_destroyed] = race_pair(
            round,
            move || host_destroy(runtime, host),
            move || destroy(runtime),
        );
        assert_eq!(runtime_destroyed, SAS_PAIRING_OK);
        match destroyed {
            SAS_PAIRING_OK => orders[0] += 1,
            SAS_PAIRING_INVALID_HANDLE => orders[1] += 1,
            other => panic!("unexpected host destroy outcome {other}"),
        }
        assert_eq!(host_destroy(runtime, host), SAS_PAIRING_INVALID_HANDLE);
        assert_eq!(registration(scope), Some(Registration::Inactive));
    }
    println!(
        "host destroy admitted first: {}, runtime destroy admitted first: {}",
        orders[0], orders[1]
    );
}

#[cfg(windows)]
#[test]
fn host_destroy_racing_runtime_destroy_drops_once() {
    run_child("host::child_destroy_runtime_destroy_race");
}
