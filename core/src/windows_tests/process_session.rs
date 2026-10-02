//! P6.3 regressions for P5-F-003 under owner decision P6-D-002: the opportunity budget and the
//! START limiter belong to this OS process's session for a canonical authority, not to one
//! `TrustedAuthority` registration. Release, the final drop, a failed or uncertain
//! reacquisition, and idle time never start fresh accounting inside one live process. Every
//! test uses its own scopes, because a process session lives as long as the test process.
use crate::{
    CeremonyExecutor, DOMAIN, Error, Registration, Role, StartLimit, Status, TrustedAuthority,
    deadline::ManualClock, os_lock, registry, start_limiter::StartLimiterSnapshot,
};
use std::time::Duration;

fn secs(value: u64) -> Duration {
    Duration::from_secs(value)
}

fn identity(scope: &[u8]) -> Vec<u8> {
    let mut identity = DOMAIN.to_vec();
    identity.extend_from_slice(&(scope.len() as u32).to_be_bytes());
    identity.extend_from_slice(scope);
    identity
}

/// The registry's view of a scope: its registration state and remaining budget, read without
/// registering. `None` when this process never owned the scope.
fn session(scope: &[u8]) -> Option<(Registration, u8)> {
    let sessions = registry().lock().unwrap();
    let session = sessions.get(&identity(scope))?;
    let remaining = session.shared.lock().unwrap().remaining;
    Some((session.registration, remaining))
}

/// One locally authorized exposure reservation, terminated at once; the opportunity stays spent.
fn spend(authority: &TrustedAuthority) -> Result<u8, Error> {
    let executor = authority.executor();
    let mut ceremony = executor.begin(Role::Initiator).unwrap();
    let token = authority.authorize(&mut ceremony).unwrap();
    let result = executor.reserve(&mut ceremony, Some(token));
    executor.terminate(&mut ceremony).unwrap();
    result
}

fn status(authority: &TrustedAuthority) -> Status {
    authority.executor().status().unwrap()
}

/// One START limiter decision for a new Responder candidate at the session clock's instant.
fn decide(executor: &CeremonyExecutor) -> StartLimit {
    executor
        .admit_start(&executor.begin(Role::Responder).unwrap())
        .unwrap()
}

fn limiter(authority: &TrustedAuthority) -> StartLimiterSnapshot {
    authority.executor().start_limiter_snapshot()
}

#[test]
fn explicit_release_keeps_a_partly_spent_budget() {
    let scope = b"p6-session-release";
    let authority = TrustedAuthority::register(scope).unwrap();
    for expected in [9, 8, 7] {
        assert_eq!(spend(&authority), Ok(expected));
    }
    authority.release().unwrap();
    assert_eq!(session(scope), Some((Registration::Inactive, 7)));
    let again = TrustedAuthority::register(scope).unwrap();
    assert_eq!(status(&again), Status::Ready { remaining: 7 });
    assert_eq!(spend(&again), Ok(6));
    again.release().unwrap();
}

#[test]
fn the_final_drop_keeps_the_budget_without_an_explicit_release() {
    let scope = b"p6-session-drop";
    let authority = TrustedAuthority::register(scope).unwrap();
    let executor = authority.executor();
    let mut ceremony = executor.begin(Role::Responder).unwrap();
    let token = authority.authorize(&mut ceremony).unwrap();
    assert_eq!(executor.reserve(&mut ceremony, Some(token)), Ok(9));
    executor.terminate(&mut ceremony).unwrap();
    // Every handle goes away; nobody calls `release`.
    drop((ceremony, executor, authority));
    assert_eq!(session(scope), Some((Registration::Inactive, 9)));
    let again = TrustedAuthority::register(scope).unwrap();
    assert_eq!(status(&again), Status::Ready { remaining: 9 });
    drop(again);
    assert_eq!(session(scope), Some((Registration::Inactive, 9)));
}

#[test]
fn exhaustion_survives_re_registration() {
    let scope = b"p6-session-exhausted";
    let authority = TrustedAuthority::register(scope).unwrap();
    for expected in (0..10).rev() {
        assert_eq!(spend(&authority), Ok(expected));
    }
    assert_eq!(status(&authority), Status::Exhausted);
    authority.release().unwrap();
    for _ in 0..3 {
        let again = TrustedAuthority::register(scope).unwrap();
        assert_eq!(status(&again), Status::Exhausted);
        assert_eq!(spend(&again), Err(Error::Exhausted));
        again.release().unwrap();
    }
}

// I1: however the registrations are cycled, one process session exposes at most ten.
#[test]
fn registration_cycles_share_one_budget() {
    let scope = b"p6-session-cycles";
    let mut granted = 0;
    for (spent, left) in [(2, 8), (3, 5), (5, 0)] {
        let authority = TrustedAuthority::register(scope).unwrap();
        for _ in 0..spent {
            spend(&authority).unwrap();
            granted += 1;
        }
        authority.release().unwrap();
        assert_eq!(session(scope), Some((Registration::Inactive, left)));
    }
    let again = TrustedAuthority::register(scope).unwrap();
    assert_eq!(status(&again), Status::Exhausted);
    again.release().unwrap();
    for _ in 0..10 {
        let authority = TrustedAuthority::register(scope).unwrap();
        if spend(&authority).is_ok() {
            granted += 1;
        }
        drop(authority);
    }
    assert_eq!(granted, 10);
}

// The budget has no time refill: no amount of monotonic time restores an opportunity.
#[test]
fn elapsed_time_never_refills_the_budget() {
    let scope = b"p6-session-no-refill";
    let clock = ManualClock::new();
    let authority = TrustedAuthority::register_with_limiter_clock(scope, clock.clone()).unwrap();
    for _ in 0..4 {
        spend(&authority).unwrap();
    }
    authority.release().unwrap();
    clock.advance(secs(24 * 60 * 60));
    let again = TrustedAuthority::register_with_limiter_clock(scope, clock.clone()).unwrap();
    assert_eq!(status(&again), Status::Ready { remaining: 6 });
    // Time does refill the START limiter, which is a separate control.
    assert_eq!(decide(&again.executor()), StartLimit::Admitted);
    assert_eq!(status(&again), Status::Ready { remaining: 6 });
    again.release().unwrap();
}

// I3, R-OWNER-034 across a re-registration: an emptied bucket stays empty, then refills only
// by elapsed time.
#[test]
fn burst_credit_survives_immediate_re_registration() {
    let scope = b"p6-session-burst";
    let clock = ManualClock::new();
    let authority = TrustedAuthority::register_with_limiter_clock(scope, clock.clone()).unwrap();
    let executor = authority.executor();
    for _ in 0..4 {
        assert_eq!(decide(&executor), StartLimit::Admitted);
    }
    let drained = executor.start_limiter_snapshot();
    assert_eq!((drained.tokens, drained.rolling), (0, 4));
    drop(executor);
    authority.release().unwrap();

    let again = TrustedAuthority::register_with_limiter_clock(scope, clock.clone()).unwrap();
    assert_eq!(limiter(&again), drained, "re-registration resets nothing");
    let executor = again.executor();
    assert_eq!(
        decide(&executor),
        StartLimit::Refused,
        "t=0: no fresh credit"
    );
    clock.set(secs(5) - Duration::from_nanos(1));
    assert_eq!(decide(&executor), StartLimit::Refused);
    // Exactly one token has accrued by elapsed time at t=5 s, and the window has room.
    clock.set(secs(5));
    assert_eq!(decide(&executor), StartLimit::Admitted);
    assert_eq!(decide(&executor), StartLimit::Refused);
    let state = executor.start_limiter_snapshot();
    assert_eq!((state.tokens, state.rolling, state.last), (0, 5, secs(5)));
    drop(executor);
    again.release().unwrap();
}

// I3, R-OWNER-035 across re-registrations: the rolling window keeps refusing until monotonic
// time ages the t=0 records out at exactly 60 s.
#[test]
fn rolling_history_survives_re_registration() {
    let scope = b"p6-session-rolling";
    let clock = ManualClock::new();
    // Each step re-registers the authority before deciding.
    let decide_after_re_registration = || {
        let authority =
            TrustedAuthority::register_with_limiter_clock(scope, clock.clone()).unwrap();
        let outcome = decide(&authority.executor());
        let state = limiter(&authority);
        authority.release().unwrap();
        (outcome, state.tokens, state.rolling)
    };
    for _ in 0..4 {
        assert_eq!(decide_after_re_registration().0, StartLimit::Admitted);
    }
    for t in (5..=40).step_by(5) {
        clock.set(secs(t));
        assert_eq!(decide_after_re_registration().0, StartLimit::Admitted);
    }
    // 12 live records; the burst component has credit but the rolling one refuses.
    clock.set(secs(45));
    assert_eq!(decide_after_re_registration(), (StartLimit::Refused, 1, 12));
    clock.set(secs(60) - Duration::from_millis(1));
    assert_eq!(decide_after_re_registration(), (StartLimit::Refused, 3, 12));
    // Exactly 60 s: the four t=0 records expire by age, not by any re-registration.
    clock.set(secs(60));
    assert_eq!(decide_after_re_registration(), (StartLimit::Admitted, 3, 9));
    for rolling in [10, 11, 12] {
        assert_eq!(
            decide_after_re_registration(),
            (StartLimit::Admitted, 12 - rolling as u8, rolling)
        );
    }
    assert_eq!(decide_after_re_registration(), (StartLimit::Refused, 0, 12));
}

// A long inactive interval may legitimately restore full credit and expire every record, but
// only through the limiter's elapsed-time rules at its next evaluation.
#[test]
fn long_idle_restores_capacity_only_by_elapsed_time() {
    let scope = b"p6-session-idle";
    let clock = ManualClock::new();
    let authority = TrustedAuthority::register_with_limiter_clock(scope, clock.clone()).unwrap();
    let executor = authority.executor();
    for _ in 0..4 {
        assert_eq!(decide(&executor), StartLimit::Admitted);
    }
    drop(executor);
    authority.release().unwrap();
    clock.advance(secs(10 * 60));

    let again = TrustedAuthority::register_with_limiter_clock(scope, clock.clone()).unwrap();
    // Not a new limiter: the old state is there until time is applied to it.
    assert_eq!(
        limiter(&again),
        StartLimiterSnapshot {
            tokens: 0,
            remainder: Duration::ZERO,
            last: Duration::ZERO,
            rolling: 4,
        }
    );
    let executor = again.executor();
    assert_eq!(decide(&executor), StartLimit::Admitted);
    assert_eq!(
        executor.start_limiter_snapshot(),
        StartLimiterSnapshot {
            tokens: 3,
            remainder: Duration::ZERO,
            last: secs(10 * 60),
            rolling: 1,
        }
    );
    drop(executor);
    again.release().unwrap();
}

// The limiter clock belongs to the process session: a later registration cannot inject another
// timeline, so it can neither reset, rewind, nor break the session's limiter.
#[test]
fn a_later_registration_keeps_the_session_clock() {
    let scope = b"p6-session-clock";
    let clock = ManualClock::new();
    let authority = TrustedAuthority::register_with_limiter_clock(scope, clock.clone()).unwrap();
    let executor = authority.executor();
    for _ in 0..4 {
        assert_eq!(decide(&executor), StartLimit::Admitted);
    }
    drop(executor);
    authority.release().unwrap();

    for injected in [secs(3600), Duration::ZERO] {
        let other = ManualClock::new();
        other.set(injected);
        let again = TrustedAuthority::register_with_limiter_clock(scope, other.clone()).unwrap();
        // Still t=0 on the session clock: an hour on `other` refills nothing.
        assert_eq!(decide(&again.executor()), StartLimit::Refused);
        other.fail();
        assert_eq!(decide(&again.executor()), StartLimit::Refused);
        again.release().unwrap();
    }
    // The session clock itself keeps its unsafe-clock rule: backwards refuses, unchanged.
    clock.set(secs(5));
    let again = TrustedAuthority::register_with_limiter_clock(scope, ManualClock::new()).unwrap();
    assert_eq!(decide(&again.executor()), StartLimit::Admitted);
    clock.set(secs(4));
    assert_eq!(decide(&again.executor()), StartLimit::UnsafeClock);
    assert_eq!((limiter(&again).tokens, limiter(&again).rolling), (0, 5));
    again.release().unwrap();
}

// I4: distinct canonical authorities never share accounting.
#[test]
fn distinct_authorities_have_independent_sessions() {
    let (a, b) = (b"p6-session-a".as_slice(), b"p6-session-b".as_slice());
    let clock = ManualClock::new();
    let first = TrustedAuthority::register_with_limiter_clock(a, clock.clone()).unwrap();
    for _ in 0..3 {
        spend(&first).unwrap();
    }
    for _ in 0..4 {
        assert_eq!(decide(&first.executor()), StartLimit::Admitted);
    }
    let other = TrustedAuthority::register_with_limiter_clock(b, clock.clone()).unwrap();
    assert_eq!(status(&other), Status::Ready { remaining: 10 });
    assert_eq!((limiter(&other).tokens, limiter(&other).rolling), (4, 0));
    first.release().unwrap();
    assert_eq!(spend(&other), Ok(9));
    other.release().unwrap();

    let first = TrustedAuthority::register_with_limiter_clock(a, clock).unwrap();
    assert_eq!(status(&first), Status::Ready { remaining: 7 });
    assert_eq!((limiter(&first).tokens, limiter(&first).rolling), (0, 4));
    first.release().unwrap();
    assert_eq!(session(b), Some((Registration::Inactive, 9)));
}

// The OS lease stays authoritative: a lease held elsewhere (here another handle, which the
// OS treats like another owner) blocks both a first registration and a reactivation.
#[test]
fn ownership_is_acquired_anew_and_a_failure_keeps_the_session() {
    let scope = b"p6-session-foreign";
    let foreign = os_lock::Lease::acquire(&identity(scope)).unwrap();
    // A failed first acquisition establishes no ownership and so creates no session.
    assert_eq!(
        TrustedAuthority::register(scope).unwrap_err(),
        Error::OwnershipUnavailable
    );
    assert_eq!(session(scope), None);
    foreign.release().unwrap();

    let authority = TrustedAuthority::register(scope).unwrap();
    assert_eq!(spend(&authority), Ok(9));
    assert_eq!(
        os_lock::Lease::acquire(&identity(scope)).err(),
        Some(Error::OwnershipUnavailable),
        "the registration holds the lease"
    );
    authority.release().unwrap();

    // Another owner takes the lease in between: reactivation fails, the session survives.
    let foreign = os_lock::Lease::acquire(&identity(scope)).unwrap();
    for _ in 0..2 {
        assert_eq!(
            TrustedAuthority::register(scope).unwrap_err(),
            Error::OwnershipUnavailable
        );
        assert_eq!(session(scope), Some((Registration::Inactive, 9)));
    }
    foreign.release().unwrap();
    let again = TrustedAuthority::register(scope).unwrap();
    assert_eq!(status(&again), Status::Ready { remaining: 9 });
    again.release().unwrap();
}

// I7: an uncertain release, by `release` or by the final drop, never grants fresh accounting;
// the session stays unusable until the process is replaced.
#[test]
fn an_uncertain_release_disables_the_session_without_resetting_it() {
    for (scope, explicit) in [
        (b"p6-session-uncertain-release".as_slice(), true),
        (b"p6-session-uncertain-drop".as_slice(), false),
    ] {
        let authority = TrustedAuthority::register(scope).unwrap();
        assert_eq!(spend(&authority), Ok(9));
        os_lock::FAIL_NEXT_RELEASE.set(true);
        if explicit {
            assert_eq!(authority.release(), Err(Error::OwnershipUncertain));
        } else {
            drop(authority);
        }
        assert!(!os_lock::FAIL_NEXT_RELEASE.get());
        for _ in 0..2 {
            assert_eq!(
                TrustedAuthority::register(scope).unwrap_err(),
                Error::OwnershipUncertain
            );
        }
        assert_eq!(session(scope), Some((Registration::Uncertain, 9)));
    }
}

// A runtime resource a registration could not release (an uncertain teardown keeps its count)
// is never reset to make reactivation work: the session fails closed instead.
#[test]
fn a_held_runtime_resource_blocks_reactivation() {
    let scope = b"p6-session-held-resource";
    let authority = TrustedAuthority::register(scope).unwrap();
    assert_eq!(spend(&authority), Ok(9));
    // What an uncertain transport teardown leaves behind.
    authority
        .executor()
        .0
        .shared
        .lock()
        .unwrap()
        .live_connections += 1;
    authority.release().unwrap();
    for _ in 0..2 {
        assert_eq!(
            TrustedAuthority::register(scope).unwrap_err(),
            Error::OwnershipUncertain
        );
    }
    assert_eq!(session(scope), Some((Registration::Inactive, 9)));
}
