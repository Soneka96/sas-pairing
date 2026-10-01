//! Crate-private ceremony deadline semantics (P3 §11.3): a non-extendable five-minute absolute
//! deadline and a 60-second machine/protocol inactivity deadline, both evaluated against one
//! injected monotonic clock. This is evaluation only: nothing here schedules, sleeps, spawns,
//! or wakes anything. The owning ceremony enforces deadlines before every state-advancing
//! operation, and the host's bounded deadline driver calls `RemoteCeremony::poll_deadlines` when
//! a future adapter asks it to; expiry is never delivered on its own.
//!
//! Separately, P3 §11.1.1 gives every accepted, unexposed Responder a fixed pending
//! pre-exposure RESOURCE lifetime. It shares the 60-second value with the inactivity deadline
//! but nothing else: it is measured from pending-capacity admission, is never refreshed or
//! suspended, and ends when the Responder crosses exposure or terminates.
#![allow(dead_code)] // Used only by the internal ceremony until later P4 work defines its API.
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

/// Non-extendable, ceremony-scoped absolute deadline. Nothing refreshes it.
pub(crate) const ABSOLUTE_DEADLINE: Duration = Duration::from_secs(5 * 60);
/// Machine/protocol inactivity deadline, suspended only during the human SAS comparison.
pub(crate) const INACTIVITY_DEADLINE: Duration = Duration::from_secs(60);
/// Fixed pending pre-exposure resource lifetime from admission. Not `INACTIVITY_DEADLINE`:
/// no message, duplicate, DH, authorization, poll, or UI activity extends or pauses it.
pub(crate) const PENDING_PRE_EXPOSURE_DEADLINE: Duration = Duration::from_secs(60);

/// Whether a pending Responder admitted at `admitted` has outlived its fixed resource lifetime
/// at `now` (`elapsed >= PENDING_PRE_EXPOSURE_DEADLINE`). `None` if `now` precedes admission.
/// There is no progress input: the admission instant is the only reference point.
pub(crate) fn pending_expired(admitted: Duration, now: Duration) -> Option<bool> {
    now.checked_sub(admitted)
        .map(|held| held >= PENDING_PRE_EXPOSURE_DEADLINE)
}

/// Monotonic elapsed time since a clock-specific origin. Never wall-clock or calendar time.
pub(crate) trait MonotonicClock: Send + Sync {
    /// `None` when no trustworthy current value can be obtained.
    fn now(&self) -> Option<Duration>;
}

/// One ceremony uses exactly one clock for its whole lifetime.
pub(crate) type Clock = Arc<dyn MonotonicClock>;

/// Production source: `std::time::Instant` elapsed since this clock was created.
struct SystemClock {
    origin: Instant,
}

/// A fresh production monotonic clock for one ceremony.
pub(crate) fn system_clock() -> Clock {
    Arc::new(SystemClock {
        origin: Instant::now(),
    })
}

impl MonotonicClock for SystemClock {
    fn now(&self) -> Option<Duration> {
        Instant::now().checked_duration_since(self.origin)
    }
}

/// Which deadline expired. Diagnostic only: both use the single wire reason `0x03` timeout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Deadline {
    Absolute,
    Inactivity,
}

/// Whether the inactivity deadline runs in a live state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Inactivity {
    /// Waiting for machine/protocol progress.
    Running,
    /// The complete SAS is displayed and awaits a deliberate human decision.
    Suspended,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Live,
    Expired(Deadline),
    /// The clock gave no value, went backwards, or the elapsed time cannot be computed.
    UnsafeClock,
}

/// Timing state of one ceremony, owned by it and dropped with it. The absolute start is fixed
/// at creation; only `record_progress` moves the inactivity start.
pub(crate) struct CeremonyDeadlines {
    started: Duration,
    progress: Duration,
    observed: Duration,
}

impl CeremonyDeadlines {
    pub(crate) fn start(now: Duration) -> Self {
        Self {
            started: now,
            progress: now,
            observed: now,
        }
    }

    /// Read-only evaluation. A deadline has expired once `elapsed >= deadline`; when both
    /// have, the absolute deadline is reported. The effective expiry is always the earliest
    /// applicable deadline, never whichever window was restarted most recently.
    pub(crate) fn evaluate(&self, now: Option<Duration>, inactivity: Inactivity) -> Verdict {
        let Some(now) = now.filter(|now| *now >= self.observed) else {
            return Verdict::UnsafeClock;
        };
        let (Some(total), Some(idle)) = (
            now.checked_sub(self.started),
            now.checked_sub(self.progress),
        ) else {
            return Verdict::UnsafeClock;
        };
        if total >= ABSOLUTE_DEADLINE {
            Verdict::Expired(Deadline::Absolute)
        } else if inactivity == Inactivity::Running && idle >= INACTIVITY_DEADLINE {
            Verdict::Expired(Deadline::Inactivity)
        } else {
            Verdict::Live
        }
    }

    /// `evaluate`, additionally remembering a live `now` so a later, smaller value is unsafe.
    /// Checking never refreshes either deadline.
    pub(crate) fn check(&mut self, now: Option<Duration>, inactivity: Inactivity) -> Verdict {
        let verdict = self.evaluate(now, inactivity);
        if let (Verdict::Live, Some(now)) = (verdict, now) {
            self.observed = now;
        }
        verdict
    }

    /// Restarts the full inactivity window at `now`, the instant just checked live, after
    /// meaningful protocol progress. The absolute start never moves.
    pub(crate) fn record_progress(&mut self, now: Duration) {
        debug_assert_eq!(now, self.observed);
        self.progress = now;
    }
}

/// Test-only monotonic source, advanced by hand; tests never sleep.
#[cfg(test)]
pub(crate) struct ManualClock(std::sync::Mutex<Option<Duration>>);

#[cfg(test)]
impl ManualClock {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self(std::sync::Mutex::new(Some(Duration::ZERO))))
    }
    pub(crate) fn advance(&self, by: Duration) {
        let mut now = self.0.lock().unwrap();
        *now = Some(now.expect("clock was failed") + by);
    }
    /// Sets an arbitrary value, including one earlier than before (a backwards fault).
    pub(crate) fn set(&self, to: Duration) {
        *self.0.lock().unwrap() = Some(to);
    }
    /// Makes every later `now` report that no value can be obtained.
    pub(crate) fn fail(&self) {
        *self.0.lock().unwrap() = None;
    }
}

#[cfg(test)]
impl MonotonicClock for ManualClock {
    fn now(&self) -> Option<Duration> {
        *self.0.lock().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NS: Duration = Duration::from_nanos(1);
    const T0: Duration = Duration::from_secs(1_000);

    fn at(offset: Duration) -> Option<Duration> {
        Some(T0 + offset)
    }

    #[test]
    fn frozen_values_are_exact() {
        assert_eq!(ABSOLUTE_DEADLINE, Duration::from_secs(300));
        assert_eq!(INACTIVITY_DEADLINE, Duration::from_secs(60));
        assert_eq!(PENDING_PRE_EXPOSURE_DEADLINE, Duration::from_secs(60));
    }

    #[test]
    fn pending_lifetime_is_fixed_from_admission() {
        let limit = PENDING_PRE_EXPOSURE_DEADLINE;
        assert_eq!(pending_expired(T0, T0), Some(false));
        assert_eq!(pending_expired(T0, T0 + limit - NS), Some(false));
        assert_eq!(pending_expired(T0, T0 + limit), Some(true));
        assert_eq!(pending_expired(T0, T0 + 10 * limit), Some(true));
        assert_eq!(pending_expired(T0, T0 - NS), None);
    }

    #[test]
    fn absolute_expires_exactly_at_five_minutes_in_every_mode() {
        let mut d = CeremonyDeadlines::start(T0);
        // Progress every 50 seconds keeps inactivity fresh, so only the absolute can expire.
        for second in (50..300).step_by(50) {
            let now = T0 + Duration::from_secs(second);
            assert_eq!(d.check(Some(now), Inactivity::Running), Verdict::Live);
            d.record_progress(now);
        }
        for mode in [Inactivity::Running, Inactivity::Suspended] {
            assert_eq!(d.evaluate(at(ABSOLUTE_DEADLINE - NS), mode), Verdict::Live);
            assert_eq!(
                d.evaluate(at(ABSOLUTE_DEADLINE), mode),
                Verdict::Expired(Deadline::Absolute)
            );
        }
    }

    #[test]
    fn inactivity_expires_exactly_at_sixty_seconds_only_while_running() {
        let d = CeremonyDeadlines::start(T0);
        let idle = INACTIVITY_DEADLINE;
        assert_eq!(
            d.evaluate(at(idle - NS), Inactivity::Running),
            Verdict::Live
        );
        assert_eq!(
            d.evaluate(at(idle), Inactivity::Running),
            Verdict::Expired(Deadline::Inactivity)
        );
        for suspended in [idle, 2 * idle, ABSOLUTE_DEADLINE - NS] {
            assert_eq!(
                d.evaluate(at(suspended), Inactivity::Suspended),
                Verdict::Live
            );
        }
    }

    #[test]
    fn progress_restarts_only_inactivity_and_absolute_stays_earliest() {
        let mut d = CeremonyDeadlines::start(T0);
        let late = Duration::from_secs(290);
        assert_eq!(d.check(at(late), Inactivity::Suspended), Verdict::Live);
        d.record_progress(T0 + late);
        // A fresh nominal 60-second window, but the absolute deadline is ten seconds away.
        assert_eq!(
            d.evaluate(at(ABSOLUTE_DEADLINE - NS), Inactivity::Running),
            Verdict::Live
        );
        assert_eq!(
            d.evaluate(at(ABSOLUTE_DEADLINE), Inactivity::Running),
            Verdict::Expired(Deadline::Absolute)
        );
    }

    #[test]
    fn checking_never_refreshes() {
        let mut d = CeremonyDeadlines::start(T0);
        for second in 0..60 {
            let now = at(Duration::from_secs(second));
            assert_eq!(d.check(now, Inactivity::Running), Verdict::Live);
        }
        assert_eq!(
            d.check(at(INACTIVITY_DEADLINE), Inactivity::Running),
            Verdict::Expired(Deadline::Inactivity)
        );
    }

    #[test]
    fn large_forward_jumps_are_never_clamped() {
        let d = CeremonyDeadlines::start(T0);
        let ten_minutes = Duration::from_secs(600);
        assert_eq!(
            d.evaluate(at(ten_minutes), Inactivity::Running),
            Verdict::Expired(Deadline::Absolute)
        );
        assert_eq!(
            d.evaluate(at(Duration::from_secs(240)), Inactivity::Suspended),
            Verdict::Live
        );
        assert_eq!(
            d.evaluate(at(ABSOLUTE_DEADLINE + NS), Inactivity::Suspended),
            Verdict::Expired(Deadline::Absolute)
        );
    }

    #[test]
    fn missing_or_backwards_time_is_unsafe() {
        let mut d = CeremonyDeadlines::start(T0);
        assert_eq!(d.evaluate(None, Inactivity::Running), Verdict::UnsafeClock);
        assert_eq!(
            d.evaluate(Some(T0 - NS), Inactivity::Suspended),
            Verdict::UnsafeClock
        );
        let later = Duration::from_secs(10);
        assert_eq!(d.check(at(later), Inactivity::Running), Verdict::Live);
        // Still after the start, but before a value already observed.
        assert_eq!(
            d.evaluate(at(later - NS), Inactivity::Running),
            Verdict::UnsafeClock
        );
        // An unsafe reading is not remembered as observed.
        assert_eq!(d.check(None, Inactivity::Running), Verdict::UnsafeClock);
        assert_eq!(d.evaluate(at(later), Inactivity::Running), Verdict::Live);
    }

    #[test]
    fn manual_and_system_clocks_are_monotonic_sources() {
        let clock = ManualClock::new();
        clock.advance(INACTIVITY_DEADLINE);
        assert_eq!(clock.now(), Some(INACTIVITY_DEADLINE));
        clock.set(Duration::ZERO);
        assert_eq!(clock.now(), Some(Duration::ZERO));
        clock.fail();
        assert_eq!(clock.now(), None);

        let system = system_clock();
        let first = system.now().unwrap();
        assert!(system.now().unwrap() >= first);
    }
}
