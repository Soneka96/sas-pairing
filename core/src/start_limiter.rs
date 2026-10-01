//! Crate-private authority-wide START admission limiter (P3 §11.1.1 "START admission limiter").
//! Two independent components decide one candidate together: a burst token bucket of capacity 4
//! refilling exactly 1 token per 5 seconds, and at most 12 admissions in the rolling window
//! `(now - 60 s, now]`. Admission charges both; refusal by either charges neither; nothing ever
//! refunds a charge. Only monotonic elapsed time restores credit or expires records.
//!
//! This is pure bookkeeping over monotonic instants supplied by the owning authority, which
//! reads its one authority-scoped clock inside the same critical section that calls `admit`.
//! It never reads a clock, sleeps, waits, queues, or schedules anything, and it is unrelated to
//! the SAS opportunity budget, the exposed-ceremony guard, the pending Responder cap, the
//! preliminary-operation cap, the fixed pending-resource lifetime, and ceremony deadlines.
use std::{collections::VecDeque, time::Duration};

/// Burst capacity and initial credit, in whole tokens.
pub(crate) const BURST_CAPACITY: u8 = 4;
/// Monotonic time that refills exactly one whole token.
pub(crate) const REFILL_PERIOD: Duration = Duration::from_secs(5);
/// Maximum limiter-admitted candidates live in the rolling window.
pub(crate) const ROLLING_MAX: usize = 12;
/// A record counts only while `now - admitted_at < ROLLING_WINDOW`.
pub(crate) const ROLLING_WINDOW: Duration = Duration::from_secs(60);

/// Outcome of one atomic limiter decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartAdmission {
    /// Both components permitted; one token and one rolling record are now consumed.
    Admitted,
    /// A component refused; elapsed-time bookkeeping is committed but nothing was charged.
    Refused,
    /// No value, an instant before the last evaluation, or uncomputable elapsed time. The
    /// candidate is refused and the limiter state is exactly as it was before the call.
    UnsafeClock,
}

/// One authority's volatile limiter state. Owned with the authority's other shared state and
/// never persisted; a new owner session starts from `new()`.
#[derive(Debug, Clone)]
pub(crate) struct StartLimiter {
    /// Whole burst tokens, always `0..=BURST_CAPACITY`.
    tokens: u8,
    /// Elapsed time toward the next token, always `< REFILL_PERIOD`; zero while full.
    remainder: Duration,
    /// The last safe evaluation instant.
    last: Duration,
    /// Admission instants of live records, oldest first; never more than `ROLLING_MAX`.
    admissions: VecDeque<Duration>,
}

impl StartLimiter {
    /// Full bucket, empty history. `last` is the clock origin: a full bucket accrues nothing,
    /// so this is equivalent to initializing at the first reading, and every monotonic reading
    /// is at or after it.
    pub(crate) fn new() -> Self {
        Self {
            tokens: BURST_CAPACITY,
            remainder: Duration::ZERO,
            last: Duration::ZERO,
            admissions: VecDeque::with_capacity(ROLLING_MAX),
        }
    }

    /// One indivisible decision at the monotonic instant `now`, which the caller read inside
    /// the same critical section. Everything is computed before anything is committed, so an
    /// unsafe reading changes nothing.
    pub(crate) fn admit(&mut self, now: Option<Duration>) -> StartAdmission {
        let Some(now) = now else {
            return StartAdmission::UnsafeClock;
        };
        let Some((tokens, remainder, expired)) = self.elapsed(now) else {
            return StartAdmission::UnsafeClock;
        };
        // Elapsed-time bookkeeping, identical whatever the candidate's outcome.
        self.tokens = tokens;
        self.remainder = remainder;
        self.last = now;
        self.admissions.drain(..expired);
        if self.tokens == 0 || self.admissions.len() >= ROLLING_MAX {
            return StartAdmission::Refused;
        }
        self.tokens -= 1;
        self.admissions.push_back(now);
        StartAdmission::Admitted
    }

    /// The refilled tokens, the new remainder, and the number of expired oldest records at
    /// `now`, or `None` if `now` precedes `last` or arithmetic is not exact. Read-only.
    fn elapsed(&self, now: Duration) -> Option<(u8, Duration, usize)> {
        let total = self.remainder.checked_add(now.checked_sub(self.last)?)?;
        let period = REFILL_PERIOD.as_nanos();
        let refilled = total.as_nanos() / period;
        let tokens = u128::from(self.tokens)
            .checked_add(refilled)?
            .min(u128::from(BURST_CAPACITY));
        let tokens = u8::try_from(tokens).ok()?;
        // Time spent full creates no hidden credit beyond capacity.
        let remainder = if tokens == BURST_CAPACITY {
            Duration::ZERO
        } else {
            Duration::from_nanos(u64::try_from(total.as_nanos() % period).ok()?)
        };
        let mut expired = 0;
        for admitted in &self.admissions {
            if now.checked_sub(*admitted)? < ROLLING_WINDOW {
                break;
            }
            expired += 1;
        }
        Some((tokens, remainder, expired))
    }

    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> StartLimiterSnapshot {
        StartLimiterSnapshot {
            tokens: self.tokens,
            remainder: self.remainder,
            last: self.last,
            rolling: self.admissions.len(),
        }
    }
}

/// Test-only, read-only view of limiter state.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StartLimiterSnapshot {
    pub(crate) tokens: u8,
    pub(crate) remainder: Duration,
    pub(crate) last: Duration,
    pub(crate) rolling: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use StartAdmission::{Admitted, Refused, UnsafeClock};

    const NS: Duration = Duration::from_nanos(1);

    fn secs(value: u64) -> Duration {
        Duration::from_secs(value)
    }

    fn ms(value: u64) -> Duration {
        Duration::from_millis(value)
    }

    fn state(
        tokens: u8,
        remainder: Duration,
        last: Duration,
        rolling: usize,
    ) -> StartLimiterSnapshot {
        StartLimiterSnapshot {
            tokens,
            remainder,
            last,
            rolling,
        }
    }

    /// `count` candidates at the same instant.
    fn burst(limiter: &mut StartLimiter, now: Duration, count: usize) -> Vec<StartAdmission> {
        (0..count).map(|_| limiter.admit(Some(now))).collect()
    }

    /// A limiter that admitted four candidates at `t=0` and nothing since.
    fn drained() -> StartLimiter {
        let mut limiter = StartLimiter::new();
        assert_eq!(burst(&mut limiter, Duration::ZERO, 4), [Admitted; 4]);
        limiter
    }

    #[test]
    fn frozen_values_are_exact() {
        assert_eq!(BURST_CAPACITY, 4);
        assert_eq!(REFILL_PERIOD, secs(5));
        assert_eq!(ROLLING_MAX, 12);
        assert_eq!(ROLLING_WINDOW, secs(60));
        // 1 token / 5 s is exactly 12 tokens / 60 s.
        assert_eq!(REFILL_PERIOD * ROLLING_MAX as u32, ROLLING_WINDOW);
        assert_eq!(
            StartLimiter::new().snapshot(),
            state(4, Duration::ZERO, Duration::ZERO, 0)
        );
    }

    // R-OWNER-034 (a): four of five same-instant candidates from a fresh limiter.
    #[test]
    fn fresh_bucket_admits_four_of_five_at_one_instant() {
        let mut limiter = StartLimiter::new();
        assert_eq!(
            burst(&mut limiter, Duration::ZERO, 5),
            [Admitted, Admitted, Admitted, Admitted, Refused]
        );
        // The burst refusal appended no record.
        assert_eq!(
            limiter.snapshot(),
            state(0, Duration::ZERO, Duration::ZERO, 4)
        );
    }

    // R-OWNER-034 (b), (c): no token before 5 s, exactly one at 5 s.
    #[test]
    fn exactly_one_token_exists_at_five_seconds() {
        let mut limiter = drained();
        assert_eq!(limiter.admit(Some(secs(5) - NS)), Refused);
        assert_eq!(limiter.snapshot(), state(0, secs(5) - NS, secs(5) - NS, 4));
        assert_eq!(limiter.admit(Some(secs(5))), Admitted);
        assert_eq!(limiter.snapshot(), state(0, Duration::ZERO, secs(5), 5));
        assert_eq!(limiter.admit(Some(secs(5))), Refused);
        assert_eq!(limiter.snapshot(), state(0, Duration::ZERO, secs(5), 5));
    }

    // R-OWNER-034 (d): two tokens exactly 10 s after the drain.
    #[test]
    fn exactly_two_tokens_exist_at_ten_seconds() {
        let mut limiter = drained();
        assert_eq!(
            burst(&mut limiter, secs(10), 3),
            [Admitted, Admitted, Refused]
        );
        assert_eq!(limiter.snapshot(), state(0, Duration::ZERO, secs(10), 6));

        let mut limiter = drained();
        assert_eq!(limiter.admit(Some(secs(10) - NS)), Admitted);
        assert_eq!(limiter.snapshot(), state(0, secs(5) - NS, secs(10) - NS, 5));
    }

    // R-OWNER-034 (b): refusals neither restart nor discard refill progress.
    #[test]
    fn refusals_preserve_the_refill_remainder() {
        let mut limiter = drained();
        assert_eq!(limiter.admit(Some(secs(2))), Refused);
        assert_eq!(limiter.snapshot(), state(0, secs(2), secs(2), 4));
        assert_eq!(limiter.admit(Some(secs(4))), Refused);
        assert_eq!(limiter.snapshot(), state(0, secs(4), secs(4), 4));
        assert_eq!(limiter.admit(Some(secs(5))), Admitted);
        assert_eq!(limiter.snapshot(), state(0, Duration::ZERO, secs(5), 5));
    }

    // R-OWNER-034 (e): a long idle period caps credit at exactly 4, with no hidden credit.
    #[test]
    fn long_idle_never_exceeds_capacity() {
        let mut limiter = StartLimiter::new();
        // A full bucket idling 100 s, then one evaluation: still exactly 4, remainder zero.
        assert_eq!(
            burst(&mut limiter, secs(100), 5),
            [Admitted, Admitted, Admitted, Admitted, Refused]
        );
        assert_eq!(limiter.snapshot(), state(0, Duration::ZERO, secs(100), 4));

        // Draining, then 10 minutes idle: four admitted, the fifth refused.
        let mut limiter = drained();
        let later = secs(600);
        assert_eq!(
            burst(&mut limiter, later, 5),
            [Admitted, Admitted, Admitted, Admitted, Refused]
        );
        assert_eq!(limiter.snapshot(), state(0, Duration::ZERO, later, 4));

        // Time spent full does not pre-pay the next token: 4.999 s after leaving full is not 5.
        let mut limiter = StartLimiter::new();
        assert_eq!(limiter.admit(Some(secs(1000) + ms(4_999))), Admitted);
        assert_eq!(limiter.snapshot().remainder, Duration::ZERO);
        let left_full = secs(1000) + ms(4_999);
        assert_eq!(
            burst(&mut limiter, left_full, 4),
            [Admitted, Admitted, Admitted, Refused]
        );
        assert_eq!(limiter.admit(Some(left_full + secs(5) - NS)), Refused);
        assert_eq!(limiter.admit(Some(left_full + secs(5))), Admitted);
    }

    /// The exact R-OWNER-035 schedule: 4 at 0 s, then one at each of 5, 10, ..., 40 s.
    fn twelve() -> StartLimiter {
        let mut limiter = drained();
        for second in (5..=40).step_by(5) {
            assert_eq!(limiter.admit(Some(secs(second))), Admitted, "t={second}");
        }
        assert_eq!(limiter.snapshot(), state(0, Duration::ZERO, secs(40), 12));
        limiter
    }

    // R-OWNER-035: the rolling cap, exact eviction at 60 s, and atomic no-partial-charge.
    #[test]
    fn rolling_cap_schedule_is_exact() {
        let mut limiter = twelve();
        // 45 s: one whole token, but all 12 records are live. Refused without any charge.
        assert_eq!(limiter.admit(Some(secs(45))), Refused);
        assert_eq!(limiter.snapshot(), state(1, Duration::ZERO, secs(45), 12));
        // 59.999 s: three whole tokens, the t=0 records are 59.999 s old. Still refused.
        let almost = secs(60) - ms(1);
        assert_eq!(limiter.admit(Some(almost)), Refused);
        assert_eq!(limiter.snapshot(), state(3, secs(5) - ms(1), almost, 12));
        // 60 s: the four t=0 records reach age 60 s and go first; credit is capped at 4.
        assert_eq!(limiter.admit(Some(secs(60))), Admitted);
        assert_eq!(limiter.snapshot(), state(3, Duration::ZERO, secs(60), 9));
        assert_eq!(
            burst(&mut limiter, secs(60), 4),
            [Admitted, Admitted, Admitted, Refused]
        );
        assert_eq!(limiter.snapshot(), state(0, Duration::ZERO, secs(60), 12));
    }

    // R-OWNER-035: a rolling refusal consumes no token; a burst refusal appends no record.
    #[test]
    fn a_refusal_by_either_component_charges_neither() {
        let mut limiter = twelve();
        assert_eq!(limiter.admit(Some(secs(45))), Refused);
        // Bookkeeping refilled one token and advanced `last`; the refusal consumed nothing.
        let before = limiter.snapshot();
        assert_eq!(before, state(1, Duration::ZERO, secs(45), 12));
        for _ in 0..100 {
            assert_eq!(limiter.admit(Some(secs(45))), Refused);
        }
        assert_eq!(
            limiter.snapshot(),
            before,
            "repeated rolling refusals keep the token"
        );

        let mut limiter = drained();
        for _ in 0..100 {
            assert_eq!(limiter.admit(Some(Duration::ZERO)), Refused);
        }
        assert_eq!(
            limiter.snapshot(),
            state(0, Duration::ZERO, Duration::ZERO, 4),
            "burst refusals append no record"
        );
    }

    #[test]
    fn rolling_history_is_bounded_and_expires_by_age() {
        let mut limiter = StartLimiter::new();
        // One admission every 5 s for 10 minutes: the bucket never refuses at this rate, and
        // live history never exceeds 12.
        for step in 0..120u64 {
            assert_eq!(limiter.admit(Some(secs(5 * step))), Admitted);
            assert!(limiter.snapshot().rolling <= ROLLING_MAX);
            assert!(limiter.admissions.capacity() >= limiter.admissions.len());
        }
        assert_eq!(limiter.snapshot().rolling, 12);
        // An exactly 60 s old record no longer counts; one younger by 1 ns still does.
        let mut limiter = StartLimiter::new();
        assert_eq!(limiter.admit(Some(secs(1))), Admitted);
        assert_eq!(limiter.admit(Some(secs(61) - NS)), Admitted);
        assert_eq!(limiter.snapshot().rolling, 2);
        assert_eq!(limiter.admit(Some(secs(61))), Admitted);
        assert_eq!(limiter.snapshot().rolling, 2);
    }

    // R-OWNER-039: an unusable reading refuses and changes nothing at all.
    #[test]
    fn unsafe_readings_refuse_without_mutation() {
        let mut limiter = twelve();
        assert_eq!(limiter.admit(Some(secs(45))), Refused);
        let before = limiter.snapshot();
        let history = limiter.admissions.clone();

        // Unavailable.
        assert_eq!(limiter.admit(None), UnsafeClock);
        // Backwards relative to the last evaluation, even by 1 ns.
        assert_eq!(limiter.admit(Some(secs(45) - NS)), UnsafeClock);
        assert_eq!(limiter.admit(Some(Duration::ZERO)), UnsafeClock);
        assert_eq!(limiter.snapshot(), before);
        assert_eq!(limiter.admissions, history);

        // A later safe reading continues from the coherent state; nothing was reset.
        assert_eq!(limiter.admit(Some(secs(50))), Refused);
        assert_eq!(limiter.snapshot(), state(2, Duration::ZERO, secs(50), 12));
        assert_eq!(limiter.admit(Some(secs(60))), Admitted);
        assert_eq!(limiter.snapshot(), state(3, Duration::ZERO, secs(60), 9));
    }

    #[test]
    fn an_unsafe_first_reading_does_not_consume_initial_credit() {
        let mut limiter = StartLimiter::new();
        assert_eq!(limiter.admit(None), UnsafeClock);
        assert_eq!(
            limiter.snapshot(),
            state(4, Duration::ZERO, Duration::ZERO, 0)
        );
        assert_eq!(
            burst(&mut limiter, secs(3), 5),
            [Admitted, Admitted, Admitted, Admitted, Refused]
        );
    }
}
