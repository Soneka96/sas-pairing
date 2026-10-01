//! Test-only deterministic pause points for router concurrency tests. A hook is installed per
//! thread and fires only in the thread that installed it, so parallel tests never see it and
//! no test depends on cryptography or the scheduler being slow.
#![cfg_attr(not(windows), allow(dead_code))] // Only the Windows router tests install hooks.
use std::cell::RefCell;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Point {
    /// Responder admission holds its preliminary permit and pending slot, before its
    /// ephemeral, commitment, and ACCEPT.
    ResponderAdmitted,
    /// A routed Initiator holds its reserved request ID and built START, before route install.
    InitiatorStarted,
    /// Session teardown marked the session closing and is about to wait for in-flight work.
    CloseWaiting { in_flight: usize },
    /// Transport teardown established its Router session CLOSED and still holds its live count.
    TransportSessionClosed,
    /// The deadline driver selected an installed run and released the table lock, before
    /// trying the run's lock.
    DeadlineSelected,
    /// The deadline driver holds a run's lock (and its session lease, but no table lock),
    /// before polling that run's deadlines.
    DeadlineRunLocked,
    /// A local action through an exact run reference holds that run's lock (and its session
    /// lease, but no table lock), after the instance check and before the action itself.
    LocalRunLocked,
}

type Hook = Box<dyn FnMut(Point)>;

thread_local! {
    static HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) };
}

/// Installs `hook` for the calling thread only.
pub(crate) fn install(hook: impl FnMut(Point) + 'static) {
    HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

pub(crate) fn fire(point: Point) {
    HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().as_mut() {
            hook(point);
        }
    });
}
