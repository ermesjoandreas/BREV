//! The lock in time: the two-step unlock, the idle deadline, and the
//! [`Timer`] thread that wipes when a deadline passes.
//!
//! An unlock leaves the vault `Armed`: the DEK is loaded, but the gate stays
//! shut until [`crate::Vault::confirm_active`] comes within
//! [`CONFIRM_WINDOW`]. Then it is `Active` until it has been idle for its
//! idle time; [`Clock::note_activity`] moves that deadline. A deadline that
//! passes shuts the gate at once (the gate asks the clock), and the first of
//! the timer and the next caller to take the holder's mutex wipes.
//!
//! A deadline is kept on two clocks. On Apple platforms `Instant` is
//! CLOCK_UPTIME_RAW, which stands still while the Mac sleeps; the wall clock
//! does not. A deadline has passed when either says so, but the wall clock
//! counts only while it has not gone back since the deadline was set.
//!
//! Lock order: the holder's mutex, then the clock's. The timer never holds
//! the clock's mutex while it takes the holder's, and `note_activity` takes
//! only the clock's.

use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, Weak};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

/// How long an unlock stays `Armed`: `confirm_active` must come within it.
pub const CONFIRM_WINDOW: Duration = Duration::from_secs(2);
/// The idle time until `set_idle` changes it.
pub const DEFAULT_IDLE: Duration = Duration::from_secs(300);
/// The timer's longest wait, so a deadline the wall clock passed while the
/// Mac slept is seen within a second of waking.
const MAX_WAIT: Duration = Duration::from_secs(1);

/// A moment on both clocks.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Now {
    pub(crate) mono: Instant,
    pub(crate) wall: SystemTime,
}

impl Now {
    pub(crate) fn real() -> Now {
        Now {
            mono: Instant::now(),
            wall: SystemTime::now(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Deadline {
    mono: Instant,
    wall: SystemTime,
    /// The wall clock when the deadline was set.
    set_wall: SystemTime,
}

impl Deadline {
    /// `d` after `now`. A deadline too far to represent is `now`: it has
    /// passed at once, the safe side.
    fn after(now: Now, d: Duration) -> Deadline {
        Deadline {
            mono: now.mono.checked_add(d).unwrap_or(now.mono),
            wall: now.wall.checked_add(d).unwrap_or(now.wall),
            set_wall: now.wall,
        }
    }

    fn passed(&self, now: Now) -> bool {
        now.mono >= self.mono || (now.wall >= self.wall && now.wall >= self.set_wall)
    }
}

#[derive(Clone, Copy, Debug)]
enum Phase {
    Locked,
    /// Unlocked, waiting for `confirm_active`.
    Armed {
        until: Deadline,
    },
    /// Unlocked and confirmed, until idle for `idle`.
    Active {
        until: Deadline,
        idle: Duration,
    },
}

impl Phase {
    fn until(&self) -> Option<Deadline> {
        match *self {
            Phase::Locked => None,
            Phase::Armed { until } | Phase::Active { until, .. } => Some(until),
        }
    }
}

struct Timing {
    phase: Phase,
    shutdown: bool,
}

/// The state of a vault's lock in time, shared by the vault and its
/// [`Timer`].
pub struct Clock {
    m: Mutex<Timing>,
    cv: Condvar,
}

impl Clock {
    pub(crate) fn new() -> Clock {
        Clock {
            m: Mutex::new(Timing {
                phase: Phase::Locked,
                shutdown: false,
            }),
            cv: Condvar::new(),
        }
    }

    /// A human used the app just now: an `Active` deadline moves to its idle
    /// time from now. Does nothing while locked or armed, or once the
    /// deadline has passed (the wipe is due).
    pub fn note_activity(&self) {
        self.note_at(Now::real());
    }

    /// If an `Armed` or `Active` deadline has passed: now `Locked`, and true,
    /// and the caller, who holds the holder's mutex, must wipe.
    pub fn take_expired(&self) -> bool {
        self.take_expired_at(Now::real())
    }

    /// `Armed` for `window` from now, and the timer is woken.
    pub(crate) fn arm(&self, window: Duration) {
        self.arm_at(Now::real(), window);
    }

    /// `Armed` and in time: `Active` for `idle`, true. `Active` and in
    /// time: unchanged, true. Otherwise false.
    pub(crate) fn confirm(&self, idle: Duration) -> bool {
        self.confirm_at(Now::real(), idle)
    }

    /// True while `Active` and before its deadline: the gate is open.
    pub(crate) fn is_active(&self) -> bool {
        self.is_active_at(Now::real())
    }

    pub(crate) fn set_locked(&self) {
        self.timing().phase = Phase::Locked;
    }

    fn arm_at(&self, now: Now, window: Duration) {
        self.timing().phase = Phase::Armed {
            until: Deadline::after(now, window),
        };
        self.cv.notify_all();
    }

    fn confirm_at(&self, now: Now, idle: Duration) -> bool {
        let mut t = self.timing();
        match t.phase {
            Phase::Armed { until } if !until.passed(now) => {
                t.phase = Phase::Active {
                    until: Deadline::after(now, idle),
                    idle,
                };
                self.cv.notify_all();
                true
            }
            Phase::Active { until, .. } => !until.passed(now),
            _ => false,
        }
    }

    fn note_at(&self, now: Now) {
        let mut t = self.timing();
        if let Phase::Active { until, idle } = t.phase {
            if !until.passed(now) {
                t.phase = Phase::Active {
                    until: Deadline::after(now, idle),
                    idle,
                };
            }
        }
    }

    fn is_active_at(&self, now: Now) -> bool {
        matches!(self.timing().phase, Phase::Active { until, .. } if !until.passed(now))
    }

    fn take_expired_at(&self, now: Now) -> bool {
        let mut t = self.timing();
        match t.phase.until() {
            Some(until) if until.passed(now) => {
                t.phase = Phase::Locked;
                true
            }
            _ => false,
        }
    }

    /// Blocks until an `Armed` or `Active` deadline has passed (true) or the
    /// timer shuts down (false). Returns with the clock's mutex released.
    fn wait_for_deadline(&self) -> bool {
        let mut t = self.timing();
        loop {
            if t.shutdown {
                return false;
            }
            let Some(until) = t.phase.until() else {
                t = self.cv.wait(t).unwrap_or_else(PoisonError::into_inner);
                continue;
            };
            let now = Now::real();
            if until.passed(now) {
                return true;
            }
            let wait = until.mono.saturating_duration_since(now.mono).min(MAX_WAIT);
            t = self
                .cv
                .wait_timeout(t, wait)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// The mutex, recovered if poisoned: nothing here can be left half done.
    fn timing(&self) -> MutexGuard<'_, Timing> {
        self.m.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// What holds a vault: the timer locks it through this, under its mutex.
pub trait Holder: Send + 'static {
    /// Wipes and locks everything: the vault ([`crate::Vault::lock`]) and
    /// whatever the holder keeps beside it.
    fn lock_all(&mut self);
}

/// The thread `brev-vault-timer`, which locks the holder when a deadline of
/// its clock passes. It holds only a `Weak` to the holder, so it never
/// keeps it alive. Dropping the timer stops the thread and joins it.
pub struct Timer {
    clock: Arc<Clock>,
    thread: Option<JoinHandle<()>>,
}

impl Timer {
    /// Starts the thread for `holder`, whose vault's clock is `clock`
    /// ([`crate::Vault::clock`]).
    pub fn spawn<S: Holder>(holder: Weak<Mutex<S>>, clock: Arc<Clock>) -> std::io::Result<Timer> {
        let c = Arc::clone(&clock);
        let thread = thread::Builder::new()
            .name("brev-vault-timer".into())
            .spawn(move || run(&holder, &c))?;
        Ok(Timer {
            clock,
            thread: Some(thread),
        })
    }

    /// The clock the timer watches.
    pub fn clock(&self) -> &Clock {
        &self.clock
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        self.clock.timing().shutdown = true;
        self.clock.cv.notify_all();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// The timer's loop. The clock's mutex is released before the holder's is
/// taken; under the holder's, the deadline is checked again, since a
/// caller may have wiped or confirmed in between.
fn run<S: Holder>(holder: &Weak<Mutex<S>>, clock: &Clock) {
    while clock.wait_for_deadline() {
        let Some(h) = holder.upgrade() else { return };
        let mut held = h.lock().unwrap_or_else(PoisonError::into_inner);
        if clock.take_expired() {
            held.lock_all();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: Duration = Duration::from_secs(1);

    #[test]
    fn armed_confirms_only_in_time() {
        let t0 = Now::real();
        let c = Clock::new();
        assert!(!c.confirm_at(t0, 60 * S), "locked: nothing to confirm");
        c.arm_at(t0, 2 * S);
        assert!(!c.is_active_at(t0), "armed: the gate is shut");
        let late = Now {
            mono: t0.mono + 2 * S,
            wall: t0.wall + 2 * S,
        };
        assert!(!c.confirm_at(late, 60 * S));
        c.arm_at(t0, 2 * S);
        assert!(c.confirm_at(t0, 60 * S));
        assert!(c.is_active_at(t0));
        assert!(c.confirm_at(t0, 60 * S), "idempotent while active");
        assert!(!c.take_expired_at(t0));
    }

    #[test]
    fn idle_deadline_and_activity() {
        let t0 = Now::real();
        let at = |s: u32| Now {
            mono: t0.mono + s * S,
            wall: t0.wall + s * S,
        };
        let c = Clock::new();
        c.arm_at(t0, 2 * S);
        c.note_at(t0);
        assert!(!c.is_active_at(t0), "activity while armed does nothing");
        assert!(c.confirm_at(at(1), 60 * S));
        assert!(c.is_active_at(at(60)) && !c.is_active_at(at(61)));
        c.note_at(at(50));
        assert!(c.is_active_at(at(109)) && !c.is_active_at(at(110)));
        // Past the deadline, activity cannot bring it back.
        c.note_at(at(111));
        assert!(!c.is_active_at(at(111)));
        assert!(c.take_expired_at(at(111)));
        assert!(!c.take_expired_at(at(111)), "taken once");
        assert!(!c.is_active_at(t0), "locked");
    }

    /// Instant stands still while the Mac sleeps; the wall clock does not.
    #[test]
    fn wall_clock_catches_sleep_but_not_going_back() {
        let t0 = Now::real();
        let c = Clock::new();
        c.arm_at(t0, 2 * S);
        assert!(c.confirm_at(t0, 60 * S));
        let slept = Now {
            mono: t0.mono + S,
            wall: t0.wall + 61 * S,
        };
        assert!(!c.is_active_at(slept));
        assert!(c.take_expired_at(slept));

        // The wall clock set back an hour: only Instant counts.
        c.arm_at(t0, 2 * S);
        assert!(c.confirm_at(t0, 60 * S));
        let back = |mono: u32| Now {
            mono: t0.mono + mono * S,
            wall: t0.wall - 3600 * S,
        };
        assert!(c.is_active_at(back(59)));
        assert!(!c.is_active_at(back(60)));
    }

    #[test]
    fn a_deadline_too_far_passes_at_once() {
        let t0 = Now::real();
        let c = Clock::new();
        c.arm_at(t0, 2 * S);
        assert!(c.confirm_at(t0, Duration::MAX));
        assert!(!c.is_active_at(t0));
    }
}
