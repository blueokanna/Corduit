//! Cancellation for the synchronous engine.
//!
//! A [`CancellationToken`] is a cheap, cloneable handle that flips exactly
//! once. Loops check [`CancellationToken::is_cancelled`] between bounded
//! operations, or park on [`CancellationToken::wait`] to sleep *until*
//! cancelled or a timeout.
//!
//! # Waiting without polling
//!
//! Park-with-a-timeout is only correct for a resource that has a timeout of
//! its own. It is the wrong tool for anything that blocks on the kernel — a
//! socket read, an `accept`, a TUN descriptor — because there the timeout
//! stops being a safety net and becomes *the* mechanism: the wait has to end
//! before the loop can look at the flag, so the flag is only ever seen once
//! per timeout, and the timeout has to be small for cancellation to feel
//! immediate. Small timeouts mean a worker that wakes tens or hundreds of
//! times a second to discover that nothing happened, which on a phone is
//! battery and heat spent on nothing.
//!
//! [`CancellationToken::on_cancel`] removes the coupling. A worker that would
//! otherwise block forever registers a hook that *releases* it — a
//! `shutdown()`, a wake-up connection, a `notify` — and then waits with no
//! timeout at all. Cancellation is still immediate, but it is delivered by an
//! event instead of by a timer, so idle cost drops to zero and the interval
//! no longer has to trade off against latency.
//!
//! This is the synchronous replacement for tokio's `CancellationToken` /
//! `Notify`: no futures, no reactor — a shared atomic plus a condition
//! variable.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// A closure run once when the token is cancelled.
type Hook = Box<dyn FnOnce() + Send + 'static>;

struct Inner {
    cancelled: AtomicBool,
    wake: Mutex<()>,
    cond: Condvar,
    hooks: Mutex<Vec<Hook>>,
}

/// A single-use cancellation signal shared by clones.
#[derive(Clone)]
pub struct CancellationToken {
    inner: Arc<Inner>,
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

impl CancellationToken {
    /// Create an uncancelled token.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                cancelled: AtomicBool::new(false),
                wake: Mutex::new(()),
                cond: Condvar::new(),
                hooks: Mutex::new(Vec::new()),
            }),
        }
    }

    /// Signal cancellation. Idempotent and safe to call from any thread.
    ///
    /// Waiters are woken first, then every [`on_cancel`] hook runs, in
    /// registration order, on this thread. Hooks are expected to be quick and
    /// non-blocking — they exist to *release* a blocked worker, not to wait
    /// for it — so they run outside the internal locks and a hook that calls
    /// back into the token cannot deadlock.
    ///
    /// [`on_cancel`]: Self::on_cancel
    pub fn cancel(&self) {
        if self.inner.cancelled.swap(true, Ordering::AcqRel) {
            return;
        }
        {
            let _guard = self.inner.wake.lock().unwrap_or_else(|e| e.into_inner());
            self.inner.cond.notify_all();
        }
        let hooks: Vec<Hook> = {
            let mut guard = self.inner.hooks.lock().unwrap_or_else(|e| e.into_inner());
            std::mem::take(&mut *guard)
        };
        for hook in hooks {
            hook();
        }
    }

    /// Register a closure to run when the token is cancelled.
    ///
    /// Runs immediately when the token is already cancelled. The hook is what
    /// releases a worker that waits with no timeout of its own; see the
    /// module documentation for why that is preferable to a short poll
    /// interval.
    ///
    /// The hook runs on whichever thread calls [`cancel`](Self::cancel), so it
    /// must not block: `shutdown()`, a self-connect, a `notify_waiters()` —
    /// anything that turns a blocked wait into a returned one. It may be
    /// dropped unrun if the token is never cancelled.
    pub fn on_cancel<F>(&self, hook: F)
    where
        F: FnOnce() + Send + 'static,
    {
        if self.is_cancelled() {
            hook();
            return;
        }
        {
            let mut guard = self.inner.hooks.lock().unwrap_or_else(|e| e.into_inner());
            // Re-check under the lock: `cancel()` takes this lock to empty the
            // list, so either it has already taken the (absent) hook and this
            // thread runs it below, or this thread pushes it and `cancel()`
            // picks it up afterwards. Neither path can both run and drop it.
            if !self.is_cancelled() {
                guard.push(Box::new(hook));
                return;
            }
        }
        hook();
    }

    /// Whether cancellation has been signalled.
    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::Acquire)
    }

    /// Block until cancelled or `timeout` elapses. Returns `true` if the
    /// token was cancelled within the window.
    pub fn wait(&self, timeout: Duration) -> bool {
        if self.is_cancelled() {
            return true;
        }
        let (lock, cond) = (&self.inner.wake, &self.inner.cond);
        let guard = lock.lock().unwrap();
        let (guard, _) = cond
            .wait_timeout(guard, timeout)
            .unwrap_or_else(|e| e.into_inner());
        drop(guard);
        self.is_cancelled()
    }
    /// Block until cancelled, with no timeout at all.
    ///
    /// Returns immediately when the token is already cancelled. This parks the
    /// thread indefinitely otherwise, so it is only correct when something is
    /// guaranteed to cancel the token — which is the contract
    /// [`on_cancel`](Self::on_cancel) exists to let a caller keep. Use
    /// [`wait`](Self::wait) when that guarantee is not available.
    pub fn wait_cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        let (lock, cond) = (&self.inner.wake, &self.inner.cond);
        let guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        // Checked again with the wake lock held: `cancel()` takes the same
        // lock before notifying, so a cancel that landed in between is either
        // seen here or wakes the `wait` below.
        if self.is_cancelled() {
            return;
        }
        let _guard = cond.wait(guard).unwrap_or_else(|e| e.into_inner());
    }

    /// The number of hooks still registered, for tests.
    #[cfg(test)]
    fn pending_hooks(&self) -> usize {
        self.inner
            .hooks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }
}

impl std::fmt::Debug for CancellationToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CancellationToken")
            .field("cancelled", &self.is_cancelled())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn starts_uncancelled() {
        let t = CancellationToken::new();
        assert!(!t.is_cancelled());
    }

    #[test]
    fn cancel_is_idempotent_and_visible() {
        let t = CancellationToken::new();
        t.cancel();
        t.cancel();
        assert!(t.is_cancelled());
        assert!(t.wait(Duration::from_millis(1)));
    }

    #[test]
    fn wait_returns_false_on_timeout() {
        let t = CancellationToken::new();
        assert!(!t.wait(Duration::from_millis(50)));
    }

    #[test]
    fn wait_wakes_on_cancel() {
        let t = Arc::new(CancellationToken::new());
        let t2 = t.clone();
        let h = std::thread::spawn(move || {
            // Long wait; must be interrupted by cancel().
            t2.wait(Duration::from_secs(30))
        });
        std::thread::sleep(Duration::from_millis(50));
        t.cancel();
        assert!(h.join().unwrap());
    }

    #[test]
    fn clone_shares_signal() {
        let a = CancellationToken::new();
        let b = a.clone();
        a.cancel();
        assert!(b.is_cancelled());
    }

    #[test]
    fn on_cancel_runs_the_hook() {
        let t = CancellationToken::new();
        let hit = Arc::new(AtomicBool::new(false));
        let flag = hit.clone();
        t.on_cancel(move || flag.store(true, Ordering::Release));
        assert_eq!(t.pending_hooks(), 1);
        assert!(!hit.load(Ordering::Acquire));

        t.cancel();
        assert!(hit.load(Ordering::Acquire));
        assert_eq!(t.pending_hooks(), 0, "hooks are taken, not kept");
    }

    #[test]
    fn on_cancel_runs_immediately_when_already_cancelled() {
        let t = CancellationToken::new();
        t.cancel();
        let hit = Arc::new(AtomicBool::new(false));
        let flag = hit.clone();
        t.on_cancel(move || flag.store(true, Ordering::Release));
        assert!(hit.load(Ordering::Acquire));
        assert_eq!(t.pending_hooks(), 0);
    }

    /// The hook must land exactly once however its registration races with the
    /// cancellation: running it twice would shut a socket down twice, and
    /// dropping it would leave a worker parked forever.
    #[test]
    fn on_cancel_hook_runs_exactly_once_under_race() {
        for _ in 0..64 {
            let t = Arc::new(CancellationToken::new());
            let runs = Arc::new(std::sync::atomic::AtomicUsize::new(0));

            let registrar_token = t.clone();
            let registrar_runs = runs.clone();
            let registrar = std::thread::spawn(move || {
                registrar_token.on_cancel(move || {
                    registrar_runs.fetch_add(1, Ordering::AcqRel);
                });
            });

            t.cancel();
            registrar.join().unwrap();

            assert_eq!(runs.load(Ordering::Acquire), 1);
            assert_eq!(t.pending_hooks(), 0);
        }
    }

    #[test]
    fn hook_registered_after_cancel_from_another_thread_style_race() {
        // The cancellation is observed through a clone while the hook is being
        // registered on the original: both orders must still run it once.
        for _ in 0..64 {
            let t = CancellationToken::new();
            let watcher = t.clone();
            let runs = Arc::new(std::sync::atomic::AtomicUsize::new(0));

            let canceller = std::thread::spawn(move || watcher.cancel());
            let local_runs = runs.clone();
            t.on_cancel(move || {
                local_runs.fetch_add(1, Ordering::AcqRel);
            });
            canceller.join().unwrap();

            assert_eq!(runs.load(Ordering::Acquire), 1);
        }
    }

    #[test]
    fn wait_cancelled_returns_on_cancel() {
        let t = Arc::new(CancellationToken::new());
        let t2 = t.clone();
        let h = std::thread::spawn(move || {
            t2.wait_cancelled();
            t2.is_cancelled()
        });
        std::thread::sleep(Duration::from_millis(20));
        t.cancel();
        assert!(h.join().unwrap());
    }

    #[test]
    fn wait_cancelled_returns_immediately_when_already_cancelled() {
        let t = CancellationToken::new();
        t.cancel();
        t.wait_cancelled();
    }
}
