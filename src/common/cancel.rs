//! Cancellation for the synchronous engine.
//!
//! A [`CancellationToken`] is a cheap, cloneable handle that flips exactly
//! once. Loops check [`CancellationToken::is_cancelled`] between bounded
//! operations, or park on [`CancellationToken::wait`] to sleep *until*
//! cancelled or a timeout. Because socket reads carry their own timeouts,
//! cancellation latency is bounded: a worker notices within one read
//! timeout of `cancel()` being called.
//!
//! This is the synchronous replacement for tokio's `CancellationToken` /
//! `Notify`: no futures, no reactor — a shared atomic plus a condition
//! variable.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

struct Inner {
    cancelled: AtomicBool,
    wake: Mutex<()>,
    cond: Condvar,
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
            }),
        }
    }

    /// Signal cancellation. Idempotent and safe to call from any thread.
    pub fn cancel(&self) {
        self.inner.cancelled.store(true, Ordering::Release);
        let _guard = self.inner.wake.lock().unwrap();
        self.inner.cond.notify_all();
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
}
