//! Blocking synchronization primitives for the synchronous engine.
//!
//! [`Notify`] is the blocking counterpart of tokio's `Notify`: a latched
//! signal a thread can wait on with a timeout. Because Corduit has no
//! reactor, wakeups are *advisory* — every waiter re-checks the real shared
//! state (under the connection lock) after waking, so a consumed flag only
//! costs one extra poll, never correctness.
//!
//! This single primitive replaces tokio's `Notify`, `watch` and most
//! `oneshot` uses across the engine: cross-thread signalling in the QUIC
//! transport, per-stream data availability, and shutdown fan-out.

use parking_lot::Condvar;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

struct NotifyInner {
    /// Held only to pair with the condvar (the flag is the real state).
    lock: Mutex<()>,
    cond: Condvar,
    /// A notification is latched until a waiter consumes it.
    flag: AtomicBool,
}

/// A latched cross-thread wakeup signal.
///
/// * [`Notify::notify_one`] / [`Notify::notify_waiters`] set the latch and
///   wake waiting threads.
/// * [`Notify::wait`] blocks until the latch is set (or `timeout` elapses)
///   and returns `true` if it observed a notification. The latch is
///   consumed by the waiter that observes it.
#[derive(Clone)]
pub struct Notify {
    inner: Arc<NotifyInner>,
}

impl Default for Notify {
    fn default() -> Self {
        Self::new()
    }
}

impl Notify {
    /// Create an unset notify.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(NotifyInner {
                lock: Mutex::new(()),
                cond: Condvar::new(),
                flag: AtomicBool::new(false),
            }),
        }
    }

    /// Set the latch and wake one waiter.
    pub fn notify_one(&self) {
        let _guard = self.inner.lock.lock();
        self.inner.flag.store(true, Ordering::Release);
        self.inner.cond.notify_one();
    }

    /// Set the latch and wake all waiters.
    pub fn notify_waiters(&self) {
        let _guard = self.inner.lock.lock();
        self.inner.flag.store(true, Ordering::Release);
        self.inner.cond.notify_all();
    }

    /// Peek-and-clear the latch without waiting.
    pub fn notified(&self) -> bool {
        let _guard = self.inner.lock.lock();
        let f = self.inner.flag.load(Ordering::Acquire);
        self.inner.flag.store(false, Ordering::Release);
        f
    }

    /// Block until the latch is set or `timeout` elapses.
    ///
    /// Returns `true` if a notification was observed within the window (the
    /// latch is consumed). A `false` return means the timeout elapsed.
    pub fn wait(&self, timeout: Duration) -> bool {
        let mut guard = self.inner.lock.lock();
        if self.inner.flag.load(Ordering::Acquire) {
            self.inner.flag.store(false, Ordering::Release);
            return true;
        }
        let _ = self.inner.cond.wait_for(&mut guard, timeout);
        if self.inner.flag.load(Ordering::Acquire) {
            self.inner.flag.store(false, Ordering::Release);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn wait_times_out() {
        let n = Notify::new();
        assert!(!n.wait(Duration::from_millis(50)));
    }

    #[test]
    fn notify_wakes_one() {
        let n = Arc::new(Notify::new());
        let n2 = n.clone();
        let h = std::thread::spawn(move || n2.wait(Duration::from_secs(10)));
        std::thread::sleep(Duration::from_millis(50));
        n.notify_one();
        assert!(h.join().unwrap());
    }

    #[test]
    fn latch_is_consumed() {
        let n = Notify::new();
        n.notify_one();
        assert!(n.wait(Duration::from_millis(10)));
        assert!(!n.wait(Duration::from_millis(10)), "latch consumed");
    }

    #[test]
    fn notified_peeks_and_clears() {
        let n = Notify::new();
        n.notify_waiters();
        assert!(n.notified());
        assert!(!n.notified());
    }

    #[test]
    fn broadcast_wakes_all() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let n = Arc::new(Notify::new());
        let done = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let n2 = n.clone();
            let d = done.clone();
            handles.push(std::thread::spawn(move || {
                // Each waiter blocks until it observes a notification; a
                // single latch can be consumed by only one waiter, so the
                // test keeps broadcasting until every waiter has woken.
                while !n2.wait(Duration::from_millis(100)) {}
                d.fetch_add(1, Ordering::SeqCst);
            }));
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while done.load(Ordering::SeqCst) < 4 && std::time::Instant::now() < deadline {
            n.notify_waiters();
            std::thread::sleep(Duration::from_millis(2));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(done.load(Ordering::SeqCst), 4);
    }
}
