//! The Corduit synchronous scheduler.
//!
//! Corduit's concurrency model is deliberately *synchronous*: every network
//! operation blocks the calling worker, and parallelism comes from a
//! work-stealing thread pool — [`courierust::courierust_pool::ThreadPool`] —
//! layered with dedicated threads for long-lived relays and one accept
//! thread per listener.
//!
//! This is the inverse of the tokio reactor model Corduit previously used:
//! instead of multiplexing many tasks onto few threads with a poll-based
//! reactor, Corduit runs one blocking state machine per connection on a pool
//! whose workers steal work from each other when idle. There is no async
//! runtime anywhere in the stack — one model, not two worlds bridged by an
//! adapter.
//!
//! # Layering
//!
//! * **Short tasks** (DNS lookups, control plane, periodic refresh, timer
//!   callbacks) run on the work-stealing pool. A job may spawn further jobs
//!   without deadlocking the pool.
//! * **Long-lived relays** run on dedicated OS threads: one spawned per
//!   connection plus the connection's own thread for the other direction
//!   (see [`crate::common::stream::relay_with`]); the listener's connection
//!   budget bounds how many can be live.
//! * **Accept loops** run one thread per listener, and each accepted socket
//!   is served on a dedicated thread whose stack budget the listener sets
//!   (see [`crate::common::listener`]).
//!
//! # Cancellation
//!
//! Blocking reads are bounded by socket timeouts; loops check a
//! [`crate::common::cancel::CancellationToken`] between operations, so
//! cancellation latency is bounded by the configured read timeout.

use courierust::courierust_pool::ThreadPool;
use std::time::Duration;

/// Default worker count if `available_parallelism` reports nothing useful.
const FALLBACK_WORKERS: usize = 4;

/// The global work-stealing pool. Sized to logical cores; a pool with
/// `N` workers never spins — idle workers park on a condition variable.
static GLOBAL_POOL: once_cell::sync::Lazy<ThreadPool> = once_cell::sync::Lazy::new(|| {
    ThreadPool::new()
        .unwrap_or_else(|_| ThreadPool::with_size(FALLBACK_WORKERS).expect("courierust pool init"))
});

/// The global pool shared by the whole engine.
pub fn pool() -> &'static ThreadPool {
    &GLOBAL_POOL
}

/// Number of workers in the global pool.
pub fn workers() -> usize {
    GLOBAL_POOL.len()
}

/// Submit a fire-and-forget job to the global pool.
pub fn spawn<F>(f: F)
where
    F: FnOnce() + Send + 'static,
{
    GLOBAL_POOL.spawn(f);
}

/// A joinable task running on the global pool.
///
/// The task is executed by whichever worker picks it up; [`Task::join`]
/// blocks the caller until the value is produced. Do not call `join` from
/// inside a pool worker while the pool has a single worker — the task could
/// never be scheduled (a one-worker pool cannot run work submitted from its
/// own worker).
pub struct Task<T> {
    rx: std::sync::mpsc::Receiver<T>,
}

impl<T> Task<T> {
    /// Spawn `f` on the pool and return a handle to its result.
    pub fn spawn<F>(f: F) -> Self
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let (tx, rx) = std::sync::mpsc::channel();
        GLOBAL_POOL.spawn(move || {
            let _ = tx.send(f());
        });
        Self { rx }
    }

    /// Block until the task's result is available.
    pub fn join(self) -> T {
        self.rx.recv().unwrap_or_else(|_| {
            // The worker panicked or the pool was torn down. There is no
            // value to recover; a zeroed default is impossible to fabricate
            // generically, so fall back to panicking with a clear message
            // rather than inventing a value.
            panic!("corduit exec: task ended without producing a result")
        })
    }

    /// Block until the result is available or `timeout` elapses.
    pub fn join_timeout(self, timeout: Duration) -> Option<T> {
        self.rx.recv_timeout(timeout).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    #[test]
    fn pool_runs_jobs() {
        let done = Arc::new(AtomicBool::new(false));
        let d = done.clone();
        spawn(move || d.store(true, Ordering::SeqCst));
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !done.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(done.load(Ordering::SeqCst));
    }

    #[test]
    fn task_joins_with_value() {
        let t = Task::spawn(|| 6 * 7);
        assert_eq!(t.join(), 42);
    }
}
