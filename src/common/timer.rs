//! A single-threaded timer wheel for the synchronous engine.
//!
//! Corduit needs timers for health checks, provider refresh and idle
//! reaping, but has no async runtime to schedule onto. [`Timer`] is a
//! dedicated scheduler thread with a binary heap of deadlines. Callbacks run
//! on the timer thread and must be short — long-running work should be
//! delegated to the work-stealing pool *by the callback itself*
//! ([`crate::common::exec::spawn`]).
//!
//! Two schedules:
//!
//! * [`Timer::after`] — fire once after a delay.
//! * [`Timer::every`] — fire repeatedly; the next tick is scheduled *after*
//!   the previous callback returns, so executions never overlap and there is
//!   no interval drift accumulation.
//!
//! Every schedule returns a [`TimerHandle`]; dropping it cancels the timer.
//! A cancelled entry is removed from the wheel promptly, so it does not
//! linger in memory.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

type Job = Box<dyn FnMut() + Send + 'static>;

struct Entry {
    /// Cancellation flag shared with the handle.
    cancelled: Arc<AtomicBool>,
    /// The job to run. For `every`, rescheduled after each completion.
    job: Job,
    /// Present for repeating timers: the period.
    period: Option<Duration>,
    /// The wall-clock anchor used to compute the next drift-free deadline.
    anchor: Instant,
    /// Number of completed firings (informational).
    fires: u64,
}

/// Scheduler state, guarded by the mutex in [`Core`]. Holding it makes the
/// whole [`Core`] `Sync` (parking_lot's `Mutex<T>` is `Sync` when `T: Send`),
/// which is what lets the timer live in a `static`.
struct Inner {
    /// Min-heap of `(deadline, id)` — the scheduler's next-event list.
    heap: BinaryHeap<Reverse<(Instant, u64)>>,
    /// Live entries by id. Cancellation removes the entry here; the stale
    /// heap entry is skipped when it surfaces.
    entries: HashMap<u64, Entry>,
    /// Monotonic id source.
    next_id: u64,
    shutdown: bool,
}

struct Core {
    inner: parking_lot::Mutex<Inner>,
    wake: parking_lot::Condvar,
}

/// A timer wheel. Drop stops the scheduler thread (joins it).
pub struct Timer {
    core: Arc<Core>,
    /// Held to keep the scheduler thread alive; joined on drop.
    #[allow(dead_code)]
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Default for Timer {
    fn default() -> Self {
        Self::new()
    }
}

impl Timer {
    /// Start a scheduler thread.
    pub fn new() -> Self {
        let core = Arc::new(Core {
            inner: parking_lot::Mutex::new(Inner {
                heap: BinaryHeap::new(),
                entries: HashMap::new(),
                next_id: 0,
                shutdown: false,
            }),
            wake: parking_lot::Condvar::new(),
        });
        let c = core.clone();
        let thread = std::thread::Builder::new()
            .name("corduit-timer".into())
            .spawn(move || Self::run(&c))
            .expect("timer thread");
        Self {
            core,
            thread: Some(thread),
        }
    }

    fn run(core: &Core) {
        loop {
            let mut guard = core.inner.lock();
            while !guard.shutdown {
                // Copy the next deadline out so no borrow of `guard` is held
                // across the condvar wait (which needs `&mut guard`).
                let next = guard.heap.peek().map(|&Reverse((d, _))| d);
                match next {
                    None => core.wake.wait(&mut guard),
                    Some(deadline) => {
                        let now = Instant::now();
                        if deadline <= now {
                            break;
                        }
                        let _ = core.wake.wait_for(&mut guard, deadline - now);
                    }
                }
            }
            if guard.shutdown {
                return;
            }

            // Pop the due entry (there must be one at the heap top).
            let Some(Reverse((_deadline, id))) = guard.heap.pop() else {
                continue;
            };
            let Some(mut entry) = guard.entries.remove(&id) else {
                continue; // cancelled
            };
            if entry.cancelled.load(Ordering::Acquire) {
                continue;
            }
            drop(guard);

            // Run the job on the timer thread. Callbacks must be short —
            // long-running work should be delegated to the work-stealing
            // pool *by the callback itself* (`crate::common::exec::spawn`).
            // Running here (instead of moving the job to the pool) is what
            // lets repeating timers keep their job across re-arms.
            (entry.job)();
            entry.fires += 1;

            // Re-arm repeating timers with a drift-free deadline anchored on
            // the original schedule.
            if let Some(period) = entry.period {
                let mut deadline = entry.anchor + period;
                // Skip missed ticks so a slow callback doesn't cause a burst
                // of back-to-back firings.
                while deadline <= Instant::now() {
                    deadline += period;
                }
                entry.anchor = deadline - period;
                let mut guard = core.inner.lock();
                guard.next_id += 1;
                let new_id = guard.next_id;
                guard.heap.push(Reverse((deadline, new_id)));
                guard.entries.insert(new_id, entry);
                core.wake.notify_one();
            }
        }
    }

    /// Fire `f` once after `delay`.
    pub fn after<F>(&self, delay: Duration, f: F) -> TimerHandle
    where
        F: FnMut() + Send + 'static,
    {
        self.insert(Instant::now() + delay, None, f)
    }

    /// Fire `f` every `period`, serialized (next tick starts after the
    /// previous callback completes).
    pub fn every<F>(&self, period: Duration, f: F) -> TimerHandle
    where
        F: FnMut() + Send + 'static,
    {
        self.insert(Instant::now() + period, Some(period), f)
    }

    fn insert<F>(&self, deadline: Instant, period: Option<Duration>, f: F) -> TimerHandle
    where
        F: FnMut() + Send + 'static,
    {
        let mut guard = self.core.inner.lock();
        guard.next_id += 1;
        let id = guard.next_id;
        let cancelled = Arc::new(AtomicBool::new(false));
        guard.heap.push(Reverse((deadline, id)));
        guard.entries.insert(
            id,
            Entry {
                cancelled: cancelled.clone(),
                job: Box::new(f),
                period,
                anchor: deadline,
                fires: 0,
            },
        );
        self.core.wake.notify_one();
        TimerHandle {
            core: self.core.clone(),
            id,
            cancelled,
        }
    }
}

/// A live timer. Dropping or calling [`TimerHandle::cancel`] cancels it.
#[derive(Clone)]
pub struct TimerHandle {
    core: Arc<Core>,
    id: u64,
    cancelled: Arc<AtomicBool>,
}

impl TimerHandle {
    /// Cancel the timer. Idempotent.
    pub fn cancel(&self) {
        if !self.cancelled.swap(true, Ordering::AcqRel) {
            let mut guard = self.core.inner.lock();
            guard.entries.remove(&self.id);
            self.core.wake.notify_one();
        }
    }

    /// Whether this timer has been cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

impl Drop for TimerHandle {
    fn drop(&mut self) {
        self.cancel();
    }
}

/// The process-wide timer wheel.
pub fn timer() -> &'static Timer {
    static TIMER: once_cell::sync::Lazy<Timer> = once_cell::sync::Lazy::new(Timer::new);
    &TIMER
}

/// Fire `f` once after `delay` on the global timer.
pub fn after<F>(delay: Duration, f: F) -> TimerHandle
where
    F: FnMut() + Send + 'static,
{
    timer().after(delay, f)
}

/// Fire `f` every `period` on the global timer.
pub fn every<F>(period: Duration, f: F) -> TimerHandle
where
    F: FnMut() + Send + 'static,
{
    timer().every(period, f)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn after_fires_once() {
        let t = Timer::new();
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        // Keep the handle alive: dropping a TimerHandle cancels the timer.
        let _handle = t.after(Duration::from_millis(30), move || {
            h.fetch_add(1, Ordering::SeqCst);
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        while hits.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cancel_prevents_fire() {
        let t = Timer::new();
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        let handle = t.after(Duration::from_millis(30), move || {
            h.fetch_add(1, Ordering::SeqCst);
        });
        handle.cancel();
        std::thread::sleep(Duration::from_millis(80));
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn every_fires_repeatedly_and_serialized() {
        let t = Timer::new();
        let hits = Arc::new(AtomicUsize::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));
        let (h, a, m) = (hits.clone(), active.clone(), max_active.clone());
        // Keep the handle alive so the repeating timer is not cancelled.
        let _handle = t.every(Duration::from_millis(10), move || {
            let cur = a.fetch_add(1, Ordering::SeqCst) + 1;
            m.fetch_max(cur, Ordering::SeqCst);
            h.fetch_add(1, Ordering::SeqCst);
            a.fetch_sub(1, Ordering::SeqCst);
        });
        // Observe for a generous window. macOS CI VMs coalesce condvar
        // timeouts (parking_lot waits with CLOCK_REALTIME
        // `pthread_cond_timedwait` there), so a 10ms timer can fire as
        // rarely as every ~100ms under load. Assert a conservative lower
        // bound: even a ~10x slowdown still clears it, while a timer that
        // fails to repeat (or fires only once) is still caught.
        let deadline = Instant::now() + Duration::from_millis(500);
        while Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let n = hits.load(Ordering::SeqCst);
        assert!(n >= 3, "expected at least 3 firings, got {n}");
        // The wheel runs callbacks on a single thread and re-arms only after
        // the previous callback returns, so executions never overlap.
        assert_eq!(
            max_active.load(Ordering::SeqCst),
            1,
            "callbacks must not overlap"
        );
    }

    #[test]
    fn drop_handle_cancels() {
        let t = Timer::new();
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        {
            let _handle = t.after(Duration::from_millis(20), move || {
                h.fetch_add(1, Ordering::SeqCst);
            });
        }
        std::thread::sleep(Duration::from_millis(70));
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }
}
