//! Rate-limited logging for events a stale client can repeat endlessly.
//!
//! Some conditions are both *expected* and *arbitrarily frequent*: a phone that
//! holds a fake-IP address from a previous session keeps dialling it once the
//! mapping behind it is gone, a device on a broken link keeps retrying, a probe
//! keeps hitting a disabled feature. Logging each occurrence floods the log and
//! buries the signal; logging none of them hides a real problem.
//!
//! [`LogThrottle`] keeps the middle ground: the first occurrence is logged
//! immediately, everything inside the quiet window is counted, and the count is
//! handed to whichever call eventually breaks the silence — so the log stays
//! complete even though the lines are collapsed.

use parking_lot::Mutex;
use std::time::{Duration, Instant};

/// State behind a [`LogThrottle`].
#[derive(Default)]
struct Window {
    /// When a message was last admitted.
    last_admitted: Option<Instant>,
    /// Occurrences collapsed since then.
    suppressed: u64,
}

/// Admits at most one message per interval and reports what it collapsed.
pub struct LogThrottle {
    interval: Duration,
    window: Mutex<Window>,
}

impl LogThrottle {
    /// Create a throttle that admits one message per `interval`.
    pub const fn new(interval: Duration) -> Self {
        Self {
            interval,
            window: Mutex::new(Window {
                last_admitted: None,
                suppressed: 0,
            }),
        }
    }

    /// Decide whether the caller should log now.
    ///
    /// Returns `Some(suppressed)` on the admitted call — `suppressed` is the
    /// number of occurrences collapsed since the previous admitted message, so
    /// the line can state how many events it stands for — and `None` while the
    /// quiet window is still open.
    pub fn admit(&self) -> Option<u64> {
        self.admit_at(Instant::now())
    }

    /// Interval-injectable core of [`LogThrottle::admit`].
    fn admit_at(&self, now: Instant) -> Option<u64> {
        let mut window = self.window.lock();
        match window.last_admitted {
            Some(last) if now.saturating_duration_since(last) < self.interval => {
                window.suppressed = window.suppressed.saturating_add(1);
                None
            }
            _ => {
                window.last_admitted = Some(now);
                let suppressed = std::mem::take(&mut window.suppressed);
                Some(suppressed)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admits_the_first_event_and_collapses_the_rest_of_the_window() {
        let throttle = LogThrottle::new(Duration::from_secs(5));
        let start = Instant::now();

        assert_eq!(throttle.admit_at(start), Some(0), "first event is logged");
        assert_eq!(throttle.admit_at(start + Duration::from_millis(10)), None);
        assert_eq!(throttle.admit_at(start + Duration::from_millis(20)), None);
        assert_eq!(
            throttle.admit_at(start + Duration::from_secs(6)),
            Some(2),
            "the suppressed count travels with the next logged line"
        );
        assert_eq!(throttle.admit_at(start + Duration::from_secs(7)), None);
    }

    #[test]
    fn an_unused_throttle_admits_immediately() {
        let throttle = LogThrottle::new(Duration::from_secs(60));
        assert_eq!(throttle.admit(), Some(0));
    }
}
