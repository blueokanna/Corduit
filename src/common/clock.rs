//! A tiny UTC clock formatter.
//!
//! The logging layers need `YYYY-MM-DD HH:MM:SS` timestamps. Rather than pull
//! a date-time dependency (whose only job here is string formatting — and
//! whose crate graph conflicts with the codec stack), this module derives
//! the civil date from the Unix timestamp with Hinnant's `civil_from_days`
//! algorithm. No allocation beyond the returned string, no external crate.

use alloc::format;
use alloc::string::String;

/// Seconds in a day / hour / minute.
const SECS_PER_DAY: i64 = 86_400;
const SECS_PER_HOUR: i64 = 3_600;
const SECS_PER_MIN: i64 = 60;

/// Format the current UTC time as `YYYY-MM-DD HH:MM:SS`.
pub fn now_utc_timestamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let days = secs.div_euclid(SECS_PER_DAY);
    let rem = secs.rem_euclid(SECS_PER_DAY);
    let hour = rem / SECS_PER_HOUR;
    let minute = (rem % SECS_PER_HOUR) / SECS_PER_MIN;
    let second = rem % SECS_PER_MIN;

    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}")
}

/// Convert days since 1970-01-01 to a `(year, month, day)` civil date
/// (Howard Hinnant's `civil_from_days`, public domain).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let year = if month <= 2 { y + 1 } else { y };
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_is_1970() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    #[test]
    fn known_dates() {
        // Day counts hand-computed against the proleptic Gregorian calendar.
        assert_eq!(civil_from_days(365), (1971, 1, 1));
        assert_eq!(civil_from_days(730), (1972, 1, 1));
        assert_eq!(civil_from_days(10_957), (2000, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        assert_eq!(civil_from_days(19_782), (2024, 2, 29)); // leap day
        assert_eq!(civil_from_days(20_695), (2026, 8, 30));
    }

    #[test]
    fn negative_days_predate_epoch() {
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(civil_from_days(-365), (1969, 1, 1));
    }

    /// Hinnant's `days_from_civil` — exact inverse of `civil_from_days`.
    fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
        let y = if m <= 2 { y - 1 } else { y };
        let era = y.div_euclid(400);
        let yoe = y - era * 400; // [0, 399]
        let mp = (m as i64 + 9) % 12; // March = 0
        let doy = (153 * mp + 2) / 5 + d as i64 - 1; // [0, 365]
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
        era * 146_097 + doe - 719_468
    }

    #[test]
    fn round_trips_through_inverse() {
        // civil_from_days ∘ days_from_civil must be the identity across a
        // sweep including leap years, century boundaries, and pre-epoch days.
        for &(y, m, d) in &[
            (1969, 1, 1),
            (1969, 12, 31),
            (1970, 1, 1),
            (1971, 1, 1),
            (2000, 1, 1),
            (2024, 2, 29),
            (2024, 12, 31),
            (2026, 8, 30),
            (2037, 12, 31),
            (2100, 3, 1),
            (2400, 2, 29),
        ] {
            let days = days_from_civil(y, m, d);
            assert_eq!(civil_from_days(days), (y, m, d), "day {days}");
        }
    }

    #[test]
    fn timestamp_shape() {
        let s = now_utc_timestamp();
        assert_eq!(s.len(), 19);
        assert_eq!(&s[4..5], "-");
        assert_eq!(&s[7..8], "-");
        assert_eq!(&s[10..11], " ");
        assert_eq!(&s[13..14], ":");
        assert_eq!(&s[16..17], ":");
    }
}
