use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CertTime {
    pub year: i32,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
}

impl CertTime {
    /// Whole days remaining until `self`, counted from the exact elapsed
    /// time (not the bare calendar date): a `now` that is partway through
    /// its day has already used up those hours, so they are not counted as
    /// a whole day still remaining. `div_euclid` floors towards negative
    /// infinity, so a `now` after `self` still gives a correctly negative
    /// count.
    pub fn days_until(&self, now: &CertTime) -> i64 {
        self.unix_seconds()
            .saturating_sub(now.unix_seconds())
            .div_euclid(86_400)
    }

    fn unix_seconds(&self) -> i64 {
        days_from_civil(self.year, self.month, self.day) * 86_400
            + i64::from(self.hour) * 3_600
            + i64::from(self.minute) * 60
            + i64::from(self.second)
    }
}

impl fmt::Display for CertTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let month = MONTHS
            .get(self.month.wrapping_sub(1) as usize)
            .copied()
            .unwrap_or("???");
        write!(
            f,
            "notAfter={month} {day:>2} {hour:02}:{minute:02}:{second:02} {year} GMT",
            day = self.day,
            hour = self.hour,
            minute = self.minute,
            second = self.second,
            year = self.year,
        )
    }
}

/// OpenSSL prints a decimal year. 1970 is the Unix epoch. 9999 is the last
/// four-digit year. A date outside that range is not a certificate date.
const MIN_YEAR: i32 = 1970;
const MAX_YEAR: i32 = 9999;

pub fn parse_openssl_enddate(text: &str) -> Option<CertTime> {
    parse_openssl_date(text, "notAfter=")
}

/// `openssl x509 -noout -dates` prints both lines; this one is used only to
/// relate a certificate's total lifetime to the renewal threshold.
pub fn parse_openssl_startdate(text: &str) -> Option<CertTime> {
    parse_openssl_date(text, "notBefore=")
}

fn parse_openssl_date(text: &str, prefix: &str) -> Option<CertTime> {
    let mut found = None;
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with(prefix) {
            continue;
        }
        let parsed = parse_date_line(line, prefix)?;
        match found {
            None => found = Some(parsed),
            Some(previous) if previous == parsed => {}
            Some(_) => return None,
        }
    }
    found
}

fn parse_date_line(line: &str, prefix: &str) -> Option<CertTime> {
    let rest = line.strip_prefix(prefix)?;
    let month_name = rest.get(0..3)?;
    let month = month_number(month_name)?;
    if rest.as_bytes().get(3) != Some(&b' ') {
        return None;
    }
    let day = rest.get(4..6)?.trim().parse::<u32>().ok()?;
    if rest.as_bytes().get(6) != Some(&b' ') {
        return None;
    }
    let time = rest.get(7..15)?;
    let hour = time.get(0..2)?.parse::<u32>().ok()?;
    if time.as_bytes().get(2) != Some(&b':') {
        return None;
    }
    let minute = time.get(3..5)?.parse::<u32>().ok()?;
    if time.as_bytes().get(5) != Some(&b':') {
        return None;
    }
    let second = time.get(6..8)?.parse::<u32>().ok()?;
    if rest.as_bytes().get(15) != Some(&b' ') {
        return None;
    }
    let (year_text, zone) = rest.get(16..)?.split_once(' ')?;
    if zone != "GMT" {
        return None;
    }
    let year = year_text.parse::<i32>().ok()?;
    if !(MIN_YEAR..=MAX_YEAR).contains(&year) {
        return None;
    }
    if !(0..=23).contains(&hour) || !(0..=59).contains(&minute) || !(0..=59).contains(&second) {
        return None;
    }
    if !valid_date(year, month, day) {
        return None;
    }
    Some(CertTime {
        year,
        month,
        day,
        hour,
        minute,
        second,
    })
}

fn month_number(name: &str) -> Option<u32> {
    MONTHS
        .iter()
        .position(|month| *month == name)
        .map(|index| index as u32 + 1)
}

fn valid_date(year: i32, month: u32, day: u32) -> bool {
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => return false,
    };
    (1..=max_day).contains(&day)
}

fn is_leap(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// `None` when the UTC date is outside 1970-01-01 through 9999-12-31.
pub fn try_from_unix_seconds(secs: i64) -> Option<CertTime> {
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400) as u32;
    let (year, month, day) = civil_from_days(days)?;
    if !(MIN_YEAR..=MAX_YEAR).contains(&year) {
        return None;
    }
    Some(CertTime {
        year,
        month,
        day,
        hour: tod / 3_600,
        minute: (tod % 3_600) / 60,
        second: tod % 60,
    })
}

pub fn from_unix_seconds(secs: i64) -> CertTime {
    try_from_unix_seconds(secs).expect("Unix seconds are inside 1970-01-01 through 9999-12-31 UTC")
}

/// The system clock is not a certificate date, and it is not a Unix second of 0.
pub const SYSTEM_CLOCK_RANGE: &str = "system clock is outside 1970-01-01 through 9999-12-31 UTC";

/// `Err` when `now` is before 1970-01-01 or after 9999-12-31 UTC.
/// A clock before the epoch is not turned into second 0.
pub fn try_from_system_time(now: SystemTime) -> Result<CertTime, &'static str> {
    let secs = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SYSTEM_CLOCK_RANGE)?
        .as_secs();
    let secs = i64::try_from(secs).map_err(|_| SYSTEM_CLOCK_RANGE)?;
    try_from_unix_seconds(secs).ok_or(SYSTEM_CLOCK_RANGE)
}

/// Days since the civil epoch 1970-01-01. Howard Hinnant's `days_from_civil`.
/// The year shift uses `i64`, so `i32::MIN` does not overflow.
fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let mut year = i64::from(year);
    let month = i64::from(month);
    let day = i64::from(day);
    if month <= 2 {
        year -= 1;
    }
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_adj = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_adj + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Inverse of `days_from_civil`. Howard Hinnant's `civil_from_days`.
/// `None` when a step overflows or the year does not fit in `i32`.
fn civil_from_days(days: i64) -> Option<(i32, u32, u32)> {
    let z = days.checked_add(719_468)?;
    let era = if z >= 0 {
        z.checked_div(146_097)?
    } else {
        z.checked_sub(146_096)?.checked_div(146_097)?
    };
    let doe = z.checked_sub(era.checked_mul(146_097)?)?;
    let doe = u64::try_from(doe).ok()?;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = i64::try_from(yoe)
        .ok()?
        .checked_add(era.checked_mul(400)?)?;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    if month <= 2 {
        year = year.checked_add(1)?;
    }
    Some((
        i32::try_from(year).ok()?,
        u32::try_from(month).ok()?,
        u32::try_from(day).ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(year: i32, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> CertTime {
        CertTime {
            year,
            month,
            day,
            hour,
            minute,
            second,
        }
    }

    #[test]
    fn from_unix_seconds_known_instants() {
        assert_eq!(from_unix_seconds(0), at(1970, 1, 1, 0, 0, 0));
        assert_eq!(from_unix_seconds(951_782_400), at(2000, 2, 29, 0, 0, 0));
        assert_eq!(from_unix_seconds(1_791_244_800), at(2026, 10, 6, 0, 0, 0));
        assert_eq!(from_unix_seconds(1_791_273_600), at(2026, 10, 6, 8, 0, 0));
        assert_eq!(from_unix_seconds(3_661), at(1970, 1, 1, 1, 1, 1));
    }

    #[test]
    fn dates_output_and_enddate_output_both_parse() {
        let dates = "\
notBefore=Jun  4 11:04:38 2015 GMT
notAfter=Jun  4 11:04:38 2035 GMT
";
        assert_eq!(
            parse_openssl_enddate(dates),
            Some(at(2035, 6, 4, 11, 4, 38))
        );
        let other_dates = "\
notBefore=May  5 09:37:37 2011 GMT
notAfter=Dec 31 09:37:37 2030 GMT
";
        assert_eq!(
            parse_openssl_enddate(other_dates),
            Some(at(2030, 12, 31, 9, 37, 37))
        );
        assert_eq!(
            parse_openssl_enddate("notAfter=Jun  4 11:04:38 2035 GMT\n"),
            Some(at(2035, 6, 4, 11, 4, 38))
        );
    }

    #[test]
    fn parse_openssl_startdate_reads_notbefore_and_ignores_notafter() {
        let dates = "\
notBefore=Jun  4 11:04:38 2015 GMT
notAfter=Jun  4 11:04:38 2035 GMT
";
        assert_eq!(
            parse_openssl_startdate(dates),
            Some(at(2015, 6, 4, 11, 4, 38))
        );
        assert_eq!(
            parse_openssl_startdate("notAfter=Jun  4 11:04:38 2035 GMT\n"),
            None
        );
        assert!(parse_openssl_startdate("").is_none());
    }

    #[test]
    fn year_outside_1970_through_9999_is_not_a_date() {
        assert!(parse_openssl_enddate("notAfter=Jan  1 00:00:00 -2147483648 GMT\n").is_none());
        assert!(parse_openssl_enddate("notAfter=Jan  1 00:00:00 1969 GMT\n").is_none());
        assert!(parse_openssl_enddate("notAfter=Jan  1 00:00:00 10000 GMT\n").is_none());
        assert_eq!(
            parse_openssl_enddate("notAfter=Jan  1 00:00:00 1970 GMT\n"),
            Some(at(1970, 1, 1, 0, 0, 0))
        );
        assert_eq!(
            parse_openssl_enddate("notAfter=Dec 31 23:59:59 9999 GMT\n"),
            Some(at(9999, 12, 31, 23, 59, 59))
        );
        let bogus = at(i32::MIN, 1, 1, 0, 0, 0);
        let now = at(2026, 10, 6, 8, 0, 0);
        assert!(bogus.days_until(&now) < 0);
        assert!(try_from_unix_seconds(i64::MIN).is_none());
        assert!(try_from_unix_seconds(-1).is_none());
        assert!(try_from_unix_seconds(i64::MAX).is_none());
        assert!(try_from_unix_seconds(253_402_300_800).is_none());
        assert_eq!(try_from_unix_seconds(0), Some(at(1970, 1, 1, 0, 0, 0)));
        assert_eq!(
            try_from_unix_seconds(253_402_300_799),
            Some(at(9999, 12, 31, 23, 59, 59))
        );
    }

    #[test]
    fn hour_minute_or_second_out_of_range_alone_is_rejected() {
        // Each case is invalid in exactly one field, so an `||` mutated to
        // `&&` (which would require all three fields to be out of range at
        // once) lets it through.
        assert!(parse_openssl_enddate("notAfter=Jan  1 24:00:00 2026 GMT\n").is_none());
        assert!(parse_openssl_enddate("notAfter=Jan  1 00:60:00 2026 GMT\n").is_none());
        assert!(parse_openssl_enddate("notAfter=Jan  1 00:00:60 2026 GMT\n").is_none());
        assert_eq!(
            parse_openssl_enddate("notAfter=Jan  1 23:59:59 2026 GMT\n"),
            Some(at(2026, 1, 1, 23, 59, 59))
        );
    }

    #[test]
    fn is_leap_follows_the_4_100_400_rule() {
        // Picked to separate `%` from `/` and `+` at each operator in
        // `is_leap`: a single-digit year isolates the `% 4` and `% 100`
        // checks from the `% 400` branch, and 1900/2100 (divisible by 100,
        // not 400) separate the century rule from "divisible by 4".
        for year in [8, 2000, 2004, 2024, 1600, 2400] {
            assert!(is_leap(year), "{year} is a leap year");
        }
        for year in [1900, 2100, 2200, 2300, 2023, 1] {
            assert!(!is_leap(year), "{year} is not a leap year");
        }
    }

    #[test]
    fn february_29_is_only_valid_in_a_leap_year() {
        assert_eq!(
            parse_openssl_enddate("notAfter=Feb 29 00:00:00 2024 GMT\n"),
            Some(at(2024, 2, 29, 0, 0, 0))
        );
        assert!(parse_openssl_enddate("notAfter=Feb 29 00:00:00 2023 GMT\n").is_none());
        assert!(parse_openssl_enddate("notAfter=Feb 29 00:00:00 1900 GMT\n").is_none());
        assert_eq!(
            parse_openssl_enddate("notAfter=Feb 29 00:00:00 2000 GMT\n"),
            Some(at(2000, 2, 29, 0, 0, 0))
        );
        assert!(parse_openssl_enddate("notAfter=Apr 31 00:00:00 2026 GMT\n").is_none());
        assert!(parse_openssl_enddate("notAfter=Jan  0 00:00:00 2026 GMT\n").is_none());
        assert!(parse_openssl_enddate("notAfter=Jan 32 00:00:00 2026 GMT\n").is_none());
    }

    #[test]
    fn minute_and_second_split_the_remainder_correctly() {
        // tod % 3600 = 125 for this instant; minute must be 125 / 60 = 2 and
        // second 125 % 60 = 5. A `/` <-> `%` swap at either operator would
        // print 5 minutes 2 seconds, or fold the minutes into the hour.
        assert_eq!(from_unix_seconds(3_600 + 125), at(1970, 1, 1, 1, 2, 5));
    }

    #[test]
    fn days_until_counts_an_elapsed_partial_day_not_the_bare_calendar_date() {
        // notAfter is 64 days (5,529,600s) after notBefore: Let's Encrypt's
        // short-lived profile. A third of that lifetime is 1,843,200s, i.e.
        // 21 days and 8 hours, not a whole number of calendar days.
        let not_after = at(2026, 3, 6, 0, 0, 0);
        // Exactly 21 days and 8 hours before not_after, but still the same
        // calendar date (Feb 12) as a point only 8 hours earlier would be.
        let now = at(2026, 2, 12, 16, 0, 0);
        assert_eq!(
            not_after.days_until(&now),
            21,
            "8 hours have already elapsed on Feb 12, so only 21 whole days remain, \
             not 22 as a bare calendar-date subtraction would report"
        );
    }

    #[test]
    fn days_until_for_a_cert_expired_one_hour_ago_is_negative_one() {
        let now = at(2026, 10, 6, 8, 0, 0);
        let not_after = at(2026, 10, 6, 7, 0, 0);
        assert_eq!(not_after.days_until(&now), -1);
    }

    #[test]
    fn days_from_civil_and_civil_from_days_round_trip_across_eras() {
        // Howard Hinnant's day-count conversion is each other's inverse.
        // Sweeping dates across every kind of boundary the formula has to
        // special-case (the 400-year era, the 100-year non-leap century, the
        // 4-year leap rule and the March-based month renumbering) means a
        // wrong divisor or sign on either side almost always breaks some
        // date's round trip, even though the two functions are never
        // mutated together.
        for year in [
            1970, 1999, 2000, 2001, 2099, 2100, 2101, 2399, 2400, 2401, 9999,
        ] {
            for (month, day) in [(1u32, 1u32), (2, 28), (2, 29), (3, 1), (12, 31)] {
                if month == 2 && day == 29 && !is_leap(year) {
                    continue;
                }
                let days = days_from_civil(year, month, day);
                assert_eq!(
                    civil_from_days(days),
                    Some((year, month, day)),
                    "{year}-{month:02}-{day:02}"
                );
            }
        }
        for days in [
            -1_i64, 0, 1, 146_096, 146_097, 146_098, 719_468, 719_469, 2_932_896, 2_932_897,
        ] {
            let (year, month, day) = civil_from_days(days).unwrap_or_else(|| panic!("{days}"));
            assert_eq!(days_from_civil(year, month, day), days, "{days}");
        }
    }

    #[test]
    fn contradictory_not_after_lines_are_not_a_date() {
        assert!(parse_openssl_enddate(
            "notAfter=Jan  1 00:00:00 2030 GMT\nnotAfter=Jun  1 00:00:00 2031 GMT\n"
        )
        .is_none());
        assert!(parse_openssl_enddate(
            "notAfter=Not  1 00:00:00 2030 GMT\nnotAfter=Jan  1 00:00:00 2030 GMT\n"
        )
        .is_none());
        assert_eq!(
            parse_openssl_enddate(
                "notAfter=Jan  1 00:00:00 2030 GMT\nnotAfter=Jan  1 00:00:00 2030 GMT\n"
            ),
            Some(at(2030, 1, 1, 0, 0, 0))
        );
    }

    #[test]
    fn openssl_error_lines_and_empty_input_are_rejected() {
        let errors = "\
Could not read certificate from /etc/hostname
Unable to load certificate
";
        assert_eq!(parse_openssl_enddate(errors), None);
        assert_eq!(parse_openssl_enddate(""), None);
    }

    #[test]
    fn saved_dates_fixtures_span_ninety_days_minus_one_second() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        for name in [
            "dates-disk-renewed.txt",
            "dates-live-old.txt",
            "dates-current.txt",
        ] {
            let text = std::fs::read_to_string(root.join("tests/fixtures/certs").join(name))
                .unwrap_or_else(|err| panic!("{name}: {err}"));
            let not_before_line = text
                .lines()
                .find(|line| line.starts_with("notBefore="))
                .unwrap_or_else(|| panic!("{name} has no notBefore"));
            let not_before =
                parse_openssl_enddate(&not_before_line.replacen("notBefore=", "notAfter=", 1))
                    .unwrap_or_else(|| panic!("{name} notBefore"));
            let not_after =
                parse_openssl_enddate(&text).unwrap_or_else(|| panic!("{name} notAfter"));
            assert_eq!(
                not_after.unix_seconds() - not_before.unix_seconds(),
                90 * 86_400 - 1,
                "{name}"
            );
        }
        let errors = std::fs::read_to_string(root.join("tests/fixtures/certs/not-a-cert.txt"))
            .expect("not-a-cert");
        assert_eq!(parse_openssl_enddate(&errors), None);
    }
}
