#![no_main]

use libfuzzer_sys::fuzz_target;

use acme_renew_doctor::certtime;

const MIN_YEAR: i32 = 1970;
const MAX_YEAR: i32 = 9999;

// `certtime::parse_openssl_enddate` on arbitrary bytes. A date it returns
// must have fields inside the ranges the parser itself enforces: year
// 1970..=9999, month 1..=12, a day that fits that month, and a valid
// 24-hour clock time.
fuzz_target!(|data: &[u8]| {
    if data.len() > 65_536 {
        return;
    }
    let text = String::from_utf8_lossy(data);
    if let Some(time) = certtime::parse_openssl_enddate(&text) {
        assert!((MIN_YEAR..=MAX_YEAR).contains(&time.year), "{time:?}");
        assert!((1..=12).contains(&time.month), "{time:?}");
        let max_day = match time.month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if is_leap(time.year) => 29,
            2 => 28,
            _ => unreachable!(),
        };
        assert!((1..=max_day).contains(&time.day), "{time:?}");
        assert!((0..=23).contains(&time.hour), "{time:?}");
        assert!((0..=59).contains(&time.minute), "{time:?}");
        assert!((0..=59).contains(&time.second), "{time:?}");
        // Display must round-trip: parsing what we print gives the same date.
        let printed = time.to_string();
        assert_eq!(certtime::parse_openssl_enddate(&printed), Some(time));
    }
});

fn is_leap(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}
