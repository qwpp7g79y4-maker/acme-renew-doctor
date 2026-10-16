#![no_main]

use libfuzzer_sys::fuzz_target;

use acme_renew_doctor::certbot_log;

// `certbot_log::parse_log` on arbitrary bytes, decoded the same lossy way
// `read_log` would. Every reported problem must keep `occurrences` equal to
// the sum of its `json_hits` and `summary_hits` (that invariant is kept by
// `ProblemSet::add`), and `attempts()` must never exceed `occurrences`.
fuzz_target!(|data: &[u8]| {
    if data.len() > 65_536 {
        return;
    }
    let text = String::from_utf8_lossy(data);
    let _ = certbot_log::has_certbot_lines(&text);
    let parsed = certbot_log::parse_log(&text);
    for problem in &parsed.problems {
        assert_eq!(
            problem.occurrences,
            problem.json_hits + problem.summary_hits,
            "occurrences out of sync for {:?}",
            problem.short_type()
        );
        assert!(
            problem.attempts() <= problem.occurrences,
            "attempts() exceeded occurrences for {:?}",
            problem.short_type()
        );
    }
});
