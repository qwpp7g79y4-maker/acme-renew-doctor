#![no_main]

use libfuzzer_sys::fuzz_target;

use acme_renew_doctor::safe;

// `safe::safe_domain` on arbitrary bytes. When it accepts a domain, that
// domain must have the exact shape the SAFE checks rely on: at least two
// labels, each 1 to 63 ASCII alphanumeric or '-' bytes, no leading or
// trailing '-', and at most 253 bytes in total.
//
// Also exercises `safe::check_command` and `safe::output_violations`
// directly on arbitrary text for a no-panic check. The two are
// independent defenses (an allowlist gate on the exact command that would
// run, versus a broad substring scan over whatever text ends up in a
// report) and are not required to agree: a domain label can legitimately
// contain a FORBIDDEN_TEXT substring (e.g. a label containing "apachectl")
// without that making the `dig`/`curl` command built from it dangerous.
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if text.len() > 2048 {
        return;
    }

    if let Some(domain) = safe::safe_domain(Some(text)) {
        assert_eq!(domain, text);
        assert!(!domain.is_empty() && domain.len() <= 253);
        assert!(!domain.contains('*'));
        let mut labels = 0;
        for label in domain.split('.') {
            labels += 1;
            assert!(!label.is_empty(), "empty label in {domain:?}");
            assert!(label.len() <= 63, "label over 63 bytes in {domain:?}");
            assert!(
                !label.starts_with('-') && !label.ends_with('-'),
                "label starts/ends with '-' in {domain:?}"
            );
            assert!(
                label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
                "label has a byte outside ascii alnum/- in {domain:?}"
            );
        }
        assert!(labels >= 2, "fewer than two labels in {domain:?}");
    }

    let _ = safe::check_command(text);
    let _ = safe::output_violations(text);
});
