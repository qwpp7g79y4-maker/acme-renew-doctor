//! CLI-level regression tests for the label (<=63 bytes) and name (<=253
//! bytes) length rules in `safe::safe_domain`, and for the shape-vs-shell
//! split of the domain note in `render::report_notes`.
//!
//! A `*` is rejected by its own early check in `safe_domain`, next to the
//! length and dot checks, but it is still treated as a shell-unsafe
//! character rather than an invalid-shape one: an unquoted `*` glob-expands
//! in a shell, which is exactly what the unsafe-characters note warns
//! about. `*.example.com` is otherwise a plausible wildcard-looking
//! hostname, so it gets the unsafe-characters note, not the
//! invalid-hostname one.

use std::process::Command;

const LOG: &str = "tests/fixtures/certbot/http01-timeout.log";
const INVALID_NOTE: &str = "note: the domain is not a valid hostname";
const UNSAFE_NOTE: &str = "note: the domain contains characters that are unsafe in a shell command";

fn run_json(domain: &str) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_acme-renew-doctor"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["--json", "--from-log", LOG, "--"])
        .arg(domain)
        .output()
        .expect("run acme-renew-doctor");
    assert!(
        output.status.code() == Some(1),
        "domain {domain:?} exit {:?}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("stdout is utf-8")
}

fn assert_accepted(domain: &str) {
    let json = run_json(domain);
    assert!(
        json.contains(&format!("\"domain\": \"{domain}\"")),
        "expected {domain:?} to be accepted as-is\n{json}"
    );
    assert!(!json.contains(INVALID_NOTE), "{json}");
    assert!(!json.contains(UNSAFE_NOTE), "{json}");
}

fn assert_rejected(domain: &str, expect_invalid_shape: bool) {
    let json = run_json(domain);
    assert!(
        json.contains("\"domain\": \"YOUR_DOMAIN\""),
        "expected {domain:?} to be replaced with YOUR_DOMAIN\n{json}"
    );
    assert!(
        !json.contains(domain),
        "raw domain {domain:?} leaked into the report\n{json}"
    );
    if expect_invalid_shape {
        assert!(json.contains(INVALID_NOTE), "{json}");
        assert!(!json.contains(UNSAFE_NOTE), "{json}");
    } else {
        assert!(json.contains(UNSAFE_NOTE), "{json}");
        assert!(!json.contains(INVALID_NOTE), "{json}");
    }
}

#[test]
fn label_exactly_63_is_accepted_64_is_rejected() {
    let ok = format!("{}.com", "a".repeat(63));
    assert_accepted(&ok);
    let bad = format!("{}.com", "a".repeat(64));
    assert_rejected(&bad, true);
}

#[test]
fn multiple_63_byte_labels_are_accepted() {
    let l63 = "a".repeat(63);
    let domain = format!("{l63}.{l63}.{l63}.com");
    assert_accepted(&domain);
}

#[test]
fn name_exactly_253_is_accepted_254_is_rejected() {
    let l63 = "a".repeat(63);
    let max = format!("{l63}.{l63}.{l63}.{}", "b".repeat(61));
    assert_eq!(max.len(), 253);
    assert_accepted(&max);
    let over = format!("{l63}.{l63}.{l63}.{}", "b".repeat(62));
    assert_eq!(over.len(), 254);
    assert_rejected(&over, true);
}

#[test]
fn trailing_dot_is_rejected() {
    assert_rejected("example.com.", true);
}

#[test]
fn punycode_label_is_accepted() {
    assert_accepted("xn--bcher-kva.example");
}

#[test]
fn uppercase_domain_is_accepted_and_case_preserved() {
    assert_accepted("WWW.Example.COM");
}

#[test]
fn whitespace_in_domain_is_rejected_as_unsafe() {
    for domain in [
        "exa\nmple.com",
        "exa\rmple.com",
        "exa\tmple.com",
        "exa mple.com",
    ] {
        assert_rejected(domain, false);
    }
}

#[test]
fn unicode_labels_are_rejected_as_unsafe() {
    for domain in ["bücher.example", "例え.jp"] {
        assert_rejected(domain, false);
    }
}

#[test]
fn a_star_in_the_domain_is_rejected_as_unsafe_not_as_invalid_shape() {
    for domain in ["*.example.com", "a*.example.com", "*.a.com"] {
        assert_rejected(domain, false);
    }
}

#[test]
fn empty_domain_is_rejected_as_invalid_shape_not_unsafe() {
    // An empty domain has no character at all, so it cannot contain one
    // that is unsafe in a shell command; its problem is the shape (zero
    // labels, where at least two are required). `assert_rejected` cannot be
    // reused here: it checks the raw domain did not leak into the report,
    // and every string "contains" the empty string.
    let json = run_json("");
    assert!(
        json.contains("\"domain\": \"YOUR_DOMAIN\""),
        "expected an empty domain to be replaced with YOUR_DOMAIN\n{json}"
    );
    assert!(json.contains(INVALID_NOTE), "{json}");
    assert!(!json.contains(UNSAFE_NOTE), "{json}");
}
