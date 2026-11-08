//! W-55: remaining validity in days, and a caller-set warning threshold.
//!
//! Every certificate is synthetic text in a temporary directory: the saved
//! output of `openssl x509 -noout -dates`. There is no PEM, no key and no
//! network. The clock is `ACME_RENEW_DOCTOR_NOW`, set here. The report does
//! not store that clock. A wrong host and a broken chain stay unrecognised.
//! Exit codes stay 0, 1, 2 and 3. A missing `--output` directory stays exit 3.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// 2026-10-06 00:00:00 UTC. Twenty calendar days before 2026-10-26.
const NOW: &str = "1791244800";

/// Ninety calendar days, 2026-07-28 through 2026-10-26. Twenty days remain on `NOW`.
const TWENTY_LEFT: &str = "\
notBefore=Jul 28 00:00:00 2026 GMT
notAfter=Oct 26 12:00:00 2026 GMT
";

const WRONG_HOST: &str = "\
depth=0 CN = other.example.invalid
verify error:num=62:Hostname mismatch
verify return:1
notBefore=Sep 28 03:12:45 2026 GMT
";

const BROKEN_CHAIN: &str = "\
depth=0 CN = example.com
verify error:num=20:unable to get local issuer certificate
verify error:num=21:unable to verify the first certificate
verify return:1
";

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "acme-renew-doctor-w55-{label}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create temp dir");
        TempDir(path)
    }

    fn write(&self, name: &str, text: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, text).expect("write fake certificate");
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn doctor(disk: &Path, live: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_acme-renew-doctor"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["example.com", "--from-timer-status"])
        .arg("tests/fixtures/timer/certbot-timer-enabled.txt")
        .arg("--from-cert-disk")
        .arg(disk)
        .arg("--from-cert-live")
        .arg(live)
        .args(extra)
        .env("ACME_RENEW_DOCTOR_NOW", NOW)
        .output()
        .expect("run acme-renew-doctor")
}

fn stdout(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).expect("utf-8 stdout")
}

fn assert_no_machine_clock(text: &str) {
    assert!(
        !text.contains(NOW),
        "the test clock must not be copied into the report: {text}"
    );
    assert!(!text.contains("\"now\""), "{text}");
    assert!(!text.contains("Nov"), "{text}");
}

#[test]
fn twenty_days_left_uses_the_computed_threshold_without_the_flag() {
    let dir = TempDir::new("default");
    let cert = dir.write("dates.txt", TWENTY_LEFT);
    let out = doctor(&cert, &cert, &[]);
    let text = stdout(&out);
    assert!(
        text.contains("20 day(s) remain, at or under the 30-day renewal threshold"),
        "{text}"
    );
    assert!(text.contains("INSUFFICIENT_EVIDENCE"), "{text}");
    assert!(!text.contains("OK_NOT_DUE"), "{text}");
    assert_eq!(out.status.code(), Some(2), "{text}");
    assert!(out.stderr.is_empty(), "{text}");
    assert_no_machine_clock(&text);
}

#[test]
fn warn_days_below_the_remainder_is_ok_and_states_the_days() {
    let dir = TempDir::new("above");
    let cert = dir.write("dates.txt", TWENTY_LEFT);
    let first = doctor(&cert, &cert, &["--warn-days", "10"]);
    let second = doctor(&cert, &cert, &["--warn-days", "10"]);
    let text = stdout(&first);
    assert_eq!(
        text,
        stdout(&second),
        "the report must not depend on the machine clock"
    );
    assert!(text.contains("OK_NOT_DUE"), "{text}");
    assert!(
        text.contains("20 day(s) remain, above the 10-day renewal threshold"),
        "{text}"
    );
    assert_eq!(first.status.code(), Some(0), "{text}");
    assert!(first.stderr.is_empty(), "{text}");
    assert_no_machine_clock(&text);
}

#[test]
fn warn_days_equal_to_the_remainder_stays_the_existing_insufficient_code() {
    let dir = TempDir::new("equal");
    let cert = dir.write("dates.txt", TWENTY_LEFT);
    let out = doctor(&cert, &cert, &["--warn-days", "20"]);
    let text = stdout(&out);
    assert!(
        text.contains("20 day(s) remain, at or under the 20-day renewal threshold"),
        "{text}"
    );
    assert!(text.contains("INSUFFICIENT_EVIDENCE"), "{text}");
    assert!(!text.contains("OK_NOT_DUE"), "{text}");
    assert_eq!(out.status.code(), Some(2), "{text}");
    assert_no_machine_clock(&text);
}

#[test]
fn warn_days_json_keeps_the_schema_and_omits_the_clock() {
    let dir = TempDir::new("json");
    let cert = dir.write("dates.txt", TWENTY_LEFT);
    let first = stdout(&doctor(&cert, &cert, &["--json", "--warn-days", "10"]));
    let second = stdout(&doctor(&cert, &cert, &["--json", "--warn-days", "10"]));
    assert_eq!(first, second);
    assert!(first.contains("\"schema_version\": 1"), "{first}");
    assert!(
        first.contains("20 day(s) remain, above the 10-day renewal threshold"),
        "{first}"
    );
    assert!(first.contains("\"from_cert_disk\""), "{first}");
    assert!(first.contains("\"from_cert_live\""), "{first}");
    assert!(!first.contains("\"now\""), "{first}");
    assert!(!first.contains("\"warn_days\""), "{first}");
    assert_no_machine_clock(&first);
}

#[test]
fn warn_days_does_not_invent_a_host_or_chain_verdict() {
    let dir = TempDir::new("unreadable");
    let disk = dir.write("disk.txt", TWENTY_LEFT);
    let wrong = dir.write("wrong.txt", WRONG_HOST);
    let broken = dir.write("broken.txt", BROKEN_CHAIN);
    for live in [&wrong, &broken] {
        let out = doctor(&disk, live, &["--warn-days", "10"]);
        let text = stdout(&out);
        assert!(text.contains("not recognised"), "{text}");
        assert!(!text.to_lowercase().contains("hostname"), "{text}");
        assert!(!text.to_lowercase().contains("issuer"), "{text}");
        assert!(!text.contains("day(s) remain"), "{text}");
        assert_eq!(out.status.code(), Some(2), "{text}");
        assert_no_machine_clock(&text);
    }
}

#[test]
fn warn_days_zero_is_a_threshold_not_a_new_exit_code() {
    let dir = TempDir::new("zero");
    let cert = dir.write("dates.txt", TWENTY_LEFT);
    let out = doctor(&cert, &cert, &["--warn-days", "0"]);
    let text = stdout(&out);
    assert!(
        text.contains("20 day(s) remain, above the 0-day renewal threshold"),
        "{text}"
    );
    assert_eq!(out.status.code(), Some(0), "{text}");
}

#[test]
fn negative_warn_days_stays_exit_three() {
    let out = Command::new(env!("CARGO_BIN_EXE_acme-renew-doctor"))
        .args(["--warn-days", "-1"])
        .env("ACME_RENEW_DOCTOR_NOW", NOW)
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(3));
    assert!(out.stdout.is_empty());
    assert!(!out.stderr.is_empty());
}

#[test]
fn missing_output_directory_stays_exit_three_with_warn_days() {
    let dir = TempDir::new("missing-out");
    let cert = dir.write("dates.txt", TWENTY_LEFT);
    let missing = dir.0.join("no-such-dir");
    let report = missing.join("report.txt");
    let out = doctor(
        &cert,
        &cert,
        &[
            "--warn-days",
            "10",
            "--output",
            report.to_str().expect("utf-8 path"),
        ],
    );
    let err = String::from_utf8(out.stderr).expect("utf-8 stderr");
    assert_eq!(out.status.code(), Some(3), "{err}");
    assert!(out.stdout.is_empty());
    assert!(err.contains("could not write report to "), "{err}");
    assert!(err.contains("does not create it"), "{err}");
    assert!(!report.exists());
    assert!(!missing.exists());
}

#[test]
fn example_cannot_be_combined_with_warn_days() {
    let dir = TempDir::new("example");
    let out = Command::new(env!("CARGO_BIN_EXE_acme-renew-doctor"))
        .current_dir(&dir.0)
        .args(["--example", "--warn-days", "10"])
        .env("ACME_RENEW_DOCTOR_NOW", NOW)
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(3));
    assert!(out.stdout.is_empty());
    assert!(!dir.0.join("example-log.txt").exists());
}
