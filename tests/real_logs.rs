//! Binary tests on anonymised logs from public sources.
//! The clock is fixed: ACME_RENEW_DOCTOR_NOW=1791273600.

use std::process::Command;

const NOW: &str = "1791273600";

fn run(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_acme-renew-doctor"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(args)
        .env_remove("ACME_RENEW_DOCTOR_NOW")
        .env("ACME_RENEW_DOCTOR_NOW", NOW)
        .output()
        .expect("run acme-renew-doctor");
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr is utf-8");
    let code = output.status.code().expect("exit code");
    (code, stdout, stderr)
}

fn assert_outcome(args: &[&str], needle: &str, exit: i32) -> String {
    let (code, stdout, stderr) = run(args);
    assert!(
        stdout.contains(needle),
        "expected {needle:?}\nexit {code}\nstderr:\n{stderr}\nstdout:\n{stdout}"
    );
    assert!(
        stdout.contains(&format!("exit {exit}:")),
        "expected exit line {exit}\nstdout:\n{stdout}"
    );
    assert_eq!(code, exit, "stderr:\n{stderr}\nstdout:\n{stdout}");
    stdout
}

/// Success criterion: human output and `--json` both pass `output_violations` (empty).
fn assert_safe_outcome(args: &[&str], needle: &str, exit: i32) -> String {
    let stdout = assert_outcome(args, needle, exit);
    let violations = acme_renew_doctor::safe::output_violations(&stdout);
    assert!(violations.is_empty(), "{violations:?}\n{stdout}");

    let mut json_args = vec!["--json"];
    json_args.extend_from_slice(args);
    let (json_code, json_stdout, json_stderr) = run(&json_args);
    assert!(
        json_stdout.contains(needle),
        "expected {needle:?} in json\nexit {json_code}\nstderr:\n{json_stderr}\nstdout:\n{json_stdout}"
    );
    assert_eq!(
        json_code, exit,
        "stderr:\n{json_stderr}\nstdout:\n{json_stdout}"
    );
    let json_violations = acme_renew_doctor::safe::output_violations(&json_stdout);
    assert!(
        json_violations.is_empty(),
        "{json_violations:?}\n{json_stdout}"
    );
    stdout
}

fn assert_no_timer_ok(stdout: &str) {
    assert!(
        !stdout.contains("LAYER1_TIMER_DISABLED")
            && !stdout.contains("LAYER1_TIMER_NOT_FIRING")
            && !stdout.contains("OK_NOT_DUE"),
        "{stdout}"
    );
}

#[test]
fn e1_http01_timeout_auto() {
    let stdout = assert_safe_outcome(
        &[
            "example.com",
            "--from-log",
            "tests/fixtures/real/e1-242890-http01-timeout.log",
        ],
        "LAYER2_HTTP01_TIMEOUT",
        1,
    );
    assert!(stdout.contains("Timeout during connect"), "{stdout}");
}

#[test]
fn e3_rate_limit_auto() {
    let stdout = assert_safe_outcome(
        &[
            "example.com",
            "--from-log",
            "tests/fixtures/real/e3-235219-rate-limit.log",
        ],
        "LAYER2_RATE_LIMIT",
        1,
    );
    assert!(
        stdout.contains("retry after 2025-03-16 02:54:35 UTC"),
        "{stdout}"
    );
}

#[test]
fn e5_dns01_log_auto() {
    assert_safe_outcome(
        &[
            "example.com",
            "--from-log",
            "tests/fixtures/real/e5-136973-dns01.log",
        ],
        "LAYER2_DNS01_TXT",
        1,
    );
}

#[test]
fn e5_terminal_certbot() {
    assert_safe_outcome(
        &[
            "example.com",
            "--client",
            "certbot",
            "--from-log",
            "tests/fixtures/real/e5-211563-terminal.txt",
        ],
        "LAYER2_DNS01_TXT",
        1,
    );
}

#[test]
fn e6_raw_masked_not_recognised() {
    let stdout = assert_safe_outcome(
        &[
            "example.com",
            "--from-timer-status",
            "tests/fixtures/real/e6-197422-status-masked.txt",
        ],
        "timer status not recognised",
        2,
    );
    assert!(stdout.contains("INSUFFICIENT_EVIDENCE"), "{stdout}");
}

#[test]
fn e6_raw_snap_status_not_recognised() {
    let stdout = assert_safe_outcome(
        &[
            "example.com",
            "--from-timer-status",
            "tests/fixtures/real/e6-197422-status-snap.txt",
        ],
        "timer status not recognised",
        2,
    );
    assert!(stdout.contains("INSUFFICIENT_EVIDENCE"), "{stdout}");
}

#[test]
fn e6_raw_inactive_not_recognised() {
    let stdout = assert_safe_outcome(
        &[
            "example.com",
            "--from-timer-status",
            "tests/fixtures/real/e6-superuser-1354732-status-inactive.txt",
        ],
        "timer status not recognised",
        2,
    );
    assert!(stdout.contains("INSUFFICIENT_EVIDENCE"), "{stdout}");
}

#[test]
fn e6_show_masked_is_disabled() {
    let stdout = assert_safe_outcome(
        &[
            "example.com",
            "--from-timer-status",
            "tests/fixtures/real/e6-show-masked.txt",
        ],
        "LAYER1_TIMER_DISABLED",
        1,
    );
    assert!(stdout.contains("LoadState=masked"), "{stdout}");
    assert!(stdout.contains("UnitFileState=masked"), "{stdout}");
    assert!(stdout.contains("ActiveState=inactive"), "{stdout}");
    assert!(!stdout.contains("LAYER1_TIMER_NOT_FIRING"), "{stdout}");
}

#[test]
fn e6_show_enabled_inactive_is_not_firing() {
    let stdout = assert_safe_outcome(
        &[
            "example.com",
            "--from-timer-status",
            "tests/fixtures/real/e6-show-enabled-inactive.txt",
        ],
        "LAYER1_TIMER_NOT_FIRING",
        1,
    );
    assert!(!stdout.contains("LAYER1_TIMER_DISABLED"), "{stdout}");
}

#[test]
fn e6_show_snap_is_not_ok() {
    let stdout = assert_safe_outcome(
        &[
            "example.com",
            "--from-timer-status",
            "tests/fixtures/real/e6-show-snap.txt",
        ],
        "snap.certbot.renew.timer is active and certbot.timer is masked: snap install, not supported yet",
        2,
    );
    assert_no_timer_ok(&stdout);
    assert!(stdout.contains("INSUFFICIENT_EVIDENCE"), "{stdout}");
}

#[test]
fn e6_show_snap_with_current_certs_is_not_ok() {
    let stdout = assert_safe_outcome(
        &[
            "example.com",
            "--from-timer-status",
            "tests/fixtures/real/e6-show-snap.txt",
            "--from-cert-disk",
            "tests/fixtures/certs/dates-current.txt",
            "--from-cert-live",
            "tests/fixtures/certs/dates-current.txt",
        ],
        "snap.certbot.renew.timer is active and certbot.timer is masked: snap install, not supported yet",
        2,
    );
    assert_no_timer_ok(&stdout);
    assert!(stdout.contains("INSUFFICIENT_EVIDENCE"), "{stdout}");
}

// Recorded outcome. The shape is not a success criterion.
#[test]
fn e2_244674_auto_is_client_unknown() {
    assert_outcome(
        &[
            "example.com",
            "--from-log",
            "tests/fixtures/real/e2-244674-secondary-timeout.txt",
        ],
        "CLIENT_UNKNOWN",
        3,
    );
}

// Recorded outcome. The shape is not a success criterion.
#[test]
fn e2_244674_certbot_is_http01_timeout() {
    let stdout = assert_outcome(
        &[
            "example.com",
            "--client",
            "certbot",
            "--from-log",
            "tests/fixtures/real/e2-244674-secondary-timeout.txt",
        ],
        "LAYER2_HTTP01_TIMEOUT",
        1,
    );
    assert!(stdout.contains("Timeout during connect"), "{stdout}");
}

// Recorded outcome. The shape is not a success criterion.
#[test]
fn e2_240423_auto_is_client_unknown() {
    assert_outcome(
        &[
            "example.com",
            "--from-log",
            "tests/fixtures/real/e2-240423-secondary-timeout.txt",
        ],
        "CLIENT_UNKNOWN",
        3,
    );
}

// Recorded outcome. The shape is not a success criterion.
#[test]
fn e2_240423_certbot_finds_no_acme_error() {
    let stdout = assert_outcome(
        &[
            "example.com",
            "--client",
            "certbot",
            "--from-log",
            "tests/fixtures/real/e2-240423-secondary-timeout.txt",
        ],
        "INSUFFICIENT_EVIDENCE",
        2,
    );
    assert!(
        stdout.contains("log read, no ACME errors found"),
        "{stdout}"
    );
}

// Recorded outcome. The shape is not a success criterion.
#[test]
fn e4_206050_auto_is_client_unknown() {
    assert_outcome(
        &[
            "example.com",
            "--from-log",
            "tests/fixtures/real/e4-206050-rate-limit-old.txt",
        ],
        "CLIENT_UNKNOWN",
        3,
    );
}

// Recorded outcome. The shape is not a success criterion.
#[test]
fn e4_206050_certbot_finds_no_acme_error() {
    let stdout = assert_outcome(
        &[
            "example.com",
            "--client",
            "certbot",
            "--from-log",
            "tests/fixtures/real/e4-206050-rate-limit-old.txt",
        ],
        "INSUFFICIENT_EVIDENCE",
        2,
    );
    assert!(
        stdout.contains("log read, no ACME errors found"),
        "{stdout}"
    );
}

// Recorded outcome. The shape is not a success criterion.
#[test]
fn e4_208147_auto_is_client_unknown() {
    assert_outcome(
        &[
            "example.com",
            "--from-log",
            "tests/fixtures/real/e4-208147-failed-authz-old.txt",
        ],
        "CLIENT_UNKNOWN",
        3,
    );
}

// Recorded outcome. The shape is not a success criterion.
#[test]
fn e4_208147_certbot_finds_no_acme_error() {
    let stdout = assert_outcome(
        &[
            "example.com",
            "--client",
            "certbot",
            "--from-log",
            "tests/fixtures/real/e4-208147-failed-authz-old.txt",
        ],
        "INSUFFICIENT_EVIDENCE",
        2,
    );
    assert!(
        stdout.contains("log read, no ACME errors found"),
        "{stdout}"
    );
}

// Recorded outcome. The shape is not a success criterion.
#[test]
fn e5_terminal_auto_is_client_unknown() {
    assert_outcome(
        &[
            "example.com",
            "--from-log",
            "tests/fixtures/real/e5-211563-terminal.txt",
        ],
        "CLIENT_UNKNOWN",
        3,
    );
}
