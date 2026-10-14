use std::path::Path;
use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    run_at(args, None)
}

fn run_at(args: &[&str], now: Option<&str>) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_acme-renew-doctor"));
    command
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(args)
        .env_remove("ACME_RENEW_DOCTOR_NOW");
    if let Some(now) = now {
        command.env("ACME_RENEW_DOCTOR_NOW", now);
    }
    command.output().expect("run acme-renew-doctor")
}

fn snapshot_path(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/snapshots")
        .join(name)
}

fn explain(expected: &str, actual: &str) -> String {
    let mut out = String::from("snapshot mismatch\n");
    let expected_lines: Vec<&str> = expected.lines().collect();
    let actual_lines: Vec<&str> = actual.lines().collect();
    let count = expected_lines.len().max(actual_lines.len());
    for index in 0..count {
        let left = expected_lines.get(index).copied();
        let right = actual_lines.get(index).copied();
        if left != right {
            out.push_str(&format!(
                "line {}:\n  expected: {}\n  actual:   {}\n",
                index + 1,
                left.map(|line| format!("{line:?}"))
                    .unwrap_or_else(|| "<missing>".to_string()),
                right
                    .map(|line| format!("{line:?}"))
                    .unwrap_or_else(|| "<missing>".to_string()),
            ));
        }
    }
    if expected.ends_with('\n') != actual.ends_with('\n') {
        out.push_str(&format!(
            "trailing newline: expected {} actual {}\n",
            expected.ends_with('\n'),
            actual.ends_with('\n')
        ));
    }
    out.push_str("--- expected ---\n");
    out.push_str(expected);
    out.push_str("--- actual ---\n");
    out.push_str(actual);
    out
}

fn assert_snapshot(args: &[&str], name: &str, exit: i32) {
    assert_snapshot_at(args, name, exit, None);
}

fn assert_snapshot_at(args: &[&str], name: &str, exit: i32, now: Option<&str>) {
    let output = run_at(args, now);
    let actual = String::from_utf8(output.stdout).expect("stdout is utf-8");
    assert_eq!(
        output.status.code(),
        Some(exit),
        "stderr:\n{}\nstdout:\n{actual}",
        String::from_utf8_lossy(&output.stderr)
    );
    let path = snapshot_path(name);
    let expected = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    if actual != expected {
        panic!("{}", explain(&expected, &actual));
    }
}

#[test]
fn human_timeout_snapshot() {
    assert_snapshot(
        &[
            "example.com",
            "--from-log",
            "tests/fixtures/certbot/http01-timeout-repeated.log",
            "--from-timer-status",
            "tests/fixtures/timer/certbot-timer-disabled.txt",
        ],
        "human-timeout.txt",
        1,
    );
}

#[test]
fn json_timeout_snapshot() {
    assert_snapshot(
        &[
            "example.com",
            "--json",
            "--from-log",
            "tests/fixtures/certbot/http01-timeout-repeated.log",
            "--from-timer-status",
            "tests/fixtures/timer/certbot-timer-disabled.txt",
        ],
        "json-timeout.json",
        1,
    );
}

#[test]
fn json_timeout_snapshot_declares_schema_version() {
    let output = run(&[
        "example.com",
        "--json",
        "--from-log",
        "tests/fixtures/certbot/http01-timeout-repeated.log",
        "--from-timer-status",
        "tests/fixtures/timer/certbot-timer-disabled.txt",
    ]);
    let text = String::from_utf8(output.stdout).expect("stdout is utf-8");
    assert!(text.contains("\"schema_version\": 1"), "{text}");
    let saved = std::fs::read_to_string(snapshot_path("json-timeout.json")).expect("snapshot");
    assert!(saved.contains("\"schema_version\": 1"));
}

#[test]
fn human_insufficient_snapshot() {
    assert_snapshot(&["example.com"], "human-insufficient.txt", 2);
}

#[test]
fn json_insufficient_snapshot() {
    assert_snapshot(&["example.com", "--json"], "json-insufficient.json", 2);
}

#[test]
fn human_clean_log_snapshot() {
    assert_snapshot(
        &[
            "--from-log",
            "tests/fixtures/certbot/http01-connection-refused.log",
            "--from-timer-status",
            "tests/fixtures/timer/certbot-timer-enabled.txt",
        ],
        "human-clean-log.txt",
        1,
    );
}

#[test]
fn human_refused_snapshot() {
    assert_snapshot_at(
        &[
            "example.com",
            "--from-log",
            "tests/fixtures/certbot/http01-connection-refused.log",
        ],
        "human-refused.txt",
        1,
        Some("1791273600"),
    );
}

#[test]
fn human_rate_limit_snapshot() {
    assert_snapshot_at(
        &[
            "example.com",
            "--from-log",
            "tests/fixtures/certbot/rate-limit-exact-set.log",
        ],
        "human-rate-limit.txt",
        1,
        Some("1791273600"),
    );
}

#[test]
fn json_rate_limit_snapshot() {
    assert_snapshot_at(
        &[
            "example.com",
            "--json",
            "--from-log",
            "tests/fixtures/certbot/rate-limit-exact-set.log",
        ],
        "json-rate-limit.json",
        1,
        Some("1791273600"),
    );
}

#[test]
fn human_dns01_txt_snapshot() {
    assert_snapshot_at(
        &[
            "example.com",
            "--from-log",
            "tests/fixtures/certbot/dns01-no-txt-record.log",
        ],
        "human-dns01-txt.txt",
        1,
        Some("1791273600"),
    );
}

#[test]
fn human_dns01_secondary_snapshot() {
    assert_snapshot_at(
        &[
            "example.com",
            "--from-log",
            "tests/fixtures/certbot/dns01-no-txt-secondary.log",
        ],
        "human-dns01-secondary.txt",
        1,
        Some("1791273600"),
    );
}

#[test]
fn json_dns01_txt_snapshot() {
    assert_snapshot_at(
        &[
            "example.com",
            "--json",
            "--from-log",
            "tests/fixtures/certbot/dns01-no-txt-record.log",
        ],
        "json-dns01-txt.json",
        1,
        Some("1791273600"),
    );
}

#[test]
fn human_no_reload_snapshot() {
    assert_snapshot_at(
        &[
            "example.com",
            "--from-cert-disk",
            "tests/fixtures/certs/dates-disk-renewed.txt",
            "--from-cert-live",
            "tests/fixtures/certs/dates-live-old.txt",
        ],
        "human-no-reload.txt",
        1,
        Some("1791273600"),
    );
}

#[test]
fn json_no_reload_snapshot() {
    assert_snapshot_at(
        &[
            "example.com",
            "--json",
            "--from-cert-disk",
            "tests/fixtures/certs/dates-disk-renewed.txt",
            "--from-cert-live",
            "tests/fixtures/certs/dates-live-old.txt",
        ],
        "json-no-reload.json",
        1,
        Some("1791273600"),
    );
}

#[test]
fn human_ok_not_due_snapshot() {
    assert_snapshot_at(
        &[
            "example.com",
            "--from-timer-status",
            "tests/fixtures/timer/certbot-timer-enabled.txt",
            "--from-cert-disk",
            "tests/fixtures/certs/dates-current.txt",
            "--from-cert-live",
            "tests/fixtures/certs/dates-current.txt",
        ],
        "human-ok-not-due.txt",
        0,
        Some("1791273600"),
    );
}

#[test]
fn json_ok_not_due_snapshot() {
    assert_snapshot_at(
        &[
            "example.com",
            "--json",
            "--from-timer-status",
            "tests/fixtures/timer/certbot-timer-enabled.txt",
            "--from-cert-disk",
            "tests/fixtures/certs/dates-current.txt",
            "--from-cert-live",
            "tests/fixtures/certs/dates-current.txt",
        ],
        "json-ok-not-due.json",
        0,
        Some("1791273600"),
    );
}

#[test]
fn human_cert_not_recognised_snapshot() {
    assert_snapshot_at(
        &[
            "example.com",
            "--from-cert-disk",
            "tests/fixtures/certs/not-a-cert.txt",
            "--from-cert-live",
            "tests/fixtures/certs/dates-current.txt",
        ],
        "human-cert-not-recognised.txt",
        2,
        Some("1791273600"),
    );
}

#[test]
fn json_cert_not_recognised_snapshot() {
    assert_snapshot_at(
        &[
            "example.com",
            "--json",
            "--from-cert-disk",
            "tests/fixtures/certs/not-a-cert.txt",
            "--from-cert-live",
            "tests/fixtures/certs/dates-current.txt",
        ],
        "json-cert-not-recognised.json",
        2,
        Some("1791273600"),
    );
}

#[test]
fn human_timer_not_firing_snapshot() {
    assert_snapshot_at(
        &[
            "example.com",
            "--from-timer-status",
            "tests/fixtures/timer/certbot-timer-failed.txt",
        ],
        "human-timer-not-firing.txt",
        1,
        Some("1791273600"),
    );
}

#[test]
fn json_timer_not_firing_snapshot() {
    assert_snapshot_at(
        &[
            "example.com",
            "--json",
            "--from-timer-status",
            "tests/fixtures/timer/certbot-timer-failed.txt",
        ],
        "json-timer-not-firing.json",
        1,
        Some("1791273600"),
    );
}

#[test]
fn human_timer_inactive_snapshot() {
    assert_snapshot_at(
        &[
            "example.com",
            "--from-timer-status",
            "tests/fixtures/timer/certbot-timer-enabled-inactive.txt",
        ],
        "human-timer-inactive.txt",
        1,
        Some("1791273600"),
    );
}

#[test]
fn human_service_only_failed_snapshot() {
    assert_snapshot_at(
        &[
            "example.com",
            "--from-timer-status",
            "tests/fixtures/timer/certbot-service-only-failed.txt",
        ],
        "human-service-only-failed.txt",
        2,
        Some("1791273600"),
    );
}

#[test]
fn human_service_failed_snapshot() {
    assert_snapshot_at(
        &[
            "example.com",
            "--from-timer-status",
            "tests/fixtures/timer/certbot-timer-ok-service-failed.txt",
        ],
        "human-service-failed.txt",
        2,
        Some("1791273600"),
    );
}

#[test]
fn human_client_unknown_snapshot() {
    assert_snapshot_at(
        &[
            "example.com",
            "--from-log",
            "tests/fixtures/acme-sh/verify-error-dns01.log",
        ],
        "human-client-unknown.txt",
        3,
        Some("1791273600"),
    );
}

#[test]
fn json_client_unknown_snapshot() {
    assert_snapshot_at(
        &[
            "example.com",
            "--json",
            "--from-log",
            "tests/fixtures/acme-sh/verify-error-dns01.log",
        ],
        "json-client-unknown.json",
        3,
        Some("1791273600"),
    );
}

#[test]
fn human_client_unknown_timer_snapshot() {
    assert_snapshot_at(
        &[
            "example.com",
            "--from-log",
            "tests/fixtures/acme-sh/verify-error-dns01.log",
            "--from-timer-status",
            "tests/fixtures/timer/certbot-timer-disabled.txt",
        ],
        "human-client-unknown-timer.txt",
        3,
        Some("1791273600"),
    );
}

#[test]
fn json_unsafe_domain_snapshot() {
    assert_snapshot(
        &[
            "example.com;rm -rf ~",
            "--from-log",
            "tests/fixtures/certbot/http01-timeout.log",
            "--json",
        ],
        "json-unsafe-domain.json",
        1,
    );
}

#[test]
fn human_unsafe_domain_snapshot() {
    assert_snapshot(
        &[
            "example.com;rm -rf ~",
            "--from-log",
            "tests/fixtures/certbot/http01-timeout.log",
        ],
        "human-unsafe-domain.txt",
        1,
    );
}
