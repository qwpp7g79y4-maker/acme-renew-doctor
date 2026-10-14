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

fn assert_report_is_safe(args: &[&str]) {
    assert_report_is_safe_at(args, None);
}

fn assert_report_is_safe_at(args: &[&str], now: Option<&str>) {
    for json in [false, true] {
        let mut full = Vec::new();
        if json {
            full.push("--json");
        }
        full.extend_from_slice(args);
        let output = run_at(&full, now);
        let stdout = String::from_utf8(output.stdout).expect("stdout is utf-8");
        let violations = acme_renew_doctor::safe::output_violations(&stdout);
        assert!(
            violations.is_empty(),
            "args {full:?} exit {:?}\nviolations: {violations:?}\nstderr:\n{}\nstdout:\n{stdout}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
        if json {
            assert!(
                stdout.contains("\"next_checks\": [") && !stdout.contains("\"next_checks\": []"),
                "expected a non-empty next_checks list\nargs {full:?}\n{stdout}"
            );
            assert!(
                stdout.contains("\"safety\": \"read-only\""),
                "args {full:?}\n{stdout}"
            );
        } else {
            assert!(
                stdout.contains("Next (SAFE copy-paste checks, read-only; Doctor runs nothing and will NOT renew or reload for you):"),
                "args {full:?}\n{stdout}"
            );
            assert!(
                stdout.lines().any(|line| line.starts_with("  → ")),
                "expected at least one copy-paste check\nargs {full:?}\n{stdout}"
            );
        }
    }
}

#[test]
fn snapshot_scenarios_print_only_safe_checks() {
    assert_report_is_safe(&[
        "example.com",
        "--from-log",
        "tests/fixtures/certbot/http01-timeout-repeated.log",
        "--from-timer-status",
        "tests/fixtures/timer/certbot-timer-disabled.txt",
    ]);
    assert_report_is_safe(&["example.com"]);
    assert_report_is_safe(&[
        "--from-log",
        "tests/fixtures/certbot/http01-connection-refused.log",
        "--from-timer-status",
        "tests/fixtures/timer/certbot-timer-enabled.txt",
    ]);
    let now = Some("1791273600");
    assert_report_is_safe_at(
        &[
            "example.com",
            "--from-log",
            "tests/fixtures/certbot/http01-connection-refused.log",
        ],
        now,
    );
    assert_report_is_safe_at(
        &[
            "example.com",
            "--from-log",
            "tests/fixtures/certbot/rate-limit-exact-set.log",
        ],
        now,
    );
    assert_report_is_safe_at(
        &[
            "example.com",
            "--from-log",
            "tests/fixtures/certbot/dns01-no-txt-record.log",
        ],
        now,
    );
    assert_report_is_safe_at(
        &[
            "example.com",
            "--from-log",
            "tests/fixtures/certbot/dns01-no-txt-secondary.log",
        ],
        now,
    );
    assert_report_is_safe_at(
        &[
            "example.com",
            "--from-log",
            "tests/fixtures/certbot/dns01-incorrect-txt-record.log",
        ],
        now,
    );
    assert_report_is_safe_at(
        &[
            "example.com",
            "--from-timer-status",
            "tests/fixtures/timer/certbot-timer-failed.txt",
        ],
        now,
    );
    assert_report_is_safe_at(
        &[
            "example.com",
            "--from-timer-status",
            "tests/fixtures/timer/certbot-timer-enabled-inactive.txt",
        ],
        now,
    );
    assert_report_is_safe_at(
        &[
            "example.com",
            "--from-timer-status",
            "tests/fixtures/timer/certbot-timer-ok-service-failed.txt",
        ],
        now,
    );
    assert_report_is_safe_at(
        &[
            "example.com",
            "--from-timer-status",
            "tests/fixtures/timer/certbot-service-only-failed.txt",
        ],
        now,
    );
    assert_report_is_safe_at(
        &[
            "example.com",
            "--from-log",
            "tests/fixtures/acme-sh/verify-error-dns01.log",
        ],
        now,
    );
    assert_report_is_safe_at(
        &[
            "example.com",
            "--from-log",
            "tests/fixtures/acme-sh/verify-error-dns01.log",
            "--from-timer-status",
            "tests/fixtures/timer/certbot-timer-disabled.txt",
        ],
        now,
    );
}

#[test]
fn each_certbot_fixture_prints_only_safe_checks() {
    for path in [
        "tests/fixtures/certbot/http01-timeout.log",
        "tests/fixtures/certbot/http01-timeout-repeated.log",
        "tests/fixtures/certbot/http01-connection-refused.log",
        "tests/fixtures/certbot/rate-limit-exact-set.log",
        "tests/fixtures/certbot/dns01-no-txt-record.log",
        "tests/fixtures/certbot/dns01-no-txt-secondary.log",
        "tests/fixtures/certbot/dns01-incorrect-txt-record.log",
    ] {
        assert_report_is_safe(&["--from-log", path]);
    }
}

#[test]
fn each_timer_fixture_prints_only_safe_checks() {
    for path in [
        "tests/fixtures/timer/certbot-timer-disabled.txt",
        "tests/fixtures/timer/certbot-timer-enabled.txt",
        "tests/fixtures/timer/certbot-timer-enabled-inactive.txt",
        "tests/fixtures/timer/certbot-timer-failed.txt",
        "tests/fixtures/timer/certbot-timer-ok-service-failed.txt",
        "tests/fixtures/timer/certbot-service-only-failed.txt",
    ] {
        assert_report_is_safe(&["--from-timer-status", path]);
    }
}

#[test]
fn acme_sh_client_prints_only_safe_checks() {
    assert_report_is_safe(&["--client", "acme.sh"]);
}

#[test]
fn missing_path_prints_only_safe_checks() {
    assert_report_is_safe(&["--from-log", "tests/fixtures/certbot/does-not-exist.log"]);
}

#[test]
fn cert_date_scenarios_print_only_safe_checks() {
    let now = Some("1791273600");
    assert_report_is_safe_at(
        &[
            "example.com",
            "--from-cert-disk",
            "tests/fixtures/certs/dates-disk-renewed.txt",
            "--from-cert-live",
            "tests/fixtures/certs/dates-live-old.txt",
        ],
        now,
    );
    assert_report_is_safe_at(
        &[
            "example.com",
            "--from-timer-status",
            "tests/fixtures/timer/certbot-timer-enabled.txt",
            "--from-cert-disk",
            "tests/fixtures/certs/dates-current.txt",
            "--from-cert-live",
            "tests/fixtures/certs/dates-current.txt",
        ],
        now,
    );
    assert_report_is_safe_at(
        &[
            "example.com",
            "--from-cert-disk",
            "tests/fixtures/certs/not-a-cert.txt",
            "--from-cert-live",
            "tests/fixtures/certs/dates-current.txt",
        ],
        now,
    );
}

#[test]
fn unsafe_domain_is_replaced_before_it_reaches_a_command() {
    let args = [
        "example.com;rm -rf ~",
        "--from-log",
        "tests/fixtures/certbot/http01-timeout.log",
    ];
    assert_report_is_safe(&args);

    let human = run(&args);
    let text = String::from_utf8(human.stdout).expect("stdout is utf-8");
    assert!(text.contains("YOUR_DOMAIN"), "{text}");
    assert!(
        text.contains(
            "note: the domain contains characters that are unsafe in a shell command; replace YOUR_DOMAIN yourself."
        ),
        "{text}"
    );
    assert!(
        text.lines()
            .any(|line| line.starts_with("  → ") && line.contains("YOUR_DOMAIN")),
        "{text}"
    );
    for line in text.lines() {
        if let Some(command) = line.strip_prefix("  → ") {
            assert!(!command.contains("rm -rf"), "{command}");
            assert!(!command.contains("example.com;"), "{command}");
        }
    }

    let mut json_args = vec!["--json"];
    json_args.extend_from_slice(&args);
    let json = run(&json_args);
    let json_text = String::from_utf8(json.stdout).expect("stdout is utf-8");
    assert!(json_text.contains("YOUR_DOMAIN"), "{json_text}");
    assert!(!json_text.contains("rm -rf"), "{json_text}");
    assert!(!json_text.contains("example.com;"), "{json_text}");
    assert!(json_text.contains("\"notes\": ["), "{json_text}");
    assert!(
        json_text.contains(
            "note: the domain contains characters that are unsafe in a shell command; replace YOUR_DOMAIN yourself."
        ),
        "{json_text}"
    );
    let violations = acme_renew_doctor::safe::output_violations(&json_text);
    assert!(violations.is_empty(), "{violations:?}\n{json_text}");
}
