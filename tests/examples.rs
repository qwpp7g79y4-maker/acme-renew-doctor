//! Golden test: runs the commands in `examples/` and compares stdout with the
//! saved `expected-output.txt`. Each case runs from inside its own folder, so
//! the paths on the `inputs:` line are the short names in `command.txt`.

use std::path::Path;
use std::process::Command;

fn run_case(name: &str, args: &[&str], now: Option<&str>, expected_exit: i32) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join(name);
    let mut command = Command::new(env!("CARGO_BIN_EXE_acme-renew-doctor"));
    command
        .current_dir(&dir)
        .args(args)
        .env_remove("ACME_RENEW_DOCTOR_NOW");
    if let Some(now) = now {
        command.env("ACME_RENEW_DOCTOR_NOW", now);
    }
    let output = command.output().expect("run acme-renew-doctor");
    let expected =
        std::fs::read_to_string(dir.join("expected-output.txt")).expect("read expected-output.txt");
    assert_eq!(String::from_utf8_lossy(&output.stdout), expected, "{name}");
    assert!(output.stderr.is_empty(), "{name}: stderr was not empty");
    assert_eq!(output.status.code(), Some(expected_exit), "{name}");

    // command.txt must describe exactly what this test runs.
    let line = std::fs::read_to_string(dir.join("command.txt")).expect("read command.txt");
    let mut expected_line = String::new();
    if let Some(now) = now {
        expected_line.push_str(&format!("ACME_RENEW_DOCTOR_NOW={now} "));
    }
    expected_line.push_str("acme-renew-doctor ");
    expected_line.push_str(&args.join(" "));
    assert_eq!(line.trim_end(), expected_line, "{name}: command.txt");
}

#[test]
fn http01_timeout_example_matches_expected_output() {
    run_case(
        "http01-timeout",
        &[
            "example.com",
            "--from-log",
            "letsencrypt.log",
            "--from-timer-status",
            "timer-status.txt",
        ],
        None,
        1,
    );
}

#[test]
fn ok_not_due_example_matches_expected_output() {
    run_case(
        "ok-not-due",
        &[
            "example.com",
            "--from-timer-status",
            "timer-status.txt",
            "--from-cert-disk",
            "cert-disk.txt",
            "--from-cert-live",
            "cert-live.txt",
        ],
        Some("1791273600"),
        0,
    );
}
