//! `--quiet` and `--verbose`. A pipe prints no hint and no context line.
//! `--verbose` adds that context. Exit codes stay 0, 1, 2 and 3.
//! A missing parent directory for `--output` stays exit 3.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn run(args: &[&str]) -> (Option<i32>, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_acme-renew-doctor"))
        .args(args)
        .env("ACME_RENEW_DOCTOR_NOW", "1791273600")
        .output()
        .expect("run acme-renew-doctor");
    (
        output.status.code(),
        String::from_utf8(output.stdout).expect("stdout is utf-8"),
        String::from_utf8(output.stderr).expect("stderr is utf-8"),
    )
}

fn run_clock(value: &str, args: &[&str]) -> (Option<i32>, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_acme-renew-doctor"))
        .args(args)
        .env("ACME_RENEW_DOCTOR_NOW", value)
        .output()
        .expect("run acme-renew-doctor");
    (
        output.status.code(),
        String::from_utf8(output.stdout).expect("stdout is utf-8"),
        String::from_utf8(output.stderr).expect("stderr is utf-8"),
    )
}

fn log() -> String {
    format!(
        "{}/tests/fixtures/certbot/http01-timeout-repeated.log",
        env!("CARGO_MANIFEST_DIR")
    )
}

fn scratch() -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "acme-renew-doctor-verbosity-{}-{}-{}",
        std::process::id(),
        nanos,
        N.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&dir).expect("create scratch dir");
    dir
}

#[test]
fn help_lists_quiet_and_verbose() {
    let (code, stdout, stderr) = run(&["--help"]);
    assert_eq!(code, Some(0), "{stderr}");
    assert!(stdout.contains("--quiet"), "{stdout}");
    assert!(stdout.contains("--verbose"), "{stdout}");
    assert!(!stdout.contains("--threshold"), "{stdout}");
}

#[test]
fn pipe_and_quiet_omit_the_hint_verbose_prints_it() {
    let (code, stdout, stderr) = run_clock("1,5", &["example.com"]);
    assert_eq!(code, Some(3), "{stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert_eq!(stderr.lines().count(), 1, "{stderr:?}");
    assert!(stderr.contains("got 1,5"), "{stderr}");
    assert!(!stderr.contains("hint:"), "{stderr}");

    let (qcode, qout, qerr) = run_clock("1,5", &["--quiet", "example.com"]);
    assert_eq!(qcode, Some(3), "{qerr}");
    assert!(qout.is_empty());
    assert_eq!(qerr, stderr, "quiet matches a pipe");

    let (vcode, vout, verr) = run_clock("1,5", &["--verbose", "example.com"]);
    assert_eq!(vcode, Some(3), "{verr}");
    assert!(vout.is_empty());
    assert_eq!(verr.lines().count(), 2, "{verr:?}");
    assert_eq!(verr.lines().next(), stderr.lines().next(), "{verr}");
    assert_eq!(
        verr.lines().nth(1).unwrap(),
        "hint: unset ACME_RENEW_DOCTOR_NOW to use the system clock",
        "{verr}"
    );
    assert_ne!(vcode, Some(1), "no threshold exit");
}

#[test]
fn quiet_with_verbose_stays_exit_3() {
    let (code, stdout, stderr) = run(&["--quiet", "--verbose", "example.com"]);
    assert_eq!(code, Some(3), "{stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("error:"), "{stderr}");
    assert_ne!(code, Some(1), "no threshold exit");
}

#[test]
fn verbose_context_stays_off_stdout() {
    let file = log();
    let (code, stdout, stderr) = run(&["example.com", "--from-log", &file]);
    assert_eq!(code, Some(1), "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
    let (vcode, vout, verr) = run(&["--verbose", "example.com", "--from-log", &file]);
    assert_eq!(vcode, Some(1), "{verr}");
    assert_eq!(vout, stdout, "verbose does not change the report");
    assert!(verr.starts_with("context: files 1, findings "), "{verr:?}");
    assert_eq!(verr.lines().count(), 1, "{verr:?}");
    assert!(!verr.contains("chain"), "{verr}");
    assert!(!verr.contains("host"), "{verr}");
    let (qcode, qout, qerr) = run(&["--quiet", "example.com", "--from-log", &file]);
    assert_eq!(qcode, Some(1), "{qerr}");
    assert_eq!(qout, stdout);
    assert!(qerr.is_empty(), "{qerr}");
}

#[test]
fn missing_output_directory_stays_exit_3() {
    let root = scratch();
    let report = root.join("no-such-dir").join("report.txt");
    let report_path = report.to_str().expect("utf-8 path");
    let file = log();
    let base = [
        "example.com",
        "--output",
        report_path,
        "--from-log",
        file.as_str(),
    ];
    let (code, stdout, stderr) = run(&base);
    assert_eq!(code, Some(3), "{stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("could not write report to "), "{stderr}");
    assert!(stderr.contains("does not create it"), "{stderr}");
    assert!(!stderr.contains("hint:"), "{stderr}");
    assert!(!report.exists());

    let (vcode, vout, verr) = run(&[
        "--verbose",
        "example.com",
        "--output",
        report_path,
        "--from-log",
        file.as_str(),
    ]);
    assert_eq!(vcode, Some(3), "{verr}");
    assert!(vout.is_empty(), "{vout}");
    assert_eq!(verr.lines().next(), stderr.lines().next(), "{verr}");
    assert!(verr.lines().nth(1).unwrap().starts_with("hint: "), "{verr}");
    assert!(!report.exists());
    assert!(!root.join("no-such-dir").exists());
    fs::remove_dir_all(&root).ok();
}
