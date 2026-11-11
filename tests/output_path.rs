//! `--output PATH` writes the report to a file. An existing file is replaced.
//! A missing parent directory is exit 3, the same code as a failed write to
//! standard output, and that directory is not created.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn run(args: &[&str]) -> (i32, Vec<u8>, Vec<u8>) {
    let output = Command::new(env!("CARGO_BIN_EXE_acme-renew-doctor"))
        .args(args)
        .env("ACME_RENEW_DOCTOR_NOW", "1791273600")
        .output()
        .expect("run acme-renew-doctor");
    (
        output.status.code().expect("exit code"),
        output.stdout,
        output.stderr,
    )
}

fn fixture() -> String {
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
        "acme-renew-doctor-output-{}-{}-{}",
        std::process::id(),
        nanos,
        N.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&dir).expect("create scratch dir");
    dir
}

fn report_args<'a>(report: &'a str, log: &'a str) -> [&'a str; 6] {
    [
        "example.com",
        "--output",
        report,
        "--from-log",
        log,
        "--json",
    ]
}

#[test]
fn output_flag_writes_a_new_file() {
    let help = run(&["--help"]);
    assert_eq!(help.0, 0);
    let help_text = String::from_utf8(help.1).expect("help is utf-8");
    assert!(help_text.contains("--output"), "{help_text}");

    let root = scratch();
    let report = root.join("report.txt");
    assert!(!report.exists());
    let log = fixture();
    let report_path = report.to_str().expect("utf-8 path");
    let (code, stdout, stderr) = run(&report_args(report_path, &log));
    let err = String::from_utf8_lossy(&stderr);
    assert_eq!(code, 1, "{err}");
    assert!(stdout.is_empty(), "stdout must stay empty");
    assert!(stderr.is_empty(), "{err}");
    let (plain_code, expected, plain_err) = run(&["example.com", "--json", "--from-log", &log]);
    let plain_err = String::from_utf8_lossy(&plain_err);
    assert_eq!(plain_code, 1, "{plain_err}");
    assert!(!expected.is_empty());
    assert_eq!(fs::read(&report).expect("read report"), expected);
    fs::remove_dir_all(&root).ok();
}

#[test]
fn output_flag_overwrites_an_existing_file() {
    let root = scratch();
    let report = root.join("report.txt");
    let prior = b"PRIOR-BYTES-NOT-THE-REPORT\n";
    fs::write(&report, prior).unwrap();
    let log = fixture();
    let report_path = report.to_str().expect("utf-8 path");
    let (code, stdout, stderr) = run(&report_args(report_path, &log));
    let err = String::from_utf8_lossy(&stderr);
    assert_eq!(code, 1, "{err}");
    assert!(stdout.is_empty(), "{stdout:?}");
    assert!(stderr.is_empty(), "{err}");
    let (plain_code, expected, plain_err) = run(&["example.com", "--json", "--from-log", &log]);
    let plain_err = String::from_utf8_lossy(&plain_err);
    assert_eq!(plain_code, 1, "{plain_err}");
    let body = fs::read(&report).expect("read report");
    assert_eq!(body, expected);
    assert_ne!(body, prior);
    fs::remove_dir_all(&root).ok();
}

#[test]
fn output_flag_missing_directory_exits_three() {
    let root = scratch();
    let missing_dir = root.join("no-such-dir");
    let report = missing_dir.join("report.txt");
    let log = fixture();
    let report_path = report.to_str().expect("utf-8 path");
    let (code, stdout, stderr) = run(&report_args(report_path, &log));
    let err = String::from_utf8_lossy(&stderr);
    assert_eq!(code, 3, "{err}");
    assert!(stdout.is_empty(), "{stdout:?}");
    assert!(err.contains("could not write report to "), "{err}");
    assert!(err.contains("does not create it"), "{err}");
    assert!(!err.contains("panicked"), "{err}");
    assert!(!report.exists());
    assert!(
        !missing_dir.exists(),
        "a missing parent directory must not be created"
    );
    fs::remove_dir_all(&root).ok();
}

#[cfg(unix)]
#[test]
fn output_flag_does_not_follow_a_preplaced_temp_symlink() {
    use std::os::unix::process::CommandExt;

    let root = scratch();
    let report = root.join("report.txt");
    let victim = root.join("victim.txt");
    fs::write(&victim, b"KEEP\n").unwrap();
    let log = fixture();
    let report_path = report.to_str().expect("utf-8 path");
    let log_path = log.clone();
    let report_c = report.clone();
    let victim_c = victim.clone();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_acme-renew-doctor"));
    cmd.args(report_args(report_path, &log_path))
        .env("ACME_RENEW_DOCTOR_NOW", "1791273600");
    // The child places the symlink at the first temporary name, using its
    // own pid, after fork and before exec.
    // SAFETY: the closure only creates a symlink in a scratch directory
    // the test owns, then returns, and does not run after exec.
    unsafe {
        cmd.pre_exec(move || {
            let mut name = std::ffi::OsString::from(".");
            name.push(report_c.file_name().unwrap_or_default());
            name.push(format!(".acme-renew-doctor-{}.tmp", std::process::id()));
            let tmp = report_c
                .parent()
                .unwrap_or(std::path::Path::new("."))
                .join(name);
            let _ = fs::remove_file(&tmp);
            std::os::unix::fs::symlink(&victim_c, &tmp)?;
            Ok(())
        });
    }
    let output = cmd.output().expect("run acme-renew-doctor");
    let code = output.status.code().expect("exit code");
    let err = String::from_utf8_lossy(&output.stderr);
    assert_eq!(code, 1, "{err}");
    assert!(output.stdout.is_empty(), "stdout must stay empty");
    assert_eq!(fs::read(&victim).expect("read victim"), b"KEEP\n");
    let (plain_code, expected, plain_err) = run(&["example.com", "--json", "--from-log", &log]);
    let plain_err = String::from_utf8_lossy(&plain_err);
    assert_eq!(plain_code, 1, "{plain_err}");
    assert_eq!(fs::read(&report).expect("read report"), expected);
    fs::remove_dir_all(&root).ok();
}

#[cfg(unix)]
#[test]
fn output_flag_keeps_the_mode_of_an_existing_file() {
    use std::os::unix::fs::PermissionsExt;

    let root = scratch();
    let report = root.join("report.txt");
    fs::write(&report, b"PRIOR-BYTES-NOT-THE-REPORT\n").unwrap();
    fs::set_permissions(&report, fs::Permissions::from_mode(0o600)).unwrap();
    let log = fixture();
    let report_path = report.to_str().expect("utf-8 path");
    let (code, stdout, stderr) = run(&report_args(report_path, &log));
    let err = String::from_utf8_lossy(&stderr);
    assert_eq!(code, 1, "{err}");
    assert!(stdout.is_empty(), "{stdout:?}");
    assert!(stderr.is_empty(), "{err}");
    let mode = fs::metadata(&report).expect("meta").permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "replacement must keep the existing mode");
    let (plain_code, expected, plain_err) = run(&["example.com", "--json", "--from-log", &log]);
    let plain_err = String::from_utf8_lossy(&plain_err);
    assert_eq!(plain_code, 1, "{plain_err}");
    assert_eq!(fs::read(&report).expect("read report"), expected);
    fs::remove_dir_all(&root).ok();
}
