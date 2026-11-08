//! Every read-error path says what went wrong and what to do next, and keeps
//! its exit code (2: insufficient evidence; 3: could not run).

use std::path::{Path, PathBuf};
use std::process::Command;

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "acme-renew-doctor-w24-{}-{n}-{label}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create tempdir");
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run(dir: &Path, args: &[&str]) -> (Option<i32>, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_acme-renew-doctor"))
        .current_dir(dir)
        .args(args)
        .env("ACME_RENEW_DOCTOR_NOW", "1791273600")
        .output()
        .expect("run acme-renew-doctor");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Runs one input option against `path`; expects exit 2 and both parts of the message.
fn read_error(option: &str, path: &str, went_wrong: &str, next: &str) {
    let temp = TempDir::new("cwd");
    let (code, stdout, _) = run(&temp.0, &[option, path]);
    assert_eq!(code, Some(2), "{stdout}");
    assert!(
        stdout.contains(went_wrong),
        "missing {went_wrong:?}:\n{stdout}"
    );
    assert!(stdout.contains(next), "missing {next:?}:\n{stdout}");
}

fn file(temp: &TempDir, name: &str, bytes: &[u8]) -> String {
    let path = temp.0.join(name);
    std::fs::write(&path, bytes).expect("write input");
    path.display().to_string()
}

#[test]
fn empty_path_says_what_to_pass() {
    read_error(
        "--from-log",
        "",
        "cannot read: the path is empty",
        "give the path of a saved file after the option",
    );
}

#[test]
fn missing_file_says_to_check_the_path() {
    read_error(
        "--from-timer-status",
        "/nonexistent-w24/timer.txt",
        "NotFound",
        "check the path, or save the command output to a file first",
    );
}

#[test]
fn directory_says_to_give_a_file() {
    let temp = TempDir::new("dir");
    let dir = temp.0.display().to_string();
    read_error(
        "--from-cert-disk",
        &dir,
        "is a directory",
        "give the path of a file, not a folder",
    );
}

#[test]
fn oversized_short_text_says_to_pass_an_excerpt() {
    let temp = TempDir::new("big");
    let big = file(&temp, "big.txt", &vec![b'a'; 1024 * 1024 + 1]);
    read_error(
        "--from-timer-status",
        &big,
        "byte limit",
        "pass a smaller excerpt of it",
    );
}

#[test]
fn invalid_utf8_short_text_says_to_save_as_utf8() {
    let temp = TempDir::new("utf8");
    let bad = file(&temp, "bad.txt", b"notAfter=\xff\xfe\xfa\n");
    read_error(
        "--from-cert-live",
        &bad,
        "not valid UTF-8",
        "save it as UTF-8 and run again",
    );
}

#[test]
fn wide_encoding_says_to_save_as_utf8() {
    let temp = TempDir::new("wide");
    let wide = file(&temp, "wide.txt", b"\xff\xfeI\0d\0=\0");
    read_error(
        "--from-timer-status",
        &wide,
        "the file is UTF-16LE",
        "save it as UTF-8",
    );
}

#[test]
fn timer_without_id_says_what_to_save() {
    let temp = TempDir::new("noid");
    let text = file(&temp, "t.txt", b"ActiveState=active\n");
    read_error(
        "--from-timer-status",
        &text,
        "no Id= line",
        "save the output of systemctl show certbot.timer",
    );
}

#[test]
fn timer_with_unknown_unit_says_which_units_work() {
    let temp = TempDir::new("unit");
    let text = file(&temp, "t.txt", b"Id=other.timer\nActiveState=active\n");
    read_error(
        "--from-timer-status",
        &text,
        "no certbot.timer, certbot.service or snap.certbot.renew.timer",
        "save the output of systemctl show for one of those units",
    );
}

#[test]
fn timer_with_conflicting_states_says_to_use_one_run_per_file() {
    let temp = TempDir::new("ambig");
    let text = file(
        &temp,
        "t.txt",
        b"Id=certbot.timer\nActiveState=active\n\nId=certbot.timer\nActiveState=inactive\n",
    );
    read_error(
        "--from-timer-status",
        &text,
        "timer status is ambiguous",
        "one systemctl show run per file",
    );
}

#[test]
fn certificate_without_dates_says_what_to_save() {
    let temp = TempDir::new("cert");
    let text = file(&temp, "c.txt", b"nothing useful\n");
    read_error(
        "--from-cert-disk",
        &text,
        "no notAfter= line",
        "save the output of openssl x509 -noout -dates",
    );
}

#[test]
fn ambiguous_acme_json_says_to_check_the_log() {
    assert!(acme_renew_doctor::certbot_log::AMBIGUOUS_ACME_JSON.contains("pass the original log"));
}

#[test]
fn log_without_certbot_lines_names_the_client_problem() {
    let temp = TempDir::new("client");
    let text = file(&temp, "l.txt", b"just some text\n");
    let (code, stdout, _) = run(&temp.0, &["--from-log", &text]);
    assert_eq!(code, Some(3), "{stdout}");
    assert!(stdout.contains("no Certbot log lines found"), "{stdout}");
    assert!(stdout.contains("expected lines like"), "{stdout}");
}

#[test]
fn example_refuses_to_replace_a_different_file_and_says_how_to_continue() {
    let temp = TempDir::new("example");
    file(&temp, "example-log.txt", b"mine\n");
    let (code, _, stderr) = run(&temp.0, &["--example"]);
    assert_eq!(code, Some(3));
    assert!(
        stderr.contains("remove it or run --example in an empty directory"),
        "{stderr}"
    );
}

#[cfg(unix)]
#[test]
fn example_in_an_unwritable_directory_says_where_to_run_it() {
    use std::os::unix::fs::PermissionsExt;
    let temp = TempDir::new("readonly");
    std::fs::set_permissions(&temp.0, std::fs::Permissions::from_mode(0o555)).expect("chmod");
    if std::fs::write(temp.0.join("probe"), b"").is_ok() {
        // Running as a user that ignores permissions (root): nothing to test.
        std::fs::set_permissions(&temp.0, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        return;
    }
    let (code, _, stderr) = run(&temp.0, &["--example"]);
    std::fs::set_permissions(&temp.0, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    assert_eq!(code, Some(3));
    assert!(
        stderr.contains("run --example in a directory you can write to"),
        "{stderr}"
    );
}

#[test]
fn invalid_clock_override_says_to_unset_it() {
    let temp = TempDir::new("now");
    let out = Command::new(env!("CARGO_BIN_EXE_acme-renew-doctor"))
        .current_dir(&temp.0)
        .arg("example.com")
        .env("ACME_RENEW_DOCTOR_NOW", "abc")
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unset ACME_RENEW_DOCTOR_NOW"), "{stderr}");
}

#[test]
fn system_clock_message_says_what_to_do() {
    assert!(acme_renew_doctor::certtime::SYSTEM_CLOCK_RANGE.contains("fix the system clock"));
}
