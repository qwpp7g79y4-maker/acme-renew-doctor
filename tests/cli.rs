use std::io::Write;
use std::process::{Command, Stdio};

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_acme-renew-doctor"))
        .args(args)
        .output()
        .expect("run acme-renew-doctor")
}

fn run_with_stdin(args: &[&str], stdin: &[u8]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_acme-renew-doctor"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(args)
        .env("ACME_RENEW_DOCTOR_NOW", "1791273600")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn acme-renew-doctor");
    child
        .stdin
        .take()
        .expect("child stdin")
        .write_all(stdin)
        .expect("write to child stdin");
    child
        .wait_with_output()
        .expect("wait for acme-renew-doctor")
}

#[test]
fn help_exits_zero_and_lists_arguments() {
    let output = run(&["--help"]);
    assert_eq!(output.status.code(), Some(0));

    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));

    for needle in [
        "--all",
        "--json",
        "--from-log",
        "--from-timer-status",
        "--client",
        "certbot",
        "acme.sh",
        "auto",
        "Domain to diagnose (shown in the report; the log is not filtered by domain yet)",
        "Print the report as JSON (with schema_version) instead of text",
        "Certbot log file to analyse, e.g. a copy of /var/log/letsencrypt/letsencrypt.log",
        "Saved output of `systemctl show certbot.timer` to analyse",
        "Saved output of `openssl x509 -noout -dates` for the certificate on disk (e.g. /etc/letsencrypt/live/DOMAIN/fullchain.pem)",
        "Saved output of `openssl x509 -noout -dates` for the certificate the server sends (from openssl s_client)",
        "only Certbot logs are parsed in v0.1",
    ] {
        assert!(
            text.contains(needle),
            "help output missing {needle}\n{text}"
        );
    }
}

#[test]
fn invalid_client_exits_three() {
    let output = run(&["--client", "foo"]);
    assert_eq!(output.status.code(), Some(3));
}

#[test]
fn invalid_now_override_exits_three() {
    let output = Command::new(env!("CARGO_BIN_EXE_acme-renew-doctor"))
        .args(["example.com"])
        .env("ACME_RENEW_DOCTOR_NOW", "not-a-timestamp")
        .output()
        .expect("run acme-renew-doctor");
    assert_eq!(output.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(
            "ACME_RENEW_DOCTOR_NOW must be a whole number of Unix seconds, got not-a-timestamp"
        ),
        "{stderr}"
    );
    assert!(
        output.stdout.is_empty(),
        "stdout:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn domain_with_all_exits_three() {
    let output = run(&["example.com", "--all"]);
    assert_eq!(output.status.code(), Some(3));
}

#[test]
fn from_log_dash_reads_the_log_from_standard_input() {
    let fixture =
        std::fs::read("tests/fixtures/certbot/http01-timeout-repeated.log").expect("read fixture");
    let output = run_with_stdin(&["example.com", "--from-log", "-"], &fixture);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("LAYER2_HTTP01_TIMEOUT"),
        "missing diagnosis\n{stdout}"
    );
    assert!(
        stdout.contains("inputs: log=-"),
        "inputs line should show the dash path\n{stdout}"
    );
}

struct TempDir {
    path: std::path::PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "acme-renew-doctor-cli-{}-{label}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create tempdir");
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn run_in(dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_acme-renew-doctor"))
        .current_dir(dir)
        .args(args)
        .output()
        .expect("run acme-renew-doctor")
}

#[test]
fn example_writes_the_log_file_outside_a_repository_clone() {
    let temp = TempDir::new("example");
    let output = run_in(&temp.path, &["--example"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("wrote example-log.txt in the current directory"),
        "{stdout}"
    );
    let written =
        std::fs::read_to_string(temp.path.join("example-log.txt")).expect("read example-log.txt");
    assert!(written.contains("Timeout during connect"), "{written}");

    // Analysing it right away, with no repository clone, reproduces the
    // Quick start's LAYER2_HTTP01_TIMEOUT example.
    let analysed = run_in(
        &temp.path,
        &["example.com", "--from-log", "example-log.txt"],
    );
    assert_eq!(analysed.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&analysed.stdout).contains("LAYER2_HTTP01_TIMEOUT"),
        "{}",
        String::from_utf8_lossy(&analysed.stdout)
    );

    // Running --example again is idempotent: same content, still exit 0.
    let again = run_in(&temp.path, &["--example"]);
    assert_eq!(again.status.code(), Some(0));
}

#[test]
fn example_refuses_to_overwrite_an_unrelated_file() {
    let temp = TempDir::new("example-conflict");
    std::fs::write(
        temp.path.join("example-log.txt"),
        "not the example content\n",
    )
    .expect("write conflicting file");
    let output = run_in(&temp.path, &["--example"]);
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("example-log.txt already exists with different content"),
        "{stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(temp.path.join("example-log.txt")).expect("read back"),
        "not the example content\n",
        "the unrelated file must be left untouched"
    );
}

#[test]
fn example_refuses_to_overwrite_a_non_utf8_file() {
    let temp = TempDir::new("example-non-utf8");
    let path = temp.path.join("example-log.txt");
    // 0xFF is not valid UTF-8, so a text read fails and must not count as
    // "the file is absent".
    let original = b"keep me \xff intact\n";
    std::fs::write(&path, original).expect("write conflicting file");
    let output = run_in(&temp.path, &["--example"]);
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("example-log.txt already exists with different content"),
        "{stderr}"
    );
    assert_eq!(
        std::fs::read(&path).expect("read back"),
        original,
        "a non-UTF-8 file must be left untouched"
    );
}

#[test]
fn domain_without_inputs_exits_two() {
    let output = run(&["example.com"]);
    assert_eq!(output.status.code(), Some(2));
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("INSUFFICIENT_EVIDENCE"),
        "missing code\n{text}"
    );
    assert!(
        text.contains(
            "note: live collection is not built yet; pass --from-log, --from-timer-status, --from-cert-disk and/or --from-cert-live."
        ),
        "missing note\n{text}"
    );
}
