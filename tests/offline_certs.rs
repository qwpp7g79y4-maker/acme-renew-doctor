//! W-07: offline test mode with fake certificates.
//!
//! No network, no real certificates. Every certificate below is synthetic
//! text written into a temporary directory by the test itself: the saved
//! output of `openssl x509 -noout -dates`, or of `openssl s_client`, which
//! is what `--from-cert-*` reads. There is no key or PEM block, so nothing
//! here is a secret. The clock is fixed with `ACME_RENEW_DOCTOR_NOW`.
//!
//! The Doctor only reads dates. An expired certificate is therefore
//! diagnosed, while a wrong host or a broken chain cannot be seen in a dates
//! file. For those two the contract is: do not invent a verdict, and say the
//! evidence is not recognised.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// 2026-10-06 00:00:00 UTC.
const NOW: &str = "1791244800";

const EXPIRED: &str = "notBefore=Jan  1 00:00:00 2026 GMT\nnotAfter=Mar 31 23:59:59 2026 GMT\n";
const VALID: &str = "notBefore=Sep 28 03:12:45 2026 GMT\nnotAfter=Dec 27 03:12:44 2026 GMT\n";

/// Synthetic `s_client` text for a certificate issued to another host
/// (invalid TLD, RFC 2606), with the verify error openssl prints.
const WRONG_HOST: &str = "\
depth=0 CN = other.example.invalid
verify error:num=62:Hostname mismatch
verify return:1
notBefore=Sep 28 03:12:45 2026 GMT
";

/// Synthetic `s_client` text for a chain that does not verify.
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
            "acme-renew-doctor-w07-{label}-{}",
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

#[test]
fn expired_certificate_is_reported_with_negative_days_offline() {
    let dir = TempDir::new("expired");
    let cert = dir.write("expired.txt", EXPIRED);
    let out = doctor(&cert, &cert, &[]);
    let text = stdout(&out);
    assert!(text.contains("notAfter=Mar 31 23:59:59 2026 GMT"), "{text}");
    assert!(text.contains("-189 day(s) remain"), "{text}");
    assert!(text.contains("at or under the"), "{text}");
    assert_eq!(out.status.code(), Some(2), "{text}");
    assert!(out.stderr.is_empty());
}

#[test]
fn expired_certificate_json_is_stable_and_offline() {
    let dir = TempDir::new("expired-json");
    let cert = dir.write("expired.txt", EXPIRED);
    let first = stdout(&doctor(&cert, &cert, &["--json"]));
    let second = stdout(&doctor(&cert, &cert, &["--json"]));
    assert_eq!(first, second);
    assert!(first.contains("\"schema_version\""), "{first}");
}

#[test]
fn valid_certificate_is_not_flagged_as_expired() {
    let dir = TempDir::new("valid");
    let cert = dir.write("valid.txt", VALID);
    let out = doctor(&cert, &cert, &[]);
    let text = stdout(&out);
    assert!(text.contains("OK_NOT_DUE"), "{text}");
    assert_eq!(out.status.code(), Some(0), "{text}");
}

#[test]
fn wrong_host_output_is_not_taken_for_a_verdict() {
    let dir = TempDir::new("wrong-host");
    let disk = dir.write("disk.txt", VALID);
    let live = dir.write("live.txt", WRONG_HOST);
    let out = doctor(&disk, &live, &[]);
    let text = stdout(&out);
    // The notAfter line is missing, so the live certificate is unreadable
    // for the Doctor. It must say so rather than guess a host problem.
    assert!(text.contains("not recognised"), "{text}");
    assert!(!text.to_lowercase().contains("hostname"), "{text}");
    assert_eq!(out.status.code(), Some(2), "{text}");
}

#[test]
fn broken_chain_output_is_not_taken_for_a_verdict() {
    let dir = TempDir::new("broken-chain");
    let disk = dir.write("disk.txt", VALID);
    let live = dir.write("live.txt", BROKEN_CHAIN);
    let out = doctor(&disk, &live, &[]);
    let text = stdout(&out);
    assert!(text.contains("not recognised"), "{text}");
    assert!(!text.to_lowercase().contains("issuer"), "{text}");
    assert_eq!(out.status.code(), Some(2), "{text}");
}

#[test]
fn offline_runs_never_need_a_network_tool() {
    // The suggested checks are only printed, never run.
    let dir = TempDir::new("no-run");
    let cert = dir.write("expired.txt", EXPIRED);
    let out = doctor(&cert, &cert, &[]);
    assert!(out.stderr.is_empty());
    assert!(stdout(&out).contains("Doctor runs nothing"));
}

/// W-45: the same offline report, with outgoing connections blocked.
///
/// `unshare --user --map-root-user --net` starts a network namespace whose
/// route table is empty, so the process has no way out. The proof uses those
/// same flags, then the Doctor reads the synthetic expired dates. It does
/// not diagnose a host or a chain.
#[cfg(target_os = "linux")]
#[test]
fn expired_certificate_is_reported_with_outgoing_connections_blocked() {
    let ns = ["--user", "--map-root-user", "--net", "--"];
    let proof = Command::new("unshare")
        .args(ns)
        .args(["cat", "/proc/net/route"])
        .output()
        .expect("unshare route table");
    assert!(
        proof.status.success(),
        "unshare failed: {}",
        String::from_utf8_lossy(&proof.stderr)
    );
    let routes = String::from_utf8(proof.stdout).expect("utf-8 route table");
    assert!(
        !routes.split_whitespace().any(|field| field == "00000000"),
        "network namespace still has a route: {routes:?}"
    );

    let dir = TempDir::new("blocked");
    let cert = dir.write("expired.txt", EXPIRED);
    let out = Command::new("unshare")
        .args(ns)
        .arg(env!("CARGO_BIN_EXE_acme-renew-doctor"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["example.com", "--from-timer-status"])
        .arg("tests/fixtures/timer/certbot-timer-enabled.txt")
        .arg("--from-cert-disk")
        .arg(&cert)
        .arg("--from-cert-live")
        .arg(&cert)
        .env("ACME_RENEW_DOCTOR_NOW", NOW)
        .output()
        .expect("run acme-renew-doctor with outgoing connections blocked");
    let text = stdout(&out);
    assert!(text.contains("notAfter=Mar 31 23:59:59 2026 GMT"), "{text}");
    assert!(text.contains("-189 day(s) remain"), "{text}");
    assert!(text.contains("at or under the"), "{text}");
    assert_eq!(out.status.code(), Some(2), "{text}");
    assert!(out.stderr.is_empty(), "{text}");
    assert!(!text.to_lowercase().contains("hostname"), "{text}");
    assert!(!text.to_lowercase().contains("issuer"), "{text}");
}
