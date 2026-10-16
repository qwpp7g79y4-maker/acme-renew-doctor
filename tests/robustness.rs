//! Robustness tests for bad files, encoding, concatenated logs and odd domains.
//! Clock: ACME_RENEW_DOCTOR_NOW=1791273600.
//! Ignored tests are heavy and stay out of a normal `cargo test`.
//! The latest timestamp wins.

use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const NOW: &str = "1791273600";
#[cfg(target_os = "linux")]
const RSS_CEILING_KB: u64 = 1_048_576;
#[cfg(target_os = "linux")]
const HUNDRED_MB: usize = 100 * 1024 * 1024;
/// Above the 100 MiB heavy read. A sparse file of this size plus one byte is enough.
const LOG_BYTE_LIMIT: u64 = 256 * 1024 * 1024;
/// Saved timer status and certificate dates are short text.
const SHORT_BYTE_LIMIT: u64 = 1024 * 1024;
const FILE_FLAGS: [&str; 4] = [
    "--from-log",
    "--from-timer-status",
    "--from-cert-disk",
    "--from-cert-live",
];
#[cfg(unix)]
const NOT_REGULAR: &str = "not a regular file, save the output to a file first";

struct TempDir {
    dir: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "acme-renew-doctor-robustness-{}-{}-{label}",
            std::process::id(),
            n
        ));
        std::fs::create_dir_all(&dir)
            .unwrap_or_else(|err| panic!("tempdir {}: {err}", dir.display()));
        Self { dir }
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.dir.join(name);
        std::fs::write(&path, bytes)
            .unwrap_or_else(|err| panic!("write {}: {err}", path.display()));
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

struct ReportOut {
    exit: i32,
    stdout: String,
    stderr: String,
}

fn owned(args: &[&str]) -> Vec<String> {
    args.iter().copied().map(str::to_string).collect()
}

fn run_owned(args: &[String], now: &str, env_pairs: &[(&str, &str)]) -> ReportOut {
    let mut command = Command::new(env!("CARGO_BIN_EXE_acme-renew-doctor"));
    command
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(args)
        .env_remove("ACME_RENEW_DOCTOR_NOW")
        .env("ACME_RENEW_DOCTOR_NOW", now);
    for (key, value) in env_pairs {
        command.env(key, value);
    }
    let output = command.output().expect("run acme-renew-doctor");
    let exit = output.status.code().unwrap_or_else(|| {
        panic!(
            "process ended on a signal, not with exit 0-3\nstderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    ReportOut {
        exit,
        stdout: String::from_utf8(output.stdout)
            .unwrap_or_else(|err| panic!("stdout is not utf-8: {err}")),
        stderr: String::from_utf8(output.stderr)
            .unwrap_or_else(|err| panic!("stderr is not utf-8: {err}")),
    }
}

fn assert_no_panic(report: &ReportOut) {
    assert!(
        (0..=3).contains(&report.exit),
        "exit {} outside 0-3\nstderr:\n{}\nstdout:\n{}",
        report.exit,
        report.stderr,
        report.stdout
    );
    assert!(
        !report.stderr.contains("panicked") && !report.stdout.contains("panicked"),
        "panic in the output\nstderr:\n{}\nstdout:\n{}",
        report.stderr,
        report.stdout
    );
}

fn assert_exit_matches_decision(stdout: &str, exit: i32) {
    let expected = if stdout.contains("CLIENT_UNKNOWN") {
        3
    } else if stdout.contains("LAYER1_") || stdout.contains("LAYER2_") || stdout.contains("LAYER3_")
    {
        1
    } else if stdout.contains("OK_NOT_DUE") {
        0
    } else {
        2
    };
    assert_eq!(exit, expected, "exit does not match the report\n{stdout}");
}

fn assert_not_false_ok(report: &ReportOut) {
    assert_ne!(
        report.exit, 0,
        "exit 0 although the input does not justify it\n{}",
        report.stdout
    );
    assert!(
        !report.stdout.contains("OK_NOT_DUE"),
        "OK_NOT_DUE although the input does not justify it\n{}",
        report.stdout
    );
}

fn assert_json_document(stdout: &str) {
    let mut child = Command::new("python3")
        .args(["-m", "json.tool"])
        .env("PYTHONUTF8", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("python3");
    {
        let mut stdin = child.stdin.take().expect("json.tool stdin");
        stdin.write_all(stdout.as_bytes()).expect("json to python");
    }
    let output = child.wait_with_output().expect("json.tool");
    assert!(
        output.status.success(),
        "python3 -m json.tool rejected the output:\n{}\n---\n{stdout}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn check_in(args: &[&str], now: &str, env_pairs: &[(&str, &str)], allow_ok: bool) -> ReportOut {
    let report = run_owned(&owned(args), now, env_pairs);
    assert_no_panic(&report);
    assert_exit_matches_decision(&report.stdout, report.exit);
    assert!(
        report.stdout.contains(&format!("exit {}:", report.exit)),
        "no exit line\n{}",
        report.stdout
    );
    if allow_ok {
        assert_eq!(report.exit, 0, "{}", report.stdout);
        assert!(report.stdout.contains("OK_NOT_DUE"), "{}", report.stdout);
    } else {
        assert_not_false_ok(&report);
    }

    let mut json_args = vec!["--json".to_string()];
    json_args.extend(args.iter().copied().map(str::to_string));
    let json = run_owned(&json_args, now, env_pairs);
    assert_no_panic(&json);
    assert_eq!(json.exit, report.exit, "json exit differs\n{}", json.stdout);
    assert_exit_matches_decision(&json.stdout, json.exit);
    assert!(
        json.stdout
            .contains(&format!("\"exit_code\": {}", json.exit)),
        "{}",
        json.stdout
    );
    assert_json_document(&json.stdout);
    if allow_ok {
        assert!(json.stdout.contains("OK_NOT_DUE"), "{}", json.stdout);
    } else {
        assert_not_false_ok(&json);
    }
    report
}

fn check(args: &[&str]) -> ReportOut {
    check_in(args, NOW, &[], false)
}

fn check_ok(args: &[&str]) -> ReportOut {
    check_in(args, NOW, &[], true)
}

fn fixture(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

fn arg(path: &Path) -> String {
    path.to_str().expect("path is utf-8").to_string()
}

fn to_crlf(text: &str) -> Vec<u8> {
    text.replace("\r\n", "\n")
        .replace('\n', "\r\n")
        .into_bytes()
}

#[cfg(unix)]
fn running_as_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .any(|line| {
            line.strip_prefix("Uid:")
                .and_then(|rest| rest.split_whitespace().next())
                .is_some_and(|uid| uid == "0")
        })
}

fn prefix_through(text: &str, keep: impl Fn(&str) -> bool) -> String {
    let mut out = String::new();
    for line in text.lines() {
        out.push_str(line);
        out.push('\n');
        if keep(line) {
            break;
        }
    }
    out
}

fn embed_json(text: &str) -> String {
    let mut out = String::new();
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{code:04x}", code = c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn log_with_domain(domain: &str) -> String {
    let detail = "203.0.113.10: Fetching http://example.com/.well-known/acme-challenge/tok: Timeout during connect (likely firewall problem)";
    format!(
        "2026-09-28 03:12:44,512:DEBUG:acme.client:Received response:\n\
{{\n  \"identifier\": {{\"type\": \"dns\", \"value\": \"{domain_json}\"}},\n  \
\"status\": \"invalid\",\n  \"challenges\": [{{\"type\": \"http-01\", \"error\": {{\n    \
\"type\": \"urn:ietf:params:acme:error:connection\",\n    \
\"detail\": \"{detail_json}\"\n  }}}}]\n}}\n  \
Domain: {domain}\n  \
Type:   connection\n  \
Detail: {detail}\n",
        domain_json = embed_json(domain),
        detail_json = embed_json(detail),
    )
}

fn assert_has(report: &ReportOut, code: &str, exit: i32) {
    assert_eq!(
        report.exit, exit,
        "stderr:\n{}\nstdout:\n{}",
        report.stderr, report.stdout
    );
    assert!(
        report.stdout.contains(code),
        "expected {code}\n{}",
        report.stdout
    );
}

fn command_lines(stdout: &str) -> Vec<&str> {
    stdout
        .lines()
        .filter_map(|line| line.strip_prefix("  → "))
        .collect()
}

fn z1_bad_files(flag: &str, empty_code: &str, empty_exit: i32, empty_needle: &str) {
    let temp = TempDir::new("z1");
    let base = ["example.com", flag];

    let empty = temp.write("empty.txt", b"");
    let report = check(&[base[0], base[1], &arg(&empty)]);
    assert_has(&report, empty_code, empty_exit);
    assert!(report.stdout.contains(empty_needle), "{}", report.stdout);
    assert!(
        !report.stdout.contains("LAYER1_PERMISSION"),
        "{}",
        report.stdout
    );

    let spaces = temp.write("spaces.txt", b" \n\n\t\n  \n");
    let report = check(&[base[0], base[1], &arg(&spaces)]);
    assert_has(&report, empty_code, empty_exit);
    assert!(report.stdout.contains(empty_needle), "{}", report.stdout);

    let dir = temp.dir.join("a-directory");
    std::fs::create_dir(&dir).expect("mkdir");
    let report = check(&[base[0], base[1], &arg(&dir)]);
    assert_has(&report, "INSUFFICIENT_EVIDENCE", 2);
    assert!(report.stdout.contains("cannot read"), "{}", report.stdout);
    assert!(
        report.stdout.contains("is a directory"),
        "{}",
        report.stdout
    );
    assert!(!report.stdout.contains("other kind"), "{}", report.stdout);
    assert!(
        !report.stdout.contains("LAYER1_PERMISSION"),
        "{}",
        report.stdout
    );

    // chmod 000 is a Unix permission test; Windows has no mode bits.
    #[cfg(unix)]
    if running_as_root() {
        eprintln!("skipped: this test runs as root, chmod 000 does not stop reads ({flag})");
    } else {
        let secret = temp.write("secret.txt", b"not for the tool\n");
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o000)).expect("chmod");
        let report = check(&[base[0], base[1], &arg(&secret)]);
        assert_has(&report, "INSUFFICIENT_EVIDENCE", 2);
        assert!(
            report.stdout.contains("PermissionDenied"),
            "{}",
            report.stdout
        );
        assert!(report.stdout.contains("cannot read"), "{}", report.stdout);
        assert!(
            !report.stdout.contains("LAYER1_PERMISSION"),
            "{}",
            report.stdout
        );
    }

    let missing = temp.dir.join("missing.txt");
    let report = check(&[base[0], base[1], &arg(&missing)]);
    assert_has(&report, "INSUFFICIENT_EVIDENCE", 2);
    assert!(report.stdout.contains("NotFound"), "{}", report.stdout);
    assert!(report.stdout.contains("cannot read"), "{}", report.stdout);
    assert!(
        !report.stdout.contains("LAYER1_PERMISSION"),
        "{}",
        report.stdout
    );
}

#[test]
fn z1_from_log_bad_files() {
    z1_bad_files("--from-log", "CLIENT_UNKNOWN", 3, "no Certbot log lines");
}

#[test]
fn z1_from_timer_status_bad_files() {
    z1_bad_files(
        "--from-timer-status",
        "INSUFFICIENT_EVIDENCE",
        2,
        "timer status not recognised",
    );
}

#[test]
fn z1_from_cert_disk_bad_files() {
    z1_bad_files(
        "--from-cert-disk",
        "INSUFFICIENT_EVIDENCE",
        2,
        "certificate dates not recognised",
    );
}

#[test]
fn z1_from_cert_live_bad_files() {
    z1_bad_files(
        "--from-cert-live",
        "INSUFFICIENT_EVIDENCE",
        2,
        "certificate dates not recognised",
    );
}

#[test]
fn z2_json_cut_after_type_before_detail() {
    let full = fixture("tests/fixtures/certbot/http01-timeout.log");
    let cut = prefix_through(&full, |line| {
        line.contains("\"type\": \"urn:ietf:params:acme:error:connection\"")
    });
    assert!(
        cut.contains("urn:ietf:params:acme:error:connection"),
        "{cut}"
    );
    assert!(
        !cut.contains("\"detail\""),
        "the cut must fall before detail\n{cut}"
    );
    let temp = TempDir::new("z2a");
    let path = temp.write("cut-json.log", cut.as_bytes());
    let report = check(&["example.com", "--from-log", &arg(&path)]);
    assert_has(&report, "INSUFFICIENT_EVIDENCE", 2);
    assert!(
        report.stdout.contains("ACME errors in log not recognised"),
        "{}",
        report.stdout
    );
    assert!(!report.stdout.contains("LAYER2_"), "{}", report.stdout);
}

#[test]
fn z2_summary_cut_after_domain_line() {
    let full = fixture("tests/fixtures/certbot/http01-timeout.log");
    let cut = prefix_through(&full, |line| line == "  Domain: example.com");
    assert!(cut.contains("  Domain: example.com"), "{cut}");
    assert!(!cut.contains("\n  Type:"), "{cut}");
    assert!(!cut.contains("\n  Detail:"), "{cut}");
    assert!(
        cut.contains("\"detail\""),
        "the JSON detail should still be present"
    );
    let temp = TempDir::new("z2b");
    let path = temp.write("cut-domain.log", cut.as_bytes());
    let report = check(&["example.com", "--from-log", &arg(&path)]);
    assert_has(&report, "LAYER2_HTTP01_TIMEOUT", 1);
}

#[test]
fn z2_log_cut_at_type_line() {
    let full = fixture("tests/fixtures/certbot/http01-timeout.log");
    let cut = prefix_through(&full, |line| line == "  Type:   connection");
    assert!(cut.contains("  Type:   connection"), "{cut}");
    assert!(!cut.contains("\n  Detail:"), "{cut}");
    assert!(
        cut.contains("\"detail\""),
        "the JSON detail should still be present"
    );
    let temp = TempDir::new("z2c");
    let path = temp.write("cut-type.log", cut.as_bytes());
    let report = check(&["example.com", "--from-log", &arg(&path)]);
    assert_has(&report, "LAYER2_HTTP01_TIMEOUT", 1);
}

fn json_report(args: &[&str]) -> ReportOut {
    let mut json_args = vec!["--json".to_string()];
    json_args.extend(args.iter().copied().map(str::to_string));
    let report = run_owned(&json_args, NOW, &[]);
    assert_no_panic(&report);
    assert_json_document(&report.stdout);
    assert_exit_matches_decision(&report.stdout, report.exit);
    report
}

fn replaced_note(count: usize) -> String {
    if count == 1 {
        "note: replaced 1 invalid UTF-8 byte".to_string()
    } else {
        format!("note: replaced {count} invalid UTF-8 bytes")
    }
}

fn assert_no_replaced_text(stdout: &str) {
    assert!(
        !stdout.contains('\u{FFFD}'),
        "the report quotes a replaced byte\n{stdout}"
    );
}

fn assert_lossy_timeout(label: &str, bytes: &[u8], replaced: usize) {
    let temp = TempDir::new(label);
    let path = temp.write("lossy.log", bytes);
    let args = ["example.com", "--from-log", &arg(&path)];
    let report = check(&args);
    assert_has(&report, "LAYER2_HTTP01_TIMEOUT", 1);
    let note = replaced_note(replaced);
    assert!(
        report.stdout.contains(&note),
        "missing {note}\n{}",
        report.stdout
    );
    assert_no_replaced_text(&report.stdout);
    assert!(!report.stdout.contains("other kind"), "{}", report.stdout);
    assert!(!report.stdout.contains("UTF-16"), "{}", report.stdout);
    assert!(!report.stdout.contains("UTF-32"), "{}", report.stdout);
    let json = json_report(&args);
    assert_eq!(json.exit, 1, "{}", json.stdout);
    assert!(
        json.stdout.contains("\"code\": \"LAYER2_HTTP01_TIMEOUT\""),
        "{}",
        json.stdout
    );
    assert!(
        json.stdout.contains(&note),
        "missing {note}\n{}",
        json.stdout
    );
    assert_no_replaced_text(&json.stdout);
}

fn assert_wide_log(label: &str, bytes: &[u8], encoding: &str) {
    let temp = TempDir::new(label);
    let path = temp.write("wide.log", bytes);
    let args = ["example.com", "--from-log", &arg(&path)];
    let report = check(&args);
    assert_has(&report, "INSUFFICIENT_EVIDENCE", 2);
    let sentence = format!("the file is {encoding}; save it as UTF-8");
    assert!(
        report.stdout.contains(&sentence),
        "missing {sentence}\n{}",
        report.stdout
    );
    assert!(
        !report.stdout.contains("CLIENT_UNKNOWN"),
        "{}",
        report.stdout
    );
    assert!(!report.stdout.contains("other kind"), "{}", report.stdout);
    assert!(
        !report.stdout.contains("Timeout during connect"),
        "wide-encoding report quotes the log\n{}",
        report.stdout
    );
    assert!(!report.stdout.contains("replaced "), "{}", report.stdout);
    let json = json_report(&args);
    assert_eq!(json.exit, 2, "{}", json.stdout);
    assert!(
        json.stdout.contains("\"code\": \"INSUFFICIENT_EVIDENCE\""),
        "{}",
        json.stdout
    );
    assert!(
        json.stdout.contains(&sentence),
        "missing {sentence}\n{}",
        json.stdout
    );
    assert!(
        !json.stdout.contains("Timeout during connect"),
        "{}",
        json.stdout
    );
}

fn encode_utf16(text: &str, bom: bool, big_endian: bool) -> Vec<u8> {
    let mut bytes = Vec::new();
    if bom {
        bytes.extend_from_slice(if big_endian {
            &[0xFE, 0xFF]
        } else {
            &[0xFF, 0xFE]
        });
    }
    for unit in text.encode_utf16() {
        let coded = if big_endian {
            unit.to_be_bytes()
        } else {
            unit.to_le_bytes()
        };
        bytes.extend_from_slice(&coded);
    }
    bytes
}

fn encode_utf32(text: &str, bom: bool, big_endian: bool) -> Vec<u8> {
    let mut bytes = Vec::new();
    if bom {
        bytes.extend_from_slice(if big_endian {
            &[0x00, 0x00, 0xFE, 0xFF]
        } else {
            &[0xFF, 0xFE, 0x00, 0x00]
        });
    }
    for ch in text.chars() {
        let unit = u32::from(ch);
        let coded = if big_endian {
            unit.to_be_bytes()
        } else {
            unit.to_le_bytes()
        };
        bytes.extend_from_slice(&coded);
    }
    bytes
}

/// Put `0xFF` in the middle of every copy of the phrase.
fn corrupt_phrase(bytes: &mut [u8], phrase: &[u8]) -> usize {
    let mut hits = 0;
    let mut from = 0;
    while let Some(offset) = bytes[from..]
        .windows(phrase.len())
        .position(|window| window == phrase)
    {
        let at = from + offset + phrase.len() / 2;
        bytes[at] = 0xFF;
        hits += 1;
        from = at + 1;
    }
    hits
}

fn with_current_certs<'a>(log: &str, args: &'a mut Vec<String>) -> Vec<&'a str> {
    args.push("example.com".to_string());
    args.push("--from-log".to_string());
    args.push(log.to_string());
    args.push("--from-timer-status".to_string());
    args.push("tests/fixtures/timer/certbot-timer-enabled.txt".to_string());
    args.push("--from-cert-disk".to_string());
    args.push("tests/fixtures/certs/dates-current.txt".to_string());
    args.push("--from-cert-live".to_string());
    args.push("tests/fixtures/certs/dates-current.txt".to_string());
    args.iter().map(String::as_str).collect()
}

#[test]
fn z3_ff_byte_keeps_the_timeout_and_counts_the_byte() {
    let mut bytes = fixture("tests/fixtures/certbot/http01-timeout.log").into_bytes();
    let mid = bytes.len() / 2;
    bytes[mid] = 0xFF;
    assert_lossy_timeout("z3ff", &bytes, 1);
}

#[test]
fn z3_latin1_in_an_irrelevant_line_keeps_the_timeout_and_counts_the_byte() {
    let text = fixture("tests/fixtures/certbot/http01-timeout.log");
    let hint = text.find("Hint:").expect("hint line");
    let mut bytes = text.into_bytes();
    bytes.insert(hint + "Hint: ".len(), 0xE9);
    assert_lossy_timeout("z3latin1", &bytes, 1);
}

#[test]
fn z3_utf16le_with_bom_asks_for_utf8() {
    let text = fixture("tests/fixtures/certbot/http01-timeout.log");
    assert_wide_log(
        "z3utf16le-bom",
        &encode_utf16(&text, true, false),
        "UTF-16LE",
    );
}

#[test]
fn z3_utf16be_with_bom_asks_for_utf8() {
    let text = fixture("tests/fixtures/certbot/http01-timeout.log");
    assert_wide_log(
        "z3utf16be-bom",
        &encode_utf16(&text, true, true),
        "UTF-16BE",
    );
}

#[test]
fn z3_utf16le_without_bom_asks_for_utf8() {
    let text = fixture("tests/fixtures/certbot/http01-timeout.log");
    assert_wide_log("z3utf16le", &encode_utf16(&text, false, false), "UTF-16LE");
}

#[test]
fn z3_utf16be_without_bom_asks_for_utf8() {
    let text = fixture("tests/fixtures/certbot/http01-timeout.log");
    assert_wide_log("z3utf16be", &encode_utf16(&text, false, true), "UTF-16BE");
}

#[test]
fn z3_utf32le_with_bom_asks_for_utf8() {
    let text = fixture("tests/fixtures/certbot/http01-timeout.log");
    assert_wide_log(
        "z3utf32le-bom",
        &encode_utf32(&text, true, false),
        "UTF-32LE",
    );
}

#[test]
fn z3_utf32be_with_bom_asks_for_utf8() {
    let text = fixture("tests/fixtures/certbot/http01-timeout.log");
    assert_wide_log(
        "z3utf32be-bom",
        &encode_utf32(&text, true, true),
        "UTF-32BE",
    );
}

#[test]
fn z3_utf32le_without_bom_asks_for_utf8() {
    let text = fixture("tests/fixtures/certbot/http01-timeout.log");
    assert_wide_log("z3utf32le", &encode_utf32(&text, false, false), "UTF-32LE");
}

#[test]
fn z3_utf32be_without_bom_asks_for_utf8() {
    let text = fixture("tests/fixtures/certbot/http01-timeout.log");
    assert_wide_log("z3utf32be", &encode_utf32(&text, false, true), "UTF-32BE");
}

#[test]
fn z3_utf8_bom_keeps_the_timeout() {
    let text = fixture("tests/fixtures/certbot/http01-timeout.log");
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(text.as_bytes());
    let temp = TempDir::new("z3bom");
    let path = temp.write("bom.log", &bytes);
    let args = ["example.com", "--from-log", &arg(&path)];
    let report = check(&args);
    assert_has(&report, "LAYER2_HTTP01_TIMEOUT", 1);
    assert!(!report.stdout.contains("replaced "), "{}", report.stdout);
    let json = json_report(&args);
    assert_eq!(json.exit, 1, "{}", json.stdout);
    assert!(!json.stdout.contains("replaced "), "{}", json.stdout);
}

#[test]
fn z3_one_nul_byte_is_not_utf16() {
    let mut bytes = fixture("tests/fixtures/certbot/http01-timeout.log").into_bytes();
    bytes.insert(0, 0x00);
    let temp = TempDir::new("z3nul");
    let path = temp.write("nul.log", &bytes);
    let args = ["example.com", "--from-log", &arg(&path)];
    let report = check(&args);
    assert_has(&report, "LAYER2_HTTP01_TIMEOUT", 1);
    assert!(!report.stdout.contains("UTF-16"), "{}", report.stdout);
    assert!(!report.stdout.contains("UTF-32"), "{}", report.stdout);
    assert!(!report.stdout.contains("replaced "), "{}", report.stdout);
    let json = json_report(&args);
    assert_eq!(json.exit, 1, "{}", json.stdout);
    assert!(!json.stdout.contains("UTF-16"), "{}", json.stdout);
    assert!(!json.stdout.contains("UTF-32"), "{}", json.stdout);
}

#[test]
fn z3_loose_invalid_bytes_are_not_utf16() {
    let text = fixture("tests/fixtures/certbot/http01-timeout.log");
    let hint = text.find("Hint:").expect("hint line");
    let mut bytes = text.into_bytes();
    let at = hint + "Hint: ".len();
    bytes.insert(at, 0xE9);
    bytes.insert(at, b'x');
    bytes.insert(at, 0xFF);
    assert_lossy_timeout("z3loose", &bytes, 2);
}

#[test]
fn z3_invalid_byte_in_the_match_line_is_not_ok() {
    let mut bytes = fixture("tests/fixtures/certbot/http01-timeout.log").into_bytes();
    let hits = corrupt_phrase(&mut bytes, b"Timeout during connect");
    assert_eq!(hits, 2, "both the JSON detail and the summary detail");
    let temp = TempDir::new("z3match");
    let path = temp.write("match.log", &bytes);
    let path_arg = arg(&path);
    let mut owned_args = Vec::new();
    let args = with_current_certs(&path_arg, &mut owned_args);
    let report = check(&args);
    assert_has(&report, "INSUFFICIENT_EVIDENCE", 2);
    assert!(!report.stdout.contains("OK_NOT_DUE"), "{}", report.stdout);
    assert!(
        !report.stdout.contains("LAYER2_HTTP01_TIMEOUT"),
        "{}",
        report.stdout
    );
    let note = replaced_note(2);
    assert!(report.stdout.contains(&note), "{}\n{}", note, report.stdout);
    assert_no_replaced_text(&report.stdout);
    let json = json_report(&args);
    assert_eq!(json.exit, 2, "{}", json.stdout);
    assert!(!json.stdout.contains("OK_NOT_DUE"), "{}", json.stdout);
    assert!(json.stdout.contains(&note), "{}\n{}", note, json.stdout);
    assert_no_replaced_text(&json.stdout);
}

#[test]
fn z3_replacement_in_a_clean_log_is_not_ok() {
    let mut bytes =
        b"2026-09-28 03:12:44,512:INFO:certbot._internal.main:renewal skipped\n".to_vec();
    bytes.push(0xFF);
    let temp = TempDir::new("z3clean");
    let path = temp.write("clean.log", &bytes);
    let path_arg = arg(&path);
    let mut owned_args = Vec::new();
    let args = with_current_certs(&path_arg, &mut owned_args);
    let report = check(&args);
    assert_has(&report, "INSUFFICIENT_EVIDENCE", 2);
    assert!(!report.stdout.contains("OK_NOT_DUE"), "{}", report.stdout);
    let note = replaced_note(1);
    assert!(report.stdout.contains(&note), "{}\n{}", note, report.stdout);
    assert_no_replaced_text(&report.stdout);
    let json = json_report(&args);
    assert_eq!(json.exit, 2, "{}", json.stdout);
    assert!(!json.stdout.contains("OK_NOT_DUE"), "{}", json.stdout);
    assert!(json.stdout.contains(&note), "{}\n{}", note, json.stdout);
    assert_no_replaced_text(&json.stdout);
}

#[test]
fn z3_timer_and_cert_files_still_reject_invalid_utf8() {
    let temp = TempDir::new("z3strict");
    for (flag, rel, name) in [
        (
            "--from-timer-status",
            "tests/fixtures/timer/certbot-timer-enabled.txt",
            "timer.txt",
        ),
        (
            "--from-cert-disk",
            "tests/fixtures/certs/dates-current.txt",
            "disk.txt",
        ),
        (
            "--from-cert-live",
            "tests/fixtures/certs/dates-current.txt",
            "live.txt",
        ),
    ] {
        let mut bytes = fixture(rel).into_bytes();
        let mid = bytes.len() / 2;
        bytes[mid] = 0xFF;
        let path = temp.write(name, &bytes);
        let report = check(&["example.com", flag, &arg(&path)]);
        assert_has(&report, "INSUFFICIENT_EVIDENCE", 2);
        assert!(
            report.stdout.contains("cannot read"),
            "{flag}\n{}",
            report.stdout
        );
        assert!(
            report.stdout.contains("the file is not valid UTF-8"),
            "{flag}\n{}",
            report.stdout
        );
        assert!(
            !report.stdout.contains("other kind"),
            "{flag}\n{}",
            report.stdout
        );
        assert!(
            !report.stdout.contains("replaced "),
            "{flag}\n{}",
            report.stdout
        );
        assert!(
            !report.stdout.contains("UTF-16"),
            "{flag}\n{}",
            report.stdout
        );
        assert!(
            !report.stdout.contains("UTF-32"),
            "{flag}\n{}",
            report.stdout
        );
        assert!(
            !report.stdout.contains("OK_NOT_DUE"),
            "{flag}\n{}",
            report.stdout
        );
    }
}

#[test]
fn z4_crlf_matches_lf_code_and_exit() {
    let timeout = fixture("tests/fixtures/certbot/http01-timeout.log");
    let temp = TempDir::new("z4-timeout");
    let path = temp.write("timeout.log", &to_crlf(&timeout));
    let lf = check(&[
        "example.com",
        "--from-log",
        "tests/fixtures/certbot/http01-timeout.log",
    ]);
    let crlf = check(&["example.com", "--from-log", &arg(&path)]);
    assert_has(&lf, "LAYER2_HTTP01_TIMEOUT", 1);
    assert_has(&crlf, "LAYER2_HTTP01_TIMEOUT", 1);

    let dns = fixture("tests/fixtures/certbot/dns01-no-txt-record.log");
    let path = temp.write("dns.log", &to_crlf(&dns));
    let lf = check(&[
        "example.com",
        "--from-log",
        "tests/fixtures/certbot/dns01-no-txt-record.log",
    ]);
    let crlf = check(&["example.com", "--from-log", &arg(&path)]);
    assert_has(&lf, "LAYER2_DNS01_TXT", 1);
    assert_has(&crlf, "LAYER2_DNS01_TXT", 1);

    let disk = fixture("tests/fixtures/certs/dates-disk-renewed.txt");
    let live = fixture("tests/fixtures/certs/dates-live-old.txt");
    let disk_path = temp.write("disk.txt", &to_crlf(&disk));
    let live_path = temp.write("live.txt", &to_crlf(&live));
    let lf = check(&[
        "example.com",
        "--from-cert-disk",
        "tests/fixtures/certs/dates-disk-renewed.txt",
        "--from-cert-live",
        "tests/fixtures/certs/dates-live-old.txt",
    ]);
    let crlf = check(&[
        "example.com",
        "--from-cert-disk",
        &arg(&disk_path),
        "--from-cert-live",
        &arg(&live_path),
    ]);
    assert_has(&lf, "LAYER3_NO_RELOAD", 1);
    assert_has(&crlf, "LAYER3_NO_RELOAD", 1);

    let timer = fixture("tests/fixtures/timer/certbot-timer-disabled.txt");
    let timer_path = temp.write("timer.txt", &to_crlf(&timer));
    let lf = check(&[
        "example.com",
        "--from-timer-status",
        "tests/fixtures/timer/certbot-timer-disabled.txt",
    ]);
    let crlf = check(&["example.com", "--from-timer-status", &arg(&timer_path)]);
    assert_has(&lf, "LAYER1_TIMER_DISABLED", 1);
    assert_has(&crlf, "LAYER1_TIMER_DISABLED", 1);
}

#[cfg(target_os = "linux")]
fn time_field<'a>(stderr: &'a str, label: &str) -> &'a str {
    stderr
        .lines()
        .find_map(|line| {
            let line = line.trim();
            let rest = line.strip_prefix(label)?;
            Some(rest.trim().trim_start_matches(':').trim())
        })
        .unwrap_or_else(|| panic!("field {label:?} is not in the time output:\n{stderr}"))
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "heavy: run with cargo test --test robustness -- --ignored z5"]
fn z5_hundred_mb_log_under_rss_ceiling() {
    let temp = TempDir::new("z5-log");
    let path = temp.dir.join("huge.log");
    {
        let file = std::fs::File::create(&path).expect("huge.log");
        let mut writer = std::io::BufWriter::new(file);
        let filler = b"2026-09-28 03:12:44,600:INFO:certbot._internal.auth_handler:Challenge failed for domain example.com\n";
        let mut written = 0usize;
        while written < HUNDRED_MB {
            writer.write_all(filler).expect("write filler");
            written += filler.len();
        }
        let real = fixture("tests/fixtures/certbot/http01-timeout.log");
        writer
            .write_all(real.as_bytes())
            .expect("write the real error");
        writer.flush().expect("flush");
    }
    let binary = env!("CARGO_BIN_EXE_acme-renew-doctor");
    let output = Command::new("/usr/bin/time")
        .args(["-v", binary, "example.com", "--from-log", &arg(&path)])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env_remove("ACME_RENEW_DOCTOR_NOW")
        .env("ACME_RENEW_DOCTOR_NOW", NOW)
        .output()
        .expect("/usr/bin/time");
    let exit = output.status.code().unwrap_or_else(|| {
        panic!(
            "time/tool ended on a signal\n{}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let stdout = String::from_utf8(output.stdout).expect("stdout utf-8");
    eprintln!("Z5_TIME_BEGIN\n{stderr}Z5_TIME_END");
    assert!(!stderr.contains("panicked"), "{stderr}");
    assert!(!stdout.contains("panicked"), "{stdout}");
    assert_eq!(exit, 1, "{stderr}\n{stdout}");
    assert!(stdout.contains("LAYER2_HTTP01_TIMEOUT"), "{stdout}");
    assert!(!stdout.contains("OK_NOT_DUE"), "{stdout}");
    let rss: u64 = time_field(&stderr, "Maximum resident set size (kbytes)")
        .parse()
        .unwrap_or_else(|err| panic!("rss: {err}\n{stderr}"));
    let elapsed = time_field(&stderr, "Elapsed (wall clock) time (h:mm:ss or m:ss)");
    eprintln!("Z5_MEASURE rss_kb={rss} elapsed={elapsed}");
    assert!(
        rss < RSS_CEILING_KB,
        "Maximum resident set size {rss} kB is not under {RSS_CEILING_KB} kB\n{stderr}"
    );

    let json = check(&["example.com", "--from-log", &arg(&path)]);
    assert_has(&json, "LAYER2_HTTP01_TIMEOUT", 1);
    std::fs::remove_file(&path).expect("remove huge.log");
}

#[cfg(unix)]
#[test]
fn z5_stdin_exactly_fifty_mb_of_zeros() {
    // Stdin stays a pipe with no writer and no reader on our side. Streaming
    // 50 MiB of zeros would block once the tool stops reading the pipe.
    assert_refused_input("--from-log", OsStr::new("/dev/stdin"), NOT_REGULAR, true);
}

fn joined_logs(first: &str, second: &str) -> String {
    let mut out = first.to_string();
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(second);
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

const Z6_STAMP: &str = "2026-09-28 04:05:11,100";
const Z6_TIMEOUT_DETAIL: &str = "203.0.113.10: Fetching http://example.com/.well-known/acme-challenge/tok: Timeout during connect (likely firewall problem)";
const Z6_REFUSED_DETAIL: &str =
    "203.0.113.10: Fetching http://example.com/.well-known/acme-challenge/tok: Connection refused";

fn connection_json_block(stamp: &str, detail: &str) -> String {
    format!(
        "{stamp}:DEBUG:acme.client:Received response:\n\
         {{\"type\":\"urn:ietf:params:acme:error:connection\",\"detail\":\"{detail}\",\"status\":400}}\n"
    )
}

fn summary_block(detail: &str) -> String {
    format!("  Domain: example.com\n  Type:   connection\n  Detail: {detail}\n")
}

#[test]
fn z6_newer_refused_block_at_bottom_wins() {
    let timeout = fixture("tests/fixtures/certbot/http01-timeout.log");
    let refused = fixture("tests/fixtures/certbot/http01-connection-refused.log");
    assert!(timeout.contains("2026-09-28 03:12:44"), "timeout timestamp");
    assert!(refused.contains("2026-09-28 04:05:11"), "refused timestamp");
    let text = joined_logs(&timeout, &refused);
    let temp = TempDir::new("z6-new");
    let path = temp.write("newer-last.log", text.as_bytes());
    let report = check(&["example.com", "--from-log", &arg(&path)]);
    assert_has(&report, "LAYER2_HTTP01_REFUSED", 1);
    assert!(
        !report.stdout.contains("LAYER2_HTTP01_TIMEOUT"),
        "the older timeout must not be the code\n{}",
        report.stdout
    );
}

#[test]
fn z6_older_timeout_at_bottom_must_not_win() {
    let timeout = fixture("tests/fixtures/certbot/http01-timeout.log");
    let refused = fixture("tests/fixtures/certbot/http01-connection-refused.log");
    assert!(timeout.contains("2026-09-28 03:12:44"));
    assert!(refused.contains("2026-09-28 04:05:11"));
    let text = joined_logs(&refused, &timeout);
    let temp = TempDir::new("z6-old");
    let path = temp.write("older-last.log", text.as_bytes());
    let report = check(&["example.com", "--from-log", &arg(&path)]);
    assert!(
        report.stdout.contains("LAYER2_HTTP01_REFUSED"),
        "the error with the later timestamp (connection refused, 04:05) must win\n{}",
        report.stdout
    );
    assert!(
        !report.stdout.contains("LAYER2_HTTP01_TIMEOUT"),
        "the older timeout (03:12) must not be the current code\n{}",
        report.stdout
    );
}

#[test]
fn z6_equal_timestamps_bottom_line_wins() {
    assert_eq!(Z6_STAMP.len(), 23, "FILE_FMT timestamp is 23 characters");
    let text = joined_logs(
        &connection_json_block(Z6_STAMP, Z6_REFUSED_DETAIL),
        &connection_json_block(Z6_STAMP, Z6_TIMEOUT_DETAIL),
    );
    let temp = TempDir::new("z6-equal");
    let path = temp.write("equal-stamp.log", text.as_bytes());
    let report = check(&["example.com", "--from-log", &arg(&path)]);
    assert_has(&report, "LAYER2_HTTP01_TIMEOUT", 1);
    assert!(
        !report.stdout.contains("LAYER2_HTTP01_REFUSED"),
        "with equal timestamps the bottom line (timeout) must win\n{}",
        report.stdout
    );
}

#[test]
fn z6_no_timestamps_bottom_line_wins() {
    let text = joined_logs(
        &summary_block(Z6_REFUSED_DETAIL),
        &summary_block(Z6_TIMEOUT_DETAIL),
    );
    assert!(!text.contains("2026-"), "this log should have no timestamp");
    let temp = TempDir::new("z6-none");
    let path = temp.write("no-stamp.log", text.as_bytes());
    let report = check(&[
        "example.com",
        "--client",
        "certbot",
        "--from-log",
        &arg(&path),
    ]);
    assert_has(&report, "LAYER2_HTTP01_TIMEOUT", 1);
    assert!(
        !report.stdout.contains("LAYER2_HTTP01_REFUSED"),
        "with no timestamps the bottom line (timeout) must win\n{}",
        report.stdout
    );
}

#[test]
fn z7_second_domain_still_sees_the_other_error() {
    let detail = "203.0.113.10: Fetching http://a.example.com/.well-known/acme-challenge/tok: Timeout during connect (likely firewall problem)";
    let log = format!(
        "2026-09-28 03:12:44,512:DEBUG:acme.client:Received response:\n\
{{\n  \"identifier\": {{\"type\": \"dns\", \"value\": \"a.example.com\"}},\n  \
\"status\": \"invalid\",\n  \"challenges\": [{{\"type\": \"http-01\", \"error\": {{\n    \
\"type\": \"urn:ietf:params:acme:error:connection\",\n    \
\"detail\": \"{detail_json}\"\n  }}}}]\n}}\n\
2026-09-28 05:00:00,100:INFO:certbot._internal.main:Congratulations! Your certificate and chain have been saved at: /etc/letsencrypt/live/b.example.com/fullchain.pem\n  \
Domain: a.example.com\n  \
Type:   connection\n  \
Detail: {detail}\n",
        detail_json = embed_json(detail),
    );
    let temp = TempDir::new("z7");
    let path = temp.write("two-domains.log", log.as_bytes());
    let log_arg = arg(&path);

    let for_b = check(&["b.example.com", "--from-log", &log_arg]);
    assert_has(&for_b, "LAYER2_HTTP01_TIMEOUT", 1);
    assert!(
        for_b.stdout.contains("target: b.example.com"),
        "{}",
        for_b.stdout
    );
    assert!(
        for_b.stdout.contains("a.example.com"),
        "the error for a.example.com stays visible for b.example.com\n{}",
        for_b.stdout
    );

    let for_a = check(&["a.example.com", "--from-log", &log_arg]);
    assert_has(&for_a, "LAYER2_HTTP01_TIMEOUT", 1);
    assert!(
        for_a.stdout.contains("target: a.example.com"),
        "{}",
        for_a.stdout
    );
}

fn violations_empty(stdout: &str) {
    let violations = acme_renew_doctor::safe::output_violations(stdout);
    assert!(violations.is_empty(), "{violations:?}\n{stdout}");
}

/// Mirrors the shape check in `render::report_notes`: a domain made only of
/// hostname bytes (ASCII alnum, '-', '.') is invalid in shape, not unsafe for
/// a shell; anything else (shell metacharacters, control bytes, non-ASCII) is
/// the unsafe-characters case.
fn expects_invalid_domain_note(raw: &str) -> bool {
    !raw.is_empty()
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.')
}

fn assert_your_domain(stdout: &str, raw: &str) {
    let commands = command_lines(stdout);
    assert!(
        commands.iter().any(|line| line.contains("YOUR_DOMAIN")),
        "SAFE checks should use YOUR_DOMAIN\n{stdout}"
    );
    for line in &commands {
        assert!(
            !line.contains(raw),
            "raw domain name in a SAFE check: {line}"
        );
    }
    let (expected, other) = if expects_invalid_domain_note(raw) {
        (
            "note: the domain is not a valid hostname",
            "note: the domain contains characters that are unsafe in a shell command",
        )
    } else {
        (
            "note: the domain contains characters that are unsafe in a shell command",
            "note: the domain is not a valid hostname",
        )
    };
    assert!(stdout.contains(expected), "{stdout}");
    assert!(!stdout.contains(other), "{stdout}");
    assert!(
        !stdout.contains(raw),
        "raw domain name leaks in the output\n{stdout}"
    );
}

#[test]
fn z8_weird_domains_and_safe_checks() {
    let long = format!("{}.example.com", "a".repeat(10_000 - ".example.com".len()));
    assert_eq!(long.chars().count(), 10_000);
    let cases = [
        "a.com; rm -rf /",
        "$(id).a.com",
        "`id`.a.com",
        "-oProxyCommand=x",
        "\u{1b}[31mred.example.com",
        "foo\nbar.example.com",
        long.as_str(),
        "bücher.de",
        "*.example.com",
    ];

    for domain in cases {
        let temp = TempDir::new("z8");
        let path = temp.write("domain.log", log_with_domain(domain).as_bytes());
        let args = vec![
            "--from-log".to_string(),
            arg(&path),
            "--".to_string(),
            domain.to_string(),
        ];
        let report = run_owned(&args, NOW, &[]);
        assert_no_panic(&report);
        assert_not_false_ok(&report);
        assert_exit_matches_decision(&report.stdout, report.exit);
        assert_has(&report, "LAYER2_HTTP01_TIMEOUT", 1);
        assert!(
            !report.stdout.as_bytes().contains(&0x1B),
            "raw ESC in the human output for {domain:?}\n{}",
            report.stdout
        );
        assert!(!report.stderr.as_bytes().contains(&0x1B), "ESC on stderr");
        violations_empty(&report.stdout);
        assert_your_domain(&report.stdout, domain);

        let mut json_args = vec!["--json".to_string()];
        json_args.extend(args);
        let json = run_owned(&json_args, NOW, &[]);
        assert_no_panic(&json);
        assert_eq!(json.exit, 1, "{}", json.stdout);
        assert_json_document(&json.stdout);
        assert!(!json.stdout.as_bytes().contains(&0x1B), "raw ESC in JSON");
        violations_empty(&json.stdout);
        assert!(
            json.stdout.contains("\"domain\": \"YOUR_DOMAIN\""),
            "{}",
            json.stdout
        );
        assert!(!json.stdout.contains(domain), "{}", json.stdout);
    }

    let puny = "xn--bcher-kva.de";
    let temp = TempDir::new("z8-puny");
    let path = temp.write("puny.log", log_with_domain(puny).as_bytes());
    let report = check(&["--from-log", &arg(&path), "--", puny]);
    assert_has(&report, "LAYER2_HTTP01_TIMEOUT", 1);
    violations_empty(&report.stdout);
    assert!(
        command_lines(&report.stdout)
            .iter()
            .any(|line| line.contains(puny)),
        "punycode should be a safe domain in the SAFE checks\n{}",
        report.stdout
    );
    assert!(
        !report.stdout.contains("YOUR_DOMAIN"),
        "xn--bcher-kva.de became YOUR_DOMAIN\n{}",
        report.stdout
    );
    assert!(!report.stdout.as_bytes().contains(&0x1B));

    let proxy = temp.write("proxy.log", log_with_domain("-oProxyCommand=x").as_bytes());
    let rejected = run_owned(
        &owned(&["-oProxyCommand=x", "--from-log", &arg(&proxy)]),
        NOW,
        &[],
    );
    assert_no_panic(&rejected);
    assert_eq!(rejected.exit, 3, "stderr:\n{}", rejected.stderr);
    assert_not_false_ok(&rejected);
}

#[test]
fn z9_json_special_characters_round_trip() {
    let special = "say \"hi\" \\path\t\u{0001}\u{2028}";
    let detail = format!(
        "{special}/.well-known/acme-challenge/tok: Timeout during connect (likely firewall problem)"
    );
    let domain = format!("ex{special}.com");
    let log = format!(
        "2026-09-28 03:12:44,512:DEBUG:acme.client:Received response:\n\
{{\n  \"identifier\": {{\"type\": \"dns\", \"value\": \"{domain_json}\"}},\n  \
\"status\": \"invalid\",\n  \"challenges\": [{{\"type\": \"http-01\", \"error\": {{\n    \
\"type\": \"urn:ietf:params:acme:error:connection\",\n    \
\"detail\": \"{detail_json}\"\n  }}}}]\n}}\n  \
Domain: {domain}\n  \
Type:   connection\n  \
Detail: {detail}\n",
        domain_json = embed_json(&domain),
        detail_json = embed_json(&detail),
    );
    let temp = TempDir::new("z9");
    let path = temp.write("special.log", log.as_bytes());
    let args = vec![
        "--json".to_string(),
        "--from-log".to_string(),
        arg(&path),
        "--".to_string(),
        domain.clone(),
    ];
    let report = run_owned(&args, NOW, &[]);
    assert_no_panic(&report);
    assert_not_false_ok(&report);
    assert_eq!(report.exit, 1, "{}", report.stdout);
    assert!(
        report.stdout.contains("LAYER2_HTTP01_TIMEOUT"),
        "{}",
        report.stdout
    );
    assert_json_document(&report.stdout);

    let script = r#"
import json, sys
data = json.load(sys.stdin)
domain = data["input"]["domain"] or ""
sys.stdout.buffer.write(domain.encode())
sys.stdout.buffer.write(b"\0")
for finding in data["findings"]:
    for evidence in finding["evidence"]:
        sys.stdout.buffer.write(evidence["text"].encode())
        sys.stdout.buffer.write(b"\0")
"#;
    let mut child = Command::new("python3")
        .args(["-c", script])
        // Windows Python reads stdin as the ANSI code page unless told otherwise.
        .env("PYTHONUTF8", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("python3");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        stdin
            .write_all(report.stdout.as_bytes())
            .expect("json to python");
    }
    let extracted = child.wait_with_output().expect("python extract");
    assert!(
        extracted.status.success(),
        "{}",
        String::from_utf8_lossy(&extracted.stderr)
    );
    let mut parts = extracted.stdout.split(|byte| *byte == 0);
    let got_domain =
        String::from_utf8(parts.next().expect("domain").to_vec()).expect("domain utf-8");
    assert_eq!(got_domain, "YOUR_DOMAIN");
    let texts: Vec<String> = parts
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8(part.to_vec()).expect("evidence utf-8"))
        .collect();
    assert!(
        texts.iter().any(|text| {
            text.strip_prefix("line ")
                .and_then(|rest| rest.find(": ").map(|index| &rest[index + 2..]))
                .is_some_and(|rest| rest == detail)
        }),
        "detail does not come back\nexpected: {detail:?}\ngot: {texts:?}"
    );
}

#[test]
fn z10_acme_sh_log_is_never_layer2() {
    let log = "tests/fixtures/acme-sh/verify-error-dns01.log";
    let auto = check(&["example.com", "--from-log", log, "--client", "auto"]);
    assert_has(&auto, "CLIENT_UNKNOWN", 3);
    assert!(!auto.stdout.contains("LAYER2_"), "{}", auto.stdout);

    let acme = check(&["example.com", "--from-log", log, "--client", "acme.sh"]);
    assert_has(&acme, "INSUFFICIENT_EVIDENCE", 2);
    assert!(
        acme.stdout.contains("acme.sh logs are not parsed yet"),
        "{}",
        acme.stdout
    );
    assert!(!acme.stdout.contains("LAYER2_"), "{}", acme.stdout);
}

#[test]
fn z11_fixtures_and_dutch_month_name() {
    let env = [("LC_ALL", "nl_NL.UTF-8"), ("LANG", "nl_NL.UTF-8")];
    let timer_args = [
        "example.com",
        "--from-timer-status",
        "tests/fixtures/timer/certbot-timer-disabled.txt",
    ];
    let plain = check(&timer_args);
    let dutch_env = check_in(&timer_args, NOW, &env, false);
    assert_has(&plain, "LAYER1_TIMER_DISABLED", 1);
    assert_has(&dutch_env, "LAYER1_TIMER_DISABLED", 1);

    let cert_args = [
        "example.com",
        "--from-cert-disk",
        "tests/fixtures/certs/dates-disk-renewed.txt",
        "--from-cert-live",
        "tests/fixtures/certs/dates-live-old.txt",
    ];
    let plain = check(&cert_args);
    let dutch_env = check_in(&cert_args, NOW, &env, false);
    assert_has(&plain, "LAYER3_NO_RELOAD", 1);
    assert_has(&dutch_env, "LAYER3_NO_RELOAD", 1);

    let temp = TempDir::new("z11");
    let path = temp.write(
        "may.txt",
        b"notBefore=Mei  4 11:04:38 2034 GMT\nnotAfter=Mei  4 11:04:38 2035 GMT\n",
    );
    let report = check_in(
        &["example.com", "--from-cert-disk", &arg(&path)],
        NOW,
        &env,
        false,
    );
    assert_has(&report, "INSUFFICIENT_EVIDENCE", 2);
    assert!(
        report.stdout.contains("certificate dates not recognised"),
        "{}",
        report.stdout
    );
}

fn cert_pair(temp: &TempDir, name: &str, not_after: &str) -> (PathBuf, PathBuf) {
    let body = format!("notBefore=Jan  1 00:00:00 2019 GMT\nnotAfter={not_after}\n");
    let disk = temp.write(&format!("{name}-disk.txt"), body.as_bytes());
    let live = temp.write(&format!("{name}-live.txt"), body.as_bytes());
    (disk, live)
}

#[test]
fn z12_expired_certificate_is_not_ok_not_due() {
    let temp = TempDir::new("z12-expired");
    let (disk, live) = cert_pair(&temp, "expired", "Jan  1 00:00:00 2020 GMT");
    let report = check(&[
        "example.com",
        "--from-timer-status",
        "tests/fixtures/timer/certbot-timer-enabled.txt",
        "--from-cert-disk",
        &arg(&disk),
        "--from-cert-live",
        &arg(&live),
    ]);
    assert_has(&report, "INSUFFICIENT_EVIDENCE", 2);
    assert!(!report.stdout.contains("LAYER3_"), "{}", report.stdout);
}

#[test]
fn z12_leap_day_and_year_2051_are_accepted() {
    let temp = TempDir::new("z12-leap");
    let (disk, live) = cert_pair(&temp, "leap", "Feb 29 12:00:00 2028 GMT");
    let report = check_ok(&[
        "example.com",
        "--from-timer-status",
        "tests/fixtures/timer/certbot-timer-enabled.txt",
        "--from-cert-disk",
        &arg(&disk),
        "--from-cert-live",
        &arg(&live),
    ]);
    assert!(
        report.stdout.contains("notAfter=Feb 29 12:00:00 2028 GMT"),
        "{}",
        report.stdout
    );

    let (disk, live) = cert_pair(&temp, "far", "Jan  1 00:00:00 2051 GMT");
    let report = check_ok(&[
        "example.com",
        "--from-timer-status",
        "tests/fixtures/timer/certbot-timer-enabled.txt",
        "--from-cert-disk",
        &arg(&disk),
        "--from-cert-live",
        &arg(&live),
    ]);
    assert!(
        report.stdout.contains("notAfter=Jan  1 00:00:00 2051 GMT"),
        "{}",
        report.stdout
    );
}

#[test]
fn z12_feb_30_and_non_gmt_are_not_recognised() {
    let temp = TempDir::new("z12-bad-date");
    for not_after in [
        "Feb 30 12:00:00 2028 GMT",
        "Jun  4 11:04:38 2035 UTC",
        "Jun  4 11:04:38 2035 CEST",
    ] {
        let path = temp.write(
            &format!("date-{}.txt", not_after.len()),
            format!("notAfter={not_after}\n").as_bytes(),
        );
        let report = check(&["example.com", "--from-cert-disk", &arg(&path)]);
        assert_has(&report, "INSUFFICIENT_EVIDENCE", 2);
        assert!(
            report.stdout.contains("certificate dates not recognised"),
            "{not_after}\n{}",
            report.stdout
        );
    }
}

fn assert_now_rejected(value: &str) {
    let report = run_owned(&owned(&["example.com", "--json"]), value, &[]);
    assert_no_panic(&report);
    assert_eq!(report.exit, 3, "now={value:?} stderr:\n{}", report.stderr);
    assert!(
        report.stderr.contains("ACME_RENEW_DOCTOR_NOW"),
        "{}",
        report.stderr
    );
    assert!(report.stdout.is_empty(), "now={value:?}\n{}", report.stdout);
    assert!(!report.stdout.contains("OK_NOT_DUE"));
}

#[test]
fn unrelated_timer_does_not_hide_a_disabled_certbot_timer() {
    let temp = TempDir::new("timer-hide");
    let body = "\
Id=apt-daily.timer
LoadState=loaded
ActiveState=active
UnitFileState=enabled

Id=certbot.timer
LoadState=loaded
ActiveState=inactive
UnitFileState=disabled
";
    let path = temp.write("later.txt", body.as_bytes());
    let report = check(&[
        "example.com",
        "--from-cert-disk",
        "tests/fixtures/certs/dates-current.txt",
        "--from-cert-live",
        "tests/fixtures/certs/dates-current.txt",
        "--from-timer-status",
        &arg(&path),
    ]);
    assert_has(&report, "LAYER1_TIMER_DISABLED", 1);
    assert!(!report.stdout.contains("OK_NOT_DUE"), "{}", report.stdout);
}

#[test]
fn timer_file_without_a_certbot_unit_is_not_ok() {
    let temp = TempDir::new("timer-missing");
    let body = "\
Id=apt-daily.timer
LoadState=loaded
ActiveState=active
UnitFileState=enabled
";
    let path = temp.write("other.txt", body.as_bytes());
    let report = check(&[
        "example.com",
        "--from-cert-disk",
        "tests/fixtures/certs/dates-current.txt",
        "--from-cert-live",
        "tests/fixtures/certs/dates-current.txt",
        "--from-timer-status",
        &arg(&path),
    ]);
    assert_has(&report, "INSUFFICIENT_EVIDENCE", 2);
    assert!(
        report
            .stdout
            .contains("no certbot.timer, certbot.service or snap.certbot.renew.timer"),
        "{}",
        report.stdout
    );
}

#[test]
fn contradictory_certbot_timers_are_not_ok() {
    let temp = TempDir::new("timer-ambiguous");
    let body = "\
Id=certbot.timer
LoadState=loaded
ActiveState=active
UnitFileState=enabled

Id=certbot.timer
LoadState=loaded
ActiveState=inactive
UnitFileState=disabled
";
    let path = temp.write("both.txt", body.as_bytes());
    let report = check(&[
        "example.com",
        "--from-cert-disk",
        "tests/fixtures/certs/dates-current.txt",
        "--from-cert-live",
        "tests/fixtures/certs/dates-current.txt",
        "--from-timer-status",
        &arg(&path),
    ]);
    assert_has(&report, "INSUFFICIENT_EVIDENCE", 2);
    assert!(report.stdout.contains("ambiguous"), "{}", report.stdout);
    assert!(!report.stdout.contains("LAYER1_"), "{}", report.stdout);
    assert!(!report.stdout.contains("OK_NOT_DUE"), "{}", report.stdout);
}

#[test]
fn detail_before_type_is_http01_timeout() {
    let detail = "http://example.com/.well-known/acme-challenge/test: Timeout during connect (likely firewall problem)";
    let log = format!(
        "2026-10-06 03:00:00,000:DEBUG:acme.client:Received response:\n{{\"detail\": \"{detail}\", \"type\": \"urn:ietf:params:acme:error:connection\"}}\n"
    );
    let temp = TempDir::new("detail-first");
    let path = temp.write("detail-first.log", log.as_bytes());
    let report = check(&["example.com", "--from-log", &arg(&path)]);
    assert_has(&report, "LAYER2_HTTP01_TIMEOUT", 1);
}

#[test]
fn conflicting_json_type_is_not_a_layer_or_ok() {
    let detail = "http://example.com/.well-known/acme-challenge/test: Timeout during connect (likely firewall problem)";
    let log = format!(
        "2026-10-06 03:00:00,000:DEBUG:acme.client:Received response:\n{{\"type\": \"urn:ietf:params:acme:error:connection\", \"detail\": \"{detail}\", \"type\": \"urn:ietf:params:acme:error:malformed\"}}\n"
    );
    let temp = TempDir::new("json-type-conflict");
    let path = temp.write("conflict.log", log.as_bytes());
    let report = check(&[
        "example.com",
        "--from-log",
        &arg(&path),
        "--from-cert-disk",
        "tests/fixtures/certs/dates-current.txt",
        "--from-cert-live",
        "tests/fixtures/certs/dates-current.txt",
    ]);
    assert_has(&report, "INSUFFICIENT_EVIDENCE", 2);
    assert!(
        report.stdout.contains(
            "ACME JSON is ambiguous (the same object has type or detail more than once with different values)"
        ),
        "{}",
        report.stdout
    );
    assert!(!report.stdout.contains("LAYER1_"), "{}", report.stdout);
    assert!(!report.stdout.contains("LAYER2_"), "{}", report.stdout);
    assert!(!report.stdout.contains("LAYER3_"), "{}", report.stdout);
    assert!(!report.stdout.contains("OK_NOT_DUE"), "{}", report.stdout);
}

#[test]
fn invalid_certificate_year_is_not_ok() {
    let temp = TempDir::new("bad-year");
    for (name, not_after) in [
        ("min", "Jan  1 00:00:00 -2147483648 GMT"),
        ("early", "Jan  1 00:00:00 1969 GMT"),
        ("late", "Jan  1 00:00:00 10000 GMT"),
        (
            "clash",
            "Jan  1 00:00:00 2030 GMT\nnotAfter=Jun  1 00:00:00 2031 GMT",
        ),
    ] {
        let (disk, live) = cert_pair(&temp, name, not_after);
        let report = check(&[
            "example.com",
            "--from-cert-disk",
            &arg(&disk),
            "--from-cert-live",
            &arg(&live),
        ]);
        assert_has(&report, "INSUFFICIENT_EVIDENCE", 2);
        assert!(
            report.stdout.contains("certificate dates not recognised"),
            "{name}\n{}",
            report.stdout
        );
        assert!(
            !report.stdout.contains("OK_NOT_DUE"),
            "{name}\n{}",
            report.stdout
        );
    }
}

#[test]
fn z12_invalid_now_values() {
    assert_now_rejected("");
    assert_now_rejected("abc");
    assert_now_rejected("99999999999999999999");
    assert_now_rejected("-1");
    assert_now_rejected("-9223372036854775808");
    assert_now_rejected("9223372036854775807");
    assert_now_rejected("253402300800");

    for now in ["0", "253402300799"] {
        let accepted = check_in(&["example.com"], now, &[], false);
        assert_has(&accepted, "INSUFFICIENT_EVIDENCE", 2);
        assert!(
            !accepted.stderr.contains("ACME_RENEW_DOCTOR_NOW"),
            "now {now} was rejected\n{}",
            accepted.stderr
        );
    }
}

fn without_summary_lines(text: &str) -> String {
    let mut out = String::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("Domain:")
            || trimmed.starts_with("Identifier:")
            || trimmed.starts_with("Type:")
            || trimmed.starts_with("Detail:")
        {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

#[test]
fn z13_old_three_space_notes_and_future_identifier() {
    let e5 = fixture("tests/fixtures/real/e5-136973-dns01.log");
    let mut old = without_summary_lines(&e5);
    old.push_str(
        "IMPORTANT NOTES:\n - The following errors were reported by the server:\n\n   Domain: example.com\n   Type:   unauthorized\n   Detail: No TXT record found at _acme-challenge.example.com\n",
    );
    assert!(old.contains("IMPORTANT NOTES:"));
    assert!(old.contains("\n   Domain: example.com\n"));
    assert!(!old.contains("\n  Domain:"));
    let temp = TempDir::new("z13");
    let path = temp.write("old-notes.log", old.as_bytes());
    let report = check(&["example.com", "--from-log", &arg(&path)]);
    assert_has(&report, "LAYER2_DNS01_TXT", 1);

    let summary_only = "\
2020-10-27 21:23:27,261:DEBUG:certbot.reporter:Reporting to user: The following errors were reported by the server:
IMPORTANT NOTES:
 - The following errors were reported by the server:

   Domain: example.com
   Type:   unauthorized
   Detail: No TXT record found at _acme-challenge.example.com
";
    let path = temp.write("old-summary-only.log", summary_only.as_bytes());
    let report = check(&["example.com", "--from-log", &arg(&path)]);
    assert_has(&report, "INSUFFICIENT_EVIDENCE", 2);
    assert!(
        report.stdout.contains("log read, no ACME errors found"),
        "{}",
        report.stdout
    );
    assert!(!report.stdout.contains("LAYER2_"), "{}", report.stdout);

    let timeout = fixture("tests/fixtures/certbot/http01-timeout.log");
    let future = timeout
        .lines()
        .map(|line| {
            if let Some(rest) = line.strip_prefix("  Domain:") {
                format!("    Identifier:{rest}")
            } else if let Some(rest) = line.strip_prefix("  Type:") {
                format!("    Type:{rest}")
            } else if let Some(rest) = line.strip_prefix("  Detail:") {
                format!("    Detail:{rest}")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(future.contains("\n    Identifier: example.com\n"));
    assert!(!future.contains("\n  Domain:"));
    let path = temp.write("future.log", future.as_bytes());
    let report = check(&["example.com", "--from-log", &arg(&path)]);
    assert_has(&report, "LAYER2_HTTP01_TIMEOUT", 1);

    let future_only = "\
2026-09-28 03:12:44,602:DEBUG:certbot._internal.display.obj:Notifying user:
    Identifier: example.com
    Type:   connection
    Detail: 203.0.113.10: Fetching http://example.com/.well-known/acme-challenge/timeouttoken0000000000000000001: Timeout during connect (likely firewall problem)
";
    let path = temp.write("future-only.log", future_only.as_bytes());
    let report = check(&["example.com", "--from-log", &arg(&path)]);
    assert_has(&report, "INSUFFICIENT_EVIDENCE", 2);
    assert!(!report.stdout.contains("LAYER2_"), "{}", report.stdout);
}

fn run_bounded(args: &[OsString], hold_stdin: bool) -> ReportOut {
    let mut command = Command::new(env!("CARGO_BIN_EXE_acme-renew-doctor"));
    command
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env_remove("ACME_RENEW_DOCTOR_NOW")
        .env("ACME_RENEW_DOCTOR_NOW", NOW)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if hold_stdin {
        command.stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }
    let mut child = command.spawn().expect("spawn acme-renew-doctor");
    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();
    let stdout_task = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut pipe) = stdout_pipe {
            let _ = pipe.read_to_end(&mut buf);
        }
        buf
    });
    let stderr_task = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut pipe) = stderr_pipe {
            let _ = pipe.read_to_end(&mut buf);
        }
        buf
    });
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() >= Duration::from_secs(2) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_task.join();
                let _ = stderr_task.join();
                panic!("acme-renew-doctor was still running after 2s: {args:?}");
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(err) => panic!("wait failed: {err}"),
        }
    };
    let elapsed = started.elapsed();
    let stdout = stdout_task.join().expect("stdout thread");
    let stderr = stderr_task.join().expect("stderr thread");
    let stdout =
        String::from_utf8(stdout).unwrap_or_else(|err| panic!("stdout is not utf-8: {err}"));
    let stderr =
        String::from_utf8(stderr).unwrap_or_else(|err| panic!("stderr is not utf-8: {err}"));
    let exit = status.code().unwrap_or_else(|| {
        panic!("process ended on a signal\nstderr:\n{stderr}\nstdout:\n{stdout}")
    });
    assert!(
        elapsed < Duration::from_secs(1),
        "exited after {elapsed:?}, which is not within one second\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    ReportOut {
        exit,
        stdout,
        stderr,
    }
}

fn assert_refused_input(flag: &str, path: &OsStr, needle: &str, hold_stdin: bool) {
    for json in [false, true] {
        let mut args = Vec::new();
        if json {
            args.push(OsString::from("--json"));
        }
        args.push(OsString::from("example.com"));
        args.push(OsString::from(flag));
        args.push(path.to_os_string());
        let report = run_bounded(&args, hold_stdin);
        assert_no_panic(&report);
        assert_eq!(
            report.exit, 2,
            "{flag} json={json}\nstderr:\n{}\nstdout:\n{}",
            report.stderr, report.stdout
        );
        assert!(
            report.stderr.is_empty(),
            "{flag} stderr:\n{}",
            report.stderr
        );
        assert!(
            report.stdout.contains(needle),
            "{flag} json={json} missing {needle}\n{}",
            report.stdout
        );
        assert!(
            !report.stdout.contains("other kind"),
            "{flag} json={json}\n{}",
            report.stdout
        );
        assert!(
            !report.stdout.contains("LAYER1_PERMISSION"),
            "{flag}\n{}",
            report.stdout
        );
        assert_exit_matches_decision(&report.stdout, report.exit);
        if json {
            assert!(
                report
                    .stdout
                    .contains("\"code\": \"INSUFFICIENT_EVIDENCE\""),
                "{}",
                report.stdout
            );
            assert_json_document(&report.stdout);
        } else {
            assert!(
                report.stdout.contains("INSUFFICIENT_EVIDENCE"),
                "{}",
                report.stdout
            );
            assert!(report.stdout.contains("exit 2:"), "{}", report.stdout);
        }
    }
}

fn refuse_each_flag(path: &OsStr, needle: &str, hold_stdin: bool) {
    for flag in FILE_FLAGS {
        assert_refused_input(flag, path, needle, hold_stdin);
    }
}

#[cfg(unix)]
#[test]
fn each_input_refuses_a_fifo_with_no_writer() {
    let temp = TempDir::new("fifo");
    let path = temp.dir.join("no-writer");
    let made = Command::new("mkfifo").arg(&path).status().expect("mkfifo");
    assert!(made.success(), "mkfifo failed");
    refuse_each_flag(path.as_os_str(), NOT_REGULAR, false);
}

#[cfg(unix)]
#[test]
fn each_input_refuses_dev_zero() {
    refuse_each_flag(OsStr::new("/dev/zero"), NOT_REGULAR, false);
}

#[test]
fn each_input_refuses_a_directory() {
    let temp = TempDir::new("dir");
    let path = temp.dir.join("a-directory");
    std::fs::create_dir(&path).expect("mkdir");
    refuse_each_flag(path.as_os_str(), "is a directory", false);
}

#[cfg(unix)]
#[test]
fn each_input_refuses_stdin_when_it_is_a_pipe() {
    refuse_each_flag(OsStr::new("/dev/stdin"), NOT_REGULAR, true);
}

#[test]
fn each_input_refuses_an_empty_path() {
    refuse_each_flag(OsStr::new(""), "the path is empty", false);
}

fn sparse_file(dir: &TempDir, name: &str, len: u64) -> PathBuf {
    let path = dir.dir.join(name);
    let file = std::fs::File::create(&path)
        .unwrap_or_else(|err| panic!("create {}: {err}", path.display()));
    file.set_len(len)
        .unwrap_or_else(|err| panic!("set_len {}: {err}", path.display()));
    path
}

#[test]
fn each_input_refuses_a_file_over_its_size_limit() {
    let temp = TempDir::new("cap");
    let log = sparse_file(&temp, "over-log", LOG_BYTE_LIMIT + 1);
    let log_needle = format!(
        "the file is {} bytes, over the {LOG_BYTE_LIMIT} byte limit",
        LOG_BYTE_LIMIT + 1
    );
    assert_refused_input("--from-log", log.as_os_str(), &log_needle, false);

    let short_needle = format!(
        "the file is {} bytes, over the {SHORT_BYTE_LIMIT} byte limit",
        SHORT_BYTE_LIMIT + 1
    );
    for (flag, name) in [
        ("--from-timer-status", "over-timer"),
        ("--from-cert-disk", "over-disk"),
        ("--from-cert-live", "over-live"),
    ] {
        let path = sparse_file(&temp, name, SHORT_BYTE_LIMIT + 1);
        assert_refused_input(flag, path.as_os_str(), &short_needle, false);
    }
}

const STRICT_FILES: [(&str, &str); 3] = [
    (
        "--from-timer-status",
        "tests/fixtures/timer/certbot-timer-disabled.txt",
    ),
    ("--from-cert-disk", "tests/fixtures/certs/dates-current.txt"),
    ("--from-cert-live", "tests/fixtures/certs/dates-current.txt"),
];

fn code_line(stdout: &str) -> &str {
    stdout
        .lines()
        .find(|line| line.contains("confidence="))
        .unwrap_or_else(|| panic!("no code line\n{stdout}"))
}

/// The line the parser needs is first, so a leftover BOM changes the result.
fn critical_line_first(text: &str, prefix: &str) -> String {
    let mut lines: Vec<&str> = text.lines().collect();
    let index = lines
        .iter()
        .position(|line| line.starts_with(prefix))
        .unwrap_or_else(|| panic!("no line starts with {prefix}"));
    let line = lines.remove(index);
    lines.insert(0, line);
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

#[test]
fn timer_and_cert_utf8_bom_is_skipped() {
    let temp = TempDir::new("text-bom");
    for (flag, rel) in STRICT_FILES {
        let prefix = if flag == "--from-timer-status" {
            "Id="
        } else {
            "notAfter="
        };
        let text = critical_line_first(&fixture(rel), prefix);
        let plain = temp.write(&format!("plain-{flag}.txt"), text.as_bytes());
        let mut bom = vec![0xEF, 0xBB, 0xBF];
        bom.extend_from_slice(text.as_bytes());
        let with_bom = temp.write(&format!("bom-{flag}.txt"), &bom);
        let left = check(&["example.com", flag, &arg(&plain)]);
        let right = check(&["example.com", flag, &arg(&with_bom)]);
        assert_eq!(left.exit, right.exit, "{flag}\n{}", right.stdout);
        assert_eq!(code_line(&left.stdout), code_line(&right.stdout), "{flag}");
        assert!(
            !right.stdout.contains("not valid UTF-8"),
            "{flag}\n{}",
            right.stdout
        );
        assert!(
            !right.stdout.contains("save it as UTF-8"),
            "{flag}\n{}",
            right.stdout
        );
        if flag == "--from-timer-status" {
            assert_has(&right, "LAYER1_TIMER_DISABLED", 1);
        } else {
            assert!(
                !right.stdout.contains("not recognised"),
                "{flag}\n{}",
                right.stdout
            );
        }
    }
}

#[test]
fn timer_and_cert_wide_encodings_ask_for_utf8() {
    let temp = TempDir::new("text-wide");
    let cases = [
        ("UTF-16LE", true, false, false),
        ("UTF-16BE", true, true, false),
        ("UTF-16LE", false, false, false),
        ("UTF-16BE", false, true, false),
        ("UTF-32LE", true, false, true),
        ("UTF-32BE", true, true, true),
        ("UTF-32LE", false, false, true),
        ("UTF-32BE", false, true, true),
    ];
    for (flag, rel) in STRICT_FILES {
        let text = fixture(rel);
        for (encoding, bom, big_endian, utf32) in cases {
            let bytes = if utf32 {
                encode_utf32(&text, bom, big_endian)
            } else {
                encode_utf16(&text, bom, big_endian)
            };
            let name = format!("{flag}-{encoding}-bom{bom}");
            let path = temp.write(&name, &bytes);
            let report = check(&["example.com", flag, &arg(&path)]);
            let sentence = format!("the file is {encoding}; save it as UTF-8");
            assert_has(&report, "INSUFFICIENT_EVIDENCE", 2);
            assert!(
                report.stdout.contains(&sentence),
                "{flag} {encoding} bom={bom}\n{}",
                report.stdout
            );
            assert!(
                !report.stdout.contains("other kind"),
                "{flag}\n{}",
                report.stdout
            );
            assert!(
                !report.stdout.contains("replaced "),
                "{flag}\n{}",
                report.stdout
            );
        }
    }
}

fn assert_path_shown(flag: &str, path: &OsStr, expect_code: Option<&str>) {
    let shown = path.to_string_lossy();
    let mut text_args = vec![
        OsString::from("example.com"),
        OsString::from(flag),
        path.to_os_string(),
    ];
    let report = run_bounded(&text_args, false);
    assert_no_panic(&report);
    assert!(
        report.stdout.contains(shown.as_ref()),
        "{flag} text missing path {shown}\n{}",
        report.stdout
    );
    assert!(
        !report.stdout.contains("cannot read"),
        "{flag}\n{}",
        report.stdout
    );
    if let Some(code) = expect_code {
        assert_has(
            &report,
            code,
            if code.starts_with("LAYER") {
                1
            } else {
                report.exit
            },
        );
    }
    text_args.insert(0, OsString::from("--json"));
    let json = run_bounded(&text_args, false);
    assert_no_panic(&json);
    assert_eq!(json.exit, report.exit, "{flag}\n{}", json.stdout);
    assert_json_document(&json.stdout);
    // JSON escapes a backslash, as in a Windows path.
    let shown_json = shown.replace('\\', "\\\\");
    assert!(
        json.stdout.contains(&shown_json),
        "{flag} json missing path {shown_json}\n{}",
        json.stdout
    );
    let field = match flag {
        "--from-log" => "from_log",
        "--from-timer-status" => "from_timer_status",
        "--from-cert-disk" => "from_cert_disk",
        "--from-cert-live" => "from_cert_live",
        other => panic!("unknown flag {other}"),
    };
    assert!(
        json.stdout
            .contains(&format!("\"{field}\": \"{shown_json}\"")),
        "{flag} json field\n{}",
        json.stdout
    );
}

#[test]
fn paths_with_space_and_unicode_are_shown_in_text_and_json() {
    let temp = TempDir::new("paths");
    let dir = temp.dir.join("my log bücher");
    std::fs::create_dir(&dir).expect("mkdir");
    let samples = [
        (
            "--from-log",
            "input.log",
            "tests/fixtures/certbot/http01-timeout.log",
            Some("LAYER2_HTTP01_TIMEOUT"),
        ),
        (
            "--from-timer-status",
            "input timer.txt",
            "tests/fixtures/timer/certbot-timer-disabled.txt",
            Some("LAYER1_TIMER_DISABLED"),
        ),
        (
            "--from-cert-disk",
            "input disk.txt",
            "tests/fixtures/certs/dates-current.txt",
            None,
        ),
        (
            "--from-cert-live",
            "input live.txt",
            "tests/fixtures/certs/dates-current.txt",
            None,
        ),
    ];
    for (flag, name, rel, code) in samples {
        let path = dir.join(name);
        std::fs::write(&path, fixture(rel)).unwrap_or_else(|err| panic!("write: {err}"));
        assert_path_shown(flag, path.as_os_str(), code);
        let report_has_space = path.to_string_lossy();
        assert!(report_has_space.contains("my log"));
        assert!(report_has_space.contains("bücher"));
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn paths_with_non_utf8_bytes_are_shown_in_text_and_json() {
    use std::os::unix::ffi::OsStrExt;

    let temp = TempDir::new("bytes");
    let samples = [
        (
            "--from-log",
            "tests/fixtures/certbot/http01-timeout.log",
            Some("LAYER2_HTTP01_TIMEOUT"),
        ),
        (
            "--from-timer-status",
            "tests/fixtures/timer/certbot-timer-disabled.txt",
            Some("LAYER1_TIMER_DISABLED"),
        ),
        (
            "--from-cert-disk",
            "tests/fixtures/certs/dates-current.txt",
            None,
        ),
        (
            "--from-cert-live",
            "tests/fixtures/certs/dates-current.txt",
            None,
        ),
    ];
    for (index, (flag, rel, code)) in samples.iter().enumerate() {
        let mut name = OsString::from(format!("cert-{index}-"));
        name.push(OsStr::from_bytes(&[0xFF]));
        name.push(".txt");
        let path = temp.dir.join(name);
        std::fs::write(&path, fixture(rel)).unwrap_or_else(|err| panic!("write: {err}"));
        assert!(path.to_string_lossy().contains('\u{FFFD}'));
        assert_path_shown(flag, path.as_os_str(), *code);
    }
}
