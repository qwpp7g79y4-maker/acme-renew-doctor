//! `--json` writes DEL, C1 controls and bidirectional marks as `\uXXXX`.
//! Raw, they could move the cursor or reorder a line when the JSON is shown
//! in a terminal. Parsed, the text keeps the original character.
//! The files live under the system temp directory, not in the checkout.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

const ESCAPED: &[char] = &[
    '\u{7f}', '\u{80}', '\u{85}', '\u{9b}', '\u{9f}', '\u{202a}', '\u{202b}', '\u{202c}',
    '\u{202d}', '\u{202e}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}', '\u{200e}', '\u{200f}',
    '\u{61c}',
];

struct TempDir {
    dir: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "acme-renew-doctor-jsonctl-{}-{}",
            std::process::id(),
            n
        ));
        fs::create_dir_all(&dir).unwrap_or_else(|err| panic!("tempdir {}: {err}", dir.display()));
        Self { dir }
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.dir.join(name);
        fs::write(&path, bytes).unwrap_or_else(|err| panic!("write {}: {err}", path.display()));
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn run_json(log: &str) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_acme-renew-doctor"))
        .args(["--json", "--from-log", log, "example.com"])
        .env_remove("ACME_RENEW_DOCTOR_NOW")
        .stdin(Stdio::null())
        .output()
        .expect("run acme-renew-doctor");
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    String::from_utf8(output.stdout).expect("stdout is utf-8")
}

/// All `text` and `from_log` values after a real JSON parse, joined by NUL.
fn parsed_texts(stdout: &str) -> String {
    let mut child = Command::new("python3")
        .env("PYTHONUTF8", "1")
        .args([
            "-c",
            r#"import json, sys
data = json.load(sys.stdin)
texts = [data["input"]["from_log"] or ""]
for finding in data["findings"]:
    for evidence in finding["evidence"]:
        texts.append(evidence["text"])
sys.stdout.write("\0".join(texts))
"#,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("python3");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdout.as_bytes())
        .expect("write json");
    let out = child.wait_with_output().expect("python3");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("parsed utf-8")
}

fn assert_escaped(stdout: &str, ch: char) {
    let code = u32::from(ch);
    assert!(
        !stdout.contains(ch),
        "raw U+{code:04X} in --json output\n{stdout:?}"
    );
    assert!(
        stdout.contains(&format!("\\u{code:04x}")),
        "no \\u{code:04x} escape in --json output\n{stdout:?}"
    );
    assert!(
        parsed_texts(stdout).contains(ch),
        "parsed JSON lost U+{code:04X}"
    );
}

fn json_detail_log(detail_piece: &str) -> String {
    format!(
        concat!(
            "2026-09-28 03:12:44,512:DEBUG:acme.client:Received response:\n",
            "{{\"type\":\"urn:ietf:params:acme:error:connection\",\"detail\":\"",
            "203.0.113.10: Fetching http://example.com/.well-known/acme-challenge/x{}evil: ",
            "Timeout during connect (likely firewall problem)\"}}\n",
        ),
        detail_piece
    )
}

fn summary_log(ch: char) -> String {
    format!(
        concat!(
            "2026-09-28 03:12:44,512:ERROR:certbot._internal.auth_handler:Certbot failed to authenticate some domains (authenticator: webroot). The Certificate Authority reported these problems:\n",
            "  Domain: example.com\n",
            "  Type:   connection\n",
            "  Detail: 203.0.113.10: Fetching http://example.com/.well-known/acme-challenge/x{}evil: Timeout during connect (likely firewall problem)\n",
        ),
        ch
    )
}

#[test]
fn raw_control_in_json_detail_is_escaped_in_json_output() {
    let temp = TempDir::new();
    for (i, &ch) in ESCAPED.iter().enumerate() {
        let path = temp.write(
            &format!("raw-{i}.log"),
            json_detail_log(&ch.to_string()).as_bytes(),
        );
        let stdout = run_json(&path.display().to_string());
        assert_escaped(&stdout, ch);
    }
}

#[test]
fn json_escaped_control_in_detail_is_escaped_in_json_output() {
    let temp = TempDir::new();
    for (i, &ch) in ESCAPED.iter().enumerate() {
        let piece = format!("\\u{:04x}", u32::from(ch));
        let path = temp.write(&format!("esc-{i}.log"), json_detail_log(&piece).as_bytes());
        let stdout = run_json(&path.display().to_string());
        assert_escaped(&stdout, ch);
    }
}

#[test]
fn control_in_summary_detail_line_is_escaped_in_json_output() {
    let temp = TempDir::new();
    for (i, &ch) in ESCAPED.iter().enumerate() {
        let path = temp.write(&format!("sum-{i}.log"), summary_log(ch).as_bytes());
        let stdout = run_json(&path.display().to_string());
        assert_escaped(&stdout, ch);
    }
}

#[test]
fn bidi_and_c1_together_are_all_escaped() {
    let temp = TempDir::new();
    let path = temp.write(
        "mixed.log",
        json_detail_log("\u{202e}\u{9b}31m\u{7f}\u{2066}").as_bytes(),
    );
    let stdout = run_json(&path.display().to_string());
    for ch in ['\u{202e}', '\u{9b}', '\u{7f}', '\u{2066}'] {
        assert_escaped(&stdout, ch);
    }
}

#[test]
fn line_separator_stays_the_character_in_json() {
    let temp = TempDir::new();
    let path = temp.write("ls.log", json_detail_log("\u{2028}").as_bytes());
    let stdout = run_json(&path.display().to_string());
    assert!(stdout.contains('\u{2028}'), "{stdout:?}");
}

#[cfg(unix)]
#[test]
fn control_in_log_path_is_escaped_in_json_output() {
    let temp = TempDir::new();
    let body = json_detail_log("");
    for (i, &ch) in ESCAPED.iter().enumerate() {
        let path = temp.write(&format!("p{i}-{ch}.log"), body.as_bytes());
        let stdout = run_json(&path.display().to_string());
        assert_escaped(&stdout, ch);
    }
}
