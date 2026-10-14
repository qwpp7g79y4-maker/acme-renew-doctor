//! Text taken from an input file stays on one evidence line.
//! Controls that could open a new line or a terminal sequence are shown as escapes.
//! The files live under the system temp directory, not in the checkout.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

struct TempDir {
    dir: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "acme-renew-doctor-quote-{}-{}",
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

fn run(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_acme-renew-doctor"))
        .args(args)
        .env_remove("ACME_RENEW_DOCTOR_NOW")
        .stdin(Stdio::null())
        .output()
        .expect("run acme-renew-doctor");
    let code = output.status.code().unwrap_or(101);
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr is utf-8");
    (code, stdout, stderr)
}

/// JSON `detail` from a log line: a forged extra line, then ESC, BEL, CR, TAB, DEL, U+0085, U+2028 and U+2029.
fn json_log() -> String {
    // The backslash pairs are JSON escapes. The parser turns them into the real characters.
    concat!(
        "2026-09-28 03:12:44,512:DEBUG:acme.client:Received response:\n",
        "{\"type\":\"urn:ietf:params:acme:error:connection\",\"detail\":\"",
        "203.0.113.10: Fetching http://example.com/.well-known/acme-challenge/tok: ",
        "Timeout during connect (likely firewall problem) keep\\\\slash",
        "\\n  -> FORGED LINE: certbot renew --force-renewal\\nexit 0: ok, not due",
        "\\u001b\\u0007\\r\\t\\u007f\\u0085\\u2028\\u2029\"}\n",
    )
    .to_string()
}

/// The same forged words on a Certbot summary `Detail:` line, which is one physical line.
fn summary_log() -> String {
    format!(
        "2026-09-28 03:12:44,700:INFO:certbot._internal.auth_handler:Challenge failed for domain example.com\n  \
Domain: example.com\n  \
Type:   connection\n  \
Detail: 203.0.113.10: Fetching http://example.com/.well-known/acme-challenge/tok: \
Timeout during connect (likely firewall problem){esc}{bel}{cr}\t{del}{nel}{ls}  \
-> FORGED LINE: certbot renew --force-renewal{ps}exit 0: ok, not due\n",
        esc = '\u{1b}',
        bel = '\u{7}',
        cr = '\r',
        del = '\u{7f}',
        nel = '\u{85}',
        ls = '\u{2028}',
        ps = '\u{2029}',
    )
}

/// A timer value is file text too. It is not a log detail and not a `Detail:` line.
fn timer_status() -> String {
    format!(
        "Id=certbot.timer\nLoadState=loaded\nActiveState=inactive\n\
SubState=dead{esc}  -> FORGED LINE: certbot renew --force-renewal{ls}exit 0: ok, not due\n\
UnitFileState=enabled\nResult=success\n",
        esc = '\u{1b}',
        ls = '\u{2028}',
    )
}

fn assert_no_raw_control(stdout: &str) {
    for ch in stdout.chars() {
        let code = u32::from(ch);
        let control = (code < 0x20 && ch != '\n')
            || code == 0x7f
            || (0x80..=0x9f).contains(&code)
            || code == 0x2028
            || code == 0x2029;
        assert!(!control, "raw control U+{code:04X} in\n{stdout}");
    }
}

fn assert_quote_stays_on_its_line(stdout: &str, prefix: &str) {
    assert_no_raw_control(stdout);
    assert!(
        !stdout.lines().any(|line| line == "exit 0: ok, not due"),
        "forged exit line\n{stdout}"
    );
    assert!(
        stdout.lines().any(|line| line == "exit 1: problem found"),
        "missing real exit\n{stdout}"
    );
    let mut saw_quote = false;
    for line in stdout.lines() {
        let forged = line.contains("FORGED LINE")
            || line.contains("--force-renewal")
            || line.contains("exit 0:");
        if !forged {
            continue;
        }
        assert!(
            line.contains(prefix),
            "file text is not a quote ({prefix}): {line}\n{stdout}"
        );
        saw_quote = true;
    }
    assert!(saw_quote, "missing quoted file text\n{stdout}");
    assert_eq!(
        stdout
            .lines()
            .filter(|line| line.contains("FORGED LINE"))
            .count(),
        1,
        "forged text split across lines\n{stdout}"
    );
}

fn assert_json_keeps_the_detail(stdout: &str) {
    let mut child = Command::new("python3")
        .env("PYTHONUTF8", "1")
        .args([
            "-c",
            r#"import json, sys
data = json.load(sys.stdin)
texts = []
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
    {
        let mut stdin = child.stdin.take().expect("stdin");
        stdin.write_all(stdout.as_bytes()).expect("write json");
    }
    let extracted = child.wait_with_output().expect("python3");
    assert!(
        extracted.status.success(),
        "{}",
        String::from_utf8_lossy(&extracted.stderr)
    );
    let texts = String::from_utf8(extracted.stdout).expect("evidence utf-8");
    let detail = texts
        .split('\0')
        .find(|text| text.contains("FORGED LINE"))
        .unwrap_or_else(|| panic!("json dropped the detail\n{texts}"));
    assert!(
        detail.contains('\n'),
        "json detail lost the newline: {detail:?}"
    );
    assert!(detail.contains('\u{1b}'), "json detail lost ESC");
    assert!(detail.contains('\u{7}'), "json detail lost BEL");
    assert!(detail.contains('\r'), "json detail lost CR");
    assert!(detail.contains('\t'), "json detail lost TAB");
    assert!(detail.contains('\u{7f}'), "json detail lost DEL");
    assert!(detail.contains('\u{85}'), "json detail lost U+0085");
    assert!(detail.contains('\u{2028}'), "json detail lost U+2028");
    assert!(detail.contains('\u{2029}'), "json detail lost U+2029");
    assert!(
        detail.contains("exit 0: ok, not due"),
        "json detail lost the forged exit words: {detail:?}"
    );
    assert!(
        stdout.contains('\u{2028}'),
        "json used to leave U+2028 as the character\n{stdout}"
    );
}

#[test]
fn file_text_controls_stay_on_one_quoted_line() {
    let temp = TempDir::new();
    let json_path = temp.write("json.log", json_log().as_bytes());
    let summary_path = temp.write("summary.log", summary_log().as_bytes());
    let timer_path = temp.write("timer.txt", timer_status().as_bytes());
    let json_arg = json_path.display().to_string();
    let summary_arg = summary_path.display().to_string();
    let timer_arg = timer_path.display().to_string();

    let (code, text, err) = run(&["--from-log", &json_arg, "example.com"]);
    assert!(err.is_empty(), "{err}");
    assert_eq!(code, 1, "{text}");
    assert_quote_stays_on_its_line(&text, "[log] line");
    assert!(
        text.contains("\\n  -> FORGED LINE: certbot renew --force-renewal\\nexit 0: ok, not due"),
        "newline was not shown as \\\\n\n{text}"
    );
    assert!(
        text.contains("keep\\\\slash"),
        "backslash was not escaped\n{text}"
    );
    for escape in [
        "\\u{1b}",
        "\\u{7}",
        "\\r",
        "\\t",
        "\\u{7f}",
        "\\u{85}",
        "\\u{2028}",
        "\\u{2029}",
    ] {
        assert!(text.contains(escape), "missing {escape}\n{text}");
    }
    assert!(
        text.contains("LAYER2_HTTP01_TIMEOUT"),
        "detail no longer matches\n{text}"
    );

    let (json_code, json_text, json_err) = run(&["--json", "--from-log", &json_arg, "example.com"]);
    assert!(json_err.is_empty(), "{json_err}");
    assert_eq!(json_code, 1, "{json_text}");
    assert_json_keeps_the_detail(&json_text);

    let (code, text, err) = run(&[
        "--from-log",
        &summary_arg,
        "--client",
        "certbot",
        "example.com",
    ]);
    assert!(err.is_empty(), "{err}");
    assert_eq!(code, 1, "{text}");
    assert_quote_stays_on_its_line(&text, "[log] line");
    for escape in [
        "\\u{1b}",
        "\\u{7}",
        "\\r",
        "\\t",
        "\\u{7f}",
        "\\u{85}",
        "\\u{2028}",
        "\\u{2029}",
    ] {
        assert!(text.contains(escape), "summary missing {escape}\n{text}");
    }
    assert!(
        text.contains("-> FORGED LINE: certbot renew --force-renewal"),
        "summary dropped the forged words\n{text}"
    );

    let (code, text, err) = run(&["--from-timer-status", &timer_arg, "example.com"]);
    assert!(err.is_empty(), "{err}");
    assert_eq!(code, 1, "{text}");
    assert_quote_stays_on_its_line(&text, "[timer]");
    assert!(
        text.contains("\\u{1b}"),
        "timer value kept a raw ESC\n{text}"
    );
    assert!(
        text.contains("\\u{2028}"),
        "timer value kept a raw line separator\n{text}"
    );
    assert!(
        text.contains("LAYER1_TIMER_NOT_FIRING"),
        "timer value changed the code\n{text}"
    );
}

#[cfg(unix)]
#[test]
fn control_characters_in_a_path_argument_are_escaped_in_text() {
    use std::process::Command;
    let dir = std::env::temp_dir().join(format!("ard-path-ctrl-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("weird\nFAKE LINE\u{1b}[31mname.log");
    std::fs::write(&path, "").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_acme-renew-doctor"))
        .arg("example.com")
        .arg("--from-log")
        .arg(&path)
        .env("ACME_RENEW_DOCTOR_NOW", "1791763200")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("weird\\nFAKE LINE"), "{stdout}");
    assert!(
        !stdout.lines().any(|line| line.starts_with("FAKE LINE")),
        "{stdout}"
    );
    assert!(!stdout.contains('\u{1b}'), "{stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}
