//! Schema test for `--json` (`schema_version` 1): the exact keys, in
//! order, at each level. The output is pretty-printed with two spaces per
//! level, so a key is a line `"name": ` at a known indent. The snapshots
//! pin the values; this pins the shape. No JSON crate is needed.

use std::process::Command;

const LOG: &str = "tests/fixtures/certbot/http01-timeout-repeated.log";
const TIMER: &str = "tests/fixtures/timer/certbot-timer-disabled.txt";

fn run(args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_acme-renew-doctor"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env_remove("ACME_RENEW_DOCTOR_NOW")
        .args(args)
        .output()
        .expect("run acme-renew-doctor");
    String::from_utf8(out.stdout).expect("utf-8")
}

/// Keys of lines at exactly `indent` spaces, in order, de-duplicated
/// across consecutive array elements (first element's order is kept).
fn keys_at(text: &str, indent: usize, within: &str) -> Vec<String> {
    // `within` = the top-level key whose block we read ("" = top level).
    let mut in_block = within.is_empty();
    let mut out: Vec<String> = Vec::new();
    for line in text.lines() {
        let spaces = line.len() - line.trim_start().len();
        let t = line.trim_start();
        if !within.is_empty() && spaces == 2 {
            in_block = t.starts_with(&format!("\"{within}\":"));
            continue;
        }
        if in_block && spaces == indent && t.starts_with('"') {
            if let Some(end) = t[1..].find("\": ") {
                let k = t[1..1 + end].to_string();
                if !out.contains(&k) {
                    out.push(k);
                }
            }
        }
    }
    out
}

#[test]
fn json_top_level_and_nested_keys_are_stable() {
    let text = run(&[
        "example.com",
        "--json",
        "--from-log",
        LOG,
        "--from-timer-status",
        TIMER,
    ]);
    assert!(text.starts_with("{\n  \"schema_version\": 1,\n"), "{text}");
    assert_eq!(
        keys_at(&text, 2, ""),
        [
            "schema_version",
            "tool",
            "input",
            "findings",
            "next_checks",
            "exit_code"
        ]
    );
    assert_eq!(keys_at(&text, 4, "tool"), ["name", "version"]);
    assert_eq!(
        keys_at(&text, 4, "input"),
        [
            "domain",
            "all",
            "client",
            "from_log",
            "from_timer_status",
            "from_cert_disk",
            "from_cert_live"
        ]
    );
    assert_eq!(
        keys_at(&text, 6, "findings"),
        ["code", "layer", "confidence", "evidence"]
    );
    assert_eq!(keys_at(&text, 10, "findings"), ["source", "text"]);
    assert_eq!(
        keys_at(&text, 6, "next_checks"),
        ["for", "command", "why", "safety"]
    );
    assert!(text.contains("\"safety\": \"read-only\""));
}

#[test]
fn json_notes_key_sits_before_exit_code_only_when_a_note_applies() {
    let safe = run(&["--json", "--from-log", LOG, "--", "example.com"]);
    assert!(
        !keys_at(&safe, 2, "").contains(&"notes".to_string()),
        "{safe}"
    );

    let rejected = run(&["--json", "--from-log", LOG, "--", "bad domain"]);
    let top = keys_at(&rejected, 2, "");
    assert_eq!(
        top,
        [
            "schema_version",
            "tool",
            "input",
            "findings",
            "next_checks",
            "notes",
            "exit_code"
        ],
        "{rejected}"
    );
}
