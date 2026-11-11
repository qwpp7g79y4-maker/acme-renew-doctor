//! The manual page in `man/acme-renew-doctor.1` is generated from the CLI
//! definition (`cargo run --example gen_assets -- man`). These checks fail
//! when it is stale against `--help`.
use std::process::Command;

fn help() -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_acme-renew-doctor"))
        .arg("--help")
        .output()
        .expect("run --help");
    assert_eq!(out.status.code(), Some(0));
    String::from_utf8(out.stdout).expect("utf-8 help")
}

fn man() -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/man/acme-renew-doctor.1");
    std::fs::read_to_string(path).expect("read man page")
}

/// roff escapes `-` as `\-`; compare on plain text.
fn plain(text: &str) -> String {
    text.replace("\\-", "-")
        .replace("\\fB", "")
        .replace("\\fR", "")
}

#[test]
fn man_page_names_every_long_option_of_help() {
    let man = plain(&man());
    let help = help();
    let mut seen = 0;
    for word in help.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-')) {
        if word.starts_with("--") && word.len() > 2 {
            seen += 1;
            assert!(man.contains(word), "man page lacks {word}");
        }
    }
    assert!(seen >= 8, "found only {seen} long options in --help");
}

#[test]
fn man_page_carries_the_about_text_and_the_version() {
    let man = plain(&man());
    assert!(man.contains("Explains why ACME certificate renewal failed (read-only)."));
    assert!(man.contains(&format!("acme-renew-doctor {}", env!("CARGO_PKG_VERSION"))));
}
