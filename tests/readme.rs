//! Documentation tests: README.md, README.nl.md, docs/reference.md and
//! docs/reference.nl.md.
//!
//! Every ```console example is run against the binary. Every usage-error row
//! and every report-message row is run against the binary. The English and
//! Dutch pages must have the same number of sections, the same source URLs
//! and the same examples.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const README: &str = "README.md";
const README_DUTCH: &str = "README.nl.md";
const REF: &str = "docs/reference.md";
const REF_DUTCH: &str = "docs/reference.nl.md";

fn bin() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_acme-renew-doctor"));
    cmd.current_dir(env!("CARGO_MANIFEST_DIR"));
    cmd
}

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {rel}: {err}"))
}

/// The text under a level-2 heading, up to the next level-2 heading.
fn section<'a>(text: &'a str, heading: &str) -> &'a str {
    let marker = format!("{heading}\n");
    let start = text
        .find(&marker)
        .unwrap_or_else(|| panic!("missing heading {heading}"))
        + marker.len();
    let rest = &text[start..];
    match rest.find("\n## ") {
        Some(end) => &rest[..end],
        None => rest,
    }
}

fn headings(text: &str) -> Vec<&str> {
    text.lines()
        .filter(|line| line.starts_with("## "))
        .collect()
}

fn urls(text: &str) -> BTreeSet<String> {
    text.split(|c: char| c.is_whitespace() || c == '(' || c == ')')
        .filter(|word| word.starts_with("https://"))
        .map(|word| word.trim_end_matches(['.', ',', '"']).to_string())
        .collect()
}

fn backtick(cell: &str) -> &str {
    let cell = cell.trim();
    cell.strip_prefix('`')
        .and_then(|rest| rest.strip_suffix('`'))
        .unwrap_or_else(|| panic!("cell not in backticks: {cell}"))
}

/// `\n` in a table cell is a real newline. The cell itself has none.
fn message_of(cell: &str) -> String {
    let mut text = backtick(cell).replace("\\n", "\n");
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text
}

struct Invocation {
    env: Vec<(String, String)>,
    args: Vec<String>,
}

fn invocation(call: &str) -> Invocation {
    let mut env = Vec::new();
    let mut args = Vec::new();
    for token in call.split_whitespace() {
        if args.is_empty() && !token.starts_with('-') {
            if let Some((key, value)) = token.split_once('=') {
                env.push((key.to_string(), value.to_string()));
                continue;
            }
        }
        args.push(token.to_string());
    }
    assert!(!args.is_empty(), "no arguments in {call}");
    Invocation { env, args }
}

struct Row {
    call: String,
    invocation: Invocation,
    message: String,
    exit: i32,
}

/// Rows whose exit cell is a number. Header and separator rows are skipped.
fn rows(doc: &str, heading: &str) -> Vec<Row> {
    let part = section(doc, heading);
    let mut out = Vec::new();
    for line in part.lines().filter(|line| line.starts_with('|')) {
        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() < 6 {
            continue;
        }
        let cells: Vec<&str> = parts[1..5].iter().map(|cell| cell.trim()).collect();
        if !cells[2].chars().all(|ch| ch.is_ascii_digit()) || cells[2].is_empty() {
            continue;
        }
        let call = backtick(cells[1]).to_string();
        let exit: i32 = cells[2].parse().expect("exit cell");
        out.push(Row {
            invocation: invocation(&call),
            call,
            message: message_of(cells[3]),
            exit,
        });
    }
    assert!(!out.is_empty(), "{heading} has no data row");
    out
}

struct Example {
    invocation: Invocation,
    body: String,
}

/// Every ```console block. The first line is `$ [KEY=VAL ...] acme-renew-doctor ARGS`.
fn examples(doc: &str) -> Vec<Example> {
    let mut out = Vec::new();
    let mut lines = doc.lines();
    while let Some(line) = lines.next() {
        if line != "```console" {
            continue;
        }
        let call = lines.next().expect("empty console block");
        let (env_and_bin, args_text) = split_example(call);
        let mut body = String::new();
        let mut closed = false;
        for line in lines.by_ref() {
            if line == "```" {
                closed = true;
                break;
            }
            body.push_str(line);
            body.push('\n');
        }
        assert!(closed, "console block not closed: {call}");
        out.push(Example {
            invocation: Invocation {
                env: env_and_bin,
                args: args_text,
            },
            body,
        });
    }
    out
}

fn split_example(call: &str) -> (Vec<(String, String)>, Vec<String>) {
    let rest = call
        .strip_prefix("$ ")
        .unwrap_or_else(|| panic!("console block does not start with `$ `: {call}"));
    let mut env = Vec::new();
    let mut saw_bin = false;
    let mut args = Vec::new();
    for token in rest.split_whitespace() {
        if !saw_bin {
            if token == "acme-renew-doctor" {
                saw_bin = true;
                continue;
            }
            let (key, value) = token
                .split_once('=')
                .unwrap_or_else(|| panic!("expected KEY=VAL or the binary, got {token}"));
            env.push((key.to_string(), value.to_string()));
        } else {
            args.push(token.to_string());
        }
    }
    assert!(saw_bin, "console block has no acme-renew-doctor: {call}");
    (env, args)
}

fn run(invocation: &Invocation) -> std::process::Output {
    let mut cmd = bin();
    for (key, value) in &invocation.env {
        cmd.env(key, value);
    }
    cmd.args(&invocation.args).output().expect("start binary")
}

#[test]
fn readme_has_the_sections_and_names() {
    let readme = read(README);
    for heading in [
        "## Why",
        "## Installation",
        "## Quick start",
        "## How it works",
        "## Compared with alternatives",
        "## Limitations",
        "## Privacy",
        "## License",
        "## Contact",
    ] {
        assert!(
            readme.lines().any(|line| line == heading),
            "missing {heading}"
        );
    }
    let limits = section(&readme, "## Limitations");
    for part in [
        "Live collection is not built",
        "does not redact",
        "acme.sh logs are not parsed",
        "not from PEM",
        "does not filter the log",
        "Error creating new order :: ...",
        "localhost is not the same",
        "certbot.timer",
        "letsencrypt.log.N",
        "recognised connection error without a dedicated rule",
        "latest timestamp wins",
        "UTF-8",
        "`Mei`",
        "DANGEROUS_FORCE_BLOCKED",
    ] {
        assert!(
            limits.contains(part),
            "Limitations is missing {part}\n{limits}"
        );
    }
    assert!(section(&readme, "## License").contains("PEPAI"));
    assert!(section(&readme, "## Contact").contains("pep_ai@icloud.com"));
    for leak in [
        format!("{}{}", "ta", "sk.md"),
        format!("{}{}", "blue", "print"),
        "project notes".to_string(),
        "Willingness to pay".to_string(),
        "portfolio".to_string(),
    ] {
        assert!(!readme.contains(leak.as_str()), "README still has {leak}");
    }
    // No internal task numbers (a capital T followed by digits) in the README.
    for word in readme.split(|c: char| !c.is_ascii_alphanumeric()) {
        let task_number = word.len() > 1
            && word.starts_with('T')
            && word[1..].chars().all(|c| c.is_ascii_digit());
        assert!(!task_number, "README still has task number {word}");
    }
}

#[test]
fn readme_separates_source_install_from_the_binary_archive() {
    for (page, heading) in [
        (README, "## Installation"),
        (README_DUTCH, "## Installatie"),
    ] {
        let text = read(page);
        let body = section(&text, heading);
        assert!(body.contains("cargo install --path ."), "{page}");
        assert!(body.contains("Cargo.toml"), "{page}");
        assert!(body.contains("sha256"), "{page}");
        assert!(body.contains("PATH"), "{page}");
    }
}

#[test]
fn language_switch_on_top_of_every_page() {
    for (rel, line) in [
        (README, "English · [Nederlands](README.nl.md)"),
        (README_DUTCH, "[English](README.md) · Nederlands"),
        (REF, "English · [Nederlands](reference.nl.md)"),
        (REF_DUTCH, "[English](reference.md) · Nederlands"),
    ] {
        let text = read(rel);
        let third = text.lines().nth(2).unwrap_or_default();
        assert_eq!(third, line, "{rel} has no language switch on line 3");
    }
}

#[test]
fn english_and_dutch_pages_match() {
    for (english, dutch) in [(README, README_DUTCH), (REF, REF_DUTCH)] {
        let english_text = read(english);
        let dutch_text = read(dutch);
        assert_eq!(
            headings(&english_text).len(),
            headings(&dutch_text).len(),
            "{english} and {dutch} have a different number of sections"
        );
        assert_eq!(
            urls(&english_text),
            urls(&dutch_text),
            "{english} and {dutch} cite different URLs"
        );
        assert_eq!(
            examples(&english_text)
                .iter()
                .map(|example| example.body.clone())
                .collect::<Vec<_>>(),
            examples(&dutch_text)
                .iter()
                .map(|example| example.body.clone())
                .collect::<Vec<_>>(),
            "{english} and {dutch} have different examples"
        );
    }
}

#[test]
fn licenses_and_manifest_name_the_holder() {
    assert!(read("LICENSE-MIT").contains("Copyright (c) 2026 PEPAI"));
    assert!(read("LICENSE-APACHE").contains("Copyright 2026 PEPAI"));
    let cargo = read("Cargo.toml");
    assert!(cargo.contains("PEPAI <pep_ai@icloud.com>"), "{cargo}");
    assert!(
        !cargo.to_lowercase().contains("analyseert"),
        "description is not English"
    );
}

#[test]
fn sources_are_quoted_verbatim() {
    let readme = read(README);
    let why = section(&readme, "## Why");
    for part in [
        "https://letsencrypt.org/2025/06/26/expiration-notification-service-has-ended.html",
        "4 June 2025",
        "names that layer, with the line that proves it",
    ] {
        assert!(why.contains(part), "Why is missing {part}");
    }
    let how = section(&readme, "## How it works");
    for part in [
        "https://letsencrypt.org/docs/faq/",
        "Our default certificates are valid for 90 days.",
        "Subscribers can opt in to short-lived certificates which are valid for six days.",
    ] {
        assert!(how.contains(part), "How it works is missing {part}");
    }
    let compared = section(&readme, "## Compared with alternatives");
    assert!(compared.contains("not verified"));
    assert!(compared.contains("Red Sift"));
    assert!(compared.contains("certease"));
    let dutch = read(README_DUTCH);
    assert!(section(&dutch, "## Waarom").contains("4 juni 2025"));
    assert!(section(&dutch, "## Vergelijking met alternatieven").contains("niet geverifieerd"));
    for part in [
        "https://letsencrypt.org/2025/06/26/expiration-notification-service-has-ended.html",
        "Our default certificates are valid for 90 days.",
        "Subscribers can opt in to short-lived certificates which are valid for six days.",
    ] {
        assert!(dutch.contains(part), "Dutch page is missing {part}");
    }
}

#[test]
fn examples_match_the_binary() {
    for rel in [README, README_DUTCH] {
        let doc = read(rel);
        let found = examples(&doc);
        assert!(found.len() >= 3, "{rel} has only {} examples", found.len());
        for example in &found {
            let output = run(&example.invocation);
            let out = String::from_utf8(output.stdout).expect("stdout is utf-8");
            let err = String::from_utf8(output.stderr).expect("stderr is utf-8");
            assert!(
                err.is_empty(),
                "{rel} {:?} stderr: {err}",
                example.invocation.args
            );
            assert_eq!(out, example.body, "{rel} {:?}", example.invocation.args);
            let exit_line = example
                .body
                .lines()
                .rev()
                .find(|line| line.starts_with("exit "))
                .unwrap_or_else(|| panic!("{rel} example has no exit line"));
            let number: i32 = exit_line
                .trim_start_matches("exit ")
                .split(':')
                .next()
                .unwrap()
                .parse()
                .expect("exit number");
            assert_eq!(
                output.status.code(),
                Some(number),
                "{rel} {:?} process exit",
                example.invocation.args
            );
        }
    }
}

#[test]
fn option_and_error_tables_match_the_binary() {
    let help = bin().arg("--help").output().expect("start binary");
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).expect("help is utf-8");
    for (rel, options, usage, reports) in [
        (
            REF,
            "## Options",
            "## Exit codes and usage errors",
            "## Report messages",
        ),
        (
            REF_DUTCH,
            "## Opties",
            "## Exitcodes en gebruiksfouten",
            "## Rapportmeldingen",
        ),
    ] {
        let doc = read(rel);
        let table = section(&doc, options);
        for line in help.lines() {
            let Some(start) = line.find("--") else {
                continue;
            };
            let name = line[start..].split_whitespace().next().unwrap();
            assert!(
                table.contains(name),
                "{rel}: option table is missing {name}"
            );
        }
        let mut usage_messages = BTreeSet::new();
        for row in rows(&doc, usage) {
            let output = run(&row.invocation);
            let out = String::from_utf8(output.stdout).expect("stdout is utf-8");
            let err = String::from_utf8(output.stderr).expect("stderr is utf-8");
            assert_eq!(row.exit, 3, "{rel} {} exit cell", row.call);
            assert_eq!(
                output.status.code(),
                Some(row.exit),
                "{rel} {:?} stderr: {err}",
                row.invocation.args
            );
            assert!(out.is_empty(), "{rel} {:?} stdout: {out}", row.call);
            assert_eq!(err, row.message, "{rel} {}", row.call);
            usage_messages.insert(row.message);
        }
        for needed in [
            "invalid value 'foo' for '--client <CLIENT>'\n",
            "cannot be used with '--all'\n",
            "a value is required for '--from-log <FILE>' but none was supplied\n",
            "unexpected argument '--bogus' found\n",
            "got 1,5\n",
            "got 1.5\n",
            "got not-a-timestamp\n",
        ] {
            assert!(
                usage_messages
                    .iter()
                    .any(|message| message.contains(needed)),
                "{rel}: usage table is missing {needed:?}"
            );
        }
        let mut report_messages = BTreeSet::new();
        for row in rows(&doc, reports) {
            let output = run(&row.invocation);
            let out = String::from_utf8(output.stdout).expect("stdout is utf-8");
            let err = String::from_utf8(output.stderr).expect("stderr is utf-8");
            assert!(
                row.exit == 2 || row.exit == 3,
                "{rel} {} exit cell {}",
                row.call,
                row.exit
            );
            assert!(err.is_empty(), "{rel} {} stderr: {err}", row.call);
            assert!(
                out.contains(row.message.trim_end()),
                "{rel} {} missing message\nstdout:\n{out}",
                row.call
            );
            assert_eq!(output.status.code(), Some(row.exit), "{rel} {}", row.call);
            report_messages.insert(row.message);
        }
        for needed in [
            "does-not-exist.log: NotFound\n",
            "tests/fixtures/certbot: is a directory\n",
            "timer status not recognised (no Id= line in systemctl show output)\n",
            "certificate dates not recognised (no notAfter= line in openssl x509 -dates output)\n",
            "acme.sh logs are not parsed yet (v0.1 parses Certbot logs only)\n",
            "no Certbot log lines found in tests/fixtures/acme-sh/verify-error-dns01.log",
        ] {
            assert!(
                report_messages
                    .iter()
                    .any(|message| message.contains(needed.trim_end())),
                "{rel}: report table is missing {needed:?}"
            );
        }
    }
}

#[test]
fn plural_and_comma_are_explained() {
    let reference = read(REF);
    assert!(reference.contains("1 suggested check blocked by the anti-force gate"));
    assert!(reference.contains("2 suggested checks blocked by the anti-force gate"));
    assert!(reference.contains("`1,5` and `1.5` are not whole numbers"));
    assert!(reference.contains("only when the count is greater than 1"));
    let dutch = read(REF_DUTCH);
    assert!(dutch.contains("1 suggested check blocked by the anti-force gate"));
    assert!(dutch.contains("2 suggested checks blocked by the anti-force gate"));
}

#[test]
fn fixture_readme_describes_every_file_as_synthetic() {
    let text = read("tests/fixtures/README.md");
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut names = Vec::new();
    walk(&root, &root, &mut names);
    assert!(
        names.len() > 20,
        "expected the fixture tree, got {}",
        names.len()
    );
    for name in names {
        let part = section(&text, &format!("## {name}"));
        assert!(
            part.to_lowercase().contains("synthetic"),
            "{name} is not described as synthetic"
        );
    }
}

fn walk(dir: &std::path::Path, root: &std::path::Path, names: &mut Vec<String>) {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .unwrap_or_else(|err| panic!("read {}: {err}", dir.display()))
        .map(|entry| entry.expect("entry"))
        .collect();
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, root, names);
            continue;
        }
        if path.file_name().and_then(|name| name.to_str()) == Some("README.md") {
            continue;
        }
        let rel = path
            .strip_prefix(root)
            .expect("prefix")
            .to_str()
            .expect("utf-8")
            .replace('\\', "/");
        names.push(rel);
    }
}
