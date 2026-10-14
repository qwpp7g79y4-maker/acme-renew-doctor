//! Properties on arbitrary input for `--from-log`, `--from-timer-status`,
//! the certificate-date files and the domain argument.
//! Clock: ACME_RENEW_DOCTOR_NOW=1791273600.
//! proptest is a dev-dependency. At most 32 cases per test; generated text
//! is at most 48 characters. The binary stays read-only.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use proptest::prelude::*;

const NOW: &str = "1791273600";
const NOW_SECS: i64 = 1_791_273_600;

const DENY: &[&str] = &[
    "--force",
    "--force-renewal",
    "renew",
    "certonly",
    "revoke",
    "delete",
    "--renew",
    "--issue",
    "--remove",
    "reload",
    "restart",
    "start",
    "stop",
    "enable",
    "disable",
    "kill",
    "mask",
    "rm",
    "mv",
    "cp",
    "dd",
    "tee",
    "chmod",
    "chown",
    "wget",
    "-i",
    "--now",
    "graceful",
];

fn proptest_config(cases: u32) -> ProptestConfig {
    let mut config = ProptestConfig::with_cases(cases);
    config.max_shrink_iters = 32;
    config.failure_persistence = None;
    config
}

struct TempDir {
    dir: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "acme-renew-doctor-proptest-{}-{}-{label}",
            std::process::id(),
            n
        ));
        std::fs::create_dir_all(&dir)
            .unwrap_or_else(|err| panic!("tempdir {}: {err}", dir.display()));
        Self { dir }
    }

    fn write(&self, name: &str, text: &str) -> String {
        let path = self.dir.join(name);
        std::fs::write(&path, text).unwrap_or_else(|err| panic!("write {}: {err}", path.display()));
        path.to_str().expect("path is utf-8").to_string()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

struct Ran {
    exit: i32,
    stdout: String,
    stderr: String,
}

fn run_json(args: &[String]) -> Result<Ran, String> {
    let output = Command::new(env!("CARGO_BIN_EXE_acme-renew-doctor"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(args)
        .env_remove("ACME_RENEW_DOCTOR_NOW")
        .env("ACME_RENEW_DOCTOR_NOW", NOW)
        .output()
        .map_err(|err| format!("binary did not start: {err}"))?;
    let exit = output
        .status
        .code()
        .ok_or_else(|| "process ended on a signal".to_string())?;
    let stdout =
        String::from_utf8(output.stdout).map_err(|err| format!("stdout is not utf-8: {err}"))?;
    let stderr =
        String::from_utf8(output.stderr).map_err(|err| format!("stderr is not utf-8: {err}"))?;
    Ok(Ran {
        exit,
        stdout,
        stderr,
    })
}

fn fixture(rel: &str) -> String {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(rel)
        .to_str()
        .expect("fixture path is utf-8")
        .to_string()
}

fn json_document_ok(text: &str) -> Result<(), String> {
    let mut parser = JsonParser {
        bytes: text.as_bytes(),
        index: 0,
    };
    parser.skip_ws();
    parser.value()?;
    parser.skip_ws();
    if parser.index != parser.bytes.len() {
        return Err(format!("text after the document at byte {}", parser.index));
    }
    Ok(())
}

struct JsonParser<'a> {
    bytes: &'a [u8],
    index: usize,
}

impl JsonParser<'_> {
    fn skip_ws(&mut self) {
        while self
            .bytes
            .get(self.index)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.index += 1;
        }
    }

    fn value(&mut self) -> Result<(), String> {
        self.skip_ws();
        match self.bytes.get(self.index).copied() {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => self.string().map(|_| ()),
            Some(b't') => self.literal(b"true"),
            Some(b'f') => self.literal(b"false"),
            Some(b'n') => self.literal(b"null"),
            Some(b'-') | Some(b'0'..=b'9') => self.number(),
            Some(other) => Err(format!("unexpected byte {other} at {}", self.index)),
            None => Err("unexpected end".to_string()),
        }
    }

    fn object(&mut self) -> Result<(), String> {
        self.index += 1;
        self.skip_ws();
        if self.bytes.get(self.index) == Some(&b'}') {
            self.index += 1;
            return Ok(());
        }
        loop {
            self.skip_ws();
            if self.bytes.get(self.index) != Some(&b'"') {
                return Err(format!("object key missing at {}", self.index));
            }
            self.string()?;
            self.skip_ws();
            if self.bytes.get(self.index) != Some(&b':') {
                return Err(format!("':' missing at {}", self.index));
            }
            self.index += 1;
            self.value()?;
            self.skip_ws();
            match self.bytes.get(self.index) {
                Some(&b'}') => {
                    self.index += 1;
                    return Ok(());
                }
                Some(&b',') => self.index += 1,
                _ => return Err(format!("object does not continue at {}", self.index)),
            }
        }
    }

    fn array(&mut self) -> Result<(), String> {
        self.index += 1;
        self.skip_ws();
        if self.bytes.get(self.index) == Some(&b']') {
            self.index += 1;
            return Ok(());
        }
        loop {
            self.value()?;
            self.skip_ws();
            match self.bytes.get(self.index) {
                Some(&b']') => {
                    self.index += 1;
                    return Ok(());
                }
                Some(&b',') => self.index += 1,
                _ => return Err(format!("array does not continue at {}", self.index)),
            }
        }
    }

    fn string(&mut self) -> Result<(), String> {
        self.index += 1;
        while let Some(byte) = self.bytes.get(self.index).copied() {
            if byte == b'"' {
                self.index += 1;
                return Ok(());
            }
            if byte == b'\\' {
                self.index += 1;
                let escape = self
                    .bytes
                    .get(self.index)
                    .copied()
                    .ok_or_else(|| "escape without a character".to_string())?;
                self.index += 1;
                if escape == b'u' {
                    for _ in 0..4 {
                        let hex = self
                            .bytes
                            .get(self.index)
                            .copied()
                            .ok_or_else(|| "\\u truncated".to_string())?;
                        if !hex.is_ascii_hexdigit() {
                            return Err(format!("\\u is not hex at {}", self.index));
                        }
                        self.index += 1;
                    }
                } else if !matches!(
                    escape,
                    b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't'
                ) {
                    return Err(format!("unknown escape {escape}"));
                }
                continue;
            }
            if byte < 0x20 {
                return Err(format!("unescaped control character at {}", self.index));
            }
            self.bump_char()?;
        }
        Err("string not closed".to_string())
    }

    fn bump_char(&mut self) -> Result<(), String> {
        let byte = self.bytes[self.index];
        let width = if byte < 0x80 {
            1
        } else if byte & 0xE0 == 0xC0 {
            2
        } else if byte & 0xF0 == 0xE0 {
            3
        } else if byte & 0xF8 == 0xF0 {
            4
        } else {
            return Err(format!("invalid utf-8 at {}", self.index));
        };
        if self.index + width > self.bytes.len() {
            return Err("truncated utf-8".to_string());
        }
        self.index += width;
        Ok(())
    }

    fn literal(&mut self, expected: &[u8]) -> Result<(), String> {
        if self.bytes[self.index..].starts_with(expected) {
            self.index += expected.len();
            Ok(())
        } else {
            Err(format!("expected {}", String::from_utf8_lossy(expected)))
        }
    }

    fn number(&mut self) -> Result<(), String> {
        if self.bytes.get(self.index) == Some(&b'-') {
            self.index += 1;
        }
        match self.bytes.get(self.index) {
            Some(b'0') => self.index += 1,
            Some(b'1'..=b'9') => {
                while matches!(self.bytes.get(self.index), Some(b'0'..=b'9')) {
                    self.index += 1;
                }
            }
            _ => return Err(format!("number missing at {}", self.index)),
        }
        if self.bytes.get(self.index) == Some(&b'.') {
            self.index += 1;
            let frac = self.index;
            while matches!(self.bytes.get(self.index), Some(b'0'..=b'9')) {
                self.index += 1;
            }
            if self.index == frac {
                return Err("fraction missing".to_string());
            }
        }
        if matches!(self.bytes.get(self.index), Some(b'e' | b'E')) {
            self.index += 1;
            if matches!(self.bytes.get(self.index), Some(b'+' | b'-')) {
                self.index += 1;
            }
            let exp = self.index;
            while matches!(self.bytes.get(self.index), Some(b'0'..=b'9')) {
                self.index += 1;
            }
            if self.index == exp {
                return Err("exponent missing".to_string());
            }
        }
        Ok(())
    }
}

fn parse_json_string(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    if bytes.first() != Some(&b'"') {
        return None;
    }
    let mut out = String::new();
    let mut index = 1;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'"' {
            return Some(out);
        }
        if byte != b'\\' {
            let width = utf8_width(byte)?;
            if index + width > bytes.len() {
                return None;
            }
            out.push_str(std::str::from_utf8(&bytes[index..index + width]).ok()?);
            index += width;
            continue;
        }
        index += 1;
        let escape = *bytes.get(index)?;
        index += 1;
        match escape {
            b'"' => out.push('"'),
            b'\\' => out.push('\\'),
            b'/' => out.push('/'),
            b'b' => out.push('\u{0008}'),
            b'f' => out.push('\u{000c}'),
            b'n' => out.push('\n'),
            b'r' => out.push('\r'),
            b't' => out.push('\t'),
            b'u' => {
                if index + 4 > bytes.len() {
                    return None;
                }
                let hex = std::str::from_utf8(&bytes[index..index + 4]).ok()?;
                let code = u32::from_str_radix(hex, 16).ok()?;
                out.push(char::from_u32(code)?);
                index += 4;
            }
            _ => return None,
        }
    }
    None
}

fn utf8_width(byte: u8) -> Option<usize> {
    if byte < 0x80 {
        Some(1)
    } else if byte & 0xE0 == 0xC0 {
        Some(2)
    } else if byte & 0xF0 == 0xE0 {
        Some(3)
    } else if byte & 0xF8 == 0xF0 {
        Some(4)
    } else {
        None
    }
}

fn next_check_commands(json: &str) -> Result<Vec<String>, String> {
    let Some(start) = json.find("\"next_checks\":") else {
        return Err("no next_checks".to_string());
    };
    let mut rest = &json[start..];
    let needle = "\"command\":";
    let mut commands = Vec::new();
    while let Some(pos) = rest.find(needle) {
        let after = rest[pos + needle.len()..].trim_start();
        let value =
            parse_json_string(after).ok_or_else(|| "command is not a json string".to_string())?;
        commands.push(value);
        rest = &rest[pos + needle.len()..];
    }
    Ok(commands)
}

fn domain_has_injection(domain: &str) -> bool {
    domain.chars().any(|ch| {
        matches!(
            ch,
            ';' | '$'
                | '`'
                | '|'
                | '&'
                | '*'
                | ' '
                | '"'
                | '\''
                | '\n'
                | '\r'
                | '\u{1b}'
                | '<'
                | '>'
        ) || (ch as u32) < 0x20
            || !ch.is_ascii()
    })
}

fn command_violations(command: &str, domain: &str) -> Vec<String> {
    let mut violations = Vec::new();
    if command.contains(';') {
        violations.push("semicolon".to_string());
    }
    if command.contains("$(") {
        violations.push("command substitution".to_string());
    }
    if command.contains('`') {
        violations.push("backtick".to_string());
    }
    if command.contains("&&") {
        violations.push("&&".to_string());
    }
    if command.contains('\n') || command.contains('\r') {
        violations.push("newline".to_string());
    }
    if command.chars().any(|ch| ch == '\u{1b}') {
        violations.push("ansi".to_string());
    }
    if command.contains("--force-renewal") || command.contains("acme.sh --force") {
        violations.push("force-renewal".to_string());
    }
    if command.replace(" | ", " ").contains('|') {
        violations.push("pipe".to_string());
    }
    for token in command.split_whitespace() {
        if token == "-I" {
            continue;
        }
        if DENY.iter().any(|item| token.eq_ignore_ascii_case(item)) {
            violations.push(format!("denylist word {token}"));
        }
    }
    if domain_has_injection(domain) && command_places_domain(command, domain) {
        violations.push("unsafe domain".to_string());
    }
    violations
}

/// The host a catalog command substituted, not an arbitrary substring.
/// A space between words, or a letter inside "acme-challenge", is not that host.
fn command_places_domain(command: &str, domain: &str) -> bool {
    if domain.is_empty() {
        return false;
    }
    let between = [("http://", "/"), ("/live/", "/"), ("-connect ", ":")];
    if between
        .iter()
        .any(|(start, end)| host_between(command, start, end) == Some(domain))
    {
        return true;
    }
    let prefixes = [
        "dig +short AAAA ",
        "dig +short TXT _acme-challenge.",
        "dig +short NS ",
        "dig +short A ",
    ];
    if prefixes
        .iter()
        .any(|prefix| command.strip_prefix(prefix) == Some(domain))
    {
        return true;
    }
    servername_host(command) == Some(domain)
}

fn host_between<'a>(command: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let from = command.find(start)? + start.len();
    let rest = command.get(from..)?;
    let until = rest.find(end)?;
    rest.get(..until)
}

fn servername_host(command: &str) -> Option<&str> {
    let rest = command.split("-servername ").nth(1)?;
    Some(rest.split(" | ").next().unwrap_or(rest))
}

/// Each `{domain}` in a catalog string is a host place this function knows.
/// A new place that is only a substring, or that sits somewhere else, fails here.
#[test]
fn command_places_domain_knows_every_catalog_slot() {
    let source = include_str!("../src/safe.rs");
    let templates = catalog_domain_templates(source);
    assert!(
        !templates.is_empty(),
        "no {{domain}} string found in the catalog"
    );
    const SENTINEL: &str = "slot-marker.example";
    const OTHER: &str = "other-host.example";
    let mut slots = 0;
    for template in &templates {
        let count = template.matches("{domain}").count();
        for chosen in 0..count {
            slots += 1;
            let command = fill_one_domain_slot(template, chosen, SENTINEL, OTHER);
            assert!(
                command_places_domain(&command, SENTINEL),
                "catalog slot {chosen} of {count} is not a known host place\n  template: {template}\n  command: {command}"
            );
        }
    }
    assert!(slots >= 10, "found only {slots} domain slots");
}

fn catalog_domain_templates(source: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut start = 0;
    while let Some(rel) = source[start..].find("{domain}") {
        let at = start + rel;
        let open = source[..at]
            .rfind('"')
            .expect("domain slot is inside a string");
        let close_rel = source[at + "{domain}".len()..]
            .find('"')
            .expect("domain string has a closing quote");
        let close = at + "{domain}".len() + close_rel;
        let literal = source[open + 1..close].to_string();
        if !found.contains(&literal) {
            found.push(literal);
        }
        start = at + "{domain}".len();
    }
    found
}

fn fill_one_domain_slot(template: &str, chosen: usize, sentinel: &str, other: &str) -> String {
    let mut out = String::new();
    let mut rest = template;
    let mut index = 0;
    while let Some(at) = rest.find("{domain}") {
        out.push_str(&rest[..at]);
        out.push_str(if index == chosen { sentinel } else { other });
        rest = &rest[at + "{domain}".len()..];
        index += 1;
    }
    out.push_str(rest);
    out
}

fn ok_is_justified(log: &str, timer: &str, disk: &str, live: &str) -> bool {
    if !acme_renew_doctor::certbot_log::has_certbot_lines(log) {
        return false;
    }
    if !acme_renew_doctor::certbot_log::parse(log).is_empty() {
        return false;
    }
    let Some(show) = acme_renew_doctor::timer::parse_systemctl_show(timer) else {
        return false;
    };
    if show
        .service
        .as_ref()
        .is_some_and(|service| service.active_state == "failed")
    {
        return false;
    }
    if let Some(timer) = &show.timer {
        if timer.load_state != "loaded"
            || timer.unit_file_state != "enabled"
            || timer.active_state != "active"
        {
            return false;
        }
    } else if show
        .snap_timer
        .as_ref()
        .is_some_and(|snap| snap.load_state == "loaded" && snap.active_state == "active")
    {
        return false;
    }
    let Some(disk_time) = acme_renew_doctor::certtime::parse_openssl_enddate(disk) else {
        return false;
    };
    let Some(live_time) = acme_renew_doctor::certtime::parse_openssl_enddate(live) else {
        return false;
    };
    if disk_time != live_time {
        return false;
    }
    let now = acme_renew_doctor::certtime::from_unix_seconds(NOW_SECS);
    disk_time.days_until(&now) > acme_renew_doctor::rules::NOT_DUE_DAYS
}

fn assert_report_bounds(ran: &Ran, domain: &str) -> Result<(), TestCaseError> {
    prop_assert!(
        (0..=3).contains(&ran.exit),
        "exit {} outside 0-3\nstderr:\n{}\nstdout:\n{}",
        ran.exit,
        ran.stderr,
        ran.stdout
    );
    prop_assert!(
        !ran.stderr.contains("panicked") && !ran.stdout.contains("panicked"),
        "panic\nstderr:\n{}\nstdout:\n{}",
        ran.stderr,
        ran.stdout
    );
    if let Err(err) = json_document_ok(&ran.stdout) {
        return Err(TestCaseError::fail(format!(
            "json invalid: {err}\n{}",
            ran.stdout
        )));
    }
    prop_assert!(
        ran.stdout.contains(&format!("\"exit_code\": {}", ran.exit)),
        "exit_code differs from the process exit {}\n{}",
        ran.exit,
        ran.stdout
    );
    let says_ok = ran.stdout.contains("\"code\": \"OK_NOT_DUE\"");
    if says_ok || ran.exit == 0 {
        prop_assert!(
            says_ok && ran.exit == 0,
            "exit 0 and OK_NOT_DUE belong together\n{}",
            ran.stdout
        );
    }
    let commands = next_check_commands(&ran.stdout).map_err(TestCaseError::fail)?;
    for command in &commands {
        let violations = command_violations(command, domain);
        prop_assert!(
            violations.is_empty(),
            "next_check contains forbidden content {violations:?}: {command}"
        );
    }
    Ok(())
}

#[test]
fn blank_or_letter_domain_is_not_treated_as_check_text() {
    // A space sits in every command, a tab is an unsafe character, and "a"
    // occurs inside ordinary words such as "acme-challenge". None of those
    // strings is the host the check was given.
    for domain in [" ", "\t", "a"] {
        let args = vec![
            "--json".to_string(),
            "--from-log".to_string(),
            fixture("tests/fixtures/certbot/http01-timeout.log"),
            "--".to_string(),
            domain.to_string(),
        ];
        let ran = run_json(&args).unwrap_or_else(|err| panic!("domain {domain:?}: {err}"));
        assert!(
            (0..=3).contains(&ran.exit),
            "domain {domain:?} exit {}\n{}",
            ran.exit,
            ran.stderr
        );
        let commands = next_check_commands(&ran.stdout)
            .unwrap_or_else(|err| panic!("domain {domain:?}: {err}\n{}", ran.stdout));
        assert!(
            !commands.is_empty(),
            "domain {domain:?} produced no checks\n{}",
            ran.stdout
        );
        assert!(
            commands
                .iter()
                .any(|command| command.contains("YOUR_DOMAIN")),
            "domain {domain:?} was not replaced with the placeholder\n{}",
            ran.stdout
        );
        for command in &commands {
            let violations = command_violations(command, domain);
            assert!(
                violations.is_empty(),
                "domain {domain:?} flagged {violations:?} in {command}"
            );
        }
    }
}

proptest! {
    #![proptest_config(proptest_config(24))]

    #[test]
    fn arbitrary_from_files_and_domain_stay_bounded(
        log in "[\\x01-\\x7e]{0,48}",
        timer in "[\\x01-\\x7e]{0,48}",
        disk in "[\\x01-\\x7e]{0,48}",
        live in "[\\x01-\\x7e]{0,48}",
        domain in "[\\x01-\\x7e]{0,32}",
    ) {
        let temp = TempDir::new("arbitrary");
        let log_path = temp.write("log.txt", &log);
        let timer_path = temp.write("timer.txt", &timer);
        let disk_path = temp.write("disk.txt", &disk);
        let live_path = temp.write("live.txt", &live);
        let args = vec![
            "--json".to_string(),
            "--from-log".to_string(),
            log_path,
            "--from-timer-status".to_string(),
            timer_path,
            "--from-cert-disk".to_string(),
            disk_path,
            "--from-cert-live".to_string(),
            live_path,
            "--".to_string(),
            domain.clone(),
        ];
        let ran = run_json(&args).map_err(TestCaseError::fail)?;
        assert_report_bounds(&ran, &domain)?;
        let says_ok = ran.stdout.contains("\"code\": \"OK_NOT_DUE\"");
        if says_ok {
            prop_assert!(
                ok_is_justified(&log, &timer, &disk, &live),
                "false OK_NOT_DUE\n{}",
                ran.stdout
            );
        }
    }
}

proptest! {
    #![proptest_config(proptest_config(32))]

    #[test]
    fn injected_domain_next_checks_stay_free_of_shell_and_denylist(
        head in "[a-z]{1,6}",
        payload in prop_oneof![
            Just(";rm".to_string()),
            Just("$(id)".to_string()),
            Just("`id`".to_string()),
            Just("|id".to_string()),
            Just("&&id".to_string()),
            Just("\nid".to_string()),
            Just("\u{1b}[31m".to_string()),
        ],
        tail in "[a-z]{1,4}",
        timer in "[\\x01-\\x7e]{0,40}",
        disk in "[\\x01-\\x7e]{0,40}",
        live in "[\\x01-\\x7e]{0,40}",
    ) {
        let domain = format!("{head}{payload}{tail}.example.com");
        let temp = TempDir::new("inject");
        let log_path = fixture("tests/fixtures/certbot/http01-timeout.log");
        let timer_path = temp.write("timer.txt", &timer);
        let disk_path = temp.write("disk.txt", &disk);
        let live_path = temp.write("live.txt", &live);
        let args = vec![
            "--json".to_string(),
            "--from-log".to_string(),
            log_path,
            "--from-timer-status".to_string(),
            timer_path,
            "--from-cert-disk".to_string(),
            disk_path,
            "--from-cert-live".to_string(),
            live_path,
            "--".to_string(),
            domain.clone(),
        ];
        let ran = run_json(&args).map_err(TestCaseError::fail)?;
        assert_report_bounds(&ran, &domain)?;
        prop_assert_eq!(ran.exit, 1, "timeout log should exit 1\n{}", ran.stdout);
        prop_assert!(
            ran.stdout.contains("\"code\": \"LAYER2_HTTP01_TIMEOUT\""),
            "timeout log should give LAYER2_HTTP01_TIMEOUT\n{}",
            ran.stdout
        );
        prop_assert!(
            !ran.stdout.contains("\"code\": \"OK_NOT_DUE\""),
            "false OK_NOT_DUE on a timeout log\n{}",
            ran.stdout
        );
        let commands = next_check_commands(&ran.stdout).map_err(TestCaseError::fail)?;
        prop_assert!(
            !commands.is_empty(),
            "next_checks should be filled\n{}",
            ran.stdout
        );
        for command in &commands {
            prop_assert!(
                !command.contains(&domain),
                "unsafe domain in next_check: {command}"
            );
        }
    }
}

fn assert_python_json(stdout: &str) {
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

#[test]
fn python_json_tool_accepts_injected_and_garbage_reports() {
    let payloads = [";rm", "$(id)", "`id`", "|id", "&&id", "\nid", "\u{1b}[31m"];
    for payload in payloads {
        let domain = format!("aa{payload}zz.example.com");
        let temp = TempDir::new("pyjson");
        let args = vec![
            "--json".to_string(),
            "--from-log".to_string(),
            fixture("tests/fixtures/certbot/http01-timeout.log"),
            "--from-timer-status".to_string(),
            temp.write("timer.txt", ";$(id)`id`|&&\n--force-renewal"),
            "--from-cert-disk".to_string(),
            temp.write("disk.txt", "notAfter=not a date; rm\n"),
            "--from-cert-live".to_string(),
            temp.write("live.txt", "\u{1b}[31m\n"),
            "--".to_string(),
            domain.clone(),
        ];
        let ran = run_json(&args).expect("binary");
        assert!(
            (0..=3).contains(&ran.exit),
            "exit {}\n{}",
            ran.exit,
            ran.stderr
        );
        assert!(!ran.stdout.contains("panicked") && !ran.stderr.contains("panicked"));
        assert_python_json(&ran.stdout);
        assert!(!ran.stdout.contains("\"code\": \"OK_NOT_DUE\""));
        let commands = next_check_commands(&ran.stdout).expect("commands");
        assert!(!commands.is_empty(), "{}", ran.stdout);
        for command in &commands {
            let violations = command_violations(command, &domain);
            assert!(violations.is_empty(), "{violations:?}: {command}");
        }
    }

    let temp = TempDir::new("pygarbage");
    let domain = "a.com; rm -rf /".to_string();
    let args = vec![
        "--json".to_string(),
        "--from-log".to_string(),
        temp.write("log.txt", "\u{1b}garbage $(id) `x` && y | z\n"),
        "--from-timer-status".to_string(),
        temp.write("timer.txt", "Id=not a timer\n"),
        "--from-cert-disk".to_string(),
        temp.write("disk.txt", ""),
        "--from-cert-live".to_string(),
        temp.write("live.txt", "notAfter=Jan  1 00:00:00 1999 GMT\n"),
        "--".to_string(),
        domain.clone(),
    ];
    let ran = run_json(&args).expect("binary");
    assert!((0..=3).contains(&ran.exit), "{}", ran.stderr);
    assert_python_json(&ran.stdout);
    assert!(!ran.stdout.contains("\"code\": \"OK_NOT_DUE\""));
    let commands = next_check_commands(&ran.stdout).expect("commands");
    for command in &commands {
        let violations = command_violations(command, &domain);
        assert!(violations.is_empty(), "{violations:?}: {command}");
    }
}
