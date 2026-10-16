use std::path::PathBuf;

use crate::model::{
    ClientKind, Code, Confidence, EvidenceSource, ExitStatus, Layer, Report, Snapshot,
};
use crate::safe::{self, SafeCheck};

pub const SCHEMA_VERSION: u32 = 1;

const LIVE_NOTE: &str = "note: live collection is not built yet; pass --from-log, --from-timer-status, --from-cert-disk and/or --from-cert-live.";
const INVALID_DOMAIN_NOTE: &str = "note: the domain is not a valid hostname (it needs at least two labels of 1 to 63 characters, no label may start or end with '-', and the name may be at most 253 characters); replace YOUR_DOMAIN yourself.";
const UNSAFE_DOMAIN_NOTE: &str = "note: the domain contains characters that are unsafe in a shell command; replace YOUR_DOMAIN yourself.";

pub fn human(report: &Report, checks: &[SafeCheck]) -> String {
    let snapshot = &report.snapshot;
    let mut lines = vec![
        format!(
            "acme-renew-doctor {} (read-only, nothing was changed)",
            env!("CARGO_PKG_VERSION")
        ),
        format!(
            "target: {} · client: {}",
            target(snapshot),
            client_name(snapshot.client)
        ),
        format!(
            "inputs: log={} · timer status={} · cert disk={} · cert live={}",
            path_or_none(&snapshot.from_log),
            path_or_none(&snapshot.from_timer_status),
            path_or_none(&snapshot.from_cert_disk),
            path_or_none(&snapshot.from_cert_live)
        ),
        String::new(),
    ];

    for (index, finding) in report.findings.iter().enumerate() {
        if index > 0 {
            lines.push(String::new());
        }
        lines.push(format!(
            "{} {}  confidence={}  layer={}",
            symbol(finding.code),
            finding.code.as_str(),
            confidence_name(finding.confidence),
            layer_name(finding.layer)
        ));
        lines.push("  evidence:".to_string());
        for evidence in &finding.evidence {
            lines.push(format!(
                "  • [{}] {}",
                source_name(evidence.source),
                escape_file_text(&evidence.text)
            ));
        }
    }

    if !checks.is_empty() {
        if !report.findings.is_empty() {
            lines.push(String::new());
        }
        lines.push(
            "Next (SAFE copy-paste checks, read-only; Doctor runs nothing and will NOT renew or reload for you):"
                .to_string(),
        );
        for check in checks {
            lines.push(format!("  → {}", check.command));
            lines.push(format!("    why: {}", check.why));
        }
        if report
            .findings
            .iter()
            .any(|finding| finding.code == Code::Layer2Http01Timeout)
        {
            lines.push(
                "  # also test from outside your network: the CA does not see what localhost sees"
                    .to_string(),
            );
        }
        if report
            .findings
            .iter()
            .any(|finding| finding.code == Code::Layer2RateLimit)
        {
            lines.push(
                "  # wait until the retry-after time; repeated attempts only extend the problem"
                    .to_string(),
            );
        }
        lines.push(
            "  ⚠ Do not force a renewal: Let's Encrypt rate limits apply. Fix the named layer first."
                .to_string(),
        );
        lines.push("    (dangerous suggestions suppressed by default)".to_string());
    }

    if snapshot.from_log.is_none()
        && snapshot.from_timer_status.is_none()
        && snapshot.from_cert_disk.is_none()
        && snapshot.from_cert_live.is_none()
    {
        if !report.findings.is_empty() {
            lines.push(String::new());
        }
        lines.push(LIVE_NOTE.to_string());
    }
    for note in report_notes(report) {
        lines.push(note);
    }

    let status = report.exit_status();
    lines.push(String::new());
    lines.push(format!("exit {}: {}", status.code(), exit_label(status)));
    let mut text = lines.join("\n");
    text.push('\n');
    text
}

pub fn json(report: &Report, checks: &[SafeCheck]) -> String {
    let snapshot = &report.snapshot;
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str("  \"schema_version\": ");
    out.push_str(&SCHEMA_VERSION.to_string());
    out.push_str(",\n");
    out.push_str("  \"tool\": {\n");
    out.push_str("    \"name\": \"acme-renew-doctor\",\n");
    out.push_str("    \"version\": ");
    push_json_string(&mut out, env!("CARGO_PKG_VERSION"));
    out.push_str("\n  },\n");
    out.push_str("  \"input\": {\n");
    out.push_str("    \"domain\": ");
    push_json_option(&mut out, shown_domain(snapshot));
    out.push_str(",\n");
    out.push_str("    \"all\": ");
    out.push_str(if snapshot.all { "true" } else { "false" });
    out.push_str(",\n");
    out.push_str("    \"client\": ");
    push_json_string(&mut out, client_name(snapshot.client));
    out.push_str(",\n");
    out.push_str("    \"from_log\": ");
    push_json_option(
        &mut out,
        snapshot
            .from_log
            .as_ref()
            .map(|path| path.display().to_string())
            .as_deref(),
    );
    out.push_str(",\n");
    out.push_str("    \"from_timer_status\": ");
    push_json_option(
        &mut out,
        snapshot
            .from_timer_status
            .as_ref()
            .map(|path| path.display().to_string())
            .as_deref(),
    );
    out.push_str(",\n");
    out.push_str("    \"from_cert_disk\": ");
    push_json_option(
        &mut out,
        snapshot
            .from_cert_disk
            .as_ref()
            .map(|path| path.display().to_string())
            .as_deref(),
    );
    out.push_str(",\n");
    out.push_str("    \"from_cert_live\": ");
    push_json_option(
        &mut out,
        snapshot
            .from_cert_live
            .as_ref()
            .map(|path| path.display().to_string())
            .as_deref(),
    );
    out.push_str("\n  },\n");
    out.push_str("  \"findings\": [");
    if report.findings.is_empty() {
        out.push_str("],\n");
    } else {
        out.push('\n');
        for (index, finding) in report.findings.iter().enumerate() {
            if index > 0 {
                out.push_str(",\n");
            }
            out.push_str("    {\n");
            out.push_str("      \"code\": ");
            push_json_string(&mut out, finding.code.as_str());
            out.push_str(",\n");
            out.push_str("      \"layer\": ");
            push_json_option(&mut out, layer_json(finding.layer));
            out.push_str(",\n");
            out.push_str("      \"confidence\": ");
            push_json_string(&mut out, confidence_name(finding.confidence));
            out.push_str(",\n");
            out.push_str("      \"evidence\": [");
            if finding.evidence.is_empty() {
                out.push_str("]\n");
            } else {
                out.push('\n');
                for (evidence_index, evidence) in finding.evidence.iter().enumerate() {
                    if evidence_index > 0 {
                        out.push_str(",\n");
                    }
                    out.push_str("        {\n");
                    out.push_str("          \"source\": ");
                    push_json_string(&mut out, source_name(evidence.source));
                    out.push_str(",\n");
                    out.push_str("          \"text\": ");
                    push_json_string(&mut out, &evidence.text);
                    out.push_str("\n        }");
                }
                out.push_str("\n      ]\n");
            }
            out.push_str("    }");
        }
        out.push_str("\n  ],\n");
    }
    push_next_checks(&mut out, checks);
    let notes = report_notes(report);
    if !notes.is_empty() {
        out.push_str("  \"notes\": [");
        for (index, note) in notes.iter().enumerate() {
            if index > 0 {
                out.push_str(", ");
            }
            push_json_string(&mut out, note);
        }
        out.push_str("],\n");
    }
    out.push_str("  \"exit_code\": ");
    out.push_str(&report.exit_status().code().to_string());
    out.push_str("\n}\n");
    out
}

fn replacement_note(count: usize) -> Option<String> {
    match count {
        0 => None,
        1 => Some("note: replaced 1 invalid UTF-8 byte".to_string()),
        count => Some(format!("note: replaced {count} invalid UTF-8 bytes")),
    }
}

fn report_notes(report: &Report) -> Vec<String> {
    let mut notes = Vec::new();
    if let Some(note) = replacement_note(report.replaced_invalid_utf8_bytes) {
        notes.push(note);
    }
    if let Some(domain) = report.snapshot.domain.as_deref() {
        if safe::safe_domain(Some(domain)).is_none() {
            let only_hostname_bytes = !domain.is_empty()
                && domain
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.');
            notes.push(if only_hostname_bytes {
                INVALID_DOMAIN_NOTE.to_string()
            } else {
                UNSAFE_DOMAIN_NOTE.to_string()
            });
        }
    }
    notes
}

fn push_next_checks(out: &mut String, checks: &[SafeCheck]) {
    out.push_str("  \"next_checks\": [");
    if checks.is_empty() {
        out.push_str("],\n");
        return;
    }
    out.push('\n');
    for (index, check) in checks.iter().enumerate() {
        if index > 0 {
            out.push_str(",\n");
        }
        out.push_str("    {\n");
        out.push_str("      \"for\": ");
        push_json_string(out, check.for_code.as_str());
        out.push_str(",\n");
        out.push_str("      \"command\": ");
        push_json_string(out, &check.command);
        out.push_str(",\n");
        out.push_str("      \"why\": ");
        push_json_string(out, &check.why);
        out.push_str(",\n");
        out.push_str("      \"safety\": \"read-only\"\n");
        out.push_str("    }");
    }
    out.push_str("\n  ],\n");
}

fn shown_domain(snapshot: &Snapshot) -> Option<&str> {
    let domain = snapshot.domain.as_deref()?;
    Some(safe::safe_domain(Some(domain)).unwrap_or("YOUR_DOMAIN"))
}

fn target(snapshot: &Snapshot) -> String {
    if let Some(domain) = shown_domain(snapshot) {
        domain.to_string()
    } else if snapshot.all {
        "all".to_string()
    } else {
        "(none)".to_string()
    }
}

fn push_json_option(out: &mut String, value: Option<&str>) {
    match value {
        Some(text) => push_json_string(out, text),
        None => out.push_str("null"),
    }
}

fn push_json_string(out: &mut String, text: &str) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c if json_escaped(c) => {
                out.push_str(&format!("\\u{code:04x}", code = c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Characters that `--json` writes as a `\uXXXX` escape: C0 controls, DEL,
/// C1 controls and bidirectional marks. Raw, they can move the cursor or
/// reorder the line when the JSON is shown in a terminal. U+2028 and U+2029
/// stay the character.
fn json_escaped(ch: char) -> bool {
    let code = u32::from(ch);
    code < 0x20 || code == 0x7f || (0x80..=0x9f).contains(&code) || bidi_control(code)
}

/// File text on one line. A backslash is escaped so a newline and the two
/// characters `\` and `n` stay distinct.
pub fn escape_file_text(text: &str) -> String {
    escape_controls(text, true)
}

/// A path on one line of the text report.
///
/// Printed raw, backslashes unchanged, when the path contains no character
/// [`file_text_control`] would escape and it does not start with `"`.
/// `file_text_control` includes the bidirectional check. `C:\Users\certbot\log.txt`
/// stays as written. A real newline is quoted as `"a\nb.log"`. The two
/// characters `\` and `n` stay `a\nb.log`.
///
/// Otherwise the path is wrapped in double quotes: `\` becomes `\\`, `"` becomes
/// `\"`, a newline becomes `\n`, a carriage return becomes `\r`, a tab becomes
/// `\t`, and any other control or bidirectional character becomes `\u{..}`.
/// A raw path never starts with `"`, so it cannot look like a quoted path.
fn escape_path_text(text: &str) -> String {
    if !text.starts_with('"') && !text.chars().any(file_text_control) {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if file_text_control(c) => {
                out.push_str(&format!("\\u{{{:x}}}", u32::from(c)));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn escape_controls(text: &str, escape_backslash: bool) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '\\' if escape_backslash => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if file_text_control(c) => {
                out.push_str(&format!("\\u{{{:x}}}", u32::from(c)));
            }
            c => out.push(c),
        }
    }
    out
}

fn file_text_control(ch: char) -> bool {
    let code = u32::from(ch);
    code < 0x20
        || code == 0x7f
        || (0x80..=0x9f).contains(&code)
        || code == 0x2028
        || code == 0x2029
        || bidi_control(code)
}

/// Bidirectional overrides and isolates. They are not C0 controls, but they
/// can reorder the rest of the line if they are printed raw.
fn bidi_control(code: u32) -> bool {
    (0x202A..=0x202E).contains(&code)
        || (0x2066..=0x2069).contains(&code)
        || code == 0x200E
        || code == 0x200F
        || code == 0x061C
}

fn path_or_none(path: &Option<PathBuf>) -> String {
    match path {
        Some(path) => escape_path_text(&path.display().to_string()),
        None => "(none)".to_string(),
    }
}

fn client_name(kind: ClientKind) -> &'static str {
    match kind {
        ClientKind::Certbot => "certbot",
        ClientKind::AcmeSh => "acme.sh",
        ClientKind::Auto => "auto",
    }
}

fn symbol(code: Code) -> &'static str {
    if code.layer().is_some() {
        "✗"
    } else if code == Code::OkNotDue {
        "✓"
    } else {
        "?"
    }
}

fn confidence_name(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Low => "low",
        Confidence::Medium => "medium",
        Confidence::High => "high",
    }
}

fn layer_name(layer: Option<Layer>) -> &'static str {
    match layer {
        Some(Layer::Scheduler) => "scheduler",
        Some(Layer::Validation) => "validation",
        Some(Layer::Deployment) => "deployment",
        None => "-",
    }
}

fn layer_json(layer: Option<Layer>) -> Option<&'static str> {
    layer.map(|name| match name {
        Layer::Scheduler => "scheduler",
        Layer::Validation => "validation",
        Layer::Deployment => "deployment",
    })
}

fn source_name(source: EvidenceSource) -> &'static str {
    match source {
        EvidenceSource::Log => "log",
        EvidenceSource::Timer => "timer",
        EvidenceSource::Disk => "disk",
        EvidenceSource::Handshake => "handshake",
        EvidenceSource::Probe => "probe",
    }
}

fn exit_label(status: ExitStatus) -> &'static str {
    match status {
        ExitStatus::Ok => "ok, not due",
        ExitStatus::Problem => "problem found",
        ExitStatus::InsufficientEvidence => "insufficient evidence",
        ExitStatus::Usage => "usage error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ClientKind, Code, Confidence, Evidence, Finding};

    #[test]
    fn json_escapes_quote_backslash_newline_tab_and_control() {
        let report = Report {
            snapshot: Snapshot {
                domain: Some("a\"b\\c".to_string()),
                all: false,
                client: ClientKind::Auto,
                from_log: None,
                from_timer_status: None,
                from_cert_disk: None,
                from_cert_live: None,
            },
            findings: vec![Finding::new(
                Code::InsufficientEvidence,
                Confidence::Low,
                vec![Evidence {
                    source: EvidenceSource::Log,
                    text: "quote:\" slash:\\ line\n tab\t ctrl\u{0001}".to_string(),
                }],
            )],
            replaced_invalid_utf8_bytes: 0,
        };
        let checks = [crate::safe::SafeCheck {
            for_code: Code::InsufficientEvidence,
            command: "systemctl is-enabled certbot.timer".to_string(),
            why: "quote:\" slash:\\ line\n tab\t ctrl\u{0001}".to_string(),
        }];
        let text = json(&report, &checks);
        assert!(text.contains(r#""domain": "YOUR_DOMAIN""#), "{text}");
        assert!(
            text.contains(r#""text": "quote:\" slash:\\ line\n tab\t ctrl\u0001""#),
            "{text}"
        );
        assert!(
            text.contains(r#""why": "quote:\" slash:\\ line\n tab\t ctrl\u0001""#),
            "{text}"
        );
        assert!(text.contains("\"next_checks\": ["));
        assert!(text.ends_with('\n'));
        assert!(text.contains("\"schema_version\": 1"));
    }

    #[test]
    fn replacement_note_states_the_count_and_not_the_bytes() {
        let report = Report {
            snapshot: Snapshot {
                domain: Some("example.com".to_string()),
                all: false,
                client: ClientKind::Auto,
                from_log: Some(PathBuf::from("log")),
                from_timer_status: None,
                from_cert_disk: None,
                from_cert_live: None,
            },
            findings: vec![Finding::new(
                Code::Layer2Http01Timeout,
                Confidence::High,
                vec![Evidence {
                    source: EvidenceSource::Log,
                    text: "line 1: Timeout during connect".to_string(),
                }],
            )],
            replaced_invalid_utf8_bytes: 2,
        };
        let human_text = human(&report, &[]);
        let json_text = json(&report, &[]);
        for text in [&human_text, &json_text] {
            assert!(
                text.contains("note: replaced 2 invalid UTF-8 bytes"),
                "{text}"
            );
            assert!(!text.contains('\u{FFFD}'), "{text}");
            assert!(!text.contains("0xFF"), "{text}");
        }
        assert!(json_text
            .contains("\"notes\": [\"note: replaced 2 invalid UTF-8 bytes\"],\n  \"exit_code\":"));

        let mut one = report.clone();
        one.replaced_invalid_utf8_bytes = 1;
        assert!(human(&one, &[]).contains("note: replaced 1 invalid UTF-8 byte"));

        let mut none = report;
        none.replaced_invalid_utf8_bytes = 0;
        let clean = json(&none, &[]);
        assert!(!clean.contains("\"notes\""), "{clean}");
    }

    fn report_with_log(path: &str) -> Report {
        Report {
            snapshot: Snapshot {
                domain: Some("example.com".to_string()),
                all: false,
                client: ClientKind::Certbot,
                from_log: Some(PathBuf::from(path)),
                from_timer_status: None,
                from_cert_disk: None,
                from_cert_live: None,
            },
            findings: vec![],
            replaced_invalid_utf8_bytes: 0,
        }
    }

    fn shown_log(text: &str) -> &str {
        let line = text
            .lines()
            .find(|line| line.starts_with("inputs: "))
            .unwrap_or_else(|| panic!("no inputs line\n{text}"));
        let rest = line
            .strip_prefix("inputs: log=")
            .unwrap_or_else(|| panic!("bad inputs line {line}"));
        rest.split_once(" · timer status=")
            .map(|(path, _)| path)
            .unwrap_or_else(|| panic!("bad inputs line {line}"))
    }

    #[test]
    fn windows_path_is_raw_and_control_path_is_quoted() {
        let windows = r"C:\Users\certbot\log.txt";
        let text = human(&report_with_log(windows), &[]);
        assert_eq!(shown_log(&text), windows);
        assert_eq!(escape_path_text(windows), windows);

        let json_text = json(&report_with_log(windows), &[]);
        assert!(
            json_text.contains(r#"    "from_log": "C:\\Users\\certbot\\log.txt","#),
            "{json_text}"
        );
        assert!(
            !json_text.contains(r#"\u{202e}"#),
            "json used text escaping\n{json_text}"
        );

        let literal = r"a\nb.log";
        assert_eq!(shown_log(&human(&report_with_log(literal), &[])), literal);
        assert_eq!(
            shown_log(&human(&report_with_log("a\nb.log"), &[])),
            r#""a\nb.log""#
        );

        let mixed = "C:\\Users\\certbot\\\u{202e}log\n.txt";
        let mixed_text = human(&report_with_log(mixed), &[]);
        let shown = shown_log(&mixed_text);
        assert_eq!(shown, "\"C:\\\\Users\\\\certbot\\\\\\u{202e}log\\n.txt\"");
        assert!(shown.starts_with('"') && shown.ends_with('"'));
        assert!(!shown.contains('\u{202e}'));
        assert!(!shown.contains('\n'));

        let mixed_json = json(&report_with_log(mixed), &[]);
        assert!(
            mixed_json.contains(r#""from_log": "C:\\Users\\certbot\\\u202elog\n.txt""#),
            "{mixed_json}"
        );
        assert!(
            !mixed_json.contains(r#"\u{202e}"#),
            "json used text escaping\n{mixed_json}"
        );

        let leading_quote = "\"C:\\Users\\certbot\\log.txt";
        assert_eq!(
            shown_log(&human(&report_with_log(leading_quote), &[])),
            r#""\"C:\\Users\\certbot\\log.txt""#
        );
        assert_eq!(
            escape_path_text("a\r\t\u{001b}\u{202e}"),
            r#""a\r\t\u{1b}\u{202e}""#
        );
    }
}
