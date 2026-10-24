use std::path::{Path, PathBuf};

use acme_renew_doctor::certbot_log::{self, AcmeProblem};
use acme_renew_doctor::certtime::from_unix_seconds;
use acme_renew_doctor::model::{ClientKind, Code, Confidence, EvidenceSource, Report, Snapshot};
use acme_renew_doctor::report_input::build_report;

const TIMEOUT_DETAIL: &str = "203.0.113.10: Fetching http://example.com/.well-known/acme-challenge/timeouttoken0000000000000000001: Timeout during connect (likely firewall problem)";
const REFUSED_DETAIL: &str = "203.0.113.10: Fetching http://example.com/.well-known/acme-challenge/refusedtoken0000000000000000001: Connection refused";
const RATE_LIMIT_DETAIL: &str = "too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after 2026-10-12 08:14:02 UTC: see https://letsencrypt.org/docs/rate-limits/#new-certificates-per-exact-set-of-identifiers";

fn parse_fixture(name: &str) -> Vec<AcmeProblem> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/certbot")
        .join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    certbot_log::parse(&text)
}

#[test]
fn http01_timeout_fixture() {
    let problems = parse_fixture("http01-timeout.log");
    assert_eq!(problems.len(), 1);
    assert_eq!(problems[0].short_type(), "connection");
    assert_eq!(problems[0].detail, TIMEOUT_DETAIL);
    assert_eq!(problems[0].identifier.as_deref(), Some("example.com"));
    assert!(problems[0].line > 0);
}

#[test]
fn http01_connection_refused_fixture() {
    let problems = parse_fixture("http01-connection-refused.log");
    assert_eq!(problems.len(), 1);
    assert_eq!(problems[0].short_type(), "connection");
    assert_eq!(problems[0].detail, REFUSED_DETAIL);
    assert_eq!(problems[0].identifier.as_deref(), Some("example.com"));
    assert!(problems[0].line > 0);
}

fn repo(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn log_snapshot(client: ClientKind, log: PathBuf) -> Snapshot {
    Snapshot {
        domain: Some("example.com".to_string()),
        all: false,
        client,
        from_log: Some(log),
        from_timer_status: None,
        from_cert_disk: None,
        from_cert_live: None,
    }
}

fn acme_sh_fixture() -> PathBuf {
    repo("tests/fixtures/acme-sh/verify-error-dns01.log")
}

fn evidence_text(report: &Report) -> Vec<&str> {
    report
        .findings
        .iter()
        .flat_map(|finding| finding.evidence.iter().map(|item| item.text.as_str()))
        .collect()
}

#[test]
fn acme_sh_fixture_with_auto_is_client_unknown() {
    let report = build_report(
        log_snapshot(ClientKind::Auto, acme_sh_fixture()),
        from_unix_seconds(1_791_273_600),
    );
    assert_eq!(
        report
            .findings
            .iter()
            .map(|finding| finding.code)
            .collect::<Vec<_>>(),
        vec![Code::ClientUnknown]
    );
    assert_eq!(report.findings[0].confidence, Confidence::High);
    assert!(report.findings[0]
        .evidence
        .iter()
        .all(|item| item.source == EvidenceSource::Log));
    let path = acme_sh_fixture();
    let expected = format!(
        "no Certbot log lines found in {} (expected lines like '2026-09-28 03:12:44,512:DEBUG:certbot._internal.main:...')",
        path.display()
    );
    assert_eq!(
        evidence_text(&report),
        vec![
            expected.as_str(),
            "acme.sh logs are not parsed yet (v0.1 parses Certbot logs only)",
        ]
    );
    assert_eq!(report.exit_status().code(), 3);
}

#[test]
fn acme_sh_fixture_with_certbot_client_is_not_a_validation_code() {
    let report = build_report(
        log_snapshot(ClientKind::Certbot, acme_sh_fixture()),
        from_unix_seconds(1_791_273_600),
    );
    assert!(report
        .findings
        .iter()
        .all(|finding| finding.code != Code::ClientUnknown && finding.code.layer().is_none()));
    assert_eq!(
        report
            .findings
            .iter()
            .map(|finding| finding.code)
            .collect::<Vec<_>>(),
        vec![Code::InsufficientEvidence]
    );
    assert_eq!(
        evidence_text(&report),
        vec![
            "no timer status",
            "log read, no ACME errors found",
            "no disk notAfter",
            "no live notAfter",
        ]
    );
    assert_eq!(report.exit_status().code(), 2);
}

#[test]
fn acme_sh_fixture_with_acme_sh_client_exits_two() {
    let report = build_report(
        log_snapshot(ClientKind::AcmeSh, acme_sh_fixture()),
        from_unix_seconds(1_791_273_600),
    );
    assert!(report
        .findings
        .iter()
        .all(|finding| finding.code != Code::ClientUnknown));
    // Same missing-input lines as the `--client certbot` case above: the
    // read error on the log itself does not explain the missing timer and
    // certificate inputs.
    assert_eq!(
        evidence_text(&report),
        vec![
            "acme.sh logs are not parsed yet (v0.1 parses Certbot logs only)",
            "no timer status",
            "log read, no ACME errors found",
            "no disk notAfter",
            "no live notAfter",
        ]
    );
    assert_eq!(report.exit_status().code(), 2);
}

#[test]
fn empty_log_with_auto_is_client_unknown() {
    let dir = std::env::temp_dir().join(format!(
        "acme-renew-doctor-empty-log-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap_or_else(|err| panic!("mkdir {}: {err}", dir.display()));
    let path = dir.join("empty.log");
    std::fs::write(&path, "").unwrap_or_else(|err| panic!("write {}: {err}", path.display()));
    let report = build_report(
        log_snapshot(ClientKind::Auto, path.clone()),
        from_unix_seconds(1_791_273_600),
    );
    assert_eq!(
        report
            .findings
            .iter()
            .map(|finding| finding.code)
            .collect::<Vec<_>>(),
        vec![Code::ClientUnknown]
    );
    assert!(evidence_text(&report).iter().any(|text| {
        text.starts_with("no Certbot log lines found in ") && text.contains("empty.log")
    }));
    assert_eq!(report.exit_status().code(), 3);
    std::fs::remove_dir_all(&dir).unwrap_or_else(|err| panic!("remove {}: {err}", dir.display()));
}

#[test]
fn certbot_fixture_with_auto_stays_a_validation_code() {
    let report = build_report(
        log_snapshot(
            ClientKind::Auto,
            repo("tests/fixtures/certbot/http01-timeout.log"),
        ),
        from_unix_seconds(1_791_273_600),
    );
    assert_eq!(
        report
            .findings
            .iter()
            .map(|finding| finding.code)
            .collect::<Vec<_>>(),
        vec![Code::Layer2Http01Timeout]
    );
    assert_eq!(report.exit_status().code(), 1);
}

#[test]
fn rate_limit_exact_set_fixture() {
    let problems = parse_fixture("rate-limit-exact-set.log");
    assert_eq!(problems.len(), 1);
    assert_eq!(problems[0].short_type(), "rateLimited");
    assert_eq!(problems[0].detail, RATE_LIMIT_DETAIL);
    assert_eq!(problems[0].identifier, None);
    assert!(problems[0].line > 0);
}
