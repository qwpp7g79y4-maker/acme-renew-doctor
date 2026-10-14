use std::path::Path;

use crate::certbot_log::{self, read_log};
use crate::certtime::{self, CertTime};
use crate::model::{
    ClientKind, Code, Confidence, Evidence, EvidenceSource, Finding, Report, Snapshot,
};
use crate::rules::{self, Observations};
use crate::timer;

pub fn build_report(snapshot: Snapshot, now: CertTime) -> Report {
    let mut read_errors = Vec::new();
    let mut log_read = false;
    let mut log_has_replacement_char = false;
    let mut replaced_invalid_utf8_bytes = 0usize;
    let mut problems = Vec::new();
    let mut timer = None;
    let mut service = None;
    let mut snap_timer = None;
    let mut disk_not_after = None;
    let mut live_not_after = None;

    if let Some(path) = &snapshot.from_log {
        match read_log(path) {
            Ok(decoded) => {
                log_read = true;
                replaced_invalid_utf8_bytes = decoded.replaced_invalid_utf8_bytes;
                log_has_replacement_char = decoded.text.contains('\u{FFFD}');
                match classify_log(snapshot.client, &decoded.text) {
                    LogChoice::Parse => {
                        let parsed = certbot_log::parse_log(&decoded.text);
                        problems = parsed.problems;
                        if parsed.ambiguous_json {
                            read_errors.push(log_note(certbot_log::AMBIGUOUS_ACME_JSON));
                        }
                    }
                    LogChoice::AcmeSh => read_errors.push(acme_sh_not_parsed()),
                    LogChoice::Unknown => read_errors.push(client_unknown(path)),
                }
            }
            Err(finding) => read_errors.push(finding),
        }
    }

    if let Some(path) = &snapshot.from_timer_status {
        match read_timer(path) {
            Ok(parsed) => {
                timer = parsed.timer;
                service = parsed.service;
                snap_timer = parsed.snap_timer;
            }
            Err(finding) => read_errors.push(finding),
        }
    }

    if let Some(path) = &snapshot.from_cert_disk {
        match read_cert_dates(path, EvidenceSource::Disk) {
            Ok(time) => disk_not_after = Some(time),
            Err(finding) => read_errors.push(finding),
        }
    }
    if let Some(path) = &snapshot.from_cert_live {
        match read_cert_dates(path, EvidenceSource::Handshake) {
            Ok(time) => live_not_after = Some(time),
            Err(finding) => read_errors.push(finding),
        }
    }

    let findings = rules::analyze(&Observations {
        timer,
        service,
        snap_timer,
        problems,
        disk_not_after,
        live_not_after,
        now,
        read_errors,
        log_read,
        log_has_replacement_char,
    });

    Report {
        snapshot,
        findings,
        replaced_invalid_utf8_bytes,
    }
}

fn read_timer(path: &Path) -> Result<timer::SystemctlShow, Finding> {
    let text = certbot_log::read_strict_text(
        path,
        certbot_log::SHORT_TEXT_MAX_BYTES,
        EvidenceSource::Timer,
    )?;
    match timer::classify_show(&text) {
        timer::ShowParse::Units(show) => Ok(*show),
        timer::ShowParse::NoId => Err(timer_note(timer::NO_ID_LINE)),
        timer::ShowParse::NoSupportedUnit => Err(timer_note(timer::NO_SUPPORTED_UNIT)),
        timer::ShowParse::Ambiguous => Err(timer_note(timer::AMBIGUOUS_UNITS)),
    }
}

fn log_note(text: &str) -> Finding {
    Finding::new(
        Code::InsufficientEvidence,
        Confidence::High,
        vec![Evidence {
            source: EvidenceSource::Log,
            text: text.to_string(),
        }],
    )
}

fn timer_note(text: &str) -> Finding {
    Finding::new(
        Code::InsufficientEvidence,
        Confidence::High,
        vec![Evidence {
            source: EvidenceSource::Timer,
            text: text.to_string(),
        }],
    )
}

fn read_cert_dates(path: &Path, source: EvidenceSource) -> Result<CertTime, Finding> {
    let text = certbot_log::read_strict_text(path, certbot_log::SHORT_TEXT_MAX_BYTES, source)?;
    certtime::parse_openssl_enddate(&text).ok_or_else(|| cert_not_recognised(source))
}

fn cert_not_recognised(source: EvidenceSource) -> Finding {
    Finding::new(
        Code::InsufficientEvidence,
        Confidence::High,
        vec![Evidence {
            source,
            text:
                "certificate dates not recognised (no notAfter= line in openssl x509 -dates output)"
                    .to_string(),
        }],
    )
}

enum LogChoice {
    Parse,
    AcmeSh,
    Unknown,
}

fn classify_log(client: ClientKind, text: &str) -> LogChoice {
    match client {
        ClientKind::AcmeSh => LogChoice::AcmeSh,
        ClientKind::Certbot => LogChoice::Parse,
        ClientKind::Auto => {
            if certbot_log::has_certbot_lines(text) {
                LogChoice::Parse
            } else {
                LogChoice::Unknown
            }
        }
    }
}

fn client_unknown(path: &Path) -> Finding {
    Finding::new(
        Code::ClientUnknown,
        Confidence::High,
        vec![
            Evidence {
                source: EvidenceSource::Log,
                text: format!(
                    "no Certbot log lines found in {} (expected lines like '2026-09-28 03:12:44,512:DEBUG:certbot._internal.main:...')",
                    path.display()
                ),
            },
            Evidence {
                source: EvidenceSource::Log,
                text: "acme.sh logs are not parsed yet (v0.1 parses Certbot logs only)".to_string(),
            },
        ],
    )
}

fn acme_sh_not_parsed() -> Finding {
    Finding::new(
        Code::InsufficientEvidence,
        Confidence::High,
        vec![Evidence {
            source: EvidenceSource::Log,
            text: "acme.sh logs are not parsed yet (v0.1 parses Certbot logs only)".to_string(),
        }],
    )
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::certtime::from_unix_seconds;

    fn snapshot(client: ClientKind, log: Option<&str>, timer: Option<&str>) -> Snapshot {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        Snapshot {
            domain: Some("example.com".to_string()),
            all: false,
            client,
            from_log: log.map(|rel| root.join(rel)),
            from_timer_status: timer.map(|rel| root.join(rel)),
            from_cert_disk: None,
            from_cert_live: None,
        }
    }

    fn with_certs(timer: Option<&str>, disk: Option<&str>, live: Option<&str>) -> Snapshot {
        let mut snapshot = snapshot(ClientKind::Auto, None, timer);
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        snapshot.from_cert_disk = disk.map(|rel| root.join(rel));
        snapshot.from_cert_live = live.map(|rel| root.join(rel));
        snapshot
    }

    fn texts(report: &Report) -> Vec<&str> {
        report
            .findings
            .iter()
            .flat_map(|finding| finding.evidence.iter().map(|item| item.text.as_str()))
            .collect()
    }

    #[test]
    fn classify_log_follows_the_client_and_certbot_lines() {
        let certbot = "2026-09-28 03:12:44,512:DEBUG:certbot._internal.main:hello\n";
        let other = "[..., 15:01:25 (UTC+0200)] Verifying: example.com\n";
        assert!(matches!(
            classify_log(ClientKind::Auto, certbot),
            LogChoice::Parse
        ));
        assert!(matches!(
            classify_log(ClientKind::Auto, other),
            LogChoice::Unknown
        ));
        assert!(matches!(
            classify_log(ClientKind::Auto, ""),
            LogChoice::Unknown
        ));
        assert!(matches!(
            classify_log(ClientKind::Certbot, other),
            LogChoice::Parse
        ));
        assert!(matches!(
            classify_log(ClientKind::AcmeSh, certbot),
            LogChoice::AcmeSh
        ));
    }

    #[test]
    fn acme_sh_log_is_not_parsed() {
        let report = build_report(
            snapshot(
                ClientKind::AcmeSh,
                Some("tests/fixtures/certbot/http01-timeout.log"),
                None,
            ),
            from_unix_seconds(0),
        );
        assert!(report
            .findings
            .iter()
            .all(|finding| finding.code != Code::Layer2Http01Timeout));
        assert_eq!(
            texts(&report),
            vec!["acme.sh logs are not parsed yet (v0.1 parses Certbot logs only)"]
        );
        assert_eq!(report.exit_status().code(), 2);
    }

    #[test]
    fn timer_file_without_id_is_not_recognised() {
        let report = build_report(
            snapshot(
                ClientKind::Certbot,
                None,
                Some("tests/fixtures/certbot/http01-timeout.log"),
            ),
            from_unix_seconds(0),
        );
        assert!(texts(&report)
            .contains(&"timer status not recognised (no Id= line in systemctl show output)"));
    }

    #[test]
    fn missing_timer_file_is_a_read_error() {
        let report = build_report(
            snapshot(
                ClientKind::Auto,
                None,
                Some("tests/fixtures/timer/does-not-exist.txt"),
            ),
            from_unix_seconds(0),
        );
        let joined = texts(&report).join("\n");
        assert!(joined.contains("cannot read "));
        assert!(joined.contains("does-not-exist.txt: NotFound"));
        assert!(report.findings.iter().any(|finding| {
            finding.evidence.iter().any(|item| {
                item.source == EvidenceSource::Timer && item.text.contains("cannot read ")
            })
        }));
    }

    #[test]
    fn renewed_disk_and_old_live_are_no_reload() {
        let report = build_report(
            with_certs(
                None,
                Some("tests/fixtures/certs/dates-disk-renewed.txt"),
                Some("tests/fixtures/certs/dates-live-old.txt"),
            ),
            from_unix_seconds(1_791_273_600),
        );
        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.code)
                .collect::<Vec<_>>(),
            vec![Code::Layer3NoReload]
        );
        assert_eq!(report.exit_status().code(), 1);
    }

    #[test]
    fn current_cert_with_enabled_timer_is_ok_not_due() {
        let report = build_report(
            with_certs(
                Some("tests/fixtures/timer/certbot-timer-enabled.txt"),
                Some("tests/fixtures/certs/dates-current.txt"),
                Some("tests/fixtures/certs/dates-current.txt"),
            ),
            from_unix_seconds(1_791_273_600),
        );
        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.code)
                .collect::<Vec<_>>(),
            vec![Code::OkNotDue]
        );
        assert_eq!(report.exit_status().code(), 0);
    }

    #[test]
    fn unrecognised_cert_file_is_insufficient_evidence() {
        let report = build_report(
            with_certs(
                None,
                Some("tests/fixtures/certs/not-a-cert.txt"),
                Some("tests/fixtures/certs/dates-current.txt"),
            ),
            from_unix_seconds(1_791_273_600),
        );
        assert_eq!(report.exit_status().code(), 2);
        assert!(report.findings.iter().any(|finding| {
            finding.code == Code::InsufficientEvidence
                && finding.confidence == Confidence::High
                && finding.evidence.iter().any(|item| {
                    item.source == EvidenceSource::Disk
                        && item.text
                            == "certificate dates not recognised (no notAfter= line in openssl x509 -dates output)"
                })
        }));
    }

    #[test]
    fn missing_cert_file_is_a_read_error() {
        let report = build_report(
            with_certs(None, Some("tests/fixtures/certs/does-not-exist.txt"), None),
            from_unix_seconds(1_791_273_600),
        );
        let joined = texts(&report).join("\n");
        assert!(joined.contains("cannot read "));
        assert!(joined.contains("does-not-exist.txt: NotFound"));
        assert!(report.findings.iter().any(|finding| {
            finding.evidence.iter().any(|item| {
                item.source == EvidenceSource::Disk && item.text.contains("cannot read ")
            })
        }));
    }
}
