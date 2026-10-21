use std::path::Path;

use acme_renew_doctor::certbot_log::{self, read_log, AcmeProblem};
use acme_renew_doctor::certtime::{self, CertTime};
use acme_renew_doctor::model::{
    ClientKind, Code, Confidence, EvidenceSource, Finding, Report, Snapshot,
};
use acme_renew_doctor::rules::{self, Observations};
use acme_renew_doctor::timer::{self, TimerStatus};

const TIMEOUT_DETAIL: &str = "203.0.113.10: Fetching http://example.com/.well-known/acme-challenge/timeouttoken0000000000000000001: Timeout during connect (likely firewall problem)";
const REFUSED_DETAIL: &str = "203.0.113.10: Fetching http://example.com/.well-known/acme-challenge/refusedtoken0000000000000000001: Connection refused";
const RATE_LIMIT_DETAIL: &str = "too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after 2026-10-12 08:14:02 UTC: see https://letsencrypt.org/docs/rate-limits/#new-certificates-per-exact-set-of-identifiers";
const DNS01_NO_TXT_DETAIL: &str = "No TXT record found at _acme-challenge.example.com";
const DNS01_INCORRECT_DETAIL: &str = "Incorrect TXT record \"fakeOldTxtValue000000000000000000000000000\" found at _acme-challenge.example.com";
const DNS01_LOOKUP_DETAIL: &str = "DNS problem: NXDOMAIN looking up TXT for _acme-challenge.example.com - check that a DNS record exists for this domain";
const SECONDARY_PREFIX: &str = "During secondary validation: ";
const CONNECTION_WITHOUT_RULE: &str = "recognised connection error without a dedicated rule";
const UNRECOGNISED_ACME: &str = "ACME errors in log not recognised by the current rules";

const APT_DAILY: &str = "\
NextElapseUSecRealtime=Tue 2026-10-06 21:12:24 CEST
LastTriggerUSec=Tue 2026-10-06 09:10:06 CEST
Result=success
Id=apt-daily.timer
LoadState=loaded
ActiveState=active
SubState=waiting
UnitFileState=enabled
";

const XFS_SCRUB: &str = "\
NextElapseUSecRealtime=
LastTriggerUSec=
Result=success
Id=xfs_scrub_all.timer
LoadState=loaded
ActiveState=inactive
SubState=dead
UnitFileState=disabled
";

fn fixture(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

fn fixed_now() -> CertTime {
    CertTime {
        year: 2026,
        month: 10,
        day: 6,
        hour: 8,
        minute: 0,
        second: 0,
    }
}

fn blank() -> Observations {
    Observations {
        timer: None,
        service: None,
        snap_timer: None,
        problems: Vec::new(),
        disk_not_after: None,
        live_not_after: None,
        disk_not_before: None,
        now: fixed_now(),
        read_errors: Vec::new(),
        log_read: false,
        log_has_replacement_char: false,
    }
}

fn report(findings: Vec<Finding>) -> Report {
    Report {
        snapshot: Snapshot {
            domain: None,
            all: false,
            client: ClientKind::Auto,
            from_log: None,
            from_timer_status: None,
            from_cert_disk: None,
            from_cert_live: None,
        },
        findings,
        replaced_invalid_utf8_bytes: 0,
    }
}

fn exit_of(findings: &[Finding]) -> i32 {
    report(findings.to_vec()).exit_status().code()
}

fn show_file(name: &str) -> timer::SystemctlShow {
    timer::parse_systemctl_show(&fixture(&format!("tests/fixtures/timer/{name}")))
        .unwrap_or_else(|| panic!("parse {name}"))
}

fn timer_file(name: &str) -> TimerStatus {
    show_file(name)
        .timer
        .unwrap_or_else(|| panic!("no timer in {name}"))
}

fn dates_not_after(name: &str) -> CertTime {
    let text = fixture(&format!("tests/fixtures/certs/{name}"));
    certtime::parse_openssl_enddate(&text).unwrap_or_else(|| panic!("parse {name}"))
}

fn enddate_file(name: &str) -> CertTime {
    let text = fixture(&format!("tests/fixtures/certs/{name}"));
    let parsed = certtime::parse_openssl_enddate(&text).unwrap_or_else(|| panic!("parse {name}"));
    assert_eq!(parsed.to_string(), text.trim());
    parsed
}

fn log_problems(name: &str) -> Vec<AcmeProblem> {
    certbot_log::parse(&fixture(&format!("tests/fixtures/certbot/{name}")))
}

fn acme_problem(short: &str, detail: &str, line: usize) -> AcmeProblem {
    AcmeProblem {
        problem_type: format!("urn:ietf:params:acme:error:{short}"),
        detail: detail.to_string(),
        identifier: Some("example.com".to_string()),
        line,
        first_line: line,
        depth: 0,
        occurrences: 1,
        json_hits: 1,
        summary_hits: 0,
        logged_at: None,
    }
}

fn at(year: i32, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> CertTime {
    CertTime {
        year,
        month,
        day,
        hour,
        minute,
        second,
    }
}

#[test]
fn layer1_timer_disabled_from_fixture() {
    let timer = timer_file("certbot-timer-disabled.txt");
    assert_eq!(timer.id, "certbot.timer");
    assert_eq!(timer.load_state, "loaded");
    assert_eq!(timer.unit_file_state, "disabled");
    assert_eq!(timer.active_state, "inactive");

    let findings = rules::analyze(&Observations {
        timer: Some(timer),
        ..blank()
    });
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, Code::Layer1TimerDisabled);
    assert_eq!(findings[0].confidence, Confidence::High);
    assert_eq!(findings[0].evidence.len(), 2);
    assert_eq!(findings[0].evidence[0].source, EvidenceSource::Timer);
    assert_eq!(findings[0].evidence[0].text, "UnitFileState=disabled");
    assert_eq!(findings[0].evidence[1].source, EvidenceSource::Timer);
    assert_eq!(findings[0].evidence[1].text, "ActiveState=inactive");
    assert!(findings
        .iter()
        .all(|finding| finding.code != Code::Layer1TimerNotFiring));
}

#[test]
fn layer2_http01_timeout_from_fixture() {
    let problems = log_problems("http01-timeout.log");
    assert_eq!(problems.len(), 1);
    assert_eq!(problems[0].line, 32);
    assert_eq!(problems[0].first_line, 20);
    assert_eq!(problems[0].json_hits, 1);
    assert_eq!(problems[0].summary_hits, 1);
    assert_eq!(problems[0].occurrences, 2);
    assert_eq!(problems[0].attempts(), 1);

    let findings = rules::analyze(&Observations {
        problems,
        log_read: true,
        ..blank()
    });
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, Code::Layer2Http01Timeout);
    assert_eq!(findings[0].confidence, Confidence::High);
    assert_eq!(findings[0].evidence.len(), 1);
    assert_eq!(findings[0].evidence[0].source, EvidenceSource::Log);
    assert_eq!(
        findings[0].evidence[0].text,
        format!("line 32: {TIMEOUT_DETAIL}")
    );
}

#[test]
fn layer2_http01_timeout_repeated_uses_newest_line() {
    let problems = log_problems("http01-timeout-repeated.log");
    assert_eq!(problems.len(), 1);
    assert_eq!(problems[0].short_type(), "connection");
    assert_eq!(problems[0].detail, TIMEOUT_DETAIL);
    assert_eq!(problems[0].first_line, 20);
    assert_eq!(problems[0].line, 68);
    assert_eq!(problems[0].json_hits, 2);
    assert_eq!(problems[0].summary_hits, 2);
    assert_eq!(problems[0].occurrences, 4);
    assert_eq!(problems[0].attempts(), 2);

    let findings = rules::analyze(&Observations {
        problems,
        log_read: true,
        ..blank()
    });
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, Code::Layer2Http01Timeout);
    assert_eq!(findings[0].confidence, Confidence::High);
    assert_eq!(findings[0].evidence.len(), 2);
    assert_eq!(findings[0].evidence[0].source, EvidenceSource::Log);
    assert_eq!(
        findings[0].evidence[0].text,
        format!("line 68: {TIMEOUT_DETAIL}")
    );
    assert_eq!(findings[0].evidence[1].source, EvidenceSource::Log);
    assert_eq!(
        findings[0].evidence[1].text,
        "2 attempts in this log (ACME response and Certbot summary of one attempt count as one), first on line 20"
    );
}

#[test]
fn layer3_no_reload_from_fixtures() {
    let disk = enddate_file("disk-enddate-new.txt");
    let live = enddate_file("live-enddate-old.txt");
    assert!(disk > live);

    let findings = rules::analyze(&Observations {
        disk_not_after: Some(disk),
        live_not_after: Some(live),
        ..blank()
    });
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, Code::Layer3NoReload);
    assert_eq!(findings[0].confidence, Confidence::High);
    assert_eq!(findings[0].evidence.len(), 2);
    assert_eq!(findings[0].evidence[0].source, EvidenceSource::Disk);
    assert_eq!(
        findings[0].evidence[0].text,
        "notAfter=Jan  3 08:14:02 2027 GMT"
    );
    assert_eq!(findings[0].evidence[1].source, EvidenceSource::Handshake);
    assert_eq!(
        findings[0].evidence[1].text,
        "notAfter=Oct  5 08:14:02 2026 GMT"
    );
}

#[test]
fn ok_not_due_when_far_and_timer_enabled() {
    let far = enddate_file("enddate-far.txt");
    assert!(far.days_until(&fixed_now()) > rules::NOT_DUE_DAYS);
    let timer = timer_file("certbot-timer-enabled.txt");
    assert_eq!(timer.id, "certbot.timer");
    assert_eq!(timer.load_state, "loaded");
    assert_eq!(timer.unit_file_state, "enabled");
    assert_eq!(timer.active_state, "active");

    let findings = rules::analyze(&Observations {
        timer: Some(timer),
        disk_not_after: Some(far),
        live_not_after: Some(far),
        ..blank()
    });
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, Code::OkNotDue);
    assert_eq!(findings[0].confidence, Confidence::High);
    assert_eq!(findings[0].evidence[0].source, EvidenceSource::Disk);
    assert_eq!(
        findings[0].evidence[0].text,
        "notAfter=Dec 30 08:14:02 2026 GMT"
    );
    assert_eq!(findings[0].evidence[1].source, EvidenceSource::Handshake);
    assert_eq!(findings[0].evidence[1].text, findings[0].evidence[0].text);
    assert_eq!(findings[0].evidence[2].source, EvidenceSource::Timer);
    assert_eq!(findings[0].evidence[2].text, "Id=certbot.timer");
    assert_eq!(findings[0].evidence[3].text, "LoadState=loaded");
    assert_eq!(findings[0].evidence[4].text, "ActiveState=active");
    assert_eq!(findings[0].evidence[5].text, "UnitFileState=enabled");
    assert_eq!(exit_of(&findings), 0);
}

#[test]
fn replacement_character_blocks_ok_not_due() {
    let far = enddate_file("enddate-far.txt");
    let findings = rules::analyze(&Observations {
        timer: Some(timer_file("certbot-timer-enabled.txt")),
        disk_not_after: Some(far),
        live_not_after: Some(far),
        log_read: true,
        log_has_replacement_char: true,
        ..blank()
    });
    assert!(findings
        .iter()
        .all(|finding| finding.code != Code::OkNotDue));
    assert_eq!(exit_of(&findings), 2);
}

#[test]
fn empty_observations_are_insufficient_evidence() {
    let findings = rules::analyze(&blank());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, Code::InsufficientEvidence);
    assert_eq!(findings[0].confidence, Confidence::Low);
    assert_eq!(
        findings[0]
            .evidence
            .iter()
            .map(|item| item.text.as_str())
            .collect::<Vec<_>>(),
        vec![
            "no timer status",
            "no log given",
            "no disk notAfter",
            "no live notAfter",
        ]
    );
    assert_eq!(exit_of(&findings), 2);
}

#[test]
fn log_read_with_no_acme_errors_is_distinct_from_no_log() {
    let findings = rules::analyze(&Observations {
        log_read: true,
        ..blank()
    });
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, Code::InsufficientEvidence);
    assert_eq!(
        findings[0]
            .evidence
            .iter()
            .map(|item| item.text.as_str())
            .collect::<Vec<_>>(),
        vec![
            "no timer status",
            "log read, no ACME errors found",
            "no disk notAfter",
            "no live notAfter",
        ]
    );
}

#[test]
fn unreadable_log_is_insufficient_evidence() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/certbot/does-not-exist.log");
    let err = read_log(&path).unwrap_err();
    assert_eq!(err.code, Code::InsufficientEvidence);
    assert_eq!(err.confidence, Confidence::High);

    let findings = rules::analyze(&Observations {
        read_errors: vec![err.clone()],
        ..blank()
    });
    assert_eq!(findings, vec![err]);
    assert_eq!(exit_of(&findings), 2);
}

#[test]
fn layer2_http01_refused_from_fixture() {
    let problems = log_problems("http01-connection-refused.log");
    assert_eq!(problems.len(), 1);
    assert_eq!(problems[0].short_type(), "connection");
    assert_eq!(problems[0].detail, REFUSED_DETAIL);
    assert_eq!(problems[0].line, 32);
    assert_eq!(problems[0].first_line, 20);
    assert_eq!(problems[0].attempts(), 1);

    let findings = rules::analyze(&Observations {
        problems,
        log_read: true,
        ..blank()
    });
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, Code::Layer2Http01Refused);
    assert_eq!(findings[0].confidence, Confidence::High);
    assert_eq!(findings[0].evidence.len(), 1);
    assert_eq!(findings[0].evidence[0].source, EvidenceSource::Log);
    assert_eq!(
        findings[0].evidence[0].text,
        format!("line 32: {REFUSED_DETAIL}")
    );
    assert_eq!(exit_of(&findings), 1);
}

#[test]
fn layer2_rate_limit_from_fixture() {
    let problems = log_problems("rate-limit-exact-set.log");
    assert_eq!(problems.len(), 1);
    assert_eq!(problems[0].short_type(), "rateLimited");
    assert_eq!(problems[0].detail, RATE_LIMIT_DETAIL);
    assert_eq!(problems[0].line, 8);
    assert_eq!(problems[0].attempts(), 1);

    let findings = rules::analyze(&Observations {
        problems,
        log_read: true,
        ..blank()
    });
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, Code::Layer2RateLimit);
    assert_eq!(findings[0].confidence, Confidence::High);
    assert_eq!(findings[0].evidence.len(), 2);
    assert_eq!(findings[0].evidence[0].source, EvidenceSource::Log);
    assert_eq!(
        findings[0].evidence[0].text,
        format!("line 8: {RATE_LIMIT_DETAIL}")
    );
    assert_eq!(findings[0].evidence[1].source, EvidenceSource::Log);
    assert_eq!(
        findings[0].evidence[1].text,
        "retry after 2026-10-12 08:14:02 UTC"
    );
    assert_eq!(exit_of(&findings), 1);
}

#[test]
fn layer2_dns01_txt_no_record_from_fixture() {
    let problems = log_problems("dns01-no-txt-record.log");
    assert_eq!(problems.len(), 1);
    assert_eq!(problems[0].short_type(), "unauthorized");
    assert_eq!(problems[0].detail, DNS01_NO_TXT_DETAIL);
    assert_eq!(problems[0].line, 32);
    assert_eq!(problems[0].first_line, 20);
    assert_eq!(problems[0].json_hits, 1);
    assert_eq!(problems[0].summary_hits, 1);
    assert_eq!(problems[0].attempts(), 1);

    let findings = rules::analyze(&Observations {
        problems,
        log_read: true,
        ..blank()
    });
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, Code::Layer2Dns01Txt);
    assert_eq!(findings[0].confidence, Confidence::High);
    assert_eq!(findings[0].evidence.len(), 1);
    assert_eq!(findings[0].evidence[0].source, EvidenceSource::Log);
    assert_eq!(
        findings[0].evidence[0].text,
        format!("line 32: {DNS01_NO_TXT_DETAIL}")
    );
    assert_eq!(exit_of(&findings), 1);
}

#[test]
fn layer2_dns01_txt_incorrect_record_from_fixture() {
    let problems = log_problems("dns01-incorrect-txt-record.log");
    assert_eq!(problems.len(), 1);
    assert_eq!(problems[0].short_type(), "unauthorized");
    assert_eq!(problems[0].detail, DNS01_INCORRECT_DETAIL);
    assert_eq!(problems[0].line, 32);
    assert_eq!(problems[0].first_line, 20);
    assert_eq!(problems[0].attempts(), 1);

    let findings = rules::analyze(&Observations {
        problems,
        log_read: true,
        ..blank()
    });
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, Code::Layer2Dns01Txt);
    assert_eq!(findings[0].confidence, Confidence::High);
    assert_eq!(findings[0].evidence.len(), 1);
    assert_eq!(findings[0].evidence[0].source, EvidenceSource::Log);
    assert_eq!(
        findings[0].evidence[0].text,
        format!("line 32: {DNS01_INCORRECT_DETAIL}")
    );
    assert_eq!(exit_of(&findings), 1);
}

#[test]
fn layer2_dns01_txt_incorrect_record_with_and_more() {
    let detail = "Incorrect TXT record \"fakeOldTxtValue000000000000000000000000000\" (and 2 more) found at _acme-challenge.example.com";
    let findings = rules::analyze(&Observations {
        problems: vec![acme_problem("unauthorized", detail, 7)],
        log_read: true,
        ..blank()
    });
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, Code::Layer2Dns01Txt);
    assert_eq!(findings[0].confidence, Confidence::High);
    assert_eq!(findings[0].evidence[0].source, EvidenceSource::Log);
    assert_eq!(findings[0].evidence[0].text, format!("line 7: {detail}"));
    assert_eq!(exit_of(&findings), 1);
}

#[test]
fn layer2_dns01_txt_nxdomain_looking_up_txt() {
    let detail = DNS01_LOOKUP_DETAIL;
    let findings = rules::analyze(&Observations {
        problems: vec![acme_problem("dns", detail, 3)],
        log_read: true,
        ..blank()
    });
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, Code::Layer2Dns01Txt);
    assert_eq!(findings[0].confidence, Confidence::High);
    assert_eq!(findings[0].evidence[0].text, format!("line 3: {detail}"));
    assert_eq!(exit_of(&findings), 1);
}

#[test]
fn dns_nxdomain_for_a_record_is_not_dns01_txt() {
    let detail = "DNS problem: NXDOMAIN looking up A for example.com - check that a DNS record exists for this domain";
    let findings = rules::analyze(&Observations {
        problems: vec![acme_problem("dns", detail, 3)],
        log_read: true,
        ..blank()
    });
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, Code::InsufficientEvidence);
    assert!(findings
        .iter()
        .all(|finding| finding.code != Code::Layer2Dns01Txt));
    assert!(findings[0]
        .evidence
        .iter()
        .any(|item| item.text == "ACME errors in log not recognised by the current rules"));
    assert_eq!(exit_of(&findings), 2);
}

#[test]
fn latest_problem_wins_when_refused_is_followed_by_timeout() {
    let log = format!(
        "2026-09-28 04:05:11,100:DEBUG:acme.client:Received response:\n\
         {{\"type\":\"urn:ietf:params:acme:error:connection\",\"detail\":\"{REFUSED_DETAIL}\",\"status\":400}}\n\
         2026-09-28 04:06:11,100:DEBUG:acme.client:Received response:\n\
         {{\"type\":\"urn:ietf:params:acme:error:connection\",\"detail\":\"{TIMEOUT_DETAIL}\",\"status\":400}}\n"
    );
    let problems = certbot_log::parse(&log);
    assert_eq!(problems.len(), 2);
    assert_eq!(problems[0].detail, REFUSED_DETAIL);
    assert_eq!(problems[1].detail, TIMEOUT_DETAIL);
    assert!(problems[1].line > problems[0].line);

    let findings = rules::analyze(&Observations {
        problems,
        log_read: true,
        ..blank()
    });
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, Code::Layer2Http01Timeout);
    assert_eq!(
        findings[0].evidence[0].text,
        format!("line 4: {TIMEOUT_DETAIL}")
    );
    assert_eq!(exit_of(&findings), 1);
}

#[test]
fn disabled_timer_and_timeout_report_exit_one() {
    let findings = rules::analyze(&Observations {
        timer: Some(timer_file("certbot-timer-disabled.txt")),
        problems: log_problems("http01-timeout.log"),
        ..blank()
    });
    assert_eq!(
        findings
            .iter()
            .map(|finding| finding.code)
            .collect::<Vec<_>>(),
        vec![Code::Layer1TimerDisabled, Code::Layer2Http01Timeout]
    );
    assert_eq!(exit_of(&findings), 1);
}

#[test]
fn not_found_timer_is_not_timer_disabled() {
    let timer = TimerStatus {
        id: "certbot.timer".to_string(),
        load_state: "not-found".to_string(),
        active_state: "inactive".to_string(),
        sub_state: "dead".to_string(),
        unit_file_state: "disabled".to_string(),
        result: String::new(),
        condition_result: String::new(),
    };
    let findings = rules::analyze(&Observations {
        timer: Some(timer),
        ..blank()
    });
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, Code::InsufficientEvidence);
}

fn loaded_timer(
    unit_file_state: &str,
    active_state: &str,
    sub_state: &str,
    result: &str,
    condition_result: &str,
) -> TimerStatus {
    TimerStatus {
        id: "certbot.timer".to_string(),
        load_state: "loaded".to_string(),
        active_state: active_state.to_string(),
        sub_state: sub_state.to_string(),
        unit_file_state: unit_file_state.to_string(),
        result: result.to_string(),
        condition_result: condition_result.to_string(),
    }
}

fn evidence_text(findings: &[Finding]) -> Vec<&str> {
    findings
        .iter()
        .flat_map(|finding| finding.evidence.iter().map(|item| item.text.as_str()))
        .collect()
}

#[test]
fn enabled_inactive_timer_is_not_firing() {
    let findings = rules::analyze(&Observations {
        timer: Some(timer_file("certbot-timer-enabled-inactive.txt")),
        ..blank()
    });
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, Code::Layer1TimerNotFiring);
    assert_eq!(findings[0].confidence, Confidence::High);
    assert!(findings
        .iter()
        .all(|finding| finding.code != Code::Layer1TimerDisabled));
    assert!(findings.iter().all(|finding| finding
        .evidence
        .iter()
        .all(|item| item.source == EvidenceSource::Timer)));
    assert_eq!(
        evidence_text(&findings),
        vec![
            "certbot.timer: ActiveState=inactive",
            "SubState=dead",
            "Result=success",
            "UnitFileState=enabled",
            "ConditionResult=no",
        ]
    );
    assert_eq!(exit_of(&findings), 1);
}

#[test]
fn failed_timer_is_not_firing() {
    let findings = rules::analyze(&Observations {
        timer: Some(timer_file("certbot-timer-failed.txt")),
        ..blank()
    });
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, Code::Layer1TimerNotFiring);
    assert_eq!(findings[0].confidence, Confidence::High);
    assert!(findings
        .iter()
        .all(|finding| finding.code != Code::Layer1TimerDisabled));
    assert_eq!(
        evidence_text(&findings),
        vec![
            "certbot.timer: ActiveState=failed",
            "SubState=failed",
            "Result=resources",
            "UnitFileState=enabled",
            "ConditionResult=yes",
        ]
    );
    assert_eq!(exit_of(&findings), 1);
}

#[test]
fn enabled_active_timer_is_neither_timer_code() {
    let findings = rules::analyze(&Observations {
        timer: Some(timer_file("certbot-timer-enabled.txt")),
        ..blank()
    });
    assert!(findings.iter().all(|finding| {
        finding.code != Code::Layer1TimerDisabled && finding.code != Code::Layer1TimerNotFiring
    }));
}

#[test]
fn failed_service_is_insufficient_evidence() {
    let show = show_file("certbot-timer-ok-service-failed.txt");
    let findings = rules::analyze(&Observations {
        timer: show.timer,
        service: show.service,
        ..blank()
    });
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, Code::InsufficientEvidence);
    assert!(findings[0].evidence.iter().any(|item| {
        item.source == EvidenceSource::Timer
            && item.text
                == "certbot.service failed (Result=exit-code); the renewal ran and failed, check the Certbot log"
    }));
    assert_eq!(exit_of(&findings), 2);
}

#[test]
fn failed_service_blocks_ok_not_due() {
    let show = show_file("certbot-timer-ok-service-failed.txt");
    let cert = dates_not_after("dates-current.txt");
    assert!(cert.days_until(&fixed_now()) > rules::NOT_DUE_DAYS);
    let findings = rules::analyze(&Observations {
        timer: show.timer,
        service: show.service,
        disk_not_after: Some(cert),
        live_not_after: Some(cert),
        ..blank()
    });
    assert!(findings
        .iter()
        .all(|finding| finding.code != Code::OkNotDue));
    assert_eq!(findings[0].code, Code::InsufficientEvidence);
}

#[test]
fn service_only_failed_is_insufficient_evidence() {
    let show = show_file("certbot-service-only-failed.txt");
    assert!(show.timer.is_none());
    let findings = rules::analyze(&Observations {
        timer: show.timer,
        service: show.service,
        ..blank()
    });
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, Code::InsufficientEvidence);
    assert!(findings.iter().all(|finding| {
        finding.code != Code::Layer1TimerNotFiring && finding.code != Code::Layer1TimerDisabled
    }));
    assert_eq!(
        evidence_text(&findings),
        vec![
            "no .timer block in the timer status (only certbot.service)",
            "no log given",
            "no disk notAfter",
            "no live notAfter",
            "certbot.service failed (Result=exit-code); the renewal ran and failed, check the Certbot log",
        ]
    );
    assert_eq!(exit_of(&findings), 2);
}

#[test]
fn service_only_failed_blocks_ok_not_due() {
    let show = show_file("certbot-service-only-failed.txt");
    let cert = dates_not_after("dates-current.txt");
    assert!(cert.days_until(&fixed_now()) > rules::NOT_DUE_DAYS);
    let findings = rules::analyze(&Observations {
        timer: show.timer,
        service: show.service,
        disk_not_after: Some(cert),
        live_not_after: Some(cert),
        ..blank()
    });
    assert!(findings
        .iter()
        .all(|finding| finding.code != Code::OkNotDue));
    assert_eq!(findings[0].code, Code::InsufficientEvidence);
    assert!(findings.iter().any(|finding| {
        finding
            .evidence
            .iter()
            .any(|item| item.text == "no .timer block in the timer status (only certbot.service)")
    }));
}

#[test]
fn masked_timer_is_disabled() {
    let mut timer = loaded_timer("masked", "inactive", "dead", "success", "no");
    timer.load_state = "masked".to_string();
    let findings = rules::analyze(&Observations {
        timer: Some(timer),
        ..blank()
    });
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, Code::Layer1TimerDisabled);
    assert_eq!(
        evidence_text(&findings),
        vec![
            "LoadState=masked",
            "UnitFileState=masked",
            "ActiveState=inactive",
        ]
    );
    assert!(findings
        .iter()
        .all(|finding| finding.code != Code::Layer1TimerNotFiring));
    assert_eq!(exit_of(&findings), 1);
}

#[test]
fn loaded_unit_file_masked_is_still_disabled() {
    let findings = rules::analyze(&Observations {
        timer: Some(loaded_timer("masked", "inactive", "dead", "success", "")),
        ..blank()
    });
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, Code::Layer1TimerDisabled);
    assert_eq!(
        evidence_text(&findings),
        vec!["UnitFileState=masked", "ActiveState=inactive"]
    );
    assert!(findings
        .iter()
        .all(|finding| finding.code != Code::Layer1TimerNotFiring));
}

fn active_snap() -> TimerStatus {
    timer::parse_systemctl_show(
        "\
Id=snap.certbot.renew.timer
LoadState=loaded
ActiveState=active
UnitFileState=enabled
",
    )
    .expect("snap")
    .snap_timer
    .expect("snap timer")
}

#[test]
fn active_snap_with_off_certbot_timer_is_not_a_timer_code() {
    let snap = active_snap();
    let mut masked_timer = loaded_timer("masked", "inactive", "dead", "success", "no");
    masked_timer.load_state = "masked".to_string();

    let masked = rules::analyze(&Observations {
        timer: Some(masked_timer),
        snap_timer: Some(snap.clone()),
        ..blank()
    });
    assert_eq!(masked.len(), 1);
    assert_eq!(masked[0].code, Code::InsufficientEvidence);
    assert!(evidence_text(&masked).iter().any(|text| {
        *text == "snap.certbot.renew.timer is active and certbot.timer is masked: snap install, not supported yet"
    }));
    assert!(masked.iter().all(|finding| {
        finding.code != Code::Layer1TimerDisabled
            && finding.code != Code::Layer1TimerNotFiring
            && finding.code != Code::OkNotDue
    }));
    assert_eq!(exit_of(&masked), 2);

    let disabled = rules::analyze(&Observations {
        timer: Some(loaded_timer("disabled", "inactive", "dead", "success", "")),
        snap_timer: Some(snap),
        ..blank()
    });
    assert_eq!(disabled[0].code, Code::InsufficientEvidence);
    assert!(evidence_text(&disabled).iter().any(|text| {
        *text == "snap.certbot.renew.timer is active and certbot.timer is disabled: snap install, not supported yet"
    }));
    assert!(disabled
        .iter()
        .all(|finding| finding.code != Code::Layer1TimerDisabled));
}

#[test]
fn active_snap_alone_is_not_ok_not_due() {
    let cert = dates_not_after("dates-current.txt");
    assert!(cert.days_until(&fixed_now()) > rules::NOT_DUE_DAYS);
    let findings = rules::analyze(&Observations {
        snap_timer: Some(active_snap()),
        disk_not_after: Some(cert),
        live_not_after: Some(cert),
        ..blank()
    });
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, Code::InsufficientEvidence);
    assert!(evidence_text(&findings).iter().any(|text| {
        *text == "snap.certbot.renew.timer is active: snap install, not supported yet"
    }));
    assert!(evidence_text(&findings)
        .iter()
        .all(|text| !text.contains("no timer status")));
    assert!(findings.iter().all(|finding| {
        finding.code != Code::OkNotDue
            && finding.code != Code::Layer1TimerDisabled
            && finding.code != Code::Layer1TimerNotFiring
    }));
    assert_eq!(exit_of(&findings), 2);
}

#[test]
fn active_snap_does_not_hide_a_timer_that_is_not_off() {
    let findings = rules::analyze(&Observations {
        timer: Some(loaded_timer(
            "enabled", "inactive", "dead", "success", "yes",
        )),
        snap_timer: Some(active_snap()),
        ..blank()
    });
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, Code::Layer1TimerNotFiring);
    assert!(evidence_text(&findings)
        .iter()
        .all(|text| !text.contains("snap install")));
    assert_eq!(exit_of(&findings), 1);
}

#[test]
fn static_failed_timer_is_not_firing() {
    let findings = rules::analyze(&Observations {
        timer: Some(loaded_timer("static", "failed", "failed", "success", "")),
        ..blank()
    });
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, Code::Layer1TimerNotFiring);
    assert_eq!(
        evidence_text(&findings),
        vec![
            "certbot.timer: ActiveState=failed",
            "SubState=failed",
            "Result=success",
            "UnitFileState=static",
        ]
    );
    assert!(findings
        .iter()
        .all(|finding| finding.code != Code::Layer1TimerDisabled));
    assert_eq!(exit_of(&findings), 1);
}

#[test]
fn parse_systemctl_show_reads_real_examples() {
    assert!(timer::parse_systemctl_show(APT_DAILY).is_none());
    assert!(timer::parse_systemctl_show(XFS_SCRUB).is_none());

    let certbot = APT_DAILY.replace("Id=apt-daily.timer", "Id=certbot.timer");
    let enabled = timer::parse_systemctl_show(&certbot).expect("certbot");
    assert_eq!(
        enabled.timer,
        Some(TimerStatus {
            id: "certbot.timer".to_string(),
            load_state: "loaded".to_string(),
            active_state: "active".to_string(),
            sub_state: "waiting".to_string(),
            unit_file_state: "enabled".to_string(),
            result: "success".to_string(),
            condition_result: String::new(),
        })
    );
    assert!(enabled.service.is_none());

    let mut lines: Vec<&str> = certbot.lines().collect();
    lines.reverse();
    let reversed = lines.join("\n");
    assert_eq!(timer::parse_systemctl_show(&reversed), Some(enabled));

    let missing_sub = "\
Id=certbot.timer
LoadState=loaded
ActiveState=active
UnitFileState=enabled
Result=success
";
    let partial = timer::parse_systemctl_show(missing_sub)
        .expect("partial")
        .timer
        .expect("timer");
    assert_eq!(partial.sub_state, "");
    assert_eq!(partial.id, "certbot.timer");
    assert_eq!(partial.result, "success");
    assert_eq!(partial.condition_result, "");

    assert!(timer::parse_systemctl_show("LoadState=loaded\nActiveState=active\n").is_none());
    assert!(timer::parse_systemctl_show("Id=\nLoadState=loaded\n").is_none());
}

#[test]
fn parse_openssl_enddate_accepts_gmt_only() {
    let june = certtime::parse_openssl_enddate("notAfter=Jun  4 11:04:38 2035 GMT").expect("jun 4");
    assert_eq!(june, at(2035, 6, 4, 11, 4, 38));
    assert_eq!(june.to_string(), "notAfter=Jun  4 11:04:38 2035 GMT");

    let december =
        certtime::parse_openssl_enddate("notAfter=Dec 31 09:37:37 2030 GMT").expect("dec 31");
    assert_eq!(december, at(2030, 12, 31, 9, 37, 37));
    assert_eq!(december.to_string(), "notAfter=Dec 31 09:37:37 2030 GMT");

    assert!(certtime::parse_openssl_enddate("notAfter=Jun  4 11:04:38 2035 UTC").is_none());
    assert!(certtime::parse_openssl_enddate("notAfter=Jun  4 11:04:38 2035 CEST").is_none());
    assert!(certtime::parse_openssl_enddate("notAfter=Jun  4 11:04:38 2035 gmt").is_none());
    assert!(certtime::parse_openssl_enddate("garbage").is_none());
    assert!(certtime::parse_openssl_enddate("notAfter=Foo  4 11:04:38 2035 GMT").is_none());
    assert!(certtime::parse_openssl_enddate("notAfter=Jun 32 11:04:38 2035 GMT").is_none());
    assert!(certtime::parse_openssl_enddate("notAfter=Feb 29 00:00:00 2023 GMT").is_none());
    assert_eq!(
        certtime::parse_openssl_enddate("notAfter=Feb 29 00:00:00 2024 GMT"),
        Some(at(2024, 2, 29, 0, 0, 0))
    );
}

#[test]
fn days_until_crosses_year_and_leap_day() {
    assert_eq!(
        at(2026, 1, 1, 0, 0, 0).days_until(&at(2025, 12, 31, 23, 0, 0)),
        1
    );
    assert_eq!(
        at(2024, 3, 1, 0, 0, 0).days_until(&at(2024, 2, 28, 12, 0, 0)),
        2
    );
    assert_eq!(
        at(2023, 3, 1, 0, 0, 0).days_until(&at(2023, 2, 28, 0, 0, 0)),
        1
    );
    assert_eq!(
        at(2026, 10, 6, 23, 0, 0).days_until(&at(2026, 10, 6, 1, 0, 0)),
        0
    );
}

#[test]
fn cert_time_orders_chronologically() {
    let june = at(2035, 6, 4, 11, 4, 38);
    let december = at(2030, 12, 31, 9, 37, 37);
    assert!(june > december);
    assert!(at(2027, 1, 3, 8, 14, 2) > at(2026, 10, 5, 8, 14, 2));
    assert!(at(2026, 10, 6, 8, 0, 1) > at(2026, 10, 6, 8, 0, 0));
    assert_eq!(at(2026, 10, 6, 8, 0, 0), fixed_now());
}

#[test]
fn parser_keeps_newest_line_of_a_repeated_error() {
    let text = "  Domain: a.example\n  Type:   connection\n  Detail: older\n  Domain: b.example\n  Type:   rateLimited\n  Detail: middle\n  Domain: a.example\n  Type:   connection\n  Detail: older\n";
    let problems = certbot_log::parse(text);
    assert_eq!(problems.len(), 2);
    assert_eq!(problems[0].short_type(), "rateLimited");
    assert_eq!(problems[0].first_line, 4);
    assert_eq!(problems[0].line, 4);
    assert_eq!(problems[0].json_hits, 0);
    assert_eq!(problems[0].summary_hits, 1);
    assert_eq!(problems[0].occurrences, 1);
    assert_eq!(problems[0].attempts(), 1);
    assert_eq!(problems[1].short_type(), "connection");
    assert_eq!(problems[1].detail, "older");
    assert_eq!(problems[1].first_line, 1);
    assert_eq!(problems[1].line, 7);
    assert_eq!(problems[1].json_hits, 0);
    assert_eq!(problems[1].summary_hits, 2);
    assert_eq!(problems[1].occurrences, 2);
    assert_eq!(problems[1].attempts(), 2);
    assert_eq!(problems.last().unwrap().line, 7);
}

fn assert_same_validation_code(short: &str, detail: &str, code: Code) {
    for text in [detail.to_string(), format!("{SECONDARY_PREFIX}{detail}")] {
        let findings = rules::analyze(&Observations {
            problems: vec![acme_problem(short, &text, 4)],
            log_read: true,
            ..blank()
        });
        assert_eq!(findings.len(), 1, "{text}");
        assert_eq!(findings[0].code, code, "{text}");
        assert_eq!(findings[0].evidence[0].source, EvidenceSource::Log);
        assert_eq!(findings[0].evidence[0].text, format!("line 4: {text}"));
        assert_eq!(exit_of(&findings), 1, "{text}");
    }
}

#[test]
fn secondary_prefix_keeps_layer2_http01_timeout() {
    assert_same_validation_code("connection", TIMEOUT_DETAIL, Code::Layer2Http01Timeout);
}

#[test]
fn secondary_prefix_keeps_layer2_http01_refused() {
    assert_same_validation_code("connection", REFUSED_DETAIL, Code::Layer2Http01Refused);
}

#[test]
fn secondary_prefix_keeps_layer2_dns01_txt() {
    assert_same_validation_code("unauthorized", DNS01_NO_TXT_DETAIL, Code::Layer2Dns01Txt);
    assert_same_validation_code("unauthorized", DNS01_INCORRECT_DETAIL, Code::Layer2Dns01Txt);
    assert_same_validation_code("dns", DNS01_LOOKUP_DETAIL, Code::Layer2Dns01Txt);
}

#[test]
fn secondary_prefix_keeps_layer2_rate_limit() {
    assert_same_validation_code("rateLimited", RATE_LIMIT_DETAIL, Code::Layer2RateLimit);
}

fn http_connection_detail(message: &str) -> String {
    format!("203.0.113.10: Fetching http://example.com/.well-known/acme-challenge/connectiontoken000000000000001: {message}")
}

fn assert_connection_without_rule(detail: &str) {
    let findings = rules::analyze(&Observations {
        problems: vec![acme_problem("connection", detail, 9)],
        log_read: true,
        ..blank()
    });
    assert_eq!(findings.len(), 1, "{detail}");
    assert_eq!(findings[0].code, Code::InsufficientEvidence, "{detail}");
    assert!(findings[0].evidence.iter().any(|item| {
        item.source == EvidenceSource::Log && item.text == CONNECTION_WITHOUT_RULE
    }));
    assert!(findings[0].evidence.iter().any(|item| {
        item.source == EvidenceSource::Log && item.text == format!("line 9: {detail}")
    }));
    assert!(findings[0]
        .evidence
        .iter()
        .all(|item| item.text != UNRECOGNISED_ACME));
    assert_eq!(exit_of(&findings), 2, "{detail}");
}

#[test]
fn network_unreachable_has_no_validation_code() {
    assert_connection_without_rule(&http_connection_detail("Network unreachable"));
}

#[test]
fn connection_reset_by_peer_has_no_validation_code() {
    assert_connection_without_rule(&http_connection_detail("Connection reset by peer"));
}

#[test]
fn timeout_after_connect_has_no_validation_code() {
    assert_connection_without_rule(&http_connection_detail(
        "Timeout after connect (your server may be slow or overloaded)",
    ));
}

#[test]
fn timeout_during_read_has_no_validation_code() {
    assert_connection_without_rule(&http_connection_detail(
        "Timeout during read (your server may be slow or overloaded)",
    ));
}

#[test]
fn secondary_prefix_on_network_unreachable_stays_without_a_rule() {
    let detail = format!(
        "{SECONDARY_PREFIX}{}",
        http_connection_detail("Network unreachable")
    );
    assert_connection_without_rule(&detail);
}

#[test]
fn ordinary_unrecognised_error_keeps_the_existing_line() {
    let findings = rules::analyze(&Observations {
        problems: vec![acme_problem(
            "connection",
            "Error getting validation data",
            6,
        )],
        log_read: true,
        ..blank()
    });
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, Code::InsufficientEvidence);
    assert!(findings[0]
        .evidence
        .iter()
        .any(|item| item.text == UNRECOGNISED_ACME));
    assert!(findings[0]
        .evidence
        .iter()
        .all(|item| item.text != CONNECTION_WITHOUT_RULE));
    assert_eq!(exit_of(&findings), 2);
}

#[test]
fn secondary_prefix_is_removed_only_at_the_start() {
    let mid = format!("see note {SECONDARY_PREFIX}{DNS01_NO_TXT_DETAIL}");
    let findings = rules::analyze(&Observations {
        problems: vec![acme_problem("unauthorized", &mid, 5)],
        log_read: true,
        ..blank()
    });
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, Code::InsufficientEvidence);
    assert!(findings
        .iter()
        .all(|finding| finding.code != Code::Layer2Dns01Txt));
    assert!(findings[0]
        .evidence
        .iter()
        .any(|item| item.text == UNRECOGNISED_ACME));
    assert_eq!(exit_of(&findings), 2);

    let twice = format!("{SECONDARY_PREFIX}{SECONDARY_PREFIX}{DNS01_NO_TXT_DETAIL}");
    let findings = rules::analyze(&Observations {
        problems: vec![acme_problem("unauthorized", &twice, 5)],
        log_read: true,
        ..blank()
    });
    assert_eq!(findings[0].code, Code::InsufficientEvidence);
    assert_eq!(exit_of(&findings), 2);
}

#[test]
fn layer2_dns01_txt_secondary_prefix_from_fixture() {
    let problems = log_problems("dns01-no-txt-secondary.log");
    assert_eq!(problems.len(), 1);
    let detail = format!("{SECONDARY_PREFIX}{DNS01_NO_TXT_DETAIL}");
    assert_eq!(problems[0].short_type(), "unauthorized");
    assert_eq!(problems[0].detail, detail);
    assert_eq!(problems[0].line, 32);
    assert_eq!(problems[0].attempts(), 1);

    let findings = rules::analyze(&Observations {
        problems,
        log_read: true,
        ..blank()
    });
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, Code::Layer2Dns01Txt);
    assert_eq!(findings[0].evidence[0].source, EvidenceSource::Log);
    assert_eq!(findings[0].evidence[0].text, format!("line 32: {detail}"));
    assert_eq!(exit_of(&findings), 1);
}
