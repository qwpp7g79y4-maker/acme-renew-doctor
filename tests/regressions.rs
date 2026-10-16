//! Regressions for confirmed parser, timer and gate bugs.

#[cfg(target_os = "linux")]
use std::path::PathBuf;
use std::process::Command;
#[cfg(target_os = "linux")]
use std::process::Stdio;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "linux")]
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use acme_renew_doctor::certbot_log::{self, parse_log};
use acme_renew_doctor::certtime::{self, CertTime};
use acme_renew_doctor::model::{
    ClientKind, Code, Confidence, Evidence, EvidenceSource, Finding, Report, Snapshot,
};
use acme_renew_doctor::render::{self, escape_file_text};
use acme_renew_doctor::rules::{self, Observations};
use acme_renew_doctor::safe::check_command;
use acme_renew_doctor::timer::{self, ShowParse, TimerStatus};

const TIMEOUT_DETAIL: &str = "Fetching http://example.com/.well-known/acme-challenge/tok: Timeout during connect (likely firewall problem)";
const NOW_SECS: i64 = 1_791_273_600;

fn now() -> CertTime {
    certtime::from_unix_seconds(NOW_SECS)
}

fn later() -> CertTime {
    certtime::from_unix_seconds(NOW_SECS + 100 * 86_400)
}

fn healthy_timer() -> TimerStatus {
    TimerStatus {
        id: "certbot.timer".to_string(),
        load_state: "loaded".to_string(),
        active_state: "active".to_string(),
        sub_state: "waiting".to_string(),
        unit_file_state: "enabled".to_string(),
        result: "success".to_string(),
        condition_result: "yes".to_string(),
    }
}

fn snap_timer(load: &str, active: &str, unit_file: &str) -> TimerStatus {
    TimerStatus {
        id: "snap.certbot.renew.timer".to_string(),
        load_state: load.to_string(),
        active_state: active.to_string(),
        sub_state: "dead".to_string(),
        unit_file_state: unit_file.to_string(),
        result: "success".to_string(),
        condition_result: "no".to_string(),
    }
}

fn observations(problems: Vec<certbot_log::AcmeProblem>) -> Observations {
    Observations {
        timer: Some(healthy_timer()),
        service: None,
        snap_timer: None,
        problems,
        disk_not_after: Some(later()),
        live_not_after: Some(later()),
        now: now(),
        read_errors: Vec::new(),
        log_read: true,
        log_has_replacement_char: false,
    }
}

fn codes(findings: &[acme_renew_doctor::model::Finding]) -> Vec<Code> {
    findings.iter().map(|finding| finding.code).collect()
}

fn report_text(findings: Vec<acme_renew_doctor::model::Finding>) -> String {
    let report = Report {
        snapshot: Snapshot {
            domain: Some("example.com".to_string()),
            all: false,
            client: ClientKind::Certbot,
            from_log: None,
            from_timer_status: None,
            from_cert_disk: None,
            from_cert_live: None,
        },
        findings,
        replaced_invalid_utf8_bytes: 0,
    };
    render::human(&report, &[])
}

#[test]
fn gate_rejects_unspaced_pipeline() {
    assert!(check_command("dig +short A example.com|sh").is_err());
    assert!(check_command(
        "echo | timeout 10 openssl s_client -connect example.com:443 -servername example.com | openssl x509 -noout -dates"
    )
    .is_ok());
}

#[test]
fn gate_rejects_curl_trace_file_write() {
    assert!(check_command("curl -q -sI --trace /tmp/out http://example.com/").is_err());
    assert!(check_command("curl -q -sI --trace-ascii /tmp/out http://example.com/").is_err());
}

#[test]
fn gate_rejects_curl_stderr_file_write() {
    assert!(check_command("curl -q -sI --stderr /tmp/out http://example.com/").is_err());
}

#[test]
fn gate_rejects_curl_without_leading_q_and_other_write_options() {
    assert!(
        check_command("curl -sI http://example.com/.well-known/acme-challenge/test")
            .unwrap_err()
            .contains("curl must use -q as its first argument")
    );
    assert!(
        check_command("curl -q -sI http://example.com/.well-known/acme-challenge/test").is_ok()
    );
    for command in [
        "curl -q -sI --etag-save /tmp/out http://example.com/",
        "curl -q -sI --hsts /tmp/out http://example.com/",
        "curl -q -sI --alt-svc /tmp/out http://example.com/",
        "curl -q -sI --libcurl /tmp/out http://example.com/",
        "curl -q -sI --create-dirs http://example.com/",
        "curl -q -sI --output-dir /tmp http://example.com/",
        "curl -q -sI -w @/tmp/out http://example.com/",
        "curl -q -sI --write-out @/tmp/out http://example.com/",
    ] {
        assert!(check_command(command).is_err(), "{command}");
    }
}

#[test]
fn first_occurrence_is_the_earliest_timestamp() {
    // Same error three times: 03:00 (line 2), 05:00 (line 4), 04:00 (line 6).
    let entry = |stamp: &str| {
        format!(
            "2026-09-28 {stamp},000:DEBUG:acme.client:Received response:\n\
             {{\"type\": \"urn:ietf:params:acme:error:connection\", \"detail\": \"same\"}}\n"
        )
    };
    let text = entry("03:00:00") + &entry("05:00:00") + &entry("04:00:00");
    let problems = certbot_log::parse(&text);
    assert_eq!(problems.len(), 1);
    assert_eq!(problems[0].line, 4, "latest attempt");
    assert_eq!(problems[0].first_line, 2, "earliest attempt");
}

#[test]
fn type_value_split_across_newlines_is_a_timeout() {
    let text = format!(
        "2026-09-28 03:12:44,512:DEBUG:acme.client:Received response:\n\
         {{\n\"type\"\n:\n\"urn:ietf:params:acme:error:connection\"\n,\n\
         \"detail\": \"{TIMEOUT_DETAIL}\"\n}}\n"
    );
    let parsed = parse_log(&text);
    assert!(!parsed.ambiguous_json);
    assert_eq!(parsed.problems.len(), 1, "{:?}", parsed.problems);
    assert_eq!(parsed.problems[0].short_type(), "connection");
    assert!(parsed.problems[0].detail.contains("Timeout during connect"));
    let findings = rules::analyze(&observations(parsed.problems));
    assert_eq!(codes(&findings), vec![Code::Layer2Http01Timeout]);
    assert!(findings
        .iter()
        .all(|finding| finding.code != Code::OkNotDue));
}

#[test]
fn duplicate_unit_property_with_a_different_value_is_ambiguous() {
    let conflict = "\
Id=certbot.timer
LoadState=loaded
ActiveState=active
UnitFileState=disabled
UnitFileState=enabled
";
    assert_eq!(timer::classify_show(conflict), ShowParse::Ambiguous);

    let same = "\
Id=certbot.timer
Id=certbot.timer
LoadState=loaded
ActiveState=active
SubState=waiting
UnitFileState=enabled
UnitFileState=enabled
Result=success
";
    match timer::classify_show(same) {
        ShowParse::Units(show) => {
            let timer = show.timer.expect("timer");
            assert_eq!(timer.unit_file_state, "enabled");
            assert_eq!(timer.active_state, "active");
        }
        other => panic!("equal duplicates must parse: {other:?}"),
    }

    let unrelated = "\
Id=apt-daily.timer
LoadState=loaded
UnitFileState=disabled
UnitFileState=enabled

Id=certbot.timer
LoadState=loaded
ActiveState=active
SubState=waiting
UnitFileState=enabled
Result=success
";
    match timer::classify_show(unrelated) {
        ShowParse::Units(show) => assert!(show.timer.is_some()),
        other => panic!("an unrelated unit must not make certbot ambiguous: {other:?}"),
    }

    let id_twice = "\
Id=certbot.timer
Id=certbot.service
LoadState=loaded
ActiveState=active
UnitFileState=enabled
";
    assert_eq!(timer::classify_show(id_twice), ShowParse::Ambiguous);
}

#[test]
fn snap_timer_alone_when_not_running_is_not_ok() {
    for (load, active, unit_file) in [
        ("loaded", "inactive", "disabled"),
        ("loaded", "inactive", "enabled"),
        ("not-found", "inactive", "disabled"),
    ] {
        let mut obs = observations(Vec::new());
        obs.timer = None;
        obs.snap_timer = Some(snap_timer(load, active, unit_file));
        let findings = rules::analyze(&obs);
        assert!(
            findings
                .iter()
                .all(|finding| finding.code != Code::OkNotDue),
            "{load}/{active}/{unit_file}: {findings:?}"
        );
        let text = findings
            .iter()
            .flat_map(|finding| finding.evidence.iter())
            .map(|item| item.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            text.contains("snap.certbot.renew.timer"),
            "{load}/{active}/{unit_file}: {text}"
        );
    }

    let mut mixed = observations(Vec::new());
    mixed.snap_timer = Some(snap_timer("loaded", "inactive", "disabled"));
    let findings = rules::analyze(&mixed);
    assert_eq!(codes(&findings), vec![Code::OkNotDue]);
}

#[test]
fn parent_and_nested_subproblem_do_not_depend_on_field_order() {
    let nested = format!(
        "{{\"type\":\"urn:ietf:params:acme:error:connection\",\"detail\":\"{TIMEOUT_DETAIL}\"}}"
    );
    let parent_first = format!(
        "2026-09-28 03:12:44,512:DEBUG:acme.client:Received response:\n\
         {{\"type\":\"urn:ietf:params:acme:error:unauthorized\",\"detail\":\"outer\",\"subproblems\":[{nested}]}}\n"
    );
    let parent_last = format!(
        "2026-09-28 03:12:44,512:DEBUG:acme.client:Received response:\n\
         {{\"subproblems\":[{nested}],\"type\":\"urn:ietf:params:acme:error:unauthorized\",\"detail\":\"outer\"}}\n"
    );
    let first = parse_log(&parent_first);
    let last = parse_log(&parent_last);
    assert!(!first.ambiguous_json && !last.ambiguous_json);
    let win = |parsed: &certbot_log::LogParse| parsed.problems.last().expect("a problem").clone();
    let left = win(&first);
    let right = win(&last);
    assert_eq!(left.short_type(), "connection");
    assert_eq!(right.short_type(), "connection");
    assert_eq!(left.detail, right.detail);
    assert!(left.detail.contains("/.well-known/acme-challenge/"));
    assert!(left.detail.contains("Timeout during connect"));
    assert!(first
        .problems
        .iter()
        .any(|problem| problem.short_type() == "unauthorized"));
    assert!(last
        .problems
        .iter()
        .any(|problem| problem.short_type() == "unauthorized"));
    assert!(left.depth > 0);
    for parsed in [&first, &last] {
        let findings = rules::analyze(&observations(parsed.problems.clone()));
        assert_eq!(codes(&findings), vec![Code::Layer2Http01Timeout]);
    }
}

#[test]
fn duplicate_type_or_detail_of_any_json_kind_is_ambiguous() {
    for value in ["null", "[1, 2]", "true", "1", "{\"a\":1}"] {
        for key in ["type", "detail"] {
            let text = format!(
                "{{\"type\":\"urn:ietf:params:acme:error:connection\",\"detail\":\"{TIMEOUT_DETAIL}\",\"{key}\":{value}}}"
            );
            let parsed = parse_log(&text);
            assert!(parsed.ambiguous_json, "{text}");
            assert!(
                parsed
                    .problems
                    .iter()
                    .all(|problem| problem.short_type() != "connection"),
                "{text}: {:?}",
                parsed.problems
            );
        }
    }
    let same_null =
        "{\"type\":\"urn:ietf:params:acme:error:connection\",\"detail\":null,\"detail\":null}";
    let parsed = parse_log(same_null);
    assert!(!parsed.ambiguous_json, "{:?}", parsed.problems);
    assert_eq!(parsed.problems.len(), 1);
    assert_eq!(parsed.problems[0].short_type(), "connection");
    assert!(parsed.problems[0].detail.is_empty());
}

fn distinct_errors_log(count: usize) -> String {
    let mut text = String::with_capacity(count * 90 + 64);
    text.push_str("2026-09-28 03:12:44,512:DEBUG:certbot._internal.main:start\n");
    for n in 0..count {
        text.push_str("{\"type\":\"urn:ietf:params:acme:error:connection\",\"detail\":\"err ");
        text.push_str(&n.to_string());
        text.push_str("\"}\n");
    }
    text
}

/// Parses `text` `repeats` times and returns the fastest wall-clock time seen,
/// alongside the problem count (which is identical on every repeat).
fn fastest_parse(text: &str, repeats: u32) -> (Duration, usize) {
    let mut best = Duration::MAX;
    let mut count = 0;
    for _ in 0..repeats {
        let started = std::time::Instant::now();
        let problems = certbot_log::parse(text);
        let elapsed = started.elapsed();
        count = problems.len();
        best = best.min(elapsed);
    }
    (best, count)
}

/// A wall-clock ceiling on parsing is flaky on shared CI runners (it once
/// flaked on a slow macOS Intel runner at 3.67s against a 3s budget), since
/// the runner's absolute speed is outside our control. What we actually care
/// about is that `certbot_log::parse` stays roughly linear in the number of
/// distinct errors, so a quadratic-or-worse regression still gets caught.
/// We time a small input and a 4x-larger one (best of a few repeats each, to
/// damp scheduler jitter) and assert the runtime ratio stays far below the
/// 16x a quadratic algorithm would produce, plus a very generous absolute
/// cap as a backstop against outright hangs.
#[test]
fn distinct_errors_parse_scales_linearly() {
    const SMALL: usize = 10_000;
    const FACTOR: usize = 4;
    const REPEATS: u32 = 5;

    let small_text = distinct_errors_log(SMALL);
    let large_text = distinct_errors_log(SMALL * FACTOR);

    let (small_time, small_count) = fastest_parse(&small_text, REPEATS);
    let (large_time, large_count) = fastest_parse(&large_text, REPEATS);

    assert_eq!(small_count, SMALL);
    assert_eq!(large_count, SMALL * FACTOR);

    assert!(
        large_time < Duration::from_secs(30),
        "parsing {} distinct errors took {large_time:?}, which looks hung rather than merely slow",
        SMALL * FACTOR
    );

    let small_nanos = (small_time.as_nanos() as f64).max(1.0);
    let large_nanos = large_time.as_nanos() as f64;
    let ratio = large_nanos / small_nanos;
    assert!(
        ratio < 12.0,
        "parse time scaled {ratio:.2}x for a {FACTOR}x larger input \
         (small={small_time:?} for {SMALL}, large={large_time:?} for {}); \
         linear scaling would be {FACTOR}x and quadratic would be {}x",
        SMALL * FACTOR,
        FACTOR * FACTOR
    );
}

#[test]
fn missing_active_state_is_not_a_high_confidence_timer_failure() {
    let mut timer = healthy_timer();
    timer.active_state.clear();
    let mut obs = observations(Vec::new());
    obs.timer = Some(timer);
    let findings = rules::analyze(&obs);
    assert!(findings
        .iter()
        .all(|finding| finding.code != Code::OkNotDue));
    assert!(findings
        .iter()
        .all(|finding| finding.code != Code::Layer1TimerNotFiring));
    assert!(findings
        .iter()
        .all(|finding| finding.confidence != Confidence::High
            || finding.code != Code::Layer1TimerNotFiring));
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, Code::InsufficientEvidence);
    assert_eq!(findings[0].confidence, Confidence::Low);
}

#[test]
fn failed_service_evidence_stays_on_a_layer_finding() {
    let mut obs = observations(Vec::new());
    obs.timer = Some(TimerStatus {
        id: "certbot.timer".to_string(),
        load_state: "loaded".to_string(),
        active_state: "inactive".to_string(),
        sub_state: "dead".to_string(),
        unit_file_state: "disabled".to_string(),
        result: "success".to_string(),
        condition_result: "yes".to_string(),
    });
    obs.service = Some(TimerStatus {
        id: "certbot.service".to_string(),
        load_state: "loaded".to_string(),
        active_state: "failed".to_string(),
        sub_state: "failed".to_string(),
        unit_file_state: "enabled".to_string(),
        result: "exit-code".to_string(),
        condition_result: "yes".to_string(),
    });
    let findings = rules::analyze(&obs);
    assert_eq!(findings[0].code, Code::Layer1TimerDisabled);
    let notes = findings[0]
        .evidence
        .iter()
        .filter(|item| {
            item.text
                .contains("certbot.service failed (Result=exit-code)")
        })
        .count();
    assert_eq!(notes, 1, "{:?}", findings[0].evidence);
    assert!(findings[0]
        .evidence
        .iter()
        .any(|item| { item.text.ends_with(rules::FAILED_SERVICE_NOTE_SUFFIX) }));
}

#[test]
fn failed_service_note_attaches_to_the_diagnosis_not_a_read_error() {
    let mut obs = observations(Vec::new());
    obs.read_errors = vec![Finding::new(
        Code::InsufficientEvidence,
        Confidence::Low,
        vec![Evidence {
            source: EvidenceSource::Disk,
            text: "cannot read disk cert: permission denied".to_string(),
        }],
    )];
    obs.timer = Some(TimerStatus {
        id: "certbot.timer".to_string(),
        load_state: "loaded".to_string(),
        active_state: "inactive".to_string(),
        sub_state: "dead".to_string(),
        unit_file_state: "disabled".to_string(),
        result: "success".to_string(),
        condition_result: "yes".to_string(),
    });
    obs.service = Some(TimerStatus {
        id: "certbot.service".to_string(),
        load_state: "loaded".to_string(),
        active_state: "failed".to_string(),
        sub_state: "failed".to_string(),
        unit_file_state: "enabled".to_string(),
        result: "exit-code".to_string(),
        condition_result: "yes".to_string(),
    });
    let findings = rules::analyze(&obs);
    assert_eq!(findings[0].code, Code::InsufficientEvidence);
    assert_eq!(findings[1].code, Code::Layer1TimerDisabled);
    assert!(
        findings[0]
            .evidence
            .iter()
            .all(|item| !item.text.ends_with(rules::FAILED_SERVICE_NOTE_SUFFIX)),
        "the failed-service note must not land on the unrelated read-error finding: {:?}",
        findings[0].evidence
    );
    assert!(
        findings[1]
            .evidence
            .iter()
            .any(|item| item.text.ends_with(rules::FAILED_SERVICE_NOTE_SUFFIX)),
        "the failed-service note belongs on the real diagnosis: {:?}",
        findings[1].evidence
    );
}

#[test]
fn bidi_controls_are_escaped_in_text() {
    for ch in ['\u{202e}', '\u{2066}', '\u{200e}', '\u{200f}', '\u{061c}'] {
        let escaped = escape_file_text(&format!("name{ch}x"));
        let raw = format!("\\u{{{:x}}}", u32::from(ch));
        assert!(escaped.contains(&raw), "{escaped}");
        assert!(!escaped.contains(ch));
    }
    let detail = format!("{TIMEOUT_DETAIL} \u{202e}");
    let text =
        format!("{{\"type\":\"urn:ietf:params:acme:error:connection\",\"detail\":\"{detail}\"}}");
    let findings = rules::analyze(&observations(certbot_log::parse(&text)));
    let shown = report_text(findings);
    assert!(shown.contains("\\u{202e}"), "{shown}");
    assert!(!shown.contains('\u{202e}'));
}

#[test]
fn system_clock_before_epoch_is_rejected() {
    let before = UNIX_EPOCH
        .checked_sub(Duration::from_secs(1))
        .expect("one second before the epoch");
    let err = certtime::try_from_system_time(before).unwrap_err();
    assert!(err.contains("system clock is outside"), "{err}");
    assert!(certtime::try_from_system_time(UNIX_EPOCH).is_ok());
    assert_eq!(
        certtime::try_from_system_time(SystemTime::UNIX_EPOCH)
            .unwrap()
            .year,
        1970
    );
}

#[test]
fn invalid_now_override_escapes_controls() {
    let output = Command::new(env!("CARGO_BIN_EXE_acme-renew-doctor"))
        .args(["example.com"])
        .env("ACME_RENEW_DOCTOR_NOW", "12\u{1b}[31mRED\u{7}")
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(3));
    assert!(!output.stderr.contains(&0x1b));
    assert!(!output.stderr.contains(&0x07));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("\\u{1b}"), "{stderr}");
    assert!(stderr.contains("\\u{7}"), "{stderr}");
}

#[cfg(unix)]
fn shown_log_input(text: &str) -> &str {
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

#[cfg(unix)]
#[test]
fn newline_and_backslash_n_in_a_path_render_differently() {
    let dir = std::env::temp_dir().join(format!("acme-path-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let newline = dir.join("a\nb.log");
    let literal = dir.join("a\\nb.log");
    std::fs::write(&newline, b"x").unwrap();
    std::fs::write(&literal, b"x").unwrap();
    let show = |path: &std::path::Path| {
        let output = Command::new(env!("CARGO_BIN_EXE_acme-renew-doctor"))
            .args(["example.com", "--from-log"])
            .arg(path)
            .output()
            .expect("run");
        String::from_utf8(output.stdout).expect("utf-8")
    };
    let newline_text = show(&newline);
    let literal_text = show(&literal);
    let newline_path = newline.display().to_string();
    let literal_path = literal.display().to_string();
    assert!(
        !newline_path.contains('\\'),
        "temp path must not already contain a backslash: {newline_path:?}"
    );
    assert_eq!(
        shown_log_input(&newline_text),
        format!("\"{}\"", newline_path.replace('\n', "\\n"))
    );
    assert_eq!(shown_log_input(&literal_text), literal_path);
    assert_ne!(newline_text, literal_text);
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(target_os = "linux")]
fn run_under_256_mib(path: &std::path::Path) -> Option<i32> {
    let bin = env!("CARGO_BIN_EXE_acme-renew-doctor");
    let output = Command::new("sh")
        .arg("-c")
        .arg("ulimit -v 262144 && exec \"$0\" \"$@\"")
        .arg(bin)
        .arg("example.com")
        .arg("--client")
        .arg("certbot")
        .arg("--from-log")
        .arg(path)
        .output()
        .expect("sh");
    output.status.code()
}

#[cfg(target_os = "linux")]
fn write_filler(name: &str, byte: u8) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("acme-mem-{}-{}", std::process::id(), name));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    let mut file = std::fs::File::create(&path).unwrap();
    use std::io::Write;
    file.write_all(b"2026-09-28 03:12:44,512:DEBUG:certbot._internal.main:start\n")
        .unwrap();
    let chunk = vec![byte; 1024 * 1024];
    for _ in 0..8 {
        file.write_all(&chunk).unwrap();
    }
    path
}

#[cfg(target_os = "linux")]
#[test]
fn eight_mib_newline_log_stays_under_256_mib() {
    let path = write_filler("newlines.log", b'\n');
    let code = run_under_256_mib(&path);
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
    assert!(matches!(code, Some(0..=3)), "newline log status {code:?}");
}

#[cfg(target_os = "linux")]
#[test]
fn eight_mib_brace_log_stays_under_256_mib() {
    let path = write_filler("braces.log", b'{');
    let code = run_under_256_mib(&path);
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
    assert!(matches!(code, Some(0..=3)), "brace log status {code:?}");
}

#[cfg(target_os = "linux")]
#[test]
fn fifo_swapped_over_a_regular_file_does_not_block() {
    let dir = std::env::temp_dir().join(format!("acme-fifo-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("input.log");
    std::fs::write(&path, b"hello\n").unwrap();
    let fifo = dir.join("fifo");
    assert!(Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    let stop = Arc::new(AtomicBool::new(false));
    let stop_swap = Arc::clone(&stop);
    let path_swap = path.clone();
    let fifo_swap = fifo.clone();
    let regular = dir.join("regular.log");
    let swapper = std::thread::spawn(move || {
        while !stop_swap.load(Ordering::Relaxed) {
            let _ = std::fs::rename(&fifo_swap, &path_swap);
            let _ = std::fs::write(&regular, b"x");
            let _ = std::fs::rename(&regular, &path_swap);
            let _ = Command::new("mkfifo").arg(&fifo_swap).status();
        }
    });
    let bin = env!("CARGO_BIN_EXE_acme-renew-doctor");
    let started = std::time::Instant::now();
    let mut blocked = false;
    while started.elapsed() < Duration::from_millis(400) {
        let mut child = Command::new(bin)
            .args(["example.com", "--client", "certbot", "--from-log"])
            .arg(&path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_millis(500);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if std::time::Instant::now() > deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    blocked = true;
                    break;
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(5)),
                Err(_) => break,
            }
        }
        if blocked {
            break;
        }
    }
    stop.store(true, Ordering::Relaxed);
    let _ = swapper.join();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(!blocked, "read blocked on a fifo swapped onto the path");
}
