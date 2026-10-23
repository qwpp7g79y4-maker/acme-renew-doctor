use crate::certbot_log::AcmeProblem;
use crate::certtime::CertTime;
use crate::model::{Code, Confidence, Evidence, EvidenceSource, Finding};
use crate::timer::TimerStatus;

pub struct Observations {
    pub timer: Option<TimerStatus>,
    pub service: Option<TimerStatus>,
    pub snap_timer: Option<TimerStatus>,
    pub problems: Vec<AcmeProblem>,
    pub disk_not_after: Option<CertTime>,
    pub live_not_after: Option<CertTime>,
    /// From the same saved `-dates` output as `disk_not_after`, when that
    /// output has a `notBefore=` line. Used only to scale the `OK_NOT_DUE`
    /// threshold to the certificate's own lifetime.
    pub disk_not_before: Option<CertTime>,
    pub now: CertTime,
    pub read_errors: Vec<Finding>,
    /// True when a log was passed and read.
    pub log_read: bool,
    /// The decoded log contains U+FFFD. That character can hide an error, so it is not OK.
    pub log_has_replacement_char: bool,
}

/// Fallback threshold when the certificate's own lifetime is not known
/// (`disk_not_before` missing or not earlier than `disk_not_after`). Also
/// the value `not_due_threshold` computes for a 90-day certificate, so a
/// certbot-default certificate sees the same behaviour as before.
pub const NOT_DUE_DAYS: i64 = 30;

/// Days of validity that must remain for `OK_NOT_DUE`: one third of the
/// certificate's total lifetime, the window ACME Renewal Info (ARI) and
/// Certbot's `renew_before_expiry` advise renewing in. A fixed 30 days
/// approximated this for Certbot's 90-day default, but Let's Encrypt also
/// issues 6-day short-lived certificates, for which 30 days is longer than
/// the certificate's entire lifetime; scaling to the real lifetime keeps
/// `OK_NOT_DUE` reachable for those. Capped at `NOT_DUE_DAYS`: no publicly
/// trusted certificate is longer-lived than Certbot's 90-day default, so a
/// lifetime that implies a bigger threshold (a placeholder or malformed
/// notBefore) must not make `OK_NOT_DUE` more lenient than the old fixed
/// threshold. Falls back to `NOT_DUE_DAYS` when the lifetime is not known.
fn not_due_threshold(not_before: Option<CertTime>, not_after: CertTime) -> i64 {
    let Some(not_before) = not_before else {
        return NOT_DUE_DAYS;
    };
    let lifetime_days = not_after.days_until(&not_before);
    if lifetime_days <= 0 {
        return NOT_DUE_DAYS;
    }
    (lifetime_days / 3).min(NOT_DUE_DAYS)
}

pub const FAILED_SERVICE_NOTE_SUFFIX: &str = "; the renewal ran and failed, check the Certbot log";

pub fn analyze(obs: &Observations) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(obs.read_errors.iter().cloned());

    if let Some(finding) = timer_code(obs) {
        findings.push(finding);
    }
    if let Some(finding) = validation_on_latest(obs) {
        findings.push(finding);
    }
    if let Some(finding) = no_reload(obs) {
        findings.push(finding);
    }

    // A real problem is any finding whose code names a layer (`Code::layer`).
    // That classification is canonical, so it is reused here instead of a
    // second, hand-maintained list that can drift from it.
    let diagnosed = findings
        .iter()
        .any(|finding| counts_as_diagnosis(finding.code));
    if !diagnosed && obs.read_errors.is_empty() {
        if let Some(finding) = ok_not_due(obs) {
            findings.push(finding);
        }
    }
    if findings.is_empty() {
        findings.push(insufficient(obs));
    }
    attach_failed_service(obs, &mut findings);
    findings
}

fn timer_code(obs: &Observations) -> Option<Finding> {
    if snap_install_note(obs).is_some() {
        return None;
    }
    timer_disabled(obs).or_else(|| timer_not_firing(obs))
}

fn timer_disabled(obs: &Observations) -> Option<Finding> {
    let timer = obs.timer.as_ref()?;
    let load_masked = timer.load_state == "masked";
    let loaded_off = timer.load_state == "loaded"
        && (timer.unit_file_state == "disabled" || timer.unit_file_state == "masked");
    if !load_masked && !loaded_off {
        return None;
    }
    let mut evidence = Vec::new();
    if load_masked {
        evidence.push(timer_line("LoadState=masked"));
    }
    evidence.push(timer_line(&format!(
        "UnitFileState={}",
        timer.unit_file_state
    )));
    evidence.push(timer_line(&format!("ActiveState={}", timer.active_state)));
    Some(Finding::new(
        Code::Layer1TimerDisabled,
        Confidence::High,
        evidence,
    ))
}

fn timer_not_firing(obs: &Observations) -> Option<Finding> {
    let timer = obs.timer.as_ref()?;
    if timer.load_state != "loaded" {
        return None;
    }
    // A missing ActiveState or UnitFileState is not a high-confidence failure.
    if timer.active_state.is_empty() || timer.unit_file_state.is_empty() {
        return None;
    }
    if timer.unit_file_state == "disabled" || timer.unit_file_state == "masked" {
        return None;
    }
    let bad_result = !timer.result.is_empty() && timer.result != "success";
    if timer.active_state == "active" && !bad_result {
        return None;
    }
    let mut evidence = vec![
        timer_line(&format!("{}: ActiveState={}", timer.id, timer.active_state)),
        timer_line(&format!("SubState={}", timer.sub_state)),
    ];
    if !timer.result.is_empty() {
        evidence.push(timer_line(&format!("Result={}", timer.result)));
    }
    evidence.push(timer_line(&format!(
        "UnitFileState={}",
        timer.unit_file_state
    )));
    if !timer.condition_result.is_empty() {
        evidence.push(timer_line(&format!(
            "ConditionResult={}",
            timer.condition_result
        )));
    }
    Some(Finding::new(
        Code::Layer1TimerNotFiring,
        Confidence::High,
        evidence,
    ))
}

/// At most one validation code: the ACME error with the latest timestamp.
/// `parse` leaves that one last. At the same timestamp a nested subproblem
/// outranks its parent. Equal depth, or no timestamps at all, keeps the bottom line.
fn validation_on_latest(obs: &Observations) -> Option<Finding> {
    let problem = obs.problems.last()?;
    let code = validation_code(problem)?;
    Some(Finding::new(
        code,
        Confidence::High,
        validation_evidence(problem, code),
    ))
}

/// Boulder va/va.go r.718 puts this once in front of the original detail.
const SECONDARY_VALIDATION_PREFIX: &str = "During secondary validation: ";

fn without_secondary_prefix(detail: &str) -> &str {
    detail
        .strip_prefix(SECONDARY_VALIDATION_PREFIX)
        .unwrap_or(detail)
}

fn validation_code(problem: &AcmeProblem) -> Option<Code> {
    let short = problem.short_type();
    let detail = without_secondary_prefix(&problem.detail);
    if short == "connection"
        && detail.contains("/.well-known/acme-challenge/")
        && detail.contains("Timeout during connect")
    {
        return Some(Code::Layer2Http01Timeout);
    }
    if short == "connection"
        && detail.contains("/.well-known/acme-challenge/")
        && detail.contains("Connection refused")
    {
        return Some(Code::Layer2Http01Refused);
    }
    if short == "rateLimited" {
        return Some(Code::Layer2RateLimit);
    }
    if (short == "unauthorized"
        && (detail.starts_with("No TXT record found at _acme-challenge.")
            || (detail.starts_with("Incorrect TXT record ")
                && detail.contains(" found at _acme-challenge."))))
        || (short == "dns" && detail.contains(" looking up TXT for _acme-challenge."))
    {
        return Some(Code::Layer2Dns01Txt);
    }
    None
}

/// Boulder va/va.go r.401 (`%s: %s`) and r.408 (`Fetching %s: %s`), optional.
fn without_ip_and_fetching(detail: &str) -> &str {
    let after_ip = strip_ip_prefix(detail);
    strip_fetching_prefix(after_ip)
}

fn strip_ip_prefix(detail: &str) -> &str {
    let Some((head, rest)) = detail.split_once(": ") else {
        return detail;
    };
    if is_ip_address(head) {
        rest
    } else {
        detail
    }
}

fn is_ip_address(text: &str) -> bool {
    if text.is_empty() || !text.chars().any(|ch| ch.is_ascii_hexdigit()) {
        return false;
    }
    if text.contains(':') {
        return text
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() || ch == '.' || ch == ':');
    }
    text.contains('.') && text.chars().all(|ch| ch.is_ascii_digit() || ch == '.')
}

fn strip_fetching_prefix(detail: &str) -> &str {
    let Some(rest) = detail.strip_prefix("Fetching ") else {
        return detail;
    };
    rest.split_once(": ")
        .map(|(_, message)| message)
        .unwrap_or(detail)
}

fn connection_without_rule(obs: &Observations) -> Option<&AcmeProblem> {
    let problem = obs.problems.last()?;
    if problem.short_type() != "connection" {
        return None;
    }
    let detail = without_ip_and_fetching(without_secondary_prefix(&problem.detail));
    is_connection_error_without_rule(detail).then_some(problem)
}

fn is_connection_error_without_rule(detail: &str) -> bool {
    const PHRASES: &[&str] = &[
        "Network unreachable",
        "Connection reset by peer",
        "Timeout after connect (your server may be slow or overloaded)",
    ];
    PHRASES.iter().any(|phrase| detail.contains(phrase)) || timeout_during_other_operation(detail)
}

/// Boulder va/va.go r.426. `connect` already has its own code (r.424).
fn timeout_during_other_operation(detail: &str) -> bool {
    const HEAD: &str = "Timeout during ";
    const TAIL: &str = " (your server may be slow or overloaded)";
    let Some(at) = detail.find(HEAD) else {
        return false;
    };
    let after = &detail[at + HEAD.len()..];
    let Some(operation_len) = after.find(TAIL) else {
        return false;
    };
    let operation = &after[..operation_len];
    !operation.is_empty() && operation != "connect" && !operation.chars().any(char::is_whitespace)
}

fn validation_evidence(problem: &AcmeProblem, code: Code) -> Vec<Evidence> {
    let mut evidence = vec![Evidence {
        source: EvidenceSource::Log,
        text: format!("line {}: {}", problem.line, problem.detail),
    }];
    if problem.attempts() > 1 {
        evidence.push(Evidence {
            source: EvidenceSource::Log,
            text: format!(
                "{} attempts in this log (ACME response and Certbot summary of one attempt count as one), first on line {}",
                problem.attempts(),
                problem.first_line
            ),
        });
    }
    if code == Code::Layer2RateLimit {
        if let Some(text) = retry_after_text(&problem.detail) {
            evidence.push(Evidence {
                source: EvidenceSource::Log,
                text,
            });
        }
    }
    evidence
}

/// Boulder puts the retry-after time before ": see". The clock itself (08:14:02) also contains ':'.
fn retry_after_text(detail: &str) -> Option<String> {
    let rest = detail.split_once("retry after ")?.1;
    let end = rest
        .char_indices()
        .find(|&(index, ch)| ch == ':' && !colon_inside_clock(rest, index))
        .map(|(index, _)| index)
        .unwrap_or(rest.len());
    let time = rest[..end].trim();
    if time.is_empty() {
        None
    } else {
        Some(format!("retry after {time}"))
    }
}

fn colon_inside_clock(text: &str, index: usize) -> bool {
    let before = text[..index].chars().next_back();
    let after = text[index + 1..].chars().next();
    matches!(
        (before, after),
        (Some(left), Some(right)) if left.is_ascii_digit() && right.is_ascii_digit()
    )
}

fn no_reload(obs: &Observations) -> Option<Finding> {
    let disk = obs.disk_not_after?;
    let live = obs.live_not_after?;
    if disk <= live {
        return None;
    }
    Some(Finding::new(
        Code::Layer3NoReload,
        Confidence::High,
        vec![
            Evidence {
                source: EvidenceSource::Disk,
                text: disk.to_string(),
            },
            Evidence {
                source: EvidenceSource::Handshake,
                text: live.to_string(),
            },
        ],
    ))
}

/// `disk`/`live` notAfter, days until `disk` and the `OK_NOT_DUE` threshold,
/// once every `OK_NOT_DUE` condition other than the days threshold holds.
/// Shared by `ok_not_due` and `insufficient`, so a near-renewal certificate
/// that fails only the days check still gets its known date shown instead of
/// a bare "no log given".
fn ok_not_due_candidate(obs: &Observations) -> Option<(CertTime, CertTime, i64, i64)> {
    if obs.log_has_replacement_char {
        return None;
    }
    if snap_install_note(obs).is_some() || snap_only_note(obs).is_some() {
        return None;
    }
    if obs
        .service
        .as_ref()
        .is_some_and(|service| service.active_state == "failed")
    {
        return None;
    }
    let disk = obs.disk_not_after?;
    let live = obs.live_not_after?;
    if disk != live || !obs.problems.is_empty() {
        return None;
    }
    // A not-yet-valid certificate (clock skew, or a misdeployed cert) is not
    // OK_NOT_DUE even when notAfter is comfortably far away.
    if obs
        .disk_not_before
        .is_some_and(|not_before| obs.now < not_before)
    {
        return None;
    }
    if let Some(timer) = &obs.timer {
        if timer.load_state != "loaded"
            || timer.unit_file_state != "enabled"
            || timer.active_state != "active"
        {
            return None;
        }
    }
    let threshold = not_due_threshold(obs.disk_not_before, disk);
    let days = disk.days_until(&obs.now);
    Some((disk, live, days, threshold))
}

fn ok_not_due(obs: &Observations) -> Option<Finding> {
    let (disk, live, days, threshold) = ok_not_due_candidate(obs)?;
    if days <= threshold {
        return None;
    }
    let mut evidence = vec![
        Evidence {
            source: EvidenceSource::Disk,
            text: disk.to_string(),
        },
        Evidence {
            source: EvidenceSource::Handshake,
            text: live.to_string(),
        },
    ];
    if let Some(timer) = &obs.timer {
        evidence.push(timer_line(&format!("Id={}", timer.id)));
        evidence.push(timer_line(&format!("LoadState={}", timer.load_state)));
        evidence.push(timer_line(&format!("ActiveState={}", timer.active_state)));
        evidence.push(timer_line(&format!(
            "UnitFileState={}",
            timer.unit_file_state
        )));
    }
    Some(Finding::new(Code::OkNotDue, Confidence::High, evidence))
}

/// `masked` when LoadState=masked or UnitFileState=masked, otherwise `disabled`.
fn off_state_word(timer: &TimerStatus) -> Option<&'static str> {
    if timer.load_state == "masked" {
        return Some("masked");
    }
    if timer.load_state != "loaded" {
        return None;
    }
    match timer.unit_file_state.as_str() {
        "masked" => Some("masked"),
        "disabled" => Some("disabled"),
        _ => None,
    }
}

fn snap_install_note(obs: &Observations) -> Option<String> {
    let snap = obs.snap_timer.as_ref()?;
    if snap.load_state != "loaded" || snap.active_state != "active" {
        return None;
    }
    match obs.timer.as_ref().and_then(off_state_word) {
        Some(state) => Some(format!(
            "snap.certbot.renew.timer is active and certbot.timer is {state}: snap install, not supported yet"
        )),
        None if obs.timer.is_none() => Some(
            "snap.certbot.renew.timer is active: snap install, not supported yet".to_string(),
        ),
        None => None,
    }
}

/// The only timer in the status is `snap.certbot.renew.timer`, and it is not
/// loaded and active. That is not a healthy renewal. A real `certbot.timer`
/// beside it is left to the timer rules.
fn snap_only_note(obs: &Observations) -> Option<String> {
    if obs.timer.is_some() {
        return None;
    }
    let snap = obs.snap_timer.as_ref()?;
    if snap.load_state == "loaded" && snap.active_state == "active" {
        return None;
    }
    Some(format!(
        "snap.certbot.renew.timer is not a running renewal timer (LoadState={}, ActiveState={}, UnitFileState={})",
        snap.load_state, snap.active_state, snap.unit_file_state
    ))
}

fn failed_service_note(service: &TimerStatus) -> String {
    format!(
        "{} failed (Result={}){}",
        service.id, service.result, FAILED_SERVICE_NOTE_SUFFIX
    )
}

/// A code with a layer is a diagnosis. `OK_NOT_DUE` is not added beside one.
fn counts_as_diagnosis(code: Code) -> bool {
    code.layer().is_some()
}

/// Keep the failed-service evidence on the first real diagnosis.
/// `findings` is `obs.read_errors` followed by whatever `analyze` diagnosed.
/// `insufficient` already adds the same line, so it is not added twice.
/// When `obs.read_errors` is not empty and nothing was diagnosed, `analyze`
/// never adds an `insufficient` finding (the read errors already make
/// `findings` non-empty), so there is no finding at all past the read
/// errors to attach to; a dedicated finding carries the note instead of
/// losing it.
fn attach_failed_service(obs: &Observations, findings: &mut Vec<Finding>) {
    let Some(service) = obs.service.as_ref() else {
        return;
    };
    if service.active_state != "failed" {
        return;
    }
    let text = failed_service_note(service);
    if findings
        .iter()
        .any(|finding| finding.evidence.iter().any(|item| item.text == text))
    {
        return;
    }
    // Skip the read errors so the note lands on the actual diagnosis.
    match findings.get_mut(obs.read_errors.len()) {
        Some(target) => target.evidence.push(Evidence {
            source: EvidenceSource::Timer,
            text,
        }),
        None => findings.push(Finding::new(
            Code::InsufficientEvidence,
            Confidence::Low,
            vec![Evidence {
                source: EvidenceSource::Timer,
                text,
            }],
        )),
    }
}

fn insufficient(obs: &Observations) -> Finding {
    let mut evidence = Vec::new();
    if let Some(text) = snap_install_note(obs) {
        evidence.push(note(EvidenceSource::Timer, &text));
    } else if let Some(text) = snap_only_note(obs) {
        evidence.push(note(EvidenceSource::Timer, &text));
    } else if obs.timer.is_none() {
        if let Some(service) = obs.service.as_ref() {
            evidence.push(note(
                EvidenceSource::Timer,
                &format!("no .timer block in the timer status (only {})", service.id),
            ));
        } else {
            evidence.push(note(EvidenceSource::Timer, "no timer status"));
        }
    }
    if obs.problems.is_empty() {
        if obs.log_read {
            evidence.push(note(EvidenceSource::Log, "log read, no ACME errors found"));
        } else {
            evidence.push(note(EvidenceSource::Log, "no log given"));
        }
    }
    if obs.disk_not_after.is_none() {
        evidence.push(note(EvidenceSource::Disk, "no disk notAfter"));
    }
    if obs.live_not_after.is_none() {
        evidence.push(note(EvidenceSource::Handshake, "no live notAfter"));
    }
    // The dates are known, and every OK_NOT_DUE condition holds except the
    // days threshold: show the known notAfter date and how close it is,
    // instead of leaving the evidence silent about it.
    if let Some((disk, _live, days, threshold)) = ok_not_due_candidate(obs) {
        if days <= threshold {
            evidence.push(note(
                EvidenceSource::Disk,
                &format!("{disk}, {days} day(s) remain, at or under the {threshold}-day renewal threshold"),
            ));
        }
    }
    if !obs.problems.is_empty() {
        if let Some(problem) = connection_without_rule(obs) {
            evidence.push(note(
                EvidenceSource::Log,
                "recognised connection error without a dedicated rule",
            ));
            evidence.push(note(
                EvidenceSource::Log,
                &format!("line {}: {}", problem.line, problem.detail),
            ));
        } else {
            evidence.push(note(
                EvidenceSource::Log,
                "ACME errors in log not recognised by the current rules",
            ));
        }
    }
    if let Some(service) = obs.service.as_ref() {
        if service.active_state == "failed" {
            evidence.push(note(EvidenceSource::Timer, &failed_service_note(service)));
        }
    }
    Finding::new(Code::InsufficientEvidence, Confidence::Low, evidence)
}

fn timer_line(text: &str) -> Evidence {
    Evidence {
        source: EvidenceSource::Timer,
        text: text.to_string(),
    }
}

fn note(source: EvidenceSource, text: &str) -> Evidence {
    Evidence {
        source,
        text: text.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certtime::from_unix_seconds;

    fn timer(load: &str, active: &str, unit_file: &str, result: &str) -> TimerStatus {
        TimerStatus {
            id: "certbot.timer".to_string(),
            load_state: load.to_string(),
            active_state: active.to_string(),
            sub_state: "waiting".to_string(),
            unit_file_state: unit_file.to_string(),
            result: result.to_string(),
            condition_result: "yes".to_string(),
        }
    }

    fn bare_observations() -> Observations {
        Observations {
            timer: None,
            service: None,
            snap_timer: None,
            problems: Vec::new(),
            disk_not_after: None,
            live_not_after: None,
            disk_not_before: None,
            now: from_unix_seconds(1_791_273_600),
            read_errors: Vec::new(),
            log_read: false,
            log_has_replacement_char: false,
        }
    }

    #[test]
    fn timer_not_firing_ignores_a_disabled_unit_file_state() {
        // This guard is normally unreachable through `timer_code` (which
        // tries `timer_disabled` first), so call it directly with a
        // disabled/failed combination that would otherwise read as a
        // not-firing timer.
        let mut status = timer("loaded", "failed", "disabled", "exit-code");
        status.id = "certbot.timer".to_string();
        assert!(timer_not_firing(&bare_observations_with_timer(status)).is_none());
    }

    fn bare_observations_with_timer(status: TimerStatus) -> Observations {
        let mut obs = bare_observations();
        obs.timer = Some(status);
        obs
    }

    #[test]
    fn timer_not_firing_treats_an_empty_result_as_not_a_failure() {
        let status = timer("loaded", "active", "enabled", "");
        assert!(
            timer_not_firing(&bare_observations_with_timer(status)).is_none(),
            "an active timer with no Result= value must not be flagged"
        );
    }

    #[test]
    fn is_ip_address_accepts_ipv4_and_ipv6_forms_only() {
        assert!(is_ip_address("192.0.2.1"));
        assert!(is_ip_address("fe80::1"));
        assert!(is_ip_address("::ffff:192.0.2.1"));
        assert!(!is_ip_address("."));
        assert!(!is_ip_address("12345"));
        assert!(!is_ip_address("hello"));
        assert!(!is_ip_address(""));
    }

    #[test]
    fn timeout_during_other_operation_excludes_connect_and_whitespace() {
        assert!(!timeout_during_other_operation(
            "Timeout during connect (your server may be slow or overloaded)"
        ));
        assert!(timeout_during_other_operation(
            "Timeout during fetch (your server may be slow or overloaded)"
        ));
        assert!(!timeout_during_other_operation(
            "Timeout during  (your server may be slow or overloaded)"
        ));
        assert!(!timeout_during_other_operation(
            "Timeout during foo bar (your server may be slow or overloaded)"
        ));
    }

    #[test]
    fn colon_inside_clock_looks_after_the_colon_not_before_it() {
        assert!(colon_inside_clock("12:34", 2));
        assert!(
            !colon_inside_clock("a1:b", 2),
            "the digit before the colon must not be reused as the digit after it"
        );
    }

    #[test]
    fn ok_not_due_requires_every_timer_field_not_only_one_mismatch() {
        let now = from_unix_seconds(1_791_273_600);
        let later = from_unix_seconds(1_791_273_600 + 100 * 86_400);
        let mut obs = bare_observations();
        obs.now = now;
        obs.disk_not_after = Some(later);
        obs.live_not_after = Some(later);
        obs.timer = Some(timer("masked", "active", "enabled", "success"));
        assert!(
            ok_not_due(&obs).is_none(),
            "a masked timer must not count as ok-not-due even when unit_file_state and active_state look right"
        );
    }

    #[test]
    fn not_due_threshold_is_one_third_of_the_known_lifetime() {
        let not_before = from_unix_seconds(0);
        let ninety_days = from_unix_seconds(90 * 86_400);
        assert_eq!(not_due_threshold(Some(not_before), ninety_days), 30);
        let six_days = from_unix_seconds(6 * 86_400);
        assert_eq!(not_due_threshold(Some(not_before), six_days), 2);
    }

    #[test]
    fn not_due_threshold_is_capped_at_the_fixed_days_for_an_implausibly_long_lifetime() {
        // No publicly trusted certificate is longer-lived than 90 days; a
        // notBefore implying a much longer lifetime (a placeholder value or
        // a malformed date) must not relax OK_NOT_DUE beyond the old fixed
        // threshold.
        let not_before = from_unix_seconds(0);
        let nine_years = from_unix_seconds(9 * 365 * 86_400);
        assert_eq!(
            not_due_threshold(Some(not_before), nine_years),
            NOT_DUE_DAYS
        );
    }

    #[test]
    fn not_due_threshold_falls_back_to_the_fixed_days_without_a_usable_lifetime() {
        let not_after = from_unix_seconds(90 * 86_400);
        assert_eq!(not_due_threshold(None, not_after), NOT_DUE_DAYS);
        // notBefore not earlier than notAfter: a broken or swapped pair, not a lifetime.
        assert_eq!(not_due_threshold(Some(not_after), not_after), NOT_DUE_DAYS);
        let later_than_not_after = from_unix_seconds(91 * 86_400);
        assert_eq!(
            not_due_threshold(Some(later_than_not_after), not_after),
            NOT_DUE_DAYS
        );
    }

    #[test]
    fn ok_not_due_scales_to_a_short_lived_certificate() {
        let not_before = from_unix_seconds(0);
        let not_after = from_unix_seconds(6 * 86_400);
        let mut obs = bare_observations();
        obs.disk_not_after = Some(not_after);
        obs.live_not_after = Some(not_after);
        obs.disk_not_before = Some(not_before);

        // 5 days remain out of 6: healthy, well inside the first two thirds.
        // The old fixed 30-day threshold could never recognise this: a
        // 6-day certificate never has more than 30 days remaining.
        obs.now = from_unix_seconds(86_400);
        assert!(
            ok_not_due(&obs).is_some(),
            "a freshly issued short-lived certificate must be OK_NOT_DUE"
        );

        // 1 day remains out of 6: inside the last third, due for renewal.
        obs.now = from_unix_seconds(5 * 86_400);
        assert!(
            ok_not_due(&obs).is_none(),
            "a short-lived certificate in its last third must not be OK_NOT_DUE"
        );
    }

    #[test]
    fn ok_not_due_rejects_a_not_yet_valid_certificate() {
        // notBefore is after now (clock skew, or a misdeployed certificate),
        // even though notAfter is comfortably far away.
        let not_before = from_unix_seconds(100 * 86_400);
        let not_after = from_unix_seconds(190 * 86_400);
        let mut obs = bare_observations();
        obs.now = from_unix_seconds(50 * 86_400);
        obs.disk_not_after = Some(not_after);
        obs.live_not_after = Some(not_after);
        obs.disk_not_before = Some(not_before);
        assert!(
            ok_not_due(&obs).is_none(),
            "a not-yet-valid certificate must not be OK_NOT_DUE"
        );
    }

    #[test]
    fn off_state_word_reports_a_masked_unit_file_state() {
        let status = timer("loaded", "inactive", "masked", "success");
        assert_eq!(off_state_word(&status), Some("masked"));
        let disabled = timer("loaded", "inactive", "disabled", "success");
        assert_eq!(off_state_word(&disabled), Some("disabled"));
        assert_eq!(off_state_word(&timer("masked", "", "", "")), Some("masked"));
    }

    #[test]
    fn snap_install_note_requires_the_snap_timer_to_be_active() {
        let mut obs = bare_observations();
        obs.snap_timer = Some(timer("loaded", "inactive", "enabled", "success"));
        assert!(
            snap_install_note(&obs).is_none(),
            "a loaded but inactive snap timer is not an active snap install"
        );
        obs.snap_timer = Some(timer("loaded", "active", "enabled", "success"));
        assert!(snap_install_note(&obs).is_some());
    }

    #[test]
    fn snap_only_note_is_silent_for_a_healthy_running_snap_timer() {
        let mut obs = bare_observations();
        obs.snap_timer = Some(timer("loaded", "active", "enabled", "success"));
        assert!(
            snap_only_note(&obs).is_none(),
            "an active, loaded snap timer must not be reported as not running"
        );
        obs.snap_timer = Some(timer("loaded", "inactive", "disabled", "success"));
        assert!(snap_only_note(&obs).is_some());
    }

    #[test]
    fn insufficient_shows_the_known_date_when_only_the_days_threshold_blocked_ok_not_due() {
        let not_before = from_unix_seconds(0);
        let not_after = from_unix_seconds(90 * 86_400);
        let mut obs = bare_observations();
        obs.disk_not_after = Some(not_after);
        obs.live_not_after = Some(not_after);
        obs.disk_not_before = Some(not_before);
        obs.timer = Some(timer("loaded", "active", "enabled", "success"));
        // 20 days remain out of 90: inside the last third (threshold 30), so
        // not OK_NOT_DUE, but every other OK_NOT_DUE condition holds.
        obs.now = from_unix_seconds(70 * 86_400);
        assert!(ok_not_due(&obs).is_none());

        let finding = insufficient(&obs);
        assert!(
            finding
                .evidence
                .iter()
                .any(|item| item.source == EvidenceSource::Disk
                    && item.text.contains("notAfter=")
                    && item.text.contains("20 day(s) remain")
                    && item.text.contains("30-day renewal threshold")),
            "{:?}",
            finding.evidence
        );
        // Neither "no disk notAfter" nor "no live notAfter" applies: both are known.
        assert!(!finding
            .evidence
            .iter()
            .any(|item| item.text == "no disk notAfter" || item.text == "no live notAfter"));
    }

    #[test]
    fn insufficient_does_not_show_a_date_when_the_block_is_not_the_days_threshold() {
        // disk and live disagree: OK_NOT_DUE fails for a different reason,
        // so the near-renewal date note must not appear.
        let mut obs = bare_observations();
        obs.disk_not_after = Some(from_unix_seconds(90 * 86_400));
        obs.live_not_after = Some(from_unix_seconds(91 * 86_400));
        let finding = insufficient(&obs);
        assert!(
            !finding
                .evidence
                .iter()
                .any(|item| item.text.contains("day(s) remain")),
            "{:?}",
            finding.evidence
        );
    }

    #[test]
    fn insufficient_adds_the_failed_note_only_for_a_failed_service() {
        let mut obs = bare_observations();
        obs.service = Some(timer("loaded", "failed", "enabled", "exit-code"));
        let finding = insufficient(&obs);
        assert!(
            finding
                .evidence
                .iter()
                .any(|item| item.text.contains("failed (Result=exit-code)")),
            "{:?}",
            finding.evidence
        );

        let mut healthy = bare_observations();
        healthy.service = Some(timer("loaded", "active", "enabled", "success"));
        let finding = insufficient(&healthy);
        assert!(
            finding
                .evidence
                .iter()
                .all(|item| !item.text.contains("failed (Result=")),
            "{:?}",
            finding.evidence
        );
    }

    #[test]
    fn every_code_with_a_layer_counts_as_a_diagnosis() {
        // The old hand-maintained list omitted these layer codes. Each one
        // still names a layer, so it counts as a diagnosis.
        let omitted = [
            Code::Layer1Permission,
            Code::Layer2Http01404Webroot,
            Code::Layer2Http01Redirect,
            Code::Layer2Dns01Credentials,
            Code::Layer3CopiedPath,
        ];
        let codes = [
            Code::OkNotDue,
            Code::Layer1TimerDisabled,
            Code::Layer1TimerNotFiring,
            Code::Layer1Permission,
            Code::Layer2Http01Timeout,
            Code::Layer2Http01Refused,
            Code::Layer2Http01404Webroot,
            Code::Layer2Http01Redirect,
            Code::Layer2Dns01Txt,
            Code::Layer2Dns01Credentials,
            Code::Layer2RateLimit,
            Code::Layer3NoReload,
            Code::Layer3CopiedPath,
            Code::ClientUnknown,
            Code::InsufficientEvidence,
            Code::DangerousForceBlocked,
        ];
        assert_eq!(codes.len(), 16, "every Code variant belongs in this test");
        for code in codes {
            assert_eq!(
                counts_as_diagnosis(code),
                code.layer().is_some(),
                "{code:?}"
            );
        }
        for code in omitted {
            assert!(code.layer().is_some(), "{code:?}");
            assert!(
                counts_as_diagnosis(code),
                "{code:?} has a layer and must count as a diagnosis"
            );
        }
        for code in [
            Code::OkNotDue,
            Code::ClientUnknown,
            Code::InsufficientEvidence,
            Code::DangerousForceBlocked,
        ] {
            assert!(!counts_as_diagnosis(code), "{code:?}");
        }
    }
}
