//! Finding codes, the evidence quoted under them, and the report.

use std::path::PathBuf;

/// Where a finding sits. The report prints `scheduler`, `validation` or `deployment`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    /// The renewal timer. Printed as `scheduler`.
    Scheduler,
    /// ACME validation. Printed as `validation`.
    Validation,
    /// Disk and live certificate dates. Printed as `deployment`.
    Deployment,
}

/// How sure a finding is. The report prints `low`, `medium` or `high`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    /// Printed as `low`.
    Low,
    /// Printed as `medium`.
    Medium,
    /// Printed as `high`.
    High,
}

/// Which saved input a line of evidence came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceSource {
    /// `--from-log`. The report labels this `log`.
    Log,
    /// `--from-timer-status`. The report labels this `timer`.
    Timer,
    /// `--from-cert-disk`. The report labels this `disk`.
    Disk,
    /// `--from-cert-live`, the saved live certificate date. The report labels this `handshake`.
    Handshake,
    /// A note produced by this tool, including a check the anti-force gate dropped.
    /// The report labels this `probe`.
    Probe,
}

/// One evidence line and the input it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    /// Which saved input this line came from.
    pub source: EvidenceSource,
    /// Text quoted in the report.
    pub text: String,
}

/// Stable finding code. [`Code::as_str`] is the name printed in the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    /// Disk and live notAfter match and enough days remain. Printed as `OK_NOT_DUE`. No layer.
    OkNotDue,
    /// Timer is masked, or loaded with UnitFileState `disabled` or `masked`.
    /// Printed as `LAYER1_TIMER_DISABLED`. Layer: scheduler.
    Layer1TimerDisabled,
    /// Timer is loaded, not disabled and not masked, and it is not active or
    /// Result is set and is not `success`. Printed as `LAYER1_TIMER_NOT_FIRING`.
    /// Layer: scheduler.
    Layer1TimerNotFiring,
    /// Printed as `LAYER1_PERMISSION`. Layer: scheduler. [`crate::rules::analyze`] does not return it.
    Layer1Permission,
    /// ACME type `connection`, with `/.well-known/acme-challenge/` and `Timeout during connect` in the detail.
    /// Printed as `LAYER2_HTTP01_TIMEOUT`. Layer: validation.
    Layer2Http01Timeout,
    /// ACME type `connection`, with `/.well-known/acme-challenge/` and `Connection refused` in the detail.
    /// Printed as `LAYER2_HTTP01_REFUSED`. Layer: validation.
    Layer2Http01Refused,
    /// Printed as `LAYER2_HTTP01_404_WEBROOT`. Layer: validation. [`crate::rules::analyze`] does not return it.
    Layer2Http01404Webroot,
    /// Printed as `LAYER2_HTTP01_REDIRECT`. Layer: validation. [`crate::rules::analyze`] does not return it.
    Layer2Http01Redirect,
    /// ACME TXT failure for `_acme-challenge`. Printed as `LAYER2_DNS01_TXT`. Layer: validation.
    Layer2Dns01Txt,
    /// Printed as `LAYER2_DNS01_CREDENTIALS`. Layer: validation. [`crate::rules::analyze`] does not return it.
    Layer2Dns01Credentials,
    /// ACME type `rateLimited`. Printed as `LAYER2_RATE_LIMIT`. Layer: validation.
    Layer2RateLimit,
    /// Disk notAfter is later than live notAfter. Printed as `LAYER3_NO_RELOAD`. Layer: deployment.
    Layer3NoReload,
    /// Printed as `LAYER3_COPIED_PATH`. Layer: deployment. [`crate::rules::analyze`] does not return it.
    Layer3CopiedPath,
    /// `--client auto` and the file has no Certbot log line. Printed as `CLIENT_UNKNOWN`. No layer.
    ClientUnknown,
    /// No layer code and no `OK_NOT_DUE`. Printed as `INSUFFICIENT_EVIDENCE`. No layer.
    InsufficientEvidence,
    /// The anti-force gate dropped a suggested check. Printed as `DANGEROUS_FORCE_BLOCKED`. No layer.
    DangerousForceBlocked,
}

impl Code {
    /// Name printed in the report, such as `OK_NOT_DUE`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Code::OkNotDue => "OK_NOT_DUE",
            Code::Layer1TimerDisabled => "LAYER1_TIMER_DISABLED",
            Code::Layer1TimerNotFiring => "LAYER1_TIMER_NOT_FIRING",
            Code::Layer1Permission => "LAYER1_PERMISSION",
            Code::Layer2Http01Timeout => "LAYER2_HTTP01_TIMEOUT",
            Code::Layer2Http01Refused => "LAYER2_HTTP01_REFUSED",
            Code::Layer2Http01404Webroot => "LAYER2_HTTP01_404_WEBROOT",
            Code::Layer2Http01Redirect => "LAYER2_HTTP01_REDIRECT",
            Code::Layer2Dns01Txt => "LAYER2_DNS01_TXT",
            Code::Layer2Dns01Credentials => "LAYER2_DNS01_CREDENTIALS",
            Code::Layer2RateLimit => "LAYER2_RATE_LIMIT",
            Code::Layer3NoReload => "LAYER3_NO_RELOAD",
            Code::Layer3CopiedPath => "LAYER3_COPIED_PATH",
            Code::ClientUnknown => "CLIENT_UNKNOWN",
            Code::InsufficientEvidence => "INSUFFICIENT_EVIDENCE",
            Code::DangerousForceBlocked => "DANGEROUS_FORCE_BLOCKED",
        }
    }

    /// Scheduler, validation or deployment, or `None` when the code has no layer.
    pub fn layer(&self) -> Option<Layer> {
        match self {
            Code::Layer1TimerDisabled | Code::Layer1TimerNotFiring | Code::Layer1Permission => {
                Some(Layer::Scheduler)
            }
            Code::Layer2Http01Timeout
            | Code::Layer2Http01Refused
            | Code::Layer2Http01404Webroot
            | Code::Layer2Http01Redirect
            | Code::Layer2Dns01Txt
            | Code::Layer2Dns01Credentials
            | Code::Layer2RateLimit => Some(Layer::Validation),
            Code::Layer3NoReload | Code::Layer3CopiedPath => Some(Layer::Deployment),
            Code::OkNotDue
            | Code::ClientUnknown
            | Code::InsufficientEvidence
            | Code::DangerousForceBlocked => None,
        }
    }
}

/// One finding: a code, its layer, a confidence and the evidence lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Finding code.
    pub code: Code,
    /// [`Code::layer`] of [`Finding::code`].
    pub layer: Option<Layer>,
    /// How sure this finding is.
    pub confidence: Confidence,
    /// Lines quoted under the code.
    pub evidence: Vec<Evidence>,
}

impl Finding {
    /// A finding whose layer is [`Code::layer`] of `code`.
    pub fn new(code: Code, confidence: Confidence, evidence: Vec<Evidence>) -> Finding {
        Finding {
            layer: code.layer(),
            code,
            confidence,
            evidence,
        }
    }
}

/// ACME client the caller named with `--client`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientKind {
    /// `--client certbot`. The log is parsed as Certbot.
    Certbot,
    /// `--client acme.sh`. The log is not parsed as Certbot.
    AcmeSh,
    /// `--client auto`. A Certbot log line selects Certbot parsing.
    /// With no such line the finding is [`Code::ClientUnknown`].
    Auto,
}

/// The paths the user passes with --from-*.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// Positional domain, when the caller passed one.
    pub domain: Option<String>,
    /// `--all`. With no domain to show, the text report's target is `all`.
    pub all: bool,
    /// `--client`.
    pub client: ClientKind,
    /// `--from-log`.
    pub from_log: Option<PathBuf>,
    /// `--from-timer-status`.
    pub from_timer_status: Option<PathBuf>,
    /// `--from-cert-disk`.
    pub from_cert_disk: Option<PathBuf>,
    /// `--from-cert-live`.
    pub from_cert_live: Option<PathBuf>,
}

/// Exit selected from a [`Report`]'s findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    /// Exit 0. An `OK_NOT_DUE` finding is present, and every finding other than
    /// `DANGEROUS_FORCE_BLOCKED` is `OK_NOT_DUE`.
    Ok,
    /// Exit 1. Some finding has a layer.
    Problem,
    /// Exit 2. The report is not ok and names no layer.
    InsufficientEvidence,
    /// Exit 3. Some finding is `CLIENT_UNKNOWN`.
    Usage,
}

impl ExitStatus {
    /// `0`, `1`, `2` or `3`.
    pub fn code(self) -> i32 {
        match self {
            ExitStatus::Ok => 0,
            ExitStatus::Problem => 1,
            ExitStatus::InsufficientEvidence => 2,
            ExitStatus::Usage => 3,
        }
    }
}

/// Findings for one set of saved inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// Inputs the caller passed.
    pub snapshot: Snapshot,
    /// Findings, in report order.
    pub findings: Vec<Finding>,
    /// Invalid UTF-8 bytes in `--from-log` replaced with U+FFFD. Zero when none were.
    pub replaced_invalid_utf8_bytes: usize,
}

impl Report {
    /// Exit for these findings.
    ///
    /// `CLIENT_UNKNOWN` is exit 3. Otherwise a finding with a layer is exit 1.
    /// Otherwise `OK_NOT_DUE`, ignoring `DANGEROUS_FORCE_BLOCKED`, is exit 0.
    /// Every other report is exit 2.
    pub fn exit_status(&self) -> ExitStatus {
        if self
            .findings
            .iter()
            .any(|finding| finding.code == Code::ClientUnknown)
        {
            return ExitStatus::Usage;
        }

        if self
            .findings
            .iter()
            .any(|finding| finding.code.layer().is_some())
        {
            return ExitStatus::Problem;
        }

        let has_ok_not_due = self
            .findings
            .iter()
            .any(|finding| finding.code == Code::OkNotDue);
        let counted_are_ok_not_due = self
            .findings
            .iter()
            .filter(|finding| finding.code != Code::DangerousForceBlocked)
            .all(|finding| finding.code == Code::OkNotDue);
        if has_ok_not_due && counted_are_ok_not_due {
            return ExitStatus::Ok;
        }

        ExitStatus::InsufficientEvidence
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(code: Code) -> Finding {
        Finding::new(code, Confidence::High, Vec::new())
    }

    fn report_with(codes: &[Code]) -> Report {
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
            findings: codes.iter().copied().map(finding).collect(),
            replaced_invalid_utf8_bytes: 0,
        }
    }

    #[test]
    fn exit_status_codes() {
        assert_eq!(ExitStatus::Ok.code(), 0);
        assert_eq!(ExitStatus::Problem.code(), 1);
        assert_eq!(ExitStatus::InsufficientEvidence.code(), 2);
        assert_eq!(ExitStatus::Usage.code(), 3);
    }

    #[test]
    fn report_exit_status() {
        assert_eq!(report_with(&[]).exit_status().code(), 2);
        assert_eq!(
            report_with(&[Code::InsufficientEvidence])
                .exit_status()
                .code(),
            2
        );
        assert_eq!(
            report_with(&[Code::DangerousForceBlocked])
                .exit_status()
                .code(),
            2
        );
        assert_eq!(report_with(&[Code::OkNotDue]).exit_status().code(), 0);
        assert_eq!(
            report_with(&[Code::OkNotDue, Code::DangerousForceBlocked])
                .exit_status()
                .code(),
            0
        );
        assert_eq!(
            report_with(&[Code::Layer2Http01Timeout])
                .exit_status()
                .code(),
            1
        );
        assert_eq!(
            report_with(&[Code::OkNotDue, Code::Layer3NoReload])
                .exit_status()
                .code(),
            1
        );
        assert_eq!(
            report_with(&[Code::Layer1Permission]).exit_status().code(),
            1
        );
        assert_eq!(report_with(&[Code::ClientUnknown]).exit_status().code(), 3);
        assert_eq!(
            report_with(&[Code::ClientUnknown, Code::Layer1TimerDisabled])
                .exit_status()
                .code(),
            3
        );
    }

    #[test]
    fn code_as_str_matches_the_names() {
        let expected = [
            (Code::OkNotDue, "OK_NOT_DUE"),
            (Code::Layer1TimerDisabled, "LAYER1_TIMER_DISABLED"),
            (Code::Layer1TimerNotFiring, "LAYER1_TIMER_NOT_FIRING"),
            (Code::Layer1Permission, "LAYER1_PERMISSION"),
            (Code::Layer2Http01Timeout, "LAYER2_HTTP01_TIMEOUT"),
            (Code::Layer2Http01Refused, "LAYER2_HTTP01_REFUSED"),
            (Code::Layer2Http01404Webroot, "LAYER2_HTTP01_404_WEBROOT"),
            (Code::Layer2Http01Redirect, "LAYER2_HTTP01_REDIRECT"),
            (Code::Layer2Dns01Txt, "LAYER2_DNS01_TXT"),
            (Code::Layer2Dns01Credentials, "LAYER2_DNS01_CREDENTIALS"),
            (Code::Layer2RateLimit, "LAYER2_RATE_LIMIT"),
            (Code::Layer3NoReload, "LAYER3_NO_RELOAD"),
            (Code::Layer3CopiedPath, "LAYER3_COPIED_PATH"),
            (Code::ClientUnknown, "CLIENT_UNKNOWN"),
            (Code::InsufficientEvidence, "INSUFFICIENT_EVIDENCE"),
            (Code::DangerousForceBlocked, "DANGEROUS_FORCE_BLOCKED"),
        ];
        assert_eq!(expected.len(), 16);
        for (code, text) in expected {
            assert_eq!(code.as_str(), text);
        }
    }

    #[test]
    fn code_layer_per_group() {
        assert_eq!(Code::Layer1TimerDisabled.layer(), Some(Layer::Scheduler));
        assert_eq!(Code::Layer2Http01Timeout.layer(), Some(Layer::Validation));
        assert_eq!(Code::Layer3NoReload.layer(), Some(Layer::Deployment));
        assert_eq!(Code::OkNotDue.layer(), None);
    }

    #[test]
    fn finding_new_sets_layer_from_code() {
        for code in [
            Code::OkNotDue,
            Code::Layer1TimerDisabled,
            Code::Layer2Http01Timeout,
            Code::Layer3NoReload,
            Code::ClientUnknown,
            Code::InsufficientEvidence,
            Code::DangerousForceBlocked,
        ] {
            let finding = Finding::new(code, Confidence::Medium, Vec::new());
            assert_eq!(finding.layer, code.layer());
        }
    }
}
