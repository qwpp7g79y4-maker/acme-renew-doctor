use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    Scheduler,
    Validation,
    Deployment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceSource {
    Log,
    Timer,
    Disk,
    Handshake,
    Probe,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    pub source: EvidenceSource,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    OkNotDue,
    Layer1TimerDisabled,
    Layer1TimerNotFiring,
    Layer1Permission,
    Layer2Http01Timeout,
    Layer2Http01Refused,
    Layer2Http01404Webroot,
    Layer2Http01Redirect,
    Layer2Dns01Txt,
    Layer2Dns01Credentials,
    Layer2RateLimit,
    Layer3NoReload,
    Layer3CopiedPath,
    ClientUnknown,
    InsufficientEvidence,
    DangerousForceBlocked,
}

impl Code {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub code: Code,
    pub layer: Option<Layer>,
    pub confidence: Confidence,
    pub evidence: Vec<Evidence>,
}

impl Finding {
    pub fn new(code: Code, confidence: Confidence, evidence: Vec<Evidence>) -> Finding {
        Finding {
            layer: code.layer(),
            code,
            confidence,
            evidence,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientKind {
    Certbot,
    AcmeSh,
    Auto,
}

/// The paths the user passes with --from-*.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub domain: Option<String>,
    pub all: bool,
    pub client: ClientKind,
    pub from_log: Option<PathBuf>,
    pub from_timer_status: Option<PathBuf>,
    pub from_cert_disk: Option<PathBuf>,
    pub from_cert_live: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    Ok,
    Problem,
    InsufficientEvidence,
    Usage,
}

impl ExitStatus {
    pub fn code(self) -> i32 {
        match self {
            ExitStatus::Ok => 0,
            ExitStatus::Problem => 1,
            ExitStatus::InsufficientEvidence => 2,
            ExitStatus::Usage => 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub snapshot: Snapshot,
    pub findings: Vec<Finding>,
    /// Invalid UTF-8 bytes in `--from-log` replaced with U+FFFD. Zero when none were.
    pub replaced_invalid_utf8_bytes: usize,
}

impl Report {
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
