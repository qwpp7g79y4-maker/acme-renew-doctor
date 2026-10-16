use crate::model::{Code, Confidence, Evidence, EvidenceSource, Finding, Report};
use crate::rules::FAILED_SERVICE_NOTE_SUFFIX;

pub struct SafeCheck {
    pub for_code: Code,
    pub command: String,
    pub why: String,
}

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

const FORBIDDEN_TEXT: &[&str] = &[
    "--force-renewal",
    "acme.sh --force",
    "--force",
    "certbot renew",
    "acme.sh --renew",
    "systemctl reload",
    "systemctl restart",
    "systemctl start",
    "systemctl enable",
    "nginx -s",
    "apachectl",
    "rm -",
];

pub fn check_command(cmd: &str) -> Result<(), String> {
    if let Some(reason) = forbidden_syntax(cmd) {
        return Err(reason.to_string());
    }
    if cmd.trim().is_empty() {
        return Err("empty command".to_string());
    }
    for segment in cmd.split('|') {
        allow_segment(segment.trim())?;
    }
    Ok(())
}

pub fn output_violations(text: &str) -> Vec<String> {
    let mut violations = Vec::new();
    let lower = text.to_ascii_lowercase();
    for phrase in FORBIDDEN_TEXT {
        if lower.contains(phrase) {
            violations.push(format!("forbidden text: {phrase}"));
        }
    }
    for line in text.lines() {
        let line_lower = line.to_ascii_lowercase();
        if line_lower.contains("service ")
            && (line_lower.contains("reload") || line_lower.contains("restart"))
        {
            violations.push("forbidden text: service reload/restart".to_string());
        }
        if let Some(command) = line.strip_prefix("  → ") {
            if let Err(reason) = check_command(command) {
                violations.push(format!("command rejected: {reason}"));
            }
        }
    }
    for command in json_command_values(text) {
        if let Err(reason) = check_command(&command) {
            violations.push(format!("json command rejected: {reason}"));
        }
    }
    violations
}

pub fn gate(checks: Vec<SafeCheck>) -> (Vec<SafeCheck>, usize) {
    let mut kept = Vec::new();
    let mut blocked = 0;
    for check in checks {
        if check_command(&check.command).is_ok() {
            kept.push(check);
        } else {
            blocked += 1;
        }
    }
    (kept, blocked)
}

pub fn apply_gate(report: &mut Report, checks: Vec<SafeCheck>) -> Vec<SafeCheck> {
    let (kept, blocked) = gate(checks);
    if blocked > 0 {
        report.findings.push(Finding::new(
            Code::DangerousForceBlocked,
            Confidence::High,
            vec![Evidence {
                source: EvidenceSource::Probe,
                text: format!(
                    "{blocked} suggested {} blocked by the anti-force gate",
                    if blocked == 1 { "check" } else { "checks" }
                ),
            }],
        ));
    }
    kept
}

pub fn safe_domain(domain: Option<&str>) -> Option<&str> {
    let domain = domain?;
    if domain.len() > 253 || !domain.contains('.') || domain.contains('*') {
        return None;
    }
    let mut labels = 0;
    for label in domain.split('.') {
        labels += 1;
        if label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-') {
            return None;
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return None;
        }
    }
    if labels < 2 {
        None
    } else {
        Some(domain)
    }
}

pub fn checks_for(report: &Report) -> Vec<SafeCheck> {
    let domain = safe_domain(report.snapshot.domain.as_deref()).unwrap_or("YOUR_DOMAIN");
    let mut checks = Vec::new();
    for finding in &report.findings {
        for check in catalog(finding.code, domain, &finding.evidence) {
            if checks
                .iter()
                .any(|kept: &SafeCheck| kept.command == check.command)
            {
                continue;
            }
            checks.push(check);
        }
    }
    checks
}

fn catalog(code: Code, domain: &str, evidence: &[Evidence]) -> Vec<SafeCheck> {
    let mut checks = catalog_for_code(code, domain);
    if evidence.iter().any(is_failed_service_note)
        && !checks.iter().any(|existing| {
            existing
                .command
                .starts_with("journalctl -u certbot.service")
        })
    {
        checks.push(check(
            code,
            "journalctl -u certbot.service -n 50 --no-pager",
            "shows why the last renewal run failed",
        ));
    }
    checks
}

fn catalog_for_code(code: Code, domain: &str) -> Vec<SafeCheck> {
    match code {
        Code::Layer1TimerDisabled => vec![
            check(
                code,
                "systemctl list-timers --all certbot.timer",
                "shows whether the timer is scheduled and when it last ran",
            ),
            check(
                code,
                "systemctl is-enabled certbot.timer",
                "shows whether the timer is enabled",
            ),
            check(
                code,
                "systemctl status certbot.timer --no-pager",
                "shows whether the timer is active",
            ),
        ],
        Code::Layer1TimerNotFiring => vec![
            check(
                code,
                "systemctl list-timers --all certbot.timer",
                "shows whether the timer is scheduled and when it last ran",
            ),
            check(
                code,
                "systemctl status certbot.timer --no-pager",
                "shows whether the timer is active",
            ),
            check(
                code,
                "systemctl show certbot.timer -p ConditionResult,ConditionTimestamp,Result",
                "an unmet condition or a failed result keeps an enabled timer from firing",
            ),
            check(
                code,
                "journalctl -u certbot.timer -n 50 --no-pager",
                "recent messages about the timer",
            ),
        ],
        Code::Layer2Http01Timeout => vec![
            check(
                code,
                &format!(
                    "curl -q -sI --max-time 10 http://{domain}/.well-known/acme-challenge/acme-renew-doctor-check"
                ),
                "any HTTP answer, even 404, means port 80 answers here; a timeout points to firewall or routing",
            ),
            check(
                code,
                &format!("dig +short A {domain}"),
                "compare the A record with the public IPv4 address of this server",
            ),
            check(
                code,
                &format!("dig +short AAAA {domain}"),
                "compare with the public IP of this server; a stale AAAA record is a common cause",
            ),
            check(code, "ss -ltn", "look for a listener on port 80"),
            check(
                code,
                "sudo tail -n 200 /var/log/letsencrypt/letsencrypt.log",
                "shows recent lines from the Certbot log",
            ),
        ],
        Code::Layer2Http01Refused => vec![
            check(
                code,
                &format!(
                    "curl -q -sI --max-time 10 http://{domain}/.well-known/acme-challenge/acme-renew-doctor-check"
                ),
                "connection refused means nothing listens on port 80 here, or a firewall rejects the connection",
            ),
            check(code, "ss -ltn", "look for a listener on port 80"),
            check(
                code,
                &format!("dig +short A {domain}"),
                "compare the A record with the public IPv4 address of this server",
            ),
            check(
                code,
                &format!("dig +short AAAA {domain}"),
                "compare with the public IP of this server; a stale AAAA record is a common cause",
            ),
        ],
        Code::Layer2RateLimit => vec![check(
            code,
            "sudo tail -n 200 /var/log/letsencrypt/letsencrypt.log",
            "read the retry-after time in the error; new attempts before then fail again",
        )],
        Code::Layer2Dns01Txt => vec![
            check(
                code,
                &format!("dig +short TXT _acme-challenge.{domain}"),
                "shows the TXT records public DNS returns now; compare with the value Certbot asked for",
            ),
            check(
                code,
                &format!("dig +short NS {domain}"),
                "the TXT record must be created at the DNS provider that is authoritative for this domain",
            ),
        ],
        Code::Layer3NoReload => vec![
            check(
                code,
                &format!(
                    "sudo openssl x509 -noout -enddate -in /etc/letsencrypt/live/{domain}/fullchain.pem"
                ),
                "shows the notAfter date of the certificate file on disk",
            ),
            check(
                code,
                &format!(
                    "echo | timeout 10 openssl s_client -connect {domain}:443 -servername {domain} | openssl x509 -noout -enddate"
                ),
                "if the date on disk is newer than the live one, the web server still serves the old certificate; you decide when to reload it, Doctor never does",
            ),
        ],
        Code::ClientUnknown => vec![
            check(
                code,
                "ls -la /var/log/letsencrypt",
                "a Certbot install writes letsencrypt.log here; pass that file with --from-log",
            ),
            check(
                code,
                "sudo tail -n 400 /var/log/letsencrypt/letsencrypt.log",
                "Certbot lines start with a timestamp like 2026-09-28 03:12:44,512:DEBUG:",
            ),
            check(
                code,
                "ls -la ~/.acme.sh",
                "acme.sh keeps its files here; acme.sh logs are not parsed yet",
            ),
        ],
        Code::OkNotDue => vec![check(
            code,
            "systemctl list-timers --all certbot.timer",
            "shows whether the timer is scheduled and when it last ran",
        )],
        Code::InsufficientEvidence => vec![
            check(
                code,
                "systemctl show certbot.timer certbot.service -p Id,LoadState,ActiveState,SubState,UnitFileState,Result,ConditionResult,LastTriggerUSec,NextElapseUSecRealtime",
                "save this output yourself and pass the file with --from-timer-status",
            ),
            check(
                code,
                "sudo tail -n 400 /var/log/letsencrypt/letsencrypt.log",
                "save a copy yourself and pass it with --from-log",
            ),
            check(
                code,
                &format!(
                    "sudo openssl x509 -noout -dates -in /etc/letsencrypt/live/{domain}/fullchain.pem"
                ),
                "save this output yourself and pass the file with --from-cert-disk",
            ),
            check(
                code,
                &format!(
                    "echo | timeout 10 openssl s_client -connect {domain}:443 -servername {domain} | openssl x509 -noout -dates"
                ),
                "save this output yourself and pass the file with --from-cert-live",
            ),
        ],
        _ => Vec::new(),
    }
}

fn is_failed_service_note(item: &Evidence) -> bool {
    item.source == EvidenceSource::Timer
        && item.text.contains(" failed (Result=")
        && item.text.ends_with(FAILED_SERVICE_NOTE_SUFFIX)
}

fn check(code: Code, command: &str, why: &str) -> SafeCheck {
    SafeCheck {
        for_code: code,
        command: command.to_string(),
        why: why.to_string(),
    }
}

fn forbidden_syntax(cmd: &str) -> Option<&'static str> {
    if cmd.contains('\n') || cmd.contains('\r') {
        return Some("newline");
    }
    if cmd.contains(';') {
        return Some("semicolon");
    }
    if cmd.contains("&&") {
        return Some("&&");
    }
    if cmd.contains("||") {
        return Some("||");
    }
    if cmd.contains('`') {
        return Some("backtick");
    }
    if cmd.contains("$(") {
        return Some("command substitution");
    }
    if cmd.contains("${") {
        return Some("parameter expansion");
    }
    if cmd.contains('>') {
        return Some("redirect");
    }
    if cmd.contains('<') {
        return Some("redirect");
    }
    if cmd.contains('&') {
        return Some("background operator");
    }
    if cmd.contains('\'') || cmd.contains('"') {
        return Some("quote");
    }
    None
}

fn allow_segment(segment: &str) -> Result<(), String> {
    if segment.is_empty() {
        return Err("empty pipeline segment".to_string());
    }
    let (body, used_sudo) = if let Some(rest) = segment.strip_prefix("sudo ") {
        (rest.trim(), true)
    } else {
        (segment, false)
    };
    let tokens: Vec<&str> = body.split_whitespace().collect();
    let Some(program) = tokens.first().copied() else {
        return Err("empty pipeline segment".to_string());
    };
    if used_sudo && !sudo_target_allowed(&tokens) {
        return Err("sudo is only allowed before tail and openssl x509".to_string());
    }
    match program {
        "systemctl" => {
            let second = tokens.get(1).copied().unwrap_or("");
            if !matches!(
                second,
                "status" | "list-timers" | "is-enabled" | "is-active" | "show"
            ) {
                return Err(format!("systemctl {second} is not allowed"));
            }
        }
        "journalctl" => reject_journalctl(&tokens)?,
        "ss" => reject_ss(&tokens)?,
        "tail" => reject_tail(&tokens)?,
        "dig" | "grep" | "echo" | "ls" => {}
        "curl" => allow_curl(&tokens)?,
        "openssl" => allow_openssl(&tokens)?,
        "timeout" => allow_timeout(&tokens)?,
        other => return Err(format!("command not on the allowlist: {other}")),
    }
    if let Some(token) = tokens.iter().find(|token| is_denied(token)) {
        return Err(format!("denied word: {token}"));
    }
    Ok(())
}

fn sudo_target_allowed(tokens: &[&str]) -> bool {
    match tokens.first().copied() {
        Some("tail") => true,
        Some("openssl") => tokens.get(1) == Some(&"x509"),
        _ => false,
    }
}

fn allow_curl(tokens: &[&str]) -> Result<(), String> {
    if tokens.get(1) != Some(&"-q") {
        return Err("curl must use -q as its first argument".to_string());
    }
    if !tokens.iter().any(|token| *token == "-I" || *token == "-sI") {
        return Err("curl needs -I or -sI".to_string());
    }
    for token in tokens {
        let lower = token.to_ascii_lowercase();
        if matches!(*token, "-o" | "-O" | "-T" | "-d" | "-X" | "-F")
            || lower.starts_with("--data")
            || lower == "--upload-file"
            || lower == "--output"
        {
            return Err(format!("curl flag not allowed: {token}"));
        }
        if is_short_option(token) && token.chars().any(curl_short_forbidden) {
            return Err(format!("curl flag not allowed: {token}"));
        }
        if curl_long_forbidden(token) {
            return Err(format!("curl flag not allowed: {token}"));
        }
    }
    Ok(())
}

fn curl_short_forbidden(ch: char) -> bool {
    matches!(
        ch,
        'X' | 'o' | 'O' | 'T' | 'd' | 'F' | 'K' | 'D' | 'c' | 'J' | 'w'
    )
}

fn curl_long_forbidden(token: &str) -> bool {
    token.starts_with("--request")
        || token.starts_with("--config")
        || token.starts_with("--dump-header")
        || token.starts_with("--cookie-jar")
        || token.starts_with("--output")
        || token.starts_with("--remote-name")
        || token.starts_with("--upload-file")
        || token.starts_with("--data")
        || token.starts_with("--form")
        || token.starts_with("--json")
        || token.starts_with("--write-out")
        || token.starts_with("--trace")
        || token.starts_with("--stderr")
        || token.starts_with("--etag-save")
        || token.starts_with("--hsts")
        || token.starts_with("--alt-svc")
        || token.starts_with("--libcurl")
        || token.starts_with("--create-dirs")
}

fn allow_openssl(tokens: &[&str]) -> Result<(), String> {
    match tokens.get(1).copied() {
        Some("x509") => {
            if !tokens.contains(&"-noout") {
                return Err("openssl x509 needs -noout".to_string());
            }
            if tokens
                .iter()
                .any(|token| *token == "-out" || token.starts_with("-out"))
            {
                return Err("openssl x509 must not use -out".to_string());
            }
            Ok(())
        }
        Some("s_client") => {
            for token in tokens.iter().skip(1) {
                if s_client_writes(token) {
                    return Err(format!("openssl s_client option not allowed: {token}"));
                }
            }
            Ok(())
        }
        _ => Err("openssl only allows x509 and s_client".to_string()),
    }
}

fn s_client_writes(token: &str) -> bool {
    for flag in ["-sess_out", "-keylogfile", "-msgfile", "-writerand"] {
        if token == flag
            || token
                .strip_prefix(flag)
                .is_some_and(|rest| rest.starts_with('='))
        {
            return true;
        }
    }
    false
}

fn reject_ss(tokens: &[&str]) -> Result<(), String> {
    for token in tokens.iter().skip(1) {
        if is_short_option(token) && token.chars().any(|ch| ch == 'K' || ch == 'D') {
            return Err(format!("ss option not allowed: {token}"));
        }
        if *token == "--kill" || token.starts_with("--diag") {
            return Err(format!("ss option not allowed: {token}"));
        }
    }
    Ok(())
}

fn reject_journalctl(tokens: &[&str]) -> Result<(), String> {
    for token in tokens.iter().skip(1) {
        if is_short_option(token) && token.contains('f') {
            return Err(format!("journalctl option not allowed: {token}"));
        }
        if journalctl_long_forbidden(token) {
            return Err(format!("journalctl option not allowed: {token}"));
        }
    }
    Ok(())
}

fn journalctl_long_forbidden(token: &str) -> bool {
    token.starts_with("--vacuum")
        || token.starts_with("--rotate")
        || token.starts_with("--flush")
        || token.starts_with("--sync")
        || token.starts_with("--smart-relinquish-var")
        || token.starts_with("--relinquish-var")
        || token.starts_with("--setup-keys")
        || token.starts_with("--update-catalog")
        || token.starts_with("--cursor-file")
        || token.starts_with("--follow")
}

fn reject_tail(tokens: &[&str]) -> Result<(), String> {
    for token in tokens.iter().skip(1) {
        if is_short_option(token) && token.chars().any(|ch| ch == 'f' || ch == 'F') {
            return Err(format!("tail option not allowed: {token}"));
        }
        if token.starts_with("--follow") {
            return Err(format!("tail option not allowed: {token}"));
        }
    }
    Ok(())
}

fn allow_timeout(tokens: &[&str]) -> Result<(), String> {
    let Some(duration) = tokens.get(1).copied() else {
        return Err("timeout needs a duration".to_string());
    };
    if !timeout_duration_allowed(duration) {
        return Err(format!("timeout duration not allowed: {duration}"));
    }
    if tokens.get(2) != Some(&"openssl") || tokens.get(3) != Some(&"s_client") {
        return Err("timeout is only allowed before openssl s_client".to_string());
    }
    allow_openssl(&tokens[2..])
}

fn timeout_duration_allowed(token: &str) -> bool {
    let digits = token.strip_suffix('s').unwrap_or(token);
    if digits.is_empty() || digits.len() > 3 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    matches!(digits.parse::<u16>(), Ok(seconds) if (1..=120).contains(&seconds))
}

fn is_short_option(token: &str) -> bool {
    let Some(rest) = token.strip_prefix('-') else {
        return false;
    };
    if rest.is_empty() || rest.starts_with('-') {
        return false;
    }
    rest.chars().any(|ch| ch.is_ascii_alphabetic())
}

fn is_denied(token: &str) -> bool {
    // A short flag like "-i" is case-sensitive in real CLIs ("-I" is a
    // different flag, for example curl's HEAD request versus sed's in-place
    // edit), so it is matched exactly. Words and long flags are matched
    // without regard to ASCII case.
    DENY.iter().any(|item| {
        if is_short_option(item) {
            token == *item
        } else {
            token.eq_ignore_ascii_case(item)
        }
    })
}

fn json_command_values(text: &str) -> Vec<String> {
    let mut values = Vec::new();
    let needle = "\"command\":";
    let mut rest = text;
    while let Some(index) = rest.find(needle) {
        rest = &rest[index + needle.len()..];
        let trimmed = rest.trim_start();
        if let Some((value, _)) = crate::certbot_log::parse_json_string(trimmed, 0) {
            values.push(value);
        }
    }
    values
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ClientKind, Confidence, Evidence, EvidenceSource, Finding, Snapshot};
    use crate::render;

    const FORBIDDEN: &[&str] = &[
        "certbot renew --force-renewal",
        "sudo certbot renew --force-renewal",
        "certbot renew",
        "~/.acme.sh/acme.sh --renew -d example.com --force",
        "acme.sh --force --issue -d example.com",
        "systemctl reload nginx",
        "sudo systemctl restart nginx",
        "systemctl enable --now certbot.timer",
        "systemctl start certbot.timer",
        "nginx -s reload",
        "service nginx reload",
        "apachectl graceful",
        "curl -X POST http://example.com/",
        "curl -o /tmp/x http://example.com/",
        "curl -sI http://example.com/ -d x",
        "tail -n 5 /var/log/x > /tmp/x",
        "echo x | tee /etc/x",
        "ls; rm -rf /",
        "dig $(whoami)",
        "rm -rf /etc/letsencrypt",
        "sed -i s/a/b/ /etc/x",
        "wget http://example.com/",
        "sudo ls /root",
    ];

    fn report(code: Code, domain: Option<&str>) -> Report {
        Report {
            snapshot: Snapshot {
                domain: domain.map(str::to_string),
                all: false,
                client: ClientKind::Auto,
                from_log: None,
                from_timer_status: None,
                from_cert_disk: None,
                from_cert_live: None,
            },
            findings: vec![Finding::new(code, Confidence::High, Vec::new())],
            replaced_invalid_utf8_bytes: 0,
        }
    }

    #[test]
    fn forbidden_commands_are_rejected() {
        for command in FORBIDDEN {
            assert!(
                check_command(command).is_err(),
                "expected Err for {command}"
            );
        }
    }

    fn assert_validation_catalog(code: Code, named: &[SafeCheck], placeholder: &[SafeCheck]) {
        let expected: &[(&str, &str)] = match code {
            Code::Layer2Http01Refused => &[
                (
                    "curl -q -sI --max-time 10 http://example.com/.well-known/acme-challenge/acme-renew-doctor-check",
                    "connection refused means nothing listens on port 80 here, or a firewall rejects the connection",
                ),
                ("ss -ltn", "look for a listener on port 80"),
                (
                    "dig +short A example.com",
                    "compare the A record with the public IPv4 address of this server",
                ),
                (
                    "dig +short AAAA example.com",
                    "compare with the public IP of this server; a stale AAAA record is a common cause",
                ),
            ],
            Code::Layer2RateLimit => &[(
                "sudo tail -n 200 /var/log/letsencrypt/letsencrypt.log",
                "read the retry-after time in the error; new attempts before then fail again",
            )],
            Code::Layer1TimerNotFiring => &[
                (
                    "systemctl list-timers --all certbot.timer",
                    "shows whether the timer is scheduled and when it last ran",
                ),
                (
                    "systemctl status certbot.timer --no-pager",
                    "shows whether the timer is active",
                ),
                (
                    "systemctl show certbot.timer -p ConditionResult,ConditionTimestamp,Result",
                    "an unmet condition or a failed result keeps an enabled timer from firing",
                ),
                (
                    "journalctl -u certbot.timer -n 50 --no-pager",
                    "recent messages about the timer",
                ),
            ],
            Code::ClientUnknown => &[
                (
                    "ls -la /var/log/letsencrypt",
                    "a Certbot install writes letsencrypt.log here; pass that file with --from-log",
                ),
                (
                    "sudo tail -n 400 /var/log/letsencrypt/letsencrypt.log",
                    "Certbot lines start with a timestamp like 2026-09-28 03:12:44,512:DEBUG:",
                ),
                (
                    "ls -la ~/.acme.sh",
                    "acme.sh keeps its files here; acme.sh logs are not parsed yet",
                ),
            ],
            Code::Layer2Dns01Txt => &[
                (
                    "dig +short TXT _acme-challenge.example.com",
                    "shows the TXT records public DNS returns now; compare with the value Certbot asked for",
                ),
                (
                    "dig +short NS example.com",
                    "the TXT record must be created at the DNS provider that is authoritative for this domain",
                ),
            ],
            _ => return,
        };
        assert_eq!(named.len(), expected.len(), "{code:?}");
        assert_eq!(placeholder.len(), expected.len(), "{code:?}");
        for (check, (command, why)) in named.iter().zip(expected) {
            assert_eq!(check.command, *command, "{code:?}");
            assert_eq!(check.why, *why, "{code:?}");
        }
        for (check, (command, why)) in placeholder.iter().zip(expected) {
            let replaced = command.replace("example.com", "YOUR_DOMAIN");
            assert_eq!(check.command, replaced, "{code:?}");
            assert_eq!(check.why, *why, "{code:?}");
            assert!(
                !check.command.contains("example.com"),
                "{code:?} placeholder still names example.com: {}",
                check.command
            );
        }
    }

    fn catalog_has_checks(code: Code) -> bool {
        match code {
            Code::OkNotDue
            | Code::Layer1TimerDisabled
            | Code::Layer1TimerNotFiring
            | Code::Layer2Http01Timeout
            | Code::Layer2Http01Refused
            | Code::Layer2RateLimit
            | Code::Layer2Dns01Txt
            | Code::Layer3NoReload
            | Code::InsufficientEvidence
            | Code::ClientUnknown => true,
            Code::Layer1Permission
            | Code::Layer2Http01404Webroot
            | Code::Layer2Http01Redirect
            | Code::Layer2Dns01Credentials
            | Code::Layer3CopiedPath
            | Code::DangerousForceBlocked => false,
        }
    }

    #[test]
    fn catalog_checks_pass_for_example_com_and_placeholder() {
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
            let named = checks_for(&report(code, Some("example.com")));
            let placeholder = checks_for(&report(code, None));
            assert_eq!(catalog_has_checks(code), !named.is_empty(), "{code:?}");
            assert_eq!(named.len(), placeholder.len(), "{code:?}");
            let mut shown = String::new();
            for (named_check, placeholder_check) in named.iter().zip(&placeholder) {
                assert_eq!(
                    named_check.command.replace("example.com", "YOUR_DOMAIN"),
                    placeholder_check.command,
                    "{code:?}"
                );
                check_command(&named_check.command).unwrap_or_else(|err| {
                    panic!("{} (example.com): {err}", named_check.command);
                });
                check_command(&placeholder_check.command).unwrap_or_else(|err| {
                    panic!("{} (YOUR_DOMAIN): {err}", placeholder_check.command);
                });
                shown.push_str(&format!(
                    "  → {}\n    why: {}\n  → {}\n    why: {}\n",
                    named_check.command,
                    named_check.why,
                    placeholder_check.command,
                    placeholder_check.why
                ));
            }
            let violations = output_violations(&shown);
            assert!(violations.is_empty(), "{code:?}: {violations:?}\n{shown}");
            assert_validation_catalog(code, &named, &placeholder);
            if code == Code::InsufficientEvidence {
                assert!(named.iter().any(|check| {
                    check.command
                        == "systemctl show certbot.timer certbot.service -p Id,LoadState,ActiveState,SubState,UnitFileState,Result,ConditionResult,LastTriggerUSec,NextElapseUSecRealtime"
                        && check.why == "save this output yourself and pass the file with --from-timer-status"
                }));
                assert!(
                    named
                        .iter()
                        .all(|check| check.command
                            != "journalctl -u certbot.service -n 50 --no-pager")
                );
                assert!(named.iter().any(|check| {
                    check.command
                        == "sudo openssl x509 -noout -dates -in /etc/letsencrypt/live/example.com/fullchain.pem"
                        && check.why == "save this output yourself and pass the file with --from-cert-disk"
                }));
                assert!(named.iter().any(|check| {
                    check.command
                        == "echo | timeout 10 openssl s_client -connect example.com:443 -servername example.com | openssl x509 -noout -dates"
                        && check.why == "save this output yourself and pass the file with --from-cert-live"
                }));
            }
        }
    }

    #[test]
    fn failed_service_insufficient_adds_the_service_journal() {
        let mut report = report(Code::InsufficientEvidence, Some("example.com"));
        report.findings[0].evidence.push(Evidence {
            source: EvidenceSource::Timer,
            text: "certbot.service failed (Result=exit-code); the renewal ran and failed, check the Certbot log".to_string(),
        });
        let checks = checks_for(&report);
        let journal = checks
            .iter()
            .find(|check| check.command == "journalctl -u certbot.service -n 50 --no-pager")
            .expect("service journal");
        assert_eq!(journal.why, "shows why the last renewal run failed");
        check_command(&journal.command).expect("journalctl passes the gate");
        let shown = format!("  → {}\n    why: {}\n", journal.command, journal.why);
        assert!(output_violations(&shown).is_empty(), "{shown}");
    }

    #[test]
    fn failed_service_adds_the_service_journal_to_a_diagnosed_code_too() {
        let note = "certbot.service failed (Result=exit-code); the renewal ran and failed, check the Certbot log";
        let mut report = report(Code::Layer2RateLimit, Some("example.com"));
        report.findings[0].evidence.push(Evidence {
            source: EvidenceSource::Timer,
            text: note.to_string(),
        });
        let checks = checks_for(&report);
        let journals: Vec<_> = checks
            .iter()
            .filter(|check| check.command == "journalctl -u certbot.service -n 50 --no-pager")
            .collect();
        assert_eq!(
            journals.len(),
            1,
            "service journal suggested once for a real diagnosis, not only InsufficientEvidence"
        );
        assert_eq!(journals[0].why, "shows why the last renewal run failed");
        assert_eq!(journals[0].for_code, Code::Layer2RateLimit);

        let evidence = &report.findings[0].evidence;
        for code in [Code::Layer2RateLimit, Code::InsufficientEvidence] {
            let direct = catalog(code, "example.com", evidence);
            let count = direct
                .iter()
                .filter(|check| check.command == "journalctl -u certbot.service -n 50 --no-pager")
                .count();
            assert_eq!(
                count, 1,
                "{code:?} listed the service journal {count} times"
            );
        }
    }

    #[test]
    fn short_denylist_flags_match_exactly_and_words_ignore_case() {
        // "-i" is the denylist entry. "-I" is a different short flag (curl HEAD).
        assert!(is_denied("-i"));
        assert!(!is_denied("-I"));
        assert!(is_denied("renew"));
        assert!(is_denied("RENEW"));
        assert!(is_denied("--force"));
        assert!(is_denied("--FORCE"));
        assert!(is_denied("--now"));
        assert!(is_denied("--NOW"));

        assert!(check_command("dig +short NS example.com").is_ok());
        assert!(
            check_command("dig +short NS example.com -I").is_ok(),
            "uppercase -I is not the denylist flag -i"
        );
        let in_place = check_command("dig +short NS example.com -i").unwrap_err();
        assert!(in_place.contains("denied word: -i"), "{in_place}");
        let renew = check_command("dig +short NS example.com RENEW").unwrap_err();
        assert!(renew.contains("denied word: RENEW"), "{renew}");
        let force = check_command("dig +short NS example.com --FORCE").unwrap_err();
        assert!(force.contains("denied word: --FORCE"), "{force}");
        assert!(check_command(
            "curl -q -I http://example.com/.well-known/acme-challenge/acme-renew-doctor-check"
        )
        .is_ok());
    }

    #[test]
    fn json_command_value_reads_solidus_and_u0041() {
        let text = r#"{"command": "dig +short \u0041 http:\/\/example.com"}"#;
        assert_eq!(
            json_command_values(text),
            vec!["dig +short A http://example.com".to_string()]
        );
        let hidden = r#"{"command": "dig +short \u0041 http:\/\/example.com renew"}"#;
        let violations = output_violations(hidden);
        assert!(
            violations
                .iter()
                .any(|item| item.contains("denied word: renew")),
            "escaped command was not read: {violations:?}"
        );
    }

    #[test]
    fn output_violations_catch_forbidden_commands() {
        let human = "\
acme-renew-doctor\n\
  → sudo certbot renew --force-renewal\n\
    why: no\n";
        assert!(!output_violations(human).is_empty());
        let json = "{\"command\": \"systemctl reload nginx\"}\n";
        assert!(!output_violations(json).is_empty());
        assert!(!output_violations("see acme.sh --force here").is_empty());
    }

    #[test]
    fn gate_keeps_the_safe_check_and_blocks_the_other() {
        let checks = vec![
            SafeCheck {
                for_code: Code::Layer1TimerDisabled,
                command: "systemctl status certbot.timer --no-pager".to_string(),
                why: "shows whether the timer is active".to_string(),
            },
            SafeCheck {
                for_code: Code::Layer1TimerDisabled,
                command: "certbot renew --force-renewal".to_string(),
                why: "must not be shown".to_string(),
            },
        ];
        let (kept, blocked) = gate(checks);
        assert_eq!(kept.len(), 1);
        assert_eq!(blocked, 1);
        assert_eq!(kept[0].command, "systemctl status certbot.timer --no-pager");

        let mut report = report(Code::Layer1TimerDisabled, Some("example.com"));
        let kept = apply_gate(
            &mut report,
            vec![
                SafeCheck {
                    for_code: Code::Layer1TimerDisabled,
                    command: "systemctl status certbot.timer --no-pager".to_string(),
                    why: "shows whether the timer is active".to_string(),
                },
                SafeCheck {
                    for_code: Code::Layer1TimerDisabled,
                    command: "certbot renew --force-renewal".to_string(),
                    why: "must not be shown".to_string(),
                },
            ],
        );
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == Code::DangerousForceBlocked));
        let blocked_finding = report
            .findings
            .iter()
            .find(|finding| finding.code == Code::DangerousForceBlocked)
            .expect("blocked finding");
        assert_eq!(blocked_finding.confidence, Confidence::High);
        assert_eq!(
            blocked_finding.evidence[0].text,
            "1 suggested check blocked by the anti-force gate"
        );
        assert_eq!(blocked_finding.evidence[0].source, EvidenceSource::Probe);
        let human = render::human(&report, &kept);
        let json = render::json(&report, &kept);
        assert!(!human.contains("certbot renew"));
        assert!(!human.contains("--force-renewal"));
        assert!(!json.contains("certbot renew"));
        assert!(!json.contains("--force-renewal"));
        assert!(human.contains("DANGEROUS_FORCE_BLOCKED"));
        assert!(json.contains("DANGEROUS_FORCE_BLOCKED"));
    }

    #[test]
    fn safe_domain_accepts_plain_hostnames_only() {
        assert_eq!(safe_domain(Some("example.com")), Some("example.com"));
        assert_eq!(
            safe_domain(Some("sub.example-1.org")),
            Some("sub.example-1.org")
        );
        for rejected in [
            "example.com;rm -rf ~",
            "$(id).example.com",
            "-x.com",
            "*.example.com",
            "localhost",
            "exa mple.com",
        ] {
            assert_eq!(safe_domain(Some(rejected)), None, "{rejected}");
        }
        assert_eq!(safe_domain(None), None);
    }

    #[test]
    fn safe_domain_enforces_label_and_name_length() {
        let l63 = "a".repeat(63);
        let l64 = "a".repeat(64);
        let ok63 = format!("{l63}.com");
        assert_eq!(safe_domain(Some(&ok63)), Some(ok63.as_str()));
        let multi_ok = format!("{l63}.{l63}.{l63}.com");
        assert_eq!(safe_domain(Some(&multi_ok)), Some(multi_ok.as_str()));
        // 63+1+63+1+63+1+61 = 253 bytes: the longest accepted name.
        let max = format!("{l63}.{l63}.{l63}.{}", "b".repeat(61));
        assert_eq!(max.len(), 253);
        assert_eq!(safe_domain(Some(&max)), Some(max.as_str()));
        let over = format!("{l63}.{l63}.{l63}.{}", "b".repeat(62));
        assert_eq!(over.len(), 254);
        assert_eq!(safe_domain(Some(&over)), None);
        let punycode_ok = format!("xn--{}.example", "a".repeat(59));
        assert_eq!(safe_domain(Some(&punycode_ok)), Some(punycode_ok.as_str()));
        assert_eq!(
            safe_domain(Some("xn--bcher-kva.example")),
            Some("xn--bcher-kva.example")
        );
        assert_eq!(
            safe_domain(Some("WWW.Example.COM")),
            Some("WWW.Example.COM")
        );
        let upper_ok = format!("{}.COM", "A".repeat(63));
        assert_eq!(safe_domain(Some(&upper_ok)), Some(upper_ok.as_str()));
        for rejected in [
            format!("{l64}.com"),
            format!("www.{l64}.example.com"),
            format!("{l63}.{l64}.com"),
            format!("example.{l64}"),
            format!("{}.com", "A".repeat(64)),
            format!("xn--{}.example", "a".repeat(60)),
            format!("{}.com", "a".repeat(300)),
            format!("{l63}.com."),
            "example.com.".to_string(),
            format!("{l63}.com\n"),
            format!("{l63}.com\r"),
            format!("{l63}\t.com"),
            " example.com".to_string(),
            "bücher.example".to_string(),
            format!("{}é.com", "a".repeat(62)),
            "例え.jp".to_string(),
            "a..com".to_string(),
        ] {
            assert_eq!(safe_domain(Some(&rejected)), None, "{rejected}");
        }
        assert_eq!(safe_domain(None), None);
    }

    fn assert_rejected(commands: &[&str]) {
        for command in commands {
            assert!(
                check_command(command).is_err(),
                "expected the gate to reject {command}"
            );
        }
    }

    #[test]
    fn ss_kill_and_diag_are_rejected() {
        assert_rejected(&[
            "ss -K dst 203.0.113.10",
            "ss -tK",
            "ss -Kt",
            "ss --kill",
            "ss -D /tmp/x",
            "ss --diag=/tmp/x",
        ]);
    }

    #[test]
    fn journalctl_write_and_follow_are_rejected() {
        assert_rejected(&[
            "journalctl --vacuum-time=1s",
            "journalctl --vacuum-size=1M",
            "journalctl --vacuum-files=1",
            "journalctl --rotate",
            "journalctl --flush",
            "journalctl --sync",
            "journalctl --relinquish-var",
            "journalctl --smart-relinquish-var",
            "journalctl --setup-keys",
            "journalctl --update-catalog",
            "journalctl --cursor-file=/tmp/x",
            "journalctl -f",
            "journalctl --follow",
            "journalctl -fu certbot.service",
        ]);
    }

    #[test]
    fn curl_combined_flags_and_config_are_rejected() {
        assert_rejected(&[
            "curl -sI -XPOST https://example.com",
            "curl -sI -XDELETE https://example.com",
            "curl -sI --request POST https://example.com",
            "curl -sI --request=POST https://example.com",
            "curl -sI -K /tmp/x https://example.com",
            "curl -sI --config /tmp/x https://example.com",
            "curl -sI --config=/tmp/x https://example.com",
            "curl -sI -D /tmp/x https://example.com",
            "curl -sI --dump-header /tmp/x https://example.com",
            "curl -sI -c /tmp/x https://example.com",
            "curl -sI --cookie-jar /tmp/x https://example.com",
            "curl -sIo /tmp/x https://example.com",
            "curl -sI --remote-name https://example.com/x",
            "curl -sI --json {} https://example.com",
        ]);
    }

    #[test]
    fn tail_follow_is_rejected() {
        assert_rejected(&[
            "tail -f /var/log/letsencrypt/letsencrypt.log",
            "tail -F /var/log/letsencrypt/letsencrypt.log",
            "tail -fn 50 /var/log/letsencrypt/letsencrypt.log",
            "tail --follow /var/log/letsencrypt/letsencrypt.log",
            "tail --follow=name /var/log/letsencrypt/letsencrypt.log",
            "sudo tail -f /var/log/letsencrypt/letsencrypt.log",
        ]);
    }

    #[test]
    fn openssl_s_client_write_flags_are_rejected() {
        assert_rejected(&[
            "openssl s_client -connect example.com:443 -sess_out /tmp/x",
            "openssl s_client -connect example.com:443 -keylogfile /tmp/x",
            "openssl s_client -connect example.com:443 -msgfile /tmp/x",
            "openssl s_client -connect example.com:443 -writerand /tmp/x",
        ]);
    }

    #[test]
    fn timeout_misuse_is_rejected() {
        assert_rejected(&[
            "timeout 10 rm -rf /tmp/x",
            "timeout 10 curl -sI https://example.com",
            "timeout -s KILL 10 openssl s_client -connect example.com:443",
            "timeout 10s sudo openssl s_client -connect example.com:443",
            "timeout 99999 openssl s_client -connect example.com:443",
        ]);
    }

    #[test]
    fn read_only_forms_pass_the_gate() {
        for command in [
            "ss -ltn",
            "journalctl -u certbot.timer -n 50 --no-pager",
            "curl -q -sI http://example.com/.well-known/acme-challenge/test",
            "sudo tail -n 400 /var/log/letsencrypt/letsencrypt.log",
            "echo | timeout 10 openssl s_client -connect example.com:443 -servername example.com | openssl x509 -noout -dates",
        ] {
            check_command(command).unwrap_or_else(|err| panic!("{command} should pass: {err}"));
        }
    }
}
