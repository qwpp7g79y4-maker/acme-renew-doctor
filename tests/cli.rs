use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_acme-renew-doctor"))
        .args(args)
        .output()
        .expect("run acme-renew-doctor")
}

#[test]
fn help_exits_zero_and_lists_arguments() {
    let output = run(&["--help"]);
    assert_eq!(output.status.code(), Some(0));

    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));

    for needle in [
        "--all",
        "--json",
        "--from-log",
        "--from-timer-status",
        "--client",
        "certbot",
        "acme.sh",
        "auto",
        "Domain to diagnose (shown in the report; the log is not filtered by domain yet)",
        "Print the report as JSON (with schema_version) instead of text",
        "Certbot log file to analyse, e.g. a copy of /var/log/letsencrypt/letsencrypt.log",
        "Saved output of `systemctl show certbot.timer` to analyse",
        "Saved output of `openssl x509 -noout -dates` for the certificate on disk (e.g. /etc/letsencrypt/live/DOMAIN/fullchain.pem)",
        "Saved output of `openssl x509 -noout -dates` for the certificate the server sends (from openssl s_client)",
        "only Certbot logs are parsed in v0.1",
    ] {
        assert!(
            text.contains(needle),
            "help output missing {needle}\n{text}"
        );
    }
}

#[test]
fn invalid_client_exits_three() {
    let output = run(&["--client", "foo"]);
    assert_eq!(output.status.code(), Some(3));
}

#[test]
fn invalid_now_override_exits_three() {
    let output = Command::new(env!("CARGO_BIN_EXE_acme-renew-doctor"))
        .args(["example.com"])
        .env("ACME_RENEW_DOCTOR_NOW", "not-a-timestamp")
        .output()
        .expect("run acme-renew-doctor");
    assert_eq!(output.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(
            "ACME_RENEW_DOCTOR_NOW must be a whole number of Unix seconds, got not-a-timestamp"
        ),
        "{stderr}"
    );
    assert!(
        output.stdout.is_empty(),
        "stdout:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn domain_with_all_exits_three() {
    let output = run(&["example.com", "--all"]);
    assert_eq!(output.status.code(), Some(3));
}

#[test]
fn domain_without_inputs_exits_two() {
    let output = run(&["example.com"]);
    assert_eq!(output.status.code(), Some(2));
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("INSUFFICIENT_EVIDENCE"),
        "missing code\n{text}"
    );
    assert!(
        text.contains(
            "note: live collection is not built yet; pass --from-log, --from-timer-status, --from-cert-disk and/or --from-cert-live."
        ),
        "missing note\n{text}"
    );
}
