use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::SystemTime;

use acme_renew_doctor::certtime::{self, CertTime};
use acme_renew_doctor::model::{ClientKind, ExitStatus, Snapshot};
use acme_renew_doctor::render;
use acme_renew_doctor::report_input::build_report;
use acme_renew_doctor::safe;
use clap::builder::TypedValueParser;
use clap::{Parser, ValueEnum};

#[derive(Copy, Clone)]
struct AnyPath;

impl TypedValueParser for AnyPath {
    type Value = PathBuf;

    fn parse_ref(
        &self,
        _cmd: &clap::Command,
        _arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        Ok(PathBuf::from(value))
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "acme-renew-doctor",
    // Fixed so usage text is the same on every OS (no ".exe" on Windows).
    bin_name = "acme-renew-doctor",
    version,
    about = "Explains why ACME certificate renewal failed (read-only)."
)]
struct Cli {
    /// Domain to diagnose (shown in the report; the log is not filtered by domain yet)
    #[arg(value_name = "DOMAIN", conflicts_with = "all")]
    domain: Option<String>,

    /// Diagnose all certificates (live collection is not built yet; use --from-* files)
    #[arg(long, conflicts_with = "domain")]
    all: bool,

    /// Print the report as JSON (with schema_version) instead of text
    #[arg(long)]
    json: bool,

    /// Certbot log file to analyse, e.g. a copy of /var/log/letsencrypt/letsencrypt.log
    #[arg(long, value_name = "FILE", value_parser = AnyPath)]
    from_log: Option<PathBuf>,

    /// Saved output of `systemctl show certbot.timer` to analyse
    #[arg(long, value_name = "FILE", value_parser = AnyPath)]
    from_timer_status: Option<PathBuf>,

    /// Saved output of `openssl x509 -noout -dates` for the certificate on disk (e.g. /etc/letsencrypt/live/DOMAIN/fullchain.pem)
    #[arg(long, value_name = "FILE", value_parser = AnyPath)]
    from_cert_disk: Option<PathBuf>,

    /// Saved output of `openssl x509 -noout -dates` for the certificate the server sends (from openssl s_client)
    #[arg(long, value_name = "FILE", value_parser = AnyPath)]
    from_cert_live: Option<PathBuf>,

    /// ACME client that wrote the files (only Certbot logs are parsed in v0.1)
    #[arg(long, value_enum, default_value = "auto")]
    client: Client,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum Client {
    Certbot,
    #[value(name = "acme.sh")]
    AcmeSh,
    Auto,
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => finish_parse_error(err),
    };

    let snapshot = Snapshot {
        domain: cli.domain,
        all: cli.all,
        client: match cli.client {
            Client::Certbot => ClientKind::Certbot,
            Client::AcmeSh => ClientKind::AcmeSh,
            Client::Auto => ClientKind::Auto,
        },
        from_log: cli.from_log,
        from_timer_status: cli.from_timer_status,
        from_cert_disk: cli.from_cert_disk,
        from_cert_live: cli.from_cert_live,
    };
    let now = match now() {
        Ok(now) => now,
        Err(message) => {
            write_stderr_line(&format!("acme-renew-doctor: {message}"));
            return ExitCode::from(3);
        }
    };
    let mut report = build_report(snapshot, now);
    let suggested = safe::checks_for(&report);
    let checks = safe::apply_gate(&mut report, suggested);
    let text = if cli.json {
        render::json(&report, &checks)
    } else {
        render::human(&report, &checks)
    };
    if let Err(err) = write_stdout(text.as_bytes()) {
        return output_error(&err);
    }
    ExitCode::from(u8::try_from(report.exit_status().code()).expect("exit code fits in u8"))
}

fn write_stdout(bytes: &[u8]) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    stdout.write_all(bytes)?;
    stdout.flush()
}

fn write_stderr_line(line: &str) {
    let mut stderr = io::stderr().lock();
    let _ = writeln!(stderr, "{line}");
    let _ = stderr.flush();
}

fn output_error(err: &io::Error) -> ExitCode {
    write_stderr_line(&format!("acme-renew-doctor: could not write output: {err}"));
    ExitCode::from(3)
}

fn now() -> Result<CertTime, String> {
    match std::env::var("ACME_RENEW_DOCTOR_NOW") {
        Err(std::env::VarError::NotPresent) => system_now(),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err("ACME_RENEW_DOCTOR_NOW must be a whole number of Unix seconds".to_string())
        }
        Ok(value) => parse_now_override(&value),
    }
}

fn parse_now_override(value: &str) -> Result<CertTime, String> {
    let shown = render::escape_file_text(value);
    let secs = value.parse::<i64>().map_err(|_| {
        format!("ACME_RENEW_DOCTOR_NOW must be a whole number of Unix seconds, got {shown}")
    })?;
    certtime::try_from_unix_seconds(secs).ok_or_else(|| {
        format!(
            "ACME_RENEW_DOCTOR_NOW must be a Unix second from 1970-01-01 through 9999-12-31 UTC, got {shown}"
        )
    })
}

fn system_now() -> Result<CertTime, String> {
    certtime::try_from_system_time(SystemTime::now()).map_err(str::to_string)
}

fn finish_parse_error(err: clap::Error) -> ! {
    let code = match err.kind() {
        clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => {
            ExitStatus::Ok.code()
        }
        _ => ExitStatus::Usage.code(),
    };
    if let Err(io_err) = err.print() {
        let _ = output_error(&io_err);
        std::process::exit(3);
    }
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_only() {
        let cli = Cli::try_parse_from(["acme-renew-doctor", "example.com"]).unwrap();
        assert_eq!(cli.domain.as_deref(), Some("example.com"));
    }

    #[test]
    fn all_flag() {
        let cli = Cli::try_parse_from(["acme-renew-doctor", "--all"]).unwrap();
        assert!(cli.all);
        assert!(cli.domain.is_none());
    }

    #[test]
    fn domain_with_all_is_an_error() {
        let result = Cli::try_parse_from(["acme-renew-doctor", "example.com", "--all"]);
        assert!(result.is_err());
    }

    #[test]
    fn client_acme_sh_is_accepted() {
        let cli = Cli::try_parse_from(["acme-renew-doctor", "--client", "acme.sh"]).unwrap();
        assert_eq!(cli.client, Client::AcmeSh);
    }

    #[test]
    fn client_foo_is_an_error() {
        let result = Cli::try_parse_from(["acme-renew-doctor", "--client", "foo"]);
        assert!(result.is_err());
    }

    #[test]
    fn client_defaults_to_auto() {
        let cli = Cli::try_parse_from(["acme-renew-doctor"]).unwrap();
        assert_eq!(cli.client, Client::Auto);
    }

    #[test]
    fn empty_file_arguments_are_empty_paths() {
        let cli = Cli::try_parse_from([
            "acme-renew-doctor",
            "--from-log",
            "",
            "--from-timer-status",
            "",
            "--from-cert-disk",
            "",
            "--from-cert-live",
            "",
        ])
        .unwrap();
        assert!(cli.from_log.unwrap().as_os_str().is_empty());
        assert!(cli.from_timer_status.unwrap().as_os_str().is_empty());
        assert!(cli.from_cert_disk.unwrap().as_os_str().is_empty());
        assert!(cli.from_cert_live.unwrap().as_os_str().is_empty());
    }

    #[test]
    fn from_log_and_timer_status_return_paths() {
        let cli = Cli::try_parse_from([
            "acme-renew-doctor",
            "--from-log",
            "/tmp/letsencrypt.log",
            "--from-timer-status",
            "/tmp/timer-status.txt",
        ])
        .unwrap();
        assert_eq!(cli.from_log, Some(PathBuf::from("/tmp/letsencrypt.log")));
        assert_eq!(
            cli.from_timer_status,
            Some(PathBuf::from("/tmp/timer-status.txt"))
        );
    }

    #[test]
    fn from_cert_paths_are_returned() {
        let cli = Cli::try_parse_from([
            "acme-renew-doctor",
            "--from-cert-disk",
            "/tmp/disk-dates.txt",
            "--from-cert-live",
            "/tmp/live-dates.txt",
        ])
        .unwrap();
        assert_eq!(
            cli.from_cert_disk,
            Some(PathBuf::from("/tmp/disk-dates.txt"))
        );
        assert_eq!(
            cli.from_cert_live,
            Some(PathBuf::from("/tmp/live-dates.txt"))
        );
    }

    #[test]
    fn json_sets_the_flag() {
        let cli = Cli::try_parse_from(["acme-renew-doctor", "--json"]).unwrap();
        assert!(cli.json);
    }
}
