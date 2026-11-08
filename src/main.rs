use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::SystemTime;

use acme_renew_doctor::certtime::{self, CertTime};
use acme_renew_doctor::model::{ClientKind, ExitStatus, Snapshot};
use acme_renew_doctor::render;
use acme_renew_doctor::report_input::build_report;
use acme_renew_doctor::safe;
use clap::builder::TypedValueParser;
use clap::{Parser, ValueEnum};

/// Written by `--example`. Embedded at compile time, so it exists even after
/// `cargo install` from crates.io: the published crate includes `tests/`,
/// but a plain install leaves no clone of the repository behind to read it
/// from at runtime.
const EXAMPLE_LOG_NAME: &str = "example-log.txt";
const EXAMPLE_LOG: &str = include_str!("../tests/fixtures/certbot/http01-timeout-repeated.log");

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
pub(crate) struct Cli {
    /// Domain to diagnose (shown in the report; the log is not filtered by domain yet)
    #[arg(value_name = "DOMAIN", conflicts_with = "all")]
    domain: Option<String>,

    /// Diagnose all certificates (live collection is not built yet; use --from-* files)
    #[arg(long, conflicts_with = "domain")]
    all: bool,

    /// Print the report as JSON (with schema_version) instead of text
    #[arg(long)]
    json: bool,

    /// Write the report to this file instead of standard output. An existing file is replaced. A missing parent directory is an error and is not created
    #[arg(long, value_name = "PATH")]
    output: Option<PathBuf>,

    /// Hide the hint line. No context line. A pipe already omits both
    #[arg(long, conflicts_with = "verbose")]
    quiet: bool,

    /// Print the hint line, and on success one context line on stderr. Not with --quiet
    #[arg(long, conflicts_with = "quiet")]
    verbose: bool,

    /// Certbot log file to analyse, e.g. a copy of /var/log/letsencrypt/letsencrypt.log (- reads standard input)
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

    /// ACME client that wrote the files (only Certbot logs are parsed; acme.sh logs are recognised but not analysed yet)
    #[arg(long, value_enum, default_value = "auto")]
    client: Client,

    /// Write a synthetic Certbot log to example-log.txt in the current directory and exit (lets Quick start work without a clone of the repository); cannot be combined with any other option
    #[arg(
        long,
        conflicts_with_all = [
            "domain",
            "all",
            "json",
            "output",
            "from_log",
            "from_timer_status",
            "from_cert_disk",
            "from_cert_live",
            "client",
            "quiet",
            "verbose",
        ]
    )]
    example: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum Client {
    Certbot,
    #[value(name = "acme.sh")]
    AcmeSh,
    Auto,
}

fn main() -> ExitCode {
    acme_renew_doctor::install_sigint_handler();
    let code = run();
    if acme_renew_doctor::sigint_caught() {
        note_interrupted();
        return ExitCode::from(acme_renew_doctor::EXIT_SIGINT);
    }
    code
}

fn run() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => finish_parse_error(err),
    };
    if acme_renew_doctor::sigint_caught() {
        return ExitCode::from(acme_renew_doctor::EXIT_SIGINT);
    }

    let extra = show_extra(cli.quiet, cli.verbose, io::stderr().is_terminal());

    if cli.example {
        return write_example(extra);
    }

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
            emit_error(&format!("acme-renew-doctor: {message}"), extra);
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
    match write_report(cli.output.as_deref(), text.as_bytes()) {
        ReportWrite::Failed(err) => {
            return report_write_error(cli.output.as_deref(), &err, extra);
        }
        ReportWrite::Interrupted => return ExitCode::from(acme_renew_doctor::EXIT_SIGINT),
        ReportWrite::Done => {}
    }
    if acme_renew_doctor::sigint_caught() {
        return ExitCode::from(acme_renew_doctor::EXIT_SIGINT);
    }
    if cli.verbose {
        let files = input_file_count(&report.snapshot);
        write_stderr_line(&format!(
            "context: files {files}, findings {}",
            report.findings.len()
        ));
    }
    ExitCode::from(u8::try_from(report.exit_status().code()).expect("exit code fits in u8"))
}

/// Hint lines are extra context.
///
/// A terminal shows them. A pipe or a redirect does not, so captured stderr
/// stays the error line. `--verbose` shows them anyway. `--quiet` hides them
/// even on a terminal. The report on stdout is unchanged either way.
/// Both flags together are a clap usage error and never reach a report.
fn show_extra(quiet: bool, verbose: bool, terminal: bool) -> bool {
    if quiet {
        false
    } else if verbose {
        true
    } else {
        terminal
    }
}

fn input_file_count(snapshot: &Snapshot) -> usize {
    usize::from(snapshot.from_log.is_some())
        + usize::from(snapshot.from_timer_status.is_some())
        + usize::from(snapshot.from_cert_disk.is_some())
        + usize::from(snapshot.from_cert_live.is_some())
}

/// The next step already sits in the error after `; ` or `. `.
fn next_step(message: &str) -> Option<&str> {
    let semi = message.find("; ").map(|index| index + 2);
    let dot = message.find(". ").map(|index| index + 2);
    let start = match (semi, dot) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }?;
    let tail = message[start..].trim();
    if tail.is_empty() {
        None
    } else {
        Some(tail)
    }
}

/// Writes the error line. When `extra` is set, repeats the next step as `hint:`.
fn emit_error(message: &str, extra: bool) {
    write_stderr_line(message);
    if extra {
        if let Some(hint) = next_step(message) {
            write_stderr_line(&format!("hint: {hint}"));
        }
    }
}

/// Writes `EXAMPLE_LOG` to `EXAMPLE_LOG_NAME`, unless a file with that name
/// already exists and its bytes are not exactly the bundled example.
fn write_example(extra: bool) -> ExitCode {
    if acme_renew_doctor::sigint_caught() {
        return ExitCode::from(acme_renew_doctor::EXIT_SIGINT);
    }
    match write_example_log() {
        Ok(()) => {
            if acme_renew_doctor::sigint_caught() {
                return ExitCode::from(acme_renew_doctor::EXIT_SIGINT);
            }
            let message = format!(
                "wrote {EXAMPLE_LOG_NAME} in the current directory (synthetic Certbot log for the Quick start)\n"
            );
            match write_stdout(message.as_bytes()) {
                Ok(()) => ExitCode::from(0),
                Err(_) if acme_renew_doctor::sigint_caught() => {
                    ExitCode::from(acme_renew_doctor::EXIT_SIGINT)
                }
                Err(err) => output_error(&err, extra),
            }
        }
        Err(_) if acme_renew_doctor::sigint_caught() => {
            ExitCode::from(acme_renew_doctor::EXIT_SIGINT)
        }
        Err(message) => {
            emit_error(&format!("acme-renew-doctor: {message}"), extra);
            ExitCode::from(3)
        }
    }
}

fn write_example_log() -> Result<(), String> {
    // Compare bytes. `read_to_string` errors on a non-UTF-8 file and used to
    // fall through to `fs::write`, which overwrote that file.
    match std::fs::read(EXAMPLE_LOG_NAME) {
        Ok(existing) if existing == EXAMPLE_LOG.as_bytes() => Ok(()),
        Ok(_) => Err(format!(
            "{EXAMPLE_LOG_NAME} already exists with different content; remove it or run --example in an empty directory"
        )),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let written = acme_renew_doctor::with_sigint_blocked(|| {
                if acme_renew_doctor::sigint_caught() {
                    return None;
                }
                Some(std::fs::write(EXAMPLE_LOG_NAME, EXAMPLE_LOG))
            });
            match written {
                None => Err(format!(
                    "cannot write {EXAMPLE_LOG_NAME}: interrupted by SIGINT; run --example again"
                )),
                Some(Ok(())) => Ok(()),
                Some(Err(_)) if acme_renew_doctor::sigint_caught() => {
                    let _ = std::fs::remove_file(EXAMPLE_LOG_NAME);
                    Err(format!(
                        "cannot write {EXAMPLE_LOG_NAME}: interrupted by SIGINT; run --example again"
                    ))
                }
                Some(Err(err)) => Err(format!(
                    "cannot write {EXAMPLE_LOG_NAME}: {err}; run --example in a directory you can write to"
                )),
            }
        }
        Err(err) => Err(format!("cannot read {EXAMPLE_LOG_NAME}: {err}; remove it or run --example in an empty directory")),
    }
}

fn write_stdout(bytes: &[u8]) -> io::Result<()> {
    let result = acme_renew_doctor::with_sigint_blocked(|| {
        if acme_renew_doctor::sigint_caught() {
            return Err(io::Error::other("interrupted by SIGINT"));
        }
        let mut stdout = io::stdout().lock();
        stdout.write_all(bytes)?;
        stdout.flush()
    });
    if acme_renew_doctor::sigint_caught() {
        return Err(io::Error::other("interrupted by SIGINT"));
    }
    result
}

enum ReportWrite {
    Done,
    Failed(io::Error),
    Interrupted,
}

/// Path of a temporary file next to `path`, on the same filesystem, so the
/// finished report can replace `path` in one rename. SIGINT before that
/// rename deletes the temporary file and leaves `path` as it was.
fn temp_beside(path: &Path) -> PathBuf {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut name = std::ffi::OsString::from(".");
    name.push(
        path.file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("report")),
    );
    name.push(format!(".acme-renew-doctor-{}.tmp", std::process::id()));
    parent.join(name)
}

/// Replace `path` with the finished bytes in `tmp`.
///
/// On Unix, `rename` replaces an existing file in one step. On Windows,
/// `rename` does not replace an existing file, so the finished bytes are
/// copied over `path` after they are complete in `tmp`.
fn publish_temp(tmp: &Path, path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        let copied = std::fs::copy(tmp, path).map(|_| ());
        let _ = std::fs::remove_file(tmp);
        copied
    }
    #[cfg(not(windows))]
    {
        std::fs::rename(tmp, path)
    }
}

/// Write the report to `--output`, or to stdout when that flag is absent.
/// A missing parent directory is not created. A failed write uses exit 3,
/// the same code as a failed write to stdout. SIGINT publishes nothing
/// partial: the destination is replaced only after the new bytes are complete.
fn write_report(path: Option<&Path>, bytes: &[u8]) -> ReportWrite {
    if acme_renew_doctor::sigint_caught() {
        return ReportWrite::Interrupted;
    }
    let Some(path) = path else {
        return match write_stdout(bytes) {
            Ok(()) => ReportWrite::Done,
            Err(_) if acme_renew_doctor::sigint_caught() => ReportWrite::Interrupted,
            Err(err) => ReportWrite::Failed(err),
        };
    };
    let tmp = temp_beside(path);
    let created = std::fs::File::create(&tmp).and_then(|mut file| {
        file.write_all(bytes)?;
        file.flush()
    });
    if let Err(err) = created {
        let _ = std::fs::remove_file(&tmp);
        if acme_renew_doctor::sigint_caught() {
            return ReportWrite::Interrupted;
        }
        return ReportWrite::Failed(err);
    }
    let renamed = acme_renew_doctor::with_sigint_blocked(|| {
        if acme_renew_doctor::sigint_caught() {
            return None;
        }
        Some(publish_temp(&tmp, path))
    });
    match renamed {
        None => {
            let _ = std::fs::remove_file(&tmp);
            ReportWrite::Interrupted
        }
        Some(Ok(())) if acme_renew_doctor::sigint_caught() => ReportWrite::Interrupted,
        Some(Ok(())) => ReportWrite::Done,
        Some(Err(_)) if acme_renew_doctor::sigint_caught() => {
            let _ = std::fs::remove_file(&tmp);
            ReportWrite::Interrupted
        }
        Some(Err(err)) => {
            let _ = std::fs::remove_file(&tmp);
            ReportWrite::Failed(err)
        }
    }
}

fn report_write_error(path: Option<&Path>, err: &io::Error, extra: bool) -> ExitCode {
    let Some(path) = path else {
        return output_error(err, extra);
    };
    let shown = render::escape_file_text(&path.to_string_lossy());
    emit_error(
        &format!(
            "acme-renew-doctor: could not write report to {shown}: {err}; check that the parent directory exists and is writable; the tool does not create it"
        ),
        extra,
    );
    ExitCode::from(3)
}

fn write_stderr_line(line: &str) {
    let mut stderr = io::stderr().lock();
    let _ = writeln!(stderr, "{line}");
    let _ = stderr.flush();
}

fn note_interrupted() {
    emit_error(
        "acme-renew-doctor: interrupted by SIGINT; run the command again",
        stderr_is_extra_from_args(),
    );
}

fn output_error(err: &io::Error, extra: bool) -> ExitCode {
    emit_error(
        &format!(
            "acme-renew-doctor: could not write output: {err}; check that the output is not closed or full and run again"
        ),
        extra,
    );
    ExitCode::from(3)
}

fn now() -> Result<CertTime, String> {
    match std::env::var("ACME_RENEW_DOCTOR_NOW") {
        Err(std::env::VarError::NotPresent) => system_now(),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err("ACME_RENEW_DOCTOR_NOW must be a whole number of Unix seconds; unset it to use the system clock".to_string())
        }
        Ok(value) => parse_now_override(&value),
    }
}

fn parse_now_override(value: &str) -> Result<CertTime, String> {
    let shown = render::escape_file_text(value);
    let secs = value.parse::<i64>().map_err(|_| {
        format!("ACME_RENEW_DOCTOR_NOW must be a whole number of Unix seconds, got {shown}; unset ACME_RENEW_DOCTOR_NOW to use the system clock")
    })?;
    certtime::try_from_unix_seconds(secs).ok_or_else(|| {
        format!(
            "ACME_RENEW_DOCTOR_NOW must be a Unix second from 1970-01-01 through 9999-12-31 UTC, got {shown}; unset ACME_RENEW_DOCTOR_NOW to use the system clock"
        )
    })
}

fn system_now() -> Result<CertTime, String> {
    certtime::try_from_system_time(SystemTime::now()).map_err(str::to_string)
}

fn stderr_is_extra_from_args() -> bool {
    let mut quiet = false;
    let mut verbose = false;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--quiet" => quiet = true,
            "--verbose" => verbose = true,
            _ => {}
        }
    }
    show_extra(quiet, verbose, io::stderr().is_terminal())
}

fn finish_parse_error(err: clap::Error) -> ! {
    let code = match err.kind() {
        clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => {
            ExitStatus::Ok.code()
        }
        _ => ExitStatus::Usage.code(),
    };
    if let Err(io_err) = err.print() {
        if acme_renew_doctor::sigint_caught() {
            note_interrupted();
            std::process::exit(i32::from(acme_renew_doctor::EXIT_SIGINT));
        }
        let _ = output_error(&io_err, stderr_is_extra_from_args());
        std::process::exit(3);
    }
    if acme_renew_doctor::sigint_caught() {
        note_interrupted();
        std::process::exit(i32::from(acme_renew_doctor::EXIT_SIGINT));
    }
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extra_follows_quiet_verbose_and_the_terminal() {
        assert!(!show_extra(true, false, true));
        assert!(show_extra(false, true, false));
        assert!(!show_extra(false, false, false));
        assert!(show_extra(false, false, true));
        assert!(!show_extra(true, true, true));
    }

    #[test]
    fn next_step_is_the_clause_after_the_first_separator() {
        assert_eq!(
            next_step("missing parent. Check the directory"),
            Some("Check the directory")
        );
        assert_eq!(
            next_step("cannot write it; check the permissions"),
            Some("check the permissions")
        );
        assert_eq!(next_step("no separator"), None);
    }

    #[test]
    fn quiet_and_verbose_parse_and_conflict() {
        let quiet = Cli::try_parse_from(["acme-renew-doctor", "--quiet"]).unwrap();
        assert!(quiet.quiet);
        assert!(!quiet.verbose);
        let verbose = Cli::try_parse_from(["acme-renew-doctor", "--verbose"]).unwrap();
        assert!(verbose.verbose);
        assert!(!verbose.quiet);
        assert!(Cli::try_parse_from(["acme-renew-doctor", "--quiet", "--verbose"]).is_err());
        assert!(Cli::try_parse_from(["acme-renew-doctor", "--example", "--quiet"]).is_err());
    }

    #[test]
    fn example_flag_is_accepted() {
        let cli = Cli::try_parse_from(["acme-renew-doctor", "--example"]).unwrap();
        assert!(cli.example);
    }

    #[test]
    fn example_log_matches_the_fixture_it_is_embedded_from() {
        // Guards against the embedded copy drifting from the fixture on disk,
        // which the README's Quick start also documents as the source.
        let fixture = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/certbot/http01-timeout-repeated.log"),
        )
        .expect("read fixture");
        assert_eq!(EXAMPLE_LOG, fixture);
    }

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
