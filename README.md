# acme-renew-doctor

English · [Nederlands](README.nl.md)

Explain why a Certbot renewal failed, or quietly never ran, from files you pass.

[![crates.io](https://img.shields.io/crates/v/acme-renew-doctor.svg)](https://crates.io/crates/acme-renew-doctor) [![downloads](https://img.shields.io/crates/d/acme-renew-doctor.svg)](https://crates.io/crates/acme-renew-doctor) [![CI](https://github.com/qwpp7g79y4-maker/acme-renew-doctor/actions/workflows/ci.yml/badge.svg)](https://github.com/qwpp7g79y4-maker/acme-renew-doctor/actions/workflows/ci.yml) [![PEPAI checked](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fqwpp7g79y4-maker%2Facme-renew-doctor%2Fmain%2F.github%2Fbadge.json)](QUALITY.md) [![MSRV 1.85](https://img.shields.io/badge/MSRV-1.85-blue.svg)](https://github.com/qwpp7g79y4-maker/acme-renew-doctor/blob/main/Cargo.toml) [![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

[Installation](#installation) • [Quick start](#quick-start) • [How it works](#how-it-works) • [Alternatives](#compared-with-alternatives) • [Limitations](#limitations) • [Reference](docs/reference.md)

acme-renew-doctor is a local, read-only command-line tool written in Rust. It explains why a Certbot TLS renewal failed, or quietly never ran. It collects nothing. It only reads files you pass in: saved command output, or text you pasted into a file. It runs no command, never forces a renewal, and never reloads a service. A finding is a fixed code plus the evidence for it. Codes that name a layer use scheduler, validation, or deployment. It needs no account and makes no network connection.

## Why

Let's Encrypt stopped expiration-notification emails on 4 June 2025 (https://letsencrypt.org/2025/06/26/expiration-notification-service-has-ended.html). Since then a renewal that fails, or a timer that quietly stops, is easy to miss until the certificate expires. The cause sits in one of three layers: the scheduler, the ACME validation or the deployment. acme-renew-doctor reads the evidence you saved and names that layer, with the line that proves it.

## Installation

### From crates.io

With Rust 1.85 or newer, install from [crates.io](https://crates.io/crates/acme-renew-doctor):

```sh
cargo install --locked acme-renew-doctor
acme-renew-doctor --help
```

### Binary archive

The [v0.1.0 release](https://github.com/qwpp7g79y4-maker/acme-renew-doctor/releases/tag/v0.1.0) has archives for Linux x86_64 (`x86_64-unknown-linux-gnu` and `x86_64-unknown-linux-musl`), macOS (`x86_64-apple-darwin` and `aarch64-apple-darwin`) and Windows (`x86_64-pc-windows-msvc`, a `.zip`), each with a `.sha256` checksum file. An archive contains the binary, the documentation and the example files. It has no `Cargo.toml`, so `cargo install --path .` does not work inside the archive. Download the archive and its checksum, check the sha256 checksum, extract it, and put the binary on your `PATH`. For Linux x86_64:

```sh
name=acme-renew-doctor-v0.1.0-x86_64-unknown-linux-gnu
base=https://github.com/qwpp7g79y4-maker/acme-renew-doctor/releases/download/v0.1.0
curl -q -fsSL -O "$base/$name.tar.gz" -O "$base/$name.tar.gz.sha256"
sha256sum -c "$name.tar.gz.sha256"
tar -xzf "$name.tar.gz"
install -m 755 "$name/acme-renew-doctor" "$HOME/.local/bin/"
```

`$HOME/.local/bin` must be on your `PATH`. On macOS, check the checksum with `shasum -a 256 -c` instead of `sha256sum -c`.

### From source

Requires Rust 1.85 or newer. In a clone of this repository:

```sh
cargo install --locked --path .
acme-renew-doctor --help
```

`cargo install --path .` needs the `Cargo.toml` of the source tree. Or build it with `cargo build --release`; the binary is `target/release/acme-renew-doctor`.

### Supported systems

- Linux x86_64 (`x86_64-unknown-linux-gnu`): glibc 2.34 or newer. CI checks the highest glibc symbol the binary needs on every change and before each release. For an older distribution or Alpine, use the statically linked `x86_64-unknown-linux-musl` archive, which needs no glibc.
- macOS: 10.12 or newer on Intel, 11.0 or newer on Apple Silicon.
- Windows: Windows 10 or newer, x86_64.

## Quick start

These are the real outputs of the binary on the synthetic fixtures in `tests/fixtures`. A test runs every example and compares the output. You create each `--from-*` file yourself. The tool does not run the commands it prints.

With no files, the report asks for them and exits 2:

```console
$ acme-renew-doctor example.com
acme-renew-doctor 0.1.0 (read-only, nothing was changed)
target: example.com · client: auto
inputs: log=(none) · timer status=(none) · cert disk=(none) · cert live=(none)

? INSUFFICIENT_EVIDENCE  confidence=low  layer=-
  evidence:
  • [timer] no timer status
  • [log] no log given
  • [disk] no disk notAfter
  • [handshake] no live notAfter

Next (SAFE copy-paste checks, read-only; Doctor runs nothing and will NOT renew or reload for you):
  → systemctl show certbot.timer certbot.service -p Id,LoadState,ActiveState,SubState,UnitFileState,Result,ConditionResult,LastTriggerUSec,NextElapseUSecRealtime
    why: save this output yourself and pass the file with --from-timer-status
  → sudo tail -n 400 /var/log/letsencrypt/letsencrypt.log
    why: save a copy yourself and pass it with --from-log
  → sudo openssl x509 -noout -dates -in /etc/letsencrypt/live/example.com/fullchain.pem
    why: save this output yourself and pass the file with --from-cert-disk
  → echo | timeout 10 openssl s_client -connect example.com:443 -servername example.com | openssl x509 -noout -dates
    why: save this output yourself and pass the file with --from-cert-live
  ⚠ Do not force a renewal: Let's Encrypt rate limits apply. Fix the named layer first.
    (dangerous suggestions suppressed by default)

note: live collection is not built yet; pass --from-log, --from-timer-status, --from-cert-disk and/or --from-cert-live.

exit 2: insufficient evidence
```

A saved Certbot log and a saved timer status, both synthetic:

```console
$ acme-renew-doctor example.com --from-log tests/fixtures/certbot/http01-timeout-repeated.log --from-timer-status tests/fixtures/timer/certbot-timer-disabled.txt
acme-renew-doctor 0.1.0 (read-only, nothing was changed)
target: example.com · client: auto
inputs: log=tests/fixtures/certbot/http01-timeout-repeated.log · timer status=tests/fixtures/timer/certbot-timer-disabled.txt · cert disk=(none) · cert live=(none)

✗ LAYER1_TIMER_DISABLED  confidence=high  layer=scheduler
  evidence:
  • [timer] UnitFileState=disabled
  • [timer] ActiveState=inactive

✗ LAYER2_HTTP01_TIMEOUT  confidence=high  layer=validation
  evidence:
  • [log] line 68: 203.0.113.10: Fetching http://example.com/.well-known/acme-challenge/timeouttoken0000000000000000001: Timeout during connect (likely firewall problem)
  • [log] 2 attempts in this log (ACME response and Certbot summary of one attempt count as one), first on line 20

Next (SAFE copy-paste checks, read-only; Doctor runs nothing and will NOT renew or reload for you):
  → systemctl list-timers --all certbot.timer
    why: shows whether the timer is scheduled and when it last ran
  → systemctl is-enabled certbot.timer
    why: shows whether the timer is enabled
  → systemctl status certbot.timer --no-pager
    why: shows whether the timer is active
  → curl -q -sI --max-time 10 http://example.com/.well-known/acme-challenge/acme-renew-doctor-check
    why: any HTTP answer, even 404, means port 80 answers here; a timeout points to firewall or routing
  → dig +short A example.com
    why: compare the A record with the public IPv4 address of this server
  → dig +short AAAA example.com
    why: compare with the public IP of this server; a stale AAAA record is a common cause
  → ss -ltn
    why: look for a listener on port 80
  → sudo tail -n 200 /var/log/letsencrypt/letsencrypt.log
    why: shows recent lines from the Certbot log
  # also test from outside your network: the CA does not see what localhost sees
  ⚠ Do not force a renewal: Let's Encrypt rate limits apply. Fix the named layer first.
    (dangerous suggestions suppressed by default)

exit 1: problem found
```

`2 attempts` is the count: an ACME response and a Certbot summary of one attempt count as one. The line is printed only when that count is greater than 1, so the word is `attempts`.

Certificate dates that are equal and not yet due, with the clock pinned for the example. `ACME_RENEW_DOCTOR_NOW` is a whole number of Unix seconds. It is never printed. `1,5` and `1.5` are rejected. The UTC date must fall in 1970-01-01 through 9999-12-31.

```console
$ ACME_RENEW_DOCTOR_NOW=1791273600 acme-renew-doctor example.com --from-timer-status tests/fixtures/timer/certbot-timer-enabled.txt --from-cert-disk tests/fixtures/certs/dates-current.txt --from-cert-live tests/fixtures/certs/dates-current.txt
acme-renew-doctor 0.1.0 (read-only, nothing was changed)
target: example.com · client: auto
inputs: log=(none) · timer status=tests/fixtures/timer/certbot-timer-enabled.txt · cert disk=tests/fixtures/certs/dates-current.txt · cert live=tests/fixtures/certs/dates-current.txt

✓ OK_NOT_DUE  confidence=high  layer=-
  evidence:
  • [disk] notAfter=Dec 27 03:12:44 2026 GMT
  • [handshake] notAfter=Dec 27 03:12:44 2026 GMT
  • [timer] Id=certbot.timer
  • [timer] LoadState=loaded
  • [timer] ActiveState=active
  • [timer] UnitFileState=enabled

Next (SAFE copy-paste checks, read-only; Doctor runs nothing and will NOT renew or reload for you):
  → systemctl list-timers --all certbot.timer
    why: shows whether the timer is scheduled and when it last ran
  ⚠ Do not force a renewal: Let's Encrypt rate limits apply. Fix the named layer first.
    (dangerous suggestions suppressed by default)

exit 0: ok, not due
```

`1791273600` is 2026-10-06 08:00:00 UTC. `--json` prints one JSON object instead of this text. All options, exit codes and error messages are listed in the [reference](docs/reference.md) and in `acme-renew-doctor --help`.

## How it works

Every code can be traced back to these rules. The full match text, file formats and error messages are in the [reference](docs/reference.md#how-a-code-is-chosen).

- **One validation code.** The ACME error with the latest timestamp wins (`YYYY-MM-DD HH:MM:SS,mmm:`, Certbot `log.py` r.47). A line without a timestamp belongs to the last timestamped line above it. Equal timestamps, or no timestamps at all, keep the bottom line when the findings have the same depth. A nested subproblem outranks its parent when the timestamp is the same. The prefix `During secondary validation: ` is removed before the match. The evidence line keeps the original text. JSON `type` and `detail` come from the same object, in either order. Text after that object's `}` is not part of it. The same `type` or `detail` twice with the same value counts as one. Whitespace, including a newline, may sit between the key, the colon and the value. Two different values of any JSON kind in one object are not a layer code; the report says `ACME JSON is ambiguous (the same object has type or detail more than once with different values)`. Another object, or a Certbot summary, can still be a validation code. A blank Domain, Identifier, Type or Detail value is not a summary.
- **Timer.** Saved `systemctl show` output is read only for `certbot.timer`, `certbot.service` and `snap.certbot.renew.timer`. Any other unit is ignored. The same unit twice with the same state counts as one. The same unit twice with different states is `INSUFFICIENT_EVIDENCE` (`timer status is ambiguous (the same unit appears more than once with different states)`). `Id=` lines that name none of those three units are `INSUFFICIENT_EVIDENCE` (`timer status not recognised (no certbot.timer, certbot.service or snap.certbot.renew.timer)`). `LAYER1_TIMER_DISABLED` when LoadState is `masked`, or when the timer is `loaded` and UnitFileState is `disabled` or `masked`. `LAYER1_TIMER_NOT_FIRING` when it is loaded and not disabled or masked, and it is not `active` or its Result is non-empty and not `success`. The same key twice in one block with a different value is the same ambiguous result; the same value twice counts as one. A missing ActiveState or UnitFileState is not a high-confidence `LAYER1_TIMER_NOT_FIRING`. A failed `certbot.service` keeps its evidence line on the first layer diagnosis, not on a read error. When there is no layer diagnosis and no read error, the line stays on the insufficient-evidence finding.
- **Certificates.** Dates come from saved `openssl x509 -noout -dates` output. A year outside 1970 through 9999 is not recognised, and two `notAfter` lines that are not the same instant are not recognised. `LAYER3_NO_RELOAD` when the disk notAfter is later than the live notAfter. `OK_NOT_DUE` when disk and live notAfter are equal, more than 30 calendar days remain, there is no ACME error, the service unit is not `failed`, this is not the unsupported snap-timer case, a snap timer that is the only timer and is not loaded and active is not `OK_NOT_DUE`, and a timer if present is loaded, enabled and active. The 30 days are a fixed threshold, not notBefore. It approximates Certbot's default of 2/3 of the lifetime. As retrieved on 2026-10-17, https://letsencrypt.org/docs/faq/ says "Our default certificates are valid for 90 days." and "Subscribers can opt in to short-lived certificates which are valid for six days."
- **Client.** With `--client auto`, a log is Certbot only when a line has that timestamp form, a level, and a logger name starting with `certbot` or `acme`. Otherwise the code is `CLIENT_UNKNOWN` (exit 3). `--client acme.sh` is not parsed.
- **Checks.** The human report lists read-only copy-paste checks. Doctor does not run them. A check has to pass the allowlist and the word denylist. A short denylist flag is matched exactly, so `-i` is denied and `-I` is a different flag. A word or a long flag is matched without regard to ASCII case. A check that fails is left out, and its command is not shown. The evidence then says `1 suggested check` or `2 suggested checks`, so the word matches the number. A finding that carries the note that `certbot.service` failed also suggests `journalctl -u certbot.service -n 50 --no-pager`, once, including when that finding is a layer code.
- **Exit.** 0 ok, not due. 1 a layer was found. 2 insufficient evidence. 3 usage, including `CLIENT_UNKNOWN`. `CLIENT_UNKNOWN` is checked before any layer code. If the text report, `--json`, `--help` or `--version` cannot be written because standard output is closed or full, the tool does not panic: it writes `acme-renew-doctor: could not write output: ...` to standard error and exits 3. A usage message that cannot be written does the same. `--help` and `--version` exit 0 only when that text was written. If standard error is closed or full, the message for an invalid `ACME_RENEW_DOCTOR_NOW` does not panic, and the process still exits 3.

`DOMAIN` is shown on the report and does not filter the log. `[DOMAIN]` and `--all` cannot be used together. `--client` defaults to `auto`.

## Compared with alternatives

Other approaches and why this tool does not take them. No vendor page was checked for the products below, so none of these comparisons is a quotation from a vendor page; what was not verified is marked as such.

**A Python script.** A single Rust binary is easier to install.

**Renewing or reloading by itself.** Too risky. Let's Encrypt rate limits apply. The standard output never suggests `--force-renewal` or a reload that the tool would run.

**certease.** Described as a tool for fleet installation. Not verified: no page was checked. It is a different product: this tool diagnoses one machine from files you pass.

**A cloud monitor for expiry dates, for example Red Sift.** Such services exist and watch expiry dates from outside, but do not give a local cause. Not verified: no page was checked.

**Caddy, Traefik and cert-manager.** Not in 0.1.0. They have their own ACME implementations. Maybe later.

**acme-renew-doctor** is MIT OR Apache-2.0, a single binary, no account, no network. It reads files you pass and names a layer with the evidence line.

## Limitations

- Live collection is not built. With no `--from-*` file the report is `INSUFFICIENT_EVIDENCE` (exit 2) and says to pass those files.
- The tool does not redact. In the text report, text taken from an input file is shown as a quote on one line: C0 and C1 controls (ESC, CR, LF, TAB, DEL, and U+0080 through U+009F) and U+2028 and U+2029, plus bidirectional controls (U+202A through U+202E, U+2066 through U+2069, U+200E, U+200F and U+061C), are written as visible escapes such as `\n` and `\u{1b}`. A log quote keeps the prefix `[log] line N:`. Words in that quote, including `--force-renewal`, are the file's words, not a suggested check and not advice. `--json` keeps its own escaping.
- acme.sh logs are not parsed. `--client acme.sh` is `INSUFFICIENT_EVIDENCE`. Install paths of acme.sh differ per system.
- Certificate dates come only from saved `openssl x509 -dates` output, not from PEM and not from a live handshake. `OK_NOT_DUE` uses the fixed 30-day threshold, not notBefore.
- `DOMAIN` is shown on the report and does not filter the log.
- Pasted Certbot terminal output (not a letsencrypt.log) is `CLIENT_UNKNOWN` with `--client auto`. With `--client certbot` the summary is read. The old Boulder text `Error creating new order :: ...` in terminal output, and a summary without indentation, are not recognised.
- A check from localhost is not the same as what the CA sees from outside.
- Logs and timers often need root. Without root, only `--from-*` file mode works, or the result is exit 2.
- The checks and examples assume `certbot.timer`. A snap install (`snap.certbot.renew.timer`) or cron is not recognised.
- Certbot rotates `letsencrypt.log` on every run (`certbot/_internal/log.py` v5.0.0 r.165-173, `RotatingFileHandler` with `doRollover`). Earlier runs are in `letsencrypt.log.N`, and `--from-log` reads one file.
- The suggested checks assume Certbot on systemd (`certbot.timer`, `/etc/letsencrypt`, `/var/log/letsencrypt`). They are not yet adapted for snap or cron installs, or for acme.sh. Some checks ask for sudo, only in order to read.
- The connection errors `Network unreachable`, `Connection reset by peer`, `Timeout after connect` and `Timeout during <op>` (Boulder `va/va.go` r.426-442) have no code of their own. They are `INSUFFICIENT_EVIDENCE` with the evidence line `recognised connection error without a dedicated rule`.
- Concatenated logs: the ACME error with the latest timestamp wins. Refused at `2026-09-28 04:05:11` above timeout at `2026-09-28 03:12:44` is `LAYER2_HTTP01_REFUSED`. Equal timestamps, or a summary with no timestamps (`--client certbot`), keep the bottom line when the depth is the same. A nested subproblem outranks its parent at the same timestamp.
- `--from-log` reads invalid UTF-8 by putting U+FFFD in place of each invalid sequence, and the report says how many invalid bytes were replaced, without quoting them. One invalid byte (for example `0xFF` or Latin-1 `0xE9`) in the timeout log still yields `LAYER2_HTTP01_TIMEOUT` (exit 1). A replacement character never yields `OK_NOT_DUE`. UTF-16 and UTF-32, little-endian or big-endian, with or without a BOM, are refused (exit 2); the message names the encoding and says to save the file as UTF-8. A UTF-8 BOM still yields `LAYER2_HTTP01_TIMEOUT`. One NUL byte, or a few invalid bytes that are not that wide-encoding pattern, is not treated as UTF-16. `--from-timer-status`, `--from-cert-disk` and `--from-cert-live` use the same UTF-16 and UTF-32 check as a log, with or without a BOM, and exit 2 with the same message. A leading UTF-8 BOM is skipped and the file still works. Any other byte sequence that is not valid UTF-8 is refused (exit 2) with `cannot read PATH: the file is not valid UTF-8`.
- Each of `--from-log`, `--from-timer-status`, `--from-cert-disk` and `--from-cert-live` reads only a regular file, and the file is opened first. The type and size come from that open file. On Linux, macOS and the BSDs the open does not block when the path is a fifo. A fifo, a device such as `/dev/zero`, or a pipe such as `/dev/stdin` is exit 2 with `cannot read PATH: not a regular file, save the output to a file first`. A directory is exit 2 with `cannot read PATH: is a directory`. An empty path is exit 2 with `cannot read: the path is empty`. `--from-log` refuses a file larger than 268435456 bytes (256 MiB). The timer file and both certificate files refuse a file larger than 1048576 bytes (1 MiB). A log over that limit says `cannot read PATH: the file is N bytes, over the 268435456 byte limit`. A timer or certificate file over its limit says `cannot read PATH: the file is N bytes, over the 1048576 byte limit`. If the file grows while it is being read, a log says `cannot read PATH: the file is over the 268435456 byte limit`, and a timer or certificate file says `cannot read PATH: the file is over the 1048576 byte limit`. On the `inputs:` line of the text report a path is shown as is, so `C:\Users\certbot` stays readable, unless it contains a control or bidirectional character or starts with `"`. Then it is shown in double quotes with `\\`, `\"`, `\n`, `\r`, `\t` and `\u{..}` escapes, so a real newline is `"a\nb.log"` and the two characters backslash and n stay `a\nb.log`. In evidence lines and in JSON, controls and backslashes are escaped. A path that is not UTF-8 is shown with U+FFFD in place of the bad bytes, and the JSON stays valid.
- A certificate date with a non-English month name (for example `Mei`) is not recognised (exit 2). Produce `openssl` output with an English or C locale. This rests on source code, not on a real `nl_NL` run.
- The model also names `DANGEROUS_FORCE_BLOCKED`, `LAYER1_PERMISSION`, `LAYER2_DNS01_CREDENTIALS`, `LAYER2_HTTP01_404_WEBROOT`, `LAYER2_HTTP01_REDIRECT` and `LAYER3_COPIED_PATH`. The built-in rules do not choose those layer codes. `DANGEROUS_FORCE_BLOCKED` is added only when a suggested check fails the allowlist. The checks the tool itself suggests pass that list.

## Privacy

acme-renew-doctor is fully offline: no network, no API key, no telemetry. The only runtime dependency is clap. It does not redact: evidence text is the file text, with controls shown as visible escapes in the text report. All fixtures are synthetic or anonymised copies of public posts. See [tests/fixtures/README.md](tests/fixtures/README.md).

## Support

acme-renew-doctor is free to use. If it saves you time, you can support the work via [Ko-fi](https://ko-fi.com/pepai).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Copyright 2026 PEPAI.

Release archives include THIRD-PARTY-LICENSES.html with the licenses of the third-party crates in the binary.

## Contact

PEPAI, pep_ai@icloud.com

Report bugs and ideas via [Issues](https://github.com/qwpp7g79y4-maker/acme-renew-doctor/issues); report security problems privately as described in [SECURITY.md](SECURITY.md).
