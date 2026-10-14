# Changelog

All notable changes to this project are documented in this file.

## [0.1.0] - 2026-10-14

### Added

- Read a Certbot log, saved `systemctl show` output, and saved `openssl x509 -dates` output from files you pass with `--from-log`, `--from-timer-status`, `--from-cert-disk` and `--from-cert-live`.
- Report one fixed code per layer that the rules recognise, with the evidence line, or say the evidence is not enough.
- Human text and `--json` with `schema_version` 1.
- Read-only suggested checks. The tool runs nothing, and it does not renew or reload.
- Exit 0 when the certificate is not due, 1 when a layer was found, 2 when evidence is insufficient, 3 on a usage error or an unrecognised client.

### Robustness

- Saved `systemctl show` output counts only the Certbot units `certbot.timer`, `certbot.service` and `snap.certbot.renew.timer`.
- An ACME error's `type` and `detail` are taken from the same JSON object, in either order.
- A certificate year outside 1970 through 9999 is not a date, and `ACME_RENEW_DOCTOR_NOW` outside that UTC range is rejected.
- The same JSON object with two different `type` or `detail` values is ambiguous and is not reported as a layer.
- Decode `\u` surrogate pairs in JSON strings; a lone surrogate or a broken `\u` escape becomes U+FFFD instead of dropping the object.
- Builds and tests on Rust 1.85, the minimum supported version.
- Refuse input files that are not regular files (such as FIFOs or devices) and cap how much of each file is read before parsing.
- Decode timer and certificate files the same way as logs, and show any input path, including paths with spaces, Unicode or non-UTF-8 bytes.
- Count an unsafe domain only when a suggested check uses it as the host.
- Exit 3 with a short message instead of panicking when standard output or standard error is closed or full (for example `| head` or `/dev/full`).
- Escape control characters, line separators and terminal escape sequences from input files in the text report, so file content cannot add fake report lines or change the terminal.
- Escape the same characters in input paths shown on the `inputs:` line of the text report.
- Parse ACME JSON when whitespace, including a newline, sits between a key, the colon and the value. A nested subproblem outranks its parent at the same timestamp.
- Treat a repeated `type` or `detail` with a different value of any JSON kind as ambiguous. Deduplicate repeated errors by type and detail, and keep the earliest timestamp on `first_line`.
- Open an input file before checking its type. On Linux that open does not block on a fifo.
- A duplicate key with a different value inside one `systemctl show` block makes that unit ambiguous. Equal values still count as one.
- Do not report `OK_NOT_DUE` when the only timer is `snap.certbot.renew.timer` and it is not loaded and active. A missing ActiveState or UnitFileState is not a high-confidence timer failure.
- Suggested `curl` commands start with `curl -q`. A pipe is split on `|` without requiring spaces, and file-writing curl options are rejected.
- Escape bidirectional controls in text output. On the `inputs:` line, a path is printed raw when it has no control or bidirectional character and does not start with `"`, so `C:\Users\certbot\log.txt` stays unchanged. Otherwise it is quoted: `\` becomes `\\`, `"` becomes `\"`, a newline becomes `\n`, a carriage return becomes `\r`, a tab becomes `\t`, and any other control becomes `\u{..}`. A real newline is `"a\nb.log"`. The two characters `\` and `n` stay `a\nb.log`.
- Escape control characters in an invalid `ACME_RENEW_DOCTOR_NOW` value. A system clock before 1970-01-01 UTC is an error, not Unix second 0.
- Keep the failed `certbot.service` evidence line on the finding that is reported.
- Document installing a binary release archive separately from `cargo install --path .`. The archive has no `Cargo.toml`.
