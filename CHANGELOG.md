# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Added

- The README lists the supported systems: glibc 2.34 or newer for the Linux gnu build, macOS 10.12 (Intel) and 11.0 (Apple Silicon), and Windows 10.
- CI checks the highest glibc symbol of the Linux gnu binary and runs the tests in release mode too.
- Release archives contain `QUALITY.md` and `QUALITY.nl.md`, and the archive smoke test checks for them.
- A domain label over 63 bytes is rejected, not only a name over 253 bytes. The `--json` and text notes now say when a domain was rejected for its shape (too long, a label with a leading or trailing `-`, a trailing dot) separately from when it was rejected for a character unsafe in a shell command.
- A `fuzz/` crate (cargo-fuzz, nightly-only, outside the main build) with one target each for the Certbot log parser, the saved `systemctl show` parser, the saved certificate-date parser, `safe::safe_domain` plus the anti-force gate, and the full report-build-and-render pipeline. CI builds the targets on nightly Linux; it does not run them.
- `tests/proptest.rs` gained property tests: an accepted domain always has the shape the SAFE checks rely on, a generated shape-valid name is always accepted, and the three parsers above do not panic on arbitrary text.

### Fixed

- `--json` now writes DEL, C1 controls (U+0080 through U+009F) and bidirectional controls as `\uXXXX` in evidence text and paths. Before, they were written raw and could move the cursor or reorder a line when the JSON was shown in a terminal. U+2028 and U+2029 still stay the character.
- CI builds the fuzz targets with `--target x86_64-unknown-linux-gnu`. Without it, the prebuilt `cargo-fuzz` defaulted to the musl target, and the sanitizer does not support a statically linked libc.
- The reference pages now say a label is at most 63 characters, and quote the invalid-hostname note next to the unsafe-characters note. `tests/readme.rs` checks both note texts against `src/render.rs` verbatim.
- A domain containing `*`, such as `*.example.com`, keeps the unsafe-characters note, not the invalid-hostname one: an unquoted `*` glob-expands in a shell, which is what that note warns about. This is now documented and has a regression test.
- Two `tests/regressions.rs` tests did not exercise what their names and comments claimed: one compared a byte-identical string to itself instead of an uppercase and a lowercase `\uXXXX` hex escape, and the other used a plain `"type"`/`"detail"` key instead of a key spelled entirely in `\uXXXX` escapes. Both are rewritten to use real escapes, with key-order and whitespace (space, tab, CR, LF) variants, plus a mixed-case surrogate-pair case.
- CI now runs `cargo clippy` on the `fuzz/` crate and runs `cargo test --release` on the MSRV toolchain, matching the stable job.
- `tests/ROBUSTHEID.md` said opening a path that is a fifo only does not block "on Linux"; it now says Linux, macOS and the BSDs, matching README.md and CHANGELOG.md.
- The README and README.nl.md source for the 30-day `OK_NOT_DUE` threshold now says when the linked Let's Encrypt FAQ text was last checked.

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
- Open an input file before checking its type. On Linux, macOS and the other Unix systems that open does not block on a fifo.
- A duplicate key with a different value inside one `systemctl show` block makes that unit ambiguous. Equal values still count as one.
- Do not report `OK_NOT_DUE` when the only timer is `snap.certbot.renew.timer` and it is not loaded and active. A missing ActiveState or UnitFileState is not a high-confidence timer failure.
- Suggested `curl` commands start with `curl -q`. A pipe is split on `|` without requiring spaces, and file-writing curl options are rejected.
- Escape bidirectional controls in text output. On the `inputs:` line, a path is printed raw when it has no control or bidirectional character and does not start with `"`, so `C:\Users\certbot\log.txt` stays unchanged. Otherwise it is quoted: `\` becomes `\\`, `"` becomes `\"`, a newline becomes `\n`, a carriage return becomes `\r`, a tab becomes `\t`, and any other control becomes `\u{..}`. A real newline is `"a\nb.log"`. The two characters `\` and `n` stay `a\nb.log`.
- Escape control characters in an invalid `ACME_RENEW_DOCTOR_NOW` value. A system clock before 1970-01-01 UTC is an error, not Unix second 0.
- Keep the failed `certbot.service` evidence line on the finding that is reported.
- Document installing a binary release archive separately from `cargo install --path .`. The archive has no `Cargo.toml`.
