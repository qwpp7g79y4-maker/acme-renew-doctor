# Quality report

This page shows how acme-renew-doctor was checked before its first public release, and what was fixed. It describes checks we did. It is not a guarantee that the software is free of bugs or secure.

## main after v0.1.0

| | |
|---|---|
| Commit reviewed | [`1a5c3a6`](https://github.com/qwpp7g79y4-maker/acme-renew-doctor/commit/1a5c3a6) |
| Date | 2026-10-16 |
| Tests | 323 automated tests |

- An external review of the code. Its confirmed findings are fixed, each with a regression test.
- A fresh independent final review of commit `1a5c3a6`, against the same fixed edge-case checklist and the nine questions, every item tried with a concrete bad input. It ended DONE, with no blocking findings. Before that, a fresh final review of the previous commit found one blocking issue: `--json` wrote DEL, C1 controls and bidirectional controls raw. That is fixed in `1a5c3a6`, with regression tests.
- That final review reported three non-blocking points. They are addressed in the commit after it: release archives now contain this report, the README lists the supported systems (glibc 2.34, macOS 10.12/11.0, Windows 10), CI checks the highest glibc symbol of the Linux gnu binary, and CI runs the tests in release mode too. That commit changed only the workflows, the documentation and a check script, not the tool's code. It has not had its own final review yet.

## v0.1.0

| | |
|---|---|
| Version | 0.1.0 ([release](https://github.com/qwpp7g79y4-maker/acme-renew-doctor/releases/tag/v0.1.0), [crates.io](https://crates.io/crates/acme-renew-doctor/0.1.0)) |
| Commit checked | [`4b64288`](https://github.com/qwpp7g79y4-maker/acme-renew-doctor/commit/4b64288) |
| Date | 2026-10-14 |
| Tests | 317 automated tests, run in debug and release mode |

### What we checked

**Code review.** The code was read against nine fixed questions:
1. Does it give the right answer?
2. What happens with bad or missing input?
3. What happens when it fails halfway, for example when output cannot be written?
4. Which assumptions does it make, and are they written down?
5. Is it safe when things happen at the same time?
6. Can untrusted input leak into the output or do harm, for example through hidden characters?
7. Does it stay fast and small with large input?
8. Is every claim backed by a test?
9. Is the code easy to read and change?

**Input from every platform.** UTF-8 with and without a byte order mark, UTF-16 and UTF-32, Windows line endings (CRLF), Windows paths, and file paths that are not valid UTF-8.

**Tests on every platform.** Every change runs the full test suite on Linux, Windows, macOS on Apple Silicon and macOS on Intel, plus the oldest supported Rust version (1.85).

**Release.** The release is built only after the tests pass again on the tagged commit. Each archive gets a SHA-256 checksum.

**Dependencies.** The only runtime dependency is clap. `cargo audit` runs in CI on every change.

### How we checked

- Independent code review, by reviewers who did not write the code.
- An external automated code review. All its findings that were confirmed are fixed in this version, each with a regression test.
- Automated tests in CI: [run 38541717053](https://github.com/qwpp7g79y4-maker/acme-renew-doctor/actions/runs/38541717053).
- Dependency audit with `cargo audit`.
- A fresh independent final review of commit [`8156ad9`](https://github.com/qwpp7g79y4-maker/acme-renew-doctor/commit/8156ad9) (same code as the commit checked above; only this report changed) against a fixed edge-case checklist, every item tried with a concrete bad input. It ended DONE, with no blocking findings.

We do not name the review services here. The checks and their results are what matters, and every result can be verified in the code, the tests and the changelog.

### Not covered

- Only Certbot is supported. Other ACME clients are reported as an unrecognised client.
- The tool reads files you saved. It does not check a live server, DNS or the ACME account.
