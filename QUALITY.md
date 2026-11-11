# Quality report

This page shows how acme-renew-doctor was checked, including after 0.1.0 and 0.2.0 were published, and what was fixed. It describes checks we did. It is not a guarantee that the software is free of bugs or secure.

## Verification log

This log is updated weekly and lists only checks that actually ran, with the numbers they produced.

### 2026-11-11 (1.0.0, branch fix/docs-v1.0.0)

- The Installation binary-archive section in `README.md` and `README.nl.md` now names v1.0.0 (tag, archive name, and download URL), matching Cargo.toml 1.0.0. `tests/readme.rs` compares that section to `CARGO_PKG_VERSION`.
- The release archive now includes `examples/`. `.github/workflows/release.yml` copies that folder on every platform, the smoke test checks `examples/README.md`, and `tests/readme.rs` compares the relative links in `README.md` and `README.nl.md` with the copy list.
- `--output` creates the temporary file with `create_new`, tries another name if the first exists, and on Unix keeps the permission bits of an existing regular destination. A pre-placed symlink at the temporary name is not followed. The write error mentions that a temporary file is created next to the destination.
- The offline unshare test skips when `unshare` is missing, and when `unshare -rn true` fails with EPERM, uid_map, or permission denied (the EPERM skip was already in `bc09604`). Otherwise the test still runs in a network namespace with an empty route table.
- GitHub CI run 42943099185 was green on commit `9959bda`. This tip is not pushed; that run does not cover these changes.
- `cargo test --no-fail-fast`: 473 passed / 0 failed / 1 ignored. Measured on commit `bc09604` plus these changes.
- `cargo fmt --check`: clean. `cargo clippy --all-targets -- -D warnings`: clean.
- Version stays 1.0.0. `rust-version` stays 1.85.

### 2026-11-09 (1.0.0, branch prep/w24-fout)

- `cargo test --no-fail-fast`: 469 passed / 0 failed / 1 ignored. Measured on commit `4e954d5` plus these changes.
- `cargo fmt --check`: clean. `cargo clippy --all-targets -- -D warnings`: clean.
- Version stays 1.0.0. `rust-version` stays 1.85.

### 2026-11-08 (W-55, remaining days, branch prep/w24-fout)

- `--warn-days DAYS` sets the renewal warning threshold. Omit it and the threshold stays one third of the disk certificate lifetime, capped at 30 days. The report states how many calendar days remain. Finding codes stay the same. Exit codes stay 0, 1, 2 and 3. The log limit stays 268435456 bytes. The timer and certificate limit stays 1048576 bytes. A missing parent directory for `--output` stays exit 3. SIGINT stays exit 130. Tests use synthetic certificate dates and `ACME_RENEW_DOCTOR_NOW`. No host or chain verdict was added. The clock is not stored on the report.
- `cargo test --no-fail-fast`: 469 passed / 0 failed / 1 ignored.
- `cargo fmt --check`: clean. `cargo clippy --all-targets -- -D warnings`: clean.
- Version stays 1.0.0. `rust-version` stays 1.85.

### 2026-11-08 (W-66, version line, branch prep/w24-fout)

- `--version` and `-V` print the crate version and exit 0. A debug build also prints the git commit when git provides one. A release build prints the crate version only. No commit hash is invented. Exit codes stay 0, 1, 2 and 3. The log limit stays 268435456 bytes. The timer and certificate limit stays 1048576 bytes. A missing parent directory for `--output` stays exit 3. SIGINT stays exit 130. No host or chain finding was added.
- `cargo test --no-fail-fast`: 458 passed / 0 failed / 1 ignored.
- `cargo fmt --check`: clean. `cargo clippy --all-targets -- -D warnings`: clean.
- Version stays 1.0.0. `rust-version` stays 1.85.

### 2026-11-08 (W-48, SIGINT, branch prep/w24-fout)

- SIGINT exits 130. Stderr is `acme-renew-doctor: interrupted by SIGINT; run the command again`. The report is not left half-written. `tests/sigint.rs` sends the signal through a pidfd of the child it spawned. Ordinary exit codes stay 0, 1, 2 and 3. The log limit stays 268435456 bytes. The timer and certificate limit stays 1048576 bytes. A missing parent directory for `--output` stays exit 3. No host or chain finding was added.
- `cargo test --no-fail-fast`: 457 passed / 0 failed / 1 ignored.
- `cargo fmt --check`: clean. `cargo clippy --all-targets -- -D warnings`: clean.
- Version stays 1.0.0. `rust-version` stays 1.85.

### 2026-11-08 (W-46, input limit, branch prep/w24-fout)

- `--from-log` stays at most 268435456 bytes (256 MiB). A timer file and both certificate files stay at most 1048576 bytes (1 MiB). A larger regular file exits 2 with `over the 268435456 byte limit` or `over the 1048576 byte limit` and is not loaded. Neither limit was raised. The measured 100 MiB input stays under the log limit. The over-limit file is created in `/tmp` by the test and is not committed. Exit codes stay 0, 1, 2 and 3. A missing parent directory for `--output` stays exit 3.
- `cargo test --no-fail-fast`: 456 passed / 0 failed / 1 ignored.
- `cargo fmt --check`: clean. `cargo clippy --all-targets -- -D warnings`: clean.
- Version stays 1.0.0. `rust-version` stays 1.85.

### 2026-11-08 (W-44, `--quiet` and `--verbose`, branch prep/w24-fout)

- `--quiet` hides the hint line. A pipe or a redirect already omits it. `--verbose` prints the hint and, after a successful report write, one `context:` line on stderr (`files` and `findings`). Standard output stays the report. `--quiet` together with `--verbose` is exit 3. A missing parent directory of `--output` stays exit 3 and is not created.
- `cargo test --no-fail-fast`: 455 passed / 0 failed / 1 ignored.
- `cargo fmt --check`: clean. `cargo clippy --all-targets -- -D warnings`: clean.
- Version stays 1.0.0. `rust-version` stays 1.85.

### 2026-11-08 (W-43, `--output PATH`, branch prep/w24-fout)

- `--output PATH` writes the report to that file instead of standard output. An existing file is replaced. A missing parent directory exits 3, the same code as a failed write to standard output, and is not created.
- `cargo test --no-fail-fast`: 447 passed / 0 failed / 1 ignored.
- `cargo fmt --check`: clean. `cargo clippy --all-targets -- -D warnings`: clean.
- Version stays 1.0.0. `rust-version` stays 1.85.

### 2026-11-08 (W-45, offline report with outgoing connections blocked, branch prep/w24-fout)

- `tests/offline_certs.rs`: `expired_certificate_is_reported_with_outgoing_connections_blocked` runs the offline expired-certificate report inside `unshare --user --map-root-user --net`. That namespace has an empty route table. The findings stay the date findings. The report does not name a host or a chain problem.
- `cargo test --no-fail-fast`: 444 passed / 0 failed / 1 ignored.
- `cargo fmt --check`: clean. `cargo clippy --all-targets -- -D warnings`: clean.
- Version stays 1.0.0. `rust-version` stays 1.85.

### 2026-11-08 (W-28, line coverage, branch prep/w24-fout)

- Command: `cargo llvm-cov` (cargo-llvm-cov 0.9.1, stable toolchain), on tip `8cf74b0` plus the working-tree change below.
- Line coverage printed by the command: 97.80% (5187 lines, 114 missed). It was above 90%, so no tests were added to raise it. The same figure came out in five runs in a row.
- The first `cargo llvm-cov` run failed `unix::version_on_a_closed_pipe_exits_three` (exit 0 instead of 3). It passed in `cargo test`, and in three isolated runs of that test file. This was not a `.profraw` problem: the test helper made the pipe and spawned children from parallel tests, so a child could inherit the read end and keep the pipe open. `tests/closed_output.rs` now has a lock around creating the pipe and around `spawn`. No test uses sleep for this, no time or network was added, and `--ignore-run-fail` was not used. I did not prove the race by reproducing it on demand; the evidence is the one failure and five clean runs after the change.
- `cargo test --no-fail-fast`: 443 passed / 0 failed / 1 ignored. `cargo llvm-cov` gives the same counts.
- `cargo fmt --check`: clean. `cargo clippy --all-targets -- -D warnings`: clean.

### 2026-11-08 (W-26, speed on a 100 MiB input, branch prep/w24-fout)

- Input: a synthetic log of exactly 104857600 bytes (100 MiB), built by repeating `examples/http01-timeout/letsencrypt.log` (3332 bytes) and cutting at the byte count. It lives in `/tmp` and is not committed. The repeated lines are almost identical (the same block over and over, so the last block is cut off mid-line); this is a best case for the parser, not a typical log. The tool accepted it (the log limit is 256 MiB) and reported the same findings as for the small example, with 62940 attempts counted.
- Command: `/usr/bin/time -f "%e" target/release/acme-renew-doctor example.com --from-log big.log --from-timer-status timer-status.txt` on the release build, exit status 1 (problem found) as for the small example.
- Measured wall seconds, three runs: 0.54, 0.54, 0.55. Peak memory in one earlier run: 207076 KB.
- One machine, no other load recorded; no throughput figure is derived from this.

### 2026-11-08 (W-12, "Aan de slag in 5 minuten", branch prep/w07-offline)

- `cargo test --no-fail-fast` on commit `f3c6178` plus the working-tree change: 423 passed / 0 failed / 1 ignored. The new test `five_minute_section_commands_run_literally` runs the five commands of the section as written.
- `cargo fmt --check`: clean. `cargo clippy --all-targets -- -D warnings`: clean.
- The 416 figure below was measured on another branch; it does not describe this one.

### 2026-11-08 (pre-release quality pass, branch prep/v1-kwaliteit)

- `cargo test --no-fail-fast` on commit `de0d994`: 416 passed / 0 failed / 1 ignored.
- `cargo fmt --check`: clean. `cargo clippy --all-targets -- -D warnings`: clean.
- Only these three checks were run for this entry; the earlier entries below were not repeated.

### 2026-11-07 (release check of 0.2.0)

- `cargo test --no-fail-fast` on commit `e564dcc`: 413 passed / 0 failed / 1 ignored.
- `cargo clippy --all-targets -- -D warnings`: clean.
- Only these two checks were run for this entry; the earlier entries below were not repeated.

### 2026-10-17 (weekly)

**1. Unit and regression tests**

- `cargo test`: 339 passed / 0 failed / 1 ignored before this week's work ([`8acdc0a`](https://github.com/qwpp7g79y4-maker/acme-renew-doctor/commit/8acdc0a)), wall 5s; 385 passed / 0 failed / 1 ignored after ([`7cdf020`](https://github.com/qwpp7g79y4-maker/acme-renew-doctor/commit/7cdf020)), wall 4s.
- `cargo test --release`: 339 → 385 passed, wall 2s → 2s.
- `cargo +1.85 test` (MSRV): 339 → 385 passed, wall 5s → 5s.
- New tests added this week: 46.
- Change since last week: this is the first weekly entry; it is the baseline for later comparison.

**2. Property tests**

- `tests/proptest.rs`: 10 `#[test]` functions, unchanged before and after this week's work.
- Case settings: none beyond proptest's own defaults were recorded by this week's run.
- Change since last week: baseline; no earlier weekly number exists yet.

**3. Fuzzing**

Five targets, one run each, about 661-662 seconds wall time per target, one CPU core, foreground:
- `cert_enddate`: 32,317,640 executions, ~48,892 exec/s, corpus 2,792 → 5,590 inputs, 0 crashes/artifacts.
- `certbot_log`: 3,670,575 executions, ~5,553 exec/s, corpus 6,967 → 10,889, 0 crashes/artifacts.
- `report_render`: 674,342 executions, ~1,020 exec/s, corpus 837 → 1,220, 0 crashes/artifacts.
- `safe_domain`: 25,726,365 executions, ~38,920 exec/s, corpus 14,236 → 24,881, 0 crashes/artifacts.
- `timer_show`: 28,288,242 executions, ~42,796 exec/s, corpus 3,957 → 6,629, 0 crashes/artifacts.
- Change since last week: baseline; no earlier weekly fuzzing numbers exist yet.

**4. Mutation testing**

- Full run before this week's new tests ([`8acdc0a`](https://github.com/qwpp7g79y4-maker/acme-renew-doctor/commit/8acdc0a)): 814 caught, 137 missed, 29 timeout, 59 unviable (1,039 mutants total, 11 minutes). Mutation score, unviable excluded: 814 / (814+137+29) = 83.1%.
- `--iterate` run after this week's new tests ([`7a7a8df`](https://github.com/qwpp7g79y4-maker/acme-renew-doctor/commit/7a7a8df)), retesting the 166 mutants previously missed or timed out: 114 caught, 26 missed, 26 timeout (3 minutes). Combined score: (814+114) / (814+114+26+26) = 94.7%.
- Neither run hit the time cap (both exited with status 3, not 124).
- Killed by this week's new tests: 114.
- Equivalent mutants confirmed still missed, with reasons: `safe.rs` domain-length guard clauses redundant with downstream checks (lines 131, 470-472); `render.rs` `escape_backslash` guard always true at its only call site (line 389); `certbot_log.rs` `json_value_end`/`skip_ws_nl` branch masked by surrounding control flow (lines 835, 907). Three further mutants noted as possibly equivalent in the work notes (`safe.rs:501`, `safe.rs:617`, `certbot_log.rs:455`) were in fact caught by the `--iterate` run, so they count as killed by new tests, not as equivalent.
- Mutants left: 52 (26 missed + 26 timeout); the 59 unviable mutants are excluded since they cannot be killed by a test.
- Change since last week: baseline; no earlier weekly mutation numbers exist yet.

**5. Real-world samples**

- New public sample fixtures added this week: 0 (no fetch was performed; no source was invented).
- Change since last week: baseline; no earlier weekly number exists yet.

**6. Platforms and CI**

- CI for [`7a7a8df`](https://github.com/qwpp7g79y4-maker/acme-renew-doctor/commit/7a7a8df): completed, success.
- CI for [`7cdf020`](https://github.com/qwpp7g79y4-maker/acme-renew-doctor/commit/7cdf020): completed, success.
- CI status for the two commits in between is not recorded in this week's measurement files, so it is not claimed here.
- Change since last week: baseline; no earlier weekly CI record exists yet.

**7. Final review**

- Round 1, against [`7a7a8df`](https://github.com/qwpp7g79y4-maker/acme-renew-doctor/commit/7a7a8df): verdict NOT DONE. Finding: two of the three new regression tests added in [`243b66b`](https://github.com/qwpp7g79y4-maker/acme-renew-doctor/commit/243b66b) did not test what their names and comments claimed, because they compared already-identical text instead of real `\u`-escaped input. This was a test-correctness problem, not a bug in the tool itself.
- Round 2, against [`7cdf020`](https://github.com/qwpp7g79y4-maker/acme-renew-doctor/commit/7cdf020): verdict DONE. The rewritten tests in `7cdf020` were confirmed, with a hand-applied mutation, to actually catch the mutant they claim to catch.
- Open non-blocking points from round 2: `CHANGELOG.md` refers to `tests/ROBUSTHEID.md`, a file excluded from git by `.gitignore`, so that line cannot be checked from the published repository; an untracked `repro/` directory still describes already-fixed bugs as open.
- Change since last week: baseline; no earlier weekly review verdicts exist yet.

### Open points

- 52 mutants are still missed or timing out after this week's `--iterate` run.
- `CHANGELOG.md` refers to a file not tracked in git (`tests/ROBUSTHEID.md`); readers of the published repository cannot verify that line.
- An untracked `repro/` directory still describes already-fixed bugs as open.
- No new public real-world sample fixtures were added this week.

## main after v0.1.0

| | |
|---|---|
| Commit reviewed | [`bfb99d7`](https://github.com/qwpp7g79y4-maker/acme-renew-doctor/commit/bfb99d7) |
| Date | 2026-10-16 |
| Tests | 339 automated tests |

- An external review of the code. Its confirmed findings are fixed, each with a regression test.
- A fresh independent final review of commit `1a5c3a6`, against the same fixed edge-case checklist and the nine questions, every item tried with a concrete bad input. It ended DONE, with no blocking findings. Before that, a fresh final review of the previous commit found one blocking issue: `--json` wrote DEL, C1 controls and bidirectional controls raw. That is fixed in `1a5c3a6`, with regression tests.
- That final review reported three non-blocking points. They are addressed in the commit after it: release archives now contain this report, the README lists the supported systems (glibc 2.34, macOS 10.12/11.0, Windows 10), CI checks the highest glibc symbol of the Linux gnu binary, and CI runs the tests in release mode too. That commit changed only the workflows, the documentation and a check script, not the tool's code. A fresh independent final review of that commit, [`4ded184`](https://github.com/qwpp7g79y4-maker/acme-renew-doctor/commit/4ded184), against the same checklist ended DONE, with no blocking findings and two non-blocking points: a domain label longer than 63 characters is accepted and ends up in a suggested `dig` or `curl` command (harmless, but not a valid DNS name), and a changelog line named only Linux for the fifo behaviour, which applies to all Unix systems. The changelog line is fixed; the label length is fixed in the commit below.
- Commit [`bfb99d7`](https://github.com/qwpp7g79y4-maker/acme-renew-doctor/commit/bfb99d7) rejects a domain label over 63 bytes, the known non-blocking point above. It also adds property tests and five cargo-fuzz targets (`safe_domain`, `certbot_log`, `timer_show`, `cert_enddate`, `report_render`), each checking an invariant, not only that the code runs without panicking. Each target ran 661 seconds on one CPU core on a Linux x86_64 machine: `safe_domain` 31,498,662 runs, `certbot_log` 5,466,535 runs, `timer_show` 19,829,332 runs, `cert_enddate` 48,356,095 runs, `report_render` 630,726 runs. That run found no crash and no invariant failure. One fuzz-harness assertion was stricter than the two checks it compared actually guarantee; it was narrowed during earlier smoke runs, and no product code changed for it. A fresh independent final review of `bfb99d7`, against the same checklist, ended DONE, with no blocking findings and two non-blocking points: the reference pages did not mention the 63-character label limit or the new invalid-hostname note, and the note for a domain containing `*` was not documented as a deliberate choice. Both are addressed in the commit that follows it. CI builds the fuzz targets on Linux nightly so they keep compiling; it does not run them.

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
