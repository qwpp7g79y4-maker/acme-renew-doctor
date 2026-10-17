# Quality report

This page shows how acme-renew-doctor was checked before its first public release, and what was fixed. It describes checks we did. It is not a guarantee that the software is free of bugs or secure.

## Verification log

This log is updated weekly and lists only checks that actually ran, with the numbers they produced.

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
