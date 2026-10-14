# Snapshot tests

Expected stdout of the binary `acme-renew-doctor`, captured after running from the repository root with relative fixture paths. `tests/snapshots.rs` sets `current_dir` to the repository and compares stdout exactly, plus the exit code.

The version from `Cargo.toml` is in the text (`acme-renew-doctor 0.1.0`) and in the JSON (`"version": "0.1.0"`). A version change has to update these files too.

No clock in the text and no absolute paths: the paths are the arguments as they stood on the command line. Scenarios with certificate dates set `ACME_RENEW_DOCTOR_NOW=1791273600` (2026-10-06 08:00:00 UTC). That value is not in the output.

Human output ends, when there are checks, with the block "Next (SAFE copy-paste checks...)". The JSON has `next_checks` between `findings` and `exit_code`, and `from_cert_disk` / `from_cert_live` in `input`. `schema_version` stays 1.

Commands (6 October 2026, after reading the output):

- `human-timeout.txt` and `json-timeout.json` (exit 1): `example.com --from-log tests/fixtures/certbot/http01-timeout-repeated.log --from-timer-status tests/fixtures/timer/certbot-timer-disabled.txt` (JSON with `--json`)
- `human-insufficient.txt` and `json-insufficient.json` (exit 2): `example.com`
- `human-clean-log.txt` (exit 1): `--from-log tests/fixtures/certbot/http01-connection-refused.log --from-timer-status tests/fixtures/timer/certbot-timer-enabled.txt`. The file name is historical: the file was named that when this log did not yet have a recognised validation code. The output is `LAYER2_HTTP01_REFUSED`.
- `human-refused.txt` (exit 1, pinned clock): `example.com --from-log tests/fixtures/certbot/http01-connection-refused.log`
- `human-rate-limit.txt` and `json-rate-limit.json` (exit 1, pinned clock): `example.com --from-log tests/fixtures/certbot/rate-limit-exact-set.log` (JSON with `--json`)
- `human-dns01-txt.txt` and `json-dns01-txt.json` (exit 1, pinned clock): `example.com --from-log tests/fixtures/certbot/dns01-no-txt-record.log` (JSON with `--json`)
- `human-dns01-secondary.txt` (exit 1, pinned clock): `example.com --from-log tests/fixtures/certbot/dns01-no-txt-secondary.log`
- `human-unsafe-domain.txt` and `json-unsafe-domain.json` (exit 1): `example.com;rm -rf ~ --from-log tests/fixtures/certbot/http01-timeout.log` (JSON with `--json`; the domain becomes `YOUR_DOMAIN`; the raw text is not in a command; the JSON has `notes` before `exit_code`)
- `human-no-reload.txt` and `json-no-reload.json` (exit 1, pinned clock): `example.com --from-cert-disk tests/fixtures/certs/dates-disk-renewed.txt --from-cert-live tests/fixtures/certs/dates-live-old.txt`
- `human-ok-not-due.txt` and `json-ok-not-due.json` (exit 0, pinned clock, without `--from-log`): `example.com --from-timer-status tests/fixtures/timer/certbot-timer-enabled.txt --from-cert-disk tests/fixtures/certs/dates-current.txt --from-cert-live tests/fixtures/certs/dates-current.txt`
- `human-cert-not-recognised.txt` and `json-cert-not-recognised.json` (exit 2, pinned clock): `example.com --from-cert-disk tests/fixtures/certs/not-a-cert.txt --from-cert-live tests/fixtures/certs/dates-current.txt` (JSON with `--json`)
- `human-timer-not-firing.txt` and `json-timer-not-firing.json` (exit 1, pinned clock): `example.com --from-timer-status tests/fixtures/timer/certbot-timer-failed.txt` (JSON with `--json`)
- `human-timer-inactive.txt` (exit 1, pinned clock): `example.com --from-timer-status tests/fixtures/timer/certbot-timer-enabled-inactive.txt`
- `human-service-failed.txt` (exit 2, pinned clock): `example.com --from-timer-status tests/fixtures/timer/certbot-timer-ok-service-failed.txt`
- `human-service-only-failed.txt` (exit 2, pinned clock): `example.com --from-timer-status tests/fixtures/timer/certbot-service-only-failed.txt`
- `human-client-unknown.txt` and `json-client-unknown.json` (exit 3, pinned clock): `example.com --from-log tests/fixtures/acme-sh/verify-error-dns01.log` (JSON with `--json`)
- `human-client-unknown-timer.txt` (exit 3, pinned clock): `example.com --from-log tests/fixtures/acme-sh/verify-error-dns01.log --from-timer-status tests/fixtures/timer/certbot-timer-disabled.txt`
