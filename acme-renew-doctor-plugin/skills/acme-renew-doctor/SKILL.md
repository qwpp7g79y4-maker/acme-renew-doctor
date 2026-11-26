---
name: acme-renew-doctor
description: Diagnose why an ACME or Certbot certificate renewal failed or never ran. Use when the user mentions Let's Encrypt, Certbot, a certificate that did not renew, an expired or soon-to-expire TLS certificate, or acme-renew-doctor.
---

# acme-renew-doctor

Use the local `acme-renew-doctor` CLI (version 0.2.0). It explains why an ACME certificate renewal failed or never ran, from files the user passes. It is read-only: it does not renew, reload, or change anything, and it does not run the checks it prints.

## Install

If `acme-renew-doctor` is not on `PATH`, install it with Rust 1.85 or newer:

```sh
cargo install --locked acme-renew-doctor
acme-renew-doctor --help
```

Do not invent flags. If you are unsure, run `acme-renew-doctor --help`. The live usage line is:

`acme-renew-doctor [OPTIONS] [DOMAIN]`

## Flags (from `--help`)

- `[DOMAIN]` — Domain to diagnose (shown in the report; the log is not filtered by domain yet). Cannot be combined with `--all`.
- `--all` — Diagnose all certificates (live collection is not built yet; use `--from-*` files).
- `--json` — Print the report as JSON (with schema_version) instead of text.
- `--from-log <FILE>` — Certbot log file, for example a copy of `/var/log/letsencrypt/letsencrypt.log`. `-` reads standard input.
- `--from-timer-status <FILE>` — Saved output of `systemctl show certbot.timer`.
- `--from-cert-disk <FILE>` — Saved output of `openssl x509 -noout -dates` for the certificate on disk (for example `/etc/letsencrypt/live/DOMAIN/fullchain.pem`).
- `--from-cert-live <FILE>` — Saved output of `openssl x509 -noout -dates` for the certificate the server sends (from `openssl s_client`).
- `--client <CLIENT>` — ACME client that wrote the files. Default `auto`. Possible values: `certbot`, `acme.sh`, `auto`. Only Certbot logs are parsed in this version; `--client acme.sh` is not parsed.
- `--example` — Write a synthetic Certbot log to `example-log.txt` in the current directory and exit. Cannot be combined with any other option. It refuses to overwrite an unrelated file of that name.
- `-h`, `--help` / `-V`, `--version`

The tool does not collect live data itself. The user creates each `--from-*` file. You may suggest the read-only copy-paste checks from the report, but do not run a renewal, and do not force a renewal: Let's Encrypt rate limits apply.

## Examples from the project README

Without files, the report asks for them and exits 2:

```sh
acme-renew-doctor example.com
```

Without a clone, write the synthetic log and analyse it:

```sh
acme-renew-doctor --example
acme-renew-doctor example.com --from-log example-log.txt
```

With a saved log and timer status (paths exist only in a clone of the repository):

```sh
acme-renew-doctor example.com --from-log tests/fixtures/certbot/http01-timeout-repeated.log --from-timer-status tests/fixtures/timer/certbot-timer-disabled.txt
```

## Exit codes

- 0 — ok, not due
- 1 — a layer was found
- 2 — insufficient evidence
- 3 — usage, including `CLIENT_UNKNOWN`

## Data

Fully offline: no network, no API key, no telemetry. Evidence text is the file text. Do not paste secrets from a log into a wider chat than needed. Prefer `--json` when the user wants structured output.
