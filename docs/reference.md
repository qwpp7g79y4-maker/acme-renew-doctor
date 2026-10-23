# acme-renew-doctor reference

English · [Nederlands](reference.nl.md)

This page has the complete details. For an overview, see the [README](../README.md).

## Options

Run `acme-renew-doctor --help` for the built-in help. `--version` prints `acme-renew-doctor 0.1.0` and exits 0. `--help` and `--version` exit 0 when that text is written. If standard output is closed or full, they exit 3 and standard error says `acme-renew-doctor: could not write output: ...`. Other clap mistakes exit 3. See [Exit codes and usage errors](#exit-codes-and-usage-errors).

| Option | What it does |
| --- | --- |
| `[DOMAIN]` | Shown on the report. The log is not filtered by domain. Cannot be combined with `--all`. |
| `--all` | Diagnose all certificates. Live collection is not built; pass `--from-*` files. Cannot be combined with `[DOMAIN]`. |
| `--json` | One JSON object with `schema_version` 1, instead of text. |
| `--from-log` | Certbot log file to analyse, for example a copy of `/var/log/letsencrypt/letsencrypt.log`. `-` reads standard input instead, buffered up to the same byte limit. |
| `--from-timer-status` | Saved output of `systemctl show certbot.timer` to analyse. |
| `--from-cert-disk` | Saved output of `openssl x509 -noout -dates` for the certificate on disk. |
| `--from-cert-live` | Saved output of `openssl x509 -noout -dates` for the certificate the server sends. |
| `--client` | `certbot`, `acme.sh` or `auto`. Default `auto`. Only Certbot logs are parsed in 0.1.0. |
| `--example` | Write a synthetic Certbot log to `example-log.txt` in the current directory and exit; lets the Quick start work without a clone of the repository. |
| `--help` | Show help and exit 0 when that text is written. If standard output is closed or full, exit 3. |
| `--version` | Show the version and exit 0 when that text is written. If standard output is closed or full, exit 3. |

`ACME_RENEW_DOCTOR_NOW` is not a flag. It is an environment variable for tests: a whole number of Unix seconds, used by the 30-day check, never printed. `1,5` and `1.5` are not whole numbers, so they stay invalid. The UTC date of that second must fall in 1970-01-01 through 9999-12-31. `0` is 1970-01-01 00:00:00 UTC. `-1` and `253402300800` are outside that range. The value in the error is escaped like file text, so a control character is not printed raw. A system clock before 1970-01-01 UTC is not treated as second 0; the error is `system clock is outside 1970-01-01 through 9999-12-31 UTC`.

The tool does not format its own decimals. Evidence text is the file text, so a Certbot timestamp keeps the comma from the log (`2026-09-28 03:12:44,512`). In the text report, C0 and C1 controls (ESC, CR, LF, TAB, DEL, and U+0080 through U+009F) and U+2028 and U+2029, plus bidirectional controls (U+202A through U+202E, U+2066 through U+2069, U+200E, U+200F and U+061C), in that text are written as visible escapes such as `\n` and `\u{1b}`, so one evidence line stays one line. A log quote keeps the prefix `[log] line N:`. Words in that quote, including `--force-renewal`, are the file's words, not a suggested check and not advice. `--json` keeps its own escaping, and U+2028 stays the character there.

## Exit codes

| Exit | When |
| --- | --- |
| 0 | There is an `OK_NOT_DUE` finding, and every finding other than `DANGEROUS_FORCE_BLOCKED` is `OK_NOT_DUE`. `--help` and `--version` also exit 0 when that text is written. The text ends with `exit 0: ok, not due`. |
| 1 | Some finding has a layer (scheduler, validation or deployment). The text ends with `exit 1: problem found`. |
| 2 | Any other report, including `INSUFFICIENT_EVIDENCE`. The text ends with `exit 2: insufficient evidence`. |
| 3 | Some finding is `CLIENT_UNKNOWN`, or clap rejected the arguments, or `ACME_RENEW_DOCTOR_NOW` is not a whole number of Unix seconds, or its UTC date is outside 1970-01-01 through 9999-12-31. A `CLIENT_UNKNOWN` report ends with `exit 3: usage error`. Clap and the clock variable write to stderr and leave stdout empty. If the text report or JSON cannot be written because standard output is closed or full, the tool does not panic: it writes `acme-renew-doctor: could not write output: ...` to standard error and exits 3. A usage message that cannot be written does the same. If standard error is closed or full, the message for an invalid `ACME_RENEW_DOCTOR_NOW` does not panic, and the process still exits 3. |

`CLIENT_UNKNOWN` is checked before any layer code, so that report exits 3 even when another finding has a layer.

## Exit codes and usage errors

Every row below was run against the binary, and a test keeps it that way. Stdout is empty. The message is the complete stderr. The binary adds a newline. `\n` in the last column is a newline inside the message. A leading `NAME=value` is an environment variable, not an argument.

| Case | Command | Exit | Message |
| --- | --- | --- | --- |
| Unknown client. | `--client foo` | 3 | `error: invalid value 'foo' for '--client <CLIENT>'\n  [possible values: certbot, acme.sh, auto]\n\nFor more information, try '--help'.\n` |
| Domain together with `--all`. | `example.com --all` | 3 | `error: the argument '[DOMAIN]' cannot be used with '--all'\n\nUsage: acme-renew-doctor <DOMAIN>\n\nFor more information, try '--help'.\n` |
| `--from-log` without a file. | `--from-log` | 3 | `error: a value is required for '--from-log <FILE>' but none was supplied\n\nFor more information, try '--help'.\n` |
| Unknown flag. | `--bogus` | 3 | `error: unexpected argument '--bogus' found\n\n  tip: to pass '--bogus' as a value, use '-- --bogus'\n\nUsage: acme-renew-doctor [OPTIONS] [DOMAIN]\n\nFor more information, try '--help'.\n` |
| Clock with a comma. | `ACME_RENEW_DOCTOR_NOW=1,5 example.com` | 3 | `acme-renew-doctor: ACME_RENEW_DOCTOR_NOW must be a whole number of Unix seconds, got 1,5\n` |
| Clock with a dot fraction. | `ACME_RENEW_DOCTOR_NOW=1.5 example.com` | 3 | `acme-renew-doctor: ACME_RENEW_DOCTOR_NOW must be a whole number of Unix seconds, got 1.5\n` |
| Clock that is not a number. | `ACME_RENEW_DOCTOR_NOW=not-a-timestamp example.com` | 3 | `acme-renew-doctor: ACME_RENEW_DOCTOR_NOW must be a whole number of Unix seconds, got not-a-timestamp\n` |
| Clock before 1970. | `ACME_RENEW_DOCTOR_NOW=-1 example.com` | 3 | `acme-renew-doctor: ACME_RENEW_DOCTOR_NOW must be a Unix second from 1970-01-01 through 9999-12-31 UTC, got -1\n` |
| Clock after 9999. | `ACME_RENEW_DOCTOR_NOW=253402300800 example.com` | 3 | `acme-renew-doctor: ACME_RENEW_DOCTOR_NOW must be a Unix second from 1970-01-01 through 9999-12-31 UTC, got 253402300800\n` |

## Report messages

These messages are evidence lines inside the report on stdout. Stderr is empty. The test checks that stdout contains the line and that the process exit matches. A missing file uses `cannot read PATH: NotFound`. No permission to read uses `cannot read PATH: PermissionDenied`. A directory uses `cannot read PATH: is a directory`. A fifo, device or pipe uses `cannot read PATH: not a regular file, save the output to a file first`. An empty path uses `cannot read: the path is empty`. A log larger than 268435456 bytes (256 MiB) uses `cannot read PATH: the file is N bytes, over the 268435456 byte limit`. A timer or certificate file larger than 1048576 bytes (1 MiB) uses `cannot read PATH: the file is N bytes, over the 1048576 byte limit`. A file of exactly that size is still read. If the file grows while it is being read, a log uses `cannot read PATH: the file is over the 268435456 byte limit`, and a timer or certificate file uses `cannot read PATH: the file is over the 1048576 byte limit`.

| Case | Command | Exit | Message |
| --- | --- | --- | --- |
| Log path does not exist. | `--from-log tests/fixtures/certbot/does-not-exist.log` | 2 | `cannot read tests/fixtures/certbot/does-not-exist.log: NotFound` |
| Log path is a directory. | `--from-log tests/fixtures/certbot` | 2 | `cannot read tests/fixtures/certbot: is a directory` |
| Timer file has no `Id=` line. | `--from-timer-status tests/fixtures/certs/not-a-cert.txt` | 2 | `timer status not recognised (no Id= line in systemctl show output)` |
| Certificate file has no `notAfter=`. | `--from-cert-disk tests/fixtures/certs/not-a-cert.txt` | 2 | `certificate dates not recognised (no notAfter= line in openssl x509 -dates output)` |
| `--client acme.sh`. | `--client acme.sh --from-log tests/fixtures/acme-sh/verify-error-dns01.log` | 2 | `acme.sh logs are not parsed yet (v0.1 parses Certbot logs only)` |
| `--client auto` on a non-Certbot log. | `--from-log tests/fixtures/acme-sh/verify-error-dns01.log` | 3 | `no Certbot log lines found in tests/fixtures/acme-sh/verify-error-dns01.log (expected lines like '2026-09-28 03:12:44,512:DEBUG:certbot._internal.main:...')` |

`--from-cert-live` uses the same not-recognised sentence as `--from-cert-disk`. Other evidence lines the report can print: `no timer status`, `no log given`, `no disk notAfter`, `no live notAfter`, `log read, no ACME errors found`, `ACME errors in log not recognised by the current rules`, `recognised connection error without a dedicated rule`, `no .timer block in the timer status (only <id>)`, `timer status not recognised (no certbot.timer, certbot.service or snap.certbot.renew.timer)`, `timer status is ambiguous (the same unit appears more than once with different states)`, `ACME JSON is ambiguous (the same object has type or detail more than once with different values)`, `snap.certbot.renew.timer is active: snap install, not supported yet`, `snap.certbot.renew.timer is active and certbot.timer is masked: snap install, not supported yet`, and `<id> failed (Result=<result>); the renewal ran and failed, check the Certbot log`.

`--from-timer-status`, `--from-cert-disk` and `--from-cert-live` use the same wide-encoding check as `--from-log`. A leading UTF-8 BOM is skipped and the file is still read. Any other byte sequence that is not valid UTF-8 is exit 2 with `cannot read PATH: the file is not valid UTF-8`. On the text report's `inputs:` line, a path is printed raw when it contains no character that would be escaped as a control or bidirectional mark and it does not start with `"`. Backslashes stay as written, so `C:\Users\certbot\log.txt` is unchanged. Spaces and other Unicode stay readable. Otherwise the path is wrapped in double quotes: `\` becomes `\\`, `"` becomes `\"`, a newline becomes `\n`, a carriage return becomes `\r`, a tab becomes `\t`, and any other control or bidirectional character becomes `\u{..}`. A real newline is shown as `"a\nb.log"`. The two characters `\` and `n` stay `a\nb.log`. A raw path never starts with `"`, so it cannot look like a quoted path. JSON output is unchanged and still uses JSON escaping. A path byte that is not UTF-8 is shown as U+FFFD, and the JSON stays valid. An input/output error whose kind is neither `NotFound` nor `PermissionDenied` is `cannot read PATH: other kind`. `--from-log` reads invalid UTF-8 with U+FFFD in place of each invalid sequence and adds `note: replaced N invalid UTF-8 byte` when N is 1, or `note: replaced N invalid UTF-8 bytes` otherwise. The note states the count and does not quote the bytes. A log in `UTF-16LE`, `UTF-16BE`, `UTF-32LE` or `UTF-32BE` is exit 2 with `cannot read PATH: the file is ENCODING; save it as UTF-8`. A BOM selects the encoding. Without a BOM, the first 64 bytes must show a pure NUL pattern for at least 32 bytes: `UTF-32LE` is `c 00 00 00`, `UTF-16LE` is `c 00`, `UTF-32BE` is `00 00 00 c`, `UTF-16BE` is `00 c`, and `c` is never `00`. A UTF-8 BOM (`EF BB BF`) is skipped. One NUL byte, or a few invalid bytes that do not form that pattern, is not a wide encoding. A U+FFFD in the log blocks `OK_NOT_DUE`.

When the anti-force gate drops suggested checks, the evidence is `1 suggested check blocked by the anti-force gate` or `2 suggested checks blocked by the anti-force gate`. The word matches the number. The checks the tool itself suggests pass the gate, so a normal report does not show this line.

The attempts line is printed only when the count is greater than 1: `2 attempts in this log (ACME response and Certbot summary of one attempt count as one), first on line 20`. One attempt does not add that line.

## Codes

| Code | Layer | Meaning |
| --- | --- | --- |
| `OK_NOT_DUE` | - | Disk and live notAfter are equal, more than the renewal threshold's calendar days remain, the disk certificate's notBefore (when known) is not after `now`, there is no ACME error, the service unit is not `failed`, this is not the unsupported snap-timer case, and a timer if present is loaded, enabled and active. See below for the threshold. |
| `LAYER1_TIMER_DISABLED` | scheduler | The timer's LoadState is `masked`, or it is `loaded` with UnitFileState `disabled` or `masked`. |
| `LAYER1_TIMER_NOT_FIRING` | scheduler | The timer is `loaded` and not disabled or masked, and it is not `active` or its Result is non-empty and not `success`. |
| `LAYER2_HTTP01_TIMEOUT` | validation | The chosen ACME error has type `connection`, and the detail contains `/.well-known/acme-challenge/` and `Timeout during connect`. |
| `LAYER2_HTTP01_REFUSED` | validation | The chosen ACME error has type `connection`, and the detail contains `/.well-known/acme-challenge/` and `Connection refused`. |
| `LAYER2_RATE_LIMIT` | validation | The chosen ACME error has type `rateLimited`. A `retry after` time in the detail is copied out, up to the colon that is not inside a clock (`08:14:02`). |
| `LAYER2_DNS01_TXT` | validation | Type `unauthorized` and the detail starts with `No TXT record found at _acme-challenge.` or with `Incorrect TXT record ` and contains ` found at _acme-challenge.`, or type `dns` and the detail contains ` looking up TXT for _acme-challenge.`. |
| `LAYER3_NO_RELOAD` | deployment | Disk notAfter is later than live notAfter. |
| `CLIENT_UNKNOWN` | - | `--client auto` and the file has no Certbot log line. |
| `INSUFFICIENT_EVIDENCE` | - | Not enough evidence for a layer code or for `OK_NOT_DUE`. |

Not chosen by the built-in rules: `LAYER1_PERMISSION`, `LAYER2_DNS01_CREDENTIALS`, `LAYER2_HTTP01_404_WEBROOT`, `LAYER2_HTTP01_REDIRECT`, `LAYER3_COPIED_PATH`. `DANGEROUS_FORCE_BLOCKED` is only the gate, described above.

## How a code is chosen

- At most one validation code, from the ACME error with the latest timestamp. `parse` leaves that error last. Equal timestamps, or no timestamps, keep the bottom line when the depth is the same. A nested subproblem outranks its parent at the same timestamp. A line without a timestamp takes the timestamp of the last timestamped line above it.
- The stamp is `YYYY-MM-DD HH:MM:SS,mmm` before the colon of Certbot `FILE_FMT` (`log.py` r.47): `%(asctime)s:%(levelname)s:%(name)s:%(message)s`. A logger name starting with `certbot` or `acme` marks the file as Certbot when `--client` is `auto`.
- The prefix `During secondary validation: ` (Boulder `va/va.go` r.718) is removed once before matching. The evidence line keeps the original text.
- An ACME JSON body and a Certbot summary of one attempt count as one. The attempts line uses the greater of the two counts, and only when that number is greater than 1.
- `Timeout during connect` is `LAYER2_HTTP01_TIMEOUT` (Boulder `va/va.go` r.424). `Timeout during <op>` for another single word `op`, `Network unreachable`, `Connection reset by peer` and `Timeout after connect (your server may be slow or overloaded)` (r.426-442) are `INSUFFICIENT_EVIDENCE` with `recognised connection error without a dedicated rule`.
- A failed `certbot.service` does not get its own code. That evidence line is kept on the first layer diagnosis, not on a read error, and it blocks `OK_NOT_DUE`. When there is no layer diagnosis and no read error, the line stays on the insufficient-evidence finding. Only `certbot.timer`, `certbot.service` and `snap.certbot.renew.timer` are read, and a service block is never read as the timer.
- `snap.certbot.renew.timer`, when loaded and active, does not become a timer code and does not become `OK_NOT_DUE`. The evidence says the snap install is not supported yet. If `certbot.timer` is `masked` or `disabled`, that word is included. When that snap timer is the only timer and it is not loaded and active, the result is not `OK_NOT_DUE` and the evidence names `snap.certbot.renew.timer`. A missing ActiveState or UnitFileState is not a high-confidence `LAYER1_TIMER_NOT_FIRING`.
- ActiveState `activating` or `deactivating` would be `LAYER1_TIMER_NOT_FIRING`, but a timer does not have that state in systemd v249 `src/basic/unit-def.c` r.252-258 (`timer_state_table`).
- `OK_NOT_DUE` requires a third of the disk certificate's own lifetime (notAfter minus notBefore, from the same saved `-dates` output) to remain before notAfter, capped at 30 days, or the fixed 30 days when notBefore is missing or not before notAfter. The cap matters because no publicly trusted certificate is longer-lived than Certbot's 90-day default. The Let's Encrypt FAQ says "Our default certificates are valid for 90 days.", for which a third is 30 days. The same page says "Subscribers can opt in to short-lived certificates which are valid for six days.", for which a fixed 30 days would be longer than the certificate's entire life; scaling to the real lifetime keeps `OK_NOT_DUE` reachable for those. https://letsencrypt.org/docs/faq/
- A U+FFFD in a log that was read blocks `OK_NOT_DUE`. Invalid UTF-8 is the usual source: each invalid sequence becomes one U+FFFD, and the report counts the invalid bytes.

## File formats

**Certbot log.** Lines shaped like `2026-09-28 03:12:44,512:DEBUG:certbot._internal.main:message`. A continuation line has no new timestamp. The summary fields the parser reads are `  Domain:` or `  Identifier:`, then `  Type:`, then `  Detail:`, each with two leading spaces. A blank value in any of those fields is not a summary. A summary that starts at column 0 is not read. JSON error bodies use `type` `urn:ietf:params:acme:error:...` and `detail` from the same object, in either order. Text after that object's `}` is not part of it, and a nested object keeps its own fields. Whitespace, including a newline, may sit between a key, the colon and the value. The same `type` or `detail` twice with the same value counts as one. Two different values of any JSON kind in one object are not used as a layer code. A nested subproblem outranks its parent when the timestamp is the same. The report says `ACME JSON is ambiguous (the same object has type or detail more than once with different values)`. Another object, or a Certbot summary, can still be a validation code. An object with no `urn:ietf:params:acme:error:` type stays ignored, even when a key is repeated. The match text comes from Boulder commit `1578a1d051b8` (`va/va.go`, `va/dns.go`, `ratelimits/limiter.go`). Repositories: https://github.com/certbot/certbot and https://github.com/letsencrypt/boulder. `--from-log` accepts a leading UTF-8 BOM. Invalid UTF-8 is replaced, as described under report messages. UTF-16 and UTF-32 are refused. The path must be a regular file of at most 268435456 bytes (256 MiB).

**Timer file.** `systemctl show` output, one `Key=value` line. Blocks of several units are separated by a blank line. Only `Id=certbot.timer` (the timer), `Id=certbot.service` (the service) and `Id=snap.certbot.renew.timer` (the snap timer) are read. Any other unit is ignored, even when `Id=` ends with `.timer` or `.service`. The same unit twice with the same LoadState, ActiveState, SubState, UnitFileState, Result and ConditionResult counts as one. The same key twice inside one block with a different value is the same ambiguous result; the same value twice counts as one. The same unit twice with a different state is `timer status is ambiguous (the same unit appears more than once with different states)`. A file with no `Id=` line, including `systemctl status` text, is `timer status not recognised (no Id= line in systemctl show output)`. A file that has `Id=` lines but none of those three units is `timer status not recognised (no certbot.timer, certbot.service or snap.certbot.renew.timer)`. Field names follow `org.freedesktop.systemd1(5)` and `systemctl(1)` on systemd 249. `LoadState=not-found` is not `LAYER1_TIMER_DISABLED`. The path must be a regular file of at most 1048576 bytes (1 MiB). A leading UTF-8 BOM is skipped. UTF-16 and UTF-32 are refused with the same message as a log. Other invalid UTF-8 is `the file is not valid UTF-8`.

**Certificate dates.** `openssl x509 -noout -dates` or `-enddate` (OpenSSL 3.0.2, man `openssl-x509`). The line is `notAfter=Mon DD HH:MM:SS YYYY GMT`. A day below 10 has two spaces between the month and the day, as in `notAfter=Jun  4 11:04:38 2035 GMT`. The month must be an English abbreviation. `Mei` is not recognised. The year runs from 1970 through 9999. A year outside that range is not recognised. Two `notAfter` lines that are not the same instant are not recognised. The tool does not read PEM. The path must be a regular file of at most 1048576 bytes (1 MiB). A leading UTF-8 BOM is skipped. UTF-16 and UTF-32 are refused with the same message as a log. Other invalid UTF-8 is `the file is not valid UTF-8`.

**acme.sh.** Not parsed. The synthetic sample is the public post of 14 April 2020, with the TXT values replaced by letters of the same length. https://community.letsencrypt.org/t/verify-error-during-secondary-validation-no-txt-record-found-at-acme-challenge/119427

You create the files. The collection commands printed on `INSUFFICIENT_EVIDENCE` are:

- `--from-log`: `sudo tail -n 400 /var/log/letsencrypt/letsencrypt.log`
- `--from-timer-status`: `systemctl show certbot.timer certbot.service -p Id,LoadState,ActiveState,SubState,UnitFileState,Result,ConditionResult,LastTriggerUSec,NextElapseUSecRealtime`
- `--from-cert-disk`: `sudo openssl x509 -noout -dates -in /etc/letsencrypt/live/YOUR_DOMAIN/fullchain.pem`
- `--from-cert-live`: `echo | timeout 10 openssl s_client -connect YOUR_DOMAIN:443 -servername YOUR_DOMAIN | openssl x509 -noout -dates`

`YOUR_DOMAIN` is what the catalog prints when you pass no domain, or a domain `safe_domain` rejects. Otherwise it prints the domain you passed. A domain is safe when it is at most 253 characters, has at least two labels, contains a dot, contains no `*`, and each label is 1 to 63 ASCII letters, digits or `-`, not starting or ending with `-`.

## Suggested checks

The catalog is fixed. Each command must pass an allowlist (the program and its flags) and a denylist of words. A short denylist flag is matched exactly (`-i` is denied, `-I` is not). A word or a long flag is matched without regard to ASCII case. When a finding's evidence says `certbot.service` failed, the catalog also suggests `journalctl -u certbot.service -n 50 --no-pager`, once, for that finding's code and not only for `INSUFFICIENT_EVIDENCE`. A failing check is omitted. Its command is not shown. Combined short options are checked (`ss` `K`/`D`, `journalctl` `f`, `curl` `X`/`o`/`O`/`T`/`d`/`F`/`K`/`D`/`c`/`J`/`w`, `tail` `f`/`F`). Every `curl` command must use `-q` as its first argument. A pipe is split on `|` even when there are no spaces around it. File-writing curl options such as `--trace`, `--trace-ascii`, `--stderr`, `--etag-save`, `--hsts`, `--alt-svc`, `--libcurl`, `--create-dirs` and `--output-dir` are rejected. `timeout` is allowed only as `timeout N` with N from 1 to 120, in front of `openssl s_client`.

The human report introduces them with `Next (SAFE copy-paste checks, read-only; Doctor runs nothing and will NOT renew or reload for you):` and ends that block with `Do not force a renewal: Let's Encrypt rate limits apply.` For a timeout it adds `also test from outside your network: the CA does not see what localhost sees`. For a rate limit it adds `wait until the retry-after time; repeated attempts only extend the problem`.

## JSON output

`--json` writes one object, no serde. Keys, in order: `schema_version` (1), `tool` (`name`, `version`), `input` (`domain`, `all`, `client`, `from_log`, `from_timer_status`, `from_cert_disk`, `from_cert_live`), `findings` (each `code`, `layer`, `confidence`, `evidence` of `source` and `text`), `next_checks` (each `for`, `command`, `why`, `safety` = `read-only`), then `exit_code`. `notes` sits before `exit_code` when `safe_domain` rejects the domain, or when `--from-log` replaced invalid UTF-8 bytes. A rejected domain built only from ASCII letters, digits, `-` and `.` gets `note: the domain is not a valid hostname (it needs at least two labels of 1 to 63 characters, no label may start or end with '-', and the name may be at most 253 characters); replace YOUR_DOMAIN yourself.` Any other rejected domain, including one with a `*`, gets `note: the domain contains characters that are unsafe in a shell command; replace YOUR_DOMAIN yourself.` Only one of those two notes is ever shown. The replacement text is `note: replaced N invalid UTF-8 byte` or `note: replaced N invalid UTF-8 bytes`, and it comes first. The domain in JSON is `YOUR_DOMAIN` when either note applies. Quotes, backslashes, newlines and tabs are escaped. Other C0 controls, DEL, C1 controls (U+0080 through U+009F) and the bidirectional controls listed above are written as `\uXXXX`, so they cannot move the cursor or reorder a line when the JSON is shown in a terminal. A JSON parser gives back the original character. U+2028 and U+2029 are left as the character. There is no `notes` key when the domain is safe and no invalid UTF-8 byte was replaced.

When no `--from-*` file was passed, the human report also ends with `note: live collection is not built yet; pass --from-log, --from-timer-status, --from-cert-disk and/or --from-cert-live.`

## Sources

Let's Encrypt stopped expiration emails on 4 June 2025: https://letsencrypt.org/2025/06/26/expiration-notification-service-has-ended.html

Certificate lifetime, quoted above: https://letsencrypt.org/docs/faq/

Rate-limit detail text in the synthetic rate-limit fixture points at https://letsencrypt.org/docs/rate-limits/#new-certificates-per-exact-set-of-identifiers

Certbot and Boulder, commit `1578a1d051b8`: https://github.com/certbot/certbot and https://github.com/letsencrypt/boulder

Public posts used as anonymised fixtures. The bytes in `tests/fixtures/real/` and `tests/fixtures/acme-sh/` are the cut, with names, addresses and tokens replaced. Match lines and their indentation were left as in the post. What each file does is in [tests/fixtures/README.md](../tests/fixtures/README.md).

- 12 November 2025, certbot 5.1.0, apache, lines 10-67 of the raw post: https://community.letsencrypt.org/t/certbot-renewal-fails-with-time-out-during-connect-likely-firewall-problem-warning/242890 and https://community.letsencrypt.org/raw/242890. Outcome: `LAYER2_HTTP01_TIMEOUT`, exit 1.
- March 2025, certbot 2.11.0, lines 225-274: https://community.letsencrypt.org/t/rate-limit-issue/235219. Outcome: `LAYER2_RATE_LIMIT`, exit 1, evidence `retry after 2025-03-16 02:54:35 UTC`.
- October 2020, certbot 0.31.0, lines 360-446: https://community.letsencrypt.org/t/failed-authorization-procedure-no-txt-record-found-at-acme-challenge/136973. Outcome: `LAYER2_DNS01_TXT`, exit 1.
- January 2024, certbot 2.1.0, lines 28-46, terminal output: https://community.letsencrypt.org/t/dns-01-no-txt-record-found-at-acme-challenge-domain-tld/211563. With `--client certbot`: `LAYER2_DNS01_TXT`, exit 1. With `--client auto`: `CLIENT_UNKNOWN`, exit 3.
- Lines 13-16, terminal output: https://community.letsencrypt.org/t/timeout-during-connect-likely-firewall-problem/244674. `--client auto`: `CLIENT_UNKNOWN`, exit 3. `--client certbot`: `LAYER2_HTTP01_TIMEOUT`, exit 1.
- August 2025, lines 32-34, `Domain:` has no indent in the post: https://community.letsencrypt.org/t/update-letsencrypt-certificate-fails/240423. `--client certbot`: `INSUFFICIENT_EVIDENCE`, exit 2, `log read, no ACME errors found`.
- 2023, Certbot on Windows, lines 12-39, old Boulder text `Error creating new order :: too many certificates (5) ... retry after 2023-10-04T10:49:08Z`: https://community.letsencrypt.org/t/i-made-too-many-certificated-by-accident-how-to-fix-it/206050. `--client certbot` does not recognise that text: `log read, no ACME errors found`.
- November 2023, certbot 1.21.0, lines 113-126, a helper summary, not a full log: https://community.letsencrypt.org/t/too-many-failed-authorizations/208147. `--client certbot`: `log read, no ACME errors found`.
- May 2023, lines 382-391, `systemctl status` with `Loaded: masked`, and lines 553-570, `snap.certbot.renew.timer`: https://community.letsencrypt.org/t/another-instance-of-certbot-is-already-running/197422/20. No `Id=` line, so `timer status not recognised`, exit 2.
- Super User, the code block as posted, `Active: inactive (dead) since .....; 1 months 7 days ago` (the dots are in the post): https://superuser.com/questions/1354732. No `Id=` line, exit 2.
- 14 April 2020, acme.sh log, first post, code block "Here is the complete log": https://community.letsencrypt.org/t/verify-error-during-secondary-validation-no-txt-record-found-at-acme-challenge/119427. The same prefix appears in https://community.letsencrypt.org/t/timeout-during-connect-likely-firewall-problem/244674. The log line points at https://github.com/acmesh-official/acme.sh/wiki/How-to-debug-acme.sh.

The descriptions of certease and Red Sift in the README are not verified: no page was checked for them.
