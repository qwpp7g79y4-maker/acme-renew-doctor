# Public log extracts

Fragments from public forum posts, anonymised. The bytes of the `.log` and `.txt` files are the cut source. This note says, for each file, where it came from, what was replaced, and what the tool makes of it. Expected is the outcome the checks look for. Recorded is the outcome of `acme-renew-doctor` on these files (clock `ACME_RENEW_DOCTOR_NOW=1791273600`, domain `example.com`). The e2 and e4 files are recorded outcomes. Their result is fixed, and it is not a success criterion.

Every file in this directory is synthetic.

Where this note says "match lines and indentation left as they were", the lines the tool matches (detail, `Domain:`/`Type:`/`Detail:`, `Id=`/`LoadState=` and the error text) were not rewritten, and their indentation is that of the source.

## e1-242890-http01-timeout.log

Synthetic. Source: [post #1](https://community.letsencrypt.org/t/certbot-renewal-fails-with-time-out-during-connect-likely-firewall-problem-warning/242890), 12 November 2025, certbot 5.1.0, apache. Lines 10-67 of the [raw post](https://community.letsencrypt.org/raw/242890).

Replaced: domain `lawlec.korea.ac.kr` to `example.com`, IP to `203.0.113.10`, challenge token to T's of the same length, Replay-Nonce to N's of the same length, account `1196656447` to `1000000001`, authz id `611509808046` to `600000000001`, chall suffix to `AAAAAA`. Otherwise character for character. Match lines and indentation left as they were.

- Expected (`--client auto`): `LAYER2_HTTP01_TIMEOUT`, exit 1, evidence contains `Timeout during connect`.
- Recorded: `LAYER2_HTTP01_TIMEOUT`, exit 1, evidence contains `Timeout during connect`.

## e3-235219-rate-limit.log

Synthetic. Source: [post #1](https://community.letsencrypt.org/t/rate-limit-issue/235219), March 2025, certbot 2.11.0. Lines 225-274 of the raw post.

Replaced: Boulder requester `2283170396` to `1000000002`, Replay-Nonce to N's of the same length. Otherwise character for character, including the traceback. Match lines and indentation left as they were.

- Expected (`--client auto`): `LAYER2_RATE_LIMIT`, exit 1, evidence line `retry after 2025-03-16 02:54:35 UTC`.
- Recorded: `LAYER2_RATE_LIMIT`, exit 1, evidence line `retry after 2025-03-16 02:54:35 UTC`.

## e5-136973-dns01.log

Synthetic. Source: [post #1](https://community.letsencrypt.org/t/failed-authorization-procedure-no-txt-record-found-at-acme-challenge/136973), October 2020, certbot 0.31.0, dns-rfc2136, staging. Lines 360-446 of the raw post.

The 4 spaces of markdown code indentation at the start of each line were removed (they belong to the forum, not to the log). Also replaced: domain `menke.pl` to `example.com`, protected to A's of the same length, signature to S's of the same length, Replay-Nonce to N's, token to T's, account `16326180` to `10000003`, authz `141367042` to `100000004`, chall suffix to `AAAAAA`. Match lines and the remaining indentation left as they were. The summary has no two-space indent (`Domain: example.com` after `certbot.reporter`), the old Certbot form. The JSON body has `unauthorized` and `No TXT record found`.

- Expected (`--client auto`): `LAYER2_DNS01_TXT`, exit 1.
- Recorded: `LAYER2_DNS01_TXT`, exit 1.

## e5-211563-terminal.txt

Synthetic. Source: [post #1](https://community.letsencrypt.org/t/dns-01-no-txt-record-found-at-acme-challenge-domain-tld/211563), January 2024, certbot 2.1.0, manual. Lines 28-46 of the raw post. This is terminal output of `certbot renew`, not a `letsencrypt.log`.

Replaced: `adopteunmanchot.com` to `example.com`, `root@keewi` to `root@host`. The line mangled by the terminal (`Domain:` and `Type:` on one line with many spaces) and the long spaces were left character for character. Match lines and indentation left as they were. Lines with `  Domain:` / `  Type:` / `  Detail: No TXT record found` are indented.

- Expected (the check, `--client certbot`): `LAYER2_DNS01_TXT`, exit 1.
- Recorded (`--client certbot`): `LAYER2_DNS01_TXT`, exit 1.
- Recorded (`--client auto`): `CLIENT_UNKNOWN`, exit 3. A recorded outcome, not a success criterion: there is no Certbot `FILE_FMT` line.

## e2-244674-secondary-timeout.txt

Synthetic. Source: [post #1](https://community.letsencrypt.org/t/timeout-during-connect-likely-firewall-problem/244674), lines 13-16 (code block). Terminal output, webroot.

Unchanged: the poster had already replaced the domain, IP and token with `xxxxxx` / `XXX` / `YYYY`. Match lines and indentation left as they were. The summary is indented (`  Domain:`, `  Type:`, `  Detail:`) and the detail starts with `During secondary validation:`.

No success criterion.

- Recorded (`--client auto`): `CLIENT_UNKNOWN`, exit 3.
- Recorded (`--client certbot`): `LAYER2_HTTP01_TIMEOUT`, exit 1. A recorded outcome, not a success criterion.

## e2-240423-secondary-timeout.txt

Synthetic. Source: [post #3](https://community.letsencrypt.org/t/update-letsencrypt-certificate-fails/240423), August 2025, lines 32-34. The indentation of `Domain:` is missing in the source itself.

Replaced: `www.broesecke.eu` to `www.example.com`, IP to `203.0.113.10`, token to T's of the same length. Otherwise character for character. Match lines and indentation left as they were.

No success criterion.

- Recorded (`--client auto`): `CLIENT_UNKNOWN`, exit 3.
- Recorded (`--client certbot`): `INSUFFICIENT_EVIDENCE`, exit 2, evidence `log read, no ACME errors found`. The summary starts with `Domain:` without the two spaces, so the tool does not read it. A recorded outcome, not a success criterion.

## e4-206050-rate-limit-old.txt

Synthetic. Source: [post #1](https://community.letsencrypt.org/t/i-made-too-many-certificated-by-accident-how-to-fix-it/206050), 2023, Certbot on Windows, lines 12-39. Terminal output of `certbot renew` with the old Boulder text `Error creating new order :: too many certificates (5) ... retry after 2023-10-04T10:49:08Z`.

Replaced: `nimoweb.ddns.net` to `example.com`. Otherwise character for character. Match lines and indentation left as they were.

No success criterion.

- Recorded (`--client auto`): `CLIENT_UNKNOWN`, exit 3.
- Recorded (`--client certbot`): `INSUFFICIENT_EVIDENCE`, exit 2, evidence `log read, no ACME errors found`. The old Boulder text in terminal output is not recognised. A recorded outcome, not a success criterion.

## e4-208147-failed-authz-old.txt

Synthetic. Source: [post #11](https://community.letsencrypt.org/t/too-many-failed-authorizations/208147), November 2023, certbot 1.21.0, lines 113-126. `detail` lines from the log, summarised by a helper (rg305), not a full log.

Replaced: `81.56.56.63` to `203.0.113.10`, `pinbikets.ddns.net` to `example.com`, tokens to T's of the same length. Otherwise character for character. Match lines and indentation left as they were.

No success criterion.

- Recorded (`--client auto`): `CLIENT_UNKNOWN`, exit 3.
- Recorded (`--client certbot`): `INSUFFICIENT_EVIDENCE`, exit 2, evidence `log read, no ACME errors found`. A recorded outcome, not a success criterion.

## e6-197422-status-masked.txt

Synthetic. Source: [197422/20](https://community.letsencrypt.org/t/another-instance-of-certbot-is-already-running/197422/20), May 2023, lines 382-391. `systemctl status certbot.timer` with `Loaded: masked`.

Replaced: hostname `ubuntu-8gb-nbg1-1` to `host`. Otherwise character for character. Match lines and indentation left as they were. This is not `systemctl show` (no `Id=` lines).

- Expected: exit 2, `timer status not recognised`.
- Recorded: `INSUFFICIENT_EVIDENCE`, exit 2, `timer status not recognised`.

## e6-197422-status-snap.txt

Synthetic. Source: the same topic, lines 553-570. `systemctl status snap.certbot.renew.timer` (active, enabled) and `systemctl list-unit-files | grep cert` (`certbot.timer` masked).

Replaced: hostname to `host`. Otherwise character for character. Match lines and indentation left as they were. No `Id=` lines.

- Expected: exit 2, `timer status not recognised`.
- Recorded: `INSUFFICIENT_EVIDENCE`, exit 2, `timer status not recognised`.

## e6-superuser-1354732-status-inactive.txt

Synthetic. Source: [Super User 1354732, answer 1424486](https://superuser.com/questions/1354732) (sanmai). The code block is character for character: enabled, but `Active: inactive (dead) since .....; 1 months 7 days ago` (the dots are like that in the source).

Nothing replaced. Match lines and indentation left as they were. No `Id=` lines.

- Expected: exit 2, `timer status not recognised`.
- Recorded: `INSUFFICIENT_EVIDENCE`, exit 2, `timer status not recognised`.

## e6-show-masked.txt

Synthetic. Constructed: the status "masked" turned into the shape of `systemctl show -p Id,LoadState,ActiveState,SubState,UnitFileState,Result,ConditionResult,LastTriggerUSec,NextElapseUSecRealtime`.

Real reference for masked (run on pop-os, systemd 249, 6 October 2026, read only): `systemctl show alsa-utils.service -p ...` gave `Result=success`, `Id=alsa-utils.service`, `LoadState=masked`, `ActiveState=inactive`, `SubState=dead`, `UnitFileState=masked`, `ConditionResult=no`. A masked unit has `LoadState=masked`, not `loaded`. This file puts that shape on `Id=certbot.timer`.

- Expected: `LAYER1_TIMER_DISABLED`, exit 1. Evidence contains `LoadState=masked`, `UnitFileState=masked` and `ActiveState=inactive`.
- Recorded: `LAYER1_TIMER_DISABLED`, exit 1, with those three evidence lines.

## e6-show-enabled-inactive.txt

Synthetic. Constructed in the same `systemctl show` shape: `Id=certbot.timer`, `LoadState=loaded`, `ActiveState=inactive`, `SubState=dead`, `UnitFileState=enabled`, `Result=success`, `ConditionResult=yes`.

- Expected: `LAYER1_TIMER_NOT_FIRING`, exit 1.
- Recorded: `LAYER1_TIMER_NOT_FIRING`, exit 1.

## e6-show-snap.txt

Synthetic. Constructed in the same `systemctl show` shape, two blocks. First `certbot.timer` with `LoadState=masked`, `UnitFileState=masked`, `ActiveState=inactive`. Then `snap.certbot.renew.timer` with `LoadState=loaded`, `ActiveState=active`, `UnitFileState=enabled`.

- Expected: no `LAYER1` code, no `OK_NOT_DUE`, exit 2, evidence line `snap.certbot.renew.timer is active and certbot.timer is masked: snap install, not supported yet`. Also when `--from-cert-disk` and `--from-cert-live` are both `tests/fixtures/certs/dates-current.txt`.
- Recorded: `INSUFFICIENT_EVIDENCE`, exit 2, that evidence line, no `LAYER1_TIMER_DISABLED`, no `LAYER1_TIMER_NOT_FIRING`, no `OK_NOT_DUE`. The same with the two certificate-date files.
