# Fixtures

Every file under this directory is synthetic: written or cut for a test, not taken from this machine. Public posts were anonymised (domain, address, token and account replaced). None of them contains a real secret. The subdirectory notes say where a shape came from.

## acme-sh/verify-error-dns01.log

Synthetic acme.sh log. An anonymised copy of a public post from 14 April 2020. The two TXT values were replaced with letters of the same length (43). Not parsed: `--client auto` is `CLIENT_UNKNOWN`, `--client acme.sh` is `INSUFFICIENT_EVIDENCE`.

## certbot/dns01-incorrect-txt-record.log

Synthetic Certbot log. DNS-01, Boulder text `Incorrect TXT record`, type `unauthorized`. One fake TXT value, shorter than the 100-character cut, so no `...`.

## certbot/dns01-no-txt-record.log

Synthetic Certbot log. DNS-01, Boulder text `No TXT record found at`, Certbot v5.0.0 summary with `  Domain:`. No IP prefix and no `Fetching`, because those belong to HTTP-01.

## certbot/dns01-no-txt-secondary.log

Synthetic Certbot log. The same text as `dns01-no-txt-record.log`, plus the prefix `During secondary validation: ` on the JSON detail and on `  Detail:`.

## certbot/http01-connection-refused.log

Synthetic Certbot log. HTTP-01, detail `Connection refused`. The summary uses the main-branch form `  Identifier:`.

## certbot/http01-timeout-repeated.log

Synthetic Certbot log. Two constructed attempts, 2026-09-28 and 2026-09-29, same detail. Not a real rotated log. The winning line is the later attempt.

## certbot/http01-timeout.log

Synthetic Certbot log. HTTP-01, detail `Timeout during connect (likely firewall problem)`, Certbot v5.0.0 summary with `  Domain:`.

## certbot/rate-limit-exact-set.log

Synthetic Certbot log. Type `rateLimited`, HTTP 429, a retry-after time, no `Error creating new order :: ` prefix. The JWS body after the POST debug line is not included.

## certs/dates-current.txt

Synthetic `openssl x509 -noout -dates` output. Disk and live are the same notAfter, more than 30 days after 2026-10-06. The span is 90 days minus 1 second.

## certs/dates-disk-renewed.txt

Synthetic `openssl x509 -noout -dates` output. The disk notAfter is later than `dates-live-old.txt`. The span is 90 days minus 1 second. The dates themselves are made up.

## certs/dates-live-old.txt

Synthetic `openssl x509 -noout -dates` output. The live notAfter is earlier than `dates-disk-renewed.txt`.

## certs/disk-enddate-new.txt

Synthetic `openssl x509 -noout -enddate` line. The date is after `live-enddate-old.txt`.

## certs/enddate-far.txt

Synthetic `openssl x509 -noout -enddate` line. The date is more than 30 days after 2026-10-06.

## certs/live-enddate-old.txt

Synthetic `openssl x509 -noout -enddate` line. The date is before `disk-enddate-new.txt`.

## certs/not-a-cert.txt

Synthetic stderr text from openssl when the path is not a certificate. The path in the text is `/etc/letsencrypt/live/example.com/fullchain.pem`. There is no `notAfter=` line.

## real/e1-242890-http01-timeout.log

Synthetic test copy of a public post (12 November 2025, certbot 5.1.0). Domain, address, token and account were replaced. Match lines were not rewritten. Outcome: `LAYER2_HTTP01_TIMEOUT`, exit 1.

## real/e2-240423-secondary-timeout.txt

Synthetic test copy of a public terminal snippet (August 2025). `Domain:` has no indent in the post. `--client auto` is `CLIENT_UNKNOWN`. `--client certbot` finds no ACME error.

## real/e2-244674-secondary-timeout.txt

Synthetic test copy of a public terminal snippet. The poster had already replaced the domain, address and token. The detail starts with `During secondary validation:`. `--client certbot` is `LAYER2_HTTP01_TIMEOUT`.

## real/e3-235219-rate-limit.log

Synthetic test copy of a public post (March 2025, certbot 2.11.0). The requester id and nonce were replaced. Outcome: `LAYER2_RATE_LIMIT`, evidence `retry after 2025-03-16 02:54:35 UTC`.

## real/e4-206050-rate-limit-old.txt

Synthetic test copy of public terminal output (2023, Certbot on Windows). The old Boulder text `Error creating new order :: ...` is not recognised. `--client certbot` is `INSUFFICIENT_EVIDENCE`.

## real/e4-208147-failed-authz-old.txt

Synthetic test copy of a helper's summary of detail lines (November 2023), not a full log. `--client certbot` finds no ACME error.

## real/e5-136973-dns01.log

Synthetic test copy of a public post (October 2020, certbot 0.31.0). The four-space markdown indent was removed. Outcome: `LAYER2_DNS01_TXT`, exit 1.

## real/e5-211563-terminal.txt

Synthetic test copy of public terminal output (January 2024), not a letsencrypt.log. `--client certbot` is `LAYER2_DNS01_TXT`. `--client auto` is `CLIENT_UNKNOWN`.

## real/e6-197422-status-masked.txt

Synthetic test copy of public `systemctl status` text with `Loaded: masked`. There is no `Id=` line, so the timer status is not recognised.

## real/e6-197422-status-snap.txt

Synthetic test copy of public `systemctl status` text for `snap.certbot.renew.timer`. There is no `Id=` line.

## real/e6-show-enabled-inactive.txt

Synthetic `systemctl show` block: `certbot.timer` loaded, inactive, enabled, Result `success`. Outcome: `LAYER1_TIMER_NOT_FIRING`.

## real/e6-show-masked.txt

Synthetic `systemctl show` block: `Id=certbot.timer`, `LoadState=masked`. The shape follows a masked unit read on 6 October 2026 (systemd 249), with the id replaced. Outcome: `LAYER1_TIMER_DISABLED`.

## real/e6-show-snap.txt

Synthetic `systemctl show` with two blocks: masked `certbot.timer`, then an active `snap.certbot.renew.timer`. No timer code and no `OK_NOT_DUE`.

## real/e6-superuser-1354732-status-inactive.txt

Synthetic test copy of a public `systemctl status` block. Nothing was replaced. The dots in `since .....` are in the post. No `Id=` line.

## timer/certbot-service-only-failed.txt

Synthetic `systemctl show` block for `certbot.service` only, Result `exit-code`, ActiveState `failed`. No timer block.

## timer/certbot-timer-disabled.txt

Synthetic `systemctl show` for `certbot.timer`, UnitFileState `disabled`, ActiveState `inactive`. The empty next and last times follow a real disabled-timer shape. The id is made up.

## timer/certbot-timer-enabled-inactive.txt

Synthetic `systemctl show` for `certbot.timer`: enabled, inactive, ConditionResult `no`. The id replaces `apport-autoreport.timer` from a read on 6 October 2026.

## timer/certbot-timer-enabled.txt

Synthetic `systemctl show` for an enabled, active `certbot.timer`. The clock values are made up. The shape follows `apt-daily.timer` as read on 6 October 2026.

## timer/certbot-timer-failed.txt

Synthetic `systemctl show` for a failed timer: ActiveState `failed`, Result `resources`, UnitFileState `enabled`. No real failed timer was available, so the values come from the systemd 249 tables. The last-trigger time is made up.

## timer/certbot-timer-ok-service-failed.txt

Synthetic `systemctl show` with two blocks: an enabled active `certbot.timer`, then a failed `certbot.service`. The service id replaces a unit that was on the machine where the shape was read.
