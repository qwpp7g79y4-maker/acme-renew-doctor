# Certbot log fixtures

Fragments in the shape of `letsencrypt.log`. Not real logs, and no real domains or tokens. Repositories: [certbot/certbot](https://github.com/certbot/certbot) and [letsencrypt/boulder](https://github.com/letsencrypt/boulder) commit `1578a1d051b8`.

The line numbers below were read in those sources. Where only a function is named, that function is named and no line number is invented.

Every file in this directory is synthetic.

For every fixture in this directory the log line format is `FILE_FMT = "%(asctime)s:%(levelname)s:%(name)s:%(message)s"` from `certbot/src/certbot/_internal/log.py` line 47. A message of several lines continues without a new timestamp. Python asctime looks like `2026-09-28 03:12:44,512`.

Not from a source, and illustrative in every fixture: the timestamps, the IP address `203.0.113.10` (documentation range), the fake tokens and fake URL paths, the exact header lines and the indentation of the JSON.

## http01-timeout.log

Synthetic. Certbot v5.0.0 form of the summary: `  Domain: example.com`.

- `acme/src/acme/client.py` line 758 on Certbot main, line 764 in v5.0.0: `Received response:` then `HTTP 200`, headers, a blank line, the body.
- `certbot/src/certbot/_internal/auth_handler.py` line 175: `Challenge failed for domain example.com`.
- `certbot/src/certbot/_internal/auth_handler.py` line 379 on main, line 376 in v5.0.0: `http-01 challenge for example.com`.
- `certbot/src/certbot/_internal/display/obj.py` line 75: `Notifying user: `; the text is on the following lines.
- `certbot/src/certbot/_internal/auth_handler.py` functions `_report_failed_authzrs` and `_generate_failed_chall_msg`: the sentence about webroot, `  Domain:`, `  Type:   connection`, `  Detail:`.
- Certbot v5.0.0 `certbot/src/certbot/_internal/plugins/webroot.py` lines 86-90 (`auth_hint`): the `Hint:` line, with "listed domains".
- Authorization JSON in the shape of RFC 8555 §7.1.4, with `type` `http-01` and `dns` next to the ACME error.
- Boulder `va/va.go` lines 401-433, commit `1578a1d051b8`: detail `Timeout during connect (likely firewall problem)`, problem type `urn:ietf:params:acme:error:connection`, status 400.

## http01-connection-refused.log

Synthetic. Same shape as the timeout fixture. The summary uses the Certbot main form `  Identifier: example.com` instead of `  Domain:`.

Same Certbot sources as `http01-timeout.log`, except the Hint line: that uses the main text ("listed identifiers"). The detail comes from Boulder `va/va.go` lines 401-433, commit `1578a1d051b8`: `Connection refused`, same problem type `urn:ietf:params:acme:error:connection` and status 400.

## rate-limit-exact-set.log

Synthetic.

- `acme/src/acme/client.py` `_send_request`: `logger.debug('Sending POST request to %s:\n%s', url, data)`. The debug line is `Sending POST request to https://acme-v02.api.letsencrypt.org/acme/new-order:` (DEBUG `acme.client`). The JWS body after the newline in that format string is not included here: it does not belong to the error type.
- `acme/src/acme/client.py` line 758 on Certbot main, line 764 in v5.0.0: `Received response:`, `HTTP 429`, headers (`Content-Type: application/problem+json`, `Retry-After`), a blank line, the body.
- JSON problem `{"type", "detail", "status": 429}` with type `urn:ietf:params:acme:error:rateLimited`.
- Boulder `ratelimits/limiter.go` line 169, `errors/errors.go` line 250, `wfe2/wfe.go` line 2493 (`probs.RateLimited(err.Error())`), commit `1578a1d051b8`. No prefix `Error creating new order :: `.
- `certbot/src/certbot/_internal/log.py` lines 373-376: `An unexpected error occurred:` and then an ERROR line with only the detail.
- `certbot/src/certbot/_internal/display/util.py` `describe_acme_error` joins title and detail with ` :: `. This fixture logs only the detail, which is what that ERROR line carries.

The retry-after time is now plus the wait according to Boulder `ratelimits/limiter.go` line 103; here the upper bound of 7 days. Assumption: the Certbot log clock (local time) is UTC here. `Retry-After: 604800` matches those 7 days. The rest of the detail is the text of those Boulder lines.

## http01-timeout-repeated.log

Synthetic. Two attempts, on 2026-09-28 and 2026-09-29, each with the pattern of `http01-timeout.log`: JSON response, `Challenge failed`, `Notifying user` with `  Domain:` and the v5.0.0 Hint ("listed domains"). Both attempts have the same IP, the same token and therefore the same detail, like a repeated renew with the same error.

Same sources as `http01-timeout.log`. The timestamps of the second attempt are illustrative. `line` belongs to the second attempt, `first_line` to the first; `occurrences` counts every JSON hit and every summary.

Certbot rotates `letsencrypt.log` on every run (Certbot v5.0.0 `certbot/src/certbot/_internal/log.py` lines 165-173, `RotatingFileHandler` + `doRollover`). Two attempts in this one file are therefore constructed, as when files are concatenated (for example `letsencrypt.log.1` followed by `letsencrypt.log`). The fixture itself is not a real rotated log.

## dns01-no-txt-record.log

Synthetic. Same shape as `http01-timeout.log` (Certbot v5.0.0 form `  Domain: example.com`), for DNS-01 with the manual plugin. No IP prefix and no `Fetching`: those belong to HTTP-01 (Boulder `va/va.go` line 401 and line 408), not to DNS-01.

- Authorization JSON in the shape of RFC 8555 §7.1.4, challenge `type` `dns-01`, `status` `invalid`.
- Boulder `va/dns.go` line 171, commit `1578a1d051b8`: `No TXT record found at %s`. `challengeSubdomain` (line 159) is `<prefix>.<domain>` with prefix `_acme-challenge`.
- Boulder `va/va.go` lines 447-448: `berrors.Unauthorized` becomes `probs.Unauthorized`.
- Boulder `probs/probs.go` line 41 `UnauthorizedProblem = "unauthorized"`, lines 284-288 HTTP status 403, line 48 `ErrorNS = "urn:ietf:params:acme:error:"`.
- `acme/src/acme/client.py` line 758 on Certbot main, line 764 in v5.0.0: `Received response:`, `HTTP 200`, headers, a blank line, the body.
- `certbot/src/certbot/_internal/auth_handler.py` line 175: `Challenge failed for domain example.com`.
- `certbot/src/certbot/_internal/auth_handler.py` line 379 on main, line 376 in v5.0.0: `dns-01 challenge for example.com`.
- `certbot/src/certbot/_internal/display/obj.py` line 75: `Notifying user: `; the text is on the following lines.
- `certbot/src/certbot/_internal/auth_handler.py` lines 310-312: `Certbot failed to authenticate some domains (authenticator: manual). The Certificate Authority reported these problems:`
- line 476 in v5.0.0 (line 479 on main, there with `  Identifier:`): `  Domain:`, `  Type:   unauthorized`, `  Detail:`.
- lines 319-320: the `Hint:` line.
- `certbot/src/certbot/_internal/plugins/manual.py` lines 130-162: `auth_hint` without `--manual-auth-hook` and with DNS-01. The authenticator name is then `manual`.

Illustrative, not from a source: the time (2026-09-30), the domain `example.com`, the fake token, the fake URL and the nonce.

## dns01-incorrect-txt-record.log

Synthetic. Same shape as `dns01-no-txt-record.log`.

- Boulder `va/dns.go` lines 189-190, commit `1578a1d051b8`: `Incorrect TXT record %q%s found at %s`. `%q` puts ordinary quotes around the value. In the JSON body those quotes are escaped; in the Certbot summary they are literal, as Go's `%q` produces them.
- `andMore` (lines 185-187) is ` (and %d more)` when there is more than one record. This fixture has one record, so that addition is absent.
- `invalidRecord` is cut at 100 characters plus `...` (lines 181-183). The TXT value here is shorter, so there is no cut.
- Same Unauthorized path (status 403) and the same Certbot lines as `dns01-no-txt-record.log`.

Illustrative, not from a source: the time (2026-09-30), the domain `example.com`, the fake token, the fake URL, the nonce and the TXT value `fakeOldTxtValue000000000000000000000000000`.

## dns01-no-txt-secondary.log

Synthetic. Constructed from `dns01-no-txt-record.log`. Only the prefix `During secondary validation: ` was added, in the JSON `detail` and in the summary `  Detail:`. Otherwise the same text, character for character. Source: Boulder `va/va.go` line 718, commit `1578a1d051b8`.

Real examples of this prefix are on the Let's Encrypt forum: <https://community.letsencrypt.org/t/timeout-during-connect-likely-firewall-problem/244674> and <https://community.letsencrypt.org/t/verify-error-during-secondary-validation-no-txt-record-found-at-acme-challenge/119427>. Public copies are under `tests/fixtures/real/`.
