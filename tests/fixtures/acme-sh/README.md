# acme.sh log fixture

A fragment in the shape of an acme.sh log. Not a real log from this machine. The domain `example.com` and the shortened date are already like that in the source; the poster redacted them.

Every file in this directory is synthetic.

Source: [Let's Encrypt Community, "Verify error during secondary validation: No TXT record found at _acme-challenge"](https://community.letsencrypt.org/t/verify-error-during-secondary-validation-no-txt-record-found-at-acme-challenge/119427), first post, 14 April 2020, code block "Here is the complete log". The date there is already shortened to `[..., HH:MM:SS (UTC+0200)]` and the domain is already `example.com`.

## verify-error-dns01.log

Synthetic. The 14 lines from that code block, from `[..., 15:01:25 (UTC+0200)] All success, let's return` through `[..., 15:01:31 (UTC+0200)] See: https://github.com/acmesh-official/acme.sh/wiki/How-to-debug-acme.sh`. The `[..., ` is like that in the source.

The only change: the two TXT values were replaced with fake values of the same length (43 characters). One value is 43 letters A, the other is 43 letters B. Each value is the same replacement everywhere. The original values are not repeated here.

acme.sh v3.1.6 (tag commit `807da6498377ee5e0cf43a78091f46f12dc59a89`): `_printargs` (lines 212-215) writes `[$(date)] ` before each message. Line 5941: `_info "Verifying: $d"`.

Current acme.sh (v3.1.6) logs a different text for an invalid challenge: `"$d: Invalid status. Verification error details: ..."` (acme.sh line 6081). This old format from 2020 is only an example of a log that is not a Certbot log.
