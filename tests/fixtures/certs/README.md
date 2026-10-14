# Certificate date fixtures

Output of `openssl x509 -noout -enddate -in <cert>` (OpenSSL 3.0.2, man `openssl-x509` `-enddate`). One line:

`notAfter=<Mon> <day, right-aligned in 2 characters> <HH:MM:SS> <year> GMT`

A day below 10 has two spaces between the month and the day. Real examples: `notAfter=Jun  4 11:04:38 2035 GMT` and `notAfter=Dec 31 09:37:37 2030 GMT`. The live certificate date has the same format (`s_client` output passed through the same `openssl x509 -noout -enddate`).

Every file in this directory is synthetic. The dates are illustrative. `disk-enddate-new.txt` is later than `live-enddate-old.txt`. `enddate-far.txt` is more than 30 days after 2026-10-06.

## openssl x509 -noout -dates

Shape of `openssl x509 -noout -dates`: two lines, the day right-aligned in 2 characters (a day below 10 has two spaces between the month and the day). Source: man `openssl-x509` (options `-dates`, `-startdate`, `-enddate`) and this output of OpenSSL 3.0.2 (15 Mar 2022), read only:

- `/etc/ssl/certs/ISRG_Root_X1.pem`: `notBefore=Jun  4 11:04:38 2015 GMT` and `notAfter=Jun  4 11:04:38 2035 GMT`
- `/etc/ssl/certs/ACCVRAIZ1.pem`: `notBefore=May  5 09:37:37 2011 GMT` and `notAfter=Dec 31 09:37:37 2030 GMT`
- `/etc/hostname` is not a certificate. Both lines go to stderr and openssl exits 1: `Could not read certificate from /etc/hostname` and `Unable to load certificate`. `not-a-cert.txt` is that text with the path replaced by `/etc/letsencrypt/live/example.com/fullchain.pem`, as when someone saved stderr with the output.

`dates-disk-renewed.txt`, `dates-live-old.txt` and `dates-current.txt` use that shape. The dates themselves are illustrative. Each pair is 90 days minus 1 second: that is the lifetime of a Let's Encrypt certificate (https://letsencrypt.org/docs/faq/: "Our default certificates are valid for 90 days."). The same page says: "Subscribers can opt in to short-lived certificates which are valid for six days." The fixtures follow the default of 90 days.
