# Examples

Two synthetic cases. Every file is made up: the domain is `example.com`, the
address is from the documentation range `203.0.113.0/24`, and there is no real
customer data, key or token. Each folder holds the input files, `command.txt`
(the command to run from inside that folder) and `expected-output.txt` (what the
tool prints on stdout). `tests/examples.rs` runs both commands and compares the
output byte for byte.

| Folder | Shows | Exit |
| --- | --- | --- |
| `http01-timeout/` | A disabled Certbot timer and a repeated HTTP-01 timeout in the log | 1 |
| `ok-not-due/` | An enabled timer and equal, not yet due certificate dates (clock pinned) | 0 |
