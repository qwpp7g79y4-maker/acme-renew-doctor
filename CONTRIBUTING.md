# Contributing

Thanks for your interest in acme-renew-doctor.

## Building and testing

```sh
cargo build
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

These checks must pass before a change is merged. Test fixtures must be synthetic, or anonymised copies of a public post. Never add a real secret, a real account id, or a live certificate.

## Commit messages

Commit messages are short English sentences that say what changed, for example `Escape controls in file text shown on the report`.

## Contact

PEPAI, pep_ai@icloud.com
