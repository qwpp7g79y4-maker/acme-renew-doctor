# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |

Security fixes go into the latest release only.

## Reporting a vulnerability

Please report security problems privately, not in a public issue: open the **Security** tab of this repository and choose **Report a vulnerability**. If that is not possible, e-mail pep_ai@icloud.com. Examples are file content or a path that can add a fake line or a terminal escape to the report, a way to make acme-renew-doctor read, write, run or hang on something it should refuse, or a suggested check that could change a system.

Please include:

- the acme-renew-doctor version (`acme-renew-doctor --version`) and your operating system;
- the exact command;
- minimal synthetic input files that reproduce the problem, never real logs or certificates;
- what acme-renew-doctor printed and what you expected.

We aim to respond within 7 days (best effort). Once a fix is released, the report can be credited in the changelog if you wish.
