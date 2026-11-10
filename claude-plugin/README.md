# ACME Renew Doctor

This plugin helps Claude use the `acme-renew-doctor` command-line tool. The tool explains why an ACME certificate renewal failed or never ran. It reads files you already saved, such as a Certbot log, timer status, or certificate dates. It does not renew a certificate, reload a service, or talk to the network.

## Use it

Install the tool with Rust 1.85 or newer: `cargo install --locked acme-renew-doctor`. Ask Claude why a Let's Encrypt or Certbot renewal failed, and pass the files you have. Claude will run the tool and explain the report. To try it without your own log, `acme-renew-doctor --example` writes a synthetic log named `example-log.txt`.

## Data

The tool is fully offline: no network, no API key, and no telemetry. It only reads the paths you pass (or standard input when a path is `-`). Evidence text is taken from those files. This plugin does not send data to any service. The plugin itself stores nothing.
