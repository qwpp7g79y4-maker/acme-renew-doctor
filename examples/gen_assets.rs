//! Writes the man page and the bash and zsh completions from the real CLI
//! definition, so they cannot drift from `--help`.
//!
//! Run from the repository root:
//!
//! ```text
//! cargo run --example gen_assets -- man
//! cargo run --example gen_assets -- completions target/completions
//! ```
//!
//! `man` rewrites `man/acme-renew-doctor.1`. `completions DIR` writes
//! `DIR/acme-renew-doctor.bash` and `DIR/_acme-renew-doctor`.
#![allow(dead_code)]

#[path = "../src/main.rs"]
mod app;

use std::path::Path;

use clap::CommandFactory;
use clap_complete::{generate_to, Shell};

fn main() -> std::io::Result<()> {
    let mut args = std::env::args().skip(1);
    let mut cmd = app::Cli::command();
    match (args.next().as_deref(), args.next(), args.next()) {
        (Some("man"), None, None) => {
            let mut buf = Vec::new();
            clap_mangen::Man::new(cmd).render(&mut buf)?;
            std::fs::create_dir_all("man")?;
            std::fs::write("man/acme-renew-doctor.1", buf)
        }
        (Some("completions"), Some(dir), None) => {
            std::fs::create_dir_all(&dir)?;
            for shell in [Shell::Bash, Shell::Zsh] {
                generate_to(shell, &mut cmd, "acme-renew-doctor", Path::new(&dir))?;
            }
            Ok(())
        }
        _ => {
            eprintln!("usage: gen_assets man | gen_assets completions DIR");
            std::process::exit(2);
        }
    }
}
