//! Explain why a Certbot renewal failed, or never ran, from files the caller already has.
//!
//! The library reads those files and builds a [`model::Report`]. A finding is a fixed
//! code plus the evidence for it.
//!
//! The command-line tool calls [`install_sigint_handler`] on startup. On Linux
//! x86_64 a caught SIGINT is recorded ([`sigint_caught`]) and the tool exits
//! [`EXIT_SIGINT`] (130) instead of publishing a half-written report. Statuses
//! 0, 1, 2 and 3 stay as they are. Other targets keep the default disposition.

mod interrupt;

pub use interrupt::with_sigint_blocked;
pub use interrupt::EXIT_SIGINT;

/// Installs the SIGINT handler the command-line tool uses.
///
/// On Linux x86_64 a caught SIGINT is recorded and a blocked read returns.
/// Other targets keep the default disposition. Call [`sigint_caught`] before
/// publishing a report.
pub fn install_sigint_handler() {
    interrupt::install();
}

/// Whether a caught SIGINT asked the process to stop.
pub fn sigint_caught() -> bool {
    interrupt::interrupted()
}

pub mod certbot_log;
pub mod certtime;
pub mod model;
pub mod render;
pub mod report_input;
pub mod rules;
pub mod safe;
pub mod timer;
