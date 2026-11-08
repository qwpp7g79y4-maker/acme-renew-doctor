//! Explain why a Certbot renewal failed, or never ran, from files the caller already has.
//!
//! The library reads those files and builds a [`model::Report`]. A finding is a fixed
//! code plus the evidence for it.

pub mod certbot_log;
pub mod certtime;
pub mod model;
pub mod render;
pub mod report_input;
pub mod rules;
pub mod safe;
pub mod timer;
