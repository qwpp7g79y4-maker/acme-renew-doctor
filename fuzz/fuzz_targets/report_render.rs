#![no_main]

use std::path::PathBuf;
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;

use acme_renew_doctor::certtime;
use acme_renew_doctor::model::{ClientKind, Snapshot};
use acme_renew_doctor::render;
use acme_renew_doctor::report_input::build_report;
use acme_renew_doctor::safe;

// Drives the real end-to-end pipeline (read files, classify, analyze,
// gate, render) on arbitrary bytes split across the domain and the four
// `--from-*` files, with a fixed clock. No input may panic the tool, both
// renders must stay free of forbidden command text, and the JSON render
// must stay syntactically valid and keep control bytes escaped.
fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > 16_384 {
        return;
    }
    let dir = fuzz_dir();
    let [domain_bytes, log_bytes, timer_bytes, disk_bytes, live_bytes] = split5(data);

    let domain = String::from_utf8_lossy(domain_bytes)
        .chars()
        .take(300)
        .collect::<String>();

    let snapshot = Snapshot {
        domain: if domain.is_empty() { None } else { Some(domain) },
        all: false,
        client: ClientKind::Auto,
        from_log: Some(write(dir, "log", log_bytes)),
        from_timer_status: Some(write(dir, "timer", timer_bytes)),
        from_cert_disk: Some(write(dir, "disk", disk_bytes)),
        from_cert_live: Some(write(dir, "live", live_bytes)),
    };

    let now = certtime::from_unix_seconds(1_791_273_600);
    let mut report = build_report(snapshot, now);
    let suggested = safe::checks_for(&report);
    let checks = safe::apply_gate(&mut report, suggested);

    let exit_code = report.exit_status().code();
    assert!((0..=3).contains(&exit_code), "exit code {exit_code}");

    let human = render::human(&report, &checks);
    let json = render::json(&report, &checks);

    assert!(
        !human.as_bytes().contains(&0x1b),
        "raw ESC in the human report\n{human}"
    );
    assert!(!json.as_bytes().contains(&0x1b), "raw ESC in the JSON\n{json}");

    let human_violations = safe::output_violations(&human);
    assert!(
        human_violations.is_empty(),
        "{human_violations:?}\n{human}"
    );
    let json_violations = safe::output_violations(&json);
    assert!(json_violations.is_empty(), "{json_violations:?}\n{json}");

    if let Err(err) = serde_json::from_str::<serde_json::Value>(&json) {
        panic!("render::json produced invalid JSON: {err}\n{json}");
    }
});

fn fuzz_dir() -> &'static PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!(
            "acme-renew-doctor-fuzz-report-render-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create fuzz temp dir");
        dir
    })
}

fn write(dir: &PathBuf, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).expect("write fuzz temp file");
    path
}

fn split5(data: &[u8]) -> [&[u8]; 5] {
    let n = data.len();
    let chunk = n / 5;
    let mut start = 0;
    let mut parts: [&[u8]; 5] = [&[]; 5];
    for (index, slot) in parts.iter_mut().enumerate() {
        let end = if index == 4 { n } else { start + chunk };
        *slot = &data[start..end];
        start = end;
    }
    parts
}
