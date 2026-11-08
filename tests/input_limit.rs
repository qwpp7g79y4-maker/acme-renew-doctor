//! One byte over the documented log limit is exit 2.
//! The file is sparse, lives in `/tmp`, and is removed when the test ends.
//! It is not a repository file.

use std::process::Command;

#[test]
fn log_over_the_byte_limit_exits_2() {
    const LIMIT: u64 = 268435456;
    assert_eq!(acme_renew_doctor::certbot_log::LOG_MAX_BYTES, LIMIT);
    assert_eq!(
        acme_renew_doctor::certbot_log::SHORT_TEXT_MAX_BYTES,
        1024 * 1024
    );

    struct Gone(std::path::PathBuf);
    impl Drop for Gone {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let path = Gone(std::path::PathBuf::from(format!(
        "/tmp/acme-renew-doctor-w46-over-limit-{}.log",
        std::process::id()
    )));
    let file = std::fs::File::create(&path.0).expect("create over-limit file in /tmp");
    file.set_len(LIMIT + 1)
        .expect("sparse length one byte over the limit");
    drop(file);

    let shown = path.0.to_str().expect("path is utf-8");
    let output = Command::new(env!("CARGO_BIN_EXE_acme-renew-doctor"))
        .args(["example.com", "--from-log", shown])
        .output()
        .expect("run acme-renew-doctor");
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr is utf-8");
    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains(&format!(
            "the file is {} bytes, over the {LIMIT} byte limit",
            LIMIT + 1
        )),
        "{stdout}"
    );
    assert!(stdout.contains("INSUFFICIENT_EVIDENCE"), "{stdout}");
    assert!(stderr.is_empty(), "{stderr}");
    assert!(!stdout.contains("panicked"), "{stdout}");
    assert!(!stderr.contains("panicked"), "{stderr}");
}
