//! A closed pipe or a full standard output must not panic.
//! The process exits 3 and, when standard error is still open, writes one line there.

#[cfg(unix)]
mod unix {
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::process::{Command, Output, Stdio};
    use std::time::{Duration, Instant};

    unsafe extern "C" {
        fn pipe(fds: *mut i32) -> i32;
        fn close(fd: i32) -> i32;
    }

    const BROKEN_PIPE: &str =
        "acme-renew-doctor: could not write output: Broken pipe (os error 32)\n";

    /// Write end of a pipe whose read end is already closed.
    fn closed_pipe() -> Stdio {
        let mut fds = [0i32; 2];
        // SAFETY: `fds` is a two-int buffer, which is what `pipe` writes.
        let created = unsafe { pipe(fds.as_mut_ptr()) };
        assert_eq!(created, 0, "pipe");
        // SAFETY: `fds[0]` is the open read end from that successful call.
        let closed = unsafe { close(fds[0]) };
        assert_eq!(closed, 0, "close the read end");
        // SAFETY: `fds[1]` is the open write end, and this process owns it.
        let owned = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        Stdio::from(owned)
    }

    fn run(args: &[&str], stdout: Stdio, stderr: Stdio) -> Output {
        run_env(args, stdout, stderr, None)
    }

    fn run_env(args: &[&str], stdout: Stdio, stderr: Stdio, now: Option<&str>) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_acme-renew-doctor"));
        command
            .args(args)
            .env_remove("ACME_RENEW_DOCTOR_NOW")
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr);
        if let Some(now) = now {
            command.env("ACME_RENEW_DOCTOR_NOW", now);
        }
        let mut child = command.spawn().expect("spawn acme-renew-doctor");
        let started = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(_)) => {
                    return child
                        .wait_with_output()
                        .expect("read acme-renew-doctor output");
                }
                Ok(None) if started.elapsed() > Duration::from_secs(5) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("acme-renew-doctor did not exit within 5 seconds: {args:?}");
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
                Err(err) => panic!("wait for acme-renew-doctor: {err}"),
            }
        }
    }

    fn assert_no_panic(output: &Output) -> (String, String) {
        let err = String::from_utf8_lossy(&output.stderr).into_owned();
        let out = String::from_utf8_lossy(&output.stdout).into_owned();
        assert!(
            !err.contains("panicked") && !out.contains("panicked"),
            "panic\nstderr:\n{err}\nstdout:\n{out}"
        );
        (err, out)
    }

    fn assert_exit_three(args: &[&str], stdout: Stdio, stderr: Stdio, message: Option<&str>) {
        let output = run(args, stdout, stderr);
        let err = String::from_utf8_lossy(&output.stderr);
        let out = String::from_utf8_lossy(&output.stdout);
        assert!(
            !err.contains("panicked") && !out.contains("panicked"),
            "panic for {args:?}\nstderr:\n{err}\nstdout:\n{out}"
        );
        assert_eq!(
            output.status.code(),
            Some(3),
            "exit for {args:?}\nstderr:\n{err}\nstdout:\n{out}"
        );
        if let Some(message) = message {
            assert_eq!(err.as_ref(), message, "stderr for {args:?}");
        }
    }

    #[test]
    fn help_on_a_closed_pipe_exits_three() {
        assert_exit_three(
            &["--help"],
            closed_pipe(),
            Stdio::piped(),
            Some(BROKEN_PIPE),
        );
    }

    #[test]
    fn version_on_a_closed_pipe_exits_three() {
        assert_exit_three(
            &["--version"],
            closed_pipe(),
            Stdio::piped(),
            Some(BROKEN_PIPE),
        );
    }

    #[test]
    fn text_report_on_a_closed_pipe_exits_three() {
        assert_exit_three(
            &["example.com"],
            closed_pipe(),
            Stdio::piped(),
            Some(BROKEN_PIPE),
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn json_report_on_a_closed_pipe_exits_three() {
        assert_exit_three(
            &["--json", "example.com"],
            closed_pipe(),
            Stdio::piped(),
            Some(BROKEN_PIPE),
        );
    }

    #[test]
    fn usage_error_on_a_closed_stderr_exits_three() {
        // Usage text is written to standard error, so that is the closed pipe.
        // The notice then has nowhere to go; the exit code is what remains.
        assert_exit_three(&["--bogus"], Stdio::null(), closed_pipe(), None);
    }

    #[test]
    fn invalid_clock_on_a_closed_stderr_exits_three() {
        // The clock message is the text written to standard error. A closed
        // pipe must not panic, and the exit stays 3, the same code as when
        // that message is written.
        let output = run_env(
            &["example.com"],
            Stdio::piped(),
            closed_pipe(),
            Some("not-a-timestamp"),
        );
        let (err, out) = assert_no_panic(&output);
        assert_eq!(
            output.status.code(),
            Some(3),
            "stderr:\n{err}\nstdout:\n{out}"
        );
        assert!(out.is_empty(), "stdout:\n{out}");
    }

    #[test]
    fn usage_error_with_closed_stdout_keeps_the_clap_message() {
        let output = run(&["--bogus"], closed_pipe(), Stdio::piped());
        let err = String::from_utf8_lossy(&output.stderr);
        assert!(!err.contains("panicked"), "{err}");
        assert!(!err.contains("could not write output"), "{err}");
        assert!(err.contains("unexpected argument '--bogus'"), "{err}");
        assert_eq!(output.status.code(), Some(3), "{err}");
    }

    #[cfg(target_os = "linux")]
    const FULL_DEVICE: &str =
        "acme-renew-doctor: could not write output: No space left on device (os error 28)\n";

    #[cfg(target_os = "linux")]
    fn full_device() -> Stdio {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .expect("open /dev/full");
        Stdio::from(file)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn help_on_a_full_device_exits_three() {
        assert_exit_three(
            &["--help"],
            full_device(),
            Stdio::piped(),
            Some(FULL_DEVICE),
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn version_on_a_full_device_exits_three() {
        assert_exit_three(
            &["--version"],
            full_device(),
            Stdio::piped(),
            Some(FULL_DEVICE),
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn text_report_on_a_full_device_exits_three() {
        assert_exit_three(
            &["example.com"],
            full_device(),
            Stdio::piped(),
            Some(FULL_DEVICE),
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn json_report_on_a_full_device_exits_three() {
        assert_exit_three(
            &["--json", "example.com"],
            full_device(),
            Stdio::piped(),
            Some(FULL_DEVICE),
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn invalid_clock_on_a_full_stderr_exits_three() {
        let output = run_env(
            &["example.com"],
            Stdio::piped(),
            full_device(),
            Some("not-a-timestamp"),
        );
        let (err, out) = assert_no_panic(&output);
        assert_eq!(
            output.status.code(),
            Some(3),
            "stderr:\n{err}\nstdout:\n{out}"
        );
        assert!(out.is_empty(), "stdout:\n{out}");
    }
}
