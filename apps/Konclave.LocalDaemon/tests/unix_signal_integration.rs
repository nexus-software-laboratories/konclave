#[cfg(unix)]
mod support;

#[cfg(unix)]
mod unix {
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::support;

    /// Sends SIGTERM before the daemon can finish opening its profile.
    ///
    /// Profile initialization generates identity material and is slower than the
    /// stop request a service manager may issue immediately after start. Registering
    /// signal dispositions after that work let the default disposition terminate the
    /// process, so this asserts the early window specifically rather than relying on
    /// a delay that happens to land after registration.
    #[test]
    fn sigterm_during_startup_still_exits_cleanly() {
        for attempt in 0..10 {
            let profile = support::TestProfile::new();
            let mut command = Command::new(env!("CARGO_BIN_EXE_KonclaveLocalDaemon"));
            profile.configure(&mut command);
            let mut child = command
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();

            thread::sleep(Duration::from_millis(50));
            let status = Command::new("kill")
                .args(["-TERM", &child.id().to_string()])
                .status()
                .unwrap();
            assert!(status.success());

            let status = wait_for_exit(&mut child);
            assert!(
                status.success(),
                "attempt {attempt}: daemon exited with {status:?} after an early SIGTERM"
            );
        }
    }

    #[test]
    fn sigterm_uses_coordinated_shutdown() {
        let profile = support::TestProfile::new();
        let mut command = Command::new(env!("CARGO_BIN_EXE_KonclaveLocalDaemon"));
        profile.configure(&mut command);
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();

        thread::sleep(Duration::from_secs(1));
        let status = Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()
            .unwrap();
        assert!(status.success());

        let status = wait_for_exit(&mut child);
        assert!(status.success(), "daemon exited with {status:?}");
    }

    fn wait_for_exit(child: &mut std::process::Child) -> std::process::ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                panic!("daemon did not stop after SIGTERM");
            }
            thread::sleep(Duration::from_millis(25));
        }
    }
}
