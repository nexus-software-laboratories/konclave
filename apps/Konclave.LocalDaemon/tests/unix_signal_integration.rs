#[cfg(unix)]
mod support;

#[cfg(unix)]
mod unix {
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::support;

    /// Sends SIGTERM while the daemon is still opening its profile.
    ///
    /// A fixed delay cannot express this: too short and the signal precedes the async
    /// runtime that installs the disposition, which no process can prevent; too long
    /// and it lands after initialization and proves nothing. The profile lock appears
    /// before identity material is generated, so waiting for it puts the signal
    /// inside initialization on any machine speed.
    ///
    /// Registering dispositions only after that work therefore fails here, while the
    /// irreducible window before the runtime exists is never exercised.
    #[test]
    fn sigterm_during_profile_initialization_exits_cleanly() {
        for attempt in 0..5 {
            let profile = support::TestProfile::new();
            let mut command = Command::new(env!("CARGO_BIN_EXE_KonclaveLocalDaemon"));
            profile.configure(&mut command);
            let mut child = command
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();

            wait_for_path(&profile.lock_path());
            let status = Command::new("kill")
                .args(["-TERM", &child.id().to_string()])
                .status()
                .unwrap();
            assert!(status.success());

            let status = wait_for_exit(&mut child);
            assert!(
                status.success(),
                "attempt {attempt}: daemon exited with {status:?} after a SIGTERM during profile initialization"
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

    fn wait_for_path(path: &std::path::Path) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while !path.exists() {
            if Instant::now() >= deadline {
                panic!(
                    "daemon did not begin opening its profile at {}",
                    path.display()
                );
            }
            thread::sleep(Duration::from_millis(1));
        }
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
