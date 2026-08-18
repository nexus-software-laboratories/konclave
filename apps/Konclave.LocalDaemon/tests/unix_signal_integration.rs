#[cfg(unix)]
mod unix {
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    #[test]
    fn sigterm_uses_coordinated_shutdown() {
        let mut child = Command::new(env!("CARGO_BIN_EXE_KonclaveLocalDaemon"))
            .env("SERVICE_HTTP_ADDRESS", "127.0.0.1:0")
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

        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success());
                return;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                panic!("daemon did not stop after SIGTERM");
            }
            thread::sleep(Duration::from_millis(25));
        }
    }
}
