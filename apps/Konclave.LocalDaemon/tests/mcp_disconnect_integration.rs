use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn closing_mcp_stdin_stops_the_process() {
    let profile = support::TestProfile::new();
    let mut command = Command::new(env!("CARGO_BIN_EXE_KonclaveLocalDaemon"));
    profile.configure(&mut command);
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    drop(child.stdin.take());
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            return;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("MCP process did not stop after stdin closed");
        }
        thread::sleep(Duration::from_millis(25));
    }
}
mod support;
