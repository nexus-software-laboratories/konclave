use std::env;
use std::io::{BufRead as _, BufReader, Read, Write};
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

trait AdapterStream: Read + Write {}

impl<T> AdapterStream for T where T: Read + Write {}

enum ProbeOutcome {
    Accepted,
    Denied,
}

fn main() -> ExitCode {
    match run() {
        Ok(ProbeOutcome::Accepted) => {
            println!("adapter transport accepted");
            ExitCode::SUCCESS
        }
        Ok(ProbeOutcome::Denied) => {
            eprintln!("adapter transport denied");
            ExitCode::from(2)
        }
        Err(error) => {
            eprintln!("adapter transport probe failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ProbeOutcome, &'static str> {
    let endpoint = required_environment("KONCLAVE_ADAPTER_ENDPOINT")?;
    let token = required_environment("KONCLAVE_ADAPTER_TOKEN")?;
    let profile_id = required_environment("KONCLAVE_PROFILE_ID")?;
    validate_capability(&token)?;
    validate_profile_id(&profile_id)?;

    let mut stream = connect_with_retry(&endpoint)?;
    let request =
        format!("{{\"version\":1,\"profileId\":\"{profile_id}\",\"token\":\"{token}\"}}\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|_| "write_failed")?;
    stream.flush().map_err(|_| "write_failed")?;

    let mut response = String::new();
    BufReader::new(stream)
        .take(1_025)
        .read_line(&mut response)
        .map_err(|_| "read_failed")?;
    if response.len() > 1_024 {
        return Err("response_too_large");
    }

    match response.trim_end() {
        "{\"status\":\"accepted\"}" => Ok(ProbeOutcome::Accepted),
        "{\"status\":\"denied\"}" => Ok(ProbeOutcome::Denied),
        _ => Err("invalid_response"),
    }
}

fn required_environment(name: &'static str) -> Result<String, &'static str> {
    let value = env::var(name).map_err(|_| "missing_environment")?;
    if value.is_empty() {
        return Err("missing_environment");
    }
    Ok(value)
}

fn validate_capability(value: &str) -> Result<(), &'static str> {
    if value.len() != 43
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("invalid_capability");
    }
    Ok(())
}

fn validate_profile_id(value: &str) -> Result<(), &'static str> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err("invalid_profile");
    }
    Ok(())
}

fn connect_with_retry(endpoint: &str) -> Result<Box<dyn AdapterStream>, &'static str> {
    for _ in 0..100 {
        if let Ok(stream) = connect_once(endpoint) {
            return Ok(stream);
        }
        thread::sleep(Duration::from_millis(20));
    }
    Err("connect_failed")
}

#[cfg(unix)]
fn connect_once(endpoint: &str) -> std::io::Result<Box<dyn AdapterStream>> {
    use std::os::unix::net::UnixStream;

    UnixStream::connect(endpoint).map(|stream| Box::new(stream) as Box<dyn AdapterStream>)
}

#[cfg(windows)]
fn connect_once(endpoint: &str) -> std::io::Result<Box<dyn AdapterStream>> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(endpoint)
        .map(|stream| Box::new(stream) as Box<dyn AdapterStream>)
}
