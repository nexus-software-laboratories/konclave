use std::future::Future;
use std::process::ExitCode;

use KonclaveA2AGatewayHost as gateway;
use anyhow::{Context as _, bail};

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> anyhow::Result<()> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [] => {
            let shutdown = process_shutdown()?;
            let config_path = std::env::var_os("KONCLAVE_A2A_GATEWAY_CONFIG_FILE")
                .filter(|value| !value.is_empty())
                .map(std::path::PathBuf::from)
                .context("KONCLAVE_A2A_GATEWAY_CONFIG_FILE is required")?;
            gateway::run_until(config_path, shutdown).await
        }
        [argument] if argument == "--healthcheck" => gateway::check_health(),
        _ => bail!("unsupported command-line arguments"),
    }
}

#[cfg(unix)]
fn process_shutdown() -> anyhow::Result<impl Future<Output = ()>> {
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .context("registering SIGINT handler")?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("registering SIGTERM handler")?;
    Ok(async move {
        tokio::select! {
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
        }
    })
}

#[cfg(windows)]
fn process_shutdown() -> anyhow::Result<impl Future<Output = ()>> {
    let mut ctrl_c = tokio::signal::windows::ctrl_c().context("registering Ctrl+C handler")?;
    let mut ctrl_break =
        tokio::signal::windows::ctrl_break().context("registering Ctrl+Break handler")?;
    Ok(async move {
        tokio::select! {
            _ = ctrl_c.recv() => {}
            _ = ctrl_break.recv() => {}
        }
    })
}
