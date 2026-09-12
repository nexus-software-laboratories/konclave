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
            let config_path = std::env::var_os("KONCLAVE_A2A_GATEWAY_CONFIG_FILE")
                .filter(|value| !value.is_empty())
                .map(std::path::PathBuf::from)
                .context("KONCLAVE_A2A_GATEWAY_CONFIG_FILE is required")?;
            gateway::run_until(config_path, wait_for_process_shutdown()).await
        }
        [argument] if argument == "--healthcheck" => gateway::check_health(),
        _ => bail!("unsupported command-line arguments"),
    }
}

async fn wait_for_process_shutdown() {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    result = tokio::signal::ctrl_c() => {
                        if let Err(error) = result {
                            eprintln!("Shutdown signal failed: {error}");
                        }
                    }
                    _ = terminate.recv() => {}
                }
            }
            Err(error) => {
                eprintln!("SIGTERM registration failed: {error}");
                if let Err(error) = tokio::signal::ctrl_c().await {
                    eprintln!("Shutdown signal failed: {error}");
                }
            }
        }
    }
    #[cfg(not(unix))]
    if let Err(error) = tokio::signal::ctrl_c().await {
        eprintln!("Shutdown signal failed: {error}");
    }
}
