#[allow(dead_code)]
mod application;
#[allow(dead_code)]
mod conversation;
#[allow(dead_code)]
mod mcp;
#[allow(dead_code)]
mod observability;
#[allow(dead_code)]
mod persistence;
mod runtime;
mod service;

use std::process::ExitCode;

use anyhow::Context;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => std::process::exit(0),
        Err(err) => {
            eprintln!("Error: {err:#}");
            std::process::exit(1)
        }
    }
}

async fn run() -> anyhow::Result<()> {
    runtime::run_until(wait_for_process_shutdown()).await
}

async fn wait_for_process_shutdown() {
    if let Err(error) = wait_for_process_signal().await {
        eprintln!("Shutdown signal failed: {error:#}");
    }
}

async fn wait_for_process_signal() -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .context("registering SIGTERM handler")?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result.context("waiting for Ctrl+C")?;
            }
            _ = terminate.recv() => {}
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.context("waiting for Ctrl+C")
    }
}
