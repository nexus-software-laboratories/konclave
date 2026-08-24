#[allow(dead_code)]
mod adapter;
#[allow(dead_code)]
mod application;
#[allow(dead_code)]
mod conversation;
#[allow(dead_code)]
mod health;
#[allow(dead_code)]
mod mcp;
#[allow(dead_code)]
mod observability;
#[allow(dead_code)]
mod pairing;
#[allow(dead_code)]
mod pairing_service;
mod pairing_supervisor;
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
    // Signal dispositions are installed before any profile work because opening a
    // profile generates identity material and can outlast an early stop request. A
    // signal arriving before registration would terminate the process under its
    // default disposition, skipping coordinated shutdown entirely.
    let shutdown = register_process_shutdown()?;
    runtime::run_until(shutdown).await
}

#[cfg(unix)]
fn register_process_shutdown() -> anyhow::Result<impl Future<Output = ()>> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate()).context("registering SIGTERM handler")?;
    let mut interrupt = signal(SignalKind::interrupt()).context("registering SIGINT handler")?;
    Ok(async move {
        tokio::select! {
            _ = terminate.recv() => {}
            _ = interrupt.recv() => {}
        }
    })
}

#[cfg(not(unix))]
fn register_process_shutdown() -> anyhow::Result<impl Future<Output = ()>> {
    Ok(async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            eprintln!("Shutdown signal failed: {error:#}");
        }
    })
}
