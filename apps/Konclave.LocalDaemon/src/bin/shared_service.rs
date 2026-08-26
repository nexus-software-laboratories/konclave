use std::future::Future;
use std::process::ExitCode;

use anyhow::Context as _;

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
    let installation_path =
        konclave_local_daemon::parse_shared_service_installation_path(std::env::args_os().skip(1))?;
    let shutdown = register_process_shutdown()?;
    konclave_local_daemon::run_shared_until(&installation_path, shutdown).await
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
