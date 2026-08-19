use std::process::ExitCode;

use KonclaveCommunityRelay as relay;
use anyhow::Context;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("Error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> anyhow::Result<()> {
    if std::env::args().any(|argument| argument == "--healthcheck") {
        return relay::check_health();
    }
    relay::run_until(wait_for_process_shutdown()).await
}

async fn wait_for_process_shutdown() {
    if let Err(error) = wait_for_process_signal().await {
        eprintln!("Shutdown signal failed: {error:#}");
    }
}

async fn wait_for_process_signal() -> anyhow::Result<()> {
    tokio::signal::ctrl_c().await.context("waiting for Ctrl+C")
}
