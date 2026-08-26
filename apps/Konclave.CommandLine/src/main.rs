mod cli;
mod doctor;
mod init;
mod installation;
mod local_service_installation;
mod relay_bootstrap;

use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Command};

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
    match Cli::parse().command {
        Command::Version => print_version(),
        Command::Init(args) => init::run(args)?,
        Command::RelayBootstrap(args) => relay_bootstrap::run(args)?,
        Command::Doctor(args) => doctor::run(args).await?,
    }
    Ok(())
}

fn print_version() {
    println!("KonclaveCommandLine {}", env!("CARGO_PKG_VERSION"));
}
