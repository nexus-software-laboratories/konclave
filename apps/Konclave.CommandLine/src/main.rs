mod cli;
mod config;

use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Command};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("Error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Version => print_version(),
        Command::Config => config::run()?,
    }
    Ok(())
}

fn print_version() {
    println!("KonclaveCommandLine {}", env!("CARGO_PKG_VERSION"));
}
