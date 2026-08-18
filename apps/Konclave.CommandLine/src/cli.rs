use clap::{Parser, Subcommand};

/// KonclaveCommandLine is a command-line application.
#[derive(Parser)]
#[command(name = "KonclaveCommandLine", version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Print version information
    Version,
    /// Print the resolved configuration
    Config,
}
