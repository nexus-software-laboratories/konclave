use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// KonclaveCommandLine is a command-line application.
#[derive(Parser)]
#[command(name = "konclave", version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Print version information
    Version,
    /// Configure protected relay enrollment for later session profiles
    Init(InitArgs),
    /// Create a self-hosted relay access document and protected enrollment source
    RelayBootstrap(RelayBootstrapArgs),
    /// Check installation, custody, profile, and relay health
    Doctor(DoctorArgs),
}

#[derive(Args)]
pub struct InitArgs {
    /// Relay base URL; TLS is required outside loopback
    #[arg(long)]
    pub relay_endpoint: String,
    /// Shared profile root; defaults to the platform data directory
    #[arg(long)]
    pub profile_root: Option<PathBuf>,
    /// Absolute path for an endpoint-bound Unix headless credential record
    #[arg(long)]
    pub external_source: Option<PathBuf>,
}

#[derive(Args)]
pub struct RelayBootstrapArgs {
    /// Relay base URL; TLS is required outside loopback
    #[arg(long)]
    pub relay_endpoint: String,
    /// Non-secret relay access document to create
    #[arg(long)]
    pub access_document: PathBuf,
    /// Shared profile root for native custody; defaults to the platform data directory
    #[arg(long)]
    pub profile_root: Option<PathBuf>,
    /// Owner-protected Unix enrollment source; omit to use native custody
    #[arg(long)]
    pub external_source: Option<PathBuf>,
}

#[derive(Args)]
pub struct DoctorArgs {
    /// Shared profile root; defaults to the platform data directory
    #[arg(long)]
    pub profile_root: Option<PathBuf>,
    /// Installation root containing bin/ and share/konclave/
    #[arg(long)]
    pub install_root: Option<PathBuf>,
}
