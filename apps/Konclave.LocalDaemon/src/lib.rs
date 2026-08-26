#[allow(dead_code)]
mod activity;
#[allow(dead_code)]
mod adapter;
#[allow(dead_code)]
mod application;
#[allow(dead_code)]
mod conversation;
#[allow(dead_code)]
mod health;
#[allow(dead_code)]
#[cfg(feature = "rust-service-mcp")]
mod local_service;
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
mod profile_runtime;
#[allow(dead_code)]
mod profile_supervisor;
mod runtime;
mod service;
#[cfg(feature = "rust-service-mcp")]
mod shared_runtime;
#[cfg(feature = "rust-service-mcp")]
mod shared_service_arguments;
#[cfg(test)]
mod test_support;

use std::future::Future;

/// Runs one daemon profile until the owning process requests shutdown.
///
/// The console and Windows Service hosts share this entry point so profile,
/// enrollment, adapter, and shutdown behavior cannot drift between executables.
///
/// # Errors
///
/// Returns profile configuration, custody, persistence, enrollment, adapter, or
/// service failures encountered before or during the daemon lifetime.
pub async fn run_until<F>(shutdown: F) -> anyhow::Result<()>
where
    F: Future<Output = ()>,
{
    runtime::run_until(shutdown).await
}

/// Runs the installed multi-profile local service until shutdown.
///
/// # Errors
///
/// Returns owner-protected installation, native service-identity, adapter-registry,
/// endpoint, profile-supervision, or coordinated-shutdown failures.
#[cfg(feature = "rust-service-mcp")]
pub async fn run_shared_until<F>(
    installation_path: &std::path::Path,
    shutdown: F,
) -> anyhow::Result<()>
where
    F: Future<Output = ()>,
{
    shared_runtime::run_until(installation_path, shutdown).await
}

/// Parses the shared service's exact `--config <absolute-path>` command contract.
///
/// # Errors
///
/// Returns a bounded validation error for missing, relative, unknown, or additional
/// arguments.
#[cfg(feature = "rust-service-mcp")]
pub fn parse_shared_service_installation_path(
    arguments: impl IntoIterator<Item = std::ffi::OsString>,
) -> anyhow::Result<std::path::PathBuf> {
    shared_service_arguments::parse_installation_path(arguments.into_iter())
}
