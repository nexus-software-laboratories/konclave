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
