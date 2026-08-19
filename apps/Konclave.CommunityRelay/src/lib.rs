#![forbid(unsafe_code)]
#![allow(non_snake_case)]

//! Self-hosted opaque relay composition and transport adapters.

pub mod access;
pub mod application;
pub mod http;
#[allow(dead_code)]
mod observability;
mod runtime;
mod service;
mod websocket;

use std::future::Future;

/// Runs the relay until the supplied shutdown future completes.
///
/// # Errors
///
/// Returns an error when configuration, storage, telemetry, transport startup, or
/// graceful shutdown fails.
pub async fn run_until<F>(shutdown: F) -> anyhow::Result<()>
where
    F: Future<Output = ()>,
{
    runtime::run_until(shutdown).await
}

/// Probes the configured local health endpoint.
///
/// # Errors
///
/// Returns an error when the health address is invalid, unavailable, or unhealthy.
pub fn check_health() -> anyhow::Result<()> {
    http::check_health()
}
