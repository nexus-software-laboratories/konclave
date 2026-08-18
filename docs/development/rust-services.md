# Rust services

Genesis keeps the base `rust-service` template minimal and composes transport,
persistence, observability, packaging, and protocol concerns through opt-in
components.

Dependency-bearing capabilities share one optional Cargo dependency graph and one
committed lockfile. Individual components activate only their named default feature,
so every supported combination keeps `cargo build --locked` reproducible without
changing the default scaffold. Selecting that shared graph raises the generated
package MSRV to Rust 1.88, matching its newest locked transitive requirements.

## Service invariants

- Own every long-running task and propagate shutdown from the service root.
- Bound graceful shutdown and wait for child tasks to finish or time out.
- Move blocking work off the async executor.
- Put timeouts at external I/O boundaries and distinguish cancellation from timeout.
- Use bounded queues where producers can outpace consumers.
- Keep error ownership at the boundary that can decide whether to retry, surface, or
  log once.
- Use structured diagnostics and preserve stdout when a protocol owns it.

## Optional rust-service capabilities

- **Axum** adds an HTTP listener, router state, a health endpoint, and graceful
  shutdown tests.
- **WebSocket** builds on Axum and adds bounded session channels, ping/pong, and
  cancellation-aware lifecycle handling.
- **SQLx SQLite / PostgreSQL** add migrations, typed repositories, short
  transactions, and isolated integration tests. This repository selects SQLite for
  the local daemon and community relay; public CI does not require a PostgreSQL
  service.
- **MCP server** adds an rmcp stdio transport seam with explicit authorization and
  absolute stdout protection for logs and diagnostics. Normal stdio disconnect
  signals the same coordinated shutdown path as process signals.
- **OpenTelemetry** adds tracing plus optional OTLP export with metadata-only
  defaults, bounded metadata, and secret-safe field filtering. OTLP export activates
  only when `OTEL_EXPORTER_OTLP_ENDPOINT` is configured; local diagnostics stay on
  stderr.
- **Daemon packaging** adds systemd, launchd, and Windows Service definitions.
  PitCrew validates the package metadata, PowerShell syntax, Rust syntax, and
  non-Windows guard on Linux. Type checking and runtime validation of the native
  Windows Service host remain outside the current runner contract.
- **OCI packaging** adds a non-root image and health check without assuming a
  repository-private publisher. Pull-request validation builds one AMD64 archive
  from the locked root workspace through the socketless PitCrew image-builder
  lane. Containers bind HTTP on all interfaces while the process health command
  probes `/healthz` through loopback.

## Current divergence

The SQLx capability uses 0.8.6 because the validated Rust 1.89 fallback toolchain
cannot compile SQLx 0.9.0's Rust 1.94 minimum. Advance SQLx and the generated MSRV
together in a dependency-focused change after the validated toolchain reaches that
minimum.
