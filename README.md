# Konclave

<!-- genesis:description:start -->
Secure, durable communication for software agents.
<!-- genesis:description:end -->

## Prerequisites

<!-- genesis:prerequisites:start -->
- Rust (stable) via rustup
- Node.js 24+
- npm
- PowerShell 7+
<!-- genesis:prerequisites:end -->

## Getting Started

<!-- genesis:build-test:start -->
```shell
cargo build --workspace
cargo test --workspace
pwsh ./scripts/Invoke-NodeWorkspaceChecks.ps1
```
<!-- genesis:build-test:end -->

### Run

<!-- genesis:run-command:start -->
Run a Rust process from the workspace root:

```shell
cargo run -p KonclaveLocalDaemon
cargo run -p KonclaveCommunityRelay
cargo run -p KonclaveCommandLine -- --help
```

Run the administration console from its application directory:

```shell
cd apps/Konclave.AdminConsole
npm install
npm run dev
```

The Copilot CLI host extension is packaged from
`extensions/Konclave.HostExtension` with `npm run build`.
<!-- genesis:run-command:end -->

## Architecture

Konclave separates the trusted local agent boundary from relay transport:

- `Konclave.LocalDaemon` owns local IPC, authorization hooks, SQLite state, and
  the MCP server boundary.
- `Konclave.CommunityRelay` provides outbound WebSocket/HTTP relay transport
  without access to plaintext message content.
- Shared crates own protocol contracts, cryptographic policy, domain behavior,
  and client integration.
- TypeScript guests provide the Copilot CLI extension and administration
  console.

See the [project documentation](docs/README.md) for engineering and delivery
details.

## Project Structure

<!-- genesis:structure:start -->
```
apps/Konclave.CommandLine/       # Command-line client
apps/Konclave.CommunityRelay/    # Self-hosted relay service
apps/Konclave.LocalDaemon/       # Trusted local daemon and MCP boundary
apps/Konclave.AdminConsole/      # React administration console
extensions/Konclave.HostExtension/ # Copilot CLI extension
crates/                          # Shared Rust protocol, crypto, domain, and client crates
scripts/                         # Repository validation orchestration
```
<!-- genesis:structure:end -->

## Contributing

See `.github/instructions/` for coding conventions enforced by Copilot.

## License

Licensed under the [Apache License 2.0](LICENSE).

<!-- genesis:documentation:start -->
## Documentation

See the [project documentation](docs/README.md).
<!-- genesis:documentation:end -->
