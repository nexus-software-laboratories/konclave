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

`KonclaveCommunityRelay` requires the access-document and SQLite paths described in
the [relay transport authentication contract](docs/protocol/relay-authentication.md).
Non-loopback deployments also require trusted TLS termination.

Run the administration console from its application directory:

```shell
cd apps/Konclave.AdminConsole
npm install
npm run dev
```

The Copilot CLI host extension is packaged from
`extensions/Konclave.HostExtension` with `npm run build`.
<!-- genesis:run-command:end -->

### Initialize an installation

After installing the CLI, daemon, and Copilot plugin, configure relay enrollment once:

```shell
konclave init --relay-endpoint https://relay.example.com
konclave doctor
```

Self-hosted operators can create the verifier-only relay access document and protected
enrollment source without copying a raw credential:

```shell
konclave relay-bootstrap --relay-endpoint https://relay.example.com --access-document ./relay-access.json --external-source /run/secrets/konclave-enrollment
```

Native setup prompts without echo and stores an endpoint-bound credential in the
operating system credential store. Unix headless setup can create an owner-owned,
mode-`0600` external record from bounded stdin:

```shell
printf '%s\n' '<enrollment-credential>' | konclave init --relay-endpoint https://relay.example.com --external-source /run/secrets/konclave-enrollment
```

Later Copilot sessions create independent profiles and enroll automatically without
receiving the credential through their environment or plugin configuration. Repeating
`init` is idempotent for the same endpoint and source; conflicting setup fails.

### Run the local Copilot demo

On Windows, one script builds the Windows candidate on public CI, deletes its
transient artifact after download, installs the plugin, starts a hidden loopback
relay, and runs `init` plus `doctor`:

```powershell
pwsh -NoProfile -File .\scripts\demo\Start-KonclaveLocalDemo.ps1
```

See [Local Copilot demo](docs/distribution/local-demo.md) for pairing and cleanup.

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
