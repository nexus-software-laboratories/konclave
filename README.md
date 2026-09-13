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
cargo run -p KonclaveLocalDaemon --bin KonclaveLocalService -- --config <absolute-service-config>
cargo run -p KonclaveCommunityRelay
cargo run -p KonclaveA2AGatewayHost --bin KonclaveA2AGateway
cargo run -p KonclaveCommandLine -- --help
```

`KonclaveCommunityRelay` requires the access-document and SQLite paths described in
the [relay transport authentication contract](docs/protocol/relay-authentication.md).
Non-loopback deployments also require trusted TLS termination.
`KonclaveA2AGatewayHost` requires `KONCLAVE_A2A_GATEWAY_CONFIG_FILE` and one
initialized shared local service as described in the
[self-hosted A2A runtime contract](docs/development/a2a-self-hosting.md). Deployment
and recovery procedures are in the
[self-hosted A2A operator guide](docs/distribution/a2a-self-hosting.md).

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

After installing the CLI, shared service, and Copilot extension, configure the
installation once:

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
printf '%s\n' '<enrollment-credential>' | konclave init --relay-endpoint https://relay.example.com --authorization-policy account-trusted --external-source /run/secrets/konclave-enrollment
```

Later Copilot sessions create independent profiles and enroll automatically without
receiving the credential through their environment or extension configuration. Repeating
`init` is idempotent for the same endpoint and source; conflicting setup fails.

`AccountTrusted` trusts every process under the configured operating-system account;
it does not isolate hostile same-user sessions. On Windows, a fresh installation can
instead require native Windows Hello or compatible FIDO2 user verification:

```powershell
konclave init --relay-endpoint https://relay.example.com --authorization-policy user-presence --allow-no-recovery
```

Setup performs registration plus a confirmation ceremony, and each new Copilot
session process completes its own native ceremony for one finite exact-profile,
memory-key grant. Linux and macOS fail closed with no AccountTrusted fallback.
The first delivery does not migrate an existing AccountTrusted installation in place;
select UserPresence only during intentional fresh setup. Losing the credential can
strand a no-recovery installation, which is why the acknowledgement flag is required.
Unsupported harnesses continue to use the Generic AccountTrusted client and cannot
self-assert stronger evidence.

Operators can inspect and change the live durable authorization state without
exposing administration as an agent tool:

```shell
konclave authorization status
konclave authorization suspend-profile --profile <profile-id>
konclave authorization disable-issuer --issuer-key-id <issuer-key-id> --issuer-key-version 1 --existing-grants revoke
```

### Run the local Copilot demo

On Windows, one script builds the Windows candidate on public CI, deletes its
transient artifact after download, installs a user-scoped extension, starts a hidden loopback
relay, and runs `init` plus `doctor`:

```powershell
pwsh -NoProfile -File .\scripts\demo\Start-KonclaveLocalDemo.ps1
```

See [Local Copilot demo](docs/distribution/local-demo.md) for pairing and cleanup.

The local-only two-session agent smoke sends one explicit directed request, permits
one correlated automatic response, and then observes bounded terminal silence. It
fails if ordinary response text authorizes another model turn.

The smoke uses the current developer's local Copilot authentication and remains prohibited
from running in CI.

## Architecture

Konclave separates the trusted local agent boundary from relay transport:

- `Konclave.LocalDaemon` builds the shared authenticated local service, profile
  supervision, authorization, SQLite state, and reusable operation handlers.
- `Konclave.CommunityRelay` provides outbound WebSocket/HTTP relay transport
  without access to plaintext message content.
- `Konclave.A2AGateway` provides the inbound standard A2A HTTP+JSON edge over one
  exact local-service profile and SQLite task projection.
- Shared crates own protocol contracts, cryptographic policy, domain behavior,
  and client integration.
- TypeScript guests provide the thin Copilot CLI client and administration console.

See the [project documentation](docs/README.md) for engineering and delivery
details.

## Project Structure

<!-- genesis:structure:start -->
```
apps/Konclave.CommandLine/       # Command-line client
apps/Konclave.A2AGateway/        # Self-hosted A2A HTTP+JSON gateway
apps/Konclave.CommunityRelay/    # Self-hosted relay service
apps/Konclave.LocalDaemon/       # Shared local service and operation host
apps/Konclave.AdminConsole/      # React administration console
extensions/Konclave.HostExtension/ # Copilot CLI extension
crates/                          # Shared Rust protocol, crypto, domain, and client crates
scripts/                         # Repository validation orchestration
tools/Konclave.CopilotSmoke/     # Local-only two-session SDK smoke runner
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
