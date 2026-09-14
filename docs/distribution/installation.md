# Install an unsigned prerelease

Konclave packaging produces native archives for supported Linux, Windows, and macOS
targets. Each client archive contains the CLI, one shared local-service binary,
platform lifecycle managers, a minimal Agent Plugins 1.0 payload, separate portable
client support, and editable collaboration-policy schemas and examples under
`<install-root>/share/konclave/policy/`. The extension contains no daemon binary.
Relay archives contain the standalone Community Relay binary and its self-hosting
examples. Gateway archives contain the standalone standard A2A HTTP+JSON process,
strict configuration and publication examples, and its runtime contract. No source
checkout or compiler is required after extraction.

Package-validation artifacts are transient CI transport and are deleted immediately
after each run. No public release download is currently published. A maintainer must
build the package set locally or explicitly authorize a separate public release
channel before end users can download these archives.

Repository contributors on Windows can use the one-command
[Local Copilot demo](local-demo.md), which downloads the transient Windows candidate
before cleanup and performs setup automatically.

## Select and extract an archive

Choose the artifact matching the machine:

| Platform            | Target                     |
| ------------------- | -------------------------- |
| Linux x64           | `x86_64-unknown-linux-gnu` |
| Windows x64         | `x86_64-pc-windows-msvc`   |
| macOS Apple silicon | `aarch64-apple-darwin`     |
| macOS Intel         | `x86_64-apple-darwin`      |

Extract the archive into an owner-controlled directory. The extracted top-level
directory is the installation root used by the commands below.

Before extraction, verify the complete downloaded release set as described in
[Verify release integrity and contents](integrity.md).

## Install the Copilot Agent Plugin

The standalone `konclave-<version>.zip` contains exactly the Agent Plugins 1.0
manifest and the Copilot extension files beneath
`com.github.copilot/extensions/konclave/`. For isolated pre-marketplace validation,
extract it into an owner-controlled directory and run:

```shell
copilot plugin install <extracted-plugin-directory>
```

Current Copilot CLI builds emit the expected warning that direct plugin installation
is deprecated. The package must otherwise install without manifest warnings. The
marketplace source is deliberately not selected or created by this package.

Copilot's cache is replaceable runtime material, not an authority store.
Installer-owned `konclave.service.json` lives under the canonical Konclave platform
data root:
Installer-owned `konclave.service.json` lives under the canonical Konclave platform
data root rather than the replaceable extension directory:

- Windows: `%LOCALAPPDATA%\Konclave\service\konclave.service.json`;
- Linux: `$XDG_DATA_HOME/konclave/service/konclave.service.json`, or
  `~/.local/share/konclave/service/konclave.service.json`; and
- macOS: `~/Library/Application Support/Konclave/service/konclave.service.json`.

`init` migrates an existing module-adjacent sidecar only when its validated endpoint,
issuer, pinned service key, signing-key path, and authorization policy match the
requested installation. A legacy AccountTrusted sidecar may omit the newer
UserPresence helper. Conflicting, malformed, unsafe, linked, oversized, or
permission-invalid state fails closed, and new installations never create a legacy
sidecar. The `--local-service-client-config` option is an absolute-path override for
isolated tests and declared development scenarios; it is not a production location
selector.

UserPresence client configuration records the absolute packaged CLI path as
`userPresenceHelper`; clients never discover or launch an arbitrary executable.
AccountTrusted-only records omit that field and cannot satisfy UserPresence.
No native executable or authority state belongs under the extension directory.

The [Local Copilot demo](local-demo.md) continues to exercise the transitional raw
extension path atomically on Windows and enables experimental extension support when
necessary.

For a transitional raw extension on Linux or macOS, run `init` first so the
owner-protected canonical client configuration exists. Create the legacy extension
directory separately, then copy the Agent Plugin's
`com.github.copilot/extensions/konclave/extension.mjs` plus `client.mjs` and
`generic.mjs` from `<install-root>/share/konclave/client/` into it. Copy
`<install-root>/share/konclave/client/skills/konclave-generic/SKILL.md` only into an
unsupported harness's own skill location when the best-effort fallback is wanted.
Do not install it into Copilot CLI; the paved extension owns that harness.
Do not copy a native executable or create a `bin/` child under the extension.

## Initialize the installation

Run the packaged CLI once:

```shell
<install-root>/bin/konclave init --relay-endpoint https://relay.example.com
<install-root>/bin/konclave doctor --install-root <install-root>
```

`init` prompts without echo and stores the endpoint-bound enrollment credential in
native operating-system custody. Interactive setup also requires one explicit
authorization-policy selection. `AccountTrusted` preserves automatic startup but
trusts every process under the operating-system account and does not provide hostile
same-user session isolation. Noninteractive setup must pass the policy explicitly;
there is no default or fallback. Unix headless installations may use the external
source flow documented in the repository README. Headless service identity and
per-profile wrapping-key custody are also explicit:

```shell
<install-root>/bin/konclave init \
  --relay-endpoint https://relay.example.com \
  --authorization-policy account-trusted \
  --external-source /run/secrets/konclave-enrollment \
  --local-service-identity-file /run/secrets/konclave-service-identity \
  --local-service-profile-key-directory /run/secrets/konclave-profile-keys
```

On supported Windows systems, a fresh installation can require native user
verification for every new client process:

```powershell
<install-root>\bin\konclave.exe init --relay-endpoint https://relay.example.com --authorization-policy user-presence --allow-no-recovery
```

The installer performs one Windows WebAuthn registration and one confirmation
assertion before publishing installation state. Windows Hello or a compatible FIDO2
authenticator must satisfy `userVerification: required`. Each later process receives
one Windows-owned modal ceremony for its exact profile, ephemeral session public key,
harness, capability set, policy, and finite grant binding. The broker identifies the
Konclave relying party but does not display every bound field. Linux and macOS reject
this policy as unavailable and do not fall back to AccountTrusted. The explicit flag
acknowledges that losing every enrolled credential can strand a no-recovery
installation.

`init` creates or verifies one service identity, one AccountTrusted issuer identity,
the finite issuer registration, the explicit evidence policy, the owner-protected
`konclave-local-authorization.sqlite3` authority database, the immutable service
configuration, and the canonical client configuration. Under UserPresence, the
AccountTrusted issuer authenticates only the challenge request; it cannot satisfy the
policy without the independently verified assertion. A Copilot process obtains a finite
exact-profile grant for a memory-only session key, and the issuer cannot invoke
profile operations directly. The authority database is created before the immutable
installation record is published; once that record exists, a missing or empty
authority database fails closed instead of being recreated. Repeating the exact
command is idempotent and does not repeat enrollment when the credential is already
valid; a conflicting endpoint, policy, custody source, or existing file fails without
replacement.

The first UserPresence delivery supports fresh setup only. It does not expose an
in-place enrollment or downgrade-authorized administration flow for an existing
AccountTrusted installation.

Use `konclave authorization status` to inspect the current generation and bounded
counts. Operator-only subcommands can revoke an exact grant, suspend or resume a
profile, register a higher issuer key version, enable or disable an issuer, remove an
issuer, or replace the evidence policy. These are direct owner-authorized state
changes and are not exposed as agent tools.

`konclave doctor` reports the effective authorization path separately from provider
configuration. A UserPresence-only installation passes that configuration check only
when the credential is enrolled, the challenge issuer is enabled, and the CLI
contains the native Windows adapter. It does not trigger a ceremony and therefore
does not claim that Windows WebAuthn or a UV-capable authenticator is currently
available. Unsupported platforms report a finite failing provider check rather than
describing the policy as AccountTrusted.

## Run as a service

Platform service definitions and idempotent lifecycle managers are under
`<install-root>/share/konclave/service/`.

```shell
# Linux user service
bash <install-root>/share/konclave/service/systemd/manage-user-service.sh install <install-root>

# macOS launch agent
bash <install-root>/share/konclave/service/launchd/manage-agent.sh install <install-root>
```

On Windows, run `install-service.ps1 -Action Install -Credential <current-user>` for
an SCM-managed per-user service, or use the local demo's hidden owner-session process.
All managers also support start, stop, status, and uninstall actions and reject an
existing conflicting definition.

## Upgrade and rollback

The current unsigned prerelease has no supported external installation base.
Protocol-v2 remains a clean development transition rather than a customer migration
contract. Authorization-store schema 1 is upgraded transactionally to schema 2 on
open after its complete schema and installation fingerprint are verified. The
migration preserves policy, issuer, suspension, grant, reservation, and audit state,
then adds the empty UserPresence credential tables and widens the closed audit-kind
range. Unknown or modified schema-1 shapes fail closed.

Close old harness sessions, stop the exact recorded service, install the complete new
archive, rerun the exact `init` command with the same explicit policy, and then start
the shared service. The demo's `-Refresh` path replaces only obsolete development
authorization state and package files after stopping that service; durable profiles
remain separate.
Existing conversation credential bindings remain valid for ordinary text but do not
gain directed-request capability retroactively. Create new membership with the
upgraded clients before using `send_directed_request` or `/konclave request`.

An external-custody profile must have its original key copied to
`<profile-key-directory>/<profile-id>.key` before the shared service opens it. Every
file is owner protected and each profile resolves only its own canonical name; a
missing or wrong key fails closed without replacing identity or state. Never point
multiple profiles at one launch-scoped key as a migration shortcut.

Authorization-store schema migration is one-way for this prerelease. Rolling back to
a binary that understands only schema 1 requires restoring a pre-migration authority
database or intentionally recreating development authorization state after stopping
the service; protocol v2 never negotiates down to v1. Before a supported release
creates compatibility obligations, packaging must provide a journaled
preview/apply/recovery/rollback migration engine. Profile databases, native custody,
relay principals, and external key files remain outside the installation root and
are retained.

## Run the Community Relay

Relay archives contain a standalone native binary under `bin/`. Configure the access
document and protected enrollment source with `konclave relay-bootstrap`. Configure
the SQLite path described in
`<relay-root>/share/konclave/relay/container.md`, then place trusted TLS termination
in front of every non-loopback listener.

The Linux AMD64 container candidate is a Docker-loadable tar archive produced from the
same build result as the statically validated OCI image:

```shell
docker image load --input konclave-community-relay-container-0.1.0-linux-amd64.docker.tar
KONCLAVE_RELAY_ACCESS_SOURCE=/absolute/path/to/relay-access.json docker compose --file <relay-root>/share/konclave/relay/compose.example.yaml up --detach
```

The Compose example never pulls from or pushes to a registry. It publishes the relay
only on host loopback for connection from an operator-managed TLS reverse proxy.

## Run the A2A gateway

Follow the complete
[self-hosted A2A operator guide](a2a-self-hosting.md) for route bootstrap, file
custody, TLS, backup, and upgrade behavior.

Gateway archives contain `bin/KonclaveA2AGateway` plus maintained examples under
`share/konclave/a2a/`. Initialize and start the shared local service first, enroll the
gateway profile and target conversation, then copy the example files to
owner-controlled configuration paths and replace the all-zero route identifiers.

Set `KONCLAVE_A2A_GATEWAY_CONFIG_FILE` to the absolute gateway configuration path.
The first native profile accepts one dedicated-origin publication with bearer
authentication, or explicit unauthenticated loopback development:

```shell
KONCLAVE_A2A_GATEWAY_CONFIG_FILE=/etc/konclave/a2a/gateway.json \
  <gateway-root>/bin/KonclaveA2AGateway
```

Place trusted TLS termination in front of every non-loopback listener. Standard mode
terminates A2A plaintext at this process and stores the bounded task projection in
SQLite. Protected A2A bypasses the standard gateway and uses native Konclave.

The runtime contract and exact secret-file, local-service, persistence, health, and
shutdown behavior are in `<gateway-root>/share/konclave/a2a/README.md`.

The Linux AMD64 container candidate is a separate Docker-loadable archive:

```shell
docker image load --input konclave-a2a-gateway-container-0.1.0-linux-amd64.docker.tar
```

Use `<gateway-root>/share/konclave/a2a/compose.example.yaml`,
`gateway-config.container.json`, and `container.md`.
The gateway runs as the local-service account's nonzero numeric UID, publishes only
on host loopback, and uses separate read-only configuration, owner-protected
credential, local-service socket, SQLite, and encrypted-object mounts. Trusted TLS
termination is required before any non-loopback exposure.

Package validation starts both the native and container gateway against an
independently installed shared service and verifies discovery, authenticated task
submission, exact directed response handling, SQLite restart recovery, and encrypted
object retrieval.

## Unsigned status

These prereleases are intentionally unsigned. Every archive contains
`UNSIGNED-PRERELEASE.txt`, and `RELEASE.json` reports `signatureStatus` as `unsigned`.
The operating system cannot verify publisher identity from a code signature.

Artifact signing and notarization are post-MVP hardening work. Do not bypass operating
system warnings by weakening machine-wide security policy.

See [Packaged clean-install acceptance](acceptance.md) for the automated evidence
covering native and containerized self-hosting.

## Uninstall an archive installation

Disable or remove the exact issuer key versions owned by the package, stop the shared
service through its platform manager, stop any A2A gateway process, remove the user
extension directory, and remove the extracted installation directories. Remove the
service-level authorization database only when uninstalling the complete local
service after all issuer records have been removed; keep it for a package-specific
uninstall so unrelated issuers and profile suspensions remain intact.

Profiles and A2A task databases live outside the installation roots and are retained
for later installations. Remove either state root explicitly only when permanent
local data loss is intended.
