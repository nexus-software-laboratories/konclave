# Install an unsigned prerelease

Konclave packaging produces native archives for supported Linux, Windows, and macOS
targets. Each client archive contains the CLI, one shared local-service binary,
platform lifecycle managers, a thin Copilot CLI extension payload, and editable
collaboration-policy schemas and examples under
`<install-root>/share/konclave/policy/`. The extension contains no daemon binary.
Relay archives contain the standalone Community Relay binary and its self-hosting
examples. No source checkout or compiler is required after extraction.

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

## Install the Copilot extension

Copilot discovers user-scoped extensions under
`~/.copilot/extensions/konclave/`. A complete installation contains `extension.mjs`, the reusable `client.mjs`, and the
one-shot `generic.mjs` fallback plus the installer-created `konclave.service.json`
sidecar. No native executable lives under the extension directory.

The [Local Copilot demo](local-demo.md) performs this installation atomically on
Windows and enables experimental extension support when necessary. Direct
`copilot plugin install` is not the extension installation path: current Copilot CLI
versions can cache the plugin payload without mounting its extension.

On Linux or macOS, run `init` first so the owner-protected extension directory and
sidecar exist, then copy `extension.mjs`, `client.mjs`, and `generic.mjs` from
`<install-root>/share/konclave/plugin/extensions/Konclave.Extension/` into that
directory. Copy
`<install-root>/share/konclave/plugin/skills/konclave-generic/SKILL.md` only into an
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

`init` creates or verifies one service identity, one AccountTrusted issuer identity,
the finite issuer registration, the explicit evidence policy, the service
configuration, and the extension sidecar. A Copilot process uses the issuer only to
obtain a finite exact-profile grant for a memory-only session key. The issuer cannot
invoke profile operations directly. Repeating the exact command is idempotent; a
conflicting endpoint, policy, custody source, or existing file fails without
replacement.

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
Protocol-v2/schema-v2 setup is therefore a clean development transition, not a
customer migration contract. Close old harness sessions, stop the exact recorded
service, install the complete new archive, rerun the exact `init` command with the
same explicit policy, and then start the shared service. The demo's `-Refresh` path
replaces only the obsolete development authorization record, issuer key, sidecar, and
package after stopping that service; durable profiles remain separate.
Existing conversation credential bindings remain valid for ordinary text but do not
gain directed-request capability retroactively. Create new membership with the
upgraded clients before using `send_directed_request` or `/konclave request`.

An external-custody profile must have its original key copied to
`<profile-key-directory>/<profile-id>.key` before the shared service opens it. Every
file is owner protected and each profile resolves only its own canonical name; a
missing or wrong key fails closed without replacing identity or state. Never point
multiple profiles at one launch-scoped key as a migration shortcut.

Rollback for this pre-release transition is source/package rollback after stopping
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

## Unsigned status

These prereleases are intentionally unsigned. Every archive contains
`UNSIGNED-PRERELEASE.txt`, and `RELEASE.json` reports `signatureStatus` as `unsigned`.
The operating system cannot verify publisher identity from a code signature.

Artifact signing and notarization are post-MVP hardening work. Do not bypass operating
system warnings by weakening machine-wide security policy.

See [Packaged clean-install acceptance](acceptance.md) for the automated evidence
covering native and containerized self-hosting.

## Uninstall an archive installation

Stop the shared service through its platform manager, remove the user extension
directory, and remove the extracted installation directory.
Profiles live under the separate platform profile root and are retained for a later
installation. Remove that profile root explicitly only when permanent local data loss
is intended.
