# Install an unsigned prerelease

Konclave packaging produces native archives for supported Linux, Windows, and macOS
targets. Each client archive contains the CLI, local daemon, platform service files,
and a built Copilot CLI plugin. Relay archives contain the standalone Community Relay
binary and its self-hosting examples. No source checkout or compiler is required after
extraction.

Package-validation artifacts are transient CI transport and are deleted immediately
after each run. No public release download is currently published. A maintainer must
build the package set locally or explicitly authorize a separate public release
channel before end users can download these archives.

Repository contributors on Windows can use the one-command
[Local Copilot demo](local-demo.md), which downloads the transient Windows candidate
before cleanup and performs setup automatically.

## Select and extract an archive

Choose the artifact matching the machine:

| Platform | Target |
| --- | --- |
| Linux x64 | `x86_64-unknown-linux-gnu` |
| Windows x64 | `x86_64-pc-windows-msvc` |
| macOS Apple silicon | `aarch64-apple-darwin` |
| macOS Intel | `x86_64-apple-darwin` |

Extract the archive into an owner-controlled directory. The extracted top-level
directory is the installation root used by the commands below.

Before extraction, verify the complete downloaded release set as described in
[Verify release integrity and contents](integrity.md).

## Install the Copilot plugin

Install the unpacked plugin directory:

```shell
copilot plugin install <install-root>/share/konclave/plugin
```

Copilot CLI caches installed plugin contents. Platform client packages therefore
include the matching daemon inside the plugin itself; no per-session daemon path or
relay environment variable is required.

## Initialize the installation

Run the packaged CLI once:

```shell
<install-root>/bin/konclave init --relay-endpoint https://relay.example.com
<install-root>/bin/konclave doctor --install-root <install-root>
```

`init` prompts without echo and stores the endpoint-bound enrollment credential in
native operating-system custody. Unix headless installations may instead use the
explicit external-source flow documented in the repository README.

## Run as a service

Platform service definitions are under
`<install-root>/share/konclave/service/`. The Windows installer accepts the packaged
service-host path explicitly. For system service installation, place the extracted
client directory at `/opt/konclave` on Linux or `/usr/local/libexec/konclave` on
macOS before loading the included systemd or launchd definition.

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

Stop running daemon processes, uninstall the cached plugin with
`copilot plugin uninstall konclave`, and remove the extracted installation directory.
Profiles live under the separate platform profile root and are retained for a later
installation. Remove that profile root explicitly only when permanent local data loss
is intended.
