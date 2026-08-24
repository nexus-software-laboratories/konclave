# Copilot CLI extension

## Runtime boundary

The generated extension is a Node.js process that joins the foreground Copilot CLI
session with `@github/copilot-sdk/extension`. It starts from:

- no extension-owned tools or hooks
- one local stdio MCP server exposing the daemon's bounded Konclave tools
- stderr-only diagnostics
- explicit cleanup for event handlers and scheduled sends, plus SDK disconnect on OS
  termination signals

The extension derives a stable, non-reversible profile identifier from the foreground
Copilot session ID. Independent CLI sessions therefore run independent device
profiles without sharing a lock, while a resumed session reopens its durable profile.
The raw session ID is never passed to the daemon.

The daemon command is resolved in priority order: an explicit non-empty
`KONCLAVE_DAEMON_PATH` overrides everything and is never forwarded to the daemon's
own environment; otherwise the extension looks for a daemon bundled beside the
installed plugin at `<plugin-root>/bin/KonclaveLocalDaemon` (`.exe` on Windows),
selecting it only when that path exists and is a regular file; otherwise the bare
binary name (`KonclaveLocalDaemon` or `KonclaveLocalDaemon.exe`) is resolved against
the system `PATH`. The plugin root is derived from the compiled extension module's
own on-disk location (`import.meta.url`), never from `process.cwd()` or by probing
ancestor directories, because Copilot CLI caches installed plugins at an
unpredictable path unrelated to the original release install root. Optional
`KONCLAVE_PROFILE_ROOT` and
`KONCLAVE_WRAPPING_KEY_FILE` paths are forwarded; secret file contents and relay
credentials never cross the extension boundary. For first-run relay provisioning,
the extension also forwards `KONCLAVE_RELAY_ENDPOINT` and
`KONCLAVE_RELAY_CREDENTIAL_FILE`. The latter is a path to a local file containing the
canonical unpadded base64url bearer; the value itself is never placed in extension or
MCP configuration.

GitHub's extension contract reserves stdout for the JSON-RPC transport. The template
therefore treats any stdout write as a bug.

## Experimental and trust requirements

GitHub currently documents Copilot CLI extensions as experimental. Users must start the
CLI with `--experimental` or enable experimental mode in-session before plugin-loaded
extensions will run.

Extensions execute with the local user's privileges. Installing the plugin is
equivalent to running trusted local code. The paved-path extension explicitly enables
the daemon's write-capable MCP methods; the daemon itself remains read-only when
started without `KONCLAVE_MCP_ALLOW_WRITE=true`.

## Build outputs

- `extensions/Konclave.Extension/extension.mjs` — bundled extension entry loaded
  by Copilot CLI
- `plugin.json` — plugin manifest that exposes the extension and maintenance skill
- `skills/copilot-cli-extension-maintainer/SKILL.md` — optional skill for safely
  evolving the extension
- `build/outputs/<plugin-name>-<version>.zip` — deterministic release bundle
  containing installable plugin assets

## Safe send seam

GitHub's extension guidance warns against calling `session.send()` synchronously from a
hook. `src/runtime.ts` therefore centralizes future message injection behind
`schedulePromptSend()`, which always defers the send through a timer and tracks
cancellation during shutdown.

## Package contract

`scripts/verify-package.mjs` validates that:

- `package.json` and `plugin.json` stay in sync
- the compiled extension exists at the declared plugin manifest path
- the compiled output still uses the `joinSession()` lifecycle
- the packaged ZIP contains only the installable plugin assets
- the compiled extension does not introduce obvious stdout writes

## Release contract

The release workflow triggers on bare semver tags, rebuilds the extension, recreates
the deterministic ZIP, validates the tag against `plugin.json`, and uploads the ZIP as
a draft GitHub release asset.

## Official references

- [Creating a plugin for GitHub Copilot CLI](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/plugins-creating)
- [GitHub Copilot CLI plugin reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-plugin-reference)
- [About extensions for GitHub Copilot CLI](https://docs.github.com/en/copilot/concepts/agents/copilot-cli/about-cli-extensions)
