# Copilot CLI extension

## Runtime boundary

The generated extension is a thin Node.js process that joins the foreground Copilot
CLI session with `@github/copilot-sdk/extension`. It registers:

- the 22 bounded Konclave agent tools as native SDK handlers;
- one deterministic `/konclave` command surface;
- automatic delivery through the existing bounded coalescing and wake policy;
- no MCP server, child command, or per-session daemon; and
- stderr-only diagnostics with explicit session, signal, timer, delivery, and local
  client cleanup.

The extension derives a stable, non-reversible profile identifier from the foreground
Copilot session ID. Independent CLI sessions therefore bind to independent device
profiles, while a resumed session reuses its durable profile. The raw session ID is
never sent to the service or included in diagnostics.

## Shared-service client

Installation writes `konclave.service.json` beside the installed extension. A bounded
development override may name that file with `KONCLAVE_SERVICE_CONFIG_FILE`. The
record contains only:

- the local named-pipe or Unix-socket endpoint;
- the registered adapter key identifier and version;
- the authorized harness;
- the pinned service verification key; and
- an absolute path to the adapter signing-key custody record.

The extension never discovers an endpoint, trusts a network URL, broadens a
registration, or starts a service. Missing, malformed, unsafe, or unauthorized state
fails visibly with no per-session fallback.

On Unix, configuration and key records are opened with `O_NOFOLLOW`, verified through
the same descriptor as regular files owned by the current UID with no group or other
permissions, and read within hard byte limits. On Windows, the Rust installer creates
and verifies the extension directory and both files with an explicit
current-account-only DACL before Node reads either through one bounded descriptor.
The service named pipe independently verifies both process SIDs and integrity levels.
The Ed25519 seed and its temporary DER encoding are zeroized immediately after the
platform crypto provider imports the key.

One profile-bound client owns separate interactive and delivery lanes. Both lanes use
the same pinned registration and profile, while the second authenticated connection
prevents a bounded delivery wait from blocking an interactive tool or slash command.
Interactive reconnect retries preserve the request ID so the service returns the
recorded idempotent outcome. Delivery reconnects use a fresh claim request because a
claim response is bound to the disconnected consumer lease.

## Deterministic commands

`/konclave` handlers call the shared client directly. They never prompt a model,
inject a user turn, or interpret command text as an instruction.

```text
/konclave help
/konclave status
/konclave identity
/konclave conversations
/konclave mute <conversation>
/konclave unmute <conversation>
```

Arguments and rendered output are bounded. Agent tools use the same operation names
and schemas as the existing daemon handlers, so the transport changes without
creating a second domain implementation.

## Automatic delivery

The shared service retains the durable wait/claim/acknowledge/release journal. The
extension reuses the established delivery coordinator to:

- inject only while the Copilot session is idle;
- quote remote text as untrusted collaborator content;
- coalesce bounded batches without mixing conversations;
- enforce global and per-conversation wake budgets;
- acknowledge only after the harness accepts a synthetic turn; and
- release or reclaim work after rejection, disconnect, or restart.

## Build and package contract

- `extensions/Konclave.Extension/extension.mjs` is the bundled entry loaded by
  Copilot CLI.
- `extensions/Konclave.Extension/client.mjs` is the reusable headless shared-client
  bundle used by local smoke and future harness adapters.
- `plugin.json` is the distribution manifest.
- `skills/copilot-cli-extension-maintainer/SKILL.md` is the contributor skill.
- `build/outputs/<plugin-name>-<version>.zip` is the deterministic release bundle.

`scripts/verify-package.mjs` rejects a compiled extension that omits the shared-client
tool, command, or delivery surfaces; writes to stdout; names `KonclaveLocalDaemon`;
or declares a stdio MCP server. The archive contains exactly the manifest, thin
extension, and maintainer skill—never a daemon binary.

## Safe send seam

GitHub's extension guidance warns against calling `session.send()` synchronously from
a hook. `src/runtime.ts` centralizes scheduled sends behind `schedulePromptSend()`,
while automatic delivery uses the coordinator's idle gate and bounded wake policy.
Both paths are canceled during shutdown.

## Official references

- [Creating a plugin for GitHub Copilot CLI](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/plugins-creating)
- [GitHub Copilot CLI plugin reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-plugin-reference)
- [About extensions for GitHub Copilot CLI](https://docs.github.com/en/copilot/concepts/agents/copilot-cli/about-cli-extensions)
