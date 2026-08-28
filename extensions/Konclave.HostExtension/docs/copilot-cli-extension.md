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
inject a user turn, or interpret command text as an instruction. Bounded command
results are awaited through the SDK's `session.log()` API so they appear in the
interactive transcript; stderr remains reserved for extension diagnostics. Pairing
capabilities and peer text are emitted as ephemeral timeline entries so the CLI does
not persist those sensitive values as command output.

```text
/konclave help
/konclave status
/konclave identity
/konclave conversations
/konclave connect
/konclave connect <capability>
/konclave pair [member|administrator]
/konclave join <capability>
/konclave new
/konclave pairing <pairing>
/konclave approve <pairing> <conversation> [role]
/konclave approve <pairing> <inviter> <conversation> <role>
/konclave sync <pairing>
/konclave cancel <pairing>
/konclave send [conversation] [message-id] -- <text>
/konclave reply <conversation> <reply-to> [message-id] -- <text>
/konclave messages <conversation> [after-cursor]
/konclave mute <conversation>
/konclave unmute <conversation>
/konclave policy status
/konclave policy propose [proposal-id] -- <relative-source>
/konclave policy replace <digest> [proposal-id] -- <relative-source>
/konclave policy resume <proposal-id>
/konclave policy accept <proposal-id> <digest>
/konclave policy reject <proposal-id> <digest>
/konclave policy revoke <digest> [message-id]
```

Arguments and rendered output are bounded. High-level commands orchestrate only the
existing closed operations; they do not implement a second pairing or messaging
domain. Under `AccountTrusted`, `/konclave connect` treats the explicit transfer and
redemption of one short-lived capability as the configured approval evidence, grants
only `member`, and drives both durable pairing state machines to completion. It
labels that policy as capability-possession trust and never claims independent
identity verification. Stronger evidence policies and administrator grants retain the
manual approval workflow. The command refuses before creating pairing or conversation
state when no relay is configured. Every progress request receives the remaining
pairing/command deadline, non-advancing phases back off, phase changes are rendered,
and failures leave explicit pairing-status and cancellation commands.

`/konclave approve` reads authenticated pairing state before selecting the
role-specific authorization operation. Inviter-side approval defaults to `member`;
granting `administrator` is explicit. Joiner-side approval requires the operator to
repeat the displayed inviter, conversation, and role, and rejects any mismatch. The
inviter supplies an existing conversation explicitly, which avoids hiding a
non-atomic create-and-authorize sequence.

When `send` or `reply` generates a message identifier, it displays the identifier and
an exact retry shape before submitting the operation. Supplying that identifier on a
retry preserves both message and request idempotency. `send` may omit the conversation
identifier only when the profile owns exactly one conversation. `messages` syncs one bounded
relay page, reads at most ten records after the requested cursor, and displays an
explicit resume cursor.

Policy commands use the profile's active conversation. `propose` and `replace` read
one explicitly selected UTF-8 regular source beneath the current workspace, enforce
the source-size bound before transport, and send the source over the authenticated
local-service channel for Rust compilation into the canonical bundle. Absolute
paths, traversal, non-files, invalid UTF-8, and oversized content fail before a
policy operation. A generated proposal identifier is displayed with a source-independent
`resume` command before submission; resume reconstructs the exact canonical bundle
from the daemon's terminal journal, so editing the source requires a new proposal
identifier. Revocation displays an exact retry command. `accept` and `reject` require
the complete proposal identifier and digest; `status` returns bounded active metadata
but not guidance or canonical source content. JSON `u64` values are returned as
canonical decimal strings so JavaScript never truncates a valid policy limit.

Automatic policy-proposal delivery now shows complete identifiers plus the exact
local review command. It remains inside the untrusted collaborator fence and does not
activate policy or instruct the model to accept it.

Ephemeral SDK logs remain visible to the terminal and in-memory session consumers;
they are not a confidentiality boundary. Pairing capabilities are protected by their
short lifetime, one-time consumption, bounded handling, and daemon-side zeroization.
The ephemeral flag prevents the extension's command output from adding those values
to the persisted session event log. The `/konclave join` command text can still remain
in local CLI input history until the capability is consumed or expires; operators
must not copy it into diagnostics or public artifacts. Agent tools use the same
operation names and schemas as the existing daemon handlers.

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
  and command bundle used by local smoke and future harness adapters.
- `plugin.json` is the distribution manifest.
- `skills/copilot-cli-extension-maintainer/SKILL.md` is the contributor skill.
- `skills/konclave-generic/SKILL.md` is packaged for manual installation by
  unsupported harnesses; the manifest's empty skill list prevents Copilot from
  auto-loading it.
- `build/outputs/<plugin-name>-<version>.zip` is the deterministic release bundle.

`scripts/verify-package.mjs` rejects a compiled extension that omits the shared-client
tool, command, or delivery surfaces; writes to stdout; names `KonclaveLocalDaemon`;
or declares a stdio MCP server. The archive contains exactly the manifest, thin
extension, reusable clients, and documented skills—never a daemon binary.

## Safe send seam

GitHub's extension guidance warns against calling `session.send()` synchronously from
a hook. `src/runtime.ts` centralizes scheduled sends behind `schedulePromptSend()`,
while automatic delivery uses the coordinator's idle gate and bounded wake policy.
Both paths are canceled during shutdown.

## Official references

- [Creating a plugin for GitHub Copilot CLI](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/plugins-creating)
- [GitHub Copilot CLI plugin reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-plugin-reference)
- [About extensions for GitHub Copilot CLI](https://docs.github.com/en/copilot/concepts/agents/copilot-cli/about-cli-extensions)
