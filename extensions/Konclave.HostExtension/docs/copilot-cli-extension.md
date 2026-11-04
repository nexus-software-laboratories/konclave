# Copilot CLI extension

For installation and first use, start with the
[unsigned prerelease guide](../../../docs/distribution/installation.md), then the
[two-session demo](../../../docs/distribution/local-demo.md).
The [agent-tool reference](../../../docs/reference/agent-tools.md) describes the
separate model-callable surface. Slash commands are deterministic operator actions,
not prompts to a model.

## Runtime boundary

The generated extension is a thin Node.js process that joins the foreground Copilot
CLI session with `@github/copilot-sdk/extension`. It registers:

- the bounded Konclave agent tools as native SDK handlers;
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

Installation writes `konclave.service.json` under Konclave's canonical platform data
root, outside the replaceable Copilot plugin or raw-extension directory. A bounded
development override may name that file with `KONCLAVE_SERVICE_CONFIG_FILE`. During
migration, a module-adjacent legacy sidecar is accepted only when its validated
authority values match the canonical record; the legacy record may omit the newer
UserPresence helper. Unsafe or conflicting canonical state never falls back to legacy
configuration. The record contains only:

- the local named-pipe or Unix-socket endpoint;
- the registered adapter key identifier and version;
- the authorized harness;
- the pinned service verification key; and
- an absolute path to the adapter signing-key custody record.

The extension never discovers an endpoint, trusts a network URL, broadens a
registration, or starts a service. Missing, malformed, unsafe, or unauthorized state
joins the Copilot session in a fail-closed degraded state with only `/konclave`
repair guidance. It registers no tools, hooks, delivery, MCP server, or per-session
daemon until a later extension process authenticates to the repaired service.

A healthy connection registers policy-enforcement hooks and therefore requires the
user's Copilot extension-permission approval. Copilot withholds the entire extension
when that approval is denied; installation guidance must not represent plugin
presence alone as command activation.

The installed client gives initial authorization transport a two-second deadline.
That bound applies independently to the issuer exchange and the first session
handshake, so an endpoint that accepts a connection but never answers cannot consume
the ordinary 30-second operation deadline or hold Copilot startup indefinitely.
Missing endpoints normally fail immediately. UserPresence retains its longer
interactive ceremony window, while each service handshake and begin/complete
exchange remains subject to the startup transport bound.

On Unix, configuration and key records are opened with `O_NOFOLLOW`, verified through
the same descriptor as regular files owned by the current UID with no group or other
permissions, and read within hard byte limits. On Windows, the Rust installer creates
and verifies the canonical directory and both files with an explicit
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

Command output defaults to `normal`, which combines status and operation metadata
into concise summaries and suppresses diagnostic phase, grant, cursor, and policy
detail. `/konclave output verbose` restores the complete field-by-field view for the
current extension process; `/konclave output normal` switches back. The setting is
intentionally process-local and resets to normal on restart. Compact token handoff,
full-capability recovery, exact retry identifiers, policy accept/reject commands,
message bodies, and explicit policy inspection remain visible when they are required
to continue safely.

<!-- command-reference:start -->

```text
Konclave commands (deterministic; no model inference):
  /konclave help                                      Show this list.
  /konclave output <normal|verbose>                   Set command detail for this session.
  /konclave status                                    Show profile, delivery, and relay state.
  /konclave diagnose [conversation] <message>         Explain body-free local delivery evidence.
  /konclave identity                                  Show this profile device identifier.
  /konclave conversations                             List local conversation identifiers.
  /konclave devices                                   List local trusted-device aliases.
  /konclave device alias <device> <alias>             Bind a local alias to a current member.
  /konclave connect [--copy|--qr]                     Create a compact two-session connection token.
  /konclave connect --short                           Create a six-digit mutually verified connection code.
  /konclave connect <six-digit-code>                  Join a short-code verification attempt.
  /konclave connect <token>                           Join and complete an AccountTrusted connection.
  /konclave connect <konclave://pair/token>           Join from a pairing deep link.
  /konclave connect resume <pairing>                  Resume one interrupted AccountTrusted connection.
  /konclave clipboard clear                           Clear a token copied by this session.
  /konclave pair [member|administrator]               Create a full recovery capability.
  /konclave join <capability>                         Redeem a full recovery capability.
  /konclave new                                       Create an empty conversation.
  /konclave new <alias>                               Create and connect a new conversation.
  /konclave service create <requester-device>        Create and select a private directional operator channel.
  /konclave service channels [after-conversation]   Inspect a bounded operator-private channel page.
  /konclave service inbox [conversation] [after-cursor]
                                                       Inspect local unreplied requests; no work permission is granted.
  /konclave repeat <operation>                        Resume one alias-based connection.
  /konclave cancel-repeat <operation>                 Cancel one alias-based connection.
  /konclave pairing <pairing>                         Show authenticated pairing state.
  /konclave verification <attempt>                    Show short-code verification state.
  /konclave verify <attempt> <peer> <sas>             Explicitly confirm displayed short-code values.
  /konclave approve <pairing> [conversation] [role]   Approve a displayed joiner; defaults to selected conversation and member.
  /konclave approve <pairing> <inviter> <conversation> <role>
                                                       Approve displayed inviter fields.
  /konclave sync <pairing>                            Process one pairing progress page.
  /konclave cancel <pairing>                          Cancel an active pairing.
  /konclave cancel-verification <attempt>             Cancel a short-code verification attempt.
  /konclave send [conversation] [message-id] -- <text>
                                                       Send or retry a message.
  /konclave request [conversation] [target-device] [message-id] -- <text>
                                                       Positional group targets require a conversation ID.
  /konclave request [conversation] [message-id] --to <device> -- <text>
                                                       Target a peer in the selected or explicit conversation.
  /konclave reply [conversation] <reply-to> [message-id] -- <text>
                                                       Reply or retry with an explicit ID.
  /konclave messages [conversation] [after-cursor]    Sync and show newest-first history with UTC timestamps.
    --order asc|desc --before-cursor <cursor>          Choose cursor order and a backward page bound.
    --since <RFC3339> --until <RFC3339>                Sender timestamp range [since, until); explicit timezone required.
  /konclave use <conversation>                        Select the implicit conversation.
  /konclave mute [conversation]                       Mute automatic delivery.
  /konclave unmute [conversation]                     Resume automatic delivery.
  /konclave policy status                             Show active policy metadata.
  /konclave policy propose [proposal-id] -- <source>  Compile and propose a policy.
  /konclave policy replace <digest> [proposal-id] -- <source>
                                                       Replace the active policy.
  /konclave policy resume <proposal-id>                Resume a committed proposal.
  /konclave policy inspect <proposal-id>               Review a peer proposal.
  /konclave policy accept <proposal-id> <digest>      Accept an exact proposal.
  /konclave policy reject <proposal-id> <digest>      Reject an exact proposal.
  /konclave policy revoke <digest> [message-id]       Revoke the active policy.
```

<!-- command-reference:end -->

`/konclave connect` prints the raw 26-character token ephemerally. `--copy` writes
only that token to the native clipboard without placing it in process arguments and
does not echo it again. `--qr` renders a bounded terminal QR code containing
`konclave://pair/<token>` plus an accessible raw-token fallback. Pasting either the
URI or raw token into `connect` follows the same validation path. Every handoff names
the expiry and warns that the token is a one-time bearer secret. Unsupported
clipboards, narrow terminals, and non-interactive output degrade to the raw token.
After a successful copy, `/konclave clipboard clear` explicitly replaces the current
clipboard content with empty text.

`/konclave connect --short` instead creates a six-digit OPAQUE code that grants no
authority. The other computer enters it with `/konclave connect <six-digit-code>`.
Both commands wait for the encrypted identity exchange, then display the exact attempt,
local and peer device identifiers, common deadline, and six-digit SAS. Each operator
must compare those values through an independent channel and run the displayed
`/konclave verify <attempt> <peer> <sas>` command. The extension never infers or
automates that confirmation, and the confirmation operation is deliberately absent
from the registered agent-tool table. Only after both exact confirmations authenticate
does the daemon create an ordinary member-only capability and continue the existing
durable pairing flow. `/konclave verification <attempt>` resumes inspection and
`/konclave cancel-verification <attempt>` cancels the attempt.

Trusted-device aliases are local sealed address-book entries, not protocol
identities. `/konclave device alias <device> <alias>` accepts only a device currently
authenticated in local conversation membership and binds the alias to that exact
device root. `/konclave new <alias>` requests a fresh member capability over the
lowest qualifying existing MLS conversation and reuses the durable pairing flow to
create a separate conversation. The alias never appears on the wire, and the internal
request and response are excluded from message history and adapter delivery.
`/konclave repeat <operation>` resumes an interrupted attempt;
`/konclave cancel-repeat <operation>` cancels it.

Arguments and rendered output are bounded. High-level commands orchestrate only the
existing closed operations; they do not implement a second pairing or messaging
domain. Under `AccountTrusted`, `/konclave connect` treats the explicit transfer and
redemption of one short-lived capability as the configured approval evidence, grants
only `member`, and drives both durable pairing state machines to completion. It
labels that policy as capability-possession trust and never claims independent
identity verification. The short-code variant labels its independent mutual
verification and remains member-only. Stronger evidence policies and administrator
grants retain the manual approval workflow. The command refuses before creating pairing or conversation
state when no relay is configured. Every progress request receives the remaining
pairing/command deadline, non-advancing phases back off, and normal output identifies
the next device action with a live countdown. The command remains active for the
daemon's complete authorization and completion windows. Failures provide
`/konclave connect resume <pairing>`, pairing-status, and cancellation commands so an
interrupted extension process can continue the same durable pairing. A command
deadline requests bounded cancellation before returning, and `connected` is emitted
only after the completed conversation is present in the local profile.

`/konclave approve` reads authenticated pairing state before selecting the
role-specific authorization operation. Inviter-side approval defaults to `member`;
granting `administrator` is explicit. Joiner-side approval requires the operator to
repeat the displayed inviter, conversation, and role, and rejects any mismatch. The
inviter may supply an existing conversation explicitly or use the durable selected
conversation. `/konclave approve <pairing> administrator` is the explicit elevated
inviter form; it cannot elevate a request that asked only for member. Joiner approval
never substitutes remote metadata for the operator's explicit confirmation.

When `send` or `reply` generates a message identifier, it displays the identifier and
an exact retry shape before submitting the operation. Supplying that identifier on a
retry preserves both message and request idempotency. Implicit operations resolve
the daemon's durable selected conversation afresh; `/konclave use <conversation>`
changes that selection, including across extension restarts and agent-tool changes.
An explicit conversation overrides selection. No selection is an actionable failure,
not permission to guess from list order.

`request --to <device>` targets a member of the selected or explicit conversation.
The legacy positional target requires an explicit conversation; a leading 64-hex
identifier still means a conversation, not an inferred device. Options precede `--`;
text after it is message content. Omit a target only when there is exactly one remote
member. Directed targeting does not hide plaintext from the group's other members.
Use a [request-service channel](../../../docs/development/request-services.md) for
independently private requester-to-operator exchanges. Its enrollment and inbox
inspection do not grant work authority.

`messages` syncs one bounded relay page and returns at most ten displayed records,
newest durable cursor first, with UTC timestamps. `--order asc` restores oldest-first
browsing. Raw `read_messages` callers retain their ascending default. A positional
`after-cursor` is always an exclusive lower bound; descending continuation uses
`--before-cursor`. Follow the emitted continuation, preserving conversation, order
and filters even when a filtered page is empty.

`--since` is inclusive and `--until` exclusive. Both require RFC 3339 instants with
an explicit timezone, normalized to UTC; either may appear alone. Filtering uses the
authenticated sender's timestamp, not a trusted global clock or execution deadline.
Cursor order remains authoritative. Out-of-order clocks do not terminate a scan,
and bounded scanning can return no matches with more history still available.

### A first directed exchange

Both sessions need a healthy matching native/plugin installation and configured relay.
Create a connection in session A with `/konclave connect`, redeem its displayed
one-time token in session B with `/konclave connect <token>`, and wait for both to
report a completed conversation. Do not publish the token.

```text
/konclave conversations
/konclave use <conversation-id>
/konclave send -- Hello from the selected conversation.
/konclave request --to <peer-device-id> -- Return one status summary.
/konclave messages
/konclave messages --since 2026-10-01T00:00:00Z --until 2026-11-01T00:00:00Z
```

Replace placeholders with authenticated values shown by the commands. A send result
proves the local send outcome, not acceptance or execution of the requested work.
Without an explicitly activated local policy at the receiver, delivery remains a
notification, not autonomous authority. The receiver can inspect history without
starting a model turn. Reuse the printed message ID and exact text for an ambiguous
retry; a new ID means a new operation. Clear a copied pairing token with
`/konclave clipboard clear`. See the [policy workflow](../../../policy/README.md)
before enabling automation and [recovery reference](../../../docs/reference/recovery.md)
when a connection, request or delivery is interrupted.

Policy commands use the profile's active conversation. `propose` and `replace` read
one explicitly selected UTF-8 regular source beneath the current workspace, enforce
the source-size bound before transport, and send the source over the authenticated
local-service channel for Rust compilation into the canonical bundle. Absolute
paths, traversal, non-files, invalid UTF-8, and oversized content fail before a
policy operation. A generated proposal identifier is displayed with a source-independent
`resume` command before submission; resume reconstructs the exact canonical bundle
from the daemon's terminal journal, so editing the source requires a new proposal
identifier. Revocation displays an exact retry command. `accept` and `reject` require
the complete proposal identifier and digest. `inspect` renders the authenticated
proposal metadata and peer-proposed guidance as explicitly untrusted ephemeral data
before displaying exact accept and reject commands. `status` returns bounded active
metadata but not guidance or canonical source content. JSON `u64` values are returned
as canonical decimal strings so JavaScript never truncates a valid policy limit.

Automatic policy-proposal delivery shows the complete proposal identifier plus the
exact local `inspect` command. It remains inside the untrusted collaborator fence and
does not activate policy or instruct the model to accept it.

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

After a service outage, delivery continues its capped exponential retry policy but
does not emit one error per attempt. It reports the first occurrence of each finite
failure class and power-of-two milestones across the current outage, then resets
suppression after a valid heartbeat or claim response. A 50,000-attempt identical
outage therefore emits 16 diagnostics. Transport exceptions are reduced to bounded
class labels rather than copying arbitrary error text into extension logs.

When a conversation has a locally active collaboration policy, the delivery client
asks the shared service to authorize `conversation.reply` before injecting the
synthetic turn. The service requires an authenticated Copilot grant, the profile's
live single-consumer delivery lease, the exact active digest, all bundle-required
harness claims, and a positive evaluator result. Inactive, denied,
approval-required, malformed, or unavailable authorization preserves the original
notification-only prompt.

An authorized prompt places only locally accepted structured policy identity outside
the collaborator fence, then keeps every peer message inside the same untrusted
markers. Legacy bundle guidance is never included in a model turn. The prompt
authorizes evaluating peer data under the local structured policy; it never
reclassifies peer text as user or developer authority.

Directed requests use durable exact-attempt claim and terminal-response reservation.
An independently activated local policy may authorize `session.work` and one
correlated final response; a response does not itself request another response.
Exact locally authorized answers can resume a waiting requester continuation.
Admission, history-only delivery receipts and relay acknowledgments do not prove
external work executed, nor do they guarantee exactly-once external effects.

The gate is prepared before enqueue but becomes active only when the session observes
the exact synthetic prompt carrying a fresh extension-generated turn token. Any
ordinary user prompt clears the pending gate. This prevents an enqueue race from
applying collaboration restrictions or authority to a foreground user turn. If the
already-enqueued token-bearing collaboration prompt arrives after that clearance,
the extension recognizes its trusted header and denies every tool for that delayed
turn instead of running it without the policy gate.

The pre-tool hook intersects the locally active structured policy with ordinary
Copilot permissions. Reply-only turns allow only the exact authorized send.
Locally enabled `session.work` turns additionally admit the bounded classified
workspace/tool actions described by [Copilot delivery safety](../../../docs/development/copilot-delivery-safety.md);
they cannot broaden policy, permission, trust or membership. The hook supplies a
one-use native reply authorization after verifying the exact conversation and
message arguments. The sender-counter/outbox reservation transaction rechecks the
active digest, delivery consumer and expiry. Peer text cannot grant this authority.
Interactive and delivery lanes keep fresh per-connection handshake identifiers. The
daemon recognizes them as one policy-enforcement consumer only because both prove the
same memory-only session public key.

The initial paved integration proves `harness.session-identity`,
`harness.pre-tool-policy-gate`, `harness.native-permission-intersection`, and
`harness.single-delivery-consumer`. One delivery consumer plus one outstanding
synthetic turn enforces collaboration concurrency conservatively at one. Finite
duration is enforced from the sealed activation time. Finite turn and token limits
deny autonomous turns until durable accounting is implemented; they are never
silently treated as enforced. Explicitly unlimited turn and token values remain
supported.

A replacement authenticated delivery connection may resume only the exact still-live
handling attempt for the same stable consumer, request, responder and policy.
A fresh lease generation fences the displaced socket; expired attempts are not
revived. See [delivery recovery](../../../docs/development/copilot-delivery-safety.md)
for the boundary and its limitations. The extension's heartbeat stays independent
of a blocked owned prompt flush, but this is not a cancellation guarantee for an
arbitrarily blocked harness or event loop.

## Build and package contract

- `extensions/Konclave.Extension/extension.mjs` is the bundled entry loaded by
  Copilot CLI and copied into
  `com.github.copilot/extensions/konclave/extension.mjs` in the Agent Plugin.
- `extensions/Konclave.Extension/client.mjs` is the reusable headless shared-client,
  command, policy-gate, delivery-parser, and safety-framing bundle used by the local
  smoke and future harness adapters. It is native-package support content, not a
  separate Agent Plugin entry.
- `plugin.json` is the closed Agent Plugins 1.0 distribution manifest.
- `skills/copilot-cli-extension-maintainer/SKILL.md` is the contributor skill.
- `skills/konclave-generic/SKILL.md` and the Generic bundle are native-package
  support content for manual installation by unsupported harnesses. Neither is in
  the Copilot Agent Plugin.
- `build/outputs/<plugin-name>-<version>.zip` is the deterministic release bundle.

`scripts/verify-package.mjs` rejects a compiled extension that omits the shared-client
tool, command, or delivery surfaces; writes to stdout; names `KonclaveLocalDaemon`;
or declares a stdio MCP server. The archive contains exactly `plugin.json`, the thin
extension, and its generated runtime `package.json`—never source, tests, skills,
build tooling, `node_modules`, a daemon binary, credentials, a client sidecar, or
mutable authority state.

## Safe send seam

GitHub's extension guidance warns against calling `session.send()` synchronously from
a hook. `src/runtime.ts` centralizes scheduled sends behind `schedulePromptSend()`,
while automatic delivery uses the coordinator's idle gate and bounded wake policy.
Both paths are canceled during shutdown.

## Official references

- [Creating a plugin for GitHub Copilot CLI](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/plugins-creating)
- [GitHub Copilot CLI plugin reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-plugin-reference)
- [About extensions for GitHub Copilot CLI](https://docs.github.com/en/copilot/concepts/agents/copilot-cli/about-cli-extensions)
