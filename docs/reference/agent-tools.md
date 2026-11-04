# Agent tools and workflows

This reference is for agents and harness authors using the matching installed
Konclave service. Operators use [deterministic slash commands](../../extensions/Konclave.HostExtension/docs/copilot-cli-extension.md)
instead. The tool schema validates shape; native authentication, membership, policy,
capability and size checks still decide whether an operation is admitted.

The [complete field reference](agent-tool-contracts.md) is generated from the native
router's existing fixture and the extension's **production agent-visible projection**.
It covers every registered tool's parameters and result fields. It is not a second
operation registry. The [full JSON schemas](../../fixtures/local-service/v1/copilot-tools.json)
also contain reusable nested result definitions and service-only metadata.

## Identifier and result conventions

| Value | Meaning |
| --- | --- |
| `conversation_id`, `device_id`, routing ID, policy digest | 32 bytes encoded as 64 hex characters; identifiers are not credentials. |
| Message, proposal, pairing, verification-attempt identity | 16 bytes encoded as 32 hex characters; these are different identity domains, not interchangeable tokens. |
| Capability, compact rendezvous token | Secret one-time handoff data. Preserve exact encoding and expiry; never log it or treat it as membership. |
| Invitation, JoinProof, Welcome, canonical bundle | Hex-encoded native bytes, not a file path or a JSON representation. |
| Cursor | Durable ordering/continuation value, not a timestamp, record offset or count of matching messages. |
| `epoch`, `sender_counter` | Authenticated MLS epoch and application sender counter, not wall-clock ordering. |
| Timestamp/deadline suffix | `_unix_seconds` is seconds; `_unix_milliseconds` is milliseconds. Sender timestamps are not trusted global time. |
| Policy `u64` status values | Canonical decimal strings to preserve precision across JavaScript; null means unlimited for resolved limits. |

JSON Schema distinguishes a required property from a nullable property. Follow each
field's semantics rather than converting missing values to empty strings, zero or
`false`. Raw native `u64` JSON numbers can exceed JavaScript's safe integer range;
do not round a value and send it back as an exact identifier, counter or deadline.

Success is scoped: `create_conversation` creates local state, not a remote member;
`send_message`/`send_directed_request` returns the local send's identity, counter and
relay cursor, not proof of remote execution. `local_binding_changed` is the recorded
historical result of an exact policy operation, not a read of current policy.
`has_more` and `next_cursor` describe bounded scan progress, including empty pages.
`delivery_status` describes local event delivery, not a global peer task state.

## Choose a workflow

| Task | Tools and next actions |
| --- | --- |
| Inspect/select | `get_identity`, `list_conversations`, `set_active_conversation`, `delivery_status`. Inspect authenticated identities before pairing; selection is durable profile state. |
| High-level pairing | Create/redeem capability or rendezvous; inspect/authorize each role, then `sync_pairing`. Resume with the same pairing ID or cancel; creating a new capability is not retrying the old ceremony. |
| Short-code pairing | Create/claim the code, inspect/sync the attempt and wait for explicit operator confirmation on both devices. Agents cannot confirm SAS. Cancellation uses the attempt ID, not its code. |
| Low-level membership | Create invitation, create JoinProof, add member and accept Welcome. Roles/removal require native membership authority; these primitives are not a substitute for independent identity confirmation. |
| Messages/requests | Send stable IDs, inspect bounded history, sync/watch remote records. A directed target selects the responder but does not hide plaintext from other group members. |
| Private request services | Create a channel for an expected requester, enroll with ordinary verified pairing, then inspect operator channels/inbox. Roles are immutable and inspection grants no work authority. |
| Structured policy | Compile/propose an explicit source or canonical bundle, inspect exact received bytes/metadata, explicitly accept/reject, resume committed proposals or revoke matching authority. |
| Wake control | `set_auto_delivery` mutes/unmutes events, not membership, history, existing claims or ordinary permissions. |

Use the [pairing and command guide](../../extensions/Konclave.HostExtension/docs/copilot-cli-extension.md),
[request-service lifecycle](../development/request-services.md),
[policy authoring](../../policy/README.md) and [safe recovery](recovery.md) for
preconditions, human actions and complete examples.

## Minimal exact-retry example

Assume the authenticated profile already owns a conversation with exactly one remote
member and the caller has local permission to initiate the request. Substitute the
displayed conversation identity and generate one fresh 16-byte message identity:

```json
{
  "conversation_id": "<conversation-id-as-64-hex>",
  "message_id": "<fresh-message-id-as-32-hex>",
  "text": "Return one bounded status summary."
}
```

These are deliberate non-executable placeholders for `send_directed_request`, not a
valid ready-to-send payload. In a group, also supply `target_device_id`. After an
ambiguous disconnect, retain the exact ID, target, body and optional delivery fields;
a new ID initiates new work. Inspect history/diagnostics before deciding to replay
external effects. A receiver without independently activated work authority only
gets a notification.

`delivery_receipts` requests encrypted history-only outcome observations.
`expires_at_unix_milliseconds` is an absolute **admission** cutoff, not cancellation
of already admitted work, a relay TTL or a promise to execute before that instant.
The [delivery contract](../adr/adr-0033-request-delivery-semantics.md) owns the exact
history-only outcomes and unsupported-peer behavior.

For a locally authorized final reply, the agent supplies the exact conversation,
stable reply message ID, original `reply_to_message_id` and answer text to
`send_message`. The extension supplies its one-use authorization; agents never
manufacture, copy or pass the hidden native authorization field. A terminal answer
does not request another reply. Request-service channels reject claim-free replies,
including an ordinary manual slash reply.

## Local operations are not automatically agent tools

Trusted-device aliases, repeat-pairing helpers, short-code confirmation, diagnostics,
delivery claim/heartbeat/ack/release and local policy admission have separate service
or operator boundaries. They do not become model-callable because they appear in a
service enum or generated raw schema. `confirm_short_code_pairing` is deliberately
excluded from agent registration. Never turn a Copilot evidence failure into a
Generic fallback.

## Maintain and verify the generated reference

Authored field descriptions belong in
[`mcp.rs`](../../apps/Konclave.LocalDaemon/src/mcp.rs).
Its ignored `regenerate_copilot_tool_contract_fixture` test writes the existing
fixture; `copilot_tool_contract_fixture_matches_the_router` checks it against the
live router. [`tools.ts`](../../extensions/Konclave.HostExtension/src/service/tools.ts)
owns the projection, while
[`operations.ts`](../../extensions/Konclave.HostExtension/src/service/operations.ts)
owns the shared operation inventory.

From the repository root, regenerate native metadata with the existing owner:

```sh
cargo test --locked --package KonclaveLocalDaemon --lib mcp::tests::regenerate_copilot_tool_contract_fixture -- --ignored --exact
```

Then from `extensions/Konclave.HostExtension`, regenerate the Markdown projection
and command-help block:

```sh
KONCLAVE_GENERATE_REFERENCE=1 npm run test:unit -- tests/documentation.test.ts
```

The environment assignment above uses a POSIX shell; in PowerShell set
`$env:KONCLAVE_GENERATE_REFERENCE = '1'` for that command and remove it afterward.
Without that flag the test is read-only and refuses drift or undocumented projected
inputs/results. Nested definitions and tagged message variants come from the same
schema. The same test projects the compiled TypeScript workspace example; native
module rustdoc includes the Rust integration guide for executable doctests.
The hosted Documentation contracts check regenerates through both owners,
exports the generated files for inspection and fails on a submitted-source delta.
Inspect generated diffs; never hand-edit the fixture or generated field tables.
