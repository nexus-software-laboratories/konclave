# Local message delivery diagnostics

The authenticated local service exposes `get_message_delivery_status` for one
explicit conversation and message in its already-bound profile. ADR 0026 owns the
privacy and evidence boundary. This operation is available to deterministic
commands and explicit clients, not the agent tool catalog.

## Request and response

The request has exactly `conversation_id` and `message_id`, using the existing
canonical lowercase hexadecimal identifiers. It accepts no profile override or
additional fields. Profile-operation authority and the local read authorization
hook are required before storage lookup.

The response contains exactly:

| Field | Meaning |
|---|---|
| `message_status` | One finite authenticated local milestone |
| `auto_delivery_enabled` | The conversation's current local delivery setting |
| `profile_delivery_degraded` | The profile-wide supervisor flag, not a message-specific failure |
| `remote_outcome` | Always `unknown` |

No identifier, content, credential, capability, path, arbitrary error string or
metadata map is echoed. An invalid request, unavailable profile, storage failure or
failed authentication of state is an operation failure, never an empty healthy
result.

## Evidence

| Status | What is established |
|---|---|
| `not_observed` | No inspectable authenticated local record was found |
| `outbound_prepared` | Local content is sealed, but its envelope is not ready |
| `awaiting_relay_acceptance` | The sealed envelope is ready; acceptance has not been observed |
| `relay_accepted` | A sealed cursor observation proves an observed relay receipt |
| `outbound_expired` | The local terminal marker agrees with the sealed envelope deadline |
| `outbound_removed` | Authenticated membership state stopped the pending outbound operation |
| `inbound_prepared` | Content is sealed, but contiguous completion was not observed |
| `persisted_inbound` | Inbound completion is verified; no notification is retained |
| `awaiting_harness_delivery` | A retained notification is pending |
| `claimed_for_delivery` | A consumer claimed the notification |
| `acknowledged_by_harness` | The harness acknowledged the notification |
| `delivery_suppressed` | Local policy suppressed the notification |
| `request_claim_recorded` | A request claim has a future recorded expiry |
| `request_claim_expired` | The recorded claim expiry has elapsed |
| `response_reserved` | One correlated response is reserved |
| `completed_without_response` | Local request handling ended without reserving a response |

Neither acknowledgment nor a claim proves model execution. Claim expiry alone does
not prove consumer liveness or authorize another attempt. A response reservation
does not establish envelope submission or delivery. Relay receipts do not establish
remote persistence or future relay availability.

`not_observed` also covers hidden internal application records and unsealed
reservations. It is not proof that nothing happened remotely. Notification retention
may remove a terminal notification while authenticated message history remains.
Changing the current mute setting does not change an earlier suppression outcome.

## Existing client surfaces

The paved Copilot CLI command is:

```text
/konclave diagnose <conversation-id> <message-id>
```

It renders bounded, ephemeral explanations without starting a model turn, repairing
delivery or changing permissions. The packaged client exports
`getMessageDeliveryStatus(client, conversationId, messageId, options?)` for an already
authenticated `LocalServiceClient`.

Other supported Generic integrations may explicitly select
`--operation get_message_delivery_status` with the same request JSON. This is not a
fallback for a failing paved integration and never discovers another profile.
An older service reports an unsupported operation instead of falling back.

An explicit local request identifier retains normal reconciliation semantics:
retrying it retrieves the original observation. Use a fresh request identifier for a
fresh inspection. Neither read mode retries the selected message; an uncertain send
must be reconciled through its original operation and message identities.

## Storage and disclosure

The query opens the selected bounded sealed history and directly associated records.
Notification lookup uses the existing unique conversation/cursor index. Handling
lookup uses its conversation/request/responder primary key. There is no new schema,
history scan, per-message write, network probe or diagnostic retention table.
Underlying read-request reconciliation may retain a bounded sealed result.

Cursor, context, notification and handling authentication failures stop the read.
Clear columns alone are not accepted as proof of delivery. Internal decryption stays
inside the existing trusted daemon; only the finite projection crosses local IPC.

Output is not automatically exported. Even body-free status can disclose activity;
any saved output or support handoff remains an explicit operator disclosure.
