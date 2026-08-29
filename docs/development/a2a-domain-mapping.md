# A2A domain mapping

This document is the canonical owner of the pure mapping between validated A2A
requests and deployment-selected Konclave routes. It does not own HTTP handling,
task persistence, Agent Card publication, lifecycle transitions, or relay delivery.

## Boundary ownership

`Konclave.A2AContracts` owns generated wire DTOs and initial-profile validation.
`Konclave.A2ADomain` accepts only those validated values and maps them without network
or storage access.

The domain crate defines distinct opaque types for:

- published A2A agent identifiers;
- deployment-owned context and tenant identifiers;
- caller-owned message identifiers;
- gateway-owned task identifiers;
- artifact identifiers; and
- positional part indexes, because A2A `Part` has no wire identifier.

These types share the canonical A2A identifier bound but do not become Konclave
profile aliases, conversation identifiers, device identifiers, policy digests, or
relay routes.

## Deployment-owned routes

An `A2AAgentRoute` binds:

- one published agent identifier;
- one public A2A context identifier;
- one optional tenant;
- one configured Konclave `ConversationId`; and
- one exact target `DeviceId`.

The caller cannot supply or replace the Konclave values. A validated `SendMessage`
context may be omitted or must equal the configured context exactly. Its tenant must
equal the configured tenant exactly. `GetTask` lookups remain scoped to the same
published agent and tenant; the task store later proves task ownership.

## Deterministic task and request identity

One validated A2A source message maps to one A2A task and one Konclave directed
request. The mapper computes:

```text
digest = SHA-256(
    "konclave-a2a-task-mapping-v1\0" ||
    tenant_length_u16 || tenant_utf8 ||
    agent_length_u16 || agent_utf8 ||
    context_length_u16 || context_utf8 ||
    message_length_u16 || message_utf8 ||
    conversation_id[32] ||
    target_device_id[32]
)

konclave_request_message_id = digest[0..16]
a2a_task_id = lowercase_hex(konclave_request_message_id)
```

Lengths use unsigned big-endian encoding. An absent tenant contributes a zero length.
Every string component is already bounded to 128 bytes, and the internal identifiers
have fixed lengths, so encoding cannot truncate. Binding the configured conversation
and target prevents route replacement from aliasing one external task onto another
Konclave security boundary without exposing either identifier.

The request text does not contribute to identity. An exact retry reproduces the same
task and Konclave message identifiers; a retry that reuses the source message
identifier with different content reaches the same later storage key and must fail as
an idempotency conflict rather than creating a second task.

The mapper moves the validated request body into the directed-request mapping without
making it `Clone`, `Debug`, or serializable.

## Task state separation

`A2ATaskState` represents the A2A states `SUBMITTED`, `WORKING`, `COMPLETED`,
`FAILED`, `CANCELED`, `INPUT_REQUIRED`, `REJECTED`, and `AUTH_REQUIRED`. The
unspecified wire value fails conversion.

This enum is deliberately separate from Konclave delivery status, adapter leases,
directed-request handling claims, and response/no-response outcomes. Later task
lifecycle code may project observed Konclave facts into A2A state, but neither state
machine may be cast, stored, or interpreted as the other.

## Verification

Tests require:

- typed identifier rejection for noncanonical input;
- one fixed domain-separated mapping vector;
- deterministic exact retries and separation across source messages;
- tenant and context substitution rejection;
- agent-scoped `GetTask` mapping;
- explicit zero-based part identity; and
- complete A2A task-state wire round trips with unspecified-state rejection.
