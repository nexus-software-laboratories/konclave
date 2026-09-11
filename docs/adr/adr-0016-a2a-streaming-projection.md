---
title: Project A2A streaming from durable task status history
status: Accepted
date: 2026-09-11
authors:
  - Konclave maintainers
tags:
  - a2a
  - streaming
  - sse
  - tasks
supersedes: []
superseded_by: []
---

# Project A2A streaming from durable task status history

## Context and scope

ADR 0013 deliberately shipped a non-streaming first A2A profile and required a
separate bounded semantic mapping before advertising streaming. ADR 0014 already
persists every task transition as an ordered generation record. The reference
gateway now needs to expose that durable state through the pinned A2A 1.0
HTTP+JSON streaming operations without inventing a second task authority.

This decision owns `SendStreamingMessage`, `SubscribeToTask`, Server-Sent Events
(SSE) framing, reconnection, finite stream lifetime, event projection, and the
portable status-cursor read needed by the gateway. It does not add artifacts,
multi-turn interrupted states, push notifications, or task cancellation.

## Verified facts

- The vendored A2A v1.0.1 schema defines `SendStreamingMessage` at
  `POST /message:stream` and returns a stream of `StreamResponse`.
- The same schema annotates `SubscribeToTask` as
  `GET /tasks/{id}:subscribe`, while the v1.0.1 prose HTTP+JSON binding maps the
  operation to `POST /tasks/{id}:subscribe`.
- The prose binding requires `text/event-stream`, with each SSE `data` field
  containing one ProtoJSON `StreamResponse`.
- `SubscribeToTask` must emit a current `Task` as its first event and must reject a
  task that is already terminal.
- A stream closes at a terminal or interrupted state. If a connection ends while
  work remains active, the standard recovery operation is `SubscribeToTask`.
- A2A v1.0.1 defines no task-subscription page token, resume cursor, or
  `Last-Event-ID` contract.
- The SQLite task store already records generation zero and every later transition
  in `a2a_task_status`, in the same transaction that updates current task state.
- Disconnecting an HTTP observer does not retract a Konclave directed request and
  cannot authoritatively cancel the A2A task.

## Assumptions

- A finite SSE connection followed by standard resubscription is acceptable for
  long-running work.
- The text-only profile produces no incremental artifacts and completes with one
  authoritative agent text message.
- Managed and self-hosted stores can expose the same ordered status-after-generation
  semantic operation even when their storage engines differ.

## Decision drivers

- Preserve A2A v1.0.1 interoperability.
- Never skip an accepted task transition between gateway polls.
- Keep SQLite, managed storage, and HTTP transport behind portable semantic
  boundaries.
- Bound connection lifetime and per-event memory.
- Keep reconnect and disconnect behavior explicit without pretending that transport
  cancellation is task cancellation.

## Decision

### Use the standard HTTP+JSON SSE binding

The reference Agent Card advertises `capabilities.streaming: true`.
`SendStreamingMessage` uses `POST /message:stream`. Each successful response has
media type `text/event-stream`; each SSE `data` field is one validated ProtoJSON
`StreamResponse`.

The server accepts both `GET` and `POST` for `tasks/{id}:subscribe` because the
pinned schema annotation and the pinned prose binding disagree. The outbound client
uses `POST`, matching the prose HTTP+JSON mapping. Both spellings authenticate,
authorize, validate tenant and task identity, and produce identical events.

### Start every stream with one current Task snapshot

Both operations resolve all authentication, route, durable-task, and initial
projection failures before sending streaming headers.

`SendStreamingMessage` durably creates or reconciles the task and performs the same
idempotent downstream submission as `SendMessage`; `returnImmediately` does not
change streaming behavior. `SubscribeToTask` loads an existing task and returns
`UNSUPPORTED_OPERATION` when it is already terminal.

The first event is a bounded current `Task` snapshot. This snapshot and its durable
generation establish the internal observation cursor, eliminating the race between a
separate `GetTask` and subscription.

### Read every durable status after the internal generation cursor

The portable task store exposes consecutive status records after one previously
observed generation. The SQLite adapter reads `a2a_task_status` in generation order
and rejects a cursor ahead of current durable state.

The gateway emits one `TaskStatusUpdateEvent` per returned record and advances its
cursor only after projection. A poll that observes `WORKING` and `COMPLETED`
together therefore emits both in order rather than collapsing them to the current
state.

The generation cursor is an internal store/application value. It is not added to
A2A metadata, query parameters, SSE IDs, or another extension.

### Keep the streaming profile text-only

The admitted `StreamResponse` payloads are:

- the first current `Task`; and
- ordered `TaskStatusUpdateEvent` values.

Direct `Message` and `TaskArtifactUpdateEvent` payloads remain unsupported. A
completed status update carries the exact retained agent response as
`TaskStatus.message`. Failed, rejected, and canceled updates carry only the same
bounded immutable `konclave_terminal_reason` metadata used by `GetTask`.

### Bound streams and reconnect through the standard operation

One stream uses the existing validated gateway response deadline and polling
interval: 30 seconds and 250 milliseconds by default, with hard maxima of five
minutes and one second. SSE keep-alive comments may preserve intermediary
connections but do not extend the deadline or become protocol events.

If the deadline expires while the task remains active, the server closes the stream
without fabricating a task transition or proprietary end event. The client may call
`SubscribeToTask`; its first Task snapshot reconciles all state accepted while
disconnected.

Dropping a stream cancels only that HTTP observation future. It does not mutate,
fail, or cancel the durable task. `CancelTask` remains unsupported until Konclave
has an authoritative cancellation primitive.

### Bound and correlate outbound SSE parsing

The built-in client accepts only `text/event-stream`, ignores standard SSE comments
and non-data fields, and bounds each complete event before ProtoJSON decoding. The
first data event must be a Task. Every later event must retain the same task and
context identity; events after a terminal response are rejected except for the
optional final terminal Task snapshot allowed by A2A.

The existing protected HTTP client continues to disable redirects and ambient proxy
discovery. Its finite total request timeout bounds a remote stream.

## Alternatives considered

### Poll only the current task row

This is smaller, but a task can move from `SUBMITTED` through `WORKING` to
`COMPLETED` between polls. Emitting only the latest state would violate ordered
stream semantics and erase an accepted transition. Rejected.

### Add a proprietary resume token or long-poll endpoint

An explicit wire cursor could replay every event, but A2A v1.0.1 does not define one.
It would make Konclave clients depend on a non-standard extension when the required
first Task snapshot and `SubscribeToTask` already provide state reconciliation.
Rejected.

### Keep streams open until task completion without a deadline

This reduces reconnects but leaves request slots, parser state, and intermediary
connections unbounded for offline agents. Rejected.

### Add an in-memory broadcast broker

Broadcast channels reduce SQLite polling, but process restart loses events and still
requires durable reconciliation. The small initial state machine does not justify a
second event authority. Deferred unless measurements show polling is insufficient.

## Consequences

- Standard A2A clients can stream and resubscribe while agent devices remain
  outbound-only.
- Durable status history, not scheduler timing, determines event order.
- Self-hosted and managed stores gain one small semantic read surface.
- Streams may close before long-running tasks finish; callers must resubscribe.
- Supporting both subscribe verbs is intentional compatibility behavior that must
  remain tested until the upstream v1.0.1 inconsistency no longer matters.
- Artifacts and multi-turn status messages still require their own bounded profiles.

## Confirmation

- Contract tests validate Task and status-update payloads and reject direct messages,
  artifacts, malformed identity, and missing terminal reasons.
- Store tests prove consecutive generation reads, exact resume, empty current reads,
  and rejection of an impossible future cursor.
- Application tests prove first-Task ordering, no skipped transitions, terminal
  closure, finite expiry, and terminal-subscription rejection.
- HTTP tests cover both subscribe verbs, SSE media/cache headers, authentication
  ordering, and bounded errors.
- Client tests cover incremental parsing, correlation, terminal closure,
  resubscription errors, CRLF, comments, multiline data, and event bounds.

## References

- [ADR 0013: A2A edge interoperability](adr-0013-a2a-edge-interoperability.md)
- [ADR 0014: A2A task projection store](adr-0014-a2a-task-projection-store.md)
- [A2A compatibility contract](../protocol/a2a-compatibility.md)
- Vendored A2A v1.0.1 schema:
  `third_party/a2a/v1.0.1/a2a.proto`
- Pinned upstream streaming guidance:
  `a2aproject/A2A@3303592588e388e62e0f69f701af531d2f4e3991`
