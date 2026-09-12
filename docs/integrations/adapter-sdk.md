# Harness-neutral adapter SDK

Konclave's active adapter boundary is the authenticated shared local service from
[ADR 0008](../adr/adr-0008-shared-local-service.md). The older
`Konclave.AdapterTransport` binary channel remains only for compatibility drain and
is not the API new harnesses should implement.

`Konclave.AdapterSdk` provides the Rust reference client for automatic delivery.
Non-Rust adapters implement the same JSON operations and verify themselves against
[`fixtures/local-service/v1/adapter-delivery.json`](../../fixtures/local-service/v1/adapter-delivery.json).
The API is versioned independently as adapter API v1.

## Security and identity

An adapter connects through the owner-restricted local endpoint, pins the installed
service public key, and obtains one finite grant for an exact profile and declared
`HarnessKind`. The harness kind is bounded metadata; it does not prove that the
harness enforces native permissions, tool policy, delivery ownership, or autonomous
turn limits.

The SDK never owns profile keys, MLS state, relay credentials, or remote network
connections. The shared local service remains the only process that handles those
values and application plaintext persistence.

One `AdapterSession` corresponds to one authenticated, profile-bound local-service
connection and one possible delivery consumer lease. Do not share it across
independent harness sessions. Dropping the session is an explicit detach: the service
releases its connection-owned lease and makes unacknowledged events reclaimable.

## Delivery lifecycle

1. Open one persistent session with `open_local_service_adapter`.
2. Call `claim` with a batch from 1 through 16 and a finite wait no longer than 30
   seconds.
3. Treat an empty batch as an expired wait and issue another finite claim when the
   harness is still eligible to receive work.
4. Frame every peer-authored text value as untrusted content. Routing identity comes
   only from the event's authenticated fields.
5. Deliver through the harness's native event mechanism.
6. Call `acknowledge` only after that mechanism accepts the event.
7. Call `release` when the harness deliberately defers or rejects local delivery.
8. Send `heartbeat` at intervals no longer than 30 seconds while retaining claimed
   work or an active directed-request turn.

Request identifiers are caller-generated stable 16-byte values. A transport failure
may be ambiguous: retry only the same operation with the same request identifier and
byte-identical payload. Never allocate a new identifier merely because the response
was lost. Canceling an in-flight persistent request closes that session so a late
frame cannot be misread as the response to a later operation; reconnect before
retrying the exact request.

Acknowledgement is idempotent. A stale lease generation cannot settle a claim issued
to a newer attachment. If a process crashes after claiming, connection teardown
releases the consumer lease; a replacement session reclaims the same notification
with a newer lease generation.

## Harness mapping

A paved adapter maps lifecycle events directly:

- **idle/ready** permits a bounded claim;
- **busy** retains already claimed work and heartbeats it rather than claiming an
  unbounded queue;
- **native delivery accepted** permits acknowledgement;
- **native delivery deferred or refused** permits release;
- **shutdown** stops new claims, settles or releases owned work, then drops the
  session; and
- **crash** relies on authenticated connection closure and durable redelivery.

Prompt injection, tool permission, mute behavior, and autonomous response authority
remain harness responsibilities. The SDK does not turn peer text into instructions
or grant a model permission to act. Directed requests require the separate structured
collaboration-policy authorization flow.

## Best-effort polling integrations

A skill or generic process that cannot observe native idle, resume, fork, subagent,
and shutdown events is a best-effort fallback. It must use finite waits, surface
delivery errors, and avoid claiming work it cannot reliably settle. Polling does not
claim the lifecycle or wakeup guarantees of a paved adapter.

## Conformance

The `Adapter conformance` GitHub-hosted workflow runs without Copilot CLI,
credentials, model inference, or repository secrets. It verifies:

- the persistent authenticated JSON session;
- exact operation names and fixture request/response shapes;
- all supported delivery event kinds and bounds;
- claim, delivery, acknowledgement, release, heartbeat, and status behavior; and
- a fake harness crash followed by same-notification reclaim under a newer lease.

An implementation in another language should reproduce the fixture values and the
same lifecycle outcomes before it is presented as a paved adapter.
