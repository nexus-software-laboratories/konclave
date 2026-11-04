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

### Rust caller setup

Use the workspace `Konclave.LocalServiceClient` crate (Rust import
`KonclaveLocalServiceClient`) and `Konclave.AdapterSdk` (`KonclaveAdapterSdk`),
at the same source revision as the installed service. No registry installation or
stability guarantee is implied. `LocalServiceJsonClientConfig` explicitly supplies
the `LocalServiceEndpoint`, `LocalServiceIssuerCredential` (key identifier, version
and signing identity), pinned `Ed25519PublicKey`, `ServiceProfileId`, `HarnessKind`,
`request_timeout` and `grant_refresh_window`.

The timeout must be nonzero and at most 60 seconds; the refresh window is at most
five minutes and may be zero. `LocalServiceJsonClient::connect` obtains an
AccountTrusted grant with a fresh ephemeral session identity. It does not discover
an installed profile, run the Windows UserPresence ceremony or bypass a policy
requiring unavailable evidence.

The reconnecting JSON client's `request(RequestId, operation, Vec<u8>)` returns
response bytes; it retries a transport failure once and can refresh failed
authentication. In contrast, `open_session` and `open_local_service_adapter`
preserve a connection: session requests do not automatically reconnect. This is
necessary for connection-owned claims.

This bounded fragment accepts a configured client, a fresh cryptographic request-ID
supplier and an immediate native-delivery callback. Real asynchronous delivery must
also retain heartbeats and settle shutdown; do not acknowledge before native
acceptance.

```rust
use std::time::Duration;
use KonclaveAdapterSdk::{
    open_local_service_adapter, AdapterSdkError, DeliveredEvent, DeliverySettlement,
};
use KonclaveLocalServiceClient::LocalServiceJsonClient;
use KonclaveLocalServiceTransport::RequestId;

async fn deliver_once(
    client: &LocalServiceJsonClient,
    mut fresh_id: impl FnMut() -> RequestId,
    mut accept: impl FnMut(&DeliveredEvent) -> bool,
) -> Result<(), AdapterSdkError> {
    let mut session = open_local_service_adapter(client).await?;
    let events = session.claim(fresh_id(), 1, Duration::from_secs(5)).await?;
    for event in events {
        let settlement = DeliverySettlement::from_event(&event);
        if accept(&event) {
            session.acknowledge(fresh_id(), settlement).await?;
        } else {
            session.release(fresh_id(), settlement).await?;
        }
    }
    Ok(())
}
```

`claim` accepts whole-millisecond waits from zero through 30,000 milliseconds;
fractional milliseconds are rejected, not rounded. `DeliveredEvent` retains stable
16-byte notification identity, authenticated routing, relay cursor, sequence,
`lease_generation` and typed `DeliveredPayload`; peer text is bounded to 64 KiB.
Policy and membership events are typed notifications, not text instructions.
Use `DeliverySettlement::from_event` rather than reconstructing a stale generation.

`AdapterSdkError` distinguishes `InvalidConfiguration`, `Transport`,
`Authentication`, `DeadlineExceeded`, `ClaimOutcomeUnknown`,
`Service(LocalServiceErrorCode)` and `InvalidResponse`. The first requires correcting
inputs; authentication requires valid evidence; malformed responses fail closed.
A claim timeout/transport failure can mean the claim was admitted and is exposed as
`ClaimOutcomeUnknown`, requiring the fresh-connection procedure below. A settlement
failure never authorizes executing the native effect a second time.

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

Request identifiers are caller-generated stable 16-byte values. For acknowledgement,
release, heartbeat, and status, retry an ambiguous operation only with the same
request identifier and byte-identical payload. A claim is different because its
lease belongs to the connection that produced it. If a claim returns
`ClaimOutcomeUnknown`, discard the unusable session, reconnect, and claim with a
fresh request identifier. The service rejects replay of a successful claim on a
replacement connection rather than returning stale lease generations.

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

The constructor/request contracts are owned by
[`LocalServiceClient/src/lib.rs`](../../crates/Konclave.LocalServiceClient/src/lib.rs);
delivery models and settlement are owned by
[`AdapterSdk/src/model.rs`](../../crates/Konclave.AdapterSdk/src/model.rs).
Runnable behavior owners are
[`contract.rs`](../../crates/Konclave.AdapterSdk/tests/contract.rs) and
[`fake_harness.rs`](../../crates/Konclave.AdapterSdk/tests/fake_harness.rs).
The crate includes this page in rustdoc, so `cargo test --locked --package
KonclaveAdapterSdk --doc` compiles the exact fragment above. This does not open a
live session or qualify an external harness; no standalone package is implied.

The `Adapter conformance` GitHub-hosted workflow runs without Copilot CLI,
credentials, model inference, or repository secrets. It verifies:

- the persistent authenticated JSON session;
- exact operation names and fixture request/response shapes;
- all supported delivery event kinds and bounds;
- claim, delivery, acknowledgement, release, heartbeat, and status behavior; and
- a fake harness crash followed by same-notification reclaim under a newer lease;
- ambiguous claim recovery with a fresh request identifier; and
- rejection of a successful claim replayed without its owning connection.

An implementation in another language should reproduce the fixture values and the
same lifecycle outcomes before it is presented as a paved adapter.
