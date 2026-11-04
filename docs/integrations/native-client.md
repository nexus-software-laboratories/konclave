# Rust native endpoint integration

Use this entry point for the v0.1.31 `KonclaveClientLibrary::native` source APIs.
For a local harness using the installed daemon, prefer the
[local-service adapter](adapter-sdk.md): it leaves key custody, membership and
journals in the daemon. Native embedding instead makes your process a trusted
endpoint owning **its own** explicitly supplied identity and plaintext. It offers
storage independence at the cost of qualifying your custody, authorization,
transactions, fencing and shutdown. It is not permission to open another profile.

The canonical [native composition guide](../development/native-client.md) owns
recovery ordering and backend guarantees. [ADR 0008](../adr/adr-0008-shared-local-service.md)
is the accepted local-service boundary; the native extraction rationale in
[ADR 0031](../adr/adr-0031-embeddable-durable-native-client.md) remains marked
**Proposed**. Source availability is not a registry-publication or stability claim.

## Explicit dependencies

| Public contract | Supply and preserve |
|---|---|
| `NativeConversationJournal` | Bounded authenticated records; atomic reservation of current authority, exact live response claim, counter and immutable intent |
| `NativeConversationProcessor` | Journal, explicitly opened `DeviceIdentity` and project `SealedMlsStorageHandle`; retain exclusive operation ownership |
| `NativeSessionHost` | Processor-backed operations, host-specific authorization, persistence owner, bounded execution and shutdown |
| `NativeSession<H, T>` | `Arc` host, `Arc` `RelayTransport`, and one shared asynchronous submission gate for **all** endpoint producers |
| `RelayClient` | Explicit validated `RelayEndpoint` and protected `RelayAccessCredential`; enrollment is separate |

The submission mutex serializes cooperating producers; it is **not cross-process
or cross-replica writer fencing**. Journal and MLS mutations must reject stale
owners through the actual backend. Never replace unavailable custody or a failed
authenticated read with an empty in-memory backend.

`RelayEnrollmentClient` and `HttpRelayEnrollmentTransport` handle explicit
enrollment material separately from the routed `RelayTransport` operations.
A routing identifier or an HTTP caller identity is not a relay credential or
conversation membership. `RelayClient` disables redirects; retain the project's
protected transport behavior and TLS requirements rather than constructing an
unqualified credential-bearing HTTP client.

## Session composition skeleton

This generic fragment shows the actual public constructor and send boundary. It
assumes a qualified host and authenticated relay have already been provisioned.
It deliberately does not invent a storage provider, sealer or enrollment shortcut.

```rust
use std::sync::Arc;
use tokio::sync::Mutex;
use KonclaveClientLibrary::{
    RelayTransport,
    native::{NativeApplicationRequest, NativeSession, NativeSessionHost},
};

async fn submit<H: NativeSessionHost, T: RelayTransport>(
    host: Arc<H>,
    relay: Arc<T>,
    shared_gate: Arc<Mutex<()>>,
    request: NativeApplicationRequest<H::Authorization>,
    now_unix_seconds: u64,
) -> Result<(), KonclaveClientLibrary::native::NativeSessionError<H::Error>> {
    let session = NativeSession::new(host, relay, shared_gate);
    let accepted = session.send(request, now_unix_seconds).await?;
    let _original_cursor = accepted.cursor;
    Ok(())
}
```

Keep the same gate beyond this function and share it with membership/policy
producers; do not allocate a new gate for each send. A successful send observes
exact relay acceptance and host persistence, not remote execution.

`NativeApplicationRequest<A>` carries validated `conversation_id`, stable
`message_id`, `ApplicationContent`, optional exact `reply_to`, optional host
`authorization`, `sent_at_unix_milliseconds`, `expires_at_unix_seconds` and
`policy_operation`. The timestamp is display metadata in **milliseconds**;
expiry and the session's `now` are Unix **seconds**. `authorization: None` and a
policy-operation flag do not bypass the host's admission checks. Never infer
authorization from content, recipe selection or a web identity.

## Outcomes and recovery

`NativeOutboundStatus` distinguishes `Ready`, `Accepted { cursor }`, `Expired`
and `Removed`. Exact retries retain committed content, correlation, timestamp and
ciphertext. Changing the body or reply target under the same message identity is
`IdempotencyConflict`. A transport failure may follow a committed reservation or
relay acceptance; reopen the original authenticated journal and retry the original
intent, not a new message or regenerated ciphertext.

`NativeSessionError` is finite: `Host(E)`, `Relay(KonclaveClientError)`, `Protocol`,
`IdempotencyConflict`, `OutboundExpired`, `OutboundRemoved` and
`InvalidRelayResponse`. Preserve the distinction between absent evidence and a
failed read. Terminal expiry/removal is not permission to revive the old intent.
Contradictory relay evidence must stop processing.

`replay_once(conversation, limit, now)` starts at the host's durable route/cursor.
`process_page` validates contiguous cursor and route evidence before host effects,
then acknowledges only after durable processing. Internal application records are
not returned as ordinary messages. A later failure can follow earlier durable page
effects; resume from authenticated checkpoints, not from assumptions about rollback.
`has_more` is bounded continuation evidence, not an instruction to start an
unbounded detached loop.

The session starts no workers, scheduler or watch task. `connect_watch` supplies
transport watch sessions; the caller owns finite waits, cancellation, reconnection
and feeding scoped pages into `process_page`. Stop new admission and drain complete
session futures and any host workers before releasing persistence ownership.
Dropping a future cannot undo committed effects. Blocking workers must themselves
retain the operation owner and exact submission guard until completion.

## Reusable example versus production qualification

Start with the existing
[`native_service_session` executable fixture](../../crates/Konclave.ClientLibrary/tests/native_service_session.rs)
and its [service host](../../crates/Konclave.ClientLibrary/examples/native_service/host.rs).
It exercises actual MLS composition and a bounded sealed journal, rather than a
fake JSON facade. Its membership is preprovisioned and immutable; it does not
qualify live pairing, HTTP authentication or WebSocket delivery. Optional delivery
cutoffs/receipts are unsupported there and fail before admission.

The [canonical storage limitations](../development/native-client.md#bounded-service-storage-building-blocks)
matter before copying the example: snapshots have independent atomic replacement,
not a transaction spanning journal and MLS; Windows does not promise power-loss
durability; coherent restore/deletion is not detected by AEAD or a generation fence.
The in-memory processor fixture proves checkpoint behavior, not persistent storage.

Qualification owners include `native_service_storage`, `native_service_mls`,
`native_service_journal`, `native_service_authority`, and `native_service_session`
under [`Konclave.ClientLibrary/tests`](../../crates/Konclave.ClientLibrary/tests).
An unrelated production backend still needs direct restart, sealing, atomic
admission, claim-race and stale-writer tests. No test or hosted workflow execution
is implied by these links.
