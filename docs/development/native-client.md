# Explicit native client composition

`KonclaveClientLibrary::native` exposes conversation processing over host-owned
journals and ordered relay composition over an explicit native host. It does not
open a local profile, call local-service RPC, discover keys, or grant membership
from an HTTP identity. [ADR 0031](../adr/adr-0031-embeddable-durable-native-client.md)
records the proposed extraction boundary.

## Dependencies and ownership

`NativeConversationProcessor` borrows a `NativeConversationJournal`, an explicitly
opened native `DeviceIdentity`, and an existing project-sealed MLS storage handle.
The handle accepts project sealed wrappers, not an arbitrary unsealed provider.
The public composition type does not require SQLite or a local-profile path.
This does not imply a SQLite-free dependency graph: the existing cryptographic
crate still enables the SQLite storage feature.

The embedding process is a trusted native endpoint for its own keys and plaintext.
It must hold one exclusive operation owner throughout processing and fence every
journal and MLS mutation against that owner. A process mutex alone does not fence
another service replica. Loss of custody, ownership or record authentication is an
error, never permission to select another identity or memory-only store.

The journal adapter owns backend-specific transactions, sealing, bounds and
freshness. Bind every observation to the exact endpoint, conversation, route,
envelope, message, sender, cursor and epoch. Do not persist the public opened
record types directly in ordinary tables or logs. Seal application content,
control, credentials and policy under the existing custody/context scheme.
AEAD and writer CAS do not detect coherent old checkpoints, selective restore
or deletion by an authorized storage/restore operator.

## Atomic admission and recovery

`reserve_application` is an atomic semantic operation, not a notification that
the host checked authority earlier. In the same commit, its adapter must:

- Revalidate current native authority and the exact operation scope.
- For a response, verify and consume the exact live handling claim once.
- Reserve immutable message/envelope identities and the next sender counter.
- Persist immutable terminal response intent sufficient for exact recovery.

Policy revocation, lease loss or a competing response that wins before that commit
must deny new admission. Message content and a caller-supplied policy flag are not
authority. Membership, roles, collaboration policy and host task claims remain
independent checks.

Already committed recovery is not new admission. Resume the exact original
identities, content, reply correlation, timestamp and ciphertext. Never replace
committed response intent with newer mutable source content. Outbound failure may
leave a permanent counter gap; it cannot roll the counter back into reuse.

The shared processor preserves the split-journal ordering from
[ADR 0004](../adr/adr-0004-daemon-profile-journal.md). Authenticated inbound plaintext
is saved before receiver-ratchet persistence, and only exact saved evidence can
justify completion after an already-processed generation. An arbitrary MLS failure
does not prove success. Membership journals retain authenticated control and the
complete expected next policy before applying the MLS transition.

## Relay/session composition

`NativeSession<H, T>` accepts an explicit `NativeSessionHost`, `RelayTransport` and
shared asynchronous submission gate. All producers for that endpoint must share
the gate, including host-specific policy and membership operations. Cloning the
session shares its dependencies and gate; constructing separate gates does not
establish independent writer ownership.

Host membership operations can retain an owned guard from that exact gate while
draining applications, selecting an existing immutable membership retry, and
submitting it. The `*_with_gate` methods reject a guard from another mutex before
host or relay effects. Membership acceptance returns the original encrypted
Welcome, not newly generated enrollment material.

The host implements bounded native operations using the shared processor and its
authenticated journal adapter. `send` distinguishes new admission from immutable
ready/accepted/terminal retries. A changed body or reply target cannot reuse the
stable message identity. Accepted retries retain the original timestamp and cursor.
New work drains older ready envelopes first. Exact ready retries recheck native
membership without turning previously committed response recovery into a new
collaboration-policy admission.

Replay checks contiguous cursors and exact route evidence before processing a
page. Acknowledgment follows durable completion; failure partway through a page
does not acknowledge the unfinished suffix. An effective acknowledgment can be
ahead of the requested cursor but cannot regress or change the route.

The session starts no tasks, watch loops or blocking workers. It owns the futures
it returns, while the host owns blocking execution and shutdown. A host that
starts workers must bound, retain and join them even if a calling future is
dropped. Stop new admission and drain admitted operations before releasing
persistence ownership. Do not interpret cancellation after a durable commit as
evidence that the operation never happened.

For blocking composition, retain both operation admission and submission ownership
in the worker itself. Keeping a guard only in the calling future releases it when
that future is cancelled, even though a blocking operation can still be running.
`send_with_gate` permits retaining an `Arc` of the exact owned guard across that
boundary without reacquiring or replacing the endpoint's submission mutex.

The daemon's `ApplicationService` uses this shared session for application send,
membership submission, replay and watch-page processing. Its native host retains
the actual profile admission and submission guard in every blocking callback.
Pairing sweeps propagate their original admission rather than admitting nested
work after closing has started. Profile supervision joins the shared callback
owner before publishing its final state, including component-failure exits;
cancelling an individual requester does not detach its callback or hide its error.

## Qualification and adapter evidence

The focused `Native client conformance` workflow runs on drafts. It directly
executes native processor tests, relay/session classifier and orchestration tests,
and daemon conversation/application/persistence tests. Direct host, activity,
pairing, watch, diagnostics and profile-supervision selections cover daemon
integration, with format, Clippy and conservative dependency relevance checks.

The bounded sealed in-memory processor fixture proves actual MLS composition and
checkpoint decisions, not process durability. The separate fake host/relay tests
prove orchestration and finite evidence categories, not cryptographic or database
correctness. A production adapter still needs direct atomicity, sealing, restart,
claim-race and stale-writer tests against its actual durable backend. Existing
daemon SQLite tests qualify the daemon adapter, not an unrelated service database.

### Bounded service storage building blocks

The `examples/native_service` storage capsule requires an existing,
operator-controlled local directory with OS locking and atomic replacement.
`ServiceStorage` clones share one actual lock and generation fence for both the
Journal and MLS slots. Releasing that owner invalidates its clones; reopening
acquires a new generation. The generation fences concurrent writers, not an
authorized restore of older valid storage.

`ServiceMlsStorage` combines that owner with an explicitly supplied `SecretSealer`
and stable endpoint namespace. Only the existing project-sealed MLS handle escapes
its private backing implementation. Both individual provider records and the
bounded backing snapshot are project-sealed; failed authentication or unavailable
ownership never becomes an empty provider.

Slot replacement is atomic independently. There is no transaction spanning the
journal and MLS snapshots. Files are synced before replacement and Unix also syncs
the directory. Windows provides atomic visibility and file sync, **not power-loss
durability**. Directory mutation by another actor, deletion and coherent rollback
remain outside these guarantees. A production database needs its own qualified
ownership, freshness and durability contract rather than copying this example's
filesystem assumptions.

The direct storage and MLS test targets qualify these building blocks separately;
they do not establish an integrated durable native session. Pure service-authority
tests likewise do not prove that a concrete journal commits policy, a live claim
and complete immutable response intent atomically.

### Bounded service-owned session example

The [service host](../../crates/Konclave.ClientLibrary/examples/native_service/host.rs)
uses the same `NativeConversationProcessor` and `NativeSession` as the daemon, with
an explicitly opened identity, sealed non-SQLite MLS and
[`ServiceJournal`](../../crates/Konclave.ClientLibrary/examples/native_service/journal.rs).
It never calls local-service RPC. Its journal reloads an authenticated bounded
snapshot under the common storage owner; current policy, an exact live claim,
counter reservation and immutable response intent commit together.

The example's membership is explicitly preprovisioned and immutable. Membership
mutation fails as unsupported. Retained counters, intents, inbox evidence and
claims are never pruned or recycled; capacity exhaustion denies new work.
`pending_claim` reads an existing live claim only after the caller has drained its
previous handler. It does not issue a concurrent handling lease. New response
reservation still checks current authority and consumes that claim once.

Unlike the daemon's owned blocking workers, this bounded host starts no tasks.
Callbacks execute inline through `block_in_place` on a checked multi-thread Tokio
runtime. This avoids detached callbacks and a separate worker lifecycle, but
requires that runtime and cannot interrupt a synchronous callback midway through
its poll. All producers must share the same host and submission gate. The caller
must stop admission and own/drain complete session futures, including network
awaits, **before** releasing storage. The callback mutex does not drain those
futures. Unsupported runtimes and poisoned owners fail explicitly.

Run the executable
[service-session example target](../../crates/Konclave.ClientLibrary/tests/native_service_session.rs)
from the repository root:

```sh
cargo test --locked --package KonclaveClientLibrary --test native_service_session
```

The fixture establishes genuine signed invitation, JoinProof, Commit and Welcome
state for two independently owned endpoints, then explicitly provisions a fixed
post-join checkpoint. It does not exercise relay membership acceptance or a live
pairing ceremony. Its injected bounded relay handles opaque ciphertext only; it is
not HTTP, relay-authentication or WebSocket qualification.

The scenarios cover exact request/responder/reply binding, live-claim reopen,
original terminal intent recovered in a separate fenced process after revocation,
uncertain acceptance followed by exact ciphertext retry, both saved-inbox receiver
ratchet checkpoints, retained notification evidence and callback cancellation.
Synthetic custody exists only in the test fixture, never as a host default.
Storage guarantees and Windows power-loss limitations remain those stated above;
this is not a production database or a coherent-rollback detector.

For A2A consumers, keep `A2ATaskSubmitter` as the gateway seam. Native endpoint
composition is not a fake local-service JSON facade, and an ordinary A2A HTTP edge
still terminates plaintext as described by
[ADR 0018](../adr/adr-0018-fail-closed-protected-a2a-handoff.md).
