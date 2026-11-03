---
title: Share durable native conversation processing through injected journal ports
status: Proposed
date: 2026-10-27
authors:
  - Konclave maintainers
tags:
  - native-client
  - persistence
  - recovery
  - security
supersedes: []
superseded_by: []
---

# Share durable native conversation processing through injected journal ports

## Context and scope

An outbound relay transport is not a durable Konclave endpoint. A caller also
needs authenticated conversation state, sealed MLS persistence, monotonic sender
reservations, an exact outbox, an inbox, crash reconciliation and contiguous
acknowledgment. Those operations currently live inside the local daemon and depend
on its concrete profile store.

An independently operated native endpoint must not imitate local-service RPC,
open another user's profile or reproduce these algorithms in a deployment-specific
bridge. ADR 0013 already permits a gateway to be a native endpoint through a public
client contract while requiring its agent devices to remain outbound-only.

This decision owns the reusable conversation/journal composition boundary. It does
not replace the wire protocol, MLS provider, membership policy, key-custody scheme,
local-service authorization or local profile format. It does not choose a database,
secret provider, tenant registry, network listener or deployment topology.

## Verified facts

- `Konclave.ClientLibrary` already composes the public cryptographic, domain,
  protocol, secret-storage and authenticated relay contracts. It is the existing
  library boundary for endpoint composition rather than a new transport.
- The daemon's conversation coordinator currently combines profile ownership,
  pairing and local delivery with reusable application and membership processing.
  Its application service supplies ordered relay submission and replay.
- The daemon reserves sender identifiers and counters before encryption, persists
  the MLS sender ratchet before returning ciphertext, and durably journals an
  envelope before sending it.
- Inbound application handling distinguishes `Received`, `MessageSaved` and
  `Complete`. It saves authenticated plaintext before persisting the receiver
  ratchet, then completes the inbox and acknowledges only a contiguous cursor.
- Membership processing records authenticated control and the expected next state
  before applying MLS changes. Recovery compares the complete policy-state digest,
  not merely the epoch or roster.
- ADR 0004 explicitly does not assume a transaction spanning the application and
  MLS schemas. Its recovery ordering is necessary with independent backends too.

## Assumptions

- The embedding process is a trusted native endpoint for its own identity and
  plaintext, just as the daemon is for its own profile. This is not permission to
  import another endpoint's identity, credentials or profile.
- Hosts supply explicit key custody and atomic, bounded, authenticated persistence.
  A provider failure never selects an alternate identity or memory-only backend.
- There is one effective writer for a device's journals and MLS state. A local
  host can enforce this with the existing profile lock. A shared durable backend
  needs an equivalent ownership/fencing mechanism that rejects stale writers at
  every durable mutation, including MLS writes.
- Durable storage and restore operations remain responsible for freshness and
  completeness. Valid ciphertext and concurrency CAS do not independently detect
  a coherent old checkpoint, selective restoration or deletion.

## Decision drivers

- Preserve one implementation of sender, receiver and membership recovery.
- Remove concrete SQLite and local-service RPC from the reusable client API.
- Retain exact retries, replay protection and endpoint key custody.
- Keep authorization, storage ownership and task correlation explicit.
- Preserve existing daemon profile, pairing, adapter and shutdown behavior.
- Prove the shared boundary directly before integrating either host.

## Decision

### Put reusable native processing in the existing client library

`Konclave.ClientLibrary` owns reusable native conversation processing behind
project-owned journal contracts. The cryptographic core continues to own MLS,
credential verification and ratchet persistence. Domain and protocol crates keep
their existing responsibilities.

The shared code owns application preparation and receipt, membership processing,
recovery classification, exact replay and ordered relay composition. The daemon
uses that same code through its profile-store adapter; it does not retain a second
implementation of an extracted operation.

The public API accepts an explicitly sealed MLS backend, an explicit native
identity, bounded journal operations and authenticated relay transport. It never
discovers a local profile, starts a local service, reconstructs private RPC or
selects key custody from ambient configuration.

### Define journals by atomic semantic operations

Journal ports express durable reservations, sealed observations, message and
membership checkpoints, terminal outcomes and contiguous completion. A host must
implement each operation atomically with its documented scope, conflict, bound
and ownership checks. A successful return means committed state, not an enqueued
write. Operational failures are typed errors, never empty success responses.

New outbound admission has one stronger atomic boundary: the host's reservation
adapter revalidates current authority, exact scope and any live handling claim in
the same transaction that reserves the identifiers/counter. For a terminal directed
response, that transaction also consumes the claim once and persists the immutable
response operation needed for recovery. Separate successful checks or individually
atomic writes do not establish this joint guarantee.

Each port is bound to the exact endpoint namespace. Conversation, route, envelope,
sender, message, cursor and epoch observations are revalidated before they can
advance state. Returned plaintext and signing inputs remain inside the trusted
endpoint; ordinary backing storage receives protected values under the selected
sealing adapter.

Backend-specific transaction, migration, custody and fencing implementations
remain host responsibilities. The native client does not claim that a process
mutex supplies cross-process ownership or that a durable-looking interface proves
an implementation's durability.

### Preserve recovery order and actual durable outcomes

Outbound counter reservations cannot be rolled back into reuse. An exact durable
outbox operation can be retried after uncertain relay acceptance without allocating
a new message or envelope identity.

Received plaintext is durably saved before receiver-ratchet persistence. Recovery
from `MessageSaved` accepts an already-processed generation only when the exact
authenticated saved message and envelope establish prior success. An arbitrary MLS
failure never becomes evidence that processing completed.

Membership recovery retains the existing authenticated control, next-state and
pending-commit checks. A removed endpoint cannot continue sending. Relay
acknowledgment follows committed contiguous completion; a host notification or
worker claim does not substitute for it.

Cancellation and shutdown stop new admission but do not turn an already committed
operation into a false cancellation. Hosts own and observe their tasks and drain
admitted work before releasing persistence ownership.

### Keep authority outside message content

The host authorizes an operation before invoking the native client, and its journal
adapter atomically revalidates that authority at new reservation commit. A policy
revocation, lease loss or competing response that wins before this commit denies
the new operation. Network content, an Agent Card, a route, or a requester's claimed
tenant or device never creates local authority.

Local-service grants, collaboration handling claims, pairing approval and profile
lifecycle remain daemon-owned policy. An embedding host supplies its own explicit
authority for its own native endpoint. Neither host becomes an authority to
activate peer policies, add membership or disclose another endpoint's keys.

Exact replay of an already committed response or outbox is reconciliation of that
immutable operation, not a second admission or a new handling attempt. A newer
authority snapshot cannot manufacture a different response under the old identity,
and expired preliminary authorization cannot create a fresh reservation.

For an A2A edge, ordinary HTTP still terminates plaintext at that edge. Sharing
native client code does not establish end-to-end protection to the original A2A
caller. Protected A2A continues to require the separate native handoff defined
by ADR 0018.

## Serious alternatives

### Keep all orchestration behind local-service RPC

**Pros:** retains one existing implementation and local authorization boundary.
**Cons:** an independently owned endpoint would need an unrelated user-local
service and profile deployment. A fake RPC facade would preserve signatures, not
the actual ownership or recovery contract. Retain RPC for local adapters, not as
the only native composition surface.

### Reimplement native submission in each bridge

**Pros:** a small first HTTP integration could send ciphertext quickly.
**Cons:** sending alone omits crash-safe reservations, membership reconciliation,
receiver checkpoints and exact retries. Independent implementations would drift
at security-sensitive boundaries. Rejected.

### Generalize the entire daemon and profile database

**Pros:** could expose every existing capability through one backend abstraction.
**Cons:** would move local authorization, installation, adapter leases, native
profile administration and unrelated pairing supervision into a reusable client
contract. It also makes an unnecessarily large compatibility commitment. Extract
the durable conversation operations instead.

## Consequences

The existing daemon and independently operated native endpoints can reuse the same
recovery semantics without sharing a filesystem or service identity. Provider
selection and deployment topology remain replaceable.

The ports become public contracts with meaningful atomicity and ownership
requirements. Every production adapter needs direct conformance, failure and
restart evidence; an in-memory composition test is not durability evidence.
Cross-backend operations still require reconciliation rather than an invented
global transaction.

Existing local profile formats, custody choices, IPC and wire identities are
unchanged. This refines native client composition under ADRs 0001, 0002, 0004 and
0013 rather than replacing their cryptographic or local-service decisions.

## Confirmation

- The focused native-client gate directly executes finite recovery decisions,
  exact retry/conflict cases and journal-failure propagation before integration.
- Daemon adapters delegate extracted operations; source and tests do not preserve
  a second algorithm.
- Existing SQLite crash-point, sender-gap, inbox, membership, removed-device,
  contiguous-replay and shutdown tests pass through the shared implementation.
- An independent sealed non-SQLite fixture exercises actual native request and
  exact-response delivery, plus restart and fenced-writer rejection through its
  journal adapter. Any durability claim names the durable adapter actually used.
- Missing custody, poisoned ownership, inconsistent records, cursor gaps, unknown
  recovery states and stale writers fail closed.
- Deterministic reservation tests let revocation or lease loss win before commit,
  race two completions of one exact handling claim, and distinguish denial of new
  work from exact recovery of the one committed response.
- A specialized security review checks extraction, persistence ordering, key
  ownership and failure paths before delivery.

## References

- [ADR 0001](adr-0001-protocol-trust-and-e2ee.md) defines the unchanged wire,
  identity, MLS and relay trust assumptions.
- [ADR 0002](adr-0002-sealed-local-secret-custody.md) defines explicit custody and
  context-bound sealing; provider injection does not relax that boundary.
- [ADR 0004](adr-0004-daemon-profile-journal.md) explains the sender, receiver and
  membership crash ordering that the shared implementation must preserve.
- [ADR 0013](adr-0013-a2a-edge-interoperability.md) identifies a gateway as its own
  native endpoint and distinguishes its plaintext trust boundary.
- [ADR 0018](adr-0018-fail-closed-protected-a2a-handoff.md) preserves native bypass
  rather than treating an HTTP bridge as end-to-end encrypted.
