---
title: Persist A2A task projections behind a portable store contract
status: Accepted
date: 2026-08-29
authors:
  - Konclave maintainers
tags:
  - a2a
  - persistence
  - sqlite
  - tasks
supersedes: []
superseded_by: []
---

# Persist A2A task projections behind a portable store contract

## Context and scope

ADR 0013 maps A2A tasks onto Konclave directed requests and requires a complete
self-hosted SQLite implementation while allowing managed deployments to use another
store. The A2A domain mapping defines deterministic task and Konclave message
identifiers from one deployment-owned route and one validated source message.

The gateway must survive restart without sending a second directed request, accepting
a conflicting retry, losing the authoritative response, reopening a terminal task,
or retaining plaintext without a bound. It must also avoid coupling a public A2A
server to the local daemon's sealed profile database or to one managed storage
technology.

This decision owns the portable task-store semantics, SQLite transaction model,
idempotency horizon, terminal immutability, message and artifact persistence
boundaries, and retention behavior. It does not define HTTP handlers, Agent Card
configuration, Konclave relay orchestration, artifact content validation, managed
multi-tenant topology, billing, or operator backup tooling.

## Verified facts

- `Konclave.A2ADomain` produces one deterministic task identifier and one Konclave
  request `MessageId` bound to the exact tenant, agent, context, conversation, target,
  and caller message identifier.
- A2A task states and Konclave delivery or directed-request handling states are
  intentionally different state machines.
- A conventional A2A gateway is a plaintext Konclave endpoint. Generated A2A DTOs
  remain untrusted and do not belong in durable storage merely because they can be
  serialized.
- ADR 0013 requires public self-hosting parity and explicitly allows managed
  deployments to replace SQLite while preserving public semantics.
- SQLite transactions can atomically compare an existing identity, reserve one task,
  append ordered records, and publish one state transition without a network call.
- Finite retention and indefinite idempotency conflict: deleting every trace of a
  completed task eventually permits the same deterministic task identifier to be
  created again.

## Assumptions

- One self-hosted store belongs to one gateway deployment and is not a managed
  multi-tenant database.
- Deployment configuration selects the database path and protects the host,
  filesystem, backups, and disk encryption.
- Message and artifact validators run before the store receives their project-owned
  bounded records.
- Callers provide timestamps through an injected clock boundary; SQLite wall-clock
  functions are not task authority.
- A finite operator-configured idempotency horizon is acceptable after terminal task
  content has expired.

## Decision drivers

- Preserve exact retry behavior across process and machine restart.
- Prevent cross-agent, cross-tenant, cross-route, and conflicting-content aliasing.
- Make terminal task outcomes immutable.
- Keep the open SQLite implementation complete without making it the managed storage
  contract.
- Bound rows, bytes, history, and retention without silently dropping active work.
- Keep generated wire DTOs and Konclave daemon storage out of the persistence API.
- Make concurrency and crash outcomes deterministic and testable.

## Decision

### Define one public semantic store contract

A public A2A task-store abstraction accepts project-owned domain records and returns
typed outcomes. The contract is synchronous and transaction-oriented; an async web
host may place calls on its blocking-storage executor without imposing one runtime on
the store.

Every task is addressed by:

```text
(published agent id, optional tenant id, A2A task id)
```

The immutable task identity also contains the configured context, source A2A message
identifier, Konclave conversation, exact target device, mapped Konclave request
message identifier, request body, request options, and creation timestamp. A create
retry returns the existing task only when every immutable field matches exactly.
Reuse with changed content, route, or options is an idempotency conflict.

The store never accepts a profile alias, relay route, policy digest, generated A2A
request DTO, or arbitrary metadata map as task identity.

### Keep task state explicit and monotonic

The store persists A2A task state separately from Konclave delivery and handling
state. Allowed state transitions are:

```text
SUBMITTED -> WORKING | COMPLETED | FAILED | REJECTED | CANCELED
WORKING   -> COMPLETED | FAILED | REJECTED | CANCELED
```

`INPUT_REQUIRED` and `AUTH_REQUIRED` remain representable domain values but are not
accepted by the initial store transition policy. Supporting them requires the later
multi-turn mapping.

Every transition supplies the expected current generation. A successful transition
increments the generation and appends one ordered status record in the same
transaction. An exact repeat is idempotent. A different transition from a stale
generation conflicts. Terminal states never transition to another state, replace
their terminal reason, or regain mutable work.

The store records `CANCELED` only when orchestration supplies that authoritative
outcome. It does not infer cancellation from a disconnected HTTP client or claim that
SQLite state retracts an already delivered Konclave request.

### Persist ordered messages and opaque validated artifacts

Task history is append-only and ordered by a store-assigned sequence. A message record
contains a typed message identifier, A2A role, bounded text, and caller-supplied
timestamp. The same message identifier with identical content is idempotent; changed
role or text conflicts, while the first accepted timestamp remains display metadata.

Artifact semantics remain owned by the artifact boundary. The store accepts only a
bounded, canonical artifact record produced by that validator: typed artifact
identifier, content digest, canonical opaque bytes, and completion flag. It never
parses generated A2A DTOs, dereferences URLs, or decides whether artifact content is
safe. Reusing an artifact identifier or digest with different bytes or completion
semantics conflicts; the first accepted timestamp remains display metadata.

Appending the authoritative response message or a terminal artifact may share the
same transaction as the corresponding task transition. A task cannot publish
`COMPLETED` without the completion evidence required by the caller's operation.

### Use bounded retention with durable tombstones

Active `SUBMITTED` and `WORKING` tasks are never removed automatically.

After a task is terminal and its configured content-retention deadline passes, the
SQLite implementation may remove message bodies, artifact bytes, and other payload
rows. It retains a compact tombstone containing the complete immutable identity
digest, final state, terminal timestamp, and expiry through a longer configured
idempotency horizon.

An exact create retry during the tombstone horizon returns the terminal identity
without recreating work. A conflicting retry still fails. After the tombstone horizon
expires, the identifier may be reused only because the deployment explicitly chose a
finite idempotency window.

Every store has hard task, message, artifact, and byte capacities. Capacity pressure
first removes eligible expired terminal payloads and tombstones in deterministic
oldest-first order. If no eligible record can be removed, the operation fails with a
capacity error. Active work is never evicted and success is never fabricated.

### Make SQLite one complete reference implementation

The public SQLite adapter:

- owns its schema version and append-only migrations;
- enables foreign keys and WAL mode;
- uses parameterized statements and `BEGIN IMMEDIATE` for mutating operations;
- keeps each transaction free of network calls;
- serializes one connection behind a process-local mutex;
- applies a finite busy timeout;
- validates configured capacities and retention durations before opening;
- verifies row shapes, state values, generations, sequence order, and identity
  relationships while reading;
- uses caller-provided timestamps and checked arithmetic; and
- leaves the database recoverable when a transaction or migration fails.

The database stores gateway plaintext. The adapter does not claim Konclave daemon
sealing or built-in encryption at rest. Self-hosters protect the database through
filesystem ownership, encrypted storage, backup policy, and deployment isolation.
A future encryption adapter may implement the same public store contract.

### Preserve managed parity without sharing implementation

The public conformance suite targets the semantic store contract. A private managed
store may partition, replicate, encrypt, and retain data differently, but it must
produce the same create, retry, transition, terminal, history, artifact, cancellation,
capacity, and retention outcomes.

Managed tenancy and authorization occur before selecting one semantic store scope.
They do not add caller-visible task meanings that the public SQLite implementation
cannot represent.

## Serious alternatives

### Reuse the local daemon profile database

**Pros:** existing SQLite, locking, and sealing machinery.

**Cons:** crosses the local trust boundary, gives an internet-facing gateway knowledge
of daemon internals, couples remote task retention to MLS state, and prevents an
independent self-hosted gateway. Rejected.

### Expose SQLite directly without a store abstraction

**Pros:** fewer types and faster initial implementation.

**Cons:** makes schema details the de facto managed contract, spreads transactions and
idempotency across handlers, and makes alternate stores behaviorally ambiguous.
Rejected.

### Store generated A2A protobuf or JSON objects as the source of truth

**Pros:** easy round trips and broad future field preservation.

**Cons:** persists untrusted and unbounded semantics, allows unknown metadata to become
authority, couples storage to schema evolution, and obscures exact idempotency fields.
Rejected.

### Use only an append-only event log

**Pros:** complete history and natural audit replay.

**Cons:** every read requires projection recovery, retention and compaction become
more complex, and the first implementation still needs transactional uniqueness and
current-state indexes. A normalized task projection with append-only status, message,
and artifact histories is selected instead.

### Delete terminal tasks without tombstones

**Pros:** simplest bounded retention and smallest database.

**Cons:** the same deterministic request can recreate work immediately after cleanup.
Rejected in favor of a finite explicit tombstone horizon.

### Retain idempotency forever

**Pros:** a task identifier can never be reused.

**Cons:** an open self-hosted deployment has unbounded durable growth. Rejected; the
operator selects a finite horizon and the limitation remains explicit.

## Consequences

### Positive

- SQLite and managed stores share one testable semantic contract.
- Exact retries survive restart while conflicting retries fail deterministically.
- Terminal outcomes cannot be reopened or replaced.
- Caller identity, deployment route, and Konclave identifiers remain explicitly
  separated.
- Retention is bounded without evicting active work or immediately losing
  idempotency.
- Future artifact and multi-turn layers have a durable boundary without persisting
  generated wire DTOs.

### Negative

- The abstraction, normalized histories, generations, tombstones, capacities, and
  retention sweeps add more state than a single task table.
- Finite tombstone retention means idempotency is not permanent.
- The standard SQLite adapter contains plaintext and relies on deployment storage
  controls.
- Artifact bytes require canonical validation before storage and cannot be recovered
  from arbitrary unknown A2A fields.

### Neutral

- HTTP waiting versus immediate return remains a gateway decision.
- A2A task cancellation remains initially unadvertised even though the store can
  persist an authoritative canceled outcome.
- Managed storage topology and encryption do not need to resemble SQLite.

## Confirmation

Continued compliance requires:

- contract tests shared by the SQLite reference and any managed implementation;
- exact create retry and changed-content conflict tests across restart;
- expected-generation concurrency tests for every state transition;
- terminal-state immutability and exact-repeat tests;
- tests proving A2A state never aliases Konclave delivery or handling state;
- ordered message and artifact idempotency/conflict tests;
- crash tests around task creation, history append, terminal publication, and
  migration;
- oldest-supported-schema migration tests with recoverable failure;
- hard row and byte capacity tests that never evict active work;
- deterministic payload-retention and tombstone-retention tests with an injected
  clock;
- cross-agent and cross-tenant lookup-isolation tests;
- plaintext-at-rest documentation and checks that no stronger claim is advertised;
- SQLite foreign-key, WAL, busy-timeout, and transaction-mode verification; and
- the same semantic suite against the managed store before parity is claimed.

## References

- [ADR 0013](adr-0013-a2a-edge-interoperability.md) establishes A2A as an edge
  binding, requires a public SQLite task projection, and permits alternate managed
  storage under the same public semantics.
- [A2A compatibility contract](../protocol/a2a-compatibility.md) defines the pinned
  wire source and strict initial profile.
- [A2A domain mapping](../development/a2a-domain-mapping.md) defines typed identifiers,
  deployment-owned routes, deterministic task identity, and distinct task state.
- [Protocol compatibility contract](../protocol/compatibility.md) provides the
  existing bounded parsing, idempotency, and retry principles this store preserves.
