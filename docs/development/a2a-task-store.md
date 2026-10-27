# A2A task store

This document is the canonical implementation contract for the portable A2A task
store and its public SQLite reference. ADR 0014 owns the durable decision and tradeoffs.

## Crate boundaries

`Konclave.A2ATaskStore` owns:

- the synchronous semantic store trait;
- task keys, creation, transitions, messages, canonical artifact records, terminal
  reasons, and retention outcomes;
- domain-separated task, message, and artifact identity digests;
- pure transition, retry, durable-shape, and status-history policy; and
- persistence result types that contain no generated A2A DTO.

`Konclave.A2ATaskStoreSqlite` owns schema version `1` and the complete single-gateway
SQLite implementation. It depends on the semantic contract, not the reverse. A
managed implementation can implement the same trait without depending on SQLite.

Task, message, artifact, transition, and returned payload records do not implement
`Debug` or general serialization over plaintext.

## Durable scope and identity

Every task key is the exact tuple:

```text
(published agent id, optional tenant id, 32-hex A2A task id)
```

Task creation also persists the configured context, source message identifier,
Konclave conversation, exact target device, mapped Konclave request identifier,
request options, and request-text digest. The complete immutable identity digest is
domain separated and excludes the first-creation timestamp.

An exact create retry returns the existing task, including after content pruning and
restart. Reusing the key with changed text, route, context, source message, or options
returns `Conflict`.

The context table durably binds one agent, tenant, and public context to one Konclave
conversation and target. Another task cannot rebind that context while any task or
tombstone retains it. Removing the last expired tombstone also removes its orphaned
context binding.

## State and histories

Creation atomically inserts:

- one `SUBMITTED` task at generation `0`;
- one status-history record at generation `0`; and
- the initial `USER` message at sequence `1`.

Transitions require the exact expected generation and use `BEGIN IMMEDIATE`.
`SUBMITTED` may become `WORKING` or terminal. `WORKING` may become terminal.
`INPUT_REQUIRED` and `AUTH_REQUIRED` fail until a later multi-turn profile defines
their semantics.

`COMPLETED` requires an existing `AGENT` message or complete canonical artifact.
`FAILED`, `REJECTED`, and `CANCELED` require a bounded machine-readable terminal
reason. Terminal rows are immutable. Retrying the immediately preceding exact
transition returns the existing task; any different stale transition conflicts.

Messages and artifacts are append-only with store-assigned contiguous sequences.
Their typed identifiers are idempotency keys. An exact retry preserves the first
accepted display timestamp; changed content, role, digest, or completion semantics
conflicts.
Message reads return the most recent bounded window in chronological order, matching
A2A `history_length` rather than returning the oldest records.

`task_with_messages` returns the task projection and its bounded message window from
one persistence snapshot. SQLite holds a read transaction across both reads so a
concurrent retention sweep cannot combine a pre-prune task row with post-prune empty
history.

`task_snapshot` atomically returns the task, bounded message window, and complete
retained artifact set. `list_tasks_with_artifacts` preserves the same page ordering
and pagination cursor while reading each task and its artifacts inside one read
transaction.

`status_updates` accepts one previously observed generation and returns every later
status record in consecutive generation order. The generation is an internal durable
stream cursor, not an A2A wire field. A cursor ahead of current state is corruption;
the current generation returns an empty page.

`stream_updates` reads the current task, later status generations, later artifact
sequences, and bounded messages from one snapshot. Since terminal tasks reject later
artifact appends, the gateway can emit returned artifacts before a terminal status
without inventing a second event journal.

`list_tasks` returns only non-pruned tasks for one exact agent, tenant, and public
context. Ordering is deterministic by `(created_at_unix_milliseconds DESC, task_id
DESC)`, and the returned cursor is derived from the last visible task on the page so
HTTP pagination remains stable without exposing SQLite row identifiers.

The artifact record contains bounded opaque canonical bytes and a verified SHA-256
digest. Gateway paths accept only deterministic bytes produced by the ADR 0017
artifact validator; the store still never parses generated A2A DTOs or dereferences a
URL.

## Shared policy and adapter conformance

`plan_a2a_task_transition` operates on the current record selected inside the
adapter's write transaction. It first reconciles the immediately preceding exact
retry, preserving the original timestamp and avoiding any query for already-pruned
completion evidence. A new transition then receives either `Apply` or
`RequireCompletionEvidence`. The latter requires an Agent-role message or complete
artifact for the exact task, read under that same transaction and checked through
`validate_completion_evidence` before publication.

The shared shape, status-reason, and complete-history validators consume already
decoded, bounded persistence facts. They do not authorize a tenant, verify native
membership, acquire a lock, query a database, validate an immutable identity digest,
or replace context-binding checks. Each adapter retains those responsibilities.
SQLite uses these decisions without changing its schema or transaction boundaries.

The optional `test-support` feature exports `assert_a2a_task_store_contract` and
`A2ATaskStoreContractFixture`. A consumer supplies a fresh isolated fixture for each
case and maps the shared test limits into its backend configuration. Opening the
fixture again must create a fresh handle to the same committed state, not reset
storage or return an in-memory copy. Fixtures own cleanup after all handles have
been dropped. The feature has no default activation and is intended only for tests.

The shared runner executes the extracted semantic cases plus pruned-completion retry
recovery. It includes real independent-handle generation races, absent/present tenant
and context isolation, both completion-evidence alternatives, foreign/user/incomplete
evidence rejection, snapshots, exact/conflicting retries, capacity and retention.
SQLite-specific schema, configuration, file, and corruption cases remain in the
SQLite package. One runner assertion represents the shared cases in Cargo's test
count; extracting them does not remove their assertions.

## SQLite behavior

The adapter:

- disables trusted-schema execution, triggers, views, writable-schema access, legacy
  quoted-string parsing, and other unsafe database features before examining state;
- validates every schema row, including exact implicit autoindexes, against the
  complete canonical schema before writing to an existing database;
- enables foreign keys, rollback journaling, `synchronous=FULL`, and a finite busy
  timeout;
- creates schema version `1` in one immediate transaction;
- refuses partial, modified, or unexpected pre-existing schema objects;
- parameterizes caller values and keeps network work outside transactions;
- serializes one connection through a process-local mutex;
- verifies context bindings, task/message/artifact digests, task-to-message identity,
  status generations, transition order, timestamps, terminal shape, sequence
  continuity, and configured capacities while reading;
- counts text capacity as UTF-8 bytes rather than SQLite characters; and
- rejects a database whose existing task, context, history, artifact, or byte counts
  exceed the configured bounds.

The database is a standard-bridge plaintext trust endpoint. The adapter does not
claim local-daemon sealing or transparent encryption at rest.

## Capacity and retention

Configuration requires:

- 1 to 100,000 retained tasks and context bindings;
- 2 to 256 messages per task;
- 1 to 256 artifacts per task;
- 1 byte to 1 GiB aggregate retained message/artifact payload;
- 1 to 1,024 terminal tasks per retention transaction;
- nonzero content retention;
- idempotency retention strictly longer than content retention;
- each retention window no longer than ten years; and
- a busy timeout from 1 to 60,000 milliseconds.

Before create or append capacity decisions, the adapter removes eligible records in
oldest-terminal-first order. Active tasks are never removed.

At content expiry, message and artifact rows are deleted and the task becomes a
self-verifying tombstone retaining its route, request-text digest, immutable identity
digest, final state, status history, and deadlines. At idempotency expiry, the task
and orphaned context binding are removed.

## Verification

The draft-full `A2A task-store conformance` check executes:

```shell
cargo fmt --package KonclaveA2ATaskStore --package KonclaveA2ATaskStoreSqlite -- --check
cargo test --locked --package KonclaveA2ATaskStore --all-features
cargo test --locked --package KonclaveA2ATaskStoreSqlite
cargo clippy --locked --package KonclaveA2ATaskStore --package KonclaveA2ATaskStoreSqlite --all-targets --all-features -- -D warnings
pwsh ./scripts/ci/Test-ComponentValidationScope.ps1
```

The SQLite reference runs the shared suite through its fixture, alongside its own
database-specific cases. Together they cover:

- exact create retry, changed-content conflict, and process reopen;
- context, agent, tenant, conversation, and target isolation;
- generation races and exact transition retries;
- consecutive status reads and exact generation-cursor resume;
- atomic task/message/artifact snapshots and combined stream deltas;
- terminal reasons, cancellation, completion evidence, and terminal immutability;
- deterministic task listing, cursor pagination, and hidden pruned tombstones;
- ordered message and artifact idempotency/conflicts;
- `WORKING`-only new artifact publication with terminal exact-retry recovery;
- UTF-8 byte, row, task, and artifact capacity;
- response-before-transition restart recovery;
- payload pruning, tombstone retry, tombstone expiry, and active-task preservation;
- rollback-journal and synchronous settings;
- partial, modified, unexpected, and executable schemas; and
- live-row, status-history, and pruned-tombstone corruption.
