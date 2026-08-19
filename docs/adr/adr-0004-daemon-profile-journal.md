---
title: Use locked split-schema profile storage with sealed crash journals
status: Accepted
date: 2026-08-19
authors:
  - Konclave maintainers
tags:
  - daemon
  - persistence
  - recovery
  - security
supersedes: []
superseded_by: []
---

# Use locked split-schema profile storage with sealed crash journals

## Context and scope

The local daemon owns device roots, relay credentials, MLS private state, membership
policy, message plaintext, replay counters, and pending operations. A process crash
can occur between a relay write, MLS ratchet update, application-side journal update,
and acknowledgment. Restart must recover without key rollback, plaintext loss,
duplicate side effects, or unauthorized state substitution.

ADR 0002 defines key custody and authenticated sealing. It does not define profile
locking, database ownership, application journals, or cross-boundary recovery order.
This decision owns those daemon persistence boundaries.

## Verified facts

- Native credential stores do not provide a portable atomic create-if-absent
  operation. ADR 0002 already requires an exclusive profile lock before loading or
  creating the wrapping key.
- `SealedSqliteMlsStorage` owns an mls-rs-specific schema and schema version. The
  daemon application store has a separate migration lifecycle.
- SQLite transactions are atomic within one connection and database. The project
  cannot assume one transaction across independently owned mls-rs and daemon schemas.
- MLS receiver ratchets advance when ciphertext is decrypted. Persisting that ratchet
  before recording plaintext can permanently lose a message after a crash.
- Relay delivery is at least once. Stable envelope and application identifiers make
  replay-based recovery possible when local side effects are idempotent.

## Assumptions

- One daemon process owns a profile directory at a time.
- The daemon account and process memory are trusted while active.
- The filesystem and SQLite files may be read, replaced, truncated, or modified while
  the daemon is stopped.
- The platform wrapping key remains available to the same profile account.
- Relay availability is not guaranteed; recovery may pause until missing envelopes
  can be replayed.

## Decision drivers

- Fail-closed profile startup and wrapping-key creation.
- No raw identity key, bearer credential, MLS secret, policy state, or plaintext in
  ordinary SQLite columns.
- Deterministic recovery from every crash boundary.
- Independent schema evolution for daemon and mls-rs persistence.
- Bounded records, queries, queues, and retry behavior.
- One implementation for local, self-hosted, and managed relay clients.

## Decision

### Profile directory and lock

Each profile has a portable ASCII identifier and one directory under an
operator-selected root. The daemon acquires a non-blocking exclusive lock file before
loading native key custody or opening either database. A second daemon fails startup;
it never falls back to another profile or key.

The profile owns two SQLite files:

- `profile.sqlite` — daemon metadata, sealed application records, counters, and
  journals;
- `mls.sqlite` — the schema owned exclusively by `SealedSqliteMlsStorage`.

Separate files prevent two components from competing for `PRAGMA user_version` and
schema migration ownership. The profile lock coordinates their lifecycle.

### Sealed application store

The daemon store leaves only bounded operational metadata queryable:

- opaque conversation, route, device, envelope, and message identifiers;
- monotonic counters and cursors;
- finite status and operation-kind values;
- normalized relay endpoint.

Device identity, relay credential, conversation signing material, policy state,
credential bindings, pending operations, application messages, and other plaintext
cross into SQLite only as context-bound `SealedBlob` values.

Every read checks size before materializing a blob, authenticates its profile and
record context, decodes through bounded protocol contracts, and re-verifies signed
credential bindings. Stored signing material must match the exact self binding in the
policy record.

### Recovery ordering

Operations use durable intent and completion statuses rather than one impossible
cross-database transaction.

Incoming application envelope:

1. Record the exact envelope identifier, cursor, and ciphertext digest as received.
2. Decrypt using in-memory MLS state.
3. Store the sealed decoded message and application deduplication state.
4. Persist the receiver ratchet.
5. Mark the inbox operation complete and acknowledge the relay cursor.

If a crash occurs before ratchet persistence, replay decrypts again and deduplication
makes the side effect idempotent. If it occurs after ratchet persistence but before
completion status, the exact sealed message plus envelope binding proves that
decryption already succeeded, so recovery completes without decrypting twice.

Incoming membership Commit:

1. Journal the exact Commit, authorization, optional join proof, parent cursor, and
   expected next state.
2. Process and persist MLS state.
3. Promote the exact digest-verified policy state and mark the journal complete.

If MLS advanced but policy promotion did not, restart verifies the journaled next
state against the stored MLS GroupContext digest before promotion.

Outbound membership Commit:

1. Cryptographic creation stores the MLS pending commit.
2. Store the complete sealed relay outbox operation before transmission.
3. Submit idempotently and apply the pending commit after relay acceptance.
4. Promote policy state and clear the outbox.

An MLS pending commit without an outbox is orphaned and may only be rejected and
recreated. Acceptance always requires the exact authenticated pending next state.

Outbound application message:

1. Reserve and persist the sender counter and identifiers.
2. Encrypt; sender MLS state is persisted before ciphertext returns.
3. Store and submit the sealed relay envelope idempotently.

A crash before the outbox write can create a safe generation/counter gap but cannot
reuse a key or send an unjournaled ciphertext.

### Acknowledgment

The daemon acknowledges only the highest contiguous cursor whose local operation is
complete. It never advances acknowledgment for an unprocessed gap. On reconnect it
requests replay after that durable cursor.

## Serious alternatives

### One shared SQLite schema and transaction

**Pros:** apparent atomic updates across daemon and MLS records.

**Cons:** mls-rs storage and daemon migrations would share schema-version ownership,
couple unrelated libraries, and require exposing storage internals. Rejected.

### Persist receiver ratchets before application messages

**Pros:** simple cryptographic write ordering.

**Cons:** a crash can consume the only decryptable generation before plaintext is
durable. Rejected.

### Persist plaintext messages without sealing

**Pros:** simpler search and fewer cryptographic operations.

**Cons:** violates the protected local-history boundary and ADR 0002. Rejected.

### Hide reconnect and journals inside detached client tasks

**Pros:** smaller tool handlers.

**Cons:** obscures task ownership, cancellation, errors, and durable cursor updates.
The daemon service root instead owns and observes watch/reconnect tasks.

## Consequences

### Positive

- Profile and key creation fail closed under concurrent startup.
- Offline database theft does not reveal protected local values.
- Crash recovery has explicit, testable states.
- mls-rs and daemon schemas evolve independently.
- Relay replay and local deduplication cooperate instead of competing.

### Negative

- Cross-database operations require journal and reconciliation code.
- Searchable plaintext history requires an additional explicitly protected index or
  decrypt-on-read behavior.
- Profile backup and restore must preserve both databases and the external wrapping
  key.

### Neutral

- SQLite identifiers and status metadata remain observable to an offline attacker.
- Availability still depends on replaying any envelope absent from local journals.

## Confirmation

Continued compliance is demonstrated by:

- exclusive-lock conflict tests;
- native and external custody feature matrices;
- schema-version and malformed-row rejection;
- scans proving device, credential, policy, and message sentinels are absent from raw
  columns;
- restart tests for device, relay, conversation, policy, and credential records;
- crash-point tests for every inbox and outbox status transition;
- reconnect tests that resume from the durable contiguous cursor;
- specialized security review for profile schema, sealing, journaling, and recovery
  changes.

## References

- [ADR 0001: Protocol trust and E2EE](adr-0001-protocol-trust-and-e2ee.md)
- [ADR 0002: Sealed local secret custody](adr-0002-sealed-local-secret-custody.md)
- [Sealed secret storage](../development/secret-storage.md)
- [Threat model](../security/threat-model.md)
