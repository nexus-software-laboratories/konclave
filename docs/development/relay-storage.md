# Opaque relay storage

`Konclave.RelayCore` implements the public relay's authorization boundary and durable
delivery invariants without interpreting MLS, KeyPackage, or application bytes.
Callers provide a `RelayAuthorizer`; the service checks route-scoped permission before
it invokes persistence.

## Submission order

One SQLite transaction performs these operations in order:

1. resolve the globally unique envelope identifier;
2. return the original cursor for an identical retry, even after its acceptance
   deadline;
3. reject reuse of that identifier with different route, metadata, or payload;
4. reject a new envelope whose acceptance deadline has passed;
5. compare-and-set the expected epoch for Proposal and Commit classes;
6. assign the next route cursor and insert the envelope.

Proposal submissions check the current epoch without advancing it. A successful
Commit advances the epoch and cursor atomically, so concurrent Commits for one parent
epoch have one winner. This honest compare-and-set behavior implements the initial
trusted-sequencer assumption in ADR 0001; it does not prevent a malicious relay from
showing isolated clients different histories.

## SQLite schema

Schema version 1 uses three tables:

- `relay_route` stores the opaque routing identifier, next cursor, and current epoch;
- `relay_envelope` stores the cursor, globally unique envelope identifier, protocol
  version, delivery class, expected parent epoch, acceptance deadline, and opaque
  payload;
- `relay_acknowledgment` stores one monotonic cursor per opaque route and authenticated
  principal.

The schema uses constraints for identifier sizes, payload size, delivery-class epoch
rules, and positive counters. An unknown schema version or missing required table
fails startup. SQLite write contention waits for a bounded interval, and route
compare-and-set behavior remains transactional across connections.

The database intentionally contains no application plaintext, membership copy,
sender identity, key, token, or searchable field derived from encrypted content.
Relay payloads are already end-to-end encrypted; this database is not part of local
MLS secret custody.

## Replay and acknowledgment

Replay is ordered by route cursor and bounded by both the requested maximum of 100
envelopes and the 16 MiB v1 encoded-page limit. The repository first reads only
cursor and payload-length metadata, chooses a bounded prefix using a conservative
wire-overhead budget, and only then materializes the selected payloads.

Acknowledgments never decrease and cannot exceed the highest assigned cursor.
They are scoped to the authenticated principal so one client's progress does not
overwrite another client's progress.

Protocol v1 treats `expires_at_unix_seconds` as a first-submission acceptance
deadline. Once accepted, an envelope remains replayable and an identical retry keeps
its original success outcome. Version 1 does not purge accepted envelopes because it
has no authenticated gap record with which to preserve cursor continuity.

## Validation surfaces

Focused tests cover:

- exact and conflicting retries, including cross-route identifier reuse;
- concurrent duplicate and Commit submissions;
- Proposal and Commit epoch behavior;
- count- and byte-bounded ordered replay;
- principal-scoped monotonic acknowledgment;
- authorization and expiration before storage side effects;
- schema version rejection and sequence-exhaustion classification;
- the exact allowlist of persisted envelope columns.

Transport authentication and public HTTP or WebSocket framing remain separate
application adapters. They must convert bounded protobuf input into validated domain
types and supply a fail-closed `RelayAuthorizer` before invoking this crate.
