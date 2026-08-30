# Conformance and security evidence

This document is the canonical owner of the evidence required before Konclave
protocol, cryptographic, identity, relay, daemon, or adapter changes are delivered.

## Evidence levels

### Focused iteration

During implementation, run the smallest deterministic test covering the changed
invariant. Do not substitute a full workspace build for a missing assertion.

### Pull-request merge gates

PitCrew owns complete workspace, integration, packaging, and hosted evidence. Merge
gates grow with implemented capabilities and include the suites below once their
corresponding surfaces exist.

### Release evidence

A release records exact dependency versions, supported protocol versions, fixture
set hashes, conformance results, security-review disposition, and known limitations.
Machine-readable manifests live under `protocol/releases/` and are verified by
`scripts/protocol/Test-ProtocolRelease.ps1`. A manifest becomes immutable when its
declared protocol tag is created from the merged `main` commit.

The verifier evaluates a released manifest against the exact declared Git tag rather
than against later source evolution. It first requires the tracked manifest to remain
identical to that tag, then validates lockfiles, fixtures, dependency versions,
protocol limits, MLS configuration, and profile schema from an isolated tag archive.
An unreleased manifest whose tag does not yet exist is validated against the current
working tree.

Continuous integration checks out a shallow revision without tags, so a locally
missing tag does not prove that a release is unpublished. The verifier asks the
origin remote, shallow-fetches the exact release tag when it exists, and fails closed
when that lookup cannot complete. It never falls back to the working tree for a
manifest whose release already exists.

## Required suites

### Schema compatibility

- compile every Konclave-owned `.proto` schema for Rust and TypeScript, and compile
  the vendored A2A schema through its dedicated Rust boundary;
- decode immutable fixtures from every supported major version;
- verify additive-field compatibility with a previous reader;
- reject reused field numbers, invalid enum zero values, malformed lengths, and
  unsupported major versions;
- compare canonical semantic values across Rust and TypeScript implementations.
- verify the vendored A2A v1.0.1 schema, license, generation stubs, and immutable
  fixtures against their recorded byte lengths and SHA-256 digests;
- reject initial-profile A2A requests that use another protocol version, binding,
  tenant, role, part form, media type, metadata, extension, task reference, URL trust
  mode, encoded size, text size, identifier shape, or history range.
- prove A2A mapping derives one stable task and Konclave request identifier from the
  exact tenant, agent, context, and source message; rejects tenant/context
  substitution; and keeps A2A task state distinct from delivery and handling state.
- run the portable A2A task-store contract against SQLite, covering exact create
  retry, context binding, expected-generation transitions, completion evidence,
  terminal immutability, message/artifact idempotency, restart recovery, hard byte
  and row capacities, retention tombstones, and corruption refusal.
- validate bounded public and extended Agent Cards, exact production or loopback
  interfaces, Bearer/mTLS requirements, public/private visibility,
  authorization-before-lookup, explicit no-scan catalogs, and deterministic OASF
  projection without claiming full OASF server validation.
- exercise the A2A HTTP+JSON reference router and outbound client over exact tenant
  paths, preferred media/version headers, bounded status errors, immediate and
  terminal-wait tasks, ETag revalidation, redirect refusal, no-proxy client
  construction, response
  correlation, SQLite restart state, and TLS-or-loopback binding.

### MLS and cryptographic integration

- run upstream RFC 9420 known-answer and interoperability vectors supported by the
  selected provider;
- keep project vectors for device credential bindings, invitations, group creation,
  membership changes, application framing, exporters, and state restoration;
- test invalid signatures, wrong groups, stale epochs, removed members, corrupted
  Welcome messages, downgrade attempts, deleted secrets, invitation substitution,
  and device root-key compromise recovery;
- prove key material and plaintext are absent from `Debug`, serialization, logs,
  telemetry, panic messages, and snapshots;
- verify provider and persistence adapters fail closed.
- restart from sealed conversation signing material and MLS state across pending join,
  pending commit, application ratchet, and removed-device tombstone transitions;
- restart Join and Membership replay heads after later local policy acceptance but
  before the accepted operation's own relay echo;
- reject a same-route, same-class, same-parent Commit receipt whose envelope identifier
  differs from the identifier authenticated by the Welcome, and prove exact acceptance
  across checkpoint and restart;
- resume an exact historical add retry with its original Welcome and cursor after later
  policy transitions;
- terminalize ready application outbox rows atomically on self-removal, return a
  permanent not-member retry result, perform no relay submission, and keep later exact
  route replay healthy;

### Property and fuzz testing

Property tests cover identifiers, counters, authorization transitions,
deduplication, cursor acknowledgment, epoch transitions, and encode/decode
round trips.

Fuzz targets cover all untrusted binary decoders, protobuf-to-domain conversion,
relay envelope framing, invitation parsing, and MLS adapter entry points. Every fixed
crash or excessive-allocation case becomes a permanent regression input.

### Relay opacity and delivery

- persist and replay only allowlisted metadata plus opaque MLS bytes;
- scan storage, logs, metrics, and traces for fixture plaintext and key sentinels;
- test at-least-once duplicates, gaps, pagination, expiration, reconnect, and atomic
  invitation redemption;
- test conflicting Commits, honest compare-and-set epoch serialization, and
  fail-closed behavior when a client observes a fork;
- reject an N+2-first replay page without journal or MLS mutation, then accept the
  exact N+1/N+2 page; reject cursor arithmetic overflow before mutation;
- test authenticated WebSocket catch-up, live notification, disconnect, reconnect,
  missed-message replay, heartbeat failure, and notification-loss recovery;
- document that an isolated split view cannot be detected under the initial trusted
  sequencer assumption;
- prove retries are idempotent and do not repeat application side effects.

### Daemon and adapter authorization

- reject unauthorized local peers and malformed model-generated tool arguments;
- authenticate protocol-v2 issuer and session roles with exact key versions, exact
  profile/session-key grants, policy and evidence claims, fresh challenges, pinned
  service identity, and uniform signed rejection;
- prove the issuer cannot invoke operational methods, grants expire without active
  eviction, quota exhaustion denies, and active-registration checks close revoked
  connections;
- bound shared-service request payload plus cached-response reservations, never
  publish a false terminal outcome for abandoned execution, reject conflicting
  idempotency-key reuse, and return one sealed recorded outcome across reconnect,
  replacement grant, and service restart;
- prove authenticated cancellation is scoped to one session key and request ID,
  wins only before commit, and yields to the actual durable result after commit;
- inject terminal-journal read/write failures and prove they neither leak process-wide
  ledger capacity nor replace a committed result with a false terminal response;
- reproduce `fixtures/local-service/v2/authorization-transcript.json` from Rust and
  TypeScript, including every grant claim and both role-separated signatures;
- keep `fixtures/local-service/v1/copilot-tools.json` byte-semantically aligned with
  the Rust router and consume that generated input schema from the Copilot SDK
  adapter;
- prove fresh interactive and delivery handshakes correlate policy authority only
  through the same authenticated session public key, then reject another session key;
- exchange and activate one exact policy digest across packaged clients, restart the
  shared service, and complete one exact directed request without bypassing native
  permission or delivery-lease checks;
- reject ordinary text, another device's request, stale delivery generations, stale
  handling attempts, changed policy digests, and a second response before any model
  or outbound side effect;
- prove claim recovery is bounded, idle no-response completion is terminal and
  idempotent, and one response transition shares the sender-counter/outbox
  transaction;
- prove root-signed device capability advertisement preserves legacy credential
  fixtures, rejects capability substitution, and prevents directed requests to a
  local or absent target or a conversation with any legacy incapable remote member
  before sender-counter allocation;
- prove delivery heartbeats renew one active handling claim without changing its
  attempt or lease generation, ordinary polling leaves abandoned event claims
  reclaimable, prompt startup is bounded, and Copilot acknowledges only after
  terminal turn completion;
- verify schema-18 migration, authenticated downgrade refusal, sealed handling-record
  and row-count tampering detection, hard capacity, and absence of response plaintext
  from ordinary SQLite columns;
- normalize bounded object and serialized-object pre-tool arguments into the same
  exact `send_message` decision while rejecting malformed, oversized, scalar,
  collection, proxy, and unknown-field inputs;
- reconcile an exact policy-operation own echo against its reserved outbound message
  while continuing to reject different local or remote content under that identifier;
- prove tools expose no raw identity key, MLS secret, or storage wrapping key;
- test cancellation, backpressure, bounded watches, reconnect, and daemon restart;
- verify CLI and Copilot adapters produce the same domain outcomes through the public
  client contract.
- verify the outbound relay client refuses insecure remote endpoints and redirects,
  bounds length-declared and chunked responses, services watch heartbeats, and
  reconnects from the last durable cursor.
- verify sender attribution, authorization, counters, and replay state derive from
  the authenticated MLS sender even when application bytes attempt impersonation.

### End-to-end vertical slice

The first functional milestone is not complete until two independently running
sessions can:

1. create device identities;
2. create a conversation;
3. issue and redeem one invitation;
4. join through an opaque relay;
5. exchange authenticated encrypted messages;
6. disconnect one endpoint;
7. send while it is offline;
8. reconnect and replay the missed message;
9. receive a duplicate without repeating side effects;
10. remove a device and prove it cannot decrypt a later message.

The test records no plaintext or secrets in relay diagnostics.

`shared_service_process` exercises the current process model with 20 clients and one
service PID over the Community Relay HTTP API. It covers pairing, bidirectional
messages, client disconnect, offline replay, service restart, identity recovery,
process/descriptor/memory bounds, and relay opacity. The deeper legacy
`multi_process_relay_e2e` remains supplemental domain regression coverage for removal
and post-removal denial until those cases move into the shared-process harness.

## Determinism

Tests inject clocks, randomness, storage, and transport faults through explicit
providers. Security fixtures use committed deterministic seeds only inside test code.
Production random generation never accepts a deterministic fallback.

Tests avoid arbitrary sleeps. Async behavior uses deterministic signals, paused time,
bounded deadlines, and observed task completion.

## Specialized review

Before delivery, changes affecting cryptography, identity, invitation redemption,
authorization, membership, wire parsing, replay state, secret persistence, or
relay-visible metadata require:

- repository review through `review-changes`;
- a specialized security review;
- disposition of every material finding;
- an ADR update or superseding ADR when architecture or trust assumptions change.

## Deferred platform evidence

Native Windows Service type checking and runtime execution are not covered by the
current Linux-only PitCrew contract. Code that changes the Windows host preserves the
existing static checks and explicitly reports this missing evidence until a trusted
native runner lane exists.
