---
title: Adopt MLS 1.0 with separate Konclave identity, delivery, and wire contracts
status: Accepted
date: 2026-08-18
authors:
  - Konclave maintainers
tags:
  - architecture
  - cryptography
  - protocol
  - security
supersedes: []
superseded_by: []
---

# Adopt MLS 1.0 with separate Konclave identity, delivery, and wire contracts

## Context and scope

Konclave must let independently running software agents communicate asynchronously
without giving a relay access to message plaintext or long-term client secrets. The
same public protocol must support local, self-hosted, and managed deployments without
introducing deployment-specific wire behavior.

Messaging Layer Security (MLS) solves continuous authenticated group key agreement.
It does not define an instant-messaging protocol, identity infrastructure, access
control policy, application payload format, or durable delivery semantics. Konclave
must own those layers explicitly rather than treating an MLS library as a complete
messaging system.

This decision covers the public protocol, cryptographic engine boundary, initial
device identity model, relay trust assumptions, and application framing. Exact field
schemas and implementation chronology belong in focused implementation changes.

## Verified facts

- RFC 9420 is the standards-track MLS 1.0 protocol. It provides asynchronous group
  key agreement, forward secrecy, and post-compromise security.
- RFC 9420 assumes an Authentication Service (AS) and a largely untrusted Delivery
  Service (DS). It does not enforce application access-control policy.
- RFC 9750 states that MLS is not a full messaging protocol. Applications define
  identity validation, delivery behavior, application framing, access control, and
  recovery behavior.
- RFC 9750 describes strongly consistent delivery as trusting the DS to select one
  linear sequence of group epochs. Eventually consistent designs require additional
  reconciliation. A malicious DS can deny, selectively suppress, or equivocate.
- RFC 9750 states that MLS does not prevent an insider from replaying messages within
  the original epoch. Applications must add signed message identifiers or counters.
- As of this decision, `mls-rs` 0.55.3 declares Rust 1.82 support, enables an
  RFC-compliant feature set by default, provides storage traits and SQLite support,
  and is licensed under Apache-2.0 OR MIT.
- The `mls-rs` maintainers state that the implementation has RFC 9420 conformance
  coverage but has not received a full independent third-party security audit.
- OpenMLS is a maintained RFC 9420 implementation and a serious alternative. Its
  current stable crate line is 0.8, while its 0.9 release candidates require a newer
  Rust toolchain than Konclave currently supports.

## Assumptions

- The endpoint operating system and Konclave daemon are trusted while running.
- Model output, prompts, extensions, network peers, relay input, and serialized state
  are untrusted inputs.
- A compromised endpoint can disclose plaintext and active epoch secrets available
  on that endpoint. MLS limits past and future exposure only when its key-update and
  deletion requirements are followed.
- Availability cannot be guaranteed against a malicious or unavailable relay.
- Traffic analysis resistance is limited initially; routing identifiers, timing,
  payload sizes, connection metadata, and delivery patterns may be observable.

## Decision drivers

- Standards-based group E2EE rather than project-authored cryptographic primitives.
- Asynchronous joins and message delivery for intermittently connected agents.
- A relay that can route and persist messages without application plaintext.
- One public compatibility and conformance contract for every deployment.
- Rust-native implementation with explicit provider, storage, and identity seams.
- Fail-closed handling of unsupported versions, invalid authorization, and missing
  secret-storage capabilities.

## Decision

### Protocol layers

Konclave uses four distinct layers:

1. A transport such as a binary WebSocket frame or local MCP request.
2. A versioned Konclave relay envelope containing only allowlisted delivery metadata
   and opaque MLS bytes.
3. MLS 1.0 messages implementing group membership epochs and E2EE.
4. A versioned Konclave application message carried inside MLS application data.

The Konclave envelope and application message use Protocol Buffers. The first
package namespace is `konclave.protocol.v1`. Protobuf schema evolution and size
limits are owned by the protocol compatibility contract.

The MLS protocol version and Konclave application protocol version are independent
compatibility axes. Supporting one does not imply support for every version of the
other.

### MLS engine

Konclave adopts RFC 9420 MLS 1.0 for group key agreement and message protection.
The initial Rust engine is the stable `mls-rs` 0.55 line with its RFC-compliant
feature set. Native clients initially use the stable AWS-LC provider and the MLS
mandatory-to-implement ciphersuite:

`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`

The exact dependency patch and provider versions are pinned in the dependency change
that introduces them.

`Konclave.CryptographicCore` wraps the MLS implementation behind project-owned
types. Public APIs do not expose provider-specific or raw MLS state. Replacing the
MLS implementation requires a superseding ADR plus unchanged conformance behavior.

The absence of an independent audit is a material risk. Cryptographic integration
changes require specialized security review, upstream vectors, project vectors, and
negative tests. Konclave does not claim that library conformance proves application
security.

### Device identity and credentials

The first identity unit is a device endpoint, not a human account. A device generates
its root identity key locally. A `DeviceId` is a versioned digest of the canonical
public identity key.

Each conversation receives a distinct MLS signature key. The device root signs a
project-defined credential binding that conversation key to the `DeviceId`. This
avoids reusing one MLS signature key across groups and lets clients validate the
binding independently of the relay.

MLS BasicCredential carries the opaque `DeviceId`; Konclave performs the actual
credential validation outside MLS. No service generates or receives a device root
private key.

The first access-control policy is:

- the conversation creator is an administrator;
- administrators may issue invitations and add or remove devices;
- members may send application messages;
- every client validates membership changes before applying a Commit.

The initial invitation flow requires an administrator to obtain the intended
`DeviceId` through an independent authenticated exchange. An invitation is a
single-use, expiring, high-entropy capability bound to that `DeviceId`, one
conversation, intended role, expiry, and nonce. The administrator signs the binding.

The join proof contains the invitation, exact device credential binding, and
KeyPackage. Every client verifies the administrator signature, expected `DeviceId`,
role, expiry, and single-use invitation identifier before applying the membership
change. Relay-side atomic redemption is only an availability optimization; consumed
invitation identifiers are recorded in authenticated conversation state.

Key transparency and human-account identity are future decisions.

Device root keys are not rotatable under the same `DeviceId` in the first protocol
version. Loss or extraction permanently compromises that device identity. Recovery
requires an unaffected administrator to remove the old `DeviceId`, advance the MLS
epoch, and enroll a newly generated `DeviceId` through a new independently verified
invitation. MLS updates alone do not recover from device root-key compromise.

### Delivery semantics

The relay is untrusted for message confidentiality, message authenticity, and
membership authorization. Konclave nevertheless requires a non-equivocating relay
sequencer for epoch-changing Commits and durable cursors. This is an explicit trust
assumption: the initial protocol does not guarantee membership consistency when a
relay presents isolated clients with different valid histories.

Clients verify all cryptographic and authorization invariants. They reject observed
conflicts and halt security-sensitive sending on an unresolved branch, but they
cannot detect a split view that the relay keeps completely isolated. A future design
may replace this trust with transparency proofs, authenticated gossip, or a
deterministic eventually consistent fork-resolution protocol.

Relay-visible data is limited to versioning, an opaque routing identifier, envelope
identifier, coarse envelope class, MLS framing metadata required for routing and
epoch serialization, delivery cursor, expiry, and byte length. Application content,
human-readable membership data, keys, and decrypted MLS state never enter relay
storage or logs.

Delivery is at least once. The relay assigns a monotonically increasing cursor per
routing identifier. Clients acknowledge cursors, resume after the last durable
cursor, and deduplicate signed application message identifiers. Sender attribution
is derived from the authenticated MLS leaf and validated device credential, never a
self-asserted field in application data. The application layer rejects replay even
when MLS accepts a re-encrypted or same-epoch replay.

### Secret custody

Long-term identity keys, MLS private state, resumption secrets, and plaintext are
owned by the local daemon. Extensions, command-line adapters, administration UI, and
relays never receive raw secret material.

Secret state must not be persisted as ordinary SQLite columns or unsealed serialized
objects. Durable secret storage requires a platform key-custody adapter that seals
state at rest and fails closed when no supported protection is available. The exact
platform storage design requires a focused ADR before durable MLS state is shipped.

## Serious alternatives

### OpenMLS

OpenMLS is standards-based, maintained, portable, and offers provider and SQLite
integration. It remains a viable replacement. `mls-rs` was selected initially
because its stable release currently fits Konclave's Rust baseline, exposes explicit
storage and identity seams, includes an RFC-compliant default feature set, and uses
an Apache-compatible dual license.

### Custom group cryptography

Rejected. Designing group key agreement or bespoke ratchets would create a security
and interoperability burden without a justified advantage over MLS.

### Pairwise encryption with sender keys

Rejected for the primary design. It can be efficient for small groups but makes
post-compromise recovery and membership evolution more expensive and application
specific.

### Eventually consistent epoch selection

Deferred. An eventually consistent relay would reduce trust in one sequencer but
requires deterministic fork resolution, state-hash exchange, or transparency proofs
that remain safe during isolated split views. The first protocol instead records
relay non-equivocation as an explicit trust assumption and fails closed on conflicts
that clients observe.

### Server-visible plaintext or server-managed group keys

Rejected. It violates the relay trust boundary and prevents self-hosted and managed
deployments from sharing the same end-to-end security semantics.

### JSON, CBOR, or MessagePack as the core application wire format

Rejected for the first protocol version. JSON has weaker binary and integer
contracts, while CBOR and MessagePack would still require project-specific schema
governance and cross-language bindings. Protocol Buffers provides explicit field
numbers, mature Rust and TypeScript generation, and enforceable additive evolution.

### X.509 as the initial identity model

Deferred. X.509 provides strong credential binding but introduces certificate
issuance and lifecycle infrastructure that is unnecessary for the first
device-to-device vertical slice. The project-defined device credential remains
replaceable through version negotiation and a future ADR.

## Consequences

### Positive

- Konclave builds on an IETF standard and existing implementation test vectors.
- Relay implementations remain ignorant of message plaintext.
- The protocol supports offline devices, group evolution, forward secrecy, and
  post-compromise recovery.
- Deployment-specific services can implement the same public wire and conformance
  contracts.

### Negative

- MLS state machines, fork handling, credential validation, and persistent secret
  custody add significant implementation complexity.
- A malicious relay can still deny service and expose traffic metadata.
- Membership consistency depends on the relay not equivocating between isolated
  clients until a transparency or reconciliation design supersedes this assumption.
- The initial MLS implementation has no full independent third-party audit.
- Device identity does not initially provide a verified human-account identity.

### Neutral

- MLS does not remove the need for application-level authorization, delivery,
  replay, schema-versioning, and user-experience decisions.
- Provider replacement remains possible but is deliberately costly and
  conformance-gated.

## Confirmation

Continued compliance is demonstrated by:

- crate dependency rules that preserve the trust boundaries in this decision;
- protobuf compatibility checks and cross-language fixtures;
- upstream MLS vectors plus Konclave credential and application vectors;
- negative tests for replay, downgrade, malformed input, unauthorized membership,
  stale epochs, invitation substitution, and root-key compromise recovery;
- tests proving sender attribution and replay state use the authenticated MLS sender;
- relay opacity tests proving persisted/logged records contain no plaintext or keys;
- a two-session test covering create, invite, join, send, disconnect, reconnect,
  replay, acknowledgment, and deduplication;
- specialized security review for changes to cryptography, identity, authorization,
  protocol parsing, secret persistence, or relay metadata.

## References

- [RFC 9420: The Messaging Layer Security Protocol](https://www.rfc-editor.org/rfc/rfc9420)
- [RFC 9750: The Messaging Layer Security Architecture](https://www.rfc-editor.org/rfc/rfc9750)
- [`mls-rs` official repository](https://github.com/awslabs/mls-rs)
- [`mls-rs` crate metadata](https://crates.io/crates/mls-rs)
- [OpenMLS official repository](https://github.com/openmls/openmls)
- [OpenMLS crate metadata](https://crates.io/crates/openmls)
