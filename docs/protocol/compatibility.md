# Protocol compatibility contract

This document is the canonical owner of Konclave wire compatibility, framing,
delivery, ordering, replay, and schema-evolution rules.

The terms MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY describe project requirements.

## Independent version axes

Konclave tracks these versions independently:

- transport endpoint version;
- local-service authorization protocol version;
- collaboration-policy bundle version;
- relay envelope version;
- Konclave application protocol version;
- MLS protocol version;
- MLS ciphersuite and extension capabilities;
- persisted storage schema version.

A client MUST advertise supported ranges and capabilities. Selection MUST choose the
highest mutually supported non-deprecated version. An empty intersection or
unrecognized major version fails closed. Version selection that affects security is
authenticated inside the conversation state and cannot rely only on relay metadata.

## Protobuf schema

Konclave relay envelopes and application messages use Protocol Buffers with
`syntax = "proto3"` and versioned package namespaces beginning with
`konclave.protocol.v1`.

Schema rules:

- field numbers are permanent and MUST NOT be reused;
- removed fields and enum values are reserved by number and name;
- enum zero values are `*_UNSPECIFIED` and invalid at validated boundaries unless
  explicitly documented;
- additive optional fields are the only compatible change within a major version;
- changing meaning, required validation, wire type, or cardinality requires a new
  field or major package version;
- `google.protobuf.Any` and unbounded maps are not used in security-sensitive
  contracts;
- unknown fields are tolerated by endpoints that do not need to interpret them, but
  forwarding components preserve the original opaque bytes instead of decoding and
  re-encoding;
- generated types are wire DTOs and are converted into validated domain types before
  use.

## Wire layers

### Local service authorization

The supported shared-service protocol is version 2. It has separate issuer and
session-grant handshake roles and never negotiates down to protocol version 1. An old
client cannot parse a protocol-v2 rejection, so the service classifies the attempt as
`client_upgrade_required` while the old client observes a failed attach. A version-2
client classifies a reachable old service as `service_upgrade_required`.

Every operational connection presents one complete finite grant and proves the
matching ephemeral session private key. The canonical transcript binds the exact
profile, harness, evidence, policy version, issuance, expiry, capabilities, issuer,
client instance, both fresh challenges, and pinned service key. Invalid grants use one
signed uniform rejection after proof exchange.

Installation schema version 2 emits only this protocol. Because no supported Konclave
release or external installation predates it, the current transition is a clean
pre-release cut rather than a v1 compatibility mode. A supported release requires the
journaled migration and rollback machinery defined by ADR 0009 before changing this
schema again.

### Transport frame

The v1 WebSocket watch begins with one binary `ReplayRequest` and returns binary
`ReplayPage` messages for catch-up and live delivery. Submit and acknowledgment
remain HTTP operations using an explicit protobuf media type. JSON is not a core
relay wire format. Local MCP messages remain a separate adapter contract.

Relay data-plane authentication is transport metadata, not a protobuf field. The
community HTTP and WebSocket adapter follows the
[relay transport authentication contract](relay-authentication.md). Other
deployments may replace the authentication mechanism while producing the same opaque
principal and route-authorization outcomes.

### Relay envelope

The relay envelope contains only:

- envelope major version;
- opaque conversation routing identifier;
- globally unique envelope identifier;
- coarse delivery class needed to distinguish key-package, direct Welcome, group
  handshake, and group application delivery;
- expected parent epoch for Proposal and Commit serialization;
- expiry policy;
- opaque MLS or KeyPackage bytes.

After acceptance, the relay associates the envelope with a durable cursor in a
`StoredRelayEnvelope`; the submitted `RelayEnvelope` never self-asserts that cursor.

The relay MUST NOT deserialize Konclave application messages, duplicate decrypted
membership data, or derive searchable fields from encrypted content.

### MLS payload

MLS messages follow RFC 9420. Application and membership-sensitive handshake content
uses PrivateMessage unless an accepted ADR documents why relay-visible handshake
metadata is required.

### Device credentials and invitations

A device credential binding identifies the device and conversation, names the
signature scheme, carries the device-root and conversation-scoped public keys, and
carries the device-root signature over that canonical binding. A join proof combines
the exact credential binding with an invitation for the same device and conversation
and one bounded MLS KeyPackage. Newly issued join-capable invitations also bind the
opaque relay routing identifier in the issuer signature, so handoff cannot redirect
the new member to a different route. Generic readers retain compatibility with early
unbound invitation fixtures, but the daemon refuses them for joining. Signature,
expiry, route, role, and invitation-consumption checks occur outside generic wire
decoding.

The exact v1 hash and signature inputs are defined in
[Identity signature encodings](identity-signatures.md).

### Konclave application message

Application data encrypted by MLS includes:

- Konclave application protocol major version;
- conversation-scoped unique message identifier;
- sender-local monotonic counter;
- content kind and versioned content body;
- optional reply/reference identifiers;
- sender timestamp as display metadata, never authorization or ordering authority.

Protocol-v1 content kinds include UTF-8 text, a request directed to one exact device,
and collaboration-policy proposal, response, and revocation messages. These are
additive application content variants. An endpoint MUST negotiate support before
sending a variant to a member that needs to interpret it. An older endpoint presented
with a directed request fails visibly rather than treating its body as ordinary text.

The entire application message is covered by MLS authentication. Sender identity is
derived from the authenticated MLS leaf and validated device credential. Application
bytes MUST NOT override attribution, authorization, counters, or replay state with a
self-asserted sender identifier.

Automatic request handling is local durable state, not peer-authored application
content. It is keyed by conversation, directed-request message, and local responder.
Only a live exact delivery claim may create a bounded handling attempt. A response
must reference that request and is reserved atomically with the terminal handling
transition; a no-response outcome is terminal without creating an application
message.

### Collaboration-policy bundle

The protocol-v1 `CollaborationPolicyBundle` is a source-independent, content-addressed
contract. It contains a canonical name, ordered action statements, ordered required
harness claims, fully resolved optional semantic limits, and a legacy optional
guidance field retained only for historical byte and digest compatibility. Guidance
is untrusted annotation and is never injected into a model turn or used as authority.
The bundle does not contain source paths, mutable includes, executable code, or
unresolved provider references.

Policy names are display metadata. Bundle identity is the domain-separated SHA-256
digest defined in [Collaboration policy contracts](../development/collaboration-policies.md).
Decoders reject alternate encodings, noncanonical collection ordering, duplicate
identifiers, unknown effects, missing limits, unsupported major versions, and values
outside their bounds.

The bundle contract does not itself grant local authority. A proposal carries one
16-byte proposal identifier, the claimed 32-byte digest, the complete bounded
canonical bundle, and an optional digest it intends to replace. A response is
`accepted` or `rejected` and binds both the proposal identifier and digest. A
revocation binds the withdrawn digest.

Receivers validate fixed-width values, bounds, required fields, and response outcomes.
They then decode the proposed bundle canonically and require its derived digest to
match the claim. Receipt and validation are not activation: proposal state and local
binding changes belong to the endpoint service layer and require local authorization.

The closed binary adapter protocol v1 retains its original event-kind set. A daemon
using that legacy path projects policy exchange content into a bounded,
non-authorizing text notice so an older decoder can acknowledge it. The shared local
service uses typed JSON policy metadata and never sends bundle content or guidance
through automatic delivery.

## Bounds

Parsing enforces limits before allocation or decompression. Initial hard limits are:

- 1 MiB encoded relay envelope, with up to 1,023 KiB of opaque payload;
- 256 KiB encoded application message, with up to 255 KiB of UTF-8 text;
- 64 KiB encoded collaboration-policy bundle, with at most 256 statements and 64
  required harness claims;
- 16 MiB encoded replay page and 100 envelopes per page;
- 1 KiB encoded replay requests and acknowledgments;
- 4,096 top-level fields in any decoded Protobuf message;
- 128 active devices per conversation;
- 1,024 bytes per human-readable metadata field;
- 32 outstanding unacknowledged send operations per local client.

Attachments and larger artifacts use a separately versioned chunking or object
transfer protocol. They are never smuggled through an oversized chat envelope.
Changing a hard limit requires compatibility and denial-of-service review.

## Delivery and ordering

Relay delivery is at least once. A successful submission means the envelope is
durably assigned a cursor, not that every recipient has processed it.

- Each routing identifier has an append-only, monotonically increasing cursor.
- Clients persist the highest contiguous processed cursor and acknowledge it.
- Reconnect requests messages after the last durable cursor.
- Before processing a replay page, clients validate every returned cursor as exactly
  `after_cursor + 1`, then the next value in sequence, using checked arithmetic. A gap,
  duplicate, regression, overflow, or inconsistent page `next_cursor` rejects the
  whole page before journal or MLS mutation.
- Cursor gaps remain visible until filled, expired by policy, or explicitly reported
  unrecoverable.
- Application messages may arrive more than once and are deduplicated by signed
  message identifier.
- Application display order follows accepted relay cursor unless a content type
  defines a stronger domain order.

Epoch-changing Commits require compare-and-set serialization against the expected
parent epoch. Only one Commit is selected for an epoch. The initial protocol trusts
the relay sequencer not to return different winning Commits to isolated clients.

Membership-sensitive MLS control messages use PrivateMessage framing. Their
authenticated data contains only the domain-separated SHA-256 digest of the canonical
`MembershipChange` bytes so clients can reject a valid MLS Commit paired with a
different application authorization without exposing membership data to the relay.

The complete canonical `MembershipChange` and optional add-member `JoinProof` form a
bounded `MembershipControl` payload encrypted as an MLS application PrivateMessage in
the parent epoch. `MembershipCommitBundle` pairs that encrypted control message with
the bound MLS Commit PrivateMessage. Both bundle fields are opaque to the relay, and
their aggregate encoding must fit the normal relay payload bound.

An add-member sender reserves the relay `EnvelopeId` before creating the MLS Commit.
The Welcome's signed GroupInfo carries extension `0xff02` with payload
`version_u8 = 1 || expected_envelope_id[16]`. This extension accompanies the full
conversation-state GroupInfo extension (`0xff00`), while the next GroupContext retains
the authenticated state digest extension (`0xff01`). A joining daemon accepts only the
exact GroupCommit receipt whose envelope identifier equals the signed expected value,
in addition to matching route, class, parent epoch, and state. Legacy Welcomes without
extension `0xff02` remain distinguishable for compatibility handling but fail daemon
join before checkpoint or MLS persistence.

Clients verify the selected Commit, reject observed conflicts or stale proposals, and
halt security-sensitive sending on an unresolved branch. Compare-and-set does not
provide non-equivocation against a malicious relay; replacing this trust requires a
future transparency, gossip, or fork-resolution design.

## Replay protection

MLS generations alone do not prevent insider replay. Clients therefore persist:

- accepted application message identifiers;
- the highest accepted sender-local counter per authenticated MLS sender and
  conversation epoch;
- envelope identifiers needed for idempotent retry;
- delivery cursors and acknowledgments.

A duplicate produces the original success outcome without repeating side effects.
A reused identifier with different authenticated content is a protocol violation.
Attribution, deduplication, and authorization always key from the authenticated MLS
sender, not a field asserted by the encrypted application payload.

An exact retry of an already applied add-member operation returns its original sealed
Welcome and accepted cursor even after later authenticated policy transitions. The
retry must match the complete canonical JoinProof and historical operation, next
state, Welcome, and exact receipt. Current policy must prove monotonic invitation
consumption, but it is not required to equal the historical next state.

In protocol v1, `expires_at_unix_seconds` is the deadline for accepting a first
submission. An identical envelope retry returns its original cursor after that
deadline. An accepted envelope remains replayable because v1 has no authenticated
gap record that could preserve cursor continuity after deletion; retention and
authenticated expiration gaps require a future compatible protocol extension.

## Errors and retries

Wire errors use stable machine-readable codes plus bounded diagnostic metadata.
Human-readable text is not parsed for behavior.

Errors classify at least:

- malformed or oversized input;
- unsupported or downgraded version;
- unauthenticated device;
- unauthorized operation;
- stale epoch or conflicting Commit;
- duplicate or replayed message;
- expired or consumed invitation;
- unavailable dependency;
- unrecoverable local state.

A ready application operation terminalized by removal of its local sender returns a
permanent not-member error. It is distinct from expiry, retains its stable identifiers
and sealed envelope, and is never automatically resubmitted.

Retryability is explicit. Clients use bounded exponential backoff with jitter and
idempotency identifiers. Permanent validation and authorization failures are not
retried automatically.

## Compatibility lifecycle

- Every released schema has immutable binary fixtures.
- A new reader must decode all supported prior fixtures.
- A prior reader must safely ignore additive fields produced by a new writer.
- A major-version writer is enabled only after capability negotiation confirms every
  required member can process it.
- Storage migrations do not silently change wire bytes.
- Deprecated versions have a documented read window, write cutoff, and removal path.
- Relay implementations conform to the public contract and do not introduce
  deployment-specific fields that clients must understand.

## References

- [RFC 9420: The Messaging Layer Security Protocol](https://www.rfc-editor.org/rfc/rfc9420)
- [RFC 9750: The Messaging Layer Security Architecture](https://www.rfc-editor.org/rfc/rfc9750)
- [Protocol Buffers language guide](https://protobuf.dev/programming-guides/proto3/)
