# Protocol compatibility contract

This document is the canonical owner of Konclave wire compatibility, framing,
delivery, ordering, replay, and schema-evolution rules.

The terms MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY describe project requirements.

## Independent version axes

Konclave tracks these versions independently:

- transport endpoint version;
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

### Transport frame

One binary WebSocket message carries one encoded relay operation or envelope. HTTP
operations use an explicit protobuf media type. JSON is not a core relay wire format.
Local MCP messages remain a separate adapter contract.

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
and one bounded MLS KeyPackage. Signature, expiry, role, and invitation-consumption
checks occur outside generic wire decoding.

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

The entire application message is covered by MLS authentication. Sender identity is
derived from the authenticated MLS leaf and validated device credential. Application
bytes MUST NOT override attribution, authorization, counters, or replay state with a
self-asserted sender identifier.

## Bounds

Parsing enforces limits before allocation or decompression. Initial hard limits are:

- 1 MiB encoded relay envelope, with up to 1,023 KiB of opaque payload;
- 256 KiB encoded application message, with up to 255 KiB of UTF-8 text;
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
