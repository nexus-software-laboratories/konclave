---
title: Use OPAQUE and mutual SAS confirmation for short-code pairing
status: Accepted
date: 2026-09-17
authors:
  - Konclave maintainers
tags:
  - pairing
  - pake
  - authorization
  - relay
supersedes: []
superseded_by: []
---

# Use OPAQUE and mutual SAS confirmation for short-code pairing

## Context and scope

ADR 0023 reduces ordinary pairing handoff to a 128-bit, 26-character bearer token.
That token remains too long for reliable voice transfer or repeated manual entry. A
six-digit decimal code is convenient, but its roughly 20 bits of entropy cannot
authorize membership and cannot safely encrypt the existing pairing capability by
itself.

This decision adds a separate member-only convenience flow. It owns short-code
generation, password-authenticated key exchange, encrypted identity exchange, a
transcript-derived short authentication string (SAS), explicit local and peer
confirmation, bounded relay attempts, and release of the existing capability only
after mutual confirmation. It does not replace the compact bearer-token flow, change
MLS membership semantics, permit administrator grants, add peer discovery, or make
the relay an identity authority.

## Verified facts

- Six decimal digits have only 1,000,000 possibilities and are practical to guess.
- A password-authenticated key exchange prevents passive and offline network
  dictionary attacks; each active execution permits an online guess that must be
  rate-limited.
- OPAQUE is standardized as RFC 9807. The `opaque-ke` implementation was audited by
  NCC Group in 2021; findings against 0.5.0 were fixed in 1.2.0. The selected stable
  4.0.1 release implements RFC 9807, but has not received a separate published audit
  covering every later major-version change.
- The relay is untrusted and must not receive stable device identifiers, OPAQUE
  session keys, confirmation keys, SAS values, or pairing capabilities in plaintext.
- The existing pairing capability and daemon state machine already authenticate the
  final invitation, JoinProof, Welcome, device identities, and member role.

## Assumptions

- The two operators can compare a six-digit SAS and bounded device identifiers over
  an independent human channel before confirming.
- Relay authentication limits anonymous abuse; explicit per-principal and per-window
  bounds limit online code guesses.
- A malicious relay can race, suppress, reorder, replay, or split OPAQUE messages.
  Such behavior may deny service but must not produce the same confirmed transcript
  at two honest endpoints.

## Decision drivers

- Make the entered code short enough for voice and manual transfer.
- Ensure possession or observation of the code does not authorize membership.
- Use a standardized, reviewed PAKE implementation rather than custom key agreement.
- Keep stable device identity and membership authority opaque to the relay.
- Require affirmative confirmation at both endpoints before creating a capability.
- Preserve the existing member pairing protocol after verification succeeds.

## Decision

### Use a six-digit code only as locator and OPAQUE password

The creator generates six unbiased decimal digits and a random 128-bit attempt
identifier. A domain-separated SHA-256 digest of the code selects one ephemeral relay
slot; this locator is not secret and grants no authority. The attempt expires after
ten minutes.

The creator acts as the ephemeral OPAQUE server. It performs local registration under
the code using stable `opaque-ke` 4.0.1 with:

- RFC 9807 Ristretto255 OPRF;
- TripleDH over Ristretto255 with SHA-512; and
- Argon2id password stretching.

OPAQUE identities bind the protocol domain, attempt identifier, and creator/claimant
roles. Serialized OPAQUE setup, password file, and in-progress login state are
secret-bearing and remain sealed by the daemon.

### Exchange identity only after OPAQUE completes

The relay carries bounded opaque OPAQUE messages. After both sides derive the same
session key, they exchange encrypted identity descriptors containing their public
`DeviceId` values. Role-separated HKDF-SHA-256 outputs provide:

- creator-to-claimant and claimant-to-creator AES-256-GCM keys;
- creator and claimant confirmation keys;
- a capability-transfer key; and
- SAS material.

The SAS is six decimal digits derived from the session key, attempt identifier, exact
OPAQUE messages, and the canonical ordered pair of encrypted device identities. A
relay substitution, wrong code, or active claimant therefore produces a different
session key or transcript and a different SAS.

### Require both explicit confirmations

Each endpoint displays:

- the same six-digit SAS;
- its local and claimed peer `DeviceId`; and
- the common deadline.

The operator confirms the exact displayed attempt, peer identity, and SAS. The daemon
then publishes one role-separated authenticated confirmation. Local confirmation
alone grants nothing. Only after both confirmation records authenticate under the
session key does the creator issue a standard capability requesting `member`, encrypt
it under the capability-transfer key, and publish it for one logical retrieval.

The claimant decrypts and redeems that capability into the existing pairing flow.
Existing invitation, JoinProof, Commit, Welcome, completion, replay, cancellation,
and compensation behavior remains authoritative.

Capability retrieval uses a caller-stable random take identifier persisted before the
request. The relay commits one logical take and returns the same encrypted capability
only for an exact retry of that identifier, so response loss cannot consume authority
before the claimant durably receives it. A different take identifier remains
unavailable.

### Bound online guesses and conflicting claimants

The Community Relay enforces:

- one active claimant per attempt;
- at most five claim attempts for one code locator;
- at most ten new short-code claims per authenticated principal per ten-minute
  window;
- at most 1,000 active short-code attempts globally and eight per creator principal;
  and
- atomic expiry, cancellation, and idempotent one-logical-take capability retrieval.

Unknown, expired, cancelled, consumed, and guess-exhausted attempts share one
unavailable response where practical. A conflicting claimant may be reported to the
creator as a finite state but never receives membership authority.

### Keep administrator and unattended approval unavailable

Short-code verification always requests `member`. Neither relay input nor client
arguments can select `administrator`. Both confirmations are explicit local
operations; no timeout, possession proof, relay response, or model inference can
substitute for them.

## Serious alternatives

### Use SPAKE2

**Pros:** symmetric one-round-trip PAKE, small messages, and a natural two-device fit.

**Cons:** the stable Rust release documents a pre-RFC draft and explicitly states it
has not received an independent audit. The 0.5 line was prerelease when selected.
Rejected for this authorization boundary despite lower implementation complexity.

### Use Noise XX and compare its handshake hash

**Pros:** mature framework, simple encrypted identity exchange, and natural SAS.

**Cons:** Noise is not a PAKE. The six-digit locator would not resist offline or
active password guessing without adding another password-authentication construction.
Rejected as incomplete.

### Use OPAQUE with the relay as server

**Pros:** conventional client/server deployment and centralized online-guess limits.

**Cons:** requires the relay to hold OPAQUE server secrets and password files, making
relay compromise part of the authentication boundary. Rejected.

### Treat six digits as a bearer token

**Pros:** minimal state and messaging.

**Cons:** online enumeration directly grants membership. Rejected.

## Consequences

### Positive

- The transferred locator is six decimal digits.
- Passive observers and a stolen relay database cannot test codes offline.
- Stable device IDs and capabilities remain encrypted from the relay.
- A malicious relay cannot make two honest endpoints confirm the same substituted
  transcript.
- The verified flow reuses the existing member pairing state machine.

### Negative

- OPAQUE adds registration, login, key-confirmation, encrypted identity, and durable
  resume state.
- The flow requires explicit comparison and confirmation on both devices.
- The selected crate has audited lineage but not a published audit of every 4.x
  change.
- Online denial and claimant racing remain possible within strict bounds.

### Neutral

- The six-digit code is intentionally not a secret after PAKE completion.
- The 26-character bearer-token path remains faster when copying or QR scanning is
  available.
- A successful SAS comparison verifies this one transcript, not a durable human
  identity.

## Confirmation

Continued compliance is demonstrated by:

- fixed OPAQUE interoperability vectors and wrong-code failure;
- pure transition tables for both confirmation orders, expiry, cancellation, replay,
  duplicate confirmation, and conflicting claimant;
- relay tests for global, creator, code, principal, and time-window bounds;
- tests proving device IDs, SAS values, session keys, and capability bytes never
  enter relay plaintext storage or logs;
- active relay substitution and claimant-race tests producing mismatched SAS or no
  capability;
- a two-client acceptance where both confirmations precede capability creation and
  complete one existing member pairing; and
- specialized security review before integration and delivery.

## References

- [RFC 9807: The OPAQUE Augmented PAKE](https://www.rfc-editor.org/rfc/rfc9807)
- [opaque-ke NCC Group audit](https://research.nccgroup.com/2021/12/13/public-report-whatsapp-opaque-ke-cryptographic-implementation-review/)
- [ADR 0006: Joiner-issued pairing capabilities](adr-0006-joiner-issued-pairing-capabilities.md)
- [ADR 0010: AccountTrusted two-command pairing](adr-0010-account-trusted-two-command-pairing.md)
- [ADR 0023: Encrypted pairing rendezvous](adr-0023-encrypted-pairing-rendezvous.md)
- [Threat model](../security/threat-model.md)
