---
title: Pair sessions through joiner-issued, self-authenticating capabilities
status: Accepted
date: 2026-08-23
authors:
  - Konclave maintainers
tags:
  - pairing
  - identity
  - protocol
  - security
supersedes: []
superseded_by: []
---

# Pair sessions through joiner-issued, self-authenticating capabilities

## Context and scope

Joining a conversation currently requires an operator to move several internal
protocol values between two agent sessions: the joiner's identity, an invitation
bundle, a JoinProof, and a Welcome receipt. Those values are useful protocol
boundaries, but they are not a usable pairing experience.

Konclave needs one bounded value that a person can transfer from a session that wants
to join to a session allowed to invite it. The subsequent exchange must remain
harness-neutral, outbound-only, encrypted from the relay, crash recoverable, and
explicitly authorized on both endpoints.

This decision owns the direction of pairing, capability authority, relay use,
pairing-record semantics, expiry and cancellation behavior, and the division between
the neutral daemon and harness presentation. It does not select final command names or
screen copy.

## Verified facts

- A `DeviceCredentialBinding` is conversation-scoped. It contains a
  `ConversationId` and a conversation signing key, so a joiner cannot construct one
  before learning the conversation from an invitation.
- A signed invitation authenticates the issuer key supplied with it. Without an
  independently bound inviter identity, any holder of a shared pairing secret could
  create a different conversation and supply a valid invitation for that conversation.
- Relay idempotency applies to an exact resubmission with the same envelope identity.
  Regenerating an envelope after a crash creates another cursor, so counting a message
  kind once is not an idempotency strategy.
- The relay may inject, replay, reorder, suppress, or retain pairing ciphertext. A
  routing identifier is a locator, not authentication.
- A wildcard relay bearer grant authorizes every route and outlives a pairing
  capability. Embedding that credential would disclose durable account-wide relay
  authority and contradict the pairing requirement not to disclose relay credentials.
- `SecretRecordKind` and the `KSC1` sealed-blob framing are an at-rest compatibility
  contract. Making them the pairing wire contract would couple local database
  evolution to peer compatibility.
- Once an add-member Commit is accepted, the inviter has changed MLS membership even
  if the joiner has not processed the Welcome. Expiry or cancellation cannot pretend
  that commit never happened.

## Assumptions

- A transferred pairing capability is a bearer secret. Whoever receives it may attempt
  the pairing until its authorization deadline.
- Each endpoint already has authorized outbound access to the same relay for the local
  MVP. Zero-setup remote peers do not yet have a safe credential-provisioning path.
- The operator or agent can explicitly approve a displayed device fingerprint, role,
  conversation, inviter identity, and expiry. Automatic approval, when later offered,
  is an explicit policy rather than a default.
- Pairing ciphertext may remain stored after expiry. Erasing local pairing keys and
  refusing expired state transitions, rather than relay deletion, provides the
  confidentiality and authorization boundary.

## Decision drivers

- One bounded capability transfer instead of copying internal protocol structures.
- Bind a real device before any inviter-side membership decision.
- Preserve the existing invitation, JoinProof, Commit, and Welcome authorization
  contracts rather than replacing them.
- Keep pairing transport and persistence independent of Copilot CLI.
- Make retries idempotent and crash recovery explicit.
- Prevent capability expiry or cancellation from leaving a silent MLS ghost member.
- Add no inbound network listener and disclose no relay or profile credential.

## Decision

### The joiner issues the capability

The device asking to join creates a short-lived `PairingOffer` signed by its device
root. The offer binds:

- protocol version;
- a fresh pairing identifier;
- the claimed device identifier and its root public key;
- the requested role; and
- an absolute authorization deadline; and
- a hash of the secret-derived route and normalized relay endpoint.

Verification re-derives the claimed `DeviceId` from the included public key and verifies
the signature over every field. The context hash prevents a public offer from being
recombined with an attacker-chosen secret or relay endpoint. The role is a request; the
inviter chooses the role it grants in the existing signed invitation.

The transferable capability contains the offer, a 256-bit random pairing secret, the
deadline, and the relay endpoint identifier needed to reject accidental cross-relay
redemption. It never contains a relay bearer credential, private identity material,
profile wrapping key, or sealed profile state.

The inviter verifies the offer and explicitly authorizes its device, role, and target
conversation before sending anything. The joiner explicitly authorizes the inviter
identity learned from the signed invitation before it emits a JoinProof. If policy
automates either decision, the policy is recorded explicitly and the surfaced status
does not claim independent identity verification.

### Pairing uses a distinct encrypted wire contract

The pairing secret and pairing identifier feed one domain-separated HKDF-SHA-256 key
schedule. It derives:

- a pseudorandom relay `RoutingId`;
- an inviter-to-joiner AES-256-GCM key; and
- a joiner-to-inviter AES-256-GCM key.

The clear, bounded `PairingEnvelope` header includes the pairing and message
identifiers, sender role, stage, reply identifier, deadline, and nonce. The complete
canonical header is authenticated as AEAD associated data. Direction-specific keys
prevent a ciphertext emitted by one role from being reflected as a valid record from
the other.

Pairing has its own relay delivery class and carries no MLS parent epoch. The relay
sees a random route, finite delivery class, expiry, size, and timing; it never sees the
offer, invitation, JoinProof, Welcome, conversation identity, device identity, or
plaintext stage payload.

The project reuses one vetted AES-GCM primitive shared with secret storage. It does not
reuse the `KSC1` storage framing, `SecretRecordKind`, or storage associated-data domain.
The pairing envelope and payload codecs belong to `ProtocolContracts`; key derivation
and encryption belong to `CryptographicCore`.

### The exchange is durable and idempotent

The neutral daemon persists one serialized pairing operation keyed by pairing
identifier. Every encrypted record carries:

- a stable pairing message identifier;
- sender role and finite stage;
- the prior message identifier it answers, when applicable; and
- ciphertext authenticated to that header.

The same logical message identifier with identical authenticated content is an
idempotent success. Reusing that identifier with different content is a conflict.
Unexpected, unauthentic, stale, reordered, or duplicate relay records do not advance
state and do not kill a valid pairing. Outbound records are durably prepared before
relay submission and resubmitted with their original envelope and message identifiers
after a crash.

The stages are:

1. inviter authorizes and sends an invitation bundle;
2. joiner authorizes the inviter and sends a JoinProof;
3. inviter commits the add and sends the durable Welcome result;
4. joiner accepts the Welcome and sends completion.

### Expiry and cancellation distinguish pre-commit from post-commit state

The capability deadline bounds starting or authorizing a pairing. Before the add-member
Commit is accepted, expiry or cancellation prevents later transitions.

Accepting the add-member Commit starts a separate bounded completion deadline. During
that recovery window, the exact authenticated Welcome remains valid and recoverable
even when the authorization deadline has passed.

Cancellation or completion timeout after commit cannot erase the commit. The inviter
issues a compensating MLS removal for the added device and persists that operation
through the ordinary membership journal. Pairing is terminal only after completion or
after the compensating removal is accepted.

### Local first, remote only with least-privilege provisioning

The first implementation pairs local sessions and remote sessions that already have
authorized access to the same relay. A random route derived from the secret is safe as
a locator but is not relay authorization.

Zero-setup remote pairing waits for a relay control plane that can mint a short-lived
principal restricted to the exact pairing route and minimum required permissions. A
wildcard or durable relay credential is never placed in the capability as a shortcut.

## Serious alternatives

### Inviter-issued capability followed by a DeviceOffer

This appears natural because the inviter starts the conversation. It is impossible
with the existing identity model: the proposed offer required a
`DeviceCredentialBinding`, which cannot exist before the invitation reveals the
conversation. Replacing it with an unsigned device identifier would also reintroduce
the identity-substitution problem. Rejected.

### Whoever proves the bearer secret joins automatically

This is a smaller state machine and `expected_device_id` would still stop a different
device from redeeming the eventual invitation. It authenticates capability possession,
not the intended collaborator. A copied or intercepted capability would silently grant
membership. Rejected as the default; it may exist only as an explicit, accurately
labelled approval policy.

### Carry the wildcard relay credential in the capability

This would make remote pairing appear zero-configuration. Capability expiry would not
revoke the credential, and the recipient would retain send, replay, and acknowledge
authority for every route. Rejected.

### Reuse sealed local-storage records on the wire

This would reuse tested AES-GCM code with less immediate implementation work. It would
also expose an at-rest record taxonomy as a peer compatibility contract and make
storage changes protocol changes. Rejected in favor of sharing the primitive beneath
two separate formats.

### Reject every repeated stage

This would make the state machine easy to describe. A crash retry with a fresh relay
envelope would become indistinguishable from an attack, and a malicious relay could
turn replay into a permanent denial of service. Rejected in favor of stable logical
message identities and content-bound idempotency.

## Consequences

### Positive

- The one transferred value identifies and authenticates the joiner before the inviter
  decides.
- Existing conversation membership authorization remains authoritative.
- Relay compromise does not reveal pairing or conversation plaintext and cannot forge
  an accepted transition.
- Crash retries and relay replay have explicit idempotent semantics.
- Pairing remains usable by future harnesses through neutral daemon operations.
- The design does not disclose long-lived relay authority.

### Negative

- Both endpoints need durable pairing state in addition to the existing membership
  journals.
- Pairing requires two local authorization decisions unless explicit policy automates
  them.
- A post-commit cancellation requires another MLS epoch change to compensate.
- Zero-setup remote pairing needs a relay provisioning control plane and is not part of
  the local MVP.

### Neutral

- A bearer capability still authorizes an attempt; it is not proof of the human
  identity behind a device.
- Pairing ciphertext may remain replayable at the relay after expiry, but erased keys
  and client-side deadlines make it unusable.
- The pairing route is observable as random metadata, like conversation routes.

## Confirmation

Continued compliance is demonstrated by:

- offer tests that reject signature, identity, role, pairing, and deadline
  substitution;
- protocol tests that bound every header and ciphertext field before allocation;
- shared AES-GCM vectors proving storage and pairing use one implementation under
  distinct domains;
- tests that reflection, header mutation, wrong direction, wrong secret, and modified
  ciphertext fail authentication;
- state-machine tests for exact retry, conflicting retry, reordering, replay,
  cancellation, both deadlines, and crash recovery at every persisted transition;
- end-to-end pairing of two daemon processes from one transferred capability without
  copying an invitation, JoinProof, Welcome, cursor, or binding;
- relay database, log, trace, and error scans showing no pairing plaintext or
  credentials; and
- specialized security review before the pairing state machine is accepted.

## References

- [ADR 0001: Protocol trust and E2EE](adr-0001-protocol-trust-and-e2ee.md)
- [ADR 0002: Sealed local secret custody](adr-0002-sealed-local-secret-custody.md)
- [ADR 0003: Relay authentication](adr-0003-relay-transport-authentication.md)
- [ADR 0004: Daemon profile journal](adr-0004-daemon-profile-journal.md)
- [Threat model](../security/threat-model.md)
