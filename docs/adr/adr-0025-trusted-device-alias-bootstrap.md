---
title: Bootstrap repeat pairing through an existing authenticated conversation
status: Accepted
date: 2026-09-17
authors:
  - Konclave maintainers
tags:
  - pairing
  - identity
  - usability
  - persistence
supersedes: []
superseded_by: []
---

# Bootstrap repeat pairing through an existing authenticated conversation

## Context and scope

ADRs 0023 and 0024 make first-contact pairing practical, but a device that has already
authenticated a peer still addresses that peer by a 64-character `DeviceId`. A local
alias such as `alienware` can improve repeat-conversation UX, but it must not become a
wire identity, a reusable membership credential, or a relay-visible directory key.

This decision owns local alias binding, stale-root detection, selection of an existing
authenticated bootstrap conversation, and repeat pairing for a fresh conversation. It
does not introduce stable device inboxes, peer discovery, reusable invitations,
automatic administrator grants, or aliases on the wire.

## Verified facts

- A current conversation stores root-verified credential bindings for each member.
- Credential bindings carry root-signed application capability bits.
- The existing pairing state machine already owns capability issuance, invitation,
  JoinProof, Commit, Welcome, completion, cancellation, replay, and compensation.
- Application messages inside an existing conversation are MLS authenticated and
  confidential from the relay.
- A pairing capability is short lived and self-authenticating, but retaining it as an
  address-book credential would turn a one-time secret into durable bearer authority.
- `DeviceId` remains the canonical protocol identity. A local alias cannot safely
  replace it in signatures, membership state, relay metadata, or authorization.

## Assumptions

- Repeat pairing is available only while both devices still share at least one current
  authenticated conversation.
- The user initiating `/konclave new <alias>` intends to create one fresh member-only
  conversation with that exact previously authenticated device root.
- A current authenticated request from an existing member can ask the targeted peer
  daemon to issue a fresh capability for this operation; it does not authorize any
  unrelated device or administrator role.

## Decision drivers

- Remove repeated long identifier entry after successful first contact.
- Preserve fresh invitation and membership-commit authorization for every conversation.
- Reuse proven crash recovery instead of implementing a second membership protocol.
- Invalidate aliases when their exact root is no longer authenticated by current state.
- Keep aliases and address-book metadata local and sealed.

## Decision

### Bind aliases locally to the exact authenticated root

An alias is canonical lowercase ASCII letters, digits, and interior hyphens, with at
most 32 UTF-8 bytes. Parsing rejects uppercase and non-canonical spellings rather than
case-folding them.

The sealed address book stores:

- the local alias;
- the canonical `DeviceId`; and
- the authenticated device-root public key.

Aliases are unique per profile, and one device root has at most one active alias.
Renaming the same active root is explicit. Reusing an alias for another active root
fails. A stale alias may be rebound only after the replacement root is independently
authenticated by current conversation state.

### Resolve through current membership, never stale storage

Before an alias is used, the daemon scans current authenticated conversation bindings.
Resolution succeeds only when at least one current conversation contains the exact
stored `DeviceId` and root key and every current member advertises the root-signed
repeat-pairing application capability. A missing device, any contradictory root for
the same identifier, or only legacy capability sets fails closed.

When several conversations qualify, the lowest canonical `ConversationId` is selected
deterministically as the bootstrap channel. The selected identifier is local
orchestration state, not new protocol authority.

### Request a fresh capability over the existing MLS conversation

`/konclave new <alias>` durably reserves an operation plus fresh conversation and
routing identifiers, then sends one bounded, targeted repeat-pairing request through
the selected existing MLS conversation. The empty conversation is not created yet,
which avoids leaving one behind when the peer never responds. The target daemon
authenticates the actual MLS sender and exact target before issuing a fresh,
short-lived `member` capability. Its response is directed to the initiating device
through that same authenticated conversation.

The initiator verifies the capability's root-signed device offer against the alias,
redeems it, creates the preselected conversation idempotently, and authorizes the
target into that conversation. The target
authorizes the inviter only when the invitation identity matches the authenticated
bootstrap request. The existing pairing state machine then remains authoritative for
all invitation, proof, Commit, Welcome, completion, replay, cancellation, and
compensation behavior.

The request and response are internal control content. They are stored sealed, never
projected to agent/model delivery, and never interpreted as free-form text.

### Keep repeat pairing member-only and bounded

Aliases cannot select a role. Repeat pairing always requests and grants `member`.
Every operation has a caller-stable identifier, finite deadline, bounded active count,
and exact retry state. The daemon retains at most 16 active and 64 total operations,
pruning expired terminal records before reserving new work. Removing the peer from all
shared conversations or observing a different root invalidates resolution before any
capability is accepted or new conversation membership side effect occurs.

The additive application control variants are sent only through a conversation where
every current member advertises support. Existing conversations created before that
capability was signed are ineligible; a fresh first-contact conversation after both
devices upgrade establishes the required negotiation.

## Serious alternatives

### Persist a reusable pairing capability

**Pros:** minimal protocol work and immediate repeat connection.

**Cons:** turns a short-lived one-time bearer secret into durable membership authority;
revocation and theft become materially harder. Rejected.

### Add a stable per-device relay inbox

**Pros:** repeat pairing would not require an existing shared conversation.

**Cons:** adds relay-visible cross-conversation linkability, durable routing authority,
and a new enrollment/delivery boundary. Rejected for this local UX feature.

### Exchange invitation, JoinProof, and Welcome directly over the old conversation

**Pros:** avoids creating an intermediate pairing capability.

**Cons:** duplicates the existing pairing journal, replay, cancellation, deadline, and
compensation state machine. Rejected in favor of reusing the proven protocol.

### Treat an alias as a wire identifier

**Pros:** short user-facing protocol values.

**Cons:** aliases are profile-local, mutable, collision-prone, and unauthenticated.
Rejected.

## Consequences

### Positive

- Repeat conversation creation uses a memorable local name.
- Every new conversation still uses a fresh signed invitation and authenticated Commit.
- Stale or rotated roots fail before repeat pairing begins.
- The relay sees no aliases or new stable device-routing metadata.
- Existing pairing recovery and compensation remain authoritative.

### Negative

- Both devices must retain at least one shared authenticated conversation.
- Internal request/response content and a bounded repeat-operation journal are added.
- One compromised current member can request member-only repeat pairing from another
  current peer; this is the explicit trust carried by the existing relationship.

### Neutral

- First-contact compact and short-code flows remain unchanged.
- The alias is local convenience metadata, not a human identity claim.
- Rebinding after device-root rotation requires another independently verified pairing.

## Confirmation

Continued compliance is demonstrated by:

- pure alias parsing, collision, rename, stale-root, removal, and deterministic
  bootstrap-selection tests;
- sealed profile-scoped address-book persistence and startup verification;
- internal control messages that authenticate actual MLS sender and exact target;
- root-signed capability negotiation across every recipient before internal control
  is sent;
- tests proving aliases never enter protocol identity, relay metadata, logs, or model
  delivery;
- response-loss, restart, duplicate, expiry, removal, and root-change tests;
- a two-device acceptance that creates a second conversation from one local alias and
  completes the existing member pairing state machine; and
- specialized security review before integration and delivery.

## References

- [ADR 0004: Daemon profile journal](adr-0004-daemon-profile-journal.md)
- [ADR 0006: Joiner-issued pairing capabilities](adr-0006-joiner-issued-pairing-capabilities.md)
- [ADR 0023: Encrypted pairing rendezvous](adr-0023-encrypted-pairing-rendezvous.md)
- [ADR 0024: OPAQUE short-code mutual verification](adr-0024-opaque-short-code-mutual-verification.md)
- [Threat model](../security/threat-model.md)
