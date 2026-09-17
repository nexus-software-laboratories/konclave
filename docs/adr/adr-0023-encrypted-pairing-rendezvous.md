---
title: Use encrypted relay rendezvous for compact pairing handoff
status: Accepted
date: 2026-09-17
authors:
  - Konclave maintainers
tags:
  - pairing
  - relay
  - cryptography
  - usability
supersedes: []
superseded_by: []
---

# Use encrypted relay rendezvous for compact pairing handoff

## Context and scope

ADR 0006 defines a self-authenticating pairing capability that contains a signed
device offer, a 256-bit pairing secret, the normalized relay endpoint, and enough
public material to verify the offer. That complete capability is intentionally
bounded and machine transferable, but its encoded form is too large for ordinary
manual transfer between computers.

This decision adds a compact handoff above the existing capability. It owns the
compact token, client-side encryption, opaque relay lookup, one-time retrieval,
expiry, and fallback to the complete capability. It does not change pairing
membership authorization, device identity, MLS invitation/JoinProof/Welcome
semantics, relay enrollment, or administrator grants.

## Verified facts

- The complete capability is a bearer secret. Shortening its text without moving
  bytes elsewhere cannot preserve its entropy and authenticated public offer.
- Both endpoints already have authenticated outbound access to the same relay.
- The relay is untrusted for pairing confidentiality and identity validation.
- `AuthenticatedCipher` provides reviewed AES-256-GCM with fresh nonces while leaving
  versioned framing and associated data to the owning protocol.
- A 128-bit uniformly random token remains infeasible to guess within a short online
  authorization window and encodes as 26 case-insensitive Crockford Base32
  characters.
- A six-digit or similarly low-entropy code cannot safely remain the membership
  authorization evidence.

## Assumptions

- The operator can transfer 26 human-enterable characters or use a clipboard, QR, or
  deep link supplied by a presentation adapter.
- Relay authentication and request-rate bounds limit unauthenticated resource abuse;
  token secrecy remains the authorization evidence for `AccountTrusted`.
- A malicious relay may retain, replace, replay, or suppress rendezvous ciphertext.
  Clients authenticate lookup identity, expiry, nonce, and ciphertext before decoding
  a capability.

## Decision drivers

- Preserve the existing capability and pairing state machine.
- Keep the relay unable to decrypt or redeem pairing authority.
- Add no inbound listener, firewall rule, LAN discovery, or hosted account.
- Keep normal handoff at or below 26 case-insensitive characters.
- Make unknown, expired, modified, consumed, and conflicting records fail closed.
- Preserve a complete-capability recovery path.

## Decision

### Derive lookup and encryption from one compact token

The creating endpoint generates 16 random bytes and renders them as canonical
uppercase Crockford Base32. Decoding accepts lowercase but rejects ambiguous,
truncated, extended, or incorrectly padded input.

HKDF-SHA-256 expands the token under separate domains into:

- a 32-byte non-secret relay lookup identifier; and
- a 32-byte AES-256-GCM key.

The token implements neither `Clone` nor `Debug` and exists only in zeroizing
ownership and the explicit handoff text.

### Encrypt the complete existing capability

The endpoint encodes the ADR 0006 capability and encrypts that exact text under a
fresh AES-GCM nonce. Associated data binds:

- the rendezvous format domain and protocol version;
- the derived lookup identifier;
- the capability authorization deadline; and
- the nonce.

The relay-facing record contains only the lookup identifier, deadline, nonce, and
bounded ciphertext. Plaintext is limited to 8 KiB, ciphertext to 8 KiB plus the
16-byte authentication tag, and the complete protobuf record to 9 KiB. Opening first
checks the token-derived lookup and deadline, then authenticates and decrypts, decodes
the existing capability, and requires its signed deadline to match the record.

### Store one bounded opaque record at the relay

The Community Relay adds an authenticated control surface for publishing and taking
one rendezvous record. Publication is idempotent only for identical content under the
same lookup. Conflicting content fails. Taking an unexpired record returns and
consumes it atomically. Unknown, expired, and consumed lookups share one unavailable
outcome so the relay does not become a token oracle.

Storage is bounded to 10,000 active records globally and 32 per authenticated
principal. Expired records may be removed during publish/take operations or scheduled
maintenance. Confidentiality and authorization do not depend on physical deletion
because the relay never has the token-derived key and the embedded capability
enforces its signed deadline.

### Keep authorization semantics unchanged

Possession of the compact high-entropy token is equivalent to possession of the full
capability under `AccountTrusted` and grants only the requested `member` workflow.
The inviter and joiner still execute the existing authenticated pairing transitions.
The complete capability remains accepted as an explicit recovery interface.

## Serious alternatives

### Compress or truncate the capability

**Pros:** no relay change.

**Cons:** signatures, public keys, and random secret material do not compress to a
human-enterable value. Truncation destroys security. Rejected.

### Store the capability as relay plaintext behind a random handle

**Pros:** smallest client implementation.

**Cons:** the relay could read and redeem membership authority. Rejected.

### Use a six-digit code as the bearer secret

**Pros:** easiest manual entry.

**Cons:** online guessing becomes practical and capability possession can no longer
justify automatic membership approval. Rejected for this flow. A separate
rendezvous-only code with mandatory mutual transcript verification may be added by a
later ADR.

### Discover peers directly on the LAN

**Pros:** no handoff value.

**Cons:** requires inbound networking, firewall behavior, discovery privacy, and a
second transport path. Rejected.

### Use a hosted identity or GitHub account

**Pros:** convenient device discovery.

**Cons:** makes local self-hosted pairing depend on a third party and changes the
identity boundary. Rejected.

## Consequences

### Positive

- Normal pairing handoff shrinks to 26 case-insensitive characters.
- The complete capability and pairing authorization model remain unchanged.
- The relay stores only bounded opaque ciphertext and cannot impersonate either
  endpoint.
- Clipboard, QR, and deep-link adapters can share one canonical token.

### Negative

- The relay gains one bounded storage table and authenticated HTTP surface.
- The client gains a versioned token and ciphertext compatibility contract.
- A token holder may race the intended recipient until one-time consumption or
  capability expiry.

### Neutral

- The compact token remains a bearer secret and must not enter logs or telemetry.
- Relay deletion improves hygiene but is not the confidentiality boundary.
- Truly short human codes still require explicit mutual confirmation.

## Confirmation

Continued compliance is demonstrated by:

- known token encoding and HKDF vectors;
- repeated plaintext producing distinct nonces and ciphertext;
- wrong token, lookup, expiry, nonce, ciphertext, capability, and trailing bytes
  failing closed;
- relay atomic publish/take, idempotency, conflict, expiry, capacity, and concurrent
  claimant tests;
- scans proving complete capability bytes never enter relay logs or plaintext
  storage;
- a two-client acceptance where the compact token retrieves and completes the
  existing pairing flow; and
- specialized security review before delivery.

## References

- [ADR 0006: Joiner-issued pairing capabilities](adr-0006-joiner-issued-pairing-capabilities.md)
- [ADR 0007: Outbound relay principal enrollment](adr-0007-outbound-relay-principal-enrollment.md)
- [Threat model](../security/threat-model.md)
