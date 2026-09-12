---
title: Negotiate protected A2A as a fail-closed native Konclave handoff
status: Accepted
date: 2026-09-12
authors:
  - Konclave maintainers
tags:
  - a2a
  - interoperability
  - mls
  - security
supersedes: []
superseded_by: []
---

# Negotiate protected A2A as a fail-closed native Konclave handoff

## Context and scope

ADR 0013 defines standard A2A bridge mode as an HTTP+JSON plaintext endpoint. The
gateway is a Konclave member in that mode and necessarily sees request and response
content while translating between A2A tasks and Konclave directed requests.

Konclave-capable A2A clients need a stronger option that preserves native Konclave
identity, MLS confidentiality, durable delivery, replay protection, and endpoint
custody. A protected mode cannot be implied by TLS, mTLS, a signed Agent Card, or an
opaque A2A byte Part. It requires explicit negotiation and an honest statement about
which component can see plaintext.

This decision owns the protected-profile extension identifier and parameters, trust
negotiation, gateway visibility claim, cryptographic behavior, downgrade policy, and
public versus managed ownership. It does not define account enrollment, invitation
UX, managed routing, billing, or a replacement for Konclave transport.

## Verified facts

- A2A protocol 1.0 Agent Cards can advertise URI-identified extensions with a
  `required` flag and extension-owned structured parameters.
- A2A Messages and Artifacts can name extension URIs, but A2A v1.0.1 does not define
  a standard application-layer end-to-end encrypted payload extension.
- Standard A2A security schemes authenticate web requests; they do not prevent the
  A2A server from seeing application plaintext.
- A gateway receiving opaque MLS bytes cannot authenticate which group member
  produced a terminal response without participating in the MLS group or adding a
  separate authenticated response protocol.
- Native Konclave already defines the required identity, MLS, membership, replay,
  durable relay, and sealed-custody behavior.
- `draft-mpsb-agntcy-slim-02` remains an Informational Internet-Draft and does not
  replace Konclave's durable ordering, contiguous acknowledgment, application replay,
  identity binding, or endpoint-custody contracts.

## Assumptions

- A protected client is Konclave-capable and has deployment-approved native
  enrollment and conversation membership outside the public Agent Card.
- Publishing a relay endpoint is acceptable; the card never publishes a bearer
  credential, route identifier, profile alias, conversation identifier, `DeviceId`,
  invitation, or policy state.
- Standard and protected access may coexist for one published agent, but selecting
  one mode is an explicit caller policy decision.

## Decision drivers

- Preserve original-client-to-agent confidentiality without new cryptography.
- Prevent an unsupported or stale client from silently falling back to plaintext.
- Keep the standard A2A bridge interoperable for clients that do not implement
  Konclave.
- Keep local agents outbound-only and the local daemon off the network.
- Make self-hosted and managed client-visible semantics identical.
- Avoid claiming trustworthy protected A2A task completion from unauthenticated
  opaque bytes.

## Decision

### Advertise one versioned protected-profile extension

The extension URI is:

```text
https://konclave.dev/a2a/extensions/protected/v1
```

The URI defines the fixed `konclave-native-v1` profile,
`konclave-relay-v1` transport, `mls-rfc9420` payload protection,
`application-opaque` gateway visibility, and `fail-closed` downgrade policy. Its
parameters contain only the deployment-specific endpoint:

```json
{
  "relayEndpoint": "https://relay.example.com/"
}
```

Only `relayEndpoint` and the A2A `required` flag are deployment inputs. Unknown
parameters, a missing endpoint, duplicate protected extensions, insecure remote URLs,
user information, query strings, and fragments fail validation.

Loopback development may use an HTTP loopback relay endpoint. Production requires
HTTPS. The endpoint is not a credential and does not authorize a route.

### Handoff to native Konclave instead of tunneling opaque A2A Parts

Protected v1 does not place encrypted payloads in A2A Message or Artifact Parts. A
client that selects the protected profile uses the native Konclave client protocol
at the advertised relay endpoint with its own approved credential, device identity,
conversation membership, and local policy.

The client maps its task intent to a native directed request and authenticates the
response through Konclave. The standard A2A HTTP gateway is not the task or plaintext
authority for that exchange. Relay-visible routing metadata remains governed by the
Konclave threat model; application plaintext and MLS keys do not become visible to
the relay or A2A discovery service.

This handoff reuses the existing Konclave cryptographic and delivery contracts. It
does not introduce JWE, HPKE, a second MLS stack, a device-key encryption oracle, or
custom key agreement.

### Make trust selection explicit and fail closed

The public client contract exposes only two choices:

- allow the standard plaintext bridge; or
- require the Konclave-protected profile.

There is no "prefer protected, otherwise standard" option. A protected-required
client fails when the exact extension is absent or malformed. A standard HTTP+JSON
client fails when the card marks the protected extension as required.

A standard gateway application also refuses to start from a card that requires the
protected extension. Protected-only cards may still be published through the
deployment-owned discovery/catalog surface, but they cannot accidentally activate
the plaintext task application and do not advertise standard A2A streaming.

An optional protected extension allows both modes. Choosing standard mode remains an
explicit statement that the gateway sees plaintext.

### Keep Message and Artifact extension use closed

The initial standard and protected-handoff profiles continue rejecting Message and
Artifact extension URIs. The Agent Card extension negotiates a transport handoff; it
does not authorize opaque A2A payloads, automatic retrieval, hidden metadata, or new
task-state semantics.

### Preserve public and managed parity

The public repository owns:

- the extension URI, fixed semantics, and exact endpoint parameter;
- Agent Card validation and publication;
- trust-mode negotiation and fail-closed behavior;
- native Konclave cryptographic and delivery semantics;
- self-hosted examples and conformance tests.

Managed code may privately own account enrollment, relay selection, tenancy,
regional routing, quotas, monitoring, and support. It cannot weaken the fixed
visibility, payload-protection, or downgrade claims.

## Serious alternatives

### Carry opaque MLS bytes in an A2A raw Part

**Pros:** keeps A2A task operations on the wire and hides plaintext from the gateway.

**Cons:** a blind gateway cannot authenticate that an observed opaque response came
from the configured target or safely declare the task complete. Adding visible
signatures and correlation would create another protocol. Rejected.

### Keep the gateway as an MLS member

**Pros:** the gateway can authenticate responses and preserve current task projection.

**Cons:** the gateway can decrypt content, so this is standard bridge mode rather than
original-client-to-agent protection. Rejected as the protected profile.

### Add JWE, HPKE, or target-device public-key encryption

**Pros:** can hide an inner payload from the gateway.

**Cons:** introduces new key discovery, custody, rotation, replay, response
authentication, and downgrade contracts alongside MLS. Rejected.

### Adopt or bridge SLIM now

**Pros:** emerging MLS-capable transport designed for agent protocols.

**Cons:** does not yet prove equivalence for Konclave's durability, replay, identity,
acknowledgment, and custody guarantees. Deferred under ADR 0013.

### Treat mTLS as end-to-end protection

**Pros:** widely deployed and already represented by A2A security schemes.

**Cons:** protects the network hop while the A2A server still sees plaintext.
Rejected.

## Consequences

### Positive

- Protected negotiation reuses audited Konclave behavior instead of creating new
  cryptography.
- Gateway visibility and downgrade behavior are explicit and testable.
- Standard A2A compatibility remains available.
- Agent devices remain outbound-only.
- Self-hosted and managed deployments expose the same protected-profile contract.

### Negative

- Only Konclave-capable A2A clients can use protected mode.
- Enrollment and membership remain separate prerequisites.
- Protected exchanges do not use the standard A2A HTTP task endpoint.
- A client that requires protection fails rather than obtaining a degraded result.

### Neutral

- Standard bridge mode continues to terminate plaintext at the gateway.
- Agent Card web authentication and native Konclave device identity remain separate.
- SLIM remains monitored rather than adopted.

## Confirmation

Continued compliance requires:

- exact Agent Card extension round-trip and malformed-parameter rejection tests;
- production HTTPS and loopback-only HTTP endpoint tests;
- client tests proving protected-required selection never falls back;
- standard-client and gateway-application tests rejecting a required protected
  extension;
- tests proving optional protected advertisement preserves explicit standard mode;
- tests proving Message and Artifact extensions remain rejected;
- existing Konclave MLS, replay, durable-delivery, custody, and downgrade suites;
- public self-hosted and managed conformance against the same extension contract; and
- a new ADR before protected A2A payload tunneling or SLIM changes these semantics.

## References

- [A2A protocol specification](https://a2a-protocol.org/latest/specification/)
- [A2A v1.0.1 normative schema](../../third_party/a2a/v1.0.1/a2a.proto)
- [SLIM Internet-Draft](https://datatracker.ietf.org/doc/draft-mpsb-agntcy-slim/)
- [ADR 0001: Protocol trust and E2EE](adr-0001-protocol-trust-and-e2ee.md)
- [ADR 0007: Outbound relay principal enrollment](adr-0007-outbound-relay-principal-enrollment.md)
- [ADR 0012: Structured directed collaboration requests](adr-0012-structured-directed-collaboration-requests.md)
- [ADR 0013: A2A edge interoperability](adr-0013-a2a-edge-interoperability.md)
- [A2A compatibility contract](../protocol/a2a-compatibility.md)
- [Threat model](../security/threat-model.md)
