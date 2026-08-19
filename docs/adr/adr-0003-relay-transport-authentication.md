---
title: Keep relay authentication deployment-provided with a hashed bearer-token adapter
status: Accepted
date: 2026-08-19
authors:
  - Konclave maintainers
tags:
  - authentication
  - relay
  - security
  - transport
supersedes: []
superseded_by: []
---

# Keep relay authentication deployment-provided with a hashed bearer-token adapter

## Context and scope

Konclave relay requests need an authenticated principal before route authorization or
storage. The public wire protocol must still work for a self-hosted relay and a
separately operated service without embedding either deployment's account system in
protobuf.

Relay authentication is not MLS membership authentication. It limits observation of
relay metadata, unauthorized storage use, and denial-of-service opportunities.
Clients still validate every message, sender, and membership transition end to end.

This decision covers data-plane HTTP and WebSocket authentication, the public
self-hosted adapter, principal pseudonymity, transport protection, and the boundary
available to other deployments. It does not define human accounts, billing,
federation, or remote administration.

## Verified facts

- RFC 6750 defines the standard HTTP `Authorization: Bearer` scheme and requires TLS
  for bearer-token confidentiality.
- A bearer token grants its holder the token's authority; it does not provide
  proof-of-possession after theft.
- A uniformly random 32-byte token has 256 bits of entropy. A domain-separated
  SHA-256 digest can serve as a non-secret lookup identifier without storing the
  bearer value, assuming the token retains that entropy.
- `DeviceId` is stable across conversations. Using it directly as relay identity
  would make otherwise unrelated routes linkable.
- `RoutingId` is observable relay metadata under the accepted threat model. Treating
  it as the only access credential would contradict that model and prevent explicit
  revocation.
- Mutual TLS and OpenID Connect are mature deployment authentication choices, but
  either would make one operational environment part of the shared data-plane wire.

## Assumptions

- The relay operator controls the access document and the TLS endpoint or trusted
  reverse proxy.
- Endpoint tooling generates bearer tokens with an operating-system cryptographic
  random source and stores raw tokens as sealed local credentials.
- The self-hosted static adapter is suitable for a single relay process. Changes to
  its access document take effect after a controlled restart.
- Other deployments may replace authentication and authorization adapters while
  preserving the public protobuf, HTTP, WebSocket, and error contracts.

## Decision drivers

- No public or anonymous relay data plane.
- No raw bearer token in relay configuration, persistence, logs, or telemetry.
- No cross-route device-identity correlation at the relay.
- One public wire contract independent of deployment account infrastructure.
- Simple self-hosted operation without custom request-signing cryptography.
- Explicit route and action grants with a fail-closed default.

## Decision

### Data-plane authentication

HTTP operations and the WebSocket upgrade use exactly one standard bearer
authorization header. The token is the base64url-without-padding encoding of exactly
32 random bytes. Missing, duplicated, malformed, incorrectly sized, or unknown
credentials receive the same opaque authentication failure.

TLS is mandatory outside loopback. The community relay serves loopback directly for
local development and otherwise starts only when the operator explicitly confirms
that a trusted reverse proxy terminates TLS. The bearer header is never accepted in
query parameters.

### Pseudonymous principals

The relay derives its opaque principal identifier as:

```text
SHA-256(
  "konclave-relay-principal-v1\0" ||
  bearer_token_bytes
)
```

The static server access document stores this digest, never the bearer token.
Principal identifiers are not device identifiers and carry no human or membership
meaning.

### Authorization

Authentication and route authorization remain separate operations. A versioned,
bounded static access document maps a principal identifier to:

- an exact `RoutingId` or an explicit wildcard;
- one or more of `send`, `replay`, and `acknowledge`.

The community relay checks authentication before reading a request body and checks
the route-specific action before persistence. Wildcards are an explicit convenience
for isolated self-hosted instances, not an implicit default.

An access grant does not authorize MLS membership or make opaque payloads valid.
Removing a member from MLS remains the confidentiality and authenticity control.
Operators should also revoke that endpoint's relay grant to reduce metadata access
and denial-of-service capacity.

### Deployment boundary

Bearer authentication is an HTTP adapter, not a protobuf field. `RelayPrincipalId`,
`RelayAuthorizer`, and `RelayService` remain the public composition seams. Another
deployment may authenticate through a different mechanism and supply its own
principal and authorizer without adding required fields to the shared relay envelope.

### Forwarding compatibility

The relay validates known bounded envelope fields but stores the exact encoded
envelope. Submit responses and replay pages embed those exact bytes, preserving
additive protobuf fields that the relay does not interpret.

## Serious alternatives

### Device-signed HTTP requests

**Pros:** proof of possession, no bearer token, and direct cryptographic device
authentication.

**Cons:** using `DeviceId` links routes; route-scoped signing keys require a new
request-signature, nonce, replay, and grant protocol; and relay-side key grants risk
duplicating membership policy. This remains possible through a future adapter but is
not the shared baseline.

### Routing identifier as a bearer capability

**Pros:** no separate provisioning and minimal request metadata.

**Cons:** routing identifiers are observable, cannot identify acknowledgments per
client, and cannot revoke one endpoint without changing the route. Rejected as the
sole authorization mechanism.

### Mutual TLS

**Pros:** standardized proof of possession and mature certificate revocation.

**Cons:** certificate issuance, rotation, proxy integration, and client setup are too
heavy for the default self-hosted agent workflow. Deployments may still terminate
mutual TLS before the relay adapter.

### OpenID Connect or hosted account tokens

**Pros:** established human-account lifecycle, centralized revocation, and strong fit
for operated services.

**Cons:** introduces issuer discovery, account identity, and service dependencies
that do not belong in the portable self-hosted data plane. Deferred to
deployment-specific adapters.

### One shared instance token

**Pros:** simplest setup.

**Cons:** no per-agent acknowledgment identity or revocation and unnecessarily broad
blast radius. The selected static adapter can express a wildcard grant while still
using a distinct token per principal.

## Consequences

### Positive

- Self-hosted relays can authenticate without storing bearer secrets.
- Hosted or enterprise authentication can change without forking protobuf.
- Relay principals are pseudonymous and independently revocable.
- Authentication occurs before bounded body materialization.
- Exact envelope bytes survive forwarding and durable replay.

### Negative

- Bearer theft grants access until the corresponding principal is removed.
- Static access changes require restart and do not automatically follow MLS
  membership changes.
- A reverse-proxy deployment must configure TLS termination and forwarded
  authorization headers correctly.
- Initial public administration remains operator-managed rather than a remote
  self-service control plane.

### Neutral

- The relay can still observe routing, timing, size, principal pseudonyms, and access
  patterns.
- Relay authorization reduces abuse but does not establish message authenticity or
  membership.

## Confirmation

Continued compliance is demonstrated by:

- a fixed principal-derivation vector;
- bounded access-document parsing with unknown-field and duplicate rejection;
- tests for missing, malformed, duplicated, and unknown bearer credentials;
- route and action authorization tests, including explicit wildcard behavior;
- tests proving unauthenticated oversized bodies fail before body processing;
- TLS binding policy tests;
- HTTP integration tests for submit, exact retry, replay, acknowledgment, stable
  error codes, and route denial;
- byte-preservation tests with an additive unknown protobuf field;
- storage migration tests from the prior canonical-envelope schema;
- secret-safe logging tests and specialized security review.

## References

- [RFC 6750: The OAuth 2.0 Authorization Framework: Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750)
- [ADR 0001: Protocol trust and E2EE](adr-0001-protocol-trust-and-e2ee.md)
- [Threat model](../security/threat-model.md)
- [Relay transport authentication](../protocol/relay-authentication.md)
