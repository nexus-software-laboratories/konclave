---
title: Keep A2A agent discovery private by default with authenticated projections
status: Accepted
date: 2026-08-30
authors:
  - Konclave maintainers
tags:
  - a2a
  - discovery
  - agent-cards
  - oasf
  - security
supersedes: []
superseded_by: []
---

# Keep A2A agent discovery private by default with authenticated projections

## Context and scope

ADR 0013 establishes A2A as an edge binding and requires a complete public
self-hosted path. It deliberately leaves authenticated extended cards and searchable
private discovery for later work. The pinned A2A 1.0 schema now provides the wire
types needed to define those surfaces without exposing Konclave profile, device,
conversation, policy, relay, or local-service authority.

A2A standardizes one public discovery location,
`/.well-known/agent-card.json`, and one authenticated
`GetExtendedAgentCard` operation. It recognizes curated registries and direct
configuration as discovery strategies but does not standardize a registry API,
authorization model, tenant namespace, cache lifetime, or public enumeration
behavior.

The Open Agentic Schema Framework (OASF) provides a versioned catalog taxonomy. OASF
1.1.0 has an A2A integration module, but an OASF record cannot represent A2A
interfaces, authentication requirements, media modes, capabilities, and free-form
skills without an embedded A2A artifact or extension. Its `skills` values are
taxonomy claims rather than arbitrary A2A skill labels, and its locators identify
downloadable artifacts rather than runtime endpoints.

This decision owns:

- the canonical deployment source for one published A2A agent;
- public, private, and extended Agent Card visibility;
- authorization boundaries for exact lookup and catalog listing;
- direct configuration and the public self-hosted file catalog;
- the relationship between A2A cards and optional OASF records; and
- the initial treatment of Agent Card signatures.

It does not define HTTP routing, authentication middleware, identity federation,
managed registry topology, card-signing key custody, dynamic registration, DNS
discovery, cache headers, or search ranking.

## Verified facts

- A2A 1.0 registers `/.well-known/agent-card.json` as its public discovery
  location.
- `GetExtendedAgentCard` uses the authentication schemes declared by the public card;
  credential acquisition and authorization remain deployment concerns.
- A2A permits authenticated callers to receive additional skills and details in an
  extended card.
- The `tenant` field is an opaque routing value. It is not a credential or
  authorization decision.
- Agent Card JWS signatures are optional and require RFC 8785 JSON canonicalization
  plus an independent verification-key distribution model.
- A2A does not define a catalog or registry API and has no standard agent-enumeration
  operation.
- OASF 1.1.0 records require authors, creation time, and taxonomy skills.
- OASF runtime record validation is produced by the OASF server from the complete
  schema and taxonomy. The repository does not publish one standalone JSON Schema
  that proves record conformance offline.
- OASF's current A2A integration carries the Agent Card through
  `module.artifact`; the older inline `a2a_data.card_data` field is deprecated.
- An OASF locator describes where an artifact may be downloaded. Treating an A2A
  runtime endpoint as a locator would change its meaning.

## Assumptions

- Operators know which agents and web-authentication schemes their deployment is
  prepared to expose.
- A bounded static catalog is sufficient for the first self-hosted gateway. Dynamic
  registration and search can be added without changing card meaning.
- One fixed extended card per publication is useful before caller-specific card
  shaping exists.
- An explicit operator-selected OASF taxonomy mapping is preferable to an automatic
  but potentially false capability claim.

## Decision drivers

- Prevent unauthenticated enumeration of private agents, tenants, skills, and routes.
- Keep generated A2A wire values outside authorization and configuration authority.
- Give self-hosters a complete direct and catalog-based discovery path.
- Make public exposure an explicit deployment decision.
- Preserve exact A2A interface, security, capability, and skill semantics.
- Avoid treating a lossy OASF projection as the source of A2A behavior.
- Keep every file, collection, string, and generated artifact bounded before
  allocation or publication.
- Leave web authentication pluggable without letting an A2A caller select Konclave
  authority.

## Decision

### Compile one canonical agent publication

Konclave defines a versioned strict-JSON publication source. Compilation produces one
validated publication identified by a canonical deployment-owned agent identifier.
The compiler, not generated wire DTOs, establishes:

- bounded name, description, version, interfaces, skills, tags, and security
  declarations;
- the exact A2A 1.0 HTTP+JSON and `text/plain` profile;
- explicit false values for unsupported streaming and push notification behavior;
- whether a fixed extended card exists;
- whether the well-known public card is enabled; and
- whether an authenticated OASF projection is enabled.

The publication source contains no web credentials, Konclave profile alias,
`DeviceId`, conversation identifier, collaboration policy, relay principal, or
local-service evidence. Interface tenants remain deployment-owned routing values and
never become authentication material.

Generated public and extended cards share the same identity, version, interfaces,
security requirements, and supported protocol profile. The public card contains only
public skills. When extended skills exist, the public card advertises
`extended_agent_card = true`, and the extended card contains the public skills plus
the additional authenticated skills. Skill identifiers are unique across the complete
publication.

The initial publication profile supports one bounded HTTP Bearer or mutual-TLS
security declaration. Production publications require one of those schemes.
Loopback-development publications may explicitly use no web authentication. This
describes the gateway's web boundary; it does not authorize any Konclave action.

Ancillary provider, documentation, icon, arbitrary extension, arbitrary metadata,
and signature fields remain unsupported in the initial compiler. They are omitted
rather than accepted without complete bounds and trust semantics.

### Make public discovery opt-in and non-enumerating

The self-hosted default exposes no public Agent Card. A deployment must explicitly
enable the well-known card for one publication before an unauthenticated exact lookup
returns it.

There is no unauthenticated list, search, fallback scan, DNS crawl, or tenant probe.
A missing publication and a private publication have the same public outcome.
Enabling the well-known card does not enable catalog enumeration.

This is an explicit private-discovery profile rather than a claim that a disabled
well-known endpoint provides standard public discovery. A2A clients use direct
configuration or an authenticated catalog when public discovery is disabled.

### Authorize private, extended, and catalog operations before lookup

The public discovery library accepts a deployment-provided authorizer. It passes only
the requested action and bounded agent identifier; credentials and raw web identity
remain at the gateway boundary.

Authorization is required before:

- resolving a private base card;
- resolving an extended card;
- listing catalog identifiers; or
- generating an OASF projection.

Denial and authorizer failure never fall through to another card, catalog, or public
surface. Authorization executes before an exact private lookup so an unauthenticated
or unauthorized caller cannot distinguish an absent agent from a private one through
library outcomes.

An authenticated catalog is still not protocol authority. It selects one compiled
publication. The mapped Konclave conversation and target remain separate deployment
configuration owned by the later gateway and bridge.

### Provide direct configuration and an explicit file catalog

A caller may compile one explicitly selected publication source directly without a
catalog or network fetch. This is the primary private configuration path.

The self-hosted file catalog:

- is selected by an explicit descriptor path;
- never scans a directory;
- lists every publication source by exact canonical agent identifier;
- accepts only portable relative regular-file paths beneath the descriptor's physical
  parent;
- opens sources through a pinned directory capability, rejects linked final files and
  root-escaping links, and rejects traversal, rooted paths, duplicate identifiers,
  and duplicate source paths;
- eagerly compiles every bounded source before the catalog becomes available; and
- returns identifiers in canonical lexical order.

Generic bounded regular-file, strict-JSON, and bounded-array behavior is shared with
other configuration-document consumers rather than copied into A2A discovery.

### Treat OASF as an authenticated generated projection

OASF 1.1.0 is an optional read-only projection from the compiled A2A publication. It
never supplies an interface, tenant, security requirement, capability, or Konclave
route.

An operator enabling OASF provides:

- bounded author strings;
- one explicit creation timestamp; and
- one or more explicitly selected OASF 1.1.0 taxonomy skill names from the supported
  projection profile.

Konclave does not infer taxonomy membership from free-form A2A skill text. The
projection embeds the complete generated A2A card as the JSON payload of the OASF
`a2a` module's artifact descriptor. The descriptor's size and SHA-256 digest cover the
exact deterministic compact JSON bytes. Runtime A2A endpoints are not emitted as
OASF locators.

The implementation validates the bounded structural subset it owns and records exact
OASF release provenance. It does not claim normative full-record validation without
the OASF server and complete taxonomy. OASF conformance evidence belongs to the later
interoperability workstream.

### Defer Agent Card signing

The initial publication compiler rejects and emits no Agent Card signatures. Signing
requires a dedicated gateway key, RFC 8785 canonicalization, verification-key
distribution, rotation, and revocation behavior. Device root keys and MLS keys remain
prohibited for this purpose.

Adding signed cards is compatible with the publication model but requires a separate
security-reviewed decision and implementation. Unsigned cards do not claim integrity
beyond the authenticated configuration or HTTPS boundary through which they are
obtained.

## Serious alternatives

### Publish every configured card and catalog entry

**Pros:** zero authentication integration and easier browser discovery.

**Cons:** exposes agent names, skills, tenants, endpoints, and deployment shape;
creates a nonstandard public enumeration API; and makes private self-hosting
impossible without a reverse-proxy workaround. Rejected.

### Use OASF as the canonical registry record

**Pros:** one catalog-oriented model and direct alignment with an emerging taxonomy.

**Cons:** OASF cannot natively preserve A2A authentication, interface, tenant, media,
and capability semantics. Reconstructing an Agent Card would require defaults or
private extensions to become protocol authority. Rejected.

### Automatically map free-form A2A skills to OASF taxonomy

**Pros:** no additional operator fields.

**Cons:** similarity is not taxonomy identity. An automatic guess can publish a false
capability claim and cannot be validated offline against the complete evolving
taxonomy. Rejected.

### Accept arbitrary Agent Card and OASF JSON files

**Pros:** maximum schema flexibility and minimal source compiler code.

**Cons:** generated DTOs and generic JSON do not enforce the initial profile, bounds,
visibility, security relationship, extended-card compatibility, or deterministic
projection. Rejected.

### Make private discovery managed-only

**Pros:** fewer public catalog and authorization abstractions.

**Cons:** withholds a client-visible capability from self-hosters and makes migration
between self-hosted and managed deployments change discovery semantics. Rejected.

### Sign Agent Cards in the initial discovery implementation

**Pros:** portable integrity independent of one HTTPS connection.

**Cons:** adds a new long-lived signing-key and revocation system before the gateway
has a complete credential lifecycle. A partial implementation would encourage false
trust. Deferred.

## Consequences

### Positive

- Self-hosted deployments can remain completely private without losing direct or
  catalog discovery.
- Public exposure is explicit, bounded, and non-enumerating.
- Extended cards and catalogs compose with any deployment web-identity system.
- A2A remains the exact runtime contract while OASF adds an optional catalog view.
- OASF taxonomy claims require deliberate operator input.
- File and collection bounds are shared and enforced before publication.
- The same publication and authorization semantics can back a managed registry.

### Negative

- A disabled well-known endpoint requires direct configuration or authenticated
  catalog integration.
- The initial authentication profile supports fewer schemes than A2A can represent.
- Static catalogs require restart or explicit reload after configuration changes.
- OASF publication requires authors, creation time, and taxonomy choices beyond the
  A2A card.
- Full OASF validation remains an external conformance activity.
- Unsigned cards rely on configuration provenance and HTTPS authentication.

### Neutral

- Public and extended cards may share one endpoint and authentication scheme without
  sharing visibility.
- The catalog API remains Konclave-specific because A2A defines no standard registry
  API.
- Managed deployments may replace file storage and authorization internals without
  changing publication meaning.
- Card signing, dynamic registration, registry search, and caller-specific extended
  cards remain compatible future additions.

## Confirmation

Continued compliance requires:

- strict source and catalog decoding with pre-allocation byte and item bounds;
- tests proving public lookup cannot distinguish private from missing publications;
- tests proving every private, extended, list, and OASF operation calls authorization
  before lookup or projection;
- production rejection of unauthenticated publications and loopback-only development
  exceptions;
- exact public/extended identity, interface, security, and skill-union tests;
- path traversal, rooted path, linked-file escape, duplicate identifier, and duplicate
  source rejection;
- deterministic card and OASF artifact bytes, size, and digest vectors;
- tests proving OASF taxonomy values come only from explicit supported mappings;
- checks that no OASF locator is generated for an A2A runtime endpoint;
- documentation that OASF projection is lossy and not normative full-record
  validation;
- specialized security review before delivery; and
- the same semantic suite against managed discovery before parity is claimed.

## References

- [ADR 0013](adr-0013-a2a-edge-interoperability.md) establishes A2A as an edge
  binding and keeps public self-hosting complete.
- [A2A compatibility contract](../protocol/a2a-compatibility.md) pins the normative
  A2A 1.0.1 wire source and initial profile.
- [A2A agent discovery](https://a2a-protocol.org/latest/topics/agent-discovery/)
  defines well-known, curated-registry, and direct-configuration strategies.
- [A2A specification](https://a2a-protocol.org/latest/specification/) defines
  authenticated extended cards, tenant behavior, web security schemes, and optional
  JWS signatures.
- [OASF v1.1.0](https://github.com/agntcy/oasf/tree/v1.1.0) defines the pinned record,
  taxonomy, descriptor, and A2A module shapes used by the optional projection.
