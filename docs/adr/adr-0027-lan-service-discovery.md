---
title: Retain explicit service trust and defer automatic LAN discovery
status: Accepted
date: 2026-09-20
authors:
  - Konclave maintainers
tags:
  - discovery
  - dns-sd
  - mdns
  - architecture
  - security
supersedes: []
superseded_by: []
---

# Retain explicit service trust and defer automatic LAN discovery

## Context and scope

DNS-SD and mDNS could help an operator locate a self-hosted relay or A2A gateway
without copying a host and port. That convenience must be assessed separately from
agent capabilities, endpoint authentication, MLS membership and local authority.

This decision compares explicit configuration, unicast DNS-SD, and opt-in multicast
discovery. It does not change encrypted message transport or conclude that UDP
cannot carry encrypted payloads.

**Decision: no-go for a new LAN discovery implementation or network prototype in
the current product scope.** Retain explicit service setup, ordinary DNS and the
existing authenticated A2A discovery surfaces. Reconsider a bounded locator
experiment only when a concrete operator workflow and independent trust bootstrap
demonstrate a gap that those mechanisms do not cover.

No accepted ADR is superseded. In particular, agents remain outbound-only, the
trusted daemon remains on local IPC, and the relay remains the durable sequencer.

## Verified facts

- [RFC 6763](https://www.rfc-editor.org/rfc/rfc6763.html) defines DNS-SD service
  enumeration and resolution using PTR, SRV and TXT records over unicast DNS or mDNS.
  The records describe service location, not application permission or native
  identity. Sections 4-6 describe the record model; section 15 addresses DNSSEC and
  secure publication.
- [RFC 6762](https://www.rfc-editor.org/rfc/rfc6762.html) describes link-local mDNS,
  interface and responder coexistence, and cooperative conflict resolution. Its
  security discussion recognizes spoofing and the need for independently
  authenticated application communication.
- The [A2A discovery guidance](https://a2a-protocol.org/latest/topics/agent-discovery/)
  defines Agent Card discovery strategies but does not prescribe a registry API or
  an A2A multicast profile. The repository pins its supported A2A contract separately.
- The [installation workflow](../distribution/installation.md) configures a relay
  endpoint once. Later profiles enroll through the protected installation
  configuration; routine pairing does not require discovering each peer's network
  address.
- [Encrypted rendezvous](adr-0023-encrypted-pairing-rendezvous.md),
  [short-code verification](adr-0024-opaque-short-code-mutual-verification.md), and
  [trusted aliases](adr-0025-trusted-device-alias-bootstrap.md) already address
  recurring peer connection without LAN advertisements.
- [ADR 0015](adr-0015-private-a2a-agent-discovery.md) keeps Agent Cards and catalog
  lookup private by default. Authenticated discovery can describe an agent without
  advertising its identity, skills or conversation relationships to a local network.
- [ADR 0008](adr-0008-shared-local-service.md) keeps the key-holding daemon on
  owner-restricted authenticated IPC. Process separation alone does not isolate an
  untrusted same-account helper under `AccountTrusted`.
- [RelayEndpoint](../../crates/Konclave.ClientLibrary/src/endpoint.rs) validates
  production HTTPS endpoint shape. [ProtectedHttp](../../crates/Konclave.ProtectedHttp/src/lib.rs)
  disables redirects and ambient proxies. Neither establishes that an
  advertisement-selected hostname belongs to the intended operator.
- Setup binds credentials to an explicitly selected endpoint. Existing relay
  migration is an explicit journaled operation, not discovery-driven failover.
- [ADR 0001](adr-0001-protocol-trust-and-e2ee.md) requires durable ordering,
  application replay protection and a non-equivocating relay sequencer for
  membership epochs. A multicast socket alone supplies none of those guarantees.

These are code and standards findings. No network discovery or performance
experiment was executed as evidence for this decision.

## Assumptions and unresolved evidence

Some installations may frequently change service location or operate without
managed DNS. Address-entry reduction could be valuable in that environment, but
no specific supported workflow, measured setup baseline, or repeated discovery
requirement currently establishes that benefit.

An isolated candidate-only experiment is technically feasible and need not receive
real credentials. Its existence would not establish safe production trust
bootstrap, useful cross-platform resolver behavior, acceptable presence disclosure,
or a messaging-performance improvement.

## Decision drivers

- Keep Konclave focused on secure, performant messaging rather than speculative
  network infrastructure.
- Solve demonstrated recurring integration problems before one-time setup friction.
- Avoid new presence disclosure and network parser/listener responsibilities without
  a concrete deployment requirement.
- Preserve existing endpoint-bound custody, explicit pairing and A2A semantics.
- Prefer deployment-owned DNS and authenticated catalogs where they solve location
  and capability lookup already.

## Decision

### Separate location, description, identity and authority

| Surface | Meaning |
|---|---|
| DNS or discovery hint | A claim that a service may be reachable at a host and port |
| A2A Agent Card | Declared interfaces, capabilities, skills and authentication requirements |
| Verified endpoint | A connection checked against an independently approved origin and trust policy |
| Native membership | Root-verified identity and authenticated MLS enrollment decisions |
| Local authority | Exact-profile grants and locally effective permissions |

None substitutes for the next. A valid certificate for an attacker-selected name
does not establish that it is the intended service. A signed or authenticated card
does not grant membership, and a cached advertisement does not prove a live agent.

### Prefer the existing paths

Keep explicit setup and ordinary DNS as the default location mechanism. Operators
may already place a configured relay on a LAN or update its DNS addresses without
introducing a discovery protocol. A stable approved HTTPS origin preserves the
existing endpoint and credential binding; a changed endpoint still requires
intentional setup or migration.

Use the existing private A2A catalog for capability discovery. Do not create a public
participant roster, broadcast Agent Cards, or introduce a proprietary registry
protocol under an A2A label.

Protected-required A2A continues to select the native Konclave handoff from ADR 0018.
Neither a discovery result nor TLS permits a plaintext fallback.

### Defer the additional discovery surface

A meaningful safe prototype would require more than enumerating multicast replies:
bounded record parsing, candidate provenance, expiry and ambiguity handling,
interface selection, cancellation, packet/resource budgets, independent endpoint
verification and a genuinely isolated network fixture.

That surface can answer a narrow location hypothesis, but it cannot eliminate the
independent origin/trust selection needed for an unknown first installation. The
normal installed-agent workflow already avoids repeated peer-address entry.
Without a concrete gap, creating and maintaining that additional surface is not
justified by the current evidence.

This is a scope/value decision, not a claim that opt-in mDNS cannot be secure enough
for an explicitly consenting deployment. No new parser, advertiser, listener,
resolver dependency, persistent directory or prototype service is approved.

### Keep transport optimization separate

UDP can carry MLS ciphertext. Multicast can reduce online one-to-many fan-out cost
on a suitable link. Neither observation proves lower end-to-end latency or preserves
offline replay, acknowledgment, congestion control and membership sequencing.

Any future QUIC or multicast transport investigation requires a measured transport
bottleneck and a separate compatibility decision. Service discovery is not its
justification.

## Serious alternatives

| Alternative | Advantages | Costs and disposition |
|---|---|---|
| Explicit setup and ordinary DNS | Already supported, clear origin provenance, no browse listener or advertisements, works across routed networks | Intentional initial configuration remains necessary. Retained. |
| Unicast DNS-SD | Reuses managed DNS and can locate changing ports across routed networks | Needs zone/publication policy, resolver behavior and separate endpoint trust. Reconsider for a demonstrated managed-DNS workflow; not a required core dependency. |
| Opt-in mDNS | Low configuration cost on an ad hoc link | Discloses services and browsing interest; spoofing, flooding, VLAN/VPN limitations and platform responder differences remain. Deferred. |
| Isolated candidate-only prototype now | Could measure enumeration and entry-work reduction without real authority | Adds parser, cache, interface and fixture maintenance before a recurring product gap is established. Not selected now. |
| Native multicast message delivery | Potentially efficient online LAN fan-out | Requires separate durability, replay, membership sequencing and congestion semantics. Outside this decision. |

## Consequences

No new network surface or metadata disclosure is added. Existing setup, pairing,
catalog, relay and E2EE behavior remain unchanged. The proposed convenience remains
unmeasured rather than being represented as a delivered feature or performance gain.

Self-hosters retain normal DNS and explicit configuration options. This decision
does not require public discovery or prevent deployment tools from providing an
operator-approved endpoint through existing interfaces.

## Confirmation and reconsideration

The conditional prototype is not planned under this decision. Reconsideration must
provide:

- a concrete recurring operator workflow and its explicit-setup baseline;
- an independently provisioned expected origin, certificate/trust lifecycle and
  endpoint selection policy;
- explicit consent for service-presence and query disclosure;
- an enforceable placement outside the daemon and real authority stores, preserving
  outbound-only agent operation;
- selected-interface/zone rules without automatic VPN participation, reflection,
  network scans or fallback;
- bounded parsing, records, candidates, packet bytes, retries, expiry and cancellation;
- negative cases for spoofing, stale/conflicting records, rebinding, malformed data,
  untrusted certificates and forbidden destinations; and
- hosted isolated evidence of useful entry-work reduction and resource impact,
  without a messaging-speed claim inferred from discovery.

A later accepted go must specify its exact boundary before a foundation is built.
The focused security-sensitive delivery gate must pass before network integration.
Prototype success alone would not authorize installation or production rollout.

## References

- [ADR 0001](adr-0001-protocol-trust-and-e2ee.md) owns MLS, durability and sequencer trust.
- [ADR 0008](adr-0008-shared-local-service.md) owns the local service boundary.
- [ADR 0015](adr-0015-private-a2a-agent-discovery.md) owns private A2A discovery.
- [ADR 0018](adr-0018-fail-closed-protected-a2a-handoff.md) owns protected transport selection.
- [Threat model](../security/threat-model.md) owns endpoint and metadata assumptions.
- [Relay enrollment](../protocol/relay-enrollment.md) owns endpoint-bound principal enrollment.
- [Security-sensitive delivery](../development/security-sensitive-delivery.md) owns
  foundation evidence before any future integration.
