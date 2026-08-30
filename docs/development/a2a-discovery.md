# A2A agent discovery

This document is the canonical implementation contract for private-by-default A2A
Agent Card publication and the public self-hosted file catalog. ADR 0015 owns the
durable visibility, authorization, direct-configuration, OASF, and signing decisions.

## Crate boundaries

`Konclave.A2AContracts` owns the pinned A2A wire DTOs and validates:

- bounded protobuf and ProtoJSON Agent Cards;
- the exact A2A 1.0 `HTTP+JSON` and `text/plain` profile;
- canonical production or loopback-development interfaces;
- one optional HTTP Bearer or mutual-TLS security declaration;
- one matching top-level security requirement;
- bounded unique skills and tags;
- explicit absence of unsupported provider, URL, extension, example, metadata, and
  signature fields; and
- tenant-bound `GetExtendedAgentCard` requests.

`Konclave.BoundedDocuments` owns reusable bounded regular-file reads, strict
single-document JSON decoding, bounded sequence decoding, and confined explicit JSON
catalog paths. Collaboration-policy and A2A discovery code share these primitives.

`Konclave.A2ADiscovery` owns:

- strict publication-source compilation;
- generation of compatible public and extended Agent Cards;
- the direct single-publication configuration path;
- eager explicit file-catalog loading;
- private operation authorization;
- public exact lookup without enumeration; and
- optional deterministic OASF 1.1.0 projection.

Generated A2A DTOs do not become configuration authority. The compiler constructs
them from bounded project-owned source types and validates the result again through
`Konclave.A2AContracts`.

## Publication source

One source is at most 256 KiB and uses strict JSON:

```json
{
  "apiVersion": "konclave.dev/v1",
  "kind": "A2AAgentPublication",
  "metadata": {
    "name": "contract-agent"
  },
  "spec": {
    "publicWellKnown": false,
    "name": "Contract agent",
    "description": "Coordinates one bounded text contract request.",
    "version": "1.0.0",
    "interfaces": [
      {
        "url": "https://agent.example.com/a2a/v1",
        "tenant": "tenant-a"
      }
    ],
    "authentication": {
      "type": "bearer",
      "name": "bearer",
      "bearerFormat": "JWT"
    },
    "skills": [
      {
        "id": "contract-review",
        "name": "Contract review",
        "description": "Reviews one text contract and returns one response.",
        "tags": ["contracts", "text"]
      }
    ],
    "extendedSkills": [
      {
        "id": "private-contract-review",
        "name": "Private contract review",
        "description": "Reviews deployment-scoped contract details.",
        "tags": ["contracts", "private"]
      }
    ],
    "oasf": {
      "authors": ["Maintainers <maintainers@example.com>"],
      "createdAt": "2026-08-30T00:00:00Z",
      "skills": ["language_generation"]
    }
  }
}
```

The maintained source and catalog examples live under `a2a/examples/` and are
compiled by the discovery test suite.

Strict JSON rejects unknown fields, duplicate object keys at every nesting level, and
trailing documents before generated wire or authorization state exists.

`publicWellKnown` defaults to `false`. Production compilation requires one Bearer or
mutual-TLS declaration. Omitting authentication is accepted only in
loopback-development mode when every interface host is `localhost`, loopback IPv4, or
loopback IPv6.

The source contains web authentication descriptions, never credentials. The A2A
`tenant` is an opaque routing value and must be identical across every interface in
one publication. Conversation, device, profile, policy, and relay identifiers do not
appear in this source.

The public card contains `skills`. When `extendedSkills` is non-empty, it advertises
extended-card support and the authenticated card contains the ordered union of public
and extended skills. Skill identifiers and per-skill tags are unique.

## Visibility and authorization

`FileA2AAgentCatalog::public_card` performs one exact lookup and returns a card only
when `publicWellKnown` is true. Private and missing entries both return no public
result. The catalog exposes no unauthenticated list or search API.

Every private method invokes `A2ADiscoveryAuthorizer` before looking up an entry:

| Action | Protected result |
|---|---|
| `ReadPrivateCard` | Base card for authenticated direct or private discovery |
| `ReadExtendedCard` | Public and authenticated skill union |
| `ListCatalog` | Canonically sorted publication identifiers |
| `ReadOasfProjection` | Generated OASF record |

The request-bound authorizer captures web identity and deployment policy. Discovery
receives only the action and optional canonical publication identifier. `Deny` and
`Unavailable` are distinct terminal errors and never fall back to another discovery
surface.

## File catalog

The catalog descriptor is at most 64 KiB and contains at most 64 entries:

```json
{
  "schemaVersion": 1,
  "entries": [
    {
      "name": "contract-agent",
      "source": "agents/contract-agent.json"
    }
  ]
}
```

The catalog never scans. Sources must be portable relative `.json` paths beneath the
descriptor's physical parent. Rooted paths, traversal, hidden paths, backslashes,
symlinks, non-files, duplicate resolved source paths, duplicate identifiers, and
source-name mismatches fail catalog creation.

Every publication is compiled eagerly. A returned catalog therefore contains no
deferred source validation or partial entry set. Configuration changes require an
explicit reload or process restart.

## Bounds

| Value | Bound |
|---|---:|
| Encoded Agent Card | 256 KiB |
| Publication source | 256 KiB |
| Catalog descriptor | 64 KiB |
| Catalog entries | 64 |
| Interfaces per card | 4 |
| Skills per card | 32 |
| Tags per skill | 16 |
| Agent or skill name | 256 UTF-8 bytes |
| Agent or skill description | 4 KiB |
| Skill tag | 64 UTF-8 bytes |
| Agent version | 64 ASCII bytes |
| Bearer format hint | 64 ASCII bytes |
| OASF authors | 8 |
| OASF author | 256 UTF-8 bytes |
| OASF taxonomy skills | 8 |

The public and extended skill union must also fit the 32-skill card bound.

## OASF projection

The optional projection pins OASF schema version `1.1.0` at upstream commit
`f510be0d4b5878ac8f86c64ffd6cd7132733c03e`.

The initial projection accepts only the verified OASF taxonomy skill
`language_generation`. Konclave never derives that claim from A2A free-form text; the
operator selects it explicitly.

The generated record embeds the extended card when configured, otherwise the public
card, in the OASF `a2a` module's `artifact.json` field. `artifact.size` and its
`sha256:` digest cover the exact deterministic compact Agent Card JSON bytes. Runtime
A2A interfaces are not emitted as OASF locators.

The implementation validates only the bounded structural subset it generates. The
OASF project produces normative record validation through its server and complete
taxonomy rather than one standalone record JSON Schema. Konclave therefore does not
claim full OASF record conformance until the later conformance work runs the pinned
server validator.

## Verification

Focused suites cover:

- protobuf and ProtoJSON card decoding;
- interface, tenant, security, capability, media, skill, tag, duplicate, and size
  rejection;
- Bearer and mutual-TLS generation;
- production authentication and loopback-only exceptions;
- public versus private exact lookup;
- authorization-before-lookup for every private action;
- extended public/private skill composition;
- explicit no-scan catalog loading and path confinement;
- eager invalid-source, duplicate, and name-mismatch refusal;
- explicit OASF taxonomy selection;
- deterministic OASF bytes and embedded-card digest/size; and
- absence of OASF runtime-endpoint locators.
