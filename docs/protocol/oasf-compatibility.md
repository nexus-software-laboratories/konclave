# OASF compatibility contract

This document is the canonical owner of Konclave's optional Open Agentic Schema
Framework projection provenance, supported subset, and conformance limits. ADR 0015
defines why OASF remains a generated catalog view rather than A2A protocol authority.

## Pinned source

The initial projection targets Apache-2.0 OASF release `v1.1.0`:

- annotated tag object: `e27d175cc33b51c249a0813066d70a9706adc6a7`;
- underlying commit: `f510be0d4b5878ac8f86c64ffd6cd7132733c03e`;
- tree: `87b48578b28c8e50d6b661228656ec66ec347c46`;
- license: `https://github.com/agntcy/oasf/blob/v1.1.0/LICENSE.md`;
- record definition blob: `2a4f9251e8bd3f3e248cedeabf68b6d7e846f867`;
- descriptor definition blob: `db10019993526cea3441cc129742686ad02184a5`;
- A2A module definition blob: `d01e47676a28314dc90512b56d63cdcac3415df2`;
- base skill definition blob: `87344cd60881bbb9ed1166140acd9077d733698b`;
- dictionary blob: `c206ee81d5e974dcf4681f3db26233c94373992f`;
- version definition blob: `fabbd9ad140dacae3ad4eb0cf6708c0b7b16b95e`.

These are upstream Git object identities, not content SHA-256 values. Konclave does
not vendor or reinterpret the complete OASF taxonomy in this workstream.

## Supported projection

One authenticated projection contains:

- the A2A card name, description, and version;
- operator-supplied bounded authors and canonical UTC creation time;
- explicitly selected supported OASF taxonomy skills;
- OASF schema version `1.1.0`; and
- one `a2a` module with the deterministic Agent Card JSON in
  `artifact.json`.

The artifact descriptor records media type `application/json`, exact byte size, and a
`sha256:` digest over the embedded deterministic compact JSON. The A2A card remains
the complete runtime source for interfaces, tenant routing, authentication,
capabilities, media modes, and free-form skills.

The initial supported OASF taxonomy allowlist contains only
`language_generation`, whose upstream class exists in the pinned release. Adding a
taxonomy value requires verified pinned-release evidence and tests. Konclave never
maps a free-form A2A skill to an OASF class by name similarity.

## Deliberate exclusions

Konclave does not:

- treat OASF as input to Agent Card generation or Konclave routing;
- emit A2A runtime endpoints as OASF locators, because locators describe downloadable
  artifacts;
- use deprecated inline `a2a_data.card_data`;
- emit arbitrary annotations or private extension fields;
- contact the hosted OASF schema service at runtime;
- require an external registry for self-hosting; or
- claim that the generated record passed normative full OASF validation.

The OASF repository's metaschemas validate schema-definition files. Normative record
validation is assembled by the OASF server from the complete definitions and
taxonomy. Later conformance work may run that Apache-licensed server against generated
fixtures, but the gateway remains functional without it.

## Security and visibility

OASF projection is disabled unless the publication source explicitly configures it.
Retrieval requires the same deployment authorization boundary as private and extended
Agent Cards. The projection embeds no credentials, Konclave profile alias, device,
conversation, policy, relay principal, or local-service evidence.

Because the embedded card can contain authenticated extended skills, there is no
unauthenticated OASF catalog or fallback projection.
