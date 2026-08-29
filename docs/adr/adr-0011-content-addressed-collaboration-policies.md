---
title: Exchange content-addressed collaboration policies with local activation
status: Superseded
date: 2026-08-27
authors:
  - Konclave maintainers
tags:
  - collaboration
  - policy
  - authorization
  - harnesses
supersedes: []
superseded_by:
  - adr-0012-structured-directed-collaboration-requests
---

# Exchange content-addressed collaboration policies with local activation

## Context and scope

Konclave authenticates collaborators and delivers their text inside an explicit
untrusted-content boundary. That boundary prevents an authenticated peer from
acquiring user, developer, permission, or tool authority merely by sending a message.
It also means that secure delivery alone cannot express a standing local instruction
to evaluate peer requests, reply, or perform bounded work.

The meaning of collaboration differs by user, repository, harness, and task.
Hardcoded modes such as `discuss` or `work` would assign product-defined semantics to
names that operators reasonably interpret differently. Free-form model guidance is
flexible but cannot by itself prove which actions, resources, approvals, or limits a
harness enforces.

This decision owns the durable separation between editable collaboration-policy
sources, immutable shared policy bundles, local activation, and effective
harness-specific enforcement. It does not select one hosted registry, user interface,
source syntax, general-purpose policy language, action catalog, or collaboration
workflow.

## Verified facts

- ADR 0009 grants a local harness session authority over one exact profile. It does
  not grant a remote conversation member authority over that harness.
- The threat model requires peer content to remain untrusted even after MLS
  authenticates its sender.
- Harnesses expose different lifecycle, tool, permission, and resource controls. A
  generic integration cannot claim a control that only a paved integration proves.
- Policy names and source paths are mutable labels. They cannot establish that two
  participants reviewed the same definition.
- Konclave already carries authenticated encrypted application content over outbound
  relay connections, so a bounded policy definition can be exchanged without a
  required hosted registry or inbound endpoint.
- ADR 0002 authenticates stored ciphertext but does not claim general rollback
  prevention for older valid records.

## Assumptions

- An operator may intentionally authorize an agent to evaluate authenticated peer
  requests and act within a locally chosen policy.
- Two participants may accept the same shared definition while retaining different
  local permissions, restrictions, and harness capabilities.
- Policy guidance may contain repository or task context and therefore requires the
  same plaintext, diagnostic, and persistence care as other local collaboration
  content.
- Optional collaboration duration, turn, token, and concurrency limits may be finite
  or explicitly unlimited. Protocol and storage safety bounds remain mandatory.

## Decision drivers

- Preserve the untrusted peer-content boundary while enabling genuine autonomous
  collaboration.
- Let operators define policy meaning outside compiled product modes.
- Prove when participants accepted the same definition.
- Prevent a peer, repository, or registry from activating authority locally.
- Keep the complete open-source path functional without a hosted service.
- Intersect requested behavior with controls the local harness actually proves.
- Make policy updates explicit, immutable, auditable, and restart safe.

## Decision

### Separate source, bundle, and binding

A collaboration-policy source is editable operator input. It may come from an
explicit user catalog, a repository proposal, a received bundle, or a configured
provider. Merely discovering or parsing a source grants no authority.

Konclave compiles a source and all explicitly selected dependencies and defaults into
one fully resolved, bounded canonical `CollaborationPolicyBundle`. The bundle contains
no source paths, mutable includes, executable code, or unresolved network references.
Its identity is a domain-separated SHA-256 digest of its canonical bytes. Names remain
display metadata; equality means digest equality.

A local `CollaborationPolicyBinding` is the authority to use one exact bundle for one
profile and conversation. Only a locally authorized operation creates or changes a
binding. A peer may propose a bundle, but cannot activate, broaden, or replace the
receiver's binding.

### Keep policies external and actions extensible

Collaboration behavior is not a closed mode enum. Policies use stable evaluator
primitives such as allow, deny, and require-local-approval over bounded namespaced
action and resource identifiers. Harness adapters register the identifiers and
evidence they can enforce. Unknown actions, resources, effects, or required evidence
fail closed.

Free-form guidance may explain semantic task scope to an agent. Guidance is not
reported as mechanically enforced unless a harness provides a corresponding
verifiable control.

### Exchange immutable bundles, not mutable references

Policy proposal and acceptance messages identify the canonical bundle digest. A
proposal carries the complete bounded bundle when the receiver does not already have
it. A registry may cache or distribute the same bytes, but registry availability is
not required and a registry reference never replaces digest verification.

Each participant independently acknowledges the base digest it accepted. Editing a
source creates a new bundle and digest. Existing bindings remain pinned until a new
locally authorized activation succeeds.

### Distinguish shared definition from effective authority

Accepting the same base bundle does not imply identical local authority. Each endpoint
computes:

```text
effective policy =
    accepted bundle
  intersection local user authority
  intersection harness-proven controls
  intersection local restrictions
```

An endpoint may make the result stricter but cannot silently make it broader. Peers
exchange only the bounded public projection needed to coordinate expectations. Local
paths, private configuration, credentials, and policy guidance are not disclosed
unless the accepted bundle intentionally contains them.

### Make semantic limits optional

Editable sources distinguish inherited limits, finite limits, and explicit unlimited
values. Compilation resolves inheritance before hashing the bundle. The canonical
bundle contains only finite or unlimited values, so every participant can identify
the exact proposed semantics.

Duration, turns, tokens, and collaboration concurrency are optional semantic limits.
Message, frame, parser, queue, journal, and storage bounds remain mandatory
availability controls and are not disabled by policy.

### Preserve truthful harness claims

Paved integrations expose evidence for controls they enforce. Unsupported and generic
harnesses receive the intersection they can prove. A requested rule that cannot be
enforced is denied or explicitly advisory; it is never silently treated as enforced.

## Serious alternatives

### Hardcode collaboration modes

**Pros:** small command surface and straightforward branching.

**Cons:** mode names acquire arbitrary product-defined meaning, composition becomes
combinatorial, and users cannot represent their own collaboration contract. Rejected.

### Treat free-form guidance as the complete policy

**Pros:** maximum authoring flexibility.

**Cons:** no deterministic action decision, resource boundary, approval requirement,
or enforceability claim. Guidance remains part of a policy but is not the enforcement
contract.

### Require identical effective policy on both endpoints

**Pros:** simple symmetry claim.

**Cons:** endpoints commonly have different repositories, permissions, and harness
controls. Rejected in favor of one shared base digest with independently restricted
effective policies.

### Require one hosted policy registry

**Pros:** centralized editing, discovery, and synchronization.

**Cons:** creates a network and product dependency for local and self-hosted
collaboration. A hosted registry remains a compatible provider, not the authority or
required transport.

### Execute a general-purpose policy language directly

**Pros:** broad existing language expressiveness.

**Cons:** interpreter lifecycle, resource bounding, sandboxing, dependency,
cross-language, and canonicalization concerns enter the trusted path. A future source
compiler may target the canonical bundle without changing this decision.

## Consequences

### Positive

- Operators define collaboration semantics without compiled preset modes.
- Digest equality proves that participants accepted the same base definition.
- Repository and peer content cannot grant local authority by discovery or transfer.
- Hosted, self-hosted, local, paved, and generic integrations share one bundle and
  binding model.
- Local restrictions and weaker harness evidence reduce authority truthfully.
- Unlimited collaboration remains expressible without weakening protocol safety
  bounds.

### Negative

- Canonical encoding, source compilation, bundle exchange, local binding, policy
  evaluation, and harness evidence add independent versioned surfaces.
- Participants must distinguish a matching base policy from differing effective
  enforcement.
- Policy updates require explicit proposal and acceptance rather than mutable
  references.

### Neutral

- Policy names remain useful human labels but carry no authority.
- General rollback prevention remains outside the initial sealed-storage guarantee.
- A hosted management product can improve editing and distribution without changing
  the open protocol.

## Confirmation

Continued compliance requires:

- exact cross-language canonical-bundle and digest fixtures;
- rejection of noncanonical ordering, duplicate identifiers, unknown effects,
  malformed names, oversized fields, unresolved references, and unsupported versions;
- tests proving same-name different-content policies have different digests;
- tests proving source edits do not change an active binding;
- proposal tests proving a peer cannot activate or broaden local authority;
- harness-evidence tests proving unsupported controls reduce or deny the effective
  policy;
- restart and tamper tests for sealed bundles and local bindings;
- optional-limit tests covering inheritance, finite values, and explicit unlimited
  values;
- a no-registry two-session acceptance exchanging a complete encrypted bundle; and
- specialized security review before policy exchange, persistence, or harness-driven
  activity is delivered.

## References

- [ADR 0002](adr-0002-sealed-local-secret-custody.md) defines authenticated local
  sealing and its explicit rollback limitation.
- [ADR 0004](adr-0004-daemon-profile-journal.md) defines profile locking, sealed
  persistence, and crash recovery.
- [ADR 0008](adr-0008-shared-local-service.md) keeps profile authority in one local
  service while harnesses remain thin clients.
- [ADR 0009](adr-0009-evidence-bound-session-grants.md) defines exact-profile local
  authorization and truthful harness evidence.
- [Threat model](../security/threat-model.md) keeps authenticated peer text outside
  local user, developer, permission, and tool authority.
- [Protocol compatibility contract](../protocol/compatibility.md) governs canonical
  wire evolution and hard bounds.
