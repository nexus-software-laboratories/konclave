---
title: Keep recipe composition in explicitly selected external providers
status: Accepted
date: 2026-09-20
authors:
  - Konclave maintainers
tags:
  - architecture
  - composition
  - security
supersedes: []
superseded_by: []
---

# Keep recipe composition in explicitly selected external providers

## Context and scope

Konclave is secure, high-performance end-to-end encrypted messaging for software
agents, not a workflow, review, or memory engine. Applications may compose its
existing messaging APIs, but their task semantics must not become core protocol
opcodes, role names, or automatic response authority.

This decision establishes a pure, bounded definition boundary for external recipes
and the constraints on an optional external consumer. It does not add a provider
registry, discovery service, dynamic loader, daemon workflow operation, or run-state
persistence.
It preserves ADR 0001's cryptographic boundary and ADR 0012's deterministic
separation between policy, requests, and terminal replies.

## Verified facts and assumptions

- ADR 0001 assigns MLS protection and key custody to the trusted local endpoint.
  The threat model treats extensions and peer content as untrusted inputs.
- ADR 0012 permits only one correlated reply during an automatic response turn;
  that turn cannot call external tools or initiate a new directed request.
- The host extension's client API exposes existing service connection, command,
  tool, policy-gate, and delivery contracts. Composition does not require a new
  messaging protocol.
- The source-independent definition codec requires no service, network, filesystem
  or model dependency.
- The proposal assumes an operator explicitly installs and locally selects an
  external provider. Provider availability and implementation integrity cannot be
  proved by a recipe's content digest.

## Decision drivers

- Keep messaging fast, bounded, and independent of task-specific orchestration.
- Select exact immutable data without confusing identity with authorization.
- Preserve original-client-to-agent E2EE and authenticated response attribution.
- Prevent recipe data from becoming code, policy guidance, or local authority.
- Reject malformed input without recursive processing or sensitive diagnostics.

## Decision

### External ownership and explicit local selection

An explicitly installed external provider owns configuration semantics, task
composition, resource limits, and its finite coordinator. A recipe is data only.
Konclave never interprets or executes its configuration and never promotes it to
policy guidance. Configuration may contain provider-specific text or serialized
data; braces inside that string are not a Konclave language.

Provider identifiers are inert lookup keys, not package names, module specifiers,
paths, URLs, or instructions to download code. A later adapter must resolve only
explicitly installed, locally selected providers. Unknown or unavailable providers
fail visibly, without remote code loading, implicit installation, or fallback.

The codec accepts a syntactically valid unknown identifier because it performs no
lookup. Successful decoding is not provider resolution, approval, or execution.
The name is display metadata; exact definition selection uses the digest.

### Exact immutable definition format

The structured input has exactly three own enumerable string data properties:
`name`, `provider`, and `configuration`. Ordinary and null-prototype records are
accepted. Accessors, proxies, inherited fields, non-data objects, extra properties,
and symbol properties are rejected without executing caller hooks.

| Field | Contract |
| --- | --- |
| `name` | 1-64 ASCII characters; lowercase alphanumeric segments separated by single hyphens |
| `provider` | 1-128 ASCII characters; lowercase alphanumeric segments separated by single hyphens, underscores, or dots |
| `configuration` | Opaque Unicode scalar text, including empty text, at most 48 KiB when UTF-8 encoded |

No spelling, case, or Unicode normalization occurs. Unpaired UTF-16 surrogates are
rejected rather than replaced. Both UTF-8 and JSON escaping expansion are measured
before allocating the complete encoded definition.

The canonical representation is UTF-8 without a byte-order mark, containing one
JSON object in the fixed order `name`, `provider`, `configuration`, without optional
whitespace. Strings use standard ECMAScript `JSON.stringify` escaping; non-ASCII
scalar values remain UTF-8. The complete encoded definition is at most 64 KiB.
This is a deliberately narrow flat format, not a general JSON canonicalization
standard, policy language, or new application wire protocol.

Definition identity is lowercase hexadecimal SHA-256 of:

```text
UTF-8("konclave.recipe-definition.v1") || 0x00 || canonical-definition-bytes
```

The domain label separates this exact definition format from other hash uses; no
additional root version field is permitted. The prototype evolves in place until
a released compatibility obligation exists. A changed published definition requires
new exact selection rather than silent reinterpretation. A digest is an identity
check, not a signature or authorization.
An expected digest must come from an independently approved exact selection, not be
trusted merely because it accompanies untrusted bytes.

`createRecipeDefinition(unknown)` returns a frozen object containing the three
validated strings, `canonicalJson`, and `digest`. Canonical JSON and digest are
immutable strings, never shared mutable byte arrays.
`decodeRecipeDefinition(bytes, expectedDigest)` bounds and privately copies a
Uint8Array view before content validation, rejects shared memory, decodes fatal
UTF-8, rejects nested containers outside strings before JSON parsing, validates all
fields, and compares the exact canonical bytes and expected digest. Duplicate root
fields, alternate escapes, ordering, whitespace, and malformed encodings fail.
Native JSON parsing has no reviver; opaque configuration is never recursively
walked. Errors use a finite code set and contain no source or configuration bytes.

### Keep local authority separate

Installing, selecting, hashing, receiving, or decoding a recipe creates no grant or
policy binding. Existing exact-profile grants and locally activated deterministic
policy remain separate prerequisites. Provider configuration cannot broaden them.
No task-specific role names or workflow opcodes enter core messaging.

Composition must preserve the original client's authenticated messaging relationship
with each agent: the original client endpoint and agent endpoints retain MLS E2EE,
and the relay receives no plaintext. No coordinator service terminates encryption
on the client's behalf. A locally selected provider may necessarily see the plaintext
the client deliberately supplies; this is an endpoint trust decision, not protection
against a compromised provider. The codec performs no I/O or plaintext persistence.

### External runtime boundary

An adapter must pin an immutable approved run descriptor containing the exact
definition digest, client profile, participant conversation and device bindings,
input, and nonce. It must reject changed selections on restore, derive stable
per-step message identifiers, and correlate replies only by exact authenticated
conversation, request identifier, and expected sender. A finite external coordinator
owns sequencing, limits, cancellation, and terminal outcomes.

That adapter must not create conversations or grants, change policy, automatically persist
plaintext, or claim safe restart when the original approved descriptor is unavailable.
It will reuse existing client APIs rather than introducing daemon workflow state.
Existing automatic response turns remain one correlated reply, without tools or
new request authority. A reply can provide data to an already locally authorized
coordinator; its text cannot authorize another request.

Fan-out/fan-in and sequential handoff are external examples, not built-in workflow
modes. Their implementation cannot introduce task-specific branching into the daemon.

## Serious alternatives

| Alternative | Benefits | Costs and disposition |
| --- | --- | --- |
| Built-in workflow modes or a recipe DSL | Centralized behavior and discoverability | Adds task semantics, interpreter surface, and authority confusion to messaging; rejected |
| Executable recipes or dynamic provider loading | Flexible distribution | Converts untrusted selection into code execution and supply-chain exposure; rejected |
| Arbitrary nested JSON configuration | Convenient structured editing | Requires recursive validation and canonicalization without core-owned semantics; opaque string chosen |
| Mutable named definitions | Simple editing and lookup | Cannot prove which definition was approved or restored; exact digest selection chosen |
| Flat canonical JSON and external ownership | Small deterministic boundary and independent provider evolution | Strict bytes reject otherwise equivalent JSON; providers own their validation and compatibility |

## Consequences

The codec has no network, filesystem, process, clock, messaging, or authority effects.
Bounds apply independently to raw configuration and encoded bytes; control-heavy
configuration can exceed the encoded limit before reaching the raw limit.
Provider code and opaque semantics remain separate trust and compatibility risks.
Configuration is not safe to log merely because it passed this codec.
Definition identity does not pin provider implementation bytes or establish safe
restart. Those claims require independent adapter evidence.

## Confirmation

The focused test source covers exact bytes and an independently calculated digest,
immutability, UTF-8 and escaping bounds, invalid identifiers and shapes, accessors,
proxies, duplicate fields, alternate encodings, malformed UTF-8, lone surrogates,
deep malformed containers, shared storage, and digest mismatch.

Under the security-sensitive delivery contract, the foundation precedes a focused
GitHub-hosted format, typecheck, lint, and test gate. Integration remains blocked
until that gate is green on the exact head. Runtime confirmation must separately
prove exact descriptor restoration, stable request identity, authenticated reply
correlation, unavailable-provider rejection, existing policy/grant enforcement,
terminal automatic replies, no plaintext persistence, and the E2EE boundary.
This proposal claims none of that deferred runtime evidence.

## References

- [Public issue 286](https://github.com/nexus-software-laboratories/konclave/issues/286)
  and [public issue 287](https://github.com/nexus-software-laboratories/konclave/issues/287)
  track the external composition scope.
- [ADR 0001](adr-0001-protocol-trust-and-e2ee.md) establishes MLS and endpoint ownership.
- [ADR 0012](adr-0012-structured-directed-collaboration-requests.md) separates
  deterministic policy from request content and constrains automatic replies.
- [Threat model](../security/threat-model.md) defines endpoint trust and untrusted inputs.
- [Security-sensitive delivery](../development/security-sensitive-delivery.md)
  requires exact-head foundation evidence before integration.
- [Client API](../../extensions/Konclave.HostExtension/src/client-api.ts) shows
  existing integration seams, unchanged by this proposal.
- [Definition codec](../../extensions/Konclave.HostExtension/src/recipes/definition.ts)
  owns the exact format and finite validation errors.
- [Focused tests](../../extensions/Konclave.HostExtension/tests/recipe-definition.test.ts)
  specify the foundation invariants without claiming execution.
- [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259) defines JSON and its interoperability
  concerns; this proposal narrows accepted representations.
- [ECMAScript JSON.stringify](https://tc39.es/ecma262/#sec-json.stringify) defines
  the string escaping used for the canonical representation.
- [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420) defines MLS, not workflow execution.
