# Architecture decisions

Architecture Decision Records preserve significant decisions that future contributors
must understand without reconstructing issue, pull-request, or conversation history.

## Accepted records

- [ADR 0001: Adopt MLS 1.0 with separate Konclave identity, delivery, and wire contracts](../adr/adr-0001-protocol-trust-and-e2ee.md)
- [ADR 0002: Seal local secrets with explicit platform or operator key custody](../adr/adr-0002-sealed-local-secret-custody.md)
- [ADR 0003: Keep relay authentication deployment-provided with a hashed bearer-token adapter](../adr/adr-0003-relay-transport-authentication.md)
- [ADR 0004: Use locked split-schema profile storage with sealed crash journals](../adr/adr-0004-daemon-profile-journal.md)
- [ADR 0006: Pair sessions through joiner-issued, self-authenticating capabilities](../adr/adr-0006-joiner-issued-pairing-capabilities.md)
- [ADR 0007: Provision per-profile relay principals through an outbound enrollment control plane](../adr/adr-0007-outbound-relay-principal-enrollment.md)
- [ADR 0008: Host logical agent profiles in one per-user local service](../adr/adr-0008-shared-local-service.md)
- [ADR 0009: Authorize local sessions through evidence-bound exact-profile grants](../adr/adr-0009-evidence-bound-session-grants.md)
- [ADR 0010: Automate two-command pairing only under AccountTrusted capability policy](../adr/adr-0010-account-trusted-two-command-pairing.md)
- [ADR 0012: Separate deterministic collaboration policy from directed request content](../adr/adr-0012-structured-directed-collaboration-requests.md)
- [ADR 0013: Expose A2A through an edge gateway without replacing Konclave transport](../adr/adr-0013-a2a-edge-interoperability.md)
- [ADR 0014: Persist A2A task projections behind a portable store contract](../adr/adr-0014-a2a-task-projection-store.md)

## Superseded records

- [ADR 0005: Separate harness delivery from the daemon through an outbound local adapter channel](../adr/adr-0005-harness-neutral-adapter-boundary.md) —
  superseded by ADR 0008 after the per-session process model proved unsuitable for
  workstations with many concurrent agent sessions.
- [ADR 0011: Exchange content-addressed collaboration policies with local activation](../adr/adr-0011-content-addressed-collaboration-policies.md) —
  superseded by ADR 0012 after free-form policy guidance proved unable to express
  deterministic request and terminal-response intent.

## When to write one

Use an ADR when a choice changes system structure, technology, integration boundaries,
important quality attributes, or another convention that is costly to reverse.

Routine implementation choices, direct bug fixes, and decisions already covered by an
accepted record do not need another ADR.

## What the record owns

One ADR explains:

- the facts, constraints, assumptions, and scope;
- the decision drivers;
- the chosen direction;
- serious alternatives and why they lost;
- positive, negative, and neutral consequences;
- how continued validity or compliance can be checked.

The record owns decision meaning, not task history. Issues and pull requests own work,
owners, rollout progress, and commits.

## Lifecycle

Proposed records may change during review. Once accepted, preserve their original
context, decision, rationale, and consequences.

A material change creates a new ADR and links both records through supersession
metadata. Rewriting an accepted ADR would erase the constraints future readers need to
understand the old decision.

## Evidence

Paths, symbols, packages, and links are locators. The ADR explains what each artifact
demonstrates and why it matters.

Essential reasoning stays in the record. External references are supplemental, not a
prerequisite for understanding the decision.
