# Architecture decisions

Architecture Decision Records preserve significant decisions that future contributors
must understand without reconstructing issue, pull-request, or conversation history.

## Accepted records

- [ADR 0001: Adopt MLS 1.0 with separate Konclave identity, delivery, and wire contracts](../adr/adr-0001-protocol-trust-and-e2ee.md)
- [ADR 0002: Seal local secrets with explicit platform or operator key custody](../adr/adr-0002-sealed-local-secret-custody.md)
- [ADR 0003: Keep relay authentication deployment-provided with a hashed bearer-token adapter](../adr/adr-0003-relay-transport-authentication.md)
- [ADR 0004: Use locked split-schema profile storage with sealed crash journals](../adr/adr-0004-daemon-profile-journal.md)
- [ADR 0005: Separate harness delivery from the daemon through an outbound local adapter channel](../adr/adr-0005-harness-neutral-adapter-boundary.md)

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
