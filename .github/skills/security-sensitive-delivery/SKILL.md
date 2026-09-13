---
name: security-sensitive-delivery
description: >
  Plan and deliver a new crate or security-sensitive state machine through a bounded
  foundation commit, focused tests, and an exact-head GitHub-hosted component gate
  before daemon, adapter, client, packaging, or product integration begins. Use for
  authorization, identity, cryptographic custody, parsing, persistence, replay,
  cancellation, policy, membership, and similarly high-risk state transitions.
---

# Deliver a security-sensitive component

Use this procedure before integration code is written. The canonical rationale and
evidence rules are in
[`docs/development/security-sensitive-delivery.md`](../../../docs/development/security-sensitive-delivery.md).

## 1. Establish the boundary

Identify the new crate or state machine, its owned invariants, finite errors or
states, and the integrations explicitly deferred. Check accepted ADRs and the threat
model before selecting the boundary.

Stop if the component cannot be tested independently from its daemon, adapter,
client, network, filesystem, or package integration. Extract the decision boundary
first.

## 2. Plan dependent delivery units

Record these ordered units:

1. **Foundation** — manifest, owned source, pure decision functions, and focused
   tests in one bounded commit.
2. **Focused gate** — a GitHub-hosted component workflow and
   `.github/genesis-delivery.json` registration in the immediately following commit.
3. **Integration** — daemon, adapter, client, packaging, and UX commits, blocked on
   exact-head focused evidence.
4. **Full validation** — workspace, platform, package, and acceptance matrices after
   integration is complete.

Do not hide integration inside the foundation commit.

## 3. Build direct deterministic tests

Keep error classifiers and state transitions pure. Use table-driven tests to cover
every finite category, including unknown values, terminal states, and operational
failures. Add boundary tests proving real SQLite, transport, parser, or filesystem
errors reach those pure decisions.

## 4. Add the focused hosted workflow

The workflow must:

- use an explicit GitHub-hosted runner;
- run the exact component format, tests, and lint commands;
- publish a stable component-specific check;
- run while the pull request is draft;
- cancel superseded revisions; and
- fail closed when relevance cannot be determined.

Classify it as a merge gate with draft behavior `full` in
`.github/genesis-delivery.json`.

## 5. Observe the foundation evidence

Push the foundation and focused-gate commits to a draft pull request. Record the exact
head SHA and inspect the actual check commands and result. Do not claim the component
is tested because an application built, a package was assembled, or another
conformance workflow passed.

Do not begin integration work until the focused component check is green on that
exact head.

## 6. Integrate and revalidate

Add integration in reviewable commits. Each component change must rerun the focused
gate. Run complete CI, cross-platform, package, and acceptance matrices only after
the focused check is green.

When a broad matrix exposes behavior omitted by the focused gate, stop integration
and add that behavior to the focused tests or workflow before continuing.

## 7. Report

State:

- the foundation and focused-gate commit identifiers;
- the exact focused check and head SHA that passed before integration;
- integration commits and deferred boundaries;
- commands and checks that actually ran;
- failures and their disposition; and
- full validation still pending or completed.
