# Security-sensitive component delivery

New crates and security-sensitive state machines require an early focused feedback
loop. Security-sensitive state includes authorization, identity, cryptographic
custody, wire parsing, persistence, replay, cancellation, policy, membership, and
other logic whose incorrect transition can broaden authority or lose durable state.

## Delivery contract

1. Create the crate or state machine and its focused tests in one bounded foundation
   commit. Do not mix daemon, adapter, client, packaging, or product integration into
   that commit.
2. Add a focused GitHub-hosted component workflow immediately. Register its stable
   check and draft behavior in `.github/genesis-delivery.json`.
3. Push the foundation to a draft pull request and require the focused check to pass
   on that exact head before beginning integration commits.
4. Keep error classification and state-transition decisions in pure functions with
   table-driven tests covering every finite input category and terminal outcome.
5. Claim only evidence that executed the relevant behavior. A build, package, or
   unrelated conformance check is not evidence that focused unit or integration tests
   passed.
6. Run complete workspace, cross-platform, packaging, and acceptance matrices only
   after the focused component gate is green.

## Commit and workflow order

The foundation commit contains the manifest, owned source, and focused tests. The next
commit adds the hosted component workflow and delivery metadata. The draft pull
request is then pushed and observed before integration begins.

The focused workflow:

- runs on an explicit GitHub-hosted runner;
- executes the component's exact format, test, and lint commands;
- has a stable, component-specific check name;
- runs for drafts so it can gate later integration work;
- cancels superseded revisions; and
- fails instead of returning a success-shaped no-op when relevant file discovery is
  unavailable.

Integration commits may connect the green component to daemons, adapters, clients,
packaging, or user-facing commands. Every later change to the component reruns the
focused gate.

## Pure decision boundaries

Error classifiers and state transitions must be independently callable without file,
database, network, clock, or process effects. Table-driven tests cover the complete
finite decision table, including unknown and operational failures. End-to-end tests
then prove that real boundaries reach those decisions; they do not replace the direct
tests.

## Evidence claims

| Claim | Required evidence |
| --- | --- |
| Component compiles | Exact component build or check command |
| Focused behavior passes | Exact component test command and check |
| Warning-free | Exact component Clippy or equivalent lint command |
| Cross-platform behavior | The named platform job that executed the tests |
| Packaged behavior | Extracted-package or clean-install acceptance |
| Full repository compatibility | Complete workspace and component merge gates |

If a workflow did not execute the relevant test, report it as unrun. Do not infer
coverage from a successful package build or another component's check.

## Failure handling

A focused failure blocks integration. Diagnose the first failing component boundary;
do not weaken the expected result, broaden accepted errors, or repeatedly rerun a
deterministic mismatch. When full CI discovers behavior the focused workflow omitted,
add that behavior to the focused gate before continuing integration.
