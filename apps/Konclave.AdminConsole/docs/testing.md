# Testing strategy

This template uses Vitest and Testing Library to verify behavior from the user's
perspective while keeping the default feedback loop lightweight.

## Development loop

For new behavior:

1. Write one failing behavior test.
2. Implement the smallest passing change.
3. Refactor while the test stays green.

For unfamiliar code, capture current behavior with characterization tests before
changing it. A regression test should fail when the original defect is restored.

## Queries and interactions

Selectors should fail when user-facing semantics regress. For repeated or localized
controls, a stable test ID may identify the entity container, but the control inside
that scope is still selected semantically. Assert a translated accessible name
separately when localization itself is the behavior under test.

Use `userEvent` for real interactions. Assert loading, success, validation, empty, and
error states when the component can produce them.

## Unit versus browser execution

The default Vitest environment is the fast path for component logic and DOM behavior.
Real browser execution can catch layout, focus, CSS, and browser-API defects that a
simulated DOM cannot.

Browser Mode remains opt-in in this pilot because browser dependencies and startup add
real CI cost. The default scaffold adds zero browser packages, downloads, or browser
CI jobs. Promote it only after representative runtime, flake rate, and runner
requirements are measured. Deterministic accessibility and browser-quality gates are
separate rollout work.

## Stable tests

- Control time, randomness, network, and storage at explicit boundaries.
- Do not wait with arbitrary sleeps; wait for observable UI state.
- Restore mocks and global state between tests.
- Assert exact results and collection counts.
- Keep reusable test builders/helpers outside individual test cases.

## Mutation testing

Stryker can expose weak assertions in pure TypeScript logic, but it is not a default
dependency or required PR job yet; the default adds zero mutation packages and jobs.
Use focused report-only runs for meaningful changed logic, triage survivors, and
measure runtime before setting a blocking threshold.

Local work uses the smallest declared package script. Complete, browser, and mutation
evidence belongs to configured CI/PitCrew capacity.
