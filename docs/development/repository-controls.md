# Repository controls

Short deterministic pull-request controls use the PitCrew
`automation-control` lane rather than the build-and-test runner queue:

- PR base validation;
- conventional PR title validation;
- review-policy evaluation.

All jobs are PitCrew-only. There is no GitHub-hosted fallback.

Pull-request workflows are loaded from the default branch with
`pull_request_target`. Every PitCrew entry job requires an exact same-repository
head before GitHub assigns a runner. Fork pull requests therefore skip all jobs,
including metadata-only controls, without reaching PitCrew.

External contributions must be reviewed as source and reproduced by a maintainer
on a branch in this repository before validation. The repository additionally
requires workflow approval for every external contributor, but approval is only
defense-in-depth and never authorizes fork code on self-hosted runners.

Third-party actions are pinned to immutable commits. Repository Actions
permissions allow only GitHub-owned actions plus the explicitly selected Rust
toolchain and cache actions, with read-only workflow tokens by default.

Runner labels isolate GitHub queue eligibility only. PitCrew owns physical capacity,
reservations, fairness, and host admission.

## Validation lifecycle

Draft pull requests use the repository's configured validation policy. Konclave
defaults to full PitCrew validation for drafts so the initial repository bootstrap
produces complete evidence before it is marked ready.

Delivery-capable templates default to pull-request-only merge-gate validation. They
may instead be scaffolded to rerun full validation whenever the default branch
advances. Post-merge deployments, documentation publication, and release workflows
remain separate under either policy and run only when their selected component owns
that behavior. The generated workflows are the executable record of the selected
policy.
