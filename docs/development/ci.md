# Continuous integration

This repository is public. Build, lint, test, and packaging jobs run on
operator-owned PitCrew runners; container validation runs on free GitHub-hosted
capacity so a required check never depends on private runner availability.

## Runner lanes

- `general-purpose` (PitCrew) runs Rust and Node builds, linting, tests, and
  daemon packaging checks.
- `automation-control` (PitCrew) runs validation planning and pull-request
  policy checks.
- `ubuntu-latest` (GitHub-hosted) runs the Community Relay OCI build and
  validation.

Named PitCrew profiles advertise `linux`, `x64`, and the profile label without
the broad `self-hosted` label. The default `general-purpose` profile retains
GitHub's default labels.

Validation is grouped per pull request rather than per branch. Under
`pull_request_target`, `github.ref` resolves to the base branch, so keying
concurrency on it alone places every open pull request in one group. GitHub keeps
only one pending run per group, so a third request cancels another pull request's
queued validation. Superseded revisions of the same pull request queue rather than
cancel, so a run already producing required checks finishes and reports.

## Fork boundary

PitCrew does not execute jobs or code from fork pull requests. Pull-request
workflows are defined by the default branch, and every PitCrew entry job checks
for an exact same-repository head before runner assignment. A maintainer must
reproduce an external contribution on a repository branch before validation.
This preserves the outbound-only self-hosted trust boundary.

Hosted container validation inherits the same boundary: it is scheduled by the
default branch through `pull_request_target` and gated on the same
same-repository head check, and it never checks out a fork head.

## OCI validation

Container validation builds one `linux/amd64` OCI archive for the Community
Relay and asserts its structure. The build backend differs by runner, but the
image contract and every archive assertion are shared in
`scripts/ci/container-image.lib.sh` so both backends validate identically.

Validation confirms the non-root runtime user, declared health check,
entrypoint presence in the final layers, and absence of Rust build tooling. It
does not run the image.

### Hosted backend

`scripts/ci/Validate-HostedContainerImage.sh` creates a run-scoped
`docker-container` buildx builder, exports an OCI archive without provenance or
SBOM attestations, and asserts the archive.

### Bounded local Docker validation

Container validation may run on a machine that holds unrelated Docker state, so
cleanup is exact rather than broad. Nothing prunes, matches wildcards, or
removes by age.

`scripts/ci/container-validation.lib.sh` derives a run identity that no
concurrent run can produce — the CI run and attempt numbers, or the process
identifier locally, plus random bytes — and every resource the run creates is
named from that identity and labelled `dev.konclave.validation.run`. That is
what makes two concurrent runs safe: neither can reuse the other's builder, and
neither can remove it.

Exporting to an OCI archive means no validation image enters the engine image
store at all, so the usual source of accumulation does not arise.

Cleanup asserts both halves of the contract and fails the job on either:

- nothing labelled for this run survived;
- nothing that existed in the pre-run baseline disappeared.

The second matters more than the first. A leak is recoverable; deleting a
developer's unrelated container is not.

`scripts/ci/Test-ContainerValidationCleanup.sh` proves this against a real
engine before anything is built. It creates a sentinel that must survive, a
second run's resources that must be left alone, and its own resources that must
be removed, then plants a deliberate leak to confirm the residue check actually
fails rather than passing silently. Reading the scripts cannot establish that,
because the failure mode is a filter that matches more than intended.

**One resource is deliberately not removed.** Bootstrapping a `docker-container`
builder pulls a BuildKit image into the engine. It is shared infrastructure
rather than validation output, and removing it would destroy a cache the machine
may be using for other work, so it is left in place. Every Konclave-owned image,
builder, container, network, and volume returns to baseline.

### Self-hosted BuildKit backend

`scripts/ci/Validate-RemoteContainerImage.sh` remains available for operators
who run this project's CI on a socketless image builder. It connects to a
rootless BuildKit service with a job-scoped mTLS client and additionally
asserts that BuildKit history and cache are empty afterwards. That backend
requires client-side secrets (`BUILDKIT_CLIENT_CA_PEM_B64`,
`BUILDKIT_CLIENT_CERT_PEM_B64`, `BUILDKIT_CLIENT_KEY_PEM_B64`) decoded beneath
`RUNNER_TEMP`.

`scripts/ci/Initialize-JobPrivatePaths.sh` and
`scripts/ci/Cleanup-JobPrivatePaths.sh` declare and remove job-private
directories for either backend and refuse any target outside `RUNNER_TEMP`.
`scripts/ci/Initialize-ImageBuilderPaths.sh` and
`scripts/ci/Cleanup-ImageBuilder.sh` are the self-hosted backend's named entry
points over those helpers.

Docker-based validation must not run on developer workstations.
