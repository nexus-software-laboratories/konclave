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

Superseding CI revisions queue instead of cancelling an active run, so a build
backend can complete its mandatory cleanup before shared state is reused.

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

`scripts/ci/Validate-HostedContainerImage.sh` creates a job-scoped
`docker-container` buildx builder, exports an OCI archive without provenance or
SBOM attestations, and asserts the archive.
`scripts/ci/Cleanup-HostedContainerImage.sh` removes the builder, its cache,
and the job-private archive directory unconditionally, so no Docker state
survives a job.

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

Docker-based validation must not run on developer workstations.
