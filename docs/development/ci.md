# Continuous integration

This repository is public. Build, lint, and test jobs run on operator-owned PitCrew
runners. Container and cross-platform release-package validation run on free
GitHub-hosted capacity so those required checks never depend on private runner
availability.

## Runner lanes

- `general-purpose` (PitCrew) runs Rust and Node builds, linting, tests, and
  daemon packaging checks.
- `automation-control` (PitCrew) runs validation planning and pull-request
  policy checks.
- `ubuntu-latest` (GitHub-hosted) runs the Community Relay OCI build and
  validation.
- `ubuntu-latest`, `windows-latest`, `macos-15`, and `macos-15-intel`
  (GitHub-hosted) build and exercise native unsigned release candidates.

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

The separate package-validation workflow uses `pull_request` and only
GitHub-hosted runners with read-only repository permissions. Fork code may execute
there because it cannot reach PitCrew, credentials, a registry, or a deployment
target.

## Native package validation

`.github/workflows/package-validation.yml` builds Linux x64, Windows x64, macOS
Apple-silicon, and macOS Intel binaries. Each lane packages the CLI, daemon,
standalone relay, platform service files, and built Copilot plugin according to
`distribution/release-artifacts.json`.

The package gate creates each native archive twice and requires byte-identical output,
extracts it outside the source tree, runs the packaged CLI, and requires `konclave
doctor` to recognize the packaged daemon and plugin. Candidates are uploaded as
transient unsigned workflow artifacts used only to transfer files between jobs; the
workflow does not publish a release.

After every native and container lane succeeds, `Release integrity` downloads the
candidates into one flat release set. It emits target-filtered Rust, npm-lock, and
container CycloneDX SBOMs; one deterministic SLSA provenance statement per executable
archive; and an exact SHA-256 manifest. The shipped `RELEASE.json` independently
defines every required archive and sidecar, so a partial download cannot redefine
itself as complete merely by omitting a checksum line. Negative tests mutate, remove,
and add files before the final verifier is allowed to pass. The complete set exists
only on that job's ephemeral filesystem and is never uploaded or published.

The default-branch `Package artifact cleanup` workflow runs after every completed
package-validation run, including failures and cancellations, and deletes artifacts
belonging to that exact run. Pull-request code receives no `actions: write`
permission. One-day retention is only a fallback if trusted cleanup cannot run.

`Packaged clean-install acceptance` then extracts the Linux client and relay archives
twice, creates temporary trusted TLS, and drives the plugin-bundled daemon through the
same MCP and authenticated adapter contracts used by Copilot. It repeats the same
pairing, delivery, restart, cancellation, enrollment, and opacity assertions against
the Docker-loaded relay candidate. The Docker path captures a baseline and removes
only its exact labelled container and loaded release image.

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
SBOM attestations, and asserts the archive. Package validation can request a
deterministically tagged Docker-loadable archive as a second exporter from the same
build result. That candidate is uploaded before exact cleanup; it is never loaded,
pushed, or deployed by CI. The release export omits the ephemeral validation-ownership
label, and the shared OCI assertion rejects any release config containing that label
or the current run identity before staging.

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
