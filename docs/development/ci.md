# Continuous integration

This repository is public. Every pull-request build, lint, test, packaging,
conformance, policy, and container job runs on GitHub-hosted capacity. Pull-request
validation never consumes PitCrew or another self-hosted runner.

## Runner lanes

- `ubuntu-latest` runs Rust and Node builds, linting, tests, daemon packaging,
  pull-request policy checks, both OCI validation lanes, the pinned A2A TCK, and
  official Python SDK interoperability.
- `ubuntu-latest`, `windows-latest`, `macos-15`, and `macos-15-intel`
  (GitHub-hosted) build and exercise native unsigned release candidates.

The Rust workspace lane starts directly with `cargo test --workspace`. It does not
repeat a debug `cargo build` first: all-target Clippy owns compile-only target
coverage, while ready-only package validation builds the release binaries that ship.
The separate fuzz manifest is compiled and linted once through its pinned Clippy
command instead of receiving an earlier duplicate `cargo check`.
`scripts/ci/Test-CiWorkDeduplication.ps1` keeps these responsibilities separate so a
future workflow edit cannot silently restore duplicate compilation.

Validation is grouped per pull request. A new head revision cancels the prior run for
that pull request, while each manual dispatch uses its unique run identifier. Stale
commits therefore cannot consume runner capacity or report after the current head.

`Workflow syntax` is an independent five-minute merge gate on every pull-request
revision. It downloads the pinned Linux x64 actionlint `1.7.12` archive, verifies its
SHA-256 digest, proves the binary rejects a deterministic invalid fixture, and checks
every top-level GitHub Actions workflow. The gate disables ShellCheck and pyflakes
integration because command bodies have separate repository checks; its purpose is a
fast signal for workflow YAML, expression, action, and schema failures. Keeping this
gate outside the primary workflow lets it report when another workflow file cannot be
loaded.

The final `CI` verdict also reads the executed, completed jobs from its own workflow
attempt and publishes one-day performance evidence without scheduling another runner.
Skipped jobs are excluded because GitHub may publish synthetic timestamps for them
that are not execution intervals. The job summary and JSON artifact report initial
runner delay, observed workflow span, summed job occupancy, active coverage, parallel
overlap, idle gaps, and the slowest jobs and steps. These measurements describe
elapsed Actions execution rather than CPU usage or billed cost, and they remain
fail-closed if GitHub returns malformed or incomplete timing data.

Feature conformance workflows use one shared, fail-closed ownership resolver. Host
Extension changes select only the client, pairing, alias, or user-presence contracts
that own the changed source or test surface; generic runtime, policy, and tool
changes remain with Agent Plugin and startup validation instead of compiling six
unrelated Rust integration graphs. Workflow changes, Cargo workspace changes,
manual dispatches, missing changed-file evidence, and GitHub's 3,000-file boundary
select the affected component conservatively.

Routine Dependabot minor and patch updates are grouped once per Cargo and GitHub
Actions ecosystem. Major updates remain separate so compatibility changes stay
independently reviewable. Cargo is capped at three open update pull requests and
GitHub Actions at two, bounding the weekly burst.

Dependabot pull requests do not schedule the ordinary component, package, container,
installer, or cross-platform matrices. Required jobs report `skipped`, which GitHub
treats as successful for branch protection, while the primary `CI` workflow runs one
fail-closed dependency lane. Cargo-only updates run the complete workspace tests,
all-target compilation, fuzz-target compilation, and the Rust security-dependency
policy in one job. Node-only updates run the Node workspace checks; GitHub Actions
updates run the workflow, storage, and security-sensitive delivery contracts.
Unexpected changed paths fail instead of silently receiving reduced validation.
Human-authored dependency changes continue through the ordinary full matrix.

## Reuse validation on ready promotion

Draft pull requests perform only lightweight validation planning and publish
`Draft CI`; runner-intensive build, test, package, container, A2A, and adapter work is
deferred. Moving a pull request to ready-for-review triggers fresh full validation on
the unchanged head and publishes the required `CI` and component check contexts.

Code-validation workflows do not run for metadata-only `edited` events. The title,
base, and Review policy checks still react to edits because their decisions depend on
pull-request metadata. Retargeting onto `main` makes the base check fail once with an
explicit instruction to close and reopen the pull request or push a new commit; that
subsequent event launches every eligible code-validation workflow against the current
base.

`scripts/ci/Test-PullRequestValidationTriggers.ps1` owns this trigger contract and
prevents metadata edits from reintroducing code-validation fan-out while preserving
ready/draft transitions for workflows whose execution scope depends on that state.

## Fork boundary

The primary CI and component workflows use `pull_request`, read-only permissions, and
GitHub-hosted runners, so fork code cannot reach private runner state, repository
secrets, a registry, or a deployment target. Metadata-only title, base, and review
policy workflows may use `pull_request_target`; they never check out or execute pull
request code.

The package-validation workflow uses only GitHub-hosted runners with read-only
repository permissions. Fork code may execute there because it cannot reach
credentials, a registry, or a deployment target.

The A2A conformance workflow follows the same hosted-only trust boundary. Its stable
required check uses a read-only pull-request file query and runs the external suite
only when A2A contracts, gateway code, provenance, or harness files changed. It
checks out no source for unrelated changes. Relevant runs also format, test, and
Clippy the standalone gateway host and format/Clippy the packaged A2A acceptance
harness before executing external code. Ready and draft transitions still rerun
validation because execution scope depends on that state. Metadata edits retain the
existing exact-head result instead of scheduling another scope-only runner.

The adapter-conformance workflow follows the same hosted-only boundary. Its stable
check validates the persistent shared-local-service client, harness-neutral adapter
SDK, immutable delivery fixture, and fake-harness claim/crash/reclaim lifecycle. It
uses a read-only pull-request file query and skips source checkout for unrelated
changes. It also runs the focused local-service authorization-loss regression and
Clippy over the service library, and type-checks the TypeScript fixture consumer
before running its focused Vitest case.

## Native package validation

`.github/workflows/package-validation.yml` builds Linux x64, Windows x64, macOS
Apple-silicon, and macOS Intel binaries. Each lane packages the CLI, shared local
service, standalone relay, platform service files, and built Copilot plugin according
to `distribution/release-artifacts.json`. A separate hosted lane builds the portable
Agent Plugin once and emits its provenance.

A fail-closed package plan resolves the complete pull-request file set once before
runner-intensive jobs start. Rust, application, release-manifest, installer,
marketplace, packaging, package-workflow, or unknown package-owned changes retain the
complete native, Agent Plugin, container, integrity, and acceptance matrix. Changes
limited to the Host Extension select only Agent Plugin packaging, while changes to
container-validation support select only the container lanes. Distribution
documentation and unrelated CI support publish the stable `Package validation`
context without building candidates. File-discovery failures and inventories at
GitHub's 3,000-file limit expand back to the complete matrix.

The package gate creates each native archive twice and requires byte-identical output,
extracts it outside the source tree, runs the packaged CLI, and requires `konclave
doctor` to recognize the packaged daemon and plugin. Candidates are uploaded as transient unsigned workflow artifacts used only to
transfer files between jobs; package validation itself does not publish a release.

After every native and container lane succeeds, `Release integrity` downloads the
candidates into one flat release set. It emits target-filtered Rust, npm-lock, and
container CycloneDX SBOMs; one deterministic SLSA provenance statement per executable
archive; and an exact SHA-256 manifest. The shipped `RELEASE.json` independently
defines every required archive and sidecar, so a partial download cannot redefine
itself as complete merely by omitting a checksum line. Negative tests mutate, remove, and add files before the final verifier is allowed to
pass. A trusted reusable-workflow caller may retain the complete set as a one-day
Actions artifact; pull-request validation does not.

Repository artifact and log retention is capped at one day through the repository
setting. The repository `GITHUB_TOKEN` cannot read that administrative setting, so
workflows enforce one-day retention on every upload rather than fabricating a runtime
verification. The default-branch `Actions storage cleanup` workflow runs after Agent
Plugin conformance, every completed package-validation run including failures and
cancellations, and successful prerelease publication. Cleanup uses one global
concurrency group and cancels superseded runs because every invocation reconciles all
completed eligible runs and repository caches, not only the event that launched it.
The newest invocation therefore subsumes older queued or interrupted cleanup without
orphaning bytes. Failed publication runs keep their candidate for at most one day so
a maintainer can diagnose or resume a draft or tag failure without presenting it as
a release.

Pull requests may restore Rust caches created from `main`, but cannot persist new
Rust or npm caches. Trusted `main` runs share npm's content-addressed download store
instead of creating one copy per job. Scheduled and post-package cleanup removes every
pull-request cache and deletes the oldest trusted caches until the repository is at or
below 5 GiB. Pull-request code receives no `actions: write` permission.

`Marketplace conformance` verifies pure materialization decisions, Release checksum
and SLSA provenance binding, safe exact-path writes, and byte identity between the
immutable Agent Plugin archive and the four committed marketplace files. Pull
requests run minimum/current Copilot CLI lifecycle against the local default-branch
tree. A trusted post-merge dispatch repeats registration through the public
`owner/repo` source without a ref suffix.

`Extension startup conformance` verifies the finite startup failure policy and the
runtime join behavior independently. A service connection failure must register
exactly one deterministic repair command with no tools, hooks, MCP server, or
delivery; profile derivation and Copilot SDK join failures remain fatal.

## Immutable prerelease publication

`.github/workflows/publish-prerelease.yml` is manual, main-only, and uses public
GitHub-hosted runners plus the repository-scoped `GITHUB_TOKEN`. It calls package
validation as a reusable workflow and waits for every native, container, integrity,
and packaged-acceptance job before receiving the complete set.

The publisher requires repository release immutability, an unused `v<version>` tag,
and exact agreement among the release manifest, Agent Plugin, and npm package. It
creates the tag only after local verification, creates a draft release, uploads every
file without replacement, compares GitHub's asset sizes and digests, downloads the
draft to a clean directory, and runs the shipped verifier. The final publish must
report an immutable prerelease whose lightweight tag identifies the validated source
commit. Any earlier failure leaves no published release.

Release immutability is an administrator-owned repository setting. GitHub does not
allow the credential-free workflow token to read that setting, so maintainers verify
it before dispatch; the final release response is the workflow's authoritative
immutability check. If GitHub reports a mutable release, the workflow returns it to
draft and fails.

If publication fails after tag or draft creation, dispatch `Publish prerelease` in
`resume` mode with the failed source run identifier. Resume downloads that run's
retained complete-set artifact, requires the existing tag and mutable draft to match
its provenance, rejects changed or extra assets, uploads only missing exact assets,
and retries each draft download with a bounded digest check. It never rebuilds after
tag creation. A successful resume deletes the original run's transient artifacts.

```shell
gh workflow run publish-prerelease.yml \
  --ref main \
  -f mode=resume \
  -f version=<version> \
  -f source_run_id=<failed-run-id>
```

## Installer lifecycle validation

`Installer lifecycle conformance` runs while a pull request is draft on
`ubuntu-latest`, `windows-latest`, and `macos-15`, then publishes one stable aggregate
check. The platform jobs exercise pure install/update/rollback/uninstall decisions,
owner-only state, bounded archive extraction, legacy-extension preservation, and
failed-update recovery. Windows additionally installs, inspects, stops, and removes
the exact limited scheduled task used by the per-user supervisor.

One hosted resolver now selects installer ownership before the platform matrix is
expanded. Unrelated pull requests publish the stable aggregate after the resolver
without allocating Windows or macOS runners; installer, package-workflow,
distribution, platform-packaging, installation, and packaging changes retain all
three platforms. Missing changed-file evidence and the 3,000-file boundary remain
conservative.

Ready-only package validation invokes the installer from each extracted client
archive with an isolated empty data root. Release integrity also checksums the
installer and its support functions in the complete release set.

`Packaged clean-install acceptance` then extracts the Linux client, relay, and gateway archives
twice, creates temporary trusted TLS, and drives the packaged shared local service
through the same authenticated thin-client contract used by Copilot. It repeats the
same pairing, delivery, restart, cancellation, enrollment, and opacity assertions
against the Docker-loaded relay candidate. The Docker path captures a baseline and
removes only its exact labelled container and loaded release image.

## Local Copilot inference boundary

The two-session Copilot smoke is outside the CI execution contract. Workflows may
compile, lint, and unit-test `tools/Konclave.CopilotSmoke`, but must never execute
`Invoke-KonclaveCopilotSmoke.ps1`, start Copilot SDK sessions, or consume a
developer's Copilot authentication. Both live entry points reject recognized CI
environment markers before inference begins.

## OCI validation

Container validation builds separate `linux/amd64` OCI archives for the Community
Relay and standalone A2A gateway and asserts their structure. The build backend
differs by runner, but the image contract and every archive assertion are shared in
`scripts/ci/container-image.lib.sh` so both backends validate identically.

Validation confirms the non-root runtime user, declared health check,
entrypoint presence in the final layers, and absence of Rust build tooling. It
does not run the image. The A2A lane additionally compiles the maintained Compose
definition and checks its loopback publication, read-only root, dropped capabilities,
non-root identity, finite PID budget, and five explicit mount boundaries.

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
