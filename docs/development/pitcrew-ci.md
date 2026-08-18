# PitCrew CI

Every GitHub Actions job in this repository runs on PitCrew. GitHub-hosted
runners are not a fallback.

## Runner lanes

- `general-purpose` runs Rust and Node builds, linting, tests, and daemon
  packaging checks.
- `automation-control` runs validation planning and pull-request policy checks.
- `image-builder` runs the Community Relay OCI build through the operator-owned
  rootless BuildKit service.

Named PitCrew profiles advertise `linux`, `x64`, and the profile label without
the broad `self-hosted` label. The default `general-purpose` profile retains
GitHub's default labels.

Superseding CI revisions queue instead of cancelling an active run. This lets
the BuildKit helper complete its mandatory history and cache cleanup before the
shared daemon is reused.

## Fork boundary

PitCrew does not execute jobs or code from fork pull requests. Pull-request
workflows are defined by the default branch, and every PitCrew entry job checks
for an exact same-repository head before runner assignment. A maintainer must
reproduce an external contribution on a repository branch before validation.
This preserves the outbound-only self-hosted trust boundary without using
GitHub-hosted runners.

## OCI validation

The image-builder worker has no Docker socket. The workflow connects to
`buildkitd:1234` with a job-scoped mTLS client and builds one
`linux/amd64` OCI archive for the Community Relay.

The repository stores only client-side material:

- `BUILDKIT_CLIENT_CA_PEM_B64`;
- `BUILDKIT_CLIENT_CERT_PEM_B64`;
- `BUILDKIT_CLIENT_KEY_PEM_B64`.

Workflows decode these secrets beneath `RUNNER_TEMP`, validate the image
structure, and remove the exact job-private directories unconditionally.
Validation confirms the non-root runtime user, health check, entrypoint,
absence of Rust build tooling, and empty BuildKit history/cache. It does not
run the image inside the socketless worker.

Docker-based validation must not run on developer workstations.
