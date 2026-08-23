#!/usr/bin/env bash
set -euo pipefail

# Removes hosted container-validation state: the isolated buildx builder, its cache,
# and the job-private archive directory. Local Docker state must not accumulate
# across runs, so teardown continues past individual failures and reports at the end.

: "${CONTAINER_VALIDATION_BUILDER:?CONTAINER_VALIDATION_BUILDER is required.}"

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if docker buildx inspect "$CONTAINER_VALIDATION_BUILDER" >/dev/null 2>&1; then
    docker buildx rm --force "$CONTAINER_VALIDATION_BUILDER" || true
fi

if docker buildx inspect "$CONTAINER_VALIDATION_BUILDER" >/dev/null 2>&1; then
    echo '::error::Container validation builder remains after cleanup.'
    exit 1
fi

bash "$script_directory/Cleanup-JobPrivatePaths.sh" CONTAINER_VALIDATION_ROOT
