#!/usr/bin/env bash
set -euo pipefail

# Records what Docker held before validation started, so cleanup can prove it removed
# nothing it did not create. The baseline is read-only evidence and is never used to
# decide what to delete; a resource that predates the run is not this run's to remove
# even when it looks like validation state.

: "${CONTAINER_VALIDATION_ROOT:?CONTAINER_VALIDATION_ROOT is required.}"

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/ci/container-validation.lib.sh
. "$script_directory/container-validation.lib.sh"

if ! container_validation_docker_available; then
    echo 'Docker is unavailable; no baseline is required.'
    exit 0
fi

install -d -m 0700 "$CONTAINER_VALIDATION_ROOT"
baseline="$CONTAINER_VALIDATION_ROOT/docker-baseline.tsv"
container_validation_capture_baseline "$baseline"

if [ -n "${GITHUB_ENV:-}" ]; then
    printf 'CONTAINER_VALIDATION_BASELINE=%s\n' "$baseline" >>"$GITHUB_ENV"
fi

printf 'Captured %s Docker resources as the validation baseline.\n' \
    "$(wc -l <"$baseline" | tr -d ' ')"