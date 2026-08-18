#!/usr/bin/env bash
set -euo pipefail

: "${GITHUB_ENV:?GITHUB_ENV is required.}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required.}"

runner_temp="$(realpath -e -- "$RUNNER_TEMP")"
{
    printf 'BUILDKIT_TLS_DIR=%s\n' "$runner_temp/buildkit-tls"
    printf 'CONTAINER_VALIDATION_ROOT=%s\n' "$runner_temp/konclave-container-validation"
} >> "$GITHUB_ENV"
