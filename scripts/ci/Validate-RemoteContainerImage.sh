#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo 'Usage: Validate-RemoteContainerImage.sh <application-root> <image-name>' >&2
    exit 2
fi

: "${BUILDKIT_HOST:?BUILDKIT_HOST is required.}"
: "${BUILDKIT_TLS_DIR:?BUILDKIT_TLS_DIR is required.}"
: "${CONTAINER_VALIDATION_ROOT:?CONTAINER_VALIDATION_ROOT is required.}"
: "${GITHUB_RUN_ID:?GITHUB_RUN_ID is required.}"
: "${GITHUB_RUN_ATTEMPT:?GITHUB_RUN_ATTEMPT is required.}"
: "${GITHUB_WORKSPACE:?GITHUB_WORKSPACE is required.}"
: "${GITHUB_STEP_SUMMARY:?GITHUB_STEP_SUMMARY is required.}"

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/ci/container-image.lib.sh
. "$script_directory/container-image.lib.sh"

application_root="$(container_image_resolve_application_root "$1")"
workspace_root="$(realpath -e -- "$GITHUB_WORKSPACE")"
image_name="$2"
architecture=amd64

container_image_assert_contract "$application_root" "$image_name"

declare -a buildctl_arguments=(
    --addr "$BUILDKIT_HOST"
    --tlsservername buildkitd
    --tlsdir "$BUILDKIT_TLS_DIR"
)

buildctl "${buildctl_arguments[@]}" debug workers >/dev/null

archive="$CONTAINER_VALIDATION_ROOT/${image_name}-${architecture}.tar"
pitcrew-build-image \
    --image-ref \
    "local/${image_name}:validation-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${architecture}" \
    --context "$workspace_root" \
    --dockerfile "$application_root" \
    --platform "linux/$architecture" \
    --output-oci "$archive"

container_image_assert_archive "$archive" "$architecture"

usage="$(buildctl "${buildctl_arguments[@]}" du --format '{{json .}}')"
histories="$(
    buildctl \
        "${buildctl_arguments[@]}" \
        debug histories \
        --format '{{json .}}'
)"
if ! jq -e \
    '. == null or (type == "array" and length == 0)' \
    <<<"$usage" >/dev/null; then
    echo '::error::BuildKit disk usage is not empty after validation.'
    exit 1
fi
if [ -n "$histories" ]; then
    echo '::error::BuildKit history is not empty after validation.'
    exit 1
fi

container_image_write_summary \
    "$image_name" \
    "$architecture" \
    'mTLS-authenticated socketless BuildKit service'
