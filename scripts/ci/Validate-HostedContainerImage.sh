#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo 'Usage: Validate-HostedContainerImage.sh <application-root> <image-name>' >&2
    exit 2
fi

: "${CONTAINER_VALIDATION_ROOT:?CONTAINER_VALIDATION_ROOT is required.}"
: "${CONTAINER_VALIDATION_BUILDER:?CONTAINER_VALIDATION_BUILDER is required.}"
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

install -d -m 0700 "$CONTAINER_VALIDATION_ROOT"
archive="$CONTAINER_VALIDATION_ROOT/${image_name}-${architecture}.tar"

# An OCI archive export requires the container driver; the default docker driver
# cannot export one. The builder is job-scoped so no state survives the run.
docker buildx create \
    --name "$CONTAINER_VALIDATION_BUILDER" \
    --driver docker-container \
    --bootstrap >/dev/null

# Attestations would add a second manifest to the exported index and are not part of
# the validated contract, so the export stays a single-platform image manifest.
docker buildx build \
    --builder "$CONTAINER_VALIDATION_BUILDER" \
    --file "$application_root/Dockerfile" \
    --platform "linux/$architecture" \
    --provenance=false \
    --sbom=false \
    --tag "local/${image_name}:validation-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${architecture}" \
    --output "type=oci,dest=$archive" \
    "$workspace_root"

container_image_assert_archive "$archive" "$architecture"
container_image_write_summary \
    "$image_name" \
    "$architecture" \
    'hosted job-scoped buildx builder'
