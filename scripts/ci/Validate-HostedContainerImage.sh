#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo 'Usage: Validate-HostedContainerImage.sh <application-root> <image-name>' >&2
    exit 2
fi

: "${CONTAINER_VALIDATION_ROOT:?CONTAINER_VALIDATION_ROOT is required.}"
: "${CONTAINER_VALIDATION_RUN_ID:?CONTAINER_VALIDATION_RUN_ID is required.}"
: "${GITHUB_WORKSPACE:?GITHUB_WORKSPACE is required.}"
: "${GITHUB_STEP_SUMMARY:?GITHUB_STEP_SUMMARY is required.}"

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/ci/container-image.lib.sh
. "$script_directory/container-image.lib.sh"
# shellcheck source=scripts/ci/container-validation.lib.sh
. "$script_directory/container-validation.lib.sh"

builder="$(container_validation_builder_name "$CONTAINER_VALIDATION_RUN_ID")"

application_root="$(container_image_resolve_application_root "$1")"
workspace_root="$(realpath -e -- "$GITHUB_WORKSPACE")"
image_name="$2"
architecture=amd64

container_image_assert_contract "$application_root" "$image_name"

install -d -m 0700 "$CONTAINER_VALIDATION_ROOT"
archive="$CONTAINER_VALIDATION_ROOT/${image_name}-${architecture}.tar"

# An OCI archive export requires the container driver; the default docker driver
# cannot export one. The builder is named from this run identity, so a concurrent run
# can neither reuse it nor have it removed by this run cleaning up after itself.
docker buildx create \
    --name "$builder" \
    --driver docker-container \
    --driver-opt "env.KONCLAVE_VALIDATION_RUN=$CONTAINER_VALIDATION_RUN_ID" \
    --bootstrap >/dev/null

# Attestations would add a second manifest to the exported index and are not part of
# the validated contract, so the export stays a single-platform image manifest.
docker buildx build \
    --builder "$builder" \
    --file "$application_root/Dockerfile" \
    --platform "linux/$architecture" \
    --provenance=false \
    --sbom=false \
    --label "${CONTAINER_VALIDATION_OWNER_LABEL}=${CONTAINER_VALIDATION_RUN_ID}" \
    --tag "local/${image_name}:validation-${CONTAINER_VALIDATION_RUN_ID}-${architecture}" \
    --output "type=oci,dest=$archive" \
    "$workspace_root"

container_image_assert_archive "$archive" "$architecture"
container_image_write_summary \
    "$image_name" \
    "$architecture" \
    "hosted run-scoped buildx builder $builder"
