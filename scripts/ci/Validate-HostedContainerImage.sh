#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    echo 'Usage: Validate-HostedContainerImage.sh <application-root> <image-name> [release-reference]' >&2
    exit 2
fi

: "${CONTAINER_VALIDATION_ROOT:?CONTAINER_VALIDATION_ROOT is required.}"
: "${GITHUB_WORKSPACE:?GITHUB_WORKSPACE is required.}"
: "${GITHUB_STEP_SUMMARY:?GITHUB_STEP_SUMMARY is required.}"

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/ci/container-image.lib.sh
. "$script_directory/container-image.lib.sh"
# shellcheck source=scripts/ci/container-validation.lib.sh
. "$script_directory/container-validation.lib.sh"

# The identity is derived rather than required. Under pull_request_target the workflow
# comes from the default branch while these scripts come from the pull request, so a
# script that demanded a newly introduced variable could never be merged.
run_identity="$(container_validation_run_identity)"
builder="$(container_validation_builder_name "$run_identity")"
if [ -n "${GITHUB_ENV:-}" ]; then
    printf 'CONTAINER_VALIDATION_RUN_ID=%s\n' "$run_identity" >>"$GITHUB_ENV"
fi

application_root="$(container_image_resolve_application_root "$1")"
workspace_root="$(realpath -e -- "$GITHUB_WORKSPACE")"
image_name="$2"
architecture=amd64

container_image_assert_contract "$application_root" "$image_name"

install -d -m 0700 "$CONTAINER_VALIDATION_ROOT"
archive="$CONTAINER_VALIDATION_ROOT/${image_name}-${architecture}.tar"
image_reference="local/${image_name}:validation-${run_identity}-${architecture}"
outputs=(--output "type=oci,dest=$archive")
image_labels=(--label "${CONTAINER_VALIDATION_OWNER_LABEL}=${run_identity}")
release_archive=''
if [ "$#" -eq 3 ]; then
    image_reference="$(container_image_release_reference "$image_name" "$3")"
    release_archive="$CONTAINER_VALIDATION_ROOT/${image_name}-${architecture}-docker.tar"
    outputs+=(--output "type=docker,dest=$release_archive")
    image_labels=()
fi

# An OCI archive export requires the container driver; the default docker driver
# cannot export one. The builder is named from this run identity, so a concurrent run
# can neither reuse it nor have it removed by this run cleaning up after itself.
docker buildx create \
    --name "$builder" \
    --driver docker-container \
    --driver-opt "env.KONCLAVE_VALIDATION_RUN=$run_identity" \
    --bootstrap >/dev/null

# Attestations would add a second manifest to the exported index and are not part of
# the validated contract, so the export stays a single-platform image manifest.
docker buildx build \
    --builder "$builder" \
    --file "$application_root/Dockerfile" \
    --platform "linux/$architecture" \
    --provenance=false \
    --sbom=false \
    "${image_labels[@]}" \
    --tag "$image_reference" \
    "${outputs[@]}" \
    "$workspace_root"

container_image_assert_archive "$archive" "$architecture"
if [ -n "$release_archive" ] && [ ! -s "$release_archive" ]; then
    echo '::error::Docker-loadable release archive was not created.'
    exit 1
fi
if [ -n "$release_archive" ]; then
    container_image_assert_public_release_config "$archive" "$run_identity"
fi
container_image_write_summary \
    "$image_name" \
    "$architecture" \
    "hosted run-scoped buildx builder $builder"
