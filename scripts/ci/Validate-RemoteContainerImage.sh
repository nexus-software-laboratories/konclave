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

application_root="$(realpath -e -- "$1")"
workspace_root="$(realpath -e -- "$GITHUB_WORKSPACE")"
image_name="$2"
architecture=amd64

case "$application_root" in
    "$workspace_root"/*) ;;
    *)
        echo '::error::Application root resolves outside GITHUB_WORKSPACE.'
        exit 1
        ;;
esac

if [[ ! "$image_name" =~ ^[a-z0-9]+([._-][a-z0-9]+)*$ ]]; then
    echo '::error::Image name must be a normalized lowercase OCI name.'
    exit 1
fi

dockerfile="$application_root/Dockerfile"
config_path="$application_root/.container/image.json"
test -f "$dockerfile"
test -f "$config_path"

jq -e '
    .schemaVersion == 1
    and .requireImageHealthCheck == true
    and .smoke.kind == "process"
' "$config_path" >/dev/null

build_helper="$(
    bash "$workspace_root/scripts/ci/Initialize-PitCrewBuildHelper.sh"
)"
if [ ! -x "$build_helper" ]; then
    echo '::error::Pinned PitCrew build helper is not executable.'
    exit 1
fi

declare -a buildctl_arguments=(
    --addr "$BUILDKIT_HOST"
    --tlsservername buildkitd
    --tlsdir "$BUILDKIT_TLS_DIR"
)

buildctl "${buildctl_arguments[@]}" debug workers >/dev/null

archive="$CONTAINER_VALIDATION_ROOT/${image_name}-${architecture}.tar"
"$build_helper" \
    --image-ref \
    "local/${image_name}:validation-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${architecture}" \
    --context "$workspace_root" \
    --dockerfile "$application_root" \
    --platform "linux/$architecture" \
    --output-oci "$archive"

test -s "$archive"

manifest_digest="$(
    tar -xOf "$archive" index.json |
        jq -er '
            if (.manifests | length) == 1
            then .manifests[0].digest
            else error("expected exactly one OCI manifest")
            end
        '
)"
manifest="$(
    tar -xOf "$archive" "blobs/sha256/${manifest_digest#sha256:}"
)"
config_digest="$(jq -er '.config.digest' <<<"$manifest")"
image_config="$(
    tar -xOf "$archive" "blobs/sha256/${config_digest#sha256:}"
)"

if [ "$(jq -r '.architecture' <<<"$image_config")" != "$architecture" ]; then
    echo "::error::OCI config architecture does not match $architecture."
    exit 1
fi

runtime_user="$(jq -r '.config.User // ""' <<<"$image_config")"
runtime_identity="${runtime_user%%:*}"
if [ -z "$runtime_identity" ] ||
    [ "$runtime_identity" = 'root' ] ||
    [[ "$runtime_identity" =~ ^0+$ ]]; then
    echo "::error::Image runtime user '$runtime_user' is not non-root."
    exit 1
fi

if ! jq -e '
    (.config.Healthcheck.Test // []) | length > 0
' <<<"$image_config" >/dev/null; then
    echo '::error::Image does not declare a health check.'
    exit 1
fi

entrypoint="$(
    jq -er '
        (.config.Entrypoint // [])[0]
        | select(type == "string" and length > 1)
    ' <<<"$image_config"
)"
entrypoint_path="${entrypoint#/}"
entrypoint_found=false

while IFS=$'\t' read -r layer_digest layer_media_type; do
    layer_path="blobs/sha256/${layer_digest#sha256:}"
    case "$layer_media_type" in
        application/vnd.oci.image.layer.v1.tar|\
        application/vnd.docker.image.rootfs.diff.tar)
            layer_entries="$(
                tar -xOf "$archive" "$layer_path" |
                    tar -tf -
            )"
            ;;
        application/vnd.oci.image.layer.v1.tar+gzip|\
        application/vnd.docker.image.rootfs.diff.tar.gzip)
            layer_entries="$(
                tar -xOf "$archive" "$layer_path" |
                    tar -tzf -
            )"
            ;;
        application/vnd.oci.image.layer.v1.tar+zstd)
            layer_entries="$(
                tar -xOf "$archive" "$layer_path" |
                    tar --zstd -tf -
            )"
            ;;
        *)
            echo "::error::Unsupported OCI layer media type '$layer_media_type'."
            exit 1
            ;;
    esac

    if grep -Eq \
        '^(./)?(usr/local/cargo/|usr/local/rustup/|usr/local/bin/rustc$|usr/bin/cargo$)' \
        <<<"$layer_entries"; then
        echo '::error::Final image contains Rust build tooling.'
        exit 1
    fi

    if grep -Fxq "$entrypoint_path" <<<"${layer_entries#./}" ||
        grep -Fxq "./$entrypoint_path" <<<"$layer_entries"; then
        entrypoint_found=true
    fi
done < <(
    jq -er '.layers[] | [.digest, .mediaType] | @tsv' <<<"$manifest"
)

if [ "$entrypoint_found" != 'true' ]; then
    echo "::error::Image entrypoint '$entrypoint' was not found in the final layers."
    exit 1
fi

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

{
    echo '### Remote OCI validation'
    echo
    echo "- Image: \`$image_name\`"
    echo "- Platform: \`linux/$architecture\`"
    echo '- BuildKit: mTLS-authenticated socketless service'
    echo '- Runtime user: non-root'
    echo '- Health check: present'
    echo '- Rust build tooling in final layers: absent'
    echo '- Entrypoint in final layers: present'
} >> "$GITHUB_STEP_SUMMARY"
