#!/usr/bin/env bash
set -euo pipefail

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/ci/container-image.lib.sh
. "$script_directory/container-image.lib.sh"
# shellcheck source=scripts/ci/container-validation.lib.sh
. "$script_directory/container-validation.lib.sh"

image_name='konclave-community-relay'
expected='konclave-community-relay:0.1.0'
actual="$(container_image_release_reference "$image_name" "$expected")"
if [ "$actual" != "$expected" ]; then
    echo '::error::Release image reference did not round-trip exactly.'
    exit 1
fi

for invalid in \
    'other-image:0.1.0' \
    'registry.example.com/konclave-community-relay:0.1.0' \
    'konclave-community-relay:bad:tag' \
    'konclave-community-relay:'
do
    if container_image_release_reference "$image_name" "$invalid" >/dev/null 2>&1; then
        echo "::error::Invalid release image reference was accepted: $invalid"
        exit 1
    fi
done

fixture_root="$(mktemp -d)"
cleanup() {
    rm -rf -- "$fixture_root"
}
trap cleanup EXIT

create_oci_fixture() {
    local destination="$1"
    local config_json="$2"
    local layout="$fixture_root/layout"
    local config_digest manifest_digest

    rm -rf -- "$layout"
    mkdir -p "$layout/blobs/sha256"
    printf '%s' "$config_json" >"$layout/config.json"
    config_digest="$(sha256sum "$layout/config.json" | cut -d' ' -f1)"
    mv "$layout/config.json" "$layout/blobs/sha256/$config_digest"
    jq -n \
        --arg digest "sha256:$config_digest" \
        '{
            schemaVersion: 2,
            mediaType: "application/vnd.oci.image.manifest.v1+json",
            config: {
                mediaType: "application/vnd.oci.image.config.v1+json",
                digest: $digest,
                size: 1
            },
            layers: []
        }' >"$layout/manifest.json"
    manifest_digest="$(sha256sum "$layout/manifest.json" | cut -d' ' -f1)"
    mv "$layout/manifest.json" "$layout/blobs/sha256/$manifest_digest"
    jq -n \
        --arg digest "sha256:$manifest_digest" \
        '{
            schemaVersion: 2,
            manifests: [{
                mediaType: "application/vnd.oci.image.manifest.v1+json",
                digest: $digest,
                size: 1
            }]
        }' >"$layout/index.json"
    tar -cf "$destination" -C "$layout" index.json blobs
}

public_archive="$fixture_root/public.tar"
create_oci_fixture "$public_archive" '{"config":{"Labels":{"purpose":"release"}}}'
container_image_assert_public_release_config "$public_archive" 'ci-test-run'

labelled_archive="$fixture_root/labelled.tar"
create_oci_fixture \
    "$labelled_archive" \
    '{"config":{"Labels":{"dev.konclave.validation.run":"ci-test-run"}}}'
if container_image_assert_public_release_config "$labelled_archive" 'ci-test-run' >/dev/null 2>&1; then
    echo '::error::Release config accepted the validation ownership label.'
    exit 1
fi

identified_archive="$fixture_root/identified.tar"
create_oci_fixture "$identified_archive" '{"config":{"Labels":{"other":"ci-test-run"}}}'
if container_image_assert_public_release_config "$identified_archive" 'ci-test-run' >/dev/null 2>&1; then
    echo '::error::Release config accepted its validation run identity.'
    exit 1
fi

echo 'Container image release-reference contract passed.'
