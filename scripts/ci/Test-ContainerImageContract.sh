#!/usr/bin/env bash
set -euo pipefail

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/ci/container-image.lib.sh
. "$script_directory/container-image.lib.sh"

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

echo 'Container image release-reference contract passed.'
