#!/usr/bin/env bash
set -euo pipefail

: "${RUNNER_TEMP:?RUNNER_TEMP is required.}"

# PitCrew v0.10.5 is pinned by both its immutable commit and script content hash.
readonly pitcrew_commit='dc9f9b5ca927a7ad8e08eacb8dd1e33b44c09fe0'
readonly expected_sha256='23a32376c12c5a6c337a95c8d4664a9a267562895c1a7df937f67cd1d3026190'
readonly helper_url="https://raw.githubusercontent.com/ncosentino/pitcrew/${pitcrew_commit}/profiles/image-builder/pitcrew-build-image"
readonly helper_directory="${RUNNER_TEMP}/pitcrew-build-helper"
readonly helper_path="${helper_directory}/pitcrew-build-image"
readonly temporary_path="${helper_path}.download"

mkdir -p -- "${helper_directory}"
rm -f -- "${temporary_path}"

curl \
    --disable \
    --fail \
    --location \
    --proto '=https' \
    --tlsv1.2 \
    --silent \
    --show-error \
    --output "${temporary_path}" \
    "${helper_url}"

printf '%s  %s\n' "${expected_sha256}" "${temporary_path}" |
    sha256sum --check --status

chmod 0555 -- "${temporary_path}"
mv -f -- "${temporary_path}" "${helper_path}"
printf '%s\n' "${helper_path}"
