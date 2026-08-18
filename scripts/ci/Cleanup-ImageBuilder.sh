#!/usr/bin/env bash
set -euo pipefail

: "${RUNNER_TEMP:?RUNNER_TEMP is required.}"
: "${BUILDKIT_TLS_DIR:?BUILDKIT_TLS_DIR is required.}"
: "${CONTAINER_VALIDATION_ROOT:?CONTAINER_VALIDATION_ROOT is required.}"

runner_temp="$(realpath -m -- "$RUNNER_TEMP")"
declare -a targets=("$BUILDKIT_TLS_DIR" "$CONTAINER_VALIDATION_ROOT")

for target in "${targets[@]}"; do
    resolved="$(realpath -m -- "$target")"
    case "$resolved" in
        "$runner_temp"/*) ;;
        *)
            echo '::error::Refusing to remove image-builder state outside RUNNER_TEMP.'
            exit 1
            ;;
    esac
done

rm -rf -- "${targets[@]}"

for target in "${targets[@]}"; do
    if [ -e "$target" ]; then
        echo '::error::Image-builder job state remains after cleanup.'
        exit 1
    fi
done
