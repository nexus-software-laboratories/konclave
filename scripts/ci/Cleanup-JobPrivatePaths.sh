#!/usr/bin/env bash
set -euo pipefail

# Removes job-private working directories, refusing any target outside RUNNER_TEMP.
#
# Cleanup runs unconditionally after container validation because a backend may leave
# credentials or build output behind, so containment is verified before deletion.

if [ "$#" -eq 0 ]; then
    echo 'Usage: Cleanup-JobPrivatePaths.sh <VARIABLE> ...' >&2
    exit 2
fi

: "${RUNNER_TEMP:?RUNNER_TEMP is required.}"

runner_temp="$(realpath -m -- "$RUNNER_TEMP")"
declare -a targets=()

for variable in "$@"; do
    if [[ ! "$variable" =~ ^[A-Z][A-Z0-9_]*$ ]]; then
        echo "::error::Path variable '$variable' is not a plain environment name."
        exit 1
    fi
    target="${!variable:-}"
    if [ -z "$target" ]; then
        echo "::error::$variable is required."
        exit 1
    fi
    resolved="$(realpath -m -- "$target")"
    case "$resolved" in
        "$runner_temp"/*) ;;
        *)
            echo '::error::Refusing to remove job state outside RUNNER_TEMP.'
            exit 1
            ;;
    esac
    targets+=("$target")
done

rm -rf -- "${targets[@]}"

for target in "${targets[@]}"; do
    if [ -e "$target" ]; then
        echo '::error::Job-private state remains after cleanup.'
        exit 1
    fi
done
