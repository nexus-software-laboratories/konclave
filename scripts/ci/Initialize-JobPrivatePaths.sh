#!/usr/bin/env bash
set -euo pipefail

# Declares job-private working directories under RUNNER_TEMP and exports them.
#
# Every container backend needs the same containment guarantee, so the directory set
# is supplied by the caller instead of being restated per backend.

if [ "$#" -eq 0 ]; then
    echo 'Usage: Initialize-JobPrivatePaths.sh <VARIABLE>=<directory-name> ...' >&2
    exit 2
fi

: "${GITHUB_ENV:?GITHUB_ENV is required.}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required.}"

runner_temp="$(realpath -e -- "$RUNNER_TEMP")"

for declaration in "$@"; do
    variable="${declaration%%=*}"
    directory_name="${declaration#*=}"
    if [ -z "$variable" ] ||
        [ -z "$directory_name" ] ||
        [ "$variable" = "$declaration" ]; then
        echo "::error::Malformed path declaration '$declaration'."
        exit 1
    fi
    if [[ ! "$variable" =~ ^[A-Z][A-Z0-9_]*$ ]]; then
        echo "::error::Path variable '$variable' is not a plain environment name."
        exit 1
    fi
    case "$directory_name" in
        */*|.|..)
            echo "::error::Path name '$directory_name' must be a single segment."
            exit 1
            ;;
    esac
    printf '%s=%s\n' "$variable" "$runner_temp/$directory_name" >>"$GITHUB_ENV"
done
