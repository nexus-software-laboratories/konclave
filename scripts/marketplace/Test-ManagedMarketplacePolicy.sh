#!/usr/bin/env bash
set -euo pipefail

copilot_command="${1:?Copilot command is required.}"
marketplace_root="${2:?Marketplace root is required.}"

test_root="$(mktemp -d)"
cleanup() {
    local status="$?"
    trap - EXIT
    if ! rm -rf -- "$test_root"; then
        echo 'Managed marketplace policy cleanup failed.' >&2
        exit 1
    fi
    exit "$status"
}
trap cleanup EXIT

export COPILOT_HOME="$test_root/copilot-home"
export COPILOT_CACHE_HOME="$test_root/copilot-cache"
export HOME="$test_root/home"
mkdir -p "$COPILOT_HOME" "$COPILOT_CACHE_HOME" "$HOME"

alternate="$test_root/alternate"
mkdir -p "$alternate/.github/plugin" "$alternate/plugins"
cp "$marketplace_root/.github/plugin/marketplace.json" \
    "$alternate/.github/plugin/marketplace.json"
cp -R "$marketplace_root/plugins/konclave" "$alternate/plugins/konclave"

marketplaces="$("$copilot_command" plugin marketplace list)"
if ! grep -Fq 'konclave' <<<"$marketplaces" ||
    ! grep -Eiq 'managed' <<<"$marketplaces"
then
    echo 'Managed Konclave marketplace was not listed as managed.' >&2
    exit 1
fi

set +e
add_output="$("$copilot_command" plugin marketplace add "$alternate" 2>&1)"
add_status="$?"
set -e
printf '%s\n' "$add_output"
if [ "$add_status" -eq 0 ] ||
    ! grep -Eiq 'managed|cannot|conflict|override' <<<"$add_output"
then
    echo 'Managed marketplace accepted a local source override.' >&2
    exit 1
fi

set +e
remove_output="$("$copilot_command" plugin marketplace remove konclave --force 2>&1)"
remove_status="$?"
set -e
printf '%s\n' "$remove_output"
if [ "$remove_status" -eq 0 ] ||
    ! grep -Eiq 'managed|cannot|remove' <<<"$remove_output"
then
    echo 'Managed marketplace accepted local removal.' >&2
    exit 1
fi

marketplaces="$("$copilot_command" plugin marketplace list)"
if ! grep -Fq 'konclave' <<<"$marketplaces"; then
    echo 'Managed marketplace disappeared after rejected local operations.' >&2
    exit 1
fi

printf 'Managed marketplace precedence passed.\n'
