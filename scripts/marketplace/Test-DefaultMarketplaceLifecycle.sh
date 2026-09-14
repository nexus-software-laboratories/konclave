#!/usr/bin/env bash
set -euo pipefail

copilot_command="${1:?Copilot command is required.}"
expected_cli_version="${2:?Copilot CLI version is required.}"
marketplace_root="${3:?Marketplace root is required.}"
marketplace_source="${4:?Marketplace source is required.}"
expected_version="${5:?Marketplace version is required.}"
source_mode="${6:?Marketplace source mode is required.}"
if [ "$source_mode" != 'live' ] && [ "$source_mode" != 'remote' ]; then
    echo "Unsupported marketplace source mode: $source_mode" >&2
    exit 1
fi

test_root="$(mktemp -d)"
git_daemon_pid=''
cleanup() {
    local status="$?"
    local cleanup_status=0
    trap - EXIT
    if [ -n "$git_daemon_pid" ] && kill -0 "$git_daemon_pid" 2>/dev/null; then
        if ! kill "$git_daemon_pid"; then
            cleanup_status=1
        fi
        set +e
        wait "$git_daemon_pid"
        local wait_status="$?"
        set -e
        if [ "$wait_status" -ne 0 ] && [ "$wait_status" -ne 143 ]; then
            cleanup_status=1
        fi
    fi
    if ! rm -rf -- "$test_root"; then
        cleanup_status=1
    fi
    if [ -e "$test_root" ]; then
        cleanup_status=1
    fi
    if [ "$cleanup_status" -ne 0 ]; then
        echo 'Marketplace lifecycle cleanup failed.' >&2
        exit 1
    fi
    exit "$status"
}
trap cleanup EXIT

export COPILOT_HOME="$test_root/copilot-home"
export COPILOT_CACHE_HOME="$test_root/copilot-cache"
export HOME="$test_root/home"
export XDG_CACHE_HOME="$HOME/.cache"
export XDG_CONFIG_HOME="$HOME/.config"
export XDG_DATA_HOME="$HOME/.local/share"
mkdir -p "$COPILOT_HOME" "$COPILOT_CACHE_HOME" "$HOME" "$test_root/authority"

authority_sentinel="$test_root/authority/konclave.service.json"
printf '{"authority":"retained"}\n' >"$authority_sentinel"
authority_digest="$(sha256sum "$authority_sentinel" | awk '{print $1}')"

supports_plugin_json=false
if "$copilot_command" plugin list --help | grep -q -- '--json'; then
    supports_plugin_json=true
fi
supports_plugin_toggle=false
set +e
disable_help="$("$copilot_command" plugin disable --help 2>&1)"
disable_status="$?"
enable_help="$("$copilot_command" plugin enable --help 2>&1)"
enable_status="$?"
set -e
if [ "$disable_status" -eq 0 ] &&
    [ "$enable_status" -eq 0 ] &&
    grep -Fq 'Usage: copilot plugin disable' <<<"$disable_help" &&
    grep -Fq 'Usage: copilot plugin enable' <<<"$enable_help"
then
    supports_plugin_toggle=true
fi

assert_registered() {
    local name="$1"
    local marketplaces
    marketplaces="$("$copilot_command" plugin marketplace list)"
    if ! grep -Fq "$name" <<<"$marketplaces"; then
        echo "Marketplace is not registered: $name" >&2
        exit 1
    fi
    local available
    available="$("$copilot_command" plugin marketplace browse "$name")"
    if ! grep -Fq 'konclave' <<<"$available"; then
        echo "Marketplace does not expose Konclave: $name" >&2
        exit 1
    fi
}

assert_not_registered() {
    local name="$1"
    if "$copilot_command" plugin marketplace list | grep -Fq "$name"; then
        echo "Marketplace remained registered: $name" >&2
        exit 1
    fi
}

find_installed_manifest() {
    local version="$1"
    mapfile -t manifests < <(
        find "$COPILOT_HOME" -type f -name plugin.json -print |
            while IFS= read -r manifest; do
                if jq -e \
                    --arg version "$version" \
                    '.name == "konclave" and .version == $version' \
                    "$manifest" >/dev/null; then
                    printf '%s\n' "$manifest"
                fi
            done
    )
    if [ "${#manifests[@]}" -ne 1 ]; then
        echo "Expected one installed Konclave plugin at version $version." >&2
        exit 1
    fi
    printf '%s\n' "${manifests[0]}"
}

assert_installed() {
    local marketplace="$1"
    local version="$2"
    local enabled="${3:-}"
    local mode="${4:-remote}"
    local plugin_root
    if [ "$mode" = 'live' ]; then
        plugin_root="$marketplace_root/plugins/konclave"
    else
        local manifest
        manifest="$(find_installed_manifest "$version")"
        plugin_root="$(dirname "$manifest")"
    fi
    find "$plugin_root" -type f -printf '%P\n' | sort >"$test_root/actual-plugin-files"
    cat >"$test_root/expected-plugin-files" <<'EOF'
com.github.copilot/extensions/konclave/extension.mjs
com.github.copilot/extensions/konclave/package.json
plugin.json
EOF
    diff -u "$test_root/expected-plugin-files" "$test_root/actual-plugin-files"
    if [ "$supports_plugin_json" = true ]; then
        local listing
        listing="$("$copilot_command" plugin list --json)"
        if [ "$(
            jq \
                --arg marketplace "$marketplace" \
                --arg version "$version" \
                --arg enabled "$enabled" \
                '[
                  .[]
                  | select(
                      .name == "konclave"
                      and .marketplace == $marketplace
                      and .version == $version
                      and (
                        $enabled == ""
                        or (.enabled | tostring) == $enabled
                      )
                    )
                ] | length' <<<"$listing"
        )" -ne 1 ]; then
            echo 'Structured plugin listing does not match the installed plugin.' >&2
            exit 1
        fi
    fi
}

assert_not_installed() {
    if find "$COPILOT_HOME" -type f -name plugin.json -exec \
        jq -e 'select(.name == "konclave")' {} \; | grep -q .
    then
        echo 'Konclave remained installed.' >&2
        exit 1
    fi
}

install_plugin() {
    local marketplace="$1"
    set +e
    local output
    output="$("$copilot_command" plugin install "konclave@$marketplace" 2>&1)"
    local status="$?"
    set -e
    printf '%s\n' "$output"
    if [ "$status" -ne 0 ]; then
        echo "Marketplace plugin installation failed: $marketplace" >&2
        exit "$status"
    fi
    if grep -Eiq 'deprecat(ed|ion)' <<<"$output"; then
        echo 'Marketplace installation emitted a direct-install deprecation warning.' >&2
        exit 1
    fi
    if grep -Eiq \
        'invalid|malformed|unrecognized|unknown (field|key)|manifest.*(error|warning)|schema.*(error|warning)' \
        <<<"$output"
    then
        echo 'Marketplace installation emitted a manifest warning or error.' >&2
        exit 1
    fi
}

exercise_registration() {
    local source="$1"
    local marketplace="$2"
    local mode="$3"
    "$copilot_command" plugin marketplace add "$source"
    assert_registered "$marketplace"
    install_plugin "$marketplace"
    assert_installed "$marketplace" "$expected_version" true "$mode"

    if [ "$supports_plugin_toggle" = true ]; then
        "$copilot_command" plugin disable "konclave@$marketplace"
        assert_installed "$marketplace" "$expected_version" false "$mode"
        "$copilot_command" plugin enable "konclave@$marketplace"
        assert_installed "$marketplace" "$expected_version" true "$mode"
    else
        printf 'Copilot CLI %s does not expose plugin disable/enable commands.\n' \
            "$expected_cli_version"
    fi

    "$copilot_command" plugin marketplace remove "$marketplace" --force
    assert_not_registered "$marketplace"
    assert_not_installed

    "$copilot_command" plugin marketplace add "$source"
    install_plugin "$marketplace"
    assert_installed "$marketplace" "$expected_version" true "$mode"
    "$copilot_command" plugin uninstall "konclave@$marketplace"
    assert_not_installed
    "$copilot_command" plugin marketplace remove "$marketplace"
    assert_not_registered "$marketplace"
}

copy_fixture() {
    local destination="$1"
    local name="$2"
    mkdir -p "$destination/.github/plugin" "$destination/plugins"
    cp "$marketplace_root/.github/plugin/marketplace.json" \
        "$destination/.github/plugin/marketplace.json"
    cp -R "$marketplace_root/plugins/konclave" "$destination/plugins/konclave"
    jq --arg name "$name" '.name = $name' \
        "$destination/.github/plugin/marketplace.json" \
        >"$test_root/marketplace.next"
    mv "$test_root/marketplace.next" "$destination/.github/plugin/marketplace.json"
}

exercise_update_and_rollback() {
    local marketplace="konclave-fixture"
    local work="$test_root/fixture-work"
    local remote="$test_root/fixture.git"
    git init --bare --quiet "$remote"
    git init --quiet --initial-branch=main "$work"
    git -C "$work" config user.name 'Konclave acceptance'
    git -C "$work" config user.email 'user@example.com'
    copy_fixture "$work" "$marketplace"
    git -C "$work" add .
    git -C "$work" commit --quiet -m 'initial marketplace'
    git -C "$work" remote add origin "$remote"
    git -C "$work" push --quiet --set-upstream origin main
    git -C "$remote" symbolic-ref HEAD refs/heads/main

    local port
    port="$(
        python3 -c \
            'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
    )"
    git daemon \
        --reuseaddr \
        --export-all \
        --base-path="$test_root" \
        --listen=127.0.0.1 \
        --port="$port" \
        "$remote" \
        >"$test_root/git-daemon.log" 2>"$test_root/git-daemon.error.log" &
    git_daemon_pid="$!"
    for _ in $(seq 1 50); do
        if (echo >"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
            break
        fi
        sleep 0.1
    done
    if ! kill -0 "$git_daemon_pid" 2>/dev/null; then
        cat "$test_root/git-daemon.log" >&2
        cat "$test_root/git-daemon.error.log" >&2
        echo 'Marketplace Git fixture did not start.' >&2
        exit 1
    fi

    local source="git://127.0.0.1:$port/fixture.git"
    "$copilot_command" plugin marketplace add "$source"
    assert_registered "$marketplace"
    install_plugin "$marketplace"
    assert_installed "$marketplace" "$expected_version" true

    local next_version
    next_version="$(awk -F. '{ printf "%d.%d.%d", $1, $2, $3 + 1 }' <<<"$expected_version")"
    jq --arg version "$next_version" \
        '.metadata.version = $version | .plugins[0].version = $version' \
        "$work/.github/plugin/marketplace.json" >"$test_root/marketplace.update"
    mv "$test_root/marketplace.update" "$work/.github/plugin/marketplace.json"
    for path in \
        "$work/plugins/konclave/plugin.json" \
        "$work/plugins/konclave/com.github.copilot/extensions/konclave/package.json"
    do
        jq --arg version "$next_version" '.version = $version' "$path" >"$test_root/version.next"
        mv "$test_root/version.next" "$path"
    done
    git -C "$work" add .
    git -C "$work" commit --quiet -m 'update marketplace'
    git -C "$work" push --quiet

    "$copilot_command" plugin marketplace update "$marketplace"
    "$copilot_command" plugin update "konclave@$marketplace"
    assert_installed "$marketplace" "$next_version" true

    rm -rf -- "$work/.github/plugin" "$work/plugins/konclave"
    copy_fixture "$work" "$marketplace"
    git -C "$work" add .
    git -C "$work" commit --quiet -m 'rollback marketplace'
    git -C "$work" push --quiet

    "$copilot_command" plugin marketplace update "$marketplace"
    "$copilot_command" plugin uninstall "konclave@$marketplace"
    install_plugin "$marketplace"
    assert_installed "$marketplace" "$expected_version" true
    "$copilot_command" plugin marketplace remove "$marketplace" --force
    assert_not_registered "$marketplace"
    assert_not_installed
}

"$copilot_command" --version | grep -F "$expected_cli_version"
exercise_registration "$marketplace_source" konclave "$source_mode"
exercise_update_and_rollback

if [ "$(sha256sum "$authority_sentinel" | awk '{print $1}')" != "$authority_digest" ]; then
    echo 'Marketplace lifecycle changed canonical authority state.' >&2
    exit 1
fi
if pgrep -f 'KonclaveLocalDaemon|KonclaveLocalService' >/dev/null 2>&1; then
    echo 'Marketplace lifecycle launched a native Konclave process.' >&2
    exit 1
fi

printf 'Copilot CLI %s default-branch marketplace lifecycle passed.\n' "$expected_cli_version"
