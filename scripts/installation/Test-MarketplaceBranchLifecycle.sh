#!/usr/bin/env bash
set -euo pipefail

copilot_command="${1:?Copilot command is required.}"
expected_cli_version="${2:?Copilot CLI version is required.}"
repository="${3:?Repository is required.}"
branch="${4:?Ephemeral branch is required.}"
marketplace_name="${5:?Marketplace name is required.}"
plugin_archive="${6:?Agent Plugin archive is required.}"
plugin_version="${7:?Agent Plugin version is required.}"
source_commit="${8:?Source commit is required.}"

test_root="$(mktemp -d)"
cleanup() {
    local status="$?"
    trap - EXIT
    if ! rm -rf -- "$test_root"; then
        echo 'Marketplace lifecycle root cleanup failed.' >&2
        exit 1
    fi
    if [ -e "$test_root" ]; then
        echo 'Marketplace lifecycle root remained after cleanup.' >&2
        exit 1
    fi
    exit "$status"
}
trap cleanup EXIT
export COPILOT_HOME="$test_root/copilot-home"
export HOME="$test_root/home"
export COPILOT_CACHE_HOME="$test_root/copilot-cache"
export XDG_CACHE_HOME="$HOME/.cache"
export XDG_CONFIG_HOME="$HOME/.config"
export XDG_DATA_HOME="$HOME/.local/share"
mkdir -p \
    "$COPILOT_HOME" \
    "$HOME" \
    "$XDG_CACHE_HOME" \
    "$XDG_CONFIG_HOME" \
    "$XDG_DATA_HOME" \
    "$test_root/distribution/plugins/konclave"
unzip -q "$plugin_archive" -d "$test_root/distribution/plugins/konclave"

next_version="$(
    awk -F. '{ printf "%d.%d.%d", $1, $2, $3 + 1 }' <<<"$plugin_version"
)"
plugin_digest="$(sha256sum "$plugin_archive" | awk '{print $1}')"

write_catalog() {
    local version="$1"
    jq -n \
        --arg name "$marketplace_name" \
        --arg version "$version" \
        '{
          name: $name,
          metadata: {
            description: "Ephemeral Konclave marketplace lifecycle acceptance",
            version: "1.0.0"
          },
          owner: {
            name: "Nexus Software Laboratories",
            email: "github@nexussoftwarelabs.com"
          },
          plugins: [
            {
              name: "konclave",
              source: "plugins/konclave",
              description: "Secure, durable agent-to-agent communication for GitHub Copilot CLI",
              version: $version
            }
          ]
        }' >"$test_root/distribution/.github-plugin-marketplace.json"
    mkdir -p "$test_root/distribution/.github/plugin"
    mv \
        "$test_root/distribution/.github-plugin-marketplace.json" \
        "$test_root/distribution/.github/plugin/marketplace.json"
}

write_source_record() {
    local materialized_version="$1"
    local synthetic_update="$2"
    jq -n \
        --arg source_commit "$source_commit" \
        --arg plugin_digest "$plugin_digest" \
        --arg release_version "$plugin_version" \
        --arg materialized_version "$materialized_version" \
        --argjson synthetic_update "$synthetic_update" \
        '{
          schemaVersion: 1,
          sourceCommit: $source_commit,
          releasePluginVersion: $release_version,
          releasePluginArchiveSha256: $plugin_digest,
          materializedPluginVersion: $materialized_version,
          syntheticUpdate: $synthetic_update
        }' >"$test_root/distribution/SOURCE.json"
}

create_commit() {
    local message="$1"
    local parent="${2:-}"
    local index="$test_root/index"
    rm -f -- "$index"
    GIT_INDEX_FILE="$index" git read-tree --empty
    GIT_INDEX_FILE="$index" git --work-tree="$test_root/distribution" add --all
    tree="$(GIT_INDEX_FILE="$index" git write-tree)"
    if [ -n "$parent" ]; then
        printf '%s\n' "$message" |
            git commit-tree "$tree" -p "$parent"
    else
        printf '%s\n' "$message" |
            git commit-tree "$tree"
    fi
}

find_cached_manifest() {
    local version="$1"
    mapfile -t matches < <(
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
    if [ "${#matches[@]}" -ne 1 ]; then
        echo "Expected one cached Konclave plugin at version $version." >&2
        return 1
    fi
    printf '%s\n' "${matches[0]}"
}

verify_cached_plugin() {
    local version="$1"
    local manifest
    local cache_root
    manifest="$(find_cached_manifest "$version")"
    cache_root="$(dirname "$manifest")"
    find "$cache_root" -type f -printf '%P\n' | sort >"$test_root/actual-plugin-files"
    cat >"$test_root/expected-plugin-files" <<'EOF'
com.github.copilot/extensions/konclave/extension.mjs
com.github.copilot/extensions/konclave/package.json
plugin.json
EOF
    diff -u "$test_root/expected-plugin-files" "$test_root/actual-plugin-files"
    printf '%s\n' "$manifest"
}

add_marketplace() {
    local label="$1"
    local source="$2"
    set +e
    add_output="$("$copilot_command" plugin marketplace add "$source" 2>&1)"
    add_status=$?
    set -e
    printf '%s\n' "$add_output"
    if [ "$add_status" -eq 0 ]; then
        printf 'Non-default marketplace source form: %s\n' "$label"
        return 0
    fi
    printf 'Non-default marketplace source form failed: %s\n' "$label" >&2
    return "$add_status"
}

write_catalog "$plugin_version"
write_source_record "$plugin_version" false
git config user.name 'github-actions[bot]'
git config user.email '41898282+github-actions[bot]@users.noreply.github.com'
first_commit="$(create_commit 'test: materialize initial marketplace')"
git push origin "$first_commit:refs/heads/$branch"

"$copilot_command" --version | grep -F "$expected_cli_version"
if ! add_marketplace shorthand "$repository#$branch"; then
    marketplaces="$("$copilot_command" plugin marketplace list)"
    if grep -Fq "$marketplace_name" <<<"$marketplaces"; then
        echo 'Failed shorthand registration left a marketplace behind.' >&2
        exit 1
    fi
    add_marketplace \
        full-url \
        "https://github.com/$repository.git#$branch"
fi
marketplaces="$("$copilot_command" plugin marketplace list)"
if ! grep -Fq "$marketplace_name" <<<"$marketplaces"; then
    echo 'Registered marketplace was not listed.' >&2
    exit 1
fi
available_plugins="$("$copilot_command" plugin marketplace browse "$marketplace_name")"
if ! grep -Fq 'konclave' <<<"$available_plugins"; then
    echo 'Registered marketplace did not expose the Konclave plugin.' >&2
    exit 1
fi
"$copilot_command" plugin install "konclave@$marketplace_name"
initial_manifest="$(verify_cached_plugin "$plugin_version")"

jq \
    --arg version "$next_version" \
    '.version = $version' \
    "$test_root/distribution/plugins/konclave/plugin.json" \
    >"$test_root/plugin.json.next"
mv "$test_root/plugin.json.next" "$test_root/distribution/plugins/konclave/plugin.json"
jq \
    --arg version "$next_version" \
    '.version = $version' \
    "$test_root/distribution/plugins/konclave/com.github.copilot/extensions/konclave/package.json" \
    >"$test_root/package.json.next"
mv \
    "$test_root/package.json.next" \
    "$test_root/distribution/plugins/konclave/com.github.copilot/extensions/konclave/package.json"
write_catalog "$next_version"
write_source_record "$next_version" true
second_commit="$(create_commit 'test: update marketplace plugin' "$first_commit")"
git push origin "$second_commit:refs/heads/$branch"

"$copilot_command" plugin marketplace update "$marketplace_name"
"$copilot_command" plugin update "konclave@$marketplace_name"
updated_manifest="$(verify_cached_plugin "$next_version")"
if [ "$updated_manifest" = "$initial_manifest" ]; then
    printf 'Marketplace update reused cache root with updated bytes.\n'
fi

git push \
    --force-with-lease="refs/heads/$branch:$second_commit" \
    origin \
    "$first_commit:refs/heads/$branch"
"$copilot_command" plugin marketplace update "$marketplace_name"
"$copilot_command" plugin uninstall "konclave@$marketplace_name"
"$copilot_command" plugin install "konclave@$marketplace_name"
verify_cached_plugin "$plugin_version" >/dev/null

"$copilot_command" plugin marketplace remove "$marketplace_name" --force
marketplaces="$("$copilot_command" plugin marketplace list)"
if grep -Fq "$marketplace_name" <<<"$marketplaces"; then
    echo 'Marketplace remained registered after removal.' >&2
    exit 1
fi
if find "$COPILOT_HOME" -type f -name plugin.json -exec \
    jq -e 'select(.name == "konclave")' {} \; | grep -q .
then
    echo 'Marketplace removal left a Konclave plugin cache.' >&2
    exit 1
fi
# Removing a marketplace unregisters it and its installed plugins; the reusable
# remote-source cache remains implementation-owned and is removed with this test root.
if [ -d "$COPILOT_CACHE_HOME" ] &&
    find "$COPILOT_CACHE_HOME" -mindepth 1 -print -quit |
        grep -q .
then
    printf 'Copilot retained its reusable source cache inside the isolated test root.\n'
fi

printf 'Copilot CLI %s non-default marketplace lifecycle passed.\n' "$expected_cli_version"
