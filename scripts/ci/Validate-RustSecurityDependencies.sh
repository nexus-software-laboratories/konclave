#!/usr/bin/env bash
set -euo pipefail

dependency_tree="$(cargo tree --workspace --locked --prefix none)"

require_single_version() {
    local package_name="$1"
    local expected_version="$2"
    mapfile -t versions < <(
        awk -v package_name="$package_name" '
            $1 == package_name { print $2 }
        ' <<<"$dependency_tree" | sort -u
    )
    if [ "${#versions[@]}" -ne 1 ] || [ "${versions[0]}" != "$expected_version" ]; then
        echo "::error::$package_name must resolve exactly once at $expected_version; found: ${versions[*]:-none}."
        exit 1
    fi
}

require_single_version log v0.4.33
require_single_version rustls-webpki v0.103.14
require_single_version aws-lc-rs v1.16.3

log_features="$(cargo tree --workspace --locked -e features -i log@0.4.33)"
for required_feature in max_level_debug release_max_level_info; do
    if ! grep -Fq "log feature \"$required_feature\"" <<<"$log_features"; then
        echo "::error::log feature '$required_feature' is required to compile dependency trace logging out."
        exit 1
    fi
done
if grep -Eq 'log feature "(release_)?max_level_trace"' <<<"$log_features"; then
    echo '::error::Trace-level log features can disclose relay credentials or payloads.'
    exit 1
fi

echo 'Rust security dependency policy passed.'
