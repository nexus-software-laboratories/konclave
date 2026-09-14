#!/usr/bin/env bash
set -euo pipefail

copilot_command="${1:?Copilot command is required.}"
expected_cli_version="${2:?Copilot CLI version is required.}"
plugin_archive="${3:?Agent Plugin archive is required.}"

test_root="$(mktemp -d)"
silent_pid=''
cleanup() {
    if [ -n "$silent_pid" ] && kill -0 "$silent_pid" 2>/dev/null; then
        kill "$silent_pid"
        wait "$silent_pid" 2>/dev/null || true
    fi
    rm -rf -- "$test_root"
}
trap cleanup EXIT

export COPILOT_HOME="$test_root/copilot-home"
mkdir -p "$COPILOT_HOME" "$test_root/plugin" "$test_root/workspace" "$test_root/config"
unzip -q "$plugin_archive" -d "$test_root/plugin"

"$copilot_command" --version | grep -F "$expected_cli_version"
set +e
install_output="$("$copilot_command" plugin install "$test_root/plugin" 2>&1)"
install_status=$?
set -e
printf '%s\n' "$install_output"
if [ "$install_status" -ne 0 ]; then
    echo 'Direct Agent Plugin installation failed.' >&2
    exit "$install_status"
fi
if [ "$(printf '%s\n' "$install_output" | grep -Eio 'deprecat(ed|ion)' | wc -l)" -ne 1 ]; then
    echo 'Expected one direct-install deprecation notice.' >&2
    exit 1
fi

supports_json=false
if "$copilot_command" plugin list --help | grep -q -- '--json'; then
    supports_json=true
    plugin_list="$("$copilot_command" plugin list --json)"
    if [ "$(jq '[.. | objects | select(.name? == "konclave")] | length' <<<"$plugin_list")" -ne 1 ]; then
        echo 'Expected exactly one installed Konclave plugin.' >&2
        exit 1
    fi
else
    plugin_list="$("$copilot_command" plugin list)"
    if [ "$(grep -Eic '(^|[^a-z0-9-])konclave([^a-z0-9-]|$)' <<<"$plugin_list")" -ne 1 ]; then
        echo 'Expected one textual Konclave plugin listing.' >&2
        exit 1
    fi
fi
mapfile -d '' manifests < <(find "$COPILOT_HOME" -type f -name plugin.json -print0)
konclave_roots=()
for manifest in "${manifests[@]}"; do
    if jq -e '.name == "konclave"' "$manifest" >/dev/null; then
        konclave_roots+=("$(dirname "$manifest")")
    fi
done
if [ "${#konclave_roots[@]}" -ne 1 ]; then
    echo 'Expected one cached Konclave plugin root.' >&2
    exit 1
fi
cache_root="${konclave_roots[0]}"
find "$cache_root" -type f -printf '%P\n' | sort >"$test_root/actual-plugin-files"
cat >"$test_root/expected-plugin-files" <<'EOF'
com.github.copilot/extensions/konclave/extension.mjs
com.github.copilot/extensions/konclave/package.json
plugin.json
EOF
diff -u "$test_root/expected-plugin-files" "$test_root/actual-plugin-files"

issuer_key="$test_root/config/account-issuer.key"
head -c 32 /dev/zero >"$issuer_key"
chmod 0600 "$issuer_key"

write_config() {
    local endpoint="$1"
    local evidence="$2"
    jq -n \
        --arg endpoint "$endpoint" \
        --arg issuer_key "$issuer_key" \
        --arg evidence "$evidence" \
        '{
          schemaVersion: 2,
          endpoint: $endpoint,
          issuerKeyId: ("22" * 16),
          issuerKeyVersion: 1,
          harness: "copilot",
          serviceKey: ("11" * 32),
          issuerKeyFile: $issuer_key,
          authorizationPolicy: {
            version: 1,
            acceptedEvidence: [[$evidence]]
          }
        }' >"$test_root/config/konclave.service.json"
    chmod 0600 "$test_root/config/konclave.service.json"
}

run_prompt_probe() {
    local scenario="$1"
    local transcript="$test_root/$scenario.transcript"
    local started elapsed status command
    local args=(
        "$copilot_command"
        --no-auto-update
        --no-auto-login
        --no-ask-user
        --no-custom-instructions
        --disable-builtin-mcps
        --no-remote
        --no-color
        --screen-reader
        --log-level error
        -C "$test_root/workspace"
    )
    printf -v command '%q ' "${args[@]}"
    started="$(date +%s%3N)"
    set +e
    printf '/exit\n' |
        KONCLAVE_SERVICE_CONFIG_FILE="$test_root/config/konclave.service.json" \
        timeout 8s script --quiet --return --command "$command" "$transcript" \
            >"$test_root/$scenario.stdout" 2>"$test_root/$scenario.stderr"
    status=$?
    set -e
    elapsed="$(( $(date +%s%3N) - started ))"
    if [ "$status" -ne 0 ]; then
        cat "$test_root/$scenario.stdout" >&2
        cat "$test_root/$scenario.stderr" >&2
        echo "$scenario did not reach and exit a usable prompt." >&2
        exit 1
    fi
    if [ "$elapsed" -ge 7000 ]; then
        echo "$scenario exceeded the 7-second prompt budget: ${elapsed}ms." >&2
        exit 1
    fi
    printf '%s=%sms\n' "$scenario" "$elapsed"
}

absent_socket="$test_root/config/absent.sock"
write_config "$absent_socket" account_trusted
run_prompt_probe absent-service

silent_socket="$test_root/config/silent.sock"
node -e '
  const fs = require("node:fs");
  const net = require("node:net");
  const path = process.argv[1];
  try { fs.unlinkSync(path); } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  const sockets = new Set();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  server.listen(path);
  const close = () => {
    for (const socket of sockets) socket.destroy();
    server.close(() => process.exit(0));
  };
  process.on("SIGTERM", close);
  process.on("SIGINT", close);
' "$silent_socket" &
silent_pid="$!"
for _ in $(seq 1 50); do
    [ -S "$silent_socket" ] && break
    sleep 0.1
done
if [ ! -S "$silent_socket" ]; then
    echo 'Silent service fixture did not start.' >&2
    exit 1
fi
write_config "$silent_socket" account_trusted
run_prompt_probe silent-service
kill "$silent_pid"
wait "$silent_pid"
silent_pid=''

write_config "$absent_socket" user_presence
run_prompt_probe unavailable-policy

"$copilot_command" plugin uninstall konclave
if [ "$supports_json" = true ]; then
    if "$copilot_command" plugin list --json |
        jq -e '.. | objects | select(.name? == "konclave")' >/dev/null
    then
        echo 'Konclave plugin remained after uninstall.' >&2
        exit 1
    fi
elif "$copilot_command" plugin list |
    grep -Eiq '(^|[^a-z0-9-])konclave([^a-z0-9-]|$)'
then
    echo 'Konclave plugin remained after uninstall.' >&2
    exit 1
fi
if find "$COPILOT_HOME" -type f -name plugin.json -exec \
    jq -e 'select(.name == "konclave")' {} \; | grep -q .
then
    echo 'Konclave cache remained after uninstall.' >&2
    exit 1
fi
if pgrep -f 'KonclaveLocalDaemon|KonclaveLocalService' >/dev/null 2>&1; then
    echo 'Copilot lifecycle launched a native Konclave process.' >&2
    exit 1
fi

printf 'Copilot CLI %s plugin lifecycle passed.\n' "$expected_cli_version"
