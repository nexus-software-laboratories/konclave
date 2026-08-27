#!/usr/bin/env bash
set -euo pipefail

action="${1:-install}"
install_root="${2:-/usr/local/libexec/konclave}"
config_path="${3:-$HOME/Library/Application Support/Konclave/service/konclave-local-service.json}"
label='com.genesis.KonclaveLocalService'
agent_root="$HOME/Library/LaunchAgents"
agent_path="$agent_root/$label.plist"
domain="gui/$(id -u)"

render_agent() {
    local content binary config
    if [[ "$install_root$config_path" == *$'\n'* ||
        "$install_root$config_path" == *$'\r'* ]]; then
        echo 'Service paths contain unsupported launchd control characters.' >&2
        return 1
    fi
    xml_escape() {
        local value="$1"
        value="${value//&/&amp;}"
        value="${value//</&lt;}"
        value="${value//>/&gt;}"
        value="${value//\"/&quot;}"
        value="${value//\'/&apos;}"
        printf '%s' "$value"
    }
    binary="$(xml_escape "$install_root/bin/KonclaveLocalService")"
    config="$(xml_escape "$config_path")"
    content="$(<"$(dirname "$0")/$label.plist")"
    content="${content//@SERVICE_BINARY@/$binary}"
    content="${content//@SERVICE_CONFIG@/$config}"
    printf '%s\n' "$content"
}

install_agent() {
    test -x "$install_root/bin/KonclaveLocalService"
    test -f "$config_path"
    mkdir -p "$agent_root"
    temporary="$(mktemp "$agent_root/.${label}.XXXXXXXX")"
    trap 'rm -f -- "${temporary:-}"' EXIT
    render_agent >"$temporary"
    chmod 0600 "$temporary"
    if [ -e "$agent_path" ] && ! cmp --silent "$temporary" "$agent_path"; then
        echo "Conflicting launch agent already exists: $agent_path" >&2
        return 1
    fi
    if [ ! -e "$agent_path" ]; then
        mv -- "$temporary" "$agent_path"
    fi
    # Replacement tolerates an agent that has not been bootstrapped yet.
    launchctl bootout "$domain/$label" 2>/dev/null || true
    launchctl bootstrap "$domain" "$agent_path"
    launchctl enable "$domain/$label"
}

remove_agent() {
    if [ ! -e "$agent_path" ]; then
        return 0
    fi
    temporary="$(mktemp "$agent_root/.${label}.XXXXXXXX")"
    trap 'rm -f -- "${temporary:-}"' EXIT
    render_agent >"$temporary"
    if ! cmp --silent "$temporary" "$agent_path"; then
        echo "Refusing to remove conflicting launch agent: $agent_path" >&2
        return 1
    fi
    # Idempotent uninstall tolerates an already unloaded agent.
    launchctl bootout "$domain/$label" 2>/dev/null || true
    rm -f -- "$agent_path"
}

case "$action" in
    install) install_agent ;;
    render) render_agent ;;
    start) launchctl kickstart "$domain/$label" ;;
    stop) launchctl kill SIGTERM "$domain/$label" ;;
    status) launchctl print "$domain/$label" ;;
    uninstall) remove_agent ;;
    *)
        echo 'Usage: manage-agent.sh [install|render|start|stop|status|uninstall] [install-root] [config-path]' >&2
        exit 2
        ;;
esac
