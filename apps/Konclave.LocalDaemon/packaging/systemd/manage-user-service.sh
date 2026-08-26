#!/usr/bin/env bash
set -euo pipefail

action="${1:-install}"
install_root="${2:-/opt/konclave}"
config_path="${3:-$HOME/.local/share/konclave/service/konclave-local-service.json}"
unit_name='KonclaveLocalService.service'
unit_root="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
unit_path="$unit_root/$unit_name"

render_unit() {
    local content combined
    combined="$install_root$config_path"
    if [[ "$combined" == *$'\n'* || "$combined" == *$'\r'* ||
        "$combined" == *'"'* || "$combined" == *'$'* || "$combined" == *'\'* ]]; then
        echo 'Service paths contain unsupported systemd quoting characters.' >&2
        return 1
    fi
    content="$(<"$(dirname "$0")/$unit_name")"
    content="${content//@SERVICE_BINARY@/$install_root/bin/KonclaveLocalService}"
    content="${content//@SERVICE_CONFIG@/$config_path}"
    printf '%s\n' "$content"
}

install_unit() {
    test -x "$install_root/bin/KonclaveLocalService"
    test -f "$config_path"
    mkdir -p "$unit_root"
    temporary="$(mktemp "$unit_root/.${unit_name}.XXXXXXXX")"
    trap 'rm -f -- "${temporary:-}"' EXIT
    render_unit >"$temporary"
    chmod 0600 "$temporary"
    if [ -e "$unit_path" ] && ! cmp --silent "$temporary" "$unit_path"; then
        echo "Conflicting user service already exists: $unit_path" >&2
        return 1
    fi
    if [ ! -e "$unit_path" ]; then
        mv -- "$temporary" "$unit_path"
    fi
    systemctl --user daemon-reload
    systemctl --user enable --now "$unit_name"
}

remove_unit() {
    if [ ! -e "$unit_path" ]; then
        return 0
    fi
    temporary="$(mktemp "$unit_root/.${unit_name}.XXXXXXXX")"
    trap 'rm -f -- "${temporary:-}"' EXIT
    render_unit >"$temporary"
    if ! cmp --silent "$temporary" "$unit_path"; then
        echo "Refusing to remove conflicting user service: $unit_path" >&2
        return 1
    fi
    # Idempotent uninstall tolerates an already inactive or unloaded unit.
    systemctl --user disable --now "$unit_name" 2>/dev/null || true
    rm -f -- "$unit_path"
    systemctl --user daemon-reload
}

case "$action" in
    install) install_unit ;;
    render) render_unit ;;
    start) systemctl --user start "$unit_name" ;;
    stop) systemctl --user stop "$unit_name" ;;
    status) systemctl --user --no-pager status "$unit_name" ;;
    uninstall) remove_unit ;;
    *)
        echo 'Usage: manage-user-service.sh [install|render|start|stop|status|uninstall] [install-root] [config-path]' >&2
        exit 2
        ;;
esac
