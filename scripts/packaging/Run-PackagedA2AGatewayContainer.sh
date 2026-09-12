#!/usr/bin/env bash
set -euo pipefail

: "${KONCLAVE_A2A_GATEWAY_CONFIG_FILE:?KONCLAVE_A2A_GATEWAY_CONFIG_FILE is required.}"
: "${KONCLAVE_ACCEPTANCE_GATEWAY_IMAGE:?KONCLAVE_ACCEPTANCE_GATEWAY_IMAGE is required.}"
: "${KONCLAVE_ACCEPTANCE_GATEWAY_CONTAINER_NAME:?KONCLAVE_ACCEPTANCE_GATEWAY_CONTAINER_NAME is required.}"
: "${KONCLAVE_ACCEPTANCE_CONTAINER_RUN_ID:?KONCLAVE_ACCEPTANCE_CONTAINER_RUN_ID is required.}"
: "${KONCLAVE_ACCEPTANCE_GATEWAY_CONFIG_ROOT:?KONCLAVE_ACCEPTANCE_GATEWAY_CONFIG_ROOT is required.}"
: "${KONCLAVE_ACCEPTANCE_GATEWAY_CREDENTIAL_ROOT:?KONCLAVE_ACCEPTANCE_GATEWAY_CREDENTIAL_ROOT is required.}"
: "${KONCLAVE_ACCEPTANCE_GATEWAY_SOCKET_ROOT:?KONCLAVE_ACCEPTANCE_GATEWAY_SOCKET_ROOT is required.}"
: "${KONCLAVE_ACCEPTANCE_GATEWAY_TASK_ROOT:?KONCLAVE_ACCEPTANCE_GATEWAY_TASK_ROOT is required.}"
: "${KONCLAVE_ACCEPTANCE_GATEWAY_OBJECT_ROOT:?KONCLAVE_ACCEPTANCE_GATEWAY_OBJECT_ROOT is required.}"
: "${KONCLAVE_ACCEPTANCE_GATEWAY_HEALTH_ADDRESS:?KONCLAVE_ACCEPTANCE_GATEWAY_HEALTH_ADDRESS is required.}"

require_absolute_mount() {
    local name="$1"
    local value="$2"
    case "$value" in
        /*) ;;
        *)
            echo "$name must be an absolute Linux path." >&2
            exit 2
            ;;
    esac
    if [[ "$value" == *','* || "$value" == *$'\n'* || "$value" == *$'\r'* ]]; then
        echo "$name contains an unsupported mount character." >&2
        exit 2
    fi
}

for entry in \
    "configuration:$KONCLAVE_ACCEPTANCE_GATEWAY_CONFIG_ROOT" \
    "credentials:$KONCLAVE_ACCEPTANCE_GATEWAY_CREDENTIAL_ROOT" \
    "socket:$KONCLAVE_ACCEPTANCE_GATEWAY_SOCKET_ROOT" \
    "tasks:$KONCLAVE_ACCEPTANCE_GATEWAY_TASK_ROOT" \
    "objects:$KONCLAVE_ACCEPTANCE_GATEWAY_OBJECT_ROOT"
do
    require_absolute_mount "${entry%%:*}" "${entry#*:}"
done

if [[ ! "$KONCLAVE_ACCEPTANCE_GATEWAY_IMAGE" =~ ^konclave-a2a-gateway:[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$ ]]; then
    echo 'Gateway image reference is invalid.' >&2
    exit 2
fi
if [[ ! "$KONCLAVE_ACCEPTANCE_GATEWAY_CONTAINER_NAME" =~ ^[a-z0-9][a-z0-9_.-]{0,127}$ ]]; then
    echo 'Gateway container name is invalid.' >&2
    exit 2
fi
if [[ ! "$KONCLAVE_ACCEPTANCE_CONTAINER_RUN_ID" =~ ^[A-Za-z0-9._-]{1,128}$ ]]; then
    echo 'Container validation identity is invalid.' >&2
    exit 2
fi

runtime_uid="$(id -u)"
runtime_gid="$(id -g)"
if [ "$runtime_uid" -eq 0 ]; then
    echo 'Packaged gateway container acceptance requires a non-root host account.' >&2
    exit 2
fi

exec docker run --rm \
    --name "$KONCLAVE_ACCEPTANCE_GATEWAY_CONTAINER_NAME" \
    --label "dev.konclave.validation.run=$KONCLAVE_ACCEPTANCE_CONTAINER_RUN_ID" \
    --network host \
    --user "$runtime_uid:$runtime_gid" \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --pids-limit 256 \
    --env "KONCLAVE_A2A_GATEWAY_CONFIG_FILE=$KONCLAVE_A2A_GATEWAY_CONFIG_FILE" \
    --env "SERVICE_HEALTH_ADDRESS=$KONCLAVE_ACCEPTANCE_GATEWAY_HEALTH_ADDRESS" \
    --mount "type=bind,source=$KONCLAVE_ACCEPTANCE_GATEWAY_CONFIG_ROOT,target=/etc/konclave/a2a,readonly" \
    --mount "type=bind,source=$KONCLAVE_ACCEPTANCE_GATEWAY_CREDENTIAL_ROOT,target=/run/konclave/credentials,readonly" \
    --mount "type=bind,source=$KONCLAVE_ACCEPTANCE_GATEWAY_SOCKET_ROOT,target=$KONCLAVE_ACCEPTANCE_GATEWAY_SOCKET_ROOT,readonly" \
    --mount "type=bind,source=$KONCLAVE_ACCEPTANCE_GATEWAY_TASK_ROOT,target=/var/lib/konclave/a2a/tasks" \
    --mount "type=bind,source=$KONCLAVE_ACCEPTANCE_GATEWAY_OBJECT_ROOT,target=/var/lib/konclave/a2a/objects" \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16777216 \
    "$KONCLAVE_ACCEPTANCE_GATEWAY_IMAGE"
