#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo 'Usage: Test-A2AGatewayContainerContract.sh <expected-image>' >&2
    exit 2
fi

expected_image="$1"
project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
application_root="$project_root/apps/Konclave.A2AGateway"
compose_file="$application_root/compose.example.yaml"
config_file="$application_root/gateway-config.container.json"

if ! grep -Fxq '    stop_grace_period: 90s' "$compose_file"; then
    echo '::error::A2A gateway Compose shutdown grace is not 90 seconds.' >&2
    exit 1
fi

compose_json="$(
    KONCLAVE_GATEWAY_UID=10001 \
    KONCLAVE_GATEWAY_GID=10001 \
    KONCLAVE_GATEWAY_PORT=8090 \
    KONCLAVE_GATEWAY_CONFIG_ROOT=/tmp/konclave-a2a-config \
    KONCLAVE_GATEWAY_CREDENTIAL_ROOT=/tmp/konclave-a2a-credentials \
    KONCLAVE_LOCAL_SERVICE_SOCKET_ROOT=/run/user/1000/konclave \
    KONCLAVE_GATEWAY_TASK_ROOT=/tmp/konclave-a2a-tasks \
    KONCLAVE_GATEWAY_OBJECT_ROOT=/tmp/konclave-a2a-objects \
        docker compose --file "$compose_file" config --format json
)"

if ! jq -e \
    --arg image "$expected_image" \
    '
      .services.gateway as $gateway
      | $gateway.image == $image
        and $gateway.pull_policy == "never"
        and $gateway.restart == "unless-stopped"
        and $gateway.init == true
        and $gateway.user == "10001:10001"
        and $gateway.read_only == true
        and ($gateway.cap_drop | index("ALL")) != null
        and ($gateway.security_opt | index("no-new-privileges:true")) != null
        and $gateway.pids_limit == 256
        and ($gateway.privileged // false) == false
        and ($gateway.network_mode // "") != "host"
        and ($gateway.ports | length) == 1
        and $gateway.ports[0].host_ip == "127.0.0.1"
        and ($gateway.ports[0].target | tostring) == "8090"
        and ($gateway.ports[0].published | tostring) == "8090"
        and (
          $gateway.environment
          | keys
          | sort
        ) == [
          "KONCLAVE_A2A_GATEWAY_CONFIG_FILE",
          "SERVICE_HEALTH_ADDRESS"
        ]
        and (
          $gateway.volumes
          | map(select(.type == "bind"))
          | map({
              target,
              read_only: (.read_only // false),
              create_host_path: (.bind.create_host_path // false)
            })
          | sort_by(.target)
        ) == [
          {"target":"/etc/konclave/a2a","read_only":true,"create_host_path":false},
          {"target":"/run/konclave/credentials","read_only":true,"create_host_path":false},
          {"target":"/run/user/1000/konclave","read_only":true,"create_host_path":false},
          {"target":"/var/lib/konclave/a2a/objects","read_only":false,"create_host_path":false},
          {"target":"/var/lib/konclave/a2a/tasks","read_only":false,"create_host_path":false}
        ]
    ' <<<"$compose_json" >/dev/null
then
    echo '::error::A2A gateway Compose security contract failed.' >&2
    jq -c '
      .services.gateway
      | {
          image,
          pull_policy,
          restart,
          init,
          user,
          read_only,
          cap_drop,
          security_opt,
          pids_limit,
          privileged,
          network_mode,
          ports,
          environment,
          volumes
        }
    ' <<<"$compose_json" >&2
    exit 1
fi

if ! jq -e '
    .schemaVersion == 1
    and .interfaceEnvironment == "production"
    and .listener.address == "0.0.0.0:8090"
    and .listener.tlsTerminated == true
    and .publicationFile == "/etc/konclave/a2a/agent-publication.json"
    and .taskDatabaseFile == "/var/lib/konclave/a2a/tasks/tasks.sqlite"
    and .artifactObjectDirectory == "/var/lib/konclave/a2a/objects"
    and .localService.installationFile == "/run/konclave/credentials/konclave-local-service.json"
    and .localService.issuerKeyFile == "/run/konclave/credentials/account-issuer.key"
    and .bearerTokenFiles == ["/run/konclave/credentials/a2a-bearer"]
' "$config_file" >/dev/null
then
    echo '::error::A2A gateway container configuration contract failed.' >&2
    exit 1
fi

echo 'A2A gateway Compose and container configuration contract passed.'
