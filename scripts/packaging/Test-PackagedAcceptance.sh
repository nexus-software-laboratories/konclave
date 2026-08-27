#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 4 ]; then
    echo 'Usage: Test-PackagedAcceptance.sh <client-tar.gz> <relay-tar.gz> <container-docker.tar> <image-reference>' >&2
    exit 2
fi

: "${GITHUB_WORKSPACE:?GITHUB_WORKSPACE is required.}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required.}"

workspace_root="$(realpath -e -- "$GITHUB_WORKSPACE")"
# shellcheck source=scripts/ci/container-image.lib.sh
. "$workspace_root/scripts/ci/container-image.lib.sh"
# shellcheck source=scripts/ci/container-validation.lib.sh
. "$workspace_root/scripts/ci/container-validation.lib.sh"

client_archive="$(realpath -e -- "$1")"
relay_archive="$(realpath -e -- "$2")"
container_archive="$(realpath -e -- "$3")"
image_reference="$(container_image_release_reference 'konclave-community-relay' "$4")"
acceptance_root="$(mktemp -d "$RUNNER_TEMP/konclave-acceptance-XXXXXXXX")"
harness_target="$acceptance_root/harness-target"
native_relay_pid=''
proxy_pid=''
container_name=''
container_run_identity=''
container_baseline=''
image_loaded=false
loaded_image_id=''

terminate_process() {
    local process_id="$1"
    if [ -n "$process_id" ] && kill -0 "$process_id" 2>/dev/null; then
        kill -TERM "$process_id" 2>/dev/null || true
        for _ in $(seq 1 40); do
            if ! kill -0 "$process_id" 2>/dev/null; then
                wait "$process_id" 2>/dev/null || true
                return 0
            fi
            sleep 0.1
        done
        kill -KILL "$process_id" 2>/dev/null || true
        wait "$process_id" 2>/dev/null || true
    fi
}

cleanup() {
    local status="$?"
    local cleanup_failed=0
    trap - EXIT
    set +e
    terminate_process "$proxy_pid"
    terminate_process "$native_relay_pid"
    if [ -n "$container_run_identity" ]; then
        container_validation_remove_owned "$container_run_identity" || cleanup_failed=1
        container_validation_assert_no_residue "$container_run_identity" || cleanup_failed=1
    fi
    if [ "$image_loaded" = true ]; then
        docker image rm --force "$loaded_image_id" >/dev/null 2>&1 || cleanup_failed=1
        docker image inspect "$loaded_image_id" >/dev/null 2>&1 && cleanup_failed=1
    fi
    if [ -n "$container_baseline" ] && [ -f "$container_baseline" ]; then
        container_validation_assert_baseline_intact "$container_baseline" || cleanup_failed=1
    fi
    rm -rf -- "$acceptance_root"
    if [ "$status" -eq 0 ] && [ "$cleanup_failed" -ne 0 ]; then
        status=1
    fi
    exit "$status"
}
trap cleanup EXIT

extract_single_root() {
    local archive="$1"
    local destination="$2"
    local roots
    mkdir -p "$destination"
    tar -xzf "$archive" -C "$destination"
    mapfile -t roots < <(find "$destination" -mindepth 1 -maxdepth 1 -type d -print)
    if [ "${#roots[@]}" -ne 1 ]; then
        echo "::error::Archive does not contain exactly one root: $archive" >&2
        return 1
    fi
    realpath -e -- "${roots[0]}"
}

free_port() {
    python3 -c \
        'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}

wait_for_health() {
    local endpoint="$1"
    for _ in $(seq 1 120); do
        if curl --fail --silent --show-error --cacert "$acceptance_root/tls/ca.crt" \
            "$endpoint/healthz" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.25
    done
    echo "::error::Relay health endpoint never became ready: $endpoint" >&2
    return 1
}

assert_anonymous_rejected() {
    local endpoint="$1"
    local status
    status="$(
        curl \
            --silent \
            --show-error \
            --cacert "$acceptance_root/tls/ca.crt" \
            --output /dev/null \
            --write-out '%{http_code}' \
            --request POST \
            --header 'Content-Type: application/protobuf' \
            --data-binary '' \
            "$endpoint/v1/replay"
    )"
    if [ "$status" != '401' ]; then
        echo "::error::Anonymous relay replay returned HTTP $status." >&2
        return 1
    fi
}

start_tls_proxy() {
    local upstream_port="$1"
    local listen_port="$2"
    local log_path="$3"
    KONCLAVE_TLS_UPSTREAM_PORT="$upstream_port" \
    KONCLAVE_TLS_LISTEN_PORT="$listen_port" \
    KONCLAVE_TLS_CERT_FILE="$acceptance_root/tls/server.crt" \
    KONCLAVE_TLS_KEY_FILE="$acceptance_root/tls/server.key" \
        node "$workspace_root/apps/Konclave.LocalDaemon/tests/packaged-tls-proxy.mjs" \
        >"$log_path" 2>&1 &
    proxy_pid="$!"
}

prepare_state() {
    local mode="$1"
    local endpoint="$2"
    local state_root="$acceptance_root/state-$mode"
    mkdir -p "$state_root/relay" "$state_root/profile-keys"
    chmod 0700 "$state_root/profile-keys"
    "$client_root_a/bin/konclave" relay-bootstrap \
        --relay-endpoint "$endpoint" \
        --access-document "$state_root/access.json" \
        --external-source "$state_root/enrollment.credential" \
        >"$state_root/bootstrap.log"
    printf '%s\n' "$state_root"
}

run_harness() {
    local state_root="$1"
    local endpoint="$2"
    SSL_CERT_FILE="$acceptance_root/tls/ca.crt" \
    CARGO_TARGET_DIR="$harness_target" \
    KONCLAVE_ACCEPTANCE_CLI="$client_root_a/bin/konclave" \
    KONCLAVE_ACCEPTANCE_SERVICE="$client_root_a/bin/KonclaveLocalService" \
    KONCLAVE_ACCEPTANCE_SECOND_SERVICE="$client_root_b/bin/KonclaveLocalService" \
    KONCLAVE_ACCEPTANCE_CLIENT_MODULE="$client_root_a/share/konclave/plugin/extensions/Konclave.Extension/client.mjs" \
    KONCLAVE_ACCEPTANCE_GENERIC_MODULE="$client_root_a/share/konclave/plugin/extensions/Konclave.Extension/generic.mjs" \
    KONCLAVE_ACCEPTANCE_GENERIC_SKILL="$client_root_a/share/konclave/plugin/skills/konclave-generic/SKILL.md" \
    KONCLAVE_ACCEPTANCE_INSTALL_ROOT="$client_root_a" \
    KONCLAVE_ACCEPTANCE_RELAY_ENDPOINT="$endpoint" \
    KONCLAVE_ACCEPTANCE_ACCESS_DOCUMENT="$state_root/access.json" \
    KONCLAVE_ACCEPTANCE_ENROLLMENT_SOURCE="$state_root/enrollment.credential" \
    KONCLAVE_ACCEPTANCE_PROFILE_ROOT="$state_root/profiles" \
    KONCLAVE_ACCEPTANCE_PROFILE_KEYS="$state_root/profile-keys" \
    KONCLAVE_ACCEPTANCE_SERVICE_IDENTITY="$state_root/service/identity.key" \
    KONCLAVE_ACCEPTANCE_EXTENSION_ROOT="$state_root/extension" \
    KONCLAVE_ACCEPTANCE_RELAY_STATE="$state_root/relay" \
    KONCLAVE_ACCEPTANCE_RELAY_DATABASE="$state_root/relay/relay.sqlite" \
        cargo test \
            --manifest-path "$workspace_root/Cargo.toml" \
            -p KonclaveLocalDaemon \
            --test packaged_distribution_e2e \
            -- \
            --ignored \
            --nocapture
}

assert_untrusted_tls_rejected() {
    local state_root="$1"
    local endpoint="$2"
    local untrusted_root="$state_root/untrusted"
    local profile_root="$untrusted_root/profiles"
    local extension_root="$untrusted_root/extension"
    local identity_file="$untrusted_root/service/identity.key"
    local profile_keys="$untrusted_root/profile-keys"
    "$client_root_a/bin/konclave" init \
        --relay-endpoint "$endpoint" \
        --authorization-policy account-trusted \
        --profile-root "$profile_root" \
        --external-source "$state_root/enrollment.credential" \
        --copilot-extension-root "$extension_root" \
        --local-service-identity-file "$identity_file" \
        --local-service-profile-key-directory "$profile_keys" \
        >"$state_root/untrusted-init.log"
    if "$client_root_a/bin/konclave" doctor \
        --profile-root "$profile_root" \
        --install-root "$client_root_a" \
        >"$state_root/untrusted-doctor.log" 2>&1; then
        echo '::error::Doctor accepted a relay certificate outside the system trust store.' >&2
        return 1
    fi
    if ! grep -Fq 'FAIL relay_reachable:' "$state_root/untrusted-doctor.log"; then
        echo '::error::Untrusted TLS probe failed for a reason other than relay trust.' >&2
        return 1
    fi
}

mkdir -p "$acceptance_root/tls"
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$acceptance_root/tls/ca.key" \
    -out "$acceptance_root/tls/ca.crt" \
    -days 1 \
    -subj '/CN=Konclave Acceptance CA' >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
    -keyout "$acceptance_root/tls/server.key" \
    -out "$acceptance_root/tls/server.csr" \
    -subj '/CN=localhost' >/dev/null 2>&1
printf '%s\n' \
    'subjectAltName=DNS:localhost,IP:127.0.0.1' \
    'extendedKeyUsage=serverAuth' >"$acceptance_root/tls/server.ext"
openssl x509 -req \
    -in "$acceptance_root/tls/server.csr" \
    -CA "$acceptance_root/tls/ca.crt" \
    -CAkey "$acceptance_root/tls/ca.key" \
    -CAcreateserial \
    -out "$acceptance_root/tls/server.crt" \
    -days 1 \
    -extfile "$acceptance_root/tls/server.ext" >/dev/null 2>&1

client_root_a="$(extract_single_root "$client_archive" "$acceptance_root/client-a")"
client_root_b="$(extract_single_root "$client_archive" "$acceptance_root/client-b")"
relay_root="$(extract_single_root "$relay_archive" "$acceptance_root/relay-install")"
for root in "$client_root_a" "$client_root_b" "$relay_root"; do
    test -f "$root/UNSIGNED-PRERELEASE.txt"
done

native_http_port="$(free_port)"
native_tls_port="$(free_port)"
native_endpoint="https://localhost:$native_tls_port"
native_state="$(prepare_state native "$native_endpoint")"
SERVICE_HTTP_ADDRESS="127.0.0.1:$native_http_port" \
SERVICE_HEALTH_ADDRESS="127.0.0.1:$native_http_port" \
KONCLAVE_RELAY_ACCESS_FILE="$native_state/access.json" \
KONCLAVE_RELAY_DATABASE_PATH="$native_state/relay/relay.sqlite" \
    "$relay_root/bin/KonclaveCommunityRelay" \
    >"$native_state/relay/relay.log" 2>&1 &
native_relay_pid="$!"
start_tls_proxy "$native_http_port" "$native_tls_port" "$native_state/relay/tls-proxy.log"
wait_for_health "$native_endpoint"
assert_anonymous_rejected "$native_endpoint"
assert_untrusted_tls_rejected "$native_state" "$native_endpoint"
run_harness "$native_state" "$native_endpoint"
terminate_process "$proxy_pid"
proxy_pid=''
terminate_process "$native_relay_pid"
native_relay_pid=''

if docker image inspect "$image_reference" >/dev/null 2>&1; then
    echo "::error::Acceptance runner already contains $image_reference." >&2
    exit 1
fi
container_run_identity="$(container_validation_run_identity)"
container_baseline="$acceptance_root/docker-baseline.tsv"
container_validation_capture_baseline "$container_baseline"
docker image load --input "$container_archive" >/dev/null
image_loaded=true
loaded_image_id="$(docker image inspect --format '{{.Id}}' "$image_reference")"

container_http_port="$(free_port)"
container_tls_port="$(free_port)"
container_endpoint="https://localhost:$container_tls_port"
container_state="$(prepare_state container "$container_endpoint")"
chmod 0777 "$container_state/relay"
chmod 0644 "$container_state/access.json"
container_name="konclave-acceptance-$container_run_identity"
docker run --detach \
    --name "$container_name" \
    --label "${CONTAINER_VALIDATION_OWNER_LABEL}=${container_run_identity}" \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --publish "127.0.0.1:${container_http_port}:8080" \
    --env SERVICE_HTTP_ADDRESS=0.0.0.0:8080 \
    --env SERVICE_HEALTH_ADDRESS=127.0.0.1:8080 \
    --env KONCLAVE_RELAY_ACCESS_FILE=/run/secrets/konclave-relay-access.json \
    --env KONCLAVE_RELAY_DATABASE_PATH=/var/lib/konclave/relay.sqlite \
    --env KONCLAVE_RELAY_TLS_TERMINATED=true \
    --mount "type=bind,source=$container_state/access.json,target=/run/secrets/konclave-relay-access.json,readonly" \
    --mount "type=bind,source=$container_state/relay,target=/var/lib/konclave" \
    --tmpfs /tmp \
    "$image_reference" >/dev/null
start_tls_proxy \
    "$container_http_port" \
    "$container_tls_port" \
    "$container_state/relay/tls-proxy.log"
wait_for_health "$container_endpoint"
assert_anonymous_rejected "$container_endpoint"
run_harness "$container_state" "$container_endpoint"
terminate_process "$proxy_pid"
proxy_pid=''
container_validation_remove_owned "$container_run_identity"
container_validation_assert_no_residue "$container_run_identity"
container_name=''
docker image rm --force "$loaded_image_id" >/dev/null
if docker image inspect "$loaded_image_id" >/dev/null 2>&1; then
    echo '::error::Acceptance image remained after exact removal.' >&2
    exit 1
fi
image_loaded=false
container_validation_assert_baseline_intact "$container_baseline"

native_profiles="$(find "$native_state/profiles" -name profile.sqlite -type f | wc -l)"
container_profiles="$(find "$container_state/profiles" -name profile.sqlite -type f | wc -l)"
if [ "$native_profiles" -ne 2 ] || [ "$container_profiles" -ne 2 ]; then
    echo '::error::Packaged sessions did not preserve two profile databases per relay mode.' >&2
    exit 1
fi

rm -rf -- "$acceptance_root/client-a" "$acceptance_root/client-b" "$acceptance_root/relay-install"
if [ ! -f "$native_state/profiles/session-packaged-a/profile.sqlite" ] ||
    [ ! -f "$container_state/profiles/session-packaged-b/profile.sqlite" ]; then
    echo '::error::Removing installed artifacts also removed durable profile state.' >&2
    exit 1
fi

echo 'Packaged native and container acceptance passed with exact cleanup.'
