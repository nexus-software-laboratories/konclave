#!/usr/bin/env bash
set -euo pipefail

: "${RUNNER_TEMP:?RUNNER_TEMP is required.}"
: "${BUILDKIT_TLS_DIR:?BUILDKIT_TLS_DIR is required.}"
: "${CONTAINER_VALIDATION_ROOT:?CONTAINER_VALIDATION_ROOT is required.}"
: "${BUILDKIT_CLIENT_CA_PEM_B64:?BUILDKIT_CLIENT_CA_PEM_B64 is required.}"
: "${BUILDKIT_CLIENT_CERT_PEM_B64:?BUILDKIT_CLIENT_CERT_PEM_B64 is required.}"
: "${BUILDKIT_CLIENT_KEY_PEM_B64:?BUILDKIT_CLIENT_KEY_PEM_B64 is required.}"

runner_temp="$(realpath -m -- "$RUNNER_TEMP")"
for directory in "$BUILDKIT_TLS_DIR" "$CONTAINER_VALIDATION_ROOT"; do
    resolved="$(realpath -m -- "$directory")"
    case "$resolved" in
        "$runner_temp"/*) ;;
        *)
            echo '::error::Image-builder state must remain under RUNNER_TEMP.'
            exit 1
            ;;
    esac

    if [ -e "$resolved" ]; then
        echo '::error::Image-builder job state already exists.'
        exit 1
    fi
done

umask 077
install -d -m 0700 "$BUILDKIT_TLS_DIR" "$CONTAINER_VALIDATION_ROOT"

printf '%s' "$BUILDKIT_CLIENT_CA_PEM_B64" |
    base64 --decode > "$BUILDKIT_TLS_DIR/ca.pem"
printf '%s' "$BUILDKIT_CLIENT_CERT_PEM_B64" |
    base64 --decode > "$BUILDKIT_TLS_DIR/cert.pem"
printf '%s' "$BUILDKIT_CLIENT_KEY_PEM_B64" |
    base64 --decode > "$BUILDKIT_TLS_DIR/key.pem"

chmod 0600 \
    "$BUILDKIT_TLS_DIR/ca.pem" \
    "$BUILDKIT_TLS_DIR/cert.pem" \
    "$BUILDKIT_TLS_DIR/key.pem"

for certificate in ca.pem cert.pem key.pem; do
    if [ ! -s "$BUILDKIT_TLS_DIR/$certificate" ]; then
        echo '::error::A BuildKit client credential decoded to an empty file.'
        exit 1
    fi
done
