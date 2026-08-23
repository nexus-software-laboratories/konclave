#!/usr/bin/env bash
set -euo pipefail

# Declares the job-private directories the self-hosted BuildKit backend needs.
#
# The backend keeps a named entry point so operators wire one command, while the
# containment rules stay in the shared path helper.

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

bash "$script_directory/Initialize-JobPrivatePaths.sh" \
    BUILDKIT_TLS_DIR=buildkit-tls \
    CONTAINER_VALIDATION_ROOT=konclave-container-validation
