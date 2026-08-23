#!/usr/bin/env bash
set -euo pipefail

# Removes the self-hosted BuildKit backend's job-private state.
#
# Cleanup is unconditional because the decoded client key material is job-private, so
# it must not survive the job even when validation failed.

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

bash "$script_directory/Cleanup-JobPrivatePaths.sh" \
    BUILDKIT_TLS_DIR \
    CONTAINER_VALIDATION_ROOT
