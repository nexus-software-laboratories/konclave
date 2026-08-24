#!/usr/bin/env bash
set -euo pipefail

# Removes exactly the Docker state one validation run created, then proves both halves
# of the contract: nothing this run owned survived, and nothing this run did not own
# disappeared. Teardown continues past individual failures and reports at the end, so a
# single stuck resource cannot leave the rest behind unreported.

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/ci/container-validation.lib.sh
. "$script_directory/container-validation.lib.sh"

# Validation exports the identity it actually used. Deriving a fresh one here would
# name resources nothing created, so an absent value means validation never got far
# enough to make anything and there is nothing owned to remove.
run_identity="${CONTAINER_VALIDATION_RUN_ID:-}"
status=0

if [ -n "$run_identity" ] && container_validation_docker_available; then
    container_validation_remove_owned "$run_identity"
    container_validation_assert_no_residue "$run_identity" || status=1

    # The baseline is optional: a run that failed before capturing one still has to
    # clean up, and demanding the file would turn that into a second failure.
    if [ -n "${CONTAINER_VALIDATION_BASELINE:-}" ] &&
        [ -f "${CONTAINER_VALIDATION_BASELINE}" ]; then
        container_validation_assert_baseline_intact \
            "$CONTAINER_VALIDATION_BASELINE" || status=1
    fi
fi

if ! bash "$script_directory/Cleanup-JobPrivatePaths.sh" CONTAINER_VALIDATION_ROOT; then
    status=1
fi

exit "$status"