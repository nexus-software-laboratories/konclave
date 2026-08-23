#!/usr/bin/env bash
set -euo pipefail

# Proves the cleanup contract on a real engine, without building anything.
#
# The property that matters is not "cleanup ran" but "cleanup removed exactly what this
# run created". That cannot be asserted by reading the script, because the failure mode
# is a filter that matches more than intended, so this creates a sentinel that must
# survive alongside resources that must not.
#
# Every resource created here is cheap: labelled networks and volumes, no images and no
# builds. A leak in this test is therefore trivially recoverable, which is the point.

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/ci/container-validation.lib.sh
. "$script_directory/container-validation.lib.sh"

if ! container_validation_docker_available; then
    echo 'Docker is unavailable; the cleanup contract test has nothing to exercise.'
    exit 0
fi

run_identity="$(container_validation_run_identity)"
other_identity="$(container_validation_run_identity)"

if [ "$run_identity" = "$other_identity" ]; then
    echo '::error::Run identities collided; concurrent runs would share resources.'
    exit 1
fi

sentinel="konclave-cleanup-sentinel-${run_identity}"
baseline="$(mktemp)"
failures=0

teardown() {
    docker network rm "$sentinel" >/dev/null 2>&1 || true
    container_validation_remove_owned "$run_identity" || true
    container_validation_remove_owned "$other_identity" || true
    rm -f "$baseline"
}
trap teardown EXIT

# An unrelated resource that no validation run owns. Cleanup must not touch it.
docker network create "$sentinel" >/dev/null
container_validation_capture_baseline "$baseline"

owner_label="${CONTAINER_VALIDATION_OWNER_LABEL}"
docker network create \
    --label "${owner_label}=${run_identity}" \
    "konclave-cleanup-owned-${run_identity}" >/dev/null
docker volume create \
    --label "${owner_label}=${run_identity}" \
    "konclave-cleanup-owned-${run_identity}" >/dev/null
# A second run's resource, which this run must leave strictly alone.
docker network create \
    --label "${owner_label}=${other_identity}" \
    "konclave-cleanup-owned-${other_identity}" >/dev/null

if [ -z "$(container_validation_owned_resources "$run_identity")" ]; then
    echo '::error::Ownership query found nothing it had just created.'
    failures=1
fi

container_validation_remove_owned "$run_identity"

if ! container_validation_assert_no_residue "$run_identity"; then
    echo '::error::Cleanup left resources the run created.'
    failures=1
fi

if [ -z "$(container_validation_owned_resources "$other_identity")" ]; then
    echo '::error::Cleanup removed a concurrent run''s resources.'
    failures=1
fi

if ! docker network inspect "$sentinel" >/dev/null 2>&1; then
    echo '::error::Cleanup removed an unrelated resource it did not create.'
    failures=1
fi

# The baseline check must still pass even though the sentinel is the only pre-existing
# resource under test, because a run that deletes nothing it did not create is exactly
# what the baseline is asserting.
if ! container_validation_assert_baseline_intact "$baseline"; then
    echo '::error::Baseline verification reported a removal that did not happen.'
    failures=1
fi

# Now prove the detector actually detects. A residue the cleanup does not know about
# must fail the assertion, or a real leak would pass silently.
docker network create \
    --label "${owner_label}=${run_identity}" \
    "konclave-cleanup-leak-${run_identity}" >/dev/null
if container_validation_assert_no_residue "$run_identity" 2>/dev/null; then
    echo '::error::Residue detection passed while a run-owned resource existed.'
    failures=1
fi
container_validation_remove_owned "$run_identity"

if [ "$failures" -ne 0 ]; then
    exit 1
fi

echo 'Container validation cleanup contract verified.'
