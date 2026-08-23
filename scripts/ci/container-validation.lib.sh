#!/usr/bin/env bash
# Run-scoped ownership and leak detection for local Docker validation.
#
# Container validation runs on developer and self-hosted machines that hold unrelated
# Docker state, so cleanup can never be broad. Every resource a run creates is named
# from a run identity that no other run can produce and labelled as belonging to that
# run, which makes exact removal possible and makes "did anything leak" a question with
# a precise answer instead of a judgement call.
#
# Nothing here prunes, filters by age, or matches wildcards. A resource is removed
# because this run's identity is on it, or it is left alone.

# Label carried by every resource a validation run creates.
CONTAINER_VALIDATION_OWNER_LABEL='dev.konclave.validation.run'

# Derives the identity that scopes one validation run.
#
# In CI the run and attempt numbers already distinguish concurrent jobs. Locally there
# is no such counter, so the process identifier and a random suffix supply it. Either
# way two runs cannot collide, which is what stops one run's cleanup from removing
# another run's builder.
container_validation_run_identity() {
    if [ -n "${CONTAINER_VALIDATION_RUN_ID:-}" ]; then
        printf '%s\n' "$CONTAINER_VALIDATION_RUN_ID"
        return 0
    fi

    local scope suffix
    if [ -n "${GITHUB_RUN_ID:-}" ] && [ -n "${GITHUB_RUN_ATTEMPT:-}" ]; then
        scope="ci-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
    else
        scope="local-$$"
    fi
    suffix="$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
    printf '%s-%s\n' "$scope" "$suffix"
}

# Returns the builder name owned by one run identity.
container_validation_builder_name() {
    printf 'konclave-validation-%s\n' "$1"
}

# Reports whether a Docker CLI is usable.
#
# Validation is skipped rather than failed when Docker is absent, because a machine
# without Docker has nothing to leak.
container_validation_docker_available() {
    command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1
}

# Lists every Docker resource currently labelled as owned by one run identity.
#
# Buildx builders carry no queryable labels, so the builder is matched by its
# deterministic name instead. Everything else is matched by label.
container_validation_owned_resources() {
    local run_identity="$1"
    local filter="label=${CONTAINER_VALIDATION_OWNER_LABEL}=${run_identity}"
    local builder
    builder="$(container_validation_builder_name "$run_identity")"

    if docker buildx inspect "$builder" >/dev/null 2>&1; then
        printf 'builder\t%s\n' "$builder"
    fi
    docker ps --all --quiet --filter "$filter" |
        while read -r id; do printf 'container\t%s\n' "$id"; done
    docker images --quiet --filter "$filter" |
        while read -r id; do printf 'image\t%s\n' "$id"; done
    docker volume ls --quiet --filter "$filter" |
        while read -r id; do printf 'volume\t%s\n' "$id"; done
    docker network ls --quiet --filter "$filter" |
        while read -r id; do printf 'network\t%s\n' "$id"; done
}

# Records a read-only baseline of everything Docker holds right now.
#
# The baseline is what proves a run put things back. It is never used to decide what to
# delete: a resource that predates the run is not this run's to remove even if it looks
# like validation state.
container_validation_capture_baseline() {
    local destination="$1"

    {
        docker ps --all --format '{{.ID}}' | sed 's/^/container\t/'
        docker images --format '{{.ID}}' | sed 's/^/image\t/'
        docker volume ls --format '{{.Name}}' | sed 's/^/volume\t/'
        docker network ls --format '{{.ID}}' | sed 's/^/network\t/'
        docker buildx ls --format '{{.Name}}' 2>/dev/null | sed 's/^/builder\t/'
    } | LC_ALL=C sort >"$destination"
}

# Removes exactly the resources one run created, continuing past individual failures.
#
# Teardown keeps going after a failure so one stuck resource cannot strand the rest,
# and the caller verifies the result separately rather than trusting these exit codes.
container_validation_remove_owned() {
    local run_identity="$1"
    local filter="label=${CONTAINER_VALIDATION_OWNER_LABEL}=${run_identity}"
    local builder id
    builder="$(container_validation_builder_name "$run_identity")"

    if docker buildx inspect "$builder" >/dev/null 2>&1; then
        docker buildx rm --force "$builder" >/dev/null 2>&1 || true
    fi

    for id in $(docker ps --all --quiet --filter "$filter"); do
        docker rm --force --volumes "$id" >/dev/null 2>&1 || true
    done
    for id in $(docker images --quiet --filter "$filter"); do
        docker rmi --force "$id" >/dev/null 2>&1 || true
    done
    for id in $(docker volume ls --quiet --filter "$filter"); do
        docker volume rm --force "$id" >/dev/null 2>&1 || true
    done
    for id in $(docker network ls --quiet --filter "$filter"); do
        docker network rm "$id" >/dev/null 2>&1 || true
    done
}

# Fails when any resource owned by one run survived cleanup.
container_validation_assert_no_residue() {
    local run_identity="$1"
    local residue

    residue="$(container_validation_owned_resources "$run_identity")"
    if [ -n "$residue" ]; then
        echo "::error::Container validation left run-owned Docker resources behind."
        printf '%s\n' "$residue" >&2
        return 1
    fi
}

# Fails when anything that existed before the run has disappeared.
#
# This is the half that protects unrelated developer state. Removing a resource this
# run did not create is a worse failure than leaking one, because the leak is
# recoverable and the deletion is not.
container_validation_assert_baseline_intact() {
    local baseline="$1"
    local current missing

    current="$(mktemp)"
    container_validation_capture_baseline "$current"
    missing="$(LC_ALL=C comm -23 "$baseline" "$current")"
    rm -f "$current"

    if [ -n "$missing" ]; then
        echo '::error::Container validation removed Docker resources it did not create.'
        printf '%s\n' "$missing" >&2
        return 1
    fi
}
