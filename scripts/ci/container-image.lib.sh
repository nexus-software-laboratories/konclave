#!/usr/bin/env bash
# Shared container-image contract and OCI archive assertions.
#
# Build backends differ by runner: a self-hosted image builder reaches a socketless
# mTLS BuildKit service, while a hosted runner builds locally. The image contract and
# every archive assertion must stay identical across both, so they live here and are
# sourced rather than restated per backend.

container_image_resolve_application_root() {
    local application_root workspace_root
    application_root="$(realpath -e -- "$1")"
    workspace_root="$(realpath -e -- "$GITHUB_WORKSPACE")"
    case "$application_root" in
        "$workspace_root"/*) ;;
        *)
            echo '::error::Application root resolves outside GITHUB_WORKSPACE.'
            return 1
            ;;
    esac
    printf '%s\n' "$application_root"
}

container_image_assert_contract() {
    local application_root="$1"
    local image_name="$2"

    if [[ ! "$image_name" =~ ^[a-z0-9]+([._-][a-z0-9]+)*$ ]]; then
        echo '::error::Image name must be a normalized lowercase OCI name.'
        return 1
    fi

    local dockerfile="$application_root/Dockerfile"
    local config_path="$application_root/.container/image.json"
    test -f "$dockerfile"
    test -f "$config_path"

    jq -e '
        .schemaVersion == 1
        and .requireImageHealthCheck == true
        and .smoke.kind == "process"
    ' "$config_path" >/dev/null
}

# Validates one local release reference for a previously validated image name.
#
# Registry paths and digests are deliberately excluded: release validation exports a
# local Docker archive and never gains a push or deployment destination.
container_image_release_reference() {
    local image_name="$1"
    local reference="$2"
    local tag

    case "$reference" in
        "${image_name}":*) tag="${reference#"${image_name}:"}" ;;
        *)
            echo '::error::Release image reference must use the validated local image name.'
            return 1
            ;;
    esac
    if [[ ! "$tag" =~ ^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$ ]]; then
        echo '::error::Release image tag is invalid.'
        return 1
    fi
    printf '%s\n' "$reference"
}

# Resolves the single image manifest in an OCI layout archive.
#
# A build backend may emit the image manifest directly in index.json or nest it behind
# an image index, so the descriptor is followed until an image manifest is reached.
container_image_manifest() {
    local archive="$1"
    local descriptor digest media_type manifest

    descriptor="$(
        tar -xOf "$archive" index.json |
            jq -er '
                if (.manifests | length) == 1
                then .manifests[0]
                else error("expected exactly one OCI manifest")
                end
            '
    )"

    while true; do
        digest="$(jq -er '.digest' <<<"$descriptor")"
        media_type="$(jq -er '.mediaType' <<<"$descriptor")"
        manifest="$(tar -xOf "$archive" "blobs/sha256/${digest#sha256:}")"
        case "$media_type" in
            application/vnd.oci.image.index.v1+json|\
            application/vnd.docker.distribution.manifest.list.v2+json)
                descriptor="$(
                    jq -er '
                        if (.manifests | length) == 1
                        then .manifests[0]
                        else error("expected exactly one platform manifest")
                        end
                    ' <<<"$manifest"
                )"
                ;;
            *)
                printf '%s\n' "$manifest"
                return 0
                ;;
        esac
    done
}

container_image_config() {
    local archive="$1"
    local manifest config_digest

    manifest="$(container_image_manifest "$archive")"
    config_digest="$(jq -er '.config.digest' <<<"$manifest")"
    tar -xOf "$archive" "blobs/sha256/${config_digest#sha256:}"
}

container_image_assert_public_release_config() {
    local archive="$1"
    local run_identity="$2"
    local image_config

    image_config="$(container_image_config "$archive")"
    if jq -e \
        --arg label "$CONTAINER_VALIDATION_OWNER_LABEL" \
        '.config.Labels[$label] != null' <<<"$image_config" >/dev/null; then
        echo '::error::Release image contains the validation ownership label.'
        return 1
    fi
    if grep -Fq "$run_identity" <<<"$image_config"; then
        echo '::error::Release image contains its CI validation run identity.'
        return 1
    fi
}

container_image_assert_archive() {
    local archive="$1"
    local architecture="$2"

    test -s "$archive"

    local manifest image_config
    manifest="$(container_image_manifest "$archive")"
    image_config="$(container_image_config "$archive")"

    if [ "$(jq -r '.architecture' <<<"$image_config")" != "$architecture" ]; then
        echo "::error::OCI config architecture does not match $architecture."
        return 1
    fi

    local runtime_user runtime_identity
    runtime_user="$(jq -r '.config.User // ""' <<<"$image_config")"
    runtime_identity="${runtime_user%%:*}"
    if [ -z "$runtime_identity" ] ||
        [ "$runtime_identity" = 'root' ] ||
        [[ "$runtime_identity" =~ ^0+$ ]]; then
        echo "::error::Image runtime user '$runtime_user' is not non-root."
        return 1
    fi

    if ! jq -e '
        (.config.Healthcheck.Test // []) | length > 0
    ' <<<"$image_config" >/dev/null; then
        echo '::error::Image does not declare a health check.'
        return 1
    fi

    local entrypoint entrypoint_path entrypoint_found=false
    entrypoint="$(
        jq -er '
            (.config.Entrypoint // [])[0]
            | select(type == "string" and length > 1)
        ' <<<"$image_config"
    )"
    entrypoint_path="${entrypoint#/}"

    local layer_digest layer_media_type layer_path layer_entries
    while IFS=$'\t' read -r layer_digest layer_media_type; do
        layer_path="blobs/sha256/${layer_digest#sha256:}"
        case "$layer_media_type" in
            application/vnd.oci.image.layer.v1.tar|\
            application/vnd.docker.image.rootfs.diff.tar)
                layer_entries="$(
                    tar -xOf "$archive" "$layer_path" |
                        tar -tf -
                )"
                ;;
            application/vnd.oci.image.layer.v1.tar+gzip|\
            application/vnd.docker.image.rootfs.diff.tar.gzip)
                layer_entries="$(
                    tar -xOf "$archive" "$layer_path" |
                        tar -tzf -
                )"
                ;;
            application/vnd.oci.image.layer.v1.tar+zstd)
                layer_entries="$(
                    tar -xOf "$archive" "$layer_path" |
                        tar --zstd -tf -
                )"
                ;;
            *)
                echo "::error::Unsupported OCI layer media type '$layer_media_type'."
                return 1
                ;;
        esac

        if grep -Eq \
            '^(./)?(usr/local/cargo/|usr/local/rustup/|usr/local/bin/rustc$|usr/bin/cargo$)' \
            <<<"$layer_entries"; then
            echo '::error::Final image contains Rust build tooling.'
            return 1
        fi

        if grep -Fxq "$entrypoint_path" <<<"${layer_entries#./}" ||
            grep -Fxq "./$entrypoint_path" <<<"$layer_entries"; then
            entrypoint_found=true
        fi
    done < <(
        jq -er '.layers[] | [.digest, .mediaType] | @tsv' <<<"$manifest"
    )

    if [ "$entrypoint_found" != 'true' ]; then
        echo "::error::Image entrypoint '$entrypoint' was not found in the final layers."
        return 1
    fi
}

container_image_write_summary() {
    local image_name="$1"
    local architecture="$2"
    local builder="$3"

    {
        echo '### OCI validation'
        echo
        echo "- Image: \`$image_name\`"
        echo "- Platform: \`linux/$architecture\`"
        echo "- Builder: $builder"
        echo '- Runtime user: non-root'
        echo '- Health check: present'
        echo '- Rust build tooling in final layers: absent'
        echo '- Entrypoint in final layers: present'
    } >>"$GITHUB_STEP_SUMMARY"
}
