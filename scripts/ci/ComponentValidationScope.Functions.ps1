#Requires -Version 7.0

Set-StrictMode -Version Latest

function Get-ComponentValidationContracts {
    return [ordered]@{
        'a2a-discovery' = @(
            '^Cargo\.(lock|toml)$'
            '^\.github/genesis-delivery\.json$'
            '^\.github/workflows/a2a-discovery-conformance\.yml$'
            '^crates/Konclave\.(?:A2AContracts|A2ADiscovery|A2ADomain|BoundedDocuments|DomainCore)/'
            '^docs/development/a2a-discovery\.md$'
            '^fixtures/a2a/'
            '^third_party/a2a/'
            '^scripts/ci/(?:ComponentValidationScope\.Functions|Resolve-ComponentValidationScope|Test-ComponentValidationScope)\.ps1$'
        )
        'a2a-task-store' = @(
            '^Cargo\.(lock|toml)$'
            '^\.github/genesis-delivery\.json$'
            '^\.github/workflows/a2a-task-store-conformance\.yml$'
            '^crates/Konclave\.(?:A2AContracts|A2ADomain|A2ATaskStore|A2ATaskStoreSqlite|BoundedDocuments|DomainCore)/'
            '^docs/(?:development/a2a-task-store|adr/adr-0014-a2a-task-projection-store)\.md$'
            '^third_party/a2a/'
            '^scripts/ci/(?:ComponentValidationScope\.Functions|Resolve-ComponentValidationScope|Test-ComponentValidationScope)\.ps1$'
        )
        'client-runtime-config' = @(
            '^Cargo\.(lock|toml)$'
            '^\.github/genesis-delivery\.json$'
            '^\.github/workflows/client-runtime-config-conformance\.yml$'
            '^apps/Konclave\.CommandLine/'
            '^crates/Konclave\.LocalServiceTransport/'
            '^docs/(?:adr/adr-0008-shared-local-service|distribution/installation|integrations/generic-client)\.md$'
            '^extensions/Konclave\.HostExtension/(?:package(?:-lock)?\.json|src/(?:client-api|generic-cli|generic-command|startup)\.ts|src/service/(?:client|config|installed|keys|transcript|user-presence)\.ts|tests/(?:generic-command|service-client|service-config|startup|user-presence)\.test\.ts)$'
            '^scripts/demo/(?:Invoke-KonclaveCopilotSmoke|Start-KonclaveLocalDemo)\.ps1$'
            '^tools/Konclave\.CopilotSmoke/'
        )
        'external-recipes' = @(
            '^\.github/genesis-delivery\.json$'
            '^\.github/workflows/recipe-conformance\.yml$'
            '^distribution/release-artifacts\.json$'
            '^docs/adr/adr-0028-external-recipe-composition\.md$'
            '^docs/integrations/recipes\.md$'
            '^extensions/Konclave\.HostExtension/(?:package(?:-lock)?\.json|src/recipes/|src/client-api\.ts|src/service/(?:client|operations|transcript|validation)\.ts|tests/recipe[^/]*\.test\.ts|examples/recipes/)'
            '^extensions/Konclave\.HostExtension/scripts/(?:build-extension|package-contract|verify-package|test-package-contract)\.mjs$'
            '^scripts/ci/(?:ComponentValidationScope\.Functions|Resolve-ComponentValidationScope|Test-ComponentValidationScope)\.ps1$'
        )
        'generic-client' = @(
            '^Cargo\.(lock|toml)$'
            '^\.github/workflows/generic-client-conformance\.yml$'
            '^apps/Konclave\.LocalDaemon/Cargo\.toml$'
            '^apps/Konclave\.LocalDaemon/src/(?:authorization_runtime|local_service)\.rs$'
            '^apps/Konclave\.LocalDaemon/tests/packaged_distribution_e2e\.rs$'
            '^crates/Konclave\.(?:LocalAuthorizationStore|LocalServiceTransport|SecretStorage|WindowsSecurity)/'
            '^docs/integrations/generic-client\.md$'
            '^extensions/Konclave\.HostExtension/(?:package(?:-lock)?\.json|src/(?:client-api|generic-cli|generic-command)\.ts|src/service/(?:client|config|installed|operations|transcript)\.ts|tests/(?:generic-command|service-client|service-config)\.test\.ts)$'
        )
        'installer-lifecycle' = @(
            '^\.github/genesis-delivery\.json$'
            '^\.github/workflows/(?:installer-lifecycle-conformance|package-validation)\.yml$'
            '^apps/Konclave\.LocalDaemon/packaging/'
            '^distribution/'
            '^docs/distribution/'
            '^scripts/installation/'
            '^scripts/packaging/'
        )
        'local-delivery-diagnostics' = @(
            '^crates/Konclave\.LocalServiceTransport/(?:src/(?:lib|authorization_handshake)\.rs|tests/authorization_handshake\.rs)$'
            '^Cargo\.(lock|toml)$'
            '^\.github/genesis-delivery\.json$'
            '^\.github/workflows/local-delivery-diagnostics-conformance\.yml$'
            '^crates/Konclave\.DomainCore/'
            '^docs/adr/adr-0026-local-delivery-diagnostics\.md$'
            '^docs/development/local-delivery-diagnostics\.md$'
            '^apps/Konclave\.LocalDaemon/(?:Cargo\.toml|src/(?:conversation|local_service|local_failure_diagnostics|local_failure_log|observability|shared_runtime|mcp|persistence)\.rs|src/persistence/(?:delivery_diagnostics|directed_request_handling|message_history)\.rs)$'
            '^fixtures/local-service/v1/copilot-tools\.json$'
            '^extensions/Konclave\.HostExtension/(?:package(?:-lock)?\.json|src/(?:client-api|generic-command|runtime)\.ts|src/adapter/runtime\.ts|src/service/(?:client|tools|commands|failure-diagnostics|delivery-diagnostics|operations|validation)\.ts|tests/(?:delivery-diagnostics|failure-diagnostics|generic-command|service-client|thin-client|delivery-runtime|extension-runtime)\.test\.ts)$'
            '^scripts/ci/(?:ComponentValidationScope\.Functions|Resolve-ComponentValidationScope|Test-ComponentValidationScope)\.ps1$'
        )
        'native-client' = @(
            '^Cargo\.(lock|toml)$'
            '^\.github/genesis-delivery\.json$'
            '^\.github/workflows/native-client-conformance\.yml$'
            '^crates/Konclave\.(?:ClientLibrary|CryptographicCore|SecretStorage|DomainCore|ProtocolContracts|RelayAuthentication|ProtectedHttp|WindowsSecurity|RelayCore|BoundedDocuments|CollaborationPolicies|AdapterSdk|AdapterTransport|LocalAuthorizationStore|LocalFraming|LocalServiceClient|LocalServiceTransport|UserPresence)/'
            '^apps/Konclave\.CommunityRelay/'
            '^proto/konclave/protocol/'
            '^fixtures/protocol/'
            '^apps/Konclave\.LocalDaemon/(?:Cargo\.toml|src/|tests/)'
            '^docs/(?:development/(?:native-client|secret-storage)|adr/adr-0031-embeddable-durable-native-client)\.md$'
            '^scripts/ci/(?:ComponentValidationScope\.Functions|Resolve-ComponentValidationScope|Test-ComponentValidationScope)\.ps1$'
        )
        'native-storage' = @(
            '^Cargo\.(lock|toml)$'
            '^\.github/genesis-delivery\.json$'
            '^\.github/workflows/native-storage-conformance\.yml$'
            '^crates/Konclave\.(?:SecretStorage|CryptographicCore|DomainCore|ProtocolContracts|RelayAuthentication|WindowsSecurity)/'
            '^proto/konclave/protocol/'
            '^fixtures/protocol/'
            '^docs/(?:development/secret-storage|adr/adr-0002-sealed-local-secret-custody)\.md$'
            '^scripts/ci/(?:ComponentValidationScope\.Functions|Resolve-ComponentValidationScope|Test-ComponentValidationScope)\.ps1$'
        )
        'profile-lifecycle' = @(
            '^Cargo\.(lock|toml)$'
            '^\.github/genesis-delivery\.json$'
            '^\.github/workflows/profile-lifecycle-conformance\.yml$'
            '^crates/Konclave\.LocalServiceTransport/'
            '^apps/Konclave\.LocalDaemon/(?:Cargo\.toml|src/(?:lib|activity|profile_lifecycle|profile_runtime|profile_supervisor|local_service|local_failure_diagnostics|session_request_read|service|pairing_supervisor|persistence|test_support)\.rs)$'
            '^scripts/ci/(?:ComponentValidationScope\.Functions|Resolve-ComponentValidationScope|Test-ComponentValidationScope)\.ps1$'
        )
        'pairing-rendezvous' = @(
            '^Cargo\.(lock|toml)$'
            '^\.github/genesis-delivery\.json$'
            '^\.github/workflows/pairing-rendezvous-conformance\.yml$'
            '^docs/adr/adr-0023-encrypted-pairing-rendezvous\.md$'
            '^docs/development/conformance\.md$'
            '^proto/konclave/protocol/v1/pairing_rendezvous\.proto$'
            '^fixtures/local-service/v1/copilot-tools\.json$'
            '^crates/Konclave\.(?:ClientLibrary|CryptographicCore|DomainCore|ProtocolContracts|RelayCore|SecretStorage)/(?:Cargo\.toml|build\.rs|src/.*|tests/.*)$'
            '^apps/Konclave\.(?:CommunityRelay|LocalDaemon)/(?:Cargo\.toml|src/.*|tests/.*)$'
            '^extensions/Konclave\.HostExtension/(?:package(?:-lock)?\.json|src/service/(?:client|commands|operations|pairing-handoff|validation)\.ts|tests/(?:pairing-handoff|service-client)\.test\.ts)$'
            '^packages/Konclave\.ProtocolContracts\.TypeScript/(?:package(?:-lock)?\.json|buf\.gen\.yaml|src/.*|tests/.*)$'
        )
        'response-continuation' = @(
            '^Cargo\.(lock|toml)$'
            '^\.github/genesis-delivery\.json$'
            '^\.github/workflows/response-continuation-conformance\.yml$'
            '^crates/Konclave\.DomainCore/'
            '^apps/Konclave\.LocalDaemon/(?:Cargo\.toml|src/.*|tests/.*)$'
            '^extensions/Konclave\.HostExtension/(?:package(?:-lock)?\.json|src/.*|tests/.*)$'
            '^fixtures/local-service/'
            '^docs/(?:development/(?:collaboration-policies|copilot-delivery-safety)|adr/adr-0030-correlated-response-continuation|security/threat-model)\.md$'
            '^scripts/ci/(?:ComponentValidationScope\.Functions|Resolve-ComponentValidationScope|Test-ComponentValidationScope)\.ps1$'
        )
        'short-code-pairing' = @(
            '^Cargo\.(lock|toml)$'
            '^\.github/genesis-delivery\.json$'
            '^\.github/workflows/short-code-pairing-conformance\.yml$'
            '^docs/adr/adr-0024-opaque-short-code-mutual-verification\.md$'
            '^docs/development/conformance\.md$'
            '^proto/konclave/protocol/v1/short_code_pairing\.proto$'
            '^scripts/ci/Validate-RustSecurityDependencies\.sh$'
            '^fixtures/local-service/v1/copilot-tools\.json$'
            '^crates/Konclave\.(?:ClientLibrary|CryptographicCore|DomainCore|ProtocolContracts|RelayCore|SecretStorage)/(?:Cargo\.toml|build\.rs|src/.*|tests/.*)$'
            '^apps/Konclave\.(?:CommunityRelay|LocalDaemon)/(?:Cargo\.toml|src/.*|tests/.*)$'
            '^extensions/Konclave\.HostExtension/(?:package(?:-lock)?\.json|src/service/(?:client|commands|operations|pairing-handoff|validation)\.ts|tests/(?:pairing-handoff|service-client)\.test\.ts)$'
            '^packages/Konclave\.ProtocolContracts\.TypeScript/(?:package(?:-lock)?\.json|buf\.gen\.yaml|src/.*|tests/.*)$'
        )
        'trusted-device-alias' = @(
            '^Cargo\.(lock|toml)$'
            '^\.github/genesis-delivery\.json$'
            '^\.github/workflows/trusted-device-alias-conformance\.yml$'
            '^docs/adr/adr-0025-trusted-device-alias-bootstrap\.md$'
            '^proto/konclave/protocol/v1/(?:application|common)\.proto$'
            '^crates/Konclave\.(?:CryptographicCore|DomainCore|ProtocolContracts|SecretStorage)/(?:Cargo\.toml|build\.rs|src/.*|tests/.*)$'
            '^apps/Konclave\.LocalDaemon/(?:Cargo\.toml|src/.*|tests/.*)$'
            '^extensions/Konclave\.HostExtension/(?:package(?:-lock)?\.json|src/service/(?:client|commands|operations|pairing-handoff|validation)\.ts|tests/(?:pairing-handoff|service-client)\.test\.ts)$'
            '^packages/Konclave\.ProtocolContracts\.TypeScript/(?:package(?:-lock)?\.json|buf\.gen\.yaml|src/.*|tests/.*)$'
        )
        'user-presence' = @(
            '^Cargo\.(lock|toml)$'
            '^\.github/workflows/user-presence-conformance\.yml$'
            '^apps/Konclave\.CommandLine/'
            '^apps/Konclave\.LocalDaemon/(?:Cargo\.toml|src/(?:authorization_runtime|local_service)\.rs)$'
            '^crates/Konclave\.DomainCore/'
            '^crates/Konclave\.LocalAuthorizationStore/'
            '^crates/Konclave\.LocalServiceTransport/'
            '^crates/Konclave\.SecretStorage/'
            '^crates/Konclave\.UserPresence/'
            '^extensions/Konclave\.HostExtension/(?:package(?:-lock)?\.json|src/service/(?:client|config|installed|transcript|user-presence)\.ts|tests/(?:service-client|service-config|user-presence)\.test\.ts)$'
            '^scripts/packaging/Test-ReleasePackaging\.ps1$'
        )
    }
}

function Get-ComponentValidationDecision {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Contract,

        [Parameter(Mandatory)]
        [ValidateSet('pull_request', 'workflow_dispatch')]
        [string]$EventName,

        [AllowEmptyCollection()]
        [string[]]$ChangedFiles = @(),

        [switch]$Conservative
    )

    $contracts = Get-ComponentValidationContracts
    if (-not $contracts.Contains($Contract)) {
        throw "Unknown component validation contract '$Contract'."
    }
    if ($EventName -eq 'workflow_dispatch') {
        return $true
    }

    $normalizedFiles = @(
        @(
            foreach ($changedFile in $ChangedFiles) {
                $normalized = ([string]$changedFile).Replace('\', '/')
                while ($normalized.StartsWith('./', [StringComparison]::Ordinal)) {
                    $normalized = $normalized.Substring(2)
                }
                $normalized = $normalized.TrimStart('/')
                if ($normalized) {
                    $normalized
                }
            }
        ) | Sort-Object -CaseSensitive -Unique
    )
    if ($Conservative -or $normalizedFiles.Count -eq 0 -or $normalizedFiles.Count -ge 3000) {
        return $true
    }

    if (
        $Contract -cnotin @('external-recipes', 'installer-lifecycle') -and
        @($normalizedFiles | Where-Object {
            $_ -cmatch '^\.github/actions/setup-rust/' -or
            $_ -ceq 'distribution/release-artifacts.json'
        }).Count -ne 0
    ) {
        return $true
    }

    foreach ($pattern in @($contracts[$Contract])) {
        [void][regex]::new($pattern)
        if (@($normalizedFiles | Where-Object { $_ -cmatch $pattern }).Count -ne 0) {
            return $true
        }
    }
    return $false
}
