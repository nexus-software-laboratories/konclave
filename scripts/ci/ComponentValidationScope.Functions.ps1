#Requires -Version 7.0

Set-StrictMode -Version Latest

function Get-ComponentValidationContracts {
    return [ordered]@{
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
            '^extensions/Konclave\.HostExtension/(?:package(?:-lock)?\.json|src/service/(?:client|commands|operations|pairing-handoff)\.ts|tests/(?:pairing-handoff|service-client)\.test\.ts)$'
            '^packages/Konclave\.ProtocolContracts\.TypeScript/(?:package(?:-lock)?\.json|buf\.gen\.yaml|src/.*|tests/.*)$'
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
            '^extensions/Konclave\.HostExtension/(?:package(?:-lock)?\.json|src/service/(?:client|commands|operations|pairing-handoff)\.ts|tests/(?:pairing-handoff|service-client)\.test\.ts)$'
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
            '^extensions/Konclave\.HostExtension/(?:package(?:-lock)?\.json|src/service/(?:client|commands|operations|pairing-handoff)\.ts|tests/(?:pairing-handoff|service-client)\.test\.ts)$'
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

    foreach ($pattern in @($contracts[$Contract])) {
        [void][regex]::new($pattern)
        if (@($normalizedFiles | Where-Object { $_ -cmatch $pattern }).Count -ne 0) {
            return $true
        }
    }
    return $false
}
