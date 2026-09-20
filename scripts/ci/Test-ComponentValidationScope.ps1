#Requires -Version 7.0
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'ComponentValidationScope.Functions.ps1')

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
$contracts = Get-ComponentValidationContracts
$expectedContracts = @(
    'a2a-discovery'
    'client-runtime-config'
    'generic-client'
    'installer-lifecycle'
    'pairing-rendezvous'
    'short-code-pairing'
    'trusted-device-alias'
    'user-presence'
)
if (($contracts.Keys -join ',') -cne ($expectedContracts -join ',')) {
    throw 'Component validation contract inventory is incomplete or unordered.'
}

$workflowByContract = [ordered]@{
    'a2a-discovery' = 'a2a-discovery-conformance.yml'
    'client-runtime-config' = 'client-runtime-config-conformance.yml'
    'generic-client' = 'generic-client-conformance.yml'
    'installer-lifecycle' = 'installer-lifecycle-conformance.yml'
    'pairing-rendezvous' = 'pairing-rendezvous-conformance.yml'
    'short-code-pairing' = 'short-code-pairing-conformance.yml'
    'trusted-device-alias' = 'trusted-device-alias-conformance.yml'
    'user-presence' = 'user-presence-conformance.yml'
}
foreach ($entry in $workflowByContract.GetEnumerator()) {
    $workflow = Get-Content -LiteralPath (
        Join-Path $repositoryRoot '.github' 'workflows' $entry.Value
    ) -Raw
    foreach ($required in @(
        'Resolve-ComponentValidationScope.ps1',
        "-Contract '$($entry.Key)'"
    )) {
        if (-not $workflow.Contains($required)) {
            throw "$($entry.Value) is missing '$required'."
        }
    }
    if ($workflow.Contains('/pulls/$env:PULL_REQUEST_NUMBER/files')) {
        throw "$($entry.Value) retains an inline changed-file resolver."
    }
}

$authorizationHistoryFiles = @(
    'docs/development/collaboration-policies.md'
    'docs/development/copilot-delivery-safety.md'
    'docs/security/threat-model.md'
    'extensions/Konclave.HostExtension/src/runtime.ts'
    'extensions/Konclave.HostExtension/src/service/policy-enforcement.ts'
    'extensions/Konclave.HostExtension/src/service/tools.ts'
    'extensions/Konclave.HostExtension/tests/policy-enforcement.test.ts'
    'extensions/Konclave.HostExtension/tests/thin-client.test.ts'
)
foreach ($contract in $expectedContracts) {
    $selected = Get-ComponentValidationDecision `
        -Contract $contract `
        -EventName pull_request `
        -ChangedFiles $authorizationHistoryFiles
    if ($selected) {
        throw "Authorization history changes over-select '$contract'."
    }
    Write-Output "authorization history: contract=$contract, run=False"
}

$ownedCases = [ordered]@{
    'a2a-discovery' =
        'crates/Konclave.A2ADiscovery/src/catalog.rs'
    'client-runtime-config' =
        'extensions/Konclave.HostExtension/src/service/config.ts'
    'generic-client' =
        'extensions/Konclave.HostExtension/src/generic-command.ts'
    'installer-lifecycle' =
        'scripts/installation/Install-Konclave.ps1'
    'pairing-rendezvous' =
        'extensions/Konclave.HostExtension/src/service/pairing-handoff.ts'
    'short-code-pairing' =
        'proto/konclave/protocol/v1/short_code_pairing.proto'
    'trusted-device-alias' =
        'docs/adr/adr-0025-trusted-device-alias-bootstrap.md'
    'user-presence' =
        'extensions/Konclave.HostExtension/src/service/user-presence.ts'
}
foreach ($entry in $ownedCases.GetEnumerator()) {
    $selected = Get-ComponentValidationDecision `
        -Contract $entry.Key `
        -EventName pull_request `
        -ChangedFiles @($entry.Value)
    if (-not $selected) {
        throw "Owned component change did not select '$($entry.Key)'."
    }
    Write-Output "owned change: contract=$($entry.Key), run=True"
}

foreach ($contract in $expectedContracts) {
    $workflowSelected = Get-ComponentValidationDecision `
        -Contract $contract `
        -EventName pull_request `
        -ChangedFiles @(".github/workflows/$($workflowByContract[$contract])")
    $cargoSelected = Get-ComponentValidationDecision `
        -Contract $contract `
        -EventName pull_request `
        -ChangedFiles @('Cargo.lock')
    $dispatchSelected = Get-ComponentValidationDecision `
        -Contract $contract `
        -EventName workflow_dispatch
    $conservativeSelected = Get-ComponentValidationDecision `
        -Contract $contract `
        -EventName pull_request `
        -ChangedFiles @('docs/development/ci.md') `
        -Conservative
    if (
        -not $workflowSelected -or
        -not $dispatchSelected -or
        -not $conservativeSelected
    ) {
        throw "Fail-closed selection is incomplete for '$contract'."
    }
    if (
        ($contract -ceq 'installer-lifecycle' -and $cargoSelected) -or
        ($contract -cne 'installer-lifecycle' -and -not $cargoSelected)
    ) {
        throw "Cargo ownership is incorrect for '$contract'."
    }
}

$boundedSelected = Get-ComponentValidationDecision `
    -Contract 'generic-client' `
    -EventName pull_request `
    -ChangedFiles @(
        1..3000 | ForEach-Object { "docs/file-$_.md" }
    )
if (-not $boundedSelected) {
    throw 'The 3,000-file boundary did not select component validation.'
}

Write-Output 'Component validation scope contract passed.'
