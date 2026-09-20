#Requires -Version 7.0
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
$workflows = Join-Path $repositoryRoot '.github' 'workflows'
$expectations = [ordered]@{
    'ci.yml' = @('validation-plan')
    'a2a-conformance.yml' = @('a2a-conformance')
    'a2a-discovery-conformance.yml' = @('a2a-discovery-conformance')
    'actions-storage-conformance.yml' = @('actions-storage-conformance')
    'adapter-conformance.yml' = @('adapter-conformance')
    'agent-plugin-conformance.yml' = @('agent-plugin-conformance')
    'authorization-reload-conformance.yml' = @('authorization-reload-conformance')
    'authorization-store-conformance.yml' = @('authorization-store-conformance')
    'client-runtime-config-conformance.yml' = @('client-runtime-config-conformance')
    'distribution-lifecycle-acceptance.yml' = @(
        'resolve-scope',
        'distribution-lifecycle-acceptance'
    )
    'extension-startup-conformance.yml' = @('extension-startup-conformance')
    'recipe-conformance.yml' = @('recipe-conformance')
    'generic-client-conformance.yml' = @('generic-client-conformance')
    'installer-lifecycle-conformance.yml' = @(
        'installer-platform-conformance',
        'installer-lifecycle-conformance'
    )
    'marketplace-conformance.yml' = @(
        'marketplace-materialization',
        'marketplace-client-lifecycle',
        'managed-marketplace-policy',
        'marketplace-conformance'
    )
    'package-validation.yml' = @(
        'package-native',
        'package-plugin',
        'package-container',
        'release-integrity',
        'packaged-acceptance',
        'package-validation'
    )
    'pairing-rendezvous-conformance.yml' = @('pairing-rendezvous-conformance')
    'relay-migration-conformance.yml' = @(
        'relay-migration-conformance',
        'relay-migration-windows-conformance'
    )
    'release-publication-conformance.yml' = @('release-publication-conformance')
    'short-code-pairing-conformance.yml' = @('short-code-pairing-conformance')
    'trusted-device-alias-conformance.yml' = @('trusted-device-alias-conformance')
    'user-presence-conformance.yml' = @('user-presence-conformance')
}

foreach ($workflow in $expectations.Keys) {
    $content = Get-Content -LiteralPath (Join-Path $workflows $workflow) -Raw
    foreach ($job in $expectations[$workflow]) {
        $escapedJob = [regex]::Escape($job)
        $match = [regex]::Match(
            $content,
            "(?ms)^  ${escapedJob}:\r?\n(?<body>.*?)(?=^  [a-z0-9][a-z0-9-]*:\r?\n|\z)"
        )
        if (-not $match.Success) {
            throw "Workflow '$workflow' is missing job '$job'."
        }
        if (
            $match.Groups['body'].Value -notmatch
                "(?m)^    if: .*github\.actor != 'dependabot\[bot\]'"
        ) {
            throw "Workflow '$workflow' job '$job' can schedule Dependabot pull-request work."
        }
    }
}

$ci = Get-Content -LiteralPath (Join-Path $workflows 'ci.yml') -Raw
foreach ($required in @(
    'dependabot-validation:',
    "--jq '.[] | .filename, (.previous_filename // empty)'",
    'cargo test --workspace --locked',
    './scripts/Invoke-NodeWorkspaceChecks.ps1',
    './scripts/ci/Test-ActionsStoragePolicy.ps1',
    'DEPENDABOT_RESULT:',
    "Dependabot validation passed without scheduling the full pull-request matrix."
)) {
    if (-not $ci.Contains($required, [StringComparison]::Ordinal)) {
        throw "CI is missing Dependabot validation contract '$required'."
    }
}

foreach ($job in @(
    'rust-build-test',
    'rust-lint',
    'node-build-and-test',
    'container-ci',
    'local-daemon-daemon-packaging'
)) {
    $escapedJob = [regex]::Escape($job)
    $match = [regex]::Match(
        $ci,
        "(?ms)^  ${escapedJob}:\r?\n(?<body>.*?)(?=^  [a-z0-9][a-z0-9-]*:\r?\n|\z)"
    )
    if (
        -not $match.Success -or
        $match.Groups['body'].Value -notmatch '(?m)^    needs: validation-plan$'
    ) {
        throw "CI job '$job' is not blocked by the skipped Dependabot validation plan."
    }
}

$dependabotJob = [regex]::Match(
    $ci,
    "(?ms)^  dependabot-validation:\r?\n(?<body>.*?)(?=^  [a-z0-9][a-z0-9-]*:\r?\n|\z)"
)
if (
    -not $dependabotJob.Success -or
    $dependabotJob.Groups['body'].Value -notmatch
        "(?m)^    if: .*github\.actor == 'dependabot\[bot\]'"
) {
    throw 'The bounded Dependabot lane is not restricted to Dependabot pull requests.'
}

Write-Host 'Dependabot workflow isolation passed.'
