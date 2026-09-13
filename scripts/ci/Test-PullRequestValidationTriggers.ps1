#Requires -Version 7.0
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
$workflowRoot = Join-Path $repositoryRoot '.github' 'workflows'
$contracts = [ordered]@{
    'ci.yml' = '    types: [opened, edited, synchronize, reopened, ready_for_review, converted_to_draft]'
    'a2a-conformance.yml' = '    types: [opened, edited, synchronize, reopened, ready_for_review, converted_to_draft]'
    'adapter-conformance.yml' = '    types: [opened, edited, synchronize, reopened, ready_for_review, converted_to_draft]'
    'authorization-store-conformance.yml' = '    types: [opened, edited, synchronize, reopened]'
    'generic-client-conformance.yml' = '    types: [opened, edited, synchronize, reopened]'
    'package-validation.yml' = '    types: [opened, synchronize, reopened, ready_for_review, converted_to_draft]'
    'pr-title.yml' = '    types: [opened, edited, synchronize, reopened]'
    'pr-base.yml' = '    types: [opened, edited, synchronize, reopened]'
}

foreach ($entry in $contracts.GetEnumerator()) {
    $path = Join-Path $workflowRoot $entry.Key
    $lines = @(Get-Content -LiteralPath $path)
    $typeDeclarations = @($lines | Where-Object { $_ -cmatch '^\s+types: \[.+\]$' })
    if ($typeDeclarations.Count -ne 1 -or $typeDeclarations[0] -cne $entry.Value) {
        throw "$($entry.Key) does not match the single-validation trigger contract."
    }
}

$reviewPolicyLines = @(
    Get-Content -LiteralPath (Join-Path $workflowRoot 'pr-review-policy.yml')
)
$reviewPolicyTrigger =
    '    types: [opened, edited, synchronize, reopened, ready_for_review, converted_to_draft]'
if ($reviewPolicyTrigger -cnotin $reviewPolicyLines) {
    throw 'Review policy must re-evaluate ready and draft transitions.'
}

$ciLines = @(Get-Content -LiteralPath (Join-Path $workflowRoot 'ci.yml'))
$aggregateIndex = [Array]::IndexOf($ciLines, '  ci:')
if (
    $aggregateIndex -lt 0 -or
    -not $ciLines[$aggregateIndex + 1].Contains("'Draft CI'") -or
    -not $ciLines[$aggregateIndex + 1].Contains("'CI'")
) {
    throw 'The aggregate must publish Draft CI for drafts and CI for ready validation.'
}
if ('      draft_mode: ready-only' -cnotin $ciLines -or $ciLines -cmatch 'CI_DRAFT_MODE') {
    throw 'Draft CI must defer runner-intensive work until ready-for-review.'
}
if (
    '  cancel-in-progress: ${{ github.event_name == ''pull_request'' }}' -cnotin $ciLines
) {
    throw 'Superseded pull-request CI must be cancelled automatically.'
}

foreach ($workflow in Get-ChildItem -LiteralPath $workflowRoot -File |
    Where-Object { $_.Extension -in @('.yml', '.yaml') }) {
    $content = Get-Content -LiteralPath $workflow.FullName -Raw
    if ($content -cmatch 'runs-on:\s*\[[^\]]*(self-hosted|automation-control|general-purpose)') {
        throw "$($workflow.Name) routes public repository work to a private runner."
    }
}

Write-Output 'Pull-request validation trigger contract passed.'
