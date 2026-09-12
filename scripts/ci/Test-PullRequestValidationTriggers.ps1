#Requires -Version 7.0
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
$workflowRoot = Join-Path $repositoryRoot '.github' 'workflows'
$contracts = [ordered]@{
    'ci.yml' = '    types: [opened, edited, synchronize, reopened]'
    'package-validation.yml' = '    types: [opened, synchronize, reopened]'
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

foreach ($name in @('ci.yml', 'package-validation.yml', 'pr-title.yml', 'pr-base.yml')) {
    $content = Get-Content -Raw -LiteralPath (Join-Path $workflowRoot $name)
    if ($content.Contains('ready_for_review')) {
        throw "$name must reuse successful checks when an unchanged draft becomes ready."
    }
}

$ciLines = @(Get-Content -LiteralPath (Join-Path $workflowRoot 'ci.yml'))
$aggregateIndex = [Array]::IndexOf($ciLines, '  ci:')
if ($aggregateIndex -lt 0 -or $ciLines[$aggregateIndex + 1] -cne '    name: CI') {
    throw 'The aggregate required check must retain the stable CI name for draft reuse.'
}
if ('      draft_mode: full' -cnotin $ciLines -or $ciLines -cmatch 'CI_DRAFT_MODE') {
    throw 'Draft CI must remain full when ready promotion reuses the existing head checks.'
}

Write-Output 'Pull-request validation trigger contract passed.'
