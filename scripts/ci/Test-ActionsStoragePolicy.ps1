#Requires -Version 7.0
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
$workflowRoot = Join-Path $root '.github' 'workflows'
$mainOnlySave =
    "          save-if: `${{ github.ref == 'refs/heads/main' }}"

function Get-StepBlock {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string[]]$Lines,

        [Parameter(Mandatory)]
        [int]$Line
    )

    $start = $Line
    while ($start -ge 0 -and $Lines[$start] -cnotmatch '^\s*- (?:name|uses|run):') {
        $start--
    }
    if ($start -lt 0) {
        throw "Action at line $($Line + 1) has no workflow step boundary."
    }
    $indent = $Lines[$start].Length - $Lines[$start].TrimStart().Length
    $end = $Lines.Count
    for ($index = $start + 1; $index -lt $Lines.Count; $index++) {
        if ($Lines[$index] -cmatch "^\s{$indent}- (?:name|uses|run):") {
            $end = $index
            break
        }
    }
    return @($Lines[$Start..($end - 1)])
}

$uploadCount = 0
$rustCacheCount = 0
$workflows = @(
    Get-ChildItem -LiteralPath $workflowRoot -File |
        Where-Object { $_.Extension -in @('.yml', '.yaml') }
)
foreach ($workflow in $workflows) {
    $lines = @(Get-Content -LiteralPath $workflow.FullName)
    for ($index = 0; $index -lt $lines.Count; $index++) {
        if ($lines[$index] -cmatch '^\s+(?:- )?uses: actions/upload-artifact@') {
            $uploadCount++
            $block = Get-StepBlock -Lines $lines -Line $index
            if (-not ($block -cmatch '^\s+retention-days: 1$')) {
                throw "$($workflow.Name) contains an artifact upload without one-day retention."
            }
        }
        if ($lines[$index] -cmatch '^\s+(?:- )?uses: Swatinem/rust-cache@') {
            $rustCacheCount++
            $block = Get-StepBlock -Lines $lines -Line $index
            if ($mainOnlySave -cnotin $block) {
                throw "$($workflow.Name) contains a Rust cache that can persist outside main."
            }
        }
    }
}
if ($uploadCount -eq 0 -or $rustCacheCount -eq 0) {
    throw 'Actions storage policy found no artifact uploads or Rust caches.'
}

$nodeSetup = Get-Content -LiteralPath (
    Join-Path $root '.github' 'actions' 'setup-node' 'action.yml'
) -Raw
foreach ($required in @(
    "github.ref == 'refs/heads/main'",
    'uses: actions/cache@'
)) {
    if (-not $nodeSetup.Contains($required)) {
        throw "Node setup does not enforce shared main-only caching: $required"
    }
}
$nodeCacheKey = @(
    $nodeSetup -split "`r?`n" |
        Where-Object { $_ -cmatch '^\s+key: npm-download-' }
)
if (
    $nodeCacheKey.Count -ne 1 -or
    $nodeCacheKey[0].Contains('inputs.npm-cache-scope')
) {
    throw 'Node setup partitions identical npm download stores by workflow scope.'
}

$cleanup = Get-Content -LiteralPath (
    Join-Path $workflowRoot 'package-artifact-cleanup.yml'
) -Raw
foreach ($required in @(
    'name: Actions storage cleanup',
    '- Agent plugin conformance',
    "github.event.workflow_run.path == '.github/workflows/agent-plugin-conformance.yml'",
    "github.event.workflow_run.path == '.github/workflows/package-validation.yml'",
    "github.event.workflow_run.path == '.github/workflows/publish-prerelease.yml'",
    'CACHE_BUDGET_BYTES: ''5368709120''',
    'Pull-request cache remained after cleanup'
)) {
    if (-not $cleanup.Contains($required)) {
        throw "Actions storage cleanup is missing '$required'."
    }
}

$delivery = Get-Content -LiteralPath (
    Join-Path $root '.github' 'genesis-delivery.json'
) -Raw | ConvertFrom-Json -Depth 100
$hosted = @($delivery.runnerProfiles | Where-Object id -ceq 'ubuntu-latest-hosted')
if (
    $hosted.Count -ne 1 -or
    @($hosted[0].jobs) -cnotcontains 'prune-actions-caches'
) {
    throw 'Delivery metadata does not route cache pruning through GitHub-hosted CI.'
}

Write-Output (
    "Actions storage policy passed for $uploadCount artifact upload(s) and " +
    "$rustCacheCount Rust cache(s)."
)
