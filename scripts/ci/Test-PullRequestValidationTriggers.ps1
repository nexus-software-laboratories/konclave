#Requires -Version 7.0
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
$workflowRoot = Join-Path $repositoryRoot '.github' 'workflows'
$contracts = [ordered]@{
    'ci.yml' = '    types: [opened, synchronize, reopened, ready_for_review, converted_to_draft, closed]'
    'workflow-syntax.yml' = '    types: [opened, synchronize, reopened]'
    'a2a-conformance.yml' = '    types: [opened, synchronize, reopened, ready_for_review, converted_to_draft]'
    'a2a-discovery-conformance.yml' = '    types: [opened, synchronize, reopened]'
    'adapter-conformance.yml' = '    types: [opened, synchronize, reopened, ready_for_review, converted_to_draft, closed]'
    'actions-storage-conformance.yml' = '    types: [opened, synchronize, reopened]'
    'agent-plugin-conformance.yml' = '    types: [opened, synchronize, reopened]'
    'authorization-reload-conformance.yml' = '    types: [opened, synchronize, reopened]'
    'authorization-store-conformance.yml' = '    types: [opened, synchronize, reopened]'
    'client-runtime-config-conformance.yml' = '    types: [opened, synchronize, reopened]'
    'distribution-lifecycle-acceptance.yml' = '    types: [opened, synchronize, reopened]'
    'extension-startup-conformance.yml' = '    types: [opened, synchronize, reopened]'
    'recipe-conformance.yml' = '    types: [opened, synchronize, reopened]'
    'generic-client-conformance.yml' = '    types: [opened, synchronize, reopened]'
    'local-delivery-diagnostics-conformance.yml' = '    types: [opened, synchronize, reopened]'
    'installer-lifecycle-conformance.yml' = '    types: [opened, synchronize, reopened]'
    'marketplace-conformance.yml' = '    types: [opened, synchronize, reopened]'
    'pairing-rendezvous-conformance.yml' = '    types: [opened, synchronize, reopened]'
    'relay-migration-conformance.yml' = '    types: [opened, synchronize, reopened]'
    'release-publication-conformance.yml' = '    types: [opened, synchronize, reopened]'
    'short-code-pairing-conformance.yml' = '    types: [opened, synchronize, reopened]'
    'trusted-device-alias-conformance.yml' = '    types: [opened, synchronize, reopened]'
    'user-presence-conformance.yml' = '    types: [opened, synchronize, reopened]'
    'package-validation.yml' = '    types: [opened, synchronize, reopened, ready_for_review, converted_to_draft]'
    'pr-title.yml' = '    types: [opened, edited, synchronize, reopened]'
    'pr-base.yml' = '    types: [opened, edited, synchronize, reopened, closed]'
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

$prBase = Get-Content -LiteralPath (Join-Path $workflowRoot 'pr-base.yml') -Raw
foreach ($required in @(
    'PREVIOUS_BASE_REF: ${{ github.event.changes.base.ref.from || '''' }}',
    'Close and reopen it, or push a new commit',
    'group: pr-base-${{ github.event.pull_request.number }}',
    "github.event.action != 'closed'"
)) {
    if (-not $prBase.Contains($required)) {
        throw "PR base retarget recovery is missing '$required'."
    }

    foreach ($workflow in @('ci.yml', 'adapter-conformance.yml')) {
        $content = Get-Content -LiteralPath (Join-Path $workflowRoot $workflow) -Raw
        if (-not $content.Contains("github.event.action != 'closed'")) {
            throw "$workflow does not suppress jobs on the cancellation sentinel."
        }
    }
}

$dependabot = Get-Content -LiteralPath (
    Join-Path $repositoryRoot '.github' 'dependabot.yml'
) -Raw
foreach ($group in @(
    'cargo-minor-and-patch',
    'github-actions-minor-and-patch'
)) {
    if (-not $dependabot.Contains("      ${group}:")) {
        throw "Dependabot is missing the '$group' update group."
    }
}
if (
    [regex]::Matches($dependabot, '(?m)^        patterns:$').Count -ne 2 -or
    [regex]::Matches($dependabot, '(?m)^          - "\*"$').Count -ne 2 -or
    [regex]::Matches($dependabot, '(?m)^        update-types:$').Count -ne 2 -or
    [regex]::Matches($dependabot, '(?m)^          - "minor"$').Count -ne 2 -or
    [regex]::Matches($dependabot, '(?m)^          - "patch"$').Count -ne 2
) {
    throw 'Dependabot routine-update grouping is incomplete.'
}
if (
    [regex]::Matches($dependabot, '(?m)^    open-pull-requests-limit: 3$').Count -ne 1 -or
    [regex]::Matches($dependabot, '(?m)^    open-pull-requests-limit: 2$').Count -ne 1
) {
    throw 'Dependabot burst limits must remain bounded by ecosystem.'
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

function Get-CiJobLines {
    param(
        [Parameter(Mandatory)]
        [string]$Job
    )

    $start = [Array]::IndexOf($ciLines, "  ${Job}:")
    if ($start -lt 0) {
        throw "CI workflow is missing the '$Job' job."
    }

    $end = $ciLines.Count
    for ($index = $start + 1; $index -lt $ciLines.Count; $index++) {
        if ($ciLines[$index] -cmatch '^  [a-z0-9-]+:$') {
            $end = $index
            break
        }
    }

    return @($ciLines[$start..($end - 1)])
}

$requiredContextCondition =
    '    if: ${{ needs.validation-plan.outputs.scope == ''full'' || needs.validation-plan.outputs.scope == ''guidance'' }}'
$fullStepCondition = "        if: needs.validation-plan.outputs.scope == 'full'"
$cleanupStepCondition =
    '        if: ${{ always() && needs.validation-plan.outputs.scope == ''full'' }}'

foreach ($job in @('container-ci', 'local-daemon-daemon-packaging')) {
    $jobLines = Get-CiJobLines -Job $job
    if ($requiredContextCondition -cnotin $jobLines) {
        throw "$job must publish its required context for ready guidance-only changes."
    }

    $stepStarts = @(
        for ($index = 0; $index -lt $jobLines.Count; $index++) {
            if ($jobLines[$index] -cmatch '^      - (name|uses): ') {
                $index
            }
        }
    )
    if ($stepStarts.Count -lt 2) {
        throw "$job must contain a guidance-only publisher and full validation steps."
    }

    for ($step = 0; $step -lt $stepStarts.Count; $step++) {
        $start = $stepStarts[$step]
        $end = if ($step + 1 -lt $stepStarts.Count) {
            $stepStarts[$step + 1] - 1
        }
        else {
            $jobLines.Count - 1
        }
        $stepLines = @($jobLines[$start..$end])
        if ($stepLines[0] -ceq '      - name: Publish guidance-only required check') {
            if ("        if: needs.validation-plan.outputs.scope == 'guidance'" -cnotin $stepLines) {
                throw "$job guidance-only publisher has the wrong scope."
            }
            continue
        }
        if ($fullStepCondition -cnotin $stepLines -and $cleanupStepCondition -cnotin $stepLines) {
            throw "$job has a runner-intensive step without a full-scope guard: $($stepLines[0])"
        }
    }
}

foreach ($workflow in Get-ChildItem -LiteralPath $workflowRoot -File |
    Where-Object { $_.Extension -in @('.yml', '.yaml') }) {
    $content = Get-Content -LiteralPath $workflow.FullName -Raw
    if ($content -cmatch 'runs-on:\s*\[[^\]]*(self-hosted|automation-control|general-purpose)') {
        throw "$($workflow.Name) routes public repository work to a private runner."
    }
}

Write-Output 'Pull-request validation trigger contract passed.'
