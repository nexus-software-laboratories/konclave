#Requires -Version 7.0
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'ActionsStoragePolicy.Functions.ps1')

$mainOnlySave = "          save-if: `${{ github.ref == 'refs/heads/main' }}"
$disabledSave = '          save-if: false'
$savePolicyCases = @(
    @{ name = 'main only'; lines = @($mainOnlySave); allowed = $true },
    @{ name = 'restore only'; lines = @($disabledSave); allowed = $true },
    @{ name = 'missing'; lines = @(); allowed = $false },
    @{ name = 'unconditional'; lines = @('          save-if: true'); allowed = $false },
    @{ name = 'empty'; lines = @('          save-if:'); allowed = $false },
    @{
        name = 'pull request'
        lines = @("          save-if: `${{ github.event_name == 'pull_request' }}")
        allowed = $false
    },
    @{
        name = 'overridden main guard'
        lines = @($mainOnlySave, '          save-if: true')
        allowed = $false
    },
    @{
        name = 'duplicate disabled guard'
        lines = @($disabledSave, $disabledSave)
        allowed = $false
    }
)
foreach ($case in $savePolicyCases) {
    if ((Test-ActionsRustCacheSavePolicy -Lines $case.lines) -ne $case.allowed) {
        throw "Rust cache save policy failed: $($case.name)"
    }
}
Write-Output "Rust cache save policy tests passed: $($savePolicyCases.Count) cases."

function New-Artifact {
    param(
        [long]$Id,
        [long]$RunId,
        [long]$Size = 1
    )

    return [pscustomobject]@{
        id = $Id
        size_in_bytes = $Size
        workflow_run = [pscustomobject]@{
            id = $RunId
        }
    }
}

function New-WorkflowRun {
    param(
        [long]$Id,
        [string]$Path,
        [string]$Status = 'completed',
        [AllowEmptyString()]
        [string]$Conclusion = 'success'
    )

    return [pscustomobject]@{
        id = $Id
        path = $Path
        status = $Status
        conclusion = $Conclusion
    }
}

function New-Cache {
    param(
        [long]$Id,
        [long]$Size,
        [string]$Ref = 'refs/heads/main',
        [string]$LastAccessed = '2026-09-14T00:00:00Z'
    )

    return [pscustomobject]@{
        id = $Id
        size_in_bytes = $Size
        ref = $Ref
        last_accessed_at = $LastAccessed
    }
}

$agentPluginWorkflow = '.github/workflows/agent-plugin-conformance.yml'
$packageWorkflow = '.github/workflows/package-validation.yml'
$publishWorkflow = '.github/workflows/publish-prerelease.yml'

$emptyRunIds = @(
    Get-ActionsArtifactWorkflowRunIds -Artifacts @()
)
if ($emptyRunIds.Count -ne 0) {
    throw 'Empty Actions artifact inventory produced workflow run identifiers.'
}
$runIds = @(
    Get-ActionsArtifactWorkflowRunIds -Artifacts @(
        New-Artifact -Id 1 -RunId 12
        New-Artifact -Id 2 -RunId 11
        New-Artifact -Id 3 -RunId 12
    )
)
if (($runIds -join ',') -cne '11,12') {
    throw 'Actions artifact workflow run identifiers were not unique and ordered.'
}
$invalidArtifacts = [Collections.Generic.List[object]]::new()
$invalidArtifacts.Add($null)
$invalidArtifacts.Add([pscustomobject]@{
    id = 1
    size_in_bytes = 1
})
$invalidArtifacts.Add((New-Artifact -Id 1 -RunId 0))
foreach ($invalidArtifact in $invalidArtifacts) {
    $failed = $false
    try {
        [void](Get-ActionsArtifactWorkflowRunIds -Artifacts @($invalidArtifact))
    }
    catch {
        $failed =
            $_.Exception.Message.IndexOf(
                'artifact',
                [StringComparison]::OrdinalIgnoreCase
            ) -ge 0
    }
    if (-not $failed) {
        throw 'Invalid Actions artifact workflow run was not rejected.'
    }
}

$artifactCases = @(
    @{
        name = 'empty'
        artifacts = @()
        runs = @()
        delete = @()
        deleteBytes = 0
    },
    @{
        name = 'completed plugin and package runs'
        artifacts = @(
            New-Artifact -Id 1 -RunId 11 -Size 40
            New-Artifact -Id 2 -RunId 12 -Size 60
        )
        runs = @(
            New-WorkflowRun -Id 11 -Path $agentPluginWorkflow -Conclusion 'failure'
            New-WorkflowRun -Id 12 -Path $packageWorkflow -Conclusion 'cancelled'
        )
        delete = @(1, 2)
        deleteBytes = 100
    },
    @{
        name = 'successful publication'
        artifacts = @(New-Artifact -Id 3 -RunId 13 -Size 75)
        runs = @(New-WorkflowRun -Id 13 -Path $publishWorkflow)
        delete = @(3)
        deleteBytes = 75
    },
    @{
        name = 'failed publication retained for resume'
        artifacts = @(New-Artifact -Id 4 -RunId 14 -Size 80)
        runs = @(New-WorkflowRun -Id 14 -Path $publishWorkflow -Conclusion 'failure')
        delete = @()
        deleteBytes = 0
    },
    @{
        name = 'active and unrelated runs retained'
        artifacts = @(
            New-Artifact -Id 5 -RunId 15 -Size 20
            New-Artifact -Id 6 -RunId 16 -Size 30
        )
        runs = @(
            New-WorkflowRun `
                -Id 15 `
                -Path $packageWorkflow `
                -Status 'in_progress' `
                -Conclusion ''
            New-WorkflowRun -Id 16 -Path '.github/workflows/other.yml'
        )
        delete = @()
        deleteBytes = 0
    },
    @{
        name = 'mixed repository sweep'
        artifacts = @(
            New-Artifact -Id 7 -RunId 17 -Size 10
            New-Artifact -Id 8 -RunId 18 -Size 20
            New-Artifact -Id 9 -RunId 19 -Size 30
        )
        runs = @(
            New-WorkflowRun -Id 17 -Path $packageWorkflow
            New-WorkflowRun -Id 18 -Path $publishWorkflow -Conclusion 'failure'
            New-WorkflowRun -Id 19 -Path '.github/workflows/other.yml'
        )
        delete = @(7)
        deleteBytes = 10
    }
)

foreach ($case in $artifactCases) {
    $result = Select-ActionsArtifactDeletion `
        -Artifacts $case.artifacts `
        -Runs $case.runs
    $actualIds = @($result.deleteIds)
    $expectedIds = @($case.delete)
    if (
        ($actualIds -join ',') -cne ($expectedIds -join ',') -or
        [long]$result.deleteBytes -ne [long]$case.deleteBytes -or
        [int]$result.retainedCount -ne ($case.artifacts.Count - $expectedIds.Count)
    ) {
        throw "Actions artifact selection failed: $($case.name)"
    }
}

foreach ($invalid in @(
    @{
        artifacts = @(New-Artifact -Id 0 -RunId 1)
        runs = @(New-WorkflowRun -Id 1 -Path $packageWorkflow)
        error = 'artifact identifier'
    },
    @{
        artifacts = @(
            New-Artifact -Id 1 -RunId 1
            New-Artifact -Id 1 -RunId 1
        )
        runs = @(New-WorkflowRun -Id 1 -Path $packageWorkflow)
        error = 'duplicated'
    },
    @{
        artifacts = @(New-Artifact -Id 1 -RunId 1 -Size -1)
        runs = @(New-WorkflowRun -Id 1 -Path $packageWorkflow)
        error = 'negative'
    },
    @{
        artifacts = @(New-Artifact -Id 1 -RunId 2)
        runs = @(New-WorkflowRun -Id 1 -Path $packageWorkflow)
        error = 'workflow run'
    },
    @{
        artifacts = @()
        runs = @(
            New-WorkflowRun -Id 1 -Path $packageWorkflow
            New-WorkflowRun -Id 1 -Path $packageWorkflow
        )
        error = 'workflow run identifier'
    },
    @{
        artifacts = @()
        runs = @(New-WorkflowRun -Id 1 -Path '')
        error = 'path'
    }
)) {
    $failed = $false
    try {
        [void](Select-ActionsArtifactDeletion `
            -Artifacts $invalid.artifacts `
            -Runs $invalid.runs)
    }
    catch {
        $failed = $_.Exception.Message.Contains([string]$invalid.error)
    }
    if (-not $failed) {
        throw "Invalid Actions artifact input was not rejected: $($invalid.error)"
    }
}

$cases = @(
    @{
        name = 'empty'
        caches = @()
        budget = 100
        delete = @()
        retainedBytes = 0
    },
    @{
        name = 'trusted within budget'
        caches = @(
            New-Cache -Id 1 -Size 60
            New-Cache -Id 2 -Size 40
        )
        budget = 100
        delete = @()
        retainedBytes = 100
    },
    @{
        name = 'all pull request caches'
        caches = @(
            New-Cache -Id 1 -Size 40 -Ref 'refs/pull/1/merge'
            New-Cache -Id 2 -Size 60 -Ref 'refs/pull/2/merge'
        )
        budget = 1000
        delete = @(1, 2)
        retainedBytes = 0
    },
    @{
        name = 'oldest trusted caches until budget'
        caches = @(
            New-Cache -Id 1 -Size 40 -LastAccessed '2026-09-12T00:00:00Z'
            New-Cache -Id 2 -Size 40 -LastAccessed '2026-09-13T00:00:00Z'
            New-Cache -Id 3 -Size 40 -LastAccessed '2026-09-14T00:00:00Z'
        )
        budget = 80
        delete = @(1)
        retainedBytes = 80
    },
    @{
        name = 'pull requests before trusted eviction'
        caches = @(
            New-Cache -Id 1 -Size 20 -Ref 'refs/pull/1/merge'
            New-Cache -Id 2 -Size 60 -LastAccessed '2026-09-12T00:00:00Z'
            New-Cache -Id 3 -Size 60 -LastAccessed '2026-09-13T00:00:00Z'
        )
        budget = 60
        delete = @(1, 2)
        retainedBytes = 60
    },
    @{
        name = 'stable identifier tie break'
        caches = @(
            New-Cache -Id 2 -Size 60
            New-Cache -Id 1 -Size 60
        )
        budget = 60
        delete = @(1)
        retainedBytes = 60
    }
)

foreach ($case in $cases) {
    $result = Select-ActionsCacheDeletion `
        -Caches $case.caches `
        -BudgetBytes $case.budget
    $actualIds = @($result.deleteIds)
    $expectedIds = @($case.delete)
    if (
        ($actualIds -join ',') -cne ($expectedIds -join ',') -or
        [long]$result.retainedBytes -ne [long]$case.retainedBytes -or
        [int]$result.retainedCount -ne ($case.caches.Count - $expectedIds.Count)
    ) {
        throw "Actions cache selection failed: $($case.name)"
    }
}

foreach ($invalid in @(
    @{ caches = @(); budget = -1; error = 'budget' },
    @{
        caches = @(New-Cache -Id 0 -Size 1)
        budget = 1
        error = 'identifier'
    },
    @{
        caches = @(
            New-Cache -Id 1 -Size 1
            New-Cache -Id 1 -Size 1
        )
        budget = 1
        error = 'duplicated'
    },
    @{
        caches = @(New-Cache -Id 1 -Size -1)
        budget = 1
        error = 'negative'
    },
    @{
        caches = @(New-Cache -Id 1 -Size 1 -Ref '')
        budget = 1
        error = 'ref'
    },
    @{
        caches = @(New-Cache -Id 1 -Size 1 -LastAccessed 'invalid')
        budget = 1
        error = 'timestamp'
    }
)) {
    $failed = $false
    try {
        [void](Select-ActionsCacheDeletion `
            -Caches $invalid.caches `
            -BudgetBytes $invalid.budget)
    }
    catch {
        $failed = $_.Exception.Message.Contains([string]$invalid.error)
    }
    if (-not $failed) {
        throw "Invalid Actions cache input was not rejected: $($invalid.error)"
    }
}

$cleanupCases = @(
    @{
        name = 'scheduled reconciliation'
        arguments = @{ EventName = 'schedule' }
        deleteArtifacts = $true
        pruneCaches = $true
    },
    @{
        name = 'manual reconciliation'
        arguments = @{ EventName = 'workflow_dispatch' }
        deleteArtifacts = $true
        pruneCaches = $true
    },
    @{
        name = 'no-work package pull request'
        arguments = @{
            EventName = 'workflow_run'
            SourceWorkflowPath = $packageWorkflow
            SourceConclusion = 'success'
            SourceHeadBranch = 'feature'
            DefaultBranch = 'main'
            ArtifactCount = 0
        }
        deleteArtifacts = $false
        pruneCaches = $false
    },
    @{
        name = 'package pull request with artifacts'
        arguments = @{
            EventName = 'workflow_run'
            SourceWorkflowPath = $packageWorkflow
            SourceConclusion = 'success'
            SourceHeadBranch = 'feature'
            DefaultBranch = 'main'
            ArtifactCount = 12
        }
        deleteArtifacts = $true
        pruneCaches = $false
    },
    @{
        name = 'default-branch package dispatch'
        arguments = @{
            EventName = 'workflow_run'
            SourceWorkflowPath = $packageWorkflow
            SourceConclusion = 'success'
            SourceHeadBranch = 'main'
            DefaultBranch = 'main'
            ArtifactCount = 12
        }
        deleteArtifacts = $true
        pruneCaches = $true
    },
    @{
        name = 'Agent Plugin pull request artifact'
        arguments = @{
            EventName = 'workflow_run'
            SourceWorkflowPath = $agentPluginWorkflow
            SourceConclusion = 'failure'
            SourceHeadBranch = 'feature'
            DefaultBranch = 'main'
            ArtifactCount = 1
        }
        deleteArtifacts = $true
        pruneCaches = $false
    },
    @{
        name = 'failed publication'
        arguments = @{
            EventName = 'workflow_run'
            SourceWorkflowPath = $publishWorkflow
            SourceConclusion = 'failure'
            SourceHeadBranch = 'main'
            DefaultBranch = 'main'
            ArtifactCount = 1
        }
        deleteArtifacts = $false
        pruneCaches = $true
    },
    @{
        name = 'successful publication'
        arguments = @{
            EventName = 'workflow_run'
            SourceWorkflowPath = $publishWorkflow
            SourceConclusion = 'success'
            SourceHeadBranch = 'main'
            DefaultBranch = 'main'
            ArtifactCount = 1
        }
        deleteArtifacts = $true
        pruneCaches = $true
    }
)
foreach ($case in $cleanupCases) {
    $arguments = $case.arguments
    $plan = Get-ActionsStorageCleanupPlan @arguments
    if (
        [bool]$plan.DeleteArtifacts -ne [bool]$case.deleteArtifacts -or
        [bool]$plan.PruneCaches -ne [bool]$case.pruneCaches
    ) {
        throw "Actions storage cleanup planning failed: $($case.name)"
    }
}
foreach ($invalid in @(
    @{
        arguments = @{
            EventName = 'workflow_run'
            SourceWorkflowPath = '.github/workflows/unknown.yml'
            SourceHeadBranch = 'main'
            DefaultBranch = 'main'
        }
        error = 'Unsupported'
    },
    @{
        arguments = @{
            EventName = 'workflow_run'
            SourceWorkflowPath = $packageWorkflow
            SourceHeadBranch = ''
            DefaultBranch = 'main'
        }
        error = 'incomplete'
    }
)) {
    $failed = $false
    try {
        $arguments = $invalid.arguments
        [void](Get-ActionsStorageCleanupPlan @arguments)
    }
    catch {
        $failed = $_.Exception.Message.Contains(
            [string]$invalid.error,
            [StringComparison]::OrdinalIgnoreCase
        )
    }
    if (-not $failed) {
        throw "Invalid cleanup plan was not rejected: $($invalid.error)"
    }
}

Write-Output (
    "Actions storage decision tests passed: $($artifactCases.Count) artifact and " +
    "$($cases.Count) cache and $($cleanupCases.Count) cleanup-plan cases."
)
