#Requires -Version 7.0
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'CiPerformance.Functions.ps1')

function New-Step {
    param(
        [string]$Name,
        [string]$StartedAt,
        [string]$CompletedAt
    )

    return [pscustomobject]@{
        name = $Name
        status = 'completed'
        started_at = $StartedAt
        completed_at = $CompletedAt
    }
}

function New-Job {
    param(
        [long]$Id,
        [string]$Name,
        [string]$StartedAt,
        [string]$CompletedAt,
        [object[]]$Steps = @(),
        [string]$Status = 'completed',
        [string]$Conclusion = 'success'
    )

    return [pscustomobject]@{
        id = $Id
        name = $Name
        status = $Status
        conclusion = $Conclusion
        started_at = $StartedAt
        completed_at = $CompletedAt
        steps = $Steps
    }
}

$run = [pscustomobject]@{
    id = 42
    run_attempt = 2
    name = 'CI'
    head_sha = ('a' * 40)
    html_url = 'https://example.com/actions/runs/42'
    created_at = '2026-09-19T00:00:00Z'
}
$jobs = @(
    New-Job `
        -Id 1 `
        -Name 'validation-plan / plan' `
        -StartedAt '2026-09-19T00:00:10Z' `
        -CompletedAt '2026-09-19T00:00:20Z' `
        -Steps @(
            New-Step `
                -Name 'Resolve validation scope' `
                -StartedAt '2026-09-19T00:00:12Z' `
                -CompletedAt '2026-09-19T00:00:18Z'
        )
    New-Job `
        -Id 2 `
        -Name 'Build and test Rust workspace' `
        -StartedAt '2026-09-19T00:00:25Z' `
        -CompletedAt '2026-09-19T00:01:25Z' `
        -Steps @(
            New-Step `
                -Name 'Run cargo test' `
                -StartedAt '2026-09-19T00:00:30Z' `
                -CompletedAt '2026-09-19T00:01:20Z'
        )
    New-Job `
        -Id 3 `
        -Name 'Build and test Node guests' `
        -StartedAt '2026-09-19T00:00:30Z' `
        -CompletedAt '2026-09-19T00:01:00Z' `
        -Steps @(
            New-Step `
                -Name 'Run tests' `
                -StartedAt '2026-09-19T00:00:35Z' `
                -CompletedAt '2026-09-19T00:00:55Z'
        )
    New-Job `
        -Id 4 `
        -Name 'CI' `
        -StartedAt '2026-09-19T00:01:30Z' `
        -CompletedAt '' `
        -Status 'in_progress' `
        -Conclusion ''
)

$evidence = Get-CiPerformanceEvidence -Run $run -Jobs $jobs
$expectedMetrics = [ordered]@{
    completedJobCount = 3
    initialDelaySeconds = 10
    observedSpanSeconds = 75
    jobOccupancySeconds = 100
    activeCoverageSeconds = 70
    parallelOverlapSeconds = 30
    idleGapSeconds = 5
}
foreach ($entry in $expectedMetrics.GetEnumerator()) {
    if ([long]$evidence.metrics.($entry.Key) -ne [long]$entry.Value) {
        throw (
            "CI performance metric '$($entry.Key)' was " +
            "$($evidence.metrics.($entry.Key)); expected $($entry.Value)."
        )
    }
}
if (
    $evidence.slowestJobs.Count -ne 3 -or
    $evidence.slowestJobs[0].name -cne 'Build and test Rust workspace' -or
    $evidence.slowestSteps[0].name -cne 'Run cargo test'
) {
    throw 'CI performance ranking is not deterministic.'
}
$markdown = ConvertTo-CiPerformanceMarkdown -Evidence $evidence
foreach ($required in @(
    '## CI performance',
    '| Observed workflow span | 75 |',
    '| Build and test Rust workspace | success | 60 |',
    '| Build and test Rust workspace | Run cargo test | 50 |'
)) {
    if (-not $markdown.Contains($required)) {
        throw "CI performance Markdown is missing '$required'."
    }
}

$invalidCases = @(
    @{
        name = 'duplicate job identifiers'
        jobs = @(
            New-Job `
                -Id 1 `
                -Name 'one' `
                -StartedAt '2026-09-19T00:00:00Z' `
                -CompletedAt '2026-09-19T00:00:01Z'
            New-Job `
                -Id 1 `
                -Name 'two' `
                -StartedAt '2026-09-19T00:00:00Z' `
                -CompletedAt '2026-09-19T00:00:01Z'
        )
        error = 'duplicated'
    },
    @{
        name = 'reversed job interval'
        jobs = @(
            New-Job `
                -Id 1 `
                -Name 'reversed' `
                -StartedAt '2026-09-19T00:00:02Z' `
                -CompletedAt '2026-09-19T00:00:01Z'
        )
        error = 'before'
    },
    @{
        name = 'no completed jobs'
        jobs = @(
            New-Job `
                -Id 1 `
                -Name 'active' `
                -StartedAt '2026-09-19T00:00:00Z' `
                -CompletedAt '' `
                -Status 'in_progress' `
                -Conclusion ''
        )
        error = 'no completed jobs'
    }
)
foreach ($case in $invalidCases) {
    $failed = $false
    try {
        [void](Get-CiPerformanceEvidence -Run $run -Jobs $case.jobs)
    }
    catch {
        $failed = $_.Exception.Message.Contains(
            [string]$case.error,
            [StringComparison]::OrdinalIgnoreCase
        )
    }
    if (-not $failed) {
        throw "Invalid CI performance case was not rejected: $($case.name)"
    }
}

Write-Output 'CI performance evidence contract passed.'
