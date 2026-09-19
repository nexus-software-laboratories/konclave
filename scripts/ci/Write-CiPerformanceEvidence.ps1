#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Repository,

    [Parameter(Mandatory)]
    [ValidateRange(1, [long]::MaxValue)]
    [long]$RunId,

    [Parameter(Mandatory)]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$Attempt,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'CiPerformance.Functions.ps1')

if ([string]::IsNullOrWhiteSpace($env:GH_TOKEN)) {
    throw 'GH_TOKEN is required to read workflow timing evidence.'
}

$runOutput = @(
    gh api "repos/$Repository/actions/runs/$RunId" 2>&1
)
if ($LASTEXITCODE -ne 0) {
    throw "Could not read workflow run $RunId.`n$($runOutput -join "`n")"
}
$run = ($runOutput -join "`n") | ConvertFrom-Json -Depth 100
if ([long]$run.id -ne $RunId -or [int]$run.run_attempt -ne $Attempt) {
    throw 'Workflow run response does not match the requested run and attempt.'
}

$jobsOutput = @(
    gh api `
        --method GET `
        "repos/$Repository/actions/runs/$RunId/attempts/$Attempt/jobs" `
        -f per_page=100 2>&1
)
if ($LASTEXITCODE -ne 0) {
    throw (
        "Could not read jobs for workflow run $RunId attempt $Attempt.`n" +
        ($jobsOutput -join "`n")
    )
}
$jobResponse = ($jobsOutput -join "`n") | ConvertFrom-Json -Depth 100
if ([int]$jobResponse.total_count -gt 100) {
    throw 'Workflow timing evidence exceeds the bounded 100-job inventory.'
}
$jobs = @($jobResponse.jobs)
if ($jobs.Count -ne [int]$jobResponse.total_count) {
    throw 'Workflow timing evidence returned an incomplete job inventory.'
}

$evidence = Get-CiPerformanceEvidence -Run $run -Jobs $jobs
$markdown = ConvertTo-CiPerformanceMarkdown -Evidence $evidence

$resolvedOutput = [IO.Path]::GetFullPath($OutputDirectory)
[void][IO.Directory]::CreateDirectory($resolvedOutput)
$jsonPath = Join-Path $resolvedOutput 'ci-performance.json'
$markdownPath = Join-Path $resolvedOutput 'ci-performance.md'
[IO.File]::WriteAllText(
    $jsonPath,
    ($evidence | ConvertTo-Json -Depth 20),
    [Text.UTF8Encoding]::new($false)
)
[IO.File]::WriteAllText(
    $markdownPath,
    $markdown,
    [Text.UTF8Encoding]::new($false)
)

if (-not [string]::IsNullOrWhiteSpace($env:GITHUB_STEP_SUMMARY)) {
    Add-Content `
        -LiteralPath $env:GITHUB_STEP_SUMMARY `
        -Value $markdown `
        -Encoding utf8
}

Write-Output (
    "CI performance evidence: span=$($evidence.metrics.observedSpanSeconds)s, " +
    "occupancy=$($evidence.metrics.jobOccupancySeconds)s, " +
    "jobs=$($evidence.metrics.completedJobCount)."
)
