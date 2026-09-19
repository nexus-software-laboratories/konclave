#Requires -Version 7.0

Set-StrictMode -Version Latest

function ConvertTo-CiTimestamp {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Value,

        [Parameter(Mandatory)]
        [string]$Label
    )

    if ([string]::IsNullOrWhiteSpace([string]$Value)) {
        throw "$Label timestamp is missing."
    }

    try {
        return [DateTimeOffset]::Parse(
            [string]$Value,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind
        )
    }
    catch {
        throw "$Label timestamp is invalid."
    }
}

function Get-CiPerformanceEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Run,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Jobs,

        [ValidateRange(1, 100)]
        [int]$SlowestCount = 10
    )

    [long]$runId = $Run.id
    [int]$runAttempt = $Run.run_attempt
    [string]$runName = $Run.name
    [string]$headSha = $Run.head_sha
    [string]$runUrl = $Run.html_url
    if (
        $runId -le 0 -or
        $runAttempt -le 0 -or
        [string]::IsNullOrWhiteSpace($runName) -or
        [string]::IsNullOrWhiteSpace($headSha) -or
        [string]::IsNullOrWhiteSpace($runUrl)
    ) {
        throw 'Workflow run metadata is incomplete.'
    }
    $createdAt = ConvertTo-CiTimestamp -Value $Run.created_at -Label 'Run creation'

    $seenJobs = [Collections.Generic.HashSet[long]]::new()
    $completedJobs = [Collections.Generic.List[object]]::new()
    $completedSteps = [Collections.Generic.List[object]]::new()
    foreach ($job in $Jobs) {
        if ($null -eq $job) {
            throw 'Workflow job cannot be null.'
        }

        [long]$jobId = $job.id
        [string]$jobName = $job.name
        if ($jobId -le 0 -or -not $seenJobs.Add($jobId)) {
            throw "Workflow job identifier is invalid or duplicated: $jobId"
        }
        if ([string]::IsNullOrWhiteSpace($jobName)) {
            throw "Workflow job name is missing: $jobId"
        }
        if (
            [string]$job.status -cne 'completed' -or
            [string]::IsNullOrWhiteSpace([string]$job.completed_at)
        ) {
            continue
        }
        if ([string]$job.conclusion -ceq 'skipped') {
            continue
        }
        if ([string]::IsNullOrWhiteSpace([string]$job.started_at)) {
            throw "Completed workflow job start time is missing: $jobName"
        }

        $startedAt = ConvertTo-CiTimestamp `
            -Value $job.started_at `
            -Label "Workflow job '$jobName' start"
        $completedAt = ConvertTo-CiTimestamp `
            -Value $job.completed_at `
            -Label "Workflow job '$jobName' completion"
        if ($completedAt -lt $startedAt) {
            throw "Workflow job completed before it started: $jobName"
        }

        [long]$durationSeconds = [math]::Round(
            ($completedAt - $startedAt).TotalSeconds
        )
        $completedJobs.Add([pscustomobject]@{
            id = $jobId
            name = $jobName
            conclusion = [string]$job.conclusion
            startedAt = $startedAt
            completedAt = $completedAt
            durationSeconds = $durationSeconds
        })

        foreach ($step in @($job.steps)) {
            if (
                $null -eq $step -or
                [string]$step.status -cne 'completed' -or
                [string]::IsNullOrWhiteSpace([string]$step.started_at) -or
                [string]::IsNullOrWhiteSpace([string]$step.completed_at)
            ) {
                continue
            }

            [string]$stepName = $step.name
            if ([string]::IsNullOrWhiteSpace($stepName)) {
                throw "Workflow step name is missing in job '$jobName'."
            }
            $stepStartedAt = ConvertTo-CiTimestamp `
                -Value $step.started_at `
                -Label "Workflow step '$jobName / $stepName' start"
            $stepCompletedAt = ConvertTo-CiTimestamp `
                -Value $step.completed_at `
                -Label "Workflow step '$jobName / $stepName' completion"
            if ($stepCompletedAt -lt $stepStartedAt) {
                throw "Workflow step completed before it started: $jobName / $stepName"
            }
            $completedSteps.Add([pscustomobject]@{
                jobName = $jobName
                name = $stepName
                durationSeconds = [long][math]::Round(
                    ($stepCompletedAt - $stepStartedAt).TotalSeconds
                )
            })
        }
    }

    if ($completedJobs.Count -eq 0) {
        throw 'Workflow run has no completed jobs to measure.'
    }

    $orderedByStart = @(
        $completedJobs |
            Sort-Object `
                @{ Expression = { $_.startedAt } }, `
                @{ Expression = { $_.completedAt } }, `
                @{ Expression = { $_.id } }
    )
    $firstStart = $orderedByStart[0].startedAt
    $lastCompletion = $orderedByStart[0].completedAt
    $currentStart = $firstStart
    $currentEnd = $lastCompletion
    [long]$activeCoverageSeconds = 0
    [long]$jobOccupancySeconds = 0
    foreach ($job in $orderedByStart) {
        $jobOccupancySeconds += $job.durationSeconds
        if ($job.startedAt -le $currentEnd) {
            if ($job.completedAt -gt $currentEnd) {
                $currentEnd = $job.completedAt
            }
        }
        else {
            $activeCoverageSeconds += [math]::Round(
                ($currentEnd - $currentStart).TotalSeconds
            )
            $currentStart = $job.startedAt
            $currentEnd = $job.completedAt
        }
        if ($job.completedAt -gt $lastCompletion) {
            $lastCompletion = $job.completedAt
        }
    }
    $activeCoverageSeconds += [math]::Round(
        ($currentEnd - $currentStart).TotalSeconds
    )

    [long]$initialDelaySeconds = [math]::Max(
        0,
        [math]::Round(($firstStart - $createdAt).TotalSeconds)
    )
    [long]$observedSpanSeconds = [math]::Round(
        ($lastCompletion - $firstStart).TotalSeconds
    )
    [long]$parallelOverlapSeconds = [math]::Max(
        0,
        $jobOccupancySeconds - $activeCoverageSeconds
    )
    [long]$idleGapSeconds = [math]::Max(
        0,
        $observedSpanSeconds - $activeCoverageSeconds
    )

    $slowestJobs = @(
        $completedJobs |
            Sort-Object `
                @{ Expression = { $_.durationSeconds }; Descending = $true }, `
                @{ Expression = { $_.name } } |
            Select-Object -First $SlowestCount |
            ForEach-Object {
                [pscustomobject]@{
                    name = $_.name
                    conclusion = $_.conclusion
                    durationSeconds = $_.durationSeconds
                    startedAt = $_.startedAt.ToString('O')
                    completedAt = $_.completedAt.ToString('O')
                }
            }
    )
    $slowestSteps = @(
        $completedSteps |
            Sort-Object `
                @{ Expression = { $_.durationSeconds }; Descending = $true }, `
                @{ Expression = { $_.jobName } }, `
                @{ Expression = { $_.name } } |
            Select-Object -First $SlowestCount
    )

    return [pscustomobject]@{
        schemaVersion = 1
        run = [pscustomobject]@{
            id = $runId
            attempt = $runAttempt
            name = $runName
            headSha = $headSha
            url = $runUrl
            createdAt = $createdAt.ToString('O')
            firstJobStartedAt = $firstStart.ToString('O')
            lastJobCompletedAt = $lastCompletion.ToString('O')
        }
        metrics = [pscustomobject]@{
            completedJobCount = $completedJobs.Count
            initialDelaySeconds = $initialDelaySeconds
            observedSpanSeconds = $observedSpanSeconds
            jobOccupancySeconds = $jobOccupancySeconds
            activeCoverageSeconds = $activeCoverageSeconds
            parallelOverlapSeconds = $parallelOverlapSeconds
            idleGapSeconds = $idleGapSeconds
        }
        slowestJobs = $slowestJobs
        slowestSteps = $slowestSteps
    }
}

function ConvertTo-CiPerformanceMarkdown {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Evidence
    )

    function Protect-MarkdownCell {
        param([object]$Value)

        return ([string]$Value).Replace('|', '\|').Replace(
            "`r",
            ' '
        ).Replace(
            "`n",
            ' '
        )
    }

    $lines = [Collections.Generic.List[string]]::new()
    $lines.Add('## CI performance')
    $lines.Add('')
    $lines.Add('| Metric | Seconds |')
    $lines.Add('|---|---:|')
    $lines.Add("| Initial runner delay | $($Evidence.metrics.initialDelaySeconds) |")
    $lines.Add("| Observed workflow span | $($Evidence.metrics.observedSpanSeconds) |")
    $lines.Add("| Summed job occupancy | $($Evidence.metrics.jobOccupancySeconds) |")
    $lines.Add("| Active runner coverage | $($Evidence.metrics.activeCoverageSeconds) |")
    $lines.Add("| Parallel overlap | $($Evidence.metrics.parallelOverlapSeconds) |")
    $lines.Add("| Idle gaps | $($Evidence.metrics.idleGapSeconds) |")
    $lines.Add('')
    $lines.Add('### Slowest jobs')
    $lines.Add('')
    $lines.Add('| Job | Conclusion | Seconds |')
    $lines.Add('|---|---|---:|')
    foreach ($job in @($Evidence.slowestJobs)) {
        $lines.Add(
            "| $(Protect-MarkdownCell $job.name) | " +
            "$(Protect-MarkdownCell $job.conclusion) | $($job.durationSeconds) |"
        )
    }
    $lines.Add('')
    $lines.Add('### Slowest steps')
    $lines.Add('')
    $lines.Add('| Job | Step | Seconds |')
    $lines.Add('|---|---|---:|')
    foreach ($step in @($Evidence.slowestSteps)) {
        $lines.Add(
            "| $(Protect-MarkdownCell $step.jobName) | " +
            "$(Protect-MarkdownCell $step.name) | $($step.durationSeconds) |"
        )
    }
    $lines.Add('')

    return $lines -join [Environment]::NewLine
}
