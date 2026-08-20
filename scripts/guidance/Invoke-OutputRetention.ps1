#Requires -Version 7.0
<#
.SYNOPSIS
    Audits or prunes ignored repository build outputs.

.DESCRIPTION
    Each discovered output root is limited by age and size. Pruning removes whole
    immediate cache generations, oldest first, and refuses paths that are tracked,
    outside the repository, or not ignored by Git.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path,
    [string[]]$Path,
    [ValidateRange(0.01, 1024)]
    [double]$MaxGiB = 5,
    [ValidateRange(1, 3650)]
    [int]$MaxAgeDays = 7,
    [switch]$Prune,
    [switch]$Json
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = (Resolve-Path $ProjectRoot).Path
$repositoryPrefix = $ProjectRoot.TrimEnd(
    [IO.Path]::DirectorySeparatorChar,
    [IO.Path]::AltDirectorySeparatorChar
) + [IO.Path]::DirectorySeparatorChar
$maximumBytes = [long][Math]::Floor($MaxGiB * 1GB)
$cutoff = [DateTime]::UtcNow.AddDays(-$MaxAgeDays)

function Get-RelativePath {
    param([string]$FullPath)
    return [IO.Path]::GetRelativePath($ProjectRoot, $FullPath).Replace('\', '/')
}

function Resolve-OutputPath {
    param([string]$Candidate)
    $combined =
        if ([IO.Path]::IsPathRooted($Candidate)) {
            $Candidate
        } else {
            Join-Path $ProjectRoot $Candidate
        }
    $fullPath = [IO.Path]::GetFullPath($combined)
    if (-not $fullPath.StartsWith($repositoryPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Output path resolves outside the repository: $Candidate"
    }
    return $fullPath
}

function Test-IgnoredPath {
    param([string]$FullPath)
    $relativePath = Get-RelativePath $FullPath
    & git -C $ProjectRoot check-ignore --quiet -- $relativePath
    if ($LASTEXITCODE -eq 0) {
        return $true
    }
    if ($LASTEXITCODE -eq 1) {
        return $false
    }
    throw "git check-ignore failed for $relativePath."
}

function Assert-DisposableOutput {
    param([string]$FullPath)
    if (-not (Test-IgnoredPath $FullPath)) {
        throw "Output path is not ignored by Git: $(Get-RelativePath $FullPath)"
    }
    $relativePath = Get-RelativePath $FullPath
    $tracked = @(& git -C $ProjectRoot ls-files -- $relativePath)
    if ($LASTEXITCODE -ne 0) {
        throw "git ls-files failed for $relativePath."
    }
    if ($tracked.Count -gt 0) {
        throw "Output path contains tracked files: $relativePath"
    }
}

function Get-DiscoveredOutputRoots {
    $outputNames = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($name in @(
        '.next',
        '.nuxt',
        '.output',
        '.stryker-tmp',
        '.vite',
        'build',
        'coverage',
        'dist',
        'mutation',
        'obj',
        'out',
        'output',
        'site',
        'target'
    )) {
        [void]$outputNames.Add($name)
    }
    $excludedNames = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($name in @('.git', 'node_modules')) {
        [void]$excludedNames.Add($name)
    }

    $pending = [Collections.Generic.Stack[string]]::new()
    $pending.Push($ProjectRoot)
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        foreach ($child in Get-ChildItem -LiteralPath $directory -Directory -Force) {
            if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                continue
            }
            if ($excludedNames.Contains($child.Name)) {
                continue
            }
            if ($outputNames.Contains($child.Name) -and (Test-IgnoredPath $child.FullName)) {
                $child.FullName
                continue
            }
            $pending.Push($child.FullName)
        }
    }

    $incremental = Join-Path $ProjectRoot 'target' 'debug' 'incremental'
    if (Test-Path -LiteralPath $incremental -PathType Container) {
        $incremental
    }
}

function Measure-RetentionUnit {
    param([IO.FileSystemInfo]$Unit)
    if ($Unit.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Output retention refuses reparse points: $($Unit.FullName)"
    }
    $bytes = if ($Unit.PSIsContainer) { 0L } else { [long]$Unit.Length }
    $latest = $Unit.LastWriteTimeUtc
    if ($Unit.PSIsContainer) {
        foreach ($entry in Get-ChildItem -LiteralPath $Unit.FullName -Recurse -Force) {
            if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "Output retention refuses reparse points: $($entry.FullName)"
            }
            if (-not $entry.PSIsContainer) {
                $bytes += [long]$entry.Length
            }
            if ($entry.LastWriteTimeUtc -gt $latest) {
                $latest = $entry.LastWriteTimeUtc
            }
        }
    }
    return [PSCustomObject]@{
        fullPath        = $Unit.FullName
        bytes           = $bytes
        lastWriteTimeUtc = $latest
    }
}

function Measure-OutputRoot {
    param([string]$FullPath)
    $units = @(
        Get-ChildItem -LiteralPath $FullPath -Force |
            ForEach-Object { Measure-RetentionUnit $_ }
    )
    $totalBytes = 0L
    foreach ($unit in $units) {
        $totalBytes += [long]$unit.bytes
    }
    return [PSCustomObject]@{
        units      = $units
        totalBytes = $totalBytes
    }
}

$roots =
    if ($Path.Count -gt 0) {
        @($Path | ForEach-Object { Resolve-OutputPath $_ })
    } else {
        @(Get-DiscoveredOutputRoots)
    }
$roots = @(
    $roots |
        Sort-Object { $_.Length } -Unique
)

$results = foreach ($root in $roots) {
    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        [PSCustomObject]@{
            path             = Get-RelativePath $root
            exists           = $false
            initialBytes     = 0L
            finalBytes       = 0L
            staleUnits       = 0
            removedUnits     = 0
            retentionPassed  = $true
        }
        continue
    }
    Assert-DisposableOutput $root
    $measurement = Measure-OutputRoot $root
    $initialBytes = $measurement.totalBytes
    $stale = @($measurement.units | Where-Object lastWriteTimeUtc -lt $cutoff)
    $remove = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($unit in $stale) {
        [void]$remove.Add($unit.fullPath)
    }
    $retainedBytes = $initialBytes
    foreach ($unit in $stale) {
        $retainedBytes -= $unit.bytes
    }
    foreach ($unit in @(
        $measurement.units |
            Where-Object { -not $remove.Contains($_.fullPath) } |
            Sort-Object lastWriteTimeUtc, fullPath
    )) {
        if ($retainedBytes -le $maximumBytes) {
            break
        }
        [void]$remove.Add($unit.fullPath)
        $retainedBytes -= $unit.bytes
    }

    $removedUnits = 0
    if ($Prune) {
        foreach ($fullPath in @($remove | Sort-Object)) {
            if ($PSCmdlet.ShouldProcess($fullPath, 'Remove expired generated output')) {
                Remove-Item -LiteralPath $fullPath -Recurse -Force
                $removedUnits++
            }
        }
    }

    $finalMeasurement = if ($Prune) { Measure-OutputRoot $root } else { $measurement }
    $finalStale = @($finalMeasurement.units | Where-Object lastWriteTimeUtc -lt $cutoff)
    [PSCustomObject]@{
        path             = Get-RelativePath $root
        exists           = $true
        initialBytes     = $initialBytes
        finalBytes       = $finalMeasurement.totalBytes
        staleUnits       = $finalStale.Count
        removedUnits     = $removedUnits
        retentionPassed  = (
            $finalMeasurement.totalBytes -le $maximumBytes -and
            $finalStale.Count -eq 0
        )
    }
}

if ($Json) {
    $results | ConvertTo-Json -Depth 4
} else {
    $results
}

$failed = @($results | Where-Object { -not $_.retentionPassed })
if ($failed.Count -gt 0) {
    throw "Output retention policy failed for $($failed.Count) output root(s)."
}
