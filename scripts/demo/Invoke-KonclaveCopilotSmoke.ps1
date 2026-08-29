#Requires -Version 7.4
<#
.SYNOPSIS
    Runs the local-only two-session Copilot communication smoke.
#>
[CmdletBinding()]
param(
    [switch]$Refresh,

    [switch]$SkipSetup,

    [string]$Model,

    [ValidateRange(30, 600)]
    [int]$TurnTimeoutSeconds = 180,

    [ValidateRange(30, 1000)]
    [int]$MaxAiCreditsPerSession = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

foreach ($name in @(
    'CI',
    'GITHUB_ACTIONS',
    'TF_BUILD',
    'BUILDKITE',
    'CIRCLECI',
    'GITLAB_CI',
    'JENKINS_URL'
)) {
    $value = [Environment]::GetEnvironmentVariable($name)
    if (
        -not [string]::IsNullOrWhiteSpace($value) -and
        $value.Trim().ToLowerInvariant() -notin @('0', 'false', 'no', 'off')
    ) {
        throw "Live Copilot smoke is local-only; active CI marker: $name"
    }
}

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
$setupScript = Join-Path $PSScriptRoot 'Start-KonclaveLocalDemo.ps1'
$smokeRoot = Join-Path $projectRoot 'tools' 'Konclave.CopilotSmoke'

foreach ($command in @('node', 'npm', 'copilot')) {
    if ($null -eq (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "$command is required."
    }
}

if (-not $SkipSetup) {
    $setupArguments = @(
        '-NoProfile',
        '-File',
        $setupScript,
        '-Port',
        '43181',
        '-IsolatedSmokeState'
    )
    if ($Refresh) {
        $setupArguments += '-Refresh'
    }
    & pwsh @setupArguments
    if ($LASTEXITCODE -ne 0) {
        throw "Konclave local demo setup failed with exit code $LASTEXITCODE."
    }
}

$localAppData = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::LocalApplicationData
)
$smokeStateRoot = Join-Path $localAppData 'Konclave' 'demo' 'smoke'
$copilotHome = Join-Path $smokeStateRoot 'copilot-home'
$extensionRoot = Join-Path $copilotHome 'extensions' 'konclave'
$clientModulePath = Join-Path $extensionRoot 'client.mjs'
$serviceConfigPath = Join-Path $extensionRoot 'konclave.service.json'
foreach ($path in @($clientModulePath, $serviceConfigPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Installed Konclave shared-client asset is unavailable: $path"
    }
}
$statusPath = Join-Path $smokeStateRoot 'demo-status.json'
if (-not (Test-Path -LiteralPath $statusPath -PathType Leaf)) {
    throw 'Konclave demo status is unavailable; run setup without -SkipSetup.'
}
$status = Get-Content -LiteralPath $statusPath -Raw -Encoding UTF8 |
    ConvertFrom-Json -Depth 20
if (
    [int64]$status.schemaVersion -ne 3 -or
    [int64]$status.serviceProcessId -le 0
) {
    throw 'Konclave demo shared-service status is malformed.'
}
$serviceProcess = Get-Process -Id ([int]$status.serviceProcessId) -ErrorAction SilentlyContinue
if ($null -eq $serviceProcess -or $serviceProcess.HasExited) {
    throw 'Konclave demo shared service is not running.'
}
if (
    -not [IO.Path]::GetFullPath($serviceProcess.Path).Equals(
        [IO.Path]::GetFullPath([string]$status.serviceExecutable),
        [StringComparison]::OrdinalIgnoreCase
    ) -or
    $serviceProcess.StartTime.ToUniversalTime().ToFileTimeUtc() -ne
        [int64]$status.serviceStartTimeUtcFileTime
) {
    throw 'Konclave demo shared-service process no longer matches recorded status.'
}

$smokeError = $null
Push-Location $smokeRoot
try {
    $packageDocument = Get-Content -LiteralPath (
        Join-Path $smokeRoot 'package.json'
    ) -Raw -Encoding UTF8 | ConvertFrom-Json -Depth 20
    $expectedSdkVersion = [string]$packageDocument.dependencies.'@github/copilot-sdk'
    $installedSdkManifest = Join-Path (
        $smokeRoot
    ) 'node_modules' '@github' 'copilot-sdk' 'package.json'
    $installedSdkVersion = if (
        Test-Path -LiteralPath $installedSdkManifest -PathType Leaf
    ) {
        [string](
            Get-Content -LiteralPath $installedSdkManifest -Raw -Encoding UTF8 |
                ConvertFrom-Json -Depth 20
        ).version
    }
    else {
        ''
    }
    if ($installedSdkVersion -cne $expectedSdkVersion) {
        npm ci --ignore-scripts
        if ($LASTEXITCODE -ne 0) {
            throw 'Installing the Copilot smoke dependencies failed.'
        }
    }
    npm run build
    if ($LASTEXITCODE -ne 0) {
        throw 'Building the Copilot smoke runner failed.'
    }

    $timeoutMs = ($TurnTimeoutSeconds * 1000).ToString()
    $maxAiCredits = $MaxAiCreditsPerSession.ToString()
    $nodeArguments = @(
        'dist/src/cli.js',
        '--client-module', $clientModulePath,
        '--service-config', $serviceConfigPath,
        '--service-pid', ([string]$status.serviceProcessId),
        '--working-directory', $projectRoot,
        '--timeout-ms', $timeoutMs,
        '--max-ai-credits', $maxAiCredits
    )
    if (-not [string]::IsNullOrWhiteSpace($Model)) {
        $nodeArguments += @('--model', $Model)
    }
    & node @nodeArguments
    if ($LASTEXITCODE -ne 0) {
        throw "Konclave Copilot smoke failed with exit code $LASTEXITCODE."
    }
}
catch {
    $smokeError = $_.Exception
}
finally {
    Pop-Location
}

$cleanupError = $null
if (-not $SkipSetup) {
    try {
        [void](& pwsh -NoProfile -File $setupScript `
            -Port 43181 `
            -IsolatedSmokeState `
            -Stop)
        if ($LASTEXITCODE -ne 0) {
            throw "Konclave smoke cleanup failed with exit code $LASTEXITCODE."
        }
    }
    catch {
        $cleanupError = $_.Exception
    }
}
if ($null -ne $smokeError -and $null -ne $cleanupError) {
    throw [AggregateException]::new(
        'Konclave smoke and cleanup failed.',
        [Exception[]]@($smokeError, $cleanupError)
    )
}
if ($null -ne $smokeError) {
    throw $smokeError
}
if ($null -ne $cleanupError) {
    throw $cleanupError
}
