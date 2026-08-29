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

$directedRequestAdapterAvailable = $false
if (-not $directedRequestAdapterAvailable) {
    throw (
        'Live Copilot smoke is disabled until the packaged adapter implements ' +
        'durable directed-request handling; no Copilot sessions were started.'
    )
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
    $setupArguments = @('-NoProfile', '-File', $setupScript)
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
$userProfile = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::UserProfile
)
$copilotHome = if ([string]::IsNullOrWhiteSpace($env:COPILOT_HOME)) {
    Join-Path $userProfile '.copilot'
}
else {
    if (-not [IO.Path]::IsPathRooted($env:COPILOT_HOME)) {
        throw 'COPILOT_HOME must be an absolute path.'
    }
    [IO.Path]::GetFullPath($env:COPILOT_HOME)
}
$extensionRoot = Join-Path $copilotHome 'extensions' 'konclave'
$clientModulePath = Join-Path $extensionRoot 'client.mjs'
$serviceConfigPath = Join-Path $extensionRoot 'konclave.service.json'
foreach ($path in @($clientModulePath, $serviceConfigPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Installed Konclave shared-client asset is unavailable: $path"
    }
}
$statusPath = Join-Path $localAppData 'Konclave' 'demo' 'demo-status.json'
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
finally {
    Pop-Location
}
