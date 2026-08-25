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
$daemonPath = Join-Path (
    $copilotHome
) 'extensions' 'konclave' 'bin' 'KonclaveLocalDaemon.exe'
$runtimeConfigPath = Join-Path $copilotHome 'extensions' 'konclave' 'konclave.runtime.json'
if (-not (Test-Path -LiteralPath $runtimeConfigPath -PathType Leaf)) {
    throw 'Installed Konclave extension runtime configuration is unavailable.'
}
$runtimeConfigItem = Get-Item -LiteralPath $runtimeConfigPath
if (
    $runtimeConfigItem.Attributes -band [IO.FileAttributes]::ReparsePoint -or
    $runtimeConfigItem.Length -gt 4096
) {
    throw 'Installed Konclave extension runtime configuration is unsafe.'
}
$runtimeConfig = Get-Content -LiteralPath $runtimeConfigPath -Raw -Encoding UTF8 |
    ConvertFrom-Json -Depth 10
if (
    [int64]$runtimeConfig.schemaVersion -ne 1 -or
    [string]::IsNullOrWhiteSpace([string]$runtimeConfig.profileRoot) -or
    -not [IO.Path]::IsPathRooted([string]$runtimeConfig.profileRoot)
) {
    throw 'Installed Konclave extension runtime configuration is malformed.'
}
$profileRoot = [IO.Path]::GetFullPath([string]$runtimeConfig.profileRoot)

if (-not (Test-Path -LiteralPath $daemonPath -PathType Leaf)) {
    throw 'Installed Konclave extension daemon is unavailable.'
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
        '--daemon', $daemonPath,
        '--profile-root', $profileRoot,
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
