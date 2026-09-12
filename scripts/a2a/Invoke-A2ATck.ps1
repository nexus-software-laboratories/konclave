#Requires -Version 7.0
[CmdletBinding()]
param(
    [string] $ProfilePath,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $OutputDirectory
)

$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
if ([string]::IsNullOrWhiteSpace($ProfilePath)) {
    $ProfilePath = Join-Path $repositoryRoot 'conformance' 'a2a' 'tck-v1.0.1.json'
}
$validatorPath = Join-Path $PSScriptRoot 'Test-A2ATckProfile.ps1'
& $validatorPath -ProfilePath $ProfilePath

$profile = Get-Content -LiteralPath $ProfilePath -Raw -Encoding UTF8 |
    ConvertFrom-Json -Depth 30
$uvVersion = (& uv --version).Trim()
if ($LASTEXITCODE -ne 0 -or $uvVersion -notmatch "^uv $([regex]::Escape([string] $profile.tck.uvVersion))(?:\s|$)") {
    throw "The A2A TCK requires uv $($profile.tck.uvVersion)."
}

$resolvedOutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$repositoryPrefix = $repositoryRoot.TrimEnd(
    [IO.Path]::DirectorySeparatorChar,
    [IO.Path]::AltDirectorySeparatorChar
) + [IO.Path]::DirectorySeparatorChar
if (
    $resolvedOutputDirectory.Equals($repositoryRoot, [StringComparison]::OrdinalIgnoreCase) -or
    $resolvedOutputDirectory.StartsWith($repositoryPrefix, [StringComparison]::OrdinalIgnoreCase)
) {
    throw 'The A2A TCK output directory must be outside the repository.'
}
if (Test-Path -LiteralPath $resolvedOutputDirectory) {
    if (@(Get-ChildItem -LiteralPath $resolvedOutputDirectory -Force).Count -ne 0) {
        throw 'The A2A TCK output directory must be empty.'
    }
}
else {
    New-Item -ItemType Directory -Path $resolvedOutputDirectory | Out-Null
}

$tckRoot = Join-Path $resolvedOutputDirectory 'a2a-tck'
New-Item -ItemType Directory -Path $tckRoot | Out-Null

function Invoke-CheckedNative {
    param(
        [Parameter(Mandatory, Position = 0)]
        [string] $Command,

        [Parameter(Position = 1, ValueFromRemainingArguments)]
        [string[]] $Arguments
    )

    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $Command"
    }
}

Invoke-CheckedNative -Command git -Arguments @('init', '--quiet', $tckRoot)
Invoke-CheckedNative -Command git -Arguments @(
    '-C',
    $tckRoot,
    'remote',
    'add',
    'origin',
    [string] $profile.tck.repository
)
Invoke-CheckedNative -Command git -Arguments @(
    '-C',
    $tckRoot,
    'fetch',
    '--quiet',
    '--depth',
    '1',
    'origin',
    [string] $profile.tck.commit
)
Invoke-CheckedNative -Command git -Arguments @(
    '-C',
    $tckRoot,
    'checkout',
    '--quiet',
    '--detach',
    'FETCH_HEAD'
)
& $validatorPath -ProfilePath $ProfilePath -TckRoot $tckRoot

Push-Location $tckRoot
try {
    Invoke-CheckedNative -Command uv -Arguments @(
        'sync',
        '--locked',
        '--link-mode',
        'copy',
        '--no-progress',
        '--quiet'
    )
}
finally {
    Pop-Location
}

Invoke-CheckedNative -Command cargo -Arguments @(
    'build',
    '--locked',
    '-p',
    'KonclaveA2AGateway',
    '--example',
    'tck_sut',
    '--manifest-path',
    (Join-Path $repositoryRoot 'Cargo.toml')
)

$executableName = if ($IsWindows) { 'tck_sut.exe' } else { 'tck_sut' }
$sutExecutable = Join-Path $repositoryRoot 'target' 'debug' 'examples' $executableName
$sutUrl = [string] $profile.execution.sutUrl
$sutAddress = ([Uri] $sutUrl).Authority

function Start-TckSut {
    param(
        [Parameter(Mandatory)]
        [string] $Name
    )

    $stdoutPath = Join-Path $resolvedOutputDirectory "$Name.stdout.log"
    $stderrPath = Join-Path $resolvedOutputDirectory "$Name.stderr.log"
    $process = Start-Process -FilePath $sutExecutable -ArgumentList $sutAddress -PassThru `
        -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
    for ($attempt = 0; $attempt -lt 100; $attempt++) {
        if ($process.HasExited) {
            throw "The A2A TCK SUT exited before becoming ready: $Name"
        }
        try {
            $response = Invoke-WebRequest -UseBasicParsing `
                -Uri "$sutUrl/.well-known/agent-card.json" `
                -MaximumRedirection 0 `
                -TimeoutSec 1
            if ($response.StatusCode -eq 200) {
                return $process
            }
        }
        catch {
            Start-Sleep -Milliseconds 100
        }
    }
    Stop-Process -Id $process.Id
    $process.WaitForExit()
    throw "The A2A TCK SUT did not become ready: $Name"
}

function Stop-TckSut {
    param(
        [Parameter(Mandatory)]
        [System.Diagnostics.Process] $Process
    )

    if (-not $Process.HasExited) {
        Stop-Process -Id $Process.Id
        $Process.WaitForExit()
    }
}

foreach ($isolated in $profile.isolatedRequirements) {
    $process = Start-TckSut -Name "isolated-$($isolated.id)"
    try {
        Push-Location $tckRoot
        try {
            $reportPrefix = Join-Path $resolvedOutputDirectory "isolated-$($isolated.id)"
            $logPath = Join-Path $resolvedOutputDirectory "isolated-$($isolated.id).log"
            & uv run --no-sync python -m pytest ([string] $isolated.selector) `
                "--sut-host=$sutUrl" `
                "--transport=$($profile.execution.transport)" `
                "--compatibility-report=$reportPrefix" `
                -q *> $logPath
            if ($LASTEXITCODE -ne 0) {
                Get-Content -LiteralPath $logPath -Tail 80
                throw "Isolated A2A TCK requirement failed: $($isolated.id)"
            }
            Write-Output "Isolated A2A TCK requirement passed: $($isolated.id)"
        }
        finally {
            Pop-Location
        }
    }
    finally {
        Stop-TckSut -Process $process
    }
}

$process = Start-TckSut -Name 'full'
try {
    Push-Location $tckRoot
    try {
        # The pinned TCK exits nonzero for the exact documented differences.
        # The strict report classifier below is the pass/fail decision.
        $fullLogPath = Join-Path $resolvedOutputDirectory 'full-tck.log'
        & uv run --no-sync python (Join-Path $tckRoot 'run_tck.py') `
            --sut-host $sutUrl `
            --transport ([string] $profile.execution.transport) `
            --level ([string] $profile.execution.level) *> $fullLogPath
        $tckExitCode = $LASTEXITCODE
    }
    finally {
        Pop-Location
    }

    $sourceReportPath = Join-Path $tckRoot 'reports' 'compatibility.json'
    $reportPath = Join-Path $resolvedOutputDirectory 'compatibility.json'
    Copy-Item -LiteralPath $sourceReportPath -Destination $reportPath
    & $validatorPath -ProfilePath $ProfilePath -TckRoot $tckRoot -ReportPath $reportPath
    Write-Output "Pinned A2A TCK raw exit code: $tckExitCode"
}
finally {
    Stop-TckSut -Process $process
}
