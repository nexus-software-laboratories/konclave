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
    throw "The a2a-python interoperability check requires uv $($profile.tck.uvVersion)."
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
    throw 'The a2a-python output directory must be outside the repository.'
}
if (Test-Path -LiteralPath $resolvedOutputDirectory) {
    if (@(Get-ChildItem -LiteralPath $resolvedOutputDirectory -Force).Count -ne 0) {
        throw 'The a2a-python output directory must be empty.'
    }
}
else {
    New-Item -ItemType Directory -Path $resolvedOutputDirectory | Out-Null
}

$sdkProject = Join-Path $repositoryRoot ([string] $profile.sdkInterop.project)
$env:UV_PROJECT_ENVIRONMENT = Join-Path $resolvedOutputDirectory '.venv'
& uv sync --project $sdkProject --locked --link-mode copy --no-progress --quiet
if ($LASTEXITCODE -ne 0) {
    throw 'The pinned a2a-python environment could not be restored.'
}

& cargo build --locked -p KonclaveA2AGateway --example tck_sut `
    --manifest-path (Join-Path $repositoryRoot 'Cargo.toml')
if ($LASTEXITCODE -ne 0) {
    throw 'The A2A SDK interoperability SUT could not be built.'
}

$executableName = if ($IsWindows) { 'tck_sut.exe' } else { 'tck_sut' }
$sutExecutable = Join-Path $repositoryRoot 'target' 'debug' 'examples' $executableName
$sutUrl = [string] $profile.execution.sutUrl
$sutAddress = ([Uri] $sutUrl).Authority
$process = Start-Process -FilePath $sutExecutable -ArgumentList $sutAddress -PassThru `
    -RedirectStandardOutput (Join-Path $resolvedOutputDirectory 'sut.stdout.log') `
    -RedirectStandardError (Join-Path $resolvedOutputDirectory 'sut.stderr.log')
try {
    $ready = $false
    for ($attempt = 0; $attempt -lt 100; $attempt++) {
        if ($process.HasExited) {
            throw 'The A2A SDK interoperability SUT exited before becoming ready.'
        }
        try {
            $response = Invoke-WebRequest -UseBasicParsing `
                -Uri "$sutUrl/.well-known/agent-card.json" `
                -MaximumRedirection 0 `
                -TimeoutSec 1
            if ($response.StatusCode -eq 200) {
                $ready = $true
                break
            }
        }
        catch {
            Start-Sleep -Milliseconds 100
        }
    }
    if (-not $ready) {
        throw 'The A2A SDK interoperability SUT did not become ready.'
    }

    $logPath = Join-Path $resolvedOutputDirectory 'a2a-python.log'
    & uv run --project $sdkProject --no-sync python `
        (Join-Path $sdkProject 'interop.py') `
        --sut-url $sutUrl *> $logPath
    if ($LASTEXITCODE -ne 0) {
        Get-Content -LiteralPath $logPath -Tail 80
        throw 'a2a-python interoperability failed.'
    }
    Get-Content -LiteralPath $logPath
}
finally {
    if (-not $process.HasExited) {
        Stop-Process -Id $process.Id
        $process.WaitForExit()
    }
}
