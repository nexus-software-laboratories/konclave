#Requires -Version 7.0
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
$ciPath = Join-Path $repositoryRoot '.github' 'workflows' 'ci.yml'
$packagePath = Join-Path `
    $repositoryRoot `
    '.github' `
    'workflows' `
    'package-validation.yml'
$ciLines = @(Get-Content -LiteralPath $ciPath)

function Get-CiJobLines {
    param(
        [Parameter(Mandatory)]
        [string]$Job
    )

    $start = [Array]::IndexOf($ciLines, "  ${Job}:")
    if ($start -lt 0) {
        throw "CI workflow is missing the '$Job' job."
    }
    $end = $ciLines.Count
    for ($index = $start + 1; $index -lt $ciLines.Count; $index++) {
        if ($ciLines[$index] -cmatch '^  [a-z0-9-]+:$') {
            $end = $index
            break
        }
    }
    return @($ciLines[$start..($end - 1)])
}

$rustBuild = (Get-CiJobLines -Job 'rust-build-test') -join "`n"
if ($rustBuild -cmatch 'cargo build\s+--workspace') {
    throw 'Rust workspace CI repeats compilation before the workspace test.'
}
if (
    [regex]::Matches(
        $rustBuild,
        '(?m)^\s*- run: cargo test --workspace --verbose$'
    ).Count -ne 1
) {
    throw 'Rust workspace CI must run one complete workspace test command.'
}
if ($rustBuild -cmatch 'fuzz/Cargo\.toml') {
    throw 'Rust workspace CI duplicates the fuzz target owned by Rust lint.'
}

$rustLint = (Get-CiJobLines -Job 'rust-lint') -join "`n"
if ($rustLint -cnotmatch 'cargo clippy --workspace --all-targets -- -D warnings') {
    throw 'Rust lint no longer covers every workspace target.'
}
if (
    $rustLint -cnotmatch
        'cargo clippy --locked --manifest-path fuzz/Cargo\.toml --bin protocol_v1_decode -- -D warnings'
) {
    throw 'Rust lint no longer compiles and lints the pinned fuzz target.'
}

$packageWorkflow = Get-Content -LiteralPath $packagePath -Raw
foreach ($required in @(
    'cargo build `',
    '--release `',
    '-p KonclaveCommandLine `',
    '-p KonclaveLocalDaemon `',
    '-p KonclaveCommunityRelay `',
    '-p KonclaveA2AGatewayHost `'
)) {
    if (-not $packageWorkflow.Contains($required)) {
        throw "Release package compilation is missing '$required'."
    }
}

Write-Output 'CI work deduplication contract passed.'
