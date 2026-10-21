#Requires -Version 7.0
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
$crateRoot = Join-Path $repositoryRoot 'crates' 'Konclave.A2AKonclaveBridge'
$tests = Get-Content -LiteralPath (Join-Path $crateRoot 'src' 'tests.rs') -Raw
$manifest = Get-Content -LiteralPath (Join-Path $crateRoot 'Cargo.toml') -Raw

function Assert-BridgeTestTiming {
    param(
        [string]$Tests,
        [string]$Manifest
    )

    $attributes = [regex]::Matches($Tests, '#\[tokio::test(?<options>[^\]]*)\]')
    if ($attributes.Count -eq 0) {
        throw 'No bridge Tokio tests were found.'
    }
    foreach ($attribute in $attributes) {
        $options = $attribute.Groups['options'].Value
        if (
            $options -cnotmatch '\bstart_paused\s*=\s*true\b' -or
            $options -cmatch 'multi_thread'
        ) {
            throw 'Every bridge Tokio test must use paused, current-thread time.'
        }
    }
    if ($Tests -cmatch 'std::time::Instant|std::thread::sleep|tokio::time::resume') {
        throw 'Bridge fixture timing must not depend on wall-clock progress.'
    }
    $development = ($Manifest -split '(?m)^\[dev-dependencies\]\s*$', 2)
    if (
        $development.Count -ne 2 -or
        $development[1] -cnotmatch '(?m)^tokio\s*=\s*\{[^\r\n]*"test-util"'
    ) {
        throw 'Bridge dev-dependencies must enable Tokio test-util explicitly.'
    }
}

Assert-BridgeTestTiming -Tests $tests -Manifest $manifest

foreach ($mutation in @(
    @{
        Tests = [regex]::Replace($tests, '\bstart_paused\s*=\s*true\b', 'start_paused = false')
        Manifest = $manifest
    },
    @{
        Tests = $tests
        Manifest = $manifest.Replace('"test-util"', '"rt"')
    }
)) {
    $rejected = $false
    try {
        Assert-BridgeTestTiming @mutation
    } catch {
        $rejected = $true
    }
    if (-not $rejected) {
        throw 'Bridge timing guard failed to reject an invalid source mutation.'
    }
}

Write-Output 'Deterministic bridge test timing contract passed.'
