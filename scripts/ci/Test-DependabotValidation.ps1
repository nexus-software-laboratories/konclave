#Requires -Version 7.0
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$scriptPath = Join-Path $PSScriptRoot 'Resolve-DependabotValidation.ps1'

$cargo = & $scriptPath -ChangedFiles @('Cargo.toml', 'Cargo.lock', 'fuzz/Cargo.lock')
if (-not $cargo.Cargo -or $cargo.Node -or $cargo.Actions) {
    throw 'Cargo dependency validation was classified incorrectly.'
}

$node = & $scriptPath -ChangedFiles @(
    'extensions/Konclave.HostExtension/package.json',
    'extensions/Konclave.HostExtension/package-lock.json'
)
if ($node.Cargo -or -not $node.Node -or $node.Actions) {
    throw 'Node dependency validation was classified incorrectly.'
}

$actions = & $scriptPath -ChangedFiles @('.github/workflows/ci.yml')
if ($actions.Cargo -or $actions.Node -or -not $actions.Actions) {
    throw 'GitHub Actions dependency validation was classified incorrectly.'
}

$mixed = & $scriptPath -ChangedFiles @('Cargo.lock', '.github/workflows/ci.yml')
if (-not $mixed.Cargo -or $mixed.Node -or -not $mixed.Actions) {
    throw 'Mixed dependency validation was classified incorrectly.'
}

foreach ($invalid in @(
    @(),
    @('src/lib.rs'),
    @('../Cargo.lock'),
    @('https://example.test/Cargo.lock')
)) {
    $failed = $false
    try {
        $null = & $scriptPath -ChangedFiles $invalid
    }
    catch {
        $failed = $true
    }
    if (-not $failed) {
        throw "Invalid Dependabot path set was accepted: $($invalid -join ', ')."
    }
}

Write-Host 'Dependabot validation classification passed.'
