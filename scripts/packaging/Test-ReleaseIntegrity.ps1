#Requires -Version 7.4

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'ReleaseIntegrity.Functions.ps1')

function Assert-VerificationFails {
    param(
        [Parameter(Mandatory)]
        [string]$Directory,

        [Parameter(Mandatory)]
        [string]$Scenario
    )

    try {
        [void](Test-ReleaseChecksums -Directory $Directory)
    }
    catch {
        return
    }
    throw "Checksum verification accepted $Scenario."
}

$root = Join-Path (
    [IO.Path]::GetTempPath()
) "konclave-integrity-test-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $root | Out-Null
try {
    $artifact = Join-Path $root 'artifact.tar.gz'
    $metadata = Join-Path $root 'artifact.cdx.json'
    [IO.File]::WriteAllText($artifact, 'artifact')
    [IO.File]::WriteAllText($metadata, '{"bomFormat":"CycloneDX"}')
    [void](New-ReleaseChecksums -Directory $root)
    if ((Test-ReleaseChecksums -Directory $root) -ne 2) {
        throw 'Checksum verification returned an unexpected file count.'
    }

    [IO.File]::WriteAllText($artifact, 'modified')
    Assert-VerificationFails $root 'modified artifact content'
    [IO.File]::WriteAllText($artifact, 'artifact')

    $extra = Join-Path $root 'unexpected.txt'
    [IO.File]::WriteAllText($extra, 'extra')
    Assert-VerificationFails $root 'an unlisted extra artifact'
    Remove-Item -LiteralPath $extra -Force

    Remove-Item -LiteralPath $metadata -Force
    Assert-VerificationFails $root 'a missing artifact'
}
finally {
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force
    }
}

$contractRoot = Join-Path (
    [IO.Path]::GetTempPath()
) "konclave-contract-test-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $contractRoot | Out-Null
try {
    $projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
    Copy-Item (Join-Path $projectRoot 'distribution' 'release-artifacts.json') (
        Join-Path $contractRoot 'RELEASE.json'
    )
    foreach ($relative in @(
        'distribution/release-artifacts.schema.json',
        'distribution/UNSIGNED-PRERELEASE.txt',
        'scripts/packaging/ReleaseIntegrity.Functions.ps1',
        'scripts/packaging/Verify-Release.ps1'
    )) {
        Copy-Item (Join-Path $projectRoot $relative) $contractRoot
    }
    $manifest = Get-Content (Join-Path $contractRoot 'RELEASE.json') -Raw |
        ConvertFrom-Json -Depth 100
    [IO.File]::WriteAllText(
        (Join-Path $contractRoot "konclave-copilot-plugin-$($manifest.release.version).cdx.json"),
        '{}'
    )
    foreach ($entry in $manifest.artifacts) {
        $archive = Join-Path $contractRoot ([string]$entry.fileName)
        [IO.File]::WriteAllText($archive, [string]$entry.id)
        [IO.File]::WriteAllText("$archive.intoto.jsonl", '{}')
        if ([string]$entry.kind -in @('client', 'relay')) {
            [IO.File]::WriteAllText("$archive.rust.cdx.json", '{}')
        }
        else {
            [IO.File]::WriteAllText("$archive.cdx.json", '{}')
        }
    }
    [void](New-ReleaseChecksums -Directory $contractRoot)
    $checksumCount = Test-ReleaseChecksums -Directory $contractRoot
    $contractCount = Test-ReleaseContractCoverage -Directory $contractRoot
    if ($checksumCount -ne $contractCount) {
        throw 'Complete release contract and checksum counts differ.'
    }

    $victim = [string]$manifest.artifacts[0].fileName
    Remove-Item -LiteralPath (Join-Path $contractRoot $victim) -Force
    $checksumPath = Join-Path $contractRoot 'SHA256SUMS'
    $remaining = @(
        Get-Content -LiteralPath $checksumPath |
            Where-Object { -not $_.EndsWith("  $victim", [StringComparison]::Ordinal) }
    )
    [IO.File]::WriteAllText(
        $checksumPath,
        ($remaining -join "`n") + "`n",
        [Text.UTF8Encoding]::new($false)
    )
    [void](Test-ReleaseChecksums -Directory $contractRoot)
    $contractRejectedRemoval = $false
    try {
        [void](Test-ReleaseContractCoverage -Directory $contractRoot)
    }
    catch {
        $contractRejectedRemoval = $true
    }
    if (-not $contractRejectedRemoval) {
        throw 'Release contract accepted coordinated artifact and checksum removal.'
    }
}
finally {
    if (Test-Path -LiteralPath $contractRoot) {
        Remove-Item -LiteralPath $contractRoot -Recurse -Force
    }
}

Write-Output 'Release checksum tamper tests passed.'
