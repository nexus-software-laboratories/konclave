#Requires -Version 7.0
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
$sourceRoot = Join-Path $repositoryRoot 'third_party' 'a2a' 'v1.0.1'
$provenancePath = Join-Path $sourceRoot 'provenance.json'
$provenance = Get-Content -LiteralPath $provenancePath -Raw -Encoding UTF8 |
    ConvertFrom-Json -Depth 20
if ([int64]$provenance.schemaVersion -ne 1) {
    throw 'A2A provenance schema version is unsupported.'
}
if (
    [string]$provenance.protocol.repository -cne 'https://github.com/a2aproject/A2A' -or
    [string]$provenance.protocol.release -cne 'v1.0.1' -or
    [string]$provenance.protocol.commit -cne '3303592588e388e62e0f69f701af531d2f4e3991' -or
    [string]$provenance.protocol.sourcePath -cne 'specification/a2a.proto' -or
    [string]$provenance.protocol.gitBlobSha1 -cne '400cdbad934654e27d7abbae1e145923eb40ac52' -or
    [string]$provenance.protocol.license -cne 'Apache-2.0' -or
    [string]$provenance.protocol.licenseGitBlobSha1 -cne 'd645695673349e3947e8e5ae42332d0ac3164cd7' -or
    [string]$provenance.generationStubs.repository -cne 'https://github.com/a2aproject/a2a-rs' -or
    [string]$provenance.generationStubs.commit -cne '4fdb6a9e6016978cb35e3f91cc50ffd056ce21b5' -or
    [string]$provenance.generationStubs.license -cne 'Apache-2.0'
) {
    throw 'A2A provenance identity changed without a versioned contract update.'
}

$files = @(
    [pscustomobject]@{
        Path = 'a2a.proto'
        Bytes = [int64]$provenance.protocol.bytes
        Sha256 = [string]$provenance.protocol.sha256
    },
    [pscustomobject]@{
        Path = 'LICENSE'
        Bytes = [int64]$provenance.protocol.licenseBytes
        Sha256 = [string]$provenance.protocol.licenseSha256
    }
)
foreach ($stub in $provenance.generationStubs.files) {
    $files += [pscustomobject]@{
        Path = [string]$stub.path
        Bytes = [int64]$stub.bytes
        Sha256 = [string]$stub.sha256
    }
}

foreach ($file in $files) {
    $path = Join-Path $sourceRoot $file.Path
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Pinned A2A source file is missing: $($file.Path)"
    }
    $item = Get-Item -LiteralPath $path
    if ($item.Length -ne $file.Bytes) {
        throw "Pinned A2A source length changed: $($file.Path)"
    }
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hash -cne $file.Sha256) {
        throw "Pinned A2A source digest changed: $($file.Path)"
    }
}

$expected = @(
    'a2a.proto',
    'google/api/annotations.proto',
    'google/api/client.proto',
    'google/api/field_behavior.proto',
    'LICENSE',
    'provenance.json',
    'README.md'
) | Sort-Object
$actual = @(
    Get-ChildItem -LiteralPath $sourceRoot -Recurse -File |
        ForEach-Object { [IO.Path]::GetRelativePath($sourceRoot, $_.FullName).Replace('\', '/') } |
        Sort-Object
)
if (($actual -join "`n") -cne ($expected -join "`n")) {
    throw 'Pinned A2A source directory contains an unexpected file set.'
}

$schema = Get-Content -LiteralPath (Join-Path $sourceRoot 'a2a.proto') -Raw -Encoding UTF8
if (
    $schema -notmatch '(?m)^package lf\.a2a\.v1;$' -or
    [string]$provenance.protocol.protocolVersion -cne '1.0'
) {
    throw 'Pinned A2A schema identity does not match the declared release.'
}

Write-Output 'A2A v1.0.1 source provenance passed.'
