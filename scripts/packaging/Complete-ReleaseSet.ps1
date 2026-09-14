#Requires -Version 7.4
<#
.SYNOPSIS
    Finalizes and verifies one complete prerelease set without cross-step state.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Directory,

    [Parameter(Mandatory)]
    [string]$SourceCommit,

    [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
)

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'ReleaseIntegrity.Functions.ps1')
. (Join-Path $PSScriptRoot 'ReleasePublication.Functions.ps1')

$root = (Resolve-Path -LiteralPath $Directory).Path
$manifestPath = Join-Path $root 'RELEASE.json'
$schemaPath = Join-Path $root 'release-artifacts.schema.json'
$manifestJson = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8
if (-not ($manifestJson | Test-Json -SchemaFile $schemaPath)) {
    throw 'Complete release manifest does not satisfy its shipped schema.'
}
$manifest = $manifestJson | ConvertFrom-Json -Depth 100

[void](Test-ReleaseContractCoverage -Directory $root)
$provenanceCount = Assert-ReleaseProvenanceSet `
    -Directory $root `
    -Manifest $manifest `
    -SourceCommit $SourceCommit
if ($provenanceCount -ne @($manifest.artifacts).Count) {
    throw 'Release manifest and provenance artifact counts differ.'
}

& (Join-Path $PSScriptRoot 'Test-PublicReleaseMetadata.ps1') `
    -Directory $root `
    -ProjectRoot $ProjectRoot
[void](New-ReleaseChecksums -Directory $root)
& (Join-Path $root 'Verify-Release.ps1') -Directory $root

Write-Output "Completed and verified $provenanceCount release artifacts."
