#Requires -Version 7.4
<#
.SYNOPSIS
    Emits one deterministic CycloneDX 1.6 SBOM for a native Rust release artifact.
#>
[CmdletBinding()]
param(
    [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path,

    [Parameter(Mandatory)]
    [ValidateSet(
        'x86_64-unknown-linux-gnu',
        'x86_64-pc-windows-msvc',
        'aarch64-apple-darwin',
        'x86_64-apple-darwin'
    )]
    [string]$Target,

    [Parameter(Mandatory)]
    [string]$ArtifactId,

    [Parameter(Mandatory)]
    [string]$ArtifactName,

    [Parameter(Mandatory)]
    [string]$ArtifactVersion,

    [Parameter(Mandatory)]
    [string[]]$RootPackageName,

    [Parameter(Mandatory)]
    [string]$OutputPath,

    [string]$MetadataPath
)

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot '..' 'CargoLock.Functions.ps1')
. (Join-Path $PSScriptRoot 'ReleaseMetadata.Functions.ps1')
. (Join-Path $PSScriptRoot 'RustSbom.Functions.ps1')

$projectRootPath = (Resolve-Path -LiteralPath $ProjectRoot).Path
$metadata = Get-CargoWorkspaceMetadata `
    -ProjectRoot $projectRootPath `
    -Target $Target `
    -MetadataPath $MetadataPath
$checksums = Get-CargoLockedChecksums -LockPath (Join-Path $projectRootPath 'Cargo.lock')
$document = New-RustReleaseSbomDocument `
    -ArtifactId $ArtifactId `
    -ArtifactName $ArtifactName `
    -ArtifactVersion $ArtifactVersion `
    -Metadata $metadata `
    -RootPackageName $RootPackageName `
    -Checksums $checksums
Sort-CycloneDxCollections $document
Write-PublicReleaseJson `
    -Value $document `
    -Path $OutputPath `
    -ProjectRoot $projectRootPath
Write-Output "Created Rust SBOM: $OutputPath"
