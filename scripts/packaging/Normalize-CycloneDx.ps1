#Requires -Version 7.4
<#
.SYNOPSIS
    Normalizes a tool-generated CycloneDX document for deterministic public release.
#>
[CmdletBinding()]
param(
    [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path,

    [Parameter(Mandatory)]
    [string]$InputPath,

    [Parameter(Mandatory)]
    [string]$OutputPath,

    [Parameter(Mandatory)]
    [string]$ComponentName,

    [Parameter(Mandatory)]
    [string]$ComponentVersion,

    [ValidateSet('application', 'container')]
    [string]$ComponentType = 'application'
)

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'ReleaseMetadata.Functions.ps1')

$inputFullPath = (Resolve-Path -LiteralPath $InputPath).Path
$document = Get-Content -LiteralPath $inputFullPath -Raw -Encoding UTF8 |
    ConvertFrom-Json -Depth 100
if ([string]$document.bomFormat -cne 'CycloneDX') {
    throw 'Input document is not a CycloneDX SBOM.'
}
$document.PSObject.Properties.Remove('serialNumber')
Set-ReleaseJsonProperty $document '$schema' 'http://cyclonedx.org/schema/bom-1.6.schema.json'
Set-ReleaseJsonProperty $document 'specVersion' '1.6'
Set-ReleaseJsonProperty $document 'version' 1
if (-not $document.metadata) {
    Set-ReleaseJsonProperty $document 'metadata' ([pscustomobject]@{})
}
$document.metadata.PSObject.Properties.Remove('timestamp')
Set-ReleaseJsonProperty $document.metadata 'component' ([ordered]@{
    type = $ComponentType
    'bom-ref' = "pkg:generic/$([Uri]::EscapeDataString($ComponentName))@$ComponentVersion"
    name = $ComponentName
    version = $ComponentVersion
})
Sort-CycloneDxCollections $document
Write-PublicReleaseJson `
    -Value $document `
    -Path $OutputPath `
    -ProjectRoot $ProjectRoot
