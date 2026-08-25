#Requires -Version 7.4
<#
.SYNOPSIS
    Rejects build-host paths from all JSON release metadata.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Directory,

    [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
)

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'ReleaseMetadata.Functions.ps1')

$files = @(
    Get-ChildItem -LiteralPath $Directory -File |
        Where-Object { $_.Extension -in @('.json', '.jsonl') }
)
if ($files.Count -eq 0 -or $files.Count -gt 128) {
    throw 'Public release metadata file count is outside its bound.'
}
$forbidden = Get-ReleaseMetadataForbiddenValues $ProjectRoot
foreach ($file in $files) {
    if ($file.Length -le 0 -or $file.Length -gt 32MB) {
        throw "Public release metadata size is invalid: $($file.Name)"
    }
    Assert-PublicReleaseMetadata `
        -Json (Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8) `
        -ForbiddenValues $forbidden
}

Write-Output "Public release metadata passed for $($files.Count) files."
