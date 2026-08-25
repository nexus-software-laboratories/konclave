#Requires -Version 7.4
<#
.SYNOPSIS
    Verifies exact release-file coverage and every SHA-256 digest.
#>
[CmdletBinding()]
param(
    [string]$Directory = $PSScriptRoot
)

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'ReleaseIntegrity.Functions.ps1')

$count = Test-ReleaseChecksums -Directory $Directory
$contractCount = Test-ReleaseContractCoverage -Directory $Directory
if ($count -ne $contractCount) {
    throw 'Checksum and release-contract file counts differ.'
}
Write-Output "Verified $count release files against SHA256SUMS and RELEASE.json."
