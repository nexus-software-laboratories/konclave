#Requires -Version 7.4
<#
.SYNOPSIS
    Creates a canonical SHA-256 manifest for one complete release directory.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Directory
)

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'ReleaseIntegrity.Functions.ps1')

$manifest = New-ReleaseChecksums -Directory $Directory
Write-Output "Created checksum manifest: $manifest"
