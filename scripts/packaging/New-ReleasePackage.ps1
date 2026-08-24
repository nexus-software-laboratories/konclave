#Requires -Version 7.4
<#
.SYNOPSIS
    Creates one deterministic unsigned Konclave prerelease archive.
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
    [ValidateSet('client', 'relay')]
    [string]$Kind,

    [Parameter(Mandatory)]
    [string]$BinaryDirectory,

    [string]$PluginArchivePath,

    [string]$OutputDirectory = 'target/release-artifacts'
)

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'ReleasePackaging.Functions.ps1')

$artifact = New-ReleasePackage `
    -ProjectRoot $ProjectRoot `
    -Target $Target `
    -Kind $Kind `
    -BinaryDirectory $BinaryDirectory `
    -PluginArchivePath $PluginArchivePath `
    -OutputDirectory $OutputDirectory

Write-Output "Created release artifact: $artifact"
