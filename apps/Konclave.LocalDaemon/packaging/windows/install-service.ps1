#Requires -Version 7.0
<#
.SYNOPSIS
    Install the release binary as a Windows Service.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$BinaryPath = (
        Join-Path $PSScriptRoot '..' '..' 'target' 'release' 'windows_service.exe'
    )
)

$ErrorActionPreference = 'Stop'

if (-not $IsWindows) {
    throw 'Windows Service installation must run on Windows.'
}
$serviceName = 'KonclaveLocalDaemon'
$displayName = 'KonclaveLocalDaemon service'
$resolvedBinary = (Resolve-Path -LiteralPath $BinaryPath).Path
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    throw "Windows Service '$serviceName' already exists."
}
if ($PSCmdlet.ShouldProcess($serviceName, "Install '$resolvedBinary'")) {
    New-Service `
        -Name $serviceName `
        -DisplayName $displayName `
        -BinaryPathName "`"$resolvedBinary`"" `
        -StartupType Automatic
}
