#Requires -Version 7.0
<#
.SYNOPSIS
    Install the release binary as a Windows Service.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$BinaryPath = (
        Join-Path $PSScriptRoot '..' '..' '..' '..' 'bin' 'KonclaveLocalServiceHost.exe'
    ),

    [string]$ConfigPath = (
        Join-Path $env:LOCALAPPDATA 'Konclave' 'service' 'konclave-local-service.json'
    ),

    [PSCredential]$Credential,

    [ValidateSet('Install', 'Start', 'Stop', 'Status', 'Uninstall')]
    [string]$Action = 'Install'
)

$ErrorActionPreference = 'Stop'

if (-not $IsWindows) {
    throw 'Windows Service installation must run on Windows.'
}
$serviceName = 'KonclaveLocalService'
$displayName = 'Konclave shared local service'
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

function Get-ExpectedServiceCommand {
    $resolvedBinary = (Resolve-Path -LiteralPath $BinaryPath).Path
    $resolvedConfig = (Resolve-Path -LiteralPath $ConfigPath).Path
    return "`"$resolvedBinary`" --config `"$resolvedConfig`""
}

function Assert-ManagedService {
    if ($null -eq $service) {
        throw "Windows Service '$serviceName' is not installed."
    }
    $record = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if (-not ([string]$record.PathName).Equals(
        (Get-ExpectedServiceCommand),
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Windows Service '$serviceName' uses another command."
    }
}

switch ($Action) {
    'Install' {
        $resolvedBinary = (Resolve-Path -LiteralPath $BinaryPath).Path
        $command = Get-ExpectedServiceCommand
        if ($null -ne $service) {
            $record = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
            if (-not ([string]$record.PathName).Equals(
                $command,
                [StringComparison]::OrdinalIgnoreCase
            )) {
                throw "Windows Service '$serviceName' already exists with another command."
            }
        }
        else {
            if ($null -eq $Credential) {
                throw '-Credential is required when creating the per-user service.'
            }
            if ($PSCmdlet.ShouldProcess($serviceName, "Install '$resolvedBinary'")) {
                $service = New-Service `
                    -Name $serviceName `
                    -DisplayName $displayName `
                    -BinaryPathName $command `
                    -Credential $Credential `
                    -StartupType Automatic
            }
        }
        if ($null -eq $service) { return }
        if ($service.Status -ne 'Running' -and $PSCmdlet.ShouldProcess($serviceName, 'Start')) {
            Start-Service -Name $serviceName
        }
    }
    'Start' {
        Assert-ManagedService
        if ($PSCmdlet.ShouldProcess($serviceName, 'Start')) { Start-Service -Name $serviceName }
    }
    'Stop' {
        if ($null -ne $service) { Assert-ManagedService }
        if ($null -ne $service -and $service.Status -ne 'Stopped' -and
            $PSCmdlet.ShouldProcess($serviceName, 'Stop')) {
            Stop-Service -Name $serviceName
        }
    }
    'Status' {
        Assert-ManagedService
        $service
    }
    'Uninstall' {
        if ($null -ne $service) { Assert-ManagedService }
        if ($null -ne $service -and $PSCmdlet.ShouldProcess($serviceName, 'Uninstall')) {
            if ($service.Status -ne 'Stopped') { Stop-Service -Name $serviceName }
            Remove-Service -Name $serviceName
        }
    }
}
