#Requires -Version 7.4
<#
.SYNOPSIS
    Manages the owner-session Konclave service through one exact scheduled task.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$InstallRoot,

    [Parameter(Mandatory)]
    [string]$ConfigPath,

    [ValidateSet('Install', 'Start', 'Stop', 'Status', 'Uninstall', 'Render')]
    [string]$Action = 'Install'
)

$ErrorActionPreference = 'Stop'

$taskName = 'KonclaveLocalService'
$binaryPath = [IO.Path]::GetFullPath(
    (Join-Path $InstallRoot 'bin' 'KonclaveLocalService.exe')
)
$configurationPath = [IO.Path]::GetFullPath($ConfigPath)
if (
    "$binaryPath$configurationPath".Contains("`r") -or
    "$binaryPath$configurationPath".Contains("`n") -or
    "$binaryPath$configurationPath".Contains('"')
) {
    throw 'Service paths contain unsupported task-scheduler characters.'
}
$arguments = "--config `"$configurationPath`""
$restartCount = 999
$restartInterval = New-TimeSpan -Minutes 1

if ($Action -ceq 'Render') {
    [pscustomobject][ordered]@{
        taskName = $taskName
        executable = $binaryPath
        arguments = $arguments
        logonType = 'Interactive'
        runLevel = 'Limited'
        startWhenAvailable = $true
        stopOnIdleEnd = $false
        restartCount = $restartCount
        restartInterval = $restartInterval.ToString()
    } | ConvertTo-Json -Compress
    return
}
if (-not $IsWindows) {
    throw 'Windows user-service management must run on Windows.'
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($null -eq $identity.User -or [string]::IsNullOrWhiteSpace($identity.Name)) {
    throw 'Current Windows identity is unavailable.'
}
$currentSid = $identity.User.Value

function Resolve-TaskPrincipalSid {
    param(
        [Parameter(Mandatory)]
        [string]$UserId
    )

    if ($UserId -match '^S-\d-(?:\d+-)+\d+$') {
        return $UserId
    }
    return ([Security.Principal.NTAccount]::new($UserId)).Translate(
        [Security.Principal.SecurityIdentifier]
    ).Value
}

function Get-ManagedTask {
    return Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
}

function Assert-ManagedTaskOwnership {
    param(
        [Parameter(Mandatory)]
        $Task
    )

    $actions = @($Task.Actions)
    if (
        $actions.Count -ne 1 -or
        -not ([string]$actions[0].Execute).Equals(
            $binaryPath,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        [string]$actions[0].Arguments -cne $arguments -or
        (Resolve-TaskPrincipalSid -UserId ([string]$Task.Principal.UserId)) -cne
            $currentSid
    ) {
        throw "Scheduled task '$taskName' is not owned by this installation."
    }
}

function Test-ManagedTaskSettings {
    param(
        [Parameter(Mandatory)]
        $Task
    )

    return (
        [bool]$Task.Settings.StartWhenAvailable -and
        -not [bool]$Task.Settings.IdleSettings.StopOnIdleEnd -and
        [int]$Task.Settings.RestartCount -eq $restartCount -and
        [string]$Task.Settings.RestartInterval -ceq "PT$(
            [int]$restartInterval.TotalMinutes
        )M"
    )
}

function Assert-ManagedTask {
    param(
        [Parameter(Mandatory)]
        $Task
    )

    Assert-ManagedTaskOwnership -Task $Task
    if (-not (Test-ManagedTaskSettings -Task $Task)) {
        throw "Scheduled task '$taskName' recovery settings do not match this installation."
    }
}

function Wait-ManagedProcessExit {
    for ($attempt = 0; $attempt -lt 50; $attempt++) {
        $processes = @(
            Get-CimInstance Win32_Process -Filter "Name='KonclaveLocalService.exe'" |
                Where-Object {
                    -not [string]::IsNullOrWhiteSpace([string]$_.ExecutablePath) -and
                    ([string]$_.ExecutablePath).Equals(
                        $binaryPath,
                        [StringComparison]::OrdinalIgnoreCase
                    )
                }
        )
        if ($processes.Count -eq 0) {
            return
        }
        Start-Sleep -Milliseconds 100
    }
    throw "Scheduled task '$taskName' process did not stop."
}

function Stop-ManagedTask {
    param(
        [Parameter(Mandatory)]
        $Task
    )

    Assert-ManagedTaskOwnership -Task $Task
    if ($Task.State -eq 'Running') {
        Stop-ScheduledTask -TaskName $taskName
    }
    Wait-ManagedProcessExit
}

$task = Get-ManagedTask
switch ($Action) {
    'Install' {
        if (
            -not (Test-Path -LiteralPath $binaryPath -PathType Leaf) -or
            -not (Test-Path -LiteralPath $configurationPath -PathType Leaf)
        ) {
            throw 'Service binary or configuration is missing.'
        }
        if ($null -ne $task) {
            Assert-ManagedTaskOwnership -Task $task
            if (-not (Test-ManagedTaskSettings -Task $task)) {
                Stop-ManagedTask -Task $task
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
                $task = $null
            }
        }
        if ($null -eq $task) {
            $taskAction = New-ScheduledTaskAction `
                -Execute $binaryPath `
                -Argument $arguments
            $trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity.Name
            $principal = New-ScheduledTaskPrincipal `
                -UserId $identity.Name `
                -LogonType Interactive `
                -RunLevel Limited
            $settings = New-ScheduledTaskSettingsSet `
                -AllowStartIfOnBatteries `
                -DontStopIfGoingOnBatteries `
                -DontStopOnIdleEnd `
                -ExecutionTimeLimit ([TimeSpan]::Zero) `
                -MultipleInstances IgnoreNew `
                -RestartCount $restartCount `
                -RestartInterval $restartInterval `
                -StartWhenAvailable
            $task = Register-ScheduledTask `
                -TaskName $taskName `
                -Action $taskAction `
                -Trigger $trigger `
                -Principal $principal `
                -Settings $settings
        }
        Start-ScheduledTask -TaskName $taskName
    }
    'Start' {
        if ($null -eq $task) {
            throw "Scheduled task '$taskName' is not installed."
        }
        Assert-ManagedTask -Task $task
        Start-ScheduledTask -TaskName $taskName
    }
    'Stop' {
        if ($null -ne $task) {
            Stop-ManagedTask -Task $task
        }
    }
    'Status' {
        if ($null -eq $task) {
            throw "Scheduled task '$taskName' is not installed."
        }
        Assert-ManagedTask -Task $task
        $information = Get-ScheduledTaskInfo -TaskName $taskName
        [pscustomobject][ordered]@{
            taskName = $taskName
            state = [string]$task.State
            lastTaskResult = [int]$information.LastTaskResult
            lastRunTime = $information.LastRunTime
            nextRunTime = $information.NextRunTime
        }
    }
    'Uninstall' {
        if ($null -ne $task) {
            Stop-ManagedTask -Task $task
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        }
    }
}
