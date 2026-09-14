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

if ($Action -ceq 'Render') {
    [pscustomobject][ordered]@{
        taskName = $taskName
        executable = $binaryPath
        arguments = $arguments
        logonType = 'Interactive'
        runLevel = 'Limited'
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

function Assert-ManagedTask {
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

    Assert-ManagedTask -Task $Task
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
            Assert-ManagedTask -Task $task
        }
        else {
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
                -ExecutionTimeLimit ([TimeSpan]::Zero) `
                -MultipleInstances IgnoreNew `
                -RestartCount 3 `
                -RestartInterval (New-TimeSpan -Minutes 1)
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
