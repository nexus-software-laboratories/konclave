#Requires -Version 7.4

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'InstallationRuntime.Functions.ps1')

$paths = [pscustomobject]@{
    serviceConfigPath = 'C:\Konclave\service.json'
}

function Invoke-TestRelayMigration {
    param(
        [string]$Failure
    )

    $events = [Collections.Generic.List[string]]::new()
    $healthCalls = 0
    $migration = {
        param($Mode)
        $events.Add("migration:$Mode")
        if ($Failure -ceq "migration:$Mode") {
            throw "synthetic $Mode failure"
        }
        [pscustomobject]@{
            action = switch ($Mode) {
                'Abort' { 'RelayMigrationAborted' }
                'Finalize' { 'RelayMigrated' }
                default { 'RelayMigrationPendingHealth' }
            }
            sourceEndpoint = 'http://127.0.0.1:43180/'
            destinationEndpoint = 'https://relay.example.com/'
            totalProfiles = 2
            migratedProfiles = 2
            unchangedProfiles = 0
        }
    }.GetNewClosure()
    $service = {
        param($Action)
        $events.Add("service:$Action")
    }.GetNewClosure()
    $health = {
        $events.Add('health')
        $healthCalls++
        if ($Failure -ceq 'health' -and $healthCalls -eq 1) {
            throw 'synthetic health failure'
        }
    }.GetNewClosure()
    $protect = {
        $events.Add('protect')
        if ($Failure -ceq 'protect') {
            throw 'synthetic profile-root protection failure'
        }
    }.GetNewClosure()

    $error = $null
    try {
        $result = Invoke-TransactionalRelayMigration `
            -InstallRoot 'C:\Konclave\runtime' `
            -Paths $paths `
            -RelayEndpoint 'https://relay.example.com' `
            -MigrationInvoker $migration `
            -ServiceInvoker $service `
            -HealthVerifier $health `
            -ProfileRootProtector $protect
    }
    catch {
        $error = $_
        $result = $null
    }
    return [pscustomobject]@{
        events = @($events)
        result = $result
        error = $error
    }
}

$success = Invoke-TestRelayMigration
if (
    ($success.events -join '|') -cne (
        'service:Stop|protect|migration:Apply|service:Start|health|' +
        'migration:Finalize'
    ) -or
    [string]$success.result.action -cne 'RelayMigrated' -or
    [int]$success.result.migratedProfiles -ne 2 -or
    $null -ne $success.error
) {
    throw 'Successful relay migration orchestration is invalid.'
}

$applyFailure = Invoke-TestRelayMigration -Failure 'migration:Apply'
if (
    ($applyFailure.events -join '|') -cne (
        'service:Stop|protect|migration:Apply|migration:Abort|service:Start|health'
    ) -or
    $null -eq $applyFailure.error
) {
    throw 'Relay migration apply failure did not restore the source service.'
}

$healthFailure = Invoke-TestRelayMigration -Failure 'health'
if (
    ($healthFailure.events -join '|') -cne (
        'service:Stop|protect|migration:Apply|service:Start|health|service:Stop|' +
        'migration:Abort|service:Start|health'
    ) -or
    $null -eq $healthFailure.error
) {
    throw 'Relay migration health failure did not abort and restore the source service.'
}

$finalizeFailure = Invoke-TestRelayMigration -Failure 'migration:Finalize'
if (
    ($finalizeFailure.events -join '|') -cne (
        'service:Stop|protect|migration:Apply|service:Start|health|' +
        'migration:Finalize|service:Stop|migration:Abort|service:Start|health'
    ) -or
    $null -eq $finalizeFailure.error
) {
    throw 'Relay migration finalize failure did not abort and restore the source service.'
}

$protectionFailure = Invoke-TestRelayMigration -Failure 'protect'
if (
    ($protectionFailure.events -join '|') -cne (
        'service:Stop|protect|migration:Abort|service:Start|health'
    ) -or
    $null -eq $protectionFailure.error
) {
    throw 'Profile-root protection failure did not restore the source service.'
}

$defaultEvents = [Collections.Generic.List[string]]::new()
$functionNames = @(
    'Invoke-InstalledRelayMigration',
    'Invoke-ServiceManager',
    'Set-OwnerOnlyDirectory',
    'Wait-InstalledRuntimeHealth'
)
$originalFunctions = @{}
foreach ($name in $functionNames) {
    $originalFunctions[$name] = (Get-Item -LiteralPath "Function:$name").ScriptBlock
}
try {
    Set-Item -LiteralPath Function:Invoke-ServiceManager -Value {
        param(
            [string]$Action,
            [string]$InstallRoot,
            [string]$ConfigPath
        )
        $defaultEvents.Add("service:$Action")
    }
    Set-Item -LiteralPath Function:Set-OwnerOnlyDirectory -Value {
        param([string]$Path)
        $defaultEvents.Add('protect')
        return $Path
    }
    Set-Item -LiteralPath Function:Wait-InstalledRuntimeHealth -Value {
        param(
            [string]$InstallRoot,
            $Paths
        )
        $defaultEvents.Add('health')
    }
    Set-Item -LiteralPath Function:Invoke-InstalledRelayMigration -Value {
        param(
            [string]$InstallRoot,
            [string]$ConfigPath,
            [string]$RelayEndpoint,
            [switch]$Abort,
            [switch]$Finalize
        )
        $mode = if ($Abort) {
            'Abort'
        }
        elseif ($Finalize) {
            'Finalize'
        }
        else {
            'Apply'
        }
        $defaultEvents.Add("migration:$mode")
        [pscustomobject]@{
            action = if ($Finalize) {
                'RelayMigrated'
            }
            elseif ($Abort) {
                'RelayMigrationAborted'
            }
            else {
                'RelayMigrationPendingHealth'
            }
            sourceEndpoint = 'http://127.0.0.1:43180/'
            destinationEndpoint = 'https://relay.example.com/'
            totalProfiles = 2
            migratedProfiles = 2
            unchangedProfiles = 0
        }
    }

    $defaultPaths = [pscustomobject]@{
        serviceConfigPath = 'C:\Konclave\service.json'
        profileRoot = 'C:\Konclave\profiles'
    }
    $defaultResult = Invoke-TransactionalRelayMigration `
        -InstallRoot 'C:\Konclave\runtime' `
        -Paths $defaultPaths `
        -RelayEndpoint 'https://relay.example.com'
    if (
        ($defaultEvents -join '|') -cne (
            'service:Stop|protect|migration:Apply|service:Start|health|' +
            'migration:Finalize'
        ) -or
        [string]$defaultResult.action -cne 'RelayMigrated'
    ) {
        throw 'Default relay migration orchestration lost installer function scope.'
    }
}
finally {
    foreach ($name in $functionNames) {
        Set-Item -LiteralPath "Function:$name" -Value $originalFunctions[$name]
    }
}

Write-Output 'Relay migration installer orchestration passed.'
