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

Write-Output 'Relay migration installer orchestration passed.'
