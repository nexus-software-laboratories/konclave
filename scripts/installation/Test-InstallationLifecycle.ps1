#Requires -Version 7.4

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'InstallationLifecycle.Functions.ps1')

function New-TestVersion {
    param(
        [string]$Version,
        [string]$DigestCharacter
    )

    return New-InstalledVersionRecord `
        -Version $Version `
        -ArtifactSha256 ($DigestCharacter * 64) `
        -SourceCommit ($DigestCharacter * 40) `
        -Target 'x86_64-unknown-linux-gnu' `
        -RootDirectory "konclave-client-$Version-x86_64-unknown-linux-gnu"
}

function Assert-LifecycleError {
    param(
        [scriptblock]$Action,
        [string]$Expected
    )

    try {
        & $Action
    }
    catch {
        if ($_.Exception.Message -cne $Expected) {
            throw "Expected $Expected, received $($_.Exception.Message)."
        }
        return
    }
    throw "Expected lifecycle error: $Expected"
}

$v1 = New-TestVersion -Version '0.1.0' -DigestCharacter '1'
$v2 = New-TestVersion -Version '0.2.0' -DigestCharacter '2'
$empty = New-InstallationState
$installed = New-InstallationState -ActiveVersion '0.1.0' -Versions @($v1)
$updated = New-InstallationState `
    -ActiveVersion '0.2.0' `
    -PreviousVersion '0.1.0' `
    -Versions @($v1, $v2)

$cases = @(
    @{ Name = 'fresh install'; Action = 'Install'; State = $empty; Candidate = $v1; Kind = 'Install' },
    @{ Name = 'repeat install'; Action = 'Install'; State = $installed; Candidate = $v1; Kind = 'Verify' },
    @{ Name = 'new update'; Action = 'Update'; State = $installed; Candidate = $v2; Kind = 'Update' },
    @{ Name = 'repeat update'; Action = 'Update'; State = $updated; Candidate = $v2; Kind = 'Verify' },
    @{ Name = 'switch installed'; Action = 'Update'; State = $updated; Candidate = $v1; Kind = 'Switch' },
    @{ Name = 'default rollback'; Action = 'Rollback'; State = $updated; Kind = 'Rollback'; Target = '0.1.0' },
    @{ Name = 'installed status'; Action = 'Status'; State = $installed; Kind = 'Inspect'; Target = '0.1.0' },
    @{ Name = 'empty uninstall'; Action = 'Uninstall'; State = $empty; Kind = 'NoOp' },
    @{ Name = 'installed uninstall'; Action = 'Uninstall'; State = $installed; Kind = 'Uninstall'; Target = '0.1.0' }
)
foreach ($case in $cases) {
    $arguments = @{
        Action = $case.Action
        State = $case.State
    }
    if ($case.ContainsKey('Candidate')) {
        $arguments.Candidate = $case.Candidate
    }
    $decision = Resolve-InstallationLifecycle @arguments
    $expectedTarget = if ($case.ContainsKey('Target')) {
        [string]$case.Target
    }
    elseif ($case.ContainsKey('Candidate')) {
        [string]$case.Candidate.version
    }
    else {
        ''
    }
    if (
        [string]$decision.kind -cne [string]$case.Kind -or
        [string]$decision.targetVersion -cne $expectedTarget
    ) {
        throw "Lifecycle case failed: $($case.Name)"
    }
}

Assert-LifecycleError {
    Resolve-InstallationLifecycle `
        -Action Install `
        -State $installed `
        -Candidate $v2
} 'installer.use_update'
Assert-LifecycleError {
    Resolve-InstallationLifecycle -Action Update -State $empty -Candidate $v1
} 'installer.not_installed'
Assert-LifecycleError {
    Resolve-InstallationLifecycle -Action Rollback -State $installed
} 'installer.rollback_unavailable'
Assert-LifecycleError {
    $conflict = New-TestVersion -Version '0.1.0' -DigestCharacter '3'
    Resolve-InstallationLifecycle -Action Update -State $installed -Candidate $conflict
} 'installer.version_digest_conflict'
Assert-LifecycleError {
    Resolve-InstallationLifecycle `
        -Action Rollback `
        -State $updated `
        -RollbackVersion '0.3.0'
} 'installer.rollback_missing'
Assert-LifecycleError {
    Complete-InstallationLifecycle `
        -State $installed `
        -Decision ([pscustomobject]@{ kind = 'Unknown'; targetVersion = $null })
} 'installer.unknown_decision'
Assert-LifecycleError {
    Assert-InstallationState -State ([pscustomobject]@{
        schemaVersion = 1
        activeVersion = $null
        previousVersion = $null
        versions = @()
        unexpected = $true
    })
} 'installer.invalid_state'

$afterInstall = Complete-InstallationLifecycle `
    -State $empty `
    -Decision (Resolve-InstallationLifecycle -Action Install -State $empty -Candidate $v1) `
    -Candidate $v1
if (
    [string]$afterInstall.activeVersion -cne '0.1.0' -or
    $afterInstall.versions.Count -ne 1
) {
    throw 'Install transition did not publish the candidate.'
}
$afterUpdate = Complete-InstallationLifecycle `
    -State $installed `
    -Decision (Resolve-InstallationLifecycle -Action Update -State $installed -Candidate $v2) `
    -Candidate $v2
if (
    [string]$afterUpdate.activeVersion -cne '0.2.0' -or
    [string]$afterUpdate.previousVersion -cne '0.1.0' -or
    $afterUpdate.versions.Count -ne 2
) {
    throw 'Update transition did not retain the rollback version.'
}
$afterRollback = Complete-InstallationLifecycle `
    -State $updated `
    -Decision (Resolve-InstallationLifecycle -Action Rollback -State $updated)
if (
    [string]$afterRollback.activeVersion -cne '0.1.0' -or
    [string]$afterRollback.previousVersion -cne '0.2.0'
) {
    throw 'Rollback transition did not swap active and previous versions.'
}

$recoveryCases = @(
    @{ Phase = 'Prepared'; Previous = '0.1.0'; Expected = 'RemoveCandidate' },
    @{ Phase = 'PreviousStopped'; Previous = '0.1.0'; Expected = 'RestorePrevious' },
    @{ Phase = 'CandidateStarted'; Previous = $null; Expected = 'RemoveCandidate' },
    @{ Phase = 'CandidateHealthy'; Previous = '0.1.0'; Expected = 'RestorePrevious' },
    @{ Phase = 'Committed'; Previous = '0.1.0'; Expected = 'None' }
)
foreach ($case in $recoveryCases) {
    $actual = Resolve-InstallationRecovery `
        -Phase $case.Phase `
        -PreviousVersion $case.Previous
    if ($actual -cne $case.Expected) {
        throw "Recovery case failed: $($case.Phase)"
    }
}

$blocked = Resolve-AgentPluginActivation `
    -ServiceHealth Unhealthy `
    -LegacyExtensionPresent $true
$ready = Resolve-AgentPluginActivation `
    -ServiceHealth Healthy `
    -LegacyExtensionPresent $true
if (
    $blocked.status -cne 'Blocked' -or
    $blocked.restartRequired -or
    $ready.status -cne 'Ready' -or
    -not $ready.restartRequired
) {
    throw 'Agent Plugin activation readiness is not health-gated.'
}

Write-Output "Installer lifecycle contract passed for $($cases.Count) decisions."
