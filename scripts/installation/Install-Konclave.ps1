#Requires -Version 7.4

<#
.SYNOPSIS
    Installs, updates, migrates relay state, or removes the per-user runtime.
.DESCRIPTION
    Uses an explicitly selected, verified release directory for native runtime
    installation. Keep checksums, provenance and assets from the same release.
    Native runtime health and plugin activation are separate lifecycle decisions.

    Update failures restore and recheck the previous runtime. Ordinary uninstall
    retains identity, profiles and durable authority; permanent state deletion
    requires both destructive switches. Errors stop the operation rather than
    creating replacement custody or silently changing authorization policy.
.PARAMETER Action
    Defaults to Install. Update changes the native version; Rollback selects a
    retained version; Status inspects installation state. PrepareMarketplace is
    the normal marketplace setup path. ActivatePlugin is direct-install
    compatibility. MigrateRelay uses journaled apply/abort recovery.
.PARAMETER ReleaseDirectory
    Directory containing the matching verified release assets. Required by
    actions that consume a candidate release; not a download URL or plugin cache.
.PARAMETER DataRoot
    Explicit installation data-root override. Omit for the platform convention.
    Select the existing installation deliberately; do not discover another profile.
.PARAMETER RollbackVersion
    Exact retained version for Rollback. Omit to use the recorded previous version.
.PARAMETER RelayEndpoint
    Explicit relay URL for initialization or migration. TLS is required outside
    loopback. A route or URL alone is not enrollment authority.
.PARAMETER AuthorizationPolicy
    Initial account-trusted or user-presence evidence policy; noninteractive
    initialization requires an explicit choice. UserPresence needs supported
    Windows native evidence. This is not an in-place policy migration shortcut.
.PARAMETER ExternalSource
    Absolute Unix headless enrollment-source path, not a plaintext environment
    credential. Retain the protected source independently of versioned binaries.
.PARAMETER ServiceIdentityFile
    Explicit owner-protected headless service identity input. Do not replace it
    to repair an existing installation or expose its contents.
.PARAMETER ProfileKeyDirectory
    Explicit headless per-profile wrapping-key directory. Preserve its custody,
    ownership and contents across runtime updates.
.PARAMETER AllowNoRecovery
    Explicitly acknowledges that loss of all UserPresence credentials can strand
    administration. It does not bypass authentication or authorize fallback.
.PARAMETER RemoveState
    Requests permanent installation-state deletion during Uninstall. Requires
    the separate ConfirmStateRemoval acknowledgment; incomplete requests fail.
.PARAMETER ConfirmStateRemoval
    Confirms the destructive RemoveState request. Ordinary Uninstall omits both.
.EXAMPLE
    .\Install-Konclave.ps1 -Action Status

    Inspects the platform-default installation without changing plugin activation.
.EXAMPLE
    .\Install-Konclave.ps1 -Action Update -ReleaseDirectory '.\verified-release'

    Updates an existing installation from an independently verified matching
    release set. Replace the example directory with that explicit input.
.EXAMPLE
    .\Install-Konclave.ps1 -Action Uninstall

    Removes the owned runtime and supervision while preserving durable state.
.NOTES
    Requires PowerShell 7.4 or newer. Follow docs/distribution/installation.md for
    release verification, platform prerequisites, initialization and recovery.
    Plugin hooks/restart and native runtime supervision have separate owners.
#>
[CmdletBinding()]
param(
    [ValidateSet(
        'Install',
        'Update',
        'Rollback',
        'Uninstall',
        'Status',
        'ActivatePlugin',
        'PrepareMarketplace',
        'MigrateRelay'
    )]
    [string]$Action = 'Install',

    [string]$ReleaseDirectory,

    [string]$DataRoot,

    [string]$RollbackVersion,

    [string]$RelayEndpoint,

    [ValidateSet('account-trusted', 'user-presence')]
    [string]$AuthorizationPolicy,

    [string]$ExternalSource,

    [string]$ServiceIdentityFile,

    [string]$ProfileKeyDirectory,

    [switch]$AllowNoRecovery,

    [switch]$RemoveState,

    [switch]$ConfirmStateRemoval
)

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'InstallationRuntime.Functions.ps1')

function Get-StateVersionRecord {
    param(
        [Parameter(Mandatory)]
        $State,

        [Parameter(Mandatory)]
        [string]$Version
    )

    $record = Find-InstalledVersion -State $State -Version $Version
    if ($null -eq $record) {
        throw "Installed version is missing from state: $Version"
    }
    return $record
}

function Remove-CandidateVersion {
    param(
        [Parameter(Mandatory)]
        $Paths,

        [Parameter(Mandatory)]
        [string]$Version
    )

    $versionRoot = Join-Path $Paths.versionsRoot $Version
    if (Test-Path -LiteralPath $versionRoot) {
        Remove-InstallerDirectory -Path $versionRoot
    }
}

function Restore-PreviousRuntime {
    param(
        [Parameter(Mandatory)]
        $Paths,

        [Parameter(Mandatory)]
        $PreviousRecord
    )

    $previousRoot = Get-InstalledVersionRoot -Paths $Paths -Record $PreviousRecord
    [void](Invoke-ServiceManager `
        -Action Install `
        -InstallRoot $previousRoot `
        -ConfigPath $Paths.serviceConfigPath)
    [void](Wait-InstalledRuntimeHealth `
        -InstallRoot $previousRoot `
        -Paths $Paths)
}

function Write-InstallationResult {
    param(
        [Parameter(Mandatory)]
        [string]$ResultAction,

        [AllowNull()]
        [string]$Version,

        [AllowNull()]
        [string]$InstallRoot,

        [AllowNull()]
        $Plugin
    )

    [pscustomobject][ordered]@{
        action = $ResultAction
        version = $Version
        installRoot = $InstallRoot
        pluginStatus = if ($null -eq $Plugin) { 'NotChanged' } else { $Plugin.status }
        pluginRoot = if ($null -eq $Plugin) { $null } else { $Plugin.pluginRoot }
        restartRequired = if ($null -eq $Plugin) { $false } else { $Plugin.restartRequired }
    } | ConvertTo-Json -Depth 10
}

function Write-RelayMigrationResult {
    param(
        [Parameter(Mandatory)]
        [string]$Version,

        [Parameter(Mandatory)]
        [string]$InstallRoot,

        [Parameter(Mandatory)]
        $Migration
    )

    [pscustomobject][ordered]@{
        action = [string]$Migration.action
        version = $Version
        installRoot = $InstallRoot
        sourceEndpoint = [string]$Migration.sourceEndpoint
        destinationEndpoint = [string]$Migration.destinationEndpoint
        totalProfiles = [int]$Migration.totalProfiles
        migratedProfiles = [int]$Migration.migratedProfiles
        unchangedProfiles = [int]$Migration.unchangedProfiles
        pluginStatus = 'NotChanged'
        pluginRoot = $null
        restartRequired = $false
    } | ConvertTo-Json -Depth 10
}

$paths = Get-InstallationPaths -DataRoot $DataRoot
Initialize-InstallationPaths -Paths $paths
$state = Read-InstallationState -Path $paths.statePath

if ($Action -ceq 'ActivatePlugin') {
    if ([string]::IsNullOrEmpty([string]$state.activeVersion)) {
        throw 'installer.not_installed'
    }
    $record = Get-StateVersionRecord -State $state -Version ([string]$state.activeVersion)
    $root = Get-InstalledVersionRoot -Paths $paths -Record $record
    [void](Wait-InstalledRuntimeHealth -InstallRoot $root -Paths $paths -Attempts 1 -DelaySeconds 0)
    $plugin = Enable-InstallerAgentPlugin `
        -InstallRoot $root `
        -Paths $paths `
        -Version ([string]$record.version) `
        -EnableDirectAgentPlugin
    Write-InstallationResult `
        -ResultAction PluginActivated `
        -Version $record.version `
        -InstallRoot $root `
        -Plugin $plugin
    return
}

if ($Action -ceq 'PrepareMarketplace') {
    if ([string]::IsNullOrEmpty([string]$state.activeVersion)) {
        throw 'installer.not_installed'
    }
    $record = Get-StateVersionRecord -State $state -Version ([string]$state.activeVersion)
    $root = Get-InstalledVersionRoot -Paths $paths -Record $record
    [void](Wait-InstalledRuntimeHealth `
        -InstallRoot $root `
        -Paths $paths `
        -Attempts 1 `
        -DelaySeconds 0)
    $plugin = Prepare-InstallerMarketplace -Paths $paths
    Write-InstallationResult `
        -ResultAction MarketplacePrepared `
        -Version $record.version `
        -InstallRoot $root `
        -Plugin $plugin
    return
}

if ($Action -ceq 'MigrateRelay') {
    if ([string]::IsNullOrEmpty([string]$state.activeVersion)) {
        throw 'installer.not_installed'
    }
    if ([string]::IsNullOrWhiteSpace($RelayEndpoint)) {
        throw '-RelayEndpoint is required for MigrateRelay.'
    }
    $record = Get-StateVersionRecord -State $state -Version ([string]$state.activeVersion)
    $root = Get-InstalledVersionRoot -Paths $paths -Record $record
    $migration = Invoke-TransactionalRelayMigration `
        -InstallRoot $root `
        -Paths $paths `
        -RelayEndpoint $RelayEndpoint
    Write-RelayMigrationResult `
        -Version ([string]$record.version) `
        -InstallRoot $root `
        -Migration $migration
    return
}

if ($Action -ceq 'Status') {
    $decision = Resolve-InstallationLifecycle -Action Status -State $state
    if ([string]$decision.targetVersion -eq '') {
        Write-InstallationResult -ResultAction NotInstalled
        return
    }
    $record = Get-StateVersionRecord -State $state -Version $decision.targetVersion
    $root = Get-InstalledVersionRoot -Paths $paths -Record $record
    [void](Invoke-ServiceManager `
        -Action Status `
        -InstallRoot $root `
        -ConfigPath $paths.serviceConfigPath)
    [void](Wait-InstalledRuntimeHealth -InstallRoot $root -Paths $paths -Attempts 1 -DelaySeconds 0)
    Write-InstallationResult `
        -ResultAction Healthy `
        -Version $record.version `
        -InstallRoot $root
    return
}

if ($Action -ceq 'Uninstall') {
    if ($RemoveState -and -not $ConfirmStateRemoval) {
        throw '-RemoveState requires -ConfirmStateRemoval.'
    }
    $decision = Resolve-InstallationLifecycle -Action Uninstall -State $state
    if ($decision.kind -ceq 'NoOp') {
        Write-InstallationResult -ResultAction NotInstalled
        return
    }
    $record = Get-StateVersionRecord -State $state -Version $decision.targetVersion
    $root = Get-InstalledVersionRoot -Paths $paths -Record $record
    $pluginRemoved = Disable-InstallerAgentPlugin -Paths $paths
    [void](Invoke-ServiceManager `
        -Action Uninstall `
        -InstallRoot $root `
        -ConfigPath $paths.serviceConfigPath)
    if (Test-Path -LiteralPath $paths.versionsRoot) {
        Remove-InstallerDirectory -Path $paths.versionsRoot
    }
    if (Test-Path -LiteralPath $paths.statePath) {
        Remove-Item -LiteralPath $paths.statePath -Force
    }
    if (Test-Path -LiteralPath $paths.clientConfigPath) {
        [void](Assert-SafeInstallationItem -Path $paths.clientConfigPath -Kind File)
        Remove-Item -LiteralPath $paths.clientConfigPath -Force
    }
    if ($RemoveState) {
        foreach ($path in @($paths.profileRoot, $paths.serviceRoot, $paths.legacyRoot)) {
            if (Test-Path -LiteralPath $path) {
                [void](Assert-SafeInstallationItem -Path $path -Kind Directory)
                Remove-Item -LiteralPath $path -Recurse -Force
            }
        }
    }
    $plugin = if ($pluginRemoved) {
        [pscustomobject]@{
            status = 'RemovedDirect'
            pluginRoot = $null
            restartRequired = $true
        }
    }
    else {
        $null
    }
    Write-InstallationResult `
        -ResultAction Uninstalled `
        -Version $record.version `
        -Plugin $plugin
    return
}

if ($Action -ceq 'Rollback') {
    $decision = Resolve-InstallationLifecycle `
        -Action Rollback `
        -State $state `
        -RollbackVersion $RollbackVersion
    $currentRecord = Get-StateVersionRecord `
        -State $state `
        -Version ([string]$state.activeVersion)
    $targetRecord = Get-StateVersionRecord `
        -State $state `
        -Version ([string]$decision.targetVersion)
    $currentRoot = Get-InstalledVersionRoot -Paths $paths -Record $currentRecord
    $targetRoot = Get-InstalledVersionRoot -Paths $paths -Record $targetRecord
    try {
        [void](Invoke-ServiceManager `
            -Action Uninstall `
            -InstallRoot $currentRoot `
            -ConfigPath $paths.serviceConfigPath)
        [void](Invoke-ServiceManager `
            -Action Install `
            -InstallRoot $targetRoot `
            -ConfigPath $paths.serviceConfigPath)
        [void](Wait-InstalledRuntimeHealth -InstallRoot $targetRoot -Paths $paths)
        $nextState = Complete-InstallationLifecycle -State $state -Decision $decision
        Write-InstallationState -Path $paths.statePath -State $nextState
    }
    catch {
        $operationError = $_
        try {
            [void](Invoke-ServiceManager `
                -Action Uninstall `
                -InstallRoot $targetRoot `
                -ConfigPath $paths.serviceConfigPath)
            Restore-PreviousRuntime -Paths $paths -PreviousRecord $currentRecord
        }
        catch {
            throw "Rollback failed and the active runtime could not be restored: $(
                $operationError.Exception.Message
            )`nRecovery: $($_.Exception.Message)"
        }
        throw $operationError
    }
    $plugin = Enable-InstallerAgentPlugin `
        -InstallRoot $targetRoot `
        -Paths $paths `
        -Version ([string]$targetRecord.version)
    Write-InstallationResult `
        -ResultAction RolledBack `
        -Version $targetRecord.version `
        -InstallRoot $targetRoot `
        -Plugin $plugin
    return
}

if ([string]::IsNullOrWhiteSpace($ReleaseDirectory)) {
    throw "-ReleaseDirectory is required for $Action."
}
$candidate = Get-ReleaseInstallationCandidate -ReleaseDirectory $ReleaseDirectory
$decision = Resolve-InstallationLifecycle `
    -Action $Action `
    -State $state `
    -Candidate $candidate.record
$knownCandidate = Find-InstalledVersion `
    -State $state `
    -Version ([string]$candidate.record.version)
$candidateVersionRoot = Join-Path $paths.versionsRoot ([string]$candidate.record.version)
if ($null -eq $knownCandidate -and (Test-Path -LiteralPath $candidateVersionRoot)) {
    throw 'Untracked installer version directory already exists.'
}
$installedCandidate = Install-ReleaseCandidateFiles -Paths $paths -Candidate $candidate
$candidateRoot = [string]$installedCandidate.root

$initializationRequired = (
    -not (Test-Path -LiteralPath $paths.serviceConfigPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $paths.clientConfigPath -PathType Leaf)
)
if ($initializationRequired) {
    if ([string]::IsNullOrWhiteSpace($RelayEndpoint)) {
        if ($installedCandidate.created) {
            Remove-CandidateVersion -Paths $paths -Version $candidate.record.version
        }
        throw '-RelayEndpoint is required for the first installation.'
    }
    [void](Invoke-InstallationInitialization `
        -InstallRoot $candidateRoot `
        -Paths $paths `
        -RelayEndpoint $RelayEndpoint `
        -AuthorizationPolicy $AuthorizationPolicy `
        -ExternalSource $ExternalSource `
        -ServiceIdentityFile $ServiceIdentityFile `
        -ProfileKeyDirectory $ProfileKeyDirectory `
        -AllowNoRecovery ([bool]$AllowNoRecovery) `
        -CandidateCreated ([bool]$installedCandidate.created) `
        -CandidateVersion ([string]$candidate.record.version))
}

if ($decision.kind -ceq 'Verify') {
    [void](Invoke-ServiceManager `
        -Action Install `
        -InstallRoot $candidateRoot `
        -ConfigPath $paths.serviceConfigPath)
    [void](Wait-InstalledRuntimeHealth -InstallRoot $candidateRoot -Paths $paths)
    $plugin = Enable-InstallerAgentPlugin `
        -InstallRoot $candidateRoot `
        -Paths $paths `
        -Version ([string]$candidate.record.version)
    Write-InstallationResult `
        -ResultAction Verified `
        -Version $candidate.record.version `
        -InstallRoot $candidateRoot `
        -Plugin $plugin
    return
}

[void](Invoke-TransactionalRuntimeSwitch `
    -Paths $paths `
    -State $state `
    -Decision $decision `
    -CandidateRecord $candidate.record `
    -CandidateRoot $candidateRoot `
    -CandidateCreated ([bool]$installedCandidate.created))

$plugin = Enable-InstallerAgentPlugin `
    -InstallRoot $candidateRoot `
    -Paths $paths `
    -Version ([string]$candidate.record.version)
Write-InstallationResult `
    -ResultAction ([string]$decision.kind) `
    -Version $candidate.record.version `
    -InstallRoot $candidateRoot `
    -Plugin $plugin
