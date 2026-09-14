#Requires -Version 7.4
<#
.SYNOPSIS
    Installs, updates, rolls back, inspects, or removes the per-user Konclave runtime.
#>
[CmdletBinding()]
param(
    [ValidateSet('Install', 'Update', 'Rollback', 'Uninstall', 'Status')]
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

    [switch]$EnableDirectAgentPlugin,

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
        [void](Assert-SafeInstallationItem -Path $versionRoot -Kind Directory)
        Remove-Item -LiteralPath $versionRoot -Recurse -Force
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

$paths = Get-InstallationPaths -DataRoot $DataRoot
Initialize-InstallationPaths -Paths $paths
$state = Read-InstallationState -Path $paths.statePath

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
    [void](Invoke-ServiceManager `
        -Action Uninstall `
        -InstallRoot $root `
        -ConfigPath $paths.serviceConfigPath)
    if (Test-Path -LiteralPath $paths.versionsRoot) {
        Remove-Item -LiteralPath $paths.versionsRoot -Recurse -Force
    }
    if (Test-Path -LiteralPath $paths.statePath) {
        Remove-Item -LiteralPath $paths.statePath -Force
    }
    if ($RemoveState) {
        foreach ($path in @($paths.profileRoot, $paths.serviceRoot)) {
            if (Test-Path -LiteralPath $path) {
                [void](Assert-SafeInstallationItem -Path $path -Kind Directory)
                Remove-Item -LiteralPath $path -Recurse -Force
            }
        }
    }
    Write-InstallationResult -ResultAction Uninstalled -Version $record.version
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
        -EnableDirectAgentPlugin:$EnableDirectAgentPlugin
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

if (-not (Test-Path -LiteralPath $paths.serviceConfigPath -PathType Leaf)) {
    if ([string]::IsNullOrWhiteSpace($RelayEndpoint)) {
        if ($installedCandidate.created) {
            Remove-CandidateVersion -Paths $paths -Version $candidate.record.version
        }
        throw '-RelayEndpoint is required for the first installation.'
    }
    $legacyRoot = Resolve-LegacyCopilotExtensionRoot
    if (-not (Test-Path -LiteralPath $legacyRoot -PathType Container)) {
        $legacyRoot = $null
    }
    [void](Initialize-InstalledRuntime `
        -InstallRoot $candidateRoot `
        -Paths $paths `
        -RelayEndpoint $RelayEndpoint `
        -AuthorizationPolicy $AuthorizationPolicy `
        -ExternalSource $ExternalSource `
        -ServiceIdentityFile $ServiceIdentityFile `
        -ProfileKeyDirectory $ProfileKeyDirectory `
        -LegacyExtensionRoot $legacyRoot `
        -AllowNoRecovery:$AllowNoRecovery)
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
        -EnableDirectAgentPlugin:$EnableDirectAgentPlugin
    Write-InstallationResult `
        -ResultAction Verified `
        -Version $candidate.record.version `
        -InstallRoot $candidateRoot `
        -Plugin $plugin
    return
}

$previousRecord = if ([string]::IsNullOrEmpty([string]$state.activeVersion)) {
    $null
}
else {
    Get-StateVersionRecord -State $state -Version ([string]$state.activeVersion)
}
$candidateManagerInstalled = $false
try {
    if ($null -ne $previousRecord) {
        $previousRoot = Get-InstalledVersionRoot -Paths $paths -Record $previousRecord
        [void](Invoke-ServiceManager `
            -Action Uninstall `
            -InstallRoot $previousRoot `
            -ConfigPath $paths.serviceConfigPath)
    }
    [void](Invoke-ServiceManager `
        -Action Install `
        -InstallRoot $candidateRoot `
        -ConfigPath $paths.serviceConfigPath)
    $candidateManagerInstalled = $true
    [void](Wait-InstalledRuntimeHealth -InstallRoot $candidateRoot -Paths $paths)
    $nextState = Complete-InstallationLifecycle `
        -State $state `
        -Decision $decision `
        -Candidate $candidate.record
    Write-InstallationState -Path $paths.statePath -State $nextState
}
catch {
    $operationError = $_
    try {
        if ($candidateManagerInstalled) {
            [void](Invoke-ServiceManager `
                -Action Uninstall `
                -InstallRoot $candidateRoot `
                -ConfigPath $paths.serviceConfigPath)
        }
        if ($null -ne $previousRecord) {
            Restore-PreviousRuntime -Paths $paths -PreviousRecord $previousRecord
        }
        if ($installedCandidate.created) {
            Remove-CandidateVersion -Paths $paths -Version $candidate.record.version
        }
    }
    catch {
        throw "$Action failed and the previous runtime could not be restored: $(
            $operationError.Exception.Message
        )`nRecovery: $($_.Exception.Message)"
    }
    throw $operationError
}

$plugin = Enable-InstallerAgentPlugin `
    -InstallRoot $candidateRoot `
    -Paths $paths `
    -EnableDirectAgentPlugin:$EnableDirectAgentPlugin
Write-InstallationResult `
    -ResultAction ([string]$decision.kind) `
    -Version $candidate.record.version `
    -InstallRoot $candidateRoot `
    -Plugin $plugin
