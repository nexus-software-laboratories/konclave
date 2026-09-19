#Requires -Version 7.4

Set-StrictMode -Version Latest

$script:InstallationSchemaVersion = 1
$script:VersionPattern = '^[0-9]+\.[0-9]+\.[0-9]+$'
$script:Sha256Pattern = '^[0-9a-f]{64}$'
$script:CommitPattern = '^[0-9a-f]{40}$'
$script:TargetPattern = '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'
$script:RootDirectoryPattern = '^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$'

function New-InstalledVersionRecord {
    param(
        [Parameter(Mandatory)]
        [string]$Version,

        [Parameter(Mandatory)]
        [string]$ArtifactSha256,

        [Parameter(Mandatory)]
        [string]$SourceCommit,

        [Parameter(Mandatory)]
        [string]$Target,

        [Parameter(Mandatory)]
        [string]$RootDirectory
    )

    if (
        $Version -cnotmatch $script:VersionPattern -or
        $ArtifactSha256 -cnotmatch $script:Sha256Pattern -or
        $SourceCommit -cnotmatch $script:CommitPattern -or
        $Target -cnotmatch $script:TargetPattern -or
        $RootDirectory -cnotmatch $script:RootDirectoryPattern -or
        -not $RootDirectory.Contains($Version, [StringComparison]::Ordinal)
    ) {
        throw [ArgumentException]::new('installer.invalid_version_record')
    }
    return [pscustomobject][ordered]@{
        version = $Version
        artifactSha256 = $ArtifactSha256
        sourceCommit = $SourceCommit
        target = $Target
        rootDirectory = $RootDirectory
    }
}

function New-InstallationState {
    param(
        [AllowNull()]
        [string]$ActiveVersion,

        [AllowNull()]
        [string]$PreviousVersion,

        [object[]]$Versions = @()
    )

    $state = [pscustomobject][ordered]@{
        schemaVersion = $script:InstallationSchemaVersion
        activeVersion = $ActiveVersion
        previousVersion = $PreviousVersion
        versions = @($Versions)
    }
    Assert-InstallationState -State $state
    return $state
}

function Assert-InstallationState {
    param(
        [Parameter(Mandatory)]
        $State
    )

    $stateFields = [string[]]@($State.PSObject.Properties.Name)
    $expectedStateFields = [string[]]@(
        'schemaVersion',
        'activeVersion',
        'previousVersion',
        'versions'
    )
    if (
        @(Compare-Object $stateFields $expectedStateFields -CaseSensitive).Count -gt 0 -or
        [int]$State.schemaVersion -ne $script:InstallationSchemaVersion
    ) {
        throw [ArgumentException]::new('installer.invalid_state')
    }

    $records = @($State.versions)
    $recordsByVersion = [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::Ordinal
    )
    foreach ($record in $records) {
        $recordFields = [string[]]@($record.PSObject.Properties.Name)
        $expectedRecordFields = [string[]]@(
            'version',
            'artifactSha256',
            'sourceCommit',
            'target',
            'rootDirectory'
        )
        if (@(Compare-Object $recordFields $expectedRecordFields -CaseSensitive).Count -gt 0) {
            throw [ArgumentException]::new('installer.invalid_state')
        }
        $validated = New-InstalledVersionRecord `
            -Version ([string]$record.version) `
            -ArtifactSha256 ([string]$record.artifactSha256) `
            -SourceCommit ([string]$record.sourceCommit) `
            -Target ([string]$record.target) `
            -RootDirectory ([string]$record.rootDirectory)
        if (-not $recordsByVersion.TryAdd([string]$validated.version, $validated)) {
            throw [ArgumentException]::new('installer.duplicate_version')
        }
    }

    $active = [string]$State.activeVersion
    $previous = [string]$State.previousVersion
    if (
        (-not [string]::IsNullOrEmpty($active) -and
            -not $recordsByVersion.ContainsKey($active)) -or
        (-not [string]::IsNullOrEmpty($previous) -and
            -not $recordsByVersion.ContainsKey($previous)) -or
        (-not [string]::IsNullOrEmpty($active) -and $active -ceq $previous) -or
        ([string]::IsNullOrEmpty($active) -and -not [string]::IsNullOrEmpty($previous))
    ) {
        throw [ArgumentException]::new('installer.invalid_state')
    }
}

function Find-InstalledVersion {
    param(
        [Parameter(Mandatory)]
        $State,

        [Parameter(Mandatory)]
        [string]$Version
    )

    Assert-InstallationState -State $State
    return @(
        $State.versions |
            Where-Object { [string]$_.version -ceq $Version }
    ) | Select-Object -First 1
}

function New-LifecycleDecision {
    param(
        [Parameter(Mandatory)]
        [string]$Kind,

        [AllowNull()]
        [string]$TargetVersion
    )

    return [pscustomobject][ordered]@{
        kind = $Kind
        targetVersion = $TargetVersion
    }
}

function Resolve-InstallationLifecycle {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Install', 'Update', 'Rollback', 'Uninstall', 'Status')]
        [string]$Action,

        [Parameter(Mandatory)]
        $State,

        $Candidate,

        [string]$RollbackVersion
    )

    Assert-InstallationState -State $State
    $activeVersion = [string]$State.activeVersion
    switch ($Action) {
        'Status' {
            return New-LifecycleDecision -Kind Inspect -TargetVersion $activeVersion
        }
        'Uninstall' {
            $kind = if ([string]::IsNullOrEmpty($activeVersion)) { 'NoOp' } else { 'Uninstall' }
            return New-LifecycleDecision -Kind $kind -TargetVersion $activeVersion
        }
        'Rollback' {
            if ([string]::IsNullOrEmpty($activeVersion)) {
                throw [InvalidOperationException]::new('installer.not_installed')
            }
            $target = if ([string]::IsNullOrWhiteSpace($RollbackVersion)) {
                [string]$State.previousVersion
            }
            else {
                $RollbackVersion
            }
            if ([string]::IsNullOrEmpty($target)) {
                throw [InvalidOperationException]::new('installer.rollback_unavailable')
            }
            if ($target -ceq $activeVersion) {
                throw [InvalidOperationException]::new('installer.rollback_is_active')
            }
            if ($null -eq (Find-InstalledVersion -State $State -Version $target)) {
                throw [InvalidOperationException]::new('installer.rollback_missing')
            }
            return New-LifecycleDecision -Kind Rollback -TargetVersion $target
        }
    }

    if ($null -eq $Candidate) {
        throw [ArgumentException]::new('installer.candidate_required')
    }
    $candidate = New-InstalledVersionRecord `
        -Version ([string]$Candidate.version) `
        -ArtifactSha256 ([string]$Candidate.artifactSha256) `
        -SourceCommit ([string]$Candidate.sourceCommit) `
        -Target ([string]$Candidate.target) `
        -RootDirectory ([string]$Candidate.rootDirectory)
    $installedCandidate = Find-InstalledVersion -State $State -Version $candidate.version
    if (
        $null -ne $installedCandidate -and
        [string]$installedCandidate.artifactSha256 -cne $candidate.artifactSha256
    ) {
        throw [InvalidOperationException]::new('installer.version_digest_conflict')
    }

    if ($Action -ceq 'Install') {
        if ([string]::IsNullOrEmpty($activeVersion)) {
            return New-LifecycleDecision -Kind Install -TargetVersion $candidate.version
        }
        if ($activeVersion -cne $candidate.version) {
            throw [InvalidOperationException]::new('installer.use_update')
        }
        return New-LifecycleDecision -Kind Verify -TargetVersion $candidate.version
    }

    if ([string]::IsNullOrEmpty($activeVersion)) {
        throw [InvalidOperationException]::new('installer.not_installed')
    }
    if ($activeVersion -ceq $candidate.version) {
        return New-LifecycleDecision -Kind Verify -TargetVersion $candidate.version
    }
    $kind = if ($null -eq $installedCandidate) { 'Update' } else { 'Switch' }
    return New-LifecycleDecision -Kind $kind -TargetVersion $candidate.version
}

function Complete-InstallationLifecycle {
    param(
        [Parameter(Mandatory)]
        $State,

        [Parameter(Mandatory)]
        $Decision,

        $Candidate
    )

    Assert-InstallationState -State $State
    $records = [Collections.Generic.List[object]]::new()
    foreach ($record in @($State.versions)) {
        $records.Add((New-InstalledVersionRecord `
            -Version ([string]$record.version) `
            -ArtifactSha256 ([string]$record.artifactSha256) `
            -SourceCommit ([string]$record.sourceCommit) `
            -Target ([string]$record.target) `
            -RootDirectory ([string]$record.rootDirectory)))
    }
    switch ([string]$Decision.kind) {
        { $_ -in @('Inspect', 'Verify', 'NoOp') } {
            return New-InstallationState `
                -ActiveVersion ([string]$State.activeVersion) `
                -PreviousVersion ([string]$State.previousVersion) `
                -Versions $records
        }
        'Uninstall' {
            return New-InstallationState
        }
        'Rollback' {
            return New-InstallationState `
                -ActiveVersion ([string]$Decision.targetVersion) `
                -PreviousVersion ([string]$State.activeVersion) `
                -Versions $records
        }
        { $_ -in @('Install', 'Update', 'Switch') } {
            if ($null -eq $Candidate) {
                throw [ArgumentException]::new('installer.candidate_required')
            }
            $candidateRecord = New-InstalledVersionRecord `
                -Version ([string]$Candidate.version) `
                -ArtifactSha256 ([string]$Candidate.artifactSha256) `
                -SourceCommit ([string]$Candidate.sourceCommit) `
                -Target ([string]$Candidate.target) `
                -RootDirectory ([string]$Candidate.rootDirectory)
            if ($null -eq (Find-InstalledVersion -State $State -Version $candidateRecord.version)) {
                $records.Add($candidateRecord)
            }
            $previous = if ([string]::IsNullOrEmpty([string]$State.activeVersion)) {
                $null
            }
            else {
                [string]$State.activeVersion
            }
            return New-InstallationState `
                -ActiveVersion $candidateRecord.version `
                -PreviousVersion $previous `
                -Versions $records
        }
        default {
            throw [ArgumentException]::new('installer.unknown_decision')
        }
    }
}

function Resolve-InstallationRecovery {
    param(
        [Parameter(Mandatory)]
        [ValidateSet(
            'Prepared',
            'PreviousStopped',
            'CandidateInstalled',
            'CandidateStarted',
            'CandidateHealthy',
            'Committed'
        )]
        [string]$Phase,

        [AllowNull()]
        [string]$PreviousVersion
    )

    if ($Phase -ceq 'Committed') {
        return 'None'
    }
    if (
        $Phase -in @(
            'PreviousStopped',
            'CandidateInstalled',
            'CandidateStarted',
            'CandidateHealthy'
        ) -and
        -not [string]::IsNullOrEmpty($PreviousVersion)
    ) {
        return 'RestorePrevious'
    }
    return 'RemoveCandidate'
}

function Resolve-AgentPluginActivation {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Healthy', 'Missing', 'Unhealthy')]
        [string]$ServiceHealth,

        [Parameter(Mandatory)]
        [bool]$LegacyExtensionPresent
    )

    return [pscustomobject][ordered]@{
        status = if ($ServiceHealth -ceq 'Healthy') { 'Ready' } else { 'Blocked' }
        restartRequired = $ServiceHealth -ceq 'Healthy' -and $LegacyExtensionPresent
    }
}
