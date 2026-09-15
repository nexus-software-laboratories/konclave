#Requires -Version 7.4

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'InstallationRuntime.Functions.ps1')

function Write-TestZip {
    param(
        [string]$Path,
        [string]$EntryName,
        [string]$Content
    )

    Add-Type -AssemblyName System.IO.Compression
    $archive = [IO.Compression.ZipFile]::Open(
        $Path,
        [IO.Compression.ZipArchiveMode]::Create
    )
    try {
        $entry = $archive.CreateEntry($EntryName)
        $stream = [IO.StreamWriter]::new($entry.Open())
        try {
            $stream.Write($Content)
        }
        finally {
            $stream.Dispose()
        }
    }
    finally {
        $archive.Dispose()
    }
}

function Write-TestTarGzip {
    param(
        [string]$Path,
        [string]$EntryName,
        [string]$Content
    )

    $output = [IO.File]::Create($Path)
    $gzip = [IO.Compression.GZipStream]::new(
        $output,
        [IO.Compression.CompressionLevel]::Optimal,
        $true
    )
    $writer = [System.Formats.Tar.TarWriter]::new($gzip, $true)
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Content)
        $stream = [IO.MemoryStream]::new($bytes, $false)
        $entry = [System.Formats.Tar.PaxTarEntry]::new(
            [System.Formats.Tar.TarEntryType]::RegularFile,
            $EntryName
        )
        $entry.DataStream = $stream
        $entry.Mode = [IO.UnixFileMode]493
        try {
            $writer.WriteEntry($entry)
        }
        finally {
            $stream.Dispose()
        }
    }
    finally {
        $writer.Dispose()
        $gzip.Dispose()
        $output.Dispose()
    }
}

function Assert-RuntimeCheckFails {
    param(
        [scriptblock]$Action,
        [string]$Scenario
    )

    try {
        & $Action
    }
    catch {
        return
    }
    throw "Installer runtime accepted $Scenario."
}

$root = Join-Path (
    [IO.Path]::GetTempPath()
) "konclave-installer-runtime-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $root | Out-Null
try {
    $paths = Get-InstallationPaths -DataRoot (Join-Path $root 'data')
    Initialize-InstallationPaths -Paths $paths
    $previousCopilotHome = $env:COPILOT_HOME
    try {
        [Environment]::SetEnvironmentVariable(
            'COPILOT_HOME',
            $null,
            [EnvironmentVariableTarget]::Process
        )
        $defaultLegacyRoot = Resolve-LegacyCopilotExtensionRoot
        $expectedLegacyRoot = Join-Path (
            [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
        ) '.copilot' 'extensions' 'konclave'
        if ($defaultLegacyRoot -cne $expectedLegacyRoot) {
            throw 'Default Copilot extension root resolution failed.'
        }
    }
    finally {
        [Environment]::SetEnvironmentVariable(
            'COPILOT_HOME',
            $previousCopilotHome,
            [EnvironmentVariableTarget]::Process
        )
    }
    if ($IsWindows) {
        $windowsIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $identity = $windowsIdentity.User
        $tokenOwnerIdentity = $windowsIdentity.Owner
        if ($null -eq $tokenOwnerIdentity) {
            $tokenOwnerIdentity = $identity
        }
        $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
        $world = [Security.Principal.SecurityIdentifier]::new('S-1-1-0')
        $ownerCases = @(
            @{
                name = 'user owner'
                owner = $identity
                user = $identity
                tokenOwner = $system
                expected = 'Preserve'
            },
            @{
                name = 'token owner'
                owner = $system
                user = $identity
                tokenOwner = $system
                expected = 'Initialize'
            },
            @{
                name = 'foreign owner'
                owner = $world
                user = $identity
                tokenOwner = $system
                expected = 'Reject'
            }
        )
        foreach ($case in $ownerCases) {
            if (
                (Resolve-WindowsOwnerAction `
                    -Owner $case.owner `
                    -UserIdentity $case.user `
                    -TokenOwnerIdentity $case.tokenOwner) -cne [string]$case.expected
            ) {
                throw "Windows owner decision failed: $($case.name)"
            }
        }
        if (-not (Test-WindowsOwnerOnlyAcl `
            -Acl (Get-Acl -LiteralPath $paths.dataRoot -ErrorAction Stop) `
            -Identity $identity `
            -Kind Directory)) {
            throw 'Installer data root is not owner-protected.'
        }
    }
    $record = New-InstalledVersionRecord `
        -Version '0.1.0' `
        -ArtifactSha256 ('1' * 64) `
        -SourceCommit ('2' * 40) `
        -Target 'x86_64-unknown-linux-gnu' `
        -RootDirectory 'konclave-client-0.1.0-x86_64-unknown-linux-gnu'
    $state = New-InstallationState -ActiveVersion '0.1.0' -Versions @($record)
    Write-InstallationState -Path $paths.statePath -State $state
    if (
        $IsWindows -and
        -not (Test-WindowsOwnerOnlyAcl `
            -Acl (Get-Acl -LiteralPath $paths.statePath -ErrorAction Stop) `
            -Identity $identity `
            -Kind File)
    ) {
        throw 'Installer state is not owner-protected.'
    }
    $roundTrip = Read-InstallationState -Path $paths.statePath
    if (
        [string]$roundTrip.activeVersion -cne '0.1.0' -or
        $roundTrip.versions.Count -ne 1
    ) {
        throw 'Installer state did not round-trip.'
    }
    if (-not $IsWindows) {
        $mode = [IO.File]::GetUnixFileMode($paths.statePath)
        $forbidden = [IO.UnixFileMode]::GroupRead -bor
            [IO.UnixFileMode]::GroupWrite -bor
            [IO.UnixFileMode]::GroupExecute -bor
            [IO.UnixFileMode]::OtherRead -bor
            [IO.UnixFileMode]::OtherWrite -bor
            [IO.UnixFileMode]::OtherExecute
        if (($mode -band $forbidden) -ne 0) {
            throw 'Installer state is not owner-only.'
        }
    }

    $zipPath = Join-Path $root 'client.zip'
    Write-TestZip `
        -Path $zipPath `
        -EntryName "$($record.rootDirectory)/bin/konclave.exe" `
        -Content 'zip-client'
    $zipCandidate = [pscustomobject]@{
        record = $record
        archivePath = $zipPath
        artifact = [pscustomobject]@{ archiveFormat = 'zip' }
    }
    $zipInstall = Install-ReleaseCandidateFiles -Paths $paths -Candidate $zipCandidate
    if (
        -not $zipInstall.created -or
        (Get-Content -LiteralPath (
            Join-Path $zipInstall.root 'bin' 'konclave.exe'
        ) -Raw) -cne 'zip-client'
    ) {
        throw 'Protected ZIP installation failed.'
    }

    $tarRecord = New-InstalledVersionRecord `
        -Version '0.2.0' `
        -ArtifactSha256 ('3' * 64) `
        -SourceCommit ('4' * 40) `
        -Target 'x86_64-unknown-linux-gnu' `
        -RootDirectory 'konclave-client-0.2.0-x86_64-unknown-linux-gnu'
    $tarPath = Join-Path $root 'client.tar.gz'
    Write-TestTarGzip `
        -Path $tarPath `
        -EntryName "$($tarRecord.rootDirectory)/bin/konclave" `
        -Content 'tar-client'
    $tarCandidate = [pscustomobject]@{
        record = $tarRecord
        archivePath = $tarPath
        artifact = [pscustomobject]@{ archiveFormat = 'tar.gz' }
    }
    $tarInstall = Install-ReleaseCandidateFiles -Paths $paths -Candidate $tarCandidate
    if (
        -not $tarInstall.created -or
        (Get-Content -LiteralPath (
            Join-Path $tarInstall.root 'bin' 'konclave'
        ) -Raw) -cne 'tar-client'
    ) {
        throw 'Protected tar.gz installation failed.'
    }

    $events = [Collections.Generic.List[string]]::new()
    $managerInvoker = {
        param($Action, $InstallRoot, $ConfigPath)
        $events.Add("$Action|$InstallRoot")
    }.GetNewClosure()
    $healthInvoker = {
        param($InstallRoot, $InstallationPaths)
        $events.Add("Health|$InstallRoot")
        if ($InstallRoot -ceq [string]$tarInstall.root) {
            throw 'synthetic candidate health failure'
        }
    }.GetNewClosure()
    $stateWriter = {
        param($StatePath, $NextState)
        throw 'failed update must not publish state'
    }
    $candidateRemover = {
        param($InstallationPaths, $Version)
        $events.Add("Remove|$Version")
    }.GetNewClosure()
    $updateDecision = Resolve-InstallationLifecycle `
        -Action Update `
        -State $state `
        -Candidate $tarRecord
    Assert-RuntimeCheckFails {
        Invoke-TransactionalRuntimeSwitch `
            -Paths $paths `
            -State $state `
            -Decision $updateDecision `
            -CandidateRecord $tarRecord `
            -CandidateRoot $tarInstall.root `
            -CandidateCreated $true `
            -ManagerInvoker $managerInvoker `
            -HealthInvoker $healthInvoker `
            -StateWriter $stateWriter `
            -CandidateRemover $candidateRemover
    } 'an unhealthy update'
    $expectedEvents = [string[]]@(
        "Uninstall|$($zipInstall.root)",
        "Install|$($tarInstall.root)",
        "Health|$($tarInstall.root)",
        "Uninstall|$($tarInstall.root)",
        "Install|$($zipInstall.root)",
        "Health|$($zipInstall.root)",
        'Remove|0.2.0'
    )
    if (
        @(Compare-Object `
            ([string[]]$events) `
            $expectedEvents `
            -CaseSensitive `
            -SyncWindow 0).Count -gt 0
    ) {
        throw 'Failed update did not restore the previous runnable version.'
    }

    $unsafeZip = Join-Path $root 'unsafe.zip'
    Write-TestZip -Path $unsafeZip -EntryName '../escape.txt' -Content 'escape'
    Assert-RuntimeCheckFails {
        Expand-ProtectedZipRelease `
            -ArchivePath $unsafeZip `
            -DestinationRoot (Join-Path $root 'unsafe-destination')
    } 'a parent-directory archive entry'

    if (
        (Get-HostReleaseTarget -Platform windows -Architecture x64) -cne
            'x86_64-pc-windows-msvc' -or
        (Get-HostReleaseTarget -Platform linux -Architecture x64) -cne
            'x86_64-unknown-linux-gnu' -or
        (Get-HostReleaseTarget -Platform macos -Architecture arm64) -cne
            'aarch64-apple-darwin'
    ) {
        throw 'Host release target resolution failed.'
    }

    $manager = Join-Path (
        $PSScriptRoot
    ) '..' '..' 'apps' 'Konclave.LocalDaemon' 'packaging' 'windows' `
        'manage-user-service.ps1'
    $rendered = & $manager `
        -Action Render `
        -InstallRoot (Join-Path $root 'render-install') `
        -ConfigPath (Join-Path $root 'render-config.json') |
            ConvertFrom-Json
    if (
        [string]$rendered.taskName -cne 'KonclaveLocalService' -or
        [string]$rendered.logonType -cne 'Interactive' -or
        [string]$rendered.runLevel -cne 'Limited'
    ) {
        throw 'Windows user-service descriptor is invalid.'
    }
    if ($IsWindows) {
        $windowsInstall = Join-Path $root 'windows-install'
        $windowsBin = Join-Path $windowsInstall 'bin'
        New-Item -ItemType Directory -Path $windowsBin | Out-Null
        Copy-Item -LiteralPath (
            Join-Path $env:SystemRoot 'System32' 'where.exe'
        ) -Destination (
            Join-Path $windowsBin 'KonclaveLocalService.exe'
        )
        $windowsConfig = Join-Path $root 'windows-service.json'
        [IO.File]::WriteAllText($windowsConfig, '{}')
        try {
            & $manager `
                -Action Install `
                -InstallRoot $windowsInstall `
                -ConfigPath $windowsConfig
            $taskStatus = & $manager `
                -Action Status `
                -InstallRoot $windowsInstall `
                -ConfigPath $windowsConfig
            if ([string]::IsNullOrWhiteSpace(($taskStatus | Out-String))) {
                throw 'Windows user-service manager returned no status.'
            }
        }
        finally {
            & $manager `
                -Action Uninstall `
                -InstallRoot $windowsInstall `
                -ConfigPath $windowsConfig
        }
    }

    [IO.File]::WriteAllText(
        $paths.directPluginPath,
        '{"schemaVersion":1,"mode":"direct","name":"konclave","version":"0.1.1"}'
    )
    Set-OwnerOnlyFile -Path $paths.directPluginPath
    $directMarker = Read-DirectPluginMarker -Path $paths.directPluginPath
    if ([string]$directMarker.version -cne '0.1.1') {
        throw 'Direct Agent Plugin marker did not validate.'
    }
    [IO.File]::WriteAllText(
        $paths.directPluginPath,
        '{"schemaVersion":1,"mode":"direct","name":"konclave","version":"0.1.1","extra":true}'
    )
    Assert-RuntimeCheckFails {
        Read-DirectPluginMarker -Path $paths.directPluginPath
    } 'an extended direct-plugin marker'
    Remove-Item -LiteralPath $paths.directPluginPath -Force

    $legacy = Join-Path $root 'legacy-extension'
    [void](Set-OwnerOnlyDirectory -Path $legacy)
    [IO.File]::WriteAllText((Join-Path $legacy 'extension.mjs'), 'legacy')
    $backup = Move-LegacyCopilotExtension `
        -Source $legacy `
        -LegacyRoot $paths.legacyRoot
    if (
        (Test-Path -LiteralPath $legacy) -or
        (Get-Content -LiteralPath (Join-Path $backup 'extension.mjs') -Raw) -cne 'legacy'
    ) {
        throw 'Legacy Copilot extension was not preserved before removal.'
    }

    $marketplaceCases = @(
        @{
            name = 'ready'
            direct = $false
            legacy = $false
            status = 'ReadyMarketplace'
        },
        @{
            name = 'direct'
            direct = $true
            legacy = $false
            status = 'RemovedDirect'
        },
        @{
            name = 'legacy'
            direct = $false
            legacy = $true
            status = 'PreservedLegacy'
        },
        @{
            name = 'direct and legacy'
            direct = $true
            legacy = $true
            status = 'RemovedDirectAndPreservedLegacy'
        }
    )
    foreach ($case in $marketplaceCases) {
        $caseRoot = Join-Path $root "marketplace-$($case.name.Replace(' ', '-'))"
        if ($case.legacy) {
            [void](Set-OwnerOnlyDirectory -Path $caseRoot)
        }
        $tracker = [pscustomobject]@{
            disabled = $false
            moved = $false
        }
        $directResult = [bool]$case.direct
        $directDisabler = {
            param($InstallationPaths)
            $tracker.disabled = $directResult
            return $directResult
        }.GetNewClosure()
        $legacyResolver = {
            return $caseRoot
        }.GetNewClosure()
        $legacyMover = {
            param($Source, $LegacyRoot)
            $tracker.moved = $true
            Remove-Item -LiteralPath $Source -Recurse -Force
        }.GetNewClosure()
        $result = Prepare-InstallerMarketplace `
            -Paths $paths `
            -DirectPluginDisabler $directDisabler `
            -LegacyRootResolver $legacyResolver `
            -LegacyMover $legacyMover
        if (
            [string]$result.status -cne [string]$case.status -or
            [bool]$result.restartRequired -ne ([bool]$case.direct -or [bool]$case.legacy) -or
            $tracker.disabled -ne [bool]$case.direct -or
            $tracker.moved -ne [bool]$case.legacy
        ) {
            throw "Marketplace preparation decision failed: $($case.name)"
        }
    }
}
finally {
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force
    }
}

Write-Output 'Installer runtime filesystem and archive tests passed.'
