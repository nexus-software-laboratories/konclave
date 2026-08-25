#Requires -Version 7.4
<#
.SYNOPSIS
    Prepares or stops a local Konclave relay and Copilot extension demo on Windows.
#>
[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)]
    [int]$Port = 43180,

    [switch]$Refresh,

    [switch]$Validate,

    [switch]$Stop,

    [Alias('UninstallPlugin')]
    [switch]$UninstallExtension
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $IsWindows) {
    throw 'The local Copilot demo script currently supports Windows only.'
}
if ($UninstallExtension -and -not $Stop) {
    throw '-UninstallExtension requires -Stop.'
}

function Stop-PackageWorkflowAndDeleteArtifacts {
    param(
        [Parameter(Mandatory)]
        [int64]$RunId
    )

    $run = Invoke-RequiredCommand gh @(
        'run',
        'view',
        $RunId.ToString(),
        '--repo',
        $repository,
        '--json',
        'status'
    ) | ConvertFrom-Json
    if ($run.status -ne 'completed') {
        $cancelOutput = & gh run cancel `
            $RunId.ToString() `
            --repo $repository 2>&1
        if ($LASTEXITCODE -ne 0) {
            $run = Invoke-RequiredCommand gh @(
                'run',
                'view',
                $RunId.ToString(),
                '--repo',
                $repository,
                '--json',
                'status'
            ) | ConvertFrom-Json
            if ($run.status -ne 'completed') {
                throw (
                    "Could not cancel package workflow $RunId. " +
                    ($cancelOutput -join "`n")
                )
            }
        }
    }

    $deadline = [DateTimeOffset]::UtcNow.AddMinutes(10)
    do {
        $run = Invoke-RequiredCommand gh @(
            'run',
            'view',
            $RunId.ToString(),
            '--repo',
            $repository,
            '--json',
            'status'
        ) | ConvertFrom-Json
        if ($run.status -eq 'completed') {
            break
        }
        Start-Sleep -Seconds 5
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    if ($run.status -ne 'completed') {
        throw "Package workflow $RunId did not stop within the cleanup deadline."
    }

    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        $count = Invoke-RequiredCommand gh @(
            'api',
            "repos/$repository/actions/runs/$RunId/artifacts?per_page=1",
            '--jq',
            '.total_count'
        )
        if (($count -join '').Trim() -eq '0') {
            return
        }
        Start-Sleep -Seconds 2
    }

    $artifacts = Invoke-RequiredCommand gh @(
        'api',
        "repos/$repository/actions/runs/$RunId/artifacts?per_page=100"
    ) | ConvertFrom-Json -Depth 20
    foreach ($artifact in $artifacts.artifacts) {
        $deleteOutput = & gh api `
            --method DELETE `
            "repos/$repository/actions/artifacts/$($artifact.id)" 2>&1
        if ($LASTEXITCODE -ne 0) {
            # Trusted cleanup may win the deletion race. The exact run-level count
            # below remains authoritative and fails if any artifact actually remains.
            Write-Verbose ($deleteOutput -join "`n")
        }
    }
    $remaining = Invoke-RequiredCommand gh @(
        'api',
        "repos/$repository/actions/runs/$RunId/artifacts?per_page=1",
        '--jq',
        '.total_count'
    )
    if (($remaining -join '').Trim() -ne '0') {
        throw "Package workflow $RunId still retains artifacts."
    }
}

$repository = 'nexus-software-laboratories/konclave'
$workflowRunsApiPath = "repos/$repository/actions/workflows/package-validation.yml/runs?event=workflow_dispatch&branch=main&per_page=100"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
$localAppData = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::LocalApplicationData
)
if ([string]::IsNullOrWhiteSpace($localAppData)) {
    throw 'LOCALAPPDATA is unavailable.'
}

$demoRoot = Join-Path $localAppData 'Konclave' 'demo'
$profileRoot = Join-Path $demoRoot 'profiles'
$relayStateRoot = Join-Path $demoRoot 'relay'
$statusPath = Join-Path $demoRoot 'demo-status.json'
$profileRootBackupPath = Join-Path $demoRoot 'original-profile-root.json'
$copilotExperimentalBackupPath = Join-Path $demoRoot 'original-copilot-experimental.json'
$installParent = Join-Path $localAppData 'Programs' 'Konclave'
$installRoot = Join-Path $installParent 'demo'
$releaseManifest = Get-Content -LiteralPath (
    Join-Path $projectRoot 'distribution' 'release-artifacts.json'
) -Raw -Encoding UTF8 | ConvertFrom-Json -Depth 100
$clientContract = @(
    $releaseManifest.artifacts |
        Where-Object id -CEQ 'konclave-client-windows-x64'
)
$relayContract = @(
    $releaseManifest.artifacts |
        Where-Object id -CEQ 'konclave-relay-windows-x64'
)
if ($clientContract.Count -ne 1 -or $relayContract.Count -ne 1) {
    throw 'Windows release artifact contract is incomplete.'
}
$clientRootName = [string]$clientContract[0].rootDirectory
$relayRootName = [string]$relayContract[0].rootDirectory
$clientRoot = Join-Path $installRoot $clientRootName
$relayRoot = Join-Path $installRoot $relayRootName
$cliPath = Join-Path $clientRoot 'bin' 'konclave.exe'
$relayExecutable = Join-Path $relayRoot 'bin' 'KonclaveCommunityRelay.exe'
$pluginRoot = Join-Path $clientRoot 'share' 'konclave' 'plugin'
$extensionSource = Join-Path $pluginRoot 'extensions' 'Konclave.Extension' 'extension.mjs'
$extensionDaemonSource = Join-Path $pluginRoot 'bin' 'KonclaveLocalDaemon.exe'
$copilotHomeValue = $env:COPILOT_HOME
if ([string]::IsNullOrWhiteSpace($copilotHomeValue)) {
    $userProfile = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::UserProfile
    )
    if ([string]::IsNullOrWhiteSpace($userProfile)) {
        throw 'The user profile directory is unavailable.'
    }
    $copilotHome = Join-Path $userProfile '.copilot'
}
elseif (-not [IO.Path]::IsPathRooted($copilotHomeValue)) {
    throw 'COPILOT_HOME must be an absolute path.'
}
else {
    $copilotHome = [IO.Path]::GetFullPath($copilotHomeValue)
}
$copilotSettingsPath = Join-Path $copilotHome 'settings.json'
$copilotExtensionRoot = Join-Path $copilotHome 'extensions' 'konclave'
$endpoint = "http://127.0.0.1:$Port"

function Invoke-RequiredCommand {
    param(
        [Parameter(Mandatory)]
        [string]$Command,

        [Parameter(Mandatory)]
        [string[]]$Arguments
    )

    $output = & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Command failed with exit code $LASTEXITCODE."
    }
    return $output
}

function Read-DemoStatus {
    param([string]$StatusFile = $statusPath)

    if (-not (Test-Path -LiteralPath $StatusFile -PathType Leaf)) {
        return $null
    }
    $status = Get-Content -LiteralPath $StatusFile -Raw -Encoding UTF8 |
        ConvertFrom-Json -Depth 20
    if (
        [int64]$status.schemaVersion -ne 2 -or
        [int64]$status.relayProcessId -le 0 -or
        [int64]$status.relayStartTimeUtcFileTime -le 0 -or
        [string]::IsNullOrWhiteSpace([string]$status.relayExecutable)
    ) {
        throw 'Konclave demo status is malformed.'
    }
    return $status
}

function Stop-DemoRelay {
    param([string]$StatusFile = $statusPath)

    $status = Read-DemoStatus -StatusFile $StatusFile
    if ($null -eq $status) {
        return
    }
    $processId = [int]$status.relayProcessId
    $expectedStartTime = [int64]$status.relayStartTimeUtcFileTime
    $expectedExecutable = [IO.Path]::GetFullPath([string]$status.relayExecutable)
    $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
    if ($null -ne $process) {
        try {
            $actualExecutable = [IO.Path]::GetFullPath($process.Path)
            $actualStartTime = $process.StartTime.ToUniversalTime().ToFileTimeUtc()
        }
        catch {
            Remove-Item -LiteralPath $StatusFile -Force
            Write-Warning (
                "Process $processId could not be verified; stale demo status was " +
                'removed without terminating that process.'
            )
            return
        }
        if (
            -not $actualExecutable.Equals(
                $expectedExecutable,
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            $actualStartTime -ne $expectedStartTime
        ) {
            Remove-Item -LiteralPath $StatusFile -Force
            Write-Warning (
                "Process $processId no longer matches the recorded relay; stale " +
                'demo status was removed without terminating that process.'
            )
            return
        }
        Stop-Process -Id $processId
        if (-not $process.WaitForExit(10000)) {
            throw "Konclave relay process $processId did not stop."
        }
    }
    Remove-Item -LiteralPath $StatusFile -Force
}

function Read-OriginalProfileRoot {
    if (-not (Test-Path -LiteralPath $profileRootBackupPath -PathType Leaf)) {
        return $null
    }
    if (
        (Get-Item -LiteralPath $profileRootBackupPath).Attributes -band
        [IO.FileAttributes]::ReparsePoint
    ) {
        throw 'Konclave demo environment backup must not be a reparse point.'
    }
    $backup = Get-Content -LiteralPath $profileRootBackupPath -Raw -Encoding UTF8 |
        ConvertFrom-Json -Depth 10
    if (
        [int64]$backup.schemaVersion -ne 1 -or
        -not $backup.PSObject.Properties['value']
    ) {
        throw 'Konclave demo environment backup is malformed.'
    }
    if ($null -eq $backup.value) {
        return $null
    }
    $value = [string]$backup.value
    if ([IO.Path]::IsPathRooted($value)) {
        $fullValue = [IO.Path]::GetFullPath($value)
        $fullDemoRoot = [IO.Path]::GetFullPath($demoRoot)
        if (
            $fullValue.Equals(
                $fullDemoRoot,
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            $fullValue.StartsWith(
                $fullDemoRoot + [IO.Path]::DirectorySeparatorChar,
                [StringComparison]::OrdinalIgnoreCase
            )
        ) {
            throw 'Konclave demo environment backup points inside demo state.'
        }
    }
    return $value
}

function Restore-LegacyProfileRoot {
    $configuredRoot = [Environment]::GetEnvironmentVariable(
        'KONCLAVE_PROFILE_ROOT',
        'User'
    )
    if (-not (Test-Path -LiteralPath $profileRootBackupPath -PathType Leaf)) {
        if ($configuredRoot -eq $profileRoot) {
            throw 'Demo profile root is configured but its restoration backup is missing.'
        }
        return
    }
    if ($configuredRoot -eq $profileRoot) {
        [Environment]::SetEnvironmentVariable(
            'KONCLAVE_PROFILE_ROOT',
            (Read-OriginalProfileRoot),
            'User'
        )
    }
    Remove-Item -LiteralPath $profileRootBackupPath -Force
}

function Read-JsonObject {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [ordered]@{}
    }
    $item = Get-Item -LiteralPath $Path
    if (
        $item.Attributes -band
        [IO.FileAttributes]::ReparsePoint
    ) {
        throw "JSON configuration must not be a reparse point: $Path"
    }
    if ($item.Length -gt 1048576) {
        throw "JSON configuration exceeds its size limit: $Path"
    }
    $document = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 |
        ConvertFrom-Json -AsHashtable -Depth 100
    if ($document -isnot [Collections.IDictionary]) {
        throw "JSON configuration must contain an object: $Path"
    }
    return $document
}

function Write-AtomicJsonObject {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [Collections.IDictionary]$Value,

        [switch]$NoClobber
    )

    $parent = [IO.Path]::GetDirectoryName($Path)
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $temporary = "$Path.$([Guid]::NewGuid().ToString('N')).tmp"
    [IO.File]::WriteAllText(
        $temporary,
        ($Value | ConvertTo-Json -Depth 100) + "`n",
        [Text.UTF8Encoding]::new($false)
    )
    try {
        [IO.File]::Move($temporary, $Path, -not $NoClobber)
    }
    finally {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Force
        }
    }
}

function Enable-CopilotExperimentalExtensions {
    $settings = Read-JsonObject -Path $copilotSettingsPath
    $propertyExists = $settings.Contains('experimental')
    if ($propertyExists -and $settings['experimental'] -isnot [bool]) {
        throw 'Copilot experimental setting must be a boolean.'
    }
    if ($propertyExists -and [bool]$settings['experimental']) {
        return $false
    }

    if (-not (Test-Path -LiteralPath $copilotExperimentalBackupPath -PathType Leaf)) {
        Write-AtomicJsonObject `
            -Path $copilotExperimentalBackupPath `
            -Value ([ordered]@{
                schemaVersion = 1
                propertyExisted = $propertyExists
                value = if ($propertyExists) { [bool]$settings['experimental'] } else { $null }
            }) `
            -NoClobber
    }
    $settings['experimental'] = $true
    Write-AtomicJsonObject -Path $copilotSettingsPath -Value $settings
    return $true
}

function Restore-CopilotExperimentalSetting {
    if (-not (Test-Path -LiteralPath $copilotExperimentalBackupPath -PathType Leaf)) {
        return
    }
    $backup = Read-JsonObject -Path $copilotExperimentalBackupPath
    if (
        [int64]$backup['schemaVersion'] -ne 1 -or
        $backup['propertyExisted'] -isnot [bool]
    ) {
        throw 'Copilot experimental setting backup is malformed.'
    }
    $settings = Read-JsonObject -Path $copilotSettingsPath
    if ($settings.Contains('experimental') -and [bool]$settings['experimental']) {
        if ([bool]$backup['propertyExisted']) {
            if ($backup['value'] -isnot [bool]) {
                throw 'Copilot experimental setting backup value is malformed.'
            }
            $settings['experimental'] = [bool]$backup['value']
        }
        else {
            $settings.Remove('experimental')
        }
        Write-AtomicJsonObject -Path $copilotSettingsPath -Value $settings
    }
    Remove-Item -LiteralPath $copilotExperimentalBackupPath -Force
}

function Install-CopilotExtension {
    foreach ($source in @($extensionSource, $extensionDaemonSource)) {
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            throw "Packaged extension asset is missing: $source"
        }
        if (
            (Get-Item -LiteralPath $source).Attributes -band
            [IO.FileAttributes]::ReparsePoint
        ) {
            throw "Packaged extension asset must not be a reparse point: $source"
        }
    }

    $experimentalChanged = Enable-CopilotExperimentalExtensions
    $extensionParent = [IO.Path]::GetDirectoryName($copilotExtensionRoot)
    $stagingRoot = Join-Path (
        $extensionParent
    ) ".konclave.$([Guid]::NewGuid().ToString('N')).tmp"
    $previousRoot = Join-Path (
        $extensionParent
    ) ".konclave.$([Guid]::NewGuid().ToString('N')).previous"
    $previousMoved = $false
    $installed = $false
    try {
        # A running prior extension can keep its renamed executable locked.
        # Cleanup is retried on every setup but never invalidates a completed swap.
        foreach ($stale in Get-ChildItem `
            -LiteralPath $extensionParent `
            -Directory `
            -Filter '.konclave.*.previous' `
            -ErrorAction SilentlyContinue) {
            if (
                $stale.Name -notmatch '^\.konclave\.[0-9a-f]{32}\.previous$' -or
                $stale.Attributes -band [IO.FileAttributes]::ReparsePoint
            ) {
                continue
            }
            try {
                Remove-Item -LiteralPath $stale.FullName -Recurse -Force
            }
            catch {
                Write-Warning "A prior Konclave extension backup is still in use: $($stale.FullName)"
            }
        }
        New-Item -ItemType Directory -Path (Join-Path $stagingRoot 'bin') -Force |
            Out-Null
        Copy-Item -LiteralPath $extensionSource -Destination (
            Join-Path $stagingRoot 'extension.mjs'
        )
        Copy-Item -LiteralPath $extensionDaemonSource -Destination (
            Join-Path $stagingRoot 'bin' 'KonclaveLocalDaemon.exe'
        )
        Write-AtomicJsonObject `
            -Path (Join-Path $stagingRoot 'konclave.runtime.json') `
            -Value ([ordered]@{
                schemaVersion = 1
                profileRoot = [IO.Path]::GetFullPath($profileRoot)
            })

        if (Test-Path -LiteralPath $copilotExtensionRoot) {
            $existing = Get-Item -LiteralPath $copilotExtensionRoot
            if (
                -not $existing.PSIsContainer -or
                $existing.Attributes -band [IO.FileAttributes]::ReparsePoint
            ) {
                throw 'Installed Konclave extension root is unsafe to replace.'
            }
            Move-Item -LiteralPath $copilotExtensionRoot -Destination $previousRoot
            $previousMoved = $true
        }
        Move-Item -LiteralPath $stagingRoot -Destination $copilotExtensionRoot
        $installed = $true
    }
    catch {
        if (-not $installed) {
            try {
                if (
                    $previousMoved -and
                    -not (Test-Path -LiteralPath $copilotExtensionRoot) -and
                    (Test-Path -LiteralPath $previousRoot -PathType Container)
                ) {
                    Move-Item -LiteralPath $previousRoot -Destination $copilotExtensionRoot
                    $previousMoved = $false
                }
            }
            finally {
                if ($experimentalChanged) {
                    Restore-CopilotExperimentalSetting
                }
            }
        }
        throw
    }
    finally {
        foreach ($path in @($stagingRoot, $previousRoot)) {
            if (Test-Path -LiteralPath $path -PathType Container) {
                try {
                    Remove-Item -LiteralPath $path -Recurse -Force
                }
                catch {
                    if ($path -eq $stagingRoot -or -not $installed) {
                        throw
                    }
                    Write-Warning "A prior Konclave extension backup remains in use: $path"
                }
            }
        }
    }
}

function Remove-CopilotExtension {
    if (Test-Path -LiteralPath $copilotExtensionRoot) {
        $extension = Get-Item -LiteralPath $copilotExtensionRoot
        if (
            -not $extension.PSIsContainer -or
            $extension.Attributes -band [IO.FileAttributes]::ReparsePoint
        ) {
            throw 'Installed Konclave extension root is unsafe to remove.'
        }
        Remove-Item -LiteralPath $copilotExtensionRoot -Recurse -Force
    }
    Restore-CopilotExperimentalSetting
}

function Remove-LegacyKonclavePlugin {
    try {
        $directRoot = Join-Path $copilotHome 'installed-plugins' '_direct'
        if (-not (Test-Path -LiteralPath $directRoot -PathType Container)) {
            return
        }
        $found = $false
        foreach ($directory in Get-ChildItem -LiteralPath $directRoot -Directory) {
            $manifestPath = Join-Path $directory.FullName 'plugin.json'
            if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
                continue
            }
            try {
                $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 |
                    ConvertFrom-Json -Depth 20
            }
            catch {
                Write-Verbose "Skipping unreadable direct plugin manifest: $manifestPath"
                continue
            }
            if (
                $manifest.PSObject.Properties['name'] -and
                [string]$manifest.name -ceq 'konclave'
            ) {
                $found = $true
                break
            }
        }
        if (-not $found) {
            return
        }

        if ($null -eq (Get-Command copilot -ErrorAction SilentlyContinue)) {
            Write-Warning 'The obsolete Konclave direct plugin remains because Copilot CLI is unavailable.'
            return
        }
        $output = & copilot plugin uninstall konclave 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Warning (
                'The runnable extension is installed, but removal of the obsolete ' +
                "direct plugin failed: $($output -join ' ')"
            )
        }
    }
    catch {
        Write-Warning (
            'The runnable extension is installed, but obsolete direct-plugin ' +
            "cleanup failed: $($_.Exception.Message)"
        )
    }
}

function Test-PortAvailable {
    param([int]$Candidate)

    $listener = [Net.Sockets.TcpListener]::new(
        [Net.IPAddress]::Loopback,
        $Candidate
    )
    try {
        $listener.Start()
    }
    catch {
        throw "Loopback port $Candidate is already in use."
    }
    finally {
        $listener.Stop()
    }
}

function Wait-RelayHealth {
    param(
        [Parameter(Mandatory)]
        [Diagnostics.Process]$Process
    )

    for ($attempt = 0; $attempt -lt 120; $attempt++) {
        if ($Process.HasExited) {
            $diagnostics = if (Test-Path -LiteralPath (
                Join-Path $relayStateRoot 'stderr.log'
            )) {
                Get-Content -LiteralPath (
                    Join-Path $relayStateRoot 'stderr.log'
                ) -Raw
            }
            else {
                ''
            }
            throw "Konclave relay exited during startup. $diagnostics"
        }
        try {
            $response = Invoke-WebRequest -Uri "$endpoint/healthz" -TimeoutSec 2
            if ($response.StatusCode -eq 200) {
                return
            }
        }
        catch {
            Start-Sleep -Milliseconds 250
        }
    }
    throw 'Konclave relay health endpoint did not become ready.'
}

function Get-PackageWorkflowRun {
    $requestId = [Guid]::NewGuid().ToString('N')
    $expectedTitle = "Package validation [$requestId]"
    $dispatchOutput = & gh workflow run package-validation.yml `
        --repo $repository `
        --ref main `
        --field "request_id=$requestId" `
        --field 'demo_windows_only=true' 2>&1
    $dispatchExitCode = $LASTEXITCODE
    $deadline = [DateTimeOffset]::UtcNow.AddMinutes(2)
    do {
        try {
            $runs = Invoke-RequiredCommand gh @(
                'api',
                $workflowRunsApiPath
            ) | ConvertFrom-Json -Depth 20
        }
        catch {
            if ([DateTimeOffset]::UtcNow -ge $deadline) {
                throw
            }
            Start-Sleep -Seconds 2
            continue
        }
        $matches = @(
            $runs.workflow_runs |
                Where-Object display_title -CEQ $expectedTitle
        )
        if ($matches.Count -gt 1) {
            throw "Multiple package workflow runs matched request $requestId."
        }
        if ($matches.Count -eq 1) {
            $run = $matches[0]
            if ([string]$run.head_sha -match '^[0-9a-f]{40}$') {
                return [pscustomobject]@{
                    Id = [int64]$run.id
                    HeadSha = [string]$run.head_sha
                }
            }
        }
        Start-Sleep -Seconds 2
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    if ($dispatchExitCode -ne 0) {
        throw (
            "Package workflow dispatch failed with exit code $dispatchExitCode. " +
            ($dispatchOutput -join "`n")
        )
    }
    throw "Could not resolve package workflow request $requestId."
}

function Wait-WindowsPackageArtifact {
    param(
        [Parameter(Mandatory)]
        [int64]$RunId,

        [Parameter(Mandatory)]
        [string]$Destination
    )

    $deadline = [DateTimeOffset]::UtcNow.AddMinutes(45)
    $attempt = 0
    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        $attempt++
        $artifacts = Invoke-RequiredCommand gh @(
            'api',
            "repos/$repository/actions/runs/$RunId/artifacts?per_page=100"
        ) | ConvertFrom-Json -Depth 20
        $windows = @(
            $artifacts.artifacts |
                Where-Object name -CEQ 'konclave-x86_64-pc-windows-msvc-unsigned'
        )
        if ($windows.Count -eq 1) {
            [void](Invoke-RequiredCommand gh @(
                'run',
                'download',
                $RunId.ToString(),
                '--repo',
                $repository,
                '--name',
                'konclave-x86_64-pc-windows-msvc-unsigned',
                '--dir',
                $Destination
            ))
            return
        }

        $run = Invoke-RequiredCommand gh @(
            'run',
            'view',
            $RunId.ToString(),
            '--repo',
            $repository,
            '--json',
            'status,conclusion'
        ) | ConvertFrom-Json
        if ($run.status -eq 'completed') {
            throw "Package workflow completed as $($run.conclusion) before Windows download."
        }
        if ($attempt % 6 -eq 0) {
            Write-Output "Waiting for Windows package from workflow run $RunId..."
        }
        Start-Sleep -Seconds 10
    }
    throw 'Timed out waiting for the Windows package candidate.'
}

function Test-ProvenanceDigest {
    param(
        [Parameter(Mandatory)]
        [string]$ArchivePath,

        [Parameter(Mandatory)]
        [string]$ExpectedSourceCommit
    )

    $provenancePath = "$ArchivePath.intoto.jsonl"
    $statement = Get-Content -LiteralPath $provenancePath -Raw -Encoding UTF8 |
        ConvertFrom-Json -Depth 100
    $subject = @(
        $statement.subject |
            Where-Object name -CEQ ([IO.Path]::GetFileName($ArchivePath))
    )
    if ($subject.Count -ne 1) {
        throw "Provenance does not identify $ArchivePath."
    }
    $actual = (Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).
        Hash.ToLowerInvariant()
    if ($actual -cne [string]$subject[0].digest.sha256) {
        throw "Provenance digest mismatch for $ArchivePath."
    }
    $source = @(
        $statement.predicate.buildDefinition.resolvedDependencies |
            Where-Object {
                $_.PSObject.Properties['digest'] -and
                $_.digest.PSObject.Properties['gitCommit']
            }
    )
    if (
        $source.Count -ne 1 -or
        [string]$source[0].digest.gitCommit -cne $ExpectedSourceCommit
    ) {
        throw "Provenance source revision mismatch for $ArchivePath."
    }
}

function Expand-ProtectedZipArchive {
    param(
        [Parameter(Mandatory)]
        [string]$ArchivePath,

        [Parameter(Mandatory)]
        [string]$DestinationPath
    )

    Add-Type -AssemblyName System.IO.Compression
    $destinationRoot = [IO.Path]::GetFullPath($DestinationPath)
    $destinationPrefix = $destinationRoot + [IO.Path]::DirectorySeparatorChar
    $seen = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    $archive = [IO.Compression.ZipFile]::OpenRead($ArchivePath)
    try {
        if ($archive.Entries.Count -gt 2048) {
            throw "Archive contains too many entries: $ArchivePath"
        }
        [int64]$totalLength = 0
        foreach ($entry in $archive.Entries) {
            $entryName = [string]$entry.FullName
            if (
                [string]::IsNullOrWhiteSpace($entryName) -or
                $entryName.Contains('\') -or
                $entryName.Contains(':') -or
                $entryName.StartsWith('/') -or
                $entryName.Contains([char]0)
            ) {
                throw "Archive contains an unsafe entry name: $entryName"
            }
            $isDirectory = $entryName.EndsWith('/')
            $segments = @($entryName.TrimEnd('/').Split('/'))
            if (
                $segments.Count -eq 0 -or
                @($segments | Where-Object { $_ -in @('', '.', '..') }).Count -gt 0
            ) {
                throw "Archive contains an unsafe entry path: $entryName"
            }
            $unixFileType = ($entry.ExternalAttributes -shr 16) -band 0xF000
            if (
                $unixFileType -eq 0xA000 -or
                ($entry.ExternalAttributes -band [int][IO.FileAttributes]::ReparsePoint)
            ) {
                throw "Archive contains a link entry: $entryName"
            }
            if ($entry.Length -gt 536870912) {
                throw "Archive entry exceeds the extraction limit: $entryName"
            }
            $totalLength += $entry.Length
            if ($totalLength -gt 1073741824) {
                throw "Archive exceeds the extraction limit: $ArchivePath"
            }

            $targetPath = [IO.Path]::GetFullPath(
                [IO.Path]::Combine($destinationRoot, ($segments -join '\'))
            )
            if (-not $targetPath.StartsWith(
                $destinationPrefix,
                [StringComparison]::OrdinalIgnoreCase
            )) {
                throw "Archive entry escapes the destination: $entryName"
            }
            if (-not $seen.Add($targetPath)) {
                throw "Archive contains a duplicate destination: $entryName"
            }
            if ($isDirectory) {
                New-Item -ItemType Directory -Path $targetPath -Force | Out-Null
                continue
            }

            $parent = [IO.Path]::GetDirectoryName($targetPath)
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
            $source = $entry.Open()
            $destination = [IO.File]::Open(
                $targetPath,
                [IO.FileMode]::CreateNew,
                [IO.FileAccess]::Write,
                [IO.FileShare]::None
            )
            try {
                $buffer = [byte[]]::new(81920)
                [int64]$written = 0
                while (($read = $source.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $written += $read
                    if ($written -gt $entry.Length -or $written -gt 536870912) {
                        throw "Archive entry expanded beyond its limit: $entryName"
                    }
                    $destination.Write($buffer, 0, $read)
                }
            }
            finally {
                $destination.Dispose()
                $source.Dispose()
            }
            if ($written -ne $entry.Length) {
                throw "Archive entry length mismatch: $entryName"
            }
        }
    }
    finally {
        $archive.Dispose()
    }
}

function Install-DemoPackages {
    foreach ($command in @('gh', 'git', 'copilot')) {
        if ($null -eq (Get-Command $command -ErrorAction SilentlyContinue)) {
            throw "$command is required."
        }
    }
    [void](Invoke-RequiredCommand gh @('auth', 'status'))
    $settings = Read-JsonObject -Path $copilotSettingsPath
    if (
        $settings.Contains('experimental') -and
        $settings['experimental'] -isnot [bool]
    ) {
        throw 'Copilot experimental setting must be a boolean.'
    }
    $localHead = (
        Invoke-RequiredCommand git @('-C', $projectRoot, 'rev-parse', 'HEAD')
    ).Trim()
    $publishedMain = (
        Invoke-RequiredCommand gh @(
            'api',
            "repos/$repository/commits/main",
            '--jq',
            '.sha'
        )
    ).Trim()
    if ($localHead -cne $publishedMain) {
        throw (
            'This checkout must be at the current published main revision before ' +
            'building a demo package.'
        )
    }

    $downloadRoot = Join-Path (
        [IO.Path]::GetTempPath()
    ) "konclave-demo-$([Guid]::NewGuid().ToString('N'))"
    $stagingRoot = Join-Path $installParent "demo.$([Guid]::NewGuid().ToString('N'))"
    $runId = [int64]0
    $runCleaned = $false
    try {
        New-Item -ItemType Directory -Path $downloadRoot, $stagingRoot -Force |
            Out-Null
        $workflowRun = Get-PackageWorkflowRun
        $runId = [int64]$workflowRun.Id
        Write-Output "Building the Windows demo package in public workflow run $runId..."
        if ($workflowRun.HeadSha -cne $localHead) {
            throw (
                'Package workflow source does not match this checkout: ' +
                "$($workflowRun.HeadSha) != $localHead"
            )
        }
        Wait-WindowsPackageArtifact -RunId $runId -Destination $downloadRoot
        Stop-PackageWorkflowAndDeleteArtifacts -RunId $runId
        $runCleaned = $true
        $clientArchive = Join-Path $downloadRoot ([string]$clientContract[0].fileName)
        $relayArchive = Join-Path $downloadRoot ([string]$relayContract[0].fileName)
        Test-ProvenanceDigest $clientArchive $workflowRun.HeadSha
        Test-ProvenanceDigest $relayArchive $workflowRun.HeadSha
        Expand-ProtectedZipArchive $clientArchive $stagingRoot
        Expand-ProtectedZipArchive $relayArchive $stagingRoot
        foreach ($path in @(
            (Join-Path $stagingRoot $clientRootName 'bin' 'konclave.exe'),
            (Join-Path $stagingRoot $relayRootName 'bin' 'KonclaveCommunityRelay.exe'),
            (Join-Path $stagingRoot $clientRootName 'share' 'konclave' 'plugin' 'plugin.json')
        )) {
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
                throw "Downloaded package is missing $path."
            }
        }

        Stop-DemoRelay
        if (Test-Path -LiteralPath $installRoot) {
            $item = Get-Item -LiteralPath $installRoot
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'Konclave demo install root must not be a reparse point.'
            }
            Remove-Item -LiteralPath $installRoot -Recurse -Force
        }
        Move-Item -LiteralPath $stagingRoot -Destination $installRoot
    }
    finally {
        if ($runId -gt 0 -and -not $runCleaned) {
            try {
                Stop-PackageWorkflowAndDeleteArtifacts -RunId $runId
            }
            catch {
                # Preserve the primary setup failure while making incomplete
                # artifact cleanup visible to the operator.
                Write-Warning "Package workflow cleanup also failed: $($_.Exception.Message)"
            }
        }
        if (Test-Path -LiteralPath $stagingRoot) {
            Remove-Item -LiteralPath $stagingRoot -Recurse -Force
        }
        if (Test-Path -LiteralPath $downloadRoot) {
            Remove-Item -LiteralPath $downloadRoot -Recurse -Force
        }
    }
}

function Write-DemoStatus {
    param(
        [Parameter(Mandatory)]
        [Diagnostics.Process]$RelayProcess
    )

    $status = [ordered]@{
        schemaVersion = 2
        relayProcessId = $RelayProcess.Id
        relayStartTimeUtcFileTime = (
            $RelayProcess.StartTime.ToUniversalTime().ToFileTimeUtc()
        )
        relayExecutable = $relayExecutable
        endpoint = $endpoint
        installRoot = $installRoot
        profileRoot = $profileRoot
    }
    $temporary = "$statusPath.$([Guid]::NewGuid().ToString('N')).tmp"
    [IO.File]::WriteAllText(
        $temporary,
        ($status | ConvertTo-Json -Depth 10) + "`n",
        [Text.UTF8Encoding]::new($false)
    )
    [IO.File]::Move($temporary, $statusPath, $true)
}

function Test-DemoStopPath {
    $testRoot = Join-Path (
        [IO.Path]::GetTempPath()
    ) "konclave-stop-test-$([Guid]::NewGuid().ToString('N'))"
    $testStatus = Join-Path $testRoot 'status.json'
    New-Item -ItemType Directory -Path $testRoot | Out-Null
    try {
        [IO.File]::WriteAllText(
            $testStatus,
            (@{
                schemaVersion = 2
                relayProcessId = [int]::MaxValue
                relayStartTimeUtcFileTime = 1
                relayExecutable = 'C:\nonexistent-konclave-relay.exe'
            } | ConvertTo-Json),
            [Text.UTF8Encoding]::new($false)
        )
        Stop-DemoRelay -StatusFile $testStatus
        if (Test-Path -LiteralPath $testStatus) {
            throw 'Synthetic demo stop did not remove its status file.'
        }
    }
    finally {
        if (Test-Path -LiteralPath $testRoot) {
            Remove-Item -LiteralPath $testRoot -Recurse -Force
        }
    }
}

function Test-ProtectedZipExtraction {
    Add-Type -AssemblyName System.IO.Compression
    $testRoot = Join-Path (
        [IO.Path]::GetTempPath()
    ) "konclave-zip-test-$([Guid]::NewGuid().ToString('N'))"
    $validArchivePath = Join-Path $testRoot 'valid.zip'
    $unsafeArchivePath = Join-Path $testRoot 'unsafe.zip'
    $validDestination = Join-Path $testRoot 'valid'
    $unsafeDestination = Join-Path $testRoot 'unsafe'
    $escapedPath = Join-Path $testRoot 'escaped.txt'
    New-Item -ItemType Directory `
        -Path $validDestination, $unsafeDestination `
        -Force | Out-Null
    foreach ($specification in @(
        @{ Path = $validArchivePath; Entry = 'root/demo.txt'; Content = 'valid' },
        @{ Path = $unsafeArchivePath; Entry = '../escaped.txt'; Content = '' }
    )) {
        $file = [IO.File]::Open(
            $specification.Path,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::None
        )
        $archive = [IO.Compression.ZipArchive]::new(
            $file,
            [IO.Compression.ZipArchiveMode]::Create
        )
        try {
            $entry = $archive.CreateEntry($specification.Entry)
            $writer = [IO.StreamWriter]::new($entry.Open())
            try {
                $writer.Write($specification.Content)
            }
            finally {
                $writer.Dispose()
            }
        }
        finally {
            $archive.Dispose()
            $file.Dispose()
        }
    }
    try {
        Expand-ProtectedZipArchive $validArchivePath $validDestination
        $validContent = Get-Content -LiteralPath (
            Join-Path $validDestination 'root' 'demo.txt'
        ) -Raw
        if ($validContent -cne 'valid') {
            throw 'Protected ZIP extraction did not preserve a valid entry.'
        }
        $rejected = $false
        try {
            Expand-ProtectedZipArchive $unsafeArchivePath $unsafeDestination
        }
        catch {
            $rejected = $true
        }
        if (-not $rejected -or (Test-Path -LiteralPath $escapedPath)) {
            throw 'Protected ZIP extraction accepted an escaping entry.'
        }
    }
    finally {
        if (Test-Path -LiteralPath $testRoot) {
            Remove-Item -LiteralPath $testRoot -Recurse -Force
        }
    }
}

function Test-ProvenanceValidation {
    $testRoot = Join-Path (
        [IO.Path]::GetTempPath()
    ) "konclave-provenance-test-$([Guid]::NewGuid().ToString('N'))"
    $archivePath = Join-Path $testRoot 'candidate.zip'
    $sourceCommit = '0000000000000000000000000000000000000000'
    New-Item -ItemType Directory -Path $testRoot | Out-Null
    try {
        [IO.File]::WriteAllText(
            $archivePath,
            'candidate',
            [Text.UTF8Encoding]::new($false)
        )
        $digest = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).
            Hash.ToLowerInvariant()
        $statement = @{
            subject = @(
                @{
                    name = [IO.Path]::GetFileName($archivePath)
                    digest = @{ sha256 = $digest }
                }
            )
            predicate = @{
                buildDefinition = @{
                    resolvedDependencies = @(
                        @{ digest = @{ sha256 = $digest } },
                        @{ digest = @{ gitCommit = $sourceCommit } }
                    )
                }
            }
        }
        [IO.File]::WriteAllText(
            "$archivePath.intoto.jsonl",
            ($statement | ConvertTo-Json -Depth 20 -Compress),
            [Text.UTF8Encoding]::new($false)
        )
        Test-ProvenanceDigest $archivePath $sourceCommit
        [IO.File]::AppendAllText($archivePath, 'tampered')
        $rejected = $false
        try {
            Test-ProvenanceDigest $archivePath $sourceCommit
        }
        catch {
            $rejected = $true
        }
        if (-not $rejected) {
            throw 'Provenance validation accepted a tampered archive.'
        }
    }
    finally {
        if (Test-Path -LiteralPath $testRoot) {
            Remove-Item -LiteralPath $testRoot -Recurse -Force
        }
    }
}

if ($Validate) {
    foreach ($command in @('gh', 'git', 'copilot')) {
        if ($null -eq (Get-Command $command -ErrorAction SilentlyContinue)) {
            throw "$command is required."
        }
    }
    [void](Invoke-RequiredCommand gh @('auth', 'status'))
    $runListType = Invoke-RequiredCommand gh @(
        'api',
        $workflowRunsApiPath,
        '--jq',
        '.workflow_runs | type'
    )
    if (($runListType -join '').Trim() -cne 'array') {
        throw 'Package workflow run API did not return an array.'
    }
    if (-not (Test-Path -LiteralPath (
        Join-Path $projectRoot '.github' 'workflows' 'package-validation.yml'
    ) -PathType Leaf)) {
        throw 'Package validation workflow is missing.'
    }
    Test-DemoStopPath
    Test-ProtectedZipExtraction
    Test-ProvenanceValidation
    Write-Output 'Konclave local demo prerequisites and release contract are valid.'
    return
}

if ($Stop) {
    Stop-DemoRelay
    Restore-LegacyProfileRoot
    if ($UninstallExtension) {
        Remove-CopilotExtension
        Remove-LegacyKonclavePlugin
    }
    Write-Output 'Konclave local demo stopped. Profile and relay state were preserved.'
    return
}

Stop-DemoRelay
Restore-LegacyProfileRoot
Test-PortAvailable $Port
if ($Refresh -or -not (
    (Test-Path -LiteralPath $cliPath -PathType Leaf) -and
    (Test-Path -LiteralPath $relayExecutable -PathType Leaf)
)) {
    Install-DemoPackages
}

New-Item -ItemType Directory -Path $relayStateRoot, $profileRoot -Force |
    Out-Null
[void](Invoke-RequiredCommand $cliPath @(
    'relay-bootstrap',
    '--relay-endpoint',
    $endpoint,
    '--access-document',
    (Join-Path $relayStateRoot 'access.json'),
    '--profile-root',
    $profileRoot
))

$relayProcess = Start-Process `
    -FilePath $relayExecutable `
    -Environment @{
        SERVICE_HTTP_ADDRESS = "127.0.0.1:$Port"
        SERVICE_HEALTH_ADDRESS = "127.0.0.1:$Port"
        KONCLAVE_RELAY_ACCESS_FILE = (Join-Path $relayStateRoot 'access.json')
        KONCLAVE_RELAY_DATABASE_PATH = (Join-Path $relayStateRoot 'relay.sqlite')
    } `
    -RedirectStandardOutput (Join-Path $relayStateRoot 'stdout.log') `
    -RedirectStandardError (Join-Path $relayStateRoot 'stderr.log') `
    -WindowStyle Hidden `
    -PassThru
try {
    Wait-RelayHealth -Process $relayProcess
    [void](Invoke-RequiredCommand $cliPath @(
        'init',
        '--relay-endpoint',
        $endpoint,
        '--profile-root',
        $profileRoot
    ))
    [void](Invoke-RequiredCommand $cliPath @(
        'doctor',
        '--profile-root',
        $profileRoot,
        '--install-root',
        $clientRoot
    ))
    Install-CopilotExtension
    Remove-LegacyKonclavePlugin
    Write-DemoStatus -RelayProcess $relayProcess
}
catch {
    if (-not $relayProcess.HasExited) {
        Stop-Process -Id $relayProcess.Id
        [void]$relayProcess.WaitForExit(10000)
    }
    throw
}

Write-Output ''
Write-Output 'Konclave local demo is ready.'
Write-Output "Relay endpoint: $endpoint"
Write-Output "Relay process ID: $($relayProcess.Id)"
Write-Output "Copilot extension: $copilotExtensionRoot"
Write-Output 'Close existing Copilot CLI sessions, then open fresh sessions in two repositories.'
Write-Output 'In one session, ask: Use Konclave to create a pairing capability requesting member role.'
Write-Output 'Give that one capability to the other session and ask it to redeem and authorize the joiner.'
Write-Output 'Back in the first session, review and authorize the inviter. Automatic delivery is then active.'
Write-Output ''
Write-Output "Stop later with: pwsh -NoProfile -File `"$PSCommandPath`" -Stop"
