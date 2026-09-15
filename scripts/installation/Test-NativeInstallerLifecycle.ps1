#Requires -Version 7.4

[CmdletBinding()]
param(
    [string]$Repository = 'nexus-software-laboratories/konclave',
    [string]$BaselineTag = 'v0.1.0',
    [string]$CandidateTag = 'v0.1.4',
    [switch]$UseCandidateInstaller
)

$ErrorActionPreference = 'Stop'

if (-not $IsWindows) {
    throw 'Native installer lifecycle acceptance requires Windows.'
}
$baselineMatch = [regex]::Match($BaselineTag, '^v([0-9]+\.[0-9]+\.[0-9]+)$')
$candidateMatch = [regex]::Match($CandidateTag, '^v([0-9]+\.[0-9]+\.[0-9]+)$')
if (-not $baselineMatch.Success -or -not $candidateMatch.Success) {
    throw 'Lifecycle release tags must be canonical v-prefixed SemVer.'
}
$baselineVersion = $baselineMatch.Groups[1].Value
$candidateVersion = $candidateMatch.Groups[1].Value
if ($baselineVersion -ceq $candidateVersion) {
    throw 'Lifecycle baseline and candidate versions must differ.'
}

function Invoke-NativeCommand {
    param(
        [string]$Command,
        [string[]]$Arguments
    )

    $output = & $Command @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "$Command failed: $($output -join "`n")"
    }
    return @($output)
}

function Receive-ReleaseAssets {
    param(
        [string]$Tag,
        [string]$Destination
    )

    for ($attempt = 1; $attempt -le 5; $attempt++) {
        $output = & gh release download `
            $Tag `
            --repo $Repository `
            --dir $Destination `
            --clobber 2>&1
        if ($LASTEXITCODE -eq 0) {
            return
        }
        $diagnostics = ($output -join "`n")
        if ($diagnostics -match 'HTTP (?:400|401|403|404|405|422)\b') {
            throw "Release download is not retryable: $Tag"
        }
        if ($attempt -eq 5) {
            $tail = @($output | Select-Object -Last 5) -join "`n"
            throw "Release download failed after five attempts: $Tag`n$tail"
        }
        Write-Warning "Release download attempt $attempt failed for $Tag."
        Start-Sleep -Seconds ([math]::Pow(2, $attempt - 1))
    }
}

function Get-ReleaseArtifact {
    param(
        $Manifest,
        [string]$Id
    )

    $matches = @($Manifest.artifacts | Where-Object id -CEQ $Id)
    if ($matches.Count -ne 1) {
        throw "Release artifact is missing or duplicated: $Id"
    }
    return $matches[0]
}

function Expand-SingleZipRoot {
    param(
        [string]$Archive,
        [string]$Destination
    )

    [IO.Compression.ZipFile]::ExtractToDirectory($Archive, $Destination)
    $roots = @(Get-ChildItem -LiteralPath $Destination -Directory)
    if ($roots.Count -ne 1) {
        throw "Archive does not contain one root: $Archive"
    }
    return $roots[0].FullName
}

function Get-FreePort {
    $listener = [Net.Sockets.TcpListener]::new(
        [Net.IPAddress]::Loopback,
        0
    )
    $listener.Start()
    try {
        return ([Net.IPEndPoint]$listener.LocalEndpoint).Port
    }
    finally {
        $listener.Stop()
    }
}

function Wait-RelayHealth {
    param(
        [string]$Endpoint
    )

    for ($attempt = 0; $attempt -lt 120; $attempt++) {
        try {
            $response = Invoke-WebRequest `
                -Uri "$Endpoint/healthz" `
                -UseBasicParsing `
                -TimeoutSec 2
            if ($response.StatusCode -eq 200) {
                return
            }
        }
        catch {
            if ($attempt -eq 119) {
                throw
            }
        }
        Start-Sleep -Milliseconds 250
    }
    throw 'Relay did not become healthy.'
}

function Get-FileHashAfterRelease {
    param(
        [string]$Path
    )

    for ($attempt = 0; $attempt -lt 50; $attempt++) {
        try {
            return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
        }
        catch {
            if ($attempt -eq 49) {
                throw
            }
            Start-Sleep -Milliseconds 100
        }
    }
}

function Invoke-Installer {
    param(
        [string]$Installer,
        [hashtable]$Arguments
    )

    $output = & $Installer @Arguments
    return ($output -join "`n") | ConvertFrom-Json -Depth 20
}

function Assert-InstallerAction {
    param(
        $Result,
        [string]$Action,
        [string]$Version
    )

    if (
        [string]$Result.action -cne $Action -or
        [string]$Result.version -cne $Version
    ) {
        throw "Installer returned $($Result.action) $($Result.version), expected $Action $Version."
    }
}

function Get-KonclavePluginRecords {
    $json = Invoke-NativeCommand copilot @('plugin', 'list', '--json') |
        ConvertFrom-Json -Depth 20
    $matches = [Collections.Generic.List[object]]::new()
    $queue = [Collections.Generic.Queue[object]]::new()
    $queue.Enqueue($json)
    while ($queue.Count -gt 0) {
        $value = $queue.Dequeue()
        if ($value -is [array]) {
            foreach ($item in $value) {
                if ($null -ne $item) {
                    $queue.Enqueue($item)
                }
            }
            continue
        }
        if ($value -isnot [Management.Automation.PSCustomObject]) {
            continue
        }
        if (
            $value.PSObject.Properties['name'] -and
            [string]$value.name -ceq 'konclave'
        ) {
            $matches.Add($value)
        }
        foreach ($property in $value.PSObject.Properties) {
            if (
                $null -ne $property.Value -and
                (
                    $property.Value -is [array] -or
                    $property.Value -is [Management.Automation.PSCustomObject]
                )
            ) {
                $queue.Enqueue($property.Value)
            }
        }
    }
    return @($matches)
}

$root = Join-Path (
    [IO.Path]::GetTempPath()
) "konclave-native-lifecycle-$([Guid]::NewGuid().ToString('N'))"
$baselineRelease = Join-Path $root "release-$baselineVersion"
$candidateRelease = Join-Path $root "release-$candidateVersion"
$currentInstallerRoot = Join-Path $root 'current-installer'
$bootstrapRoot = Join-Path $root 'bootstrap'
$localAppData = Join-Path $root 'local-app-data'
$dataRoot = Join-Path $localAppData 'Konclave'
$relayState = Join-Path $root 'relay'
$copilotHome = Join-Path $root 'copilot-home'
$relayProcess = $null
$manager = $null
$managerInstallRoot = $null
$marketplaceRegistered = $false
$managerConfig = Join-Path $dataRoot 'service' 'konclave-local-service.json'

New-Item -ItemType Directory -Path (
    $root,
    $baselineRelease,
    $candidateRelease,
    $currentInstallerRoot,
    $bootstrapRoot,
    $relayState,
    $copilotHome
) | Out-Null
$previousCopilotHome = $env:COPILOT_HOME
$previousLocalAppData = $env:LOCALAPPDATA
$env:COPILOT_HOME = $copilotHome
$env:LOCALAPPDATA = $localAppData
try {
    Receive-ReleaseAssets -Tag $BaselineTag -Destination $baselineRelease
    Receive-ReleaseAssets -Tag $CandidateTag -Destination $candidateRelease
    & (Join-Path $baselineRelease 'Verify-Release.ps1') -Directory $baselineRelease
    & (Join-Path $candidateRelease 'Verify-Release.ps1') -Directory $candidateRelease
    foreach ($name in @(
        'Install-Konclave.ps1',
        'InstallationLifecycle.Functions.ps1',
        'InstallationRuntime.Functions.ps1'
    )) {
        Copy-Item `
            -LiteralPath (Join-Path $PSScriptRoot $name) `
            -Destination (Join-Path $currentInstallerRoot $name) `
            -Force
    }
    foreach ($name in @(
        'ReleaseIntegrity.Functions.ps1',
        'ReleasePublication.Functions.ps1'
    )) {
        Copy-Item `
            -LiteralPath (Join-Path $PSScriptRoot '..' 'packaging' $name) `
            -Destination (Join-Path $currentInstallerRoot $name) `
            -Force
    }
    Copy-Item `
        -LiteralPath (
            Join-Path $PSScriptRoot '..' '..' 'apps' 'Konclave.LocalDaemon' `
                'packaging' 'windows' 'manage-user-service.ps1'
        ) `
        -Destination (Join-Path $currentInstallerRoot 'WindowsUserService.ps1') `
        -Force

    $candidateManifest = Get-Content -LiteralPath (
        Join-Path $candidateRelease 'RELEASE.json'
    ) -Raw -Encoding UTF8 | ConvertFrom-Json -Depth 100
    $clientArtifact = Get-ReleaseArtifact `
        -Manifest $candidateManifest `
        -Id 'konclave-client-windows-x64'
    $relayArtifact = Get-ReleaseArtifact `
        -Manifest $candidateManifest `
        -Id 'konclave-relay-windows-x64'
    $bootstrapClient = Expand-SingleZipRoot `
        -Archive (Join-Path $candidateRelease $clientArtifact.fileName) `
        -Destination (Join-Path $bootstrapRoot 'client')
    $bootstrapRelay = Expand-SingleZipRoot `
        -Archive (Join-Path $candidateRelease $relayArtifact.fileName) `
        -Destination (Join-Path $bootstrapRoot 'relay')

    $port = Get-FreePort
    $endpoint = "http://127.0.0.1:$port"
    $accessDocument = Join-Path $relayState 'access.json'
    $profileRoot = Join-Path $dataRoot 'profiles'
    [void](Invoke-NativeCommand (
        Join-Path $bootstrapClient 'bin' 'konclave.exe'
    ) @(
        'relay-bootstrap',
        '--relay-endpoint',
        $endpoint,
        '--access-document',
        $accessDocument,
        '--profile-root',
        $profileRoot
    ))

    $relayLog = Join-Path $relayState 'relay.log'
    $previousEnvironment = @{
        SERVICE_HTTP_ADDRESS = $env:SERVICE_HTTP_ADDRESS
        SERVICE_HEALTH_ADDRESS = $env:SERVICE_HEALTH_ADDRESS
        KONCLAVE_RELAY_ACCESS_FILE = $env:KONCLAVE_RELAY_ACCESS_FILE
        KONCLAVE_RELAY_DATABASE_PATH = $env:KONCLAVE_RELAY_DATABASE_PATH
    }
    $env:SERVICE_HTTP_ADDRESS = "127.0.0.1:$port"
    $env:SERVICE_HEALTH_ADDRESS = "127.0.0.1:$port"
    $env:KONCLAVE_RELAY_ACCESS_FILE = $accessDocument
    $env:KONCLAVE_RELAY_DATABASE_PATH = Join-Path $relayState 'relay.sqlite'
    try {
        $relayProcess = Start-Process `
            -FilePath (Join-Path $bootstrapRelay 'bin' 'KonclaveCommunityRelay.exe') `
            -RedirectStandardOutput $relayLog `
            -RedirectStandardError (Join-Path $relayState 'relay.error.log') `
            -PassThru
    }
    finally {
        foreach ($entry in $previousEnvironment.GetEnumerator()) {
            [Environment]::SetEnvironmentVariable(
                $entry.Key,
                $entry.Value,
                [EnvironmentVariableTarget]::Process
            )
        }
    }
    Wait-RelayHealth -Endpoint $endpoint

    $installerRoot = if ($UseCandidateInstaller) {
        $candidateRelease
    }
    else {
        $currentInstallerRoot
    }
    $installer = Join-Path $installerRoot 'Install-Konclave.ps1'
    $manager = Join-Path $installerRoot 'WindowsUserService.ps1'
    foreach ($path in @($installer, $manager)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Installer lifecycle support is missing: $path"
        }
    }
    if ($UseCandidateInstaller) {
        Write-Output 'lifecycle: immutable candidate installer selected'
    }
    $installArguments = @{
        Action = 'Install'
        ReleaseDirectory = $baselineRelease
        DataRoot = $dataRoot
        RelayEndpoint = $endpoint
        AuthorizationPolicy = 'account-trusted'
    }
    $installed = Invoke-Installer -Installer $installer -Arguments $installArguments
    Assert-InstallerAction -Result $installed -Action Install -Version $baselineVersion
    Write-Output 'lifecycle: baseline installed'
    $managerInstallRoot = [string]$installed.installRoot

    $profileSentinel = Join-Path $dataRoot 'profiles' 'retained-profile.sqlite3'
    [IO.File]::WriteAllText($profileSentinel, 'retained-profile')
    $authorityPath = Join-Path $dataRoot 'service' 'konclave-local-authorization.sqlite3'
    $task = @(Get-ScheduledTask | Where-Object TaskName -CEQ 'KonclaveLocalService')
    $renderedTask = & $manager `
        -Action Render `
        -InstallRoot $managerInstallRoot `
        -ConfigPath $managerConfig |
            ConvertFrom-Json
    if ($task.Count -ne 1) {
        throw 'Installed runtime did not create one scheduled task.'
    }
    $taskActions = @($task[0].Actions)
    if (
        $taskActions.Count -ne 1 -or
        -not ([string]$taskActions[0].Execute).Equals(
            [string]$renderedTask.executable,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        [string]$taskActions[0].Arguments -cne [string]$renderedTask.arguments
    ) {
        throw "Scheduled task action mismatch. Expected $(
            $renderedTask.executable
        ) $($renderedTask.arguments); actual $(
            $taskActions[0].Execute
        ) $($taskActions[0].Arguments)."
    }
    $expectedSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $actualSid = if ([string]$task[0].Principal.UserId -match '^S-') {
        [string]$task[0].Principal.UserId
    }
    else {
        ([Security.Principal.NTAccount]::new(
            [string]$task[0].Principal.UserId
        )).Translate([Security.Principal.SecurityIdentifier]).Value
    }
    if ($actualSid -cne $expectedSid) {
        throw "Scheduled task principal mismatch: $actualSid rather than $expectedSid."
    }
    & $manager `
        -Action Stop `
        -InstallRoot $managerInstallRoot `
        -ConfigPath $managerConfig
    $authorityHash = Get-FileHashAfterRelease -Path $authorityPath
    & $manager `
        -Action Start `
        -InstallRoot $managerInstallRoot `
        -ConfigPath $managerConfig
    $healthyAfterRestart = Invoke-Installer -Installer $installer -Arguments @{
        Action = 'Status'
        DataRoot = $dataRoot
    }
    Assert-InstallerAction `
        -Result $healthyAfterRestart `
        -Action Healthy `
        -Version $baselineVersion
    Write-Output 'lifecycle: supervisor stop and start passed'

    $verified = Invoke-Installer -Installer $installer -Arguments $installArguments
    Assert-InstallerAction -Result $verified -Action Verified -Version $baselineVersion
    Write-Output 'lifecycle: repeat install passed'

    $legacyRoot = Join-Path $copilotHome 'extensions' 'konclave'
    . (Join-Path $PSScriptRoot 'InstallationRuntime.Functions.ps1')
    [void](Set-OwnerOnlyDirectory -Path $legacyRoot)
    Copy-Item (
        Join-Path $managerInstallRoot 'share' 'konclave' 'client' 'client.mjs'
    ) $legacyRoot
    Copy-Item (
        Join-Path $managerInstallRoot 'share' 'konclave' 'plugin' `
            'com.github.copilot' 'extensions' 'konclave' 'extension.mjs'
    ) $legacyRoot
    $canonicalClientConfig = Get-Content -LiteralPath (
        Join-Path $dataRoot 'service' 'konclave.service.json'
    ) -Raw -Encoding UTF8
    Write-OwnerOnlyTextFile `
        -Path (Join-Path $legacyRoot 'konclave.service.json') `
        -Content $canonicalClientConfig `
        -MaximumBytes 64KB
    Remove-Item -LiteralPath (
        Join-Path $dataRoot 'service' 'konclave.service.json'
    ) -Force
    $migrated = Invoke-Installer -Installer $installer -Arguments $installArguments
    Assert-InstallerAction -Result $migrated -Action Verified -Version $baselineVersion
    Write-Output 'lifecycle: legacy sidecar migrated'
    if (-not (Test-Path -LiteralPath (
        Join-Path $dataRoot 'service' 'konclave.service.json'
    ) -PathType Leaf)) {
        throw 'Legacy client sidecar was not migrated to the canonical location.'
    }

    $activated = Invoke-Installer -Installer $installer -Arguments @{
        Action = 'ActivatePlugin'
        DataRoot = $dataRoot
    }
    Assert-InstallerAction -Result $activated -Action PluginActivated -Version $baselineVersion
    Write-Output 'lifecycle: baseline plugin activated'
    if (
        (Test-Path -LiteralPath $legacyRoot) -or
        -not (Test-Path -LiteralPath (
            Join-Path $dataRoot 'runtime' 'legacy' 'copilot-extension'
        ) -PathType Container)
    ) {
        throw 'Legacy raw extension was not preserved and removed after activation.'
    }
    if (@(Get-KonclavePluginRecords).Count -ne 1) {
        throw 'Direct activation did not leave exactly one Konclave plugin.'
    }

    $updated = Invoke-Installer -Installer $installer -Arguments @{
        Action = 'Update'
        ReleaseDirectory = $candidateRelease
        DataRoot = $dataRoot
    }
    Assert-InstallerAction -Result $updated -Action Update -Version $candidateVersion
    Write-Output 'lifecycle: candidate updated'
    $candidateInstallRoot = [string]$updated.installRoot

    $rolledBack = Invoke-Installer -Installer $installer -Arguments @{
        Action = 'Rollback'
        DataRoot = $dataRoot
    }
    Assert-InstallerAction -Result $rolledBack -Action RolledBack -Version $baselineVersion
    Write-Output 'lifecycle: candidate rolled back'
    $managerInstallRoot = [string]$rolledBack.installRoot

    $candidateService = Join-Path $candidateInstallRoot 'bin' 'KonclaveLocalService.exe'
    $healthyCandidateService = "$candidateService.healthy"
    Move-Item -LiteralPath $candidateService -Destination $healthyCandidateService
    Copy-Item -LiteralPath (
        Join-Path $env:SystemRoot 'System32' 'where.exe'
    ) -Destination $candidateService
    $updateFailed = $false
    try {
        [void](Invoke-Installer -Installer $installer -Arguments @{
            Action = 'Update'
            ReleaseDirectory = $candidateRelease
            DataRoot = $dataRoot
        })
    }
    catch {
        $updateFailed = $true
    }
    finally {
        Remove-Item -LiteralPath $candidateService -Force
        Move-Item -LiteralPath $healthyCandidateService -Destination $candidateService
    }
    if (-not $updateFailed) {
        throw 'Unhealthy update unexpectedly succeeded.'
    }
    Write-Output 'lifecycle: unhealthy update rejected'
    $state = Get-Content -LiteralPath (
        Join-Path $dataRoot 'runtime' 'installation.json'
    ) -Raw -Encoding UTF8 | ConvertFrom-Json -Depth 20
    if ([string]$state.activeVersion -cne $baselineVersion) {
        throw 'Failed update did not retain the previous active version.'
    }
    $status = Invoke-Installer -Installer $installer -Arguments @{
        Action = 'Status'
        DataRoot = $dataRoot
    }
    Assert-InstallerAction -Result $status -Action Healthy -Version $baselineVersion
    if (
        @(Get-KonclavePluginRecords).Count -ne 1 -or
        -not (Test-Path -LiteralPath (
            Join-Path $dataRoot 'runtime' 'direct-plugin.json'
        ) -PathType Leaf)
    ) {
        throw 'Status changed installer-owned Agent Plugin state.'
    }
    Write-Output 'lifecycle: previous runtime restored'

    $updatedAgain = Invoke-Installer -Installer $installer -Arguments @{
        Action = 'Update'
        ReleaseDirectory = $candidateRelease
        DataRoot = $dataRoot
    }
    Assert-InstallerAction -Result $updatedAgain -Action Switch -Version $candidateVersion
    Write-Output 'lifecycle: retained candidate reactivated'
    $managerInstallRoot = [string]$updatedAgain.installRoot
    $activatedAgain = Invoke-Installer -Installer $installer -Arguments @{
        Action = 'ActivatePlugin'
        DataRoot = $dataRoot
    }
    Assert-InstallerAction -Result $activatedAgain -Action PluginActivated -Version $candidateVersion
    Write-Output 'lifecycle: candidate plugin activated'
    if (@(Get-KonclavePluginRecords).Count -ne 1) {
        throw 'Plugin update created a duplicate Konclave installation.'
    }

    $prepared = Invoke-Installer -Installer $installer -Arguments @{
        Action = 'PrepareMarketplace'
        DataRoot = $dataRoot
    }
    Assert-InstallerAction `
        -Result $prepared `
        -Action MarketplacePrepared `
        -Version $candidateVersion
    if (
        [string]$prepared.pluginStatus -cne 'RemovedDirect' -or
        -not [bool]$prepared.restartRequired -or
        @(Get-KonclavePluginRecords).Count -ne 0 -or
        (Test-Path -LiteralPath (
            Join-Path $dataRoot 'runtime' 'direct-plugin.json'
        ))
    ) {
        throw 'Marketplace preparation did not remove the installer-owned direct plugin.'
    }
    $projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
    [void](Invoke-NativeCommand copilot @(
        'plugin',
        'marketplace',
        'add',
        $projectRoot
    ))
    $marketplaceRegistered = $true
    [void](Invoke-NativeCommand copilot @(
        'plugin',
        'install',
        'konclave@konclave'
    ))
    if (@(Get-KonclavePluginRecords).Count -ne 1) {
        throw 'Marketplace migration did not leave exactly one Konclave plugin.'
    }
    Write-Output 'lifecycle: direct plugin migrated to marketplace'

    $uninstalled = Invoke-Installer -Installer $installer -Arguments @{
        Action = 'Uninstall'
        DataRoot = $dataRoot
    }
    Assert-InstallerAction -Result $uninstalled -Action Uninstalled -Version $candidateVersion
    Write-Output 'lifecycle: installer uninstalled'
    $task = @(Get-ScheduledTask | Where-Object TaskName -CEQ 'KonclaveLocalService')
    if (
        $task.Count -ne 0 -or
        (Test-Path -LiteralPath (Join-Path $dataRoot 'runtime' 'versions')) -or
        (Test-Path -LiteralPath (Join-Path $dataRoot 'service' 'konclave.service.json')) -or
        -not (Test-Path -LiteralPath $profileSentinel -PathType Leaf) -or
        (Get-FileHashAfterRelease -Path $authorityPath) -cne $authorityHash -or
        @(Get-KonclavePluginRecords).Count -ne 1
    ) {
        throw 'Uninstall did not separate marketplace state from retained durable data.'
    }
    [void](Invoke-NativeCommand copilot @(
        'plugin',
        'marketplace',
        'remove',
        'konclave',
        '--force'
    ))
    $marketplaceRegistered = $false
    if (@(Get-KonclavePluginRecords).Count -ne 0) {
        throw 'Marketplace removal left a Konclave plugin after native uninstall.'
    }
    $managerInstallRoot = $null
}
finally {
    if ($marketplaceRegistered) {
        [void](Invoke-NativeCommand copilot @(
            'plugin',
            'marketplace',
            'remove',
            'konclave',
            '--force'
        ))
    }
    $env:COPILOT_HOME = $previousCopilotHome
    $env:LOCALAPPDATA = $previousLocalAppData
    $tasks = @(Get-ScheduledTask | Where-Object TaskName -CEQ 'KonclaveLocalService')
    if ($null -ne $manager -and $tasks.Count -ne 0) {
        if ($null -eq $managerInstallRoot) {
            $taskAction = @($tasks[0].Actions)[0]
            $binary = [string]$taskAction.Execute
            $managerInstallRoot = Split-Path -Parent (Split-Path -Parent $binary)
        }
        if (-not [string]::IsNullOrWhiteSpace($managerInstallRoot)) {
            & $manager `
                -Action Uninstall `
                -InstallRoot $managerInstallRoot `
                -ConfigPath $managerConfig
        }
    }
    if ($null -ne $relayProcess -and -not $relayProcess.HasExited) {
        Stop-Process -Id $relayProcess.Id
        $relayProcess.WaitForExit()
    }
    for ($attempt = 0; $attempt -lt 20; $attempt++) {
        if (-not (Test-Path -LiteralPath $root)) {
            break
        }
        try {
            Remove-Item -LiteralPath $root -Recurse -Force
            break
        }
        catch {
            if ($attempt -eq 19) {
                throw
            }
            Start-Sleep -Milliseconds 250
        }
    }
}

Write-Output 'Native installer clean, repeat, update, recovery, rollback, and uninstall passed.'
