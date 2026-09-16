#Requires -Version 7.4

Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot 'InstallationLifecycle.Functions.ps1')
$integrityFunctions = Join-Path $PSScriptRoot 'ReleaseIntegrity.Functions.ps1'
if (-not (Test-Path -LiteralPath $integrityFunctions -PathType Leaf)) {
    $integrityFunctions = Join-Path $PSScriptRoot '..' 'packaging' `
        'ReleaseIntegrity.Functions.ps1'
}
. $integrityFunctions
$publicationFunctions = Join-Path $PSScriptRoot 'ReleasePublication.Functions.ps1'
if (-not (Test-Path -LiteralPath $publicationFunctions -PathType Leaf)) {
    $publicationFunctions = Join-Path $PSScriptRoot '..' 'packaging' `
        'ReleasePublication.Functions.ps1'
}
. $publicationFunctions

$script:MaximumInstallationStateBytes = 64KB
$script:MaximumArchiveEntries = 4096
$script:MaximumArchiveEntryBytes = 1GB
$script:MaximumArchiveBytes = 2GB
$script:MaximumLegacyEntries = 2048
$script:MaximumLegacyFileBytes = 16MB
$script:MaximumLegacyBytes = 128MB

function Assert-SafeInstallationItem {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [ValidateSet('File', 'Directory')]
        [string]$Kind
    )

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (
        $item.Attributes -band [IO.FileAttributes]::ReparsePoint -or
        $item.LinkType -in @('SymbolicLink', 'Junction') -or
        ($Kind -ceq 'File' -and $item.PSIsContainer) -or
        ($Kind -ceq 'Directory' -and -not $item.PSIsContainer)
    ) {
        throw "Installer path is not a safe $Kind`: $Path"
    }
    return $item
}

function Resolve-WindowsOwnerAction {
    param(
        [Parameter(Mandatory)]
        [Security.Principal.SecurityIdentifier]$Owner,

        [Parameter(Mandatory)]
        [Security.Principal.SecurityIdentifier]$UserIdentity,

        [Parameter(Mandatory)]
        [Security.Principal.SecurityIdentifier]$TokenOwnerIdentity
    )

    if ($Owner.Value -ceq $UserIdentity.Value) {
        return 'Preserve'
    }
    if ($Owner.Value -ceq $TokenOwnerIdentity.Value) {
        return 'Initialize'
    }
    return 'Reject'
}

function Test-WindowsOwnerOnlyAcl {
    param(
        [Parameter(Mandatory)]
        [Security.AccessControl.FileSystemSecurity]$Acl,

        [Parameter(Mandatory)]
        [Security.Principal.SecurityIdentifier]$Identity,

        [Parameter(Mandatory)]
        [ValidateSet('File', 'Directory')]
        [string]$Kind
    )

    $rules = @($Acl.Access)
    $expectedInheritance = if ($Kind -ceq 'Directory') {
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [Security.AccessControl.InheritanceFlags]::ObjectInherit
    }
    else {
        [Security.AccessControl.InheritanceFlags]::None
    }
    return (
        $Acl.GetOwner(
            [Security.Principal.SecurityIdentifier]
        ).Value -ceq $Identity.Value -and
        $Acl.AreAccessRulesProtected -and
        $rules.Count -eq 1 -and
        $rules[0].AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
        $rules[0].FileSystemRights -eq [Security.AccessControl.FileSystemRights]::FullControl -and
        -not $rules[0].IsInherited -and
        $rules[0].InheritanceFlags -eq $expectedInheritance -and
        $rules[0].PropagationFlags -eq [Security.AccessControl.PropagationFlags]::None -and
        $rules[0].IdentityReference.Translate(
            [Security.Principal.SecurityIdentifier]
        ).Value -ceq $Identity.Value
    )
}

function Get-WindowsPathOwnerState {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [Security.Principal.SecurityIdentifier]$Identity,

        [Parameter(Mandatory)]
        [Security.Principal.SecurityIdentifier]$TokenOwnerIdentity
    )

    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $owner = $acl.GetOwner(
        [Security.Principal.SecurityIdentifier]
    )
    $action = Resolve-WindowsOwnerAction `
        -Owner $owner `
        -UserIdentity $Identity `
        -TokenOwnerIdentity $TokenOwnerIdentity
    if ($action -ceq 'Reject') {
        throw "Installer path is not owned by the current Windows user: $Path"
    }
    return [pscustomobject]@{
        acl = $acl
        action = $action
    }
}

function Set-OwnerOnlyDirectory {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    if (Test-Path -LiteralPath $fullPath) {
        [void](Assert-SafeInstallationItem -Path $fullPath -Kind Directory)
    }
    else {
        New-Item -ItemType Directory -Path $fullPath | Out-Null
    }
    if ($IsWindows) {
        $windowsIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $identity = $windowsIdentity.User
        if ($null -eq $identity) {
            throw 'Current Windows user SID is unavailable.'
        }
        $tokenOwnerIdentity = $windowsIdentity.Owner
        if ($null -eq $tokenOwnerIdentity) {
            $tokenOwnerIdentity = $identity
        }
        $ownerState = Get-WindowsPathOwnerState `
            -Path $fullPath `
            -Identity $identity `
            -TokenOwnerIdentity $tokenOwnerIdentity
        if (Test-WindowsOwnerOnlyAcl `
            -Acl $ownerState.acl `
            -Identity $identity `
            -Kind Directory) {
            return $fullPath
        }
        $security = [Security.AccessControl.DirectorySecurity]::new()
        if ($ownerState.action -ceq 'Initialize') {
            $security.SetOwner($identity)
        }
        $security.SetAccessRuleProtection($true, $false)
        $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [Security.AccessControl.InheritanceFlags]::ObjectInherit
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $identity,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$security.AddAccessRule($rule)
        Set-Acl -LiteralPath $fullPath -AclObject $security -ErrorAction Stop
        if (-not (Test-WindowsOwnerOnlyAcl `
            -Acl (Get-Acl -LiteralPath $fullPath -ErrorAction Stop) `
            -Identity $identity `
            -Kind Directory)) {
            throw "Installer directory could not be owner-protected: $fullPath"
        }
    }
    else {
        $mode = [IO.UnixFileMode]::UserRead -bor
            [IO.UnixFileMode]::UserWrite -bor
            [IO.UnixFileMode]::UserExecute
        [IO.File]::SetUnixFileMode($fullPath, $mode)
    }
    return $fullPath
}

function Set-OwnerOnlyFile {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    [void](Assert-SafeInstallationItem -Path $Path -Kind File)
    if ($IsWindows) {
        $windowsIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $identity = $windowsIdentity.User
        if ($null -eq $identity) {
            throw 'Current Windows user SID is unavailable.'
        }
        $tokenOwnerIdentity = $windowsIdentity.Owner
        if ($null -eq $tokenOwnerIdentity) {
            $tokenOwnerIdentity = $identity
        }
        $ownerState = Get-WindowsPathOwnerState `
            -Path $Path `
            -Identity $identity `
            -TokenOwnerIdentity $tokenOwnerIdentity
        if (Test-WindowsOwnerOnlyAcl `
            -Acl $ownerState.acl `
            -Identity $identity `
            -Kind File) {
            return
        }
        $security = [Security.AccessControl.FileSecurity]::new()
        if ($ownerState.action -ceq 'Initialize') {
            $security.SetOwner($identity)
        }
        $security.SetAccessRuleProtection($true, $false)
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $identity,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$security.AddAccessRule($rule)
        Set-Acl -LiteralPath $Path -AclObject $security -ErrorAction Stop
        if (-not (Test-WindowsOwnerOnlyAcl `
            -Acl (Get-Acl -LiteralPath $Path -ErrorAction Stop) `
            -Identity $identity `
            -Kind File)) {
            throw "Installer file could not be owner-protected: $Path"
        }
    }
    else {
        $mode = [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite
        [IO.File]::SetUnixFileMode($Path, $mode)
    }
}

function Write-OwnerOnlyTextFile {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Content,

        [Parameter(Mandatory)]
        [int]$MaximumBytes
    )

    $encoding = [Text.UTF8Encoding]::new($false)
    if ($encoding.GetByteCount($Content) -gt $MaximumBytes) {
        throw 'Installer-owned text file exceeds its size bound.'
    }
    $parent = Set-OwnerOnlyDirectory -Path (Split-Path -Parent $Path)
    $temporary = Join-Path $parent ".$([IO.Path]::GetFileName($Path)).$(
        [Guid]::NewGuid().ToString('N')
    ).tmp"
    try {
        [IO.File]::WriteAllText($temporary, $Content, $encoding)
        Set-OwnerOnlyFile -Path $temporary
        [IO.File]::Move($temporary, $Path, $true)
        Set-OwnerOnlyFile -Path $Path
    }
    finally {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Force
        }
    }
}

function Resolve-KonclaveDataRoot {
    param(
        [string]$DataRoot
    )

    if (-not [string]::IsNullOrWhiteSpace($DataRoot)) {
        if (-not [IO.Path]::IsPathRooted($DataRoot)) {
            throw 'Installer data root must be absolute.'
        }
        return [IO.Path]::GetFullPath($DataRoot)
    }
    if ($IsWindows) {
        $root = [Environment]::GetFolderPath(
            [Environment+SpecialFolder]::LocalApplicationData
        )
        if ([string]::IsNullOrWhiteSpace($root)) {
            throw 'LOCALAPPDATA is unavailable.'
        }
        return Join-Path $root 'Konclave'
    }
    $userProfile = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
    if ([string]::IsNullOrWhiteSpace($userProfile)) {
        throw 'User profile directory is unavailable.'
    }
    if ($IsMacOS) {
        return Join-Path $userProfile 'Library' 'Application Support' 'Konclave'
    }
    if (-not [string]::IsNullOrWhiteSpace($env:XDG_DATA_HOME)) {
        if (-not [IO.Path]::IsPathRooted($env:XDG_DATA_HOME)) {
            throw 'XDG_DATA_HOME must be absolute.'
        }
        return Join-Path ([IO.Path]::GetFullPath($env:XDG_DATA_HOME)) 'konclave'
    }
    return Join-Path $userProfile '.local' 'share' 'konclave'
}

function Get-InstallationPaths {
    param(
        [string]$DataRoot
    )

    $data = Resolve-KonclaveDataRoot -DataRoot $DataRoot
    $runtime = Join-Path $data 'runtime'
    return [pscustomobject][ordered]@{
        dataRoot = $data
        runtimeRoot = $runtime
        versionsRoot = Join-Path $runtime 'versions'
        stagingRoot = Join-Path $runtime 'staging'
        legacyRoot = Join-Path $runtime 'legacy'
        statePath = Join-Path $runtime 'installation.json'
        directPluginPath = Join-Path $runtime 'direct-plugin.json'
        profileRoot = Join-Path $data 'profiles'
        serviceRoot = Join-Path $data 'service'
        serviceConfigPath = Join-Path $data 'service' 'konclave-local-service.json'
        clientConfigPath = Join-Path $data 'service' 'konclave.service.json'
    }
}

function Initialize-InstallationPaths {
    param(
        [Parameter(Mandatory)]
        $Paths
    )

    foreach ($path in @(
        $Paths.dataRoot,
        $Paths.runtimeRoot,
        $Paths.versionsRoot,
        $Paths.stagingRoot,
        $Paths.legacyRoot
    )) {
        [void](Set-OwnerOnlyDirectory -Path $path)
    }
}

function Read-InstallationState {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return New-InstallationState
    }
    $file = Assert-SafeInstallationItem -Path $Path -Kind File
    if ($file.Length -le 0 -or $file.Length -gt $script:MaximumInstallationStateBytes) {
        throw 'Installer state file is empty or oversized.'
    }
    $state = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 |
        ConvertFrom-Json -Depth 20
    Assert-InstallationState -State $state
    return $state
}

function Write-InstallationState {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        $State
    )

    Assert-InstallationState -State $State
    $json = ($State | ConvertTo-Json -Depth 20).Replace("`r`n", "`n") + "`n"
    Write-OwnerOnlyTextFile `
        -Path $Path `
        -Content $json `
        -MaximumBytes $script:MaximumInstallationStateBytes
}

function Get-HostReleaseTarget {
    param(
        [ValidateSet('windows', 'linux', 'macos')]
        [string]$Platform,

        [ValidateSet('x64', 'arm64')]
        [string]$Architecture
    )

    if ([string]::IsNullOrEmpty($Platform)) {
        $Platform = if ($IsWindows) {
            'windows'
        }
        elseif ($IsMacOS) {
            'macos'
        }
        else {
            'linux'
        }
    }
    if ([string]::IsNullOrEmpty($Architecture)) {
        $Architecture = switch ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture) {
            { $_ -eq [Runtime.InteropServices.Architecture]::X64 } { 'x64' }
            { $_ -eq [Runtime.InteropServices.Architecture]::Arm64 } { 'arm64' }
            default { throw 'Installer does not support this processor architecture.' }
        }
    }
    $target = switch ("$Platform/$Architecture") {
        'windows/x64' { 'x86_64-pc-windows-msvc' }
        'linux/x64' { 'x86_64-unknown-linux-gnu' }
        'macos/x64' { 'x86_64-apple-darwin' }
        'macos/arm64' { 'aarch64-apple-darwin' }
        default { throw "Installer does not support $Platform/$Architecture." }
    }
    return $target
}

function Get-ReleaseInstallationCandidate {
    param(
        [Parameter(Mandatory)]
        [string]$ReleaseDirectory,

        [string]$Target = (Get-HostReleaseTarget)
    )

    $root = (Resolve-Path -LiteralPath $ReleaseDirectory).Path
    [void](Assert-SafeInstallationItem -Path $root -Kind Directory)
    [void](Test-ReleaseChecksums -Directory $root)
    $manifest = Get-Content -LiteralPath (
        Join-Path $root 'RELEASE.json'
    ) -Raw -Encoding UTF8 | ConvertFrom-Json -Depth 100
    if (
        [int]$manifest.schemaVersion -ne 1 -or
        [string]$manifest.release.channel -cne 'prerelease' -or
        [string]$manifest.release.signatureStatus -cne 'unsigned'
    ) {
        throw 'Release manifest is not a supported unsigned prerelease.'
    }
    foreach ($property in @('id', 'fileName')) {
        if (@(
            $manifest.artifacts |
                Group-Object -Property $property |
                Where-Object Count -ne 1
        ).Count -ne 0) {
            throw "Release manifest contains a duplicate $property."
        }
    }
    $sourceCommit = Get-ReleaseProvenanceSourceCommit `
        -Directory $root `
        -Manifest $manifest
    [void](Assert-ReleaseProvenanceSet `
        -Directory $root `
        -Manifest $manifest `
        -SourceCommit $sourceCommit)
    $matches = @(
        $manifest.artifacts |
            Where-Object {
                [string]$_.kind -ceq 'client' -and
                [string]$_.target -ceq $Target
            }
    )
    if ($matches.Count -ne 1) {
        throw "Release does not contain one client artifact for $Target."
    }
    $artifact = $matches[0]
    $archivePath = Join-Path $root ([string]$artifact.fileName)
    $record = New-InstalledVersionRecord `
        -Version ([string]$manifest.release.version) `
        -ArtifactSha256 (
            (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
        ) `
        -SourceCommit $sourceCommit `
        -Target $Target `
        -RootDirectory ([string]$artifact.rootDirectory)
    return [pscustomobject][ordered]@{
        manifest = $manifest
        artifact = $artifact
        archivePath = $archivePath
        record = $record
    }
}

function Resolve-ArchiveEntryPath {
    param(
        [Parameter(Mandatory)]
        [string]$DestinationRoot,

        [Parameter(Mandatory)]
        [string]$EntryName,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [Collections.Generic.HashSet[string]]$Seen
    )

    if (
        [string]::IsNullOrWhiteSpace($EntryName) -or
        $EntryName.Contains('\') -or
        $EntryName.Contains(':') -or
        $EntryName.StartsWith('/', [StringComparison]::Ordinal) -or
        $EntryName.Contains([char]0)
    ) {
        throw "Release archive contains an unsafe entry name: $EntryName"
    }
    $segments = @($EntryName.TrimEnd('/').Split('/'))
    if (
        $segments.Count -eq 0 -or
        @($segments | Where-Object { $_ -in @('', '.', '..') }).Count -gt 0
    ) {
        throw "Release archive contains an unsafe entry path: $EntryName"
    }
    $root = [IO.Path]::GetFullPath($DestinationRoot).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
    $target = [IO.Path]::GetFullPath(
        (Join-Path $root ($segments -join [IO.Path]::DirectorySeparatorChar))
    )
    $prefix = $root + [IO.Path]::DirectorySeparatorChar
    if (
        -not $target.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or
        -not $Seen.Add($target)
    ) {
        throw "Release archive entry escapes or duplicates its destination: $EntryName"
    }
    return $target
}

function Expand-ProtectedZipRelease {
    param(
        [Parameter(Mandatory)]
        [string]$ArchivePath,

        [Parameter(Mandatory)]
        [string]$DestinationRoot
    )

    Add-Type -AssemblyName System.IO.Compression
    $seen = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    $archive = [IO.Compression.ZipFile]::OpenRead($ArchivePath)
    try {
        if ($archive.Entries.Count -gt $script:MaximumArchiveEntries) {
            throw 'Release archive contains too many entries.'
        }
        [int64]$total = 0
        foreach ($entry in $archive.Entries) {
            $name = [string]$entry.FullName
            $target = Resolve-ArchiveEntryPath `
                -DestinationRoot $DestinationRoot `
                -EntryName $name `
                -Seen $seen
            $isDirectory = $name.EndsWith('/', [StringComparison]::Ordinal)
            $unixFileType = ($entry.ExternalAttributes -shr 16) -band 0xF000
            if (
                $unixFileType -eq 0xA000 -or
                ($entry.ExternalAttributes -band [int][IO.FileAttributes]::ReparsePoint)
            ) {
                throw "Release archive contains a link entry: $name"
            }
            if ($entry.Length -gt $script:MaximumArchiveEntryBytes) {
                throw "Release archive entry exceeds its size bound: $name"
            }
            $total += [int64]$entry.Length
            if ($total -gt $script:MaximumArchiveBytes) {
                throw 'Release archive exceeds its total size bound.'
            }
            if ($isDirectory) {
                [void](Set-OwnerOnlyDirectory -Path $target)
                continue
            }
            [void](Set-OwnerOnlyDirectory -Path (Split-Path -Parent $target))
            $input = $entry.Open()
            $output = [IO.File]::Open(
                $target,
                [IO.FileMode]::CreateNew,
                [IO.FileAccess]::Write,
                [IO.FileShare]::None
            )
            try {
                $input.CopyTo($output)
            }
            finally {
                $output.Dispose()
                $input.Dispose()
            }
            if ((Get-Item -LiteralPath $target -Force).Length -ne $entry.Length) {
                throw "Release archive entry length mismatch: $name"
            }
        }
    }
    finally {
        $archive.Dispose()
    }
}

function Expand-ProtectedTarGzipRelease {
    param(
        [Parameter(Mandatory)]
        [string]$ArchivePath,

        [Parameter(Mandatory)]
        [string]$DestinationRoot
    )

    $seen = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    $input = [IO.File]::OpenRead($ArchivePath)
    $gzip = [IO.Compression.GZipStream]::new(
        $input,
        [IO.Compression.CompressionMode]::Decompress,
        $true
    )
    $reader = [System.Formats.Tar.TarReader]::new($gzip, $true)
    try {
        [int64]$total = 0
        [int]$count = 0
        while ($null -ne ($entry = $reader.GetNextEntry())) {
            $count++
            if ($count -gt $script:MaximumArchiveEntries) {
                throw 'Release archive contains too many entries.'
            }
            $name = [string]$entry.Name
            $target = Resolve-ArchiveEntryPath `
                -DestinationRoot $DestinationRoot `
                -EntryName $name `
                -Seen $seen
            if ($entry.EntryType -eq [System.Formats.Tar.TarEntryType]::Directory) {
                [void](Set-OwnerOnlyDirectory -Path $target)
                continue
            }
            if (
                $entry.EntryType -notin @(
                    [System.Formats.Tar.TarEntryType]::RegularFile,
                    [System.Formats.Tar.TarEntryType]::V7RegularFile
                )
            ) {
                throw "Release archive contains a non-regular entry: $name"
            }
            if ($entry.Length -gt $script:MaximumArchiveEntryBytes) {
                throw "Release archive entry exceeds its size bound: $name"
            }
            $total += [int64]$entry.Length
            if ($total -gt $script:MaximumArchiveBytes) {
                throw 'Release archive exceeds its total size bound.'
            }
            [void](Set-OwnerOnlyDirectory -Path (Split-Path -Parent $target))
            $output = [IO.File]::Open(
                $target,
                [IO.FileMode]::CreateNew,
                [IO.FileAccess]::Write,
                [IO.FileShare]::None
            )
            try {
                $entry.DataStream.CopyTo($output)
            }
            finally {
                $output.Dispose()
            }
            if ((Get-Item -LiteralPath $target -Force).Length -ne $entry.Length) {
                throw "Release archive entry length mismatch: $name"
            }
            if (-not $IsWindows) {
                [IO.File]::SetUnixFileMode($target, $entry.Mode)
            }
        }
    }
    finally {
        $reader.Dispose()
        $gzip.Dispose()
        $input.Dispose()
    }
}

function Install-ReleaseCandidateFiles {
    param(
        [Parameter(Mandatory)]
        $Paths,

        [Parameter(Mandatory)]
        $Candidate
    )

    $record = $Candidate.record
    $versionRoot = Join-Path $Paths.versionsRoot ([string]$record.version)
    $installedRoot = Join-Path $versionRoot ([string]$record.rootDirectory)
    if (Test-Path -LiteralPath $versionRoot) {
        [void](Assert-SafeInstallationItem -Path $versionRoot -Kind Directory)
        if (-not (Test-Path -LiteralPath $installedRoot -PathType Container)) {
            throw 'Installed version directory conflicts with its release record.'
        }
        return [pscustomobject]@{
            root = $installedRoot
            created = $false
        }
    }
    return Install-NewReleaseCandidateFiles -Paths $Paths -Candidate $Candidate
}

function Get-InstalledVersionRoot {
        param(
            [Parameter(Mandatory)]
            $Paths,

            [Parameter(Mandatory)]
            $Record
        )

        $root = Join-Path (
            Join-Path $Paths.versionsRoot ([string]$Record.version)
        ) ([string]$Record.rootDirectory)
        [void](Assert-SafeInstallationItem -Path $root -Kind Directory)
        return $root
    }

function Get-ServiceManagerPath {
        param(
            [Parameter(Mandatory)]
            [string]$InstallRoot
        )

        if ($IsWindows) {
            $fallback = Join-Path $PSScriptRoot 'WindowsUserService.ps1'
            if (Test-Path -LiteralPath $fallback -PathType Leaf) {
                return $fallback
            }
            $manager = Join-Path $InstallRoot 'share' 'konclave' 'service' 'windows' `
                'manage-user-service.ps1'
            if (Test-Path -LiteralPath $manager -PathType Leaf) {
                return $manager
            }
            throw 'Windows user-service manager is unavailable.'
        }
        if ($IsMacOS) {
            return Join-Path $InstallRoot 'share' 'konclave' 'service' 'launchd' `
                'manage-agent.sh'
        }
        return Join-Path $InstallRoot 'share' 'konclave' 'service' 'systemd' `
            'manage-user-service.sh'
    }

function Invoke-ServiceManager {
        param(
            [Parameter(Mandatory)]
            [ValidateSet('Install', 'Start', 'Stop', 'Status', 'Uninstall')]
            [string]$Action,

            [Parameter(Mandatory)]
            [string]$InstallRoot,

            [Parameter(Mandatory)]
            [string]$ConfigPath
        )

        $manager = Get-ServiceManagerPath -InstallRoot $InstallRoot
        [void](Assert-SafeInstallationItem -Path $manager -Kind File)
        if ($IsWindows) {
            $output = & $manager `
                -Action $Action `
                -InstallRoot $InstallRoot `
                -ConfigPath $ConfigPath 2>&1
            return @($output)
        }
        $output = & bash `
            $manager `
            $Action.ToLowerInvariant() `
            $InstallRoot `
            $ConfigPath 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Service manager $Action failed: $($output -join "`n")"
        }
        return @($output)
    }

function Invoke-InstalledCli {
        param(
            [Parameter(Mandatory)]
            [string]$InstallRoot,

            [Parameter(Mandatory)]
            [string[]]$Arguments
        )

        $suffix = if ($IsWindows) { '.exe' } else { '' }
        $cli = Join-Path $InstallRoot 'bin' "konclave$suffix"
        [void](Assert-SafeInstallationItem -Path $cli -Kind File)
        $output = & $cli @Arguments 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Konclave CLI failed: $($output -join "`n")"
        }
        return @($output)
    }

function Get-RelayMigrationArguments {
        param(
            [Parameter(Mandatory)]
            [string]$ConfigPath,

            [Parameter(Mandatory)]
            [string]$RelayEndpoint,

            [switch]$Abort,

            [switch]$Finalize
        )

        if ($Abort -and $Finalize) {
            throw 'Relay migration cannot abort and finalize together.'
        }
        $arguments = @(
            '--config',
            $ConfigPath,
            '--relay-endpoint',
            $RelayEndpoint
        )
        if ($Abort) {
            $arguments += '--abort'
        }
        elseif ($Finalize) {
            $arguments += '--finalize'
        }
        return $arguments
    }

function Invoke-InstalledRelayMigration {
        param(
            [Parameter(Mandatory)]
            [string]$InstallRoot,

            [Parameter(Mandatory)]
            [string]$ConfigPath,

            [Parameter(Mandatory)]
            [string]$RelayEndpoint,

            [switch]$Abort,

            [switch]$Finalize
        )

        $suffix = if ($IsWindows) { '.exe' } else { '' }
        $migration = Join-Path $InstallRoot 'bin' "KonclaveRelayMigration$suffix"
        [void](Assert-SafeInstallationItem -Path $migration -Kind File)
        $arguments = Get-RelayMigrationArguments `
            -ConfigPath $ConfigPath `
            -RelayEndpoint $RelayEndpoint `
            -Abort:$Abort `
            -Finalize:$Finalize
        $output = & $migration @arguments 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Konclave relay migration failed: $($output -join "`n")"
        }
        try {
            return ($output -join "`n") | ConvertFrom-Json -Depth 20
        }
        catch {
            throw 'Konclave relay migration returned malformed output.'
        }
    }

function Invoke-TransactionalRelayMigration {
        param(
            [Parameter(Mandatory)]
            [string]$InstallRoot,

            [Parameter(Mandatory)]
            $Paths,

            [Parameter(Mandatory)]
            [string]$RelayEndpoint,

            [scriptblock]$MigrationInvoker,

            [scriptblock]$ServiceInvoker,

            [scriptblock]$HealthVerifier
        )

        if ($null -eq $MigrationInvoker) {
            $MigrationInvoker = {
                param($Mode)
                $arguments = @{
                    InstallRoot = $InstallRoot
                    ConfigPath = $Paths.serviceConfigPath
                    RelayEndpoint = $RelayEndpoint
                }
                if ($Mode -ceq 'Abort') {
                    $arguments.Abort = $true
                }
                elseif ($Mode -ceq 'Finalize') {
                    $arguments.Finalize = $true
                }
                Invoke-InstalledRelayMigration @arguments
            }.GetNewClosure()
        }
        if ($null -eq $ServiceInvoker) {
            $ServiceInvoker = {
                param($Action)
                Invoke-ServiceManager `
                    -Action $Action `
                    -InstallRoot $InstallRoot `
                    -ConfigPath $Paths.serviceConfigPath
            }.GetNewClosure()
        }
        if ($null -eq $HealthVerifier) {
            $HealthVerifier = {
                Wait-InstalledRuntimeHealth -InstallRoot $InstallRoot -Paths $Paths
            }.GetNewClosure()
        }

        [void](& $ServiceInvoker 'Stop')
        try {
            $migration = & $MigrationInvoker 'Apply'
        }
        catch {
            $migrationError = $_
            try {
                [void](& $MigrationInvoker 'Abort')
                [void](& $ServiceInvoker 'Start')
                [void](& $HealthVerifier)
            }
            catch {
                throw "Relay migration failed and source recovery did not complete: $(
                    $migrationError.Exception.Message
                )`nRecovery: $($_.Exception.Message)"
            }
            throw $migrationError
        }
        try {
            [void](& $ServiceInvoker 'Start')
            [void](& $HealthVerifier)
            return & $MigrationInvoker 'Finalize'
        }
        catch {
            $healthError = $_
            try {
                [void](& $ServiceInvoker 'Stop')
                [void](& $MigrationInvoker 'Abort')
                [void](& $ServiceInvoker 'Start')
                [void](& $HealthVerifier)
            }
            catch {
                throw "Migrated relay did not become healthy and rollback failed: $(
                    $healthError.Exception.Message
                )`nRollback: $($_.Exception.Message)"
            }
            throw $healthError
        }
    }

function Initialize-InstalledRuntime {
        param(
            [Parameter(Mandatory)]
            [string]$InstallRoot,

            [Parameter(Mandatory)]
            $Paths,

            [Parameter(Mandatory)]
            [string]$RelayEndpoint,

            [ValidateSet('account-trusted', 'user-presence')]
            [string]$AuthorizationPolicy,

            [string]$ExternalSource,

            [string]$ServiceIdentityFile,

            [string]$ProfileKeyDirectory,

            [string]$LegacyExtensionRoot,

            [switch]$AllowNoRecovery
        )

        $arguments = [Collections.Generic.List[string]]::new()
        foreach ($value in @(
            'init',
            '--relay-endpoint',
            $RelayEndpoint,
            '--profile-root',
            [string]$Paths.profileRoot
        )) {
            $arguments.Add($value)
        }
        foreach ($option in @(
            @{ Name = '--authorization-policy'; Value = $AuthorizationPolicy },
            @{ Name = '--external-source'; Value = $ExternalSource },
            @{ Name = '--local-service-identity-file'; Value = $ServiceIdentityFile },
            @{ Name = '--local-service-profile-key-directory'; Value = $ProfileKeyDirectory },
            @{ Name = '--copilot-extension-root'; Value = $LegacyExtensionRoot }
        )) {
            if (-not [string]::IsNullOrWhiteSpace([string]$option.Value)) {
                if (
                    $option.Name -ne '--authorization-policy' -and
                    -not [IO.Path]::IsPathRooted([string]$option.Value)
                ) {
                    throw "$($option.Name) must be absolute."
                }
                $arguments.Add([string]$option.Name)
                $arguments.Add([string]$option.Value)
            }
        }
        if ($AllowNoRecovery) {
            $arguments.Add('--allow-no-recovery')
        }
        return Invoke-InstalledCli -InstallRoot $InstallRoot -Arguments $arguments
    }

function Wait-InstalledRuntimeHealth {
        param(
            [Parameter(Mandatory)]
            [string]$InstallRoot,

            [Parameter(Mandatory)]
            $Paths,

            [ValidateRange(1, 60)]
            [int]$Attempts = 15,

            [ValidateRange(0, 30)]
            [int]$DelaySeconds = 2
        )

        $lastOutput = @()
        for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
            try {
                $lastOutput = Invoke-InstalledCli `
                    -InstallRoot $InstallRoot `
                    -Arguments @(
                        'doctor',
                        '--profile-root',
                        [string]$Paths.profileRoot,
                        '--install-root',
                        $InstallRoot
                    )
                return $lastOutput
            }
            catch {
                $lastOutput = @($_.Exception.Message)
                if ($attempt -lt $Attempts -and $DelaySeconds -gt 0) {
                    Start-Sleep -Seconds $DelaySeconds
                }
            }
        }
        throw "Installed runtime did not become healthy: $($lastOutput -join "`n")"
    }

function Resolve-LegacyCopilotExtensionRoot {
        $copilotHome = $env:COPILOT_HOME
        if ([string]::IsNullOrWhiteSpace($copilotHome)) {
            $userProfile = [Environment]::GetFolderPath(
                [Environment+SpecialFolder]::UserProfile
            )
            if ([string]::IsNullOrWhiteSpace($userProfile)) {
                throw 'User profile directory is unavailable.'
            }
            $copilotHome = Join-Path $userProfile '.copilot'
        }
        elseif (-not [IO.Path]::IsPathRooted($copilotHome)) {
            throw 'COPILOT_HOME must be absolute.'
        }
        return Join-Path ([IO.Path]::GetFullPath($copilotHome)) 'extensions' 'konclave'
    }

    function Read-DirectPluginMarker {
        param(
            [Parameter(Mandatory)]
            [string]$Path
        )

        if (-not (Test-Path -LiteralPath $Path)) {
            return $null
        }
        $file = Assert-SafeInstallationItem -Path $Path -Kind File
        if ($file.Length -le 0 -or $file.Length -gt 4KB) {
            throw 'Direct Agent Plugin marker is empty or oversized.'
        }
        $marker = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 |
            ConvertFrom-Json -Depth 10
        $fields = [string[]]@($marker.PSObject.Properties.Name)
        $expected = [string[]]@('schemaVersion', 'mode', 'name', 'version')
        if (
            @(Compare-Object $fields $expected -CaseSensitive).Count -gt 0 -or
            [int]$marker.schemaVersion -ne 1 -or
            [string]$marker.mode -cne 'direct' -or
            [string]$marker.name -cne 'konclave' -or
            [string]$marker.version -cnotmatch '^[0-9]+\.[0-9]+\.[0-9]+$'
        ) {
            throw 'Direct Agent Plugin marker is invalid.'
        }
        return $marker
    }

    function Move-LegacyCopilotExtension {
        param(
            [Parameter(Mandatory)]
            [string]$Source,

            [Parameter(Mandatory)]
            [string]$LegacyRoot
        )

        [void](Assert-SafeInstallationItem -Path $Source -Kind Directory)
        $destination = Join-Path $LegacyRoot 'copilot-extension'
        if (Test-Path -LiteralPath $destination) {
            throw 'Legacy Copilot extension backup already exists.'
        }
        $staging = Join-Path $LegacyRoot ".copilot-extension-$(
            [Guid]::NewGuid().ToString('N')
        )"
        [void](Set-OwnerOnlyDirectory -Path $staging)
        try {
            $sourceRoot = [IO.Path]::GetFullPath($Source)
            $items = @(Get-ChildItem -LiteralPath $sourceRoot -Recurse -Force)
            if ($items.Count -gt $script:MaximumLegacyEntries) {
                throw 'Legacy Copilot extension contains too many entries.'
            }
            [int64]$totalBytes = 0
            foreach ($item in $items) {
                if (
                    $item.Attributes -band [IO.FileAttributes]::ReparsePoint -or
                    $item.LinkType -in @('SymbolicLink', 'Junction')
                ) {
                    throw "Legacy Copilot extension contains a link: $($item.FullName)"
                }
                $relative = [IO.Path]::GetRelativePath($sourceRoot, $item.FullName)
                $target = Join-Path $staging $relative
                if ($item.PSIsContainer) {
                    [void](Set-OwnerOnlyDirectory -Path $target)
                }
                else {
                    if ($item.Length -gt $script:MaximumLegacyFileBytes) {
                        throw "Legacy Copilot extension file is oversized: $relative"
                    }
                    $totalBytes += [int64]$item.Length
                    if ($totalBytes -gt $script:MaximumLegacyBytes) {
                        throw 'Legacy Copilot extension exceeds its total size bound.'
                    }
                    [void](Set-OwnerOnlyDirectory -Path (Split-Path -Parent $target))
                    Copy-Item -LiteralPath $item.FullName -Destination $target
                    Set-OwnerOnlyFile -Path $target
                    if (
                        (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash -cne
                        (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
                    ) {
                        throw "Legacy Copilot extension backup mismatch: $relative"
                    }
                }
            }
            [IO.Directory]::Move($staging, $destination)
            Remove-Item -LiteralPath $sourceRoot -Recurse -Force
        }
        finally {
            if (Test-Path -LiteralPath $staging) {
                Remove-Item -LiteralPath $staging -Recurse -Force
            }
        }
        return $destination
    }

function Enable-InstallerAgentPlugin {
        param(
            [Parameter(Mandatory)]
            [string]$InstallRoot,

            [Parameter(Mandatory)]
            $Paths,

            [Parameter(Mandatory)]
            [string]$Version,

            [switch]$EnableDirectAgentPlugin
        )

        $pluginRoot = Join-Path $InstallRoot 'share' 'konclave' 'plugin'
        [void](Assert-SafeInstallationItem -Path $pluginRoot -Kind Directory)
        if (-not $EnableDirectAgentPlugin) {
            return [pscustomobject][ordered]@{
                status = 'Ready'
                pluginRoot = $pluginRoot
                restartRequired = $false
            }
        }
        if ($null -eq (Get-Command copilot -ErrorAction SilentlyContinue)) {
            throw 'Copilot CLI is required for direct Agent Plugin activation.'
        }
        [void](Read-DirectPluginMarker -Path $Paths.directPluginPath)
        $output = & copilot plugin install $pluginRoot 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Direct Agent Plugin activation failed: $($output -join "`n")"
        }
        $marker = [pscustomobject][ordered]@{
            schemaVersion = 1
            mode = 'direct'
            name = 'konclave'
            version = $Version
        }
        $markerJson = ($marker | ConvertTo-Json -Compress) + "`n"
        Write-OwnerOnlyTextFile `
            -Path $Paths.directPluginPath `
            -Content $markerJson `
            -MaximumBytes 4KB

        $legacy = Resolve-LegacyCopilotExtensionRoot
        $restartRequired = $false
        if (Test-Path -LiteralPath $legacy) {
            [void](Move-LegacyCopilotExtension `
                -Source $legacy `
                -LegacyRoot $Paths.legacyRoot)
            $restartRequired = $true
        }
        return [pscustomobject][ordered]@{
            status = 'InstalledDirect'
            pluginRoot = $pluginRoot
            restartRequired = $restartRequired
        }
    }

    function Disable-InstallerAgentPlugin {
        param(
            [Parameter(Mandatory)]
            $Paths
        )

        if (-not (Test-Path -LiteralPath $Paths.directPluginPath)) {
            return $false
        }
        [void](Read-DirectPluginMarker -Path $Paths.directPluginPath)
        if ($null -eq (Get-Command copilot -ErrorAction SilentlyContinue)) {
            throw 'Copilot CLI is required to remove the installer-owned direct plugin.'
        }
        $output = & copilot plugin uninstall konclave 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Direct Agent Plugin removal failed: $($output -join "`n")"
        }
        Remove-Item -LiteralPath $Paths.directPluginPath -Force
        return $true
    }

    function Prepare-InstallerMarketplace {
        param(
            [Parameter(Mandatory)]
            $Paths,

            [scriptblock]$DirectPluginDisabler,

            [scriptblock]$LegacyRootResolver,

            [scriptblock]$LegacyMover
        )

        if ($null -eq $DirectPluginDisabler) {
            $DirectPluginDisabler = {
                param($InstallationPaths)
                Disable-InstallerAgentPlugin -Paths $InstallationPaths
            }
        }
        if ($null -eq $LegacyRootResolver) {
            $LegacyRootResolver = {
                Resolve-LegacyCopilotExtensionRoot
            }
        }
        if ($null -eq $LegacyMover) {
            $LegacyMover = {
                param($Source, $LegacyRoot)
                Move-LegacyCopilotExtension -Source $Source -LegacyRoot $LegacyRoot
            }
        }

        $directRemoved = [bool](& $DirectPluginDisabler $Paths)
        $legacyRoot = [string](& $LegacyRootResolver)
        $legacyPreserved = $false
        if (Test-Path -LiteralPath $legacyRoot) {
            [void](& $LegacyMover $legacyRoot $Paths.legacyRoot)
            $legacyPreserved = $true
        }
        return [pscustomobject][ordered]@{
            status = if ($directRemoved -and $legacyPreserved) {
                'RemovedDirectAndPreservedLegacy'
            }
            elseif ($directRemoved) {
                'RemovedDirect'
            }
            elseif ($legacyPreserved) {
                'PreservedLegacy'
            }
            else {
                'ReadyMarketplace'
            }
            pluginRoot = $null
            restartRequired = $directRemoved -or $legacyPreserved
        }
    }

    function Invoke-InstallationInitialization {
        param(
            [Parameter(Mandatory)]
            [string]$InstallRoot,

            [Parameter(Mandatory)]
            $Paths,

            [Parameter(Mandatory)]
            [string]$RelayEndpoint,

            [AllowNull()]
            [string]$AuthorizationPolicy,

            [AllowNull()]
            [string]$ExternalSource,

            [AllowNull()]
            [string]$ServiceIdentityFile,

            [AllowNull()]
            [string]$ProfileKeyDirectory,

            [Parameter(Mandatory)]
            [bool]$AllowNoRecovery,

            [Parameter(Mandatory)]
            [bool]$CandidateCreated,

            [Parameter(Mandatory)]
            [string]$CandidateVersion,

            [scriptblock]$LegacyRootResolver,

            [scriptblock]$RuntimeInitializer,

            [scriptblock]$CandidateRemover
        )

        if ($null -eq $LegacyRootResolver) {
            $LegacyRootResolver = {
                Resolve-LegacyCopilotExtensionRoot
            }
        }
        if ($null -eq $RuntimeInitializer) {
            $RuntimeInitializer = {
                param(
                    $Root,
                    $InstallationPaths,
                    $Endpoint,
                    $Policy,
                    $EnrollmentSource,
                    $IdentityFile,
                    $KeyDirectory,
                    $LegacyRoot,
                    $PermitNoRecovery
                )
                [void](Initialize-InstalledRuntime `
                    -InstallRoot $Root `
                    -Paths $InstallationPaths `
                    -RelayEndpoint $Endpoint `
                    -AuthorizationPolicy $Policy `
                    -ExternalSource $EnrollmentSource `
                    -ServiceIdentityFile $IdentityFile `
                    -ProfileKeyDirectory $KeyDirectory `
                    -LegacyExtensionRoot $LegacyRoot `
                    -AllowNoRecovery:$PermitNoRecovery)
            }
        }
        if ($null -eq $CandidateRemover) {
            $CandidateRemover = {
                param($InstallationPaths, $Version)
                $versionRoot = Join-Path $InstallationPaths.versionsRoot $Version
                if (Test-Path -LiteralPath $versionRoot) {
                    Remove-InstallerDirectory -Path $versionRoot
                }
            }
        }

        try {
            $legacyRoot = & $LegacyRootResolver
            if (-not (Test-Path -LiteralPath $legacyRoot -PathType Container)) {
                $legacyRoot = $null
            }
            & $RuntimeInitializer `
                $InstallRoot `
                $Paths `
                $RelayEndpoint `
                $AuthorizationPolicy `
                $ExternalSource `
                $ServiceIdentityFile `
                $ProfileKeyDirectory `
                $legacyRoot `
                $AllowNoRecovery
        }
        catch {
            $operationError = $_
            if ($CandidateCreated) {
                try {
                    & $CandidateRemover $Paths $CandidateVersion
                }
                catch {
                    throw "Runtime initialization failed and candidate cleanup failed: $(
                        $operationError.Exception.Message
                    )`nCleanup: $($_.Exception.Message)"
                }
            }
            throw $operationError
        }
    }

    function Invoke-TransactionalRuntimeSwitch {
        param(
            [Parameter(Mandatory)]
            $Paths,

            [Parameter(Mandatory)]
            $State,

            [Parameter(Mandatory)]
            $Decision,

            [Parameter(Mandatory)]
            $CandidateRecord,

            [Parameter(Mandatory)]
            [string]$CandidateRoot,

            [Parameter(Mandatory)]
            [bool]$CandidateCreated,

            [scriptblock]$ManagerInvoker,

            [scriptblock]$HealthInvoker,

            [scriptblock]$StateWriter,

            [scriptblock]$CandidateRemover
        )

        if ($null -eq $ManagerInvoker) {
            $ManagerInvoker = {
                param($ManagerAction, $Root, $Configuration)
                [void](Invoke-ServiceManager `
                    -Action $ManagerAction `
                    -InstallRoot $Root `
                    -ConfigPath $Configuration)
            }
        }
        if ($null -eq $HealthInvoker) {
            $HealthInvoker = {
                param($Root, $InstallationPaths)
                [void](Wait-InstalledRuntimeHealth `
                    -InstallRoot $Root `
                    -Paths $InstallationPaths)
            }
        }
        if ($null -eq $StateWriter) {
            $StateWriter = {
                param($StatePath, $NextState)
                Write-InstallationState -Path $StatePath -State $NextState
            }
        }
        if ($null -eq $CandidateRemover) {
            $CandidateRemover = {
                param($InstallationPaths, $Version)
                $versionRoot = Join-Path $InstallationPaths.versionsRoot $Version
                if (Test-Path -LiteralPath $versionRoot) {
                    Remove-InstallerDirectory -Path $versionRoot
                }
            }
        }

        $previousRecord = if ([string]::IsNullOrEmpty([string]$State.activeVersion)) {
            $null
        }
        else {
            Find-InstalledVersion -State $State -Version ([string]$State.activeVersion)
        }
        $previousRoot = if ($null -eq $previousRecord) {
            $null
        }
        else {
            Get-InstalledVersionRoot -Paths $Paths -Record $previousRecord
        }
        $candidateManagerInstalled = $false
        try {
            if ($null -ne $previousRoot) {
                & $ManagerInvoker 'Uninstall' $previousRoot $Paths.serviceConfigPath
            }
            & $ManagerInvoker 'Install' $CandidateRoot $Paths.serviceConfigPath
            $candidateManagerInstalled = $true
            & $HealthInvoker $CandidateRoot $Paths
            $nextState = Complete-InstallationLifecycle `
                -State $State `
                -Decision $Decision `
                -Candidate $CandidateRecord
            & $StateWriter $Paths.statePath $nextState
            return $nextState
        }
        catch {
            $operationError = $_
            try {
                if ($candidateManagerInstalled) {
                    & $ManagerInvoker 'Uninstall' $CandidateRoot $Paths.serviceConfigPath
                }
                if ($null -ne $previousRoot) {
                    & $ManagerInvoker 'Install' $previousRoot $Paths.serviceConfigPath
                    & $HealthInvoker $previousRoot $Paths
                }
                if ($CandidateCreated) {
                    & $CandidateRemover $Paths ([string]$CandidateRecord.version)
                }
            }
            catch {
                throw "Runtime switch failed and recovery failed: $(
                    $operationError.Exception.Message
                )`nRecovery: $($_.Exception.Message)"
            }
            throw $operationError
        }
    }

    function Remove-InstallerDirectory {
        param(
            [Parameter(Mandatory)]
            [string]$Path
        )

        if (-not (Test-Path -LiteralPath $Path)) {
            return
        }
        [void](Assert-SafeInstallationItem -Path $Path -Kind Directory)
        for ($attempt = 0; $attempt -lt 50; $attempt++) {
            try {
                Remove-Item -LiteralPath $Path -Recurse -Force
                return
            }
            catch {
                if ($attempt -eq 49) {
                    throw
                }
                Start-Sleep -Milliseconds 100
            }
        }
    }

    function Install-NewReleaseCandidateFiles {
    param(
        [Parameter(Mandatory)]
        $Paths,

        [Parameter(Mandatory)]
        $Candidate
    )

    $record = $Candidate.record
    $versionRoot = Join-Path $Paths.versionsRoot ([string]$record.version)
    $installedRoot = Join-Path $versionRoot ([string]$record.rootDirectory)
    $staging = Join-Path $Paths.stagingRoot ([Guid]::NewGuid().ToString('N'))
    [void](Set-OwnerOnlyDirectory -Path $staging)
    try {
        switch ([string]$Candidate.artifact.archiveFormat) {
            'zip' {
                Expand-ProtectedZipRelease `
                    -ArchivePath $Candidate.archivePath `
                    -DestinationRoot $staging
            }
            'tar.gz' {
                Expand-ProtectedTarGzipRelease `
                    -ArchivePath $Candidate.archivePath `
                    -DestinationRoot $staging
            }
            default {
                throw "Unsupported client archive format: $($Candidate.artifact.archiveFormat)"
            }
        }
        $entries = @(Get-ChildItem -LiteralPath $staging)
        $stagedRoot = Join-Path $staging ([string]$record.rootDirectory)
        if (
            $entries.Count -ne 1 -or
            -not (Test-Path -LiteralPath $stagedRoot -PathType Container)
        ) {
            throw 'Client archive does not contain its one declared root directory.'
        }
        [IO.Directory]::Move($staging, $versionRoot)
        return [pscustomobject]@{
            root = $installedRoot
            created = $true
        }
    }
    finally {
        if (Test-Path -LiteralPath $staging) {
            Remove-Item -LiteralPath $staging -Recurse -Force
        }
    }
}
