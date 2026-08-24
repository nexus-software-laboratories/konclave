#Requires -Version 7.4

Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot '..' 'CargoLock.Functions.ps1')

$script:ReleaseTimestamp = [DateTimeOffset]::Parse(
    '2000-01-01T00:00:00Z',
    [Globalization.CultureInfo]::InvariantCulture
)
$script:MaximumPluginEntries = 128
$script:MaximumPluginEntryBytes = 16MB
$script:MaximumPluginBytes = 32MB

function Resolve-ReleasePath {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$BasePath
    )

    if ([IO.Path]::IsPathRooted($Path)) {
        return [IO.Path]::GetFullPath($Path)
    }
    return [IO.Path]::GetFullPath((Join-Path $BasePath $Path))
}

function Read-ReleaseArtifactContract {
    param(
        [Parameter(Mandatory)]
        [string]$ProjectRoot
    )

    $manifestPath = Join-Path $ProjectRoot 'distribution' 'release-artifacts.json'
    $schemaPath = Join-Path $ProjectRoot 'distribution' 'release-artifacts.schema.json'
    foreach ($path in @($manifestPath, $schemaPath)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Release contract file is missing: $path"
        }
    }
    $json = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8
    if (-not ($json | Test-Json -SchemaFile $schemaPath)) {
        throw 'Release artifact manifest does not satisfy its schema.'
    }
    $manifest = $json | ConvertFrom-Json -Depth 100
    foreach ($property in @('id', 'fileName')) {
        $duplicates = @(
            $manifest.artifacts |
                Group-Object -Property $property |
                Where-Object Count -ne 1
        )
        if ($duplicates.Count -gt 0) {
            throw "Release artifact manifest contains a duplicate $property."
        }
    }
    return $manifest
}

function Get-ReleaseArtifact {
    param(
        [Parameter(Mandatory)]
        $Manifest,

        [Parameter(Mandatory)]
        [string]$Target,

        [Parameter(Mandatory)]
        [string]$Kind
    )

    $matches = @(
        $Manifest.artifacts |
            Where-Object {
                [string]$_.target -ceq $Target -and
                [string]$_.kind -ceq $Kind
            }
    )
    if ($matches.Count -ne 1) {
        throw "Release manifest must contain exactly one $Kind artifact for $Target."
    }
    return $matches[0]
}

function Assert-ReleaseSourceVersions {
    param(
        [Parameter(Mandatory)]
        [string]$ProjectRoot,

        [Parameter(Mandatory)]
        [string]$ExpectedVersion
    )

    $versions = Get-CargoLockedPackageVersions (
        Join-Path $ProjectRoot 'Cargo.lock'
    )
    foreach ($name in @(
        'KonclaveCommandLine',
        'KonclaveLocalDaemon',
        'KonclaveCommunityRelay'
    )) {
        if ([string]$versions[$name] -cne $ExpectedVersion) {
            throw "Release version mismatch for $name."
        }
    }

    $pluginRoot = Join-Path $ProjectRoot 'extensions' 'Konclave.HostExtension'
    foreach ($fileName in @('package.json', 'plugin.json')) {
        $path = Join-Path $pluginRoot $fileName
        $document = Get-Content -LiteralPath $path -Raw -Encoding UTF8 |
            ConvertFrom-Json -Depth 100
        if ([string]$document.version -cne $ExpectedVersion) {
            throw "Release version mismatch for $fileName."
        }
    }
}

function Copy-ReleaseFile {
    param(
        [Parameter(Mandatory)]
        [string]$Source,

        [Parameter(Mandatory)]
        [string]$Destination
    )

    $item = Get-Item -LiteralPath $Source -ErrorAction Stop
    if ($item.LinkType -in @('SymbolicLink', 'Junction')) {
        throw "Release input must not be a symbolic link: $Source"
    }
    if ($item.PSIsContainer) {
        throw "Release input must be a regular file: $Source"
    }
    $parent = Split-Path -Parent $Destination
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    Copy-Item -LiteralPath $Source -Destination $Destination
    [IO.File]::SetLastWriteTimeUtc($Destination, $script:ReleaseTimestamp.UtcDateTime)
}

function Write-ReleaseJson {
    param(
        [Parameter(Mandatory)]
        $Value,

        [Parameter(Mandatory)]
        [string]$Path
    )

    $json = ($Value | ConvertTo-Json -Depth 100).Replace("`r`n", "`n") + "`n"
    [IO.File]::WriteAllText(
        $Path,
        $json,
        [Text.UTF8Encoding]::new($false)
    )
    [IO.File]::SetLastWriteTimeUtc($Path, $script:ReleaseTimestamp.UtcDateTime)
}

function Expand-ProtectedPluginArchive {
    param(
        [Parameter(Mandatory)]
        [string]$ArchivePath,

        [Parameter(Mandatory)]
        [string]$Destination
    )

    Add-Type -AssemblyName System.IO.Compression
    $destinationRoot = [IO.Path]::GetFullPath($Destination).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
    $destinationPrefix = $destinationRoot + [IO.Path]::DirectorySeparatorChar
    New-Item -ItemType Directory -Path $destinationRoot -Force | Out-Null
    $archive = [IO.Compression.ZipFile]::OpenRead($ArchivePath)
    try {
        if ($archive.Entries.Count -gt $script:MaximumPluginEntries) {
            throw 'Plugin archive contains too many entries.'
        }
        $totalBytes = 0L
        foreach ($entry in $archive.Entries) {
            $name = [string]$entry.FullName
            if (
                [string]::IsNullOrWhiteSpace($name) -or
                $name.Contains('\') -or
                $name.StartsWith('/', [StringComparison]::Ordinal)
            ) {
                throw 'Plugin archive contains an unsafe entry name.'
            }
            $segments = @($name.Split('/'))
            if ($segments | Where-Object { $_ -in @('', '.', '..') }) {
                throw 'Plugin archive contains an unsafe path segment.'
            }
            if ($entry.Length -gt $script:MaximumPluginEntryBytes) {
                throw 'Plugin archive entry exceeds its size bound.'
            }
            $totalBytes += [long]$entry.Length
            if ($totalBytes -gt $script:MaximumPluginBytes) {
                throw 'Plugin archive exceeds its total size bound.'
            }
            $destinationPath = [IO.Path]::GetFullPath(
                (Join-Path $destinationRoot ($name.Replace('/', [IO.Path]::DirectorySeparatorChar)))
            )
            if (
                -not $destinationPath.StartsWith(
                    $destinationPrefix,
                    [StringComparison]::OrdinalIgnoreCase
                )
            ) {
                throw 'Plugin archive entry resolves outside its destination.'
            }
            if ($name.EndsWith('/', [StringComparison]::Ordinal)) {
                New-Item -ItemType Directory -Path $destinationPath -Force | Out-Null
                continue
            }
            New-Item -ItemType Directory -Path (Split-Path -Parent $destinationPath) -Force |
                Out-Null
            $input = $entry.Open()
            $output = [IO.File]::Open(
                $destinationPath,
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
            [IO.File]::SetLastWriteTimeUtc(
                $destinationPath,
                $script:ReleaseTimestamp.UtcDateTime
            )
        }
    }
    finally {
        $archive.Dispose()
    }
}

function Assert-PackagedPlugin {
    param(
        [Parameter(Mandatory)]
        [string]$PluginRoot,

        [Parameter(Mandatory)]
        [string]$ExpectedVersion
    )

    $manifestPath = Join-Path $PluginRoot 'plugin.json'
    $extensionPath = Join-Path $PluginRoot 'extensions' 'Konclave.Extension' 'extension.mjs'
    foreach ($path in @($manifestPath, $extensionPath)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Packaged plugin file is missing: $path"
        }
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 |
        ConvertFrom-Json -Depth 100
    if (
        [string]$manifest.name -cne 'konclave' -or
        [string]$manifest.version -cne $ExpectedVersion
    ) {
        throw 'Packaged plugin identity does not match the release.'
    }
}

function Get-OrderedArchivePaths {
    param(
        [Parameter(Mandatory)]
        [string]$StagingRoot
    )

    $paths = [string[]]@(
        Get-ChildItem -LiteralPath $StagingRoot -Recurse -File |
            ForEach-Object {
                [IO.Path]::GetRelativePath($StagingRoot, $_.FullName).Replace('\', '/')
            }
    )
    [Array]::Sort($paths, [StringComparer]::Ordinal)
    return $paths
}

function Test-ArchiveExecutablePath {
    param(
        [Parameter(Mandatory)]
        [string]$RelativePath
    )

    return $RelativePath.Contains('/bin/', [StringComparison]::Ordinal)
}

function New-DeterministicZip {
    param(
        [Parameter(Mandatory)]
        [string]$StagingRoot,

        [Parameter(Mandatory)]
        [string]$ArchivePath
    )

    Add-Type -AssemblyName System.IO.Compression
    $output = [IO.File]::Open(
        $ArchivePath,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    $archive = [IO.Compression.ZipArchive]::new(
        $output,
        [IO.Compression.ZipArchiveMode]::Create,
        $true
    )
    try {
        foreach ($relativePath in Get-OrderedArchivePaths $StagingRoot) {
            $entry = $archive.CreateEntry(
                $relativePath,
                [IO.Compression.CompressionLevel]::Optimal
            )
            $entry.LastWriteTime = $script:ReleaseTimestamp
            $input = [IO.File]::OpenRead(
                (Join-Path $StagingRoot ($relativePath.Replace('/', [IO.Path]::DirectorySeparatorChar)))
            )
            $entryStream = $entry.Open()
            try {
                $input.CopyTo($entryStream)
            }
            finally {
                $entryStream.Dispose()
                $input.Dispose()
            }
        }
    }
    finally {
        $archive.Dispose()
        $output.Dispose()
    }
}

function New-DeterministicTarGzip {
    param(
        [Parameter(Mandatory)]
        [string]$StagingRoot,

        [Parameter(Mandatory)]
        [string]$ArchivePath
    )

    $output = [IO.File]::Open(
        $ArchivePath,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    $gzip = [IO.Compression.GZipStream]::new(
        $output,
        [IO.Compression.CompressionLevel]::Optimal,
        $true
    )
    $writer = [System.Formats.Tar.TarWriter]::new(
        $gzip,
        [System.Formats.Tar.TarEntryFormat]::Pax,
        $true
    )
    try {
        foreach ($relativePath in Get-OrderedArchivePaths $StagingRoot) {
            $entry = [System.Formats.Tar.PaxTarEntry]::new(
                [System.Formats.Tar.TarEntryType]::RegularFile,
                $relativePath
            )
            $entry.ModificationTime = $script:ReleaseTimestamp
            $entry.Uid = 0
            $entry.Gid = 0
            $entry.UserName = 'root'
            $entry.GroupName = 'root'
            $entry.Mode = if (Test-ArchiveExecutablePath $relativePath) {
                [IO.UnixFileMode]493
            }
            else {
                [IO.UnixFileMode]420
            }
            $input = [IO.File]::OpenRead(
                (Join-Path $StagingRoot ($relativePath.Replace('/', [IO.Path]::DirectorySeparatorChar)))
            )
            try {
                $entry.DataStream = $input
                $writer.WriteEntry($entry)
            }
            finally {
                $input.Dispose()
            }
        }
    }
    finally {
        $writer.Dispose()
        $gzip.Dispose()
        $output.Dispose()
    }
}

function Copy-ClientPayload {
    param(
        [Parameter(Mandatory)]
        [string]$ProjectRoot,

        [Parameter(Mandatory)]
        [string]$BinaryDirectory,

        [Parameter(Mandatory)]
        [string]$PluginArchivePath,

        [Parameter(Mandatory)]
        [string]$DestinationRoot,

        [Parameter(Mandatory)]
        $Artifact,

        [Parameter(Mandatory)]
        [string]$Version
    )

    $suffix = if ([string]$Artifact.operatingSystem -ceq 'windows') { '.exe' } else { '' }
    $cliSource = Join-Path $BinaryDirectory "KonclaveCommandLine$suffix"
    $daemonSource = Join-Path $BinaryDirectory "KonclaveLocalDaemon$suffix"
    Copy-ReleaseFile $cliSource (Join-Path $DestinationRoot 'bin' "konclave$suffix")
    Copy-ReleaseFile $daemonSource (
        Join-Path $DestinationRoot 'bin' "KonclaveLocalDaemon$suffix"
    )

    $pluginRoot = Join-Path $DestinationRoot 'share' 'konclave' 'plugin'
    Expand-ProtectedPluginArchive $PluginArchivePath $pluginRoot
    Assert-PackagedPlugin $pluginRoot $Version
    Copy-ReleaseFile $daemonSource (
        Join-Path $pluginRoot 'bin' "KonclaveLocalDaemon$suffix"
    )

    $serviceRoot = Join-Path $DestinationRoot 'share' 'konclave' 'service'
    switch ([string]$Artifact.operatingSystem) {
        'linux' {
            Copy-ReleaseFile (
                Join-Path $ProjectRoot 'apps' 'Konclave.LocalDaemon' 'packaging' 'systemd' `
                    'KonclaveLocalDaemon-daemon.service'
            ) (
                Join-Path $serviceRoot 'systemd' 'KonclaveLocalDaemon-daemon.service'
            )
        }
        'macos' {
            Copy-ReleaseFile (
                Join-Path $ProjectRoot 'apps' 'Konclave.LocalDaemon' 'packaging' 'launchd' `
                    'com.genesis.KonclaveLocalDaemon.plist'
            ) (
                Join-Path $serviceRoot 'launchd' 'com.genesis.KonclaveLocalDaemon.plist'
            )
        }
        'windows' {
            $serviceSource = Join-Path $BinaryDirectory 'windows_service.exe'
            Copy-ReleaseFile $serviceSource (
                Join-Path $DestinationRoot 'bin' 'KonclaveLocalDaemonService.exe'
            )
            Copy-ReleaseFile (
                Join-Path $ProjectRoot 'apps' 'Konclave.LocalDaemon' 'packaging' 'windows' `
                    'install-service.ps1'
            ) (
                Join-Path $serviceRoot 'windows' 'install-service.ps1'
            )
        }
        default {
            throw "Unsupported release operating system: $($Artifact.operatingSystem)"
        }
    }
}

function Copy-RelayPayload {
    param(
        [Parameter(Mandatory)]
        [string]$ProjectRoot,

        [Parameter(Mandatory)]
        [string]$BinaryDirectory,

        [Parameter(Mandatory)]
        [string]$DestinationRoot,

        [Parameter(Mandatory)]
        $Artifact
    )

    $suffix = if ([string]$Artifact.operatingSystem -ceq 'windows') { '.exe' } else { '' }
    Copy-ReleaseFile (
        Join-Path $BinaryDirectory "KonclaveCommunityRelay$suffix"
    ) (
        Join-Path $DestinationRoot 'bin' "KonclaveCommunityRelay$suffix"
    )
    $relayRoot = Join-Path $DestinationRoot 'share' 'konclave' 'relay'
    Copy-ReleaseFile (
        Join-Path $ProjectRoot 'apps' 'Konclave.CommunityRelay' 'compose.example.yaml'
    ) (
        Join-Path $relayRoot 'compose.example.yaml'
    )
    Copy-ReleaseFile (
        Join-Path $ProjectRoot 'apps' 'Konclave.CommunityRelay' 'docs' 'container' `
            'rust-service.md'
    ) (
        Join-Path $relayRoot 'container.md'
    )
}

function New-ReleasePackage {
    param(
        [Parameter(Mandatory)]
        [string]$ProjectRoot,

        [Parameter(Mandatory)]
        [string]$Target,

        [Parameter(Mandatory)]
        [ValidateSet('client', 'relay')]
        [string]$Kind,

        [Parameter(Mandatory)]
        [string]$BinaryDirectory,

        [string]$PluginArchivePath,

        [Parameter(Mandatory)]
        [string]$OutputDirectory
    )

    $projectRootPath = (Resolve-Path -LiteralPath $ProjectRoot).Path
    $binaryPath = (Resolve-Path -LiteralPath $BinaryDirectory).Path
    $outputPath = Resolve-ReleasePath $OutputDirectory $projectRootPath
    $manifest = Read-ReleaseArtifactContract $projectRootPath
    $version = [string]$manifest.release.version
    Assert-ReleaseSourceVersions $projectRootPath $version
    $artifact = Get-ReleaseArtifact $manifest $Target $Kind
    if (
        [string]$artifact.fileName -notmatch [regex]::Escape($version) -or
        [string]$artifact.rootDirectory -notmatch [regex]::Escape($version) -or
        -not ([string]$artifact.fileName).Contains($Target, [StringComparison]::Ordinal) -or
        -not ([string]$artifact.rootDirectory).Contains($Target, [StringComparison]::Ordinal) -or
        -not ([string]$artifact.fileName).StartsWith(
            "konclave-$Kind-",
            [StringComparison]::Ordinal
        ) -or
        -not ([string]$artifact.fileName).EndsWith(
            ".$([string]$artifact.archiveFormat)",
            [StringComparison]::Ordinal
        )
    ) {
        throw "Release artifact names do not match $Kind $version for $Target."
    }

    $stagingRoot = Join-Path (
        [IO.Path]::GetTempPath()
    ) "konclave-release-$([Guid]::NewGuid().ToString('N'))"
    $payloadRoot = Join-Path $stagingRoot ([string]$artifact.rootDirectory)
    New-Item -ItemType Directory -Path $payloadRoot -Force | Out-Null
    try {
        if ($Kind -ceq 'client') {
            if ([string]::IsNullOrWhiteSpace($PluginArchivePath)) {
                throw 'Client packaging requires a built plugin archive.'
            }
            $pluginPath = (Resolve-Path -LiteralPath $PluginArchivePath).Path
            Copy-ClientPayload `
                $projectRootPath `
                $binaryPath `
                $pluginPath `
                $payloadRoot `
                $artifact `
                $version
        }
        else {
            Copy-RelayPayload $projectRootPath $binaryPath $payloadRoot $artifact
        }

        Copy-ReleaseFile (
            Join-Path $projectRootPath 'distribution' 'UNSIGNED-PRERELEASE.txt'
        ) (
            Join-Path $payloadRoot 'UNSIGNED-PRERELEASE.txt'
        )
        Copy-ReleaseFile (
            Join-Path $projectRootPath 'docs' 'distribution' 'installation.md'
        ) (
            Join-Path $payloadRoot 'README.md'
        )
        Write-ReleaseJson $manifest (Join-Path $payloadRoot 'RELEASE.json')
        Write-ReleaseJson ([ordered]@{
            schemaVersion = 1
            id = [string]$artifact.id
            kind = [string]$artifact.kind
            version = $version
            target = [string]$artifact.target
            operatingSystem = [string]$artifact.operatingSystem
            architecture = [string]$artifact.architecture
            archiveFormat = [string]$artifact.archiveFormat
            signatureStatus = [string]$manifest.release.signatureStatus
        }) (Join-Path $payloadRoot 'ARTIFACT.json')

        New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
        $destination = Join-Path $outputPath ([string]$artifact.fileName)
        if (Test-Path -LiteralPath $destination) {
            throw "Release artifact already exists: $destination"
        }
        $temporary = Join-Path $outputPath (
            ".$([string]$artifact.fileName).$([Guid]::NewGuid().ToString('N')).tmp"
        )
        try {
            switch ([string]$artifact.archiveFormat) {
                'zip' {
                    New-DeterministicZip $stagingRoot $temporary
                }
                'tar.gz' {
                    New-DeterministicTarGzip $stagingRoot $temporary
                }
                default {
                    throw "Unsupported release archive format: $($artifact.archiveFormat)"
                }
            }
            [IO.File]::Move($temporary, $destination, $false)
        }
        finally {
            if (Test-Path -LiteralPath $temporary) {
                Remove-Item -LiteralPath $temporary -Force
            }
        }
        return $destination
    }
    finally {
        if (Test-Path -LiteralPath $stagingRoot) {
            Remove-Item -LiteralPath $stagingRoot -Recurse -Force
        }
    }
}
