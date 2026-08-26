#Requires -Version 7.4
<#
.SYNOPSIS
    Proves deterministic release packaging and validates extracted artifact layout.
#>
[CmdletBinding()]
param(
    [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path,

    [Parameter(Mandatory)]
    [ValidateSet(
        'x86_64-unknown-linux-gnu',
        'x86_64-pc-windows-msvc',
        'aarch64-apple-darwin',
        'x86_64-apple-darwin'
    )]
    [string]$Target,

    [Parameter(Mandatory)]
    [string]$BinaryDirectory,

    [Parameter(Mandatory)]
    [string]$PluginArchivePath,

    [string]$OutputDirectory = 'target/release-artifacts',

    [switch]$RunBinaries
)

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'ReleasePackaging.Functions.ps1')

function Expand-ReleaseArchive {
    param(
        [Parameter(Mandatory)]
        [string]$ArchivePath,

        [Parameter(Mandatory)]
        [string]$Format,

        [Parameter(Mandatory)]
        [string]$Destination
    )

    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    switch ($Format) {
        'zip' {
            [IO.Compression.ZipFile]::ExtractToDirectory(
                $ArchivePath,
                $Destination,
                $false
            )
        }
        'tar.gz' {
            $input = [IO.File]::OpenRead($ArchivePath)
            $gzip = [IO.Compression.GZipStream]::new(
                $input,
                [IO.Compression.CompressionMode]::Decompress,
                $true
            )
            try {
                [System.Formats.Tar.TarFile]::ExtractToDirectory(
                    $gzip,
                    $Destination,
                    $false
                )
            }
            finally {
                $gzip.Dispose()
                $input.Dispose()
            }
        }
        default {
            throw "Unsupported release archive format: $Format"
        }
    }
}

function Assert-ReleaseLayout {
    param(
        [Parameter(Mandatory)]
        [string]$ExtractedRoot,

        [Parameter(Mandatory)]
        $Manifest,

        [Parameter(Mandatory)]
        $Artifact
    )

    foreach ($fileName in @(
        'ARTIFACT.json',
        'README.md',
        'RELEASE.json',
        'UNSIGNED-PRERELEASE.txt'
    )) {
        if (-not (Test-Path -LiteralPath (Join-Path $ExtractedRoot $fileName) -PathType Leaf)) {
            throw "Release package is missing $fileName."
        }
    }
    $metadata = Get-Content -LiteralPath (
        Join-Path $ExtractedRoot 'ARTIFACT.json'
    ) -Raw -Encoding UTF8 | ConvertFrom-Json -Depth 100
    if (
        [string]$metadata.id -cne [string]$Artifact.id -or
        [string]$metadata.signatureStatus -cne 'unsigned' -or
        [string]$metadata.version -cne [string]$Manifest.release.version
    ) {
        throw 'Extracted artifact metadata does not match the release contract.'
    }

    $suffix = if ([string]$Artifact.operatingSystem -ceq 'windows') { '.exe' } else { '' }
    if ([string]$Artifact.kind -ceq 'client') {
        foreach ($relative in @(
            "bin/konclave$suffix",
            "bin/KonclaveLocalService$suffix",
            'share/konclave/plugin/plugin.json',
            'share/konclave/plugin/extensions/Konclave.Extension/client.mjs',
            'share/konclave/plugin/extensions/Konclave.Extension/extension.mjs'
        )) {
            if (-not (Test-Path -LiteralPath (Join-Path $ExtractedRoot $relative) -PathType Leaf)) {
                throw "Client package is missing $relative."
            }
        }
        $serviceRelative = switch ([string]$Artifact.operatingSystem) {
            'linux' { 'share/konclave/service/systemd/KonclaveLocalService.service' }
            'macos' { 'share/konclave/service/launchd/com.genesis.KonclaveLocalService.plist' }
            'windows' { 'share/konclave/service/windows/install-service.ps1' }
            default { throw "Unsupported release operating system: $($Artifact.operatingSystem)" }
        }
        if (
            -not (
                Test-Path -LiteralPath (Join-Path $ExtractedRoot $serviceRelative) -PathType Leaf
            )
        ) {
            throw "Client package is missing $serviceRelative."
        }
        $managerRelative = switch ([string]$Artifact.operatingSystem) {
            'linux' { 'share/konclave/service/systemd/manage-user-service.sh' }
            'macos' { 'share/konclave/service/launchd/manage-agent.sh' }
            'windows' { 'share/konclave/service/windows/install-service.ps1' }
            default { throw "Unsupported release operating system: $($Artifact.operatingSystem)" }
        }
        if (
            -not (
                Test-Path -LiteralPath (Join-Path $ExtractedRoot $managerRelative) -PathType Leaf
            )
        ) {
            throw "Client package is missing $managerRelative."
        }
        if (
            [string]$Artifact.operatingSystem -ceq 'windows' -and
            -not (
                Test-Path -LiteralPath (
                    Join-Path $ExtractedRoot 'bin/KonclaveLocalServiceHost.exe'
                ) -PathType Leaf
            )
        ) {
            throw 'Windows client package is missing its shared-service host.'
        }
    }
    else {
        foreach ($relative in @(
            "bin/KonclaveCommunityRelay$suffix",
            'share/konclave/relay/compose.example.yaml',
            'share/konclave/relay/container.md'
        )) {
            if (-not (Test-Path -LiteralPath (Join-Path $ExtractedRoot $relative) -PathType Leaf)) {
                throw "Relay package is missing $relative."
            }
        }
    }
    if (Get-ChildItem -LiteralPath $ExtractedRoot -Recurse -Filter Cargo.toml -File) {
        throw 'Release package contains a Rust source manifest.'
    }
}

$projectRootPath = (Resolve-Path -LiteralPath $ProjectRoot).Path
$outputPath = Resolve-ReleasePath $OutputDirectory $projectRootPath
$manifest = Read-ReleaseArtifactContract $projectRootPath
$firstRoot = Join-Path (
    [IO.Path]::GetTempPath()
) "konclave-package-first-$([Guid]::NewGuid().ToString('N'))"
$secondRoot = Join-Path (
    [IO.Path]::GetTempPath()
) "konclave-package-second-$([Guid]::NewGuid().ToString('N'))"
$extractRoot = Join-Path (
    [IO.Path]::GetTempPath()
) "konclave-package-extract-$([Guid]::NewGuid().ToString('N'))"

New-Item -ItemType Directory -Path $firstRoot, $secondRoot, $extractRoot | Out-Null
try {
    New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
    foreach ($kind in @('client', 'relay')) {
        $artifact = Get-ReleaseArtifact $manifest $Target $kind
        $first = New-ReleasePackage `
            -ProjectRoot $projectRootPath `
            -Target $Target `
            -Kind $kind `
            -BinaryDirectory $BinaryDirectory `
            -PluginArchivePath $PluginArchivePath `
            -OutputDirectory $firstRoot
        $second = New-ReleasePackage `
            -ProjectRoot $projectRootPath `
            -Target $Target `
            -Kind $kind `
            -BinaryDirectory $BinaryDirectory `
            -PluginArchivePath $PluginArchivePath `
            -OutputDirectory $secondRoot
        $firstHash = (Get-FileHash -LiteralPath $first -Algorithm SHA256).Hash
        $secondHash = (Get-FileHash -LiteralPath $second -Algorithm SHA256).Hash
        if ($firstHash -cne $secondHash) {
            throw "Repeated $kind packaging is not byte-identical for $Target."
        }

        $kindExtractRoot = Join-Path $extractRoot $kind
        Expand-ReleaseArchive $first ([string]$artifact.archiveFormat) $kindExtractRoot
        $payloadRoot = Join-Path $kindExtractRoot ([string]$artifact.rootDirectory)
        Assert-ReleaseLayout $payloadRoot $manifest $artifact

        if ($RunBinaries -and $kind -ceq 'client') {
            $suffix = if ([string]$artifact.operatingSystem -ceq 'windows') { '.exe' } else { '' }
            $cli = Join-Path $payloadRoot 'bin' "konclave$suffix"
            if ([string]$artifact.operatingSystem -cne 'windows') {
                foreach ($relative in @(
                    "bin/konclave$suffix",
                    "bin/KonclaveLocalService$suffix"
                )) {
                    $mode = (Get-Item -LiteralPath (Join-Path $payloadRoot $relative)).UnixFileMode
                    if (($mode -band [IO.UnixFileMode]::UserExecute) -eq 0) {
                        throw "Extracted executable lacks owner execute permission: $relative"
                    }
                }
            }
            $versionOutput = & $cli version
            if (
                $LASTEXITCODE -ne 0 -or
                ($versionOutput -join "`n") -notmatch [regex]::Escape(
                    [string]$manifest.release.version
                )
            ) {
                throw 'Extracted CLI did not report the release version.'
            }
            $doctorProfile = Join-Path $kindExtractRoot 'doctor-profile'
            $nativeErrorPreference = $PSNativeCommandUseErrorActionPreference
            $PSNativeCommandUseErrorActionPreference = $false
            try {
                $doctorOutput = & $cli doctor `
                    --install-root $payloadRoot `
                    --profile-root $doctorProfile 2>&1
                $doctorExitCode = $LASTEXITCODE
                $global:LASTEXITCODE = 0
            }
            finally {
                $PSNativeCommandUseErrorActionPreference = $nativeErrorPreference
            }
            $doctorText = $doctorOutput -join "`n"
            if (
                $doctorExitCode -eq 0 -or
                $doctorText -notmatch 'PASS local_service_binary:' -or
                $doctorText -notmatch 'PASS copilot_plugin:'
            ) {
                throw 'Extracted CLI did not recognize the packaged shared service and plugin.'
            }
        }

        $destination = Join-Path $outputPath ([string]$artifact.fileName)
        if (Test-Path -LiteralPath $destination) {
            throw "Release validation output already exists: $destination"
        }
        Copy-Item -LiteralPath $first -Destination $destination
    }
}
finally {
    foreach ($path in @($firstRoot, $secondRoot, $extractRoot)) {
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Recurse -Force
        }
    }
}

Write-Output "Release packaging passed for $Target; client and relay archives are deterministic."
