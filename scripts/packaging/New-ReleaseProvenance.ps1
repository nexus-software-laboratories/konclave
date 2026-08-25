#Requires -Version 7.4
<#
.SYNOPSIS
    Emits one deterministic public SLSA v1 provenance statement for an artifact.
#>
[CmdletBinding()]
param(
    [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path,

    [Parameter(Mandatory)]
    [string]$ArtifactPath,

    [Parameter(Mandatory)]
    [string]$ArtifactId,

    [Parameter(Mandatory)]
    [string]$Target,

    [Parameter(Mandatory)]
    [ValidateSet('native', 'container')]
    [string]$BuildKind,

    [Parameter(Mandatory)]
    [string]$OutputPath,

    [string]$SyftCommand
)

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'ReleaseMetadata.Functions.ps1')

function Invoke-VersionCommand {
    param(
        [Parameter(Mandatory)]
        [string]$Command,

        [string[]]$Arguments = @()
    )

    $output = & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Version command failed: $Command"
    }
    return ($output -join "`n").Trim()
}

function Get-InputDescriptor {
    param(
        [Parameter(Mandatory)]
        [string]$Root,

        [Parameter(Mandatory)]
        [string]$RelativePath,

        [Parameter(Mandatory)]
        [string]$SourceCommit
    )

    $fullPath = Join-Path $Root $RelativePath
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        throw "Provenance input is missing: $RelativePath"
    }
    return [ordered]@{
        uri = "git+https://github.com/nexus-software-laboratories/konclave@$SourceCommit#$($RelativePath.Replace('\', '/'))"
        digest = [ordered]@{
            sha256 = (Get-FileHash -LiteralPath $fullPath -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
}

$projectRootPath = (Resolve-Path -LiteralPath $ProjectRoot).Path
$artifactFullPath = (Resolve-Path -LiteralPath $ArtifactPath).Path
$manifestPath = Join-Path $projectRootPath 'distribution' 'release-artifacts.json'
$release = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 |
    ConvertFrom-Json -Depth 100
$artifacts = @($release.artifacts | Where-Object { [string]$_.id -ceq $ArtifactId })
if (
    $artifacts.Count -ne 1 -or
    [IO.Path]::GetFileName($artifactFullPath) -cne [string]$artifacts[0].fileName
) {
    throw 'Provenance artifact does not match the release manifest.'
}
$sourceCommit = (Invoke-VersionCommand git @('-C', $projectRootPath, 'rev-parse', 'HEAD')).Trim()
if ($sourceCommit -cnotmatch '^[0-9a-f]{40}$') {
    throw 'Source revision is not a full Git commit.'
}

$toolVersions = [ordered]@{
    powershell = $PSVersionTable.PSVersion.ToString()
}
if ($BuildKind -ceq 'native') {
    $rust = Invoke-VersionCommand rustc @('--version', '--verbose')
    foreach ($field in @('release', 'commit-hash', 'LLVM version')) {
        $match = [regex]::Match($rust, "(?m)^$([regex]::Escape($field)): (.+)$")
        if (-not $match.Success) {
            throw "rustc output is missing $field."
        }
        $toolVersions[$field.Replace(' ', '-').ToLowerInvariant()] = $match.Groups[1].Value
    }
    $toolVersions.cargo = Invoke-VersionCommand cargo @('--version')
    $toolVersions.node = (Invoke-VersionCommand node @('--version')).TrimStart('v')
    $toolVersions.npm = Invoke-VersionCommand npm @('--version')
    if (
        $toolVersions.release -cne [string]$release.release.toolchains.rust -or
        $toolVersions.node -cne [string]$release.release.toolchains.node -or
        $toolVersions.npm -cne [string]$release.release.toolchains.npm
    ) {
        throw 'Resolved native toolchains do not match the release manifest.'
    }
}
else {
    if ([string]::IsNullOrWhiteSpace($SyftCommand)) {
        throw 'Container provenance requires the pinned Syft command.'
    }
    $toolVersions.docker = Invoke-VersionCommand docker @('--version')
    $toolVersions.buildx = Invoke-VersionCommand docker @('buildx', 'version')
    $syft = Invoke-VersionCommand $SyftCommand @('version', '-o', 'json') |
        ConvertFrom-Json -Depth 20
    $toolVersions.syft = [string]$syft.version
    $rustBase = [regex]::Match(
        (Get-Content -LiteralPath (
            Join-Path $projectRootPath 'apps' 'Konclave.CommunityRelay' 'Dockerfile'
        ) -Raw),
        '(?m)^FROM rust:([^@\s]+)@sha256:[0-9a-f]{64}\s'
    )
    if (-not $rustBase.Success) {
        throw 'Container Dockerfile does not identify its pinned Rust compiler.'
    }
    $toolVersions.'container-rust' = $rustBase.Groups[1].Value
    if ($toolVersions.syft -cne [string]$release.release.toolchains.syft) {
        throw 'Resolved Syft version does not match the release manifest.'
    }
    if ($toolVersions.'container-rust' -cne [string]$release.release.toolchains.rust) {
        throw 'Container Rust compiler does not match the release manifest.'
    }
}

$inputPaths = [Collections.Generic.List[string]]::new()
foreach ($path in @(
    'Cargo.lock',
    'distribution/release-artifacts.json',
    '.github/workflows/package-validation.yml'
)) {
    $inputPaths.Add($path)
}
if ($BuildKind -ceq 'native') {
    $inputPaths.Add('extensions/Konclave.HostExtension/package-lock.json')
}
else {
    $inputPaths.Add('apps/Konclave.CommunityRelay/Dockerfile')
    $inputPaths.Add('apps/Konclave.CommunityRelay/compose.example.yaml')
}
$resolvedDependencies = [Collections.Generic.List[object]]::new()
$resolvedDependencies.Add([ordered]@{
    uri = "git+https://github.com/nexus-software-laboratories/konclave@$sourceCommit"
    digest = [ordered]@{ gitCommit = $sourceCommit }
})
foreach ($path in @($inputPaths | Sort-Object -CaseSensitive)) {
    $resolvedDependencies.Add(
        (Get-InputDescriptor $projectRootPath $path $sourceCommit)
    )
}
if ($BuildKind -ceq 'container') {
    $dockerfile = Get-Content -LiteralPath (
        Join-Path $projectRootPath 'apps' 'Konclave.CommunityRelay' 'Dockerfile'
    )
    $baseImages = @(
        foreach ($line in $dockerfile) {
            $match = [regex]::Match(
                $line,
                '^FROM ([^@\s]+)@sha256:([0-9a-f]{64})(?:\s|$)'
            )
            if ($match.Success) {
                [ordered]@{
                    uri = "docker://$($match.Groups[1].Value)"
                    digest = [ordered]@{ sha256 = $match.Groups[2].Value }
                }
            }
        }
    )
    if ($baseImages.Count -ne 2) {
        throw 'Container provenance requires two digest-pinned base images.'
    }
    foreach ($baseImage in $baseImages) {
        $resolvedDependencies.Add($baseImage)
    }
}

$statement = [ordered]@{
    _type = 'https://in-toto.io/Statement/v1'
    subject = @(
        [ordered]@{
            name = [IO.Path]::GetFileName($artifactFullPath)
            digest = [ordered]@{
                sha256 = (Get-FileHash -LiteralPath $artifactFullPath -Algorithm SHA256).
                    Hash.ToLowerInvariant()
            }
        }
    )
    predicateType = 'https://slsa.dev/provenance/v1'
    predicate = [ordered]@{
        buildDefinition = [ordered]@{
            buildType = "https://github.com/nexus-software-laboratories/konclave/blob/$sourceCommit/.github/workflows/package-validation.yml"
            externalParameters = [ordered]@{
                artifactId = $ArtifactId
                buildKind = $BuildKind
                signatureStatus = [string]$release.release.signatureStatus
                target = $Target
                version = [string]$release.release.version
            }
            internalParameters = [ordered]@{}
            resolvedDependencies = @($resolvedDependencies)
        }
        runDetails = [ordered]@{
            builder = [ordered]@{
                id = 'https://github.com/nexus-software-laboratories/konclave/actions/workflows/package-validation.yml'
                version = $toolVersions
            }
            metadata = [ordered]@{}
            byproducts = @()
        }
    }
}
Write-PublicReleaseJson `
    -Value $statement `
    -Path $OutputPath `
    -ProjectRoot $projectRootPath `
    -Compress
