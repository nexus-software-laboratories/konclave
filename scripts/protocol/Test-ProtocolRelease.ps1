#Requires -Version 7.0
[CmdletBinding()]
param(
    [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path,
    [string]$ManifestPath = 'protocol/releases/protocol-v1.0.0-alpha.1.json'
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = (Resolve-Path $ProjectRoot).Path
$rootPrefix = $ProjectRoot.TrimEnd(
    [IO.Path]::DirectorySeparatorChar,
    [IO.Path]::AltDirectorySeparatorChar
) + [IO.Path]::DirectorySeparatorChar

function Resolve-RepositoryFile {
    param([string]$RelativePath)
    $fullPath = [IO.Path]::GetFullPath((Join-Path $ProjectRoot $RelativePath))
    if (-not $fullPath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Release path resolves outside the repository: $RelativePath"
    }
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        throw "Release file is missing: $RelativePath"
    }
    return $fullPath
}

function Assert-FileHash {
    param($Entry)
    $fullPath = Resolve-RepositoryFile ([string]$Entry.path)
    $item = Get-Item -LiteralPath $fullPath
    if ($item.Length -ne [long]$Entry.bytes) {
        throw "Release byte length mismatch: $($Entry.path)"
    }
    $actual = (Get-FileHash -LiteralPath $fullPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne [string]$Entry.sha256) {
        throw "Release SHA-256 mismatch: $($Entry.path)"
    }
}

$manifestFullPath = Resolve-RepositoryFile $ManifestPath
$schemaFullPath = Resolve-RepositoryFile 'protocol/releases/protocol-release.schema.json'
$manifestJson = Get-Content -LiteralPath $manifestFullPath -Raw -Encoding UTF8
if (-not ($manifestJson | Test-Json -SchemaFile $schemaFullPath)) {
    throw 'Protocol release manifest does not satisfy its schema.'
}
$manifest = $manifestJson | ConvertFrom-Json -Depth 100
$expectedFileName = "$($manifest.release.tag).json"
if ([IO.Path]::GetFileName($manifestFullPath) -cne $expectedFileName) {
    throw "Release tag and manifest filename differ: $expectedFileName"
}

foreach ($entry in $manifest.dependencies.lockfiles) {
    Assert-FileHash $entry
}
foreach ($entry in $manifest.fixtures) {
    Assert-FileHash $entry
}

$fixtureRoot = Join-Path $ProjectRoot 'fixtures' 'protocol' 'v1'
$actualFixtures = @(
    Get-ChildItem -LiteralPath $fixtureRoot -Filter '*.bin' -File |
        ForEach-Object { "fixtures/protocol/v1/$($_.Name)" } |
        Sort-Object
)
$manifestFixtures = @($manifest.fixtures.path | Sort-Object)
$fixtureDifference = @(Compare-Object $actualFixtures $manifestFixtures)
if ($fixtureDifference.Count -gt 0) {
    throw 'Protocol release fixture set does not exactly match fixtures/protocol/v1.'
}

$cargoLock = Get-Content -LiteralPath (Join-Path $ProjectRoot 'Cargo.lock') -Raw -Encoding UTF8
$cargoVersions = @{}
foreach ($block in [regex]::Split($cargoLock, '(?m)^\[\[package\]\]\s*$')) {
    $name = [regex]::Match($block, '(?m)^name = "([^"]+)"\s*$')
    $version = [regex]::Match($block, '(?m)^version = "([^"]+)"\s*$')
    if ($name.Success -and $version.Success) {
        $cargoVersions[$name.Groups[1].Value] = $version.Groups[1].Value
    }
}
foreach ($dependency in $manifest.dependencies.securityCritical) {
    $actual = $cargoVersions[[string]$dependency.name]
    if ($actual -cne [string]$dependency.version) {
        throw "Release dependency mismatch: $($dependency.name)"
    }
}

$expectedLimits = [ordered]@{
    relayEnvelopeBytes        = 1024 * 1024
    relayPayloadBytes         = (1024 * 1024) - 1024
    applicationMessageBytes   = 256 * 1024
    applicationTextBytes      = (256 * 1024) - 1024
    replayPageBytes           = 16 * 1024 * 1024
    replayPageEnvelopes       = 100
    relayControlMessageBytes  = 1024
    activeDevices             = 128
    metadataFieldBytes        = 1024
    pendingLocalOperations    = 32
}
$actualLimitNames = @($manifest.protocol.hardLimits.PSObject.Properties.Name | Sort-Object)
$expectedLimitNames = @($expectedLimits.Keys | Sort-Object)
if (@(Compare-Object $actualLimitNames $expectedLimitNames).Count -gt 0) {
    throw 'Release hard-limit set is incomplete or contains an unknown entry.'
}
foreach ($entry in $expectedLimits.GetEnumerator()) {
    if ([long]$manifest.protocol.hardLimits.($entry.Key) -ne [long]$entry.Value) {
        throw "Release hard-limit mismatch: $($entry.Key)"
    }
}

$persistence = Get-Content -LiteralPath (
    Join-Path $ProjectRoot 'apps' 'Konclave.LocalDaemon' 'src' 'persistence.rs'
) -Raw -Encoding UTF8
$schemaVersion = [regex]::Match(
    $persistence,
    'const PROFILE_SCHEMA_VERSION: u32 = ([0-9]+);'
)
if (
    -not $schemaVersion.Success -or
    [int]$schemaVersion.Groups[1].Value -ne [int]$manifest.storage.daemonProfileSchema
) {
    throw 'Release daemon profile schema does not match source.'
}

$mls = Get-Content -LiteralPath (
    Join-Path $ProjectRoot 'crates' 'Konclave.CryptographicCore' 'src' 'mls.rs'
) -Raw -Encoding UTF8
foreach ($extension in $manifest.protocol.mls.extensions) {
    if ($mls -notmatch [regex]::Escape([string]$extension)) {
        throw "Release MLS extension is absent from source: $extension"
    }
}
$identity = Get-Content -LiteralPath (
    Join-Path $ProjectRoot 'crates' 'Konclave.CryptographicCore' 'src' 'identity.rs'
) -Raw -Encoding UTF8
if ($identity -notmatch 'CIPHER_SUITE: CipherSuite = CipherSuite::CURVE25519_AES128;') {
    throw 'Release MLS ciphersuite does not match source.'
}

Write-Host (
    "Protocol release manifest passed: {0}, {1} fixtures, {2} lockfiles." -f
    $manifest.release.tag,
    $manifestFixtures.Count,
    @($manifest.dependencies.lockfiles).Count
)
