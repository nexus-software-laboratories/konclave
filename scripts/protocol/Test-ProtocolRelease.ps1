#Requires -Version 7.0
[CmdletBinding()]
param(
    [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path,
    [string]$ManifestPath,
    [switch]$CurrentTree
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = (Resolve-Path $ProjectRoot).Path
. (Join-Path $PSScriptRoot '..' 'CargoLock.Functions.ps1')
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

if ([string]::IsNullOrWhiteSpace($ManifestPath)) {
    $releaseRoot = Join-Path $ProjectRoot 'protocol' 'releases'
    $manifests = @(
        Get-ChildItem -LiteralPath $releaseRoot -Filter 'protocol-v*.json' -File |
            Sort-Object Name
    )
    if ($manifests.Count -eq 0) {
        throw 'No protocol release manifests were found.'
    }
    foreach ($releaseManifest in $manifests) {
        $relativePath = [IO.Path]::GetRelativePath(
            $ProjectRoot,
            $releaseManifest.FullName
        ).Replace('\', '/')
        & $PSCommandPath `
            -ProjectRoot $ProjectRoot `
            -ManifestPath $relativePath `
            -CurrentTree:$CurrentTree
    }
    return
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

if (-not $CurrentTree) {
    $tag = [string]$manifest.release.tag
    if ($tag -notmatch '^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$') {
        throw 'Release tag is not safe for repository lookup.'
    }
    $tagRef = "refs/tags/$tag"
    & git -C $ProjectRoot rev-parse --verify --quiet "$tagRef^{commit}" | Out-Null
    $tagIsPresent = $LASTEXITCODE -eq 0
    if (-not $tagIsPresent) {
        if ($LASTEXITCODE -ne 1) {
            throw "Could not determine whether protocol tag $tag exists locally."
        }
        # A shallow CI checkout omits tags, so absence here does not prove the
        # release is unpublished. Ask the origin before choosing a baseline.
        $remoteTag = & git -C $ProjectRoot ls-remote --tags origin $tagRef
        if ($LASTEXITCODE -ne 0) {
            throw "Could not query origin for protocol tag $tag."
        }
        if ($remoteTag) {
            & git -C $ProjectRoot fetch --no-recurse-submodules --depth=1 origin "+${tagRef}:${tagRef}"
            if ($LASTEXITCODE -ne 0) {
                throw "Could not fetch immutable protocol tag $tag."
            }
            & git -C $ProjectRoot rev-parse --verify --quiet "$tagRef^{commit}" | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw "Fetched protocol tag $tag is unusable."
            }
            $tagIsPresent = $true
        }
    }
    if ($tagIsPresent) {
        & git -C $ProjectRoot diff --quiet $tagRef -- $ManifestPath
        if ($LASTEXITCODE -ne 0) {
            throw "Released protocol manifest differs from immutable tag $tag."
        }
        $snapshotRoot = Join-Path (
            [IO.Path]::GetTempPath()
        ) "konclave-protocol-release-$([Guid]::NewGuid().ToString('N'))"
        $archivePath = "$snapshotRoot.tar"
        New-Item -ItemType Directory -Path $snapshotRoot | Out-Null
        try {
            & git -C $ProjectRoot archive --format=tar "--output=$archivePath" $tagRef
            if ($LASTEXITCODE -ne 0) {
                throw "Could not archive immutable protocol tag $tag."
            }
            & tar -xf $archivePath -C $snapshotRoot
            if ($LASTEXITCODE -ne 0) {
                throw "Could not extract immutable protocol tag $tag."
            }
            & $PSCommandPath `
                -ProjectRoot $snapshotRoot `
                -ManifestPath $ManifestPath `
                -CurrentTree
            return
        }
        finally {
            if (Test-Path -LiteralPath $archivePath) {
                Remove-Item -LiteralPath $archivePath -Force
            }
            if (Test-Path -LiteralPath $snapshotRoot) {
                Remove-Item -LiteralPath $snapshotRoot -Recurse -Force
            }
        }
    }
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

$cargoVersions = Get-CargoLockedPackageVersions (
    Join-Path $ProjectRoot 'Cargo.lock'
)
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

$legacyTag = 'protocol-v1.0.0-alpha.1'
if ([string]$manifest.release.tag -cne $legacyTag) {
    if ($null -eq $manifest.interoperability -or $null -eq $manifest.interoperability.a2a) {
        throw 'Protocol release is missing the required A2A interoperability evidence.'
    }
    $a2a = $manifest.interoperability.a2a
    if (
        [string]$a2a.name -cne 'Linux Foundation Agent2Agent Protocol' -or
        [string]$a2a.protocolVersion -cne '1.0' -or
        [string]$a2a.release -cne 'v1.0.1' -or
        [string]$a2a.commit -cne '3303592588e388e62e0f69f701af531d2f4e3991' -or
        [string]$a2a.source.path -cne 'third_party/a2a/v1.0.1/a2a.proto' -or
        [string]$a2a.provenance.path -cne 'third_party/a2a/v1.0.1/provenance.json' -or
        [string]$a2a.conformanceProfile.path -cne 'conformance/a2a/tck-v1.0.1.json' -or
        [string]$a2a.tck.repository -cne 'https://github.com/a2aproject/a2a-tck' -or
        [string]$a2a.tck.version -cne '1.0.0' -or
        [string]$a2a.tck.commit -cne '263b9cfaf16a554bdfb166a7ba5b67716e946349' -or
        [string]$a2a.tck.uvVersion -cne '0.11.7' -or
        [string]$a2a.tck.uvArtifactSha256 -cne '4e4d5e31bea86e1b6e0f5a0f95e14e80018e6f6c0129256d2915a4b3d793644d' -or
        [string]$a2a.sdk.repository -cne 'https://github.com/a2aproject/a2a-python' -or
        [string]$a2a.sdk.package -cne 'a2a-sdk' -or
        [string]$a2a.sdk.version -cne '1.0.3' -or
        [string]$a2a.sdk.release -cne 'v1.0.3' -or
        [string]$a2a.sdk.commit -cne '8a82061571142b12745576c972bf07077930a4ff' -or
        [string]$a2a.sdk.sdistSha256 -cne 'c57ddd910aece4a426ae26b8f0d0e8e2f3271a6adde974078075e4f600aaf628'
    ) {
        throw 'Protocol release A2A identity does not match the selected public profile.'
    }
    Assert-FileHash $a2a.source
    Assert-FileHash $a2a.provenance
    Assert-FileHash $a2a.conformanceProfile
    foreach ($entry in $a2a.fixtures) {
        Assert-FileHash $entry
    }

    $a2aFixtureRoot = Join-Path $ProjectRoot 'fixtures' 'a2a' 'v1.0.1'
    $actualA2AFixtures = @(
        Get-ChildItem -LiteralPath $a2aFixtureRoot -Filter '*.bin' -File |
            ForEach-Object { "fixtures/a2a/v1.0.1/$($_.Name)" } |
            Sort-Object
    )
    $manifestA2AFixtures = @($a2a.fixtures.path | Sort-Object)
    if (@(Compare-Object $actualA2AFixtures $manifestA2AFixtures).Count -gt 0) {
        throw 'Protocol release A2A fixture set is incomplete or contains an unknown entry.'
    }

    $expectedA2ACrates = @(
        'KonclaveA2AArtifactHttp',
        'KonclaveA2AArtifactStorage',
        'KonclaveA2AContracts',
        'KonclaveA2ADiscovery',
        'KonclaveA2ADomain',
        'KonclaveA2AGateway',
        'KonclaveA2AKonclaveBridge',
        'KonclaveA2ATaskStore',
        'KonclaveA2ATaskStoreSqlite'
    ) | Sort-Object
    $manifestA2ACrates = @($a2a.publicCrates.name | Sort-Object)
    if (@(Compare-Object $expectedA2ACrates $manifestA2ACrates).Count -gt 0) {
        throw 'Protocol release A2A public crate set is incomplete or contains an unknown entry.'
    }
    foreach ($crate in $a2a.publicCrates) {
        if ([string]$cargoVersions[[string]$crate.name] -cne [string]$crate.version) {
            throw "Protocol release A2A crate version mismatch: $($crate.name)"
        }
    }

    $profile = Get-Content -LiteralPath (
        Resolve-RepositoryFile ([string]$a2a.conformanceProfile.path)
    ) -Raw -Encoding UTF8 | ConvertFrom-Json -Depth 100
    $counts = [ordered]@{
        supportedMustRequirements = @($profile.supportedRequirements).Count
        inapplicablePasses = @(
            $profile.expectedInapplicablePasses |
                ForEach-Object requirements
        ).Count
        allowedFailures = @(
            $profile.allowedFailures |
                ForEach-Object requirements
        ).Count
        expectedSkips = @(
            $profile.expectedSkips |
                ForEach-Object requirements
        ).Count
        expectedNotTested = @(
            $profile.expectedNotTested |
                ForEach-Object requirements
        ).Count
    }
    foreach ($count in $counts.GetEnumerator()) {
        if ([int]$a2a.conformanceProfile.($count.Key) -ne [int]$count.Value) {
            throw "Protocol release A2A conformance count mismatch: $($count.Key)"
        }
    }
    if (
        [string]$profile.protocol.release -cne [string]$a2a.release -or
        [string]$profile.protocol.commit -cne [string]$a2a.commit -or
        [string]$profile.tck.repository -cne [string]$a2a.tck.repository -or
        [string]$profile.tck.version -cne [string]$a2a.tck.version -or
        [string]$profile.tck.commit -cne [string]$a2a.tck.commit -or
        [string]$profile.tck.uvVersion -cne [string]$a2a.tck.uvVersion -or
        [string]$profile.tck.uvArtifact.sha256 -cne [string]$a2a.tck.uvArtifactSha256 -or
        [string]$profile.sdkInterop.repository -cne [string]$a2a.sdk.repository -or
        [string]$profile.sdkInterop.package -cne [string]$a2a.sdk.package -or
        [string]$profile.sdkInterop.version -cne [string]$a2a.sdk.version -or
        [string]$profile.sdkInterop.release -cne [string]$a2a.sdk.release -or
        [string]$profile.sdkInterop.commit -cne [string]$a2a.sdk.commit -or
        [string]$profile.sdkInterop.sdistSha256 -cne [string]$a2a.sdk.sdistSha256
    ) {
        throw 'Protocol release A2A conformance profile identity is inconsistent.'
    }
}

Write-Host (
    "Protocol release manifest passed: {0}, {1} fixtures, {2} lockfiles." -f
    $manifest.release.tag,
    $manifestFixtures.Count,
    @($manifest.dependencies.lockfiles).Count
)
