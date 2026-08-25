#Requires -Version 7.4

Set-StrictMode -Version Latest

$script:ChecksumManifestName = 'SHA256SUMS'
$script:MaximumIntegrityFiles = 512
$script:MaximumChecksumManifestBytes = 1MB
$script:PortableReleaseFilePattern = '^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$'

function Get-ReleaseIntegrityFiles {
    param(
        [Parameter(Mandatory)]
        [string]$Directory
    )

    $root = (Resolve-Path -LiteralPath $Directory).Path
    if (Get-ChildItem -LiteralPath $root -Directory) {
        throw 'Release integrity directory must contain files only.'
    }
    $files = @(
        Get-ChildItem -LiteralPath $root -File |
            Where-Object Name -cne $script:ChecksumManifestName
    )
    if ($files.Count -eq 0 -or $files.Count -gt $script:MaximumIntegrityFiles) {
        throw 'Release integrity file count is outside its bound.'
    }
    foreach ($file in $files) {
        if (
            $file.Name -cnotmatch $script:PortableReleaseFilePattern -or
            $file.LinkType -in @('SymbolicLink', 'Junction')
        ) {
            throw "Release integrity input is unsafe: $($file.Name)"
        }
    }
    $filesByName = [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::Ordinal
    )
    foreach ($file in $files) {
        if (-not $filesByName.TryAdd($file.Name, $file)) {
            throw "Release integrity directory contains a duplicate name: $($file.Name)"
        }
    }
    $names = [string[]]@($filesByName.Keys)
    [Array]::Sort($names, [StringComparer]::Ordinal)
    return @($names | ForEach-Object { $filesByName[$_] })
}

function New-ReleaseChecksums {
    param(
        [Parameter(Mandatory)]
        [string]$Directory
    )

    $root = (Resolve-Path -LiteralPath $Directory).Path
    $manifestPath = Join-Path $root $script:ChecksumManifestName
    if (Test-Path -LiteralPath $manifestPath) {
        throw "Checksum manifest already exists: $manifestPath"
    }
    $lines = foreach ($file in Get-ReleaseIntegrityFiles $root) {
        $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $($file.Name)"
    }
    $content = ($lines -join "`n") + "`n"
    [IO.File]::WriteAllText(
        $manifestPath,
        $content,
        [Text.UTF8Encoding]::new($false)
    )
    return $manifestPath
}

function Test-ReleaseContractCoverage {
    param(
        [Parameter(Mandatory)]
        [string]$Directory
    )

    $root = (Resolve-Path -LiteralPath $Directory).Path
    $manifestPath = Join-Path $root 'RELEASE.json'
    $schemaPath = Join-Path $root 'release-artifacts.schema.json'
    $manifestJson = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8
    if (-not ($manifestJson | Test-Json -SchemaFile $schemaPath)) {
        throw 'Shipped release manifest does not satisfy its schema.'
    }
    $manifest = $manifestJson | ConvertFrom-Json -Depth 100
    $expected = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($name in @(
        'RELEASE.json',
        'release-artifacts.schema.json',
        'UNSIGNED-PRERELEASE.txt',
        'ReleaseIntegrity.Functions.ps1',
        'Verify-Release.ps1',
        "konclave-copilot-plugin-$($manifest.release.version).cdx.json"
    )) {
        [void]$expected.Add($name)
    }
    foreach ($artifact in $manifest.artifacts) {
        $fileName = [string]$artifact.fileName
        [void]$expected.Add($fileName)
        [void]$expected.Add("$fileName.intoto.jsonl")
        if ([string]$artifact.kind -in @('client', 'relay')) {
            [void]$expected.Add("$fileName.rust.cdx.json")
        }
        elseif ([string]$artifact.kind -ceq 'container') {
            [void]$expected.Add("$fileName.cdx.json")
        }
        else {
            throw "Release manifest contains an unsupported artifact kind: $($artifact.kind)"
        }
    }

    $actual = [string[]]@((Get-ReleaseIntegrityFiles $root).Name)
    $expectedNames = [string[]]@($expected)
    [Array]::Sort($actual, [StringComparer]::Ordinal)
    [Array]::Sort($expectedNames, [StringComparer]::Ordinal)
    if (@(Compare-Object $actual $expectedNames -CaseSensitive).Count -gt 0) {
        throw 'Release directory does not exactly match the shipped release contract.'
    }
    return $actual.Count
}

function Test-ReleaseChecksums {
    param(
        [Parameter(Mandatory)]
        [string]$Directory
    )

    $root = (Resolve-Path -LiteralPath $Directory).Path
    $manifestPath = Join-Path $root $script:ChecksumManifestName
    $manifest = Get-Item -LiteralPath $manifestPath -ErrorAction Stop
    if (
        $manifest.LinkType -in @('SymbolicLink', 'Junction') -or
        $manifest.Length -le 0 -or
        $manifest.Length -gt $script:MaximumChecksumManifestBytes
    ) {
        throw 'Checksum manifest is missing, linked, empty, or oversized.'
    }
    $content = [IO.File]::ReadAllText($manifestPath, [Text.Encoding]::UTF8)
    if ($content.Contains("`r") -or -not $content.EndsWith("`n", [StringComparison]::Ordinal)) {
        throw 'Checksum manifest line endings are not canonical.'
    }
    $lines = @($content.TrimEnd("`n").Split("`n"))
    if ($lines.Count -eq 0 -or $lines.Count -gt $script:MaximumIntegrityFiles) {
        throw 'Checksum manifest entry count is outside its bound.'
    }
    $expected = [Collections.Generic.Dictionary[string, string]]::new(
        [StringComparer]::Ordinal
    )
    foreach ($line in $lines) {
        $match = [regex]::Match(
            $line,
            '^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]{0,255})$'
        )
        if (-not $match.Success) {
            throw 'Checksum manifest contains a malformed entry.'
        }
        $name = $match.Groups[2].Value
        if (-not $expected.TryAdd($name, $match.Groups[1].Value)) {
            throw "Checksum manifest contains a duplicate entry: $name"
        }
    }

    $actualFiles = @(Get-ReleaseIntegrityFiles $root)
    $actualNames = [string[]]@($actualFiles.Name)
    $expectedNames = [string[]]@($expected.Keys)
    [Array]::Sort($actualNames, [StringComparer]::Ordinal)
    [Array]::Sort($expectedNames, [StringComparer]::Ordinal)
    if (@(Compare-Object $actualNames $expectedNames -CaseSensitive).Count -gt 0) {
        throw 'Checksum manifest does not exactly cover the release file set.'
    }
    foreach ($file in $actualFiles) {
        $actual = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -cne [string]$expected[$file.Name]) {
            throw "Checksum verification failed: $($file.Name)"
        }
    }
    return $actualFiles.Count
}
