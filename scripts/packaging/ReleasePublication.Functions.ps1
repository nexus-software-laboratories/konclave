#Requires -Version 7.4

Set-StrictMode -Version Latest

$script:MaximumPublishedReleaseFiles = 100
$script:PortablePublishedReleaseFilePattern = '^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$'

function Read-PrereleaseContract {
    param(
        [Parameter(Mandatory)]
        [string]$ProjectRoot
    )

    $manifestPath = Join-Path $ProjectRoot 'distribution' 'release-artifacts.json'
    $schemaPath = Join-Path $ProjectRoot 'distribution' 'release-artifacts.schema.json'
    $json = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8
    if (-not ($json | Test-Json -SchemaFile $schemaPath)) {
        throw 'Release artifact manifest does not satisfy its schema.'
    }
    $manifest = $json | ConvertFrom-Json -Depth 100
    if (
        [string]$manifest.release.channel -cne 'prerelease' -or
        [string]$manifest.release.signatureStatus -cne 'unsigned'
    ) {
        throw 'Publication requires the declared unsigned prerelease channel.'
    }
    return $manifest
}

function Get-PrereleaseTag {
    param(
        [Parameter(Mandatory)]
        $Manifest
    )

    $version = [string]$Manifest.release.version
    if ($version -cnotmatch '^[0-9]+\.[0-9]+\.[0-9]+$') {
        throw 'Release version is not canonical SemVer.'
    }
    return "v$version"
}

function Assert-PrereleaseSourceVersions {
    param(
        [Parameter(Mandatory)]
        [string]$ProjectRoot,

        [Parameter(Mandatory)]
        [string]$Tag
    )

    $manifest = Read-PrereleaseContract -ProjectRoot $ProjectRoot
    $expectedTag = Get-PrereleaseTag -Manifest $manifest
    if ($Tag -cne $expectedTag) {
        throw "Release tag must be $expectedTag."
    }

    $plugin = Get-Content -LiteralPath (
        Join-Path $ProjectRoot 'extensions' 'Konclave.HostExtension' 'plugin.json'
    ) -Raw -Encoding UTF8 | ConvertFrom-Json -Depth 100
    $package = Get-Content -LiteralPath (
        Join-Path $ProjectRoot 'extensions' 'Konclave.HostExtension' 'package.json'
    ) -Raw -Encoding UTF8 | ConvertFrom-Json -Depth 100
    $version = [string]$manifest.release.version
    if (
        [string]$plugin.version -cne $version -or
        [string]$package.version -cne $version
    ) {
        throw 'Release, Agent Plugin, and package versions differ.'
    }
    foreach ($artifact in $manifest.artifacts) {
        if (-not ([string]$artifact.fileName).Contains(
            $version,
            [StringComparison]::Ordinal
        )) {
            throw "Release artifact name does not contain version $version."
        }
    }
    return $manifest
}

function Assert-PublishedReleaseAssetInventory {
    param(
        [Parameter(Mandatory)]
        [string]$Directory,

        [Parameter(Mandatory)]
        [object[]]$Assets
    )

    $root = (Resolve-Path -LiteralPath $Directory).Path
    if (Get-ChildItem -LiteralPath $root -Directory) {
        throw 'Published release directory must contain files only.'
    }
    $files = @(
        Get-ChildItem -LiteralPath $root -File
    )
    if (
        $files.Count -eq 0 -or
        $files.Count -gt $script:MaximumPublishedReleaseFiles
    ) {
        throw 'Published release file count is outside its bound.'
    }

    $filesByName = [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::Ordinal
    )
    foreach ($file in $files) {
        if (
            $file.Name -cnotmatch $script:PortablePublishedReleaseFilePattern -or
            $file.LinkType -in @('SymbolicLink', 'Junction') -or
            -not $filesByName.TryAdd($file.Name, $file)
        ) {
            throw "Published release input is unsafe or duplicated: $($file.Name)"
        }
    }

    $assetsByName = [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::Ordinal
    )
    foreach ($asset in $Assets) {
        $name = [string]$asset.name
        if (
            $name -cnotmatch $script:PortablePublishedReleaseFilePattern -or
            -not $assetsByName.TryAdd($name, $asset)
        ) {
            throw "Published release asset is unsafe or duplicated: $name"
        }
    }

    $fileNames = [string[]]@($filesByName.Keys)
    $assetNames = [string[]]@($assetsByName.Keys)
    [Array]::Sort($fileNames, [StringComparer]::Ordinal)
    [Array]::Sort($assetNames, [StringComparer]::Ordinal)
    if (@(Compare-Object $fileNames $assetNames -CaseSensitive).Count -gt 0) {
        throw 'Published release asset names do not exactly match the validated set.'
    }

    foreach ($name in $fileNames) {
        $file = $filesByName[$name]
        $asset = $assetsByName[$name]
        $expectedDigest = 'sha256:' + (
            Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        if (
            [string]$asset.state -cne 'uploaded' -or
            [long]$asset.size -ne $file.Length -or
            [string]$asset.digest -cne $expectedDigest
        ) {
            throw "Published release asset bytes do not match: $name"
        }
    }
    return $fileNames.Count
}

function Assert-ReleaseProvenanceSet {
    param(
        [Parameter(Mandatory)]
        [string]$Directory,

        [Parameter(Mandatory)]
        $Manifest,

        [Parameter(Mandatory)]
        [string]$SourceCommit
    )

    if ($SourceCommit -cnotmatch '^[0-9a-f]{40}$') {
        throw 'Published source revision is not a full Git commit.'
    }
    $root = (Resolve-Path -LiteralPath $Directory).Path
    foreach ($artifact in $Manifest.artifacts) {
        $artifactPath = Join-Path $root ([string]$artifact.fileName)
        $provenancePath = "$artifactPath.intoto.jsonl"
        $statement = Get-Content -LiteralPath $provenancePath -Raw -Encoding UTF8 |
            ConvertFrom-Json -Depth 100
        $subjects = @($statement.subject)
        $sourceDependencies = @(
            $statement.predicate.buildDefinition.resolvedDependencies |
                Where-Object {
                    $digestProperty = $_.PSObject.Properties['digest']
                    $uriProperty = $_.PSObject.Properties['uri']
                    if ($null -eq $digestProperty -or $null -eq $uriProperty) {
                        $false
                    }
                    else {
                        $gitCommitProperty = $digestProperty.Value.PSObject.Properties['gitCommit']
                        $null -ne $gitCommitProperty -and
                            [string]$gitCommitProperty.Value -ceq $SourceCommit -and
                            [string]$uriProperty.Value -ceq (
                                'git+https://github.com/nexus-software-laboratories/' +
                                "konclave@$SourceCommit"
                            )
                    }
                }
        )
        $expectedBuildKind = switch ([string]$artifact.kind) {
            'plugin' { 'plugin' }
            'container' { 'container' }
            { $_ -in @('client', 'relay', 'gateway') } { 'native' }
            default {
                throw "Unsupported provenance artifact kind: $($artifact.kind)"
            }
        }
        $artifactDigest = (
            Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        if (
            [string]$statement._type -cne 'https://in-toto.io/Statement/v1' -or
            [string]$statement.predicateType -cne 'https://slsa.dev/provenance/v1' -or
            $subjects.Count -ne 1 -or
            [string]$subjects[0].name -cne [string]$artifact.fileName -or
            [string]$subjects[0].digest.sha256 -cne $artifactDigest -or
            [string]$statement.predicate.buildDefinition.externalParameters.artifactId -cne
                [string]$artifact.id -or
            [string]$statement.predicate.buildDefinition.externalParameters.buildKind -cne
                $expectedBuildKind -or
            [string]$statement.predicate.buildDefinition.externalParameters.target -cne
                [string]$artifact.target -or
            [string]$statement.predicate.buildDefinition.externalParameters.version -cne
                [string]$Manifest.release.version -or
            [string]$statement.predicate.buildDefinition.externalParameters.signatureStatus -cne
                [string]$Manifest.release.signatureStatus -or
            $sourceDependencies.Count -ne 1
        ) {
            throw "Release provenance does not match artifact: $($artifact.fileName)"
        }
    }
    return @($Manifest.artifacts).Count
}
