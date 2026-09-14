#Requires -Version 7.4

Set-StrictMode -Version Latest

$script:MaximumPublishedReleaseFiles = 100
$script:PortablePublishedReleaseFilePattern = '^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$'
$script:PublishedSourceCommitPattern = '^[0-9a-f]{40}$'

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

function Get-MissingPublishedReleaseAssetNames {
    param(
        [Parameter(Mandatory)]
        [string]$Directory,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
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

    foreach ($name in [string[]]@($assetsByName.Keys)) {
        if (-not $filesByName.ContainsKey($name)) {
            throw "Published release contains an unexpected asset: $name"
        }
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
    $missing = [string[]]@(
        $filesByName.Keys |
            Where-Object { -not $assetsByName.ContainsKey($_) }
    )
    [Array]::Sort($missing, [StringComparer]::Ordinal)
    return $missing
}

function Assert-PublishedReleaseAssetInventory {
    param(
        [Parameter(Mandatory)]
        [string]$Directory,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Assets
    )

    $missing = @(
        Get-MissingPublishedReleaseAssetNames `
            -Directory $Directory `
            -Assets $Assets
    )
    if ($missing.Count -ne 0) {
        throw "Published release is missing assets: $($missing -join ', ')"
    }
    return @(Get-ChildItem -LiteralPath $Directory -File).Count
}

function Resolve-ReleaseArtifactPath {
    param(
        [Parameter(Mandatory)]
        [string]$Directory,

        [Parameter(Mandatory)]
        [string]$FileName
    )

    if ($FileName -cnotmatch $script:PortablePublishedReleaseFilePattern) {
        throw "Release artifact file name is unsafe: $FileName"
    }
    $root = (Resolve-Path -LiteralPath $Directory).Path
    $path = [IO.Path]::GetFullPath((Join-Path $root $FileName))
    if ([IO.Path]::GetDirectoryName($path) -cne $root) {
        throw "Release artifact resolves outside its directory: $FileName"
    }
    return $path
}

function Get-ReleaseProvenanceSourceCommit {
    param(
        [Parameter(Mandatory)]
        [string]$Directory,

        [Parameter(Mandatory)]
        $Manifest
    )

    $root = (Resolve-Path -LiteralPath $Directory).Path
    $commits = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($artifact in $Manifest.artifacts) {
        $artifactPath = Resolve-ReleaseArtifactPath `
            -Directory $root `
            -FileName ([string]$artifact.fileName)
        $provenancePath = "$artifactPath.intoto.jsonl"
        $statement = Get-Content -LiteralPath $provenancePath -Raw -Encoding UTF8 |
            ConvertFrom-Json -Depth 100
        $dependencies = @(
            $statement.predicate.buildDefinition.resolvedDependencies |
                Where-Object {
                    $digest = $_.PSObject.Properties['digest']
                    $uri = $_.PSObject.Properties['uri']
                    $null -ne $digest -and
                        $null -ne $uri -and
                        $null -ne $digest.Value.PSObject.Properties['gitCommit']
                }
        )
        if ($dependencies.Count -ne 1) {
            throw "Release provenance has an invalid source dependency: $($artifact.fileName)"
        }
        $commit = [string]$dependencies[0].digest.gitCommit
        if (
            $commit -cnotmatch $script:PublishedSourceCommitPattern -or
            [string]$dependencies[0].uri -cne (
                'git+https://github.com/nexus-software-laboratories/' +
                "konclave@$commit"
            )
        ) {
            throw "Release provenance has an invalid source revision: $($artifact.fileName)"
        }
        [void]$commits.Add($commit)
    }
    if ($commits.Count -ne 1) {
        throw 'Release provenance does not identify one source revision.'
    }
    return [string]@($commits)[0]
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
        $artifactPath = Resolve-ReleaseArtifactPath `
            -Directory $root `
            -FileName ([string]$artifact.fileName)
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
