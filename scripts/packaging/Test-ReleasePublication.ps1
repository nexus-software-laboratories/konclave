#Requires -Version 7.4

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'ReleasePublication.Functions.ps1')

function Assert-PublicationCheckFails {
    param(
        [Parameter(Mandatory)]
        [scriptblock]$Action,

        [Parameter(Mandatory)]
        [string]$Scenario
    )

    try {
        & $Action
    }
    catch {
        return
    }
    throw "Release publication accepted $Scenario."
}

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
$sourceManifest = Read-PrereleaseContract -ProjectRoot $projectRoot
$expectedTag = Get-PrereleaseTag -Manifest $sourceManifest
$manifest = Assert-PrereleaseSourceVersions `
    -ProjectRoot $projectRoot `
    -Tag $expectedTag
if ((Get-PrereleaseTag -Manifest $manifest) -cne $expectedTag) {
    throw 'Prerelease tag derivation returned an unexpected value.'
}
Assert-PublicationCheckFails {
    Assert-PrereleaseSourceVersions `
        -ProjectRoot $projectRoot `
        -Tag 'v999.999.999'
} 'a cross-version tag'

$root = Join-Path (
    [IO.Path]::GetTempPath()
) "konclave-release-publication-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $root | Out-Null
try {
    [IO.File]::WriteAllText((Join-Path $root 'artifact.zip'), 'artifact')
    [IO.File]::WriteAllText((Join-Path $root 'SHA256SUMS'), 'checksums')
    $assets = @(
        Get-ChildItem -LiteralPath $root -File |
            ForEach-Object {
                [pscustomobject]@{
                    name = $_.Name
                    state = 'uploaded'
                    size = $_.Length
                    digest = 'sha256:' + (
                        Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256
                    ).Hash.ToLowerInvariant()
                }
            }
    )
    if ((Assert-PublishedReleaseAssetInventory -Directory $root -Assets $assets) -ne 2) {
        throw 'Published release inventory returned an unexpected file count.'
    }

    Assert-PublicationCheckFails {
        Assert-PublishedReleaseAssetInventory `
            -Directory $root `
            -Assets @($assets | Select-Object -Skip 1)
    } 'a missing asset'

    $extraAssets = @($assets) + @(
        [pscustomobject]@{
            name = 'unexpected.txt'
            state = 'uploaded'
            size = 1
            digest = 'sha256:' + ('0' * 64)
        }
    )
    Assert-PublicationCheckFails {
        Assert-PublishedReleaseAssetInventory -Directory $root -Assets $extraAssets
    } 'an extra asset'

    $replacedAssets = @(
        foreach ($asset in $assets) {
            [pscustomobject]@{
                name = $asset.name
                state = $asset.state
                size = $asset.size
                digest = if ($asset.name -ceq 'artifact.zip') {
                    'sha256:' + ('0' * 64)
                }
                else {
                    $asset.digest
                }
            }
        }
    )
    Assert-PublicationCheckFails {
        Assert-PublishedReleaseAssetInventory -Directory $root -Assets $replacedAssets
    } 'replaced asset bytes'

    Get-ChildItem -LiteralPath $root -File | Remove-Item -Force
    $artifactPath = Join-Path $root 'plugin.zip'
    [IO.File]::WriteAllText($artifactPath, 'plugin')
    $sourceCommit = '0123456789abcdef0123456789abcdef01234567'
    $artifactDigest = (
        Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    $provenanceManifest = [pscustomobject]@{
        release = [pscustomobject]@{
            version = '0.1.0'
            signatureStatus = 'unsigned'
        }
        artifacts = @(
            [pscustomobject]@{
                id = 'konclave-agent-plugin'
                kind = 'plugin'
                target = 'portable'
                fileName = 'plugin.zip'
            }
        )
    }
    $statement = [ordered]@{
        _type = 'https://in-toto.io/Statement/v1'
        subject = @(
            [ordered]@{
                name = 'plugin.zip'
                digest = [ordered]@{ sha256 = $artifactDigest }
            }
        )
        predicateType = 'https://slsa.dev/provenance/v1'
        predicate = [ordered]@{
            buildDefinition = [ordered]@{
                externalParameters = [ordered]@{
                    artifactId = 'konclave-agent-plugin'
                    buildKind = 'plugin'
                    signatureStatus = 'unsigned'
                    target = 'portable'
                    version = '0.1.0'
                }
                resolvedDependencies = @(
                    [ordered]@{
                        uri = (
                            'git+https://github.com/nexus-software-laboratories/' +
                            "konclave@$sourceCommit"
                        )
                        digest = [ordered]@{ gitCommit = $sourceCommit }
                    },
                    [ordered]@{
                        uri = 'git+https://example.invalid/dependency'
                        digest = [ordered]@{ sha256 = '0' * 64 }
                    }
                )
            }
        }
    }
    $provenancePath = "$artifactPath.intoto.jsonl"
    [IO.File]::WriteAllText(
        $provenancePath,
        ($statement | ConvertTo-Json -Depth 20 -Compress) + "`n",
        [Text.UTF8Encoding]::new($false)
    )
    if (
        (Assert-ReleaseProvenanceSet `
            -Directory $root `
            -Manifest $provenanceManifest `
            -SourceCommit $sourceCommit) -ne 1
    ) {
        throw 'Release provenance check returned an unexpected artifact count.'
    }
    if (
        (Get-ReleaseProvenanceSourceCommit `
            -Directory $root `
            -Manifest $provenanceManifest) -cne $sourceCommit
    ) {
        throw 'Release provenance source discovery returned an unexpected commit.'
    }
    $statement.subject[0].digest.sha256 = '0' * 64
    [IO.File]::WriteAllText(
        $provenancePath,
        ($statement | ConvertTo-Json -Depth 20 -Compress) + "`n",
        [Text.UTF8Encoding]::new($false)
    )
    Assert-PublicationCheckFails {
        Assert-ReleaseProvenanceSet `
            -Directory $root `
            -Manifest $provenanceManifest `
            -SourceCommit $sourceCommit
    } 'mismatched artifact provenance'
    $provenanceManifest.artifacts[0].fileName = '../plugin.zip'
    Assert-PublicationCheckFails {
        Get-ReleaseProvenanceSourceCommit `
            -Directory $root `
            -Manifest $provenanceManifest
    } 'an escaping provenance artifact path'
}
finally {
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force
    }
}

Write-Output 'Release publication contract tests passed.'
