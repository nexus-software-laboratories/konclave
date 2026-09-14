#Requires -Version 7.4

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
$root = Join-Path (
    [IO.Path]::GetTempPath()
) "konclave-complete-release-$([Guid]::NewGuid().ToString('N'))"
$sourceCommit = '0123456789abcdef0123456789abcdef01234567'
New-Item -ItemType Directory -Path $root | Out-Null
try {
    Copy-Item (
        Join-Path $projectRoot 'distribution' 'release-artifacts.json'
    ) (
        Join-Path $root 'RELEASE.json'
    )
    foreach ($relative in @(
        'distribution/release-artifacts.schema.json',
        'distribution/UNSIGNED-PRERELEASE.txt',
        'scripts/packaging/ReleaseIntegrity.Functions.ps1',
        'scripts/packaging/Verify-Release.ps1'
    )) {
        Copy-Item (Join-Path $projectRoot $relative) $root
    }
    $manifest = Get-Content -LiteralPath (
        Join-Path $root 'RELEASE.json'
    ) -Raw -Encoding UTF8 | ConvertFrom-Json -Depth 100
    foreach ($artifact in $manifest.artifacts) {
        $artifactPath = Join-Path $root ([string]$artifact.fileName)
        [IO.File]::WriteAllText($artifactPath, [string]$artifact.id)
        $digest = (
            Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        $buildKind = switch ([string]$artifact.kind) {
            'plugin' { 'plugin' }
            'container' { 'container' }
            { $_ -in @('client', 'relay', 'gateway') } { 'native' }
            default { throw "Unsupported fixture artifact kind: $($artifact.kind)" }
        }
        $statement = [ordered]@{
            _type = 'https://in-toto.io/Statement/v1'
            subject = @(
                [ordered]@{
                    name = [string]$artifact.fileName
                    digest = [ordered]@{ sha256 = $digest }
                }
            )
            predicateType = 'https://slsa.dev/provenance/v1'
            predicate = [ordered]@{
                buildDefinition = [ordered]@{
                    externalParameters = [ordered]@{
                        artifactId = [string]$artifact.id
                        buildKind = $buildKind
                        signatureStatus = [string]$manifest.release.signatureStatus
                        target = [string]$artifact.target
                        version = [string]$manifest.release.version
                    }
                    resolvedDependencies = @(
                        [ordered]@{
                            uri = (
                                'git+https://github.com/nexus-software-laboratories/' +
                                "konclave@$sourceCommit"
                            )
                            digest = [ordered]@{ gitCommit = $sourceCommit }
                        }
                    )
                }
            }
        }
        [IO.File]::WriteAllText(
            "$artifactPath.intoto.jsonl",
            ($statement | ConvertTo-Json -Depth 20 -Compress) + "`n",
            [Text.UTF8Encoding]::new($false)
        )
        $sbomPath = if ([string]$artifact.kind -in @('client', 'relay', 'gateway')) {
            "$artifactPath.rust.cdx.json"
        }
        else {
            "$artifactPath.cdx.json"
        }
        [IO.File]::WriteAllText($sbomPath, '{"bomFormat":"CycloneDX"}')
    }

    & (Join-Path $PSScriptRoot 'Complete-ReleaseSet.ps1') `
        -Directory $root `
        -SourceCommit $sourceCommit `
        -ProjectRoot $projectRoot
}
finally {
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force
    }
}

Write-Output 'Complete release-set integration test passed.'
