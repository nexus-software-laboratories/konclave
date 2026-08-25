#Requires -Version 7.4

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$root = Join-Path (
    [IO.Path]::GetTempPath()
) "konclave-metadata-test-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $root | Out-Null
try {
    $raw = Join-Path $root 'raw.cdx.json'
    $first = Join-Path $root 'first.cdx.json'
    $second = Join-Path $root 'second.cdx.json'
    $document = [ordered]@{
        '$schema' = 'http://cyclonedx.org/schema/bom-1.5.schema.json'
        bomFormat = 'CycloneDX'
        specVersion = '1.5'
        serialNumber = 'urn:uuid:00000000-0000-0000-0000-000000000000'
        version = 1
        metadata = [ordered]@{
            timestamp = '2026-01-01T00:00:00Z'
            component = [ordered]@{ type = 'application'; name = 'old'; version = '0' }
        }
        components = @(
            [ordered]@{ type = 'library'; 'bom-ref' = 'z'; name = 'z'; version = '1' },
            [ordered]@{ type = 'library'; 'bom-ref' = 'foobar'; name = 'foobar'; version = '1' },
            [ordered]@{ type = 'library'; 'bom-ref' = 'foo_baz'; name = 'foo_baz'; version = '1' },
            [ordered]@{ type = 'library'; 'bom-ref' = 'foo-bar'; name = 'foo-bar'; version = '1' },
            [ordered]@{ type = 'library'; 'bom-ref' = 'a'; name = 'a'; version = '1' }
        )
        dependencies = @(
            [ordered]@{ ref = 'z'; dependsOn = @('z2', 'z1') },
            [ordered]@{ ref = 'a'; dependsOn = @() }
        )
    }
    [IO.File]::WriteAllText(
        $raw,
        ($document | ConvertTo-Json -Depth 20),
        [Text.UTF8Encoding]::new($false)
    )
    foreach ($output in @($first, $second)) {
        & (Join-Path $PSScriptRoot 'Normalize-CycloneDx.ps1') `
            -ProjectRoot (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path `
            -InputPath $raw `
            -OutputPath $output `
            -ComponentName 'konclave-test' `
            -ComponentVersion '0.1.0'
    }
    if (
        (Get-FileHash $first).Hash -cne (Get-FileHash $second).Hash
    ) {
        throw 'CycloneDX normalization is not deterministic.'
    }
    $normalized = Get-Content $first -Raw | ConvertFrom-Json -Depth 20
    $orderedRefs = [string[]]@($normalized.components | ForEach-Object { $_.'bom-ref' })
    $expectedRefs = [string[]]@('a', 'foo-bar', 'foo_baz', 'foobar', 'z')
    if (
        $normalized.serialNumber -or
        $normalized.metadata.timestamp -or
        [string]$normalized.specVersion -cne '1.6' -or
        @(Compare-Object $orderedRefs $expectedRefs -CaseSensitive -SyncWindow 0).Count -gt 0 -or
        [string]$normalized.dependencies[1].dependsOn[0] -cne 'z1'
    ) {
        throw 'CycloneDX normalization did not enforce its public deterministic shape.'
    }

    $document.components[0].description = (Resolve-Path .).Path
    [IO.File]::WriteAllText(
        $raw,
        ($document | ConvertTo-Json -Depth 20),
        [Text.UTF8Encoding]::new($false)
    )
    try {
        & (Join-Path $PSScriptRoot 'Normalize-CycloneDx.ps1') `
            -ProjectRoot (Resolve-Path .).Path `
            -InputPath $raw `
            -OutputPath (Join-Path $root 'forbidden.cdx.json') `
            -ComponentName 'konclave-test' `
            -ComponentVersion '0.1.0'
    }
    catch {
        Write-Output 'Release metadata normalization and path-redaction tests passed.'
        return
    }
    throw 'CycloneDX normalization accepted a local build path.'
}
finally {
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force
    }
}
