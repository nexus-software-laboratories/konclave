#Requires -Version 7.4

Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot '..' 'CargoLock.Functions.ps1')

function Get-CargoWorkspaceMetadata {
    param(
        [Parameter(Mandatory)]
        [string]$ProjectRoot,

        [Parameter(Mandatory)]
        [string]$Target,

        [string]$MetadataPath
    )

    if (-not [string]::IsNullOrWhiteSpace($MetadataPath)) {
        $json = Get-Content -LiteralPath $MetadataPath -Raw -Encoding UTF8
        return $json | ConvertFrom-Json -Depth 100
    }

    $manifestPath = Join-Path $ProjectRoot 'Cargo.toml'
    $output = & cargo metadata `
        '--locked' `
        '--filter-platform' $Target `
        '--format-version' '1' `
        '--manifest-path' $manifestPath
    if ($LASTEXITCODE -ne 0) {
        throw "cargo metadata failed for target $Target."
    }
    return ($output -join "`n") | ConvertFrom-Json -Depth 100
}

function Get-CargoLockedChecksums {
    param(
        [Parameter(Mandatory)]
        [string]$LockPath
    )

    $checksums = @{}
    foreach ($package in Get-CargoLockedPackages -LockPath $LockPath) {
        if (-not [string]::IsNullOrWhiteSpace($package.Checksum)) {
            $checksums["$($package.Name)@$($package.Version)"] = $package.Checksum
        }
    }
    return $checksums
}

function Resolve-RustSbomRootPackageId {
    param(
        [Parameter(Mandatory)]
        $Metadata,

        [Parameter(Mandatory)]
        [string]$PackageName
    )

    $workspaceIds = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    foreach ($id in @($Metadata.workspace_members)) {
        [void]$workspaceIds.Add([string]$id)
    }
    $matches = @(
        $Metadata.packages |
            Where-Object {
                [string]$_.name -ceq $PackageName -and $workspaceIds.Contains([string]$_.id)
            }
    )
    if ($matches.Count -ne 1) {
        throw "Root package is not a unique workspace member: $PackageName"
    }
    return [string]$matches[0].id
}

function Resolve-RustSbomDependencyClosure {
    param(
        [Parameter(Mandatory)]
        $Metadata,

        [Parameter(Mandatory)]
        [string[]]$RootPackageName
    )

    $nodesById = @{}
    foreach ($node in @($Metadata.resolve.nodes)) {
        $nodesById[[string]$node.id] = $node
    }

    $rootIds = [Collections.Generic.List[string]]::new()
    foreach ($name in $RootPackageName) {
        $rootIds.Add((Resolve-RustSbomRootPackageId -Metadata $Metadata -PackageName $name))
    }

    # Only "normal" dep_kinds ship inside a built binary; dev-dependencies are
    # test-only and build-dependencies run at build time, so neither belongs
    # in a release SBOM. cargo's --filter-platform already trims edges that
    # are inapplicable to the requested target before this graph is walked.
    $edges = @{}
    $visited = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $queue = [Collections.Generic.Queue[string]]::new()
    foreach ($id in $rootIds) {
        if ($visited.Add($id)) {
            $queue.Enqueue($id)
        }
    }
    while ($queue.Count -gt 0) {
        $id = $queue.Dequeue()
        $node = $nodesById[$id]
        if (-not $node) {
            throw "Dependency resolution is missing a node: $id"
        }
        $dependsOn = [Collections.Generic.List[string]]::new()
        foreach ($dep in @($node.deps)) {
            $isNormal = @(
                $dep.dep_kinds | Where-Object { -not $_.kind }
            ).Count -gt 0
            if (-not $isNormal) {
                continue
            }
            $depId = [string]$dep.pkg
            $dependsOn.Add($depId)
            if ($visited.Add($depId)) {
                $queue.Enqueue($depId)
            }
        }
        $edges[$id] = [string[]]@($dependsOn)
    }

    return [pscustomobject]@{
        RootIds = [string[]]@($rootIds)
        Edges = $edges
    }
}

function New-RustSbomPurl {
    param(
        [Parameter(Mandatory)]
        [string]$PurlType,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Version
    )

    return "pkg:$PurlType/$([Uri]::EscapeDataString($Name))@$([Uri]::EscapeDataString($Version))"
}

function New-RustReleaseSbomDocument {
    param(
        [Parameter(Mandatory)]
        [string]$ArtifactId,

        [Parameter(Mandatory)]
        [string]$ArtifactName,

        [Parameter(Mandatory)]
        [string]$ArtifactVersion,

        [Parameter(Mandatory)]
        $Metadata,

        [Parameter(Mandatory)]
        [string[]]$RootPackageName,

        [Parameter(Mandatory)]
        [hashtable]$Checksums
    )

    $packagesById = @{}
    foreach ($package in @($Metadata.packages)) {
        $packagesById[[string]$package.id] = $package
    }

    $closure = Resolve-RustSbomDependencyClosure -Metadata $Metadata -RootPackageName $RootPackageName

    $bomRefById = @{}
    $idByBomRef = @{}
    $components = [Collections.Generic.List[object]]::new()
    foreach ($id in @($closure.Edges.Keys)) {
        $package = $packagesById[$id]
        if (-not $package) {
            throw "Dependency closure references an unknown package: $id"
        }
        $name = [string]$package.name
        $version = [string]$package.version
        $bomRef = New-RustSbomPurl -PurlType 'cargo' -Name $name -Version $version

        if ($idByBomRef.ContainsKey($bomRef) -and $idByBomRef[$bomRef] -cne $id) {
            throw "SBOM component collision detected for bom-ref: $bomRef"
        }
        $idByBomRef[$bomRef] = $id
        $bomRefById[$id] = $bomRef

        $component = [ordered]@{
            type = 'library'
            'bom-ref' = $bomRef
            name = $name
            version = $version
            purl = $bomRef
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$package.license)) {
            $component.licenses = @(
                [ordered]@{ expression = [string]$package.license }
            )
        }
        $checksum = $Checksums["$name@$version"]
        if (-not [string]::IsNullOrWhiteSpace([string]$checksum)) {
            $component.hashes = @(
                [ordered]@{ alg = 'SHA-256'; content = [string]$checksum }
            )
        }
        $components.Add($component)
    }

    $artifactPurl = New-RustSbomPurl -PurlType 'generic' -Name $ArtifactName -Version $ArtifactVersion
    $metadataComponent = [ordered]@{
        type = 'application'
        'bom-ref' = $ArtifactId
        name = $ArtifactName
        version = $ArtifactVersion
        purl = $artifactPurl
    }

    $dependencies = [Collections.Generic.List[object]]::new()
    $dependencies.Add([ordered]@{
        ref = $ArtifactId
        dependsOn = [string[]]@($closure.RootIds | ForEach-Object { $bomRefById[$_] })
    })
    foreach ($id in @($closure.Edges.Keys)) {
        $dependencies.Add([ordered]@{
            ref = $bomRefById[$id]
            dependsOn = [string[]]@($closure.Edges[$id] | ForEach-Object { $bomRefById[$_] })
        })
    }

    return [ordered]@{
        '$schema' = 'http://cyclonedx.org/schema/bom-1.6.schema.json'
        bomFormat = 'CycloneDX'
        specVersion = '1.6'
        version = 1
        metadata = [ordered]@{ component = $metadataComponent }
        components = @($components)
        dependencies = @($dependencies)
    }
}
