#Requires -Version 7.4

Set-StrictMode -Version Latest

function Get-ReleaseMetadataForbiddenValues {
    param(
        [Parameter(Mandatory)]
        [string]$ProjectRoot
    )

    $values = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($value in @(
        $ProjectRoot,
        $env:GITHUB_WORKSPACE,
        $env:RUNNER_TEMP,
        $env:HOME,
        $env:USERPROFILE
    )) {
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            [void]$values.Add([IO.Path]::GetFullPath($value))
        }
    }
    return [string[]]@($values)
}

function Assert-PublicReleaseMetadata {
    param(
        [Parameter(Mandatory)]
        [string]$Json,

        [Parameter(Mandatory)]
        [string[]]$ForbiddenValues
    )

    if (
        $Json.Contains('file://', [StringComparison]::OrdinalIgnoreCase) -or
        $Json.Contains('/home/runner/', [StringComparison]::OrdinalIgnoreCase) -or
        $Json.Contains('/Users/runner/', [StringComparison]::OrdinalIgnoreCase) -or
        $Json.Contains('/actions-runner/', [StringComparison]::OrdinalIgnoreCase) -or
        $Json.Contains('C:\\Users\\runneradmin\\', [StringComparison]::OrdinalIgnoreCase) -or
        $Json.Contains('D:\\a\\', [StringComparison]::OrdinalIgnoreCase)
    ) {
        throw 'Release metadata contains a build-host path.'
    }
    foreach ($value in $ForbiddenValues) {
        $native = $value.Replace('\', '\\')
        $posix = $value.Replace('\', '/')
        if (
            $Json.Contains($native, [StringComparison]::OrdinalIgnoreCase) -or
            $Json.Contains($posix, [StringComparison]::OrdinalIgnoreCase)
        ) {
            throw 'Release metadata contains a forbidden local path.'
        }
    }
}

function Write-PublicReleaseJson {
    param(
        [Parameter(Mandatory)]
        $Value,

        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$ProjectRoot,

        [switch]$Compress
    )

    $json = if ($Compress) {
        $Value | ConvertTo-Json -Depth 100 -Compress
    }
    else {
        ($Value | ConvertTo-Json -Depth 100).Replace("`r`n", "`n")
    }
    Assert-PublicReleaseMetadata `
        -Json $json `
        -ForbiddenValues (Get-ReleaseMetadataForbiddenValues $ProjectRoot)
    [IO.File]::WriteAllText(
        $Path,
        $json + "`n",
        [Text.UTF8Encoding]::new($false)
    )
}

function Set-ReleaseJsonProperty {
    param(
        [Parameter(Mandatory)]
        $Object,

        [Parameter(Mandatory)]
        [string]$Name,

        $Value
    )

    if ($Object.PSObject.Properties[$Name]) {
        $Object.$Name = $Value
    }
    else {
        $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value
    }
}

function Sort-CycloneDxCollections {
    param(
        [Parameter(Mandatory)]
        $Document
    )

    if ($Document.components) {
        $componentsByKey = [Collections.Generic.Dictionary[string, object]]::new(
            [StringComparer]::Ordinal
        )
        foreach ($component in $Document.components) {
            $key = if ($component.'bom-ref') {
                [string]$component.'bom-ref'
            }
            else {
                [string]$component.name
            }
            if (-not $componentsByKey.TryAdd($key, $component)) {
                throw "CycloneDX component sort key is duplicated: $key"
            }
        }
        $keys = [string[]]@($componentsByKey.Keys)
        [Array]::Sort($keys, [StringComparer]::Ordinal)
        $Document.components = @($keys | ForEach-Object { $componentsByKey[$_] })
    }
    if ($Document.dependencies) {
        $dependenciesByRef = [Collections.Generic.Dictionary[string, object]]::new(
            [StringComparer]::Ordinal
        )
        foreach ($dependency in $Document.dependencies) {
            if ($dependency.dependsOn) {
                $dependency.dependsOn = [string[]]@($dependency.dependsOn)
                [Array]::Sort($dependency.dependsOn, [StringComparer]::Ordinal)
            }
            $reference = [string]$dependency.ref
            if (-not $dependenciesByRef.TryAdd($reference, $dependency)) {
                throw "CycloneDX dependency reference is duplicated: $reference"
            }
        }
        $references = [string[]]@($dependenciesByRef.Keys)
        [Array]::Sort($references, [StringComparer]::Ordinal)
        $Document.dependencies = @(
            $references | ForEach-Object { $dependenciesByRef[$_] }
        )
    }
}
