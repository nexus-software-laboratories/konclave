#Requires -Version 7.0

Set-StrictMode -Version Latest

function Get-CargoLockedPackages {
    param(
        [Parameter(Mandatory)]
        [string]$LockPath
    )

    $cargoLock = Get-Content -LiteralPath $LockPath -Raw -Encoding UTF8
    $packages = [Collections.Generic.List[object]]::new()
    foreach ($block in [regex]::Split($cargoLock, '(?m)^\[\[package\]\]\s*$')) {
        $name = [regex]::Match($block, '(?m)^name = "([^"]+)"\s*$')
        $version = [regex]::Match($block, '(?m)^version = "([^"]+)"\s*$')
        if (-not ($name.Success -and $version.Success)) {
            continue
        }
        $checksum = [regex]::Match($block, '(?m)^checksum = "([0-9a-f]+)"\s*$')
        $packages.Add([pscustomobject]@{
            Name = $name.Groups[1].Value
            Version = $version.Groups[1].Value
            Checksum = if ($checksum.Success) { $checksum.Groups[1].Value } else { $null }
        })
    }
    return $packages
}

function Get-CargoLockedPackageVersions {
    param(
        [Parameter(Mandatory)]
        [string]$LockPath
    )

    $versions = @{}
    foreach ($package in Get-CargoLockedPackages -LockPath $LockPath) {
        $versions[$package.Name] = $package.Version
    }
    return $versions
}
