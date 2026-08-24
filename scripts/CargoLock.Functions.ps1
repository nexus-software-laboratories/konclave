#Requires -Version 7.0

Set-StrictMode -Version Latest

function Get-CargoLockedPackageVersions {
    param(
        [Parameter(Mandatory)]
        [string]$LockPath
    )

    $cargoLock = Get-Content -LiteralPath $LockPath -Raw -Encoding UTF8
    $versions = @{}
    foreach ($block in [regex]::Split($cargoLock, '(?m)^\[\[package\]\]\s*$')) {
        $name = [regex]::Match($block, '(?m)^name = "([^"]+)"\s*$')
        $version = [regex]::Match($block, '(?m)^version = "([^"]+)"\s*$')
        if ($name.Success -and $version.Success) {
            $versions[$name.Groups[1].Value] = $version.Groups[1].Value
        }
    }
    return $versions
}
