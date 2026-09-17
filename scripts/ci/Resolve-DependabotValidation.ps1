#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string[]]$ChangedFiles
)

$ErrorActionPreference = 'Stop'

$normalizedFiles = @(
    foreach ($changedFile in $ChangedFiles) {
        $path = ([string]$changedFile).Replace('\', '/').Trim()
        while ($path.StartsWith('./', [StringComparison]::Ordinal)) {
            $path = $path.Substring(2)
        }
        if (
            -not $path -or
            $path.StartsWith('/', [StringComparison]::Ordinal) -or
            $path -match '(^|/)\.\.(/|$)'
        ) {
            throw "Dependabot reported an invalid changed path: '$changedFile'."
        }
        $path
    }
) | Sort-Object -CaseSensitive -Unique

if ($normalizedFiles.Count -eq 0) {
    throw 'Dependabot validation requires at least one changed file.'
}

$cargo = $false
$node = $false
$actions = $false
foreach ($path in $normalizedFiles) {
    if (
        $path -match '^(?:Cargo\.(?:toml|lock)|fuzz/Cargo\.lock|(?:apps|crates)/[^/]+/Cargo\.toml)$'
    ) {
        $cargo = $true
        continue
    }
    if ($path -match '^(?:apps|extensions|packages)/[^/]+/package(?:-lock)?\.json$') {
        $node = $true
        continue
    }
    if ($path -match '^\.github/(?:dependabot\.yml|workflows/[^/]+\.ya?ml|actions/.+)$') {
        $actions = $true
        continue
    }
    throw "Dependabot validation does not allow changed path '$path'."
}

[pscustomobject]@{
    Cargo = $cargo
    Node = $node
    Actions = $actions
    Files = $normalizedFiles
}
