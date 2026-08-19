#Requires -Version 7.0
<#
.SYNOPSIS
    Runs the root-owned build, package, and test contract for every composed Node guest.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$workspaceRoots = @(
    'packages/Konclave.ProtocolContracts.TypeScript',
    'apps/Konclave.AdminConsole',
    'extensions/Konclave.HostExtension'
)

foreach ($workspaceRoot in $workspaceRoots) {
    if (-not (Test-Path $workspaceRoot -PathType Container)) {
        throw "Composed workspace is missing: $workspaceRoot"
    }
    Push-Location $workspaceRoot
    try {
        if (Test-Path package-lock.json -PathType Leaf) { npm ci } else { npm install }
        if ($LASTEXITCODE -ne 0) { throw "npm install failed for $workspaceRoot." }
        npm run build --if-present
        if ($LASTEXITCODE -ne 0) { throw "npm run build failed for $workspaceRoot." }
        npm run package --if-present
        if ($LASTEXITCODE -ne 0) { throw "npm run package failed for $workspaceRoot." }
        npm test --if-present
        if ($LASTEXITCODE -ne 0) { throw "npm test failed for $workspaceRoot." }
    } finally {
        Pop-Location
    }
}
