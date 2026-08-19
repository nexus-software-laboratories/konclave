#Requires -Version 7.0
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
. (Join-Path $PSScriptRoot 'ProtocolBaseline.Functions.ps1')
$protoPath = Join-Path $repositoryRoot 'proto'
$baseRef = Resolve-ProtocolBaseline -RepositoryRoot $repositoryRoot

$baseFiles = @(
    git -C $repositoryRoot ls-tree -r --name-only $baseRef -- proto
)
if ($LASTEXITCODE -ne 0) {
    throw "Could not inspect protocol files at '$baseRef'."
}

if ($baseFiles.Count -eq 0) {
    Write-Host 'No protocol schema exists on origin/main; this change establishes v1.'
    return
}

$temporaryRoot = Join-Path (
    [IO.Path]::GetTempPath()
) "konclave-protocol-baseline-$([Guid]::NewGuid().ToString('N'))"
$archivePath = Join-Path $temporaryRoot 'baseline.tar'

try {
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
    git -C $repositoryRoot archive --output $archivePath $baseRef proto
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not archive the protocol compatibility baseline.'
    }
    tar -xf $archivePath -C $temporaryRoot
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not extract the protocol compatibility baseline.'
    }

    & buf breaking $protoPath --against (Join-Path $temporaryRoot 'proto')
    if ($LASTEXITCODE -ne 0) {
        throw 'Protocol schema contains a breaking change.'
    }
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}
