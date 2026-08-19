#Requires -Version 7.0
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
. (Join-Path $PSScriptRoot 'ProtocolBaseline.Functions.ps1')
$fixtureRelativeRoot = 'fixtures/protocol'
$fixtureRoot = Join-Path $repositoryRoot $fixtureRelativeRoot
$baseRef = Resolve-ProtocolBaseline -RepositoryRoot $repositoryRoot

$backtick = [char]96
foreach ($fixture in Get-ChildItem -LiteralPath $fixtureRoot -Recurse -Filter '*.bin' -File) {
    $readmePath = Join-Path $fixture.DirectoryName 'README.md'
    $readmeLines = @(Get-Content -LiteralPath $readmePath)
    $hash = (Get-FileHash -LiteralPath $fixture.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $expectedRow = (
        "| $backtick$($fixture.Name)$backtick | $($fixture.Length) | " +
        "$backtick$hash$backtick |"
    )
    if ($expectedRow -cnotin $readmeLines) {
        throw "Fixture manifest is stale for $($fixture.Name)."
    }
}

$baseFiles = @(
    git -C $repositoryRoot ls-tree -r --name-only $baseRef -- $fixtureRelativeRoot |
        Where-Object { $_ -like '*.bin' }
)
if ($LASTEXITCODE -ne 0) {
    throw "Could not inspect protocol fixtures at '$baseRef'."
}
if ($baseFiles.Count -eq 0) {
    Write-Host 'No protocol fixtures exist on origin/main; this change establishes v1.'
    return
}

$temporaryRoot = Join-Path (
    [IO.Path]::GetTempPath()
) "konclave-protocol-fixtures-$([Guid]::NewGuid().ToString('N'))"
$archivePath = Join-Path $temporaryRoot 'baseline.tar'

try {
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
    git -C $repositoryRoot archive --output $archivePath $baseRef $fixtureRelativeRoot
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not archive the protocol fixture baseline.'
    }
    tar -xf $archivePath -C $temporaryRoot
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not extract the protocol fixture baseline.'
    }

    foreach ($baseFile in $baseFiles) {
        $relativePath = [IO.Path]::GetRelativePath(
            $fixtureRelativeRoot,
            $baseFile
        )
        $currentPath = Join-Path $fixtureRoot $relativePath
        $baselinePath = Join-Path $temporaryRoot $baseFile
        if (-not (Test-Path -LiteralPath $currentPath -PathType Leaf)) {
            throw "Released protocol fixture was removed: $baseFile"
        }
        $currentHash = (Get-FileHash -LiteralPath $currentPath -Algorithm SHA256).Hash
        $baselineHash = (Get-FileHash -LiteralPath $baselinePath -Algorithm SHA256).Hash
        if ($currentHash -cne $baselineHash) {
            throw "Released protocol fixture was modified: $baseFile"
        }
    }
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}
