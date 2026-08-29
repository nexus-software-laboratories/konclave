#Requires -Version 7.0
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
. (Join-Path $repositoryRoot 'scripts' 'protocol' 'ProtocolBaseline.Functions.ps1')
$fixtureRelativeRoot = 'fixtures/a2a'
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
        throw "A2A fixture manifest is stale for $($fixture.Name)."
    }
}

$baseFiles = @(
    git -C $repositoryRoot ls-tree -r --name-only $baseRef -- $fixtureRelativeRoot |
        Where-Object { $_ -like '*.bin' }
)
if ($LASTEXITCODE -ne 0) {
    throw "Could not inspect A2A fixtures at '$baseRef'."
}
if ($baseFiles.Count -eq 0) {
    Write-Output 'No A2A fixtures exist on origin/main; this change establishes v1.0.1.'
    return
}

$temporaryRoot = Join-Path (
    [IO.Path]::GetTempPath()
) "konclave-a2a-fixtures-$([Guid]::NewGuid().ToString('N'))"
$archivePath = Join-Path $temporaryRoot 'baseline.tar'
try {
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
    git -C $repositoryRoot archive --output $archivePath $baseRef $fixtureRelativeRoot
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not archive the A2A fixture baseline.'
    }
    tar -xf $archivePath -C $temporaryRoot
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not extract the A2A fixture baseline.'
    }
    foreach ($baseFile in $baseFiles) {
        $relativePath = [IO.Path]::GetRelativePath($fixtureRelativeRoot, $baseFile)
        $currentPath = Join-Path $fixtureRoot $relativePath
        $baselinePath = Join-Path $temporaryRoot $baseFile
        if (-not (Test-Path -LiteralPath $currentPath -PathType Leaf)) {
            throw "Released A2A fixture was removed: $baseFile"
        }
        if (
            (Get-FileHash -LiteralPath $currentPath -Algorithm SHA256).Hash -cne
            (Get-FileHash -LiteralPath $baselinePath -Algorithm SHA256).Hash
        ) {
            throw "Released A2A fixture was modified: $baseFile"
        }
    }
}
finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}

Write-Output 'A2A fixture immutability passed.'
