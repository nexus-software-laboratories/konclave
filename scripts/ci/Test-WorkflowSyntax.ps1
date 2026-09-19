#Requires -Version 7.0
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
$workflowRoot = Join-Path $repositoryRoot '.github' 'workflows'
if (-not (Test-Path -LiteralPath $workflowRoot -PathType Container)) {
    throw 'GitHub Actions workflow directory is missing.'
}
if (
    [string]::IsNullOrWhiteSpace($env:RUNNER_TEMP) -or
    -not $IsLinux -or
    [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne
        [Runtime.InteropServices.Architecture]::X64
) {
    throw 'Workflow syntax validation requires a Linux x64 GitHub-hosted runner.'
}

$version = '1.7.12'
$archiveName = "actionlint_${version}_linux_amd64.tar.gz"
$archiveSha256 = '8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8'
$toolRoot = Join-Path $env:RUNNER_TEMP "actionlint-$version-linux-x64"
$archivePath = Join-Path $toolRoot $archiveName
$actionlintPath = Join-Path $toolRoot 'actionlint'
[void][IO.Directory]::CreateDirectory($toolRoot)

$downloadUri = (
    "https://github.com/rhysd/actionlint/releases/download/v$version/" +
    $archiveName
)
& curl `
    --fail `
    --location `
    --proto '=https' `
    --tlsv1.2 `
    --output $archivePath `
    $downloadUri
if ($LASTEXITCODE -ne 0) {
    throw "Could not download actionlint $version."
}
$actualSha256 = (
    Get-FileHash -LiteralPath $archivePath -Algorithm SHA256
).Hash.ToLowerInvariant()
if ($actualSha256 -cne $archiveSha256) {
    throw (
        "actionlint archive checksum mismatch: expected $archiveSha256, " +
        "received $actualSha256."
    )
}

& tar -xzf $archivePath -C $toolRoot actionlint
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $actionlintPath -PathType Leaf)) {
    throw 'Could not extract the pinned actionlint binary.'
}
& chmod 0700 $actionlintPath
if ($LASTEXITCODE -ne 0) {
    throw 'Could not restrict the actionlint executable permissions.'
}
$reportedVersion = @(& $actionlintPath -version 2>&1) -join "`n"
$reportedVersion = ($reportedVersion -replace '\s+', ' ').Trim()
$expectedVersionPrefix =
    "$version installed by downloading from release page built with "
if (
    $LASTEXITCODE -ne 0 -or
    -not $reportedVersion.StartsWith(
        $expectedVersionPrefix,
        [StringComparison]::Ordinal
    ) -or
    -not $reportedVersion.EndsWith(
        ' compiler for linux/amd64',
        [StringComparison]::Ordinal
    )
) {
    throw "Unexpected actionlint version: $reportedVersion"
}

$negativeFixture = Join-Path $toolRoot 'invalid-workflow.yml'
[IO.File]::WriteAllText(
    $negativeFixture,
    @'
name: Invalid fixture
on: push
jobs:
  invalid:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.ref && }}"
'@,
    [Text.UTF8Encoding]::new($false)
)
$negativeOutput = @(
    & $actionlintPath '-shellcheck=' '-pyflakes=' $negativeFixture 2>&1
)
if ($LASTEXITCODE -eq 0 -or $negativeOutput.Count -eq 0) {
    throw 'actionlint accepted the deterministic invalid workflow fixture.'
}

$workflowPaths = @(
    Get-ChildItem -LiteralPath $workflowRoot -File |
        Where-Object { $_.Extension -in @('.yml', '.yaml') } |
        Sort-Object FullName |
        ForEach-Object FullName
)
if ($workflowPaths.Count -eq 0) {
    throw 'Workflow syntax validation found no workflow files.'
}

# Shell commands have separate repository checks; this gate isolates workflow YAML,
# expression, action, and schema failures so it remains a fast independent signal.
& $actionlintPath '-shellcheck=' '-pyflakes=' @workflowPaths
if ($LASTEXITCODE -ne 0) {
    throw 'GitHub Actions workflow syntax validation failed.'
}

Write-Output (
    "Workflow syntax passed for $($workflowPaths.Count) file(s) with " +
    "actionlint $version."
)
