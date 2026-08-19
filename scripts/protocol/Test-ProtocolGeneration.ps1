#Requires -Version 7.0
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
$packageRoot = Join-Path $repositoryRoot 'packages' 'Konclave.ProtocolContracts.TypeScript'
$sourceRoot = Join-Path $packageRoot 'src' 'generated'
$templatePath = Join-Path $packageRoot 'buf.gen.yaml'
$temporaryRoot = Join-Path (
    [IO.Path]::GetTempPath()
) "konclave-protocol-generation-$([Guid]::NewGuid().ToString('N'))"
$generatedRoot = Join-Path $temporaryRoot 'generated'
$temporaryTemplate = Join-Path $temporaryRoot 'buf.gen.yaml'

try {
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
    $portableOutput = $generatedRoot.Replace('\', '/')
    $template = Get-Content -LiteralPath $templatePath -Raw
    $temporaryContent = $template -replace (
        '(?m)^(\s*out:\s*)src/generated\s*$'
    ), "`${1}'$portableOutput'"
    if ($temporaryContent -ceq $template) {
        throw 'Could not locate the generated output in buf.gen.yaml.'
    }
    Set-Content -LiteralPath $temporaryTemplate -Value $temporaryContent -Encoding utf8NoBOM

    Push-Location $packageRoot
    try {
        & buf generate --template $temporaryTemplate
        if ($LASTEXITCODE -ne 0) {
            throw 'Protocol binding generation failed.'
        }
    } finally {
        Pop-Location
    }

    $expected = @(
        Get-ChildItem -LiteralPath $sourceRoot -Recurse -Filter '*.ts' -File |
            ForEach-Object {
                [IO.Path]::GetRelativePath($sourceRoot, $_.FullName)
            } |
            Sort-Object
    )
    $actual = @(
        Get-ChildItem -LiteralPath $generatedRoot -Recurse -Filter '*.ts' -File |
            ForEach-Object {
                [IO.Path]::GetRelativePath($generatedRoot, $_.FullName)
            } |
            Sort-Object
    )
    if (($expected -join "`n") -cne ($actual -join "`n")) {
        throw 'Generated protocol binding file names are stale.'
    }

    foreach ($relativePath in $expected) {
        $expectedHash = (Get-FileHash -LiteralPath (
            Join-Path $sourceRoot $relativePath
        ) -Algorithm SHA256).Hash
        $actualHash = (Get-FileHash -LiteralPath (
            Join-Path $generatedRoot $relativePath
        ) -Algorithm SHA256).Hash
        if ($expectedHash -cne $actualHash) {
            throw "Generated protocol binding is stale: $relativePath"
        }
    }
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}
