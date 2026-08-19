#Requires -Version 7.0
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
$protoPath = Join-Path $repositoryRoot 'proto'
$temporaryRoot = Join-Path (
    [IO.Path]::GetTempPath()
) "konclave-protocol-format-$([Guid]::NewGuid().ToString('N'))"

try {
    & buf format $protoPath --output $temporaryRoot
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not format protocol schemas for comparison.'
    }

    $differences = [System.Collections.Generic.List[string]]::new()
    foreach ($source in Get-ChildItem $protoPath -Recurse -Filter '*.proto' -File) {
        $relativePath = [IO.Path]::GetRelativePath($protoPath, $source.FullName)
        $formattedPath = Join-Path $temporaryRoot $relativePath
        if (-not (Test-Path -LiteralPath $formattedPath -PathType Leaf)) {
            $differences.Add("$relativePath (missing from formatted output)")
            continue
        }

        $sourceText = (Get-Content $source.FullName -Raw).Replace("`r`n", "`n")
        $formattedText = (Get-Content $formattedPath -Raw).Replace("`r`n", "`n")
        if ($sourceText -cne $formattedText) {
            $differences.Add($relativePath)
        }
    }

    if ($differences.Count -gt 0) {
        throw (
            "Protocol schemas are not formatted: " +
            ($differences -join ', ') +
            '. Run buf format -w proto.'
        )
    }
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}
