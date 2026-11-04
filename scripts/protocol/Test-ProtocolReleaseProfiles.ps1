#Requires -Version 7.0
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
$temporary = Join-Path ([IO.Path]::GetTempPath()) (
    "konclave-protocol-profiles-$([Guid]::NewGuid().ToString('N'))"
)
$snapshot = Join-Path $temporary 'source'
$archive = Join-Path $temporary 'source.tar'
$relative = 'protocol/releases/protocol-v1.0.0-alpha.5.json'
$verifier = Join-Path $root 'scripts' 'protocol' 'Test-ProtocolRelease.ps1'

& $verifier -ProjectRoot $root -ManifestPath $relative
$tag = 'refs/tags/protocol-v1.0.0-alpha.5'
& git -C $root rev-parse --verify --quiet "$tag^{commit}" | Out-Null
if ($LASTEXITCODE -eq 0) {
    $source = $tag
}
elseif ($LASTEXITCODE -eq 1) {
    $source = 'HEAD'
}
else {
    throw 'Could not resolve the verified protocol-release fixture source.'
}

New-Item -ItemType Directory -Path $snapshot -Force | Out-Null
try {
    & git -C $root archive --format=tar "--output=$archive" $source
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not archive the submitted protocol-release source.'
    }
    & tar -xf $archive -C $snapshot
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not extract the protocol-release profile fixture.'
    }
    $original = Get-Content -LiteralPath (Join-Path $snapshot $relative) -Raw
    & $verifier -ProjectRoot $snapshot -ManifestPath $relative -CurrentTree

    $cases = @(
        @{
            Name = 'unknown protocol release'
            Tag = 'protocol-v1.0.0-alpha.999'
            Expected = '*has no profile for tag*'
            Mutate = { param($manifest) }
        }
        @{
            Name = 'missing A2A interoperability evidence'
            Tag = 'protocol-v1.0.0-alpha.5'
            Expected = '*missing the required A2A interoperability evidence*'
            Mutate = {
                param($manifest)
                $manifest.PSObject.Properties.Remove('interoperability')
            }
        }
        @{
            Name = 'substituted upstream SDK identity'
            Tag = 'protocol-v1.0.0-alpha.5'
            Expected = '*A2A identity does not match the selected public profile*'
            Mutate = {
                param($manifest)
                $manifest.interoperability.a2a.sdk.version = '0.0.0'
            }
        }
    )
    foreach ($case in $cases) {
        $manifest = $original | ConvertFrom-Json -Depth 100
        $manifest.release.tag = $case.Tag
        & $case.Mutate $manifest
        $candidate = "protocol/releases/$($case.Tag).json"
        $manifest | ConvertTo-Json -Depth 100 |
            Set-Content -LiteralPath (Join-Path $snapshot $candidate) -Encoding utf8NoBOM
        $rejected = $false
        try {
            & $verifier -ProjectRoot $snapshot -ManifestPath $candidate -CurrentTree
        }
        catch {
            if ($_.Exception.Message -notlike $case.Expected) {
                throw
            }
            $rejected = $true
        }
        if (-not $rejected) {
            throw "Protocol release verifier accepted $($case.Name)."
        }
        Write-Output "Protocol release profile refused $($case.Name)."
    }
}
finally {
    if (Test-Path -LiteralPath $temporary -PathType Container) {
        Remove-Item -LiteralPath $temporary -Recurse -Force
    }
}

Write-Output 'Protocol release profile regressions passed.'
