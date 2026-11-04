#Requires -Version 7.0
<#
.SYNOPSIS
Runs the pinned requirement profile against an explicitly owned external test SUT.
.DESCRIPTION
The caller supplies a clean pinned TCK checkout, its locked Python environment,
and a running synthetic-data SUT. This command starts no SUT and grants no native
authority. Use a fresh SUT for each isolated requirement and the complete suite.
Credentials are supplied only by a bounded file. Reports retain the exact target;
requirement classifications and upstream test sources remain unchanged.
.PARAMETER RequirementId
Runs one profile-declared isolated requirement; omission runs the complete profile.
.PARAMETER TrustedCaFile
An explicit PEM CA for hostname-verified HTTPS, never a private key or TLS bypass.
#>
[CmdletBinding()]
param(
    [string] $ProfilePath,
    [Parameter(Mandatory)][string] $TckRoot,
    [Parameter(Mandatory)][string] $PythonExecutable,
    [Parameter(Mandatory)][string] $SutUrl,
    [Parameter(Mandatory)][string] $OutputDirectory,
    [ValidateNotNullOrEmpty()][string] $Tenant,
    [ValidateNotNullOrEmpty()][string] $BearerTokenFile,
    [ValidateNotNullOrEmpty()][string] $TrustedCaFile,
    [string] $RequirementId
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
if ([string]::IsNullOrWhiteSpace($ProfilePath)) {
    $ProfilePath = Join-Path $repositoryRoot 'conformance' 'a2a' 'tck-v1.0.1.json'
}
$validator = Join-Path $PSScriptRoot 'Test-A2ATckProfile.ps1'
& $validator -ProfilePath $ProfilePath -TckRoot $TckRoot -SutUrl $SutUrl
$profile = Get-Content -LiteralPath $ProfilePath -Raw | ConvertFrom-Json -Depth 30
$output = [IO.Path]::GetFullPath($OutputDirectory)
$prefix = $repositoryRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) +
    [IO.Path]::DirectorySeparatorChar
if ($output -eq $repositoryRoot -or $output.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'External conformance output must be outside the repository.'
}
if (Test-Path -LiteralPath $output) {
    if (@(Get-ChildItem -LiteralPath $output -Force).Count -ne 0) {
        throw 'External conformance output must be empty.'
    }
} else {
    New-Item -ItemType Directory -Path $output | Out-Null
}
$isolated = @()
if (-not [string]::IsNullOrWhiteSpace($RequirementId)) {
    $isolated = @($profile.isolatedRequirements | Where-Object id -CEQ $RequirementId)
    if ($isolated.Count -ne 1) {
        throw 'The isolated conformance requirement is not declared by the pinned profile.'
    }
}
$environment = @{
    'A2A_TCK_SUT_URL' = $SutUrl
    'A2A_TCK_TENANT' = if ($PSBoundParameters.ContainsKey('Tenant')) { $Tenant } else { $null }
    'A2A_TCK_BEARER_TOKEN_FILE' = if ($PSBoundParameters.ContainsKey('BearerTokenFile')) { $BearerTokenFile } else { $null }
    'A2A_TCK_CA_FILE' = if ($PSBoundParameters.ContainsKey('TrustedCaFile')) { $TrustedCaFile } else { $null }
    'SSL_CERT_FILE' = if ($PSBoundParameters.ContainsKey('TrustedCaFile')) { $TrustedCaFile } else { $null }
    'PYTHONPATH' = $PSScriptRoot
    'PYTEST_ADDOPTS' = '-p a2a_tck_deployment'
    'HTTP_PROXY' = $null
    'HTTPS_PROXY' = $null
    'ALL_PROXY' = $null
}
$configured = [hashtable]::new([StringComparer]::Ordinal)
foreach ($key in $environment.Keys) { $configured[$key] = $environment[$key] }
foreach ($key in @('http_proxy', 'https_proxy', 'all_proxy')) { $configured[$key] = $null }
$environment = $configured
$original = [hashtable]::new([StringComparer]::Ordinal)
foreach ($key in $environment.Keys) {
    $original[$key] = [Environment]::GetEnvironmentVariable($key)
}
foreach ($key in $environment.Keys) {
    [Environment]::SetEnvironmentVariable($key, $environment[$key])
}
$reportPrefix = Join-Path $output 'compatibility'
$log = Join-Path $output 'tck.log'
Push-Location $TckRoot
try {
    if ($isolated.Count -eq 1) {
        & $PythonExecutable -m pytest ([string] $isolated[0].selector) `
            "--sut-host=$SutUrl" "--transport=$($profile.execution.transport)" `
            "--compatibility-report=$reportPrefix" -q *> $log
        if ($LASTEXITCODE -ne 0) { throw 'The isolated external conformance requirement failed.' }
        $reportPath = "$reportPrefix.json"
        $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json -Depth 30
        if (
            $report.summary.sut_url -cne $SutUrl -or
            $report.per_requirement.$RequirementId.status -cne 'PASS' -or
            $report.per_requirement.$RequirementId.level -cne 'MUST'
        ) { throw 'The isolated external conformance report lacks its required passing evidence.' }
    } else {
        # The unchanged classifier, not the upstream runner's known-gap exit code, owns this verdict.
        & $PythonExecutable (Join-Path $TckRoot 'run_tck.py') --sut-host $SutUrl `
            --transport ([string] $profile.execution.transport) `
            --level ([string] $profile.execution.level) `
            -- "--compatibility-report=$reportPrefix" *> $log
        $rawExit = $LASTEXITCODE
        $reportPath = "$reportPrefix.json"
        if (-not (Test-Path -LiteralPath $reportPath -PathType Leaf)) {
            if ($rawExit -eq 4) {
                Get-Content -LiteralPath $log -Tail 40 |
                    Where-Object { $_ -match '^ERROR: A2A TCK deployment: .{1,256}$' } |
                    ForEach-Object { Write-Output $_ }
            }
            throw "The pinned TCK produced no compatibility report (exit $rawExit); inspect tck.log."
        }
        & $validator -ProfilePath $ProfilePath -TckRoot $TckRoot `
            -ReportPath $reportPath -SutUrl $SutUrl
        Write-Output "Pinned external A2A TCK raw exit code: $rawExit"
    }
} finally {
    Pop-Location
    foreach ($key in $original.Keys) {
        [Environment]::SetEnvironmentVariable($key, $original[$key])
    }
}
Write-Output 'External A2A conformance evidence passed the unchanged requirement profile.'
