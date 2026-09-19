#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('pull_request', 'workflow_call', 'workflow_dispatch')]
    [string]$EventName,

    [ValidateRange(0, [int]::MaxValue)]
    [int]$PullRequestNumber = 0,

    [bool]$IsDraft = $false,
    [bool]$DemoWindowsOnly = $false
)

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'PackageValidationScope.Functions.ps1')

$changedFiles = @()
$conservative = $false
if ($EventName -eq 'pull_request' -and -not $IsDraft) {
    if ($PullRequestNumber -le 0) {
        $conservative = $true
        Write-Warning (
            'Pull-request number is unavailable; selecting full package validation.'
        )
    }
    else {
        try {
            $changedFiles = @(
                & gh api `
                    --paginate `
                    "repos/$env:GITHUB_REPOSITORY/pulls/$PullRequestNumber/files?per_page=100" `
                    --jq '.[] | .filename, (.previous_filename // empty)' 2>&1
            )
            if ($LASTEXITCODE -ne 0) {
                $conservative = $true
                $changedFiles = @()
                Write-Warning (
                    'Changed-file discovery failed; selecting full package validation.'
                )
            }
        }
        catch {
            $conservative = $true
            $changedFiles = @()
            Write-Warning (
                'Changed-file discovery failed; selecting full package validation.'
            )
        }
    }
}

$scope = Get-PackageValidationScope `
    -EventName $EventName `
    -IsDraft $IsDraft `
    -DemoWindowsOnly $DemoWindowsOnly `
    -ChangedFiles $changedFiles `
    -Conservative:$conservative

if ([string]::IsNullOrWhiteSpace($env:GITHUB_OUTPUT)) {
    throw 'GITHUB_OUTPUT is required to publish package validation scope.'
}
foreach ($entry in ([ordered]@{
    mode = $scope.Mode
    native = $scope.Native.ToString().ToLowerInvariant()
    plugin = $scope.Plugin.ToString().ToLowerInvariant()
    container = $scope.Container.ToString().ToLowerInvariant()
    release_set = $scope.ReleaseSet.ToString().ToLowerInvariant()
    acceptance = $scope.Acceptance.ToString().ToLowerInvariant()
}).GetEnumerator()) {
    "$($entry.Key)=$($entry.Value)" |
        Out-File -LiteralPath $env:GITHUB_OUTPUT -Append -Encoding utf8
}

Write-Output (
    "Package validation scope: mode=$($scope.Mode), native=$($scope.Native), " +
    "plugin=$($scope.Plugin), container=$($scope.Container), " +
    "releaseSet=$($scope.ReleaseSet), acceptance=$($scope.Acceptance)."
)
