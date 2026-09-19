#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Contract,

    [Parameter(Mandatory)]
    [ValidateSet('pull_request', 'workflow_dispatch')]
    [string]$EventName,

    [ValidateRange(0, [int]::MaxValue)]
    [int]$PullRequestNumber = 0
)

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'ComponentValidationScope.Functions.ps1')

$changedFiles = @()
$conservative = $false
if ($EventName -eq 'pull_request') {
    if ($PullRequestNumber -le 0) {
        $conservative = $true
        Write-Warning (
            'Pull-request number is unavailable; selecting component validation.'
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
                    'Changed-file discovery failed; selecting component validation.'
                )
            }
        }
        catch {
            $conservative = $true
            $changedFiles = @()
            Write-Warning (
                'Changed-file discovery failed; selecting component validation.'
            )
        }
    }
}

$run = Get-ComponentValidationDecision `
    -Contract $Contract `
    -EventName $EventName `
    -ChangedFiles $changedFiles `
    -Conservative:$conservative

if ([string]::IsNullOrWhiteSpace($env:GITHUB_OUTPUT)) {
    throw 'GITHUB_OUTPUT is required to publish component validation scope.'
}
"run=$($run.ToString().ToLowerInvariant())" |
    Out-File -LiteralPath $env:GITHUB_OUTPUT -Append -Encoding utf8
Write-Output "Component validation scope: contract=$Contract, run=$run."
