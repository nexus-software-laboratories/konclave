#Requires -Version 7.0
<#
.SYNOPSIS
    Applies the public Konclave repository's GitHub Actions security baseline.

.PARAMETER Repository
    Public GitHub repository in owner/name form.

.EXAMPLE
    ./scripts/delivery/Configure-PublicRepositorySecurity.ps1 `
        -Repository <owner>/<repository>

.EXAMPLE
    ./scripts/delivery/Configure-PublicRepositorySecurity.ps1 `
        -Repository <owner>/<repository> `
        -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')]
    [string]$Repository
)

$ErrorActionPreference = 'Stop'

$gh = (Get-Command gh -ErrorAction Stop).Source
$caller = $PSCmdlet
$repositoryState = & $gh api "repos/$Repository" | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) {
    throw "Could not read repository '$Repository'."
}
if ([string]$repositoryState.visibility -cne 'public') {
    throw "Repository '$Repository' must be public."
}

function Invoke-GitHubJsonRequest {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('PATCH', 'PUT')]
        [string]$Method,

        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [hashtable]$Body,

        [Parameter(Mandatory)]
        [string]$Description
    )

    if (-not $caller.ShouldProcess($Path, $Description)) {
        return
    }

    $temporaryPath = Join-Path (
        [IO.Path]::GetTempPath()
    ) "konclave-github-security-$([Guid]::NewGuid().ToString('N')).json"
    try {
        [IO.File]::WriteAllText(
            $temporaryPath,
            ($Body | ConvertTo-Json -Depth 10 -Compress),
            [Text.UTF8Encoding]::new($false))
        & $gh api `
            --method $Method `
            -H 'X-GitHub-Api-Version: 2022-11-28' `
            $Path `
            --input $temporaryPath *> $null
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to $Description."
        }
    } finally {
        # This run-scoped file contains only the non-secret request body.
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
    }
}

Invoke-GitHubJsonRequest `
    -Method PUT `
    -Path "repos/$Repository/actions/permissions" `
    -Description 'restrict enabled Actions and require immutable action references' `
    -Body @{
        enabled = $true
        allowed_actions = 'selected'
        sha_pinning_required = $true
    }

Invoke-GitHubJsonRequest `
    -Method PUT `
    -Path "repos/$Repository/actions/permissions/selected-actions" `
    -Description 'allow only reviewed external Actions' `
    -Body @{
        github_owned_allowed = $true
        verified_allowed = $false
        patterns_allowed = @(
            'dtolnay/rust-toolchain@*',
            'Swatinem/rust-cache@*'
        )
    }

Invoke-GitHubJsonRequest `
    -Method PUT `
    -Path "repos/$Repository/actions/permissions/workflow" `
    -Description 'set read-only workflow token defaults' `
    -Body @{
        default_workflow_permissions = 'read'
        can_approve_pull_request_reviews = $false
    }

Invoke-GitHubJsonRequest `
    -Method PUT `
    -Path "repos/$Repository/actions/permissions/fork-pr-contributor-approval" `
    -Description 'require approval for every external contributor workflow' `
    -Body @{
        approval_policy = 'all_external_contributors'
    }

Invoke-GitHubJsonRequest `
    -Method PATCH `
    -Path "repos/$Repository" `
    -Description 'enable public security analysis and squash-only delivery' `
    -Body @{
        allow_merge_commit = $false
        allow_rebase_merge = $false
        allow_squash_merge = $true
        delete_branch_on_merge = $true
        security_and_analysis = @{
            dependabot_security_updates = @{ status = 'enabled' }
            secret_scanning = @{ status = 'enabled' }
            secret_scanning_non_provider_patterns = @{ status = 'enabled' }
            secret_scanning_push_protection = @{ status = 'enabled' }
            secret_scanning_validity_checks = @{ status = 'enabled' }
        }
    }

Invoke-GitHubJsonRequest `
    -Method PUT `
    -Path "repos/$Repository/vulnerability-alerts" `
    -Description 'enable dependency vulnerability alerts' `
    -Body @{}

Invoke-GitHubJsonRequest `
    -Method PUT `
    -Path "repos/$Repository/private-vulnerability-reporting" `
    -Description 'enable private vulnerability reporting' `
    -Body @{}

[PSCustomObject]@{
    Repository = $Repository
    ForkApproval = 'all_external_contributors'
    WorkflowPermissions = 'read'
    AllowedActions = 'selected'
    PrivateVulnerabilityReporting = $true
    ShaPinningRequired = $true
}
