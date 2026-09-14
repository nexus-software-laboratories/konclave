#Requires -Version 7.0
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'ActionsStoragePolicy.Functions.ps1')

function New-Cache {
    param(
        [long]$Id,
        [long]$Size,
        [string]$Ref = 'refs/heads/main',
        [string]$LastAccessed = '2026-09-14T00:00:00Z'
    )

    return [pscustomobject]@{
        id = $Id
        size_in_bytes = $Size
        ref = $Ref
        last_accessed_at = $LastAccessed
    }
}

$cases = @(
    @{
        name = 'empty'
        caches = @()
        budget = 100
        delete = @()
        retainedBytes = 0
    },
    @{
        name = 'trusted within budget'
        caches = @(
            New-Cache -Id 1 -Size 60
            New-Cache -Id 2 -Size 40
        )
        budget = 100
        delete = @()
        retainedBytes = 100
    },
    @{
        name = 'all pull request caches'
        caches = @(
            New-Cache -Id 1 -Size 40 -Ref 'refs/pull/1/merge'
            New-Cache -Id 2 -Size 60 -Ref 'refs/pull/2/merge'
        )
        budget = 1000
        delete = @(1, 2)
        retainedBytes = 0
    },
    @{
        name = 'oldest trusted caches until budget'
        caches = @(
            New-Cache -Id 1 -Size 40 -LastAccessed '2026-09-12T00:00:00Z'
            New-Cache -Id 2 -Size 40 -LastAccessed '2026-09-13T00:00:00Z'
            New-Cache -Id 3 -Size 40 -LastAccessed '2026-09-14T00:00:00Z'
        )
        budget = 80
        delete = @(1)
        retainedBytes = 80
    },
    @{
        name = 'pull requests before trusted eviction'
        caches = @(
            New-Cache -Id 1 -Size 20 -Ref 'refs/pull/1/merge'
            New-Cache -Id 2 -Size 60 -LastAccessed '2026-09-12T00:00:00Z'
            New-Cache -Id 3 -Size 60 -LastAccessed '2026-09-13T00:00:00Z'
        )
        budget = 60
        delete = @(1, 2)
        retainedBytes = 60
    },
    @{
        name = 'stable identifier tie break'
        caches = @(
            New-Cache -Id 2 -Size 60
            New-Cache -Id 1 -Size 60
        )
        budget = 60
        delete = @(1)
        retainedBytes = 60
    }
)

foreach ($case in $cases) {
    $result = Select-ActionsCacheDeletion `
        -Caches $case.caches `
        -BudgetBytes $case.budget
    $actualIds = @($result.deleteIds)
    $expectedIds = @($case.delete)
    if (
        ($actualIds -join ',') -cne ($expectedIds -join ',') -or
        [long]$result.retainedBytes -ne [long]$case.retainedBytes -or
        [int]$result.retainedCount -ne ($case.caches.Count - $expectedIds.Count)
    ) {
        throw "Actions cache selection failed: $($case.name)"
    }
}

foreach ($invalid in @(
    @{ caches = @(); budget = -1; error = 'budget' },
    @{
        caches = @(New-Cache -Id 0 -Size 1)
        budget = 1
        error = 'identifier'
    },
    @{
        caches = @(
            New-Cache -Id 1 -Size 1
            New-Cache -Id 1 -Size 1
        )
        budget = 1
        error = 'duplicated'
    },
    @{
        caches = @(New-Cache -Id 1 -Size -1)
        budget = 1
        error = 'negative'
    },
    @{
        caches = @(New-Cache -Id 1 -Size 1 -Ref '')
        budget = 1
        error = 'ref'
    },
    @{
        caches = @(New-Cache -Id 1 -Size 1 -LastAccessed 'invalid')
        budget = 1
        error = 'timestamp'
    }
)) {
    $failed = $false
    try {
        [void](Select-ActionsCacheDeletion `
            -Caches $invalid.caches `
            -BudgetBytes $invalid.budget)
    }
    catch {
        $failed = $_.Exception.Message.Contains([string]$invalid.error)
    }
    if (-not $failed) {
        throw "Invalid Actions cache input was not rejected: $($invalid.error)"
    }
}

Write-Output "Actions storage decision tests passed: $($cases.Count) finite cases."
