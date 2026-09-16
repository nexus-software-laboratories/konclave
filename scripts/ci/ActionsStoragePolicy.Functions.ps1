#Requires -Version 7.0

Set-StrictMode -Version Latest

function Select-ActionsArtifactDeletion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Artifacts,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Runs
    )

    $runsById = [Collections.Generic.Dictionary[long, object]]::new()
    foreach ($run in $Runs) {
        if ($null -eq $run) {
            throw 'Actions workflow run cannot be null.'
        }
        [long]$id = $run.id
        [string]$status = $run.status
        [string]$conclusion = $run.conclusion
        [string]$path = $run.path
        if ($id -le 0 -or $runsById.ContainsKey($id)) {
            throw "Actions workflow run identifier is invalid or duplicated: $id"
        }
        if ([string]::IsNullOrWhiteSpace($status)) {
            throw "Actions workflow run status is missing: $id"
        }
        if ([string]::IsNullOrWhiteSpace($path)) {
            throw "Actions workflow run path is missing: $id"
        }
        $eligible =
            $status -ceq 'completed' -and
            (
                $path -ceq '.github/workflows/agent-plugin-conformance.yml' -or
                $path -ceq '.github/workflows/package-validation.yml' -or
                (
                    $path -ceq '.github/workflows/publish-prerelease.yml' -and
                    $conclusion -ceq 'success'
                )
            )
        $runsById.Add($id, [pscustomobject]@{
            eligible = $eligible
        })
    }

    $seenArtifacts = [Collections.Generic.HashSet[long]]::new()
    $deleteIds = [Collections.Generic.List[long]]::new()
    [long]$deleteBytes = 0
    foreach ($artifact in $Artifacts) {
        if ($null -eq $artifact) {
            throw 'Actions artifact cannot be null.'
        }
        [long]$id = $artifact.id
        [long]$size = $artifact.size_in_bytes
        [long]$runId = $artifact.workflow_run.id
        if ($id -le 0 -or -not $seenArtifacts.Add($id)) {
            throw "Actions artifact identifier is invalid or duplicated: $id"
        }
        if ($size -lt 0) {
            throw "Actions artifact size cannot be negative: $id"
        }
        if ($runId -le 0 -or -not $runsById.ContainsKey($runId)) {
            throw "Actions artifact workflow run is invalid or missing: $id"
        }
        if ($runsById[$runId].eligible) {
            $deleteIds.Add($id)
            $deleteBytes += $size
        }
    }

    return [pscustomobject]@{
        deleteIds = @($deleteIds)
        deleteBytes = $deleteBytes
        retainedCount = $Artifacts.Count - $deleteIds.Count
    }
}

function Select-ActionsCacheDeletion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Caches,

        [Parameter(Mandatory)]
        [long]$BudgetBytes,

        [string]$TrustedRef = 'refs/heads/main'
    )

    if ($BudgetBytes -lt 0) {
        throw 'Actions cache budget cannot be negative.'
    }
    if ([string]::IsNullOrWhiteSpace($TrustedRef)) {
        throw 'Trusted Actions cache ref is required.'
    }

    $seen = [Collections.Generic.HashSet[long]]::new()
    $normalized = foreach ($cache in $Caches) {
        if ($null -eq $cache) {
            throw 'Actions cache entry cannot be null.'
        }
        [long]$id = $cache.id
        [long]$size = $cache.size_in_bytes
        [string]$ref = $cache.ref
        if ($id -le 0 -or -not $seen.Add($id)) {
            throw "Actions cache identifier is invalid or duplicated: $id"
        }
        if ($size -lt 0) {
            throw "Actions cache size cannot be negative: $id"
        }
        if ([string]::IsNullOrWhiteSpace($ref)) {
            throw "Actions cache ref is missing: $id"
        }
        try {
            $lastAccessed = [DateTimeOffset]$cache.last_accessed_at
        }
        catch {
            throw "Actions cache last-accessed timestamp is invalid: $id"
        }
        [pscustomobject]@{
            id = $id
            size = $size
            ref = $ref
            trusted = $ref -ceq $TrustedRef
            lastAccessed = $lastAccessed
        }
    }

    [long]$total = 0
    foreach ($cache in $normalized) {
        $total += $cache.size
    }
    $originalBytes = $total
    $deleteIds = [Collections.Generic.List[long]]::new()
    $ordered = @(
        $normalized |
            Sort-Object `
                @{ Expression = { $_.trusted } }, `
                @{ Expression = { $_.lastAccessed } }, `
                @{ Expression = { $_.id } }
    )
    foreach ($cache in $ordered) {
        if ($cache.trusted -and $total -le $BudgetBytes) {
            continue
        }
        $deleteIds.Add($cache.id)
        $total -= $cache.size
    }

    return [pscustomobject]@{
        deleteIds = @($deleteIds)
        originalBytes = $originalBytes
        retainedBytes = $total
        retainedCount = $Caches.Count - $deleteIds.Count
    }
}
