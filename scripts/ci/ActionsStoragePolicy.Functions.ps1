#Requires -Version 7.0

Set-StrictMode -Version Latest

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
