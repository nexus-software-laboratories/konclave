function Resolve-ProtocolBaseline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RepositoryRoot
    )

    $baseRef = 'refs/remotes/origin/main'
    git -C $RepositoryRoot rev-parse --verify $baseRef *> $null
    if ($LASTEXITCODE -eq 0) {
        return $baseRef
    }

    # Pull-request checkouts may contain only the exact head commit.
    git -C $RepositoryRoot fetch --no-tags --depth=1 origin `
        'refs/heads/main:refs/remotes/origin/main'
    if ($LASTEXITCODE -ne 0) {
        throw "Could not fetch required protocol baseline '$baseRef'."
    }

    git -C $RepositoryRoot rev-parse --verify $baseRef *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "Required protocol baseline '$baseRef' remains unavailable."
    }
    return $baseRef
}
