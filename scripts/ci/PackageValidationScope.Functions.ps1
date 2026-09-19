#Requires -Version 7.0

Set-StrictMode -Version Latest

function New-PackageValidationScope {
    param(
        [Parameter(Mandatory)]
        [string]$Mode,

        [bool]$Native = $false,
        [bool]$Plugin = $false,
        [bool]$Container = $false,
        [bool]$ReleaseSet = $false,
        [bool]$Acceptance = $false
    )

    return [pscustomobject]@{
        Mode = $Mode
        Native = $Native
        Plugin = $Plugin
        Container = $Container
        ReleaseSet = $ReleaseSet
        Acceptance = $Acceptance
    }
}

function Get-PackageContainerScriptPaths {
    return @(
        'scripts/ci/Capture-ContainerValidationBaseline.sh'
        'scripts/ci/Cleanup-HostedContainerImage.sh'
        'scripts/ci/Cleanup-JobPrivatePaths.sh'
        'scripts/ci/Initialize-JobPrivatePaths.sh'
        'scripts/ci/Test-A2AGatewayContainerContract.sh'
        'scripts/ci/Test-ContainerImageContract.sh'
        'scripts/ci/Test-ContainerValidationCleanup.sh'
        'scripts/ci/Validate-HostedContainerImage.sh'
        'scripts/ci/container-image.lib.sh'
        'scripts/ci/container-validation.lib.sh'
    )
}

function Get-PackageValidationScope {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('pull_request', 'workflow_call', 'workflow_dispatch')]
        [string]$EventName,

        [bool]$IsDraft = $false,
        [bool]$DemoWindowsOnly = $false,

        [AllowEmptyCollection()]
        [string[]]$ChangedFiles = @(),

        [switch]$Conservative
    )

    if ($DemoWindowsOnly) {
        return New-PackageValidationScope `
            -Mode 'demo-windows' `
            -Native $true
    }
    if ($EventName -ne 'pull_request') {
        return New-PackageValidationScope `
            -Mode 'full' `
            -Native $true `
            -Plugin $true `
            -Container $true `
            -ReleaseSet $true `
            -Acceptance $true
    }
    if ($IsDraft) {
        return New-PackageValidationScope -Mode 'draft'
    }

    $normalizedFiles = @(
        @(
            foreach ($changedFile in $ChangedFiles) {
                $normalized = ([string]$changedFile).Replace('\', '/')
                while ($normalized.StartsWith('./', [StringComparison]::Ordinal)) {
                    $normalized = $normalized.Substring(2)
                }
                $normalized = $normalized.TrimStart('/')
                if ($normalized) {
                    $normalized
                }
            }
        ) | Sort-Object -CaseSensitive -Unique
    )
    if ($Conservative -or $normalizedFiles.Count -eq 0 -or $normalizedFiles.Count -ge 3000) {
        return New-PackageValidationScope `
            -Mode 'full' `
            -Native $true `
            -Plugin $true `
            -Container $true `
            -ReleaseSet $true `
            -Acceptance $true
    }

    $fullPatterns = @(
        '^\.github/plugin/',
        '^\.github/workflows/package-validation\.yml$',
        '^Cargo\.(?:lock|toml)$',
        '^apps/Konclave\.(?:A2AGateway|CommandLine|CommunityRelay|LocalDaemon)/',
        '^crates/',
        '^distribution/',
        '^plugins/konclave/',
        '^scripts/CargoLock\.Functions\.ps1$',
        '^scripts/installation/',
        '^scripts/marketplace/',
        '^scripts/packaging/'
    )
    $packageOwnedPatterns = @(
        '^\.github/plugin/',
        '^\.github/workflows/package-validation\.yml$',
        '^Cargo\.(?:lock|toml)$',
        '^apps/Konclave\.(?:A2AGateway|CommandLine|CommunityRelay|LocalDaemon)/',
        '^crates/',
        '^distribution/',
        '^docs/distribution/',
        '^extensions/Konclave\.HostExtension/',
        '^plugins/konclave/',
        '^scripts/CargoLock\.Functions\.ps1$',
        '^scripts/ci/',
        '^scripts/installation/',
        '^scripts/marketplace/',
        '^scripts/packaging/'
    )
    $containerScripts = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    foreach ($path in Get-PackageContainerScriptPaths) {
        [void]$containerScripts.Add($path)
    }

    $plugin = $false
    $container = $false
    foreach ($path in $normalizedFiles) {
        if (@($fullPatterns | Where-Object { $path -cmatch $_ }).Count -ne 0) {
            return New-PackageValidationScope `
                -Mode 'full' `
                -Native $true `
                -Plugin $true `
                -Container $true `
                -ReleaseSet $true `
                -Acceptance $true
        }
        if ($path -cmatch '^extensions/Konclave\.HostExtension/') {
            $plugin = $true
            continue
        }
        if ($containerScripts.Contains($path)) {
            $container = $true
            continue
        }
        if (
            $path -cmatch '^docs/distribution/' -or
            $path -cmatch '^scripts/ci/'
        ) {
            continue
        }
        if (@($packageOwnedPatterns | Where-Object { $path -cmatch $_ }).Count -ne 0) {
            return New-PackageValidationScope `
                -Mode 'full' `
                -Native $true `
                -Plugin $true `
                -Container $true `
                -ReleaseSet $true `
                -Acceptance $true
        }
    }

    if ($plugin -and $container) {
        return New-PackageValidationScope `
            -Mode 'plugin-container' `
            -Plugin $true `
            -Container $true
    }
    if ($plugin) {
        return New-PackageValidationScope -Mode 'plugin' -Plugin $true
    }
    if ($container) {
        return New-PackageValidationScope -Mode 'container' -Container $true
    }
    return New-PackageValidationScope -Mode 'none'
}
