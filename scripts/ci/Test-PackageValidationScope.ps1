#Requires -Version 7.0
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'PackageValidationScope.Functions.ps1')

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
$packageWorkflowPath = Join-Path `
    $repositoryRoot `
    '.github' `
    'workflows' `
    'package-validation.yml'
$workflowContent = Get-Content -LiteralPath $packageWorkflowPath -Raw
$directContainerScripts = @(
    [regex]::Matches(
        $workflowContent,
        'scripts/ci/[A-Za-z0-9._/-]+'
    ) |
        ForEach-Object Value |
        Where-Object { $_ -clike '*.sh' } |
        Sort-Object -CaseSensitive -Unique
)
$ownedContainerScripts = @(Get-PackageContainerScriptPaths)
foreach ($path in $ownedContainerScripts) {
    if (-not (Test-Path -LiteralPath (Join-Path $repositoryRoot $path) -PathType Leaf)) {
        throw "Package container scope references a missing script: $path"
    }
}
foreach ($path in $directContainerScripts) {
    if ($path -cnotin $ownedContainerScripts) {
        throw "Package workflow references an unowned container script: $path"
    }
}

$pluginOnlyFiles = @(
    'docs/development/collaboration-policies.md'
    'docs/development/copilot-delivery-safety.md'
    'docs/security/threat-model.md'
    'extensions/Konclave.HostExtension/src/runtime.ts'
    'extensions/Konclave.HostExtension/src/service/policy-enforcement.ts'
    'extensions/Konclave.HostExtension/src/service/tools.ts'
    'extensions/Konclave.HostExtension/tests/policy-enforcement.test.ts'
    'extensions/Konclave.HostExtension/tests/thin-client.test.ts'
)
$cases = @(
    @{
        Name = 'manual full release'
        Arguments = @{ EventName = 'workflow_dispatch' }
        Mode = 'full'
        Native = $true
        Plugin = $true
        Container = $true
        ReleaseSet = $true
        Acceptance = $true
    },
    @{
        Name = 'reusable full release'
        Arguments = @{ EventName = 'workflow_call' }
        Mode = 'full'
        Native = $true
        Plugin = $true
        Container = $true
        ReleaseSet = $true
        Acceptance = $true
    },
    @{
        Name = 'Windows demo'
        Arguments = @{
            EventName = 'workflow_dispatch'
            DemoWindowsOnly = $true
        }
        Mode = 'demo-windows'
        Native = $true
        Plugin = $false
        Container = $false
        ReleaseSet = $false
        Acceptance = $false
    },
    @{
        Name = 'draft pull request'
        Arguments = @{
            EventName = 'pull_request'
            IsDraft = $true
        }
        Mode = 'draft'
        Native = $false
        Plugin = $false
        Container = $false
        ReleaseSet = $false
        Acceptance = $false
    },
    @{
        Name = 'authorization plugin change'
        Arguments = @{
            EventName = 'pull_request'
            ChangedFiles = $pluginOnlyFiles
        }
        Mode = 'plugin'
        Native = $false
        Plugin = $true
        Container = $false
        ReleaseSet = $false
        Acceptance = $false
    },
    @{
        Name = 'container validation change'
        Arguments = @{
            EventName = 'pull_request'
            ChangedFiles = @('scripts/ci/container-validation.lib.sh')
        }
        Mode = 'container'
        Native = $false
        Plugin = $false
        Container = $true
        ReleaseSet = $false
        Acceptance = $false
    },
    @{
        Name = 'plugin and container change'
        Arguments = @{
            EventName = 'pull_request'
            ChangedFiles = @(
                'extensions/Konclave.HostExtension/src/runtime.ts'
                'scripts/ci/container-image.lib.sh'
            )
        }
        Mode = 'plugin-container'
        Native = $false
        Plugin = $true
        Container = $true
        ReleaseSet = $false
        Acceptance = $false
    },
    @{
        Name = 'unrelated CI evidence change'
        Arguments = @{
            EventName = 'pull_request'
            ChangedFiles = @(
                '.github/workflows/ci.yml'
                'docs/development/ci.md'
                'scripts/ci/CiPerformance.Functions.ps1'
            )
        }
        Mode = 'none'
        Native = $false
        Plugin = $false
        Container = $false
        ReleaseSet = $false
        Acceptance = $false
    },
    @{
        Name = 'workspace dependency change'
        Arguments = @{
            EventName = 'pull_request'
            ChangedFiles = @('Cargo.lock')
        }
        Mode = 'full'
        Native = $true
        Plugin = $true
        Container = $true
        ReleaseSet = $true
        Acceptance = $true
    },
    @{
        Name = 'package workflow change'
        Arguments = @{
            EventName = 'pull_request'
            ChangedFiles = @('.github/workflows/package-validation.yml')
        }
        Mode = 'full'
        Native = $true
        Plugin = $true
        Container = $true
        ReleaseSet = $true
        Acceptance = $true
    },
    @{
        Name = 'empty file discovery'
        Arguments = @{ EventName = 'pull_request' }
        Mode = 'full'
        Native = $true
        Plugin = $true
        Container = $true
        ReleaseSet = $true
        Acceptance = $true
    },
    @{
        Name = 'conservative fallback'
        Arguments = @{
            EventName = 'pull_request'
            ChangedFiles = @('extensions/Konclave.HostExtension/src/runtime.ts')
            Conservative = $true
        }
        Mode = 'full'
        Native = $true
        Plugin = $true
        Container = $true
        ReleaseSet = $true
        Acceptance = $true
    },
    @{
        Name = 'bounded inventory fallback'
        Arguments = @{
            EventName = 'pull_request'
            ChangedFiles = @(
                1..3000 | ForEach-Object { "docs/file-$_.md" }
            )
        }
        Mode = 'full'
        Native = $true
        Plugin = $true
        Container = $true
        ReleaseSet = $true
        Acceptance = $true
    }
)

foreach ($case in $cases) {
    $arguments = $case.Arguments
    $scope = Get-PackageValidationScope @arguments
    foreach ($property in @(
        'Mode',
        'Native',
        'Plugin',
        'Container',
        'ReleaseSet',
        'Acceptance'
    )) {
        if ($scope.$property -cne $case.$property) {
            throw (
                "Package validation scope '$($case.Name)' returned " +
                "$property=$($scope.$property); expected $($case.$property)."
            )
        }
    }
    Write-Output (
        "$($case.Name): mode=$($scope.Mode), native=$($scope.Native), " +
        "plugin=$($scope.Plugin), container=$($scope.Container), " +
        "releaseSet=$($scope.ReleaseSet), acceptance=$($scope.Acceptance)"
    )
}

Write-Output 'Package validation scope contract passed.'
