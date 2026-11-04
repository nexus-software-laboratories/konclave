#Requires -Version 7.0
<#
.SYNOPSIS
Checks report-target binding with synthetic classifier fixtures, not protocol evidence.
#>
[CmdletBinding()]
param([string] $ProfilePath)
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($ProfilePath)) {
    $ProfilePath = Join-Path $PSScriptRoot '..' '..' 'conformance' 'a2a' 'tck-v1.0.1.json'
}
$validator = Join-Path $PSScriptRoot 'Test-A2ATckProfile.ps1'
$profile = Get-Content -LiteralPath $ProfilePath -Raw | ConvertFrom-Json -Depth 30
$requirements = @{}
foreach ($id in $profile.supportedRequirements) {
    $requirements[$id] = @{ level = 'MUST'; status = 'PASS'; errors = @() }
}
foreach ($group in $profile.expectedInapplicablePasses) {
    foreach ($id in $group.requirements) {
        $requirements[$id] = @{ level = 'MUST'; status = 'PASS'; errors = @() }
    }
}
foreach ($group in $profile.allowedFailures) {
    foreach ($id in $group.requirements) {
        $requirements[$id] = @{
            level = 'MUST'; status = 'FAIL'; errors = @($group.expectedErrors.$id)
        }
    }
}
foreach ($group in $profile.expectedSkips) {
    foreach ($id in $group.requirements) {
        $requirements[$id] = @{ level = 'MUST'; status = 'SKIPPED'; errors = @() }
    }
}
foreach ($group in $profile.expectedNotTested) {
    foreach ($id in $group.requirements) {
        $requirements[$id] = @{ level = 'MUST'; status = 'NOT TESTED'; errors = @() }
    }
}
$fixture = @{
    summary = @{ sut_url = [string] $profile.execution.sutUrl }
    per_requirement = $requirements
}
$temporary = [IO.Directory]::CreateTempSubdirectory('konclave-tck-target-')
$reportPath = Join-Path $temporary.FullName 'synthetic-report.json'
function Save-Fixture {
    $fixture | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $reportPath -Encoding utf8NoBOM
}
function Assert-Rejected {
    param([scriptblock] $Operation, [string] $Message)
    try { & $Operation | Out-Null } catch {
        if ($_.Exception.Message -cnotlike "$Message*") { throw }
        return
    }
    throw 'Expected report-target rejection did not occur.'
}
try {
    Save-Fixture
    & $validator -ProfilePath $ProfilePath -ReportPath $reportPath | Out-Null
    $fixture.summary.sut_url = 'https://127.0.0.1:19999/'
    Save-Fixture
    Assert-Rejected { & $validator -ProfilePath $ProfilePath -ReportPath $reportPath } `
        'A2A TCK report targets an unexpected SUT URL.'
    & $validator -ProfilePath $ProfilePath -ReportPath $reportPath `
        -SutUrl $fixture.summary.sut_url | Out-Null
    Assert-Rejected {
        & $validator -ProfilePath $ProfilePath -ReportPath $reportPath -SutUrl 'https://127.0.0.1:20000/'
    } 'A2A TCK report targets an unexpected SUT URL.'
    Assert-Rejected {
        & $validator -ProfilePath $ProfilePath -SutUrl 'http://agent.example.com/'
    } 'A2A conformance requires HTTPS outside explicit loopback development.'
    $fixture.per_requirement[$profile.supportedRequirements[0]].status = 'FAIL'
    Save-Fixture
    Assert-Rejected {
        & $validator -ProfilePath $ProfilePath -ReportPath $reportPath -SutUrl $fixture.summary.sut_url
    } 'Supported A2A TCK requirement did not pass:'
} finally {
    $temporary.Delete($true)
}
Write-Output 'Six synthetic report-target/classification cases passed; no protocol execution is claimed.'
