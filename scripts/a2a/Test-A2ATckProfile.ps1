#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $ProfilePath,

    [string] $TckRoot,

    [string] $ReportPath
)

$ErrorActionPreference = 'Stop'

$resolvedProfilePath = (Resolve-Path -LiteralPath $ProfilePath).Path
$repositoryRoot = (
    Resolve-Path (Join-Path (Split-Path $resolvedProfilePath -Parent) '..' '..')
).Path
$profile = Get-Content -LiteralPath $resolvedProfilePath -Raw -Encoding UTF8 |
    ConvertFrom-Json -Depth 30

if (
    [int64] $profile.schemaVersion -ne 1 -or
    [string] $profile.profileId -cne 'a2a-v1.0.1-http-json-must' -or
    [string] $profile.protocol.repository -cne 'https://github.com/a2aproject/A2A' -or
    [string] $profile.protocol.release -cne 'v1.0.1' -or
    [string] $profile.protocol.protocolVersion -cne '1.0' -or
    [string] $profile.protocol.commit -cne '3303592588e388e62e0f69f701af531d2f4e3991' -or
    [string] $profile.tck.repository -cne 'https://github.com/a2aproject/a2a-tck' -or
    [string] $profile.tck.commit -cne '263b9cfaf16a554bdfb166a7ba5b67716e946349' -or
    [string] $profile.tck.version -cne '1.0.0' -or
    [string] $profile.tck.license -cne 'Apache-2.0' -or
    [string] $profile.tck.uvVersion -cne '0.11.7' -or
    [string] $profile.tck.uvArtifact.filename -cne 'uv-0.11.7-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl' -or
    [string] $profile.tck.uvArtifact.sha256 -cne '4e4d5e31bea86e1b6e0f5a0f95e14e80018e6f6c0129256d2915a4b3d793644d' -or
    [string] $profile.tck.specification.release -cne 'v1.0.0' -or
    [string] $profile.tck.specification.commit -cne '173695755607e884aa9acf8ce4feed90e32727a1' -or
    [string] $profile.execution.transport -cne 'http_json' -or
    [string] $profile.execution.level -cne 'must' -or
    [string] $profile.execution.sutUrl -cne 'http://127.0.0.1:9999' -or
    [string] $profile.sdkInterop.repository -cne 'https://github.com/a2aproject/a2a-python' -or
    [string] $profile.sdkInterop.release -cne 'v1.0.3' -or
    [string] $profile.sdkInterop.commit -cne '8a82061571142b12745576c972bf07077930a4ff' -or
    [string] $profile.sdkInterop.package -cne 'a2a-sdk' -or
    [string] $profile.sdkInterop.version -cne '1.0.3' -or
    [string] $profile.sdkInterop.license -cne 'Apache-2.0' -or
    [string] $profile.sdkInterop.sdistSha256 -cne 'c57ddd910aece4a426ae26b8f0d0e8e2f3271a6adde974078075e4f600aaf628' -or
    [string] $profile.sdkInterop.project -cne 'conformance/a2a/python-sdk'
) {
    throw 'A2A TCK profile identity changed without a versioned conformance update.'
}

$expectedFiles = @(
    'LICENSE',
    'pyproject.toml',
    'run_tck.py',
    'specification/version.json',
    'uv.lock'
)
$files = @($profile.tck.files)
$actualFiles = @($files | ForEach-Object { [string] $_.path } | Sort-Object)
if (($actualFiles -join "`n") -cne (($expectedFiles | Sort-Object) -join "`n")) {
    throw 'A2A TCK profile contains an unexpected provenance file set.'
}
foreach ($file in $files) {
    if (
        [string] $file.path -notmatch '^[A-Za-z0-9._/-]+$' -or
        [string] $file.path -match '(^|/)\.\.(/|$)' -or
        [int64] $file.bytes -le 0 -or
        [string] $file.sha256 -notmatch '^[0-9a-f]{64}$'
    ) {
        throw "A2A TCK provenance entry is invalid: $($file.path)"
    }
}

$expectedSdkFiles = @(
    'interop.py',
    'pyproject.toml',
    'uv.lock'
)

function Get-CanonicalRepositoryText {
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    $text = [IO.File]::ReadAllText($Path).Replace("`r`n", "`n")
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($text)
    return [PSCustomObject]@{
        Bytes = $bytes.Length
        Sha256 = [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($bytes)
        ).ToLowerInvariant()
    }
}

function Get-GitBlobMeasurement {
    param(
        [Parameter(Mandatory)]
        [string] $RepositoryRoot,

        [Parameter(Mandatory)]
        [string] $Revision,

        [Parameter(Mandatory)]
        [string] $Path
    )

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = 'git'
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in @('-C', $RepositoryRoot, 'cat-file', 'blob', "${Revision}:$Path")) {
        [void] $startInfo.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::Start($startInfo)
    if ($null -eq $process) {
        throw 'Could not start Git while validating A2A TCK provenance.'
    }
    $content = [IO.MemoryStream]::new()
    try {
        $process.StandardOutput.BaseStream.CopyTo($content)
        $errorText = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) {
            throw "Could not read pinned A2A TCK blob '$Path': $errorText"
        }
        $bytes = $content.ToArray()
        return [PSCustomObject]@{
            Bytes = $bytes.Length
            Sha256 = [Convert]::ToHexString(
                [Security.Cryptography.SHA256]::HashData($bytes)
            ).ToLowerInvariant()
        }
    }
    finally {
        $content.Dispose()
        $process.Dispose()
    }
}

$sdkFiles = @($profile.sdkInterop.files)
$actualSdkFiles = @($sdkFiles | ForEach-Object { [string] $_.path } | Sort-Object)
if (($actualSdkFiles -join "`n") -cne (($expectedSdkFiles | Sort-Object) -join "`n")) {
    throw 'A2A Python SDK profile contains an unexpected file set.'
}
foreach ($file in $sdkFiles) {
    if (
        [string] $file.path -notmatch '^[A-Za-z0-9._/-]+$' -or
        [string] $file.path -match '(^|/)\.\.(/|$)' -or
        [int64] $file.bytes -le 0 -or
        [string] $file.sha256 -notmatch '^[0-9a-f]{64}$'
    ) {
        throw "A2A Python SDK profile entry is invalid: $($file.path)"
    }
    $path = Join-Path $repositoryRoot ([string] $profile.sdkInterop.project) ([string] $file.path)
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Pinned A2A Python SDK interoperability file is missing: $($file.path)"
    }
    $canonical = Get-CanonicalRepositoryText -Path $path
    if ($canonical.Bytes -ne [int64] $file.bytes) {
        throw "Pinned A2A Python SDK interoperability file length changed: $($file.path)"
    }
    if ($canonical.Sha256 -cne [string] $file.sha256) {
        throw "Pinned A2A Python SDK interoperability file digest changed: $($file.path)"
    }
}
$sdkLock = Get-Content -LiteralPath (
    Join-Path $repositoryRoot ([string] $profile.sdkInterop.project) 'uv.lock'
) -Raw -Encoding UTF8
if (
    $sdkLock -notmatch '(?ms)^\[\[package\]\]\s+name = "a2a-sdk"\s+version = "1\.0\.3"' -or
    $sdkLock -notmatch [regex]::Escape("sha256:$($profile.sdkInterop.sdistSha256)")
) {
    throw 'A2A Python SDK lockfile does not contain the pinned package artifact.'
}

$workflowPath = Join-Path $repositoryRoot '.github' 'workflows' 'a2a-conformance.yml'
$workflow = Get-Content -LiteralPath $workflowPath -Raw -Encoding UTF8
$uvRequirement = (
    "uv==$($profile.tck.uvVersion) --hash=sha256:$($profile.tck.uvArtifact.sha256)"
)
if (
    $workflow -notmatch '(?m)^\s+types: \[opened, edited, synchronize, reopened, ready_for_review, converted_to_draft\]\s*$' -or
    $workflow -notmatch '(?m)^\s+cancel-in-progress: true\s*$' -or
    $workflow -notmatch '(?m)^\s+runs-on: ubuntu-latest\s*$' -or
    $workflow -match '\b(?:self-hosted|general-purpose|automation-control)\b' -or
    $workflow -notmatch [regex]::Escape($uvRequirement) -or
    $workflow -notmatch '(?m)^\s+contents: read\s*$' -or
    $workflow -notmatch '(?m)^\s+pull-requests: read\s*$'
) {
    throw 'A2A conformance workflow drifted from the hosted, draft-aware profile.'
}

$delivery = Get-Content -LiteralPath (
    Join-Path $repositoryRoot '.github' 'genesis-delivery.json'
) -Raw -Encoding UTF8 | ConvertFrom-Json -Depth 20
$hostedProfile = @(
    $delivery.runnerProfiles |
        Where-Object id -ceq 'ubuntu-latest-hosted'
)
$component = @(
    $delivery.componentWorkflows |
        Where-Object path -ceq '.github/workflows/a2a-conformance.yml'
)
if (
    @($delivery.requiredChecks) -cnotcontains 'A2A conformance' -or
    $hostedProfile.Count -ne 1 -or
    @($hostedProfile[0].jobs) -cnotcontains 'a2a-conformance' -or
    $component.Count -ne 1 -or
    @($component[0].roles) -cnotcontains 'merge-gate' -or
    [string]$component[0].draftBehavior -cne 'ready-only' -or
    @($component[0].requiredChecks) -cnotcontains 'A2A conformance'
) {
    throw 'A2A conformance delivery metadata is incomplete.'
}

$allowedClassifications = @(
    'mixed-known-gap',
    'profile-exclusion',
    'tck-protocol-version-mismatch',
    'upstream-suite-state-collision',
    'upstream-validator-defect'
)
$skipClassifications = @(
    'profile-exclusion',
    'sut-capability-not-enabled',
    'tck-scenario-not-exercised',
    'transport-filter'
)
$notTestedClassifications = @(
    'transport-filter-not-tested',
    'upstream-test-not-implemented'
)
$inapplicablePassClassifications = @(
    'conditional-not-exercised',
    'transport-static-pass'
)

function Get-RequirementIds {
    param(
        [Parameter(Mandatory)]
        [object[]] $Groups,

        [Parameter(Mandatory)]
        [string[]] $Classifications
    )

    $ids = @()
    foreach ($group in $Groups) {
        if (
            [string] $group.classification -cnotin $Classifications -or
            [string]::IsNullOrWhiteSpace([string] $group.rationale)
        ) {
            throw 'A2A TCK classification is invalid or lacks a rationale.'
        }
        $groupIds = @($group.requirements)
        if ($groupIds.Count -eq 0) {
            throw 'A2A TCK classification contains no requirements.'
        }
        foreach ($id in $groupIds) {
            if ([string] $id -notmatch '^[A-Za-z0-9_]+(?:-[A-Za-z0-9_]+)+$') {
                throw "A2A TCK requirement identifier is invalid: $id"
            }
            $ids += [string] $id
        }
    }
    return $ids
}

$supportedIds = @($profile.supportedRequirements | ForEach-Object { [string] $_ })
foreach ($id in $supportedIds) {
    if ($id -notmatch '^[A-Za-z0-9_]+(?:-[A-Za-z0-9_]+)+$') {
        throw "Supported A2A TCK requirement identifier is invalid: $id"
    }
}
$expectedFailureErrors = @{}
foreach ($group in $profile.allowedFailures) {
    $evidence = @($group.evidence)
    if (
        $evidence.Count -eq 0 -or
        @($evidence | Where-Object { [string]::IsNullOrWhiteSpace([string] $_) }).Count -ne 0
    ) {
        throw 'Every allowed A2A TCK failure must cite concrete evidence.'
    }
    $groupIds = @($group.requirements | ForEach-Object { [string] $_ } | Sort-Object)
    $errorIds = @(
        $group.expectedErrors.PSObject.Properties |
            ForEach-Object Name |
            Sort-Object
    )
    if (($groupIds -join "`n") -cne ($errorIds -join "`n")) {
        throw 'Every allowed A2A TCK failure must define its expected error evidence.'
    }
    foreach ($property in $group.expectedErrors.PSObject.Properties) {
        $errors = @($property.Value | ForEach-Object { [string] $_ })
        if (
            $errors.Count -eq 0 -or
            @($errors | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count -ne 0
        ) {
            throw "Allowed A2A TCK failure has invalid error evidence: $($property.Name)"
        }
        $expectedFailureErrors[$property.Name] = $errors
    }
}
$expectedInapplicablePassIds = @(
    Get-RequirementIds `
        -Groups @($profile.expectedInapplicablePasses) `
        -Classifications $inapplicablePassClassifications
)
$allowedFailureIds = @(
    Get-RequirementIds -Groups @($profile.allowedFailures) -Classifications $allowedClassifications
)
$expectedSkipIds = @(
    Get-RequirementIds -Groups @($profile.expectedSkips) -Classifications $skipClassifications
)
$expectedNotTestedIds = @(
    Get-RequirementIds `
        -Groups @($profile.expectedNotTested) `
        -Classifications $notTestedClassifications
)
$allClassifiedIds = @(
    $supportedIds +
    $expectedInapplicablePassIds +
    $allowedFailureIds +
    $expectedSkipIds +
    $expectedNotTestedIds
)
$duplicates = @(
    $allClassifiedIds |
        Group-Object |
        Where-Object Count -gt 1 |
        ForEach-Object Name
)
if ($duplicates.Count -ne 0) {
    throw "A2A TCK requirements are classified more than once: $($duplicates -join ', ')"
}

$stateCollisionIds = @(
    $profile.allowedFailures |
        Where-Object classification -ceq 'upstream-suite-state-collision' |
        ForEach-Object requirements
)
$isolatedIds = @($profile.isolatedRequirements | ForEach-Object { [string] $_.id })
if (
    (($stateCollisionIds | Sort-Object) -join "`n") -cne
    (($isolatedIds | Sort-Object) -join "`n")
) {
    throw 'Every suite-state collision must have one isolated passing requirement.'
}
foreach ($isolated in $profile.isolatedRequirements) {
    if (
        [string]::IsNullOrWhiteSpace([string] $isolated.selector) -or
        [string] $isolated.selector -notmatch '^tests/compatibility/'
    ) {
        throw "A2A TCK isolated selector is invalid: $($isolated.id)"
    }
}

if (-not [string]::IsNullOrWhiteSpace($TckRoot)) {
    $resolvedTckRoot = (Resolve-Path -LiteralPath $TckRoot).Path
    $head = (& git -C $resolvedTckRoot rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $head -cne [string] $profile.tck.commit) {
        throw 'A2A TCK checkout does not match the pinned commit.'
    }
    $trackedChanges = @(
        git -C $resolvedTckRoot status --porcelain --untracked-files=no
    )
    if ($LASTEXITCODE -ne 0 -or $trackedChanges.Count -ne 0) {
        throw 'A2A TCK checkout contains tracked modifications.'
    }
    foreach ($file in $files) {
        $path = Join-Path $resolvedTckRoot ([string] $file.path)
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Pinned A2A TCK file is missing: $($file.path)"
        }
        $blob = Get-GitBlobMeasurement `
            -RepositoryRoot $resolvedTckRoot `
            -Revision $head `
            -Path ([string] $file.path)
        if ($blob.Bytes -ne [int64] $file.bytes) {
            throw "Pinned A2A TCK file length changed: $($file.path)"
        }
        if ($blob.Sha256 -cne [string] $file.sha256) {
            throw "Pinned A2A TCK file digest changed: $($file.path)"
        }
    }
}

if (-not [string]::IsNullOrWhiteSpace($ReportPath)) {
    $resolvedReportPath = (Resolve-Path -LiteralPath $ReportPath).Path
    $report = Get-Content -LiteralPath $resolvedReportPath -Raw -Encoding UTF8 |
        ConvertFrom-Json -Depth 30
    if ([string] $report.summary.sut_url -cne [string] $profile.execution.sutUrl) {
        throw 'A2A TCK report targets an unexpected SUT URL.'
    }

    $requirements = @{}
    foreach ($property in $report.per_requirement.PSObject.Properties) {
        $requirements[$property.Name] = $property.Value
    }

    foreach ($id in $supportedIds) {
        if (-not $requirements.ContainsKey($id)) {
            throw "Supported A2A TCK requirement is absent from the report: $id"
        }
        if (
            [string] $requirements[$id].level -cne 'MUST' -or
            [string] $requirements[$id].status -cne 'PASS'
        ) {
            throw "Supported A2A TCK requirement did not pass: $id"
        }
    }
    foreach ($id in $expectedInapplicablePassIds) {
        if (-not $requirements.ContainsKey($id)) {
            throw "Expected inapplicable A2A TCK pass is absent from the report: $id"
        }
        if (
            [string] $requirements[$id].level -cne 'MUST' -or
            [string] $requirements[$id].status -cne 'PASS'
        ) {
            throw "Expected inapplicable A2A TCK pass changed and must be reclassified: $id"
        }
    }
    foreach ($id in $allowedFailureIds) {
        if (-not $requirements.ContainsKey($id)) {
            throw "Allowed A2A TCK failure is absent from the report: $id"
        }
        if (
            [string] $requirements[$id].level -cne 'MUST' -or
            [string] $requirements[$id].status -cne 'FAIL' -or
            @($requirements[$id].errors).Count -eq 0
        ) {
            throw "Allowed A2A TCK failure changed and must be reclassified: $id"
        }
        $expectedErrors = @($expectedFailureErrors[$id] | Sort-Object)
        $actualErrors = @($requirements[$id].errors | ForEach-Object { [string] $_ } | Sort-Object)
        if (($actualErrors -join "`n") -cne ($expectedErrors -join "`n")) {
            throw "Allowed A2A TCK failure reasons changed and must be reclassified: $id"
        }
    }
    foreach ($id in $expectedSkipIds) {
        if (-not $requirements.ContainsKey($id)) {
            throw "Expected A2A TCK skip is absent from the report: $id"
        }
        if (
            [string] $requirements[$id].level -cne 'MUST' -or
            [string] $requirements[$id].status -cne 'SKIPPED'
        ) {
            throw "Expected A2A TCK skip changed and must be reclassified: $id"
        }
    }
    foreach ($id in $expectedNotTestedIds) {
        if (-not $requirements.ContainsKey($id)) {
            throw "Expected untested A2A TCK requirement is absent from the report: $id"
        }
        if (
            [string] $requirements[$id].level -cne 'MUST' -or
            [string] $requirements[$id].status -cne 'NOT TESTED'
        ) {
            throw "Expected untested A2A TCK requirement changed and must be reclassified: $id"
        }
    }

    $reportedMustIds = @(
        $requirements.GetEnumerator() |
            Where-Object { [string] $_.Value.level -ceq 'MUST' } |
            ForEach-Object Key |
            Sort-Object
    )
    $classifiedMustIds = @($allClassifiedIds | Sort-Object)
    if (($reportedMustIds -join "`n") -cne ($classifiedMustIds -join "`n")) {
        throw 'A2A TCK report contains missing or unclassified MUST requirements.'
    }

    Write-Output (
        "A2A TCK report passed the strict profile: " +
        "$($supportedIds.Count) supported, " +
        "$($expectedInapplicablePassIds.Count) inapplicable passes, " +
        "$($allowedFailureIds.Count) allowed failures, " +
        "$($expectedSkipIds.Count) expected skips, " +
        "$($expectedNotTestedIds.Count) expected untested."
    )
    return
}

Write-Output 'A2A conformance profile provenance passed.'
