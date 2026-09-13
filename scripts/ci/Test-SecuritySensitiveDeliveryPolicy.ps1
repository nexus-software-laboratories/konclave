#Requires -Version 7.0
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
$paths = [ordered]@{
    Agents = 'AGENTS.md'
    Documentation = 'docs/development/security-sensitive-delivery.md'
    DocumentationMap = 'docs/README.md'
    GuidanceMap = '.github/genesis-guidance.json'
    Instruction = '.github/instructions/security-sensitive-delivery.instructions.md'
    ReviewSkill = '.github/skills/review-changes/SKILL.md'
    DeliverySkill = '.github/skills/security-sensitive-delivery/SKILL.md'
    Delivery = '.github/genesis-delivery.json'
    Workflow = '.github/workflows/ci.yml'
}

foreach ($relative in $paths.Values) {
    if (-not (Test-Path -LiteralPath (Join-Path $root $relative) -PathType Leaf)) {
        throw "Security-sensitive delivery policy file is missing: $relative"
    }
}

$agents = Get-Content -LiteralPath (Join-Path $root $paths.Agents) -Raw
if (
    -not $agents.Contains(
        '[security-sensitive-delivery](.github/skills/security-sensitive-delivery/SKILL.md)'
    )
) {
    throw 'AGENTS.md does not route new security-sensitive components through the delivery skill.'
}

$instruction = Get-Content -LiteralPath (Join-Path $root $paths.Instruction) -Raw
foreach ($required in @(
    'Cargo.toml',
    'crates/**/Cargo.toml',
    'apps/Konclave.LocalDaemon/**/*.rs',
    '.github/workflows/**/*.yml',
    'exact foundation',
    'table-driven tests'
)) {
    if (-not $instruction.Contains($required)) {
        throw "Security-sensitive delivery instruction is missing '$required'."
    }
}

$skill = Get-Content -LiteralPath (Join-Path $root $paths.DeliverySkill) -Raw
foreach ($required in @(
    'name: security-sensitive-delivery',
    'one bounded commit',
    'GitHub-hosted component workflow',
    'head SHA',
    'table-driven tests',
    'Do not begin integration work'
)) {
    if (-not $skill.Contains($required)) {
        throw "Security-sensitive delivery skill is missing '$required'."
    }
}

$review = Get-Content -LiteralPath (Join-Path $root $paths.ReviewSkill) -Raw
if (-not $review.Contains('.github/skills/security-sensitive-delivery/SKILL.md')) {
    throw 'review-changes does not enforce the security-sensitive delivery procedure.'
}

$docsMap = Get-Content -LiteralPath (Join-Path $root $paths.DocumentationMap) -Raw
if (-not $docsMap.Contains('(development/security-sensitive-delivery.md)')) {
    throw 'The documentation map does not link the security-sensitive delivery contract.'
}

$guidance = Get-Content -LiteralPath (Join-Path $root $paths.GuidanceMap) -Raw |
    ConvertFrom-Json -Depth 100
if (
    @(
        $guidance.docs.pages |
            Where-Object path -ceq 'docs/development/security-sensitive-delivery.md'
    ).Count -ne 1
) {
    throw 'Genesis guidance metadata does not own the security-sensitive delivery document.'
}

$delivery = Get-Content -LiteralPath (Join-Path $root $paths.Delivery) -Raw |
    ConvertFrom-Json -Depth 100
$hostedProfile = @(
    $delivery.runnerProfiles |
        Where-Object id -ceq 'ubuntu-latest-hosted'
)
if (
    $hostedProfile.Count -ne 1 -or
    @($hostedProfile[0].jobs) -cnotcontains 'guidance-policy'
) {
    throw 'Delivery metadata does not route the guidance policy through hosted CI.'
}

$workflow = Get-Content -LiteralPath (Join-Path $root $paths.Workflow) -Raw
if (
    $workflow -notmatch '(?m)^  guidance-policy:\s*$' -or
    $workflow -notmatch [regex]::Escape(
        'run: ./scripts/ci/Test-SecuritySensitiveDeliveryPolicy.ps1'
    )
) {
    throw 'Primary CI does not execute the security-sensitive delivery policy check.'
}

Write-Output 'Security-sensitive delivery policy contract passed.'
