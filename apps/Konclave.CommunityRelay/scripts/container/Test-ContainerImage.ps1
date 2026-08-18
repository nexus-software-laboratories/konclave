#Requires -Version 7.0
<#
.SYNOPSIS
    Build and validate the generated Rust service container image.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ConfigPath,

    [Parameter(Mandatory)]
    [ValidateSet('Smoke', 'Validate')]
    [string]$Mode
)

$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
$resolvedConfigPath = (Resolve-Path (
    Join-Path $repositoryRoot $ConfigPath
)).Path
if (
    [IO.Path]::GetRelativePath($repositoryRoot, $resolvedConfigPath) -match
        '^\.\.(?:[\\/]|$)'
) {
    throw "Container config '$resolvedConfigPath' escapes the repository."
}

$config = Get-Content $resolvedConfigPath -Raw -Encoding UTF8 |
    ConvertFrom-Json
if ($config.schemaVersion -ne 1) {
    throw "Unsupported container image schema '$($config.schemaVersion)'."
}
if ([string]$config.smoke.kind -cne 'process') {
    throw "Rust service container smoke kind must be 'process'."
}

$dockerfile = (Resolve-Path (
    Join-Path $repositoryRoot ([string]$config.dockerfile)
)).Path
if (
    [IO.Path]::GetRelativePath($repositoryRoot, $dockerfile) -match
        '^\.\.(?:[\\/]|$)'
) {
    throw "Dockerfile '$dockerfile' escapes the repository."
}
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'Docker with Buildx is required for container validation.'
}

$runId = [Guid]::NewGuid().ToString('N').Substring(0, 10)
$imageName = (([string]$config.imageName).ToLowerInvariant() -replace
    '[^a-z0-9._-]+',
    '-').Trim('-', '.')
if ([string]::IsNullOrWhiteSpace($imageName)) {
    throw "Image name '$($config.imageName)' cannot be normalized."
}

$imageTag = "${imageName}:genesis-$runId"
$containerName = "genesis-rust-$runId"
$builderName = "genesis-rust-$runId"
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) "genesis-rust-$runId"
$filesystemArchive = Join-Path $tempRoot 'filesystem.tar'
$arm64Archive = Join-Path $tempRoot 'arm64.tar'
$errors = [Collections.Generic.List[string]]::new()
$containerStarted = $false
$builderCreated = $false
$amd64ImageBytes = 0L
$arm64ArchiveBytes = 0L
$runtimeUser = ''

function Invoke-Docker {
    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments,

        [switch]$Capture
    )

    $output = & docker @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "docker $($Arguments -join ' ') failed:`n$(
            $output | Out-String)"
    }
    if ($Capture) {
        return @($output)
    }
}

function Get-ContainerState {
    return (
        [string]@(
            Invoke-Docker -Arguments @(
                'inspect',
                '--format',
                '{{.State.Status}}',
                $containerName
            ) -Capture
        )[-1]
    ).Trim()
}

try {
    New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
    Push-Location $repositoryRoot
    try {
        Invoke-Docker -Arguments @(
            'buildx',
            'create',
            '--name',
            $builderName,
            '--driver',
            'docker-container'
        )
        $builderCreated = $true
        Invoke-Docker -Arguments @(
            'buildx',
            'inspect',
            $builderName,
            '--bootstrap'
        )
        Invoke-Docker -Arguments @(
            'buildx',
            'build',
            '--builder',
            $builderName,
            '--platform',
            'linux/amd64',
            '--load',
            '--tag',
            $imageTag,
            '--file',
            ([IO.Path]::GetRelativePath($repositoryRoot, $dockerfile)),
            '.'
        )

        $imageSize = @(
            Invoke-Docker -Arguments @(
                'image',
                'inspect',
                '--format',
                '{{.Size}}',
                $imageTag
            ) -Capture
        )
        $amd64ImageBytes = [long]([string]$imageSize[-1]).Trim()
        $runtimeUser = (
            [string]@(
                Invoke-Docker -Arguments @(
                    'image',
                    'inspect',
                    '--format',
                    '{{.Config.User}}',
                    $imageTag
                ) -Capture
            )[-1]
        ).Trim()
        if ($runtimeUser -in @('', '0', 'root')) {
            throw "Image runtime user '$runtimeUser' is not non-root."
        }
        if ([bool]$config.requireImageHealthCheck) {
            $health = (
                [string]@(
                    Invoke-Docker -Arguments @(
                        'image',
                        'inspect',
                        '--format',
                        '{{json .Config.Healthcheck}}',
                        $imageTag
                    ) -Capture
                )[-1]
            ).Trim()
            if ($health -in @('', 'null', '<nil>')) {
                throw 'Image does not declare a health check.'
            }
        }

        Invoke-Docker -Arguments @(
            'run',
            '--detach',
            '--name',
            $containerName,
            $imageTag
        )
        $containerStarted = $true
        Start-Sleep -Seconds ([int]$config.smoke.startupSeconds)
        if ((Get-ContainerState) -cne 'running') {
            throw 'Container exited during the process smoke window.'
        }

        for ($attempt = 1; $attempt -le 24; $attempt++) {
            $healthState = (
                [string]@(
                    Invoke-Docker -Arguments @(
                        'inspect',
                        '--format',
                        '{{.State.Health.Status}}',
                        $containerName
                    ) -Capture
                )[-1]
            ).Trim()
            if ($healthState -ceq 'healthy') {
                break
            }
            if ($healthState -ceq 'unhealthy' -or $attempt -eq 24) {
                throw "Container health state is '$healthState'."
            }
            Start-Sleep -Seconds 2
        }

        Invoke-Docker -Arguments @(
            'export',
            '--output',
            $filesystemArchive,
            $containerName
        )
        $filesystemEntries = @(& tar -tf $filesystemArchive)
        if ($LASTEXITCODE -ne 0) {
            throw 'Could not inspect the container filesystem.'
        }
        foreach ($pattern in @(
            '^usr/local/cargo/',
            '^usr/local/rustup/',
            '^usr/local/bin/rustc$',
            '^usr/bin/cargo$'
        )) {
            if ($filesystemEntries | Where-Object { $_ -match $pattern }) {
                throw "Final image contains Rust build tooling matching '$pattern'."
            }
        }

        if ($Mode -ceq 'Validate') {
            Invoke-Docker -Arguments @(
                'buildx',
                'build',
                '--builder',
                $builderName,
                '--platform',
                'linux/arm64',
                '--output',
                "type=oci,dest=$arm64Archive",
                '--file',
                ([IO.Path]::GetRelativePath($repositoryRoot, $dockerfile)),
                '.'
            )
            $arm64ArchiveBytes = (Get-Item $arm64Archive).Length
            if ($arm64ArchiveBytes -le 0) {
                throw 'ARM64 OCI archive is empty.'
            }
        }
    } finally {
        Pop-Location
    }
} catch {
    $errors.Add($_.Exception.Message)
} finally {
    if ($containerStarted) {
        & docker rm --force $containerName *> $null
    }
    & docker image rm --force $imageTag *> $null
    if ($builderCreated) {
        & docker buildx rm $builderName *> $null
    }
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}

[PSCustomObject]@{
    IsClean = $errors.Count -eq 0
    Errors = @($errors)
    Amd64ImageBytes = $amd64ImageBytes
    Arm64ArchiveBytes = $arm64ArchiveBytes
    RuntimeUser = $runtimeUser
}
