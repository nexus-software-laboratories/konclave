#Requires -Version 7.4

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'WindowsExecutableSubsystem.Functions.ps1')

function Write-TestPeFile {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [ValidateSet(0x10b, 0x20b)]
        [int]$Magic,

        [Parameter(Mandatory)]
        [ValidateRange(0, 65535)]
        [int]$Subsystem
    )

    $bytes = [byte[]]::new(512)
    [BitConverter]::GetBytes([uint16]0x5a4d).CopyTo($bytes, 0)
    [BitConverter]::GetBytes([int32]0x80).CopyTo($bytes, 0x3c)
    [BitConverter]::GetBytes([uint32]0x00004550).CopyTo($bytes, 0x80)
    $optionalHeader = 0x80 + 24
    [BitConverter]::GetBytes([uint16]$Magic).CopyTo($bytes, $optionalHeader)
    [BitConverter]::GetBytes([uint16]$Subsystem).CopyTo(
        $bytes,
        $optionalHeader + 0x44
    )
    [IO.File]::WriteAllBytes($Path, $bytes)
}

function Assert-SubsystemReadFails {
    param(
        [Parameter(Mandatory)]
        [scriptblock]$Action,

        [Parameter(Mandatory)]
        [string]$Scenario
    )

    try {
        & $Action
    }
    catch {
        return
    }
    throw "Windows executable subsystem reader accepted $Scenario."
}

$classificationCases = @(
    @{ subsystem = 2; expected = 'Gui' },
    @{ subsystem = 3; expected = 'Console' },
    @{ subsystem = 0; expected = 'Unsupported' },
    @{ subsystem = 9; expected = 'Unsupported' }
)
foreach ($case in $classificationCases) {
    if (
        (Resolve-WindowsExecutableSubsystem -Subsystem $case.subsystem) -cne
            [string]$case.expected
    ) {
        throw "Windows subsystem classification failed: $($case.subsystem)"
    }
}

$root = Join-Path (
    [IO.Path]::GetTempPath()
) "konclave-pe-subsystem-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $root | Out-Null
try {
    foreach ($case in @(
        @{ name = 'pe32-gui'; magic = 0x10b; subsystem = 2 },
        @{ name = 'pe32-console'; magic = 0x10b; subsystem = 3 },
        @{ name = 'pe64-gui'; magic = 0x20b; subsystem = 2 },
        @{ name = 'pe64-console'; magic = 0x20b; subsystem = 3 }
    )) {
        $path = Join-Path $root "$($case.name).exe"
        Write-TestPeFile `
            -Path $path `
            -Magic $case.magic `
            -Subsystem $case.subsystem
        if ((Get-WindowsExecutableSubsystem -Path $path) -ne [int]$case.subsystem) {
            throw "Windows subsystem read failed: $($case.name)"
        }
    }

    $truncated = Join-Path $root 'truncated.exe'
    [IO.File]::WriteAllBytes($truncated, [byte[]]::new(16))
    Assert-SubsystemReadFails {
        Get-WindowsExecutableSubsystem -Path $truncated
    } 'a truncated file'

    $invalidSignature = Join-Path $root 'invalid-signature.exe'
    Write-TestPeFile -Path $invalidSignature -Magic 0x20b -Subsystem 2
    $bytes = [IO.File]::ReadAllBytes($invalidSignature)
    [BitConverter]::GetBytes([uint32]0).CopyTo($bytes, 0x80)
    [IO.File]::WriteAllBytes($invalidSignature, $bytes)
    Assert-SubsystemReadFails {
        Get-WindowsExecutableSubsystem -Path $invalidSignature
    } 'an invalid PE signature'

    $invalidMagic = Join-Path $root 'invalid-magic.exe'
    Write-TestPeFile -Path $invalidMagic -Magic 0x20b -Subsystem 2
    $bytes = [IO.File]::ReadAllBytes($invalidMagic)
    [BitConverter]::GetBytes([uint16]0).CopyTo($bytes, 0x80 + 24)
    [IO.File]::WriteAllBytes($invalidMagic, $bytes)
    Assert-SubsystemReadFails {
        Get-WindowsExecutableSubsystem -Path $invalidMagic
    } 'an unsupported optional header'
}
finally {
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force
    }
}

Write-Output 'Windows executable subsystem tests passed.'
