#Requires -Version 7.4

Set-StrictMode -Version Latest

$script:MaximumPeHeaderOffset = 1MB
$script:PeOptionalHeaderMagic32 = 0x10b
$script:PeOptionalHeaderMagic64 = 0x20b
$script:PeSubsystemOffset = 0x44

function Resolve-WindowsExecutableSubsystem {
    param(
        [Parameter(Mandatory)]
        [ValidateRange(0, 65535)]
        [int]$Subsystem
    )

    switch ($Subsystem) {
        2 { return 'Gui' }
        3 { return 'Console' }
        default { return 'Unsupported' }
    }
}

function Get-WindowsExecutableSubsystem {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $file = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (
        $file.PSIsContainer -or
        $file.LinkType -in @('SymbolicLink', 'Junction') -or
        $file.Length -lt 64
    ) {
        throw 'Windows executable input is missing, linked, or truncated.'
    }

    $stream = [IO.File]::Open(
        $file.FullName,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    $reader = [IO.BinaryReader]::new($stream)
    try {
        if ($reader.ReadUInt16() -ne 0x5a4d) {
            throw 'Windows executable does not contain an MZ header.'
        }
        $stream.Position = 0x3c
        $peOffset = $reader.ReadInt32()
        if (
            $peOffset -lt 64 -or
            $peOffset -gt $script:MaximumPeHeaderOffset -or
            [int64]$peOffset + 24 + $script:PeSubsystemOffset + 2 -gt $stream.Length
        ) {
            throw 'Windows executable PE header offset is invalid.'
        }

        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) {
            throw 'Windows executable does not contain a PE signature.'
        }

        $optionalHeader = $peOffset + 24
        $stream.Position = $optionalHeader
        $magic = $reader.ReadUInt16()
        if ($magic -notin @($script:PeOptionalHeaderMagic32, $script:PeOptionalHeaderMagic64)) {
            throw 'Windows executable optional header is unsupported.'
        }

        $stream.Position = $optionalHeader + $script:PeSubsystemOffset
        return [int]$reader.ReadUInt16()
    }
    finally {
        $reader.Dispose()
        $stream.Dispose()
    }
}
