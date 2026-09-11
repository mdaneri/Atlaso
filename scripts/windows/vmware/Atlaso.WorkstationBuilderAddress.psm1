<#
.SYNOPSIS
Reserve temporary VMware Workstation builder addresses safely.

.DESCRIPTION
Provides a host-local, cross-worktree reservation ledger for the temporary
static IPv4 addresses used by canonical Atlaso Photon builders. VMware DHCP
ranges and fixed addresses are excluded before a reservation is published.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'Atlaso.WorkstationCleanup.psm1') -Force

function Initialize-AtlasoBuilderHandoffRoot {
    <#
    .SYNOPSIS
    Create and pin one task-owned builder-address handoff directory.
    .PARAMETER BuildStateRoot
    Exact task-owned Photon build-state root.
    .PARAMETER HandoffStateRoot
    Exact builder-address handoff state directory.
    .PARAMETER PendingRoot
    Exact pending-release directory beneath the handoff state root.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$BuildStateRoot,
        [Parameter(Mandatory = $true)][string]$HandoffStateRoot,
        [Parameter(Mandatory = $true)][string]$PendingRoot
    )

    Assert-AtlasoStrictDescendantPath `
        -ParentPath $BuildStateRoot `
        -ChildPath $HandoffStateRoot `
        -FailureMessage 'Builder-address handoff state escaped task build state'
    [void][System.IO.Directory]::CreateDirectory($HandoffStateRoot)
    Assert-AtlasoStrictDescendantPath `
        -ParentPath $BuildStateRoot `
        -ChildPath $HandoffStateRoot `
        -FailureMessage 'Builder-address handoff state changed during creation'
    $stateIdentity = Get-AtlasoPathIdentity `
        -Path $HandoffStateRoot `
        -Description 'Builder-address handoff state'
    Assert-AtlasoStrictDescendantPath `
        -ParentPath $HandoffStateRoot `
        -ChildPath $PendingRoot `
        -FailureMessage 'Builder-address pending-release root escaped handoff state'
    [void][System.IO.Directory]::CreateDirectory($PendingRoot)
    Assert-AtlasoStrictDescendantPath `
        -ParentPath $HandoffStateRoot `
        -ChildPath $PendingRoot `
        -FailureMessage 'Builder-address pending-release root changed during creation'
    return [pscustomobject][ordered]@{
        StateIdentity   = $stateIdentity
        PendingIdentity = Get-AtlasoPathIdentity `
            -Path $PendingRoot `
            -Description 'Builder-address pending-release root'
    }
}

function Assert-AtlasoBuilderHandoffRootIdentity {
    <#
    .SYNOPSIS
    Revalidate one pinned task-owned builder-address handoff directory.
    .PARAMETER BuildStateRoot
    Exact task-owned Photon build-state root.
    .PARAMETER HandoffStateRoot
    Exact builder-address handoff state directory.
    .PARAMETER PendingRoot
    Exact pending-release directory beneath the handoff state root.
    .PARAMETER StateIdentity
    Pinned filesystem identity for the handoff state directory.
    .PARAMETER PendingIdentity
    Pinned filesystem identity for the pending-release directory.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$BuildStateRoot,
        [Parameter(Mandatory = $true)][string]$HandoffStateRoot,
        [Parameter(Mandatory = $true)][string]$PendingRoot,
        [Parameter(Mandatory = $true)][string]$StateIdentity,
        [Parameter(Mandatory = $true)][string]$PendingIdentity
    )

    Assert-AtlasoStrictDescendantPath `
        -ParentPath $BuildStateRoot `
        -ChildPath $HandoffStateRoot `
        -FailureMessage 'Builder-address handoff state escaped task build state'
    Assert-AtlasoStrictDescendantPath `
        -ParentPath $HandoffStateRoot `
        -ChildPath $PendingRoot `
        -FailureMessage 'Builder-address pending-release root escaped handoff state'
    if ((Get-AtlasoPathIdentity -Path $HandoffStateRoot -Description 'Builder-address handoff state') -ne
        $StateIdentity -or
        (Get-AtlasoPathIdentity -Path $PendingRoot -Description 'Builder-address pending-release root') -ne
        $PendingIdentity) {
        throw 'Builder-address handoff ancestry changed after admission; publication was blocked.'
    }
}

function ConvertTo-AtlasoIpv4Integer {
    <#
    .SYNOPSIS
    Convert an IPv4 address to an unsigned integer.
    .PARAMETER Address
    IPv4 address to convert.
    #>
    param([Parameter(Mandatory = $true)][string]$Address)

    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($Address, [ref]$parsed) -or
        $parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        throw "Expected a canonical IPv4 address, got '$Address'."
    }
    $canonical = $parsed.ToString()
    if ($canonical -cne $Address) {
        throw "Expected a canonical IPv4 address, got '$Address'."
    }
    $bytes = $parsed.GetAddressBytes()
    return (([uint32]$bytes[0] -shl 24) -bor
        ([uint32]$bytes[1] -shl 16) -bor
        ([uint32]$bytes[2] -shl 8) -bor
        [uint32]$bytes[3])
}

function ConvertFrom-AtlasoIpv4Integer {
    <#
    .SYNOPSIS
    Convert an unsigned integer to an IPv4 address.
    .PARAMETER Address
    Unsigned network-order integer containing the four IPv4 octets.
    #>
    param([Parameter(Mandatory = $true)][uint32]$Address)

    $bytes = [byte[]]@(
        (($Address -shr 24) -band 0xff),
        (($Address -shr 16) -band 0xff),
        (($Address -shr 8) -band 0xff),
        ($Address -band 0xff)
    )
    return ([System.Net.IPAddress]::new($bytes)).ToString()
}

function Get-AtlasoIpv4Network {
    <#
    .SYNOPSIS
    Return validated IPv4 network bounds.
    .PARAMETER Subnet
    Canonical IPv4 subnet address.
    .PARAMETER Netmask
    Canonical contiguous IPv4 netmask.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Subnet,
        [Parameter(Mandatory = $true)][string]$Netmask
    )

    $subnetValue = ConvertTo-AtlasoIpv4Integer -Address $Subnet
    $maskValue = ConvertTo-AtlasoIpv4Integer -Address $Netmask
    $prefix = 0
    $seenZero = $false
    for ($bit = 31; $bit -ge 0; $bit--) {
        $set = (($maskValue -shr $bit) -band 1) -eq 1
        if ($set -and $seenZero) {
            throw "VMware network netmask is not contiguous: $Netmask"
        }
        if ($set) { $prefix++ } else { $seenZero = $true }
    }
    $network = $subnetValue -band $maskValue
    if ($network -ne $subnetValue) {
        throw "VMware subnet $Subnet is not the network address for netmask $Netmask."
    }
    $broadcast = $network -bor (-bnot $maskValue)
    return [pscustomobject]@{
        Network   = [uint32]$network
        Broadcast = [uint32]$broadcast
        Prefix    = $prefix
    }
}

function Get-AtlasoVmwareDhcpExclusions {
    <#
    .SYNOPSIS
    Read VMware DHCP ranges and fixed addresses for one IPv4 subnet.
    .PARAMETER Subnet
    Canonical VMware IPv4 subnet.
    .PARAMETER Netmask
    Canonical VMware IPv4 netmask.
    .PARAMETER DhcpEnabled
    Whether VMware reports DHCP enabled for the selected vmnet.
    .PARAMETER ConfigPath
    Optional explicit VMware vmnetdhcp.conf path.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Subnet,
        [Parameter(Mandatory = $true)][string]$Netmask,
        [Parameter(Mandatory = $true)][bool]$DhcpEnabled,
        [string]$ConfigPath = ''
    )

    $network = Get-AtlasoIpv4Network -Subnet $Subnet -Netmask $Netmask
    $resolvedConfig = if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
        Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'VMware\vmnetdhcp.conf'
    }
    else {
        [System.IO.Path]::GetFullPath($ConfigPath)
    }
    if (-not (Test-Path -LiteralPath $resolvedConfig -PathType Leaf)) {
        if ($DhcpEnabled) {
            throw "VMware reports DHCP enabled for $Subnet/$($network.Prefix), but its DHCP configuration is unavailable: $resolvedConfig"
        }
        return [pscustomobject]@{ ConfigPath = $resolvedConfig; Ranges = @(); FixedAddresses = @() }
    }

    $content = [System.IO.File]::ReadAllText($resolvedConfig)
    $blockPattern = '(?ms)^\s*subnet\s+(?<subnet>\S+)\s+netmask\s+(?<mask>\S+)\s*\{(?<body>.*?)^\s*\}'
    $matchingBlocks = @([regex]::Matches($content, $blockPattern) | Where-Object {
            $_.Groups['subnet'].Value -ceq $Subnet -and $_.Groups['mask'].Value -ceq $Netmask
        })
    if ($matchingBlocks.Count -gt 1) {
        throw "VMware DHCP configuration contains duplicate subnet blocks for $Subnet/$($network.Prefix)."
    }
    if ($DhcpEnabled -and $matchingBlocks.Count -ne 1) {
        throw "VMware reports DHCP enabled for $Subnet/$($network.Prefix), but vmnetdhcp.conf has no exact matching subnet block."
    }

    $ranges = @()
    if ($matchingBlocks.Count -eq 1) {
        foreach ($match in [regex]::Matches($matchingBlocks[0].Groups['body'].Value, '(?m)^\s*range\s+(\S+)\s+(\S+)\s*;')) {
            $start = ConvertTo-AtlasoIpv4Integer -Address $match.Groups[1].Value
            $end = ConvertTo-AtlasoIpv4Integer -Address $match.Groups[2].Value
            if ($start -gt $end -or $start -le $network.Network -or $end -ge $network.Broadcast) {
                throw "VMware DHCP range $($match.Groups[1].Value)-$($match.Groups[2].Value) is invalid for $Subnet/$($network.Prefix)."
            }
            $ranges += [pscustomobject]@{ Start = [uint32]$start; End = [uint32]$end }
        }
        if ($DhcpEnabled -and $ranges.Count -eq 0) {
            throw "VMware reports DHCP enabled for $Subnet/$($network.Prefix), but no usable DHCP range was found."
        }
    }

    $fixed = @()
    foreach ($match in [regex]::Matches($content, '(?m)^\s*fixed-address\s+(\S+)\s*;')) {
        $value = ConvertTo-AtlasoIpv4Integer -Address $match.Groups[1].Value
        if ($value -gt $network.Network -and $value -lt $network.Broadcast) {
            $fixed += [uint32]$value
        }
    }
    return [pscustomobject]@{
        ConfigPath     = $resolvedConfig
        Ranges         = @($ranges)
        FixedAddresses = @($fixed | Sort-Object -Unique)
    }
}

function Test-AtlasoProcessIdentityActive {
    <#
    .SYNOPSIS
    Check whether a recorded Windows process identity is still active.
    .PARAMETER ProcessId
    Recorded process identifier.
    .PARAMETER StartTimeUtcTicks
    Recorded UTC process start time in ticks.
    #>
    param(
        [Parameter(Mandatory = $true)][int]$ProcessId,
        [Parameter(Mandatory = $true)][long]$StartTimeUtcTicks
    )

    try {
        $process = Get-Process -Id $ProcessId -ErrorAction Stop
        return $process.StartTime.ToUniversalTime().Ticks -eq $StartTimeUtcTicks
    }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoProcessFoundForGivenId*') { return $false }
        throw 'The recorded process identity could not be inspected; reservation state was preserved.'
    }
}

function Get-AtlasoBuilderHostBootIdentity {
    <#
    .SYNOPSIS
    Return the stable identity of the current Windows host boot.
    #>
    $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop |
        Select-Object -First 1
    if ($null -eq $operatingSystem -or $null -eq $operatingSystem.LastBootUpTime) {
        throw 'The Windows host boot identity could not be determined.'
    }
    return ([DateTimeOffset]$operatingSystem.LastBootUpTime).ToUniversalTime().Ticks.ToString(
        [Globalization.CultureInfo]::InvariantCulture
    )
}

function Get-AtlasoRunningVmwareVmxPaths {
    <#
    .SYNOPSIS
    Return the checked running VMware Workstation VMX inventory.
    .PARAMETER VmrunPath
    Exact vmrun executable path.
    #>
    param([Parameter(Mandatory = $true)][string]$VmrunPath)

    $lines = @(& $VmrunPath -T ws list)
    if ($LASTEXITCODE -ne 0 -or $lines.Count -eq 0 -or $lines[0] -notmatch '^Total running VMs:\s*(\d+)\s*$') {
        throw 'Could not obtain a trustworthy VMware Workstation running inventory.'
    }
    $declaredCount = [int]$Matches[1]
    $reportedPaths = @($lines | Select-Object -Skip 1 | Where-Object {
            -not [string]::IsNullOrWhiteSpace($_)
        } | ForEach-Object { [System.IO.Path]::GetFullPath($_.Trim()) })
    if ($reportedPaths.Count -ne $declaredCount) {
        throw "vmrun list reported $declaredCount VMs but returned $($reportedPaths.Count) paths; the builder address remains reserved."
    }
    return $reportedPaths
}

function Test-AtlasoVmwareAddressObservedInUse {
    <#
    .SYNOPSIS
    Check non-ICMP host and VMware observations for one builder address.
    .PARAMETER Address
    Candidate IPv4 address.
    .PARAMETER VmrunPath
    Exact vmrun executable path.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Address,
        [Parameter(Mandatory = $true)][string]$VmrunPath
    )

    $running = @(Get-AtlasoRunningVmwareVmxPaths -VmrunPath $VmrunPath)
    foreach ($vmx in $running) {
        $answer = @(& $VmrunPath -T ws getGuestIPAddress $vmx 2>$null)
        if ($LASTEXITCODE -eq 0 -and @($answer | Where-Object { $_.Trim() -ceq $Address }).Count -gt 0) {
            return $true
        }
    }
    try {
        $neighbors = @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop | Where-Object {
                $_.IPAddress -ceq $Address -and
                $_.State -notin @('Unreachable', 'Incomplete') -and
                $_.LinkLayerAddress -notin @('', '00-00-00-00-00-00')
            })
        if ($neighbors.Count -gt 0) {
            return $true
        }
    }
    catch {
        throw "Could not inspect the Windows IPv4 neighbor table before reserving $Address."
    }
    return $false
}

function Invoke-WithAtlasoBuilderReservationLock {
    <#
    .SYNOPSIS
    Execute an action while holding the exclusive reservation-ledger lock.
    .PARAMETER StateRoot
    Stable per-user reservation state directory.
    .PARAMETER Action
    Action to run while the lock is held.
    .PARAMETER ReadOnly
    Require the existing lock and do not create state while verifying.
    .PARAMETER TimeoutSeconds
    Maximum bounded lock acquisition interval.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$StateRoot,
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [ValidateRange(1, 120)][int]$TimeoutSeconds = 30,
        [switch]$ReadOnly
    )

    if (-not $ReadOnly) { [void][System.IO.Directory]::CreateDirectory($StateRoot) }
    $lockPath = Join-Path $StateRoot 'reservations.lock'
    if ($ReadOnly -and -not (Test-Path -LiteralPath $lockPath -PathType Leaf)) {
        throw 'The allocator lock is missing; read-only verification cannot establish state.'
    }
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $stream = $null
    while ($null -eq $stream -and [DateTime]::UtcNow -lt $deadline) {
        try {
            $mode = if ($ReadOnly) { [IO.FileMode]::Open } else { [IO.FileMode]::OpenOrCreate }
            $stream = [System.IO.File]::Open($lockPath, $mode, 'ReadWrite', 'None')
        }
        catch [System.IO.IOException] {
            Start-Sleep -Milliseconds 100
        }
    }
    if ($null -eq $stream) {
        throw "Timed out waiting for the Atlaso VMware builder-address reservation lock: $lockPath"
    }
    try {
        return & $Action
    }
    finally {
        $stream.Dispose()
    }
}

function Read-AtlasoBuilderReservationLedger {
    <#
    .SYNOPSIS
    Read and validate the builder reservation ledger.
    .PARAMETER Path
    Exact ledger path.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return @()
    }
    $ledgerPin = $null
    try {
        $ledgerPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($Path, $true)
        if ((Get-Item -LiteralPath $Path).Length -gt 1048576) { throw 'Reservation ledger exceeds its size limit.' }
        $payload = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json
    }
    catch {
        throw "The Atlaso VMware builder-address reservation ledger is unreadable: $Path"
    }
    finally { if ($null -ne $ledgerPin) { $ledgerPin.Dispose() } }
    if ($payload.Schema -ne 1 -or $null -eq $payload.Reservations) {
        throw "The Atlaso VMware builder-address reservation ledger has an unsupported schema: $Path"
    }
    return @($payload.Reservations)
}

function Write-AtlasoBuilderReservationLedger {
    <#
    .SYNOPSIS
    Atomically replace the builder reservation ledger.
    .PARAMETER Path
    Exact ledger path.
    .PARAMETER Reservations
    Complete validated reservation collection.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Reservations
    )

    Write-AtlasoBuilderDurableJsonFile `
        -Path $Path `
        -Payload ([ordered]@{ Schema = 1; Reservations = @($Reservations) }) `
        -Replace
}

function Write-AtlasoBuilderDurableJsonFile {
    <#
    .SYNOPSIS
    Durably publish one builder-state JSON payload.
    .PARAMETER Path
    Exact destination path.
    .PARAMETER Payload
    Complete JSON-serializable payload.
    .PARAMETER Replace
    Replace an existing destination instead of requiring a new path.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][object]$Payload,
        [switch]$Replace
    )

    $temporary = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        $json = $Payload | ConvertTo-Json -Depth 6
        $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes("$json`n")
        $stream = [System.IO.FileStream]::new(
            $temporary,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None,
            4096,
            [System.IO.FileOptions]::WriteThrough
        )
        try {
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        }
        finally {
            $stream.Dispose()
        }
        Move-AtlasoBuilderLedgerDurableFile `
            -SourcePath $temporary `
            -DestinationPath $Path `
            -Replace:$Replace
        try {
            Sync-AtlasoBuilderLedgerDirectory -DirectoryPath (Split-Path -Parent $Path)
        }
        catch {
            # MoveFileEx publishes the write-through replacement before the
            # supplementary directory flush. Reconcile that visible state so
            # callers never lose the exact record needed to release it.
            $publishedBytes = [System.IO.File]::ReadAllBytes($Path)
            if ($publishedBytes.Length -ne $bytes.Length -or
                -not [System.Linq.Enumerable]::SequenceEqual[byte]($publishedBytes, $bytes)) {
                throw
            }
        }
    }
    finally {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Force
        }
    }
}

function Move-AtlasoBuilderLedgerDurableFile {
    <#
    .SYNOPSIS
    Replace the builder ledger with Windows write-through rename semantics.
    .PARAMETER SourcePath
    Exact flushed temporary ledger path.
    .PARAMETER DestinationPath
    Exact final ledger path on the same volume.
    .PARAMETER Replace
    Replace an existing validated ledger.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$SourcePath,
        [Parameter(Mandatory = $true)][string]$DestinationPath,
        [switch]$Replace
    )

    if (-not $IsWindows) {
        throw 'Durable builder-ledger replacement requires Windows.'
    }
    if (-not ('Atlaso.WorkstationDurableFile' -as [type])) {
        Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
namespace Atlaso {
    public static class WorkstationDurableFile {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool MoveFileEx(string existingPath, string newPath, uint flags);
    }
}
'@
    }
    [uint32]$flags = 0x00000008
    if ($Replace) { $flags = $flags -bor 0x00000001 }
    if (-not [Atlaso.WorkstationDurableFile]::MoveFileEx(
            (Resolve-Path -LiteralPath $SourcePath).Path,
            [System.IO.Path]::GetFullPath($DestinationPath),
            $flags
        )) {
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw [ComponentModel.Win32Exception]::new(
            $errorCode,
            'Durable builder-ledger replacement failed.'
        )
    }
}

function Sync-AtlasoBuilderLedgerDirectory {
    <#
    .SYNOPSIS
    Flush builder-ledger directory metadata through an exact Windows handle.
    .PARAMETER DirectoryPath
    Existing non-reparse-point ledger directory.
    #>
    param([Parameter(Mandatory = $true)][string]$DirectoryPath)

    $resolvedDirectory = (Resolve-Path -LiteralPath $DirectoryPath).Path
    $directory = Get-Item -LiteralPath $resolvedDirectory -Force -ErrorAction Stop
    if (-not $directory.PSIsContainer -or
        ($directory.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw 'Durable builder-ledger synchronization requires a non-reparse-point directory.'
    }
    if (-not ('Atlaso.WorkstationDurableDirectory' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace Atlaso {
    public static class WorkstationDurableDirectory {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern SafeFileHandle CreateFileW(string path, uint desiredAccess,
            uint shareMode, IntPtr securityAttributes, uint creationDisposition,
            uint flagsAndAttributes, IntPtr templateFile);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool FlushFileBuffers(SafeFileHandle handle);
    }
}
'@
    }
    [uint32]$flags = [uint32]::Parse(
        '82000000',
        [Globalization.NumberStyles]::HexNumber
    )
    $handle = [Atlaso.WorkstationDurableDirectory]::CreateFileW(
        $resolvedDirectory,
        [uint32]0x40000000,
        [uint32]0x00000007,
        [IntPtr]::Zero,
        [uint32]0x00000003,
        $flags,
        [IntPtr]::Zero
    )
    try {
        if ($handle.IsInvalid -or
            -not [Atlaso.WorkstationDurableDirectory]::FlushFileBuffers($handle)) {
            $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw [ComponentModel.Win32Exception]::new(
                $errorCode,
                'Durable builder-ledger directory synchronization failed.'
            )
        }
    }
    finally {
        $handle.Dispose()
    }
}

function Enter-AtlasoVmwareBuilderAddressReservation {
    <#
    .SYNOPSIS
    Atomically reserve one safe temporary VMware builder address.
    .PARAMETER NetworkName
    Selected VMware vmnet name.
    .PARAMETER Subnet
    Canonical selected vmnet subnet.
    .PARAMETER Netmask
    Canonical selected vmnet netmask.
    .PARAMETER DhcpEnabled
    Whether VMware reports DHCP enabled on the vmnet.
    .PARAMETER PreferredAddress
    Explicit caller-selected address, or empty to allocate from the pool.
    .PARAMETER PoolStartOffset
    First host offset in the configured default builder pool.
    .PARAMETER PoolEndOffset
    Final host offset in the configured default builder pool.
    .PARAMETER AdditionalExcludedAddresses
    Gateway or other selected-vmnet addresses that must not be allocated.
    .PARAMETER DhcpConfigPath
    Optional explicit VMware DHCP configuration path.
    .PARAMETER StateRoot
    Optional stable host-shared reservation lock and ledger directory.
    .PARAMETER HandoffStateRoot
    Optional task-owned state directory containing the pending-release handoff.
    When omitted, handoffs remain beneath StateRoot for backward compatibility.
    .PARAMETER HandoffBuildStateRoot
    Exact task-owned build-state root that bounds HandoffStateRoot.
    .PARAMETER HandoffStateIdentity
    Pinned filesystem identity for HandoffStateRoot.
    .PARAMETER HandoffPendingIdentity
    Pinned filesystem identity for its pending-releases directory.
    .PARAMETER ReservationHandoffPath
    Optional exact pending-release handoff to publish before ledger admission.
    .PARAMETER VmrunPath
    Exact vmrun executable path.
    .PARAMETER OutputDirectory
    Exact build output directory owned by this reservation.
    .PARAMETER VmName
    Exact builder VM name.
    .PARAMETER RepositoryRoot
    Exact checkout root owning the build.
    .PARAMETER SourceCommit
    Exact source commit admitted for the build.
    .PARAMETER SourceBranch
    Exact task or local/test branch admitted for the build.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$NetworkName,
        [Parameter(Mandatory = $true)][string]$Subnet,
        [Parameter(Mandatory = $true)][string]$Netmask,
        [Parameter(Mandatory = $true)][bool]$DhcpEnabled,
        [string]$PreferredAddress = '',
        [ValidateRange(1, 4294967294)][uint32]$PoolStartOffset = 30,
        [ValidateRange(1, 4294967294)][uint32]$PoolEndOffset = 49,
        [string[]]$AdditionalExcludedAddresses = @(),
        [string]$DhcpConfigPath = '',
        [string]$StateRoot = '',
        [string]$HandoffStateRoot = '',
        [string]$HandoffBuildStateRoot = '',
        [string]$HandoffStateIdentity = '',
        [string]$HandoffPendingIdentity = '',
        [string]$ReservationHandoffPath = '',
        [Parameter(Mandatory = $true)][string]$VmrunPath,
        [Parameter(Mandatory = $true)][string]$OutputDirectory,
        [Parameter(Mandatory = $true)][string]$VmName,
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$SourceCommit,
        [Parameter(Mandatory = $true)][string]$SourceBranch
    )

    if ($PoolStartOffset -gt $PoolEndOffset) {
        throw 'BuilderAddressPoolStartOffset must not exceed BuilderAddressPoolEndOffset.'
    }
    $network = Get-AtlasoIpv4Network -Subnet $Subnet -Netmask $Netmask
    $dhcp = Get-AtlasoVmwareDhcpExclusions -Subnet $Subnet -Netmask $Netmask -DhcpEnabled $DhcpEnabled -ConfigPath $DhcpConfigPath
    $fixedExcluded = [System.Collections.Generic.HashSet[uint32]]::new()
    foreach ($value in $dhcp.FixedAddresses) { [void]$fixedExcluded.Add([uint32]$value) }
    $ordinaryExcluded = [System.Collections.Generic.HashSet[uint32]]::new()
    foreach ($address in $AdditionalExcludedAddresses) {
        if (-not [string]::IsNullOrWhiteSpace($address)) {
            [void]$ordinaryExcluded.Add((ConvertTo-AtlasoIpv4Integer -Address $address))
        }
    }

    $preferredAddressSupplied = -not [string]::IsNullOrWhiteSpace($PreferredAddress)
    $candidateValues = if ($preferredAddressSupplied) {
        @((ConvertTo-AtlasoIpv4Integer -Address $PreferredAddress))
    }
    else {
        $start = [uint64]$network.Network + $PoolStartOffset
        $end = [uint64]$network.Network + $PoolEndOffset
        if ($start -le $network.Network -or $end -ge $network.Broadcast) {
            throw "The configured builder-address pool offsets are outside $Subnet/$($network.Prefix)."
        }
        $pool = [System.Collections.Generic.List[uint32]]::new()
        for ($candidate = $start; $candidate -le $end; $candidate++) {
            $pool.Add([uint32]$candidate)
        }
        @($pool)
    }
    foreach ($candidate in $candidateValues) {
        if ($candidate -le $network.Network -or $candidate -ge $network.Broadcast) {
            throw "Builder address $(ConvertFrom-AtlasoIpv4Integer -Address $candidate) is outside usable network $Subnet/$($network.Prefix)."
        }
        foreach ($range in $dhcp.Ranges) {
            if ($candidate -ge [uint32]$range.Start -and $candidate -le [uint32]$range.End) {
                throw "Builder address pool overlaps VMware DHCP range $(ConvertFrom-AtlasoIpv4Integer -Address $range.Start)-$(ConvertFrom-AtlasoIpv4Integer -Address $range.End)."
            }
        }
        if ($fixedExcluded.Contains($candidate)) {
            throw "Builder address pool includes VMware-reserved address $(ConvertFrom-AtlasoIpv4Integer -Address $candidate)."
        }
        if ($preferredAddressSupplied -and $ordinaryExcluded.Contains($candidate)) {
            throw "Preferred builder address $(ConvertFrom-AtlasoIpv4Integer -Address $candidate) is reserved by the host or network configuration."
        }
    }
    if (-not $preferredAddressSupplied) {
        $candidateValues = @($candidateValues | Where-Object { -not $ordinaryExcluded.Contains([uint32]$_) })
    }

    $resolvedStateRoot = if ([string]::IsNullOrWhiteSpace($StateRoot)) {
        Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Atlaso\vmware-builder-addresses'
    }
    else {
        [System.IO.Path]::GetFullPath($StateRoot)
    }
    $ledgerPath = Join-Path $resolvedStateRoot 'reservations.json'
    $resolvedHandoffStateRoot = if ([string]::IsNullOrWhiteSpace($HandoffStateRoot)) {
        $resolvedStateRoot
    }
    else {
        [System.IO.Path]::GetFullPath($HandoffStateRoot)
    }
    $resolvedHandoffPath = ''
    if (-not [string]::IsNullOrWhiteSpace($ReservationHandoffPath)) {
        $pendingRoot = [System.IO.Path]::GetFullPath((Join-Path $resolvedHandoffStateRoot 'pending-releases'))
        $resolvedHandoffPath = [System.IO.Path]::GetFullPath($ReservationHandoffPath)
        if ([string]::IsNullOrWhiteSpace($HandoffBuildStateRoot) -or
            [string]::IsNullOrWhiteSpace($HandoffStateIdentity) -or
            [string]::IsNullOrWhiteSpace($HandoffPendingIdentity) -or
            -not (Split-Path -Parent $resolvedHandoffPath).Equals(
                $pendingRoot,
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            (Split-Path -Leaf $resolvedHandoffPath) -notmatch '^builder-address-reservation-[0-9a-f]{32}\.json$' -or
            -not (Test-Path -LiteralPath $pendingRoot -PathType Container)) {
            throw 'The VMware builder-address release handoff path is invalid.'
        }
        Assert-AtlasoBuilderHandoffRootIdentity `
            -BuildStateRoot ([System.IO.Path]::GetFullPath($HandoffBuildStateRoot)) `
            -HandoffStateRoot $resolvedHandoffStateRoot `
            -PendingRoot $pendingRoot `
            -StateIdentity $HandoffStateIdentity `
            -PendingIdentity $HandoffPendingIdentity
    }
    $resolvedOutput = [System.IO.Path]::GetFullPath($OutputDirectory)
    $canonicalTaskName = '^Atlaso-PR-[1-9][0-9]*-Photon-Builder-VMware(?:-[a-z0-9]+(?:-[a-z0-9]+)*)?$'
    $canonicalLocalName = '^Atlaso-Local-[0-9a-f]{12}-Photon-Builder-VMware(?:-[a-z0-9]+(?:-[a-z0-9]+)*)?$'
    $canonicalReleaseName = '^Atlaso-Release-v[0-9]+-[0-9]+-[0-9]+-[0-9a-f]{12}-Photon-Builder-VMware(?:-run-[1-9][0-9]*)?$'
    if ($VmName -notmatch $canonicalTaskName -and $VmName -notmatch $canonicalLocalName -and
        $VmName -notmatch $canonicalReleaseName) {
        throw 'The VMware builder reservation requires one canonical task-owned, local/test, or release-owned builder identity.'
    }
    $vmxPath = [System.IO.Path]::GetFullPath((Join-Path $resolvedOutput "$VmName.vmx"))
    $resolvedRepository = (Resolve-Path -LiteralPath $RepositoryRoot -ErrorAction Stop).Path
    if ($SourceCommit -notmatch '^[0-9a-f]{40}$') {
        throw 'Could not bind the VMware builder reservation to an exact source commit.'
    }
    $sourceBranch = [string](& git -C $resolvedRepository branch --show-current)
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not bind the VMware builder reservation to an exact checkout branch.'
    }
    if ([string]::IsNullOrWhiteSpace($sourceBranch)) {
        if ($VmName -match $canonicalReleaseName) {
            $sourceBranch = '(detached-release)'
        }
        else {
            throw 'Could not bind the task or local/test VMware builder reservation to an exact checkout branch.'
        }
    }
    $owner = Get-Process -Id $PID -ErrorAction Stop
    $hostBootIdentity = Get-AtlasoBuilderHostBootIdentity
    $reservationId = [guid]::NewGuid().ToString('N')

    return Invoke-WithAtlasoBuilderReservationLock -StateRoot $resolvedStateRoot -Action {
        $reservations = @(Read-AtlasoBuilderReservationLedger -Path $ledgerPath)
        $retained = @()
        foreach ($entry in $reservations) {
            $required = @(
                'Id', 'Address', 'Cidr', 'NetworkName', 'Subnet', 'Netmask',
                'OwnerPid', 'OwnerStartTimeUtcTicks', 'HostBootIdentity', 'RepositoryRoot', 'SourceCommit',
                'SourceBranch', 'OutputDirectory', 'VmName', 'VmxPath', 'CreatedUtc'
            )
            $entryProperties = @($entry.PSObject.Properties.Name)
            if ($entryProperties.Count -ne $required.Count -or
                @($required | Where-Object { $_ -notin $entryProperties }).Count -gt 0 -or
                [string]$entry.Id -notmatch '^[0-9a-f]{32}$' -or
                [string]$entry.HostBootIdentity -notmatch '^[0-9]{1,19}$' -or
                [string]$entry.SourceCommit -notmatch '^[0-9a-f]{40}$') {
                throw "The Atlaso VMware builder-address reservation ledger is ambiguous: $ledgerPath"
            }
            if (Test-AtlasoProcessIdentityActive -ProcessId ([int]$entry.OwnerPid) -StartTimeUtcTicks ([long]$entry.OwnerStartTimeUtcTicks)) {
                $retained += $entry
                continue
            }
            if ([string]$entry.HostBootIdentity -ceq $hostBootIdentity) {
                # A dead parent does not prove its descendants are gone. On the same
                # host boot, one could still start the reserved VM after this check.
                $retained += $entry
                continue
            }
            $running = @(Get-AtlasoRunningVmwareVmxPaths -VmrunPath $VmrunPath)
            $entryVmx = [System.IO.Path]::GetFullPath([string]$entry.VmxPath)
            if (@($running | Where-Object { $_.Equals($entryVmx, [StringComparison]::OrdinalIgnoreCase) }).Count -gt 0) {
                $retained += $entry
                continue
            }
            $entryAddress = [string]$entry.Address
            if (Test-AtlasoVmwareAddressObservedInUse -Address $entryAddress -VmrunPath $VmrunPath) {
                $retained += $entry
                continue
            }
        }
        foreach ($candidate in $candidateValues) {
            $address = ConvertFrom-AtlasoIpv4Integer -Address $candidate
            if (@($retained | Where-Object { [string]$_.Address -ceq $address }).Count -gt 0) {
                continue
            }
            if (Test-AtlasoVmwareAddressObservedInUse -Address $address -VmrunPath $VmrunPath) {
                continue
            }
            $record = [ordered]@{
                Id                     = $reservationId
                Address                = $address
                Cidr                   = "$address/$($network.Prefix)"
                NetworkName            = $NetworkName.ToLowerInvariant()
                Subnet                 = $Subnet
                Netmask                = $Netmask
                OwnerPid               = $PID
                OwnerStartTimeUtcTicks = $owner.StartTime.ToUniversalTime().Ticks
                HostBootIdentity       = $hostBootIdentity
                RepositoryRoot         = $resolvedRepository
                SourceCommit           = $SourceCommit
                SourceBranch           = $SourceBranch
                OutputDirectory        = $resolvedOutput
                VmName                 = $VmName
                VmxPath                = $vmxPath
                CreatedUtc             = [DateTime]::UtcNow.ToString('o')
            }
            if (-not [string]::IsNullOrWhiteSpace($resolvedHandoffPath)) {
                # Publish recoverable intent first. A concurrent recovery keeps
                # it while this exact owner is active; after owner termination,
                # absence from the ledger is an idempotently completed release.
                Assert-AtlasoBuilderHandoffRootIdentity `
                    -BuildStateRoot ([System.IO.Path]::GetFullPath($HandoffBuildStateRoot)) `
                    -HandoffStateRoot $resolvedHandoffStateRoot `
                    -PendingRoot $pendingRoot `
                    -StateIdentity $HandoffStateIdentity `
                    -PendingIdentity $HandoffPendingIdentity
                Write-AtlasoBuilderDurableJsonFile `
                    -Path $resolvedHandoffPath `
                    -Payload ([pscustomobject]$record)
            }
            Write-AtlasoBuilderReservationLedger -Path $ledgerPath -Reservations @($retained + [pscustomobject]$record)
            return [pscustomobject]$record
        }
        throw "No safe address remains in the configured Atlaso builder pool on $NetworkName."
    }
}

function Get-AtlasoBuilderReservationFingerprint {
    <#
    .SYNOPSIS
    Bind termination evidence to every field of one allocation record.
    .PARAMETER Reservation
    Allocation record, optionally carrying a handoff-only termination receipt.
    #>
    param([Parameter(Mandatory = $true)][object]$Reservation)
    $required = @('Id', 'Address', 'Cidr', 'NetworkName', 'Subnet', 'Netmask',
        'OwnerPid', 'OwnerStartTimeUtcTicks', 'HostBootIdentity', 'RepositoryRoot',
        'SourceCommit', 'SourceBranch', 'OutputDirectory', 'VmName', 'VmxPath', 'CreatedUtc')
    $names = @($Reservation.PSObject.Properties.Name | Where-Object { $_ -cne 'TerminationProof' })
    if ($names.Count -ne $required.Count -or @($required | Where-Object { $_ -notin $names }).Count -gt 0) {
        throw 'The reservation record has missing or unexpected fields.'
    }
    $canonical = [ordered]@{}
    foreach ($property in @($Reservation.PSObject.Properties | Sort-Object Name)) {
        if ($property.Name -ceq 'CreatedUtc') {
            $canonical[$property.Name] = ([DateTimeOffset]$property.Value).UtcTicks
        } elseif ($property.Name -cne 'TerminationProof') { $canonical[$property.Name] = $property.Value }
    }
    $bytes = [Text.Encoding]::UTF8.GetBytes(($canonical | ConvertTo-Json -Compress -Depth 8))
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))
}

function Save-AtlasoBuilderTerminationProof {
    <#
    .SYNOPSIS
    Preserve a bounded parent's proven termination before fallible VM cleanup.
    .DESCRIPTION
    Internal build-controller integration. Call only after the bounded runner has
    proved complete job termination. This is not an operator assertion switch.
    .PARAMETER HandoffPath
    Exact existing allocation handoff outside temporary credential storage.
    .PARAMETER ExpectedOwnerPid
    Child PID published by the bounded runner before it resumed that child.
    .PARAMETER ExpectedOwnerStartTimeUtcTicks
    Corresponding child process start identity from the runner publication.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$HandoffPath,
        [Parameter(Mandatory = $true)][int]$ExpectedOwnerPid,
        [Parameter(Mandatory = $true)][long]$ExpectedOwnerStartTimeUtcTicks
    )
    $path = [IO.Path]::GetFullPath($HandoffPath)
    $pins = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath((Split-Path -Parent $path), $true)
    try {
        $pin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($path, $true)
        try {
            if ((Get-Item -LiteralPath $path).Length -gt 16384) { throw 'Reservation handoff exceeds its size limit.' }
            $reservation = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        }
        finally { $pin.Dispose() }
        if ([int]$reservation.OwnerPid -ne $ExpectedOwnerPid -or
            [long]$reservation.OwnerStartTimeUtcTicks -ne $ExpectedOwnerStartTimeUtcTicks -or
            [string]$reservation.HostBootIdentity -cne (Get-AtlasoBuilderHostBootIdentity) -or
            (Test-AtlasoProcessIdentityActive -ProcessId $ExpectedOwnerPid -StartTimeUtcTicks $ExpectedOwnerStartTimeUtcTicks)) {
            throw 'Termination proof does not match the exact completed builder child.'
        }
        $controller = Get-Process -Id $PID -ErrorAction Stop
        $proof = [pscustomobject]@{
            Schema = 1
            ReservationSha256 = Get-AtlasoBuilderReservationFingerprint -Reservation $reservation
            ControllerPid = $PID
            ControllerStartTimeUtcTicks = $controller.StartTime.ToUniversalTime().Ticks
            CompletedUtc = [DateTime]::UtcNow.ToString('o')
        }
        $reservation | Add-Member -NotePropertyName TerminationProof -NotePropertyValue $proof -Force
        Write-AtlasoBuilderDurableJsonFile -Path $path -Payload $reservation -Replace
    }
    finally { $pins.Dispose() }
}

function Test-AtlasoBuilderTerminationProof {
    <#
    .SYNOPSIS
    Verify a retained exact-allocation termination receipt for a later caller.
    .PARAMETER Reservation
    Handoff record to check without altering allocation or provider state.
    #>
    param([Parameter(Mandatory = $true)][object]$Reservation)
    if ('TerminationProof' -notin $Reservation.PSObject.Properties.Name) { return $false }
    $proof = $Reservation.TerminationProof
    if ([int]$proof.Schema -ne 1 -or
        [string]$proof.ReservationSha256 -cne (Get-AtlasoBuilderReservationFingerprint -Reservation $Reservation) -or
        [long]$proof.ControllerStartTimeUtcTicks -le 0 -or [int]$proof.ControllerPid -le 0 -or
        ([DateTimeOffset]$proof.CompletedUtc).UtcDateTime -gt [DateTime]::UtcNow) {
        throw 'The retained builder termination receipt does not match its allocation.'
    }
    if (Test-AtlasoProcessIdentityActive -ProcessId ([int]$proof.ControllerPid) -StartTimeUtcTicks ([long]$proof.ControllerStartTimeUtcTicks)) {
        throw 'The original build controller is still active; reservation recovery must wait for it to finish.'
    }
    return $true
}

function Exit-AtlasoVmwareBuilderAddressReservation {
    <#
    .SYNOPSIS
    Release one exact builder reservation after proving its VM is inactive.
    .PARAMETER Reservation
    Exact reservation record returned by the allocator.
    .PARAMETER VmrunPath
    Exact vmrun executable path.
    .PARAMETER StateRoot
    Optional stable per-user reservation state directory.
    .PARAMETER VerifyOnly
    Run release eligibility checks without changing the ledger.
    .PARAMETER ProcessTreeTerminationProven
    Permit the controlling parent to release a dead foreign owner on the same
    host boot only after it has proven termination of the complete child tree.
    #>
    param(
        [Parameter(Mandatory = $true)][object]$Reservation,
        [Parameter(Mandatory = $true)][string]$VmrunPath,
        [string]$StateRoot = '',
        [switch]$ProcessTreeTerminationProven,
        [switch]$VerifyOnly
    )

    $resolvedStateRoot = if ([string]::IsNullOrWhiteSpace($StateRoot)) {
        Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Atlaso\vmware-builder-addresses'
    }
    else {
        [System.IO.Path]::GetFullPath($StateRoot)
    }
    $ledgerPath = Join-Path $resolvedStateRoot 'reservations.json'
    Invoke-WithAtlasoBuilderReservationLock -StateRoot $resolvedStateRoot -ReadOnly:$VerifyOnly -Action {
        $reservations = @(Read-AtlasoBuilderReservationLedger -Path $ledgerPath)
        $matching = @($reservations | Where-Object { [string]$_.Id -ceq [string]$Reservation.Id })
        if ($matching.Count -eq 0) {
            # The ledger removal can durably complete before the caller deletes
            # its handoff. A pre-ledger handoff must remain while its exact owner
            # is active; otherwise absence makes the release safe to replay.
            if (Test-AtlasoProcessIdentityActive `
                    -ProcessId ([int]$Reservation.OwnerPid) `
                    -StartTimeUtcTicks ([long]$Reservation.OwnerStartTimeUtcTicks)) {
                throw "Builder address handoff $($Reservation.Id) remains pending because its exact owner process is still active."
            }
            return
        }
        if ($matching.Count -ne 1 -or
            (Get-AtlasoBuilderReservationFingerprint -Reservation $matching[0]) -cne
            (Get-AtlasoBuilderReservationFingerprint -Reservation $Reservation) -or
            [string]$matching[0].Address -cne [string]$Reservation.Address -or
            [int]$matching[0].OwnerPid -ne [int]$Reservation.OwnerPid -or
            [long]$matching[0].OwnerStartTimeUtcTicks -ne [long]$Reservation.OwnerStartTimeUtcTicks -or
            [string]$matching[0].HostBootIdentity -cne [string]$Reservation.HostBootIdentity -or
            [string]$matching[0].SourceCommit -cne [string]$Reservation.SourceCommit -or
            [string]$matching[0].SourceBranch -cne [string]$Reservation.SourceBranch -or
            [string]$matching[0].VmName -cne [string]$Reservation.VmName -or
            -not [System.IO.Path]::GetFullPath([string]$matching[0].RepositoryRoot).Equals(
                [System.IO.Path]::GetFullPath([string]$Reservation.RepositoryRoot),
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            -not [System.IO.Path]::GetFullPath([string]$matching[0].OutputDirectory).Equals(
                [System.IO.Path]::GetFullPath([string]$Reservation.OutputDirectory),
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            -not [System.IO.Path]::GetFullPath([string]$matching[0].VmxPath).Equals(
                [System.IO.Path]::GetFullPath([string]$Reservation.VmxPath),
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw 'The exact VMware builder-address reservation could not be proven for release.'
        }
        $currentOwner = Get-Process -Id $PID -ErrorAction Stop
        $isExactCurrentOwner = (
            [int]$matching[0].OwnerPid -eq $PID -and
            [long]$matching[0].OwnerStartTimeUtcTicks -eq $currentOwner.StartTime.ToUniversalTime().Ticks
        )
        if (-not $isExactCurrentOwner) {
            $ownerActive = Test-AtlasoProcessIdentityActive `
                -ProcessId ([int]$matching[0].OwnerPid) `
                -StartTimeUtcTicks ([long]$matching[0].OwnerStartTimeUtcTicks)
            if ($ownerActive) {
                throw "Builder address $($matching[0].Address) remains reserved because its exact owner process is still active."
            }
            $currentBootIdentity = Get-AtlasoBuilderHostBootIdentity
            # A new boot proves the old tree gone independently of receipt clocks
            # or contents. Only same-boot recovery depends on that extra evidence.
            if ([string]$matching[0].HostBootIdentity -ceq $currentBootIdentity -and
                -not $ProcessTreeTerminationProven -and
                -not (Test-AtlasoBuilderTerminationProof -Reservation $Reservation)) {
                throw "Builder address $($matching[0].Address) remains reserved because a dead same-boot owner does not prove its descendants are inactive."
            }
        }
        $running = @(Get-AtlasoRunningVmwareVmxPaths -VmrunPath $VmrunPath)
        $vmx = [System.IO.Path]::GetFullPath([string]$matching[0].VmxPath)
        if (@($running | Where-Object { $_.Equals($vmx, [StringComparison]::OrdinalIgnoreCase) }).Count -gt 0) {
            throw "Builder address $($matching[0].Address) remains reserved because its exact VMware VM is still running: $vmx"
        }
        if (-not $isExactCurrentOwner -and
            (Test-AtlasoVmwareAddressObservedInUse -Address ([string]$matching[0].Address) -VmrunPath $VmrunPath)) {
            throw 'The reserved address still has host or VMware usage evidence.'
        }
        if ($VerifyOnly) { return }
        Write-AtlasoBuilderReservationLedger -Path $ledgerPath -Reservations @($reservations | Where-Object {
                [string]$_.Id -cne [string]$Reservation.Id
            })
    }
}

function Invoke-AtlasoBuilderReservationRecovery {
    <#
    .SYNOPSIS
    Inspect or complete one retained reservation without launching a build.
    .PARAMETER HandoffPath
    Exact existing pending-release handoff to inspect.
    .PARAMETER VmrunPath
    Exact VMware Workstation vmrun executable.
    .PARAMETER StateRoot
    Optional existing shared allocation directory; defaults to the allocator's directory.
    .PARAMETER Execute
    Release the exact verified reservation and then remove its handoff.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$HandoffPath,
        [Parameter(Mandatory = $true)][string]$VmrunPath,
        [string]$StateRoot = '',
        [switch]$Execute
    )
    $path = [IO.Path]::GetFullPath($HandoffPath)
    $result = [ordered]@{ Id = ''; Address = ''; Status = 'blocked'; Reason = ''; HandoffPath = $path }
    $pins = $null
    $filePin = $null
    $statePin = $null
    try {
        if ((Split-Path -Leaf $path) -notmatch '^builder-address-reservation-[0-9a-f]{32}\.json$' -or
            (Split-Path -Leaf (Split-Path -Parent $path)) -cne 'pending-releases') {
            throw 'Select one exact pending-release handoff file.'
        }
        $pins = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath((Split-Path -Parent $path), $true)
        $filePin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($path, $true, [bool]$Execute)
        $borrowed = [Microsoft.Win32.SafeHandles.SafeFileHandle]::new($filePin.DangerousGetHandle(), $false)
        $reader = [IO.StreamReader]::new([IO.FileStream]::new($borrowed, [IO.FileAccess]::Read))
        try {
            if ($reader.BaseStream.Length -gt 16384) { throw 'Reservation handoff exceeds its size limit.' }
            $reservation = $reader.ReadToEnd() | ConvertFrom-Json
        }
        finally { $reader.Dispose() }
        $result.Id = [string]$reservation.Id
        $result.Address = [string]$reservation.Address
        foreach ($field in @('RepositoryRoot', 'SourceCommit', 'SourceBranch', 'VmName', 'VmxPath',
                'OutputDirectory', 'OwnerPid', 'OwnerStartTimeUtcTicks', 'HostBootIdentity')) {
            $result[$field] = $reservation.$field
        }
        $result.CurrentHostBootIdentity = Get-AtlasoBuilderHostBootIdentity
        if ($result.Id -notmatch '^[0-9a-f]{32}$' -or [string]$reservation.SourceCommit -notmatch '^[0-9a-f]{40}$' -or
            [string]$reservation.HostBootIdentity -notmatch '^[0-9]{1,19}$' -or
            [int]$reservation.OwnerPid -le 0 -or [long]$reservation.OwnerStartTimeUtcTicks -le 0) {
            throw 'Reservation handoff has invalid allocation identity.'
        }
        $null = ConvertTo-AtlasoIpv4Integer -Address $result.Address
        $resolvedState = if ([string]::IsNullOrWhiteSpace($StateRoot)) {
            Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Atlaso\vmware-builder-addresses'
        } else { [IO.Path]::GetFullPath($StateRoot) }
        $statePin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($resolvedState, $true)
        if (-not (Test-Path -LiteralPath (Join-Path $resolvedState 'reservations.json') -PathType Leaf)) {
            throw 'The allocation ledger is missing; handoff absence from it cannot be proven.'
        }
        # Explicitly reject a still-active owner even if recovery runs in that process.
        if (Test-AtlasoProcessIdentityActive -ProcessId ([int]$reservation.OwnerPid) -StartTimeUtcTicks ([long]$reservation.OwnerStartTimeUtcTicks)) {
            throw 'The exact allocation owner is still active.'
        }
        Exit-AtlasoVmwareBuilderAddressReservation -Reservation $reservation -VmrunPath $VmrunPath -StateRoot $resolvedState -VerifyOnly
        $entries = @(Read-AtlasoBuilderReservationLedger -Path (Join-Path $resolvedState 'reservations.json'))
        $result.Status = if (@($entries | Where-Object { [string]$_.Id -ceq $result.Id }).Count -eq 0) { 'already-released' } else { 'releasable' }
        $result.Reason = 'Exact allocation and inactive VM verified.'
        if ($Execute) {
            # The release primitive repeats ownership, receipt, and provider checks
            # under the same shared allocator lock used by new builds.
            Exit-AtlasoVmwareBuilderAddressReservation -Reservation $reservation -VmrunPath $VmrunPath -StateRoot $resolvedState
            [Atlaso.WorkstationFileIdentity]::DeletePinnedFile($filePin)
            $filePin.Dispose()
            $filePin = $null
            if (Test-Path -LiteralPath $path) { throw 'The released handoff remains; retry completion.' }
            $result.Status = 'released'
            $result.Reason = 'Exact reservation released and handoff removed.'
        }
    }
    catch { $result.Status = 'blocked'; $result.Reason = $_.Exception.Message }
    finally {
        if ($null -ne $filePin) { $filePin.Dispose() }
        if ($null -ne $pins) { $pins.Dispose() }
        if ($null -ne $statePin) { $statePin.Dispose() }
    }
    return [pscustomobject]$result
}

Export-ModuleMember -Function @(
    'Save-AtlasoBuilderTerminationProof',
    'Invoke-AtlasoBuilderReservationRecovery',
    'Assert-AtlasoBuilderHandoffRootIdentity',
    'Initialize-AtlasoBuilderHandoffRoot',
    'Get-AtlasoVmwareDhcpExclusions',
    'Enter-AtlasoVmwareBuilderAddressReservation',
    'Exit-AtlasoVmwareBuilderAddressReservation'
)
