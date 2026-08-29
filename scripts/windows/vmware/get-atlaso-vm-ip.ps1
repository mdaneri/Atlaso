<#
.SYNOPSIS
Wait for a uniquely bound VMware Workstation test-appliance IPv4 address.

.DESCRIPTION
Reads the address reported by VMware Tools for the exact target VMX, compares it
with every running VMware guest, and requires the Windows neighbor entry for the
host-facing address to match the target management NIC MAC. It also requires the
guest-published hostname to match the injected hostname. A duplicate static address
or ambiguous or incomplete identity observation fails closed before readiness is returned.

.PARAMETER VmxPath
Exact running VMX expected to own the management address.
.PARAMETER ExpectedHostname
Hostname injected into this clone's first-boot environment.
.PARAMETER VmrunPath
Optional VMware vmrun executable override.
.PARAMETER TimeoutSeconds
Total bounded readiness wait.
.PARAMETER PollSeconds
Delay between transiently incomplete readiness observations.
.PARAMETER PassThruIdentity
Return the VMX, MAC, hostname, and address object instead of only the address.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$VmxPath,
    [Parameter(Mandatory = $true)][string]$ExpectedHostname,
    [string]$VmrunPath = '',
    [int]$TimeoutSeconds = 120,
    [int]$PollSeconds = 5,
    [switch]$PassThruIdentity
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Atlaso.WorkstationReadiness.psm1') -Force

<#
.SYNOPSIS
Resolve the VMware vmrun executable.
.PARAMETER Path
Optional explicit executable path.
#>
function Resolve-VmrunPath {
    param([string]$Path)
    if ($Path) {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "vmrun.exe not found: $Path" }
        return (Resolve-Path -LiteralPath $Path).Path
    }
    foreach ($candidate in @(
            'C:\Program Files\VMware\VMware Workstation\vmrun.exe',
            'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
        )) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    $command = Get-Command vmrun -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    throw 'vmrun.exe was not found. Install VMware Workstation Pro or pass -VmrunPath.'
}

<#
.SYNOPSIS
Read one usable IPv4 address reported by VMware Tools.
.PARAMETER VmrunPath
Resolved vmrun executable.
.PARAMETER VmxPath
Exact running VMX to query.
.PARAMETER Deadline
Absolute readiness deadline that bounds the provider query.
#>
function Get-VmwareGuestIPv4Address {
    param(
        [Parameter(Mandatory = $true)][string]$VmrunPath,
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $true)][datetime]$Deadline
    )
    $arguments = @('-T', 'ws', 'getGuestIPAddress', $VmxPath)
    $result = Invoke-AtlasoWorkstationVmrunBounded `
        -VmrunPath $VmrunPath -Arguments $arguments -Deadline $Deadline
    $reported = @($result.StdOut -split '\r?\n' | Where-Object { $_ }) | Select-Object -First 1
    if ($result.TimedOut -or $result.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($reported)) { return '' }
    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($reported.Trim(), [ref]$parsed) -or
        $parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -or
        [System.Net.IPAddress]::IsLoopback($parsed)) { return '' }
    $bytes = $parsed.GetAddressBytes()
    if (($bytes[0] -eq 169 -and $bytes[1] -eq 254) -or $bytes[0] -ge 224) { return '' }
    return $parsed.ToString()
}

<#
.SYNOPSIS
Read the actual first-boot hostname published through VMware Tools.
.PARAMETER VmrunPath
Resolved vmrun executable.
.PARAMETER VmxPath
Exact running VMX to query.
.PARAMETER Deadline
Absolute readiness deadline that bounds the provider query.
#>
function Get-VmwareGuestHostname {
    param(
        [Parameter(Mandatory = $true)][string]$VmrunPath,
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $true)][datetime]$Deadline
    )
    $arguments = @(
        '-T', 'ws', 'readVariable', $VmxPath, 'runtimeConfig',
        'guestinfo.atlaso.test_vm_hostname'
    )
    $result = Invoke-AtlasoWorkstationVmrunBounded `
        -VmrunPath $VmrunPath -Arguments $arguments -Deadline $Deadline
    $reported = @($result.StdOut -split '\r?\n' | Where-Object { $_ }) | Select-Object -First 1
    if ($result.TimedOut -or $result.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($reported)) { return '' }
    return ConvertFrom-AtlasoWorkstationRuntimeConfigValue -Value $reported
}

<#
.SYNOPSIS
Return usable Windows neighbor MAC evidence for an IPv4 address.
.PARAMETER IPAddress
Host-facing IPv4 address to populate and inspect.
#>
function Get-HostNeighborMacAddress {
    param([Parameter(Mandatory = $true)][string]$IPAddress)
    # Populate the cache immediately before inspection. A stale or wrong owner
    # is ambiguity evidence, never a reason to continue with host-side probes.
    Test-Connection -TargetName $IPAddress -Count 1 -Quiet -TimeoutSeconds 1 -ErrorAction SilentlyContinue | Out-Null
    return @(
        Get-NetNeighbor -AddressFamily IPv4 -IPAddress $IPAddress -ErrorAction SilentlyContinue |
            Where-Object {
                $_.State -notin @('Unreachable', 'Incomplete') -and
                -not [string]::IsNullOrWhiteSpace($_.LinkLayerAddress)
            } |
            ForEach-Object { $_.LinkLayerAddress }
    )
}

$resolvedVmxPath = (Resolve-Path -LiteralPath $VmxPath -ErrorAction Stop).Path
$resolvedVmrun = Resolve-VmrunPath -Path $VmrunPath
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
$lastReadinessError = ''
do {
    $ipAddress = Get-VmwareGuestIPv4Address `
        -VmrunPath $resolvedVmrun -VmxPath $resolvedVmxPath -Deadline $deadline
    if ($ipAddress) {
        try {
            $observedHostname = Get-VmwareGuestHostname `
                -VmrunPath $resolvedVmrun -VmxPath $resolvedVmxPath -Deadline $deadline
            $runningPaths = @(
                Get-AtlasoWorkstationRunningVmxPath -VmrunPath $resolvedVmrun -Deadline $deadline
            )
            $runningGuests = @(
                foreach ($runningPath in $runningPaths) {
                    $runningIpAddress = if ($runningPath.Equals(
                            $resolvedVmxPath,
                            [System.StringComparison]::OrdinalIgnoreCase
                        )) {
                        $ipAddress
                    } else {
                        Get-VmwareGuestIPv4Address `
                            -VmrunPath $resolvedVmrun -VmxPath $runningPath -Deadline $deadline
                    }
                    [pscustomobject]@{
                        Path       = $runningPath
                        MacAddress = Get-AtlasoWorkstationVmxMacAddress -VmxPath $runningPath
                        IPAddress  = $runningIpAddress
                    }
                }
            )
            $targetMacAddress = Get-AtlasoWorkstationVmxMacAddress -VmxPath $resolvedVmxPath
            Assert-AtlasoWorkstationAddressIdentity `
                -TargetVmxPath $resolvedVmxPath `
                -TargetMacAddress $targetMacAddress `
                -TargetIPAddress $ipAddress `
                -ExpectedHostname $ExpectedHostname `
                -ObservedHostname $observedHostname `
                -RunningGuests $runningGuests `
                -NeighborMacAddresses @(Get-HostNeighborMacAddress -IPAddress $ipAddress) | Out-Null
            # Close the concurrent-start window after the slower per-guest and
            # neighbor observations. Readiness is returned only from a stable
            # running set whose target still reports the proven address.
            $confirmedPaths = @(
                Get-AtlasoWorkstationRunningVmxPath -VmrunPath $resolvedVmrun -Deadline $deadline
            )
            $confirmedGuests = @(
                foreach ($confirmedPath in $confirmedPaths) {
                    [pscustomobject]@{
                        Path       = $confirmedPath
                        MacAddress = Get-AtlasoWorkstationVmxMacAddress -VmxPath $confirmedPath
                        IPAddress  = Get-VmwareGuestIPv4Address `
                            -VmrunPath $resolvedVmrun `
                            -VmxPath $confirmedPath `
                            -Deadline $deadline
                    }
                }
            )
            $confirmedTarget = @($confirmedGuests | Where-Object {
                    $_.Path.Equals($resolvedVmxPath, [System.StringComparison]::OrdinalIgnoreCase)
                })
            $confirmedIpAddress = if ($confirmedTarget.Count -eq 1) {
                $confirmedTarget[0].IPAddress
            } else { '' }
            Assert-AtlasoWorkstationStableObservation `
                -InitialVmxPaths $runningPaths `
                -ConfirmedVmxPaths $confirmedPaths `
                -InitialTargetIPAddress $ipAddress `
                -ConfirmedTargetIPAddress $confirmedIpAddress `
                -InitialRunningGuests $runningGuests `
                -ConfirmedRunningGuests $confirmedGuests
            $confirmedIdentity = Assert-AtlasoWorkstationAddressIdentity `
                -TargetVmxPath $resolvedVmxPath `
                -TargetMacAddress $targetMacAddress `
                -TargetIPAddress $confirmedIpAddress `
                -ExpectedHostname $ExpectedHostname `
                -ObservedHostname (Get-VmwareGuestHostname `
                    -VmrunPath $resolvedVmrun `
                    -VmxPath $resolvedVmxPath `
                    -Deadline $deadline) `
                -RunningGuests $confirmedGuests `
                -NeighborMacAddresses @(Get-HostNeighborMacAddress -IPAddress $confirmedIpAddress)
            Write-Information `
                "Verified VMware readiness: VMX='$($confirmedIdentity.VmxPath)'; MAC=$($confirmedIdentity.MacAddress); hostname=$($confirmedIdentity.Hostname); host address=$($confirmedIdentity.IPAddress)" `
                -InformationAction Continue
            if ($PassThruIdentity) { return $confirmedIdentity }
            return $confirmedIdentity.IPAddress
        } catch {
            $lastReadinessError = $_.Exception.Message
            if ($lastReadinessError -like 'Duplicate VMware management address*' -or
                $lastReadinessError -like 'VMware guest hostname mismatch*' -or
                $lastReadinessError -like 'VMware runtimeConfig representation is malformed*' -or
                ($lastReadinessError -like 'Host-facing address*' -and
                    $lastReadinessError -notlike '*Windows neighbor evidence is <none>*')) { throw }
        }
    }
    if ((Get-Date) -lt $deadline) { Start-Sleep -Seconds $PollSeconds }
} while ((Get-Date) -lt $deadline)

$detail = if ($lastReadinessError) { " Last readiness error: $lastReadinessError" } else { '' }
throw "No uniquely bound IPv4 address was proven for VM '$resolvedVmxPath' within $TimeoutSeconds seconds.$detail Confirm open-vm-tools, the exact VMX management MAC, and Windows neighbor state."
