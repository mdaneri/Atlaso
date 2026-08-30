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
Read one bounded first-boot hostname observation through VMware Tools.
.PARAMETER VmrunPath
Resolved vmrun executable.
.PARAMETER VmxPath
Exact running VMX to query.
.PARAMETER Deadline
Absolute readiness deadline that bounds the provider query.
#>
function Get-VmwareGuestHostnameObservation {
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
    if ($result.TimedOut) {
        return [pscustomobject]@{ Value = ''; TimedOut = $true; Succeeded = $false; ExitCode = -1 }
    }
    if ($result.ExitCode -ne 0) {
        return [pscustomobject]@{
            Value = ''; TimedOut = $false; Succeeded = $false; ExitCode = $result.ExitCode
        }
    }
    if ([string]::IsNullOrWhiteSpace($reported)) {
        return [pscustomobject]@{ Value = ''; TimedOut = $false; Succeeded = $true; ExitCode = 0 }
    }
    return [pscustomobject]@{
        Value    = ConvertFrom-AtlasoWorkstationRuntimeConfigValue -Value $reported
        TimedOut = $false
        Succeeded = $true
        ExitCode = 0
    }
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
$lastAddressOwnership = $null
$lastObservedHostname = ''
$lastFirstBootStage = ''
$lastHostnameObservationState = 'Unobserved'
$lastHostnameProviderExitCode = $null
do {
    # Diagnostic ownership is valid only for the current complete observation.
    # A later poll that loses Tools, inventory, or neighbor evidence must not
    # reuse an older tuple to diagnose a guest-initialization stall.
    $lastAddressOwnership = $null
    $lastObservedHostname = ''
    $lastFirstBootStage = ''
    $lastHostnameObservationState = 'Unobserved'
    $lastHostnameProviderExitCode = $null
    $ipAddress = Get-VmwareGuestIPv4Address `
        -VmrunPath $resolvedVmrun -VmxPath $resolvedVmxPath -Deadline $deadline
    if ($ipAddress) {
        try {
            # Normalize provider representation before host network probing so
            # malformed guest-info remains an immediate fail-closed boundary.
            $initialHostnameObservation = Get-VmwareGuestHostnameObservation `
                -VmrunPath $resolvedVmrun -VmxPath $resolvedVmxPath -Deadline $deadline
            if ($initialHostnameObservation.TimedOut) {
                $lastHostnameObservationState = 'TimedOut'
                throw 'Read the VMware guest hostname exceeded the readiness deadline.'
            }
            if ($initialHostnameObservation.Succeeded) {
                $lastHostnameObservationState = 'Answered'
                $lastObservedHostname = $initialHostnameObservation.Value
            }
            else {
                # Preserve provider failure independently from a successful empty
                # answer so address ownership can still be proven truthfully.
                $lastHostnameObservationState = 'ProviderFailed'
                $lastHostnameProviderExitCode = $initialHostnameObservation.ExitCode
            }
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
            $initialOwnership = Assert-AtlasoWorkstationAddressOwnership `
                -TargetVmxPath $resolvedVmxPath `
                -TargetMacAddress $targetMacAddress `
                -TargetIPAddress $ipAddress `
                -RunningGuests $runningGuests `
                -NeighborMacAddresses @(Get-HostNeighborMacAddress -IPAddress $ipAddress)
            $lastAddressOwnership = $initialOwnership
            $confirmedHostnameObservation = Get-VmwareGuestHostnameObservation `
                -VmrunPath $resolvedVmrun `
                -VmxPath $resolvedVmxPath `
                -Deadline $deadline
            if ($confirmedHostnameObservation.Succeeded) {
                $lastHostnameObservationState = 'Answered'
                $lastObservedHostname = $confirmedHostnameObservation.Value
            }
            elseif (-not $confirmedHostnameObservation.TimedOut) {
                $lastHostnameObservationState = 'ProviderFailed'
                $lastHostnameProviderExitCode = $confirmedHostnameObservation.ExitCode
            }
            else {
                # The earlier hostname remains useful diagnostic evidence, but
                # ownership may have changed while the confirmation provider was
                # stalled. Never return readiness without a fresh complete proof.
                $lastHostnameObservationState = 'TimedOut'
            }
            if ($lastHostnameObservationState -eq 'ProviderFailed') {
                throw "Read the VMware guest hostname failed with exit code $lastHostnameProviderExitCode."
            }
            if ($lastHostnameObservationState -eq 'TimedOut') {
                throw 'Read the VMware guest hostname exceeded the readiness deadline.'
            }
            # From this point forward, the initial tuple is stale diagnostic
            # evidence. The optional first-boot-stage read is another provider
            # call during which ownership can change, so require a fresh complete
            # proof after it before retaining an ownership tuple.
            $lastAddressOwnership = $null
            if (-not $lastObservedHostname) {
                $stage = Get-AtlasoWorkstationFirstBootStage `
                    -VmxPath $resolvedVmxPath `
                    -VmrunPath $resolvedVmrun `
                    -Deadline $deadline
                if ($stage) { $lastFirstBootStage = $stage }
            }
            # Close the hostname, diagnostic-stage, and concurrent-start windows.
            # Readiness or an initialization diagnosis is returned only from a
            # stable final inventory, target address, and neighbor proof.
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
            $confirmedOwnership = Assert-AtlasoWorkstationAddressOwnership `
                -TargetVmxPath $resolvedVmxPath `
                -TargetMacAddress $targetMacAddress `
                -TargetIPAddress $confirmedIpAddress `
                -RunningGuests $confirmedGuests `
                -NeighborMacAddresses @(Get-HostNeighborMacAddress -IPAddress $confirmedIpAddress)
            $lastAddressOwnership = $confirmedOwnership
            $confirmedHostname = Assert-AtlasoWorkstationHostnameIdentity `
                -TargetVmxPath $resolvedVmxPath `
                -ExpectedHostname $ExpectedHostname `
                -ObservedHostname $lastObservedHostname
            $confirmedIdentity = [pscustomobject]@{
                VmxPath    = $confirmedOwnership.VmxPath
                MacAddress = $confirmedOwnership.MacAddress
                Hostname   = $confirmedHostname
                IPAddress  = $confirmedOwnership.IPAddress
            }
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

$normalizedExpectedHostname = $ExpectedHostname.Trim().TrimEnd('.').ToLowerInvariant()
if ($null -ne $lastAddressOwnership) {
    if ($lastHostnameObservationState -eq 'ProviderFailed') {
        throw "An initial VMware ownership observation completed for VMX '$($lastAddressOwnership.VmxPath)', MAC $($lastAddressOwnership.MacAddress), and host-facing address $($lastAddressOwnership.IPAddress), but the VMware Tools hostname evidence query failed with exit code $lastHostnameProviderExitCode. Readiness was not returned; retry the complete proof after restoring the VMware Tools provider path. No guest-initialization conclusion was made."
    }
    if ($lastHostnameObservationState -eq 'TimedOut') {
        $earlierHostname = if ($lastObservedHostname) { $lastObservedHostname } else { '<not reported>' }
        throw "An initial VMware ownership observation completed for VMX '$($lastAddressOwnership.VmxPath)', MAC $($lastAddressOwnership.MacAddress), and host-facing address $($lastAddressOwnership.IPAddress), but the VMware Tools hostname confirmation exceeded the shared $TimeoutSeconds-second readiness deadline. Earlier observed hostname: '$earlierHostname'. Readiness was not returned because ownership could have changed during the stalled provider call; retry the complete proof with a responsive VMware Tools provider."
    }
    $observedHostname = if ($lastObservedHostname) { $lastObservedHostname } else { '<not reported>' }
    $stageDetail = if ($lastFirstBootStage) {
        " Last allowlisted first-boot stage: '$lastFirstBootStage'."
    }
    else {
        ' No allowlisted first-boot stage was reported.'
    }
    throw "VMware address ownership was proven for VMX '$($lastAddressOwnership.VmxPath)', MAC $($lastAddressOwnership.MacAddress), and host-facing address $($lastAddressOwnership.IPAddress), but guest initialization did not publish the injected hostname '$normalizedExpectedHostname' within $TimeoutSeconds seconds. Observed hostname: '$observedHostname'.$stageDetail The HTTPS/application readiness path was not reached; inspect the appliance console and first-boot service state."
}
$detail = if ($lastReadinessError) { " Last readiness error: $lastReadinessError" } else { '' }
throw "No uniquely bound IPv4 address was proven for VM '$resolvedVmxPath' within $TimeoutSeconds seconds.$detail Confirm open-vm-tools, the exact VMX management MAC, and Windows neighbor state."
