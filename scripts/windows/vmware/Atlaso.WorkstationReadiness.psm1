<#
.SYNOPSIS
Fail-closed identity checks for a VMware Workstation test appliance address.

.DESCRIPTION
Normalizes VMX management-NIC identity and proves that one host-facing IPv4
address belongs uniquely to the expected running VM. The decision layer accepts
provider and Windows neighbor evidence as explicit inputs so focused tests can
exercise duplicate static-address and wrong-neighbor failures without mutating
VMware or host network state.
#>

Set-StrictMode -Version Latest

<#
.SYNOPSIS
Normalize a VMware ethernet MAC address.

.PARAMETER MacAddress
Colon, hyphen, or compact hexadecimal MAC address.
#>
function ConvertTo-AtlasoWorkstationMacAddress {
    param([Parameter(Mandatory = $true)][string]$MacAddress)

    if ($MacAddress -notmatch '^(?:[0-9A-Fa-f]{12}|(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}|(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2})$') {
        throw "VMware management MAC address is malformed: $MacAddress"
    }
    $compact = $MacAddress -replace '[:-]', ''
    return (($compact.ToLowerInvariant() -split '(.{2})' | Where-Object { $_ }) -join '-')
}

<#
.SYNOPSIS
Read the single management-adapter MAC address from a VMX.

.PARAMETER VmxPath
Exact VMX file whose ethernet0 identity is required.
#>
function Get-AtlasoWorkstationVmxMacAddress {
    param([Parameter(Mandatory = $true)][string]$VmxPath)

    $resolvedVmxPath = (Resolve-Path -LiteralPath $VmxPath -ErrorAction Stop).Path
    $assignments = @(
        Get-Content -LiteralPath $resolvedVmxPath -ErrorAction Stop |
            Where-Object { $_ -match '^\s*ethernet0\.(?:address|generatedAddress)\s*=' }
    )
    $values = @()
    foreach ($assignment in $assignments) {
        if ($assignment -notmatch '^\s*ethernet0\.(?:address|generatedAddress)\s*=\s*"(?<mac>[^"]+)"\s*$') {
            throw "VMware management MAC assignment is malformed in VMX: $resolvedVmxPath"
        }
        $values += ConvertTo-AtlasoWorkstationMacAddress -MacAddress $Matches.mac
    }
    $uniqueValues = @($values | Sort-Object -Unique)
    if ($uniqueValues.Count -ne 1) {
        throw "VMX must contain one unambiguous ethernet0 MAC address before readiness can be reported: $resolvedVmxPath"
    }
    return $uniqueValues[0]
}

<#
.SYNOPSIS
Run one vmrun command within the shared readiness deadline.

.PARAMETER VmrunPath
Resolved vmrun executable.

.PARAMETER Arguments
Exact vmrun argument list.

.PARAMETER Deadline
Absolute readiness deadline that bounds this provider call.
#>
function Invoke-AtlasoWorkstationVmrunBounded {
    param(
        [Parameter(Mandatory = $true)][string]$VmrunPath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][datetime]$Deadline
    )

    $remainingMilliseconds = [int][Math]::Floor(($Deadline - (Get-Date)).TotalMilliseconds)
    if ($remainingMilliseconds -le 0) {
        return [pscustomobject]@{ ExitCode = -1; TimedOut = $true; StdOut = ''; StdErr = '' }
    }
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $VmrunPath
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in $Arguments) { [void]$startInfo.ArgumentList.Add($argument) }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        [void]$process.Start()
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($remainingMilliseconds)) {
            try {
                $process.Kill($true)
                [void]$process.WaitForExit(1000)
            }
            catch {
                Write-Verbose 'Unable to confirm termination of the timed-out vmrun process.'
            }
            return [pscustomobject]@{ ExitCode = -1; TimedOut = $true; StdOut = ''; StdErr = '' }
        }
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            TimedOut = $false
            StdOut   = $stdoutTask.GetAwaiter().GetResult()
            StdErr   = $stderrTask.GetAwaiter().GetResult()
        }
    }
    finally {
        $process.Dispose()
    }
}

<#
.SYNOPSIS
Return the checked running VMware Workstation VMX paths.

.PARAMETER VmrunPath
Resolved vmrun executable used for the provider inventory.

.PARAMETER Deadline
Absolute readiness deadline that bounds the inventory query.
#>
function Get-AtlasoWorkstationRunningVmxPath {
    param(
        [Parameter(Mandatory = $true)][string]$VmrunPath,
        [Parameter(Mandatory = $true)][datetime]$Deadline
    )

    $result = Invoke-AtlasoWorkstationVmrunBounded `
        -VmrunPath $VmrunPath `
        -Arguments @('-T', 'ws', 'list') `
        -Deadline $Deadline
    if ($result.TimedOut) {
        throw 'List running VMware Workstation VMs exceeded the readiness deadline.'
    }
    if ($result.ExitCode -ne 0) {
        throw "List running VMware Workstation VMs failed with exit code $($result.ExitCode)."
    }
    $output = @($result.StdOut -split '\r?\n' | Where-Object { $_ -ne '' })
    if ($output.Count -lt 1 -or $output[0].ToString() -notmatch '^Total running VMs:\s*(?<count>\d+)\s*$') {
        throw 'vmrun list returned an unrecognized running-VM inventory.'
    }
    $declaredCount = [int]$Matches.count
    $paths = @(
        $output | Select-Object -Skip 1 | ForEach-Object {
            $candidate = $_.ToString().Trim()
            if ($candidate.StartsWith('"') -and $candidate.EndsWith('"') -and $candidate.Length -ge 2) {
                $candidate = $candidate.Substring(1, $candidate.Length - 2)
            }
            if ($candidate) { $candidate }
        }
    )
    if ($paths.Count -ne $declaredCount) {
        throw "vmrun list reported $declaredCount VMs but returned $($paths.Count) paths."
    }
    $resolvedPaths = @()
    foreach ($path in $paths) {
        if (-not [System.IO.Path]::IsPathFullyQualified($path) -or
            $path.Contains('"') -or
            [System.IO.Path]::GetExtension($path) -ine '.vmx' -or
            -not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw 'vmrun list returned a non-absolute, malformed, missing, or non-VMX running path.'
        }
        $resolvedPaths += (Resolve-Path -LiteralPath $path -ErrorAction Stop).Path
    }
    return $resolvedPaths
}

<#
.SYNOPSIS
Normalize one value returned by a VMware runtimeConfig read.

.PARAMETER Value
Raw stdout value returned by vmrun readVariable.
#>
function ConvertFrom-AtlasoWorkstationRuntimeConfigValue {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)

    $candidate = $Value.Trim()
    if (-not $candidate) {
        return ''
    }

    $startsWithQuote = $candidate.StartsWith('"')
    $endsWithQuote = $candidate.EndsWith('"')
    if ($startsWithQuote -xor $endsWithQuote) {
        throw 'VMware runtimeConfig representation is malformed because its surrounding quotes are unbalanced.'
    }
    if ($startsWithQuote) {
        if ($candidate.Length -lt 2) {
            throw 'VMware runtimeConfig representation is malformed because it contains only one quote.'
        }
        $candidate = $candidate.Substring(1, $candidate.Length - 2)
    }
    if ($candidate.Contains('"')) {
        throw 'VMware runtimeConfig representation is malformed because its quoting is ambiguous.'
    }
    return $candidate
}

<#
.SYNOPSIS
Prove that a host-facing address belongs uniquely to one running VMX.

.PARAMETER TargetVmxPath
Exact VMX expected to own the address.

.PARAMETER TargetMacAddress
Management NIC MAC read from the target VMX.

.PARAMETER TargetIPAddress
IPv4 address reported by VMware Tools for the target.

.PARAMETER RunningGuests
Running VMware guests with Path, MacAddress, and IPAddress properties.

.PARAMETER NeighborMacAddresses
Usable Windows IPv4-neighbor MAC entries for the target address.
#>
function Assert-AtlasoWorkstationAddressOwnership {
    param(
        [Parameter(Mandatory = $true)][string]$TargetVmxPath,
        [Parameter(Mandatory = $true)][string]$TargetMacAddress,
        [Parameter(Mandatory = $true)][string]$TargetIPAddress,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$RunningGuests,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$NeighborMacAddresses
    )

    $resolvedTargetVmxPath = (Resolve-Path -LiteralPath $TargetVmxPath -ErrorAction Stop).Path
    $normalizedTargetMac = ConvertTo-AtlasoWorkstationMacAddress -MacAddress $TargetMacAddress
    $targetRows = @($RunningGuests | Where-Object {
            $_.Path -and (Resolve-Path -LiteralPath $_.Path -ErrorAction Stop).Path.Equals(
                $resolvedTargetVmxPath,
                [System.StringComparison]::OrdinalIgnoreCase
            )
        })
    if ($targetRows.Count -ne 1) {
        throw "Readiness cannot bind the address because the exact target VMX is not uniquely present in the running inventory: $resolvedTargetVmxPath"
    }
    $inventoryTargetMac = ConvertTo-AtlasoWorkstationMacAddress -MacAddress $targetRows[0].MacAddress
    if ($inventoryTargetMac -ne $normalizedTargetMac -or $targetRows[0].IPAddress -ne $TargetIPAddress) {
        throw "Readiness inventory evidence does not match target VMX '$resolvedTargetVmxPath', MAC $normalizedTargetMac, and address $TargetIPAddress."
    }

    $incompleteGuests = @($RunningGuests | Where-Object { [string]::IsNullOrWhiteSpace($_.IPAddress) })
    if ($incompleteGuests.Count -gt 0) {
        $incompletePath = (Resolve-Path -LiteralPath $incompleteGuests[0].Path -ErrorAction Stop).Path
        throw "Running VMware guest inventory is incomplete because VMX '$incompletePath' did not report a usable IPv4 address."
    }

    $conflicts = @($RunningGuests | Where-Object {
            $_.Path -and
            -not (Resolve-Path -LiteralPath $_.Path -ErrorAction Stop).Path.Equals(
                $resolvedTargetVmxPath,
                [System.StringComparison]::OrdinalIgnoreCase
            ) -and
            $_.IPAddress -eq $TargetIPAddress
        })
    if ($conflicts.Count -gt 0) {
        $conflict = $conflicts[0]
        $conflictPath = (Resolve-Path -LiteralPath $conflict.Path -ErrorAction Stop).Path
        $conflictMac = ConvertTo-AtlasoWorkstationMacAddress -MacAddress $conflict.MacAddress
        throw "Duplicate VMware management address $TargetIPAddress`: target VMX '$resolvedTargetVmxPath' uses MAC $normalizedTargetMac, but running VMX '$conflictPath' uses MAC $conflictMac and reports the same address. Stop or readdress the conflicting VM before retrying."
    }

    $normalizedNeighborMacs = @(
        $NeighborMacAddresses |
            ForEach-Object { ConvertTo-AtlasoWorkstationMacAddress -MacAddress $_ } |
            Sort-Object -Unique
    )
    if ($normalizedNeighborMacs.Count -ne 1 -or $normalizedNeighborMacs[0] -ne $normalizedTargetMac) {
        $observed = if ($normalizedNeighborMacs.Count -gt 0) { $normalizedNeighborMacs -join ', ' } else { '<none>' }
        $owner = $RunningGuests | Where-Object {
            $_.MacAddress -and
            (ConvertTo-AtlasoWorkstationMacAddress -MacAddress $_.MacAddress) -ne $normalizedTargetMac -and
            (ConvertTo-AtlasoWorkstationMacAddress -MacAddress $_.MacAddress) -in $normalizedNeighborMacs
        } | Select-Object -First 1
        $ownerDetail = if ($owner) {
            " The observed MAC belongs to running VMX '$((Resolve-Path -LiteralPath $owner.Path -ErrorAction Stop).Path)'."
        }
        else { '' }
        throw "Host-facing address $TargetIPAddress is not bound uniquely to target MAC $normalizedTargetMac; Windows neighbor evidence is $observed.$ownerDetail Stop or readdress the conflicting VM and retry."
    }

    return [pscustomobject]@{
        VmxPath    = $resolvedTargetVmxPath
        MacAddress = $normalizedTargetMac
        IPAddress  = $TargetIPAddress
    }
}

<#
.SYNOPSIS
Prove that a guest-published hostname matches the injected hostname.

.PARAMETER TargetVmxPath
Exact VMX whose guest-published hostname is being checked.

.PARAMETER ExpectedHostname
Hostname injected into the target's first-boot environment.

.PARAMETER ObservedHostname
Actual hostname published by the target through VMware Tools after first boot.
#>
function Assert-AtlasoWorkstationHostnameIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$TargetVmxPath,
        [Parameter(Mandatory = $true)][string]$ExpectedHostname,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$ObservedHostname
    )

    $resolvedTargetVmxPath = (Resolve-Path -LiteralPath $TargetVmxPath -ErrorAction Stop).Path
    $normalizedExpectedHostname = $ExpectedHostname.Trim().TrimEnd('.').ToLowerInvariant()
    $normalizedObservedHostname = $ObservedHostname.Trim().TrimEnd('.').ToLowerInvariant()
    if (-not $normalizedExpectedHostname) {
        throw "Expected VMware guest hostname is empty for target VMX '$resolvedTargetVmxPath'."
    }
    if (-not $normalizedObservedHostname) {
        throw "VMware guest hostname evidence is incomplete for target VMX '$resolvedTargetVmxPath'."
    }
    if ($normalizedObservedHostname -ne $normalizedExpectedHostname) {
        throw "VMware guest hostname mismatch for target VMX '$resolvedTargetVmxPath': expected '$normalizedExpectedHostname', but VMware Tools reported '$normalizedObservedHostname'."
    }
    return $normalizedObservedHostname
}

<#
.SYNOPSIS
Prove the complete VMX, MAC, address, neighbor, and hostname identity tuple.

.PARAMETER TargetVmxPath
Exact VMX expected to own the address.

.PARAMETER TargetMacAddress
Management NIC MAC read from the target VMX.

.PARAMETER TargetIPAddress
IPv4 address reported by VMware Tools for the target.

.PARAMETER ExpectedHostname
Hostname injected into the target's first-boot environment.

.PARAMETER ObservedHostname
Actual hostname published by the target through VMware Tools after first boot.

.PARAMETER RunningGuests
Running VMware guests with Path, MacAddress, and IPAddress properties.

.PARAMETER NeighborMacAddresses
Usable Windows IPv4-neighbor MAC entries for the target address.
#>
function Assert-AtlasoWorkstationAddressIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$TargetVmxPath,
        [Parameter(Mandatory = $true)][string]$TargetMacAddress,
        [Parameter(Mandatory = $true)][string]$TargetIPAddress,
        [Parameter(Mandatory = $true)][string]$ExpectedHostname,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$ObservedHostname,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$RunningGuests,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$NeighborMacAddresses
    )

    $ownership = Assert-AtlasoWorkstationAddressOwnership `
        -TargetVmxPath $TargetVmxPath `
        -TargetMacAddress $TargetMacAddress `
        -TargetIPAddress $TargetIPAddress `
        -RunningGuests $RunningGuests `
        -NeighborMacAddresses $NeighborMacAddresses
    $hostname = Assert-AtlasoWorkstationHostnameIdentity `
        -TargetVmxPath $TargetVmxPath `
        -ExpectedHostname $ExpectedHostname `
        -ObservedHostname $ObservedHostname
    return [pscustomobject]@{
        VmxPath    = $ownership.VmxPath
        MacAddress = $ownership.MacAddress
        Hostname   = $hostname
        IPAddress  = $ownership.IPAddress
    }
}

<#
.SYNOPSIS
Read one allowlisted first-boot stage for bounded readiness diagnostics.

.PARAMETER VmxPath
Exact running normal test VMX path.

.PARAMETER VmrunPath
Exact VMware vmrun executable path.

.PARAMETER Deadline
Absolute deadline that bounds the diagnostic guest-info read.
#>
function Get-AtlasoWorkstationFirstBootStage {
    param(
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $true)][string]$VmrunPath,
        [Parameter(Mandatory = $true)][datetime]$Deadline
    )

    $result = Invoke-AtlasoWorkstationVmrunBounded `
        -VmrunPath $VmrunPath `
        -Arguments @(
            '-T', 'ws', 'readVariable', $VmxPath, 'runtimeConfig',
            'guestinfo.atlaso.test_vm_first_boot_stage'
        ) `
        -Deadline $Deadline
    if ($result.TimedOut -or $result.ExitCode -ne 0) { return '' }
    $reported = @($result.StdOut -split '\r?\n' | Where-Object { $_ }) | Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($reported)) { return '' }
    try {
        $normalized = ConvertFrom-AtlasoWorkstationRuntimeConfigValue -Value $reported
    }
    catch {
        return ''
    }
    $normalized = $normalized.Trim().ToLowerInvariant()
    $layerStages = @(
        'management-network', 'resolver', 'management-web-server', 'firewall',
        'hostname', 'root-password', 'root-ssh', 'bootstrap-administrator-password',
        'ssh-host-key', 'development-administrator-ssh', 'test-vm-hostname',
        'appliance-environment', 'development-root-ca-staging-and-guest-info-scrub',
        'console-credential-refresh', 'host-state-durability', 'pending-success-marker',
        'ovf-credential-scrub', 'applied-marker'
    )
    $knownStages = @($layerStages)
    $knownStages += @($layerStages | ForEach-Object { "failed-$_" })
    $knownStages += @(
        'vmware-customization-complete', 'https-development-root-proof',
        'https-development-root-proof-complete', 'https-development-root-import',
        'https-development-root-import-complete', 'failed-https-development-root-proof',
        'failed-https-development-root-import', 'failed-https-development-root-staging-removal'
    )
    if ($knownStages -ccontains $normalized) { return $normalized }
    return ''
}

<#
.SYNOPSIS
Require a stable running inventory and target address across a readiness proof.

.PARAMETER InitialVmxPaths
Exact running VMX paths captured before per-guest observations.

.PARAMETER ConfirmedVmxPaths
Exact running VMX paths captured immediately before readiness returns.

.PARAMETER InitialTargetIPAddress
Target address used for the identity and neighbor proof.

.PARAMETER ConfirmedTargetIPAddress
Target address re-read immediately before readiness returns.

.PARAMETER InitialRunningGuests
VMX, MAC, and address observations captured during the initial identity proof.

.PARAMETER ConfirmedRunningGuests
VMX, MAC, and address observations re-read during the confirmation proof.
#>
function Assert-AtlasoWorkstationStableObservation {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$InitialVmxPaths,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$ConfirmedVmxPaths,
        [Parameter(Mandatory = $true)][string]$InitialTargetIPAddress,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$ConfirmedTargetIPAddress,
        [AllowEmptyCollection()][object[]]$InitialRunningGuests = @(),
        [AllowEmptyCollection()][object[]]$ConfirmedRunningGuests = @()
    )

    $initialKey = @(
        $InitialVmxPaths |
            ForEach-Object { (Resolve-Path -LiteralPath $_ -ErrorAction Stop).Path.ToLowerInvariant() } |
            Sort-Object
    ) -join "`n"
    $confirmedKey = @(
        $ConfirmedVmxPaths |
            ForEach-Object { (Resolve-Path -LiteralPath $_ -ErrorAction Stop).Path.ToLowerInvariant() } |
            Sort-Object
    ) -join "`n"
    if ($confirmedKey -cne $initialKey -or $ConfirmedTargetIPAddress -ne $InitialTargetIPAddress) {
        throw 'Running VMware guest inventory or target address changed during the readiness proof.'
    }
    if ($InitialRunningGuests.Count -gt 0 -or $ConfirmedRunningGuests.Count -gt 0) {
        $initialGuestKey = @(
            $InitialRunningGuests |
                ForEach-Object {
                    $path = (Resolve-Path -LiteralPath $_.Path -ErrorAction Stop).Path.ToLowerInvariant()
                    $mac = ConvertTo-AtlasoWorkstationMacAddress -MacAddress $_.MacAddress
                    "$path|$mac|$($_.IPAddress)"
                } |
                Sort-Object
        ) -join "`n"
        $confirmedGuestKey = @(
            $ConfirmedRunningGuests |
                ForEach-Object {
                    $path = (Resolve-Path -LiteralPath $_.Path -ErrorAction Stop).Path.ToLowerInvariant()
                    $mac = ConvertTo-AtlasoWorkstationMacAddress -MacAddress $_.MacAddress
                    "$path|$mac|$($_.IPAddress)"
                } |
                Sort-Object
        ) -join "`n"
        if ($confirmedGuestKey -cne $initialGuestKey) {
            throw 'Running VMware guest identity evidence changed during the readiness proof.'
        }
    }
}

Export-ModuleMember -Function @(
    'Assert-AtlasoWorkstationAddressIdentity',
    'Assert-AtlasoWorkstationAddressOwnership',
    'Assert-AtlasoWorkstationHostnameIdentity',
    'Assert-AtlasoWorkstationStableObservation',
    'ConvertFrom-AtlasoWorkstationRuntimeConfigValue',
    'ConvertTo-AtlasoWorkstationMacAddress',
    'Get-AtlasoWorkstationRunningVmxPath',
    'Get-AtlasoWorkstationFirstBootStage',
    'Get-AtlasoWorkstationVmxMacAddress',
    'Invoke-AtlasoWorkstationVmrunBounded'
)
