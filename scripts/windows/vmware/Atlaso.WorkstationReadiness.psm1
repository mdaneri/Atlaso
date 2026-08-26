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
Return the checked running VMware Workstation VMX paths.

.PARAMETER VmrunPath
Resolved vmrun executable used for the provider inventory.
#>
function Get-AtlasoWorkstationRunningVmxPath {
    param([Parameter(Mandatory = $true)][string]$VmrunPath)

    $output = @(& $VmrunPath -T ws list 2>&1)
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "List running VMware Workstation VMs failed with exit code $exitCode."
    }
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
Prove that a host-facing address belongs uniquely to one running VMX.

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
        Hostname   = $normalizedObservedHostname
        IPAddress  = $TargetIPAddress
    }
}

Export-ModuleMember -Function @(
    'Assert-AtlasoWorkstationAddressIdentity',
    'ConvertTo-AtlasoWorkstationMacAddress',
    'Get-AtlasoWorkstationRunningVmxPath',
    'Get-AtlasoWorkstationVmxMacAddress'
)
