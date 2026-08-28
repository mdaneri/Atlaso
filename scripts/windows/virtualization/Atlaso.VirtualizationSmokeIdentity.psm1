<#
.SYNOPSIS
Resolve provider-bound management network identity for virtualization smoke tests.

.DESCRIPTION
Normalizes Hyper-V and VMware network evidence so smoke probes use only an
IPv4 address bound to the provider-side management adapter. The functions are
side-effect free: callers gather provider and host-neighbor evidence, then
revalidate the returned identity immediately around SSH and HTTPS probes.
#>

Set-StrictMode -Version Latest

<#
.SYNOPSIS
Normalize a virtualization adapter MAC address.

.PARAMETER MacAddress
Colon, hyphen, or compact hexadecimal MAC address.
#>
function ConvertTo-AtlasoSmokeMacAddress {
    param([Parameter(Mandatory = $true)][string]$MacAddress)

    if ($MacAddress -notmatch '^(?:[0-9A-Fa-f]{12}|(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}|(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2})$') {
        throw "Virtualization smoke MAC address is malformed: $MacAddress"
    }
    $compact = ($MacAddress -replace '[:-]', '').ToLowerInvariant()
    return (($compact -split '(.{2})' | Where-Object { $_ }) -join ':')
}

<#
.SYNOPSIS
Return unique usable IPv4 addresses from provider evidence.

.PARAMETER Addresses
Candidate address strings reported for one adapter.
#>
function Get-AtlasoSmokeUsableIPv4Address {
    param([AllowEmptyCollection()][string[]]$Addresses = @())

    $usable = [System.Collections.Generic.List[string]]::new()
    foreach ($candidate in @($Addresses)) {
        $parsed = $null
        if (-not [System.Net.IPAddress]::TryParse([string]$candidate, [ref]$parsed) -or
            $parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -or
            [System.Net.IPAddress]::IsLoopback($parsed)) {
            continue
        }
        $bytes = $parsed.GetAddressBytes()
        if (($bytes[0] -eq 169 -and $bytes[1] -eq 254) -or
            $bytes[0] -eq 0 -or
            ($bytes[0] -ge 224 -and $bytes[0] -le 239)) {
            continue
        }
        $usable.Add($parsed.ToString())
    }
    return @($usable | Sort-Object -Unique)
}

<#
.SYNOPSIS
Return DHCP lease addresses bound to one exact VMware management MAC.

.PARAMETER LeaseText
Raw VMware DHCP lease-file content.

.PARAMETER ManagementMac
Expected ethernet0 management adapter MAC address.
#>
function Get-AtlasoVmwareDhcpLeaseAddress {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$LeaseText,
        [Parameter(Mandatory = $true)][string]$ManagementMac
    )

    $expectedMac = ConvertTo-AtlasoSmokeMacAddress -MacAddress $ManagementMac
    $leasePattern = [regex]::new(
        '(?ms)\blease\s+(?<address>\d{1,3}(?:\.\d{1,3}){3})\s*\{(?<body>.*?)\}'
    )
    $macPattern = [regex]::new(
        '(?im)^\s*hardware\s+ethernet\s+(?<mac>[0-9a-f]{2}(?::[0-9a-f]{2}){5})\s*;'
    )
    $addresses = foreach ($lease in $leasePattern.Matches(($LeaseText -join "`n"))) {
        $macMatch = $macPattern.Match($lease.Groups['body'].Value)
        if ($macMatch.Success -and
            (ConvertTo-AtlasoSmokeMacAddress -MacAddress $macMatch.Groups['mac'].Value) -eq $expectedMac) {
            $lease.Groups['address'].Value
        }
    }
    return @(Get-AtlasoSmokeUsableIPv4Address -Addresses @($addresses))
}

<#
.SYNOPSIS
Resolve the Hyper-V management adapter and its unique usable IPv4 address.

.PARAMETER Adapters
Exact network adapters returned for the invocation-owned Hyper-V VM.

.PARAMETER ManagementSwitch
Expected switch attached to the named Management adapter.

.PARAMETER ServiceSwitch
Expected switch attached to the named Services adapter.

.PARAMETER ExpectedIdentity
Previously captured identity that the current evidence must match.

.PARAMETER AllowMissingAddress
Permit the management adapter to have no usable IPv4 while topology is captured.
#>
function Resolve-AtlasoHyperVSmokeNetworkIdentity {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Adapters,
        [Parameter(Mandatory = $true)][string]$ManagementSwitch,
        [Parameter(Mandatory = $true)][string]$ServiceSwitch,
        [AllowNull()][object]$ExpectedIdentity = $null,
        [switch]$AllowMissingAddress
    )

    if ($Adapters.Count -ne 2) {
        throw 'The Hyper-V smoke VM must expose exactly two provider adapters.'
    }
    $management = @($Adapters | Where-Object { [string]$_.Name -ceq 'Management' })
    $services = @($Adapters | Where-Object { [string]$_.Name -ceq 'Services' })
    if ($management.Count -ne 1 -or $services.Count -ne 1) {
        throw 'The Hyper-V smoke VM must expose one Management and one Services adapter.'
    }
    if ([string]$management[0].SwitchName -cne $ManagementSwitch -or
        [string]$services[0].SwitchName -cne $ServiceSwitch) {
        throw 'The Hyper-V smoke adapter-to-switch mapping does not match the requested topology.'
    }
    $managementMac = ConvertTo-AtlasoSmokeMacAddress -MacAddress ([string]$management[0].MacAddress)
    $serviceMac = ConvertTo-AtlasoSmokeMacAddress -MacAddress ([string]$services[0].MacAddress)
    if ($managementMac -eq $serviceMac) {
        throw 'The Hyper-V management and services adapters must have distinct MAC addresses.'
    }
    $addresses = @(Get-AtlasoSmokeUsableIPv4Address -Addresses @($management[0].IPAddresses))
    $serviceAddresses = @(Get-AtlasoSmokeUsableIPv4Address -Addresses @($services[0].IPAddresses))
    if ($addresses.Count -gt 1 -or ($addresses.Count -eq 0 -and -not $AllowMissingAddress)) {
        throw 'The Hyper-V Management adapter must report exactly one usable IPv4 address.'
    }
    if ($addresses.Count -eq 1 -and $addresses[0] -in $serviceAddresses) {
        throw 'The Hyper-V management IPv4 address is also reported by the Services adapter.'
    }
    $identity = [pscustomobject]@{
        Provider            = 'hyperv'
        ManagementAdapterId = [string]$management[0].Id
        ManagementMac       = $managementMac
        ManagementNetwork   = [string]$management[0].SwitchName
        ServiceAdapterId    = [string]$services[0].Id
        ServiceMac          = $serviceMac
        ServiceNetwork      = [string]$services[0].SwitchName
        Address             = if ($addresses.Count -eq 1) { $addresses[0] } else { '' }
    }
    if (-not $identity.ManagementAdapterId -or -not $identity.ServiceAdapterId -or
        $identity.ManagementAdapterId -eq $identity.ServiceAdapterId) {
        throw 'The Hyper-V smoke adapters do not expose distinct stable provider identities.'
    }
    if ($null -ne $ExpectedIdentity) {
        foreach ($field in @(
                'Provider', 'ManagementAdapterId', 'ManagementMac', 'ManagementNetwork',
                'ServiceAdapterId', 'ServiceMac', 'ServiceNetwork'
            )) {
            if ([string]$identity.$field -cne [string]$ExpectedIdentity.$field) {
                throw "The Hyper-V smoke network identity changed at field $field."
            }
        }
        if ([string]$ExpectedIdentity.Address -and
            [string]$identity.Address -and
            [string]$identity.Address -cne [string]$ExpectedIdentity.Address) {
            throw 'The Hyper-V management IPv4 address changed during smoke validation.'
        }
    }
    return $identity
}

<#
.SYNOPSIS
Read the two role-bound adapter identities from a VMware smoke VMX.

.PARAMETER VmxPath
Exact invocation-owned VMware VMX file.

.PARAMETER ManagementVmnet
Expected vmnet mapped to ethernet0.

.PARAMETER ServiceVmnet
Expected vmnet mapped to ethernet1.

.PARAMETER ExpectedIdentity
Previously captured VMX identity that the current file must match.
#>
function Get-AtlasoVmwareSmokeVmxNetworkIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $true)][string]$ManagementVmnet,
        [Parameter(Mandatory = $true)][string]$ServiceVmnet,
        [AllowNull()][object]$ExpectedIdentity = $null
    )

    $resolvedVmxPath = (Resolve-Path -LiteralPath $VmxPath -ErrorAction Stop).Path
    $lines = @(Get-Content -LiteralPath $resolvedVmxPath -ErrorAction Stop)
    $values = @{}
    foreach ($key in @('ethernet0.vnet', 'ethernet1.vnet')) {
        $assignments = @($lines | Where-Object { $_ -match ('^\s*' + [regex]::Escape($key) + '\s*=') })
        if ($assignments.Count -ne 1 -or
            $assignments[0] -notmatch ('^\s*' + [regex]::Escape($key) + '\s*=\s*"(?<value>[^"]+)"\s*$')) {
            throw "VMware smoke VMX must contain one canonical $key assignment."
        }
        $values[$key] = [string]$Matches.value
    }
    foreach ($index in 0, 1) {
        $key = "ethernet$index.mac"
        $assignments = @($lines | Where-Object { $_ -match "^\s*ethernet$index\.(?:address|generatedAddress)\s*=" })
        $macs = @()
        $macPattern = '^\s*ethernet' + $index + '\.(?:address|generatedAddress)\s*=\s*"(?<mac>[^"]+)"\s*$'
        foreach ($assignment in $assignments) {
            if ($assignment -notmatch $macPattern) {
                throw "VMware smoke VMX contains a malformed ethernet$index MAC assignment."
            }
            $macs += ConvertTo-AtlasoSmokeMacAddress -MacAddress ([string]$Matches.mac)
        }
        $uniqueMacs = @($macs | Sort-Object -Unique)
        if ($uniqueMacs.Count -ne 1) {
            throw "VMware smoke VMX must contain one unambiguous ethernet$index MAC address."
        }
        $values[$key] = $uniqueMacs[0]
    }
    if ($values['ethernet0.vnet'] -cne $ManagementVmnet -or
        $values['ethernet1.vnet'] -cne $ServiceVmnet) {
        throw 'The VMware smoke adapter-to-vmnet mapping does not match the requested topology.'
    }
    if ($values['ethernet0.mac'] -eq $values['ethernet1.mac']) {
        throw 'The VMware management and services adapters must have distinct MAC addresses.'
    }
    $identity = [pscustomobject]@{
        Provider          = 'vmware'
        VmxPath           = $resolvedVmxPath
        ManagementMac     = $values['ethernet0.mac']
        ManagementNetwork = $values['ethernet0.vnet']
        ServiceMac        = $values['ethernet1.mac']
        ServiceNetwork    = $values['ethernet1.vnet']
        Address           = ''
    }
    if ($null -ne $ExpectedIdentity) {
        foreach ($field in @(
                'Provider', 'VmxPath', 'ManagementMac', 'ManagementNetwork',
                'ServiceMac', 'ServiceNetwork'
            )) {
            if ([string]$identity.$field -cne [string]$ExpectedIdentity.$field) {
                throw "The VMware smoke network identity changed at field $field."
            }
        }
    }
    return $identity
}

<#
.SYNOPSIS
Resolve a VMware management IPv4 from the exact vmnet and management MAC.

.PARAMETER VmxIdentity
Role-bound VMX identity returned by Get-AtlasoVmwareSmokeVmxNetworkIdentity.

.PARAMETER NetworkAdapters
Windows host adapter inventory containing Name, InterfaceDescription, ifIndex, and Status.

.PARAMETER Neighbors
Windows IPv4 neighbor inventory containing InterfaceIndex, IPAddress, LinkLayerAddress, and State.

.PARAMETER ExpectedIdentity
Previously captured complete identity that the current evidence must match.

.PARAMETER AllowMissingAddress
Permit no usable neighbor entry while readiness polling continues.
#>
function Resolve-AtlasoVmwareSmokeAddressIdentity {
    param(
        [Parameter(Mandatory = $true)][object]$VmxIdentity,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$NetworkAdapters,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Neighbors,
        [AllowNull()][object]$ExpectedIdentity = $null,
        [switch]$AllowMissingAddress
    )

    $expectedName = "VMware Network Adapter $($VmxIdentity.ManagementNetwork)"
    $expectedDescription = "VMware Virtual Ethernet Adapter for $($VmxIdentity.ManagementNetwork)"
    $hostAdapters = @($NetworkAdapters | Where-Object {
            [string]$_.Name -ieq $expectedName -or
            [string]$_.InterfaceDescription -ieq $expectedDescription
        })
    if ($hostAdapters.Count -ne 1 -or [string]$hostAdapters[0].Status -ine 'Up') {
        throw 'The VMware management vmnet must resolve to one active Windows host adapter.'
    }
    $managementMac = ConvertTo-AtlasoSmokeMacAddress -MacAddress ([string]$VmxIdentity.ManagementMac)
    $matchingNeighbors = @($Neighbors | Where-Object {
            [int]$_.InterfaceIndex -eq [int]$hostAdapters[0].ifIndex -and
            [string]$_.State -notin @('Incomplete', 'Unreachable') -and
            $_.LinkLayerAddress -and
            (ConvertTo-AtlasoSmokeMacAddress -MacAddress ([string]$_.LinkLayerAddress)) -eq $managementMac
        })
    $addresses = @(Get-AtlasoSmokeUsableIPv4Address -Addresses @(
            $matchingNeighbors | ForEach-Object { [string]$_.IPAddress }
        ))
    if ($addresses.Count -gt 1 -or ($addresses.Count -eq 0 -and -not $AllowMissingAddress)) {
        throw 'The VMware management MAC must resolve to exactly one usable IPv4 neighbor on its vmnet.'
    }
    $identity = [pscustomobject]@{
        Provider          = [string]$VmxIdentity.Provider
        VmxPath           = [string]$VmxIdentity.VmxPath
        ManagementMac     = $managementMac
        ManagementNetwork = [string]$VmxIdentity.ManagementNetwork
        ServiceMac        = [string]$VmxIdentity.ServiceMac
        ServiceNetwork    = [string]$VmxIdentity.ServiceNetwork
        HostInterfaceIndex = [int]$hostAdapters[0].ifIndex
        Address           = if ($addresses.Count -eq 1) { $addresses[0] } else { '' }
    }
    if ($identity.Address) {
        $addressOwners = @($Neighbors | Where-Object {
                [int]$_.InterfaceIndex -eq $identity.HostInterfaceIndex -and
                [string]$_.IPAddress -eq $identity.Address -and
                [string]$_.State -notin @('Incomplete', 'Unreachable')
            })
        $ownerMacs = @($addressOwners | ForEach-Object {
                ConvertTo-AtlasoSmokeMacAddress -MacAddress ([string]$_.LinkLayerAddress)
            } | Sort-Object -Unique)
        if ($ownerMacs.Count -ne 1 -or $ownerMacs[0] -ne $managementMac) {
            throw 'The VMware management IPv4 neighbor has duplicate or mismatched MAC ownership evidence.'
        }
    }
    if ($null -ne $ExpectedIdentity) {
        foreach ($field in @(
                'Provider', 'VmxPath', 'ManagementMac', 'ManagementNetwork',
                'ServiceMac', 'ServiceNetwork'
            )) {
            if ([string]$identity.$field -cne [string]$ExpectedIdentity.$field) {
                throw "The VMware smoke network identity changed at field $field."
            }
        }
        if ('HostInterfaceIndex' -in $ExpectedIdentity.PSObject.Properties.Name -and
            [int]$ExpectedIdentity.HostInterfaceIndex -ne $identity.HostInterfaceIndex) {
            throw 'The VMware smoke network identity changed at field HostInterfaceIndex.'
        }
        if ([string]$ExpectedIdentity.Address -and
            [string]$identity.Address -and
            [string]$identity.Address -cne [string]$ExpectedIdentity.Address) {
            throw 'The VMware management IPv4 address changed during smoke validation.'
        }
    }
    return $identity
}

Export-ModuleMember -Function @(
    'ConvertTo-AtlasoSmokeMacAddress',
    'Get-AtlasoSmokeUsableIPv4Address',
    'Get-AtlasoVmwareDhcpLeaseAddress',
    'Get-AtlasoVmwareSmokeVmxNetworkIdentity',
    'Resolve-AtlasoHyperVSmokeNetworkIdentity',
    'Resolve-AtlasoVmwareSmokeAddressIdentity'
)
