<#
.SYNOPSIS
Validate host reachability for the focused VMware OIDC lifecycle probe.
#>

Set-StrictMode -Version Latest

<#
.SYNOPSIS
Convert an IPv4 address to an integer for subnet comparison.
.PARAMETER Address
IPv4 address to convert.
#>
function ConvertTo-AtlasoIpv4Integer {
    param([Parameter(Mandatory = $true)][System.Net.IPAddress]$Address)

    $bytes = $Address.GetAddressBytes()
    if ($bytes.Count -ne 4) { throw 'OIDC Site A network requires IPv4 addresses.' }
    return (([uint32]$bytes[0] -shl 24) -bor ([uint32]$bytes[1] -shl 16) -bor ([uint32]$bytes[2] -shl 8) -bor [uint32]$bytes[3])
}

<#
.SYNOPSIS
Reject a focused OIDC topology the Windows host cannot probe.
.PARAMETER SiteANetwork
VMware network attached to the appliance site adapter.
.PARAMETER SiteCidr
IPv4 address and prefix configured on the appliance site adapter.
.PARAMETER PrepareNetworksPath
Path to the VMware network inventory script in the admitted source checkout.
.PARAMETER PrepareNetworksScript
Parsed VMware network inventory script from the admitted source commit.
.PARAMETER VmrunPath
Optional VMware vmrun executable path.
.PARAMETER BridgedInterfaceAlias
Optional host interface used for a bridged vmnet0.
#>
function Assert-AtlasoOidcSiteNetwork {
    param(
        [Parameter(Mandatory = $true)][string]$SiteANetwork,
        [Parameter(Mandatory = $true)][string]$SiteCidr,
        [string]$PrepareNetworksPath = '',
        [scriptblock]$PrepareNetworksScript = $null,
        [string]$VmrunPath = '',
        [string]$BridgedInterfaceAlias = ''
    )

    $networkArgs = @{
        ManagementNetwork = $SiteANetwork
        ManagementOnly = $true
        PlanOnly = $true
    }
    if ($VmrunPath) { $networkArgs['VmrunPath'] = $VmrunPath }
    if ($BridgedInterfaceAlias) { $networkArgs['BridgedInterfaceAlias'] = $BridgedInterfaceAlias }
    if ([bool]$PrepareNetworksPath -eq [bool]$PrepareNetworksScript) {
        throw 'Provide exactly one VMware network inventory source.'
    }
    $planText = if ($PrepareNetworksScript) {
        (& $PrepareNetworksScript @networkArgs | Out-String).Trim()
    } else {
        (& $PrepareNetworksPath @networkArgs | Out-String).Trim()
    }
    if (-not $?) { throw 'VMware Workstation network discovery failed.' }
    $networkPlan = $planText | ConvertFrom-Json
    $siteNetwork = @($networkPlan.discovered_networks | Where-Object { $_.Name -eq $SiteANetwork.ToLowerInvariant() }) | Select-Object -First 1
    if (-not $siteNetwork) {
        throw "OIDC Site A network $SiteANetwork was not found in VMware Workstation network inventory."
    }
    if ($SiteCidr -notmatch '^([0-9]{1,3}(?:\.[0-9]{1,3}){3})/([0-9]|[12][0-9]|3[0-2])$') {
        throw "OIDC SiteCidr must be an IPv4 CIDR: $SiteCidr"
    }
    $siteAddress = [System.Net.IPAddress]::Parse($Matches[1])
    if ($siteAddress.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        throw "OIDC SiteCidr must be an IPv4 CIDR: $SiteCidr"
    }
    $prefix = [int]$Matches[2]
    $expectedMask = if ($prefix -eq 0) { [uint32]0 } else { [uint32]([uint32]::MaxValue -shl (32 - $prefix)) }
    $siteIp = ConvertTo-AtlasoIpv4Integer -Address $siteAddress
    $networkIp = ConvertTo-AtlasoIpv4Integer -Address ([System.Net.IPAddress]::Parse($siteNetwork.Subnet))
    $networkMask = ConvertTo-AtlasoIpv4Integer -Address ([System.Net.IPAddress]::Parse($siteNetwork.Mask))
    if ($networkMask -ne $expectedMask -or ($siteIp -band $networkMask) -ne ($networkIp -band $networkMask)) {
        throw "OIDC SiteCidr $SiteCidr does not match $SiteANetwork subnet $($siteNetwork.Subnet)/$($siteNetwork.Mask). Choose a matching SiteCidr or configure the vmnet."
    }

    $hostAlias = if ($siteNetwork.PSObject.Properties['InterfaceAlias']) {
        $siteNetwork.InterfaceAlias
    } else {
        "VMware Network Adapter $SiteANetwork"
    }
    $hostAdapter = Get-NetAdapter -Name $hostAlias -ErrorAction SilentlyContinue
    $hostAddresses = @(Get-NetIPAddress -InterfaceAlias $hostAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.AddressState -eq 'Preferred' })
    if (@($hostAddresses | Where-Object {
        (ConvertTo-AtlasoIpv4Integer -Address ([System.Net.IPAddress]::Parse($_.IPAddress))) -eq $siteIp
    }).Count -gt 0) {
        throw "OIDC Site A address $SiteCidr is already assigned to the host adapter for $SiteANetwork ($hostAlias)."
    }
    $reachable = $hostAdapter -and $hostAdapter.Status -eq 'Up' -and @($hostAddresses | Where-Object {
        $hostIp = ConvertTo-AtlasoIpv4Integer -Address ([System.Net.IPAddress]::Parse($_.IPAddress))
        $_.PrefixLength -eq $prefix -and ($hostIp -band $networkMask) -eq ($siteIp -band $networkMask)
    }).Count -gt 0
    if (-not $reachable) {
        throw "OIDC Site A address $SiteCidr is not reachable from an active host adapter for $SiteANetwork ($hostAlias)."
    }
}

Export-ModuleMember -Function Assert-AtlasoOidcSiteNetwork
