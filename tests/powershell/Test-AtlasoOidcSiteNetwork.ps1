<#
.SYNOPSIS
Exercise focused OIDC host-address admission without VMware.
.PARAMETER RepositoryRoot
Checkout containing the OIDC site-network module.
#>
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$RepositoryRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $RepositoryRoot 'scripts/windows/vmware/Atlaso.OidcSiteNetwork.psm1'
$module = Import-Module $modulePath -Force -PassThru
$networkPlan = {
    param($ManagementNetwork, $ManagementOnly, $PlanOnly)
    if ($ManagementNetwork -ne 'VMnet2' -or -not $ManagementOnly -or -not $PlanOnly) {
        throw 'Incorrect network inventory request.'
    }
    '{"discovered_networks":[{"Name":"vmnet2","Subnet":"192.168.84.0","Mask":"255.255.255.0","InterfaceAlias":"VMware Network Adapter VMnet2"}]}'
}

try {
    & $module {
        Set-Item Function:script:Get-NetAdapter -Value {
            param($Name, $ErrorAction)
            [pscustomobject]@{ Status = 'Up'; InterfaceIndex = 24 }
        }
        Set-Item Function:script:Get-NetIPAddress -Value {
            param($InterfaceAlias, $AddressFamily, $ErrorAction)
            $script:fixtureAddresses
        }
        Set-Item Function:script:Find-NetRoute -Value {
            param($RemoteIPAddress, $ErrorAction)
            [pscustomobject]@{ IPAddress = '192.168.84.1'; InterfaceIndex = 24 }
            [pscustomobject]@{ DestinationPrefix = '192.168.84.0/24'; InterfaceIndex = $script:fixtureRouteIndex }
        }
        $script:fixtureRouteIndex = 24
    }

    & $module {
        $script:fixtureAddresses = @(
            [pscustomobject]@{ IPAddress = '192.168.84.1'; PrefixLength = 24; AddressState = 'Preferred' },
            [pscustomobject]@{ IPAddress = '192.168.84.2'; PrefixLength = 24; AddressState = 'Preferred' }
        )
    }
    $collision = $null
    try {
        Assert-AtlasoOidcSiteNetwork -SiteANetwork VMnet2 -SiteCidr '192.168.84.1/24' -PrepareNetworksScript $networkPlan
    } catch {
        $collision = $_
    }
    if ($null -eq $collision -or $collision.Exception.Message -notlike '*already assigned to the host adapter*') {
        throw 'A site IP already assigned to the multihomed host was admitted.'
    }

    Assert-AtlasoOidcSiteNetwork -SiteANetwork VMnet2 -SiteCidr '192.168.84.3/24' -PrepareNetworksScript $networkPlan

    & $module { $script:fixtureRouteIndex = 42 }
    $wrongRoute = $null
    try {
        Assert-AtlasoOidcSiteNetwork -SiteANetwork VMnet2 -SiteCidr '192.168.84.3/24' -PrepareNetworksScript $networkPlan
    } catch {
        $wrongRoute = $_
    }
    if ($null -eq $wrongRoute -or $wrongRoute.Exception.Message -notlike '*does not route through the selected host adapter*') {
        throw 'A competing Windows route was admitted.'
    }

    foreach ($unusableAddress in @('192.168.84.0/24', '192.168.84.255/24')) {
        $invalid = $null
        try {
            Assert-AtlasoOidcSiteNetwork -SiteANetwork VMnet2 -SiteCidr $unusableAddress -PrepareNetworksScript $networkPlan
        } catch {
            $invalid = $_
        }
        if ($null -eq $invalid -or $invalid.Exception.Message -notlike '*must be a usable host address*') {
            throw "An unusable subnet or broadcast address was admitted: $unusableAddress"
        }
    }
    Write-Output 'OIDC site-network admission checks passed.'
} finally {
    Remove-Module $module -ErrorAction SilentlyContinue
}
