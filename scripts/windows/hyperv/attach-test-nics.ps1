[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Name = 'Atlaso'
)

$ErrorActionPreference = 'Stop'

$adapters = @(
    @{ Name = 'SiteA'; SwitchName = 'Atlaso-SiteA' },
    @{ Name = 'SiteB'; SwitchName = 'Atlaso-SiteB' },
    @{ Name = 'Trunk'; SwitchName = 'Atlaso-Trunk' }
)

foreach ($adapter in $adapters) {
    if ($PSCmdlet.ShouldProcess($Name, "Attach $($adapter.Name) NIC")) {
        Add-VMNetworkAdapter -VMName $Name -Name $adapter.Name -SwitchName $adapter.SwitchName
        Write-Host "Attached $($adapter.Name) to $($adapter.SwitchName)"
    }
}
