[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$MgmtNatName = 'Atlaso-Mgmt-NAT'
)

$ErrorActionPreference = 'Stop'

$switchNames = @(
    'Atlaso-Mgmt',
    'Atlaso-Services',
    'Atlaso-SiteA',
    'Atlaso-SiteB',
    'Atlaso-Trunk'
)

foreach ($switchName in $switchNames) {
    $switch = Get-VMSwitch -Name $switchName -ErrorAction SilentlyContinue
    if (-not $switch) {
        continue
    }
    $attached = Get-VMNetworkAdapter -All | Where-Object { $_.SwitchName -eq $switchName }
    if ($attached) {
        $attachedNames = ($attached | ForEach-Object { "$($_.VMName)/$($_.Name)" }) -join ', '
        throw "Refusing to remove switch $switchName because VM adapters are still attached: $attachedNames"
    }
}

$nat = Get-NetNat -Name $MgmtNatName -ErrorAction SilentlyContinue
if ($nat) {
    if ($PSCmdlet.ShouldProcess($MgmtNatName, 'Remove Atlaso management NAT')) {
        Remove-NetNat -Name $MgmtNatName -Confirm:$false
        Write-Host "Removed NAT: $MgmtNatName"
    }
}

foreach ($switchName in $switchNames) {
    $switch = Get-VMSwitch -Name $switchName -ErrorAction SilentlyContinue
    if (-not $switch) {
        Write-Host "Switch already absent: $switchName"
        continue
    }
    if ($PSCmdlet.ShouldProcess($switchName, 'Remove Atlaso Hyper-V switch')) {
        Remove-VMSwitch -Name $switchName -Force
        Write-Host "Removed switch: $switchName"
    }
}
