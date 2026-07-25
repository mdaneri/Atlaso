[CmdletBinding(SupportsShouldProcess = $true)]
param([string]$Name = 'Atlaso')

$ErrorActionPreference = 'Stop'

if ($PSCmdlet.ShouldProcess($Name, 'Remove Atlaso VM')) {
    Stop-VM -Name $Name -Force -ErrorAction SilentlyContinue
    Remove-VM -Name $Name -Force
    Write-Host "Removed VM: $Name"
}
