[CmdletBinding()]
param([string]$Name = 'Atlaso')

$ErrorActionPreference = 'Stop'
Stop-VM -Name $Name -Force
Write-Host "Stopped VM: $Name"
