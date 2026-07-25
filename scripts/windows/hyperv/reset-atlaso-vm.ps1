[CmdletBinding()]
param([string]$Name = 'Atlaso')

$ErrorActionPreference = 'Stop'
Restart-VM -Name $Name -Force
Write-Host "Reset VM: $Name"
