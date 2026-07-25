[CmdletBinding()]
param([string]$Name = 'Atlaso')

$ErrorActionPreference = 'Stop'
Start-VM -Name $Name
Write-Host "Started VM: $Name"
