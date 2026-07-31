[CmdletBinding()]
param()

$vmwarePath = Join-Path $PSScriptRoot '..\..\..\image\vmware-workstation'
if (Test-Path -LiteralPath $vmwarePath) {
    if (Test-Path -LiteralPath (Join-Path $vmwarePath 'output')) {
        Remove-Item -LiteralPath (Join-Path $vmwarePath 'output') -Recurse -Force
    }
    if (Test-Path -LiteralPath (Join-Path $vmwarePath 'test-vms')) {
        Remove-Item -LiteralPath (Join-Path $vmwarePath 'test-vms') -Recurse -Force
    }
    if (Test-Path -LiteralPath (Join-Path $vmwarePath 'ovf')) {
        Remove-Item -LiteralPath (Join-Path $vmwarePath 'ovf') -Recurse -Force
    }
}
Write-Host 'Cleaned up VMware Workstation build artifacts.'