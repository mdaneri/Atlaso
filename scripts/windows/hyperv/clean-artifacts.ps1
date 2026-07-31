[CmdletBinding()]
param()

$hypervPath = Join-Path $PSScriptRoot '..\..\..\image\hyperv'
if (Test-Path -LiteralPath $hypervPath) {
    if (Test-Path -LiteralPath (Join-Path $hypervPath 'output')) {
        Remove-Item -LiteralPath (Join-Path $hypervPath 'output') -Recurse -Force
    }
    if (Test-Path -LiteralPath (Join-Path $hypervPath 'test-vms')) {
        Remove-Item -LiteralPath (Join-Path $hypervPath 'test-vms') -Recurse -Force
    }
}
Write-Host 'Cleaned up Hyper-V build artifacts.'