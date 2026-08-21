[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Atlaso.HypervCleanup.psm1') -Force

$hypervPath = Join-Path $PSScriptRoot '..\..\..\image\hyperv'
if (Test-Path -LiteralPath $hypervPath) {
    foreach ($artifactName in @('output', 'test-vms')) {
        $artifactRoot = Join-Path $hypervPath $artifactName
        if ($null -ne (Get-Item -LiteralPath $artifactRoot -Force -ErrorAction SilentlyContinue)) {
            Remove-AtlasoHypervArtifactRoot `
                -HypervRoot $hypervPath `
                -RemovalRoot $artifactRoot `
                -Confirm:$false
        }
    }
}
Write-Host 'Cleaned up Hyper-V build artifacts.'
