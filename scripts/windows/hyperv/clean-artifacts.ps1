[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Atlaso.HypervCleanup.psm1') -Force

$hypervPath = Join-Path $PSScriptRoot '..\..\..\image\hyperv'
if (Test-Path -LiteralPath $hypervPath) {
    foreach ($artifactName in @('output', 'test-vms')) {
        $artifactRoot = Join-Path $hypervPath $artifactName
        if (Test-Path -LiteralPath $artifactRoot -PathType Container) {
            Remove-AtlasoHypervArtifactRoot `
                -HypervRoot $hypervPath `
                -RemovalRoot $artifactRoot `
                -Confirm:$false
        }
    }
}
Write-Host 'Cleaned up Hyper-V build artifacts.'
