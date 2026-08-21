[CmdletBinding()]
param([string]$VmrunPath = '')

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Atlaso.WorkstationCleanup.psm1') -Force

function Resolve-VmrunPath {
    param([string]$Path)
    if ($Path) {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "vmrun.exe not found: $Path" }
        return (Resolve-Path -LiteralPath $Path).Path
    }
    foreach ($candidate in @('C:\Program Files\VMware\VMware Workstation\vmrun.exe', 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe')) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    $command = Get-Command vmrun -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    throw 'vmrun.exe was not found. Install VMware Workstation Pro or pass -VmrunPath.'
}

$vmwarePath = Join-Path $PSScriptRoot '..\..\..\image\vmware-workstation'
if (Test-Path -LiteralPath $vmwarePath) {
    $artifactRoots = @('output', 'test-vms', 'ovf') |
        ForEach-Object { Join-Path $vmwarePath $_ } |
        Where-Object { Test-Path -LiteralPath $_ }
    if ($artifactRoots.Count -gt 0) {
        $resolvedVmrun = Resolve-VmrunPath -Path $VmrunPath
        foreach ($artifactRoot in $artifactRoots) {
            Remove-AtlasoWorkstationArtifactRoot `
                -VmrunPath $resolvedVmrun `
                -ArtifactParentRoot $vmwarePath `
                -RemovalRoot $artifactRoot `
                -Confirm:$false
        }
    }
}
Write-Host 'Cleaned up VMware Workstation build artifacts.'
