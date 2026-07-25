[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$VmxPath,
    [string]$VmrunPath = '',
    [ValidateSet('gui', 'nogui')]
    [string]$Mode = 'gui'
)

$ErrorActionPreference = 'Stop'

function Resolve-VmrunPath {
    param([string]$Path)
    if ($Path) {
        if (-not (Test-Path -LiteralPath $Path)) { throw "vmrun.exe not found: $Path" }
        return (Resolve-Path -LiteralPath $Path).Path
    }
    foreach ($candidate in @('C:\Program Files\VMware\VMware Workstation\vmrun.exe', 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe')) {
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    $command = Get-Command vmrun -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    throw 'vmrun.exe was not found. Install VMware Workstation Pro or pass -VmrunPath.'
}

$resolvedVmxPath = (Resolve-Path -LiteralPath $VmxPath).Path
$resolvedVmrun = Resolve-VmrunPath -Path $VmrunPath
& $resolvedVmrun -T ws start $resolvedVmxPath $Mode
if ($LASTEXITCODE -ne 0) {
    throw "vmrun start failed with exit code $LASTEXITCODE."
}
Write-Host "Started VMware Workstation VM: $resolvedVmxPath"
