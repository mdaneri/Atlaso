[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$VmxPath,
    [string]$VmrunPath = '',
    [switch]$AllowImageOutputRemoval
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
$vmDirectory = Split-Path -Parent $resolvedVmxPath
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).Path
$imageOutputRoot = Join-Path $repoRoot 'image\vmware-workstation\output'

if (-not $AllowImageOutputRemoval -and (Test-Path -LiteralPath $imageOutputRoot)) {
    $resolvedImageOutputRoot = (Resolve-Path -LiteralPath $imageOutputRoot).Path
    if ($vmDirectory.StartsWith($resolvedImageOutputRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove a VM under built image output: $vmDirectory. Pass -AllowImageOutputRemoval only for intentional image cleanup."
    }
}

$resolvedVmrun = Resolve-VmrunPath -Path $VmrunPath

if ($PSCmdlet.ShouldProcess($resolvedVmxPath, 'Stop VMware Workstation VM')) {
    & $resolvedVmrun -T ws stop $resolvedVmxPath hard 2>$null | Out-Null
}

if ($PSCmdlet.ShouldProcess($vmDirectory, 'Remove VMware Workstation VM directory')) {
    Remove-Item -LiteralPath $vmDirectory -Recurse -Force
    Write-Host "Removed VMware Workstation VM directory: $vmDirectory"
}
