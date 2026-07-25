[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$LabName = 'AtlasoWorkstationLifecycle',
    [string]$VmrunPath = ''
)

$ErrorActionPreference = 'Stop'

if (-not $LabName.StartsWith('AtlasoWorkstationLifecycle')) {
    throw "Refusing VM cleanup for prefix '$LabName'. Cleanup is limited to AtlasoWorkstationLifecycle* VM names."
}

function Resolve-VmrunPath {
    param([string]$Path)

    if ($Path) {
        if (-not (Test-Path -LiteralPath $Path)) {
            throw "vmrun.exe not found: $Path"
        }
        return (Resolve-Path -LiteralPath $Path).Path
    }

    foreach ($candidate in @(
        'C:\Program Files\VMware\VMware Workstation\vmrun.exe',
        'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
    )) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    $command = Get-Command vmrun -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }
    throw 'vmrun.exe was not found. Install VMware Workstation Pro or pass -VmrunPath.'
}

function Get-VmxDisplayName {
    param([string]$Path)

    $line = Get-Content -LiteralPath $Path |
        Where-Object { $_ -match '^\s*displayName\s*=' } |
        Select-Object -First 1
    if ($line -and $line -match '^\s*displayName\s*=\s*"(.+)"\s*$') {
        return $Matches[1]
    }
    return [System.IO.Path]::GetFileNameWithoutExtension($Path)
}

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).Path
$lifecycleRoot = Join-Path $repoRoot 'test-results\vmware-workstation-lifecycle'

if (-not (Test-Path -LiteralPath $lifecycleRoot)) {
    Write-Host "No Workstation lifecycle result directory found: $lifecycleRoot"
    return
}

$resolvedLifecycleRoot = (Resolve-Path -LiteralPath $lifecycleRoot).Path
$resolvedVmrun = Resolve-VmrunPath -Path $VmrunPath
$runningVmxPaths = @(& $resolvedVmrun -T ws list 2>$null | Select-Object -Skip 1)
$candidates = @(
    Get-ChildItem -LiteralPath $resolvedLifecycleRoot -Recurse -Filter '*.vmx' -File |
        ForEach-Object {
            $resolvedPath = $_.FullName
            $displayName = Get-VmxDisplayName -Path $resolvedPath
            [pscustomobject]@{
                Path        = $resolvedPath
                DisplayName = $displayName
                Directory   = $_.DirectoryName
                IsRunning   = $runningVmxPaths -contains $resolvedPath
            }
        } |
        Where-Object { $_.DisplayName.StartsWith($LabName) } |
        Sort-Object -Property Directory, DisplayName -Unique
)

if (-not $candidates) {
    Write-Host "No Workstation lifecycle VMs found for prefix: $LabName"
    return
}

foreach ($candidate in $candidates | Sort-Object -Property DisplayName) {
    if (-not $candidate.Path.StartsWith($resolvedLifecycleRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove VM outside Workstation lifecycle results: $($candidate.Path)"
    }
    if (-not $candidate.DisplayName.StartsWith($LabName)) {
        throw "Refusing to remove VM '$($candidate.DisplayName)' because it does not start with '$LabName'."
    }

    if ($PSCmdlet.ShouldProcess($candidate.DisplayName, 'Stop and remove Workstation lifecycle VM')) {
        & $resolvedVmrun -T ws stop $candidate.Path hard 2>$null | Out-Null
        & $resolvedVmrun -T ws unregister $candidate.Path 2>$null | Out-Null
        if (Test-Path -LiteralPath $candidate.Directory) {
            Remove-Item -LiteralPath $candidate.Directory -Recurse -Force
            Write-Host "Removed Workstation lifecycle VM: $($candidate.DisplayName)"
        } else {
            Write-Host "Workstation lifecycle VM already removed: $($candidate.DisplayName)"
        }
    }
}
