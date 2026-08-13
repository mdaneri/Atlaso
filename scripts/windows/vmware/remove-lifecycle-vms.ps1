[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$LabName = 'AtlasoWorkstationLifecycle',
    [string]$VmrunPath = ''
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Atlaso.WorkstationCleanup.psm1') -Force

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
$candidates = @(
    Get-ChildItem -LiteralPath $resolvedLifecycleRoot -Recurse -Filter '*.vmx' -File |
        ForEach-Object {
            $resolvedPath = $_.FullName
            $displayName = Get-VmxDisplayName -Path $resolvedPath
            [pscustomobject]@{
                Path        = $resolvedPath
                DisplayName = $displayName
                Directory   = $_.DirectoryName
            }
        } |
        Where-Object { $_.DisplayName.StartsWith($LabName) } |
        Sort-Object -Property Directory, DisplayName -Unique
)

if (-not $candidates) {
    Write-Host "No Workstation lifecycle VMs found for prefix: $LabName"
    return
}

foreach ($candidateGroup in $candidates | Group-Object -Property Directory) {
    $groupCandidates = @($candidateGroup.Group | Sort-Object -Property DisplayName)
    foreach ($candidate in $groupCandidates) {
        Assert-AtlasoStrictDescendantPath `
            -ParentPath $resolvedLifecycleRoot `
            -ChildPath $candidate.Path `
            -FailureMessage 'Refusing to remove VM outside Workstation lifecycle results'
        if (-not $candidate.DisplayName.StartsWith($LabName)) {
            throw "Refusing to remove VM '$($candidate.DisplayName)' because it does not start with '$LabName'."
        }
    }

    Remove-AtlasoWorkstationVmArtifacts `
        -VmrunPath $resolvedVmrun `
        -VmxPaths @($groupCandidates.Path) `
        -RemovalRoot $candidateGroup.Name `
        -WhatIf:$WhatIfPreference `
        -Confirm:$false
    if (-not $WhatIfPreference) {
        Write-Host "Removed Workstation lifecycle VM directory: $($candidateGroup.Name)"
    }
}
