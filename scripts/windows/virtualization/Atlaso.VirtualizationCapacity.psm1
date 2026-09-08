<#
.SYNOPSIS
Models additional storage demand across the Windows prerelease pipeline.
#>
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'Atlaso.StorageCapacity.psm1') -Force

<#
.SYNOPSIS
Returns conservative allocation lifetimes for the selected verified resume path.
.PARAMETER RepoRoot
Exact source checkout containing exports, caches, and smoke output.
.PARAMETER Operation
Resolved retained prerelease staging directory.
.PARAMETER BuilderOutput
Resolved builder directory, required for a new build.
.PARAMETER Resume
Read-only verified entry point: Build, Template, or Candidate.
.PARAMETER SourceBytes
Conservative source expansion estimate, or verified retained source tree length.
.PARAMETER RetainedSource
The source tree passed read-only verification and reconstruction creates only a temporary comparison copy.
#>
function Get-AtlasoVirtualizationStoragePlan {
    param(
        [Parameter(Mandatory)][string]$RepoRoot,
        [Parameter(Mandatory)][string]$Operation,
        [string]$BuilderOutput = '',
        [ValidateSet('Build', 'Template', 'Candidate')][string]$Resume = 'Build',
        [ValidateRange(1, 17179869184)][long]$SourceBytes = 16GB,
        [switch]$RetainedSource
    )
    # Lifetimes represent peak simultaneous use, not the sum of sequential VMs.
    # End=7 retains output through candidate staging. Existing bytes are already
    # reflected in free space; only additional allocations enter this plan.
    $plan = @(
        [pscustomobject]@{ Path=$Operation; Name='signed source downloads'; Bytes=2GB; Start=0; End=0 }
        [pscustomobject]@{ Path=$Operation; Name='verified source reconstruction'; Bytes=$SourceBytes; Start=0; End=$(if ($RetainedSource) { 0 } else { 7 }) }
    )
    if ($Resume -eq 'Candidate') { return $plan }
    if ($Resume -eq 'Build') {
        if (-not $BuilderOutput) { throw 'A new-build capacity plan requires its exact builder output.' }
        $plan += @(
            [pscustomobject]@{ Path=$BuilderOutput; Name='two payload disks after zero fill'; Bytes=64GB; Start=1; End=7 }
            [pscustomobject]@{ Path=$BuilderOutput; Name='compaction copy and builder memory'; Bytes=64GB; Start=1; End=1 }
            [pscustomobject]@{ Path=(Join-Path $RepoRoot '.atlaso-local/photon-image-build-state'); Name='snapshot, source copies, ISO and credential staging'; Bytes=($SourceBytes + 8GB); Start=1; End=1 }
            [pscustomobject]@{ Path=(Join-Path $RepoRoot 'image/common/source'); Name='verified ISO cache'; Bytes=4GB; Start=1; End=7 }
        )
    }
    $plan += @(
        [pscustomobject]@{ Path=(Join-Path $RepoRoot 'image/vmware-workstation/ovf'); Name='OVF, OVA and staged OVA copy'; Bytes=8GB; Start=2; End=7 }
        [pscustomobject]@{ Path=(Join-Path $RepoRoot 'image/vmware-workstation/ovf'); Name='OVF export before asset-size admission'; Bytes=60GB; Start=2; End=2 }
        [pscustomobject]@{ Path=(Join-Path $RepoRoot 'artifacts/virtualization'); Name='Hyper-V ZIP'; Bytes=2GB; Start=3; End=7 }
        [pscustomobject]@{ Path=(Join-Path $RepoRoot 'artifacts/virtualization'); Name='OVA extraction and VHDX conversion'; Bytes=68GB; Start=3; End=3 }
        [pscustomobject]@{ Path=(Join-Path $RepoRoot 'artifacts/virtualization-smoke'); Name='VMware import, guest disk growth, 4 GiB memory and validation'; Bytes=84GB; Start=4; End=4 }
        [pscustomobject]@{ Path=(Join-Path $RepoRoot 'artifacts/virtualization-smoke'); Name='Hyper-V extraction, disk copies, guest growth and 4 GiB VMRS'; Bytes=36GB; Start=5; End=5 }
        [pscustomobject]@{ Path=$Operation; Name='candidate asset copies and metadata'; Bytes=8GB; Start=6; End=7 }
    )
    return $plan
}

<#
.SYNOPSIS
Admits the maximum remaining simultaneous demand on each actual destination volume.
.PARAMETER Plan
Allocation lifetimes from Get-AtlasoVirtualizationStoragePlan.
.PARAMETER Stage
Next stage: Source=0, Build=1, Export=2, Conversion=3, VMware=4, HyperV=5, Candidate=6.
#>
function Assert-AtlasoVirtualizationStoragePlan {
    param(
        [Parameter(Mandatory)][object[]]$Plan,
        [ValidateRange(0, 6)][int]$Stage = 0
    )
    $volumes = @{}
    foreach ($component in $Plan) {
        if ($component.Start -lt $Stage) { continue }
        $volume = Get-AtlasoStorageVolume -Path $component.Path
        if (-not $volumes.ContainsKey($volume.VolumeId)) {
            $volumes[$volume.VolumeId] = @()
        }
        $volumes[$volume.VolumeId] += $component
    }
    $peaks = @(
        foreach ($entries in $volumes.Values) {
            $peak = 0L
            $peakComponents = @()
            for ($future = $Stage; $future -le 7; $future++) {
                $active = @($entries | Where-Object { $_.Start -le $future -and $_.End -ge $future })
                if ($active.Count -eq 0) { continue }
                $bytes = [long](($active | Measure-Object -Property Bytes -Sum).Sum)
                if ($bytes -gt $peak) { $peak = $bytes; $peakComponents = $active }
            }
            foreach ($entry in $peakComponents) {
                [pscustomobject]@{ Path=$entry.Path; Name=$entry.Name; Bytes=[long]$entry.Bytes }
            }
        }
    )
    Assert-AtlasoStorageCapacity -Components $peaks -Stage "prerelease remaining stages from $Stage"
}

Export-ModuleMember -Function Get-AtlasoVirtualizationStoragePlan, Assert-AtlasoVirtualizationStoragePlan
