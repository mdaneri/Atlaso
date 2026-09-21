<#
.SYNOPSIS
Models additional storage demand across the Windows prerelease pipeline.
#>
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'Atlaso.StorageCapacity.psm1') -Force

<#
.SYNOPSIS
Checks the canonical cached ISO against the builder's pinned default checksum without modifying it.
.PARAMETER RepoRoot
Exact source checkout containing the builder and ISO cache.
#>
function Test-AtlasoVirtualizationIsoCache {
    param([Parameter(Mandatory)][string]$RepoRoot)
    $builder = Join-Path $RepoRoot 'scripts/windows/vmware/build-photon-image.ps1'
    $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($builder, [ref]$null, [ref]$parseErrors)
    if ($parseErrors.Count -gt 0) { throw 'Cannot read the canonical builder ISO defaults.' }
    $defaults = @{}
    foreach ($name in @('IsoChecksum')) {
        $parameter = @($ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq $name })
        if ($parameter.Count -ne 1 -or $null -eq $parameter[0].DefaultValue) { throw 'Canonical ISO defaults are ambiguous.' }
        $defaults[$name] = [string]$parameter[0].DefaultValue.SafeGetValue()
    }
    if ($defaults.IsoChecksum -notmatch '^sha512:([a-fA-F0-9]{128})$') { throw 'Canonical ISO checksum is unsupported.' }
    $expected = $Matches[1]
    $directory = Join-Path $RepoRoot 'image/common/source'
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) { return $false }
    $null = Get-AtlasoStorageVolume -Path $directory
    # Resolve-AtlasoPhotonSourceIso accepts any checksum-valid *.iso filename.
    # The release wrapper forwards this shared cache, but creates a fresh private
    # packer-work directory: checkout-local build/source and packer_cache are not
    # visible to that child and must not receive speculative reuse credit.
    foreach ($item in Get-ChildItem -LiteralPath $directory -Filter '*.iso' -File) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
        if ((Get-FileHash -LiteralPath $item.FullName -Algorithm SHA512).Hash -ieq $expected) { return $true }
    }
    return $false
}

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
.PARAMETER VerifiedIsoCache
The canonical cached ISO passed its pinned checksum check and requires no new download allocation.
#>
function Get-AtlasoVirtualizationStoragePlan {
    param(
        [Parameter(Mandatory)][string]$RepoRoot,
        [Parameter(Mandatory)][string]$Operation,
        [string]$BuilderOutput = '',
        [ValidateSet('Build', 'Template', 'Candidate')][string]$Resume = 'Build',
        [ValidateRange(1, 17179869184)][long]$SourceBytes = 16GB,
        [switch]$RetainedSource,
        [switch]$VerifiedIsoCache
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
            # Pinned VMware plugin 2.1.5 compacts one disk at a time. Reserve the
            # largest payload (40 GiB), plus 4 GiB for metadata/memory, rather
            # than a second simultaneous copy of both 40 + 20 GiB payloads.
            [pscustomobject]@{ Path=$BuilderOutput; Name='one-disk compaction scratch and builder memory'; Bytes=44GB; Start=1; End=1 }
            [pscustomobject]@{ Path=(Join-Path $RepoRoot '.atlaso-local/photon-image-build-state'); Name='snapshot, source copies, ISO and credential staging'; Bytes=($SourceBytes + 8GB); Start=1; End=1 }
            # The pinned Photon ISO is 4,624,398,336 bytes, exceeding 4 GiB.
            [pscustomobject]@{ Path=(Join-Path $RepoRoot 'image/common/source'); Name='verified ISO cache'; Bytes=$(if ($VerifiedIsoCache) { 0L } else { 5GB }); Start=1; End=7 }
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
.PARAMETER ThroughStage
Last stage whose inputs are known. Later stages are admitted again after their inputs exist.
Omission retains the conservative full remaining-plan forecast for diagnostic callers.
#>
function Assert-AtlasoVirtualizationStoragePlan {
    param(
        [Parameter(Mandatory)][object[]]$Plan,
        [ValidateRange(0, 6)][int]$Stage = 0,
        [ValidateRange(0, 7)][int]$ThroughStage = 7
    )
    if ($ThroughStage -lt $Stage) { throw 'Storage admission horizon precedes the next stage.' }
    $stageNames = @('source verification', 'build and compaction', 'OVF export', 'Hyper-V conversion',
        'VMware smoke', 'Hyper-V smoke', 'candidate staging', 'retained candidate')
    $volumes = @{}
    foreach ($component in $Plan) {
        if ($component.Start -lt $Stage -or $component.Start -gt $ThroughStage) { continue }
        $volume = Get-AtlasoStorageVolume -Path $component.Path
        if (-not $volumes.ContainsKey($volume.VolumeId)) {
            $volumes[$volume.VolumeId] = @()
        }
        $volumes[$volume.VolumeId] += $component
    }
    $peaks = @(
        foreach ($entries in $volumes.Values) {
            $peak = 0L
            $peakStage = $Stage
            $peakComponents = @()
            for ($future = $Stage; $future -le $ThroughStage; $future++) {
                $active = @($entries | Where-Object { $_.Start -le $future -and $_.End -ge $future })
                if ($active.Count -eq 0) { continue }
                $bytes = [long](($active | Measure-Object -Property Bytes -Sum).Sum)
                if ($bytes -gt $peak) { $peak = $bytes; $peakComponents = $active; $peakStage = $future }
            }
            Write-Host ("Predicted peak stage: {0}; additional components: {1:N2} GiB; path: {2}" -f
                $stageNames[$peakStage], ($peak / 1GB), $entries[0].Path)
            foreach ($entry in $peakComponents) {
                [pscustomobject]@{ Path=$entry.Path; Name=$entry.Name; Bytes=[long]$entry.Bytes; PeakStage=$stageNames[$peakStage] }
            }
        }
    )
    Assert-AtlasoStorageCapacity -Components $peaks -Stage "prerelease $($stageNames[$Stage]) through $($stageNames[$ThroughStage])"
}

Export-ModuleMember -Function Get-AtlasoVirtualizationStoragePlan, Assert-AtlasoVirtualizationStoragePlan, Test-AtlasoVirtualizationIsoCache
