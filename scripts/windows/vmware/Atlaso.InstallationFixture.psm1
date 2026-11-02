<#
.SYNOPSIS
Define the finite installation-test disk profiles without filesystem or provider activity.
#>
Set-StrictMode -Version Latest

<#
.SYNOPSIS
Return a fresh fixed disk recipe for an explicitly selected installation fixture.
.PARAMETER FixtureProfile
SingleDisk preserves 64/4 GiB; MultiDisk adds selected data; OldSystemLabel seeds only the unselected disk.
#>
function Get-AtlasoInstallationFixture {
    param([ValidateSet('SingleDisk', 'MultiDisk', 'OldSystemLabel')][string]$FixtureProfile = 'SingleDisk')
    $fixtureName = @('SingleDisk', 'MultiDisk', 'OldSystemLabel') | Where-Object { $_ -ieq $FixtureProfile }
    $disks = @(
        [pscustomobject]@{ Role = 'target'; Name = 'target-64g.vmdk'; SizeGiB = 64; Device = 'scsi0:0'; Selected = $true },
        [pscustomobject]@{ Role = 'unselected'; Name = 'unselected-4g.vmdk'; SizeGiB = 4; Device = 'scsi0:1'; Selected = $false }
    )
    if ($fixtureName -ceq 'MultiDisk') {
        $disks += [pscustomobject]@{ Role = 'data'; Name = 'data-8g.vmdk'; SizeGiB = 8; Device = 'scsi0:2'; Selected = $true }
    }
    return [pscustomobject]@{ Profile = $fixtureName; Disks = $disks }
}

<#
.SYNOPSIS
Read a fixed profile from an admitted context, preserving legacy two-disk callers.
.PARAMETER Context
Task context whose profile was selected at creation or read from original sealed receipts.
#>
function Get-AtlasoInstallationContextFixture {
    param([psobject]$Context)
    $fixtureName = 'SingleDisk'
    if ($Context.PSObject.Properties['FixtureProfile']) {
        if ($Context.FixtureProfile -isnot [string] -or $Context.FixtureProfile -cnotin @('SingleDisk', 'MultiDisk', 'OldSystemLabel')) {
            throw 'Installation fixture context profile is malformed.'
        }
        $fixtureName = $Context.FixtureProfile
    }
    return Get-AtlasoInstallationFixture -FixtureProfile $fixtureName
}

<#
.SYNOPSIS
Require original and baseline receipts to agree on their immutable fixed profile.
.PARAMETER Original
Hash-admitted original VM record.
.PARAMETER Baseline
Hash-admitted baseline record bound to that original VM.
#>
function Resolve-AtlasoInstallationReceiptFixture {
    param([psobject]$Original, [psobject]$Baseline)
    $originalField = $Original.PSObject.Properties['fixture_profile']
    $baselineField = $Baseline.PSObject.Properties['fixture_profile']
    if (-not $originalField -and -not $baselineField) {
        return Get-AtlasoInstallationFixture -FixtureProfile SingleDisk
    }
    if (-not $originalField -or -not $baselineField -or $originalField.Value -isnot [string] -or
        $originalField.Value -cnotin @('SingleDisk', 'MultiDisk', 'OldSystemLabel') -or
        $baselineField.Value -cne $originalField.Value) {
        throw 'Original and baseline installation fixture profiles do not match.'
    }
    return Get-AtlasoInstallationFixture -FixtureProfile $originalField.Value
}

<#
.SYNOPSIS
Require all fixed roles, paths, sizes and original identity/hash shapes before provider or filesystem activity.
.PARAMETER Fixture
Finite recipe resolved from the original and baseline receipt pair.
.PARAMETER Baseline
Sealed original disk-baseline record.
.PARAMETER OutputDirectory
Exact original VM artifact directory.
#>
function Assert-AtlasoInstallationBaselineDisks {
    param([psobject]$Fixture, [psobject]$Baseline, [string]$OutputDirectory)
    $recipe = Get-AtlasoInstallationFixture -FixtureProfile $Fixture.Profile
    if (@($Baseline.disks).Count -ne $recipe.Disks.Count) { throw 'Installation baseline disk count differs from its original profile.' }
    foreach ($disk in $recipe.Disks) {
        $entries = @($Baseline.disks | Where-Object { $_.role -ceq $disk.Role })
        if ($entries.Count -ne 1) { throw 'Installation baseline must contain every original fixed role exactly once.' }
        foreach ($kind in @('source', 'baseline')) {
            $name = if ($kind -ceq 'source') { $disk.Name } else { $disk.Name.Replace('.vmdk', '.baseline.vmdk') }
            $evidence = $entries[0].$kind
            if ($evidence.path -cne (Join-Path $OutputDirectory $name) -or
                [long]$evidence.virtual_size_bytes -ne [long]$disk.SizeGiB * 1GB -or
                [string]$evidence.file_identity -cnotmatch '^[0-9A-F]{8}:[0-9A-F]{16}$' -or
                [string]$evidence.sha256 -cnotmatch '^[0-9a-f]{64}$') {
                throw 'Installation baseline role, path, virtual size or original evidence is malformed.'
            }
        }
    }
}

<#
.SYNOPSIS
Always select the untouched disk for comparison and include every selected disk on cancellation.
.PARAMETER FixtureProfile
Original sealed fixed recipe.
.PARAMETER IncludeSelected
Compare all selected disks as well as the unselected disk before admitting a no-write result.
#>
function Get-AtlasoInstallationVerificationRoles {
    param([ValidateSet('SingleDisk', 'MultiDisk', 'OldSystemLabel')][string]$FixtureProfile = 'SingleDisk', [switch]$IncludeSelected)
    $roles = @('unselected')
    if ($IncludeSelected) {
        $roles += @((Get-AtlasoInstallationFixture -FixtureProfile $FixtureProfile).Disks | Where-Object Selected | ForEach-Object Role)
    }
    return [string[]]$roles
}

Export-ModuleMember -Function Get-AtlasoInstallationFixture, Get-AtlasoInstallationContextFixture, Resolve-AtlasoInstallationReceiptFixture, Assert-AtlasoInstallationBaselineDisks, Get-AtlasoInstallationVerificationRoles
