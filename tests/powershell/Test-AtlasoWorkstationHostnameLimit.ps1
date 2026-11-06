<#
.SYNOPSIS
Verify generated guest identities and pre-clone hostname-limit refusal without a VM.
.PARAMETER RepositoryRoot
Checkout containing the canonical VMware first-boot and creation helpers.
.PARAMETER OutputDirectory
Task-owned directory for synthetic VMX and preservation evidence.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RepositoryRoot,
    [Parameter(Mandatory = $true)][string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
. (Join-Path $RepositoryRoot 'scripts/windows/vmware/Atlaso.WorkstationFirstBoot.ps1')
Import-Module (Join-Path $RepositoryRoot 'scripts/windows/vmware/Atlaso.VmwareTestIdentity.psm1') -Force
Import-Module (Join-Path $RepositoryRoot 'scripts/windows/vmware/Atlaso.WorkstationReadiness.psm1') -Force

$short = New-AtlasoVmwareTestIdentity -PullRequestNumber 1083 -Purpose test-vm -CollisionSuffix a
if ((New-AtlasoWorkstationFqdn -Name $short.Name) -cne 'atlaso-pr-1083-test-vm-a.atlaso.internal') {
    throw 'An ordinary short canonical identity changed.'
}
$example = New-AtlasoVmwareTestIdentity -PullRequestNumber 1083 -Purpose guest-tools-time-peer -CollisionSuffix offline20261101
$exampleFqdn = New-AtlasoWorkstationFqdn -Name $example.Name
if ($example.Name -cne 'Atlaso-PR-1083-guest-tools-time-peer-offline20261101' -or
    $exampleFqdn.Length -gt 63 -or
    $exampleFqdn -cnotmatch '^atlaso-pr-1083-[a-z0-9-]+-[0-9a-f]{12}\.atlaso\.internal$' -or
    (New-AtlasoWorkstationFqdn -Name $example.Name) -cne $exampleFqdn) {
    throw 'The documented offline identity must retain its VM owner and derive a stable supported FQDN.'
}
foreach ($length in @(46, 47, 48, 63, 64)) {
    $label = 'a' * $length
    $fqdn = New-AtlasoWorkstationFqdn -Name $label
    if ($fqdn.Length -gt 63 -or $fqdn -cnotmatch '^[a-z0-9]([a-z0-9-]*[a-z0-9])?\.atlaso\.internal$') {
        throw "Generated name at label length $length exceeded the whole-hostname boundary."
    }
    if ($length -le 47 -and $fqdn -cne "$label.atlaso.internal") {
        throw 'A complete hostname at or below the exact 63-character boundary was changed.'
    }
}
$local = New-AtlasoVmwareTestIdentity -LocalBuilder -SourceCommit ('a' * 40) -Purpose ('p' * 32) -CollisionSuffix ('x' * 32)
$names = @(
    $exampleFqdn
    New-AtlasoWorkstationFqdn -Name ($example.Name -replace 'offline20261101$', 'offline20261102')
    New-AtlasoWorkstationFqdn -Name ($example.Name -replace 'PR-1083-', 'PR-1084-')
    New-AtlasoWorkstationFqdn -Name $local.Name
    New-AtlasoWorkstationFqdn -Name ($local.Name.Substring(0, $local.Name.Length - 1) + 'y')
)
if (@($names | Sort-Object -Unique).Count -ne $names.Count -or @($names | Where-Object Length -GT 63).Count) {
    throw 'Long PR/local identities or late collision suffixes lost their distinction.'
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$targetVmx = Join-Path $OutputDirectory 'fixture.vmx'
[IO.File]::WriteAllText($targetVmx, 'displayName = "fixture"')
$boundaryFqdn = ('a' * 47) + '.atlaso.internal'
if ((Assert-AtlasoWorkstationHostnameIdentity -TargetVmxPath $targetVmx -ExpectedHostname $boundaryFqdn -ObservedHostname $boundaryFqdn) -cne $boundaryFqdn) {
    throw 'An exact 63-character observed identity was refused.'
}
try {
    $null = Assert-AtlasoWorkstationHostnameIdentity -TargetVmxPath $targetVmx -ExpectedHostname $boundaryFqdn -ObservedHostname $boundaryFqdn.Substring(0, 62)
    throw 'A truncated hostname was admitted.'
}
catch {
    if ($_.Exception.Message -notlike 'VMware guest hostname mismatch*') { throw }
}

# Invoke the actual wrapper without provider/credential access. Oversized input
# must refuse even when the requested source and vmrun do not exist, preserving
# the existing output instead of entering redeploy or clone preparation.
$wrapper = Join-Path $RepositoryRoot 'scripts/windows/vmware/create-atlaso-test-vm.ps1'
$canonicalOutput = Join-Path $OutputDirectory $short.Name
New-Item -ItemType Directory -Path $canonicalOutput | Out-Null
$marker = Join-Path $canonicalOutput 'preserve.txt'
[IO.File]::WriteAllText($marker, 'original')
$savedThread = $env:CODEX_THREAD_ID
try {
    $env:CODEX_THREAD_ID = ''
    foreach ($acceptedLength in @(62, 63)) {
        $acceptedFqdn = ('a' * ($acceptedLength - '.atlaso.internal'.Length)) + '.atlaso.internal'
        try {
            & $wrapper -PullRequestNumber 1083 -Purpose test-vm -CollisionSuffix a -OutputDirectory $canonicalOutput `
                -ApplianceVmxPath (Join-Path $OutputDirectory 'missing-source.vmx') `
                -FirstBootFqdn $acceptedFqdn -SkipSshKeyProvisioning -Redeploy -WhatIf
            throw 'The deliberately missing source template was accepted.'
        }
        catch {
            if ($_.CategoryInfo.Category -ne 'ObjectNotFound' -or $_.Exception.Message -notlike '*missing-source.vmx*') { throw }
        }
    }
    foreach ($oversized in @((('a' * 48) + '.atlaso.internal'), ($example.Name.ToLowerInvariant() + '.atlaso.internal'))) {
        try {
            & $wrapper -PullRequestNumber 1083 -Purpose test-vm -CollisionSuffix a -OutputDirectory $canonicalOutput `
                -ApplianceVmxPath (Join-Path $OutputDirectory 'missing-source.vmx') `
                -VmrunPath (Join-Path $OutputDirectory 'must-not-run.exe') `
                -FirstBootFqdn $oversized -SkipSshKeyProvisioning -Redeploy -WhatIf
            throw 'An oversized explicit FQDN passed creation preflight.'
        }
        catch {
            if ($_.Exception.Message -notlike 'FirstBootFqdn exceeds the 63-character guest hostname limit*') { throw }
        }
        if ([IO.File]::ReadAllText($marker) -cne 'original' -or @(Get-ChildItem -LiteralPath $canonicalOutput -Force).Count -ne 1) {
            throw 'Hostname-limit refusal changed the requested VM output.'
        }
    }
}
finally {
    $env:CODEX_THREAD_ID = $savedThread
}
Write-Host 'Atlaso Workstation hostname-limit tests passed.'
