<#
.SYNOPSIS
Exercise canonical PR-owned VMware test identity and ownership validation.

.PARAMETER RepositoryRoot
Atlaso checkout containing the VMware identity module under test.
#>
[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

$ErrorActionPreference = 'Stop'
Import-Module (
    Join-Path $RepositoryRoot 'scripts\windows\vmware\Atlaso.VmwareTestIdentity.psm1'
) -Force

<#
.SYNOPSIS
Require one test action to fail.

.PARAMETER Action
Action expected to throw.

.PARAMETER Message
Failure message emitted when the action unexpectedly succeeds.
#>
function Assert-Throws {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $true)][string]$Message
    )
    try {
        & $Action
    }
    catch {
        return
    }
    throw $Message
}

$identity = New-AtlasoVmwareTestIdentity `
    -PullRequestNumber 634 `
    -Purpose 'Lifecycle Acceptance' `
    -CollisionSuffix 'Run 02'
if ($identity.Name -cne 'Atlaso-PR-634-lifecycle-acceptance-run-02') {
    throw "Canonical VMware identity was unexpected: $($identity.Name)"
}
if ($identity.PullRequestNumber -ne 634 -or $identity.Purpose -cne 'lifecycle-acceptance') {
    throw 'Canonical VMware identity did not retain its exact PR owner and sanitized purpose.'
}

$secondIdentity = New-AtlasoVmwareTestIdentity `
    -PullRequestNumber 634 `
    -Purpose 'Lifecycle Acceptance' `
    -CollisionSuffix 'Run 03'
if (
    $secondIdentity.Name -ceq $identity.Name -or
    -not $secondIdentity.Name.StartsWith('Atlaso-PR-634-', [System.StringComparison]::Ordinal)
) {
    throw 'Collision-safe suffixes must distinguish VMs without losing the exact PR identity.'
}

Assert-Throws {
    New-AtlasoVmwareTestIdentity -PullRequestNumber 0 -Purpose 'test-vm'
} 'PR number zero must fail closed.'
Assert-Throws {
    New-AtlasoVmwareTestIdentity -PullRequestNumber -1 -Purpose 'test-vm'
} 'Negative PR numbers must fail closed.'
Assert-Throws {
    New-AtlasoVmwareTestIdentity -PullRequestNumber 634 -Purpose '---'
} 'A purpose that sanitizes to empty must fail closed.'

$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    "atlaso-vmware-identity-$([guid]::NewGuid().ToString('N'))"
)
try {
    $canonicalDirectory = Join-Path $testRoot $identity.Name
    New-Item -ItemType Directory -Path $canonicalDirectory -Force | Out-Null
    $resolvedDirectory = Assert-AtlasoVmwareIdentityDirectory `
        -Path $canonicalDirectory `
        -ExpectedName $identity.Name
    if (-not $resolvedDirectory.EndsWith($identity.Name, [System.StringComparison]::Ordinal)) {
        throw 'Canonical output-directory validation returned the wrong path.'
    }
    Assert-Throws {
        Assert-AtlasoVmwareIdentityDirectory `
            -Path (Join-Path $testRoot 'Atlaso-VMware') `
            -ExpectedName $identity.Name
    } 'A generic output directory must not satisfy PR ownership.'

    $vmxPath = Join-Path $canonicalDirectory "$($identity.Name).vmx"
    [System.IO.File]::WriteAllText(
        $vmxPath,
        "displayName = `"$($identity.Name)`"`r`n"
    )
    $verifiedVmx = Assert-AtlasoVmwareOwnedVmx `
        -VmxPath $vmxPath `
        -ExpectedDirectory $canonicalDirectory `
        -ExpectedName $identity.Name
    if ($verifiedVmx -cne (Resolve-Path -LiteralPath $vmxPath).Path) {
        throw 'Exact PR-owned VMX validation returned the wrong path.'
    }

    [System.IO.File]::WriteAllText($vmxPath, 'displayName = "Atlaso-VMware"')
    Assert-Throws {
        Assert-AtlasoVmwareOwnedVmx `
            -VmxPath $vmxPath `
            -ExpectedDirectory $canonicalDirectory `
            -ExpectedName $identity.Name
    } 'A differently owned displayName must fail closed.'

    $wrongPath = Join-Path $canonicalDirectory 'different.vmx'
    [System.IO.File]::WriteAllText(
        $wrongPath,
        "displayName = `"$($identity.Name)`"`r`n"
    )
    Assert-Throws {
        Assert-AtlasoVmwareOwnedVmx `
            -VmxPath $wrongPath `
            -ExpectedDirectory $canonicalDirectory `
            -ExpectedName $identity.Name
    } 'A mismatched VMX filename must fail closed.'
}
finally {
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}

$cleanupSuffix = "test-$([guid]::NewGuid().ToString('N').Substring(0, 16))"
$cleanupIdentity = New-AtlasoVmwareTestIdentity `
    -PullRequestNumber 2147483647 `
    -Purpose 'lifecycle-cleanup-test' `
    -CollisionSuffix $cleanupSuffix
$cleanupRoot = Join-Path $RepositoryRoot (
    "test-results\vmware-workstation-lifecycle\$($cleanupIdentity.Name)"
)
try {
    $cleanupDisplayName = "$($cleanupIdentity.Name)-Appliance"
    $cleanupVmDirectory = Join-Path $cleanupRoot "vms\$cleanupDisplayName"
    $cleanupVmxPath = Join-Path $cleanupVmDirectory "$cleanupDisplayName.vmx"
    New-Item -ItemType Directory -Path $cleanupVmDirectory -Force | Out-Null
    [System.IO.File]::WriteAllText(
        $cleanupVmxPath,
        "displayName = `"$cleanupDisplayName`"`r`n"
    )
    [ordered]@{
        lab_name            = $cleanupIdentity.Name
        pull_request_number = 2147483647
        purpose             = $cleanupIdentity.Purpose
        collision_suffix    = $cleanupIdentity.CollisionSuffix
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $cleanupRoot 'plan.json') -Encoding UTF8
    $manifestPath = Join-Path $cleanupRoot 'vmware-identity.json'
    [ordered]@{
        lab_name            = $cleanupIdentity.Name
        pull_request_number = 2147483647
        purpose             = $cleanupIdentity.Purpose
        collision_suffix    = $cleanupIdentity.CollisionSuffix
        result_root         = $cleanupRoot
        log_identity        = $cleanupIdentity.Name
        vms                 = @(
            [ordered]@{
                role         = 'appliance'
                display_name = $cleanupDisplayName
                vmx          = $cleanupVmxPath
            }
        )
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

    & (Join-Path $RepositoryRoot 'scripts\windows\vmware\remove-lifecycle-vms.ps1') `
        -PullRequestNumber 2147483647 `
        -Purpose $cleanupIdentity.Purpose `
        -CollisionSuffix $cleanupIdentity.CollisionSuffix `
        -VmrunPath (Get-Process -Id $PID).Path `
        -WhatIf
    if (-not $?) {
        throw 'Exact lifecycle cleanup evidence unexpectedly failed validation.'
    }

    $mismatchedManifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $mismatchedManifest.vms[0].vmx = Join-Path $cleanupVmDirectory 'different.vmx'
    $mismatchedManifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    Assert-Throws {
        & (Join-Path $RepositoryRoot 'scripts\windows\vmware\remove-lifecycle-vms.ps1') `
            -PullRequestNumber 2147483647 `
            -Purpose $cleanupIdentity.Purpose `
            -CollisionSuffix $cleanupIdentity.CollisionSuffix `
            -VmrunPath (Get-Process -Id $PID).Path `
            -WhatIf
    } 'Lifecycle cleanup must reject identity evidence for a different VMX path.'
}
finally {
    if (Test-Path -LiteralPath $cleanupRoot) {
        Remove-Item -LiteralPath $cleanupRoot -Recurse -Force
    }
}

Write-Host 'Atlaso VMware test identity checks passed.'
