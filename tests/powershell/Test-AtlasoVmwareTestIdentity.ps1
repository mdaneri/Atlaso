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

Write-Host 'Atlaso VMware test identity checks passed.'
