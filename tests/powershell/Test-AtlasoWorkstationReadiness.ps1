<#
.SYNOPSIS
Validate fail-closed VMware Workstation address identity decisions.

.PARAMETER RepositoryRoot
Atlaso checkout containing the readiness module.

.PARAMETER OutputDirectory
Temporary directory used for synthetic VMX evidence.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RepositoryRoot,
    [Parameter(Mandatory = $true)][string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $RepositoryRoot 'scripts/windows/vmware/Atlaso.WorkstationReadiness.psm1') -Force
[System.IO.Directory]::CreateDirectory($OutputDirectory) | Out-Null
$targetVmx = Join-Path $OutputDirectory 'Issue-535.vmx'
$sourceVmx = Join-Path $OutputDirectory 'Existing-Static-Source.vmx'
[System.IO.File]::WriteAllText(
    $targetVmx,
    "displayName = `"Issue-535`"`nethernet0.generatedAddress = `"00:0c:29:11:22:33`"`n",
    [System.Text.UTF8Encoding]::new($false)
)
[System.IO.File]::WriteAllText(
    $sourceVmx,
    "displayName = `"Existing-Static-Source`"`nethernet0.generatedAddress = `"00:0c:29:aa:bb:cc`"`n",
    [System.Text.UTF8Encoding]::new($false)
)
$fakeVmrun = Join-Path $OutputDirectory 'fake-vmrun.cmd'
[System.IO.File]::WriteAllText(
    $fakeVmrun,
    "@echo off`r`nif /I `"%3`"==`"getGuestIPAddress`" (`r`n  echo 192.168.167.134`r`n  exit /b 0`r`n)`r`nif /I `"%3`"==`"readVariable`" (`r`n  echo issue-535.atlaso.internal`r`n  exit /b 0`r`n)`r`nif /I `"%3`"==`"list`" (`r`n  echo Total running VMs: 2`r`n  echo `"$targetVmx`"`r`n  echo `"$sourceVmx`"`r`n  exit /b 0`r`n)`r`nexit /b 9`r`n",
    [System.Text.UTF8Encoding]::new($false)
)
$runningPaths = @(Get-AtlasoWorkstationRunningVmxPath -VmrunPath $fakeVmrun)
if ($runningPaths.Count -ne 2 -or
    $runningPaths[0] -cne (Resolve-Path -LiteralPath $targetVmx).Path -or
    $runningPaths[1] -cne (Resolve-Path -LiteralPath $sourceVmx).Path) {
    throw 'Checked vmrun inventory did not retain the exact running VMX paths.'
}
$workflowError = $null
try {
    & (Join-Path $RepositoryRoot 'scripts/windows/vmware/get-atlaso-vm-ip.ps1') `
        -VmxPath $targetVmx `
        -ExpectedHostname 'issue-535.atlaso.internal' `
        -VmrunPath $fakeVmrun `
        -TimeoutSeconds 2 `
        -PollSeconds 1 | Out-Null
} catch { $workflowError = $_ }
if ($null -eq $workflowError -or
    $workflowError.Exception.Message -notlike '*Existing-Static-Source.vmx*' -or
    $workflowError.Exception.Message -notlike '*192.168.167.134*') {
    throw 'The complete readiness workflow did not reject the source appliance duplicate address.'
}

$targetMac = Get-AtlasoWorkstationVmxMacAddress -VmxPath $targetVmx
if ($targetMac -cne '00-0c-29-11-22-33') { throw 'Target VMX MAC normalization failed.' }
try {
    ConvertTo-AtlasoWorkstationMacAddress -MacAddress 'noise-00:0c:29:11:22:33' | Out-Null
    throw 'Malformed MAC text was accepted.'
} catch {
    if ($_.Exception.Message -eq 'Malformed MAC text was accepted.') { throw }
}

$duplicateGuests = @(
    [pscustomobject]@{ Path = $targetVmx; MacAddress = $targetMac; IPAddress = '192.168.167.134' },
    [pscustomobject]@{ Path = $sourceVmx; MacAddress = '00-0c-29-aa-bb-cc'; IPAddress = '192.168.167.134' }
)
$duplicateError = $null
try {
    Assert-AtlasoWorkstationAddressIdentity `
        -TargetVmxPath $targetVmx `
        -TargetMacAddress $targetMac `
        -TargetIPAddress '192.168.167.134' `
        -ExpectedHostname 'issue-535.atlaso.internal' `
        -ObservedHostname 'issue-535.atlaso.internal' `
        -RunningGuests $duplicateGuests `
        -NeighborMacAddresses @($targetMac) | Out-Null
} catch { $duplicateError = $_ }
if ($null -eq $duplicateError -or
    $duplicateError.Exception.Message -notlike '*Existing-Static-Source.vmx*' -or
    $duplicateError.Exception.Message -notlike '*00-0c-29-aa-bb-cc*' -or
    $duplicateError.Exception.Message -notlike '*192.168.167.134*') {
    throw 'A running source appliance with the same static management address did not fail with exact conflict evidence.'
}

$uniqueGuests = @(
    [pscustomobject]@{ Path = $targetVmx; MacAddress = $targetMac; IPAddress = '192.168.167.135' },
    [pscustomobject]@{ Path = $sourceVmx; MacAddress = '00-0c-29-aa-bb-cc'; IPAddress = '192.168.167.134' }
)
$identity = Assert-AtlasoWorkstationAddressIdentity `
    -TargetVmxPath $targetVmx `
    -TargetMacAddress $targetMac `
    -TargetIPAddress '192.168.167.135' `
    -ExpectedHostname 'issue-535.atlaso.internal' `
    -ObservedHostname 'ISSUE-535.ATLASO.INTERNAL.' `
    -RunningGuests $uniqueGuests `
    -NeighborMacAddresses @($targetMac)
if ($identity.VmxPath -cne (Resolve-Path -LiteralPath $targetVmx).Path -or
    $identity.MacAddress -cne $targetMac -or
    $identity.Hostname -cne 'issue-535.atlaso.internal' -or
    $identity.IPAddress -cne '192.168.167.135') {
    throw 'Successful readiness did not retain the complete VMX, MAC, hostname, and address identity tuple.'
}

$neighborError = $null
try {
    Assert-AtlasoWorkstationAddressIdentity `
        -TargetVmxPath $targetVmx `
        -TargetMacAddress $targetMac `
        -TargetIPAddress '192.168.167.135' `
        -ExpectedHostname 'issue-535.atlaso.internal' `
        -ObservedHostname 'issue-535.atlaso.internal' `
        -RunningGuests $uniqueGuests `
        -NeighborMacAddresses @('00-0c-29-aa-bb-cc') | Out-Null
} catch { $neighborError = $_ }
if ($null -eq $neighborError -or $neighborError.Exception.Message -notlike '*Existing-Static-Source.vmx*') {
    throw 'A host-facing neighbor mapping to another running VMX did not fail closed with exact owner evidence.'
}

$incompleteGuests = @(
    [pscustomobject]@{ Path = $targetVmx; MacAddress = $targetMac; IPAddress = '192.168.167.135' },
    [pscustomobject]@{ Path = $sourceVmx; MacAddress = '00-0c-29-aa-bb-cc'; IPAddress = '' }
)
try {
    Assert-AtlasoWorkstationAddressIdentity `
        -TargetVmxPath $targetVmx `
        -TargetMacAddress $targetMac `
        -TargetIPAddress '192.168.167.135' `
        -ExpectedHostname 'issue-535.atlaso.internal' `
        -ObservedHostname 'issue-535.atlaso.internal' `
        -RunningGuests $incompleteGuests `
        -NeighborMacAddresses @($targetMac) | Out-Null
    throw 'Incomplete running-guest evidence was accepted.'
} catch {
    if ($_.Exception.Message -eq 'Incomplete running-guest evidence was accepted.' -or
        $_.Exception.Message -notlike '*Existing-Static-Source.vmx*') { throw }
}

try {
    Assert-AtlasoWorkstationAddressIdentity `
        -TargetVmxPath $targetVmx `
        -TargetMacAddress $targetMac `
        -TargetIPAddress '192.168.167.135' `
        -ExpectedHostname 'issue-535.atlaso.internal' `
        -ObservedHostname 'wrong.atlaso.internal' `
        -RunningGuests $uniqueGuests `
        -NeighborMacAddresses @($targetMac) | Out-Null
    throw 'Mismatched guest hostname evidence was accepted.'
} catch {
    if ($_.Exception.Message -eq 'Mismatched guest hostname evidence was accepted.' -or
        $_.Exception.Message -notlike '*wrong.atlaso.internal*') { throw }
}

try {
    Assert-AtlasoWorkstationAddressIdentity `
        -TargetVmxPath $targetVmx `
        -TargetMacAddress $targetMac `
        -TargetIPAddress '192.168.167.135' `
        -ExpectedHostname 'issue-535.atlaso.internal' `
        -ObservedHostname '' `
        -RunningGuests $uniqueGuests `
        -NeighborMacAddresses @($targetMac) | Out-Null
    throw 'Missing guest hostname evidence was accepted.'
} catch {
    if ($_.Exception.Message -eq 'Missing guest hostname evidence was accepted.' -or
        $_.Exception.Message -notlike '*hostname evidence is incomplete*') { throw }
}

Write-Output 'Atlaso VMware Workstation readiness tests passed.'
