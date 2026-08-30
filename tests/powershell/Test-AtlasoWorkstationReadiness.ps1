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
$concurrentVmx = Join-Path $OutputDirectory 'Concurrent-Clone.vmx'
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
[System.IO.File]::WriteAllText(
    $concurrentVmx,
    "displayName = `"Concurrent-Clone`"`nethernet0.generatedAddress = `"00:0c:29:44:55:66`"`n",
    [System.Text.UTF8Encoding]::new($false)
)
$fakeVmrun = Join-Path $OutputDirectory 'fake-vmrun.cmd'
[System.IO.File]::WriteAllText(
    $fakeVmrun,
    "@echo off`r`nif /I `"%3`"==`"getGuestIPAddress`" (`r`n  echo 192.168.167.134`r`n  exit /b 0`r`n)`r`nif /I `"%3`"==`"readVariable`" (`r`n  if /I not `"%5`"==`"runtimeConfig`" exit /b 8`r`n  echo `"issue-535.atlaso.internal`"`r`n  exit /b 0`r`n)`r`nif /I `"%3`"==`"list`" (`r`n  echo Total running VMs: 2`r`n  echo `"$targetVmx`"`r`n  echo `"$sourceVmx`"`r`n  exit /b 0`r`n)`r`nexit /b 9`r`n",
    [System.Text.UTF8Encoding]::new($false)
)
$runtimeConfigValues = @(
    'issue-535.atlaso.internal',
    '  issue-535.atlaso.internal  ',
    '"issue-535.atlaso.internal"',
    '  "issue-535.atlaso.internal"  '
)
foreach ($runtimeConfigValue in $runtimeConfigValues) {
    $normalizedValue = ConvertFrom-AtlasoWorkstationRuntimeConfigValue -Value $runtimeConfigValue
    if ($normalizedValue -cne 'issue-535.atlaso.internal') {
        throw "VMware runtimeConfig normalization changed the hostname value: $runtimeConfigValue"
    }
}
foreach ($malformedRuntimeConfigValue in @(
        '"issue-535.atlaso.internal',
        'issue-535.atlaso.internal"',
        '""issue-535.atlaso.internal""',
        'issue-"535.atlaso.internal'
    )) {
    try {
        ConvertFrom-AtlasoWorkstationRuntimeConfigValue -Value $malformedRuntimeConfigValue | Out-Null
        throw "Malformed VMware runtimeConfig quoting was accepted: $malformedRuntimeConfigValue"
    }
    catch {
        if ($_.Exception.Message -like 'Malformed VMware runtimeConfig quoting was accepted:*' -or
            $_.Exception.Message -notlike 'VMware runtimeConfig representation is malformed*') {
            throw
        }
    }
}
$malformedVmrun = Join-Path $OutputDirectory 'malformed-vmrun.cmd'
[System.IO.File]::WriteAllText(
    $malformedVmrun,
    (Get-Content -LiteralPath $fakeVmrun -Raw).Replace(
        'echo "issue-535.atlaso.internal"',
        'echo "issue-535.atlaso.internal'
    ),
    [System.Text.UTF8Encoding]::new($false)
)
$malformedWorkflowError = $null
try {
    & (Join-Path $RepositoryRoot 'scripts/windows/vmware/get-atlaso-vm-ip.ps1') `
        -VmxPath $targetVmx `
        -ExpectedHostname 'issue-535.atlaso.internal' `
        -VmrunPath $malformedVmrun `
        -TimeoutSeconds 2 `
        -PollSeconds 1 | Out-Null
}
catch {
    $malformedWorkflowError = $_
}
if ($null -eq $malformedWorkflowError -or
    $malformedWorkflowError.Exception.Message -notlike 'VMware runtimeConfig representation is malformed*') {
    throw 'The complete readiness workflow did not fail closed on malformed runtimeConfig quoting.'
}
$runningPaths = @(
    Get-AtlasoWorkstationRunningVmxPath -VmrunPath $fakeVmrun -Deadline (Get-Date).AddSeconds(2)
)
if ($runningPaths.Count -ne 2 -or
    $runningPaths[0] -cne (Resolve-Path -LiteralPath $targetVmx).Path -or
    $runningPaths[1] -cne (Resolve-Path -LiteralPath $sourceVmx).Path) {
    throw 'Checked vmrun inventory did not retain the exact running VMX paths.'
}
$slowVmrun = Join-Path $OutputDirectory 'slow-vmrun.cmd'
[System.IO.File]::WriteAllText(
    $slowVmrun,
    "@echo off`r`nping -n 6 127.0.0.1 >nul`r`necho Total running VMs: 0`r`n",
    [System.Text.UTF8Encoding]::new($false)
)
$boundedStart = Get-Date
try {
    Get-AtlasoWorkstationRunningVmxPath `
        -VmrunPath $slowVmrun `
        -Deadline (Get-Date).AddMilliseconds(250) | Out-Null
    throw 'A stalled vmrun inventory query exceeded its readiness deadline.'
} catch {
    if ($_.Exception.Message -eq 'A stalled vmrun inventory query exceeded its readiness deadline.' -or
        $_.Exception.Message -notlike '*exceeded the readiness deadline*') { throw }
}
if (((Get-Date) - $boundedStart).TotalSeconds -ge 2) {
    throw 'The bounded vmrun timeout did not stop the stalled provider query promptly.'
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
$ownership = Assert-AtlasoWorkstationAddressOwnership `
    -TargetVmxPath $targetVmx `
    -TargetMacAddress $targetMac `
    -TargetIPAddress '192.168.167.135' `
    -RunningGuests $uniqueGuests `
    -NeighborMacAddresses @($targetMac)
if ($ownership.VmxPath -cne (Resolve-Path -LiteralPath $targetVmx).Path -or
    $ownership.MacAddress -cne $targetMac -or
    $ownership.IPAddress -cne '192.168.167.135') {
    throw 'Address ownership proof did not retain the VMX, MAC, and address tuple independently of hostname readiness.'
}
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

$stalledVmrun = Join-Path $OutputDirectory 'stalled-first-boot-vmrun.cmd'
[System.IO.File]::WriteAllText(
    $stalledVmrun,
    "@echo off`r`nif /I `"%3`"==`"getGuestIPAddress`" (`r`n  echo 192.168.167.135`r`n  exit /b 0`r`n)`r`nif /I `"%3`"==`"readVariable`" (`r`n  if /I `"%6`"==`"guestinfo.atlaso.test_vm_first_boot_stage`" echo failed-hostname`r`n  exit /b 0`r`n)`r`nif /I `"%3`"==`"list`" (`r`n  echo Total running VMs: 1`r`n  echo `"$targetVmx`"`r`n  exit /b 0`r`n)`r`nexit /b 9`r`n",
    [System.Text.UTF8Encoding]::new($false)
)
<#
.SYNOPSIS
Return synthetic Windows neighbor evidence for the stalled first-boot fixture.
.PARAMETER AddressFamily
Ignored address-family selector.
.PARAMETER IPAddress
Ignored fixture address.
.PARAMETER ErrorAction
Ignored error preference.
#>
function Get-TestNetNeighbor {
    param(
        [string]$AddressFamily,
        [string]$IPAddress,
        [System.Management.Automation.ActionPreference]$ErrorAction
    )
    return [pscustomobject]@{ State = 'Reachable'; LinkLayerAddress = $targetMac }
}
<#
.SYNOPSIS
Populate synthetic neighbor state for the stalled first-boot fixture.
.PARAMETER TargetName
Ignored fixture address.
.PARAMETER Count
Ignored probe count.
.PARAMETER Quiet
Ignored quiet selector.
.PARAMETER TimeoutSeconds
Ignored timeout.
.PARAMETER ErrorAction
Ignored error preference.
#>
function Test-TestConnection {
    param(
        [string]$TargetName,
        [int]$Count,
        [switch]$Quiet,
        [int]$TimeoutSeconds,
        [System.Management.Automation.ActionPreference]$ErrorAction
    )
    return $true
}
$hostnameCounter = Join-Path $OutputDirectory 'hostname-confirmation-count.txt'
[System.IO.File]::WriteAllText($hostnameCounter, '0', [System.Text.UTF8Encoding]::new($false))
$hostnameTimeoutVmrun = Join-Path $OutputDirectory 'hostname-confirmation-timeout-vmrun.cmd'
[System.IO.File]::WriteAllText(
    $hostnameTimeoutVmrun,
    "@echo off`r`nsetlocal EnableDelayedExpansion`r`nif /I `"%3`"==`"getGuestIPAddress`" (`r`n  echo 192.168.167.135`r`n  exit /b 0`r`n)`r`nif /I `"%3`"==`"readVariable`" (`r`n  if /I not `"%6`"==`"guestinfo.atlaso.test_vm_hostname`" exit /b 0`r`n  set /p count=<`"$hostnameCounter`"`r`n  set /a count+=1`r`n  >`"$hostnameCounter`" echo !count!`r`n  if !count! EQU 1 (`r`n    echo issue-584.atlaso.internal`r`n    exit /b 0`r`n  )`r`n  ping -n 6 127.0.0.1 >nul`r`n  exit /b 0`r`n)`r`nif /I `"%3`"==`"list`" (`r`n  echo Total running VMs: 1`r`n  echo `"$targetVmx`"`r`n  exit /b 0`r`n)`r`nexit /b 9`r`n",
    [System.Text.UTF8Encoding]::new($false)
)
$timeoutIdentity = $null
try {
    Set-Alias -Name Get-NetNeighbor -Value Get-TestNetNeighbor -Scope Global
    Set-Alias -Name Test-Connection -Value Test-TestConnection -Scope Global
    $timeoutIdentity = & (Join-Path $RepositoryRoot 'scripts/windows/vmware/get-atlaso-vm-ip.ps1') `
        -VmxPath $targetVmx `
        -ExpectedHostname 'issue-584.atlaso.internal' `
        -VmrunPath $hostnameTimeoutVmrun `
        -TimeoutSeconds 2 `
        -PollSeconds 1 `
        -PassThruIdentity
}
finally {
    Remove-Item Alias:Get-NetNeighbor -ErrorAction SilentlyContinue
    Remove-Item Alias:Test-Connection -ErrorAction SilentlyContinue
}
if ($null -eq $timeoutIdentity -or
    $timeoutIdentity.Hostname -cne 'issue-584.atlaso.internal' -or
    $timeoutIdentity.IPAddress -cne '192.168.167.135') {
    throw 'A timed-out confirmation read erased the valid hostname from the same stable ownership observation.'
}
$stalledError = $null
try {
    Set-Alias -Name Get-NetNeighbor -Value Get-TestNetNeighbor -Scope Global
    Set-Alias -Name Test-Connection -Value Test-TestConnection -Scope Global
    & (Join-Path $RepositoryRoot 'scripts/windows/vmware/get-atlaso-vm-ip.ps1') `
        -VmxPath $targetVmx `
        -ExpectedHostname 'issue-584.atlaso.internal' `
        -VmrunPath $stalledVmrun `
        -TimeoutSeconds 2 `
        -PollSeconds 1 | Out-Null
}
catch {
    $stalledError = $_
}
finally {
    Remove-Item Alias:Get-NetNeighbor -ErrorAction SilentlyContinue
    Remove-Item Alias:Test-Connection -ErrorAction SilentlyContinue
}
if ($null -eq $stalledError -or
    $stalledError.Exception.Message -notlike 'VMware address ownership was proven*' -or
    $stalledError.Exception.Message -notlike '*failed-hostname*' -or
    $stalledError.Exception.Message -notlike '*Observed hostname: ''<not reported>''*' -or
    $stalledError.Exception.Message -like 'No uniquely bound IPv4 address*') {
    throw 'A guest-initialization stall after stable address ownership did not report the sanitized first-boot layer.'
}
$providerFailureVmrun = Join-Path $OutputDirectory 'hostname-provider-failure-vmrun.cmd'
[System.IO.File]::WriteAllText(
    $providerFailureVmrun,
    "@echo off`r`nif /I `"%3`"==`"getGuestIPAddress`" (`r`n  echo 192.168.167.135`r`n  exit /b 0`r`n)`r`nif /I `"%3`"==`"readVariable`" exit /b 8`r`nif /I `"%3`"==`"list`" (`r`n  echo Total running VMs: 1`r`n  echo `"$targetVmx`"`r`n  exit /b 0`r`n)`r`nexit /b 9`r`n",
    [System.Text.UTF8Encoding]::new($false)
)
$providerFailureError = $null
try {
    Set-Alias -Name Get-NetNeighbor -Value Get-TestNetNeighbor -Scope Global
    Set-Alias -Name Test-Connection -Value Test-TestConnection -Scope Global
    & (Join-Path $RepositoryRoot 'scripts/windows/vmware/get-atlaso-vm-ip.ps1') `
        -VmxPath $targetVmx `
        -ExpectedHostname 'issue-584.atlaso.internal' `
        -VmrunPath $providerFailureVmrun `
        -TimeoutSeconds 2 `
        -PollSeconds 1 | Out-Null
}
catch {
    $providerFailureError = $_
}
finally {
    Remove-Item Alias:Get-NetNeighbor -ErrorAction SilentlyContinue
    Remove-Item Alias:Test-Connection -ErrorAction SilentlyContinue
}
if ($null -eq $providerFailureError -or
    $providerFailureError.Exception.Message -notlike 'VMware address ownership was proven*' -or
    $providerFailureError.Exception.Message -notlike '*hostname evidence query failed with exit code 8*' -or
    $providerFailureError.Exception.Message -like '*guest initialization did not publish*') {
    throw 'A failed hostname provider read was misclassified as a successful empty first-boot answer.'
}
$addressCounter = Join-Path $OutputDirectory 'transient-address-count.txt'
[System.IO.File]::WriteAllText($addressCounter, '0', [System.Text.UTF8Encoding]::new($false))
$transientVmrun = Join-Path $OutputDirectory 'transient-address-vmrun.cmd'
[System.IO.File]::WriteAllText(
    $transientVmrun,
    "@echo off`r`nsetlocal EnableDelayedExpansion`r`nif /I `"%3`"==`"getGuestIPAddress`" (`r`n  set /p count=<`"$addressCounter`"`r`n  set /a count+=1`r`n  >`"$addressCounter`" echo !count!`r`n  if !count! LEQ 2 echo 192.168.167.135`r`n  exit /b 0`r`n)`r`nif /I `"%3`"==`"readVariable`" (`r`n  if /I `"%6`"==`"guestinfo.atlaso.test_vm_first_boot_stage`" echo failed-hostname`r`n  exit /b 0`r`n)`r`nif /I `"%3`"==`"list`" (`r`n  echo Total running VMs: 1`r`n  echo `"$targetVmx`"`r`n  exit /b 0`r`n)`r`nexit /b 9`r`n",
    [System.Text.UTF8Encoding]::new($false)
)
$transientError = $null
try {
    Set-Alias -Name Get-NetNeighbor -Value Get-TestNetNeighbor -Scope Global
    Set-Alias -Name Test-Connection -Value Test-TestConnection -Scope Global
    & (Join-Path $RepositoryRoot 'scripts/windows/vmware/get-atlaso-vm-ip.ps1') `
        -VmxPath $targetVmx `
        -ExpectedHostname 'issue-584.atlaso.internal' `
        -VmrunPath $transientVmrun `
        -TimeoutSeconds 3 `
        -PollSeconds 1 | Out-Null
}
catch {
    $transientError = $_
}
finally {
    Remove-Item Alias:Get-NetNeighbor -ErrorAction SilentlyContinue
    Remove-Item Alias:Test-Connection -ErrorAction SilentlyContinue
}
if ($null -eq $transientError -or
    $transientError.Exception.Message -notlike 'No uniquely bound IPv4 address*' -or
    $transientError.Exception.Message -like 'VMware address ownership was proven*') {
    throw 'A later loss of address evidence reused a stale ownership tuple for guest-initialization diagnostics.'
}
$unknownStageVmrun = Join-Path $OutputDirectory 'unknown-first-boot-stage-vmrun.cmd'
[System.IO.File]::WriteAllText(
    $unknownStageVmrun,
    (Get-Content -LiteralPath $stalledVmrun -Raw).Replace('failed-hostname', 'credential-shaped-value'),
    [System.Text.UTF8Encoding]::new($false)
)
$unknownStage = Get-AtlasoWorkstationFirstBootStage `
    -VmxPath $targetVmx `
    -VmrunPath $unknownStageVmrun `
    -Deadline (Get-Date).AddSeconds(2)
if ($unknownStage) {
    throw 'An unknown first-boot stage was accepted into readiness diagnostics.'
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

Assert-AtlasoWorkstationStableObservation `
    -InitialVmxPaths @($targetVmx, $sourceVmx) `
    -ConfirmedVmxPaths @($sourceVmx, $targetVmx) `
    -InitialTargetIPAddress '192.168.167.135' `
    -ConfirmedTargetIPAddress '192.168.167.135' `
    -InitialRunningGuests $uniqueGuests `
    -ConfirmedRunningGuests @($uniqueGuests[1], $uniqueGuests[0])
try {
    Assert-AtlasoWorkstationStableObservation `
        -InitialVmxPaths @($targetVmx, $sourceVmx) `
        -ConfirmedVmxPaths @($targetVmx, $sourceVmx, $concurrentVmx) `
        -InitialTargetIPAddress '192.168.167.135' `
        -ConfirmedTargetIPAddress '192.168.167.135'
    throw 'A concurrent running VM was accepted.'
} catch {
    if ($_.Exception.Message -eq 'A concurrent running VM was accepted.' -or
        $_.Exception.Message -notlike '*inventory or target address changed*') { throw }
}
$changedPeerGuests = @(
    [pscustomobject]@{ Path = $targetVmx; MacAddress = $targetMac; IPAddress = '192.168.167.135' },
    [pscustomobject]@{ Path = $sourceVmx; MacAddress = '00-0c-29-aa-bb-cc'; IPAddress = '192.168.167.135' }
)
try {
    Assert-AtlasoWorkstationStableObservation `
        -InitialVmxPaths @($targetVmx, $sourceVmx) `
        -ConfirmedVmxPaths @($targetVmx, $sourceVmx) `
        -InitialTargetIPAddress '192.168.167.135' `
        -ConfirmedTargetIPAddress '192.168.167.135' `
        -InitialRunningGuests $uniqueGuests `
        -ConfirmedRunningGuests $changedPeerGuests
    throw 'A peer address change was accepted.'
} catch {
    if ($_.Exception.Message -eq 'A peer address change was accepted.' -or
        $_.Exception.Message -notlike '*identity evidence changed*') { throw }
}
try {
    Assert-AtlasoWorkstationStableObservation `
        -InitialVmxPaths @($targetVmx, $sourceVmx) `
        -ConfirmedVmxPaths @($targetVmx, $sourceVmx) `
        -InitialTargetIPAddress '192.168.167.135' `
        -ConfirmedTargetIPAddress '192.168.167.136'
    throw 'A changing target address was accepted.'
} catch {
    if ($_.Exception.Message -eq 'A changing target address was accepted.' -or
        $_.Exception.Message -notlike '*inventory or target address changed*') { throw }
}

Write-Output 'Atlaso VMware Workstation readiness tests passed.'
