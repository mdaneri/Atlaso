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
$readinessScript = Join-Path $RepositoryRoot 'scripts/windows/vmware/get-atlaso-vm-ip.ps1'
# Invalid timing must fail during binding, before path or provider access.
foreach ($invalidTiming in @(
        @{ TimeoutSeconds = 0 }, @{ TimeoutSeconds = -1 },
        @{ TimeoutSeconds = 2147484 }, @{ PollSeconds = 0 }, @{ PollSeconds = -1 }
    )) {
    $bindingError = $null
    try {
        & $readinessScript -VmxPath 'does-not-exist.vmx' -ExpectedHostname 'fixture.invalid' @invalidTiming
    }
    catch { $bindingError = $_ }
    if ($null -eq $bindingError -or $bindingError.FullyQualifiedErrorId -notlike 'ParameterArgumentValidationError*') {
        throw 'Invalid readiness timing did not fail parameter validation before filesystem access.'
    }
}
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
$failingVmrun = Join-Path $OutputDirectory 'fast-failing-vmrun.cmd'
[System.IO.File]::WriteAllText($failingVmrun, "@echo off`r`nexit /b 1`r`n")
foreach ($pollInterval in @(5, [int]::MaxValue)) {
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    $timeoutError = $null
    try {
        & $readinessScript -VmxPath $targetVmx -ExpectedHostname 'fixture.invalid' `
            -VmrunPath $failingVmrun -TimeoutSeconds 1 -PollSeconds $pollInterval | Out-Null
    }
    catch { $timeoutError = $_ }
    $timer.Stop()
    if ($null -eq $timeoutError -or $timeoutError.Exception.Message -notlike 'No uniquely bound IPv4 address*within 1 seconds*') {
        throw 'The fast-failing fixture did not reach the expected readiness timeout.'
    }
    # Allow scheduler/module-loading overhead but reject the old full five-second sleep.
    if ($timer.Elapsed.TotalSeconds -lt 0.9 -or $timer.Elapsed.TotalSeconds -ge 2.5) {
        throw "Readiness deadline was not bounded: $($timer.Elapsed.TotalSeconds) seconds, poll $pollInterval."
    }
    Write-Output "Bounded readiness: timeout 1s, poll $pollInterval s, elapsed $($timer.Elapsed.TotalSeconds.ToString('F3'))s."
}
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

<#
.SYNOPSIS
Return synthetic Windows neighbor evidence for the readiness scenarios.
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
Populate synthetic neighbor state for the readiness scenarios.
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

<#
.SYNOPSIS
Run the production readiness script against scripted provider responses and a controlled poll clock.
.PARAMETER Responses
Ordered provider operations with optional stdout, exit code, or a real stalled-child marker.
#>
function Invoke-TestReadinessScenario {
    param([Parameter(Mandatory = $true)][hashtable[]]$Responses)

    $clock = @{ Now = [datetime]'2026-01-01T00:00:00'; Deadline = [datetime]'2026-01-01T00:00:02' }
    $provider = @{ Next = 0; Failure = ''; StalledCalls = 0 }
    $expectedStalls = @($Responses | Where-Object { $_.Stall }).Count
    try {
        # Aliases also intercept calls inside the re-imported production module.
        # Use the module-qualified function to exercise the actual child timeout where requested.
        Set-Item Function:global:Get-TestReadinessDate -Value {
            <#
            .SYNOPSIS
            Return the scenario's current time.
            #>
            $clock.Now
        }.GetNewClosure()
        Set-Item Function:global:Wait-TestReadinessPoll -Value {
            <#
            .SYNOPSIS
            Advance the scenario clock by the actual requested poll duration.
            .PARAMETER Milliseconds
            Requested poll duration.
            #>
            param([int]$Milliseconds)
            $clock.Now = $clock.Now.AddMilliseconds($Milliseconds)
        }.GetNewClosure()
        Set-Item Function:global:Invoke-TestReadinessVmrun -Value {
            <#
            .SYNOPSIS
            Verify provider order and deadline, then supply the next response.
            .PARAMETER VmrunPath
            Fixture executable, used for a deliberately stalled child.
            .PARAMETER Arguments
            Actual provider argument list.
            .PARAMETER Deadline
            Absolute readiness deadline supplied by the call.
            #>
            param([string]$VmrunPath, [string[]]$Arguments, [datetime]$Deadline)

            if ($Deadline -ne $clock.Deadline) {
                $provider.Failure = "Expected the shared readiness deadline, received '$Deadline'."
                throw $provider.Failure
            }
            if ($clock.Now -ge $Deadline) {
                return Atlaso.WorkstationReadiness\Invoke-AtlasoWorkstationVmrunBounded @PSBoundParameters
            }
            $operation = $Arguments[2]
            if ($operation -eq 'readVariable') { $operation = $Arguments[5] }
            $response = $Responses[$provider.Next]
            if ($null -eq $response -or $operation -cne $response.Operation) {
                $provider.Failure = "Unexpected provider operation '$operation' at position $($provider.Next + 1)."
                throw $provider.Failure
            }
            $provider.Next++
            if ($response.Stall) {
                # Earlier observations have consumed part of the shared budget.
                $clock.Now = $Deadline.AddMilliseconds(-250)
                $result = Atlaso.WorkstationReadiness\Invoke-AtlasoWorkstationVmrunBounded @PSBoundParameters
                if (-not $result.TimedOut) {
                    $provider.Failure = "The real stalled child for '$operation' did not time out."
                    throw $provider.Failure
                }
                $provider.StalledCalls++
                $clock.Now = $Deadline
                return $result
            }
            return [pscustomobject]@{
                ExitCode = [int]$response.ExitCode
                TimedOut = $false
                StdOut   = [string]$response.StdOut
                StdErr   = ''
            }
        }.GetNewClosure()
        Set-Alias -Name Get-Date -Value Get-TestReadinessDate -Scope Global
        Set-Alias -Name Start-Sleep -Value Wait-TestReadinessPoll -Scope Global
        Set-Alias -Name Invoke-AtlasoWorkstationVmrunBounded -Value Invoke-TestReadinessVmrun -Scope Global
        Set-Alias -Name Get-NetNeighbor -Value Get-TestNetNeighbor -Scope Global
        Set-Alias -Name Test-Connection -Value Test-TestConnection -Scope Global
        $diagnostic = '<no error>'
        try {
            & $readinessScript -VmxPath $targetVmx -ExpectedHostname 'issue-584.atlaso.internal' `
                -VmrunPath $slowVmrun -TimeoutSeconds 2 -PollSeconds 1 | Out-Null
        }
        catch {
            $diagnostic = $_.Exception.Message
        }
        if ($provider.Failure -or $provider.Next -ne $Responses.Count -or
            $provider.StalledCalls -ne $expectedStalls) {
            throw "Readiness provider sequence failed ($($provider.Next)/$($Responses.Count) operations). $($provider.Failure) Diagnostic: $diagnostic"
        }
        return $diagnostic
    }
    finally {
        Remove-Item Alias:Get-Date, Alias:Start-Sleep, Alias:Invoke-AtlasoWorkstationVmrunBounded,
            Alias:Get-NetNeighbor, Alias:Test-Connection -ErrorAction SilentlyContinue
        Remove-Item Function:Get-TestReadinessDate, Function:Wait-TestReadinessPoll,
            Function:Invoke-TestReadinessVmrun -ErrorAction SilentlyContinue
    }
}

$ip = @{ Operation = 'getGuestIPAddress'; StdOut = '192.168.167.135' }
$missingIp = @{ Operation = 'getGuestIPAddress' }
$inventory = @{ Operation = 'list'; StdOut = "Total running VMs: 1`n`"$targetVmx`"" }
$hostnameKey = 'guestinfo.atlaso.test_vm_hostname'
$stageKey = 'guestinfo.atlaso.test_vm_first_boot_stage'
$hostname = @{ Operation = $hostnameKey; StdOut = 'issue-584.atlaso.internal' }
$emptyHostname = @{ Operation = $hostnameKey }
$hostnameFailure = @{ Operation = $hostnameKey; ExitCode = 8 }
$stage = @{ Operation = $stageKey; StdOut = 'failed-hostname' }
$unknownStage = @{ Operation = $stageKey; StdOut = 'credential-shaped-value' }
$hostnameStall = @{ Operation = $hostnameKey; Stall = $true }
$stageStall = @{ Operation = $stageKey; Stall = $true }

$hostnameTimeoutMessage = Invoke-TestReadinessScenario -Responses @($ip, $hostname, $inventory, $hostnameStall)
if ($hostnameTimeoutMessage -notlike '*hostname confirmation exceeded*' -or
    $hostnameTimeoutMessage -notlike '*Earlier observed hostname: ''issue-584.atlaso.internal''*' -or
    $hostnameTimeoutMessage -notlike '*Readiness was not returned*' -or
    $hostnameTimeoutMessage -like '*guest initialization did not publish*') {
    throw "A timed-out hostname confirmation returned readiness or discarded the earlier observation. Diagnostic: $hostnameTimeoutMessage"
}

$stalledObservation = @($ip, $emptyHostname, $inventory, $emptyHostname, $stage, $inventory, $ip)
$stalledMessage = Invoke-TestReadinessScenario -Responses ($stalledObservation + $stalledObservation)
if ($stalledMessage -notlike 'VMware address ownership was proven*' -or
    $stalledMessage -notlike '*Last allowlisted first-boot stage: ''failed-hostname''*' -or
    $stalledMessage -notlike '*Observed hostname: ''<not reported>''*' -or
    $stalledMessage -like 'No uniquely bound IPv4 address*') {
    throw "A guest-initialization stall after stable address ownership did not report the sanitized first-boot layer. Diagnostic: $stalledMessage"
}

$stageTimeoutMessage = Invoke-TestReadinessScenario -Responses @($ip, $emptyHostname, $inventory, $emptyHostname, $stageStall)
if ($stageTimeoutMessage -notlike 'No uniquely bound IPv4 address*' -or
    $stageTimeoutMessage -like 'VMware address ownership was proven*' -or
    $stageTimeoutMessage -like '*guest initialization did not publish*') {
    throw "A timed-out first-boot-stage read reused stale ownership for an initialization diagnosis. Diagnostic: $stageTimeoutMessage"
}

$failedObservation = @($ip, $hostnameFailure, $inventory, $hostnameFailure)
$providerFailureMessage = Invoke-TestReadinessScenario -Responses ($failedObservation + $failedObservation)
if ($providerFailureMessage -notlike 'An initial VMware ownership observation completed*' -or
    $providerFailureMessage -notlike '*hostname evidence query failed with exit code 8*' -or
    $providerFailureMessage -like '*guest initialization did not publish*') {
    throw "Expected a hostname provider failure with exit code 8 after initial ownership. Diagnostic: $providerFailureMessage"
}

$transientMessage = Invoke-TestReadinessScenario -Responses ($stalledObservation + $missingIp)
if ($transientMessage -notlike 'No uniquely bound IPv4 address*' -or
    $transientMessage -like 'VMware address ownership was proven*') {
    throw "A later loss of address evidence reused a stale ownership tuple. Diagnostic: $transientMessage"
}

$unknownStageObservation = @($ip, $emptyHostname, $inventory, $emptyHostname, $unknownStage, $inventory, $ip)
$unknownStageMessage = Invoke-TestReadinessScenario -Responses ($unknownStageObservation + $unknownStageObservation)
if ($unknownStageMessage -notlike '*No allowlisted first-boot stage was reported.*' -or
    $unknownStageMessage -like '*credential-shaped-value*') {
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
