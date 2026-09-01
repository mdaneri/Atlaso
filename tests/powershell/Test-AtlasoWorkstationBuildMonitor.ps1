<#
.SYNOPSIS
Verify bounded VMware Workstation Packer startup monitoring.
.PARAMETER RepositoryRoot
Atlaso repository root.
.PARAMETER OutputDirectory
Isolated test-output directory.
#>
param(
    [Parameter(Mandatory = $true)][string]$RepositoryRoot,
    [Parameter(Mandatory = $true)][string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$cleanupModulePath = Join-Path $RepositoryRoot 'scripts/windows/vmware/Atlaso.WorkstationCleanup.psm1'
$modulePath = Join-Path $RepositoryRoot 'scripts/windows/vmware/Atlaso.WorkstationBuildMonitor.psm1'
Import-Module $cleanupModulePath -Force
Import-Module $modulePath -Force
if ($null -eq (Get-Command Remove-AtlasoWorkstationArtifactRoot -ErrorAction SilentlyContinue)) {
    throw 'Importing the build monitor removed the wrapper cleanup command from global scope.'
}
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

function New-TestBuilderState {
    <#
    .SYNOPSIS
    Create one safe simulated builder-state object.
    .PARAMETER VmxExists
    Whether the expected VMX exists.
    .PARAMETER IdentityMatches
    Whether the expected VMX identity is unchanged.
    .PARAMETER ProviderResponsive
    Whether vmrun returned a valid running inventory.
    .PARAMETER ExactRunning
    Whether the exact builder is running.
    .PARAMETER Tcp22Reachable
    Whether the configured builder address answers TCP/22.
    #>
    param(
        [bool]$VmxExists = $true,
        [bool]$IdentityMatches = $true,
        [bool]$ProviderResponsive = $true,
        [bool]$ExactRunning = $true,
        [bool]$Tcp22Reachable = $true
    )

    return [pscustomobject]@{
        VmxExists          = $VmxExists
        VmxIdentity        = 'test-identity'
        IdentityMatches    = $IdentityMatches
        ProviderResponsive = $ProviderResponsive
        ProviderError      = ''
        ExactRunning       = $ExactRunning
        Tcp22Reachable     = $Tcp22Reachable
    }
}

$diagnosticCases = @(
    @('powering_on', (New-TestBuilderState -VmxExists $false), 'vmx_missing'),
    @('powering_on', (New-TestBuilderState -IdentityMatches $false), 'vmx_replaced'),
    @('powering_on', (New-TestBuilderState -ProviderResponsive $false), 'provider_unavailable'),
    @('powering_on', (New-TestBuilderState -ExactRunning $false), 'vm_not_running'),
    @('powering_on', (New-TestBuilderState -Tcp22Reachable $false), 'ssh_port_closed'),
    @('powering_on', (New-TestBuilderState), 'start_handoff_stalled'),
    @('waiting_ssh', (New-TestBuilderState), 'ssh_authentication_pending'),
    @('provisioning', (New-TestBuilderState), 'provisioning')
)
foreach ($case in $diagnosticCases) {
    $actual = Get-AtlasoWorkstationStartupDiagnostic -PackerPhase $case[0] -State $case[1]
    if ($actual.Code -cne $case[2]) {
        throw "Expected diagnostic '$($case[2])'; got '$($actual.Code)'."
    }
}

$secret = 'generated-vnc-test-secret'
$safeLine = ConvertTo-AtlasoSanitizedPackerLine -Line "==> builder: Password: `"$secret`""
if ($safeLine.Contains($secret) -or -not $safeLine.Contains('[redacted]')) {
    throw 'Packer connection credential output was not redacted.'
}

$fakePacker = Join-Path $OutputDirectory 'fake-packer.ps1'
$effectiveCleanupArguments = ConvertTo-AtlasoMonitoredPackerArguments `
    -Arguments @('build', '-force', '-on-error=cleanup', 'template.pkr.hcl') `
    -PackerOnError cleanup
if (($effectiveCleanupArguments -join '|') -cne 'build|-force|-on-error=abort|template.pkr.hcl') {
    throw 'Logical cleanup did not preserve the failed VMX for checked provider cleanup.'
}
$effectiveAbortArguments = ConvertTo-AtlasoMonitoredPackerArguments `
    -Arguments @('build', '-on-error=abort', 'template.pkr.hcl') `
    -PackerOnError abort
if (($effectiveAbortArguments -join '|') -cne 'build|-on-error=abort|template.pkr.hcl') {
    throw 'An explicit non-cleanup Packer selection was changed.'
}

$fakeScript = @'
param([ValidateSet('prepower-stall', 'stall', 'success', 'failure', 'burst')][string]$Mode)
Write-Output '==> builder: Password: "generated-vnc-test-secret"'
if ($Mode -eq 'prepower-stall') {
    Start-Sleep -Seconds 30
    exit 0
}
Write-Output '==> builder: Powering on virtual machine...'
if ($Mode -eq 'stall') {
    Start-Sleep -Seconds 30
    exit 0
}
if ($Mode -eq 'failure') {
    exit 9
}
if ($Mode -eq 'burst') {
    foreach ($lineNumber in 1..2000) {
        Write-Output ("==> builder: burst-output-{0:D4}-{1}" -f $lineNumber, ('x' * 96))
    }
    Write-Output '==> builder: Provisioning with shell script: burst-complete'
    exit 0
}
Write-Output '==> builder: Connecting to VNC...'
Write-Output '==> builder: Using SSH communicator to connect: 192.0.2.30'
Write-Output '==> builder: Waiting for SSH to become available...'
Write-Output '==> builder: Connected to SSH!'
Write-Output '==> builder: Provisioning with shell script: safe-test-script'
exit 0
'@
[System.IO.File]::WriteAllText($fakePacker, $fakeScript, [System.Text.UTF8Encoding]::new($false))
$pwshPath = (Get-Process -Id $PID).Path
$probe = {
    param($Phase, $Identity)
    return New-TestBuilderState
}
$timeoutRecord = Join-Path $OutputDirectory 'timeout.txt'
$timeoutHandler = {
    param($SelectedOnError, $State, $Diagnostic)
    [System.IO.File]::WriteAllText(
        $timeoutRecord,
        "$SelectedOnError|$($Diagnostic.Code)",
        [System.Text.UTF8Encoding]::new($false)
    )
}.GetNewClosure()

$prePowerRecord = Join-Path $OutputDirectory 'prepower-timeout.txt'
$prePowerHandler = {
    param($SelectedOnError, $State, $Diagnostic)
    [System.IO.File]::WriteAllText(
        $prePowerRecord,
        "$SelectedOnError|$($Diagnostic.Code)",
        [System.Text.UTF8Encoding]::new($false)
    )
}.GetNewClosure()
$prePowerProbe = {
    param($Phase, $Identity)
    return New-TestBuilderState -VmxExists $false -IdentityMatches $false -ExactRunning $false -Tcp22Reachable $false
}
$prePowerError = $null
try {
    Invoke-AtlasoMonitoredPackerBuild `
        -PackerPath $pwshPath `
        -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $fakePacker, '-Mode', 'prepower-stall') `
        -WorkingDirectory $OutputDirectory `
        -VmrunPath $pwshPath `
        -VmxPath (Join-Path $OutputDirectory 'not-created.vmx') `
        -BuilderAddress '192.0.2.30' `
        -StartupTimeoutSeconds 2 `
        -HeartbeatSeconds 1 `
        -PackerOnError cleanup `
        -TimeoutHandler $prePowerHandler `
        -StateProbe $prePowerProbe
}
catch {
    $prePowerError = $_
}
if ($null -eq $prePowerError -or $prePowerError.Exception.Message -notmatch 'vmx_missing') {
    throw 'A pre-power-on Packer stall did not fail with the expected bounded diagnosis.'
}
if ((Get-Content -LiteralPath $prePowerRecord -Raw) -cne 'cleanup|vmx_missing') {
    throw 'A pre-power-on Packer stall did not invoke checked failure handling.'
}

$stallLines = [System.Collections.Generic.List[string]]::new()
$stallError = $null
try {
    & {
        Invoke-AtlasoMonitoredPackerBuild `
            -PackerPath $pwshPath `
            -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $fakePacker, '-Mode', 'stall') `
            -WorkingDirectory $OutputDirectory `
            -VmrunPath $pwshPath `
            -VmxPath (Join-Path $OutputDirectory 'builder.vmx') `
            -BuilderAddress '192.0.2.30' `
            -StartupTimeoutSeconds 2 `
            -HeartbeatSeconds 1 `
            -PackerOnError cleanup `
            -TimeoutHandler $timeoutHandler `
            -StateProbe $probe
    } *>&1 | ForEach-Object { $stallLines.Add($_.ToString()) }
}
catch {
    $stallError = $_
}
$stallOutput = $stallLines -join "`n"
if ($null -eq $stallError -or $stallError.Exception.Message -notmatch 'start_handoff_stalled') {
    throw 'A live-VM/TCP Packer stall did not fail with the expected bounded diagnosis.'
}
if ($stallOutput.Contains($secret)) {
    throw 'Monitored Packer output exposed a generated connection credential.'
}
if (-not $stallOutput.Contains('[redacted]')) {
    throw 'Monitored Packer output did not retain the redaction marker.'
}
if (-not $stallOutput.Contains('Packer startup heartbeat [start_handoff_stalled]')) {
    throw 'The monitored stall did not emit its bounded safe heartbeat.'
}
if ((Get-Content -LiteralPath $timeoutRecord -Raw) -cne 'cleanup|start_handoff_stalled') {
    throw 'The monitored timeout did not preserve the selected cleanup mode and exact diagnosis.'
}

$builderVmx = Join-Path $OutputDirectory 'builder.vmx'
[System.IO.File]::WriteAllText($builderVmx, 'safe test vmx', [System.Text.UTF8Encoding]::new($false))
$rewrittenProbe = {
    param($Phase, $Identity)
    $state = New-TestBuilderState
    $state.VmxIdentity = 'provider-confirmed-rewrite'
    $state.IdentityMatches = $false
    return $state
}
$rewriteLines = [System.Collections.Generic.List[string]]::new()
$rewriteError = $null
try {
    & {
        Invoke-AtlasoMonitoredPackerBuild `
            -PackerPath $pwshPath `
            -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $fakePacker, '-Mode', 'stall') `
            -WorkingDirectory $OutputDirectory `
            -VmrunPath $pwshPath `
            -VmxPath $builderVmx `
            -BuilderAddress '192.0.2.30' `
            -StartupTimeoutSeconds 2 `
            -HeartbeatSeconds 1 `
            -PackerOnError cleanup `
            -TimeoutHandler $timeoutHandler `
            -StateProbe $rewrittenProbe
    } *>&1 | ForEach-Object { $rewriteLines.Add($_.ToString()) }
}
catch {
    $rewriteError = $_
}
$rewriteOutput = $rewriteLines -join "`n"
if ($null -eq $rewriteError -or $rewriteError.Exception.Message -notmatch 'start_handoff_stalled') {
    throw 'A provider-confirmed Workstation VMX rewrite did not retain the truthful start-handoff diagnosis.'
}
if (-not $rewriteOutput.Contains('identity refresh [vmx_rewritten]') -or
    $rewriteOutput.Contains('heartbeat [vmx_replaced]')) {
    throw 'A provider-confirmed Workstation VMX rewrite was reported as stale replacement.'
}

$interruptionRecord = Join-Path $OutputDirectory 'interruption.txt'
$interruptionHandler = {
    param($SelectedOnError, $State, $Diagnostic)
    [System.IO.File]::WriteAllText(
        $interruptionRecord,
        "$SelectedOnError|$($Diagnostic.Code)",
        [System.Text.UTF8Encoding]::new($false)
    )
}.GetNewClosure()
$failedProbe = {
    param($Phase, $Identity)
    throw 'simulated safe state-probe failure'
}
$interruptionError = $null
try {
    Invoke-AtlasoMonitoredPackerBuild `
        -PackerPath $pwshPath `
        -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $fakePacker, '-Mode', 'stall') `
        -WorkingDirectory $OutputDirectory `
        -VmrunPath $pwshPath `
        -VmxPath (Join-Path $OutputDirectory 'builder.vmx') `
        -BuilderAddress '192.0.2.30' `
        -StartupTimeoutSeconds 3 `
        -HeartbeatSeconds 1 `
        -PackerOnError abort `
        -TimeoutHandler $interruptionHandler `
        -StateProbe $failedProbe
}
catch {
    $interruptionError = $_
}
if ($null -eq $interruptionError -or $interruptionError.Exception.Message -notmatch 'state-probe failure') {
    throw 'An internal monitor failure did not preserve its original diagnostic.'
}
if ((Get-Content -LiteralPath $interruptionRecord -Raw) -cne 'abort|monitor_interrupted') {
    throw 'An interrupted monitor did not invoke the selected checked failure behavior.'
}

$successOutput = (& {
    Invoke-AtlasoMonitoredPackerBuild `
        -PackerPath $pwshPath `
        -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $fakePacker, '-Mode', 'success') `
        -WorkingDirectory $OutputDirectory `
        -VmrunPath $pwshPath `
        -VmxPath (Join-Path $OutputDirectory 'builder.vmx') `
        -BuilderAddress '192.0.2.30' `
        -StartupTimeoutSeconds 2 `
        -HeartbeatSeconds 1 `
        -StateProbe $probe
} *>&1 | Out-String)
if ($successOutput.Contains($secret) -or -not $successOutput.Contains('Provisioning with shell script')) {
    throw 'Successful monitored Packer progress was not sanitized or did not reach provisioning.'
}

$burstOutput = (& {
    Invoke-AtlasoMonitoredPackerBuild `
        -PackerPath $pwshPath `
        -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $fakePacker, '-Mode', 'burst') `
        -WorkingDirectory $OutputDirectory `
        -VmrunPath $pwshPath `
        -VmxPath (Join-Path $OutputDirectory 'builder.vmx') `
        -BuilderAddress '192.0.2.30' `
        -StartupTimeoutSeconds 2 `
        -HeartbeatSeconds 1 `
        -StateProbe $probe
} *>&1 | Out-String)
if (-not $burstOutput.Contains('burst-output-2000') -or
    -not $burstOutput.Contains('Provisioning with shell script: burst-complete')) {
    throw 'Verbose monitored Packer output was throttled or did not drain completely.'
}

$failureRecord = Join-Path $OutputDirectory 'failure.txt'
$failureHandler = {
    param($SelectedOnError, $State, $Diagnostic)
    [System.IO.File]::WriteAllText(
        $failureRecord,
        "$SelectedOnError|$($Diagnostic.Code)",
        [System.Text.UTF8Encoding]::new($false)
    )
}.GetNewClosure()
$failureError = $null
try {
    Invoke-AtlasoMonitoredPackerBuild `
        -PackerPath $pwshPath `
        -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $fakePacker, '-Mode', 'failure') `
        -WorkingDirectory $OutputDirectory `
        -VmrunPath $pwshPath `
        -VmxPath (Join-Path $OutputDirectory 'builder.vmx') `
        -BuilderAddress '192.0.2.30' `
        -StartupTimeoutSeconds 2 `
        -HeartbeatSeconds 1 `
        -PackerOnError cleanup `
        -TimeoutHandler $failureHandler `
        -StateProbe $probe
}
catch {
    $failureError = $_
}
if ($null -eq $failureError -or $failureError.Exception.Message -notmatch 'exit code 9') {
    throw 'A real Packer process failure was not propagated before the startup timeout.'
}
if ((Get-Content -LiteralPath $failureRecord -Raw) -cne 'cleanup|packer_failed') {
    throw 'A real Packer process failure did not invoke checked failure handling.'
}

Write-Output 'Atlaso VMware Workstation build monitor tests passed.'
