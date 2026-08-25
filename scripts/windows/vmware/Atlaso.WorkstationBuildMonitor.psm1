<#
.SYNOPSIS
Monitor Atlaso VMware Workstation Packer startup without exposing build credentials.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Reuse an already imported cleanup module so this nested module does not evict
# the wrapper's global cleanup commands while loading shared file-identity support.
Import-Module (Join-Path $PSScriptRoot 'Atlaso.WorkstationCleanup.psm1')

<#
.SYNOPSIS
Return the stable filesystem identity for a newly created builder VMX.
.PARAMETER Path
Existing VMX path to identify.
#>
function Get-AtlasoWorkstationBuilderIdentity {
    param([Parameter(Mandatory = $true)][string]$Path)

    $identityType = 'Atlaso.WorkstationFileIdentity' -as [type]
    if ($null -eq $identityType) {
        throw 'VMware Workstation file-identity support is unavailable.'
    }
    try {
        return $identityType::Get($Path)
    }
    catch {
        throw "Builder VMX filesystem identity cannot be resolved: $Path"
    }
}

<#
.SYNOPSIS
Run a bounded, non-secret VMware provider command.
.PARAMETER FilePath
Resolved vmrun executable path.
.PARAMETER Arguments
Credential-free vmrun arguments.
.PARAMETER TimeoutSeconds
Maximum command runtime.
#>
function Invoke-AtlasoWorkstationProbeCommand {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [ValidateRange(1, 30)][int]$TimeoutSeconds = 5
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in $Arguments) {
        $startInfo.ArgumentList.Add($argument)
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            throw 'The VMware provider probe did not start.'
        }
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $process.Kill($true)
            $process.WaitForExit()
            throw "VMware provider probe timed out after $TimeoutSeconds seconds."
        }
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            Stdout   = $stdout
            Stderr   = $stderr
        }
    }
    finally {
        $process.Dispose()
    }
}

<#
.SYNOPSIS
Test one TCP endpoint with a bounded asynchronous connection.
.PARAMETER Address
Builder IP address.
.PARAMETER Port
Builder TCP port.
.PARAMETER TimeoutMilliseconds
Maximum connection wait.
#>
function Test-AtlasoBuilderTcpPort {
    param(
        [Parameter(Mandatory = $true)][string]$Address,
        [ValidateRange(1, 65535)][int]$Port = 22,
        [ValidateRange(100, 5000)][int]$TimeoutMilliseconds = 1000
    )

    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $connectTask = $client.ConnectAsync($Address, $Port)
        return $connectTask.Wait($TimeoutMilliseconds) -and $client.Connected
    }
    catch {
        return $false
    }
    finally {
        $client.Dispose()
    }
}

<#
.SYNOPSIS
Return safe live state for one exact Packer builder VMX.
.PARAMETER VmrunPath
Resolved vmrun executable path.
.PARAMETER VmxPath
Expected builder VMX path.
.PARAMETER ExpectedVmxIdentity
Previously captured stable VMX identity.
.PARAMETER BuilderAddress
Configured builder IP address.
#>
function Get-AtlasoWorkstationBuilderState {
    param(
        [Parameter(Mandatory = $true)][string]$VmrunPath,
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [AllowEmptyString()][string]$ExpectedVmxIdentity,
        [Parameter(Mandatory = $true)][string]$BuilderAddress
    )

    $vmxItem = Get-Item -LiteralPath $VmxPath -Force -ErrorAction SilentlyContinue
    $currentIdentity = ''
    $identityMatches = $false
    if ($null -ne $vmxItem) {
        $currentIdentity = Get-AtlasoWorkstationBuilderIdentity -Path $vmxItem.FullName
        $identityMatches = [string]::IsNullOrWhiteSpace($ExpectedVmxIdentity) -or
            $currentIdentity -ceq $ExpectedVmxIdentity
    }

    $providerResponsive = $false
    $exactRunning = $false
    $providerError = ''
    try {
        $listResult = Invoke-AtlasoWorkstationProbeCommand `
            -FilePath $VmrunPath `
            -Arguments @('-T', 'ws', 'list')
        if ($listResult.ExitCode -eq 0) {
            $providerResponsive = $true
            $runningPaths = @(
                $listResult.Stdout -split "`r?`n" |
                    Select-Object -Skip 1 |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            )
            $exactRunning = @(
                $runningPaths | Where-Object {
                    $_.Trim().Equals($VmxPath, [System.StringComparison]::OrdinalIgnoreCase)
                }
            ).Count -eq 1
        }
        else {
            $providerError = "vmrun list exited $($listResult.ExitCode)"
        }
    }
    catch {
        $providerError = $_.Exception.Message
    }

    return [pscustomobject]@{
        VmxExists         = $null -ne $vmxItem
        VmxIdentity       = $currentIdentity
        IdentityMatches   = $identityMatches
        ProviderResponsive = $providerResponsive
        ProviderError     = $providerError
        ExactRunning      = $exactRunning
        Tcp22Reachable    = Test-AtlasoBuilderTcpPort -Address $BuilderAddress -Port 22
    }
}

<#
.SYNOPSIS
Describe one builder startup phase without credentials or VMX contents.
.PARAMETER PackerPhase
Latest safe Packer phase inferred from output.
.PARAMETER State
Safe exact-VM live state.
#>
function Get-AtlasoWorkstationStartupDiagnostic {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('preparing', 'powering_on', 'booting', 'waiting_ssh', 'provisioning')]
        [string]$PackerPhase,
        [Parameter(Mandatory = $true)][psobject]$State
    )

    if (-not $State.VmxExists) {
        return [pscustomobject]@{
            Code    = 'vmx_missing'
            Message = 'Packer has not created the expected builder VMX.'
        }
    }
    if (-not $State.IdentityMatches) {
        return [pscustomobject]@{
            Code    = 'vmx_replaced'
            Message = 'The builder VMX identity changed during startup; stale or replaced output cannot satisfy readiness.'
        }
    }
    if (-not $State.ProviderResponsive) {
        return [pscustomobject]@{
            Code    = 'provider_unavailable'
            Message = 'VMware Workstation provider state is unavailable; inspect the sanitized provider diagnostic.'
        }
    }
    if (-not $State.ExactRunning) {
        return [pscustomobject]@{
            Code    = 'vm_not_running'
            Message = 'The exact builder VM is not reported running; the Workstation start transition has not completed.'
        }
    }
    if (-not $State.Tcp22Reachable) {
        $message = if ($PackerPhase -eq 'waiting_ssh') {
            'Packer configured the SSH communicator, but the exact builder is still installing or TCP/22 is closed.'
        }
        else {
            'The exact builder VM is running; the unattended installer, reboot, or TCP/22 readiness is still pending.'
        }
        return [pscustomobject]@{
            Code    = 'ssh_port_closed'
            Message = $message
        }
    }
    if ($PackerPhase -in @('preparing', 'powering_on')) {
        return [pscustomobject]@{
            Code    = 'start_handoff_stalled'
            Message = 'The exact builder VM and TCP/22 are live, but Packer has not completed the Workstation start-to-communicator handoff.'
        }
    }
    if ($PackerPhase -eq 'waiting_ssh') {
        return [pscustomobject]@{
            Code    = 'ssh_authentication_pending'
            Message = 'The exact builder VM and TCP/22 are live; Packer is waiting for the SSH handshake or authentication.'
        }
    }
    return [pscustomobject]@{
        Code    = 'provisioning'
        Message = 'Packer reached SSH provisioning for the exact builder VM.'
    }
}

<#
.SYNOPSIS
Redact secret-bearing Packer output while preserving actionable phase text.
.PARAMETER Line
One Packer stdout or stderr line.
#>
function ConvertTo-AtlasoSanitizedPackerLine {
    param([AllowEmptyString()][string]$Line)

    if ($Line -match '(?i)Password:\s*\S') {
        return ($Line -replace '(?i)(Password:\s*).+$', '$1[redacted]')
    }
    if ($Line -match '(?i)(ssh_password|bootstrap_admin_password|PACKER_GITHUB_API_TOKEN)\s*[=:]') {
        return ($Line -replace '(?i)((?:ssh_password|bootstrap_admin_password|PACKER_GITHUB_API_TOKEN)\s*[=:]\s*).+$', '$1[redacted]')
    }
    return $Line
}

<#
.SYNOPSIS
Infer the monitored Packer startup phase from one sanitized output line.
.PARAMETER CurrentPhase
Current phase before the line is evaluated.
.PARAMETER Line
Sanitized Packer output line.
#>
function Get-AtlasoPackerPhaseFromLine {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('preparing', 'powering_on', 'booting', 'waiting_ssh', 'provisioning')]
        [string]$CurrentPhase,
        [AllowEmptyString()][string]$Line
    )

    if ($Line -match 'Connected to SSH|Provisioning with') {
        return 'provisioning'
    }
    if ($Line -match 'Using SSH communicator|Waiting for SSH to become available') {
        return 'waiting_ssh'
    }
    if ($Line -match 'Connecting to VNC|Waiting \d+s for boot|Typing the boot command') {
        return 'booting'
    }
    if ($Line -match 'Powering on virtual machine') {
        return 'powering_on'
    }
    return $CurrentPhase
}

<#
.SYNOPSIS
Start or verify a detached VMware Workstation UI before Packer requests GUI mode.
.PARAMETER VmrunPath
Resolved vmrun executable used to locate the matching Workstation UI.
.PARAMETER TimeoutSeconds
Maximum UI readiness wait.
#>
function Initialize-AtlasoWorkstationGui {
    param(
        [Parameter(Mandatory = $true)][string]$VmrunPath,
        [ValidateRange(5, 60)][int]$TimeoutSeconds = 20
    )

    $vmwarePath = Join-Path (Split-Path -Parent $VmrunPath) 'vmware.exe'
    $resolvedVmwarePath = (Resolve-Path -LiteralPath $vmwarePath -ErrorAction Stop).Path
    $existing = @(
        Get-Process -Name 'vmware' -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Path -and $_.Path.Equals($resolvedVmwarePath, [System.StringComparison]::OrdinalIgnoreCase)
            }
    )
    foreach ($process in $existing) {
        if ($process.Responding) {
            Write-Host "VMware Workstation UI is ready for the detached GUI builder start (PID $($process.Id))."
            return $process.Id
        }
    }
    if ($existing.Count -gt 0) {
        throw 'The installed VMware Workstation UI is running but not responsive. Close or recover it, then retry.'
    }

    # The visible console is the documented default. Starting it through a separate
    # process detaches Workstation from the stdout/stderr handles Packer gives vmrun.
    $process = Start-Process -FilePath $resolvedVmwarePath -PassThru
    $ready = $false
    try {
        $ready = $process.WaitForInputIdle($TimeoutSeconds * 1000)
    }
    catch {
        $ready = $false
    }
    $liveProcess = Get-Process -Id $process.Id -ErrorAction SilentlyContinue
    if (-not $ready -or $null -eq $liveProcess -or -not $liveProcess.Responding) {
        if ($null -ne $liveProcess) {
            $liveProcess.Kill()
        }
        throw "VMware Workstation UI did not become responsive within $TimeoutSeconds seconds."
    }
    Write-Host "VMware Workstation UI is ready for the detached GUI builder start (PID $($process.Id))."
    return $process.Id
}

<#
.SYNOPSIS
Run Packer with bounded VMware startup diagnostics and sanitized live output.
.PARAMETER PackerPath
Resolved Packer executable path.
.PARAMETER Arguments
Packer build arguments.
.PARAMETER WorkingDirectory
Packer template working directory.
.PARAMETER VmrunPath
Resolved VMware vmrun executable.
.PARAMETER VmxPath
Expected builder VMX path.
.PARAMETER BuilderAddress
Configured Packer SSH endpoint address.
.PARAMETER StartupTimeoutSeconds
Maximum interval from monitored Packer process start to SSH provisioning.
.PARAMETER HeartbeatSeconds
Interval for safe startup phase heartbeats.
.PARAMETER PackerOnError
Selected Packer failure behavior.
.PARAMETER TimeoutHandler
Provider cleanup or preservation callback invoked after a monitored timeout.
.PARAMETER StateProbe
Optional focused-test replacement for live VMware state collection.
#>
function Invoke-AtlasoMonitoredPackerBuild {
    param(
        [Parameter(Mandatory = $true)][string]$PackerPath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$VmrunPath,
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $true)][string]$BuilderAddress,
        [ValidateRange(2, 3600)][int]$StartupTimeoutSeconds = 900,
        [ValidateRange(1, 300)][int]$HeartbeatSeconds = 30,
        [ValidateSet('cleanup', 'abort', 'ask', 'run-cleanup-provisioner')]
        [string]$PackerOnError = 'cleanup',
        [scriptblock]$TimeoutHandler,
        [scriptblock]$StateProbe
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $PackerPath
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in $Arguments) {
        $startInfo.ArgumentList.Add($argument)
    }
    # Raw Packer debug logs are outside the wrapper's redaction boundary.
    $null = $startInfo.Environment.Remove('PACKER_LOG')
    $null = $startInfo.Environment.Remove('PACKER_LOG_PATH')

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $phase = 'preparing'
    $startupStarted = $null
    $nextHeartbeat = [System.DateTimeOffset]::UtcNow.AddSeconds($HeartbeatSeconds)
    $vmxIdentity = ''
    $lastState = $null
    $timedOut = $false
    $processStarted = $false
    $handlerInvoked = $false
    $pendingLines = [System.Collections.Generic.Queue[string]]::new()
    $stdoutTask = $null
    $stderrTask = $null

    try {
        $processStarted = $process.Start()
        if (-not $processStarted) {
            throw 'Packer build process did not start.'
        }
        $startupStarted = [System.DateTimeOffset]::UtcNow
        $stdoutTask = $process.StandardOutput.ReadLineAsync()
        $stderrTask = $process.StandardError.ReadLineAsync()

        while (-not $process.HasExited) {
            $drainedOutput = $false
            for ($drainCount = 0; $drainCount -lt 4096; $drainCount++) {
                $readCompleted = $false
                if ($null -ne $stdoutTask -and $stdoutTask.IsCompleted) {
                    $line = $stdoutTask.GetAwaiter().GetResult()
                    if ($null -eq $line) {
                        $stdoutTask = $null
                    }
                    else {
                        $pendingLines.Enqueue($line)
                        $stdoutTask = $process.StandardOutput.ReadLineAsync()
                    }
                    $readCompleted = $true
                }
                if ($null -ne $stderrTask -and $stderrTask.IsCompleted) {
                    $line = $stderrTask.GetAwaiter().GetResult()
                    if ($null -eq $line) {
                        $stderrTask = $null
                    }
                    else {
                        $pendingLines.Enqueue($line)
                        $stderrTask = $process.StandardError.ReadLineAsync()
                    }
                    $readCompleted = $true
                }
                if (-not $readCompleted) {
                    break
                }
                $drainedOutput = $true
            }
            while ($pendingLines.Count -gt 0) {
                $safeLine = ConvertTo-AtlasoSanitizedPackerLine -Line $pendingLines.Dequeue()
                Write-Host $safeLine
                $newPhase = Get-AtlasoPackerPhaseFromLine -CurrentPhase $phase -Line $safeLine
                if ($newPhase -ne $phase) {
                    $phase = $newPhase
                }
            }

            if ($phase -ne 'provisioning' -and [System.DateTimeOffset]::UtcNow -ge $nextHeartbeat) {
                if ([string]::IsNullOrWhiteSpace($vmxIdentity) -and (Test-Path -LiteralPath $VmxPath -PathType Leaf)) {
                    $vmxIdentity = Get-AtlasoWorkstationBuilderIdentity -Path $VmxPath
                }
                $lastState = if ($null -ne $StateProbe) {
                    & $StateProbe $phase $vmxIdentity
                }
                else {
                    Get-AtlasoWorkstationBuilderState `
                        -VmrunPath $VmrunPath `
                        -VmxPath $VmxPath `
                        -ExpectedVmxIdentity $vmxIdentity `
                        -BuilderAddress $BuilderAddress
                }
                if (-not $lastState.IdentityMatches -and $lastState.VmxExists -and
                    $lastState.ProviderResponsive -and $lastState.ExactRunning) {
                    # Workstation can atomically rewrite its VMX during normal
                    # power-on. Re-anchor only after exact provider inventory
                    # proves that the expected path is the running builder.
                    $vmxIdentity = $lastState.VmxIdentity
                    $lastState.IdentityMatches = $true
                    Write-Host 'Packer startup identity refresh [vmx_rewritten]: exact provider inventory confirmed the running builder after a Workstation VMX rewrite.'
                }
                $diagnostic = Get-AtlasoWorkstationStartupDiagnostic -PackerPhase $phase -State $lastState
                Write-Host "Packer startup heartbeat [$($diagnostic.Code)]: $($diagnostic.Message)"
                if (-not [string]::IsNullOrWhiteSpace($lastState.ProviderError)) {
                    Write-Host "VMware provider probe: $($lastState.ProviderError)"
                }
                $nextHeartbeat = [System.DateTimeOffset]::UtcNow.AddSeconds($HeartbeatSeconds)
            }

            if ($null -ne $startupStarted -and $phase -ne 'provisioning' -and
                ([System.DateTimeOffset]::UtcNow - $startupStarted).TotalSeconds -ge $StartupTimeoutSeconds) {
                $timedOut = $true
                break
            }
            # Do not throttle a verbose child behind redirected pipe capacity.
            # A full batch returns immediately to phase/timeout checks; an idle
            # pass yields briefly until either stream completes or the child exits.
            if (-not $drainedOutput) {
                Start-Sleep -Milliseconds 20
            }
        }

        if ($timedOut) {
            if ($null -eq $lastState) {
                if ([string]::IsNullOrWhiteSpace($vmxIdentity) -and (Test-Path -LiteralPath $VmxPath -PathType Leaf)) {
                    $vmxIdentity = Get-AtlasoWorkstationBuilderIdentity -Path $VmxPath
                }
                $lastState = if ($null -ne $StateProbe) {
                    & $StateProbe $phase $vmxIdentity
                }
                else {
                    Get-AtlasoWorkstationBuilderState `
                        -VmrunPath $VmrunPath `
                        -VmxPath $VmxPath `
                        -ExpectedVmxIdentity $vmxIdentity `
                        -BuilderAddress $BuilderAddress
                }
                if (-not $lastState.IdentityMatches -and $lastState.VmxExists -and
                    $lastState.ProviderResponsive -and $lastState.ExactRunning) {
                    $vmxIdentity = $lastState.VmxIdentity
                    $lastState.IdentityMatches = $true
                    Write-Host 'Packer startup identity refresh [vmx_rewritten]: exact provider inventory confirmed the running builder after a Workstation VMX rewrite.'
                }
            }
            $diagnostic = Get-AtlasoWorkstationStartupDiagnostic -PackerPhase $phase -State $lastState
            $process.Kill($true)
            $process.WaitForExit()
            $handlerError = $null
            if ($null -ne $TimeoutHandler) {
                $handlerInvoked = $true
                try {
                    & $TimeoutHandler $PackerOnError $lastState $diagnostic
                }
                catch {
                    $handlerError = $_.Exception.Message
                }
            }
            if ($null -ne $handlerError) {
                throw "Packer startup timed out after $StartupTimeoutSeconds seconds [$($diagnostic.Code)]: $($diagnostic.Message) Checked failure handling also failed: $handlerError"
            }
            throw "Packer startup timed out after $StartupTimeoutSeconds seconds [$($diagnostic.Code)]: $($diagnostic.Message)"
        }

        $process.WaitForExit()
        # A provider descendant must not turn final output draining into another
        # unbounded inherited-handle wait after the Packer parent has exited.
        $drainDeadline = [System.DateTimeOffset]::UtcNow.AddSeconds(5)
        while (($null -ne $stdoutTask -or $null -ne $stderrTask) -and
            [System.DateTimeOffset]::UtcNow -lt $drainDeadline) {
            $drainedOutput = $false
            for ($drainCount = 0; $drainCount -lt 4096; $drainCount++) {
                $readCompleted = $false
                if ($null -ne $stdoutTask -and $stdoutTask.IsCompleted) {
                    $line = $stdoutTask.GetAwaiter().GetResult()
                    if ($null -eq $line) {
                        $stdoutTask = $null
                    }
                    else {
                        Write-Host (ConvertTo-AtlasoSanitizedPackerLine -Line $line)
                        $stdoutTask = $process.StandardOutput.ReadLineAsync()
                    }
                    $readCompleted = $true
                }
                if ($null -ne $stderrTask -and $stderrTask.IsCompleted) {
                    $line = $stderrTask.GetAwaiter().GetResult()
                    if ($null -eq $line) {
                        $stderrTask = $null
                    }
                    else {
                        Write-Host (ConvertTo-AtlasoSanitizedPackerLine -Line $line)
                        $stderrTask = $process.StandardError.ReadLineAsync()
                    }
                    $readCompleted = $true
                }
                if (-not $readCompleted) {
                    break
                }
                $drainedOutput = $true
            }
            if (-not $drainedOutput) {
                Start-Sleep -Milliseconds 20
            }
        }
        if ($null -ne $stdoutTask -or $null -ne $stderrTask) {
            Write-Warning 'Packer exited before its redirected output handles closed; remaining output was discarded.'
        }
        if ($process.ExitCode -ne 0) {
            throw "packer build failed with exit code $($process.ExitCode)."
        }
    }
    finally {
        $finalHandlerError = $null
        try {
            if ($processStarted -and -not $process.HasExited) {
                $process.Kill($true)
                $process.WaitForExit()
                if (-not $handlerInvoked -and $null -ne $TimeoutHandler) {
                    # Ctrl+C or an internal monitor failure bypasses Packer's own
                    # on-error path, so apply the caller-selected checked behavior.
                    $interruptedDiagnostic = [pscustomobject]@{
                        Code    = 'monitor_interrupted'
                        Message = 'The monitored Packer process ended before startup monitoring completed.'
                    }
                    try {
                        & $TimeoutHandler $PackerOnError $lastState $interruptedDiagnostic
                    }
                    catch {
                        $finalHandlerError = $_.Exception.Message
                    }
                }
            }
        }
        finally {
            $process.Dispose()
        }
        if ($null -ne $finalHandlerError) {
            throw "Checked failure handling failed after the monitored Packer process was interrupted: $finalHandlerError"
        }
    }
}

Export-ModuleMember -Function @(
    'ConvertTo-AtlasoSanitizedPackerLine',
    'Get-AtlasoWorkstationBuilderState',
    'Get-AtlasoWorkstationStartupDiagnostic',
    'Initialize-AtlasoWorkstationGui',
    'Invoke-AtlasoMonitoredPackerBuild'
)
