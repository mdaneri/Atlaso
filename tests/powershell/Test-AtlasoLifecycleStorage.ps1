<#
.SYNOPSIS
Exercise lifecycle clone storage delegation and bounded startup diagnostics without VMware.
.PARAMETER RepositoryRoot
Checkout containing the lifecycle runner.
.PARAMETER OutputDirectory
Task-owned fixture directory beneath the permitted worktree root.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RepositoryRoot,
    [Parameter(Mandatory = $true)][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
[IO.Directory]::CreateDirectory($OutputDirectory) | Out-Null
$runner = Join-Path $RepositoryRoot 'scripts/windows/vmware/run-lifecycle-test.ps1'
$ast = [Management.Automation.Language.Parser]::ParseFile($runner, [ref]$null, [ref]$null)
$functions = @('Copy-VmDirectory', 'Get-ApplianceStartupDiagnostic', 'Resolve-VdiskManagerPath')
$source = @($ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in $functions
}, $true) | ForEach-Object { $_.Extent.Text }) -join "`n"
$modulePath = Join-Path $OutputDirectory 'LifecycleFixture.psm1'
[IO.File]::WriteAllText($modulePath, $source)
# The real extracted runner delegates to this harmless clone contract fixture.
$cloneFixture = @'
param($Name, $ApplianceVmxPath, $OutputDirectory, $VmrunPath, $VdiskManagerPath, $ManagementNetwork, [switch]$SkipLabNetworkAdapters)
if (-not $SkipLabNetworkAdapters -or $ManagementNetwork -ne 'VMnet8') { throw 'Incorrect shared clone contract.' }
if ($VdiskManagerPath -ne (Join-Path (Split-Path -Parent $VmrunPath) 'vmware-vdiskmanager.exe')) { throw 'Custom sibling disk manager was not forwarded.' }
if (-not (Test-Path -LiteralPath $ApplianceVmxPath)) { throw 'Incorrect clone source.' }
[IO.Directory]::CreateDirectory($OutputDirectory) | Out-Null
[IO.File]::WriteAllText((Join-Path $OutputDirectory "$Name.vmx"), 'fixture clone')
if ($Name -eq 'failed-disk') { throw 'Fixture disk creation failed.' }
'@
[IO.File]::WriteAllText((Join-Path $OutputDirectory 'create-atlaso-vm.ps1'), $cloneFixture)
$module = Import-Module $modulePath -Force -PassThru
$runnerText = Get-Content -LiteralPath $runner -Raw
$cleanupStart = $runnerText.IndexOf('# No further provider operations are safe while a diagnostic writer may survive.')
if ($cleanupStart -lt 0) { throw 'Lifecycle cleanup gate is missing.' }
$cleanupSource = $runnerText.Substring($cleanupStart)
try {
    & $module {
        [CmdletBinding(SupportsShouldProcess = $true)]
        param($FixtureRoot, $CleanupSource)
        $toolsRoot = Join-Path $FixtureRoot 'custom VMware tools'
        [IO.Directory]::CreateDirectory($toolsRoot) | Out-Null
        $script:resolvedVmrun = Join-Path $toolsRoot 'vmrun.exe'
        [IO.File]::WriteAllText($script:resolvedVmrun, 'never executed')
        [IO.File]::WriteAllText((Join-Path $toolsRoot 'vmware-vdiskmanager.exe'), 'never executed')
        $script:ManagementNetwork = 'VMnet8'
        $script:createdVmxPaths = [Collections.Generic.List[string]]::new()
        $script:runtimeVmwareRoot = $FixtureRoot
        $script:resultRoot = $FixtureRoot
        $script:repoRoot = Join-Path $FixtureRoot 'task-checkout'
        $script:LabName = 'Atlaso-PR-812-lifecycle-fixture'
        $script:ApplianceSshUser = 'fixture'
        $script:ApplianceGuestPassword = ''
        Set-Item function:script:Assert-SafeLifecycleName -Value { param($Name) }
        Set-Item function:script:Assert-AtlasoTemplatePoweredOff -Value { param($VmxPath, $VmrunPath) }
        Set-Item function:script:Assert-AtlasoVmwarePayloadProvenance -Value { param($VmxPath) }
        $sourceVmx = Join-Path $FixtureRoot 'source.vmx'
        [IO.File]::WriteAllText($sourceVmx, 'immutable source')
        $sourceHash = (Get-FileHash -LiteralPath $sourceVmx).Hash
        $destination = Join-Path $FixtureRoot 'success'
        $vmx = Copy-VmDirectory -SourceVmx $sourceVmx -DestinationDirectory $destination -Name 'success'
        if ($vmx -ne (Join-Path $destination 'success.vmx') -or $createdVmxPaths.Count -ne 1 -or
            $createdVmxPaths[0] -ne $vmx -or -not (Test-Path -LiteralPath $vmx)) {
            throw 'Successful clone did not retain its exact VMX identity.'
        }
        $failure = $null
        try { Copy-VmDirectory -SourceVmx $sourceVmx -DestinationDirectory $destination -Name 'another' }
        catch { $failure = $_ }
        if ($null -eq $failure -or $failure.Exception.Message -notlike 'Lifecycle VM directory already exists:*' -or
            (Test-Path -LiteralPath (Join-Path $destination 'another.vmx'))) {
            throw 'Existing destination was not refused before clone mutation.'
        }
        $failedDestination = Join-Path $FixtureRoot 'failed'
        $failure = $null
        try { Copy-VmDirectory -SourceVmx $sourceVmx -DestinationDirectory $failedDestination -Name 'failed-disk' }
        catch { $failure = $_ }
        if ($null -eq $failure -or $failure.Exception.Message -ne 'Fixture disk creation failed.' -or
            $createdVmxPaths.Count -ne 2 -or $createdVmxPaths[1] -ne (Join-Path $failedDestination 'failed-disk.vmx')) {
            throw 'Failed disk creation lost the exact clone needed for cleanup.'
        }
        if ((Get-FileHash -LiteralPath $sourceVmx).Hash -ne $sourceHash) { throw 'Clone mutated the source.' }

        $script:diagnosticText = "Id=atlaso-data-disks.service`nLoadState=loaded`nActiveState=failed`nSubState=failed`nResult=exit-code`nSECRET_FIXTURE_DO_NOT_REPORT"
        $script:providerFailure = $false
        $script:terminationFailure = $false
        Set-Item function:script:Invoke-AtlasoBoundedStreamingProcess -Value {
            param($FilePath, $ArgumentList, $TimeoutSeconds, $Action, [switch]$DiscardOutput)
            if ($TimeoutSeconds -ne 15) { throw 'Unbounded prerequisite query.' }
            if (-not $DiscardOutput) { throw 'Untrusted provider output was not discarded.' }
            if ($script:providerFailure) { throw 'Fixture provider failure.' }
            if ('copyFileFromGuestToHost' -in $ArgumentList) {
                if ($ArgumentList[-1] -notlike '*lifecycle-startup-diagnostics*guest-readback.txt') {
                    throw 'Raw readback targeted retained results.'
                }
                if (Test-Path -LiteralPath (Join-Path $script:resultRoot 'appliance-startup-state.txt')) {
                    throw 'Final diagnostic was published before validation.'
                }
                [IO.File]::WriteAllText($ArgumentList[-1], $script:diagnosticText)
                if ($script:terminationFailure) {
                    $failure = [TimeoutException]::new('Fixture termination uncertainty.')
                    $failure.Data['AtlasoProcessTreeTerminationUnproven'] = $true
                    throw $failure
                }
            }
            return ''
        }
        $diagnostic = Get-ApplianceStartupDiagnostic -ApplianceVmx $vmx
        if ($diagnostic -notlike '*Id=atlaso-data-disks.service*ActiveState=failed*' -or $diagnostic -like '*SECRET_FIXTURE*') {
            throw 'Prerequisite failure was not reported with bounded non-secret state.'
        }
        $artifact = Join-Path $FixtureRoot 'appliance-startup-state.txt'
        $saved = Get-Content -LiteralPath $artifact -Raw
        if ($saved -like '*SECRET_FIXTURE*' -or $saved -notlike '*ActiveState=failed*') {
            throw 'Persisted prerequisite evidence was not sanitized.'
        }
        $raw = Join-Path $script:repoRoot ".atlaso-local/lifecycle-startup-diagnostics/$LabName/guest-readback.txt"
        if (Test-Path -LiteralPath $raw) { throw 'Transient readback was not released.' }
        $script:providerFailure = $true
        if ((Get-ApplianceStartupDiagnostic -ApplianceVmx $vmx) -notlike '*unavailable*bounded provider failure*') {
            throw 'Failed provider was treated as valid prerequisite evidence.'
        }
        if (Test-Path -LiteralPath $artifact) { throw 'Failed provider retained stale evidence.' }
        $script:providerFailure = $false
        foreach ($text in @('invalid fixture', ('x' * 4097))) {
            $script:diagnosticText = $text
            if ((Get-ApplianceStartupDiagnostic -ApplianceVmx $vmx) -notlike '*unavailable*') {
                throw 'Invalid or oversized prerequisite evidence was accepted.'
            }
            if (Test-Path -LiteralPath $artifact) { throw 'Rejected raw prerequisite evidence was retained.' }
            if (Test-Path -LiteralPath $raw) { throw 'Rejected transient readback was retained.' }
        }
        $script:terminationFailure = $true
        $failure = $null
        try { Get-ApplianceStartupDiagnostic -ApplianceVmx $vmx }
        catch { $failure = $_ }
        if ($null -eq $failure -or $failure.Exception.Message -notlike '*termination is unproven*' -or
            -not (Test-Path -LiteralPath $raw) -or (Test-Path -LiteralPath $artifact)) {
            throw 'Unproven writer termination did not preserve recoverable staging and fail closed.'
        }
        $script:cleanupCalls = 0
        Set-Item function:script:Remove-ClientSeedArtifacts -Value { $script:cleanupCalls++ }
        Set-Item function:script:Remove-AtlasoWorkstationVmArtifacts -Value { $script:cleanupCalls++ }
        $CleanupCreatedLab = $true
        $seedArtifactsRetired = $false
        $vmRoot = $FixtureRoot
        $failure = $null
        try { & ([scriptblock]::Create($CleanupSource)) }
        catch { $failure = $_ }
        if ($null -eq $failure -or $failure.Exception.Message -notlike '*cleanup is blocked*' -or $script:cleanupCalls -ne 0) {
            throw 'Unproven diagnostic termination allowed final lifecycle provider cleanup.'
        }
        Remove-Item -LiteralPath $raw
    } $OutputDirectory $cleanupSource
}
finally { Remove-Module $module }

# Exercise the actual Windows job boundary with a descendant that outlives its
# parent unless job completion terminates it. No VMware or credentials are used.
if (-not $IsWindows) {
    Write-Output 'Atlaso lifecycle storage tests passed.'
    return
}
. (Join-Path $RepositoryRoot 'scripts/windows/vmware/Atlaso.WorkstationFirstBoot.ps1')
$workerPath = Join-Path $OutputDirectory 'job-worker.ps1'
@'
param([string]$Identity, [string]$Mode)
Write-Output 'SECRET_FIXTURE_PROVIDER_OUTPUT'
$payload = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Start-Sleep -Seconds 30'))
$child = Start-Process -FilePath (Get-Command pwsh).Source -WindowStyle Hidden -ArgumentList @('-NoProfile','-EncodedCommand',$payload) -PassThru
@{pid=$child.Id; start=$child.StartTime.ToUniversalTime().Ticks} | ConvertTo-Json | Set-Content -LiteralPath $Identity
if ($Mode -eq 'timeout') { Start-Sleep -Seconds 30 }
'@ | Set-Content -LiteralPath $workerPath
foreach ($mode in @('timeout', 'parent-exit')) {
    $identityPath = Join-Path $OutputDirectory "job-$mode.json"
    $failure = $null
    try {
        Invoke-AtlasoBoundedStreamingProcess -FilePath (Get-Command pwsh).Source -DiscardOutput `
            -ArgumentList @('-NoProfile', '-File', $workerPath, '-Identity', $identityPath, '-Mode', $mode) `
            -TimeoutSeconds 3 -Action 'Lifecycle job fixture'
    }
    catch { $failure = $_ }
    if (($mode -eq 'timeout' -and ($null -eq $failure -or
                -not $failure.Exception.Data['AtlasoProcessTreeTerminationProven'])) -or
        ($mode -eq 'parent-exit' -and $null -ne $failure)) {
        throw 'Lifecycle job completion did not produce the expected proven outcome.'
    }
    $identity = Get-Content -LiteralPath $identityPath -Raw | ConvertFrom-Json
    $remaining = Get-Process -Id $identity.pid -ErrorAction SilentlyContinue
    if ($remaining -and $remaining.StartTime.ToUniversalTime().Ticks -eq $identity.start) {
        $remaining.Kill($true)
        $null = $remaining.WaitForExit(10000)
        throw 'Lifecycle job descendant survived; exact fixture cleanup attempted.'
    }
}
Write-Output 'Atlaso lifecycle storage tests passed.'
