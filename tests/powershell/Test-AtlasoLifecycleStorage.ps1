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
try {
    & $module {
        [CmdletBinding(SupportsShouldProcess = $true)]
        param($FixtureRoot)
        $toolsRoot = Join-Path $FixtureRoot 'custom VMware tools'
        [IO.Directory]::CreateDirectory($toolsRoot) | Out-Null
        $script:resolvedVmrun = Join-Path $toolsRoot 'vmrun.exe'
        [IO.File]::WriteAllText($script:resolvedVmrun, 'never executed')
        [IO.File]::WriteAllText((Join-Path $toolsRoot 'vmware-vdiskmanager.exe'), 'never executed')
        $script:ManagementNetwork = 'VMnet8'
        $script:createdVmxPaths = [Collections.Generic.List[string]]::new()
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
        Set-Item function:script:Invoke-AtlasoBoundedVmrun -Value {
            param($VmrunPath, $ArgumentList, $TimeoutSeconds, $Action)
            if ($TimeoutSeconds -ne 15) { throw 'Unbounded prerequisite query.' }
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
        Remove-Item -LiteralPath $raw
    } $OutputDirectory
}
finally { Remove-Module $module }
Write-Output 'Atlaso lifecycle storage tests passed.'
