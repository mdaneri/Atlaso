<#
.SYNOPSIS
Run source and in-process console regressions for the isolated installation ISO VM.
.DESCRIPTION
Parses the VMX and console driver without executing their script mains, then exercises local named-pipe behavior.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$harnessPath = Join-Path $repositoryRoot 'scripts\windows\vmware\test-installation-iso.ps1'
$ownershipPath = Join-Path $repositoryRoot 'scripts\windows\vmware\Atlaso.TestVmOwnership.ps1'
$cleanupPath = Join-Path $repositoryRoot 'scripts\windows\vmware\Atlaso.WorkstationCleanup.psm1'
$consoleDriverPath = Join-Path $repositoryRoot 'scripts\windows\vmware\invoke-installation-iso-test.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($harnessPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) {
    throw "Installation VM harness has PowerShell parse errors: $($parseErrors[0].Message)"
}
$driverTokens = $null
$driverParseErrors = $null
$driverAst = [System.Management.Automation.Language.Parser]::ParseFile($consoleDriverPath, [ref]$driverTokens, [ref]$driverParseErrors)
if ($driverParseErrors.Count) {
    throw "Installation console driver has PowerShell parse errors: $($driverParseErrors[0].Message)"
}

<#
.SYNOPSIS
Assert one installation harness contract.
.PARAMETER Condition
Boolean result of the contract check being asserted.
.PARAMETER Message
Failure description.
#>
function Assert-InstallationVmCondition {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

<#
.SYNOPSIS
Create a SecureString from a synthetic test fixture without the plaintext conversion helper.
.PARAMETER Text
Public, non-secret fixture text used only by these in-process tests.
#>
function New-InstallationTestSecureString {
    param([string]$Text)
    $secure = [Security.SecureString]::new()
    $characters = $Text.ToCharArray()
    try {
        foreach ($character in $characters) { $secure.AppendChar($character) }
        $secure.MakeReadOnly()
        return $secure
    }
    catch {
        $secure.Dispose()
        throw
    }
    finally { [Array]::Clear($characters, 0, $characters.Length) }
}

<#
.SYNOPSIS
Return one isolated function definition from a parsed source file.
.PARAMETER SourceAst
Parsed PowerShell source AST containing the target function.
.PARAMETER Name
Exact function name to load.
#>
function Get-InstallationVmFunctionText {
    param([System.Management.Automation.Language.Ast]$SourceAst, [string]$Name)
    $definition = $SourceAst.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $Name }, $true) |
        Select-Object -First 1
    if (-not $definition) { throw "Required function is absent: $Name" }
    return $definition.Extent.Text
}

. ([scriptblock]::Create((Get-InstallationVmFunctionText -SourceAst $ast -Name 'ConvertTo-InstallationVmxString')))
. ([scriptblock]::Create((Get-InstallationVmFunctionText -SourceAst $ast -Name 'Resolve-InstallationVmTool')))
. ([scriptblock]::Create((Get-InstallationVmFunctionText -SourceAst $ast -Name 'Switch-InstallationOutputPinToMutationMode')))
. ([scriptblock]::Create((Get-InstallationVmFunctionText -SourceAst $ast -Name 'Start-InstallationIsoVm')))
. ([scriptblock]::Create((Get-InstallationVmFunctionText -SourceAst $ast -Name 'New-InstallationVmConfiguration')))
. ([scriptblock]::Create((Get-InstallationVmFunctionText -SourceAst $ast -Name 'Get-InstallationVmxPathAssignment')))
. ([scriptblock]::Create((Get-InstallationVmFunctionText -SourceAst $ast -Name 'Assert-InstallationVmDiskBindings')))
. ([scriptblock]::Create((Get-InstallationVmFunctionText -SourceAst $ast -Name 'Assert-InstallationSerialPipePath')))
. ([scriptblock]::Create((Get-InstallationVmFunctionText -SourceAst $driverAst -Name 'ConvertFrom-InstallationConsoleFrame')))
. ([scriptblock]::Create((Get-InstallationVmFunctionText -SourceAst $driverAst -Name 'Get-InstallationConsoleDiskOptions')))
. ([scriptblock]::Create((Get-InstallationVmFunctionText -SourceAst $driverAst -Name 'Send-InstallationConsoleSecret')))
. ([scriptblock]::Create((Get-InstallationVmFunctionText -SourceAst $driverAst -Name 'Wait-InstallationConsoleState')))

$pipe = '\\.\pipe\Atlaso-Installation-0123456789abcdef0123456789abcdef'
$lines = @(New-InstallationVmConfiguration -Name 'Atlaso-Test-installation-iso' `
    -Iso 'C:\offline media\atlaso.iso' -TargetDisk 'C:\vm\target-64g.vmdk' `
    -UnselectedDisk 'C:\vm\unselected-4g.vmdk' -WorkingDirectory 'C:\vm' `
    -SerialPipe $pipe -CleanupIdentity '0123456789abcdef0123456789abcdef')
$configuration = [string]::Join("`n", $lines)
Assert-InstallationVmCondition ($configuration.Contains('firmware = "efi"')) 'EFI firmware must be enabled.'
Assert-InstallationVmCondition ($configuration.Contains('uefi.secureBoot.enabled = "FALSE"')) 'Phase-one Secure Boot must be disabled.'
Assert-InstallationVmCondition ($configuration.Contains('workingDir = "C:\vm"')) 'The VMX must bind sidecar files to its owned output directory.'
Assert-InstallationVmCondition ($configuration.Contains('scsi0:0.fileName = "C:\vm\target-64g.vmdk"')) 'The install target disk must occupy SCSI 0:0.'
Assert-InstallationVmCondition ($configuration.Contains('scsi0:1.fileName = "C:\vm\unselected-4g.vmdk"')) 'The unselected disk must occupy SCSI 0:1.'
Assert-InstallationVmCondition ($configuration.Contains('sata0:0.deviceType = "cdrom-image"')) 'The ISO must be attached as a CD-ROM.'
Assert-InstallationVmCondition ($configuration.Contains('serial0.pipe.endPoint = "client"')) 'The serial pipe must use client mode.'
$expectedPipeAssignment = 'serial0.fileName = "\\.\pipe\Atlaso-Installation-0123456789abcdef0123456789abcdef"'
Assert-InstallationVmCondition ($lines -contains $expectedPipeAssignment) 'The VMX serial assignment must contain the literal local named-pipe path.'
$parsedPipe = Get-InstallationVmxPathAssignment -VmxLines $lines -Key 'serial0.fileName'
Assert-InstallationVmCondition ($parsedPipe -ceq $pipe) 'The VMX path parser must preserve literal UNC/device-path backslashes.'
$rejectedVmxValue = foreach ($value in @('bad"quote', "bad`rcontrol", "bad`ncontrol", 'bad|pipe')) {
    $rejected = $false
    try { $null = ConvertTo-InstallationVmxString -Value $value } catch { $rejected = $true }
    -not $rejected
}
Assert-InstallationVmCondition (@($rejectedVmxValue | Where-Object { $_ }).Count -eq 0) `
    'VMX serialization must reject embedded quotes, control characters, and pipe characters.'
Assert-InstallationVmCondition ($configuration.Contains('ethernet0.present = "FALSE"')) 'The VM must have no network adapter.'
Assert-InstallationVmCondition (-not $configuration.Contains('ethernet1.present')) 'The VM must not contain additional network adapters.'
Assert-InstallationVmCondition (-not $configuration.Contains('ethernet0.connectionType = "nat"')) 'The VM must not configure a network connection.'
$bindingContext = [pscustomobject]@{ Name = 'Atlaso-Test-installation-iso'; OutputDirectory = 'C:\vm' }
$validBindings = $true
try { Assert-InstallationVmDiskBindings -VmxLines $lines -Context $bindingContext -IsoPath 'C:\offline media\atlaso.iso' }
catch { $validBindings = $false }
Assert-InstallationVmCondition $validBindings 'Exact target, unselected, and pinned ISO bindings must pass layout validation.'
$changedBindings = @($lines | ForEach-Object {
        if ($_ -ceq 'scsi0:1.fileName = "C:\vm\unselected-4g.vmdk"') { 'scsi0:1.fileName = "C:\vm\target-64g.vmdk"' } else { $_ }
    })
$changedBindingRejected = $false
try { Assert-InstallationVmDiskBindings -VmxLines $changedBindings -Context $bindingContext -IsoPath 'C:\offline media\atlaso.iso' }
catch { $changedBindingRejected = $true }
Assert-InstallationVmCondition $changedBindingRejected 'A changed unselected-disk VMX binding must fail closed.'
$changedWorkingDirectory = @($lines | ForEach-Object {
        if ($_ -ceq 'workingDir = "C:\vm"') { 'workingDir = "C:\unexpected"' } else { $_ }
    })
$changedWorkingDirectoryRejected = $false
try { Assert-InstallationVmDiskBindings -VmxLines $changedWorkingDirectory -Context $bindingContext -IsoPath 'C:\offline media\atlaso.iso' }
catch { $changedWorkingDirectoryRejected = $true }
Assert-InstallationVmCondition $changedWorkingDirectoryRejected 'A changed VMX working directory must fail closed.'
$validPipeAccepted = $true
try { Assert-InstallationSerialPipePath -Path $pipe } catch { $validPipeAccepted = $false }
Assert-InstallationVmCondition $validPipeAccepted 'A valid task-scoped serial pipe must be accepted.'
$invalidPipeRejected = $false
try { Assert-InstallationSerialPipePath -Path '\\localhost\pipe\Atlaso-Installation-0123456789abcdef0123456789abcdef' }
catch { $invalidPipeRejected = $true }
Assert-InstallationVmCondition $invalidPipeRejected 'Remote named pipes must be rejected.'

Import-Module -Name $cleanupPath -Force
$pinTestDirectory = [string](Join-Path $repositoryRoot 'image')
if (-not (Test-Path -LiteralPath $pinTestDirectory -PathType Container)) {
    throw 'The existing repository subdirectory is unavailable for read-only pin-handoff checks.'
}
$pinTestIdentity = [Atlaso.WorkstationFileIdentity]::Get($pinTestDirectory)
$creationDirectoryOpen = [Atlaso.WorkstationFileIdentity].GetMethod('CreateFileW', [Reflection.BindingFlags]'Static,NonPublic')
if (-not $creationDirectoryOpen) { throw 'Could not locate the existing native directory-open method for the sharing regression.' }
$creationPin = $creationDirectoryOpen.Invoke($null, [object[]]@(
    $pinTestDirectory, [uint32]0x00110081, [uint32]1, [IntPtr]::Zero, [uint32]3, [uint32]0x02200000, [IntPtr]::Zero
))
if (-not $creationPin -or $creationPin.IsInvalid) { throw 'Could not open the read-only strict-sharing directory fixture.' }
$overlapPin = $null
$overlapRejected = $false
try { $overlapPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($pinTestDirectory, $true) }
catch { $overlapRejected = $true }
finally { if ($overlapPin) { $overlapPin.Dispose() } }
Assert-InstallationVmCondition $overlapRejected 'The strict creation handle must reject an overlapping mutation pin because it owns delete access without delete sharing.'
try {
    $mutationPin = Switch-InstallationOutputPinToMutationMode -OutputDirectory $pinTestDirectory `
        -ExpectedDirectoryIdentity $pinTestIdentity -CreationPin $creationPin
    Assert-InstallationVmCondition $creationPin.IsClosed 'Successful pin transfer must release the strict creation handle before acquiring the mutation pin.'
    Assert-InstallationVmCondition ([Atlaso.WorkstationFileIdentity]::Get($pinTestDirectory) -ceq $pinTestIdentity) `
        'The mutation-compatible pin must retain the original directory identity.'
}
finally {
    if ($mutationPin) { $mutationPin.Dispose() }
}
$creationPin = $creationDirectoryOpen.Invoke($null, [object[]]@(
    $pinTestDirectory, [uint32]0x00110081, [uint32]1, [IntPtr]::Zero, [uint32]3, [uint32]0x02200000, [IntPtr]::Zero
))
if (-not $creationPin -or $creationPin.IsInvalid) { throw 'Could not reopen the strict-sharing directory fixture.' }
$mismatchRejected = $false
try {
    $null = Switch-InstallationOutputPinToMutationMode -OutputDirectory $pinTestDirectory `
        -ExpectedDirectoryIdentity 'invalid-directory-identity' -CreationPin $creationPin
}
catch { $mismatchRejected = $true }
Assert-InstallationVmCondition $mismatchRejected 'A changed directory identity must reject pin transfer.'
Assert-InstallationVmCondition $creationPin.IsClosed 'Identity mismatch must leave the strict pin released and fail before provider mutation.'
$reopenedCreationPin = $creationDirectoryOpen.Invoke($null, [object[]]@(
    $pinTestDirectory, [uint32]0x00110081, [uint32]1, [IntPtr]::Zero, [uint32]3, [uint32]0x02200000, [IntPtr]::Zero
))
Assert-InstallationVmCondition ($reopenedCreationPin -and -not $reopenedCreationPin.IsInvalid) `
    'Identity mismatch must dispose the replacement pin so the original strict-sharing handle can be reacquired.'
$reopenedCreationPin.Dispose()

$previousBoundedRunner = Get-Item Function:\Invoke-AtlasoBoundedStreamingProcess -ErrorAction SilentlyContinue
$script:InstallationStartRunnerFailure = $false
$script:InstallationStartObservedDirectory = ''
$previousNativeDirectory = [Environment]::CurrentDirectory
Set-Item Function:\Invoke-AtlasoBoundedStreamingProcess -Value {
    param([string]$FilePath, [string[]]$ArgumentList, [int]$TimeoutSeconds, [string]$Action, [switch]$DiscardOutput)
    $script:InstallationStartObservedDirectory = [Environment]::CurrentDirectory
    if ($script:InstallationStartRunnerFailure) { throw 'Synthetic bounded-runner failure.' }
}
try {
    Start-InstallationIsoVm -VmrunPath 'mock-vmrun.exe' -VmxPath 'C:\vm\installation.vmx' -OutputDirectory $pinTestDirectory
    Assert-InstallationVmCondition ($script:InstallationStartObservedDirectory -ceq [IO.Path]::GetFullPath($pinTestDirectory)) `
        'vmrun must inherit the receipt-bound output directory as its native working directory.'
    Assert-InstallationVmCondition ([Environment]::CurrentDirectory -ceq $previousNativeDirectory) `
        'The native working directory must be restored after successful vmrun startup.'
    $script:InstallationStartRunnerFailure = $true
    $startFailureCaught = $false
    try { Start-InstallationIsoVm -VmrunPath 'mock-vmrun.exe' -VmxPath 'C:\vm\installation.vmx' -OutputDirectory $pinTestDirectory }
    catch { $startFailureCaught = $true }
    Assert-InstallationVmCondition $startFailureCaught 'The mocked startup failure must propagate to the caller.'
    Assert-InstallationVmCondition ([Environment]::CurrentDirectory -ceq $previousNativeDirectory) `
        'The native working directory must be restored after failed vmrun startup.'
}
finally {
    [Environment]::CurrentDirectory = $previousNativeDirectory
    if ($previousBoundedRunner) { Set-Item Function:\Invoke-AtlasoBoundedStreamingProcess -Value $previousBoundedRunner.ScriptBlock }
    else { Remove-Item Function:\Invoke-AtlasoBoundedStreamingProcess -ErrorAction SilentlyContinue }
}

$previousTestPathFunction = Get-Item Function:\Test-Path -ErrorAction SilentlyContinue
$previousResolvePathFunction = Get-Item Function:\Resolve-Path -ErrorAction SilentlyContinue
$originalProgramFiles = $env:ProgramFiles
$originalProgramFilesX86 = ${env:ProgramFiles(x86)}
try {
    $env:ProgramFiles = 'C:\Synthetic VMware'
    ${env:ProgramFiles(x86)} = 'C:\Synthetic VMware x86'
    Set-Item Function:\Test-Path -Value {
        param([string]$LiteralPath, [string]$PathType)
        return $LiteralPath -ceq 'C:\Synthetic VMware\VMware\VMware Workstation\vmware-vdiskmanager.exe'
    }
    Set-Item Function:\Resolve-Path -Value {
        param([string]$LiteralPath)
        return [pscustomobject]@{ Path = $LiteralPath }
    }
    $singleCandidate = Resolve-InstallationVmTool -FileName 'vmware-vdiskmanager.exe'
    Assert-InstallationVmCondition ($singleCandidate -ceq 'C:\Synthetic VMware\VMware\VMware Workstation\vmware-vdiskmanager.exe') `
        'A single installed VMware tool candidate must resolve as a path, not be indexed as a string character.'
}
finally {
    if ($previousTestPathFunction) { Set-Item Function:\Test-Path -Value $previousTestPathFunction.ScriptBlock }
    else { Remove-Item Function:\Test-Path -ErrorAction SilentlyContinue }
    if ($previousResolvePathFunction) { Set-Item Function:\Resolve-Path -Value $previousResolvePathFunction.ScriptBlock }
    else { Remove-Item Function:\Resolve-Path -ErrorAction SilentlyContinue }
    $env:ProgramFiles = $originalProgramFiles
    ${env:ProgramFiles(x86)} = $originalProgramFilesX86
}

$source = [System.IO.File]::ReadAllText($harnessPath)
$ownershipSource = [System.IO.File]::ReadAllText($ownershipPath)
$cleanupSource = [System.IO.File]::ReadAllText($cleanupPath)
$driverSource = [System.IO.File]::ReadAllText($consoleDriverPath)
$cleanupImport = "Import-Module (Join-Path `$PSScriptRoot 'Atlaso.WorkstationCleanup.psm1') -Force"
$ownershipDotSource = ". (Join-Path `$PSScriptRoot 'Atlaso.TestVmOwnership.ps1')"
foreach ($entryPoint in @(
        [pscustomobject]@{ Name = 'VM harness'; Text = $source; Context = 'New-AtlasoTestVmOwnershipContext' },
        [pscustomobject]@{ Name = 'console driver'; Text = $driverSource; Context = 'New-AtlasoTestVmOwnershipContext' }
    )) {
    $moduleImportIndex = $entryPoint.Text.IndexOf($cleanupImport, [StringComparison]::Ordinal)
    $ownershipSourceIndex = $entryPoint.Text.IndexOf($ownershipDotSource, [StringComparison]::Ordinal)
    $contextCreationIndex = $entryPoint.Text.IndexOf($entryPoint.Context, [StringComparison]::Ordinal)
    Assert-InstallationVmCondition ($moduleImportIndex -ge 0 -and $moduleImportIndex -lt $ownershipSourceIndex -and $ownershipSourceIndex -lt $contextCreationIndex) `
        "$($entryPoint.Name) must load the cleanup module before ownership initialization and context creation."
}
$freshProcessScript = "Import-Module '$($cleanupPath.Replace("'", "''"))' -Force; if (-not ('Atlaso.WorkstationFileIdentity' -as [type])) { exit 17 }"
$freshProcessOutput = @(& (Get-Process -Id $PID).Path -NoProfile -Command $freshProcessScript 2>&1)
Assert-InstallationVmCondition ($LASTEXITCODE -eq 0) 'A fresh PowerShell process must initialize the file-identity type from the cleanup module.'
Assert-InstallationVmCondition ($freshProcessOutput.Count -eq 0) 'Fresh-process identity initialization must not emit unexpected output.'
$whatIfGate = $source.IndexOf('$PSCmdlet.ShouldProcess($resolvedOutput', [StringComparison]::Ordinal)
$intentWrite = $source.IndexOf('Publish-AtlasoTestVmOwnershipRecord -Context $context -Record $intent', [StringComparison]::Ordinal)
$originalReceipt = $source.IndexOf('Publish-InstallationVmOriginalReceipt -Context $context', [StringComparison]::Ordinal)
$originalReceiptReport = $source.IndexOf('Original installation VM receipt: path={0} sha256={1}', [StringComparison]::Ordinal)
$diskMutation = $source.IndexOf("-FileName 'vmware-vdiskmanager.exe'", [StringComparison]::Ordinal)
$providerStart = $source.IndexOf('Start-InstallationIsoVm -VmrunPath', [StringComparison]::Ordinal)
Assert-InstallationVmCondition ($whatIfGate -ge 0 -and $intentWrite -gt $whatIfGate) 'WhatIf must return before any ownership record is published.'
Assert-InstallationVmCondition ($intentWrite -lt $originalReceipt -and $originalReceipt -lt $diskMutation) 'The task intent and original VM receipt must precede disk mutations.'
Assert-InstallationVmCondition ($originalReceipt -lt $providerStart) 'The original VM receipt must precede provider startup.'
Assert-InstallationVmCondition ($originalReceipt -lt $originalReceiptReport -and $originalReceiptReport -lt $diskMutation) `
    'The original receipt path and digest must be reported before the first disk-tool/provider operation.'
foreach ($member in @('ReceiptPath', 'ReceiptSha256', 'VmxPath', 'DirectoryIdentity', 'PersistentVmIdentitySha256')) {
    Assert-InstallationVmCondition ($source.Contains("        $member = ")) "Create result must expose structured $member."
}
Assert-InstallationVmCondition ($source.Contains('if (($PullRequestNumber -gt 0) -eq [bool]$LocalBuilder)')) 'PR and local ownership selection must be explicitly exclusive.'
Assert-InstallationVmCondition ($source.Contains('-ExpectedRootIdentity ([string]$record.original_identities.directory)')) 'Cleanup must use the original directory identity.'
Assert-InstallationVmCondition ($source.Contains('-ExpectedPersistentVmIdentitySha256 ([string]$record.persistent_vm_identity_sha256)')) 'Cleanup must use the recorded persistent identity digest.'
Assert-InstallationVmCondition (-not $source.Contains('Remove-Item -Recurse')) 'Harness cleanup must delegate to the owning receipt-aware remover.'
Assert-InstallationVmCondition ($source.Contains("'-c', '-s', '64GB', '-a', 'lsilogic', '-t', '0', $targetDisk")) 'The target disk must be created at the assigned capacity.'
Assert-InstallationVmCondition ($source.Contains("'-c', '-s', '4GB', '-a', 'lsilogic', '-t', '0', $unselectedDisk")) 'The second disk must be the small unselected disk.'
$targetDiskCreate = $source.IndexOf("'-c', '-s', '64GB', '-a', 'lsilogic', '-t', '0', $targetDisk", [StringComparison]::Ordinal)
$unselectedDiskCreate = $source.IndexOf("'-c', '-s', '4GB', '-a', 'lsilogic', '-t', '0', $unselectedDisk", [StringComparison]::Ordinal)
$baselineCreate = $source.IndexOf('Publish-InstallationDiskBaseline -Context $context', [StringComparison]::Ordinal)
$baselineReport = $source.IndexOf('Installation disk baseline receipt: path={0} sha256={1}', [StringComparison]::Ordinal)
$providerStart = $source.IndexOf('Start-InstallationIsoVm -VmrunPath', [StringComparison]::Ordinal)
$pinSwitch = $source.IndexOf('$outputPin = Switch-InstallationOutputPinToMutationMode', [StringComparison]::Ordinal)
Assert-InstallationVmCondition ($targetDiskCreate -lt $baselineCreate -and $unselectedDiskCreate -lt $baselineCreate -and $baselineCreate -lt $providerStart) 'Both logical disk baselines must be durably published after disk creation and before any VM start.'
Assert-InstallationVmCondition ($baselineCreate -lt $baselineReport -and $baselineReport -lt $providerStart) `
    'The disk baseline receipt path and digest must be reported before VM startup.'
Assert-InstallationVmCondition ($baselineReport -lt $pinSwitch -and $pinSwitch -lt $providerStart) `
    'The strict directory pin must be transferred only after both receipts are durable and before VM startup.'
$pinHelper = $source.Substring($source.IndexOf('function Switch-InstallationOutputPinToMutationMode', [StringComparison]::Ordinal),
    $source.IndexOf('<#', $source.IndexOf('function Start-InstallationIsoVm', [StringComparison]::Ordinal), [StringComparison]::Ordinal) -
    $source.IndexOf('function Switch-InstallationOutputPinToMutationMode', [StringComparison]::Ordinal))
$pinAcquire = $pinHelper.IndexOf('PinOrdinaryDirectoryPath($OutputDirectory, $true)', [StringComparison]::Ordinal)
$pinIdentity = $pinHelper.IndexOf('Get($OutputDirectory) -cne $ExpectedDirectoryIdentity', [StringComparison]::Ordinal)
$pinRelease = $pinHelper.IndexOf('$CreationPin.Dispose()', [StringComparison]::Ordinal)
Assert-InstallationVmCondition ($pinRelease -ge 0 -and $pinRelease -lt $pinAcquire -and $pinAcquire -lt $pinIdentity) `
    'The strict creation handle must be released before replacement pin acquisition, with identity checked before return.'
Assert-InstallationVmCondition ($pinHelper.Contains('if ($mutationPin) { $mutationPin.Dispose() }')) `
    'A failed identity recheck must dispose the replacement pin before aborting.'
$startHelper = $source.Substring($source.IndexOf('function Start-InstallationIsoVm', [StringComparison]::Ordinal),
    $source.IndexOf('<#', $source.IndexOf('function ConvertTo-InstallationVmxString', [StringComparison]::Ordinal), [StringComparison]::Ordinal) -
    $source.IndexOf('function Start-InstallationIsoVm', [StringComparison]::Ordinal))
Assert-InstallationVmCondition ($startHelper.Contains('[Environment]::CurrentDirectory = [IO.Path]::GetFullPath($OutputDirectory)') -and
    $startHelper.Contains('[Environment]::CurrentDirectory = $previousNativeDirectory')) `
    'The bounded vmrun start must temporarily use and then restore the native current directory.'
Assert-InstallationVmCondition ($source.Contains("'compare', '-f', 'vmdk', '-F', 'vmdk'")) 'Disk comparison must use qemu-img logical VMDK comparison.'
Assert-InstallationVmCondition (-not $source.Contains("'compare', '-s'")) 'Logical comparison must not require sparse allocation layout to match.'
Assert-InstallationVmCondition ($source.Contains('-Kind installation-baseline')) 'The baseline record must use its dedicated ownership-receipt kind.'
Assert-InstallationVmCondition ($ownershipSource.Contains("'installation-baseline')")) 'The immutable ownership publisher must admit the baseline record kind.'
Assert-InstallationVmCondition ($cleanupSource.Contains("'Confirm-AtlasoWorkstationVmInactive'")) 'The guarded VM stop helper must be available to the verification mode.'
$verifyMode = $source.IndexOf('if ($Mode -eq ''Verify'')', [StringComparison]::Ordinal)
Assert-InstallationVmCondition ($verifyMode -ge 0) 'The harness must expose receipt-bound disk verification.'
$verifyOriginalRead = $source.IndexOf('Read-AtlasoTestVmSealedRecord -Context $context -Path $OriginalReceiptPath', $verifyMode, [StringComparison]::Ordinal)
$verifyBaselineRead = $source.IndexOf('Read-AtlasoTestVmSealedRecord -Context $context -Path $BaselineReceiptPath', $verifyMode, [StringComparison]::Ordinal)
$verifyStop = $source.IndexOf('Confirm-AtlasoWorkstationVmInactive -VmrunPath', $verifyMode, [StringComparison]::Ordinal)
$verifyCompare = $source.IndexOf('Assert-InstallationDiskUnchanged -Disk', $verifyMode, [StringComparison]::Ordinal)
Assert-InstallationVmCondition ($verifyOriginalRead -gt $verifyMode -and $verifyBaselineRead -gt $verifyOriginalRead -and $verifyStop -gt $verifyBaselineRead -and $verifyCompare -gt $verifyStop) 'Verification must validate both bound receipts before stopping the VM and compare only after stop.'
Assert-InstallationVmCondition ($source.Contains("`$roles = @('unselected')") -and $source.Contains('if ($VerifyTarget) { $roles += ''target'' }')) 'Verification must always check the unselected disk and optionally check the target for cancellation.'
Assert-InstallationVmCondition ($source.Contains("Invoke-AtlasoBoundedProcess -FilePath `$QemuImg -ArgumentList @('info', '--output=json', `$Path)")) 'qemu-img metadata inspection must use the existing bounded process helper.'

<#
.SYNOPSIS
Create and connect one in-process byte-mode named-pipe pair.
.PARAMETER Name
Unique local pipe identifier for the current test.
#>
function New-InstallationTestPipePair {
    param([string]$Name)
    $server = [IO.Pipes.NamedPipeServerStream]::new($Name, [IO.Pipes.PipeDirection]::InOut, 1,
        [IO.Pipes.PipeTransmissionMode]::Byte, [IO.Pipes.PipeOptions]::Asynchronous)
    $client = [IO.Pipes.NamedPipeClientStream]::new('.', $Name, [IO.Pipes.PipeDirection]::InOut,
        [IO.Pipes.PipeOptions]::Asynchronous)
    try {
        $serverAccept = $server.BeginWaitForConnection($null, $null)
        $client.Connect(5000)
        $server.EndWaitForConnection($serverAccept)
        return [pscustomobject]@{ Server = $server; Client = $client }
    }
    catch {
        $client.Dispose()
        $server.Dispose()
        throw
    }
}

Add-Type -TypeDefinition @'
using System;
using System.IO.Pipes;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

public static class AtlasoInstallationPipeTestWriter
{
    public static Task Start(NamedPipeClientStream pipe, string[] fragments)
    {
        return Task.Run(() =>
        {
            foreach (var fragment in fragments)
            {
                var bytes = Encoding.ASCII.GetBytes(fragment);
                try
                {
                    pipe.Write(bytes, 0, bytes.Length);
                    pipe.Flush();
                }
                finally
                {
                    Array.Clear(bytes, 0, bytes.Length);
                }
                Thread.Sleep(25);
            }
        });
    }
}
'@

<#
.SYNOPSIS
Dispose both endpoints of one in-process test pipe.
.PARAMETER Pair
Connected server and client endpoints to close.
#>
function Close-InstallationTestPipePair {
    param([psobject]$Pair)
    if ($Pair.Client) { $Pair.Client.Dispose() }
    if ($Pair.Server) { $Pair.Server.Dispose() }
}

$diskRowsTargetFirst = @(
    Get-InstallationConsoleDiskOptions -Text "Select a disk`r`n64 GiB @ /dev/sda`r`n4 GiB @ /dev/sdb"
)
Assert-InstallationVmCondition ($diskRowsTargetFirst.Count -eq 2) 'The parser must return both native disk rows.'
Assert-InstallationVmCondition ($diskRowsTargetFirst[0].Index -eq 0 -and $diskRowsTargetFirst[0].SizeGiB -eq 64 -and
    $diskRowsTargetFirst[0].DiskPath -ceq '/dev/sda') 'The first native row must retain its original 64 GiB target identity.'
Assert-InstallationVmCondition ($diskRowsTargetFirst[1].Index -eq 1 -and $diskRowsTargetFirst[1].SizeGiB -eq 4 -and
    $diskRowsTargetFirst[1].DiskPath -ceq '/dev/sdb') 'The second native row must retain its original 4 GiB unselected identity.'
$diskRowsUnselectedFirst = @(Get-InstallationConsoleDiskOptions -Text "Select a disk`r`n4 GiB @ /dev/sda`r`n64 GiB @ /dev/sdb")
Assert-InstallationVmCondition ($diskRowsUnselectedFirst.Count -eq 2 -and
    $diskRowsUnselectedFirst[0].SizeGiB -eq 4 -and $diskRowsUnselectedFirst[0].Index -eq 0 -and
    $diskRowsUnselectedFirst[1].SizeGiB -eq 64 -and $diskRowsUnselectedFirst[1].DiskPath -ceq '/dev/sdb' -and
    $diskRowsUnselectedFirst[1].Index -eq 1) 'Disk selection must preserve native order when the 64 GiB target is /dev/sdb.'
$diskRowsRepainted = @(Get-InstallationConsoleDiskOptions -Text "Select a disk`r`n64 GiB @ /dev/sdb`r`n4 GiB @ /dev/sda`r`n64 GiB @ /dev/sdb`r`n4 GiB @ /dev/sda")
Assert-InstallationVmCondition ($diskRowsRepainted.Count -eq 2 -and
    $diskRowsRepainted[0].DiskPath -ceq '/dev/sdb' -and $diskRowsRepainted[1].DiskPath -ceq '/dev/sda') `
    'Repainted native rows must be de-duplicated without changing their visible order.'

# Curses can paint the lower row first and subsequently repaint the upper row.
$cursorRows = @(Get-InstallationConsoleDiskOptions -Text ("`e[2J`e[5;1HSelect a disk" +
    "`e[12;22HVMware Virtual S - 64 GiB @ /dev/sdb`e[11;22HVMware Virtual S - 4 GiB @ /dev/sda"))
Assert-InstallationVmCondition ($cursorRows.Count -eq 2 -and $cursorRows[0].DiskPath -ceq '/dev/sda' -and
    $cursorRows[1].DiskPath -ceq '/dev/sdb' -and $cursorRows[1].Index -eq 1) `
    'Cursor-addressed native rows must use visible order rather than arrival order.'
$erasedRows = @(Get-InstallationConsoleDiskOptions -Text ("`e[11;1H32 GiB @ /dev/sdc`r`e[2K" +
    "4 GiB @ /dev/sda`e[1B`r64 GiB @ /dev/sdb"))
Assert-InstallationVmCondition ($erasedRows.Count -eq 2 -and $erasedRows[0].DiskPath -ceq '/dev/sda' -and
    $erasedRows[1].DiskPath -ceq '/dev/sdb') 'Erased stale rows must never remain selectable.'

$pipePair = $null
$asciiFixture = 'Atlaso-Public-Installer-Fixture-42'
$fixtureBytes = [Text.Encoding]::ASCII.GetBytes($asciiFixture)
$receivedBytes = [byte[]]::new($fixtureBytes.Length + 1)
$secureFixture = New-InstallationTestSecureString -Text $asciiFixture
try {
    $pipePair = New-InstallationTestPipePair -Name ('Atlaso-Test-' + [guid]::NewGuid().ToString('N'))
    $readCancellation = [Threading.CancellationTokenSource]::new(5000)
    try {
        $pendingRead = $pipePair.Client.ReadAsync($receivedBytes, 0, $receivedBytes.Length, $readCancellation.Token)
        Send-InstallationConsoleSecret -Pipe $pipePair.Server -Value $secureFixture
        $receivedCount = $pendingRead.GetAwaiter().GetResult()
    }
    finally { $readCancellation.Dispose() }
    $matchesExpected = $receivedCount -eq ($fixtureBytes.Length + 1)
    for ($index = 0; $matchesExpected -and $index -lt $fixtureBytes.Length; $index++) {
        $matchesExpected = $receivedBytes[$index] -eq $fixtureBytes[$index]
    }
    $matchesExpected = $matchesExpected -and $receivedBytes[$fixtureBytes.Length] -eq 10
    Assert-InstallationVmCondition $matchesExpected 'Secret sender did not write the exact ASCII fixture and newline.'
}
finally {
    if ($secureFixture) { $secureFixture.Dispose() }
    [Array]::Clear($fixtureBytes, 0, $fixtureBytes.Length)
    [Array]::Clear($receivedBytes, 0, $receivedBytes.Length)
    if ($pipePair) { Close-InstallationTestPipePair -Pair $pipePair }
}

$pipePair = $null
$nonAsciiFixtureText = 'Atlaso-public-fixture-' + [char]0x00E9
$nonAsciiFixture = New-InstallationTestSecureString -Text $nonAsciiFixtureText
$nonAsciiRejected = $false
$readCancelled = $false
$unexpectedBytes = [byte[]]::new(32)
try {
    $pipePair = New-InstallationTestPipePair -Name ('Atlaso-Test-' + [guid]::NewGuid().ToString('N'))
    try { Send-InstallationConsoleSecret -Pipe $pipePair.Server -Value $nonAsciiFixture }
    catch { $nonAsciiRejected = $_.Exception.Message -ceq 'Installer credential must satisfy the ASCII account policy.' }
    Assert-InstallationVmCondition $nonAsciiRejected 'Non-ASCII fixture was not rejected by the concealed sender.'
    $readCancellation = [Threading.CancellationTokenSource]::new(200)
    try {
        $unexpectedCount = $pipePair.Client.ReadAsync($unexpectedBytes, 0, $unexpectedBytes.Length, $readCancellation.Token).GetAwaiter().GetResult()
        Assert-InstallationVmCondition ($unexpectedCount -eq 0) 'Non-ASCII rejection wrote unexpected bytes.'
    }
    catch [OperationCanceledException] { $readCancelled = $true }
    finally { $readCancellation.Dispose() }
    Assert-InstallationVmCondition $readCancelled 'Rejected non-ASCII input left the pipe read pending instead of writing no data.'
}
finally {
    if ($nonAsciiFixture) { $nonAsciiFixture.Dispose() }
    [Array]::Clear($unexpectedBytes, 0, $unexpectedBytes.Length)
    if ($pipePair) { Close-InstallationTestPipePair -Pair $pipePair }
}

$pipePair = $null
$fragmentSender = $null
try {
    $pipePair = New-InstallationTestPipePair -Name ('Atlaso-Test-' + [guid]::NewGuid().ToString('N'))
    $clientForSender = $pipePair.Client
    $fragments = [string[]]@("Installer`e[", '32mSelect ', 'a ', 'disk ', 'review`e[0m')
    $fragmentSender = [AtlasoInstallationPipeTestWriter]::Start($clientForSender, $fragments)
    try {
        Wait-InstallationConsoleState -Pipe $pipePair.Server -Pattern 'Select a disk review' -Deadline ([DateTimeOffset]::UtcNow.AddSeconds(5))
    }
    catch {
        if ($fragmentSender.IsFaulted) { throw 'Fragmented public console writer task failed.' }
        throw
    }
    Assert-InstallationVmCondition $fragmentSender.Wait(5000) 'Fragmented public console writer did not complete.'
}
finally {
    if ($pipePair) { Close-InstallationTestPipePair -Pair $pipePair }
}

$pipePair = $null
$diskSelectionSender = $null
try {
    $pipePair = New-InstallationTestPipePair -Name ('Atlaso-Test-' + [guid]::NewGuid().ToString('N'))
    $diskSelectionSender = [AtlasoInstallationPipeTestWriter]::Start($pipePair.Client, [string[]]@(
        "`e[2J`e[5;1HSelect a disk",
        "`e[12;22H64 GiB @ /dev/sdb",
        "`e[11;22H4 GiB @ /dev/sda"))
    $selectedOptions = @(Wait-InstallationConsoleState -Pipe $pipePair.Server -Pattern 'Select a disk' `
        -Deadline ([DateTimeOffset]::UtcNow.AddSeconds(5)) -ReadDiskSelection)
    Assert-InstallationVmCondition ($selectedOptions.Count -eq 2 -and
        $selectedOptions[0].DiskPath -ceq '/dev/sda' -and $selectedOptions[0].SizeGiB -eq 4 -and
        $selectedOptions[1].DiskPath -ceq '/dev/sdb' -and $selectedOptions[1].SizeGiB -eq 64) `
        'Disk-selection wait returned before both fragmented native rows arrived or changed their order.'
    Assert-InstallationVmCondition $diskSelectionSender.Wait(5000) 'Fragmented disk selection fixture did not complete.'
}
finally {
    if ($pipePair) { Close-InstallationTestPipePair -Pair $pipePair }
}

$pipePair = $null
$mismatchedDiskSender = $null
$mismatchedDiskRejected = $false
try {
    $pipePair = New-InstallationTestPipePair -Name ('Atlaso-Test-' + [guid]::NewGuid().ToString('N'))
    $mismatchedDiskSender = [AtlasoInstallationPipeTestWriter]::Start($pipePair.Client, [string[]]@(
        "Select a disk`r`n32 GiB @ /dev/sda`r`n4 GiB @ /dev/sdb`r`n"))
    try {
        $null = Wait-InstallationConsoleState -Pipe $pipePair.Server -Pattern 'Select a disk' `
            -Deadline ([DateTimeOffset]::UtcNow.AddSeconds(5)) -ReadDiskSelection
    }
    catch {
        $mismatchedDiskRejected = $_.Exception.Message -ceq 'Native disk menu does not match the receipt-bound 64 GiB target and 4 GiB unselected fixture.'
    }
    Assert-InstallationVmCondition $mismatchedDiskRejected 'Mismatched fixture capacities must fail closed.'
    Assert-InstallationVmCondition $mismatchedDiskSender.Wait(5000) 'Mismatched disk fixture writer did not complete.'
}
finally {
    if ($pipePair) { Close-InstallationTestPipePair -Pair $pipePair }
}

$pipePair = $null
$timeoutObserved = $false
try {
    $pipePair = New-InstallationTestPipePair -Name ('Atlaso-Test-' + [guid]::NewGuid().ToString('N'))
    try {
        Wait-InstallationConsoleState -Pipe $pipePair.Server -Pattern 'NeverSentPublicPrompt' -Deadline ([DateTimeOffset]::UtcNow.AddMilliseconds(250))
    }
    catch { $timeoutObserved = $_.Exception.Message -ceq 'The installer did not reach the expected public console state before its deadline.' }
    Assert-InstallationVmCondition $timeoutObserved 'Console state wait did not end on its deadline.'
}
finally {
    if ($pipePair) { Close-InstallationTestPipePair -Pair $pipePair }
}

$peerSources = @($driverAst.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
        $node.Value.Contains('public static class AtlasoInstallationPipePeer')
}, $true))
Assert-InstallationVmCondition ($peerSources.Count -eq 1) 'Expected one native console peer verifier.'
Add-Type -TypeDefinition $peerSources[0].Value
$ownImage = [Environment]::ProcessPath
$ownArguments = [Environment]::GetCommandLineArgs()
Assert-InstallationVmCondition ($ownArguments.Length -gt 1) 'Run this regression with the documented -File command.'
$ownArgument = $ownArguments[1]
Assert-InstallationVmCondition ([AtlasoInstallationPipePeer]::MatchesExpectedProcess($PID, @($ownImage), $ownArgument)) 'Limited-query peer proof rejected the current process and exact argument.'
Assert-InstallationVmCondition (-not [AtlasoInstallationPipePeer]::MatchesExpectedProcess($PID, @($ownImage + '.different'), $ownArgument)) 'Peer proof accepted a different executable image.'
Assert-InstallationVmCondition (-not [AtlasoInstallationPipePeer]::MatchesExpectedProcess($PID, @($ownImage), $ownArgument + '.different')) 'Peer proof accepted an argument substring.'
Assert-InstallationVmCondition (-not [AtlasoInstallationPipePeer]::MatchesExpectedProcess([uint32]::MaxValue, @($ownImage), $ownArgument)) 'Peer proof accepted an unavailable process.'

$pipePair = $null
$failureSender = $null
try {
    $pipePair = New-InstallationTestPipePair -Name ('Atlaso-Test-' + [guid]::NewGuid().ToString('N'))
    $failureSender = [AtlasoInstallationPipeTestWriter]::Start($pipePair.Client,
        [string[]]@("Traceback (most recent call last):`nPublicSyntheticSensitiveFixture"))
    $failureObserved = $false
    try {
        Wait-InstallationConsoleState -Pipe $pipePair.Server -Pattern 'Select a disk' -Deadline ([DateTimeOffset]::UtcNow.AddSeconds(5))
    }
    catch { $failureObserved = $_.Exception.Message -ceq 'The installer reported a Python failure before the expected console state.' }
    Assert-InstallationVmCondition $failureObserved 'Python console failure did not fail promptly with only its public classification.'
    Assert-InstallationVmCondition $failureSender.Wait(5000) 'Public failure fixture writer did not complete.'
}
finally {
    if ($pipePair) { Close-InstallationTestPipePair -Pair $pipePair }
}

Write-Host 'Installation console pipe contract checks passed.'

$pipePair = $null
try {
    $pipePair = New-InstallationTestPipePair -Name ('Atlaso-Test-' + [guid]::NewGuid().ToString('N'))
    $failureSender = [AtlasoInstallationPipeTestWriter]::Start($pipePair.Client, [string[]]@(
        "Traceback (most recent call last):`n  File `"/PublicSyntheticSensitiveFixture/manifest.py`", line 32, in digest`n",
        "ValueError: PublicSyntheticSensitiveFixture`n"))
    $failureObserved = $false
    try {
        Wait-InstallationConsoleState -Pipe $pipePair.Server -Pattern 'Select a disk' -Deadline ([DateTimeOffset]::UtcNow.AddSeconds(5))
    }
    catch { $failureObserved = $_.Exception.Message -ceq 'The installer reported a Python failure before the expected console state. Public location: ValueError; manifest.py:32.' }
    Assert-InstallationVmCondition $failureObserved 'Fragmented error classification exposed more than public source identifiers or lost the failure.'
    Assert-InstallationVmCondition $failureSender.Wait(5000) 'Public classified fixture writer did not complete.'
}
finally {
    if ($pipePair) { Close-InstallationTestPipePair -Pair $pipePair }
}

foreach ($publicFailure in @(
    @{ Text = 'Installation cancelled. PublicSyntheticSensitiveFixture'; Expected = 'The installer cancelled before the expected console state.' },
    @{ Text = 'Password must include an uppercase letter. PublicSyntheticSensitiveFixture'; Expected = 'The installer rejected the concealed credential under its account policy.' }
)) {
    $pipePair = $null
    try {
        $pipePair = New-InstallationTestPipePair -Name ('Atlaso-Test-' + [guid]::NewGuid().ToString('N'))
        $failureSender = [AtlasoInstallationPipeTestWriter]::Start($pipePair.Client, [string[]]@($publicFailure.Text))
        $failureObserved = $false
        try {
            Wait-InstallationConsoleState -Pipe $pipePair.Server -Pattern 'Confirm admin password' -Deadline ([DateTimeOffset]::UtcNow.AddSeconds(5))
        }
        catch { $failureObserved = $_.Exception.Message -ceq $publicFailure.Expected }
        Assert-InstallationVmCondition $failureObserved 'A native refusal must fail promptly without exposing console content.'
        Assert-InstallationVmCondition $failureSender.Wait(5000) 'Public refusal fixture writer did not complete.'
    }
    finally {
        if ($pipePair) { Close-InstallationTestPipePair -Pair $pipePair }
    }
}

Write-Host 'Installation ISO VM harness source-contract checks passed.'
