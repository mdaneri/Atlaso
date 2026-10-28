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

Import-Module (Join-Path $repositoryRoot 'scripts/windows/vmware/Atlaso.VmwareTestIdentity.psm1') -Force
$identityA = New-AtlasoVmwareTestIdentity -PullRequestNumber 1036 -Purpose installation-iso -CollisionSuffix inspection-a
$identityB = New-AtlasoVmwareTestIdentity -PullRequestNumber 1036 -Purpose installation-iso -CollisionSuffix inspection-b
Assert-InstallationVmCondition ($identityA.Name -cne $identityB.Name -and
    $identityA.Name -ceq 'Atlaso-PR-1036-installation-iso-inspection-a' -and
    $identityB.Name -ceq 'Atlaso-PR-1036-installation-iso-inspection-b') `
    'Independent ISO fixtures must retain the owning PR and distinct canonical names.'
$phaseCalls = @($driverAst.FindAll({ param($node)
    $node -is [System.Management.Automation.Language.CommandAst] -and
    $node.InvocationOperator -eq [System.Management.Automation.Language.TokenKind]::Ampersand -and
    $node.Extent.Text.Contains("'test-installation-iso.ps1'")
}, $true))
Assert-InstallationVmCondition ($phaseCalls.Count -ge 4) 'The console driver must retain its owning lifecycle phases.'
foreach ($phaseCall in $phaseCalls) {
    $suffixParameters = @($phaseCall.CommandElements | Where-Object {
        $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -ceq 'CollisionSuffix'
    })
    Assert-InstallationVmCondition ($suffixParameters.Count -eq 1) 'Every ISO lifecycle phase must carry the same canonical identity suffix.'
    foreach ($selector in @('ValidationRootReceiptPath', 'ValidationRootReceiptSha256')) {
        $elements = @($phaseCall.CommandElements)
        $parameters = @($elements | Where-Object {
            $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -ceq $selector
        })
        Assert-InstallationVmCondition ($parameters.Count -eq 1) 'Every ISO phase must carry both original external-root selectors exactly once.'
        $position = [array]::IndexOf($elements, $parameters[0])
        $value = $elements[$position + 1]
        Assert-InstallationVmCondition ($value -is [System.Management.Automation.Language.VariableExpressionAst] -and
            $value.VariablePath.UserPath -ceq $selector) 'ISO phases must forward the unchanged original external-root selector.'
    }
}
$childArguments = @($driverAst.FindAll({ param($node)
    $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
    $node.Left.Extent.Text -ceq '$childArguments' -and $node.Operator -eq [System.Management.Automation.Language.TokenKind]::Equals
}, $true))
Assert-InstallationVmCondition ($childArguments.Count -eq 1) 'The bounded consumer must have one canonical child argument array.'
foreach ($selector in @('ValidationRootReceiptPath', 'ValidationRootReceiptSha256')) {
    $binding = "'-{0}', `${0}" -f $selector
    Assert-InstallationVmCondition ($childArguments[0].Right.Extent.Text.Contains($binding)) 'The bounded child must retain both original external-root selectors.'
}
foreach ($entryPoint in @(@{ Ast = $ast; Context = 'context' }, @{ Ast = $driverAst; Context = 'sourceContext' })) {
    $release = '$' + $entryPoint.Context + '.ValidationRootAdmission.Dispose()'
    $leases = @($entryPoint.Ast.FindAll({ param($node)
        $node -is [System.Management.Automation.Language.TryStatementAst] -and $node.Finally -and
        $node.Finally.Extent.Text.Contains($release)
    }, $true))
    Assert-InstallationVmCondition ($leases.Count -eq 1) 'Each ISO entry point must release its root admission on all early failures and returns.'
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
. ([scriptblock]::Create((Get-InstallationVmFunctionText -SourceAst $ast -Name 'Get-InstallationVmxEncoding')))
. ([scriptblock]::Create((Get-InstallationVmFunctionText -SourceAst $ast -Name 'Read-InstallationVmxText')))
. ([scriptblock]::Create((Get-InstallationVmFunctionText -SourceAst $ast -Name 'ConvertTo-InstallationDiskBootConfiguration')))
. ([scriptblock]::Create((Get-InstallationVmFunctionText -SourceAst $ast -Name 'Get-InstallationVmxPathAssignment')))
. ([scriptblock]::Create((Get-InstallationVmFunctionText -SourceAst $ast -Name 'Assert-InstallationVmDiskBindings')))
. ([scriptblock]::Create((Get-InstallationVmFunctionText -SourceAst $ast -Name 'Read-InstallationRunningVmxText')))
. ([scriptblock]::Create((Get-InstallationVmFunctionText -SourceAst $ast -Name 'Assert-InstallationConsoleBindings')))
. ([scriptblock]::Create((Get-InstallationVmFunctionText -SourceAst $ast -Name 'Assert-InstallationConsoleDiskIdentities')))
. ([scriptblock]::Create((Get-InstallationVmFunctionText -SourceAst $ast -Name 'Assert-InstallationVmRunning')))
. ([scriptblock]::Create((Get-InstallationVmFunctionText -SourceAst $ast -Name 'Assert-InstallationSerialPipePath')))
. ([scriptblock]::Create((Get-InstallationVmFunctionText -SourceAst $driverAst -Name 'Get-InstallationProvisioningStages')))
. ([scriptblock]::Create((Get-InstallationVmFunctionText -SourceAst $driverAst -Name 'ConvertFrom-InstallationConsoleFrame')))
. ([scriptblock]::Create((Get-InstallationVmFunctionText -SourceAst $driverAst -Name 'Get-InstallationConsoleDiskOptions')))
. ([scriptblock]::Create((Get-InstallationVmFunctionText -SourceAst $driverAst -Name 'Test-InstallationShellPrompt')))
. ([scriptblock]::Create((Get-InstallationVmFunctionText -SourceAst $driverAst -Name 'Send-InstallationConsoleSecret')))
. ([scriptblock]::Create((Get-InstallationVmFunctionText -SourceAst $driverAst -Name 'Send-InstallationConsoleText')))
. ([scriptblock]::Create((Get-InstallationVmFunctionText -SourceAst $driverAst -Name 'Wait-InstallationConsoleState')))

$pipe = '\\.\pipe\Atlaso-Installation-0123456789abcdef0123456789abcdef'
$lines = @(New-InstallationVmConfiguration -Name 'Atlaso-Test-installation-iso' `
    -Iso 'C:\offline media\atlaso.iso' -TargetDisk 'C:\vm\target-64g.vmdk' `
    -UnselectedDisk 'C:\vm\unselected-4g.vmdk' -WorkingDirectory 'C:\vm' `
    -SerialPipe $pipe -CleanupIdentity '0123456789abcdef0123456789abcdef')
$configuration = [string]::Join("`n", $lines)
Assert-InstallationVmCondition ($configuration.Contains('floppy0.present = "FALSE"')) 'The fixed test VM must disable the implicit virtual floppy.'
Assert-InstallationVmCondition ($configuration.Contains('firmware = "efi"')) 'EFI firmware must be enabled.'
Assert-InstallationVmCondition ($configuration.Contains('.encoding = "UTF-8"')) 'New VMX files must declare UTF-8.'
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
$consolePipe = ''
$consoleBindingsAccepted = $true
try { $consolePipe = Assert-InstallationConsoleBindings -VmxLines $lines -Context $bindingContext -IsoPath 'C:\offline media\atlaso.iso' }
catch { $consoleBindingsAccepted = $false }
Assert-InstallationVmCondition ($consoleBindingsAccepted -and $consolePipe -ceq $pipe) 'Console admission must reuse the isolated disk, connected ISO, and local serial configuration checks.'
$unsafeConsoleFixtures = [Collections.Generic.List[object]]::new()
$unsafeConsoleFixtures.Add([string[]](@($lines) + 'ethernet1.present = "TRUE"'))
$unsafeConsoleFixtures.Add([string[]](@($lines) + 'scsi0:2.present = "TRUE"'))
$unsafeConsoleFixtures.Add([string[]]@($lines | ForEach-Object {
        if ($_ -ceq 'sata0:0.startConnected = "TRUE"') { 'sata0:0.startConnected = "FALSE"' } else { $_ }
    }))
$unsafeConsoleFixtures.Add([string[]]@($lines | ForEach-Object {
        if ($_ -ceq 'serial0.pipe.endPoint = "client"') { 'serial0.pipe.endPoint = "server"' } else { $_ }
    }))
foreach ($unsafeConsoleLines in $unsafeConsoleFixtures) {
    $unsafeConsoleRejected = $false
    try { $null = Assert-InstallationConsoleBindings -VmxLines $unsafeConsoleLines -Context $bindingContext -IsoPath 'C:\offline media\atlaso.iso' }
    catch { $unsafeConsoleRejected = $true }
    Assert-InstallationVmCondition $unsafeConsoleRejected 'Console admission must reject changed isolation, storage, media, and serial bindings.'
}

$unicodeSegment = [string][char]0x00E9 + 'preuve-' + [string][char]0x65E5 + [string][char]0x672C
$unicodeDirectory = "C:\vm\$unicodeSegment"
$unicodeIso = "C:\offline media\$unicodeSegment.iso"
$unicodeName = "Atlaso Test $unicodeSegment"
$unicodeLines = @(New-InstallationVmConfiguration -Name $unicodeName `
    -Iso $unicodeIso -TargetDisk (Join-Path $unicodeDirectory 'target-64g.vmdk') `
    -UnselectedDisk (Join-Path $unicodeDirectory 'unselected-4g.vmdk') -WorkingDirectory $unicodeDirectory `
    -SerialPipe $pipe -CleanupIdentity '0123456789abcdef0123456789abcdef')
$strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
$unicodeSource = [string]::Join("`r`n", $unicodeLines) + "`r`n"
$unicodeBytes = $strictUtf8.GetBytes($unicodeSource)
$unicodeEncoding = Get-InstallationVmxEncoding -Bytes $unicodeBytes
$unicodeText = $unicodeEncoding.GetString($unicodeBytes)
Assert-InstallationVmCondition ($unicodeText.Contains($unicodeIso) -and $unicodeText.Contains($unicodeDirectory)) `
    'New VMX UTF-8 serialization must preserve French and Japanese paths.'
$unicodeContext = [pscustomobject]@{ Name = $unicodeName; OutputDirectory = $unicodeDirectory }
$unicodeBindingsAccepted = $true
try {
    Assert-InstallationVmDiskBindings -VmxLines ($unicodeText -split "`r?`n") -Context $unicodeContext -IsoPath $unicodeIso
}
catch { $unicodeBindingsAccepted = $false }
Assert-InstallationVmCondition $unicodeBindingsAccepted 'UTF-8 VMX disk bindings must preserve the exact Unicode paths.'
$unicodeBootText = ConvertTo-InstallationDiskBootConfiguration -Text $unicodeText
$unicodeBootRestored = $unicodeBootText.Replace('sata0:0.present = "FALSE"', 'sata0:0.present = "TRUE"').Replace(
    'sata0:0.startConnected = "FALSE"', 'sata0:0.startConnected = "TRUE"')
Assert-InstallationVmCondition ($unicodeBootRestored -ceq $unicodeText) `
    'The installed-boot transform must preserve all UTF-8 VMX text except its two CD assignments.'

$legacyValue = [string][char]0x00E9
$legacyText = '.encoding = "windows-1252"' + "`r`n" + "displayName = `"Caf$legacyValue`"`r`n"
$legacyBytes = [Text.Encoding]::GetEncoding(1252).GetBytes($legacyText)
$legacyEncoding = Get-InstallationVmxEncoding -Bytes $legacyBytes
$legacyDecoded = $legacyEncoding.GetString($legacyBytes)
Assert-InstallationVmCondition ($legacyDecoded -ceq $legacyText -and
    [Convert]::ToBase64String($legacyEncoding.GetBytes($legacyDecoded)) -ceq [Convert]::ToBase64String($legacyBytes)) `
    'Legacy Windows-1252 VMX must decode and re-encode representable text without changing bytes.'

$invalidUtf8 = [Collections.Generic.List[byte]]::new()
$invalidUtf8.AddRange($strictUtf8.GetBytes('.encoding = "UTF-8"' + "`r`n" + 'displayName = "invalid-'))
$invalidUtf8.Add([byte]0xFF)
$invalidUtf8.AddRange($strictUtf8.GetBytes('"' + "`r`n"))
$invalidUtf8Rejected = $false
try { (Get-InstallationVmxEncoding -Bytes $invalidUtf8.ToArray()).GetString($invalidUtf8.ToArray()) | Out-Null }
catch { $invalidUtf8Rejected = $true }
Assert-InstallationVmCondition $invalidUtf8Rejected 'Malformed UTF-8 VMX bytes must fail strict decoding.'

$unsupportedBytes = $strictUtf8.GetBytes('.encoding = "latin-1"' + "`r`n")
$duplicateBytes = $strictUtf8.GetBytes('.encoding = "UTF-8"' + "`r`n" + '.encoding = "windows-1252"' + "`r`n")
$missingBytes = $strictUtf8.GetBytes('displayName = "missing declaration"' + "`r`n")
$bomLegacyBytes = [Collections.Generic.List[byte]]::new()
$bomLegacyBytes.AddRange(([Text.UTF8Encoding]::new($true)).GetPreamble())
$bomLegacyBytes.AddRange($legacyBytes)
foreach ($malformedBytes in @($unsupportedBytes, $duplicateBytes, $missingBytes, $bomLegacyBytes.ToArray())) {
    $malformedRejected = $false
    try { $null = Get-InstallationVmxEncoding -Bytes $malformedBytes } catch { $malformedRejected = $true }
    Assert-InstallationVmCondition $malformedRejected 'Unsupported, duplicate, missing, or contradictory VMX encoding declarations must fail closed.'
}

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
$readHelperStart = $source.IndexOf('function Read-InstallationVmxText', [StringComparison]::Ordinal)
$readHelperEnd = $source.IndexOf('function Assert-InstallationVmDiskBindings', $readHelperStart, [StringComparison]::Ordinal)
$readHelper = $source.Substring($readHelperStart, $readHelperEnd - $readHelperStart)
Assert-InstallationVmCondition ($readHelper.Contains('Get-InstallationVmxEncoding -Bytes $bytes') -and
    $source.Contains('Read-InstallationVmxText -Path $context.VmxPath')) `
    'VMX verification must decode the retained file bytes using its declared encoding.'
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
$providerStart = $source.LastIndexOf('Start-InstallationIsoVm -VmrunPath', [StringComparison]::Ordinal)
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
$providerStart = $source.LastIndexOf('Start-InstallationIsoVm -VmrunPath', [StringComparison]::Ordinal)
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
Assert-InstallationVmCondition ($ownershipSource.Contains("'installation-baseline', 'installation-boot', 'installation-resume')")) 'The immutable ownership publisher must admit the baseline record kind.'
Assert-InstallationVmCondition ($cleanupSource.Contains("'Confirm-AtlasoWorkstationVmInactive'")) 'The guarded VM stop helper must be available to the verification mode.'
$verifyMode = $source.IndexOf('if ($Mode -in @(''AdmitConsole'', ''Verify'', ''BootInstalled'', ''ResumeInstalled''))', [StringComparison]::Ordinal)
Assert-InstallationVmCondition ($verifyMode -ge 0) 'The harness must expose receipt-bound disk verification.'
$verifyOriginalRead = $source.IndexOf('Read-AtlasoTestVmSealedRecord -Context $context -Path $OriginalReceiptPath', $verifyMode, [StringComparison]::Ordinal)
$verifyBaselineRead = $source.IndexOf('Read-AtlasoTestVmSealedRecord -Context $context -Path $BaselineReceiptPath', $verifyMode, [StringComparison]::Ordinal)
$verifyStop = $source.IndexOf('Confirm-AtlasoWorkstationVmInactive -VmrunPath', $verifyMode, [StringComparison]::Ordinal)
$verifyCompare = $source.IndexOf('Assert-InstallationDiskUnchanged -Disk', $verifyMode, [StringComparison]::Ordinal)
Assert-InstallationVmCondition ($verifyOriginalRead -gt $verifyMode -and $verifyBaselineRead -gt $verifyOriginalRead -and $verifyStop -gt $verifyBaselineRead -and $verifyCompare -gt $verifyStop) 'Verification must validate both bound receipts before stopping the VM and compare only after stop.'
Assert-InstallationVmCondition ($source.Contains("`$roles = @('unselected')") -and $source.Contains('if ($VerifyTarget) { $roles += ''target'' }')) 'Verification must always check the unselected disk and optionally check the target for cancellation.'
Assert-InstallationVmCondition ($source.Contains("Invoke-AtlasoBoundedProcess -FilePath `$QemuImg -ArgumentList @('info', '--output=json', `$Path)")) 'qemu-img metadata inspection must use the existing bounded process helper.'
Assert-InstallationVmCondition ($source.Contains("[ValidateSet('Create', 'AdmitConsole', 'Verify', 'BootInstalled', 'ResumeInstalled', 'Cleanup')]") -and
    $source.Contains('Console admission requires an enabled task-owned VM receipt context.')) `
    'AdmitConsole must be an explicit task-owned mode.'
$admitConsoleBranches = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.IfStatementAst] -and
    $node.Extent.Text.StartsWith("if (`$Mode -eq 'AdmitConsole')", [StringComparison]::Ordinal) -and
    $node.Extent.Text.Contains('SerialPipePath = $serialPath')
}, $true))
Assert-InstallationVmCondition ($admitConsoleBranches.Count -eq 1) 'Expected one dedicated read-only console-admission result branch.'
$admitConsoleSource = $admitConsoleBranches[0].Extent.Text
$admitSourceCheck = $admitConsoleSource.IndexOf('Assert-AtlasoTestVmCheckoutSource -Context $context', [StringComparison]::Ordinal)
$admitVmConfigCheck = $admitConsoleSource.IndexOf('Read-InstallationRunningVmxText', [StringComparison]::Ordinal)
$admitConsoleBindingCheck = $admitConsoleSource.IndexOf('Assert-InstallationConsoleBindings', [StringComparison]::Ordinal)
$admitRunningCheck = $admitConsoleSource.IndexOf('Assert-InstallationVmRunning', [StringComparison]::Ordinal)
Assert-InstallationVmCondition ($admitSourceCheck -ge 0 -and $admitVmConfigCheck -gt $admitSourceCheck -and
    $admitConsoleBindingCheck -gt $admitVmConfigCheck -and
    $admitRunningCheck -gt $admitConsoleBindingCheck) `
    'Console admission must revalidate exact source, VMX configuration, isolation, and running registration before returning selectors.'
Assert-InstallationVmCondition ($source.Contains('AdmitConsole requires the initial connected installation ISO.')) `
    'The initial installer console admission must reject installed-boot receipt selectors.'
foreach ($forbiddenAdmissionAction in @(
        'Confirm-AtlasoWorkstationVmInactive', 'Assert-InstallationDiskUnchanged', 'Publish-AtlasoTestVmOwnershipRecord',
        'Start-InstallationIsoVm', 'ShouldProcess', 'QemuImg', 'LogicalContentsUnchanged', 'VerifiedRoles'
    )) {
    Assert-InstallationVmCondition (-not $admitConsoleSource.Contains($forbiddenAdmissionAction)) `
        "Console admission must not perform verification, mutation, receipt publication, or expose a disk-content claim ($forbiddenAdmissionAction)."
}
$runningVmxReader = Get-InstallationVmFunctionText -SourceAst $ast -Name 'Read-InstallationRunningVmxText'
$runningVmxAdmission = Get-InstallationVmFunctionText -SourceAst $ast -Name 'Assert-InstallationVmRunning'
$vncConsumer = Get-InstallationVmFunctionText -SourceAst $driverAst -Name 'Invoke-InstallationVncCredential'
$sdkPreparation = $vncConsumer.IndexOf('Get-AtlasoOnePasswordCredentialPair', [StringComparison]::Ordinal)
$sourceGuard = $vncConsumer.IndexOf('New-AtlasoCertificateInspectorSnapshot', [StringComparison]::Ordinal)
$runtimeGuard = $vncConsumer.IndexOf('Protect-AtlasoCertificatePythonRuntime', [StringComparison]::Ordinal)
$secretSubmission = $vncConsumer.IndexOf('Send-InstallationConsoleSecret', [StringComparison]::Ordinal)
Assert-InstallationVmCondition ($sdkPreparation -ge 0 -and $sourceGuard -gt $sdkPreparation -and
    $runtimeGuard -gt $sdkPreparation -and $secretSubmission -gt $sourceGuard -and $secretSubmission -gt $runtimeGuard) `
    'SDK marker publication must complete before read-only ancestor pins, while VNC source/runtime admission must precede secret submission.'
$consoleDiskAdmission = Get-InstallationVmFunctionText -SourceAst $ast -Name 'Assert-InstallationConsoleDiskIdentities'
Assert-InstallationVmCondition ($runningVmxReader.Contains('[IO.FileShare]::ReadWrite') -and $runningVmxReader.Contains('SHA256') -and
    $runningVmxReader.Contains('ExpectedIdentity')) 'Running console admission must read a stable VMX snapshot without blocking provider writes or accepting replacement.'
Assert-InstallationVmCondition ($runningVmxAdmission.Contains("@('-T', 'ws', 'list')") -and
    $runningVmxAdmission.Contains('ConvertFrom-AtlasoVmrunListOutput') -and $runningVmxAdmission.Contains('ExpectedIdentity')) `
    'Console admission must prove the exact VMX identity appears once in checked Workstation running inventory.'
& {
    param([string]$TargetPath, [string]$OtherPath)
    <#
    .SYNOPSIS
    Return synthetic multiline provider stdout without starting a process.
    .PARAMETER FilePath
    Unused public fixture executable pathname.
    .PARAMETER ArgumentList
    Exact expected inventory arguments.
    .PARAMETER TimeoutSeconds
    Required bounded inventory deadline.
    .PARAMETER Action
    Public operation description.
    #>
    function Invoke-AtlasoBoundedProcess {
        param([string]$FilePath, [string[]]$ArgumentList, [int]$TimeoutSeconds, [string]$Action)
        if (($ArgumentList -join ' ') -cne '-T ws list' -or $TimeoutSeconds -ne 30 -or -not $FilePath -or -not $Action) {
            throw 'Running inventory lost its bounded provider contract.'
        }
        return $inventory
    }
    <#
    .SYNOPSIS
    Model the shared parser's line-array boundary using existing read-only fixture files.
    .PARAMETER Output
    Individually split provider output lines; VMX file validation belongs to the shared parser tests.
    #>
    function ConvertFrom-AtlasoVmrunListOutput {
        param([string[]]$Output)
        if ($Output.Count -lt 2 -or $Output[0] -cnotmatch '^Total running VMs: [12]$' -or
            @($Output | Where-Object { $_ -match "[`r`n]" }).Count) {
            throw 'The inventory parser requires separate stdout lines.'
        }
        return @($Output | Select-Object -Skip 1 | Where-Object { $_ })
    }
    $identity = [Atlaso.WorkstationFileIdentity]::Get($TargetPath)
    foreach ($newline in @("`n", "`r`n")) {
        $inventory = @('Total running VMs: 2', $OtherPath, $TargetPath, '') -join $newline
        Assert-InstallationVmRunning -VmrunPath 'synthetic-vmrun.exe' -VmxPath $TargetPath -ExpectedIdentity $identity
    }
    foreach ($lines in @(
            @('Total running VMs: 1', $OtherPath),
            @('Total running VMs: 2', $TargetPath, $TargetPath)
        )) {
        $inventory = $lines -join "`r`n"
        $rejected = $false
        try { Assert-InstallationVmRunning -VmrunPath 'synthetic-vmrun.exe' -VmxPath $TargetPath -ExpectedIdentity $identity }
        catch { $rejected = $true }
        if (-not $rejected) { throw 'Ambiguous or absent receipt-bound running VM was admitted.' }
    }
} $harnessPath $consoleDriverPath
Assert-InstallationVmCondition (-not $consoleDiskAdmission.Contains('Assert-InstallationDiskUnchanged') -and
    -not $consoleDiskAdmission.Contains('Invoke-AtlasoBoundedProcess')) `
    'Console disk admission may pin receipt-bound file identities but must never compare or inspect disk contents.'

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
    public static Task RawBytes(NamedPipeClientStream pipe, byte[] bytes)
    {
        return Task.Run(async () =>
        {
            using var cancel = new CancellationTokenSource(5000);
            try
            {
                await pipe.WriteAsync(bytes, 0, bytes.Length, cancel.Token);
                await pipe.FlushAsync(cancel.Token);
            }
            catch { pipe.Dispose(); throw; }
        });
    }

    public static Task CursorProbe(NamedPipeClientStream pipe, string[] fragments, string expectedReply, string prompt)
    {
        return Task.Run(async () =>
        {
            using var cancel = new CancellationTokenSource(5000);
            var reply = new byte[32];
            try
            {
                await Start(pipe, fragments);
                int length = Encoding.ASCII.GetByteCount(expectedReply);
                await pipe.ReadExactlyAsync(reply.AsMemory(0, length), cancel.Token);
                if (Encoding.ASCII.GetString(reply, 0, length) != expectedReply)
                    throw new InvalidOperationException("The fixed cursor-position reply differs.");
                var bytes = Encoding.ASCII.GetBytes(prompt);
                try { await pipe.WriteAsync(bytes, 0, bytes.Length, cancel.Token); await pipe.FlushAsync(cancel.Token); }
                finally { Array.Clear(bytes, 0, bytes.Length); }
            }
            catch { pipe.Dispose(); throw; }
            finally { Array.Clear(reply, 0, reply.Length); }
        });
    }

    public static Task NativeSizeProbe(NamedPipeClientStream pipe, string[] fragments, int repetitions, string prompt)
    {
        return Task.Run(async () =>
        {
            using var cancel = new CancellationTokenSource(5000);
            var reply = new byte[8];
            try
            {
                for (int count = 0; count < repetitions; count++)
                {
                    await Start(pipe, fragments);
                    await pipe.ReadExactlyAsync(reply, cancel.Token);
                    if (Encoding.ASCII.GetString(reply) != "\x1b[25;80R")
                        throw new InvalidOperationException("The fixed native terminal-size reply differs.");
                }
                var bytes = Encoding.ASCII.GetBytes(prompt);
                try { await pipe.WriteAsync(bytes, 0, bytes.Length, cancel.Token); await pipe.FlushAsync(cancel.Token); }
                finally { Array.Clear(bytes, 0, bytes.Length); }
            }
            catch { pipe.Dispose(); throw; }
            finally { Array.Clear(reply, 0, reply.Length); }
        });
    }

    public static Task NativeProbeFlood(NamedPipeClientStream pipe, string probes)
    {
        return Task.Run(async () =>
        {
            using var cancel = new CancellationTokenSource(5000);
            var replies = new byte[64 * 8];
            try
            {
                await Start(pipe, new[] { probes });
                await pipe.ReadExactlyAsync(replies, cancel.Token);
            }
            catch { pipe.Dispose(); throw; }
            finally { Array.Clear(replies, 0, replies.Length); }
        });
    }

    public static Task Start(NamedPipeClientStream pipe, string[] fragments)
    {
        return Start(pipe, fragments, null);
    }

    public static Task Start(NamedPipeClientStream pipe, string[] fragments, ManualResetEventSlim ready)
    {
        return Task.Run(() =>
        {
            ready?.Set();
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

$knownStageFixture = @(Get-InstallationProvisioningStages -Text ([string]::Join("`n", @(
    'log_step "PublicKnownStage"', 'log_step "PublicKnownStage"',
    'log_step "Private $SECRET"', 'log_step "Unknown `expression`"'))))
Assert-InstallationVmCondition ($knownStageFixture.Count -eq 1 -and $knownStageFixture[0] -ceq 'PublicKnownStage') `
    'Provisioning diagnostics must admit only fixed source labels and reject interpolation.'

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
$nativeModeRows = @(Get-InstallationConsoleDiskOptions -Text ("`e[?1049h`e[1;25r`e[4l`e[?1h`e[?25l`e[H" +
    "`e[5;6H" + [char]14 + 'lqqqqk' + [char]15 + 'Select a disk' +
    "`e[11;22H" + [char]15 + 'VMware Virtual S - 64 GiB @ /dev/sdb' +
    "`e[12;22H" + [char]15 + 'VMware Virtual S - 4 GiB @ /dev/sda'))
Assert-InstallationVmCondition ($nativeModeRows.Count -eq 2 -and $nativeModeRows[0].DiskPath -ceq '/dev/sdb' -and
    $nativeModeRows[0].SizeGiB -eq 64 -and $nativeModeRows[1].DiskPath -ceq '/dev/sda' -and
    $nativeModeRows[1].SizeGiB -eq 4) 'Native overwrite reset and character-set shifts must preserve both visible disk rows.'
$erasedRows = @(Get-InstallationConsoleDiskOptions -Text ("`e[11;1H32 GiB @ /dev/sdc`r`e[2K" +
    "4 GiB @ /dev/sda`e[1B`r64 GiB @ /dev/sdb"))
Assert-InstallationVmCondition ($erasedRows.Count -eq 2 -and $erasedRows[0].DiskPath -ceq '/dev/sda' -and
    $erasedRows[1].DiskPath -ceq '/dev/sdb') 'Erased stale rows must never remain selectable.'
$eraseFromCursor = @(ConvertFrom-InstallationConsoleFrame -Text ("topline`r`nmidline`r`nendline`e[2;4H`e[J"))
Assert-InstallationVmCondition ($eraseFromCursor[0] -ceq 'topline' -and $eraseFromCursor[1] -ceq 'mid' -and
    $eraseFromCursor[2] -ceq '') 'CSI J mode 0 must erase from the cursor through the rest of the screen.'
$eraseThroughCursor = @(ConvertFrom-InstallationConsoleFrame -Text ("topline`r`nmidline`r`nendline`e[2;4H`e[1J"))
Assert-InstallationVmCondition ($eraseThroughCursor[0] -ceq '' -and $eraseThroughCursor[1] -ceq '    ine' -and
    $eraseThroughCursor[2] -ceq 'endline') 'CSI J mode 1 must erase the screen through the cursor.'
$eraseLineAfter = @(ConvertFrom-InstallationConsoleFrame -Text ("midline`e[1;4H`e[K"))
Assert-InstallationVmCondition ($eraseLineAfter[0] -ceq 'mid') 'CSI K mode 0 must erase from the cursor to the end of its line.'
$eraseLineBefore = @(ConvertFrom-InstallationConsoleFrame -Text ("midline`e[1;4H`e[1K"))
Assert-InstallationVmCondition ($eraseLineBefore[0] -ceq '    ine') 'CSI K mode 1 must erase from the start of its line through the cursor.'
$wrappedFrame = @(ConvertFrom-InstallationConsoleFrame -Text ("`e[1;80HAB"))
Assert-InstallationVmCondition ($wrappedFrame[0].Length -eq 80 -and $wrappedFrame[0][79] -ceq 'A' -and
    $wrappedFrame[1].StartsWith('B', [StringComparison]::Ordinal)) 'Printable text after the last column must wrap to the next row without overwriting the prior cell.'

$unexpectedDiskRows = @(Get-InstallationConsoleDiskOptions -Text (
    "`e[11;1H0 GiB @ /dev/fd0`e[12;1H64 GiB @ /dev/sda`e[13;1H4 GiB @ /dev/sdb"))
Assert-InstallationVmCondition ($unexpectedDiskRows.Count -eq 3 -and
    $unexpectedDiskRows[0].DiskPath -ceq '/dev/fd0' -and $unexpectedDiskRows[1].Index -eq 1) `
    'Unexpected native devices must retain their menu index and never be silently skipped.'

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

$jsonStream = [IO.MemoryStream]::new()
$jsonFixture = 'Public-"quoted"-\-fixture-42'
$jsonSecure = New-InstallationTestSecureString -Text $jsonFixture
try {
    Send-InstallationConsoleSecret -Pipe $jsonStream -Value $jsonSecure -JsonRequest
    $decoded = [Text.Encoding]::ASCII.GetString($jsonStream.ToArray()) | ConvertFrom-Json
    Assert-InstallationVmCondition ($decoded.password -ceq $jsonFixture -and $jsonStream.ToArray()[-1] -eq 10) `
        'VNC stdin encoding must preserve printable ASCII quotes and backslashes without using arguments or files.'
}
finally { $jsonSecure.Dispose(); $jsonStream.Dispose() }

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
        "Select a disk`r`n0 GiB @ /dev/fd0`r`n64 GiB @ /dev/sda`r`n4 GiB @ /dev/sdb`r`n"))
    try {
        $null = Wait-InstallationConsoleState -Pipe $pipePair.Server -Pattern 'Select a disk' `
            -Deadline ([DateTimeOffset]::UtcNow.AddSeconds(5)) -ReadDiskSelection
    }
    catch {
        $mismatchedDiskRejected = $_.Exception.Message -ceq 'Native disk menu does not match the receipt-bound 64 GiB target and 4 GiB unselected fixture.'
    }
    Assert-InstallationVmCondition $mismatchedDiskRejected 'Unexpected native disk rows must fail closed before selection.'
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
$failureReady = $null
try {
    $pipePair = New-InstallationTestPipePair -Name ('Atlaso-Test-' + [guid]::NewGuid().ToString('N'))
    $failureReady = [Threading.ManualResetEventSlim]::new()
    $failureSender = [AtlasoInstallationPipeTestWriter]::Start($pipePair.Client,
        [string[]]@("Traceback (most recent call last):`nPublicSyntheticSensitiveFixture"), $failureReady)
    # Start the writer before the shorter outer deadline without waiting for
    # pipe drain, which requires the concurrent server read.
    Assert-InstallationVmCondition ($failureReady.Wait(5000)) 'Public failure fixture writer did not start.'
    $failureObserved = $false
    try {
        Wait-InstallationConsoleState -Pipe $pipePair.Server -Pattern 'Select a disk' -Deadline ([DateTimeOffset]::UtcNow.AddSeconds(1))
    }
    catch { $failureObserved = $_.Exception.Message -ceq 'The installer reported a Python failure before the expected console state.' }
    Assert-InstallationVmCondition $failureObserved 'Python console failure did not fail promptly with only its public classification.'
    Assert-InstallationVmCondition $failureSender.Wait(5000) 'Public failure fixture writer did not complete.'
}
finally {
    if ($pipePair) { Close-InstallationTestPipePair -Pair $pipePair }
    if ($failureReady) { $failureReady.Dispose() }
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

$pipePair = $null
$capacityDiagnostics = [Collections.Generic.List[object]]::new()
try {
    $pipePair = New-InstallationTestPipePair -Name ('Atlaso-Test-' + [guid]::NewGuid().ToString('N'))
    $failureSender = [AtlasoInstallationPipeTestWriter]::Start($pipePair.Client, [string[]]@(
        "==> Atlaso appliance: PublicKnownStage`n==> Atlaso appliance: PublicSyntheticSensitiveFixture`nError(1011): Failed to synchronize cache PublicSyntheticSensitiveFixture`nTraceback (most recent call last):`n  File `"/PublicSyntheticSensitiveFixture/installer.py`", line 205, in configure_console`n",
        "ValueError: default installation requires a disk of at least 64 GiB; selected /dev/sda has 4294967296 bytes`nPublicSyntheticSensitiveFixture`n"))
    $failureObserved = $false
    try {
        Wait-InstallationConsoleState -Pipe $pipePair.Server -Pattern 'Erase selected disks?' `
            -Deadline ([DateTimeOffset]::UtcNow.AddSeconds(5)) -KnownProvisioningStages $knownStageFixture 6>&1 | ForEach-Object { $capacityDiagnostics.Add($_) }
    }
    catch { $failureObserved = $_.Exception.Message -ceq 'The installer reported a Python failure before the expected console state. Public location: ValueError; installer.py:205.' }
    Assert-InstallationVmCondition $failureObserved 'Capacity refusal must retain the safe failure classification.'
    Assert-InstallationVmCondition ($capacityDiagnostics.Count -eq 4 -and
        [string]$capacityDiagnostics[0] -ceq 'Public provisioning stage: PublicKnownStage' -and
        [string]$capacityDiagnostics[1] -ceq 'Public package-manager error codes: 1011' -and
        [string]$capacityDiagnostics[2] -ceq 'Public package-manager category: repository-metadata' -and
        [string]$capacityDiagnostics[3] -ceq 'Public capacity refusal: /dev/sda, 4294967296 bytes; requires 68719476736 bytes.') `
        'Failure diagnostics must expose only fixed categories, numeric codes and the selected device capacity.'
    Assert-InstallationVmCondition $failureSender.Wait(5000) 'Capacity fixture writer did not complete.'
}
finally {
    if ($pipePair) { Close-InstallationTestPipePair -Pair $pipePair }
}

foreach ($publicFailure in @(
    @{ Text = 'Installation cancelled. PublicSyntheticSensitiveFixture'; Expected = 'The installer cancelled before the expected console state.' },
    @{ Text = 'Atlaso installation cancelled or failed (status 1). PublicSyntheticSensitiveFixture'; Expected = 'The installation launcher reported failure before the expected console state.' },
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

$stagePair = $null
try {
    $stagePair = New-InstallationTestPipePair -Name ('Atlaso-Test-' + [guid]::NewGuid().ToString('N'))
    $stageSender = [AtlasoInstallationPipeTestWriter]::Start($stagePair.Client, [string[]]@(
        "==> Atlaso appliance: KnownA`r`n", "private-console-fixture`r`n",
        "==> Atlaso appliance: KnownB`r`n", "==> Atlaso appliance: KnownA`r`nFixtureDone"))
    $stageReports = @(Wait-InstallationConsoleState -Pipe $stagePair.Server -Pattern 'FixtureDone' `
        -Deadline ([DateTimeOffset]::UtcNow.AddSeconds(5)) -KnownProvisioningStages @('KnownA', 'KnownB') 6>&1)
    Assert-InstallationVmCondition ($stageReports.Count -eq 2 -and
        [string]$stageReports[0] -ceq 'Public provisioning stage: KnownA' -and
        [string]$stageReports[1] -ceq 'Public provisioning stage: KnownB') `
        'Provisioning progress must expose only admitted labels, once each, without private console text.'
    Assert-InstallationVmCondition ($stageSender.Wait(5000)) 'Provisioning-stage fixture writer did not finish.'
}
finally { if ($stagePair) { Close-InstallationTestPipePair -Pair $stagePair } }

$bootSource = ($lines -join "`n") + "`n"
$bootText = ConvertTo-InstallationDiskBootConfiguration -Text $bootSource
Assert-InstallationVmCondition ($bootText.Contains('sata0:0.present = "FALSE"') -and $bootText.Contains('sata0:0.startConnected = "FALSE"')) 'Installed boot must disconnect the CD drive.'
Assert-InstallationVmCondition ($bootText.Replace('sata0:0.present = "FALSE"', 'sata0:0.present = "TRUE"').Replace('sata0:0.startConnected = "FALSE"', 'sata0:0.startConnected = "TRUE"') -ceq $bootSource) 'Installed boot must preserve all other VMX bytes.'
foreach ($bad in @(
    $bootSource.Replace('ethernet0.present = "FALSE"', 'ethernet0.present = "TRUE"'),
    ($bootSource + 'ethernet1.present = "TRUE"'),
    ($bootSource + 'scsi0:2.present = "TRUE"'),
    $bootSource.Replace('firmware = "efi"', 'firmware = "bios"'),
    $bootSource.Replace('serial0.fileType = "pipe"', 'serial0.fileType = "file"'),
    ($bootSource + 'sata0:0.present = "TRUE"')
)) {
    $refused = $false
    try { $null = ConvertTo-InstallationDiskBootConfiguration -Text $bad } catch { $refused = $true }
    Assert-InstallationVmCondition $refused 'Installed boot must refuse unsafe or duplicate critical configuration.'
}
$bootPublish = $source.IndexOf('-Record $transition -Kind installation-boot', [StringComparison]::Ordinal)
$bootWrite = $source.IndexOf('$writer.Write($after', $bootPublish, [StringComparison]::Ordinal)
Assert-InstallationVmCondition ($bootPublish -gt $verifyCompare -and $bootWrite -gt $bootPublish) 'Original/baseline verification and transition publication must precede VMX mutation.'
Write-Host 'Installation disk-boot transition regression tests passed.'
$resumePublish = $source.IndexOf('-Record $resume -Kind installation-resume', [StringComparison]::Ordinal)
$resumeStart = $source.IndexOf('Start-InstallationIsoVm -VmrunPath', $resumePublish, [StringComparison]::Ordinal)
Assert-InstallationVmCondition ($resumePublish -gt $verifyCompare -and $resumeStart -gt $resumePublish) 'Installed resume must compare disks and publish its immutable operation receipt before starting the VM.'
$resumeBranches = @($ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.IfStatementAst] -and $node.Extent.Text.StartsWith("if (`$Mode -in @('AdmitConsole', 'Verify', 'BootInstalled', 'ResumeInstalled'))", [StringComparison]::Ordinal)
}, $true))
Assert-InstallationVmCondition ($resumeBranches.Count -eq 1) 'Expected exactly one shared installed-VM admission branch.'
$missingResumeReceiptRefused = $false
try {
    & {
        param([string]$Branch)
        $Mode = 'ResumeInstalled'
        $BootReceiptPath = ''
        $BootReceiptSha256 = ''
        $context = [pscustomobject]@{}
        & ([scriptblock]::Create($Branch))
    } $resumeBranches[0].Extent.Text
} catch {
    $missingResumeReceiptRefused = $_.Exception.Message -ceq 'ResumeInstalled requires the independently preserved installed-boot receipt and SHA-256.'
}
Assert-InstallationVmCondition $missingResumeReceiptRefused 'Resume must refuse a missing original boot receipt before ownership reads or provider mutation.'

$installedLogin = $driverSource.IndexOf("foreach (`$account in @('root', 'admin'))", [StringComparison]::Ordinal)
$shellWait = $driverSource.IndexOf('-Pattern $accountProbe.Prompt', $installedLogin, [StringComparison]::Ordinal)
$probeSend = $driverSource.IndexOf('Send-InstallationConsoleText -Pipe $pipe -Text ($accountProbe.Command', $installedLogin, [StringComparison]::Ordinal)
Assert-InstallationVmCondition ($installedLogin -ge 0 -and $shellWait -gt $installedLogin -and $probeSend -gt $shellWait) 'Installed shell probes must wait for login to finish before sending commands.'

$bootPair = $null
try {
    $bootPair = New-InstallationTestPipePair -Name ('Atlaso-Test-' + [guid]::NewGuid().ToString('N'))
    $bootFragmentSender = [AtlasoInstallationPipeTestWriter]::Start($bootPair.Client, [string[]]@(
        "GNU GRUB`nLinux version private-fixture-details`n", "unknown-runtime-fixture`natlaso login:"))
    $bootStageEvents = @(Wait-InstallationConsoleState -Pipe $bootPair.Server -Pattern 'login:' -Deadline ([DateTimeOffset]::UtcNow.AddSeconds(5)) -ReadBootProgress 6>&1)
    $reported = $bootStageEvents | Out-String
    Assert-InstallationVmCondition ($reported.Contains('Public installed boot stage: grub-console') -and $reported.Contains('Public installed boot stage: linux-kernel')) 'Boot diagnostics must recognize fixed public stages.'
    Assert-InstallationVmCondition (-not $reported.Contains('private-fixture-details') -and -not $reported.Contains('unknown-runtime-fixture')) 'Boot diagnostics must never report unknown console content.'
    Assert-InstallationVmCondition ($bootFragmentSender.Wait(5000)) 'The boot-stage fixture writer did not finish.'
}
finally { if ($bootPair) { Close-InstallationTestPipePair -Pair $bootPair } }

. ([scriptblock]::Create((Get-InstallationVmFunctionText -SourceAst $driverAst -Name 'Get-InstallationAccountProbe')))
$loginStagePair = $null
try {
    $loginStagePair = New-InstallationTestPipePair -Name ('Atlaso-Test-' + [guid]::NewGuid().ToString('N'))
    $loginStageSender = [AtlasoInstallationPipeTestWriter]::Start($loginStagePair.Client, [string[]]@(
        "Last login: private-fixture-host private-fixture-secret`nYou are required to change your pass",
        "word immediately private-fixture-secret`nCurrent password:`nPowerShell 7.5`nPS /private-fixture-path> `nlogin: timed out after 60 seconds`nPAM failure: Critical error - immediate abort`nbash-5.3# FixtureDone"))
    $loginEvents = @(Wait-InstallationConsoleState -Pipe $loginStagePair.Server -Pattern 'FixtureDone' -Deadline ([DateTimeOffset]::UtcNow.AddSeconds(5)) -ReadLoginProgress 6>&1)
    $loginReported = $loginEvents | Out-String
    foreach ($expectedCategory in @('session-last-login', 'password-change-required', 'current-password-request', 'powershell-startup', 'powershell-prompt', 'login-prompt', 'login-timeout', 'pam-failure', 'pam-critical-error', 'bash-fallback-prompt-candidate')) {
        Assert-InstallationVmCondition ($loginReported.Contains('Public installed login stage: ' + $expectedCategory)) 'Login diagnostics must recognize fixed fragmented PAM and shell categories.'
    }
    Assert-InstallationVmCondition (-not $loginReported.Contains('private-fixture')) 'Login diagnostics must never expose console credentials, paths, or host details.'
    Assert-InstallationVmCondition ($loginStageSender.Wait(5000)) 'The fixed login-stage fixture writer did not finish.'
}
finally { if ($loginStagePair) { Close-InstallationTestPipePair -Pair $loginStagePair } }
foreach ($activityFixture in @(
    @{ Text = ''; Category = 'no-console-activity' },
    @{ Text = 'private-unclassified-fixture'; Category = 'unmatched-console-activity' },
    @{ Text = "`r`n`t `r`n"; Category = 'control-only-console-activity' }
)) {
    $activityPair = $null
    try {
        $activityPair = New-InstallationTestPipePair -Name ('Atlaso-Test-' + [guid]::NewGuid().ToString('N'))
        if ($activityFixture.Text) {
            $activitySender = [AtlasoInstallationPipeTestWriter]::Start($activityPair.Client, [string[]]@($activityFixture.Text))
        }
        $activityEvents = @(& {
            try { Wait-InstallationConsoleState -Pipe $activityPair.Server -Pattern 'NeverSentPublicPrompt' -Deadline ([DateTimeOffset]::UtcNow.AddMilliseconds(500)) -ReadLoginProgress }
            catch { if ($_.Exception.Message -cne 'The installer did not reach the expected public console state before its deadline.') { throw } }
        } 6>&1) | Out-String
        $category = $activityFixture.Category
        Assert-InstallationVmCondition ($activityEvents.Contains('Public installed login deadline: ' + $category) -and -not $activityEvents.Contains('private-unclassified-fixture')) 'Login deadline diagnostics must distinguish activity without revealing any console contents.'
        if ($activityFixture.Text) { Assert-InstallationVmCondition ($activitySender.Wait(5000)) 'The activity fixture writer did not finish.' }
    }
    finally { if ($activityPair) { Close-InstallationTestPipePair -Pair $activityPair } }
}
$rootShellProbe = Get-InstallationAccountProbe -Account root
Write-Host 'Starting installation terminal-protocol pipe fixtures.'
Assert-InstallationVmCondition ($rootShellProbe.Prompt -ceq ' ]# ' -and $rootShellProbe.Command.Contains('id -u') -and -not $rootShellProbe.Command.Contains('ATLASO-LOGIN-OK')) 'Root readiness must accept the native Photon prompt while retaining a separate identity challenge.'
Assert-InstallationVmCondition ($rootShellProbe.EnterKey -ceq "`n") 'Bash command submission must retain its existing line-feed handling.'
foreach ($probeRepetitions in @(1, 2)) {
    $nativeProbePair = $null
    try {
        $nativeProbePair = New-InstallationTestPipePair -Name ('Atlaso-Test-' + [guid]::NewGuid().ToString('N'))
        $nativeProbeTask = [AtlasoInstallationPipeTestWriter]::NativeSizeProbe($nativeProbePair.Client,
            [string[]]@("`es`e[999;", "999H`e[", "6n`eu"), $probeRepetitions, '^[[25;80Rroot [ ~ ]# ')
        $nativeProbeEvents = @(Wait-InstallationConsoleState -Pipe $nativeProbePair.Server -Pattern $rootShellProbe.Prompt `
            -Deadline ([DateTimeOffset]::UtcNow.AddSeconds(5)) -ReadLoginProgress -ShellAccount root 6>&1)
        Assert-InstallationVmCondition ($nativeProbeTask.Wait(5000)) 'The native profile must receive each reply before emitting its shell prompt.'
        $nativeReplies = @($nativeProbeEvents | Where-Object { $_.ToString() -ceq 'Answered a proven cursor-position query.' })
        Assert-InstallationVmCondition ($nativeReplies.Count -eq $probeRepetitions) 'Fragmented native probes must receive exactly one reply each.'
    }
    finally { if ($nativeProbePair) { Close-InstallationTestPipePair -Pair $nativeProbePair } }
}
$probeFloodPair = $null
$bootProbePair = $null
try {
    $bootProbePair = New-InstallationTestPipePair -Name ('Atlaso-Test-' + [guid]::NewGuid().ToString('N'))
    $bootProbeTask = [AtlasoInstallationPipeTestWriter]::NativeSizeProbe($bootProbePair.Client,
        [string[]]@("`es`e[999;", "999H`e[", "6n`eu"), 1, 'Select a disk')
    $bootProbeEvents = @(Wait-InstallationConsoleState -Pipe $bootProbePair.Server -Pattern 'Select a disk' `
        -Deadline ([DateTimeOffset]::UtcNow.AddSeconds(5)) -ReadBootProgress 6>&1)
    Assert-InstallationVmCondition ($bootProbeTask.Wait(5000)) 'A startup profile must receive its proven reply before displaying disk selection.'
    Assert-InstallationVmCondition (@($bootProbeEvents | Where-Object {
        $_.ToString() -ceq 'Answered a proven cursor-position query.'
    }).Count -eq 1) 'Boot-time cursor queries must reuse the same proven-coordinate response boundary.'
}
finally { if ($bootProbePair) { Close-InstallationTestPipePair -Pair $bootProbePair } }
try {
    $probeFloodPair = New-InstallationTestPipePair -Name ('Atlaso-Test-' + [guid]::NewGuid().ToString('N'))
    $probeFloodSender = [AtlasoInstallationPipeTestWriter]::NativeProbeFlood($probeFloodPair.Client, ("`es`e[999;999H`e[6n`eu" * 65))
    $probeFloodRefused = $false
    $null = @(& {
        try { Wait-InstallationConsoleState -Pipe $probeFloodPair.Server -Pattern 'NeverSentPublicPrompt' -Deadline ([DateTimeOffset]::UtcNow.AddSeconds(5)) -ReadLoginProgress }
        catch { $script:probeFloodRefused = $_.Exception.Message -ceq 'Installed console exceeded its bounded cursor-position queries.' }
    } 6>&1)
    Assert-InstallationVmCondition $probeFloodRefused 'Excessive terminal probes must fail within the fixed per-pipe query bound.'
    Assert-InstallationVmCondition ($probeFloodSender.Wait(5000)) 'The bounded probe-flood fixture writer did not finish.'
}
finally { if ($probeFloodPair) { Close-InstallationTestPipePair -Pair $probeFloodPair } }
$unrelatedQueryPair = $null
try {
    $unrelatedQueryPair = New-InstallationTestPipePair -Name ('Atlaso-Test-' + [guid]::NewGuid().ToString('N'))
    $privateQueryFixture = 'private-fixture-cursor-query-content'
    $unrelatedQuerySender = [AtlasoInstallationPipeTestWriter]::Start($unrelatedQueryPair.Client, [string[]]@(
        "`e[", "6", "n$privateQueryFixture`e[", "6nFixtureDone"
    ))
    $unrelatedQueryEvents = @(Wait-InstallationConsoleState -Pipe $unrelatedQueryPair.Server -Pattern 'FixtureDone' `
        -Deadline ([DateTimeOffset]::UtcNow.AddSeconds(5)) -ReadLoginProgress 6>&1)
    Assert-InstallationVmCondition ($unrelatedQuerySender.Wait(5000)) 'The unrelated query fixture writer did not finish.'
    $cursorQueryCategory = @($unrelatedQueryEvents | Where-Object {
        $_.ToString() -ceq 'Public installed login stage: cursor-position-query'
    })
    Assert-InstallationVmCondition ($cursorQueryCategory.Count -eq 1) 'Repeated fragmented cursor queries must report one fixed diagnostic category.'
    $unrelatedQueryOutput = $unrelatedQueryEvents | Out-String
    Assert-InstallationVmCondition (-not $unrelatedQueryOutput.Contains($privateQueryFixture)) 'Cursor-query diagnostics must never report private console content.'
    $unexpectedReply = [byte[]]::new(8)
    $replyDeadline = [Threading.CancellationTokenSource]::new(250)
    $noInventedReply = $false
    try { $null = $unrelatedQueryPair.Client.ReadAsync($unexpectedReply, 0, $unexpectedReply.Length, $replyDeadline.Token).GetAwaiter().GetResult() }
    catch [OperationCanceledException] { $noInventedReply = $true }
    finally { $replyDeadline.Dispose(); [Array]::Clear($unexpectedReply, 0, $unexpectedReply.Length) }
    Assert-InstallationVmCondition $noInventedReply 'An unrelated cursor query must not receive an invented screen position.'
}
finally { if ($unrelatedQueryPair) { Close-InstallationTestPipePair -Pair $unrelatedQueryPair } }
Write-Host 'Installation terminal-protocol pipe fixtures passed; starting cursor-state fixtures.'
$cursorState = @{}
$unknownPosition = @(ConvertFrom-InstallationConsoleFrame -Text "`e[6n" -CursorState $cursorState -CursorOnly)
Assert-InstallationVmCondition (-not $unknownPosition[0].Known) 'An initially unknown cursor must remain unanswered.'
Assert-InstallationVmCondition (-not ($cursorState.Values | Where-Object { $_ -is [string] -and $_.Contains('private') })) 'Cursor state must not retain terminal text.'
$anchoredPosition = @(ConvertFrom-InstallationConsoleFrame -Text "`e[7;11H`e[6n" -CursorState $cursorState -CursorOnly)
Assert-InstallationVmCondition ($anchoredPosition[-1].Known -and $anchoredPosition[-1].Row -eq 7 -and $anchoredPosition[-1].Column -eq 11) `
    'An absolute cursor anchor must permit an accurate generic position reply.'
$fragmentedState = @{}
$null = ConvertFrom-InstallationConsoleFrame -Text "`e[7;" -CursorState $fragmentedState -CursorOnly
$null = ConvertFrom-InstallationConsoleFrame -Text "11H`e[6" -CursorState $fragmentedState -CursorOnly
$fragmentedPosition = @(ConvertFrom-InstallationConsoleFrame -Text 'n' -CursorState $fragmentedState -CursorOnly)
Assert-InstallationVmCondition ($fragmentedPosition[0].Known -and $fragmentedPosition[0].Row -eq 7 -and $fragmentedPosition[0].Column -eq 11) `
    'CSI anchors and position queries must survive arbitrary read fragmentation.'
$savedState = @{}
$savedPositions = @(ConvertFrom-InstallationConsoleFrame -Text "`e[3;4H`es`e[25;80H`e[6n`eu`e[6n" -CursorState $savedState -CursorOnly)
Assert-InstallationVmCondition ($savedPositions.Count -eq 2 -and $savedPositions[0].Row -eq 25 -and $savedPositions[0].Column -eq 80 -and
    $savedPositions[1].Row -eq 3 -and $savedPositions[1].Column -eq 4) 'DSR replies must snapshot cursor coordinates before a trailing restore.'
$wrappedState = @{}
$wrapped = @(ConvertFrom-InstallationConsoleFrame -Text ("`e[1;80HX Y`e[6n".Replace(' ','')) -CursorState $wrappedState -CursorOnly)
Assert-InstallationVmCondition ($wrapped[0].Known -and $wrapped[0].Row -eq 2 -and $wrapped[0].Column -eq 2) 'Pending autowrap must advance the cursor only when the next printable character arrives.'
$convergedState = @{}
$converged = @(ConvertFrom-InstallationConsoleFrame -Text ("`r`n" * 25 + "`r`e[6n") -CursorState $convergedState -CursorOnly)
Assert-InstallationVmCondition ($converged[0].Known -and $converged[0].Row -eq 25 -and $converged[0].Column -eq 1) `
    'A full-screen run of line advances plus carriage return must converge the unknown starting row.'
$invalidState = @{}
$invalidated = @(ConvertFrom-InstallationConsoleFrame -Text "`e[?1049h`e[6n`e[10;20H`e[6n" -CursorState $invalidState -CursorOnly)
Assert-InstallationVmCondition (-not $invalidated[0].Known -and $invalidated[1].Known -and $invalidated[1].Row -eq 10 -and $invalidated[1].Column -eq 20) `
    'Unknown cursor modes must suppress replies until a new absolute anchor restores certainty.'
$originState = @{}
$originModes = @(ConvertFrom-InstallationConsoleFrame -Text "`e[?6h`e[5;9H`e[6n`e[?6l`e[6n" -CursorState $originState -CursorOnly)
Assert-InstallationVmCondition (-not $originModes[0].Known -and $originModes[1].Known -and
    $originModes[1].Row -eq 1 -and $originModes[1].Column -eq 1) 'Origin mode must invalidate positions until its default reset reanchors home.'
$marginState = @{}
$marginReset = @(ConvertFrom-InstallationConsoleFrame -Text "`e[2;24r`e[6n`e[r`e[6n" -CursorState $marginState -CursorOnly)
Assert-InstallationVmCondition (-not $marginReset[0].Known -and $marginReset[1].Known -and
    $marginReset[1].Row -eq 1 -and $marginReset[1].Column -eq 1) 'Nondefault scroll regions must suppress replies until full-screen margins reset.'
$harmlessModesState = @{}
$harmlessModes = @(ConvertFrom-InstallationConsoleFrame -Text "`e[?25l`e[?1h`e[?2004h`e=`e>`e[4;8H`e[6n" -CursorState $harmlessModesState -CursorOnly)
Assert-InstallationVmCondition ($harmlessModes[0].Known -and $harmlessModes[0].Row -eq 4 -and $harmlessModes[0].Column -eq 8) `
    'Visibility, application-cursor, bracketed-paste and keypad modes must preserve cursor certainty.'
$nativeShiftState = @{}
$null = ConvertFrom-InstallationConsoleFrame -Text "`e[4" -CursorState $nativeShiftState -CursorOnly
$nativeShiftPosition = @(ConvertFrom-InstallationConsoleFrame -Text ("l`e[8;80HX" + [char]14 + [char]15 + "Y`e[6n") `
    -CursorState $nativeShiftState -CursorOnly)
Assert-InstallationVmCondition ($nativeShiftPosition[0].Known -and $nativeShiftPosition[0].Row -eq 9 -and
    $nativeShiftPosition[0].Column -eq 2) 'Fragmented overwrite reset and nonmoving shifts must preserve pending autowrap.'
$unsupportedInsertState = @{}
$unsupportedInsertPosition = @(ConvertFrom-InstallationConsoleFrame -Text "`e[4h`e[4l`e[3;4H`e[6n" `
    -CursorState $unsupportedInsertState -CursorOnly)
Assert-InstallationVmCondition (-not $unsupportedInsertPosition[0].Known) `
    'A supported overwrite reset must not clear uncertainty from an unsupported insert-mode transition.'
$oscState = @{}
$null = ConvertFrom-InstallationConsoleFrame -Text "`e]0;private-fixture-title" -CursorState $oscState -CursorOnly
$oscStateText = $oscState | ConvertTo-Json -Compress
Assert-InstallationVmCondition ($oscState.ParserMode -eq 'String' -and -not $oscStateText.Contains('private-fixture-title')) `
    'Split OSC payloads must be discarded while only terminator bookkeeping persists.'
$null = ConvertFrom-InstallationConsoleFrame -Text "`a" -CursorState $oscState -CursorOnly
$queryBoundState = @{}
$null = ConvertFrom-InstallationConsoleFrame -Text ("`e[6n" * 64) -CursorState $queryBoundState -CursorOnly
$overLimitQuery = @(ConvertFrom-InstallationConsoleFrame -Text "`e[6n" -CursorState $queryBoundState -CursorOnly)
Assert-InstallationVmCondition ($overLimitQuery[0].Exceeded -and $queryBoundState.QueryCount -eq 65) `
    'Cursor-query limits must persist across parser calls without storing terminal text.'
$crossWaitPair = $null
Write-Host 'Installation cursor-state fixtures passed; starting cross-wait pipe fixture.'
try {
    $crossWaitPair = New-InstallationTestPipePair -Name ('Atlaso-Test-' + [guid]::NewGuid().ToString('N'))
    $crossWaitState = @{}
    $anchorWriter = [AtlasoInstallationPipeTestWriter]::Start($crossWaitPair.Client, [string[]]@("`e[7;11HAnchorReady"))
    Wait-InstallationConsoleState -Pipe $crossWaitPair.Server -Pattern 'AnchorReady' -Deadline ([DateTimeOffset]::UtcNow.AddSeconds(5)) -ReadLoginProgress -CursorState $crossWaitState
    Assert-InstallationVmCondition ($anchorWriter.Wait(5000)) 'The cross-wait anchor fixture did not finish.'
    $queryWriter = [AtlasoInstallationPipeTestWriter]::CursorProbe($crossWaitPair.Client, [string[]]@("`e[6", 'n'), "`e[7;22R", 'CrossWaitDone')
    Wait-InstallationConsoleState -Pipe $crossWaitPair.Server -Pattern 'CrossWaitDone' -Deadline ([DateTimeOffset]::UtcNow.AddSeconds(5)) -ReadLoginProgress -CursorState $crossWaitState
    Assert-InstallationVmCondition ($queryWriter.Wait(5000)) 'Cursor state must persist across login Wait calls and answer an accurate position.'
}
finally { if ($crossWaitPair) { Close-InstallationTestPipePair -Pair $crossWaitPair } }
foreach ($fragmentPrompt in @($false, $true)) {
    $adminReadyPair = $null
    try {
        $adminReadyPair = New-InstallationTestPipePair -Name ('Atlaso-Test-' + [guid]::NewGuid().ToString('N'))
        $adminReadyState = @{}
        $readyFragments = if ($fragmentPrompt) {
            [string[]]@("`e[7;11HP", "S /fixture> `e[6", 'n')
        } else { [string[]]@("`e[7;11HPS /fixture> `e[6n") }
        $adminReadyWriter = [AtlasoInstallationPipeTestWriter]::CursorProbe(
            $adminReadyPair.Client, $readyFragments, "`e[7;24R", '')
        Wait-InstallationConsoleState -Pipe $adminReadyPair.Server -Pattern 'PS ' `
            -Deadline ([DateTimeOffset]::UtcNow.AddSeconds(5)) -ReadLoginProgress -ShellAccount admin -CursorState $adminReadyState
        Assert-InstallationVmCondition ($adminReadyWriter.Wait(5000)) `
            'Administrator readiness must answer the post-prompt cursor request before permitting a queued challenge.'
    }
    finally { if ($adminReadyPair) { Close-InstallationTestPipePair -Pair $adminReadyPair } }
}
Write-Host 'Installation cross-wait pipe fixture passed; starting non-ASCII pipe fixture.'
$highBytePair = $null
try {
    $highBytePair = New-InstallationTestPipePair -Name ('Atlaso-Test-' + [guid]::NewGuid().ToString('N'))
    $highByteState = @{}
    $rawConsole = [Collections.Generic.List[byte]]::new()
    $rawConsole.AddRange([Text.Encoding]::ASCII.GetBytes("`e[4;8H"))
    $rawConsole.Add([byte]0xE9)
    $rawConsole.AddRange([Text.Encoding]::ASCII.GetBytes("`e[6nHighByteDone"))
    $highBytes = $rawConsole.ToArray()
    $highByteWriter = [AtlasoInstallationPipeTestWriter]::RawBytes($highBytePair.Client, $highBytes)
    Wait-InstallationConsoleState -Pipe $highBytePair.Server -Pattern 'HighByteDone' -Deadline ([DateTimeOffset]::UtcNow.AddSeconds(5)) -ReadLoginProgress -CursorState $highByteState
    Assert-InstallationVmCondition ($highByteWriter.Wait(5000)) 'The bounded non-ASCII fixture writer must finish.'
    Assert-InstallationVmCondition (-not $highByteState.RowKnown -and -not $highByteState.ColumnKnown) `
        'A non-ASCII console byte must invalidate cursor certainty until a later anchor.'
    $highReply = [byte[]]::new(8)
    $highReadDeadline = [Threading.CancellationTokenSource]::new(250)
    $highByteNoReply = $false
    try { $null = $highBytePair.Client.ReadAsync($highReply, 0, $highReply.Length, $highReadDeadline.Token).GetAwaiter().GetResult() }
    catch [OperationCanceledException] { $highByteNoReply = $true }
    finally { $highReadDeadline.Dispose(); [Array]::Clear($highReply, 0, $highReply.Length); [Array]::Clear($highBytes, 0, $highBytes.Length) }
    Assert-InstallationVmCondition $highByteNoReply 'Non-ASCII console text must not receive a guessed cursor reply.'
}
finally { if ($highBytePair) { Close-InstallationTestPipePair -Pair $highBytePair } }
foreach ($rootPromptFixture in @('root [ ~ ]# ', 'root@atlaso [ /root ]# ', 'root:~# ', 'root@atlaso:/root# ', 'root# ', 'bash-5.3# ', '-bash-5.3# ')) {
    Assert-InstallationVmCondition (Test-InstallationShellPrompt -Text ("Public startup`n" + $rootPromptFixture) -Account root) 'Known native Bash prompt shapes must admit the separate identity challenge.'
}
foreach ($notRootPrompt in @('admin [ ~ ]# ', 'root login:', 'Password: # ', 'root [ ~ ]$ ', 'echo root [ ~ ]# ', 'root [ ~ ]# private-tail', "root [`n~ ]# ")) {
    Assert-InstallationVmCondition (-not (Test-InstallationShellPrompt -Text $notRootPrompt -Account root)) 'A login field, another account, echoed text, or malformed prompt must not admit a root challenge.'
}
foreach ($changeField in @('You are required to change your password', 'Your password has expired', 'Current password:', '(current) UNIX password:', 'New password:', 'Retype new password:')) {
    $changeRefused = $false
    try { $null = Test-InstallationShellPrompt -Text ($changeField + "`nroot [ ~ ]# ") -Account root }
    catch { $changeRefused = $_.Exception.Message -ceq 'Installed login requested a password change before shell verification.' }
    Assert-InstallationVmCondition $changeRefused 'Password-change conversations must fail before any shell command can be submitted.'
}
$oscPromptPair = $null
try {
    $oscPromptPair = New-InstallationTestPipePair -Name ('Atlaso-Test-' + [guid]::NewGuid().ToString('N'))
    $oscPromptSender = [AtlasoInstallationPipeTestWriter]::Start($oscPromptPair.Client, [string[]]@(
        "`e]0;private-fixture-title", "`aroot@atlaso:~# "))
    $oscPromptOutput = @(Wait-InstallationConsoleState -Pipe $oscPromptPair.Server -Pattern $rootShellProbe.Prompt -Deadline ([DateTimeOffset]::UtcNow.AddSeconds(5)) -ShellAccount root 6>&1) | Out-String
    Assert-InstallationVmCondition (-not $oscPromptOutput.Contains('private-fixture-title')) 'Shell readiness must remove fragmented terminal titles without exposing their contents.'
    Assert-InstallationVmCondition ($oscPromptSender.Wait(5000)) 'The terminal-title prompt fixture writer did not finish.'
}
finally { if ($oscPromptPair) { Close-InstallationTestPipePair -Pair $oscPromptPair } }
foreach ($promptPrefix in @('root', 'root@atlaso')) {
    $rootPromptPair = $null
    try {
        $rootPromptPair = New-InstallationTestPipePair -Name ('Atlaso-Test-' + [guid]::NewGuid().ToString('N'))
        $rootPromptSender = [AtlasoInstallationPipeTestWriter]::Start($rootPromptPair.Client, [string[]]@(
            ($promptPrefix + " [ `e[0m~`e[1;31m ]"), "# `e[0m"))
        Wait-InstallationConsoleState -Pipe $rootPromptPair.Server -Pattern $rootShellProbe.Prompt -Deadline ([DateTimeOffset]::UtcNow.AddSeconds(5))
        Assert-InstallationVmCondition ($rootPromptSender.Wait(5000)) 'The native root-prompt fixture writer did not finish.'
    }
    finally { if ($rootPromptPair) { Close-InstallationTestPipePair -Pair $rootPromptPair } }
}
$adminShellProbe = Get-InstallationAccountProbe -Account admin
Assert-InstallationVmCondition ($adminShellProbe.Prompt -ceq 'PS ' -and -not $adminShellProbe.Command.Contains('ATLASO-LOGIN-OK')) 'Administrator readiness must use PowerShell and avoid a contiguous echoed marker.'
Assert-InstallationVmCondition ($adminShellProbe.EnterKey -ceq "`r" -and $adminShellProbe.EnterKey.Length -eq 1) `
    'PowerShell command submission must send ordinary Enter, not the Unix console Ctrl+Enter line feed.'
foreach ($fixtureIdentity in @('admin', 'root')) {
    $probeResult = @(& {
        param([string]$ObservedIdentity, [string]$Command)
        <#
        .SYNOPSIS
        Return only the controlled account identity for the shell-probe fixture.
        #>
        function id { if ($args.Count -ne 1 -or $args[0] -cne '-un') { throw 'Unexpected identity argument.' }; $ObservedIdentity }
        & ([scriptblock]::Create($Command))
    } $fixtureIdentity $adminShellProbe.Command)
    if ($fixtureIdentity -ceq 'admin') {
        Assert-InstallationVmCondition ($probeResult.Count -eq 1 -and $probeResult[0] -ceq 'ATLASO-LOGIN-OK') 'The administrator checkpoint must execute in PowerShell after matching its real account.'
    } else {
        Assert-InstallationVmCondition ($probeResult.Count -eq 0) 'A different account must never satisfy the administrator checkpoint.'
    }
}

foreach ($capacityFixture in @(
    @{ Disk = '/dev/sda'; Bytes = '4294967296'; Pass = $true; Fragmented = $true },
    @{ Disk = '/dev/sdb'; Bytes = '4294967296'; Pass = $false; ExpectedFailure = 'mismatched or malformed' },
    @{ Disk = '/dev/sda'; Bytes = '4096'; Pass = $false; ExpectedFailure = 'mismatched or malformed' },
    @{ Disk = '/dev/sda'; Bytes = '4294967296'; Pass = $false; Malformed = $true; ExpectedFailure = 'complete native capacity refusal' },
    @{ Disk = '/dev/sda'; Bytes = '4294967296'; Pass = $false; LegacyTraceback = $true; ExpectedFailure = 'reported a Python failure' }
)) {
    $capacityPair = $null
    $capacityReady = $null
    try {
        $capacityPair = New-InstallationTestPipePair -Name ('Atlaso-Test-' + [guid]::NewGuid().ToString('N'))
        if ($capacityFixture.LegacyTraceback) {
            $capacityLine = 'ValueError: default installation requires a disk of at least 64 GiB; selected {0} has {1} bytes' -f $capacityFixture.Disk, $capacityFixture.Bytes
            $capacityFragments = [string[]]@(
                "Traceback (most recent call last):`r`n    raise ValueError('default installation requires a disk of at least 64 GiB')`r`n",
                "  File `"/PublicFixture/installer.py`", line 205, in configure_console`r`n$capacityLine`r`n")
        } elseif ($capacityFixture.Malformed) {
            $capacityFragments = [string[]]@(
                "Insufficient disk capacity.`r`ndefault installation requires a disk of at least 64 GiB`r`n",
                (('Selected {0} has {1} bytes.' -f $capacityFixture.Disk, $capacityFixture.Bytes) + "`r`n"))
        } else {
            $capacityDialog = @(
                'Insufficient disk capacity.',
                'default installation requires a disk of at least 64 GiB',
                ('Selected {0} has {1} bytes.' -f $capacityFixture.Disk, $capacityFixture.Bytes),
                'Press Enter to choose another disk, or Esc to cancel.'
            ) -join "`r`n"
            if ($capacityFixture.Fragmented) {
                $capacityFragments = [string[]]@(
                    'Insufficient disk ',
                    "capacity.`r`ndefault installation requires a disk of at least 64 GiB`r`nSelected /dev/s",
                    'da has 4294',
                    "967296 bytes.`r`nPress Enter to choose another disk, or Esc to cancel.`r`n")
            } else {
                $capacityFragments = [string[]]@($capacityDialog + "`r`n")
            }
        }
        $capacityWaitSeconds = 5
        if ($capacityFixture.Malformed) {
            $capacityReady = [Threading.ManualResetEventSlim]::new()
            $capacitySender = [AtlasoInstallationPipeTestWriter]::Start($capacityPair.Client, $capacityFragments, $capacityReady)
            Assert-InstallationVmCondition ($capacityReady.Wait(5000)) 'The incomplete capacity writer did not start.'
            $capacityWaitSeconds = 1
        } else {
            $capacitySender = [AtlasoInstallationPipeTestWriter]::Start($capacityPair.Client, $capacityFragments)
        }
        $capacityAccepted = $false
        $capacityFailure = ''
        try {
            $null = @(Wait-InstallationConsoleState -Pipe $capacityPair.Server -Pattern 'default installation requires a disk of at least 64 GiB' -Deadline ([DateTimeOffset]::UtcNow.AddSeconds($capacityWaitSeconds)) -ExpectedCapacityDisk '/dev/sda' 6>&1)
            $capacityAccepted = $true
        } catch {
            $capacityFailure = $_.Exception.Message
            $capacityAccepted = $false
        }
        Assert-InstallationVmCondition ($capacityAccepted -eq $capacityFixture.Pass) 'Capacity acceptance must require the complete native refusal for the exact selected four-GiB disk, never an obsolete traceback or another disk.'
        if (-not $capacityFixture.Pass) {
            Assert-InstallationVmCondition ($capacityFailure.Contains($capacityFixture.ExpectedFailure, [StringComparison]::Ordinal)) `
                'Mismatched, malformed, and obsolete capacity failures must remain refused.'
        }
        Assert-InstallationVmCondition ($capacitySender.Wait(5000)) 'The capacity fixture writer did not finish.'
    }
    finally {
        if ($capacityPair) { Close-InstallationTestPipePair -Pair $capacityPair }
        if ($capacityReady) { $capacityReady.Dispose() }
    }
}

$panicPair = $null
try {
    $panicPair = New-InstallationTestPipePair -Name ('Atlaso-Test-' + [guid]::NewGuid().ToString('N'))
    $panicSender = [AtlasoInstallationPipeTestWriter]::Start($panicPair.Client, [string[]]@(
        'Kernel pan', 'ic - not syncing: VFS: Unable to mount root fs on unknown-block(0,0) private-fixture-details'))
    $panicReports = [Collections.Generic.List[string]]::new()
    $panicRefused = $false
    try {
        Wait-InstallationConsoleState -Pipe $panicPair.Server -Pattern 'login:' -Deadline ([DateTimeOffset]::UtcNow.AddSeconds(5)) -ReadBootProgress 6>&1 |
            ForEach-Object { $panicReports.Add([string]$_) }
    } catch { $panicRefused = $_.Exception.Message -ceq 'The installed system reported a kernel panic before login.' }
    Assert-InstallationVmCondition $panicRefused 'A fragmented kernel panic must stop the login wait with a fixed public failure.'
    $panicText = $panicReports -join "`n"
    Assert-InstallationVmCondition ($panicText.Contains('root-filesystem-unmountable') -and $panicText.Contains('root-device-unresolved')) 'Kernel diagnostics must retain only known root-boot failure categories.'
    Assert-InstallationVmCondition (-not $panicText.Contains('private-fixture-details') -and -not $panicText.Contains('not syncing:')) 'Kernel diagnostics must never emit raw panic text.'
    Assert-InstallationVmCondition ($panicSender.Wait(5000)) 'The kernel-panic fixture writer did not finish.'
}
finally { if ($panicPair) { Close-InstallationTestPipePair -Pair $panicPair } }

# Inspection may return a bounded encoded record, never surrounding terminal data.
$inspectionPair = $null
try {
    $inspectionPair = New-InstallationTestPipePair -Name ('Atlaso-Test-' + [guid]::NewGuid().ToString('N'))
    $inspectionSender = [AtlasoInstallationPipeTestWriter]::Start($inspectionPair.Client, [string[]]@(
        "private-console-fixture`r`n`rATLASO-INSPEC", 'TION:eyJzY2hlbWEiOjF9', ":END`r`r`n"))
    $inspectionRecord = Wait-InstallationConsoleState -Pipe $inspectionPair.Server -Pattern '' `
        -Deadline ([DateTimeOffset]::UtcNow.AddSeconds(5)) -ReadInspectionReport
    Assert-InstallationVmCondition ($inspectionRecord -ceq 'eyJzY2hlbWEiOjF9') 'Inspection must return only the fragmented encoded record.'
    Assert-InstallationVmCondition ($inspectionSender.Wait(5000)) 'Inspection fixture writer did not finish.'
}
finally { if ($inspectionPair) { Close-InstallationTestPipePair -Pair $inspectionPair } }

$maximumInspectionJson = '{"fixture":"' + ('x' * 4082) + '"}'
$maximumInspectionEncoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($maximumInspectionJson))
foreach ($fragmentedReport in @($false, $true)) {
    $inspectionPair = $null
    try {
        $inspectionPair = New-InstallationTestPipePair -Name ('Atlaso-Test-' + [guid]::NewGuid().ToString('N'))
        $wire = "ATLASO-INSPECTION:${maximumInspectionEncoded}:END`r`n"
        $fragments = if ($fragmentedReport) { [string[]]@($wire.Substring(0, 4096), $wire.Substring(4096)) }
            else { [string[]]@($wire) }
        $inspectionSender = [AtlasoInstallationPipeTestWriter]::Start($inspectionPair.Client, $fragments)
        $inspectionRecord = Wait-InstallationConsoleState -Pipe $inspectionPair.Server -Pattern '' `
            -Deadline ([DateTimeOffset]::UtcNow.AddSeconds(5)) -ReadInspectionReport
        Assert-InstallationVmCondition ($maximumInspectionJson.Length -eq 4096 -and $maximumInspectionEncoded.Length -eq 5464 -and
            $inspectionRecord -ceq $maximumInspectionEncoded) 'The complete decoded report bound must fit its Base64 wire envelope.'
        Assert-InstallationVmCondition ($inspectionSender.Wait(5000)) 'Maximum inspection report writer did not finish.'
    }
    finally { if ($inspectionPair) { Close-InstallationTestPipePair -Pair $inspectionPair } }
}

$pipPackageHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes('pip'))).ToLowerInvariant()
foreach ($fixture in @(
    @{ Text = "ATLASO-INSPECTION-FAILED`r`nprivate-error-details`r`n"; Error = 'Installed identity or application payload inspection failed.' },
    @{ Text = "`rATLASO-INSPECTION-FAILED:software-staging`r`r`nprivate-error-details`r`n"; Error = 'Installed inspection failed at public stage: software-staging.' },
    @{ Text = "ATLASO-INSPECTION-FAILED:system-rpm`r`nprivate-error-details`r`n"; Error = 'Installed inspection failed at public stage: system-rpm.' },
    @{ Text = "ATLASO-INSPECTION-FAILED:system-rpm-files`r`nprivate-error-details`r`n"; Error = 'Installed inspection failed at public stage: system-rpm-files.' },
    @{ Text = "ATLASO-INSPECTION-FAILED:system-rpm-runtime`r`nprivate-error-details`r`n"; Error = 'Installed inspection failed at public stage: system-rpm-runtime.' },
    @{ Text = ("ATLASO-INSPECTION-FAILED:system-rpm-files-package-" + $pipPackageHash + "`r`nprivate-error-details`r`n"); AllowedRpmPackages = @('pip'); Error = ('Installed inspection failed at public stage: system-rpm-files-package-' + $pipPackageHash + '.') },
    @{ Text = ("ATLASO-INSPECTION-FAILED:system-rpm-files-package-" + $pipPackageHash + "-entry30-missing`r`nprivate-error-details`r`n"); AllowedRpmPackages = @('pip'); Error = ('Installed inspection failed at public stage: system-rpm-files-package-' + $pipPackageHash + '-entry30-missing.') },
    @{ Text = ("ATLASO-INSPECTION-FAILED:system-rpm-files-package-" + $pipPackageHash + "-entry124-missing`r`nprivate-error-details`r`n"); AllowedRpmPackages = @('pip'); Error = ('Installed inspection failed at public stage: system-rpm-files-package-' + $pipPackageHash + '-entry124-missing.') },
    @{ Text = ("ATLASO-INSPECTION-FAILED:system-rpm-files-package-" + $pipPackageHash + "-entry125-missing`r`nprivate-error-details`r`n"); AllowedRpmPackages = @('pip'); Error = ('Installed inspection failed at public stage: system-rpm-files-package-' + $pipPackageHash + '.') },
    @{ Text = ("ATLASO-INSPECTION-FAILED:system-rpm-files-package-" + $pipPackageHash + "-entry27-d0700-v.M.......`r`nprivate-error-details`r`n"); AllowedRpmPackages = @('pip'); Error = ('Installed inspection failed at public stage: system-rpm-files-package-' + $pipPackageHash + '-entry27-d0700-v.M........') },
    @{ Text = ("ATLASO-INSPECTION-FAILED:system-rpm-files-package-" + $pipPackageHash + "-entry124-d0700-v.M.......`r`nprivate-error-details`r`n"); AllowedRpmPackages = @('pip'); Error = ('Installed inspection failed at public stage: system-rpm-files-package-' + $pipPackageHash + '-entry124-d0700-v.M........') },
    @{ Text = ("ATLASO-INSPECTION-FAILED:system-rpm-files-package-" + $pipPackageHash + "-entry125-d0700-v.M.......`r`nprivate-error-details`r`n"); AllowedRpmPackages = @('pip'); Error = ('Installed inspection failed at public stage: system-rpm-files-package-' + $pipPackageHash + '.') },
    @{ Text = ("ATLASO-INSPECTION-FAILED:system-rpm-files-package-" + ('a' * 64) + "-entry27-d0700-v.M.......`r`nprivate-error-details`r`n"); AllowedRpmPackages = @('pip'); Error = 'Installed inspection failed at public stage: system-rpm-files.' },
    @{ Text = ("ATLASO-INSPECTION-FAILED:system-rpm-files-package-" + $pipPackageHash + "-entry27-d0700`r`nprivate-error-details`r`n"); AllowedRpmPackages = @('pip'); Error = ('Installed inspection failed at public stage: system-rpm-files-package-' + $pipPackageHash + '-entry27-d0700.') },
    @{ Text = ("ATLASO-INSPECTION-FAILED:system-rpm-files-package-" + $pipPackageHash + "-entry113-d0700`r`nprivate-error-details`r`n"); AllowedRpmPackages = @('pip'); Error = ('Installed inspection failed at public stage: system-rpm-files-package-' + $pipPackageHash + '-entry113-d0700.') },
    @{ Text = ("ATLASO-INSPECTION-FAILED:system-rpm-files-package-" + $pipPackageHash + "-entry115-d2755`r`nprivate-error-details`r`n"); AllowedRpmPackages = @('pip'); Error = ('Installed inspection failed at public stage: system-rpm-files-package-' + $pipPackageHash + '-entry115-d2755.') },
    @{ Text = ("ATLASO-INSPECTION-FAILED:system-rpm-files-package-" + $pipPackageHash + "-entry116-d0700-v.M.......`r`nprivate-error-details`r`n"); AllowedRpmPackages = @('pip'); Error = ('Installed inspection failed at public stage: system-rpm-files-package-' + $pipPackageHash + '-entry116-d0700-v.M........') },
    @{ Text = ("ATLASO-INSPECTION-FAILED:system-rpm-files-package-" + $pipPackageHash + "-entry124-d0700`r`nprivate-error-details`r`n"); AllowedRpmPackages = @('pip'); Error = ('Installed inspection failed at public stage: system-rpm-files-package-' + $pipPackageHash + '-entry124-d0700.') },
    @{ Text = ("ATLASO-INSPECTION-FAILED:system-rpm-files-package-" + $pipPackageHash + "-entry125-d0700`r`nprivate-error-details`r`n"); AllowedRpmPackages = @('pip'); Error = ('Installed inspection failed at public stage: system-rpm-files-package-' + $pipPackageHash + '.') },
    @{ Text = ("ATLASO-INSPECTION-FAILED:system-rpm-files-package-" + $pipPackageHash + "-entry999-d0700`r`nprivate-error-details`r`n"); AllowedRpmPackages = @('pip'); Error = ('Installed inspection failed at public stage: system-rpm-files-package-' + $pipPackageHash + '.') },
    @{ Text = ("ATLASO-INSPECTION-FAILED:system-rpm-files-package-" + $pipPackageHash + "-root-d0700`r`nprivate-error-details`r`n"); AllowedRpmPackages = @('pip'); Error = ('Installed inspection failed at public stage: system-rpm-files-package-' + $pipPackageHash + '-root-d0700.') },
    @{ Text = ("ATLASO-INSPECTION-FAILED:system-rpm-files-package-" + ('a' * 64) + "-root-d0700`r`nprivate-error-details`r`n"); AllowedRpmPackages = @('pip'); Error = 'Installed inspection failed at public stage: system-rpm-files.' },
    @{ Text = ("ATLASO-INSPECTION-FAILED:system-rpm-files-package-" + ('a' * 64) + "`r`nprivate-error-details`r`n"); AllowedRpmPackages = @('pip'); Error = 'Installed inspection failed at public stage: system-rpm-files.' },
    @{ Text = ("ATLASO-INSPECTION-FAILED:system-rpm-files-package-" + $pipPackageHash + "`r`nprivate-error-details`r`n"); Error = 'Installed inspection failed at public stage: system-rpm-files.' },
    @{ Text = "ATLASO-INSPECTION-FAILED:system-notices-compare`r`nprivate-error-details`r`n"; Error = 'Installed inspection failed at public stage: system-notices-compare.' },
    @{ Text = "ATLASO-INSPECTION-FAILED:system-assets-deployed`r`nprivate-error-details`r`n"; Error = 'Installed inspection failed at public stage: system-assets-deployed.' },
    @{ Text = "ATLASO-INSPECTION-FAILED:system-python-external`r`nprivate-error-details`r`n"; Error = 'Installed inspection failed at public stage: system-python-external.' },
    @{ Text = "ATLASO-INSPECTION-FAILED:system-python-bytecode`r`nprivate-error-details`r`n"; Error = 'Installed inspection failed at public stage: system-python-bytecode.' },
    @{ Text = ("ATLASO-INSPECTION-FAILED:system-python-changed-" + ('a' * 64) + "`r`nprivate-error-details`r`n"); Error = ('Installed inspection failed at public stage: system-python-changed-' + ('a' * 64) + '.') },
    @{ Text = "ATLASO-INSPECTION:e30=:END`r`nATLASO-INSPECTION:e30=:END`r`n"; Error = 'Installed inspection returned duplicate records.' },
    @{ Text = "ATLASO-INSPECTION:AA=:END`r`n"; Error = 'Installed inspection report encoding is invalid.' },
    @{ Text = ('ATLASO-INSPECTION:' + [Convert]::ToBase64String([byte[]]::new(4097)) + ":END`r`n"); Error = 'Installed inspection report exceeds its decoded bound.' },
    @{ Text = ('x' * 17000); Error = 'Installed inspection console output exceeded its bound.' }
)) {
    $inspectionPair = $null
    try {
        $inspectionPair = New-InstallationTestPipePair -Name ('Atlaso-Test-' + [guid]::NewGuid().ToString('N'))
        $inspectionSender = [AtlasoInstallationPipeTestWriter]::Start($inspectionPair.Client, [string[]]@($fixture.Text))
        $inspectionRefused = $false
        $allowedFixturePackages = @()
        if ($fixture.ContainsKey('AllowedRpmPackages')) { $allowedFixturePackages = @($fixture.AllowedRpmPackages) }
        try {
            $null = Wait-InstallationConsoleState -Pipe $inspectionPair.Server -Pattern '' `
                -Deadline ([DateTimeOffset]::UtcNow.AddSeconds(5)) -ReadInspectionReport -AllowedRpmPackages $allowedFixturePackages
        } catch { $inspectionRefused = $_.Exception.Message -ceq $fixture.Error }
        Assert-InstallationVmCondition $inspectionRefused 'Invalid inspection output must fail with a fixed public error.'
        Assert-InstallationVmCondition ($inspectionSender.Wait(5000)) 'Inspection refusal writer did not finish.'
    }
    finally { if ($inspectionPair) { Close-InstallationTestPipePair -Pair $inspectionPair } }
}
