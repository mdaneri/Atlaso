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
. ([scriptblock]::Create((Get-InstallationVmFunctionText -SourceAst $ast -Name 'New-InstallationVmConfiguration')))
. ([scriptblock]::Create((Get-InstallationVmFunctionText -SourceAst $ast -Name 'Get-InstallationVmxPathAssignment')))
. ([scriptblock]::Create((Get-InstallationVmFunctionText -SourceAst $ast -Name 'Assert-InstallationVmDiskBindings')))
. ([scriptblock]::Create((Get-InstallationVmFunctionText -SourceAst $ast -Name 'Assert-InstallationSerialPipePath')))
. ([scriptblock]::Create((Get-InstallationVmFunctionText -SourceAst $driverAst -Name 'Send-InstallationConsoleSecret')))
. ([scriptblock]::Create((Get-InstallationVmFunctionText -SourceAst $driverAst -Name 'Wait-InstallationConsoleState')))

$pipe = '\\.\pipe\Atlaso-Installation-0123456789abcdef0123456789abcdef'
$lines = @(New-InstallationVmConfiguration -Name 'Atlaso-Test-installation-iso' `
    -Iso 'C:\offline media\atlaso.iso' -TargetDisk 'C:\vm\target-64g.vmdk' `
    -UnselectedDisk 'C:\vm\unselected-4g.vmdk' -SerialPipe $pipe -CleanupIdentity '0123456789abcdef0123456789abcdef')
$configuration = [string]::Join("`n", $lines)
Assert-InstallationVmCondition ($configuration.Contains('firmware = "efi"')) 'EFI firmware must be enabled.'
Assert-InstallationVmCondition ($configuration.Contains('uefi.secureBoot.enabled = "FALSE"')) 'Phase-one Secure Boot must be disabled.'
Assert-InstallationVmCondition ($configuration.Contains('scsi0:0.fileName = "C:\\vm\\target-64g.vmdk"')) 'The install target disk must occupy SCSI 0:0.'
Assert-InstallationVmCondition ($configuration.Contains('scsi0:1.fileName = "C:\\vm\\unselected-4g.vmdk"')) 'The unselected disk must occupy SCSI 0:1.'
Assert-InstallationVmCondition ($configuration.Contains('sata0:0.deviceType = "cdrom-image"')) 'The ISO must be attached as a CD-ROM.'
Assert-InstallationVmCondition ($configuration.Contains('serial0.pipe.endPoint = "client"')) 'The serial pipe must use client mode.'
$expectedPipeAssignment = 'serial0.fileName = ' + (ConvertTo-InstallationVmxString -Value $pipe)
Assert-InstallationVmCondition ($lines -contains $expectedPipeAssignment) 'The named pipe must be preserved in the VMX.'
Assert-InstallationVmCondition ($configuration.Contains('ethernet0.present = "FALSE"')) 'The VM must have no network adapter.'
Assert-InstallationVmCondition (-not $configuration.Contains('ethernet1.present')) 'The VM must not contain additional network adapters.'
Assert-InstallationVmCondition (-not $configuration.Contains('ethernet0.connectionType = "nat"')) 'The VM must not configure a network connection.'
$bindingContext = [pscustomobject]@{ Name = 'Atlaso-Test-installation-iso'; OutputDirectory = 'C:\vm' }
$validBindings = $true
try { Assert-InstallationVmDiskBindings -VmxLines $lines -Context $bindingContext -IsoPath 'C:\offline media\atlaso.iso' }
catch { $validBindings = $false }
Assert-InstallationVmCondition $validBindings 'Exact target, unselected, and pinned ISO bindings must pass layout validation.'
$changedBindings = @($lines | ForEach-Object {
        if ($_ -ceq 'scsi0:1.fileName = "C:\\vm\\unselected-4g.vmdk"') { 'scsi0:1.fileName = "C:\\vm\\target-64g.vmdk"' } else { $_ }
    })
$changedBindingRejected = $false
try { Assert-InstallationVmDiskBindings -VmxLines $changedBindings -Context $bindingContext -IsoPath 'C:\offline media\atlaso.iso' }
catch { $changedBindingRejected = $true }
Assert-InstallationVmCondition $changedBindingRejected 'A changed unselected-disk VMX binding must fail closed.'
$validPipeAccepted = $true
try { Assert-InstallationSerialPipePath -Path $pipe } catch { $validPipeAccepted = $false }
Assert-InstallationVmCondition $validPipeAccepted 'A valid task-scoped serial pipe must be accepted.'
$invalidPipeRejected = $false
try { Assert-InstallationSerialPipePath -Path '\\localhost\pipe\Atlaso-Installation-0123456789abcdef0123456789abcdef' }
catch { $invalidPipeRejected = $true }
Assert-InstallationVmCondition $invalidPipeRejected 'Remote named pipes must be rejected.'

$source = [System.IO.File]::ReadAllText($harnessPath)
$ownershipSource = [System.IO.File]::ReadAllText($ownershipPath)
$cleanupSource = [System.IO.File]::ReadAllText($cleanupPath)
$whatIfGate = $source.IndexOf('$PSCmdlet.ShouldProcess($resolvedOutput', [StringComparison]::Ordinal)
$intentWrite = $source.IndexOf('Publish-AtlasoTestVmOwnershipRecord -Context $context -Record $intent', [StringComparison]::Ordinal)
$originalReceipt = $source.IndexOf('Publish-InstallationVmOriginalReceipt -Context $context', [StringComparison]::Ordinal)
$diskMutation = $source.IndexOf("-FileName 'vmware-vdiskmanager.exe'", [StringComparison]::Ordinal)
$providerStart = $source.IndexOf("'Start isolated installation ISO test VM'", [StringComparison]::Ordinal)
Assert-InstallationVmCondition ($whatIfGate -ge 0 -and $intentWrite -gt $whatIfGate) 'WhatIf must return before any ownership record is published.'
Assert-InstallationVmCondition ($intentWrite -lt $originalReceipt -and $originalReceipt -lt $diskMutation) 'The task intent and original VM receipt must precede disk mutations.'
Assert-InstallationVmCondition ($originalReceipt -lt $providerStart) 'The original VM receipt must precede provider startup.'
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
$providerStart = $source.IndexOf("'Start isolated installation ISO test VM'", [StringComparison]::Ordinal)
Assert-InstallationVmCondition ($targetDiskCreate -lt $baselineCreate -and $unselectedDiskCreate -lt $baselineCreate -and $baselineCreate -lt $providerStart) 'Both logical disk baselines must be durably published after disk creation and before any VM start.'
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

Write-Host 'Installation console pipe contract checks passed.'

Write-Host 'Installation ISO VM harness source-contract checks passed.'
