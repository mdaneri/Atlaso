<#
.SYNOPSIS
Exercise native Windows LAN segment receipt, reference, and preferences safety contracts.
.PARAMETER StateRoot
Explicit task-owned parent for isolated provider fixtures; never uses the host preferences.
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$StateRoot)
$ErrorActionPreference = 'Stop'
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
Import-Module (Join-Path $repositoryRoot 'scripts/windows/vmware/Atlaso.WorkstationCleanup.psm1') -Force
$module = Get-Module Atlaso.WorkstationCleanup

<#
.SYNOPSIS
Require a refused operation without swallowing an unexpected successful result.
.PARAMETER Action
Operation required to throw.
.PARAMETER Pattern
Expected refusal message pattern.
#>
function Assert-Refused {
    param([scriptblock]$Action, [string]$Pattern)
    try { & $Action | Out-Null } catch {
        if ($_.Exception.Message -notmatch $Pattern) { throw }
        return
    }
    throw "Expected refusal: $Pattern"
}

# Process injection is confined to this imported test module. Native file identity,
# pinning, replacement, receipt hashing and provider parsing all execute for real.
& $module {
    $script:fixtureUiOpen = $false
    $script:fixtureVmRunning = $false
    <#
    .SYNOPSIS
    Supply bounded provider process fixtures without inspecting unrelated real VMs.
    .PARAMETER Name
    Requested provider process names.
    #>
    function script:Get-Process {
        [CmdletBinding()]
        param([string[]]$Name)
        if (($Name -contains 'vmware' -and $script:fixtureUiOpen) -or
            ($Name -contains 'vmware-vmx' -and $script:fixtureVmRunning)) { return @{ Id = 1 } }
    }
}
$fixture = Join-Path $StateRoot ([guid]::NewGuid().ToString('N'))
$provider = Join-Path $fixture 'provider'
$vmRoot = Join-Path $fixture 'vms'
$labRoot = Join-Path $fixture 'lab'
foreach ($path in @($provider, $vmRoot, $labRoot)) { [IO.Directory]::CreateDirectory($path) | Out-Null }
$preferences = Join-Path $provider 'preferences.ini'
$inventory = Join-Path $provider 'inventory.vmls'
$original = "# untouched caf$([char]0xe9)`r`nother.setting = `"keep`"`r`npref.namedPVNs0.name = `"Shared`"`r`npref.namedPVNs0.pvnID = `"52 00 00 00 00 00 00 00-00 00 00 00 00 00 00 01`"`r`npref.namedPVNs.count = `"1`"`r`n"
[IO.File]::WriteAllText($preferences, $original)
[IO.File]::WriteAllText($inventory, '')
$owner = @{ task_id = 'fixture-task'; repository = 'mdaneri/Atlaso'; source_commit = ('a' * 40); pr = 797; lab_root = $labRoot }
$receiptRecords = [System.Collections.Generic.List[object]]::new()
$publishReceipt = {
    param($pending)
    if ([IO.File]::ReadAllText($preferences).Contains($pending.Id)) { throw 'Registration preceded its ownership evidence.' }
    $receiptRecords.Add($pending)
    $evidenceStage = Join-Path $labRoot 'identity.tmp'
    $evidencePath = Join-Path $labRoot 'identity.json'
    [IO.File]::WriteAllText($evidenceStage, ($receiptRecords | ConvertTo-Json))
    [Atlaso.WorkstationFileIdentity]::PublishDurableFile($evidenceStage, $evidencePath)
}
$shared = Resolve-AtlasoOwnedLanSegment -Name Shared -Owner $owner -PreferencesPath $preferences -PublishReceipt $publishReceipt
if ($shared.ReceiptPath -or [IO.File]::ReadAllText($preferences) -cne $original) { throw 'Shared registration was adopted or changed.' }
$segment = Resolve-AtlasoOwnedLanSegment -Name Owned -Owner $owner -PreferencesPath $preferences -PublishReceipt $publishReceipt
if ($receiptRecords.Count -ne 1 -or $receiptRecords[0].ReceiptSha256 -cne $segment.ReceiptSha256) { throw 'Missing original receipt evidence.' }
Assert-Refused {
    Resolve-AtlasoOwnedLanSegment -Name Interrupted -Owner $owner -PreferencesPath $preferences -PublishReceipt {
        param($pending)
        & $publishReceipt $pending
        throw 'Simulated interruption after durable receipt publication.'
    }
} 'interruption after durable receipt'
if ([IO.File]::ReadAllText($preferences).Contains($receiptRecords[1].Id)) { throw 'Interrupted evidence publication registered a segment.' }
$registered = [IO.File]::ReadAllBytes($preferences)
$argsMap = @{ ReceiptPath = $segment.ReceiptPath; ReceiptSha256 = $segment.ReceiptSha256
    Owner = $owner; VmRoots = @($vmRoot); PreferencesPath = $preferences; InventoryPath = $inventory; Confirm = $false }
$foreign = $owner.Clone(); $foreign.task_id = 'other-task'
$badArgs = $argsMap.Clone(); $badArgs.Owner = $foreign
Assert-Refused { Remove-AtlasoWorkstationLanSegment @badArgs } 'owner mismatch'
$badArgs = $argsMap.Clone(); $badArgs.ReceiptSha256 = '0' * 64
Assert-Refused { Remove-AtlasoWorkstationLanSegment @badArgs } 'digest mismatch'
& $module { $script:fixtureUiOpen = $true }
Assert-Refused { Remove-AtlasoWorkstationLanSegment @argsMap } 'Close the VMware Workstation UI'
& $module { $script:fixtureUiOpen = $false; $script:fixtureVmRunning = $true }
Assert-Refused { Remove-AtlasoWorkstationLanSegment @argsMap } 'Stop VMware VM'
& $module { $script:fixtureVmRunning = $false }
$vmx = Join-Path $vmRoot 'foreign.vmx'
[IO.File]::WriteAllText($vmx, "ethernet1.pvnID = `"$($segment.Id)`"`r`n")
Assert-Refused { Remove-AtlasoWorkstationLanSegment @argsMap } 'still referenced'
# A registered VM outside the configured search roots is also authoritative.
$external = Join-Path $provider 'external.vmx'
[IO.File]::Move($vmx, $external)
[IO.File]::WriteAllText($inventory, "vmlist0.config = `"$external`"`r`n")
Assert-Refused { Remove-AtlasoWorkstationLanSegment @argsMap } 'still referenced'
[IO.File]::Delete($external)
[IO.File]::WriteAllText($inventory, 'vmlist0.config = invalid')
Assert-Refused { Remove-AtlasoWorkstationLanSegment @argsMap } 'malformed Workstation inventory'
[IO.File]::WriteAllText($inventory, "vmlist0.config = `"$(Join-Path $fixture 'missing/vm.vmx')`"")
Assert-Refused { Remove-AtlasoWorkstationLanSegment @argsMap } 'directory is unavailable'
[IO.File]::WriteAllText($inventory, '')
[IO.File]::WriteAllText($vmx, 'ethernet1.pvnID = invalid')
Assert-Refused { Remove-AtlasoWorkstationLanSegment @argsMap } 'Malformed VM adapter'
[IO.File]::Delete($vmx)
[IO.File]::AppendAllText($preferences, 'pref.namedPVNs.count = "2"')
Assert-Refused { Remove-AtlasoWorkstationLanSegment @argsMap } 'Duplicate LAN segment count'
[IO.File]::WriteAllBytes($preferences, $registered)
$drift = [Text.Encoding]::UTF8.GetString($registered).Replace('name = "Owned"', 'name = "Someone else"')
[IO.File]::WriteAllText($preferences, $drift)
Assert-Refused { Remove-AtlasoWorkstationLanSegment @argsMap } 'identity drift'
[IO.File]::WriteAllBytes($preferences, $registered)
$alias = Join-Path $provider 'preferences-alias'
New-Item -ItemType HardLink -Path $alias -Target $preferences | Out-Null
Assert-Refused { Remove-AtlasoWorkstationLanSegment @argsMap } 'single-identity file'
[IO.File]::Delete($alias)
$lock = [IO.File]::Open($preferences, 'Open', 'ReadWrite', 'None')
try { Assert-Refused { Remove-AtlasoWorkstationLanSegment @argsMap } 'used by another process' }
finally { $lock.Dispose() }
Remove-AtlasoWorkstationLanSegment @argsMap -WhatIf
if ([Convert]::ToBase64String([IO.File]::ReadAllBytes($preferences)) -cne [Convert]::ToBase64String($registered)) {
    throw 'Refusal or preview modified preferences.'
}
$result = Remove-AtlasoWorkstationLanSegment @argsMap
if (-not $result.registration_absent -or -not $result.adapter_references_absent -or -not $result.changed) { throw 'Missing absence evidence.' }
$expected = $original.Replace('count = "1"', 'count = "2"')
if ([IO.File]::ReadAllText($preferences) -cne $expected) { throw 'Unrelated preferences bytes changed.' }
$again = Remove-AtlasoWorkstationLanSegment @argsMap
if ($again.changed -or -not $again.registration_absent) { throw 'Already-absent retry was not verified.' }
# Force an actual filename replacement after the original object is locked.
# The displaced competitor's bytes must be restored, never silently discarded.
Assert-Refused {
    & $module {
        param($path)
        Update-AtlasoLanPreferences -Path $path -Transform {
            param($originalBytes)
            [IO.File]::WriteAllText("$path.competitor", 'concurrent state')
            [IO.File]::Replace("$path.competitor", $path, "$path.displaced", $true)
            return ,([Text.Encoding]::UTF8.GetBytes('candidate state'))
        }
    } $preferences
} 'displaced provider state was restored'
if ([IO.File]::ReadAllText($preferences) -cne 'concurrent state') { throw 'Concurrent preferences state was lost.' }
Assert-Refused {
    & $module {
        param($path)
        $checks = @{ Count = 0 }
        Update-AtlasoLanPreferences -Path $path -Transform {
            param($originalBytes)
            return ,([Text.Encoding]::UTF8.GetBytes('candidate state'))
        } -Validate {
            $checks.Count++
            if ($checks.Count -eq 2) { throw 'Simulated post-publication reference drift.' }
        }
    } $preferences
} 'post-publication reference drift'
if ([IO.File]::ReadAllText($preferences) -cne 'concurrent state') { throw 'Post-publication refusal did not restore preferences.' }
foreach ($suffix in @('lan-retained.tmp.backup', 'lan-retained.tmp', 'recovery-retained.tmp', 'cas-retained.tmp')) {
    $backup = "$preferences.atlaso-$suffix"
    [IO.File]::WriteAllText($backup, 'retained recovery evidence')
    Assert-Refused { Remove-AtlasoWorkstationLanSegment @argsMap } 'interrupted LAN preferences transaction'
    if ([IO.File]::ReadAllText($backup) -cne 'retained recovery evidence') { throw 'Recovery evidence was changed.' }
    [IO.File]::Delete($backup)
}
Assert-Refused {
    & $module {
        param($root, $inventoryPath, $id)
        $referencePins = [System.Collections.Generic.List[System.IDisposable]]::new()
        try {
            Assert-AtlasoLanSegmentUnreferenced -InventoryPath $inventoryPath -VmRoots @($root) -SegmentId $id -Pins $referencePins
            $lateVmx = Join-Path $root 'late.vmx'
            [IO.File]::WriteAllText($lateVmx, "ethernet0.pvnID = `"$id`"")
            [IO.File]::Delete($lateVmx)
            # A second enumeration sees no VMX, but the retained native completion
            # must reject the changed descendant set, including transient changes.
            Assert-AtlasoLanSegmentUnreferenced -InventoryPath $inventoryPath -VmRoots @($root) -SegmentId $id -Pins $referencePins
        } finally {
            for ($i = $referencePins.Count - 1; $i -ge 0; $i--) { $referencePins[$i].Dispose() }
        }
    } $vmRoot $inventory $segment.Id
} 'contents changed during LAN segment'
$runnerPath = Join-Path $repositoryRoot 'scripts/windows/vmware/run-lifecycle-test.ps1'
$tokens = $null; $parseErrors = $null
$runnerAst = [System.Management.Automation.Language.Parser]::ParseFile($runnerPath, [ref]$tokens, [ref]$parseErrors)
$sourceFunction = $runnerAst.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-LifecycleSourceCommit'
}, $false)
if ($parseErrors -or -not $sourceFunction) { throw 'Cannot load lifecycle source admission function.' }
. ([scriptblock]::Create($sourceFunction.Extent.Text))
$sourceRoot = Join-Path $fixture 'source'
[IO.Directory]::CreateDirectory($sourceRoot) | Out-Null
& git -C $sourceRoot init -q
$sourceFile = Join-Path $sourceRoot 'source.txt'
[IO.File]::WriteAllText($sourceFile, 'initial')
& git -C $sourceRoot add source.txt
& git -C $sourceRoot -c user.name=Fixture -c user.email=fixture@example.invalid -c commit.gpgsign=false commit -qm initial
if ($LASTEXITCODE -ne 0) { throw 'Could not prepare source fixture.' }
$admitted = Get-LifecycleSourceCommit -RepositoryRoot $sourceRoot
[IO.File]::WriteAllText($sourceFile, 'dirty')
Assert-Refused { Get-LifecycleSourceCommit -RepositoryRoot $sourceRoot } 'clean source worktree'
[IO.File]::WriteAllText($sourceFile, 'initial')
$untracked = Join-Path $sourceRoot 'untracked.txt'
[IO.File]::WriteAllText($untracked, 'untracked')
Assert-Refused { Get-LifecycleSourceCommit -RepositoryRoot $sourceRoot } 'clean source worktree'
[IO.File]::Delete($untracked)
[IO.File]::WriteAllText($sourceFile, 'next')
& git -C $sourceRoot add source.txt
& git -C $sourceRoot -c user.name=Fixture -c user.email=fixture@example.invalid -c commit.gpgsign=false commit -qm next
if ($LASTEXITCODE -ne 0) { throw 'Could not advance source fixture.' }
Assert-Refused { Get-LifecycleSourceCommit -RepositoryRoot $sourceRoot -ExpectedCommit $admitted } 'source commit changed'
Write-Host "LAN segment safety fixtures passed: $fixture"
