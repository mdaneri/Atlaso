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
    if (-not [IO.File]::Exists($pending.ReceiptPath) -or [IO.File]::Exists("$($pending.ReceiptPath).stage")) {
        throw 'Receipt pathname was not published before evidence callback.'
    }
    if ((Get-FileHash -LiteralPath $pending.ReceiptPath -Algorithm SHA256).Hash -cne $pending.ReceiptSha256) {
        throw 'Published receipt digest differs.'
    }
    $receiptRecords.Add($pending)
    $evidenceStage = Join-Path $labRoot 'identity.tmp'
    $evidencePath = Join-Path $labRoot 'identity.json'
    [IO.File]::WriteAllText($evidenceStage, ($receiptRecords | ConvertTo-Json))
    [Atlaso.WorkstationDurablePublisherV1]::PublishDurableFile($evidenceStage, $evidencePath)
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
Assert-Refused {
    & $module {
        param($path, $root, $inventoryPath, $id)
        $referencePins = [System.Collections.Generic.List[System.IDisposable]]::new()
        try {
            Update-AtlasoLanPreferences -Path $path -Transform {
                param($originalBytes)
                return ,([Text.Encoding]::UTF8.GetBytes('candidate state'))
            } -Validate {
                Assert-AtlasoLanSegmentUnreferenced -InventoryPath $inventoryPath -VmRoots @($root) -SegmentId $id -Pins $referencePins
            } -Readback {
                # Drift arrives after the last post-publication check. Final native
                # guard failure must still restore the displaced preferences object.
                $lateVmx = Join-Path $root 'final-readback.vmx'
                [IO.File]::WriteAllText($lateVmx, "ethernet0.pvnID = `"$id`"")
                [IO.File]::Delete($lateVmx)
                Assert-AtlasoLanSegmentUnreferenced -InventoryPath $inventoryPath -VmRoots @($root) -SegmentId $id -Pins $referencePins
            }
        } finally {
            for ($i = $referencePins.Count - 1; $i -ge 0; $i--) { $referencePins[$i].Dispose() }
        }
    } $preferences $vmRoot $inventory $segment.Id
} 'contents changed during LAN segment'
if ([IO.File]::ReadAllText($preferences) -cne 'concurrent state') { throw 'Final readback failure did not restore preferences.' }
Add-Type -Namespace AtlasoFixture -Name ShortProviderPath -MemberDefinition '[System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)] public static extern uint GetShortPathName(string path, System.Text.StringBuilder result, uint length);'
$shortBuffer = [Text.StringBuilder]::new(32768)
if ([AtlasoFixture.ShortProviderPath]::GetShortPathName($preferences, $shortBuffer, 32768) -eq 0) { throw 'Could not resolve provider alias fixture.' }
$providerAlias = $shortBuffer.ToString()
$canonicalAliasPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($providerAlias, $true)
try {
    if ([Atlaso.WorkstationCanonicalProviderV1]::Get($canonicalAliasPin) -ine $preferences) { throw 'Provider alias did not canonicalize.' }
} finally { $canonicalAliasPin.Dispose() }
$commitPins = [System.Collections.Generic.List[System.IDisposable]]::new()
try {
    & $module {
        param($path, $commitPins)
        Update-AtlasoLanPreferences -Path $path -Transform {
            param($bytes)
            return ,([Text.Encoding]::UTF8.GetBytes('committed state'))
        } -Readback { $commitPins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($path, $true)) }
    } $preferences $commitPins
    [IO.File]::WriteAllText("$preferences.after-readback", 'late replacement')
    Assert-Refused { [IO.File]::Replace("$preferences.after-readback", $preferences, "$preferences.late-backup", $true) } 'used by another process'
    if ([IO.File]::ReadAllText($preferences) -cne 'committed state') { throw 'Successful readback pin allowed replacement.' }
} finally { foreach ($pin in $commitPins) { $pin.Dispose() } }
[IO.File]::WriteAllText($preferences, 'concurrent state')
# Creation through the alias records canonical provenance; cleanup through the
# canonical path and alias both accept the same immutable receipt.
$aliasPreferences = Join-Path $provider 'alias-preferences.ini'
[IO.File]::WriteAllText($aliasPreferences, $original)
$aliasBuffer = [Text.StringBuilder]::new(32768)
if ([AtlasoFixture.ShortProviderPath]::GetShortPathName($aliasPreferences, $aliasBuffer, 32768) -eq 0) { throw 'Alias receipt fixture unavailable.' }
$aliasSegment = Resolve-AtlasoOwnedLanSegment -Name AliasOwned -Owner $owner -PreferencesPath $aliasBuffer.ToString() -PublishReceipt { param($pending) }
$aliasReceipt = [IO.File]::ReadAllText($aliasSegment.ReceiptPath) | ConvertFrom-Json
if ($aliasReceipt.preferences_path -ine $aliasPreferences) { throw 'Receipt stored alias text instead of canonical path.' }
$aliasArguments = @{ ReceiptPath = $aliasSegment.ReceiptPath; ReceiptSha256 = $aliasSegment.ReceiptSha256
    Owner = $owner; VmRoots = @($vmRoot); PreferencesPath = $aliasPreferences; InventoryPath = $inventory }
$aliasResult = Remove-AtlasoWorkstationLanSegment @aliasArguments
if (-not $aliasResult.registration_absent) { throw 'Canonical cleanup rejected alias-created receipt.' }
$aliasArguments.PreferencesPath = $aliasBuffer.ToString()
if (-not (Remove-AtlasoWorkstationLanSegment @aliasArguments).registration_absent) { throw 'Alias retry rejected canonical receipt.' }
Assert-Refused {
    & $module {
        param($path)
        $injected = @{ Done = $false }
        Update-AtlasoLanPreferences -Path $path -Transform {
            param($bytes)
            return ,([Text.Encoding]::UTF8.GetBytes('candidate'))
        } -Validate {
            if (-not $injected.Done) {
                $stagePath = (Get-ChildItem -LiteralPath (Split-Path -Parent $path) -Filter ((Split-Path -Leaf $path) + '.atlaso-lan-*.tmp')).FullName
                [IO.File]::WriteAllText("$path.foreign-stage", 'substituted stage')
                [IO.File]::Replace("$path.foreign-stage", $stagePath, "$path.old-stage", $true)
                $injected.Done = $true
            }
        }
    } $preferences
} 'staging identity changed; displaced provider state was restored'
if ([IO.File]::ReadAllText($preferences) -cne 'concurrent state') { throw 'Stage substitution left foreign provider bytes active.' }
# A second thread holds the provider transaction lock while producing unresolved
# recovery state. A concurrent retry must refuse before reading its old snapshot.
$pathKey = [Atlaso.WorkstationFileIdentity]::Get((Split-Path -Parent $preferences)) + ':' + (Split-Path -Leaf $preferences).ToUpperInvariant()
$pathHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($pathKey)))
$ready = [Threading.ManualResetEventSlim]::new($false)
$release = [Threading.ManualResetEventSlim]::new($false)
$holder = [PowerShell]::Create()
$null = $holder.AddScript({
    param($name, $ready, $release, $residue)
    $mutex = [Threading.Mutex]::new($false, $name)
    try {
        if (-not $mutex.WaitOne(0)) { throw 'Fixture mutex unavailable.' }
        try {
            $ready.Set()
            if (-not $release.Wait(30000)) { throw 'Fixture lock release timed out.' }
            [IO.File]::WriteAllText($residue, 'concurrent recovery state')
        } finally { $mutex.ReleaseMutex() }
    } finally { $mutex.Dispose() }
}).AddArgument("Global\Atlaso-LanPreferences-$pathHash").AddArgument($ready).AddArgument($release).AddArgument("$preferences.atlaso-cas-concurrent.tmp")
$pendingHolder = $holder.BeginInvoke()
try {
    if (-not $ready.Wait(10000)) { throw 'Fixture lock acquisition timed out.' }
    Assert-Refused { & $module { param($path) Update-AtlasoLanPreferences -Path $path -Transform { param($bytes) return ,$bytes } } $providerAlias } 'Another LAN preferences transaction is active'
} finally {
    $release.Set()
    $holder.EndInvoke($pendingHolder) | Out-Null
    $holder.Dispose(); $ready.Dispose(); $release.Dispose()
}
Assert-Refused { & $module { param($path) Update-AtlasoLanPreferences -Path $path -Transform { param($bytes) return ,$bytes } } $providerAlias } 'interrupted LAN preferences transaction'
if ([IO.File]::ReadAllText("$preferences.atlaso-cas-concurrent.tmp") -cne 'concurrent recovery state') { throw 'Concurrent recovery changed.' }
[IO.File]::Delete("$preferences.atlaso-cas-concurrent.tmp")
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
# Simulate an earlier guard completing after its individual poll while the later
# guard stays unchanged. One shared native event must invalidate the whole set.
$secondRoot = Join-Path $fixture 'second-root'
[IO.Directory]::CreateDirectory($secondRoot) | Out-Null
$aggregate = [Threading.EventWaitHandle]::new($false, [Threading.EventResetMode]::ManualReset)
$firstGuard = [Atlaso.WorkstationDirectoryChangeGuardV2]::new($vmRoot, $aggregate)
$secondGuard = [Atlaso.WorkstationDirectoryChangeGuardV2]::new($secondRoot, $aggregate)
try {
    $firstGuard.AssertUnchanged()
    $latePath = Join-Path $vmRoot 'after-first-poll.vmx'
    [IO.File]::WriteAllText($latePath, 'late reference')
    [IO.File]::Delete($latePath)
    $secondGuard.AssertUnchanged()
    if (-not $aggregate.WaitOne(0)) { throw 'Aggregate commit check missed an earlier-root completion.' }
} finally { $secondGuard.Dispose(); $firstGuard.Dispose(); $aggregate.Dispose() }
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
$helperFile = Join-Path $sourceRoot 'helper.psm1'
[IO.File]::WriteAllText($helperFile, "function Get-FixtureProvenance { 'initial' }")
[IO.Directory]::CreateDirectory((Join-Path $sourceRoot 'nested')) | Out-Null
[IO.File]::WriteAllText((Join-Path $sourceRoot 'nested/child.txt'), 'child')
& git -C $sourceRoot add source.txt helper.psm1 nested/child.txt
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
$snapshotFunction = $runnerAst.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'New-LifecycleSourceSnapshot'
}, $false)
if (-not $snapshotFunction) { throw 'Cannot load immutable source exporter.' }
. ([scriptblock]::Create($snapshotFunction.Extent.Text))
[IO.File]::WriteAllText($helperFile, "function Get-FixtureProvenance { 'transient' }")
[IO.File]::WriteAllText($sourceFile, 'transient build injection')
[IO.File]::WriteAllText($untracked, 'untracked build injection')
$snapshot = New-LifecycleSourceSnapshot -RepositoryRoot $sourceRoot -Commit $admitted -DestinationRoot $fixture
if ([IO.File]::ReadAllText((Join-Path $snapshot 'source.txt')) -cne 'initial' -or
    [IO.File]::Exists((Join-Path $snapshot 'untracked.txt'))) { throw 'Snapshot read live worktree bytes.' }
Import-Module (Join-Path $snapshot 'helper.psm1') -Force
if ((Get-FixtureProvenance) -cne 'initial') { throw 'Runtime helper loaded transient checkout code.' }
Remove-Module helper
[IO.File]::WriteAllText($helperFile, "function Get-FixtureProvenance { 'initial' }")
Assert-Refused { [IO.File]::WriteAllText((Join-Path $snapshot 'source.txt'), 'tampered') } 'denied'
Assert-Refused { [IO.File]::WriteAllText((Join-Path $snapshot 'injected.py'), 'tampered') } 'denied'
# Restore endpoint state: the snapshot still proves the exact admitted object.
[IO.File]::WriteAllText($sourceFile, 'next')
[IO.File]::Delete($untracked)
$reloadScript = Join-Path $fixture 'reload.ps1'
$reloadCode = "param([string]`$ModulePath, [string]`$Root)`n" +
    "`$ErrorActionPreference = 'Stop'`n" +
    "Add-Type 'namespace Atlaso { public static class WorkstationFileIdentity {} }'`n" +
    "Import-Module `$ModulePath -Force`nImport-Module `$ModulePath -Force`n" +
    "`$stage = Join-Path `$Root 'reload.stage'; `$final = Join-Path `$Root 'reload.final'`n" +
    "[IO.File]::WriteAllText(`$stage, 'reload')`n" +
    "[Atlaso.WorkstationDurablePublisherV1]::PublishDurableFile(`$stage, `$final, `$false)`n" +
    "if ([IO.File]::ReadAllText(`$final) -cne 'reload') { throw 'Reload publication failed.' }`n"
[IO.File]::WriteAllText($reloadScript, $reloadCode)
& pwsh -NoProfile -File $reloadScript -ModulePath (Join-Path $repositoryRoot 'scripts/windows/vmware/Atlaso.WorkstationCleanup.psm1') -Root $fixture
if ($LASTEXITCODE -ne 0) { throw 'Reload-safe publisher fixture failed.' }
$guardFunction = $runnerAst.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'New-LifecyclePreflightGuard'
}, $false)
. ([scriptblock]::Create($guardFunction.Extent.Text))
$preflightFunction = $runnerAst.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Remove-LifecyclePreflightArtifacts'
}, $false)
if (-not $preflightFunction) { throw 'Cannot load lifecycle preflight cleanup.' }
. ([scriptblock]::Create($preflightFunction.Extent.Text))
$preflightRoot = Join-Path $fixture 'preflight'
[IO.Directory]::CreateDirectory($preflightRoot) | Out-Null
$preflightGuard = New-LifecyclePreflightGuard -Path $preflightRoot
$preflightGuard.Expect((Join-Path $preflightRoot ('source-' + ('a' * 32) + '.zip')))
[IO.File]::WriteAllText((Join-Path $preflightRoot ('source-' + ('a' * 32) + '.zip')), 'partial archive')
$fixtureCreated = [IO.File]::OpenRead((Join-Path $preflightRoot ('source-' + ('a' * 32) + '.zip')))
try { $preflightGuard.Record((Join-Path $preflightRoot ('source-' + ('a' * 32) + '.zip')), $fixtureCreated.SafeFileHandle) }
finally { $fixtureCreated.Dispose() }
New-LifecycleSourceSnapshot -RepositoryRoot $sourceRoot -Commit $admitted -DestinationRoot $preflightRoot -PreflightGuard $preflightGuard | Out-Null
Assert-Refused { Remove-LifecyclePreflightArtifacts -Path $preflightRoot -ExpectedParent $vmRoot -Guard $preflightGuard } 'independently derived lifecycle parent'
Remove-LifecyclePreflightArtifacts -Path $preflightRoot -ExpectedParent $fixture -Guard $preflightGuard
$preflightGuard.Dispose()
if (Test-Path -LiteralPath $preflightRoot) { throw 'Failed archive preflight still blocks retry.' }
[IO.Directory]::CreateDirectory($preflightRoot) | Out-Null
$preflightGuard = New-LifecyclePreflightGuard -Path $preflightRoot
[IO.File]::WriteAllText((Join-Path $preflightRoot 'unexpected.txt'), 'preserve')
Assert-Refused { Remove-LifecyclePreflightArtifacts -Path $preflightRoot -ExpectedParent $fixture -Guard $preflightGuard } 'Unrecorded preflight artifact'
$preflightGuard.Dispose()
if ([IO.File]::ReadAllText((Join-Path $preflightRoot 'unexpected.txt')) -cne 'preserve') { throw 'Unexpected preflight state was removed.' }
$preflightGuard.Dispose()
$foreignRoot = Join-Path $fixture 'preflight-foreign'
[IO.Directory]::CreateDirectory($foreignRoot) | Out-Null
$foreignGuard = New-LifecyclePreflightGuard -Path $foreignRoot
$foreignZip = Join-Path $foreignRoot ('source-' + ('b' * 32) + '.zip')
[IO.File]::WriteAllText($foreignZip, 'foreign allowlisted name')
try { Assert-Refused { Remove-LifecyclePreflightArtifacts -Path $foreignRoot -ExpectedParent $fixture -Guard $foreignGuard } 'Unrecorded preflight artifact' }
finally { $foreignGuard.Dispose() }
if ([IO.File]::ReadAllText($foreignZip) -cne 'foreign allowlisted name') { throw 'Pre-capture foreign archive was adopted.' }
$lateRoot = Join-Path $fixture 'preflight-late'
[IO.Directory]::CreateDirectory($lateRoot) | Out-Null
$lateGuard = New-LifecyclePreflightGuard -Path $lateRoot
try {
    $ownedBeforeLate = Join-Path $lateRoot 'owned.txt'
    [IO.File]::WriteAllText($ownedBeforeLate, 'preserve owned evidence')
    $lateGuard.Expect($ownedBeforeLate)
    $ownedStream = [IO.File]::OpenRead($ownedBeforeLate)
    try { $lateGuard.Record($ownedBeforeLate, $ownedStream.SafeFileHandle) } finally { $ownedStream.Dispose() }
    $lateGuard.CaptureSnapshot()
    [IO.File]::WriteAllText((Join-Path $lateRoot 'late.txt'), 'preserve late entry')
    Assert-Refused { $lateGuard.Remove() } 'descendant set changed before deletion'
} finally { $lateGuard.Dispose() }
if ([IO.File]::ReadAllText($ownedBeforeLate) -cne 'preserve owned evidence') { throw 'Pre-deletion refusal consumed owned evidence.' }
if ([IO.File]::ReadAllText((Join-Path $lateRoot 'late.txt')) -cne 'preserve late entry') { throw 'Late preflight descendant was deleted.' }
$replacedRoot = Join-Path $fixture 'preflight-replaced'
[IO.Directory]::CreateDirectory($replacedRoot) | Out-Null
$replacedGuard = New-LifecyclePreflightGuard -Path $replacedRoot
$replacedPath = Join-Path $replacedRoot 'plan.json'
$replacedGuard.Expect($replacedPath)
$createdStream = [IO.File]::Open($replacedPath, 'CreateNew', 'Write', 'None')
try { $replacedGuard.Record($replacedPath, $createdStream.SafeFileHandle); $createdStream.WriteByte(1) } finally { $createdStream.Dispose() }
$foreignReplacement = Join-Path $fixture 'replacement.json'
[IO.File]::WriteAllText($foreignReplacement, 'foreign replacement')
[IO.File]::Replace($foreignReplacement, $replacedPath, (Join-Path $fixture 'original.json'), $true)
try { Assert-Refused { Remove-LifecyclePreflightArtifacts -Path $replacedRoot -ExpectedParent $fixture -Guard $replacedGuard } 'creation identity changed' }
finally { $replacedGuard.Dispose() }
if ([IO.File]::ReadAllText($replacedPath) -cne 'foreign replacement') { throw 'Same-path foreign preflight object was deleted.' }
$frozenRoot = Join-Path $fixture 'preflight-frozen'
[IO.Directory]::CreateDirectory($frozenRoot) | Out-Null
$frozenNative = New-LifecyclePreflightGuard -Path $frozenRoot
$frozenProbe = [pscustomobject]@{ Root = $frozenRoot; Native = $frozenNative; Blocked = $false }
$frozenProbe | Add-Member ScriptMethod CaptureSnapshot {
    $this.Native.CaptureSnapshot()
    try { [IO.File]::WriteAllText((Join-Path $this.Root 'during-delete.txt'), 'must refuse') }
    catch [UnauthorizedAccessException] { $this.Blocked = $true }
    if (-not $this.Blocked) { throw 'Cleanup namespace remained writable.' }
}
$frozenProbe | Add-Member ScriptMethod Remove { $this.Native.Remove() }
try { Remove-LifecyclePreflightArtifacts -Path $frozenRoot -ExpectedParent $fixture -Guard $frozenProbe }
finally { $frozenNative.Dispose() }
if (-not $frozenProbe.Blocked -or (Test-Path -LiteralPath $frozenRoot)) { throw 'Frozen cleanup fixture failed.' }
# Inject immediately after real extraction in this fixture's local function copy.
$injectedSnapshotSource = $snapshotFunction.Extent.Text.Replace(
    'foreach ($createdFile in $snapshotIdentities.Keys) {',
    '[IO.File]::WriteAllText((Join-Path $snapshotPath "source.txt"), "construction substitution"); foreach ($createdFile in $snapshotIdentities.Keys) {')
. ([scriptblock]::Create($injectedSnapshotSource))
try {
    Assert-Refused { New-LifecycleSourceSnapshot -RepositoryRoot $sourceRoot -Commit $admitted -DestinationRoot $fixture } 'snapshot bytes differ from the Git archive'
} finally { . ([scriptblock]::Create($snapshotFunction.Extent.Text)) }
$externalSnapshotFile = Join-Path $fixture 'external-source.txt'
[IO.File]::WriteAllText($externalSnapshotFile, 'initial')
$externalAclBefore = (Get-Acl -LiteralPath $externalSnapshotFile).Sddl
$hardlinkSnapshotSource = $snapshotFunction.Extent.Text.Replace(
    'foreach ($createdFile in $snapshotIdentities.Keys) {',
    '[IO.File]::Delete((Join-Path $snapshotPath "source.txt")); New-Item -ItemType HardLink -Path (Join-Path $snapshotPath "source.txt") -Target $externalSnapshotFile | Out-Null; foreach ($createdFile in $snapshotIdentities.Keys) {')
. ([scriptblock]::Create($hardlinkSnapshotSource))
try {
    Assert-Refused { New-LifecycleSourceSnapshot -RepositoryRoot $sourceRoot -Commit $admitted -DestinationRoot $fixture } 'creation identity or single-link'
} finally { . ([scriptblock]::Create($snapshotFunction.Extent.Text)) }
if ((Get-Acl -LiteralPath $externalSnapshotFile).Sddl -cne $externalAclBefore) { throw 'Substituted hard link changed an external ACL.' }
# Try replacing a directory at the former post-RecordDirectory race boundary.
$script:directoryRenameBlocked = $false
$directorySnapshotSource = $snapshotFunction.Extent.Text.Replace(
    '$createdDirectories.Add($directoryPath) | Out-Null',
    'try { [IO.Directory]::Move($directoryPath, $directoryPath + "-replaced") } catch [IO.IOException] { $script:directoryRenameBlocked = $true }; if (-not $script:directoryRenameBlocked) { throw "Snapshot directory replacement succeeded." }; $createdDirectories.Add($directoryPath) | Out-Null')
. ([scriptblock]::Create($directorySnapshotSource))
try {
    $directorySnapshot = New-LifecycleSourceSnapshot -RepositoryRoot $sourceRoot -Commit $admitted -DestinationRoot $fixture
    if (-not $script:directoryRenameBlocked -or [IO.File]::ReadAllText((Join-Path $directorySnapshot 'nested/child.txt')) -cne 'child') {
        throw 'Snapshot directory pin regression failed.'
    }
} finally { . ([scriptblock]::Create($snapshotFunction.Extent.Text)) }
Write-Host "LAN segment safety fixtures passed: $fixture"
