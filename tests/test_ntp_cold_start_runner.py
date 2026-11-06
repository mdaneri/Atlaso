"""Execute the NTP runner gate without loading credentials or VMware actions."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(("plan_only", "cleanup", "admitted"), [(True, True, True), (False, True, False), (False, False, True)])
def test_ntp_cleanup_gate_distinguishes_plan_only_from_a_live_retained_lab(plan_only, cleanup, admitted):
    """A default wrapper cleanup flag must not block a resource-free plan."""
    pwsh = shutil.which("pwsh")
    if not pwsh:
        pytest.skip("PowerShell is required for the executable runner guard check")
    program = r"""
$ErrorActionPreference='Stop'
$path=Join-Path (Get-Location) 'scripts/windows/vmware/run-lifecycle-test.ps1'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Runner parse failed.'}
$gate=@($ast.FindAll({param($node)
 $node -is [Management.Automation.Language.IfStatementAst] -and
 $node.Extent.Text.StartsWith('if ($NtpColdStartOnly) {')
},$true) | Sort-Object {$_.Extent.StartOffset})[0]
$NtpColdStartOnly=$true
$CertificateOnly=$false; $CertificateDhcpPeer=$false; $OidcOnly=$false; $TimeSourceOnly=$false
$ReverseProxyOnly=$false; $RoutingWanOnly=$false; $RoutingOverlapOnly=$false; $FullEsxiPxeInstall=$false
$AllowDryRunApply=$false; $ApplianceIPAddress=''; $ApplianceUrl=''; $SignedReleaseRepositoryUrl=''
$SiteInterface='eth0'; $SiteANetwork='lan:owned-ntp-plan'; $ManagementNetwork='VMnet8'
$ClientVmdkPath='public-source.vmdk'; $CertificatePeerPublicKeyPath='public-agent-key.pub'
$NtpPeerSourceReceiptPath='original.json'; $NtpPeerPreparedReceiptPath='prepared.json'
$NtpPeerSourceReceiptSha256='a'*64; $NtpPeerPreparedReceiptSha256='b'*64
$parameters=ConvertFrom-Json $env:ATLASO_NTP_TEST_GATE
$PlanOnly=[bool]$parameters.plan; $CleanupCreatedLab=[bool]$parameters.cleanup
try { . ([scriptblock]::Create($gate.Extent.Text)); '{"admitted":true}' }
catch { '{"admitted":false}' }
"""
    environment = dict(os.environ, ATLASO_NTP_TEST_GATE=json.dumps({"plan": plan_only, "cleanup": cleanup}))
    result = subprocess.run([pwsh, "-NoProfile", "-NonInteractive", "-Command", program], cwd=ROOT,
                            env=environment, capture_output=True, text=True, timeout=30, check=True)
    assert json.loads(result.stdout)["admitted"] is admitted


def test_selected_appliance_readbacks_use_the_selected_guest_credential():
    """Use AST-extracted readbacks with a stub runner and distinct secure identities."""
    pwsh = shutil.which("pwsh")
    if not pwsh:
        pytest.skip("PowerShell is required for the executable runner guard check")
    program = r"""
$ErrorActionPreference='Stop'
$path=Join-Path (Get-Location) 'scripts/windows/vmware/run-lifecycle-test.ps1'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Runner parse failed.'}
$handoff=$ast.Find({param($node)
 $node -is [Management.Automation.Language.AssignmentStatementAst] -and
 $node.Left.Extent.Text -eq '$privateAddress'
},$true)
if(-not $handoff){throw 'Private handoff address observation is missing.'}
$selector=$ast.Find({param($node)
 $node -is [Management.Automation.Language.AssignmentStatementAst] -and
 $node.Left.Extent.Text -eq '$applianceSshPasswordSecure'
},$true)
if(-not $selector){throw 'Selected appliance credential assignment is missing.'}
foreach($name in @('Get-CertificateSourceGuestState','Get-CertificateInstalledHelperSha256')){
 $definition=$ast.Find({param($node)
  $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
 },$true)
 if(-not $definition){throw "Readback helper is missing: $name"}
 . ([scriptblock]::Create($definition.Extent.Text))
}
$script:rootPasswordSecure=ConvertTo-SecureString 'synthetic-root-identity' -AsPlainText -Force
$script:adminPasswordSecure=ConvertTo-SecureString 'synthetic-admin-identity' -AsPlainText -Force
$script:LabName='synthetic-readback'
$script:resultRoot=Join-Path (Get-Location) 'test-results/ntp-cold-start-1097/credential-selection'
$script:captured=[Collections.Generic.List[object]]::new()
$script:expectedHelperHash='a'*64
$script:applianceName='synthetic-appliance'
$script:applianceVmx='synthetic.vmx'
$script:CertificateLeaseAddress='192.168.77.10'
function ConvertFrom-SecureString {
 param([Security.SecureString]$SecureString,[switch]$AsPlainText)
 if($SecureString.Equals($script:rootPasswordSecure)){return 'synthetic-root-auth'}
 if($SecureString.Equals($script:adminPasswordSecure)){return 'synthetic-admin-auth'}
 throw 'Readback selected an unexpected credential.'
}
function Invoke-VmrunBounded {
 param([object[]]$Arguments,[int]$TimeoutSeconds)
 $script:captured.Add([object]$Arguments)
 return [pscustomobject]@{TimedOut=$false;ExitCode=0}
}
function Test-Path { param($LiteralPath,$PathType) return $true }
function Get-Item { param($LiteralPath) return [pscustomobject]@{Length=128} }
function Get-Content {
 param($LiteralPath)
 if($LiteralPath -like '*source-app-readback*'){return @('LoadState=loaded','ActiveState=active')}
 return @("$($script:expectedHelperHash)  /opt/atlaso/bin/atlaso-helper")
}
function Remove-Item {
 [CmdletBinding()]
 param($LiteralPath,[switch]$Force)
}
function Wait-GuestIPv4 {
 param($Path,[int]$TimeoutSeconds,$GuestUser,[Security.SecureString]$GuestPassword,$Name,$ExpectedAddress,[switch]$SkipHostNeighbor)
 $script:handoffUser=$GuestUser
 $script:handoffCredentialMatches=$GuestPassword.Equals($script:applianceSshPasswordSecure)
 return $ExpectedAddress
}
function Test-CapturedIdentity {
 param([object[]]$Calls,[string]$ExpectedUser,[string]$ExpectedPassword)
 if($Calls.Count -ne 2){return $false}
 foreach($call in $Calls){
  $seenUser=$false; $seenPassword=$false
  for($index=0;$index -lt $call.Count-1;$index++){
   if($call[$index] -ceq '-gu' -and $call[$index+1] -ceq $ExpectedUser){$seenUser=$true}
   if($call[$index] -ceq '-gp' -and $call[$index+1] -ceq $ExpectedPassword){$seenPassword=$true}
  }
  if(-not $seenUser -or -not $seenPassword){return $false}
 }
 return $true
}
$results=@{}
foreach($user in @('root','admin')){
 $script:ApplianceSshUser=$user
 . ([scriptblock]::Create($selector.Extent.Text))
 $expectedPassword=if($user -ceq 'root'){'synthetic-root-auth'}else{'synthetic-admin-auth'}
 $script:captured.Clear()
 $null=Get-CertificateSourceGuestState -ApplianceVmx 'synthetic.vmx'
 $sourceOk=Test-CapturedIdentity -Calls @($script:captured.ToArray()) -ExpectedUser $user -ExpectedPassword $expectedPassword
 $script:captured.Clear()
 $null=Get-CertificateInstalledHelperSha256 -ApplianceVmx 'synthetic.vmx'
 $helperOk=Test-CapturedIdentity -Calls @($script:captured.ToArray()) -ExpectedUser $user -ExpectedPassword $expectedPassword
 $script:handoffUser=''
 $script:handoffCredentialMatches=$false
 . ([scriptblock]::Create($handoff.Extent.Text))
 $handoffOk=($privateAddress -ceq $script:CertificateLeaseAddress -and
  $script:handoffUser -ceq $user -and $script:handoffCredentialMatches)
 $results[$user]=@{source=$sourceOk;helper=$helperOk;handoff=$handoffOk}
}
$results | ConvertTo-Json -Compress
"""
    result = subprocess.run(
        [pwsh, "-NoProfile", "-NonInteractive", "-Command", program],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    assert json.loads(result.stdout) == {
        "root": {"source": True, "helper": True, "handoff": True},
        "admin": {"source": True, "helper": True, "handoff": True},
    }


def test_source_routing_probe_waits_for_schema_only_in_ntp_mode():
    """Execute the real probe caller with bounded native-I/O stubs for both modes."""
    pwsh = shutil.which("pwsh")
    if not pwsh:
        pytest.skip("PowerShell is required for the executable runner guard check")
    program = r"""
$ErrorActionPreference='Stop'
$path=Join-Path (Get-Location) 'scripts/windows/vmware/run-lifecycle-test.ps1'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Runner parse failed.'}
$definition=$ast.Find({param($node)
 $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
 $node.Name -eq 'Get-CertificateSourceRoutingSnapshot'
},$true)
if(-not $definition){throw 'Source routing snapshot caller is missing.'}
. ([scriptblock]::Create($definition.Extent.Text))
$script:probeSha='c'*64
$script:validJson='{"schema":1,"database":"/var/lib/atlaso/atlaso.db","state":"proven-absent","counts":{"routes":0,"routing_rules":0,"nat_rules":0,"port_forwards":0,"wan_policies":0,"route_physical_interfaces":0,"route_vlan_interfaces":0},"settings":{"routes_wan.routing_enabled":false,"routes_wan.wan_simulation_enabled":false,"routes_wan.nat_enabled":false,"traffic_publishing.nat_enabled":false}}'
$script:invalidJson='{"schema":1,"database":"/var/lib/atlaso/atlaso.db","state":"unproven","counts":{"routes":0,"routing_rules":0,"nat_rules":0,"port_forwards":0,"wan_policies":0,"route_physical_interfaces":0,"route_vlan_interfaces":0},"settings":{"routes_wan.routing_enabled":false,"routes_wan.wan_simulation_enabled":false,"routes_wan.nat_enabled":false,"traffic_publishing.nat_enabled":false}}'
$script:events=[Collections.Generic.List[string]]::new()
$script:calls=[Collections.Generic.List[object]]::new()
$script:resultRoot=Join-Path (Get-Location) 'test-results/ntp-cold-start-1097/source-probe-caller'
$script:runtimeSourceRoot=Get-Location
$script:runtimeConsumerPins=[Collections.Generic.List[IDisposable]]::new()
$script:ApplianceVmx='synthetic-appliance.vmx'
$script:rootPasswordSecure=ConvertTo-SecureString 'synthetic-root-credential' -AsPlainText -Force
$script:adminPasswordSecure=ConvertTo-SecureString 'synthetic-admin-credential' -AsPlainText -Force
function Assert-LifecycleSourcePins { param($Pins) $script:events.Add('pins') }
function Get-FileHash {
 param($LiteralPath,$Algorithm)
 $script:events.Add('hash')
 return [pscustomobject]@{Hash=$script:probeSha}
}
function ConvertFrom-SecureString {
 param([Security.SecureString]$SecureString,[switch]$AsPlainText)
 $script:events.Add('credential')
 if($SecureString.Equals($script:rootPasswordSecure)){return 'synthetic-root-auth'}
 if($SecureString.Equals($script:adminPasswordSecure)){return 'synthetic-admin-auth'}
 throw 'Unexpected synthetic probe identity.'
}
function Invoke-VmrunBounded {
 param([object[]]$Arguments,[int]$TimeoutSeconds)
 $script:events.Add('call')
 $script:calls.Add([pscustomobject]@{Arguments=$Arguments;Timeout=$TimeoutSeconds})
 if($Arguments -contains 'copyFileFromGuestToHost'){$script:outputReady=$true}
 return [pscustomobject]@{TimedOut=$false;ExitCode=0}
}
function Test-Path {
 param($LiteralPath,$PathType)
 if($LiteralPath -like '*source-routing-*'){return [bool]$script:outputReady}
 return $false
}
function Get-Item { param($LiteralPath) return [pscustomobject]@{Length=128} }
function Get-Content { param($LiteralPath,[switch]$Raw) return $script:readbackJson }
function Remove-Item { [CmdletBinding()] param($LiteralPath,[switch]$Force) }
function Test-Scenario {
 param([bool]$Ntp,[bool]$Invalid)
 $script:NtpColdStartOnly=$Ntp
 $script:readbackJson=if($Invalid){$script:invalidJson}else{$script:validJson}
 $script:outputReady=$false
 $script:events.Clear(); $script:calls.Clear()
 $script:ApplianceVmx='synthetic-appliance.vmx'
 $script:adminPasswordSecure=$script:adminPasswordSecure
 $script:rootPasswordSecure=$script:rootPasswordSecure
 $result=$null; $accepted=$false
 try {
  $result=Get-CertificateSourceRoutingSnapshot -ApplianceVmx $script:ApplianceVmx
  $accepted=$true
 } catch {}
 $query=@($script:calls | Where-Object {
  $_.Arguments -contains 'runScriptInGuest' -and $_.Arguments[-1] -like '*python3 *'
 }) | Select-Object -First 1
 $expectedCredential=if($Ntp){'synthetic-root-auth'}else{'synthetic-admin-auth'}
 $credentialMatches=@($script:calls | Where-Object {
  $position=[Array]::IndexOf($_.Arguments,'-gp')
  $position -ge 0 -and $_.Arguments[$position+1] -ceq $expectedCredential
 }).Count -eq $script:calls.Count
 $events=@($script:events)
 $callEvents=@(for($i=0;$i -lt $events.Count;$i++){if($events[$i] -ceq 'call'){$i}})
 $pinBeforeEveryCall=$true
 foreach($index in $callEvents){
  $priorPins=@($events | Select-Object -First $index | Where-Object {$_ -ceq 'pins'}).Count
  if($priorPins -eq 0){$pinBeforeEveryCall=$false}
 }
 $queryScript=[string]$query.Arguments[-1]
 $hashBeforeExecution=$queryScript.IndexOf('sha256sum -c -') -ge 0 -and
  $queryScript.IndexOf('sha256sum -c -') -lt $queryScript.IndexOf('python3 ')
 $hashIndex=[Array]::IndexOf($events,'hash')
 $credentialIndex=[Array]::IndexOf($events,'credential')
 $hashBeforeCredential=$hashIndex -ge 0 -and $hashIndex -lt $credentialIndex
 return [pscustomobject]@{
  accepted=$accepted; schema_rejected=($Invalid -and -not $accepted)
  timeout=$query.Timeout
  wait_option=($queryScript -like '*--wait-for-schema-seconds 120*')
  credential_matches=$credentialMatches
  source_pins_before_calls=$pinBeforeEveryCall
  source_hash_before_execution=$hashBeforeExecution
  source_hash_before_credential=$hashBeforeCredential
 }
}
$results=@{
 ntp_valid=Test-Scenario -Ntp $true -Invalid $false
 ntp_invalid=Test-Scenario -Ntp $true -Invalid $true
 legacy_valid=Test-Scenario -Ntp $false -Invalid $false
 legacy_invalid=Test-Scenario -Ntp $false -Invalid $true
}
$results | ConvertTo-Json -Compress -Depth 4
"""
    result = subprocess.run(
        [pwsh, "-NoProfile", "-NonInteractive", "-Command", program],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    output = json.loads(result.stdout)
    for mode in ("ntp_valid", "legacy_valid"):
        assert output[mode]["accepted"] is True
        assert output[mode]["credential_matches"] is True
        assert output[mode]["source_pins_before_calls"] is True
        assert output[mode]["source_hash_before_execution"] is True
        assert output[mode]["source_hash_before_credential"] is True
    assert output["ntp_valid"]["timeout"] == 130
    assert output["ntp_valid"]["wait_option"] is True
    assert output["legacy_valid"]["timeout"] == 20
    assert output["legacy_valid"]["wait_option"] is False
    assert output["ntp_invalid"]["schema_rejected"] is True
    assert output["legacy_invalid"]["schema_rejected"] is True


def test_ntp_peer_seed_enables_vix_without_changing_legacy_seed_arguments():
    """The focused NTP seed opts into VMware Tools guest operations only."""
    pwsh = shutil.which("pwsh")
    if not pwsh:
        pytest.skip("PowerShell is required for the executable runner guard check")
    program = r"""
$ErrorActionPreference='Stop'
$path=Join-Path (Get-Location) 'scripts/windows/vmware/run-lifecycle-test.ps1'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Runner parse failed.'}
$assignment=$ast.Find({param($node)
 $node -is [Management.Automation.Language.AssignmentStatementAst] -and
 $node.Left.Extent.Text -eq '$ntpOptions'
},$true)
if(-not $assignment){throw 'Peer seed option builder is missing.'}
$script:NtpColdStartOnly=$true
$script:LabName='synthetic-ntp'
$script:CertificateLeaseAddress='192.168.77.10'
$script:ntpBaselineAddress='192.168.78.2'
$script:ntpCandidateAddress='192.168.78.3'
$ntpAssignment=$assignment.Extent.Text
. ([scriptblock]::Create($ntpAssignment))
$ntpArgs=@($ntpOptions)
$script:NtpColdStartOnly=$false
$ntpOptions=$null
. ([scriptblock]::Create($ntpAssignment))
$legacyArgs=@($ntpOptions)
@{ntp=$ntpArgs;legacy=$legacyArgs} | ConvertTo-Json -Compress -Depth 5
"""
    result = subprocess.run(
        [pwsh, "-NoProfile", "-NonInteractive", "-Command", program],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    calls = json.loads(result.stdout)
    assert "--vmware-vix" in [str(value) for value in calls["ntp"]]
    assert "--vmware-vix" not in [str(value) for value in calls["legacy"]]


def test_peer_management_waiter_records_only_bounded_sanitized_ntp_timeout_categories():
    """Execute the actual waiter with a fake clock and bounded vmrun responses."""
    pwsh = shutil.which("pwsh")
    if not pwsh:
        pytest.skip("PowerShell is required for the executable runner guard check")
    program = r"""
$ErrorActionPreference='Stop'
$path=Join-Path (Get-Location) 'scripts/windows/vmware/run-lifecycle-test.ps1'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Runner parse failed.'}
$definition=$ast.Find({param($node)
 $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
 $node.Name -eq 'Wait-CertificatePeerManagementAddress'
},$true)
if(-not $definition){throw 'Peer management waiter is missing.'}
. ([scriptblock]::Create($definition.Extent.Text))
$script:NtpColdStartOnly=$true
$script:lifecycleTaskId='synthetic-task-id'
$script:PullRequestNumber=1121
$script:peerOwnership=[pscustomobject]@{Sha256=('d'*64)}
$script:clock=[datetime]'2026-01-01T00:00:00Z'
$script:polls=0
$script:category=$env:ATLASO_NTP_WAITER_CATEGORY
$script:commands=[Collections.Generic.List[object]]::new()
$script:receipts=[Collections.Generic.List[object]]::new()
function Get-Date { $script:clock }
function Start-Sleep { param([int]$Seconds) $script:clock=$script:clock.AddSeconds($Seconds) }
function Invoke-VmrunBounded {
 param([string[]]$Arguments,[int]$TimeoutSeconds)
 $script:polls++
 $script:commands.Add([pscustomobject]@{Arguments=$Arguments;Timeout=$TimeoutSeconds})
 switch($script:category){
  timeout {return [pscustomobject]@{TimedOut=$true;ExitCode=-1;StdOut='synthetic-secret-output'}}
  nonzero {return [pscustomobject]@{TimedOut=$false;ExitCode=1;StdOut='synthetic-secret-output'}}
  empty {return [pscustomobject]@{TimedOut=$false;ExitCode=0;StdOut=''}}
  unparseable {return [pscustomobject]@{TimedOut=$false;ExitCode=0;StdOut='boot diagnostic noise'}}
 }
}
function Get-GuestIPv4FromAddressText { param([string[]]$Lines) return '' }
function Write-CertificateLabReceipt { param([string]$Name,$Value) $script:receipts.Add([pscustomobject]@{Name=$Name;Value=$Value}); return [pscustomobject]@{Path='synthetic';Sha256=('e'*64)} }
$accepted=$false
try { $null=Wait-CertificatePeerManagementAddress -Path 'synthetic-peer.vmx'; $accepted=$true } catch {}
$commandScope=$true
foreach($call in $script:commands){
 if($call.Arguments.Count -ne 4 -or $call.Arguments[0] -cne '-T' -or
    $call.Arguments[1] -cne 'ws' -or $call.Arguments[2] -cne 'getGuestIPAddress' -or
    $call.Arguments[3] -cne 'synthetic-peer.vmx' -or $call.Timeout -ne 10){$commandScope=$false}
}
$receipt=$script:receipts | Select-Object -First 1
$receiptSafe=$false
if($receipt){
 $keys=@($receipt.Value.Keys)
 $receiptSafe=($receipt.Name -ceq 'peer-management-timeout.json' -and
   $receipt.Value.poll_count -eq $script:polls -and $receipt.Value.last_category -ceq $script:category -and
   $receipt.Value.peer_ownership_sha256 -ceq ('d'*64) -and
   $receipt.Value.task_id -ceq 'synthetic-task-id' -and
   $keys -notcontains 'address' -and $keys -notcontains 'stdout' -and $keys -notcontains 'stderr')
}
@{accepted=$accepted;polls=$script:polls;commands=$script:commands.Count;command_scope=$commandScope;
 receipt_safe=$receiptSafe;receipt_count=$script:receipts.Count} | ConvertTo-Json -Compress
"""
    for outcome in ("timeout", "nonzero", "empty", "unparseable"):
        result = subprocess.run(
            [pwsh, "-NoProfile", "-NonInteractive", "-Command", program],
            cwd=ROOT,
            env=dict(os.environ, ATLASO_NTP_WAITER_CATEGORY=outcome),
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        observed = json.loads(result.stdout)
        assert observed == {
            "accepted": False,
            "polls": 60,
            "commands": 60,
            "command_scope": True,
            "receipt_safe": True,
            "receipt_count": 1,
        }


def test_ntp_seed_cleanup_never_hard_stops_and_legacy_fallback_is_retained():
    """Execute the cleanup helper with stateful vmrun stubs for both modes."""
    pwsh = shutil.which("pwsh")
    if not pwsh:
        pytest.skip("PowerShell is required for the executable runner guard check")
    program = r"""
$ErrorActionPreference='Stop'
$path=Join-Path (Get-Location) 'scripts/windows/vmware/run-lifecycle-test.ps1'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Runner parse failed.'}
$definition=$ast.Find({param($node)
 $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
 $node.Name -eq 'Stop-WorkstationVmForSeedCleanup'
},$true)
if(-not $definition){throw 'Seed cleanup stop helper is missing.'}
. ([scriptblock]::Create($definition.Extent.Text))
function Test-Path { param($LiteralPath,$PathType) return $true }
function Test-WorkstationVmRunning { param($Path) $script:runningChecks++; return $script:running }
function Invoke-VmrunBounded {
 param([string[]]$Arguments,[int]$TimeoutSeconds)
 $script:actions.Add([pscustomobject]@{Arguments=$Arguments;Timeout=$TimeoutSeconds})
 if($Arguments[-1] -ceq 'hard'){$script:running=$false}
 elseif($Arguments[-1] -ceq 'soft' -and $script:softFails){return [pscustomobject]@{TimedOut=$false;ExitCode=1}}
 elseif($script:softStops){$script:running=$false}
 return [pscustomobject]@{TimedOut=$false;ExitCode=0}
}
function Scenario {
 param([string]$Mode,[bool]$InitiallyRunning,[bool]$SoftStops,[bool]$SoftFails=$false)
 $script:NtpColdStartOnly=($Mode -ceq 'ntp')
 $script:running=$InitiallyRunning; $script:softStops=$SoftStops; $script:softFails=$SoftFails; $script:runningChecks=0
 $script:actions=[Collections.Generic.List[object]]::new()
 $threw=$false; $returned=$null
 try{$returned=Stop-WorkstationVmForSeedCleanup -Path 'synthetic-peer.vmx'}catch{$threw=$true}
 return [pscustomobject]@{threw=$threw;returned=$returned;actions=@($script:actions | ForEach-Object {$_.Arguments[-1]})}
}
@{
 ntp_off=Scenario ntp $false $false
 ntp_soft=Scenario ntp $true $true
 ntp_stuck=Scenario ntp $true $false
 ntp_soft_failure=Scenario ntp $true $false $true
 legacy_stuck=Scenario legacy $true $false
 legacy_soft_failure=Scenario legacy $true $false $true
} | ConvertTo-Json -Compress -Depth 4
"""
    result = subprocess.run(
        [pwsh, "-NoProfile", "-NonInteractive", "-Command", program],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    assert json.loads(result.stdout) == {
        "ntp_off": {"threw": False, "returned": False, "actions": []},
        "ntp_soft": {"threw": False, "returned": True, "actions": ["soft"]},
        "ntp_stuck": {"threw": True, "returned": None, "actions": ["soft"]},
        "ntp_soft_failure": {"threw": True, "returned": None, "actions": ["soft"]},
        "legacy_stuck": {"threw": False, "returned": True, "actions": ["soft", "hard"]},
        "legacy_soft_failure": {"threw": False, "returned": True, "actions": ["soft", "hard"]},
    }


def test_ntp_post_tools_restart_is_seed_bound_single_use_and_precedes_existing_readiness(tmp_path: Path):
    """Execute the real NTP restart path and ownership/seed validators without vmrun."""
    pwsh = shutil.which("pwsh")
    if not pwsh:
        pytest.skip("PowerShell is required for the executable runner guard check")
    program = r"""
$ErrorActionPreference='Stop'
$scenario=$env:ATLASO_NTP_RESTART_SCENARIO
$scenarioRoot=Join-Path $env:ATLASO_NTP_RESTART_ROOT $scenario
if(Test-Path -LiteralPath $scenarioRoot){throw 'Synthetic scenario root already exists.'}
New-Item -ItemType Directory -Path $scenarioRoot | Out-Null
$repo=Join-Path $scenarioRoot 'durable\checkout'
$durable=Join-Path $scenarioRoot 'durable'
$lab=Join-Path $repo 'test-results\lifecycle-lab'
$peerDirectory=Join-Path $lab 'vms\synthetic-peer'
$seedDirectory=Join-Path $lab 'seed'
$evidenceRoot=Join-Path $durable 'synthetic-ntp-restart-ntp-native'
foreach($path in @($repo,$lab,$peerDirectory,$seedDirectory,$evidenceRoot)){New-Item -ItemType Directory -Path $path -Force | Out-Null}

Import-Module (Join-Path (Get-Location) 'scripts/windows/vmware/Atlaso.WorkstationCleanup.psm1') -Force
. (Join-Path (Get-Location) 'scripts/windows/vmware/Atlaso.LifecycleOwnership.ps1')
$cleanupPath=Join-Path (Get-Location) 'scripts/windows/vmware/Atlaso.WorkstationCleanup.psm1'
$ntpPath=Join-Path (Get-Location) 'scripts/windows/vmware/Atlaso.NtpColdStart.ps1'
$runnerPath=Join-Path (Get-Location) 'scripts/windows/vmware/run-lifecycle-test.ps1'
$tokens=$null; $errors=$null
$ntpAst=[Management.Automation.Language.Parser]::ParseFile($ntpPath,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'NTP module parse failed.'}
$runnerAst=[Management.Automation.Language.Parser]::ParseFile($runnerPath,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Lifecycle runner parse failed.'}
foreach($name in @('Assert-NtpPeerBootstrapOwnership','Assert-NtpPeerVmConfigBindings','Assert-NtpPeerSeedSnapshot',
                   'Initialize-NtpFixtureConsole','Release-NtpPeerBootstrapSeedPin',
                   'Invoke-NtpPeerPostToolsBootstrapRestart','Initialize-NtpPeerConsolePin')){
 $definition=$ntpAst.Find({param($node)
  $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
 },$true)
 if(-not $definition){throw "NTP function is missing: $name"}
 . ([scriptblock]::Create($definition.Extent.Text))
}
foreach($name in @('ConvertTo-VmxString','Set-VmxValue','Stop-WorkstationVmForSeedCleanup')){
 $definition=$runnerAst.Find({param($node)
  $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
 },$true)
 if(-not $definition){throw "Runner helper is missing: $name"}
 . ([scriptblock]::Create($definition.Extent.Text))
}

$script:durableOwnershipRoot=$durable
$script:repoRoot=$repo
$script:resultRoot=$lab
$script:lifecycleTaskId='synthetic-ntp-restart-task'
$script:sourceCommit='a3165c1faf804b8cb4525572c62806bb5830b942'
$script:PullRequestNumber=1121
$script:LabName='synthetic-ntp-restart'
$script:NtpColdStartOnly=$true
$script:CertificatePeerCidr='192.168.77.1/24'
$script:CertificateLeaseAddress='192.168.77.10'
$script:certificatePeerDirectory=$peerDirectory
$script:certificatePeerVmx=Join-Path $peerDirectory 'synthetic-peer.vmx'
$script:certificatePeerDiskPath=Join-Path $peerDirectory 'synthetic-peer.vmdk'
$script:certificatePeerDiskIdentity=''
$script:certificatePeerSeedIso=Join-Path $seedDirectory 'synthetic-peer.iso'
$script:certificatePeerKnownHostsPath=Join-Path $evidenceRoot 'peer-known-hosts'
$script:clientAName='synthetic-peer'
$script:ManagementNetwork='VMnet7'
$script:SiteANetwork='lan:Atlaso-PR-1121-Ntp-synthetic'
$script:ownedLanSegments=[Collections.Generic.List[object]]::new()
$script:ownedLanSegments.Add([pscustomobject]@{Id='synthetic-lan-id'})
$script:peerRunning=$false
$script:softFailure=$false
$script:postStopAttachmentDrift=$false
$script:events=[Collections.Generic.List[string]]::new()
$script:runtimeConsumerPins=[Collections.Generic.List[IDisposable]]::new()
$script:originalOwnershipRecords=[Collections.Generic.List[object]]::new()
$releaseBeforeConsoleSafe=$false
try{Release-NtpPeerBootstrapSeedPin;$releaseBeforeConsoleSafe=$true}catch{}
if(-not $releaseBeforeConsoleSafe){throw 'Early cleanup failed before the NTP console map was initialized.'}
$script:ntpConsoleReceipts=@{}

$directoryRecord=New-AtlasoLifecycleOwnershipRecord -DurableRoot $durable -Worktree $repo -LabRoot $lab `
 -ResourcePath $peerDirectory -Kind vm-directory -TaskId $lifecycleTaskId -SourceCommit $sourceCommit -PullRequestNumber $PullRequestNumber -RequireEmpty
$originalOwnershipRecords.Add($directoryRecord)
[IO.File]::WriteAllBytes($certificatePeerSeedIso,[byte[]](1,2,3,4,5,6,7,8))
$script:certificatePeerDiskPath=Join-Path $peerDirectory 'synthetic-peer.vmdk'
[IO.File]::WriteAllBytes($certificatePeerDiskPath,[byte[]](8,7,6,5,4,3,2,1))
$script:certificatePeerDiskIdentity=[Atlaso.WorkstationFileIdentity]::Get($certificatePeerDiskPath)
$attachmentLines=@(
 'displayName = "synthetic-peer"',
 'sata0:0.present = "TRUE"',
 'sata0:0.fileName = "synthetic-peer.vmdk"',
 'sata0:0.deviceType = "disk"',
 'sata0:1.present = "TRUE"',
 "sata0:1.fileName = $(ConvertTo-VmxString -Value $certificatePeerSeedIso)",
 'sata0:1.deviceType = "cdrom-image"',
 'sata0:1.startConnected = "TRUE"',
 'ethernet0.present = "TRUE"', 'ethernet0.connectionType = "custom"', 'ethernet0.vnet = "VMnet7"',
 'ethernet1.present = "TRUE"', 'ethernet1.connectionType = "pvn"', 'ethernet1.pvnID = "synthetic-lan-id"'
)
[IO.File]::WriteAllLines($certificatePeerVmx,$attachmentLines,[Text.UTF8Encoding]::new($false))
$vmxRecord=New-AtlasoLifecycleOwnershipRecord -DurableRoot $durable -Worktree $repo -LabRoot $lab `
 -ResourcePath $certificatePeerVmx -Kind vm -TaskId $lifecycleTaskId -SourceCommit $sourceCommit -PullRequestNumber $PullRequestNumber
$originalOwnershipRecords.Add($vmxRecord)
$directoryIdentity=[Atlaso.WorkstationFileIdentity]::Get($peerDirectory)
$identityParts=[regex]::Match($directoryIdentity,'^([0-9A-F]{8}):([0-9A-F]{8})([0-9A-F]{8})$')
if(-not $identityParts.Success){throw 'Synthetic peer directory identity is invalid.'}
$identityTuple=@(
 [Convert]::ToUInt32($identityParts.Groups[1].Value,16),
 [Convert]::ToUInt32($identityParts.Groups[2].Value,16),
 [Convert]::ToUInt32($identityParts.Groups[3].Value,16)
)
$script:peerIntentPath=Join-Path $evidenceRoot 'peer-vm-creation-intent.json'
$peerIntentValue=@{schema=1;kind='vm-creation-intent';task_id=$lifecycleTaskId;repository='mdaneri/Atlaso';
 pr=$PullRequestNumber;source_commit=$sourceCommit;path=$certificatePeerVmx;root_path=$peerDirectory;lab_root=$lab}
$peerIntentValue | ConvertTo-Json | Set-Content -LiteralPath $peerIntentPath -Encoding UTF8
$script:peerIntent=[pscustomobject]@{Path=$peerIntentPath;Sha256=(Get-FileHash -LiteralPath $peerIntentPath -Algorithm SHA256).Hash.ToLowerInvariant()}
$localOwnerPath=Join-Path $evidenceRoot 'peer-vm-original-ownership.json'
$localOwnerValue=@{schema=1;kind='vm';task_id=$lifecycleTaskId;repository='mdaneri/Atlaso';pr=$PullRequestNumber;
 source_commit=$sourceCommit;path=$certificatePeerVmx;root_path=$peerDirectory;root_identity=$identityTuple;
 intent_sha256=$peerIntent.Sha256;lab_root=$lab}
$localOwnerValue | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $localOwnerPath -Encoding UTF8
$script:peerOwnership=[pscustomobject]@{Path=$localOwnerPath;Sha256=(Get-FileHash -LiteralPath $localOwnerPath -Algorithm SHA256).Hash.ToLowerInvariant()}

function Write-CertificateLabReceipt {
 param([string]$Name,$Value)
 $script:events.Add("receipt:$Name")
 $target=Join-Path $script:evidenceRoot $Name
 if(Test-Path -LiteralPath $target){throw 'Synthetic immutable receipt already exists.'}
 $Value['observed_utc']=[DateTime]::UtcNow.ToString('o')
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 8))
 [IO.File]::WriteAllBytes($target,$bytes)
 return [pscustomobject]@{Path=$target;Sha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()}
}
function Test-WorkstationVmRunning { param([string]$Path) $script:events.Add("running:$($script:peerRunning)"); return $script:peerRunning }
function Invoke-VmrunBounded {
 param([string[]]$Arguments,[int]$TimeoutSeconds)
 if($Arguments -contains 'stop'){
  $script:events.Add("stop:$($Arguments[-1])")
  if($script:postStopAttachmentDrift){[IO.File]::WriteAllLines($script:certificatePeerVmx,@('sata0:1.present = "FALSE"'),[Text.UTF8Encoding]::new($false))}
  if($script:softFailure){return [pscustomobject]@{TimedOut=$false;ExitCode=1;StdErr='synthetic bounded failure'}}
  $script:peerRunning=$false
 }
 return [pscustomobject]@{TimedOut=$false;ExitCode=0;StdOut='';StdErr=''}
}
function Start-WorkstationVm { param([string]$Path) $script:events.Add('start'); $script:peerRunning=$true }
function Get-NtpConsolePublicKey { param([string]$Role) return [pscustomobject]@{PublicKey='ssh-ed25519 synthetic-public-key';Fingerprint='SHA256:synthetic-public-fingerprint'} }

Initialize-NtpFixtureConsole -Vmx $certificatePeerVmx -Role peer
$script:peerRunning=$true
Initialize-NtpPeerConsolePin
$script:events.Clear()
if($scenario -eq 'seed-drift'){
 $ntpConsoleReceipts['peer'].Seed.Pin.Dispose()
 [IO.File]::WriteAllBytes($certificatePeerSeedIso,[byte[]](8,7,6,5,4,3,2,1))
 $ntpConsoleReceipts['peer'].Seed.Pin=[Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($certificatePeerSeedIso,$true)
}
if($scenario -eq 'soft-failure'){$script:softFailure=$true}
if($scenario -eq 'post-stop-attachment-drift'){$script:postStopAttachmentDrift=$true}
if($scenario -eq 'vmx-rewrite'){
 $beforeIdentity=[Atlaso.WorkstationFileIdentity]::Get($certificatePeerVmx)
 $rewritePath="$certificatePeerVmx.rewrite"
 [IO.File]::WriteAllLines($rewritePath,(Get-Content -LiteralPath $certificatePeerVmx),[Text.UTF8Encoding]::new($false))
 Move-Item -LiteralPath $rewritePath -Destination $certificatePeerVmx -Force
 $afterIdentity=[Atlaso.WorkstationFileIdentity]::Get($certificatePeerVmx)
 if($beforeIdentity -ceq $afterIdentity){throw 'Synthetic VMX rewrite did not change its native file identity.'}
}
if($scenario -eq 'foreign-vmx-binding'){
 $foreignVmxText=[IO.File]::ReadAllText($certificatePeerVmx).Replace('ethernet0.vnet = "VMnet7"','ethernet0.vnet = "VMnet8"')
 [IO.File]::WriteAllText($certificatePeerVmx,$foreignVmxText,[Text.UTF8Encoding]::new($false))
}
if($scenario -eq 'duplicate-journal'){
 [IO.File]::WriteAllText((Join-Path $evidenceRoot 'peer-tools-bootstrap-restart-intent.json'),'synthetic prior immutable intent')
}
$accepted=$false; $errorMessage=''
try{$null=Invoke-NtpPeerPostToolsBootstrapRestart;$accepted=$true}catch{$errorMessage=$_.Exception.Message}
$terminalPath=Join-Path $evidenceRoot 'peer-tools-bootstrap-restart-terminal.json'
$terminal=$null
if(Test-Path -LiteralPath $terminalPath){$terminal=Get-Content -LiteralPath $terminalPath -Raw|ConvertFrom-Json}
$seedAttached=$false
try{Assert-NtpPeerSeedSnapshot -SeedSnapshot $ntpConsoleReceipts['peer'].Seed;$seedAttached=$true}catch{}
$terminalState='';$terminalReady=$null;$terminalCloudInit='';$terminalSeedAttached=$null
$journalVmxBirthIdentity='';$journalVmxObservedIdentity=''
if($null -ne $terminal){
 $terminalState=[string]$terminal.PSObject.Properties['state'].Value
 $terminalReady=$terminal.PSObject.Properties['ready'].Value
 $terminalCloudInit=[string]$terminal.PSObject.Properties['cloud_init_state'].Value
 $terminalSeedAttached=$terminal.PSObject.Properties['seed_attached'].Value
 $journalVmxBirthIdentity=[string]$terminal.PSObject.Properties['peer_vmx_birth_identity'].Value
 $journalVmxObservedIdentity=[string]$terminal.PSObject.Properties['peer_vmx_observed_identity'].Value
}
$startCount=0;$stopCount=0
foreach($eventName in $events){
 if([string]$eventName -ceq 'start'){$startCount++}
 if([string]$eventName -like 'stop:*'){$stopCount++}
}
$eventNames=@($events.ToArray())
$seedPathInIntent=[string]$ntpConsoleReceipts['peer'].Intent.Path
$vmxObservedIdentity=[Atlaso.WorkstationFileIdentity]::Get($certificatePeerVmx)
$vmxCreationReceipt=Get-Content -LiteralPath $vmxRecord.Path -Raw | ConvertFrom-Json
$vmxBirthIdentity=('{0:X8}:{1:X8}{2:X8}' -f [uint32]$vmxCreationReceipt.root_identity[0], [uint32]$vmxCreationReceipt.root_identity[1], [uint32]$vmxCreationReceipt.root_identity[2])
$result=[ordered]@{
 scenario=$scenario;accepted=$accepted;peer_running=$peerRunning;seed_exists=(Test-Path -LiteralPath $certificatePeerSeedIso)
 seed_attached=$seedAttached;seed_path_in_intent=$seedPathInIntent
 event_names=$eventNames;start_count=$startCount;stop_count=$stopCount
 intent_exists=(Test-Path -LiteralPath (Join-Path $evidenceRoot 'peer-tools-bootstrap-restart-intent.json'))
 terminal_state=$terminalState;terminal_ready=$terminalReady
 terminal_cloud_init=$terminalCloudInit;terminal_seed_attached=$terminalSeedAttached
 journal_vmx_birth_identity=$journalVmxBirthIdentity;journal_vmx_observed_identity=$journalVmxObservedIdentity
 vmx_observed_identity=$vmxObservedIdentity;vmx_birth_identity=$vmxBirthIdentity
 intent_has_seed_binding=$false
 error=$errorMessage
}
$consoleIntent=Get-Content -LiteralPath $ntpConsoleReceipts['peer'].Intent.Path -Raw|ConvertFrom-Json
$result.intent_has_seed_binding=($consoleIntent.seed.path -ceq $certificatePeerSeedIso -and
 $consoleIntent.seed.sha256 -ceq $ntpConsoleReceipts['peer'].Seed.sha256 -and
 $consoleIntent.seed.file_identity -ceq $ntpConsoleReceipts['peer'].Seed.file_identity -and
 $consoleIntent.seed.attachment.file_name -ceq $certificatePeerSeedIso)
$result|ConvertTo-Json -Compress -Depth 6
for($index=$runtimeConsumerPins.Count-1;$index -ge 0;$index--){$runtimeConsumerPins[$index].Dispose()}
Release-NtpPeerBootstrapSeedPin
"""
    for scenario in ("success", "vmx-rewrite", "seed-drift", "soft-failure", "post-stop-attachment-drift", "foreign-vmx-binding", "duplicate-journal"):
        result = subprocess.run(
            [pwsh, "-NoProfile", "-NonInteractive", "-Command", program],
            cwd=ROOT,
            env=dict(os.environ, ATLASO_NTP_RESTART_ROOT=str(tmp_path), ATLASO_NTP_RESTART_SCENARIO=scenario),
            capture_output=True,
            text=True,
            timeout=45,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        observed = json.loads(result.stdout)
        assert observed["scenario"] == scenario
        assert observed["intent_has_seed_binding"] is True
        assert observed["seed_exists"] is True
        if scenario in {"success", "vmx-rewrite"}:
            assert observed["accepted"] is True
            assert observed["peer_running"] is True
            assert observed["seed_attached"] is True
            assert observed["start_count"] == 1
            assert observed["stop_count"] == 1
            assert observed["event_names"].index("receipt:peer-tools-bootstrap-restart-intent.json") < observed["event_names"].index("stop:soft")
            assert observed["event_names"].index("stop:soft") < observed["event_names"].index("start")
            assert observed["event_names"].index("start") < observed["event_names"].index("receipt:peer-tools-bootstrap-restart-terminal.json")
            assert observed["terminal_state"] == "awaiting-tools-ssh"
            assert observed["terminal_ready"] is False
            assert observed["terminal_cloud_init"] == "not-observed"
            assert observed["terminal_seed_attached"] is True
            assert observed["journal_vmx_birth_identity"] == observed["vmx_birth_identity"]
            assert observed["journal_vmx_observed_identity"] == observed["vmx_observed_identity"]
            if scenario == "vmx-rewrite":
                assert observed["vmx_observed_identity"] != observed["vmx_birth_identity"]
        else:
            assert observed["accepted"] is False, observed
            assert observed["start_count"] == 0
        if scenario == "seed-drift":
            assert observed["stop_count"] == 0
            assert observed["intent_exists"] is False
        elif scenario == "soft-failure":
            assert observed["stop_count"] == 1
            assert observed["terminal_state"] == "failed-no-retry"
            assert "receipt:peer-tools-bootstrap-restart-terminal.json" in observed["event_names"]
        elif scenario == "post-stop-attachment-drift":
            assert observed["stop_count"] == 1
            assert observed["terminal_state"] == "failed-no-retry"
            assert observed["peer_running"] is False
        elif scenario == "duplicate-journal":
            assert observed["stop_count"] == 0
            assert observed["intent_exists"] is True
            assert observed["terminal_state"] == ""
        elif scenario == "foreign-vmx-binding":
            assert observed["stop_count"] == 0
            assert observed["start_count"] == 0

    # The actual runner keeps strict Tools/SSH/cloud-init readiness after the one-time restart.
    ps_program = r"""
$path=Join-Path (Get-Location) 'scripts/windows/vmware/run-lifecycle-test.ps1'
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Runner parse failed.'}
$block=$ast.Find({param($node)
 $node -is [Management.Automation.Language.IfStatementAst] -and
 $node.Extent.Text.Contains('Initialize-NtpPeerConsolePin') -and
 $node.Extent.Text.Contains('Invoke-NtpPeerPostToolsBootstrapRestart') -and
 $node.Extent.Text.Contains('Assert-CertificatePeerBootReady -Path $certificatePeerVmx')
},$true)
if(-not $block){throw 'First peer readiness block is missing.'}
$text=$block.Extent.Text
@{pin=($text.IndexOf('Initialize-NtpPeerConsolePin'));restart=($text.IndexOf('Invoke-NtpPeerPostToolsBootstrapRestart'));
 first_ready=($text.IndexOf('Assert-CertificatePeerBootReady -Path $certificatePeerVmx'));
 second_ready=($text.LastIndexOf('Assert-CertificatePeerBootReady -Path $certificatePeerVmx'))} | ConvertTo-Json -Compress
"""
    result = subprocess.run(
        [pwsh, "-NoProfile", "-NonInteractive", "-Command", ps_program],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    order = json.loads(result.stdout)
    assert 0 <= order["pin"] < order["restart"] < order["first_ready"] < order["second_ready"]

    # A pre-import runner failure must skip the later optional release helper safely.
    early_cleanup_program = r"""
$ErrorActionPreference='Stop'
$path=Join-Path (Get-Location) 'scripts/windows/vmware/run-lifecycle-test.ps1'
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Runner parse failed.'}
$guards=@($ast.FindAll({param($node)
 $node -is [Management.Automation.Language.IfStatementAst] -and
 $node.Extent.Text.Contains('Get-Command Release-NtpPeerBootstrapSeedPin') -and
 $node.Extent.Text.Contains('Release-NtpPeerBootstrapSeedPin')
},$true)|Sort-Object {$_.Extent.StartOffset})
if(-not $guards.Count){throw 'Optional NTP seed-release guard is missing.'}
$NtpColdStartOnly=$true
. ([scriptblock]::Create($guards[-1].Extent.Text))
'early cleanup guard passed'
"""
    result = subprocess.run(
        [pwsh, "-NoProfile", "-NonInteractive", "-Command", early_cleanup_program],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    assert result.stdout.strip() == "early cleanup guard passed"
