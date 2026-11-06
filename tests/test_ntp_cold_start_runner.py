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
