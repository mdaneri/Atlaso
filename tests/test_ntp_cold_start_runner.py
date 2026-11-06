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
