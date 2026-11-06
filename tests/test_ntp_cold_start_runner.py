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
