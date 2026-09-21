"""Exercise actual PowerShell private-topology readback without VMware actions."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.test_lifecycle_original_ownership import ps_literal

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(os.name != 'nt' or not shutil.which('pwsh'), reason='Windows provider identities')


@pytest.mark.parametrize('fault', [None, 'duplicate', 'generated', 'disconnected'])
def test_provider_mapping_reads_actual_vmx_and_refuses_ambiguity(tmp_path, fault):
    """Admit only explicit observed provider adapter identities under a file pin.

    Args:
        tmp_path: Owned disposable test directory.
        fault: Invalid provider identity or connection field.
    """
    vmx = tmp_path / 'owned.vmx'
    lines = ['ethernet0.present = "TRUE"', 'ethernet0.connectionType = "custom"',
        'ethernet0.vnet = "VMnet8"', 'ethernet0.addressType = "static"',
        'ethernet0.address = "00:50:56:20:00:01"', 'ethernet0.startConnected = "TRUE"']
    if fault == 'duplicate':
        lines.append(lines[2])
    elif fault == 'generated':
        lines[3] = 'ethernet0.addressType = "generated"'
    elif fault == 'disconnected':
        lines[-1] = 'ethernet0.startConnected = "FALSE"'
    vmx.write_text('\n'.join(lines))
    helpers = ROOT / 'scripts/windows/vmware'
    command = ("$ErrorActionPreference='Stop'; "
        f"Import-Module {ps_literal(helpers / 'Atlaso.WorkstationCleanup.psm1')} -Force; "
        f". {ps_literal(helpers / 'Atlaso.RoutingOverlap.ps1')}; "
        f"Get-RoutingOverlapProviderNics -Vmx {ps_literal(vmx)} -Role client-a | ConvertTo-Json -Compress")
    result = subprocess.run(['pwsh', '-NoProfile', '-Command', command], capture_output=True, text=True, timeout=60)
    if fault:
        assert result.returncode != 0
    else:
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == {'role': 'client-a', 'adapter': 0, 'mac': '00:50:56:20:00:01',
            'network_type': 'custom', 'network_id': 'VMnet8'}


def test_private_dispatch_preserves_unknown_apply_and_avoids_legacy_client():
    """Keep uncertain Apply ahead of all controller/VM cleanup and legacy auth."""
    runner = (ROOT / 'scripts/windows/vmware/run-lifecycle-test.ps1').read_text()
    start = runner.index('if ($RoutingOverlapOnly) {\n        Invoke-RoutingOverlapPhase -Phase scenario')
    legacy = runner.index('$applianceHostKey = Get-PlinkHostKey', start)
    assert '} else {' in runner[start:legacy]
    unknown = runner.index('if ($overlapRecoveryUncertain) {')
    assert unknown < runner.index('if ($overlapStarted -and', unknown)
    assert unknown < runner.index('$seedCleanupFailure = $null', unknown)
    assert "-not $RoutingOverlapOnly" in (ROOT / 'scripts/windows/vmware/invoke-lifecycle-test.ps1').read_text()
    helper = (ROOT / 'scripts/windows/vmware/Atlaso.RoutingOverlap.ps1').read_text()
    assert "$arguments = @('-B'," in helper
    assert runner.index("python -I -B -c 'import paramiko, cryptography, pycdlib'") < runner.index('$preflightRootCreated')


def test_distinct_root_credential_reaches_only_appliance_stdin():
    """Keep administrator, root and client identities separate in the real producer."""
    runner = ROOT / 'scripts/windows/vmware/run-lifecycle-test.ps1'
    command = ("$ErrorActionPreference='Stop'; $tokens=$null; $errors=$null; "
        f"$ast=[Management.Automation.Language.Parser]::ParseFile({ps_literal(runner)},[ref]$tokens,[ref]$errors); "
        "$definition=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] "
        "-and $node.Name -eq 'Invoke-LifecyclePython'},$true); . ([scriptblock]::Create($definition.Extent.Text)); "
        "function Assert-LifecycleSourcePins { }; function python { $script:received=($input | Out-String | ConvertFrom-Json); $global:LASTEXITCODE=0 }; "
        "$admin=ConvertTo-SecureString 'synthetic-admin' -AsPlainText -Force; "
        "$root=ConvertTo-SecureString 'synthetic-root' -AsPlainText -Force; "
        "$client=ConvertTo-SecureString 'synthetic-client' -AsPlainText -Force; "
        "$pins=[Collections.Generic.List[IDisposable]]::new(); "
        "$null=Invoke-LifecyclePython -Arguments @('unused') -SourcePins $pins -AdminPassword $admin -RootPassword $root -SshPassword $client; "
        "[pscustomobject]@{admin=($script:received.password -ceq 'synthetic-admin'); "
        "root=($script:received.appliance_ssh_password -ceq 'synthetic-root'); "
        "client=($script:received.ssh_password -ceq 'synthetic-client')} | ConvertTo-Json -Compress")
    result = subprocess.run(['pwsh', '-NoProfile', '-Command', command], capture_output=True, text=True, timeout=60, check=True)
    assert json.loads(result.stdout) == {'admin': True, 'root': True, 'client': True}
    content = runner.read_text()
    assert '-RootPassword $rootPasswordSecure' in content
    assert "'root', '-gp', $RootGuestPassword" in content
    assert "'root', '-gp', $ApplianceGuestPassword" not in content


def test_legacy_bundle_without_root_field_remains_valid_under_strict_mode():
    """Preserve optional legacy input while private mode refuses missing root."""
    runner = ROOT / 'scripts/windows/vmware/run-lifecycle-test.ps1'
    command = ("Set-StrictMode -Version Latest; $ErrorActionPreference='Stop'; $tokens=$null; $errors=$null; "
        f"$ast=[Management.Automation.Language.Parser]::ParseFile({ps_literal(runner)},[ref]$tokens,[ref]$errors); "
        "$definition=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] "
        "-and $node.Name -eq 'Get-LifecycleRootCredential'},$true); . ([scriptblock]::Create($definition.Extent.Text)); "
        "$admin=ConvertTo-SecureString 'synthetic-admin' -AsPlainText -Force; $legacy=[pscustomobject]@{AdminPassword=$admin}; "
        "$value=Get-LifecycleRootCredential -Bundle $legacy -AdminPassword $admin; $refused=$false; "
        "try { $null=Get-LifecycleRootCredential -Bundle $legacy -AdminPassword $admin -RequireRoot } catch { $refused=$true }; "
        "[pscustomobject]@{same=[object]::ReferenceEquals($value,$admin); refused=$refused} | ConvertTo-Json -Compress")
    result = subprocess.run(['pwsh', '-NoProfile', '-Command', command], capture_output=True, text=True, timeout=60, check=True)
    assert json.loads(result.stdout) == {'same': True, 'refused': True}


@pytest.mark.parametrize('enabled', [False, True])
def test_seed_fixture_flag_is_one_python_argument(enabled):
    """Execute the real seed producer and capture its exact Python argument vector.

    Args:
        enabled: Whether the private fixture package and network mode is requested.
    """
    runner = ROOT / 'scripts/windows/vmware/run-lifecycle-test.ps1'
    command = ("$ErrorActionPreference='Stop'; $tokens=$null; $errors=$null; "
        f"$ast=[Management.Automation.Language.Parser]::ParseFile({ps_literal(runner)},[ref]$tokens,[ref]$errors); "
        "$definition=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] "
        "-and $node.Name -eq 'New-CloudInitSeedIso'},$true); "
        "function python { $script:capturedArguments=@($args); $global:LASTEXITCODE=0 }; "
        "function Invoke-SeedProducer { [CmdletBinding(SupportsShouldProcess=$true)] param(); "
        ". ([scriptblock]::Create($definition.Extent.Text)); "
        f"$runtimeSourceRoot={ps_literal(ROOT)}; $RoutingOverlapOnly=${str(enabled).lower()}; "
        "$ClientSshUser='alpine'; $SshPassword='synthetic-fixture-only'; "
        "New-CloudInitSeedIso -Path 'owned-seed.iso' -HostName 'fixture' }; "
        "Invoke-SeedProducer -Confirm:$false; ConvertTo-Json -InputObject @($script:capturedArguments) -Compress")
    result = subprocess.run(['pwsh', '-NoProfile', '-Command', command], capture_output=True, text=True, timeout=60, check=True)
    expected = [str(ROOT / 'scripts/interop/create_nocloud_seed_iso.py'), '--output', 'owned-seed.iso',
        '--hostname', 'fixture', '--user', 'alpine', '--password-stdin']
    if enabled:
        expected.append('--routing-overlap-guest')
    assert json.loads(result.stdout) == expected
