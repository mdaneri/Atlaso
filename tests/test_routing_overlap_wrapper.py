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


def test_client_vmx_provides_canonical_pcie_bridges_for_vmxnet3():
    """Evaluate VMX generation without host writes and admit the PCIe scaffold."""
    runner = ROOT / 'scripts/windows/vmware/run-lifecycle-test.ps1'
    command = ("$ErrorActionPreference='Stop'; $tokens=$null; $errors=$null; "
        f"$ast=[Management.Automation.Language.Parser]::ParseFile({ps_literal(runner)},[ref]$tokens,[ref]$errors); "
        "if ($errors.Count) { throw 'PowerShell parse failed' }; "
        "$Name='fixture'; $diskTarget='fixture.vmdk'; $SeedIso='seed.iso'; "
        "function ConvertTo-VmxString { param($Value) return '\"' + $Value + '\"' }; "
        "$result=@{}; foreach ($nameOfFunction in @('New-ClientVm','New-EsxiPxeVm')) { "
        "$definition=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] "
        "-and $node.Name -eq $nameOfFunction},$true); "
        "$assignment=$definition.Body.Find({param($node) $node -is [Management.Automation.Language.AssignmentStatementAst] "
        "-and $node.Left.Extent.Text -eq '$lines'},$true); "
        ". ([scriptblock]::Create($assignment.Extent.Text)); "
        "$result[$nameOfFunction]=@($lines | Where-Object { $_ -like 'pciBridge*' }) }; "
        "ConvertTo-Json -InputObject $result -Compress")
    result = subprocess.run(['pwsh', '-NoProfile', '-Command', command], capture_output=True, text=True, timeout=60, check=True)
    bridges = json.loads(result.stdout)
    expected = ['pciBridge0.present = "TRUE"']
    for index in range(4, 8):
        expected.extend([f'pciBridge{index}.present = "TRUE"',
                         f'pciBridge{index}.virtualDev = "pcieRootPort"',
                         f'pciBridge{index}.functions = "8"'])
    assert bridges['New-ClientVm'] == expected
    assert bridges['New-ClientVm'] == bridges['New-EsxiPxeVm']


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


@pytest.mark.parametrize('script_name', ['invoke-lifecycle-test.ps1', 'run-lifecycle-test.ps1'])
@pytest.mark.parametrize('mode', ['plan', 'run-missing', 'run-valid', 'run-bad-task'])
def test_private_plan_binding_skips_only_execution_prerequisites(script_name, mode):
    """Execute real parameter binding and private guards without the script body.

    Args:
        script_name: Public wrapper or downstream runner to exercise.
        mode: Plan binding, incomplete Run, complete Run, or Run with an invalid task identity.
    """
    path = ROOT / 'scripts/windows/vmware' / script_name
    downstream = script_name == 'run-lifecycle-test.ps1'
    arguments = "@{PullRequestNumber=868; RoutingOverlapOnly=$true; CollisionSuffix='guard-test'}"
    additions = ""
    if downstream:
        additions += "$arguments.ApplianceVmxPath='unused-source.vmx'; $arguments.ClientVmdkPath='unused-client.vmdk'; "
    if mode == 'plan':
        additions += "$arguments.PlanOnly=$true; "
    elif mode in {'run-valid', 'run-bad-task'}:
        additions += "$arguments.ApplianceSshUser='root'; "
        if not downstream:
            additions += "$arguments.SkipClientPrepare=$true; $arguments.ClientVmdkPath='unused-client.vmdk'; "
    task_id = '11111111-2222-3333-4444-555555555555' if mode == 'run-valid' else 'ordinary-human-plan'
    # Only the real binding and the selected guards execute. No provider lookup,
    # credential prompt, source snapshot, plan.json write, or other script body.
    command = ("$ErrorActionPreference='Stop'; $tokens=$null; $errors=$null; "
        f"$ast=[Management.Automation.Language.Parser]::ParseFile({ps_literal(path)},[ref]$tokens,[ref]$errors); "
        "$guards=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.IfStatementAst] -and "
        "($node.Extent.Text.Contains(\"throw 'Private overlap requires a prepared client disk\") -or "
        "$node.Extent.Text.Contains(\"throw 'Private overlap requires external ownership\") -or "
        "$node.Extent.Text.Contains(\"throw 'Private guest ownership requires an originating UUID\")) },$true)); "
        f"if ($guards.Count -ne {2 if downstream else 1}) {{ throw 'Expected guard ASTs were not found' }}; "
        "$body=$ast.ParamBlock.Extent.Text + [Environment]::NewLine + "
        f"'$externalOwnershipEnabled=$true; $lifecycleTaskId=\"{task_id}\"; ' + "
        "(($guards | ForEach-Object {$_.Extent.Text}) -join [Environment]::NewLine); "
        f"$arguments={arguments}; {additions}"
        "$accepted=$false; try { & ([scriptblock]::Create($body)) @arguments; $accepted=$true } catch { }; "
        "$accepted | ConvertTo-Json -Compress")
    result = subprocess.run(['pwsh', '-NoProfile', '-Command', command], capture_output=True, text=True, timeout=60, check=True)
    assert json.loads(result.stdout) is (mode != 'run-missing' and not (downstream and mode == 'run-bad-task'))
