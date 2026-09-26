"""Exercise original lifecycle ownership publication without VMware or secrets."""

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from scripts.completed_task_files import WindowsFiles

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(os.name != "nt" or not shutil.which("pwsh"), reason="Windows ownership primitives")


def ps_literal(value):
    """Quote one non-secret literal for an isolated PowerShell test.

    Args:
        value: Test-owned path or public fixture value.
    """
    return "'" + str(value).replace("'", "''") + "'"


def publish_command(tmp_path, resource, *, require_empty=True):
    """Build a bounded publisher invocation confined to the owned pytest tree.

    Args:
        tmp_path: Owned pytest root standing in for the configured durable root.
        resource: Original newly created resource to publish.
        require_empty: Require an unused directory.
    """
    vmware = ROOT / "scripts/windows/vmware"
    return (
        "$ErrorActionPreference='Stop'; "
        f"Import-Module {ps_literal(vmware / 'Atlaso.WorkstationCleanup.psm1')} -Force; "
        f". {ps_literal(vmware / 'Atlaso.LifecycleOwnership.ps1')}; "
        f"New-AtlasoLifecycleOwnershipRecord -DurableRoot {ps_literal(tmp_path)} "
        f"-Worktree {ps_literal(tmp_path / 'checkout')} -LabRoot {ps_literal(tmp_path / 'checkout/lab')} "
        f"-ResourcePath {ps_literal(resource)} -Kind lifecycle -TaskId synthetic-task "
        f"-SourceCommit {'a' * 40} -PullRequestNumber 868 "
        + ("-RequireEmpty " if require_empty else "") + "| ConvertTo-Json -Compress"
    )


def test_original_empty_root_identity_published_outside_removal_roots(tmp_path):
    """A real durable publication retains the initial Windows cleanup identity.

    Args:
        tmp_path: Existing owned validation subtree.
    """
    resource = tmp_path / "checkout/lab"
    resource.mkdir(parents=True)
    original = WindowsFiles().snapshot(resource)["."]["identity"]
    result = subprocess.run(["pwsh", "-NoProfile", "-Command", publish_command(tmp_path, resource)],
                            capture_output=True, text=True, timeout=60, check=True)
    published = json.loads(result.stdout.strip().splitlines()[-1])
    manifest = Path(published["path"])
    assert manifest.parent == tmp_path
    assert hashlib.sha256(manifest.read_bytes()).hexdigest() == published["sha256"]
    record = json.loads(manifest.read_text())
    assert record["root_identity"] == original
    assert record["task_id"] == "synthetic-task" and record["source_commit"] == "a" * 40
    assert record["pr"] == 868 and record["repository"] == "mdaneri/Atlaso"
    assert not list(resource.iterdir())


@pytest.mark.parametrize("fault", ["existing-content", "outside-lab"])
def test_original_publication_refuses_adoption_or_scope_escape(tmp_path, fault):
    """Refuse invalid original-creation evidence without publishing a manifest.

    Args:
        tmp_path: Owned validation subtree.
        fault: Invalid ownership condition.
    """
    resource = tmp_path / "checkout/lab"
    resource.mkdir(parents=True)
    if fault == "existing-content":
        (resource / "preexisting.txt").write_text("preserve")
    else:
        resource = tmp_path / "other"
        resource.mkdir()
    result = subprocess.run(["pwsh", "-NoProfile", "-Command", publish_command(tmp_path, resource)],
                            capture_output=True, text=True, timeout=60)
    assert result.returncode != 0
    assert not list(tmp_path.glob("atlaso-lifecycle-original-*"))
    assert resource.is_dir()


def test_manual_cli_does_not_require_codex_configuration():
    """Execute ownership selection with no agent context or new human options."""
    source = (ROOT / 'scripts/windows/vmware/run-lifecycle-test.ps1').read_text()
    start = source.index('$originalOwnershipRecords =')
    end = source.index('try {\ntry {', start)
    command = (
        "$ErrorActionPreference='Stop'; $env:CODEX_THREAD_ID=''; $PlanOnly=$false; "
        "$OwnershipRoot=''; $OwnershipTaskId=''; $LabName='Atlaso-PR-868-lifecycle-fixture'; "
        + source[start:end]
        + "; [pscustomobject]@{enabled=$externalOwnershipEnabled; records=$originalOwnershipRecords.Count} | ConvertTo-Json -Compress"
    )
    result = subprocess.run(['pwsh', '-NoProfile', '-Command', command], capture_output=True,
                            text=True, timeout=30, check=True)
    assert json.loads(result.stdout) == {'enabled': False, 'records': 0}


def test_agent_missing_active_configuration_fails_closed(tmp_path):
    """The agent resolver never substitutes a guessed root when configuration is absent.

    Args:
        tmp_path: Owned test directory selected as an empty active Codex directory.
    """
    vmware = ROOT / 'scripts/windows/vmware'
    command = (
        "$ErrorActionPreference='Stop'; "
        f"Import-Module {ps_literal(vmware / 'Atlaso.WorkstationCleanup.psm1')} -Force; "
        f". {ps_literal(vmware / 'Atlaso.LifecycleOwnership.ps1')}; "
        f"$env:CODEX_HOME={ps_literal(tmp_path)}; Get-AtlasoLifecycleDurableRoot"
    )
    result = subprocess.run(['pwsh', '-NoProfile', '-Command', command], capture_output=True, text=True, timeout=30)
    assert result.returncode != 0
    assert not list(tmp_path.iterdir())


def test_ownership_bootstrap_loads_actual_same_commit_git_dependencies():
    """In-memory cleanup imports its real LAN dependency without PSScriptRoot."""
    script = ROOT / 'scripts/windows/vmware/run-lifecycle-test.ps1'
    command = (
        "$ErrorActionPreference='Stop'; $tokens=$null; $errors=$null; "
        f"$ast=[Management.Automation.Language.Parser]::ParseFile({ps_literal(script)},[ref]$tokens,[ref]$errors); "
        "$function=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] "
        "-and $node.Name -eq 'Import-LifecycleOwnershipPrimitives'},$true); "
        ". ([scriptblock]::Create($function.Extent.Text)); "
        f"$commit=(& git -C {ps_literal(ROOT)} rev-parse HEAD).Trim(); "
        f"Import-LifecycleOwnershipPrimitives -RepositoryRoot {ps_literal(ROOT)} -Commit $commit; "
        "$command=Get-Command Resolve-AtlasoOwnedLanSegment -ErrorAction Stop; "
        "[pscustomobject]@{command=$command.Name; typePresent=($null -ne ('Atlaso.WorkstationDurablePublisherV3' -as [type]))} | ConvertTo-Json -Compress"
    )
    result = subprocess.run(['pwsh', '-NoProfile', '-Command', command], capture_output=True,
                            text=True, timeout=60, check=True)
    assert json.loads(result.stdout) == {'command': 'Resolve-AtlasoOwnedLanSegment', 'typePresent': True}


@pytest.mark.parametrize('target,load,active,intent,allowed', [
    (False, 'not-found', 'inactive', None, True),
    (False, 'loaded', 'active', None, False),
    (False, 'not-found', 'inactive', {'schema': 1}, False),
    (True, 'loaded', 'active', {'schema': 1}, True),
])
def test_predeployment_compatibility_refuses_unsupported_routing_state(target, load, active, intent, allowed):
    """Run the real source admission function before any deployment operation.

    Args:
        target: Whether the exact target contains the canonical routing handler.
        load: Native service load state.
        active: Native service active state.
        intent: Existing public routing intent.
        allowed: Expected compatibility outcome.
    """
    evidence = {'schema': 1, 'phase': 'before-lifecycle-deployment', 'routing_intent': intent,
                'routing_service': {'LoadState': load, 'ActiveState': active}}
    script = ROOT / 'scripts/windows/vmware/run-lifecycle-test.ps1'
    command = (
        "$ErrorActionPreference='Stop'; $tokens=$null; $errors=$null; "
        f"$ast=[Management.Automation.Language.Parser]::ParseFile({ps_literal(script)},[ref]$tokens,[ref]$errors); "
        "$function=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] "
        "-and $node.Name -eq 'Assert-LifecycleSourceNetworkCompatibility'},$true); "
        ". ([scriptblock]::Create($function.Extent.Text)); "
        f"$evidence={ps_literal(json.dumps(evidence))} | ConvertFrom-Json; "
        f"Assert-LifecycleSourceNetworkCompatibility -Evidence $evidence -TargetHasRoutingDomains ${str(target).lower()}"
    )
    result = subprocess.run(['pwsh', '-NoProfile', '-Command', command], capture_output=True, text=True, timeout=30)
    assert (result.returncode == 0) == allowed
