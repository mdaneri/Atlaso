"""Exercise actual inspector consumer blocks without SDK access or live VMs."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tomllib
import venv
from pathlib import Path

import pytest

RUNTIME_PROBE = r"""
$ErrorActionPreference='Stop'
Import-Module (Join-Path $env:ATLASO_TEST_REPOSITORY 'scripts/windows/vmware/Atlaso.WorkstationCleanup.psm1')
Import-Module (Join-Path $env:ATLASO_TEST_REPOSITORY 'scripts/windows/vmware/Atlaso.SourceSnapshot.psm1')
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($env:ATLASO_TEST_WRAPPER,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Wrapper parse failed'}
$calls=@($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.CommandAst] -and
    $node.GetCommandName() -ceq 'Protect-AtlasoCertificatePythonRuntime'
},$true))
if($calls.Count -ne 1){throw 'Expected exactly one runtime admission'}
$PythonPath=$env:ATLASO_TEST_PYTHON
$evidenceRoot=$env:ATLASO_TEST_TEMP
$runtime=$null
try{
    $runtime=& ([scriptblock]::Create($calls[0].Extent.Text))
    Write-Output 'runtime-admitted'
}catch{[Console]::Error.WriteLine($_.Exception.Message);exit 1}
finally{if($runtime){foreach($pin in $runtime.Pins){$pin.Dispose()}}}
"""


def test_certificate_lock_includes_iso_reader():
    """Keep the supported credential runtime aligned with the ISO reader pin."""
    root = Path(__file__).resolve().parents[1]
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    reader = next(
        item
        for item in project["project"]["dependencies"]
        if item.startswith("pycdlib==")
    )
    for name in (
        "requirements-onepassword-deploy.in",
        "requirements-onepassword-deploy.lock",
    ):
        assert re.search(
            rf"^{re.escape(reader)}(?:\s|$)",
            (root / name).read_text(encoding="utf-8"),
            re.M,
        )


@pytest.mark.skipif(
    sys.platform != "win32" or shutil.which("pwsh") is None,
    reason="Windows runtime pins required",
)
@pytest.mark.parametrize(
    "wrapper", ["inspect-certificate-peer.ps1", "inspect-certificate-handoff.ps1"]
)
@pytest.mark.parametrize("iso_reader", [False, True])
def test_inspector_admits_iso_reader_before_credentials(tmp_path, wrapper, iso_reader):
    """Execute actual wrapper admission against an isolated synthetic runtime.

    Args:
        tmp_path: Task-owned pytest temporary directory.
        wrapper: Certificate entrypoint whose admission command is executed.
        iso_reader: Whether the required ISO reader is present alongside SSH.
    """
    root = Path(__file__).resolve().parents[1]
    runtime = tmp_path / "runtime"
    venv.EnvBuilder(with_pip=False).create(runtime)
    for name in ["paramiko", "pycdlib"] if iso_reader else ["paramiko"]:
        package = runtime / "Lib/site-packages" / name
        package.mkdir(parents=True)
        (package / "__init__.py").write_text("", encoding="utf-8")
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", RUNTIME_PROBE],
        capture_output=True,
        text=True,
        timeout=60,
        env={
            **os.environ,
            "ATLASO_TEST_REPOSITORY": str(root),
            "ATLASO_TEST_WRAPPER": str(root / "scripts/windows/vmware" / wrapper),
            "ATLASO_TEST_PYTHON": str(runtime / "Scripts/python.exe"),
            "ATLASO_TEST_TEMP": str(tmp_path),
        },
    )
    if iso_reader:
        assert result.returncode == 0, result.stdout + result.stderr
        assert "runtime-admitted" in result.stdout
    else:
        assert result.returncode != 0
        assert (
            "Credentialed validation Python dependencies are incomplete"
            in result.stderr
        )


CONSUMER_PROBE = r"""
$ErrorActionPreference='Stop'
. (Join-Path $env:ATLASO_TEST_REPOSITORY 'scripts/windows/vmware/Atlaso.WorkstationFirstBoot.ps1')
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($env:ATLASO_TEST_WRAPPER,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Wrapper parse failed'}
$calls=@($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.CommandAst] -and
    $node.GetCommandName() -ceq 'Invoke-AtlasoBoundedProcess' -and
    @($node.CommandElements|Where-Object{
        $_ -is [Management.Automation.Language.CommandParameterAst] -and
        $_.ParameterName -ceq 'EnvironmentVariables'
    }).Count -eq 1
},$true))
if($calls.Count -ne 1){throw 'Expected exactly one credentialed consumer'}
$invocation=$calls[0]
while($invocation.Parent -isnot [Management.Automation.Language.StatementBlockAst]){
    $invocation=$invocation.Parent
}
$statements=@($invocation.Parent.Statements)
$start=@($statements|Where-Object{
    $_ -is [Management.Automation.Language.AssignmentStatementAst] -and
    $_.Left -is [Management.Automation.Language.VariableExpressionAst] -and
    $_.Left.VariablePath.UserPath -ceq 'plain' -and
    $_.Extent.StartOffset -lt $invocation.Extent.StartOffset
}|Select-Object -Last 1)
if($start.Count -ne 1){throw 'Expected original administrator credential conversion'}
$consumer=($statements|Where-Object{
    $_.Extent.StartOffset -ge $start[0].Extent.StartOffset -and
    $_.Extent.EndOffset -le $invocation.Extent.EndOffset
}|ForEach-Object{$_.Extent.Text}) -join "`n"
$mode=$env:ATLASO_TEST_MODE
$transport=[pscustomobject]@{}
if($mode -ne 'default'){
    $selected=if($mode -eq 'dpapi-empty'){'dpapi-task-key'}else{$mode}
    $transport|Add-Member authentication_mode $selected
}
$planIdentity=[pscustomobject]@{peer_transport=$transport}
$pair=[pscustomobject]@{AdminPassword=(ConvertTo-SecureString 'synthetic-admin' -AsPlainText -Force)}
$peerPlain=if($mode -eq 'dpapi-task-key'){'synthetic-approved-task-key'}else{$null}
$evidenceRoot=$env:ATLASO_TEST_TEMP
$PythonPath=$env:ATLASO_TEST_PYTHON
$arguments=@('-I','-B','-c',@'
import os
assert os.environ['ATLASO_NATIVE_ADMIN']=='synthetic-admin'
assert 'ATLASO_NATIVE_UNSELECTED' not in os.environ
mode=os.environ['ATLASO_TEST_MODE']
if mode=='dpapi-task-key':
    assert os.environ['ATLASO_NATIVE_PEER_KEY']=='synthetic-approved-task-key'
else:
    assert 'ATLASO_NATIVE_PEER_KEY' not in os.environ
assert os.environ['TEMP']==os.environ['ATLASO_TEST_TEMP']
assert os.environ['TMP']==os.environ['ATLASO_TEST_TEMP']
'@)
try{& ([scriptblock]::Create($consumer));Write-Output 'credential-consumer-verified'}
catch{[Console]::Error.WriteLine($_.Exception.Message);exit 1}
finally{$pair.AdminPassword.Dispose()}
"""


@pytest.mark.skipif(
    sys.platform != "win32" or shutil.which("pwsh") is None,
    reason="Native Windows bounded process-tree containment and PowerShell are required",
)
@pytest.mark.parametrize(
    "wrapper", ["inspect-certificate-peer.ps1", "inspect-certificate-handoff.ps1"]
)
@pytest.mark.parametrize("mode", ["agent", "default", "dpapi-task-key", "dpapi-empty"])
def test_native_consumer_forwards_only_selected_credentials(tmp_path, wrapper, mode):
    """Run each real consumer with the real bounded child and synthetic inputs.

    Args:
        tmp_path: Task-owned pytest temporary directory.
        wrapper: Certificate entrypoint whose actual AST statements are executed.
        mode: Explicit/default agent mode or an approved-task-key boundary case.
    """
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", CONSUMER_PROBE],
        capture_output=True,
        text=True,
        timeout=30,
        env={
            **os.environ,
            "ATLASO_TEST_REPOSITORY": str(root),
            "ATLASO_TEST_WRAPPER": str(root / "scripts/windows/vmware" / wrapper),
            "ATLASO_TEST_PYTHON": sys.executable,
            "ATLASO_TEST_MODE": mode,
            "ATLASO_TEST_TEMP": str(tmp_path),
            "ATLASO_NATIVE_ADMIN": "synthetic-inherited-admin",
            "ATLASO_NATIVE_PEER_KEY": "synthetic-unselected-key",
            "ATLASO_NATIVE_UNSELECTED": "synthetic-inherited-native-value",
        },
    )
    if mode == "dpapi-empty":
        assert result.returncode != 0
        assert "environment override is invalid" in result.stderr
    else:
        assert result.returncode == 0, result.stdout + result.stderr
        assert "credential-consumer-verified" in result.stdout
