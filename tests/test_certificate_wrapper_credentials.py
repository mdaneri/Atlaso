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


def _isolated_runtime_fixture(tmp_path: Path) -> Path:
    """Copy a real base runtime without inheriting runner-owned aliases.

    Args:
        tmp_path: Creation-bound pytest root containing every copied file.
    """
    base = tmp_path / "base"
    source = Path(sys.base_prefix)
    shutil.copytree(
        source / "Lib", base / "Lib",
        ignore=shutil.ignore_patterns("site-packages", "__pycache__"),
    )
    for file in source.iterdir():
        if file.is_file() and file.suffix.lower() in {".exe", ".dll", ".zip"}:
            # copy2 materializes python-versions' python3.exe symlink as a
            # regular fixture file; production admission still refuses links.
            shutil.copy2(file, base / file.name)
    runtime = tmp_path / "runtime"
    venv.EnvBuilder(with_pip=False).create(runtime)
    config = runtime / "pyvenv.cfg"
    text = config.read_text(encoding="utf-8")
    config.write_text(re.sub(r"(?m)^home = .+$", lambda _: f"home = {base}", text), encoding="utf-8")
    return runtime


@pytest.mark.skipif(
    sys.platform != "win32" or shutil.which("pwsh") is None,
    reason="Windows runtime pins required",
)
@pytest.mark.parametrize(
    "wrapper", ["inspect-certificate-peer.ps1", "inspect-certificate-handoff.ps1"]
)
@pytest.mark.parametrize("iso_reader", [False, True])
@pytest.mark.parametrize("linked_base", [False, True])
def test_inspector_admits_iso_reader_before_credentials(tmp_path, wrapper, iso_reader, linked_base):
    """Execute actual wrapper admission against an isolated synthetic runtime.

    Args:
        tmp_path: Task-owned pytest temporary directory.
        wrapper: Certificate entrypoint whose admission command is executed.
        iso_reader: Whether the required ISO reader is present alongside SSH.
        linked_base: Whether to introduce a forbidden hard link after copying.
    """
    root = Path(__file__).resolve().parents[1]
    runtime = _isolated_runtime_fixture(tmp_path)
    if linked_base:
        os.link(tmp_path / "base/Lib/abc.py", tmp_path / "base/linked-code.py")
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
    if linked_base:
        assert result.returncode != 0
        assert "Expected an ordinary single-identity file" in result.stderr
    elif iso_reader:
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


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell is unavailable")
@pytest.mark.parametrize(
    ("payload", "exit_code", "category"),
    [
        ('{"success":false,"reason":"peer_connection_failed"}', 2, "peer_connection_failed"),
        ('{"success":false,"reason":"appliance_authentication_failed"}', 2, "appliance_authentication_failed"),
        ('{"success":false,"reason":"peer_original_mac_lease_expired_or_missing"}', 2, "peer_original_mac_lease_expired_or_missing"),
        ('{"success":false,"reason":"token=synthetic-private-value"}', 2, "unclassified_proof_failure"),
        ('{"success":true,"reason":"peer_connection_failed"}', 2, "unclassified_proof_failure"),
        ('{"success":"false","reason":"peer_connection_failed"}', 2, "unclassified_proof_failure"),
        ('{"success":false,"reason":"PEER_CONNECTION_FAILED"}', 2, "unclassified_proof_failure"),
        ('{"success":false,"reason":"peer_connection_failed","extra":"synthetic-private-value"}', 2, "unclassified_proof_failure"),
        ('[{"success":false,"reason":"peer_connection_failed"}]', 2, "unclassified_proof_failure"),
        ('synthetic-private-value', 2, "unclassified_proof_failure"),
        ('{"success":false,"reason":"peer_connection_failed"}', 1, "unclassified_proof_failure"),
        (' ' * 1025, 2, "unclassified_proof_failure"),
    ],
)
def test_observation_classifier_emits_only_fixed_categories(payload, exit_code, category):
    """Reject malformed, unexpected or secret-bearing diagnostic output.

    Args:
        payload: Synthetic child stdout, never actual credential material.
        exit_code: Selected child exit status.
        category: Exact permitted public diagnostic category.
    """
    root = Path(__file__).resolve().parents[1]
    command = r"""
. (Join-Path $env:ATLASO_TEST_REPOSITORY 'scripts/windows/vmware/Atlaso.WorkstationFirstBoot.ps1')
Get-AtlasoCertificateObservationFailure -ExitCode ([int]$env:ATLASO_TEST_EXIT) -StandardOutput $env:ATLASO_TEST_PAYLOAD
"""
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True, text=True, timeout=20,
        env={**os.environ, "ATLASO_TEST_REPOSITORY": str(root),
             "ATLASO_TEST_PAYLOAD": payload, "ATLASO_TEST_EXIT": str(exit_code)},
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == (
        f"Certificate private address observations failed with exit code {exit_code} ({category})."
    )
    assert "synthetic-private-value" not in result.stdout + result.stderr


@pytest.mark.skipif(
    sys.platform != "win32" or shutil.which("pwsh") is None,
    reason="Native Windows bounded process containment required",
)
def test_bounded_observation_classifier_discards_raw_streams():
    """Exercise the real bounded runner with synthetic refusal and stderr."""
    root = Path(__file__).resolve().parents[1]
    command = r"""
$ErrorActionPreference='Stop'
. (Join-Path $env:ATLASO_TEST_REPOSITORY 'scripts/windows/vmware/Atlaso.WorkstationFirstBoot.ps1')
$child='[Console]::Out.Write(''{"success":false,"reason":"peer_connection_failed"}''); [Console]::Error.Write(''synthetic-private-value''); exit 2'
try {
    Invoke-AtlasoBoundedProcess -FilePath (Get-Process -Id $PID).Path -ArgumentList @('-NoProfile','-Command',$child) -TimeoutSeconds 20 -Action 'Certificate observation fixture' -FailureClassification certificate_observation -DiscardOutput
    throw 'Expected refusal'
} catch {
    Write-Output $_.Exception.Message
}
"""
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True, text=True, timeout=30,
        env={**os.environ, "ATLASO_TEST_REPOSITORY": str(root)},
    )
    assert result.returncode == 0
    assert result.stdout.strip() == (
        "Certificate private address observations failed with exit code 2 (peer_connection_failed)."
    )
    assert "synthetic-private-value" not in result.stdout + result.stderr
