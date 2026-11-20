"""Exercise the real PowerShell/venv pipe relay without credentials or SSH."""

from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import sys
import threading
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(os.name != "nt" or shutil.which("pwsh") is None, reason="Windows venv launcher and process jobs")
def test_real_venv_proxy_can_exchange_receipts_before_its_parent_exits(tmp_path):
    """Regress the inherited-console deadlock with the actual production relay block.

    Args:
        tmp_path: Originally owned pytest output, containing only this synthetic fixture.
    """
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "native_rpm_ssh.py").write_text(
        "import sys,json\n"
        "print(json.dumps({'ready':True}),flush=True)\n"
        "assert json.loads(sys.stdin.readline())=={'release':'fixture'}\n"
        "print(json.dumps({'released':True}),flush=True)\n"
    )
    child = tmp_path / "relay.ps1"
    child.write_text(r"""
$ErrorActionPreference='Stop'
$source=Join-Path $env:SSH_RELAY_REPOSITORY 'scripts/windows/vmware/Invoke-AtlasoNativeRpmSsh.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Relay parser failed'}
$blocks=@($ast.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.TryStatementAst]})
if($blocks.Count -ne 1){throw 'Relay boundary differs'}
$repositoryRoot=$env:SSH_RELAY_FIXTURE
$PythonPath=$env:SSH_RELAY_PYTHON
$runtime=$repositoryRoot
$ContextPath=Join-Path $repositoryRoot 'unused-public-context.json'
$selector='synthetic-environment'
$context=@{deadline_epoch=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()+30}
$protected=ConvertTo-SecureString ('ops_'+('A'*80)) -AsPlainText -Force
$process=[Diagnostics.Process]::new()
$job=[pscustomobject]@{}
$job | Add-Member -MemberType ScriptMethod -Name Dispose -Value {}
Invoke-Expression $blocks[0].Extent.Text
""")
    owner = tmp_path / "owner.ps1"
    owner.write_text(r"""
$ErrorActionPreference='Stop'
. (Join-Path $env:SSH_RELAY_REPOSITORY 'scripts/windows/vmware/Atlaso.WorkstationFirstBoot.ps1')
$publisher={param($ProcessJob)
    @{pid=$ProcessJob.RootProcess.Id;birth=$ProcessJob.RootProcess.StartTime.ToUniversalTime().ToFileTimeUtc()} |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $env:SSH_RELAY_FIXTURE 'original-child.json')
}
Invoke-AtlasoBoundedStreamingProcess -FilePath (Get-Command pwsh).Source `
    -ArgumentList @('-NoProfile','-File',(Join-Path $env:SSH_RELAY_FIXTURE 'relay.ps1')) `
    -TimeoutSeconds 30 -Action 'Synthetic native SSH pipe relay' `
    -ProcessJobName $env:SSH_RELAY_JOB -ProcessOwnershipPublisher $publisher
""")
    environment = {**os.environ, "SSH_RELAY_REPOSITORY": str(ROOT), "SSH_RELAY_FIXTURE": str(tmp_path),
                   "SSH_RELAY_PYTHON": sys.executable, "SSH_RELAY_JOB": "Local\\Atlaso-Relay-" + uuid.uuid4().hex}
    process = subprocess.Popen(["pwsh", "-NoProfile", "-File", str(owner)], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
    messages: queue.Queue[bytes] = queue.Queue()

    def drain() -> None:
        """Read the bounded fixture's protocol without blocking the pytest owner."""
        for line in process.stdout:
            messages.put(line)
        messages.put(b"")

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    try:
        first = messages.get(timeout=20)
        assert json.loads(first) == {"ready": True}, first
        assert (tmp_path / "original-child.json").is_file()
        assert process.poll() is None, "Proxy must remain alive behind the receipt barrier"
        process.stdin.write(b'{"release":"fixture"}\n')
        process.stdin.flush()
        process.stdin.close()
        assert json.loads(messages.get(timeout=10)) == {"released": True}
        assert process.wait(timeout=10) == 0, process.stderr.read().decode()
    finally:
        if process.poll() is None:
            # The fixture controller is the sole owner of its kill-on-close job.
            # Killing only that controller closes the job and kills its children.
            process.kill()
            process.wait(timeout=10)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream and not stream.closed:
                stream.close()
        reader.join(timeout=2)
