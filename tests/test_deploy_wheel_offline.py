"""Check the shipped local-wheel commands against pip's actual network behavior."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest


@pytest.mark.parametrize("wheel_variable", ["runtime_dependency_path", "wheel"])
def test_local_wheel_install_does_not_check_the_network(tmp_path: Path, wheel_variable: str):
    """Run the shipped options through real pip without installing the probe wheel.

    Args:
        tmp_path: Originally owned disposable test directory.
        wheel_variable: Dependency or application wheel argument in the shipped engine.
    """
    source = Path("scripts/windows/vmware/deploy-wheel.ps1").read_text(encoding="utf-8")
    lines = [line.strip() for line in source.splitlines()
             if line.strip().startswith('"$python" -m pip install ')
             and line.strip().endswith(f'"${wheel_variable}"')]
    assert len(lines) == 1
    options = shlex.split(lines[0])[3:-1]
    wheel = tmp_path / "atlaso_offline_probe-0.0.1-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("atlaso_offline_probe-0.0.1.dist-info/METADATA",
                         "Metadata-Version: 2.1\nName: atlaso-offline-probe\nVersion: 0.0.1\n")
        archive.writestr("atlaso_offline_probe-0.0.1.dist-info/WHEEL",
                         "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
        archive.writestr("atlaso_offline_probe-0.0.1.dist-info/RECORD", "")
    program = '''import json,sys
from pip._internal.cli.main import main
from pip._internal.network.session import PipSession
attempts=[]
def blocked_request(self, method, url, *args, **kwargs):
    attempts.append(method)
    raise RuntimeError("Network disabled for the offline regression")
PipSession.request=blocked_request
status=main(['--isolated',*sys.argv[1:]])
print(json.dumps({'status':status,'network_attempts':len(attempts)}))
'''
    env = {key: value for key, value in os.environ.items() if not key.startswith("PIP_")}
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", program, *options,
         "--dry-run", "--ignore-installed", "--no-cache-dir", str(wheel)],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 0, result.stderr
    observation = json.loads(result.stdout.splitlines()[-1])
    assert observation == {"status": 0, "network_attempts": 0}
