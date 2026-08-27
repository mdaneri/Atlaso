"""Focused tests for provider-specific SSH smoke validation."""

from __future__ import annotations

import base64
import io
import struct
import sys
from pathlib import Path

import pytest

from scripts.virtualization import smoke_guest_ssh as smoke

HOST_KEY = "ssh-ed25519 " + base64.b64encode(
    struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + b"s" * 32
).decode()


def test_secret_input_accepts_only_exact_stdin_schema(monkeypatch: pytest.MonkeyPatch) -> None:
    """Credentials are accepted only from the exact standard-input envelope.

    Args:
        monkeypatch: Pytest fixture used to replace standard input.
    """

    monkeypatch.setattr(sys, "stdin", io.StringIO('{"username":"admin","password":"fixture"}'))
    secret = smoke.load_secret_input()
    assert secret.username == "admin"
    assert secret.password == "fixture"

    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO('{"username":"admin","password":"fixture","unexpected":true}'),
    )
    with pytest.raises(smoke.SmokeError, match="unexpected schema"):
        smoke.load_secret_input()


def test_artifact_host_key_requires_canonical_ed25519_wire_format() -> None:
    """SSH authentication uses only the manifest-bound Ed25519 host key."""

    key_type, key_blob = smoke.parse_host_public_key(HOST_KEY)
    assert key_type == "ssh-ed25519"
    assert len(key_blob) == 51
    with pytest.raises(smoke.SmokeError, match="malformed"):
        smoke.parse_host_public_key("ssh-rsa invalid")


@pytest.mark.parametrize(
    ("platform", "expected", "foreign"),
    [
        ("vmware", "rpm -q open-vm-tools", "! rpm -q hyper-v"),
        ("hyperv", "rpm -q hyper-v", "! rpm -q open-vm-tools"),
    ],
)
def test_validation_script_proves_agent_disks_services_and_front_door(
    platform: str,
    expected: str,
    foreign: str,
) -> None:
    """Each Windows-hosted smoke validates the complete guest contract.

    Args:
        platform: Guest virtualization provider.
        expected: Provider package assertion expected in the script.
        foreign: Foreign-package absence assertion expected in the script.
    """

    script = smoke._validation_script(platform)
    assert expected in script
    assert foreign in script
    assert f"platform={platform}" in script
    assert "/var/lib/atlaso-privileged/guest-agent/guest-agent.applied" in script
    assert "/var/lib/atlaso/first-boot-packages" in script
    assert "lsblk -dn -o TYPE" in script
    assert "/mnt/atlaso-vcf-offline-depot" in script
    assert "/mnt/atlaso-vcf-backups" in script
    assert "systemctl is-active --quiet atlaso.service" in script
    assert "curl -fsS http://127.0.0.1:8000/openapi.json" in script


def test_windows_smoke_wrappers_keep_credentials_out_of_child_arguments() -> None:
    """PowerShell wrappers send the secret envelope over stdin and own bounded cleanup."""

    root = Path(__file__).resolve().parents[1]
    for name in ("smoke-ova-vmware.ps1", "smoke-hyperv.ps1"):
        source = (root / "scripts/windows/virtualization" / name).read_text(encoding="utf-8")
        assert "ConvertTo-Json -Compress" in source
        assert "smoke_guest_ssh.py" in source
        assert "'--host-key' $expectedHostKey" in source
        assert "-pw" not in source
        assert "Remove-Item -LiteralPath" in source

    helper = (root / "scripts/virtualization/smoke_guest_ssh.py").read_text(encoding="utf-8")
    assert "paramiko.RejectPolicy()" in helper
    assert "paramiko.AutoAddPolicy()" not in helper
    assert "client.get_host_keys().add(host, key_type, trusted_key)" in helper
