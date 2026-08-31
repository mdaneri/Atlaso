"""Focused tests for provider-specific SSH smoke validation."""

from __future__ import annotations

import ast
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


def test_smoke_dependency_input_matches_runtime_and_shared_release_pin() -> None:
    """Keep the smoke lock narrow while aligning its shared release dependency."""
    root = Path(__file__).resolve().parents[1]
    source = (root / "scripts/virtualization/smoke_guest_ssh.py").read_text(
        encoding="utf-8"
    )
    imported_roots: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.partition(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.partition(".")[0])
    third_party = imported_roots - sys.stdlib_module_names - {"__future__"}
    declarations = [
        line
        for line in (
            root / "requirements-virtualization-smoke.in"
        ).read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    ]

    assert third_party == {"paramiko"}
    assert declarations == ["cffi==2.1.0", "paramiko>=3.5.0"]


def test_smoke_lock_matches_shared_release_tool_versions() -> None:
    """Prevent sequential candidate installs from replacing shared packages."""
    root = Path(__file__).resolve().parents[1]

    def lock_versions(path: Path) -> dict[str, str]:
        """Return exact package versions from one generated lock.

        Args:
            path: Generated lock file to inspect.
        """
        versions: dict[str, str] = {}
        for line in path.read_text(encoding="utf-8").splitlines():
            name, separator, remainder = line.partition("==")
            if separator and name and not name[0].isspace():
                versions[name.lower()] = remainder.split(maxsplit=1)[0]
        return versions

    release_versions = lock_versions(root / "requirements-release-tools.lock")
    smoke_versions = lock_versions(root / "requirements-virtualization-smoke.lock")
    shared = release_versions.keys() & smoke_versions.keys()

    assert shared
    assert {
        package: (release_versions[package], smoke_versions[package])
        for package in shared
        if release_versions[package] != smoke_versions[package]
    } == {}


class _FakeChannel:
    """Provide the bounded channel methods used by the reboot command."""

    def shutdown_write(self) -> None:
        """Accept the helper's standard-input shutdown."""

    def recv_exit_status(self) -> int:
        """Return a successful fixed reboot command status."""

        return 0


class _FakeInput:
    """Capture credential input without retaining its value in assertions."""

    def __init__(self) -> None:
        """Initialize one fake command input stream."""

        self.channel = _FakeChannel()

    def write(self, _value: str) -> None:
        """Accept one command input write.

        Args:
            _value: Input text intentionally ignored by the fixture.
        """


class _FakeOutput:
    """Expose the fake reboot command channel."""

    def __init__(self) -> None:
        """Initialize one fake command output stream."""

        self.channel = _FakeChannel()


class _FakeClient:
    """Record whether the initial phase requested the fixed reboot command."""

    def __init__(self) -> None:
        """Initialize an unused command record."""

        self.command = ""

    def exec_command(self, command: str, *, timeout: int) -> tuple[object, object, object]:
        """Return fixed streams for the expected reboot command.

        Args:
            command: Exact remote command.
            timeout: Bounded command timeout.
        """

        assert timeout == 30
        self.command = command
        return _FakeInput(), _FakeOutput(), object()

    def close(self) -> None:
        """Accept client cleanup."""


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
        assert "'--phase' 'initial'" in source
        assert "'--phase' 'post-reboot'" in source
        assert "'--expected-tls-fingerprint' $tlsFingerprint" in source
        assert "-pw" not in source
        assert "Remove-Item -LiteralPath" in source

    helper = (root / "scripts/virtualization/smoke_guest_ssh.py").read_text(encoding="utf-8")
    assert "paramiko.RejectPolicy()" in helper
    assert "paramiko.AutoAddPolicy()" not in helper
    assert "client.get_host_keys().add(host, key_type, trusted_key)" in helper
    assert 'choices=("initial", "post-reboot")' in helper


def test_initial_and_post_reboot_phases_split_provider_revalidation(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The provider wrapper receives a revalidation boundary between phases.

    Args:
        monkeypatch: Pytest fixture used to replace remote operations.
        capsys: Pytest fixture used to inspect bounded phase output.
    """

    fingerprint = "a" * 64
    client = _FakeClient()
    waited: list[str] = []
    monkeypatch.setattr(smoke, "load_secret_input", lambda: smoke.SecretInput("admin", "fixture"))
    monkeypatch.setattr(smoke, "parse_host_public_key", lambda _value: ("ssh-ed25519", b"fixture"))
    monkeypatch.setattr(smoke, "_connect", lambda *_args, **_kwargs: client)
    monkeypatch.setattr(smoke, "_run_root", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(smoke, "_front_door_fingerprint", lambda _host: fingerprint)
    monkeypatch.setattr(smoke, "_wait_for_reboot", lambda host: waited.append(host))

    assert smoke.main(
        [
            "--host",
            "192.0.2.20",
            "--host-key",
            HOST_KEY,
            "--platform",
            "hyperv",
            "--phase",
            "initial",
        ]
    ) == 0
    assert client.command == "sudo -S -p '' systemctl reboot"
    assert waited == ["192.0.2.20"]
    assert capsys.readouterr().out.strip() == fingerprint

    client.command = ""
    assert smoke.main(
        [
            "--host",
            "192.0.2.20",
            "--host-key",
            HOST_KEY,
            "--platform",
            "hyperv",
            "--phase",
            "post-reboot",
            "--expected-tls-fingerprint",
            fingerprint,
        ]
    ) == 0
    assert client.command == ""
    assert "Atlaso hyperv guest smoke test passed." in capsys.readouterr().out
