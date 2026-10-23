"""Behavioral checks for the reusable template's unconsumed guest-tool inventory."""

from __future__ import annotations

import hashlib
import importlib.util
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

SPEC = importlib.util.spec_from_file_location(
    "template_state",
    Path(__file__).resolve().parents[1]
    / "image/common/scripts/verify-template-state.py",
)
assert SPEC is not None and SPEC.loader is not None
STATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STATE)


def _packages() -> dict[str, bytes]:
    """Return two minimal provider closures with a complete checksum inventory."""
    files = {
        "qemu/atlaso-qemu-guest-agent-10.2.2.x86_64.rpm": b"qemu",
        "qemu/glib-2.x86_64.rpm": b"dependency",
        "hyperv/hyper-v-1.x86_64.rpm": b"hyperv",
    }
    files["SHA256SUMS"] = "".join(
        f"{hashlib.sha256(content).hexdigest()}  {name}\n"
        for name, content in files.items()
    ).encode()
    return files


def test_complete_offline_inventory_passes() -> None:
    """Both providers and all inventoried dependencies remain available."""
    STATE.verify_files(_packages())


def test_physical_install_inventory_requires_empty_checksum_file() -> None:
    """Only explicit physical mode admits the intentionally absent agent closures."""
    STATE.verify_files({"SHA256SUMS": b""}, installation_media=True)
    with pytest.raises(SystemExit):
        STATE.verify_files({"SHA256SUMS": b""})
    for files in ({}, _packages(), {"SHA256SUMS": b"\n"}, {"SHA256SUMS": b"", "agent.rpm": b"unexpected"}):
        with pytest.raises(SystemExit, match="must be empty"):
            STATE.verify_files(files, installation_media=True)


@pytest.mark.parametrize("state", ["pristine", "secret", "agent_directory", "ssh_key", "vmware_lock"])
def test_physical_install_keeps_full_identity_and_directory_checks(tmp_path, monkeypatch, state):
    """Exercise the complete physical verifier with portable root-metadata doubles.

    Args:
        tmp_path: Isolated installation filesystem.
        monkeypatch: Scoped metadata override for platform-independent ownership checks.
        state: Pristine filesystem or specific state that must be rejected.
    """
    staging = tmp_path / STATE.STAGING
    staging.mkdir(parents=True)
    (staging / "SHA256SUMS").write_bytes(b"")
    environment = tmp_path / "etc/atlaso/atlaso.env"
    environment.parent.mkdir(parents=True)
    environment.write_text("".join(f"{name}=INITIALIZATION_REQUIRED\n" for name in ("ATLASO_SECRET_KEY", "ATLASO_SECRETS_KEY", "ATLASO_BOOTSTRAP_ADMIN_PASSWORD")))
    if state == "secret":
        environment.write_text(environment.read_text().replace("INITIALIZATION_REQUIRED", "fixture-initialized-value"))
    elif state == "vmware_lock":
        (tmp_path / STATE.INITIALIZATION_LOCK).write_bytes(b"")
    elif state == "agent_directory":
        (staging / "qemu").mkdir()
    elif state == "ssh_key":
        ssh = tmp_path / "etc/ssh"
        ssh.mkdir()
        (ssh / "ssh_host_ed25519_key").write_bytes(b"fixture")
    original = Path.lstat

    def root_metadata(path, *args, **kwargs):
        """Retain actual file types while supplying the production ownership policy.

        Args:
            path: Fixture entry being inspected.
            *args: Native stat positional options.
            **kwargs: Native stat keyword options.
        """
        info = original(path, *args, **kwargs)
        if not path.is_relative_to(tmp_path):
            return info
        permissions = 0o700 if stat.S_ISDIR(info.st_mode) else (0o640 if path.name == "vmware-ovf-initializing" else 0o600)
        return SimpleNamespace(st_uid=0, st_gid=0, st_mode=stat.S_IFMT(info.st_mode) | permissions, st_nlink=info.st_nlink, st_size=info.st_size)

    monkeypatch.setattr(Path, "lstat", root_metadata)
    if state == "pristine":
        STATE.verify(tmp_path, installation_media=True)
    else:
        with pytest.raises(SystemExit):
            STATE.verify(tmp_path, installation_media=True)


@pytest.mark.skipif(os.name == "nt", reason="Requires Linux ownership and permission semantics")
@pytest.mark.parametrize("lock_state", ["pristine", "missing", "changed", "permissions"])
@pytest.mark.parametrize("installation_media", [False, True])
def test_complete_template_preserves_preseeded_lock(tmp_path: Path, lock_state: str, installation_media: bool) -> None:
    """The construction fixture accepts only the untouched first-boot handshake.

    Args:
        tmp_path: Isolated complete template filesystem.
        lock_state: Expected pre-seeded lock or a consumed/changed variant.
        installation_media: Exercise either the virtual template or physical-install inventory.
    """
    if os.getuid() != 0:
        pytest.skip("Template verification requires root-owned fixtures")
    staging = tmp_path / STATE.STAGING
    staging.mkdir(parents=True, mode=0o700)
    for provider in (() if installation_media else ("qemu", "hyperv")):
        (staging / provider).mkdir(mode=0o700)
    for name, content in ({"SHA256SUMS": b""} if installation_media else _packages()).items():
        target = staging / name
        target.write_bytes(content)
        target.chmod(0o600)
    environment = tmp_path / "etc/atlaso/atlaso.env"
    environment.parent.mkdir(parents=True)
    environment.write_text("".join(f"{name}=INITIALIZATION_REQUIRED\n" for name in (
        "ATLASO_SECRET_KEY", "ATLASO_SECRETS_KEY", "ATLASO_BOOTSTRAP_ADMIN_PASSWORD")))
    lock = tmp_path / STATE.INITIALIZATION_LOCK
    if lock_state != "missing":
        lock.write_bytes(b"changed" if lock_state == "changed" else b"")
        lock.chmod(0o666 if lock_state == "permissions" else 0o640)
    if (installation_media and lock_state == "missing") or (not installation_media and lock_state == "pristine"):
        STATE.verify(tmp_path, installation_media=installation_media)
    else:
        with pytest.raises(SystemExit, match="initialization lock"):
            STATE.verify(tmp_path, installation_media=installation_media)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_dependency",
        "missing_provider",
        "changed",
        "extra",
        "traversal",
        "duplicate",
    ],
)
def test_incomplete_or_changed_inventory_is_rejected(mutation: str) -> None:
    """Final verification catches incomplete cleanup and changed package bytes.

    Args:
        mutation: Inventory corruption to reject.
    """
    files = _packages()
    if mutation == "missing_dependency":
        del files["qemu/glib-2.x86_64.rpm"]
    elif mutation == "missing_provider":
        del files["hyperv/hyper-v-1.x86_64.rpm"]
        files["SHA256SUMS"] = b"\n".join(
            line for line in files["SHA256SUMS"].splitlines() if b"hyperv/" not in line
        )
    elif mutation == "changed":
        files["qemu/glib-2.x86_64.rpm"] = b"tampered"
    elif mutation == "extra":
        files["qemu/extra.rpm"] = b"extra"
    elif mutation == "traversal":
        files["SHA256SUMS"] += b"a" * 64 + b"  ../outside.rpm\n"
    else:
        files["SHA256SUMS"] += files["SHA256SUMS"].splitlines(keepends=True)[0]
    with pytest.raises(SystemExit):
        STATE.verify_files(files)


@pytest.mark.parametrize("marker", STATE.FORBIDDEN)
@pytest.mark.parametrize("installation_media", [False, True])
def test_consumed_initialization_state_is_rejected(tmp_path: Path, marker: str, installation_media: bool) -> None:
    """Any generated deployment identity or transaction state blocks completion.

    Args:
        tmp_path: Isolated template filesystem.
        marker: Deployment-owned state path that must remain absent.
        installation_media: Check that physical mode also rejects consumed identities.
    """
    target = tmp_path / marker
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"consumed")
    with pytest.raises(SystemExit, match="consumed deployment state"):
        STATE.verify(tmp_path, installation_media=installation_media)
