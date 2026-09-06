"""Behavioral checks for the reusable template's unconsumed guest-tool inventory."""

from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path

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


@pytest.mark.skipif(os.name == "nt", reason="Requires Linux ownership and permission semantics")
@pytest.mark.parametrize("lock_state", ["pristine", "missing", "changed", "permissions"])
def test_complete_template_preserves_preseeded_lock(tmp_path: Path, lock_state: str) -> None:
    """The construction fixture accepts only the untouched first-boot handshake.

    Args:
        tmp_path: Isolated complete template filesystem.
        lock_state: Expected pre-seeded lock or a consumed/changed variant.
    """
    if os.getuid() != 0:
        pytest.skip("Template verification requires root-owned fixtures")
    staging = tmp_path / STATE.STAGING
    staging.mkdir(parents=True, mode=0o700)
    for provider in ("qemu", "hyperv"):
        (staging / provider).mkdir(mode=0o700)
    for name, content in _packages().items():
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
    if lock_state == "pristine":
        STATE.verify(tmp_path)
    else:
        with pytest.raises(SystemExit, match="initialization lock"):
            STATE.verify(tmp_path)


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
def test_consumed_initialization_state_is_rejected(tmp_path: Path, marker: str) -> None:
    """Any generated deployment identity or transaction state blocks completion.

    Args:
        tmp_path: Isolated template filesystem.
        marker: Deployment-owned state path that must remain absent.
    """
    target = tmp_path / marker
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"consumed")
    with pytest.raises(SystemExit, match="consumed deployment state"):
        STATE.verify(tmp_path)
