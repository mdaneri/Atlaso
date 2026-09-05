"""Behavioral checks for the reusable template's unconsumed guest-tool inventory."""

from __future__ import annotations

import hashlib
import importlib.util
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
