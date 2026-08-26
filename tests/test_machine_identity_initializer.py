"""Focused coverage for provider-neutral first-boot machine identity."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/appliance/atlaso-initialize-machine-identity.py"


def _load_module():
    """Load the extensionless appliance initializer as a Python module."""

    spec = importlib.util.spec_from_file_location("atlaso_initialize_machine_identity", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _record(key: bytes, value: bytes) -> bytes:
    """Return one fixed-width Hyper-V KVP record.

    Args:
        key: KVP key bytes.
        value: KVP value bytes.
    """

    return key.ljust(512, b"\0") + value.ljust(2048, b"\0")


def test_hyperv_access_publication_preserves_unrelated_kvp_records(monkeypatch, tmp_path: Path) -> None:
    """Publishing Atlaso access must not replace another Hyper-V guest record.

    Args:
        monkeypatch: Pytest fixture used to replace the fixed guest path.
        tmp_path: Temporary directory provided by pytest.
    """

    module = _load_module()
    pool = tmp_path / ".kvp_pool_1"
    unrelated = _record(b"unrelated.key", b"retained")
    pool.write_bytes(unrelated)
    monkeypatch.setattr(module, "KVP_POOL_PATH", pool)
    payload = json.dumps({"username": "admin", "password": "A!a1unique-password"})

    module._publish_hyperv_access(payload)

    contents = pool.read_bytes()
    assert contents[: module.KVP_RECORD_BYTES] == unrelated
    assert contents[module.KVP_RECORD_BYTES : module.KVP_RECORD_BYTES + 512].rstrip(b"\0") == b"atlaso.first_boot_access"
    assert contents[module.KVP_RECORD_BYTES + 512 :].rstrip(b"\0").decode() == payload


def test_hyperv_access_publication_rejects_malformed_or_duplicate_pool(monkeypatch, tmp_path: Path) -> None:
    """Malformed or contradictory KVP state fails closed without replacement.

    Args:
        monkeypatch: Pytest fixture used to replace the fixed guest path.
        tmp_path: Temporary directory provided by pytest.
    """

    module = _load_module()
    pool = tmp_path / ".kvp_pool_1"
    monkeypatch.setattr(module, "KVP_POOL_PATH", pool)
    pool.write_bytes(b"truncated")
    with pytest.raises(RuntimeError, match="malformed record boundary"):
        module._publish_hyperv_access("{}")
    duplicate = _record(b"atlaso.first_boot_access", b"one") * 2
    pool.write_bytes(duplicate)
    with pytest.raises(RuntimeError, match="duplicate Atlaso access records"):
        module._publish_hyperv_access("{}")


def test_access_cleanup_removes_only_atlaso_transport(monkeypatch, tmp_path: Path) -> None:
    """First-reboot cleanup preserves unrelated KVP data and removes runtime access.

    Args:
        monkeypatch: Pytest fixture used to replace fixed guest paths.
        tmp_path: Temporary directory provided by pytest.
    """

    module = _load_module()
    pool = tmp_path / ".kvp_pool_1"
    access = tmp_path / "run/atlaso/first-boot-access.json"
    access.parent.mkdir(parents=True)
    access.write_text("one-time\n", encoding="utf-8")
    unrelated = _record(b"unrelated.key", b"retained")
    pool.write_bytes(unrelated + _record(b"atlaso.first_boot_access", b"remove"))
    monkeypatch.setattr(module, "KVP_POOL_PATH", pool)
    monkeypatch.setattr(module, "ACCESS_PATH", access)

    module.clear_access("hyperv")

    assert not access.exists()
    assert pool.read_bytes() == unrelated
