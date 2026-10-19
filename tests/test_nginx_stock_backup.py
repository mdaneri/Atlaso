"""Tests for protected recovery evidence used by the nginx stock-listener migration."""

import hashlib
import importlib.machinery
import importlib.util
import json
import os
import stat
from pathlib import Path

import pytest

HELPER_PATH = Path(__file__).resolve().parents[1] / "scripts" / "appliance" / "atlaso-helper"


def load_helper_module():
    """Load the appliance helper using the repository's source-loader convention."""
    loader = importlib.machinery.SourceFileLoader("atlaso_helper", str(HELPER_PATH))
    spec = importlib.util.spec_from_loader("atlaso_helper", loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def test_stock_listener_backup_is_byte_exact_private_and_idempotent(tmp_path, monkeypatch):
    """Persist exact original bytes and stable digest evidence on repeated calls.

    Args:
        tmp_path: Isolated pytest directory for configuration and recovery evidence.
        monkeypatch: Fixture replacing helper paths and native operations for this case.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper, "ATLASO_UPDATE_BACKUP_DIR", tmp_path / "backups")
    target = tmp_path / "nginx.conf"
    monkeypatch.setattr(helper, "NGINX_MAIN_CONFIG_PATH", target)
    original = b"# original bytes\r\nhttp {\n  server { listen 80; }\n}\n"
    cleaned = b"# original bytes\r\nhttp {\n}\n"

    helper._backup_stock_nginx_listener(original, cleaned)

    digest = hashlib.sha256(original).hexdigest()
    directory = tmp_path / "backups" / "nginx-stock-listeners"
    backup = directory / f"{digest}.conf"
    metadata_path = directory / f"{digest}.json"
    expected_metadata = {
        "schema": 1,
        "target": str(target),
        "original_sha256": digest,
        "cleaned_sha256": hashlib.sha256(cleaned).hexdigest(),
        "repair": "retire-exact-vendor-welcome-listener",
    }
    assert backup.read_bytes() == original
    assert json.loads(metadata_path.read_text(encoding="utf-8")) == expected_metadata
    assert {path.name for path in directory.iterdir()} == {backup.name, metadata_path.name}
    if os.name == "posix":
        assert directory.stat().st_mode & 0o777 == 0o700
        assert backup.stat().st_mode & 0o777 == 0o600
        assert metadata_path.stat().st_mode & 0o777 == 0o600
    original_mtime = backup.stat().st_mtime_ns
    metadata_mtime = metadata_path.stat().st_mtime_ns

    helper._backup_stock_nginx_listener(original, cleaned)

    assert backup.read_bytes() == original
    assert metadata_path.read_text(encoding="utf-8") == json.dumps(
        expected_metadata, sort_keys=True
    )
    assert backup.stat().st_mtime_ns == original_mtime
    assert metadata_path.stat().st_mtime_ns == metadata_mtime
    assert {path.name for path in directory.iterdir()} == {backup.name, metadata_path.name}


def test_conflicting_original_backup_is_preserved_and_startup_repair_refused(
    tmp_path, monkeypatch
):
    """A conflicting digest path blocks repair without changing either copy.

    Args:
        tmp_path: Isolated pytest directory for configuration and recovery evidence.
        monkeypatch: Fixture replacing helper paths and native operations for this case.
    """
    helper = load_helper_module()
    backup_root = tmp_path / "backups"
    main_config = tmp_path / "nginx.conf"
    monkeypatch.setattr(helper, "ATLASO_UPDATE_BACKUP_DIR", backup_root)
    monkeypatch.setattr(helper, "NGINX_MAIN_CONFIG_PATH", main_config)
    original = (
        b"http {\n"
        b"    server {\n"
        b"        listen 80;\n"
        b"        server_name localhost;\n"
        b"        location / { root html; index index.html index.htm; }\n"
        b"        error_page 500 502 503 504 /50x.html;\n"
        b"        location = /50x.html { root html; }\n"
        b"    }\n"
        b"}\n"
    )
    main_config.write_bytes(original)
    digest = hashlib.sha256(original).hexdigest()
    directory = backup_root / "nginx-stock-listeners"
    directory.mkdir(parents=True)
    conflicting_backup = directory / f"{digest}.conf"
    conflict = b"different preexisting recovery data"
    conflicting_backup.write_bytes(conflict)
    if os.name == "posix":
        directory.chmod(0o700)
        conflicting_backup.chmod(0o600)
    monkeypatch.setattr(
        helper,
        "_nginx_test_command",
        lambda: (_ for _ in ()).throw(AssertionError("nginx validation must not run")),
    )

    result = helper._prepare_stock_nginx_listener_startup()

    assert result["success"] is False
    assert main_config.read_bytes() == original
    assert conflicting_backup.read_bytes() == conflict
    assert list(directory.iterdir()) == [conflicting_backup]


def test_backup_refuses_symlinked_evidence_directory_when_supported(tmp_path, monkeypatch):
    """Do not follow an evidence-directory symlink into another location.

    Args:
        tmp_path: Isolated pytest directory for configuration and recovery evidence.
        monkeypatch: Fixture replacing helper paths and native operations for this case.
    """
    helper = load_helper_module()
    backup_root = tmp_path / "backups"
    outside = tmp_path / "outside"
    outside.mkdir()
    link = backup_root / "nginx-stock-listeners"
    backup_root.mkdir()
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"local filesystem does not permit a test symlink: {exc}")
    monkeypatch.setattr(helper, "ATLASO_UPDATE_BACKUP_DIR", backup_root)

    with pytest.raises(ValueError, match="backup directory is unsafe"):
        helper._backup_stock_nginx_listener(b"original", b"cleaned")

    assert link.is_symlink()
    assert list(outside.iterdir()) == []


def test_backup_refuses_hardlinked_existing_original_when_supported(tmp_path, monkeypatch):
    """Reject an existing digest path with another hardlink name.

    Args:
        tmp_path: Isolated pytest directory for configuration and recovery evidence.
        monkeypatch: Fixture replacing helper paths and native operations for this case.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper, "ATLASO_UPDATE_BACKUP_DIR", tmp_path / "backups")
    original = b"original configuration"
    digest = hashlib.sha256(original).hexdigest()
    directory = tmp_path / "backups" / "nginx-stock-listeners"
    directory.mkdir(parents=True)
    backup = directory / f"{digest}.conf"
    other_name = tmp_path / "external-link.conf"
    backup.write_bytes(original)
    try:
        os.link(backup, other_name)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"local filesystem does not permit a test hardlink: {exc}")
    backup_identity = (backup.stat().st_dev, backup.stat().st_ino)
    link_identity = (other_name.stat().st_dev, other_name.stat().st_ino)
    if os.name == "posix":
        directory.chmod(0o700)
        backup.chmod(0o600)

    cleanup_succeeded = False
    try:
        with pytest.raises(ValueError, match="conflicts with original evidence"):
            helper._backup_stock_nginx_listener(original, b"cleaned")

        assert backup.read_bytes() == original
        assert other_name.read_bytes() == original
        assert backup.stat().st_nlink == 2
        assert other_name.stat().st_nlink == 2
    finally:
        try:
            backup_stat = backup.lstat()
            link_stat = other_name.lstat()
        except FileNotFoundError:
            pass
        else:
            current_backup_identity = (backup_stat.st_dev, backup_stat.st_ino)
            current_link_identity = (link_stat.st_dev, link_stat.st_ino)
            if (
                stat.S_ISREG(backup_stat.st_mode)
                and stat.S_ISREG(link_stat.st_mode)
                and current_backup_identity == backup_identity
                and current_link_identity == link_identity == backup_identity
                and backup_stat.st_nlink == 2
                and link_stat.st_nlink == 2
            ):
                other_name.unlink()
                cleanup_succeeded = True

    assert cleanup_succeeded
    assert backup.read_bytes() == original
    assert backup.stat().st_nlink == 1
    assert not other_name.exists()
