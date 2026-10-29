"""Readiness and bounded metadata checks for the applied VCF Backup receiver."""

from __future__ import annotations

import base64
import json
import stat
import subprocess
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from atlaso.app.database import Base
from atlaso.app.models import Setting, User, VcfBackupSettings
from atlaso.app.services import vcf_backup_receiver as receiver
from atlaso.app.services.applied_service_dns import APPLIANCE_APPLY_BASELINES_KEY
from atlaso.app.services.log_sanitization import redact_operational_text
from atlaso.app.services.vcf_backups import render_vcf_backup_config


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as session:
        yield session
    engine.dispose()


def _settings(db: Session, *, user: User | None = None, enabled: bool = True) -> VcfBackupSettings:
    """Save a valid VCF Backup desired state, with an optional selected local user."""
    if user is not None:
        db.add(user)
        db.flush()
    settings = VcfBackupSettings(
        id=1,
        enabled=enabled,
        listen_interface="eth1",
        listen_address="192.0.2.10",
        port=22,
        sftp_user_id=user.id if user is not None else None,
        storage_path=receiver.VCF_BACKUP_DEFAULT_VOLUME_MOUNT,
        chroot_enabled=True,
        allow_password_auth=True,
        allow_public_key_auth=True,
        max_sessions=4,
    )
    db.add(settings)
    db.flush()
    return settings


def _save_baseline(db: Session, config: str) -> None:
    """Persist the exact rendered configuration as the applied baseline."""
    db.add(
        Setting(
            key=APPLIANCE_APPLY_BASELINES_KEY,
            value=json.dumps({"vcf_backups": {"config_preview": redact_operational_text(config)}}),
        )
    )
    db.flush()


def _admit_ready_receiver(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, Any]]:
    """Replace only host-runtime probes needed to admit a known-ready receiver."""
    calls: list[tuple[str, Any]] = []
    monkeypatch.setattr(
        receiver,
        "_public_key",
        lambda: calls.append(("ecdsa", None)) or ("ecdsa-sha2-nistp256 public", "SHA256:ecdsa"),
    )
    monkeypatch.setattr(
        receiver,
        "_rsa_public_key",
        lambda: calls.append(("rsa", None)) or "ssh-rsa public",
    )
    monkeypatch.setattr(receiver, "_runtime", lambda data, preview: calls.append(("runtime", preview)))
    return calls


def test_missing_or_disabled_settings_refuse_readiness_without_host_runtime(db, monkeypatch):
    def unexpected(*_args, **_kwargs):
        raise AssertionError("Host keys and runtime must not be inspected for unavailable desired state.")

    monkeypatch.setattr(receiver, "_public_key", unexpected)
    monkeypatch.setattr(receiver, "_rsa_public_key", unexpected)
    monkeypatch.setattr(receiver, "_runtime", unexpected)

    missing = receiver.receiver_state(db)
    assert missing["ready"] is False
    assert missing["reason"] == "Enable and apply VCF Backup SFTP first."

    _settings(db, enabled=False)
    disabled = receiver.receiver_state(db)
    assert disabled["ready"] is False
    assert disabled["reason"] == "Enable and apply VCF Backup SFTP first."


@pytest.mark.parametrize(
    ("user", "pending_password", "expected_reason"),
    [
        (None, False, "selected SFTP user"),
        (User(username="disabled-backup", enabled=False, os_sync_status="applied"), False, "selected SFTP user"),
        (User(username="unapplied-backup", enabled=True, os_sync_status="pending"), False, "Apply the selected user's current Local Users settings first."),
        (User(username="pending-backup", enabled=True, os_sync_status="applied"), True, "Apply the selected user's current Local Users settings first."),
    ],
)
def test_missing_disabled_pending_or_unapplied_user_blocks_before_key_resolution(
    db, monkeypatch, user, pending_password, expected_reason
):
    settings = _settings(db, user=user)
    preview = render_vcf_backup_config(settings)
    _save_baseline(db, preview)

    monkeypatch.setattr(receiver, "has_pending_os_password", lambda _user: pending_password)
    calls = _admit_ready_receiver(monkeypatch)
    result = receiver.receiver_state(db)

    assert result["ready"] is False
    assert expected_reason in result["reason"]
    assert calls == []


def test_stale_applied_baseline_blocks_before_public_key_or_ssh_checks(db, monkeypatch):
    user = User(username="vcf-backup", enabled=True, os_sync_status="applied")
    settings = _settings(db, user=user)
    _save_baseline(db, render_vcf_backup_config(settings))
    settings.listen_address = "192.0.2.11"
    db.flush()

    calls = _admit_ready_receiver(monkeypatch)
    result = receiver.receiver_state(db)

    assert result["ready"] is False
    assert "Apply pending VCF Backup SFTP changes" in result["reason"]
    assert calls == []


def test_readiness_uses_applied_public_state_without_loading_vault_secrets(db, monkeypatch):
    statements: list[str] = []
    event.listen(
        db.get_bind(),
        "before_cursor_execute",
        lambda _conn, _cursor, statement, _parameters, _context, _many: statements.append(statement.lower()),
    )
    user = User(username="vcf-backup", enabled=True, os_sync_status="applied")
    settings = _settings(db, user=user)
    preview = render_vcf_backup_config(settings)
    _save_baseline(db, preview)
    calls = _admit_ready_receiver(monkeypatch)

    result = receiver.receiver_state(db)

    assert result["ready"] is True
    assert result["host"] == "192.0.2.10"
    assert result["directory"] == "/backups"
    assert result["username"] == "vcf-backup"
    assert result["ecdsa_fingerprint"] == "SHA256:ecdsa"
    assert [(name, value) for name, value in calls] == [
        ("ecdsa", None),
        ("rsa", None),
        ("runtime", preview),
    ]
    assert not any("vault" in statement or "secret" in statement for statement in statements)
    assert "password" not in result
    assert "rsa_host_key" in receiver.receiver_revision(result)
    assert "password" not in receiver.receiver_revision(result)


@pytest.mark.parametrize("resource", ["settings", "user"])
def test_readiness_refreshes_cached_objects_after_receiver_revocation(db, monkeypatch, resource):
    user = User(username="vcf-backup", enabled=True, os_sync_status="applied")
    settings = _settings(db, user=user)
    _save_baseline(db, render_vcf_backup_config(settings))
    db.commit()
    _admit_ready_receiver(monkeypatch)
    assert receiver.receiver_state(db)["ready"] is True
    with Session(db.get_bind()) as writer:
        row = writer.get(VcfBackupSettings, settings.id) if resource == "settings" else writer.get(User, user.id)
        row.enabled = False
        writer.commit()
    assert receiver.receiver_state(db)["ready"] is False


def test_runtime_requires_exact_applied_config_and_proves_both_live_host_key_algorithms(
    tmp_path, monkeypatch
):
    effective_config = tmp_path / "sshd_config"
    effective_config.write_text("applied config\n", encoding="utf-8")
    mount = SimpleNamespace(name="posix", path=SimpleNamespace(ismount=lambda _path: True))
    monkeypatch.setattr(receiver, "os", mount)
    monkeypatch.setattr(receiver, "VCF_BACKUP_EFFECTIVE_CONFIG_PATH", str(effective_config))
    process_calls: list[tuple[Any, ...]] = []
    monkeypatch.setattr(
        receiver.subprocess,
        "run",
        lambda *args, **kwargs: process_calls.append(args) or subprocess.CompletedProcess(args[0], 0),
    )
    transports: list[dict[str, Any]] = []

    class FakeTransport:
        def __init__(self, identity: dict[str, Any]):
            self.identity = identity

        def close(self):
            self.identity["closed"] = True

    monkeypatch.setattr(receiver, "_transport", lambda value: transports.append(value) or FakeTransport(value))
    state = {
        "host": "192.0.2.10",
        "port": 22,
        "host_key": "ecdsa-sha2-nistp256 public",
        "rsa_host_key": "ssh-rsa public",
    }

    receiver._runtime(state, "applied config\n")

    assert process_calls == [(["/usr/bin/systemctl", "is-active", "sshd.service"],)]
    assert [item.get("host_key") for item in transports] == [state["host_key"], state["rsa_host_key"]]
    assert transports[1]["negotiation_types"] == ["rsa-sha2-512", "rsa-sha2-256"]
    assert all(item["closed"] for item in transports)

    transports.clear()
    with pytest.raises(receiver.ReceiverError, match="Apply the current VCF Backup SFTP configuration first"):
        receiver._runtime(state, "old config\n")
    assert transports == []
    assert len(process_calls) == 1


class _RemoteKey:
    def __init__(self, value: bytes):
        self.value = value

    def asbytes(self) -> bytes:
        return self.value


class _SecurityOptions:
    key_types: tuple[str, ...] = ()


class _Channel:
    def settimeout(self, _value: int) -> None:
        pass


class _Sftp:
    def get_channel(self) -> _Channel:
        return _Channel()

    def close(self) -> None:
        pass


class _Transport:
    def __init__(self, _sock, events: list[str], remote_key: bytes):
        self.events = events
        self.remote_key = remote_key
        self.closed = False

    def get_security_options(self) -> _SecurityOptions:
        return _SecurityOptions()

    def start_client(self, timeout: int) -> None:
        self.events.append(f"start:{timeout}")

    def get_remote_server_key(self) -> _RemoteKey:
        self.events.append("verify-host-key")
        return _RemoteKey(self.remote_key)

    def auth_password(self, username: str, password: str, *, fallback: bool) -> None:
        self.events.append(f"auth:{username}:{password}:{fallback}")

    def close(self) -> None:
        self.closed = True
        self.events.append("close")


@pytest.mark.parametrize("remote_key", [b"appliance-ecdsa-key", b"changed-ecdsa-key"])
def test_sftp_checks_ecdsa_key_before_password_auth_and_rejects_key_change(monkeypatch, remote_key):
    events: list[str] = []
    expected_blob = b"appliance-ecdsa-key"
    host_key = f"ecdsa-sha2-nistp256 {base64.b64encode(expected_blob).decode()}"
    transports: list[_Transport] = []

    def make_transport(sock):
        item = _Transport(sock, events, remote_key)
        transports.append(item)
        return item

    monkeypatch.setattr(receiver.socket, "create_connection", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(receiver.paramiko, "Transport", make_transport)
    monkeypatch.setattr(
        receiver.paramiko,
        "SFTPClient",
        SimpleNamespace(from_transport=lambda _transport: _Sftp()),
    )
    session = receiver.ReceiverSession(
        {"host": "192.0.2.10", "port": 22, "username": "backup", "host_key": host_key},
        "request-local-password",
    )

    if remote_key == expected_blob:
        session.__enter__()
        assert events[:3] == ["start:5", "verify-host-key", "auth:backup:request-local-password:False"]
        session.__exit__(None, None, None)
        assert session.password == ""
    else:
        with pytest.raises(receiver.ReceiverError, match="identity changed"):
            session.__enter__()
        assert events == ["start:5", "verify-host-key", "close"]
        assert all(not item.closed or "auth:" not in events for item in transports)


class _Attributes:
    def __init__(self, filename: str, mode: int, size: int = 0, mtime: int = 0):
        self.filename = filename
        self.st_mode = mode
        self.st_size = size
        self.st_mtime = mtime


class _ManifestSftp:
    def __init__(self, nodes: dict[str, _Attributes], children: dict[str, list[_Attributes]]):
        self.nodes = nodes
        self.children = children
        self.content_reads = 0

    def lstat(self, path: str) -> _Attributes:
        try:
            return self.nodes[path]
        except KeyError:
            raise FileNotFoundError(path) from None

    def listdir_attr(self, path: str) -> list[_Attributes]:
        return list(self.children.get(path, []))

    def get(self, *_args, **_kwargs):
        self.content_reads += 1
        raise AssertionError("Manifest verification must never download backup contents.")

    def open(self, *_args, **_kwargs):
        self.content_reads += 1
        raise AssertionError("Manifest verification must never open backup contents.")


def _session_with_sftp(client: _ManifestSftp) -> receiver.ReceiverSession:
    session = receiver.ReceiverSession({"host": "192.0.2.10", "port": 22}, "unused")
    session.sftp = client  # The SFTP protocol is supplied by the isolated fake client.
    return session


@pytest.mark.parametrize(
    "path",
    ["/etc/passwd", "/backups/../etc/passwd", "/backups/group/../../etc/passwd", "/backups\\outside"],
)
def test_remote_paths_cannot_escape_the_reviewed_backups_chroot(path):
    session = receiver.ReceiverSession({}, "unused")
    with pytest.raises(receiver.ReceiverError, match="beneath /backups"):
        session._path(path)


def test_manifest_refuses_symlinks_and_special_files():
    root = _Attributes("group", stat.S_IFDIR)
    link = _Attributes("link", stat.S_IFLNK)
    session = _session_with_sftp(
        _ManifestSftp(
            {"/backups/group": root, "/backups/group/link": link},
            {"/backups/group": [link]},
        )
    )
    with pytest.raises(receiver.ReceiverError, match="symlinks and special files"):
        session.manifest("/backups/group")


def test_prepare_refuses_symlinked_destination_components():
    root = _Attributes("backups", stat.S_IFDIR)
    link = _Attributes("group", stat.S_IFLNK)
    session = _session_with_sftp(_ManifestSftp({"/backups": root, "/backups/group": link}, {}))
    with pytest.raises(receiver.ReceiverError, match="symlink or non-directory"):
        session.prepare("/backups/group")


def test_manifest_enforces_depth_count_and_time_bounds(monkeypatch):
    def directory_chain(path: str, depth: int) -> _ManifestSftp:
        nodes = {path: _Attributes(path.rsplit("/", 1)[-1], stat.S_IFDIR)}
        children = {}
        cursor = path
        for index in range(depth):
            child = _Attributes(f"d{index}", stat.S_IFDIR)
            children[cursor] = [child]
            cursor += f"/d{index}"
            nodes[cursor] = _Attributes(f"d{index}", stat.S_IFDIR)
        return _ManifestSftp(nodes, children)

    deep = _session_with_sftp(directory_chain("/backups/group", 14))
    with pytest.raises(receiver.ReceiverError, match="depth, file, or time limit"):
        deep.manifest("/backups/group")

    monkeypatch.setattr(receiver, "MAX_ARTIFACTS", 3)
    root = _Attributes("group", stat.S_IFDIR)
    children = [_Attributes(f"f{index}", stat.S_IFREG, 1, 1) for index in range(4)]
    many = _session_with_sftp(_ManifestSftp({"/backups/group": root}, {"/backups/group": children}))
    with pytest.raises(receiver.ReceiverError, match="supported file limit"):
        many.manifest("/backups/group")

    monkeypatch.setattr(receiver.time, "monotonic", iter([0, 46]).__next__)
    slow = _session_with_sftp(_ManifestSftp({"/backups/group": root}, {}))
    with pytest.raises(receiver.ReceiverError, match="depth, file, or time limit"):
        slow.manifest("/backups/group")


def test_manifest_returns_sparse_artifact_metadata_without_opening_contents():
    root = _Attributes("group", stat.S_IFDIR)
    sparse = _Attributes("large-backup.tar", stat.S_IFREG, 2**50, 1_800_000_000)
    client = _ManifestSftp(
        {"/backups/group": root, "/backups/group/large-backup.tar": sparse},
        {"/backups/group": [sparse]},
    )
    session = _session_with_sftp(client)

    manifest = session.manifest("/backups/group")

    assert manifest == {"/backups/group/large-backup.tar": (2**50, 1_800_000_000)}
    assert client.content_reads == 0
