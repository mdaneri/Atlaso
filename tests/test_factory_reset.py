"""Verify the complete, crash-safe Atlaso factory-reset transaction."""

import builtins
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from atlaso.app.adapters.system import AdapterResult, SystemAdapter
from atlaso.app.config import get_settings
from atlaso.app.database import Base
from atlaso.app.factory_reset import (
    FactoryResetError,
    _ca_private_key_paths,
    _remove_retired_ca_private_keys,
    _scrub_retained_credentials,
    _seed_factory_host_interfaces,
    finalize_factory_reset,
    run_factory_reset,
)
from atlaso.app.models import (
    ApiToken,
    ApplianceSettings,
    AuditEvent,
    CaCertificate,
    DnsSettings,
    Job,
    PhysicalInterface,
    Setting,
    User,
    VcfDepotDownloadProfile,
)
from atlaso.app.seed import FACTORY_RESET_SETTING_KEY, seed_initial_data
from atlaso.app.services.networking import HostPhysicalInterface


def test_factory_reset_transaction_lock_rejects_overlapping_posix_runner(
    tmp_path,
    monkeypatch,
):
    """A competing appliance runner cannot enter or alter the active transaction.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import pytest

    import atlaso.app.factory_reset as factory_reset

    class ContendedFcntl:
        """Model an already-held nonblocking appliance file lock."""

        LOCK_EX = 1
        LOCK_NB = 2
        LOCK_UN = 4

        @staticmethod
        def flock(_descriptor, operation):
            """Reject every lock acquisition.

            Args:
                _descriptor: Open transaction-lock descriptor.
                operation: Requested flock operation flags.
            """
            if operation != ContendedFcntl.LOCK_UN:
                raise BlockingIOError

    original_import = builtins.__import__

    def import_with_contended_fcntl(name, *args, **kwargs):
        """Return the contended fcntl test double.

        Args:
            name: Module name requested by import.
            *args: Additional import arguments.
            **kwargs: Additional import keyword arguments.
        """
        if name == "fcntl":
            return ContendedFcntl
        return original_import(name, *args, **kwargs)

    state_directory = tmp_path / "factory-reset"
    monkeypatch.setattr(factory_reset, "factory_reset_state_directory", lambda: state_directory)
    monkeypatch.setattr(factory_reset, "_running_as_posix_root", lambda: False)
    monkeypatch.setattr(factory_reset.os, "name", "posix")
    monkeypatch.setattr(builtins, "__import__", import_with_contended_fcntl)

    with pytest.raises(FactoryResetError, match="already running"):
        with factory_reset._factory_reset_transaction_lock():
            pytest.fail("contending runner must not enter the transaction")


def test_factory_reset_stops_timestamped_transient_automation_units(monkeypatch):
    """Reset quiesces independent automation services after stopping the worker.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.factory_reset as factory_reset

    commands: list[list[str]] = []
    units = [
        "atlaso-automation-20260815230000123456.service",
        "atlaso-automation-20260815230100654321.service",
    ]

    def fake_run(command, **_kwargs):
        """Return a bounded systemd inventory and stopped-state verification.

        Args:
            command: Exact system command arguments.
            **_kwargs: Subprocess options ignored by the test double.
        """
        commands.append(command)
        if command[1] == "list-units":
            stdout = "\n".join(f"{unit} loaded active running Atlaso automation" for unit in units)
            return subprocess.CompletedProcess(command, 0, stdout, "")
        if command[1] == "is-active":
            return subprocess.CompletedProcess(command, 3, "", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(factory_reset.subprocess, "run", fake_run)

    factory_reset._stop_application_services(boot_resume=False)

    assert commands[0] == ["systemctl", "stop", "atlaso-worker.service", "atlaso.service"]
    assert commands[1][-1] == "atlaso-automation-*.service"
    assert commands[2] == ["systemctl", "stop", *units]
    assert commands[3:] == [
        ["systemctl", "is-active", "--quiet", units[0]],
        ["systemctl", "is-active", "--quiet", units[1]],
    ]


def test_factory_reset_scrubs_credentials_outside_apply_staging(tmp_path, monkeypatch):
    """Reset removes retained SSH and Web Terminal credentials without touching payloads.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.factory_reset as factory_reset

    authorized_keys = tmp_path / "authorized_keys"
    terminal_requests = tmp_path / "web-terminal" / "requests"
    terminal_private_key = tmp_path / "web-terminal-ca"
    terminal_public_key = tmp_path / "web-terminal-ca.pub"
    local_users_home = tmp_path / "users"
    bootstrap_ssh = local_users_home / "admin" / ".ssh"
    authorized_keys.mkdir()
    terminal_requests.mkdir(parents=True)
    bootstrap_ssh.mkdir(parents=True)
    for path in (
        authorized_keys / "vcf-backup",
        terminal_requests / "request.json",
        terminal_private_key,
        terminal_public_key,
        bootstrap_ssh / "authorized_keys",
        bootstrap_ssh / "authorized_keys2",
    ):
        path.write_text("credential", encoding="utf-8")
    retained_home_file = local_users_home / "admin" / "profile.ps1"
    retained_home_file.write_text("retained payload", encoding="utf-8")
    synced_directories: list[Path] = []

    monkeypatch.setattr(factory_reset, "VCF_BACKUPS_AUTHORIZED_KEYS_DIRECTORY", authorized_keys)
    monkeypatch.setattr(factory_reset, "WEB_TERMINAL_REQUEST_DIRECTORY", terminal_requests)
    monkeypatch.setattr(
        factory_reset,
        "WEB_TERMINAL_CREDENTIAL_PATHS",
        (terminal_private_key, terminal_public_key),
    )
    monkeypatch.setattr(factory_reset, "LOCAL_USERS_HOME_DIRECTORY", local_users_home)
    monkeypatch.setattr(
        factory_reset,
        "get_settings",
        lambda: SimpleNamespace(bootstrap_admin_username="admin"),
    )
    monkeypatch.setattr(
        factory_reset,
        "_fsync_directory",
        synced_directories.append,
    )
    _scrub_retained_credentials()

    assert list(authorized_keys.iterdir()) == []
    assert list(terminal_requests.iterdir()) == []
    assert not terminal_private_key.exists()
    assert not terminal_public_key.exists()
    assert not (bootstrap_ssh / "authorized_keys").exists()
    assert not (bootstrap_ssh / "authorized_keys2").exists()
    assert retained_home_file.read_text(encoding="utf-8") == "retained payload"
    assert set(synced_directories) == {
        authorized_keys,
        terminal_requests,
        terminal_private_key.parent,
        bootstrap_ssh,
    }


def test_factory_reset_durably_clears_apply_staging(tmp_path, monkeypatch):
    """Reset synchronizes the apply root after removing staged secrets.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.factory_reset as factory_reset

    apply_root = tmp_path / "apply"
    staged_directory = apply_root / "local-users"
    staged_directory.mkdir(parents=True)
    (staged_directory / "atlaso-users.json").write_text("secret", encoding="utf-8")
    synced_directories: list[Path] = []
    real_path = factory_reset.Path
    monkeypatch.setattr(
        factory_reset,
        "Path",
        lambda value: apply_root if value == "/var/lib/atlaso/apply" else real_path(value),
    )
    monkeypatch.setattr(
        factory_reset,
        "_fsync_directory",
        synced_directories.append,
    )

    factory_reset._clear_apply_staging()

    assert list(apply_root.iterdir()) == []
    assert synced_directories == [apply_root]


def test_factory_reset_removes_only_retired_ca_private_keys(tmp_path, monkeypatch):
    """Reset removes old bounded CA keys while preserving factory-state paths.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.factory_reset as factory_reset

    managed_root = tmp_path / "etc" / "atlaso"
    retired_key = managed_root / "https" / "retired.key"
    retained_key = managed_root / "ca" / "factory.key"
    for path in (retired_key, retained_key):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("private key material", encoding="utf-8")
    monkeypatch.setattr(factory_reset, "CA_MANAGED_PATH_BASE", managed_root)
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    test_session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    with test_session() as source_db:
        source_db.add_all(
            [
                CaCertificate(common_name="retired", key_path=str(retired_key)),
                CaCertificate(common_name="factory", key_path=str(retained_key)),
            ]
        )
        source_db.commit()
        source_paths = _ca_private_key_paths(source_db)
    with test_session() as candidate_db:
        candidate_db.execute(
            CaCertificate.__table__.delete().where(CaCertificate.common_name == "retired")
        )
        candidate_db.commit()
        candidate_paths = _ca_private_key_paths(candidate_db)

    _remove_retired_ca_private_keys(source_paths - candidate_paths)

    assert not retired_key.exists()
    assert retained_key.read_text(encoding="utf-8") == "private key material"
    engine.dispose()


def test_managed_factory_reset_retains_marker_until_readiness(tmp_path, monkeypatch):
    """A real reset cannot publish success before its post-restart finalizer.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.factory_reset as factory_reset

    database_path = tmp_path / "atlaso.db"
    state_directory = tmp_path / "factory-reset"
    database_path.write_bytes(b"database")
    scheduled: list[tuple[str, ...]] = []
    monkeypatch.setenv("ATLASO_FACTORY_RESET_STATE_DIRECTORY", str(state_directory))
    monkeypatch.setattr(factory_reset, "_stop_application_services", lambda **_kwargs: None)
    monkeypatch.setattr(factory_reset, "_candidate_database", lambda *_args, **_kwargs: 16)
    monkeypatch.setattr(factory_reset, "_replace_database", lambda *_args: None)
    monkeypatch.setattr(factory_reset, "_clear_apply_staging", lambda: None)
    monkeypatch.setattr(factory_reset, "_scrub_retained_credentials", lambda: None)
    monkeypatch.setattr(
        factory_reset,
        "_schedule_readiness_finalizer",
        lambda: scheduled.append(("readiness",)),
    )

    result = factory_reset._run_factory_reset_locked(
        database_url=f"sqlite:///{database_path}",
        adapter=SystemAdapter(dry_run=False),
        manage_services=True,
    )

    assert result["state"] == "awaiting_readiness"
    assert result["applied_unit_count"] == 16
    assert (state_directory / "request.json").is_file()
    assert not (state_directory / "last-result.json").exists()
    assert scheduled == [("readiness",)]


def test_factory_reset_preflight_uses_generated_config_validators(monkeypatch):
    """Real preflight validates generated nginx and sshd artifacts without applying them.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.factory_reset as factory_reset

    calls: list[tuple[str, str, tuple[object, ...]]] = []

    def fake_helper_result(
        _adapter,
        group: str,
        action: str,
        *args: object,
        **_kwargs: object,
    ) -> AdapterResult:
        """Record one generated-config helper call.

        Args:
            _adapter: Adapter instance receiving the method call.
            group: Helper command group.
            action: Helper action.
            *args: Helper positional arguments.
            **_kwargs: Helper keyword arguments ignored by the test double.
        """
        calls.append((group, action, args))
        return AdapterResult(command=[group, action], dry_run=False)

    monkeypatch.setattr(SystemAdapter, "_helper_result", fake_helper_result)
    adapter = factory_reset._ValidationOnlyAdapter()

    adapter.apply_appliance_settings_config("/tmp/appliance.json")
    adapter.apply_vcf_backup_config("/tmp/backups.conf")
    adapter.apply_public_services_config("/tmp/public.conf")

    assert calls == [
        ("appliance-settings", "preflight", ("/tmp/appliance.json",)),
        ("vcf-backups", "preflight", ("/tmp/backups.conf",)),
        ("public-services", "preflight", ("/tmp/public.conf",)),
    ]


def test_factory_reset_readiness_finalizer_is_detached(monkeypatch):
    """The finalizer must release its caller before trying to acquire the reset lock.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.factory_reset as factory_reset

    commands: list[list[str]] = []

    def fake_run(command: list[str], **_kwargs) -> subprocess.CompletedProcess[str]:
        """Record one systemd-run command.

        Args:
            command: Exact command arguments.
            **_kwargs: Subprocess options ignored by the test double.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(factory_reset.shutil, "which", lambda _command: "/usr/bin/systemd-run")
    monkeypatch.setattr(factory_reset.subprocess, "run", fake_run)

    factory_reset._schedule_readiness_finalizer()

    assert len(commands) == 1
    assert "--collect" in commands[0]
    assert "--no-block" in commands[0]
    assert commands[0][-4:] == [sys.executable, "-m", "atlaso.app.factory_reset", "finalize"]


def test_factory_reset_finalizer_requires_stable_management_readiness(tmp_path, monkeypatch):
    """Terminal success follows two consecutive service and OpenAPI readiness samples.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.factory_reset as factory_reset

    state_directory = tmp_path / "factory-reset"
    state_directory.mkdir()
    request_path = state_directory / "request.json"
    request_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "state": "awaiting_readiness",
                "requested_at": "2026-08-15T20:00:00+00:00",
                "updated_at": "2026-08-15T20:01:00+00:00",
                "message": "waiting",
                "applied_unit_count": 16,
            }
        ),
        encoding="utf-8",
    )
    samples = iter([False, True, True])
    monkeypatch.setattr(factory_reset, "factory_reset_state_directory", lambda: state_directory)
    monkeypatch.setattr(factory_reset, "_running_as_posix_root", lambda: False)
    monkeypatch.setattr(factory_reset, "_start_required_services", lambda: None)
    monkeypatch.setattr(factory_reset, "_management_ready", lambda: next(samples))

    result = finalize_factory_reset(readiness_timeout_seconds=1, poll_seconds=0)

    assert result["state"] == "succeeded"
    assert result["applied_unit_count"] == 16
    assert not request_path.exists()
    assert json.loads((state_directory / "last-result.json").read_text(encoding="utf-8"))["state"] == "succeeded"


def test_factory_reset_finalizer_retains_failed_marker_when_readiness_never_stabilizes(
    tmp_path,
    monkeypatch,
):
    """A restart or OpenAPI failure remains resumable and never publishes success.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import pytest

    import atlaso.app.factory_reset as factory_reset

    state_directory = tmp_path / "factory-reset"
    state_directory.mkdir()
    request_path = state_directory / "request.json"
    request_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "state": "awaiting_readiness",
                "requested_at": "2026-08-15T20:00:00+00:00",
                "updated_at": "2026-08-15T20:01:00+00:00",
                "message": "waiting",
                "applied_unit_count": 16,
            }
        ),
        encoding="utf-8",
    )
    monotonic = iter([0.0, 0.0, 2.0])
    monkeypatch.setattr(factory_reset, "factory_reset_state_directory", lambda: state_directory)
    monkeypatch.setattr(factory_reset, "_running_as_posix_root", lambda: False)
    monkeypatch.setattr(factory_reset, "_start_required_services", lambda: None)
    monkeypatch.setattr(factory_reset, "_management_ready", lambda: False)
    monkeypatch.setattr(factory_reset.time, "monotonic", lambda: next(monotonic))

    with pytest.raises(FactoryResetError, match="did not stabilize"):
        finalize_factory_reset(readiness_timeout_seconds=1, poll_seconds=0)

    assert json.loads(request_path.read_text(encoding="utf-8"))["state"] == "failed"
    assert not (state_directory / "last-result.json").exists()


def test_factory_reset_finalizer_retries_post_commit_failure(tmp_path, monkeypatch):
    """A failed readiness attempt resumes activation instead of rebuilding defaults.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.factory_reset as factory_reset

    state_directory = tmp_path / "factory-reset"
    state_directory.mkdir()
    request_path = state_directory / "request.json"
    request_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "state": "failed",
                "requested_at": "2026-08-15T20:00:00+00:00",
                "updated_at": "2026-08-15T20:01:00+00:00",
                "message": "readiness failed",
                "applied_unit_count": 16,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(factory_reset, "factory_reset_state_directory", lambda: state_directory)
    monkeypatch.setattr(factory_reset, "_running_as_posix_root", lambda: False)
    monkeypatch.setattr(factory_reset, "_start_required_services", lambda: None)
    monkeypatch.setattr(factory_reset, "_management_ready", lambda: True)

    result = finalize_factory_reset(readiness_timeout_seconds=1, poll_seconds=0)

    assert result["state"] == "succeeded"
    assert result["applied_unit_count"] == 16
    assert not request_path.exists()


def test_factory_host_inventory_is_stable_across_startup_refresh(tmp_path):
    """Factory reset baselines every host NIC in its final desired posture.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    engine = create_engine(f"sqlite:///{tmp_path / 'atlaso.db'}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    with session_factory() as db:
        seed_initial_data(
            db,
            include_examples=False,
            factory_defaults=True,
            commit=False,
        )
        _seed_factory_host_interfaces(
            db,
            [
                HostPhysicalInterface(
                    name="eth0",
                    mac_address="00:50:56:00:00:01",
                    driver="vmxnet3",
                    speed="10 Gbps",
                    host_ip_cidr="192.168.167.249/24",
                    host_ipv6_cidr=None,
                    host_mtu=1500,
                    host_admin_state="up",
                    oper_state="up",
                ),
                HostPhysicalInterface(
                    name="eth1",
                    mac_address="00:50:56:00:00:02",
                    driver="vmxnet3",
                    speed="10 Gbps",
                    host_ip_cidr=None,
                    host_ipv6_cidr=None,
                    host_mtu=1500,
                    host_admin_state="up",
                    oper_state="up",
                ),
            ],
        )
        interfaces = db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all()

        assert [interface.name for interface in interfaces] == ["eth0", "eth1"]
        assert interfaces[0].mac_address == "00:50:56:00:00:01"
        assert interfaces[0].ip_cidr == "192.168.49.1/24"
        assert interfaces[0].admin_state == "up"
        assert interfaces[1].role == "unused"
        assert interfaces[1].ip_cidr is None
        assert interfaces[1].admin_state == "down"
        assert {interface.desired_state_source for interface in interfaces} == {"factory-reset"}
    engine.dispose()


def test_complete_factory_reset_replaces_database_and_establishes_baselines(
    tmp_path,
    monkeypatch,
):
    """Factory reset removes prior records and leaves every apply unit current.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    database_path = tmp_path / "atlaso.db"
    state_directory = tmp_path / "factory-reset"
    depot_payload = tmp_path / "depot" / "payload.bin"
    backup_payload = tmp_path / "backups" / "backup.bin"
    storage_payload = tmp_path / "storage" / "volume.bin"
    for payload in (depot_payload, backup_payload, storage_payload):
        payload.parent.mkdir(parents=True, exist_ok=True)
        payload.write_bytes(b"preserve-me")

    engine = create_engine(f"sqlite:///{database_path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    with session_factory() as db:
        seed_initial_data(db, include_examples=False)
        admin = db.execute(select(User).where(User.username == "admin")).scalar_one()
        db.add(User(username="remove-me", role="admin"))
        db.add(
            ApiToken(
                jti="remove-token",
                name="remove-token",
                owner_user_id=admin.id,
                owner_username=admin.username,
                role="admin",
                scopes="admin:all",
                expires_at=admin.created_at,
                token_hash="remove-hash",
            )
        )
        db.add(AuditEvent(actor="remove-me", action="remove-audit", resource_type="test"))
        db.add(Job(id="remove-job", type="managed-script", status="succeeded", created_by="remove-me"))
        db.add(Setting(key="remove.setting", value="remove-value"))
        db.commit()
    engine.dispose()

    monkeypatch.setenv("ATLASO_FACTORY_RESET_STATE_DIRECTORY", str(state_directory))
    monkeypatch.setenv("ATLASO_APPLIANCE_FQDN", "deployment.example.test")
    monkeypatch.setenv("ATLASO_APPLIANCE_MANAGEMENT_CIDR", "dhcp")
    monkeypatch.setenv("ATLASO_APPLIANCE_MANAGEMENT_IPV6_ENABLED", "true")
    monkeypatch.setenv("ATLASO_APPLIANCE_EXTERNAL_DNS_SERVERS", "")
    get_settings.cache_clear()
    adapter = SystemAdapter(dry_run=True)
    runtime_cleanup_calls: list[bool] = []
    monkeypatch.setattr(
        adapter,
        "reset_factory_network_runtime",
        lambda: runtime_cleanup_calls.append(True)
        or AdapterResult(command=["atlaso-helper", "factory-reset", "reset-network-runtime"], dry_run=True),
    )
    result = run_factory_reset(
        database_url=f"sqlite:///{database_path}",
        adapter=adapter,
        manage_services=False,
    )

    assert result["state"] == "succeeded"
    assert result["applied_unit_count"] == 16
    assert runtime_cleanup_calls == [True]
    assert not (state_directory / "request.json").exists()
    assert json.loads((state_directory / "last-result.json").read_text(encoding="utf-8"))["state"] == "succeeded"
    for payload in (depot_payload, backup_payload, storage_payload):
        assert payload.read_bytes() == b"preserve-me"

    replacement_engine = create_engine(f"sqlite:///{database_path}", connect_args={"check_same_thread": False})
    replacement_session = sessionmaker(
        bind=replacement_engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )
    with replacement_session() as db:
        assert {user.username for user in db.execute(select(User)).scalars()} == {
            "admin",
            "vcf-backup",
            "vcf-depot",
        }
        assert db.execute(select(ApiToken)).scalars().all() == []
        assert db.execute(select(AuditEvent)).scalars().all() == []
        assert db.execute(select(Job)).scalars().all() == []
        assert db.execute(select(VcfDepotDownloadProfile)).scalars().all() == []
        assert db.execute(
            select(Setting).where(Setting.key == FACTORY_RESET_SETTING_KEY)
        ).scalar_one().value == "complete"
        assert db.execute(select(Setting).where(Setting.key == "remove.setting")).scalar_one_or_none() is None
        appliance_settings = db.execute(select(ApplianceSettings)).scalar_one()
        assert appliance_settings.fqdn == "core.atlaso.internal"
        assert appliance_settings.management_https_enabled is False
        assert appliance_settings.root_ssh_enabled is False
        assert appliance_settings.external_dns_servers == "1.1.1.1\n9.9.9.9"
        management_interface = db.execute(select(PhysicalInterface)).scalar_one()
        assert management_interface.ipv4_method == "static"
        assert management_interface.ip_cidr == "192.168.49.1/24"
        assert management_interface.gateway is None
        assert management_interface.ipv6_enabled is False
        assert management_interface.ipv6_cidr is None
        dns_settings = db.execute(select(DnsSettings)).scalar_one()
        assert dns_settings.upstream_servers == "1.1.1.1\n9.9.9.9"
        from atlaso.app.ui import appliance_apply_units

        assert [unit["label"] for unit in appliance_apply_units(db, reconcile=False) if unit["changed"]] == []
    replacement_engine.dispose()


def test_complete_factory_reset_retains_recovery_marker_after_failure(
    tmp_path,
    monkeypatch,
):
    """An interrupted reset keeps the old database and a resumable marker.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    database_path = tmp_path / "atlaso.db"
    state_directory = tmp_path / "factory-reset"
    engine = create_engine(f"sqlite:///{database_path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    with session_factory() as db:
        seed_initial_data(db, include_examples=False)
        db.add(User(username="retained-after-failure", role="admin"))
        db.commit()
    engine.dispose()

    class FailingAdapter(SystemAdapter):
        """Fail the first activation after candidate validation."""

        def __init__(self) -> None:
            super().__init__(dry_run=True)

        def apply_local_users_config(self, config_path: str):
            """Inject one Local Users activation failure.

            Args:
                config_path: Staged Local Users configuration path.
            """
            result = super().apply_local_users_config(config_path)
            return type(result)(
                command=result.command,
                dry_run=True,
                stderr="injected activation failure",
                returncode=1,
            )

    monkeypatch.setenv("ATLASO_FACTORY_RESET_STATE_DIRECTORY", str(state_directory))
    import pytest

    with pytest.raises(Exception, match="Local Users"):
        run_factory_reset(
            database_url=f"sqlite:///{database_path}",
            adapter=FailingAdapter(),
            manage_services=False,
        )

    marker = json.loads((state_directory / "request.json").read_text(encoding="utf-8"))
    assert marker["state"] == "failed"
    retained_engine = create_engine(f"sqlite:///{database_path}", connect_args={"check_same_thread": False})
    retained_session = sessionmaker(bind=retained_engine)
    with retained_session() as db:
        assert db.execute(
            select(User).where(User.username == "retained-after-failure")
        ).scalar_one() is not None
    retained_engine.dispose()


def test_complete_factory_reset_resumes_after_post_replacement_interruption(
    tmp_path,
    monkeypatch,
):
    """A failure after atomic replacement can idempotently finish on resume.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import pytest

    import atlaso.app.factory_reset as factory_reset

    database_path = tmp_path / "atlaso.db"
    state_directory = tmp_path / "factory-reset"
    engine = create_engine(f"sqlite:///{database_path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    with session_factory() as db:
        seed_initial_data(db, include_examples=False)
        db.add(Setting(key="removed-before-resume", value="yes"))
        db.commit()
    engine.dispose()

    monkeypatch.setenv("ATLASO_FACTORY_RESET_STATE_DIRECTORY", str(state_directory))
    replace_database = factory_reset._replace_database

    def interrupt_after_replace(source, candidate):
        """Inject an interruption immediately after database replacement.

        Args:
            source: Installed database path.
            candidate: Validated replacement database path.
        """
        replace_database(source, candidate)
        raise FactoryResetError("injected post-replacement interruption")

    monkeypatch.setattr(factory_reset, "_replace_database", interrupt_after_replace)
    with pytest.raises(FactoryResetError, match="post-replacement"):
        run_factory_reset(
            database_url=f"sqlite:///{database_path}",
            adapter=SystemAdapter(dry_run=True),
            manage_services=False,
        )

    marker = json.loads((state_directory / "request.json").read_text(encoding="utf-8"))
    assert marker["state"] == "failed"
    interrupted_engine = create_engine(f"sqlite:///{database_path}")
    with sessionmaker(bind=interrupted_engine)() as db:
        assert db.execute(
            select(Setting).where(Setting.key == "removed-before-resume")
        ).scalar_one_or_none() is None
    interrupted_engine.dispose()

    monkeypatch.setattr(factory_reset, "_replace_database", replace_database)
    result = run_factory_reset(
        database_url=f"sqlite:///{database_path}",
        adapter=SystemAdapter(dry_run=True),
        manage_services=False,
    )

    assert result["state"] == "succeeded"
    assert result["applied_unit_count"] == 16
    assert not (state_directory / "request.json").exists()
