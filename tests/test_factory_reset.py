"""Verify the complete, crash-safe Atlaso factory-reset transaction."""

import builtins
import json

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from atlaso.app.adapters.system import SystemAdapter
from atlaso.app.config import get_settings
from atlaso.app.database import Base
from atlaso.app.factory_reset import (
    FactoryResetError,
    _seed_factory_host_interfaces,
    run_factory_reset,
)
from atlaso.app.models import (
    ApiToken,
    ApplianceSettings,
    AuditEvent,
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
    """A competing appliance runner cannot enter or alter the active transaction."""
    import pytest

    import atlaso.app.factory_reset as factory_reset

    class ContendedFcntl:
        """Model an already-held nonblocking appliance file lock."""

        LOCK_EX = 1
        LOCK_NB = 2
        LOCK_UN = 4

        @staticmethod
        def flock(_descriptor, operation):
            if operation != ContendedFcntl.LOCK_UN:
                raise BlockingIOError

    original_import = builtins.__import__

    def import_with_contended_fcntl(name, *args, **kwargs):
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


def test_factory_host_inventory_is_stable_across_startup_refresh(tmp_path):
    """Factory reset baselines every host NIC in its final desired posture."""
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
    """Factory reset removes prior records and leaves every apply unit current."""
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
    result = run_factory_reset(
        database_url=f"sqlite:///{database_path}",
        adapter=SystemAdapter(dry_run=True),
        manage_services=False,
    )

    assert result["state"] == "succeeded"
    assert result["applied_unit_count"] == 16
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
    """An interrupted reset keeps the old database and a resumable marker."""
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
    """A failure after atomic replacement can idempotently finish on resume."""
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
