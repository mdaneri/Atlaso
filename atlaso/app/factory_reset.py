"""Perform Atlaso's crash-safe complete appliance factory reset."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, cast

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from atlaso.app.adapters.system import AdapterResult, SystemAdapter
from atlaso.app.config import get_settings
from atlaso.app.database import Base
from atlaso.app.models import PhysicalInterface, Setting
from atlaso.app.seed import (
    FACTORY_MANAGEMENT_CIDR,
    SEED_EXAMPLES_SETTING_KEY,
    seed_initial_data,
)
from atlaso.app.services.ldap import (
    LDAP_PENDING_PASSWORDS,
    LDAP_PENDING_RECOVERY_PAYLOADS,
)
from atlaso.app.services.local_users import (
    pending_os_password_snapshot,
    restore_pending_os_password_snapshot,
)
from atlaso.app.services.networking import (
    HostPhysicalInterface,
    discover_host_physical_interfaces,
    reconcile_host_physical_interfaces,
)

FACTORY_RESET_SCHEMA_VERSION = 1
FACTORY_RESET_STATE_DIRECTORY = Path("/var/lib/atlaso/factory-reset")
FACTORY_RESET_REQUEST_NAME = "request.json"
FACTORY_RESET_RESULT_NAME = "last-result.json"
FACTORY_RESET_CANDIDATE_NAME = "factory-candidate.db"
FACTORY_RESET_LOCK_NAME = "transaction.lock"
ATLASO_SERVICE_USER = "atlaso"


class FactoryResetError(RuntimeError):
    """Report one safe, operator-actionable factory-reset failure."""


class _ValidationOnlyAdapter(SystemAdapter):
    """Run real helper validations while replacing mutations with no-ops."""

    _MUTATING_METHODS = frozenset(
        {
            "apply_appliance_settings_config",
            "apply_ca_config",
            "apply_dnsmasq_config",
            "apply_esx_storage_config",
            "apply_esxi_pxe_config",
            "apply_firewall_config",
            "apply_kms_config",
            "apply_ldap_config",
            "apply_local_users_config",
            "apply_network_config",
            "apply_ntpd_config",
            "apply_public_services_config",
            "apply_vcf_backup_config",
            "apply_vcf_offline_depot_application_properties",
            "apply_vcf_offline_depot_ceip",
            "apply_vcf_offline_depot_https_config",
            "apply_vcf_private_registry_config",
            "apply_wan_config",
            "generate_vcf_offline_depot_software_depot_id",
            "relocate_vcf_private_registry_bundles",
            "reload_dnsmasq",
            "reset_vcf_offline_depot_tool",
            "stage_vcf_offline_depot_tool",
            "sync_vcf_offline_depot",
        }
    )

    def __init__(self) -> None:
        """Initialize a real-validation adapter."""
        super().__init__(dry_run=False)

    def __getattribute__(self, name: str) -> Any:
        """Replace a bounded mutating adapter method with a successful no-op."""
        mutating_methods = object.__getattribute__(self, "_MUTATING_METHODS")
        if name in mutating_methods:
            def validation_noop(*_args: object, **_kwargs: object) -> AdapterResult:
                return AdapterResult(
                    command=["atlaso-factory-reset", "preflight", name],
                    dry_run=True,
                    stdout=f"preflight: {name} activation deferred",
                )

            return validation_noop
        return super().__getattribute__(name)


def _seed_factory_host_interfaces(
    db: Session,
    discovered: list[HostPhysicalInterface],
) -> None:
    """Inventory appliance NICs while retaining packaged factory desired state."""
    if not discovered:
        raise FactoryResetError("Factory reset could not inventory host network interfaces.")
    interfaces = list(
        db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all()
    )
    reconciled = reconcile_host_physical_interfaces(interfaces, discovered)
    for interface in reconciled:
        interface.desired_state_source = "factory-reset"
        interface.access_management_ui_enabled = False
        interface.gateway = None
        interface.ipv6_enabled = False
        interface.ipv6_cidr = None
        interface.ipv6_gateway = None
        interface.mtu = 1500
        if interface.name == "eth0":
            interface.role = "management"
            interface.mode = "access"
            interface.ipv4_method = "static"
            interface.ip_cidr = FACTORY_MANAGEMENT_CIDR
            interface.admin_state = "up"
        else:
            interface.role = "unused"
            interface.mode = "access"
            interface.ipv4_method = "static"
            interface.ip_cidr = None
            interface.admin_state = "down"
        db.add(interface)
    db.flush()


def _utc_iso() -> str:
    """Return one UTC timestamp for durable reset state."""
    return datetime.now(timezone.utc).isoformat()


def _running_as_posix_root() -> bool:
    """Return whether the current process is root on a POSIX appliance."""
    if os.name != "posix":
        return False
    geteuid = cast(Callable[[], int], vars(os)["geteuid"])
    return geteuid() == 0


def factory_reset_state_directory() -> Path:
    """Return the configured factory-reset state directory."""
    override = os.environ.get("ATLASO_FACTORY_RESET_STATE_DIRECTORY", "").strip()
    return Path(override) if override else FACTORY_RESET_STATE_DIRECTORY


def factory_reset_request_path() -> Path:
    """Return the durable in-progress request marker path."""
    return factory_reset_state_directory() / FACTORY_RESET_REQUEST_NAME


def factory_reset_result_path() -> Path:
    """Return the durable last-result marker path."""
    return factory_reset_state_directory() / FACTORY_RESET_RESULT_NAME


@contextmanager
def _factory_reset_transaction_lock() -> Iterator[None]:
    """Admit exactly one reset runner on the POSIX appliance."""
    state_directory = factory_reset_state_directory()
    state_directory.mkdir(parents=True, exist_ok=True)
    state_directory.chmod(0o750)
    if _running_as_posix_root():
        shutil.chown(state_directory, user="root", group=ATLASO_SERVICE_USER)
    lock_path = state_directory / FACTORY_RESET_LOCK_NAME
    with lock_path.open("a+b") as lock_handle:
        lock_path.chmod(0o600)
        if _running_as_posix_root():
            shutil.chown(lock_path, user="root", group=ATLASO_SERVICE_USER)
        if os.name == "posix":
            fcntl = cast(Any, __import__("fcntl"))

            try:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise FactoryResetError("A factory reset transaction is already running.") from exc
        try:
            yield
        finally:
            if os.name == "posix":
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    """Write bounded reset state atomically and durably."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o750)
    if _running_as_posix_root():
        shutil.chown(path.parent, user="root", group=ATLASO_SERVICE_USER)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    temporary.chmod(0o640)
    if _running_as_posix_root():
        shutil.chown(temporary, user="root", group=ATLASO_SERVICE_USER)
    os.replace(temporary, path)
    if os.name == "posix":
        directory_descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)


def read_factory_reset_state() -> dict[str, Any]:
    """Return a bounded public-safe reset state snapshot."""
    for path in (factory_reset_request_path(), factory_reset_result_path()):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            continue
        if isinstance(payload, dict) and payload.get("schema_version") == FACTORY_RESET_SCHEMA_VERSION:
            return {
                "state": str(payload.get("state") or "unknown"),
                "updated_at": str(payload.get("updated_at") or payload.get("requested_at") or ""),
                "message": str(payload.get("message") or ""),
            }
    return {"state": "idle", "updated_at": "", "message": ""}


def _update_request(state: str, message: str, **details: Any) -> dict[str, Any]:
    """Update the resumable reset marker without secret-bearing data."""
    request_path = factory_reset_request_path()
    try:
        payload = json.loads(request_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        payload = {}
    payload = {
        "schema_version": FACTORY_RESET_SCHEMA_VERSION,
        "requested_at": str(payload.get("requested_at") or _utc_iso()),
        "state": state,
        "updated_at": _utc_iso(),
        "message": message,
        **details,
    }
    _write_json_atomic(request_path, payload)
    return payload


def _sqlite_database_path(database_url: str) -> Path:
    """Resolve the appliance SQLite database path without accepting other backends."""
    prefix = "sqlite:///"
    if not database_url.startswith(prefix):
        raise FactoryResetError("Complete factory reset requires the appliance SQLite database backend.")
    raw_path = database_url.removeprefix(prefix)
    if not raw_path or raw_path == ":memory:":
        raise FactoryResetError("Complete factory reset requires a durable SQLite database path.")
    return Path(raw_path).resolve()


def _run_systemctl(*arguments: str) -> None:
    """Run one bounded systemd command or fail closed."""
    completed = subprocess.run(
        ["systemctl", *arguments],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "systemctl failed").strip()
        raise FactoryResetError(detail)


def _stop_application_services(*, boot_resume: bool) -> None:
    """Quiesce database writers before runtime and database replacement."""
    if boot_resume:
        _run_systemctl("stop", "atlaso-worker.service")
        return
    _run_systemctl("stop", "atlaso-worker.service", "atlaso.service")


def _schedule_service_restart(*services: str, unit_name: str) -> None:
    """Restart selected services after the current reset process exits."""
    systemd_run = shutil.which("systemd-run")
    if systemd_run is None:
        raise FactoryResetError("systemd-run is required to restore Atlaso services after factory reset.")
    completed = subprocess.run(
        [
            systemd_run,
            "--quiet",
            "--on-active=2",
            f"--unit={unit_name}",
            "systemctl",
            "restart",
            *services,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "unable to schedule Atlaso service restart").strip()
        raise FactoryResetError(detail)


def _clear_apply_staging() -> None:
    """Remove only Atlaso's fixed apply staging tree after successful activation."""
    apply_root = Path("/var/lib/atlaso/apply")
    if not apply_root.exists():
        return
    if apply_root.is_symlink() or not apply_root.is_dir() or apply_root.resolve() != apply_root:
        raise FactoryResetError(f"Atlaso apply staging root is unsafe: {apply_root}")
    for child in apply_root.iterdir():
        if child.is_symlink() or child.is_file():
            child.unlink(missing_ok=True)
        elif child.is_dir():
            shutil.rmtree(child)


def _preserve_database_ownership(source: Path, candidate: Path) -> None:
    """Apply the installed database ownership and mode to the replacement."""
    source_stat = source.stat()
    candidate.chmod(source_stat.st_mode & 0o777)
    if os.name == "posix":
        chown = cast(Callable[[Path, int, int], None], vars(os)["chown"])
        chown(candidate, source_stat.st_uid, source_stat.st_gid)


def _replace_database(source: Path, candidate: Path) -> None:
    """Atomically replace the appliance database and discard stale SQLite sidecars."""
    _preserve_database_ownership(source, candidate)
    for suffix in ("-wal", "-shm", "-journal"):
        Path(f"{source}{suffix}").unlink(missing_ok=True)
    os.replace(candidate, source)
    if os.name == "posix":
        directory_descriptor = os.open(source.parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)


def _candidate_database(
    source_path: Path,
    candidate_path: Path,
    *,
    adapter: SystemAdapter,
) -> int:
    """Build, preflight, activate, and baseline one clean candidate database."""
    from atlaso.app.ui import (
        appliance_apply_units,
        execute_appliance_apply_unit,
        load_appliance_apply_baselines,
        save_appliance_apply_baselines,
        update_appliance_apply_baselines,
    )

    source_engine = create_engine(f"sqlite:///{source_path}", connect_args={"check_same_thread": False})
    source_session = sessionmaker(bind=source_engine, autoflush=False, autocommit=False, expire_on_commit=False)
    try:
        with source_session() as source_db:
            previous_baselines = load_appliance_apply_baselines(source_db)
    finally:
        source_engine.dispose()

    candidate_path.unlink(missing_ok=True)
    for suffix in ("-wal", "-shm", "-journal"):
        Path(f"{candidate_path}{suffix}").unlink(missing_ok=True)
    candidate_engine = create_engine(
        f"sqlite:///{candidate_path}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(candidate_engine)
    candidate_path.chmod(0o600)
    candidate_session = sessionmaker(bind=candidate_engine, autoflush=False, autocommit=False, expire_on_commit=False)
    try:
        with candidate_session() as db:
            seed_initial_data(
                db,
                include_examples=False,
                appliance_mode=False,
                factory_defaults=True,
                commit=False,
            )
            if not adapter.dry_run:
                _seed_factory_host_interfaces(db, discover_host_physical_interfaces())
            db.add(Setting(key=SEED_EXAMPLES_SETTING_KEY, value="false"))
            save_appliance_apply_baselines(db, previous_baselines)
            db.commit()

            units = appliance_apply_units(db)
            invalid = [unit["label"] for unit in units if unit["validation_errors"]]
            if invalid:
                raise FactoryResetError(
                    "Factory default validation failed for: " + ", ".join(invalid)
                )

            validation_adapter: SystemAdapter = (
                adapter if adapter.dry_run else _ValidationOnlyAdapter()
            )
            os_passwords = pending_os_password_snapshot()
            ldap_passwords = dict(LDAP_PENDING_PASSWORDS)
            ldap_recovery_payloads = dict(LDAP_PENDING_RECOVERY_PAYLOADS)
            try:
                for unit in units:
                    result = execute_appliance_apply_unit(unit, adapter=validation_adapter, db=db)
                    if not result["success"]:
                        raise FactoryResetError(f"Factory reset preflight failed for {unit['label']}.")
            finally:
                db.rollback()
                restore_pending_os_password_snapshot(os_passwords)
                LDAP_PENDING_PASSWORDS.clear()
                LDAP_PENDING_PASSWORDS.update(ldap_passwords)
                LDAP_PENDING_RECOVERY_PAYLOADS.clear()
                LDAP_PENDING_RECOVERY_PAYLOADS.update(ldap_recovery_payloads)
            units = appliance_apply_units(db)
            _update_request("applying", "Factory default configuration validated; activating runtime defaults.")

            for unit in units:
                result = execute_appliance_apply_unit(unit, adapter=adapter, db=db)
                if not result["success"]:
                    raise FactoryResetError(f"Factory reset activation failed for {unit['label']}.")
                db.flush()

            final_units = appliance_apply_units(db, reconcile=False)
            update_appliance_apply_baselines(
                db,
                final_units,
                {unit["id"] for unit in final_units},
            )
            db.commit()
            verified_units = appliance_apply_units(db, reconcile=False)
            pending = [unit["label"] for unit in verified_units if unit["changed"]]
            if pending:
                raise FactoryResetError(
                    "Factory reset could not establish applied baselines for: " + ", ".join(pending)
                )
            seed_marker = db.execute(
                select(Setting).where(Setting.key == SEED_EXAMPLES_SETTING_KEY)
            ).scalar_one_or_none()
            if seed_marker is None or seed_marker.value != "false":
                raise FactoryResetError("Factory reset example-data suppression marker is missing.")
            unit_count = len(verified_units)
    finally:
        candidate_engine.dispose()
    return unit_count


def _run_factory_reset_locked(
    *,
    database_url: str | None = None,
    adapter: SystemAdapter | None = None,
    manage_services: bool = True,
) -> dict[str, Any]:
    """Complete or resume the dedicated appliance factory-reset transaction."""
    settings = get_settings()
    source_path = _sqlite_database_path(database_url or settings.database_url)
    state_directory = factory_reset_state_directory()
    candidate_path = state_directory / FACTORY_RESET_CANDIDATE_NAME
    boot_resume = os.environ.get("ATLASO_FACTORY_RESET_BOOT_RESUME") == "1"
    if not source_path.is_file():
        raise FactoryResetError(f"Atlaso database is missing: {source_path}")
    state_directory.mkdir(parents=True, exist_ok=True)
    state_directory.chmod(0o750)
    request_payload = _update_request("stopping", "Stopping Atlaso database writers for factory reset.")
    try:
        if manage_services:
            _stop_application_services(boot_resume=boot_resume)
        _update_request("building", "Building a clean factory database and validating packaged defaults.")
        unit_count = _candidate_database(
            source_path,
            candidate_path,
            adapter=adapter or SystemAdapter(dry_run=False),
        )
        _update_request("committing", "Replacing the Atlaso database with the validated factory database.")
        _replace_database(source_path, candidate_path)
        if not (adapter and adapter.dry_run):
            _clear_apply_staging()
        completed = {
            "schema_version": FACTORY_RESET_SCHEMA_VERSION,
            "state": "succeeded",
            "requested_at": str(request_payload.get("requested_at") or _utc_iso()),
            "updated_at": _utc_iso(),
            "message": (
                f"Factory reset completed with {unit_count} applied units and no pending appliance changes. "
                "Sign in with the bootstrap administrator credentials."
            ),
            "applied_unit_count": unit_count,
        }
        _write_json_atomic(factory_reset_result_path(), completed)
        factory_reset_request_path().unlink(missing_ok=True)
        if manage_services:
            if boot_resume:
                _schedule_service_restart(
                    "atlaso-worker.service",
                    unit_name="atlaso-factory-reset-worker-restart",
                )
            else:
                _schedule_service_restart(
                    "atlaso.service",
                    "atlaso-worker.service",
                    unit_name="atlaso-factory-reset-restart",
                )
        return completed
    except Exception as exc:
        candidate_path.unlink(missing_ok=True)
        for suffix in ("-wal", "-shm", "-journal"):
            Path(f"{candidate_path}{suffix}").unlink(missing_ok=True)
        try:
            from atlaso.app.ui import cleanup_transient_secret_staging_files

            cleanup_transient_secret_staging_files()
        except Exception:  # noqa: BLE001 - preserve the primary reset failure and durable marker.
            pass
        safe_message = str(exc) if isinstance(exc, FactoryResetError) else "Factory reset failed unexpectedly."
        _update_request(
            "failed",
            safe_message + " Reboot or run the factory-reset resume helper from the console.",
        )
        raise


def run_factory_reset(
    *,
    database_url: str | None = None,
    adapter: SystemAdapter | None = None,
    manage_services: bool = True,
) -> dict[str, Any]:
    """Complete or resume one serialized appliance factory-reset transaction."""
    with _factory_reset_transaction_lock():
        return _run_factory_reset_locked(
            database_url=database_url,
            adapter=adapter,
            manage_services=manage_services,
        )


def main() -> int:
    """Run the appliance factory-reset entry point."""
    if os.name == "posix" and not _running_as_posix_root():
        raise SystemExit("atlaso-factory-reset must run as root")
    try:
        run_factory_reset()
    except Exception as exc:  # noqa: BLE001 - the durable marker carries the safe failure state.
        message = str(exc) if isinstance(exc, FactoryResetError) else "Factory reset failed unexpectedly."
        print(message, flush=True)
        return 1
    print(json.dumps(read_factory_reset_state(), sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
