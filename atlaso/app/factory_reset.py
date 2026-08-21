"""Perform Atlaso's crash-safe complete appliance factory reset."""

from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from contextlib import closing, contextmanager
from contextvars import ContextVar, Token
from datetime import datetime, timezone
from http.client import HTTPConnection
from pathlib import Path
from typing import Any, Callable, cast

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from atlaso.app.adapters.system import AdapterResult, SystemAdapter
from atlaso.app.config import get_settings
from atlaso.app.database import Base
from atlaso.app.models import CaCertificate, PhysicalInterface, Setting, User
from atlaso.app.seed import (
    FACTORY_MANAGEMENT_CIDR,
    SEED_EXAMPLES_SETTING_KEY,
    seed_initial_data,
)
from atlaso.app.services.bootstrap_credentials import (
    write_bootstrap_admin_password_verifier,
)
from atlaso.app.services.ldap import (
    LDAP_PENDING_PASSWORDS,
    LDAP_PENDING_RECOVERY_PAYLOADS,
)
from atlaso.app.services.local_users import (
    clear_all_pending_os_passwords,
    clear_pending_os_password,
    pending_os_password_snapshot,
    restore_pending_os_password_snapshot,
    stage_user_os_password,
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
FACTORY_RESET_CREDENTIALS_NAME = "credentials.json"
FACTORY_RESET_STAGED_CREDENTIALS_PATH = (
    "/var/lib/atlaso/apply/factory-reset/credentials.json"
)
APPLIANCE_UPDATE_FINALIZER_PATH = Path(
    "/var/lib/atlaso/apply/appliance-update/finalizer-status.json"
)
FACTORY_RESET_LOCK_NAME = "transaction.lock"
ATLASO_SERVICE_USER = "atlaso"
FACTORY_RESET_MANAGEMENT_HOST = "127.0.0.1"
FACTORY_RESET_MANAGEMENT_PORT = 80
FACTORY_RESET_MANAGEMENT_PATH = "/openapi.json"
FACTORY_RESET_REQUIRED_SERVICES = (
    "atlaso.service",
    "atlaso-worker.service",
    "atlaso-console.service",
    "nginx.service",
)
VCF_BACKUPS_AUTHORIZED_KEYS_DIRECTORY = Path("/etc/atlaso/ssh/authorized_keys")
CA_MANAGED_PATH_BASE = Path("/etc/atlaso")
LOCAL_USERS_HOME_DIRECTORY = Path("/var/lib/atlaso/users")
LOCAL_USER_NAME_PATTERN = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
ROOT_SSH_DIRECTORY = Path("/root/.ssh")
SSH_AUTHORIZED_KEY_NAMES = ("authorized_keys", "authorized_keys2")
AUTOMATION_TRANSIENT_UNIT_PATTERN = re.compile(r"^atlaso-automation-\d{20}\.service$")
AUTOMATION_SCRIPT_DIRECTORY = Path("/var/lib/atlaso/automation/scripts")
AUTOMATION_RUN_DIRECTORY = Path("/var/lib/atlaso/automation/runs")
LDAP_RECOVERY_DIRECTORY = Path("/var/lib/atlaso/ldap/recovery")
HELPER_ACTION_TRANSIENT_UNIT_PATTERN = re.compile(
    r"^atlaso-helper-action-[0-9a-f]{32}\.service$"
)
HELPER_ACTION_QUIESCE_MAX_PASSES = 16
FACTORY_RESET_RUNNER_LOCK_WAIT_SECONDS = 30
MANAGEMENT_RESTART_TIMER_PATTERN = re.compile(r"^atlaso-management-ui-restart\.timer$")
MANAGEMENT_RESTART_SERVICE_PATTERN = re.compile(r"^atlaso-management-ui-restart\.service$")
UPDATE_RESTART_TIMER_PATTERN = re.compile(r"^atlaso-update-restart-\d{20}\.timer$")
UPDATE_RESTART_SERVICE_PATTERN = re.compile(r"^atlaso-update-restart-\d{20}\.service$")
WEB_TERMINAL_CREDENTIAL_PATHS = (
    Path("/etc/atlaso/ssh/web-terminal-ca"),
    Path("/etc/atlaso/ssh/web-terminal-ca.pub"),
)
WEB_TERMINAL_REQUEST_DIRECTORY = Path("/var/lib/atlaso/web-terminal/requests")
FACTORY_RESET_PASSWORD_ACTIONS = frozenset({"keep", "change"})
FACTORY_RESET_CREDENTIALS_MAX_BYTES = 16 * 1024
_PINNED_FACTORY_RESET_DIRECTORY_FD: ContextVar[int | None] = ContextVar(
    "pinned_factory_reset_directory_fd",
    default=None,
)


class FactoryResetError(RuntimeError):
    """Report one safe, operator-actionable factory-reset failure."""


class _ValidationOnlyAdapter(SystemAdapter):
    """Run real helper validations while replacing mutations with no-ops."""

    _GENERATED_CONFIG_PREFLIGHTS = {
        "apply_appliance_settings_config": "preflight_appliance_settings_config",
        "apply_public_services_config": "preflight_public_services_config",
        "apply_vcf_backup_config": "preflight_vcf_backup_config",
    }

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
        """Replace a bounded mutating adapter method with a successful no-op.

        Args:
            name: Adapter attribute requested by the apply workflow.
        """
        generated_config_preflights = object.__getattribute__(self, "_GENERATED_CONFIG_PREFLIGHTS")
        if name in generated_config_preflights:
            return super().__getattribute__(generated_config_preflights[name])
        mutating_methods = object.__getattribute__(self, "_MUTATING_METHODS")
        if name in mutating_methods:
            def validation_noop(*_args: object, **_kwargs: object) -> AdapterResult:
                """Record one deferred activation without changing the host.

                Args:
                    *_args: Positional arguments accepted by the adapter method.
                    **_kwargs: Keyword arguments accepted by the adapter method.
                """
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
    """Inventory appliance NICs while retaining packaged factory desired state.

    Args:
        db: Candidate database session receiving the discovered interfaces.
        discovered: Authoritative host-interface inventory.
    """
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
    pinned_descriptor = _PINNED_FACTORY_RESET_DIRECTORY_FD.get()
    if pinned_descriptor is not None:
        return Path(f"/proc/self/fd/{pinned_descriptor}")
    override = os.environ.get("ATLASO_FACTORY_RESET_STATE_DIRECTORY", "").strip()
    return Path(override) if override else FACTORY_RESET_STATE_DIRECTORY


def factory_reset_request_path() -> Path:
    """Return the durable in-progress request marker path."""
    return factory_reset_state_directory() / FACTORY_RESET_REQUEST_NAME


def factory_reset_result_path() -> Path:
    """Return the durable last-result marker path."""
    return factory_reset_state_directory() / FACTORY_RESET_RESULT_NAME


def factory_reset_credentials_path() -> Path:
    """Return the root-owned durable factory-reset credential path."""
    return factory_reset_state_directory() / FACTORY_RESET_CREDENTIALS_NAME


def _factory_reset_credential_plan() -> dict[str, str]:
    """Read and validate the durable factory-reset password choices."""
    path = factory_reset_credentials_path()
    try:
        pinned_descriptor = _PINNED_FACTORY_RESET_DIRECTORY_FD.get()
        if pinned_descriptor is not None:
            credential_descriptor = os.open(
                FACTORY_RESET_CREDENTIALS_NAME,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=pinned_descriptor,
            )
            try:
                file_stat = os.fstat(credential_descriptor)
                if not stat.S_ISREG(file_stat.st_mode):
                    raise FactoryResetError("Factory reset credential state is unsafe.")
                if file_stat.st_size > FACTORY_RESET_CREDENTIALS_MAX_BYTES:
                    raise FactoryResetError("Factory reset credential state is too large.")
                if file_stat.st_mode & 0o077 or file_stat.st_uid != 0:
                    raise FactoryResetError("Factory reset credential state is unsafe.")
                with os.fdopen(credential_descriptor, encoding="utf-8") as handle:
                    credential_descriptor = -1
                    payload = json.load(handle)
            finally:
                if credential_descriptor >= 0:
                    os.close(credential_descriptor)
        else:
            if path.is_symlink():
                raise FactoryResetError("Factory reset credential state is unsafe.")
            if not path.exists():
                return {"admin_action": "keep", "root_action": "keep"}
            if not path.is_file() or path.resolve() != path:
                raise FactoryResetError("Factory reset credential state is unsafe.")
            file_stat = path.stat()
            payload = json.loads(path.read_text(encoding="utf-8"))
        if file_stat.st_size > FACTORY_RESET_CREDENTIALS_MAX_BYTES:
            raise FactoryResetError("Factory reset credential state is too large.")
        if os.name == "posix" and (file_stat.st_mode & 0o077 or file_stat.st_uid != 0):
            raise FactoryResetError("Factory reset credential state is unsafe.")
    except FileNotFoundError:
        return {"admin_action": "keep", "root_action": "keep"}
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FactoryResetError("Factory reset credential state is invalid.") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise FactoryResetError("Factory reset credential state is invalid.")
    allowed_keys = {
        "schema_version",
        "admin_action",
        "admin_password",
        "root_action",
        "root_password",
    }
    if set(payload) - allowed_keys:
        raise FactoryResetError("Factory reset credential state is invalid.")
    plan: dict[str, str] = {}
    for account in ("admin", "root"):
        action = payload.get(f"{account}_action")
        password = payload.get(f"{account}_password", "")
        if action not in FACTORY_RESET_PASSWORD_ACTIONS or not isinstance(password, str):
            raise FactoryResetError("Factory reset credential state is invalid.")
        if (action == "change") != bool(password):
            raise FactoryResetError("Factory reset credential state is incomplete.")
        if password and (
            len(password) > 1024
            or any(character in password for character in ("\x00", "\r", "\n"))
        ):
            raise FactoryResetError("Factory reset credential state is invalid.")
        plan[f"{account}_action"] = action
        if action == "change":
            plan[f"{account}_password"] = password
    return plan


def _open_factory_reset_state_directory(path: Path) -> int:
    """Open the root-owned state directory without following any path component.

    Args:
        path: Exact absolute factory-reset state directory admitted by the helper.
    """
    if not path.is_absolute():
        raise FactoryResetError("Factory reset state directory is not absolute.")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path.anchor, directory_flags)
    try:
        for component in path.parts[1:]:
            next_descriptor = os.open(
                component,
                directory_flags | nofollow,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        directory_stat = os.fstat(descriptor)
        if directory_stat.st_uid != 0 or directory_stat.st_mode & 0o022:
            raise FactoryResetError("Factory reset state directory is unsafe.")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


@contextmanager
def _factory_reset_transaction_lock(*, wait_seconds: float = 0) -> Iterator[None]:
    """Admit exactly one reset runner on the POSIX appliance.

    Args:
        wait_seconds: Maximum time to wait for the reset lock.
    """
    raw_state_directory = factory_reset_state_directory()
    pinned_descriptor: int | None = None
    pinned_token: Token[int | None] | None = None
    if _running_as_posix_root():
        try:
            pinned_descriptor = _open_factory_reset_state_directory(raw_state_directory)
        except OSError as exc:
            raise FactoryResetError("Factory reset state directory is unsafe.") from exc
        pinned_token = _PINNED_FACTORY_RESET_DIRECTORY_FD.set(pinned_descriptor)
        lock_descriptor: int | None = None
        try:
            lock_descriptor = os.open(
                FACTORY_RESET_LOCK_NAME,
                os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=pinned_descriptor,
            )
            lock_handle_context = os.fdopen(lock_descriptor, "a+b")
            lock_descriptor = None
        except Exception:
            if lock_descriptor is not None:
                os.close(lock_descriptor)
            _PINNED_FACTORY_RESET_DIRECTORY_FD.reset(pinned_token)
            os.close(pinned_descriptor)
            raise
    else:
        raw_state_directory.mkdir(parents=True, exist_ok=True)
        raw_state_directory.chmod(0o750)
        lock_path = raw_state_directory / FACTORY_RESET_LOCK_NAME
        lock_handle_context = lock_path.open("a+b")
    try:
        with lock_handle_context as lock_handle:
            os.fchmod(lock_handle.fileno(), 0o600)
            if _running_as_posix_root():
                shutil.chown(
                    factory_reset_state_directory() / FACTORY_RESET_LOCK_NAME,
                    user="root",
                    group=ATLASO_SERVICE_USER,
                )
            if os.name == "posix":
                fcntl = cast(Any, __import__("fcntl"))
                deadline = time.monotonic() + wait_seconds
                while True:
                    try:
                        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError as exc:
                        if time.monotonic() >= deadline:
                            raise FactoryResetError("A factory reset transaction is already running.") from exc
                        time.sleep(min(0.25, max(0, deadline - time.monotonic())))
            try:
                yield
            finally:
                if os.name == "posix":
                    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
    finally:
        if pinned_token is not None:
            _PINNED_FACTORY_RESET_DIRECTORY_FD.reset(pinned_token)
        if pinned_descriptor is not None:
            os.close(pinned_descriptor)


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    """Write bounded reset state atomically and durably.

    Args:
        path: Durable marker path to replace.
        payload: Bounded non-secret state to serialize.
    """
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
    """Update the resumable reset marker without secret-bearing data.

    Args:
        state: New reset lifecycle state.
        message: Public-safe operator status message.
        **details: Additional bounded non-secret marker fields.
    """
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
    """Resolve the appliance SQLite database path without accepting other backends.

    Args:
        database_url: Configured SQLAlchemy database URL.
    """
    prefix = "sqlite:///"
    if not database_url.startswith(prefix):
        raise FactoryResetError("Complete factory reset requires the appliance SQLite database backend.")
    raw_path = database_url.removeprefix(prefix)
    if not raw_path or raw_path == ":memory:":
        raise FactoryResetError("Complete factory reset requires a durable SQLite database path.")
    return Path(raw_path).resolve()


def _run_systemctl(*arguments: str) -> None:
    """Run one bounded systemd command or fail closed.

    Args:
        *arguments: Systemctl action and exact unit arguments.
    """
    completed = subprocess.run(
        ["systemctl", *arguments],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "systemctl failed").strip()
        raise FactoryResetError(detail)


def _inventory_transient_units(
    *,
    unit_type: str,
    unit_glob: str,
    unit_pattern: re.Pattern[str],
    label: str,
) -> list[str]:
    """Return an exact bounded systemd transient-unit inventory.

    Args:
        unit_type: Exact systemd unit type to inventory.
        unit_glob: Exact Atlaso-owned unit glob passed to systemctl.
        unit_pattern: Full-match validator for every returned unit name.
        label: Public-safe unit family used in failures.
    """
    completed = subprocess.run(
        [
            "systemctl",
            "list-units",
            "--all",
            f"--type={unit_type}",
            "--no-legend",
            "--no-pager",
            "--plain",
            unit_glob,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise FactoryResetError(f"Factory reset could not inventory {label} units.")
    units: list[str] = []
    for line in completed.stdout.splitlines():
        matches = [token for token in line.split() if unit_pattern.fullmatch(token)]
        if len(matches) != 1:
            raise FactoryResetError(f"Factory reset encountered an unsafe {label} unit inventory.")
        units.append(matches[0])
    return sorted(set(units))


def _stop_and_verify_transient_units(units: list[str], *, label: str) -> None:
    """Stop and verify one already validated transient-unit set.

    Args:
        units: Exact validated systemd unit names.
        label: Public-safe unit family used in failures.
    """
    if not units:
        return
    _run_systemctl("stop", *units)
    for unit in units:
        active = subprocess.run(
            ["systemctl", "is-active", "--quiet", unit],
            check=False,
            capture_output=True,
            text=True,
        )
        if active.returncode == 0:
            raise FactoryResetError(f"Factory reset could not stop an Atlaso {label} unit.")
        if active.returncode not in {3, 4}:
            raise FactoryResetError(f"Factory reset could not verify an Atlaso {label} unit stopped.")


def _stop_transient_update_restart_units() -> None:
    """Cancel delayed update restarts before they can revive a database writer."""
    timers = _inventory_transient_units(
        unit_type="timer",
        unit_glob="atlaso-update-restart-*.timer",
        unit_pattern=UPDATE_RESTART_TIMER_PATTERN,
        label="update-restart timer",
    )
    _stop_and_verify_transient_units(timers, label="update-restart timer")
    services = _inventory_transient_units(
        unit_type="service",
        unit_glob="atlaso-update-restart-*.service",
        unit_pattern=UPDATE_RESTART_SERVICE_PATTERN,
        label="update-restart service",
    )
    _stop_and_verify_transient_units(services, label="update-restart service")


def _stop_transient_management_restart_units() -> None:
    """Cancel a pre-existing management restart before factory activation."""
    timers = _inventory_transient_units(
        unit_type="timer",
        unit_glob="atlaso-management-ui-restart.timer",
        unit_pattern=MANAGEMENT_RESTART_TIMER_PATTERN,
        label="management-restart timer",
    )
    _stop_and_verify_transient_units(timers, label="management-restart timer")
    services = _inventory_transient_units(
        unit_type="service",
        unit_glob="atlaso-management-ui-restart.service",
        unit_pattern=MANAGEMENT_RESTART_SERVICE_PATTERN,
        label="management-restart service",
    )
    _stop_and_verify_transient_units(services, label="management-restart service")


def _stop_transient_helper_action_units() -> None:
    """Stop privileged helper actions after their Atlaso callers are quiescent."""
    for pass_index in range(HELPER_ACTION_QUIESCE_MAX_PASSES + 1):
        units = _inventory_transient_units(
            unit_type="service",
            unit_glob="atlaso-helper-action-*.service",
            unit_pattern=HELPER_ACTION_TRANSIENT_UNIT_PATTERN,
            label="helper action",
        )
        if not units:
            return
        if pass_index == HELPER_ACTION_QUIESCE_MAX_PASSES:
            raise FactoryResetError(
                "Factory reset could not quiesce Atlaso helper action units."
            )
        _stop_and_verify_transient_units(units, label="helper action")


def _stop_transient_automation_units() -> None:
    """Stop every bounded Atlaso automation transient unit after worker quiescence."""
    units = _inventory_transient_units(
        unit_type="service",
        unit_glob="atlaso-automation-*.service",
        unit_pattern=AUTOMATION_TRANSIENT_UNIT_PATTERN,
        label="automation",
    )
    _stop_and_verify_transient_units(units, label="automation")


def _clear_directory_descriptor(directory_fd: int) -> None:
    """Recursively clear one already pinned directory without following links.

    Args:
        directory_fd: Open descriptor for the directory being cleared.
    """
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    for name in os.listdir(directory_fd):
        entry_stat = os.stat(
            name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        if stat.S_ISDIR(entry_stat.st_mode):
            child_fd = os.open(
                name,
                directory_flags | nofollow,
                dir_fd=directory_fd,
            )
            try:
                _clear_directory_descriptor(child_fd)
                os.fsync(child_fd)
            finally:
                os.close(child_fd)
            os.rmdir(name, dir_fd=directory_fd)
        else:
            os.unlink(name, dir_fd=directory_fd)


def _clear_posix_directory(path: Path, *, label: str) -> None:
    """Clear a fixed absolute directory through pinned, no-follow descriptors.

    Args:
        path: Fixed absolute directory to clear.
        label: Public-safe name used in validation failures.
    """
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not path.is_absolute():
        raise FactoryResetError(f"Factory reset {label} directory is not absolute.")
    descriptor = os.open(path.anchor, directory_flags)
    try:
        try:
            for component in path.parts[1:]:
                next_descriptor = os.open(
                    component,
                    directory_flags | nofollow,
                    dir_fd=descriptor,
                )
                os.close(descriptor)
                descriptor = next_descriptor
        except FileNotFoundError:
            return
        except OSError as exc:
            raise FactoryResetError(
                f"Factory reset {label} directory is unsafe or cannot be opened."
            ) from exc
        try:
            _clear_directory_descriptor(descriptor)
            os.fsync(descriptor)
        except OSError as exc:
            raise FactoryResetError(
                f"Factory reset {label} directory cannot be cleared durably."
            ) from exc
    finally:
        os.close(descriptor)


def _clear_portable_directory(path: Path, *, label: str) -> None:
    """Clear a fixed directory on platforms without descriptor-relative removal.

    Args:
        path: Fixed directory to clear.
        label: Public-safe name used in validation failures.
    """
    if not path.exists():
        return
    if path.is_symlink() or not path.is_dir() or path.resolve() != path:
        raise FactoryResetError(f"Factory reset {label} directory is unsafe: {path}")
    removed = False
    for child in path.iterdir():
        if child.is_symlink() or child.is_file():
            child.unlink(missing_ok=True)
            removed = True
        elif child.is_dir():
            shutil.rmtree(child)
            removed = True
        else:
            raise FactoryResetError(
                f"Factory reset {label} entry is unsafe: {child.name}"
            )
    if removed:
        _fsync_directory(path)


def _clear_symlink_resistant_directory(path: Path, *, label: str) -> None:
    """Durably clear one bounded directory without following its path.

    Args:
        path: Fixed directory whose transient contents must be removed.
        label: Public-safe name used in validation failures.
    """
    if os.name == "posix":
        _clear_posix_directory(path, label=label)
    else:
        _clear_portable_directory(path, label=label)


def _clear_automation_transient_staging() -> None:
    """Durably remove interrupted managed-script and run staging."""
    for path, label in (
        (AUTOMATION_SCRIPT_DIRECTORY, "automation script staging"),
        (AUTOMATION_RUN_DIRECTORY, "automation run staging"),
    ):
        _clear_symlink_resistant_directory(path, label=label)


def _require_terminal_release_update() -> None:
    """Reject reset while durable signed-release recovery remains pending."""
    try:
        payload = json.loads(APPLIANCE_UPDATE_FINALIZER_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FactoryResetError(
            "Factory reset cannot verify the Atlaso Release transaction; "
            "recover the release update and retry."
        ) from exc
    if not isinstance(payload, dict):
        raise FactoryResetError(
            "Factory reset cannot verify the Atlaso Release transaction; "
            "recover the release update and retry."
        )
    status = str(payload.get("status") or "")
    recovery = payload.get("transaction_recovery")
    pending = status in {
        "transaction_pending",
        "restart_pending",
        "rollback_pending",
        "activation_committed",
    } or (
        status == "failed"
        and payload.get("rolled_back") is not True
        and isinstance(recovery, dict)
    )
    terminal = status == "succeeded" or (
        status == "failed" and not pending
    )
    if not terminal:
        raise FactoryResetError(
            "Factory reset is blocked until the active Atlaso Release transaction "
            "reaches a definitive terminal state."
        )


def _stop_application_services(*, boot_resume: bool) -> None:
    """Quiesce database writers before runtime and database replacement.

    Args:
        boot_resume: Whether Atlaso is already stopped by service startup ordering.
    """
    if boot_resume:
        _run_systemctl("stop", "atlaso-worker.service", "atlaso-console.service")
    else:
        _run_systemctl(
            "stop",
            "atlaso-worker.service",
            "atlaso.service",
            "atlaso-console.service",
        )
    # Stop helper actions first, then inventory delayed update restarts that an
    # in-flight update helper may have scheduled immediately before it stopped.
    _stop_transient_helper_action_units()
    # A release helper can publish its recovery manifest between the admission
    # check and helper quiescence. Preserve that manifest and fail before any
    # factory database or apply-staging mutation.
    _require_terminal_release_update()
    # An ordinary Appliance Settings apply may have scheduled this fixed-name
    # restart before the reset marker entered applying. Cancel both sides of
    # the timer handoff, then stop and verify the application services again.
    _stop_transient_management_restart_units()
    application_services: tuple[str, ...]
    if boot_resume:
        application_services = ("atlaso-worker.service", "atlaso-console.service")
    else:
        application_services = (
            "atlaso-worker.service",
            "atlaso.service",
            "atlaso-console.service",
        )
    _run_systemctl("stop", *application_services)
    for service in application_services:
        active = subprocess.run(
            ["systemctl", "is-active", "--quiet", service],
            check=False,
            capture_output=True,
            text=True,
        )
        if active.returncode == 0:
            raise FactoryResetError(
                "Factory reset could not stop an Atlaso application service."
            )
        if active.returncode not in {3, 4}:
            raise FactoryResetError(
                "Factory reset could not verify an Atlaso application service stopped."
            )
    _stop_transient_update_restart_units()
    _stop_transient_automation_units()
    _clear_automation_transient_staging()


def _schedule_readiness_finalizer() -> None:
    """Schedule independent post-restart management readiness verification."""
    systemd_run = shutil.which("systemd-run")
    if systemd_run is None:
        raise FactoryResetError("systemd-run is required to verify factory-reset readiness.")
    unit_name = f"atlaso-factory-reset-readiness-{os.getpid()}"
    completed = subprocess.run(
        [
            systemd_run,
            "--quiet",
            "--collect",
            "--no-block",
            f"--unit={unit_name}",
            "--property=Type=oneshot",
            "--property=WorkingDirectory=/var/lib/atlaso",
            "--property=EnvironmentFile=/etc/atlaso/atlaso.env",
            sys.executable,
            "-m",
            "atlaso.app.factory_reset",
            "finalize",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "unable to schedule reset readiness verification").strip()
        raise FactoryResetError(detail)


def _clear_apply_staging() -> None:
    """Remove only Atlaso's fixed apply staging tree after successful activation."""
    # Recheck immediately before recursive cleanup so a late release transaction
    # can never lose the manifest required for rollback or forward completion.
    _require_terminal_release_update()
    apply_root = Path("/var/lib/atlaso/apply")
    if not apply_root.exists():
        return
    if apply_root.is_symlink() or not apply_root.is_dir() or apply_root.resolve() != apply_root:
        raise FactoryResetError(f"Atlaso apply staging root is unsafe: {apply_root}")
    removed = False
    for child in apply_root.iterdir():
        if child.is_symlink() or child.is_file():
            child.unlink(missing_ok=True)
            removed = True
        elif child.is_dir():
            shutil.rmtree(child)
            removed = True
    if removed:
        _fsync_directory(apply_root)


def _fsync_directory(path: Path) -> None:
    """Synchronize one directory after removing a secret-bearing entry.

    Args:
        path: Directory whose entry changes must be durable.
    """
    if os.name != "posix":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _clear_fixed_directory_contents(path: Path, *, label: str) -> None:
    """Remove direct credential entries from one fixed Atlaso-owned directory.

    Args:
        path: Fixed credential directory to clear.
        label: Public-safe name used in validation failures.
    """
    if not path.exists():
        return
    if path.is_symlink() or not path.is_dir() or path.resolve() != path:
        raise FactoryResetError(f"Factory reset {label} directory is unsafe: {path}")
    removed = False
    for child in path.iterdir():
        if child.is_symlink() or child.is_file():
            child.unlink(missing_ok=True)
            removed = True
        else:
            raise FactoryResetError(f"Factory reset {label} entry is unsafe: {child.name}")
    if removed:
        _fsync_directory(path)


def _scrub_authorized_keys(ssh_directory: Path, *, label: str) -> None:
    """Remove bounded SSH server authorization files from one retained home.

    Args:
        ssh_directory: Exact retained account SSH directory to inspect.
        label: Public-safe account description used in failures.
    """
    if ssh_directory.is_symlink() or (ssh_directory.exists() and not ssh_directory.is_dir()):
        raise FactoryResetError(f"Factory reset {label} SSH directory is unsafe.")
    if not ssh_directory.exists():
        return
    removed = False
    for name in SSH_AUTHORIZED_KEY_NAMES:
        path = ssh_directory / name
        if path.is_symlink() or path.is_file():
            path.unlink(missing_ok=True)
            removed = True
        elif path.exists():
            raise FactoryResetError(
                f"Factory reset {label} SSH authorization entry is unsafe: {name}"
            )
    if removed:
        _fsync_directory(ssh_directory)


def _scrub_bootstrap_authorized_keys() -> None:
    """Remove SSH authorization files from the retained bootstrap home."""
    username = get_settings().bootstrap_admin_username.strip().lower()
    if not LOCAL_USER_NAME_PATTERN.fullmatch(username):
        raise FactoryResetError("Factory reset bootstrap local-user name is unsafe.")
    home = LOCAL_USERS_HOME_DIRECTORY / username
    if home.is_symlink() or (home.exists() and not home.is_dir()):
        raise FactoryResetError("Factory reset bootstrap local-user home is unsafe.")
    if not home.exists():
        return
    _scrub_authorized_keys(home / ".ssh", label="bootstrap")


def _scrub_root_authorized_keys() -> None:
    """Remove SSH authorization files without changing other root SSH state."""
    _scrub_authorized_keys(ROOT_SSH_DIRECTORY, label="root")


def _ca_private_key_paths(db: Session) -> set[Path]:
    """Return normalized private-key paths from Atlaso's CA certificate inventory.

    Args:
        db: Active database session containing the CA certificate inventory.
    """
    managed_base = CA_MANAGED_PATH_BASE.resolve()
    paths: set[Path] = set()
    for value in db.execute(select(CaCertificate.key_path)).scalars().all():
        if not value or not value.strip():
            continue
        path = Path(value.strip())
        resolved = path.resolve()
        if (
            not path.is_absolute()
            or resolved == managed_base
            or not resolved.is_relative_to(managed_base)
            or resolved != path
        ):
            raise FactoryResetError("Factory reset encountered an unsafe CA-managed private-key path.")
        paths.add(path)
    return paths


def _remove_retired_ca_private_keys(paths: set[Path]) -> None:
    """Durably remove bounded CA private keys omitted from factory state.

    Args:
        paths: Validated CA-managed private-key paths to remove.
    """
    synced_directories: set[Path] = set()
    for path in sorted(paths):
        if path.is_symlink():
            raise FactoryResetError("Factory reset encountered a symlinked retired CA private key.")
        if path.is_file():
            path.unlink()
            synced_directories.add(path.parent)
        elif path.exists():
            raise FactoryResetError("Factory reset encountered an unsafe retired CA private-key entry.")
    for directory in sorted(synced_directories):
        _fsync_directory(directory)


def _scrub_retained_credentials() -> None:
    """Remove fixed credential material that intentionally lives outside Apply staging."""
    synced_directories: set[Path] = set()
    for path in WEB_TERMINAL_CREDENTIAL_PATHS:
        if path.is_symlink() or path.is_file():
            path.unlink(missing_ok=True)
            synced_directories.add(path.parent)
        elif path.exists():
            raise FactoryResetError(f"Factory reset web-terminal credential path is unsafe: {path}")
    for directory in sorted(synced_directories):
        _fsync_directory(directory)
    _clear_fixed_directory_contents(
        WEB_TERMINAL_REQUEST_DIRECTORY,
        label="web-terminal request",
    )
    _clear_fixed_directory_contents(
        VCF_BACKUPS_AUTHORIZED_KEYS_DIRECTORY,
        label="VCF Backup authorized-key",
    )
    _clear_symlink_resistant_directory(
        LDAP_RECOVERY_DIRECTORY,
        label="LDAP recovery staging",
    )
    _scrub_bootstrap_authorized_keys()
    _scrub_root_authorized_keys()


def _remove_factory_reset_credentials() -> None:
    """Durably remove the reset password plan after post-activation state is durable."""
    credential_path = factory_reset_credentials_path()
    if credential_path.is_symlink():
        raise FactoryResetError("Factory reset credential state is unsafe.")
    if credential_path.is_file():
        credential_path.unlink()
        _fsync_directory(credential_path.parent)
    elif credential_path.exists():
        raise FactoryResetError("Factory reset credential state is unsafe.")


def _management_ready() -> bool:
    """Return whether required services and the management OpenAPI front door are ready."""
    for service in FACTORY_RESET_REQUIRED_SERVICES:
        completed = subprocess.run(
            ["systemctl", "is-active", "--quiet", service],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            return False
    try:
        connection = HTTPConnection(
            FACTORY_RESET_MANAGEMENT_HOST,
            FACTORY_RESET_MANAGEMENT_PORT,
            timeout=2,
        )
        connection.request("GET", FACTORY_RESET_MANAGEMENT_PATH)
        response = connection.getresponse()
        payload = json.loads(response.read().decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    finally:
        try:
            connection.close()
        except UnboundLocalError:
            pass
    return response.status == 200 and isinstance(payload, dict) and isinstance(payload.get("info"), dict)


def _start_required_services() -> None:
    """Queue every required service without deadlocking its reset-resume preflight."""
    _run_systemctl("--no-block", "start", *FACTORY_RESET_REQUIRED_SERVICES)


def _mark_factory_reset_succeeded(request_payload: dict[str, Any], unit_count: int) -> dict[str, Any]:
    """Persist terminal success before durably removing the recovery marker.

    Args:
        request_payload: Active durable reset request.
        unit_count: Number of applied and baselined units.
    """
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
    if os.name == "posix":
        directory_descriptor = os.open(factory_reset_state_directory(), os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    return completed


def finalize_factory_reset(
    *,
    readiness_timeout_seconds: float = 120,
    poll_seconds: float = 2,
) -> dict[str, Any]:
    """Verify stable post-restart management readiness before terminal success.

    Args:
        readiness_timeout_seconds: Maximum readiness observation interval.
        poll_seconds: Delay between readiness samples.
    """
    with _factory_reset_transaction_lock(wait_seconds=30):
        request_path = factory_reset_request_path()
        try:
            request_payload = json.loads(request_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, json.JSONDecodeError):
            return read_factory_reset_state()
        applied_unit_count = request_payload.get("applied_unit_count")
        if (
            request_payload.get("state") not in {"awaiting_readiness", "failed"}
            or type(applied_unit_count) is not int
            or applied_unit_count <= 0
        ):
            raise FactoryResetError("Factory reset is not awaiting management readiness verification.")
        unit_count = applied_unit_count
        _remove_factory_reset_credentials()
        try:
            _start_required_services()
        except FactoryResetError as exc:
            message = (
                f"Factory reset applied defaults, but required services could not start: {exc} "
                "Reboot or run the factory-reset resume helper from the console."
            )
            _update_request("failed", message, applied_unit_count=unit_count)
            raise FactoryResetError(message) from exc
        deadline = time.monotonic() + readiness_timeout_seconds
        consecutive_ready = 0
        while time.monotonic() <= deadline:
            if _management_ready():
                consecutive_ready += 1
                if consecutive_ready >= 2:
                    return _mark_factory_reset_succeeded(request_payload, unit_count)
            else:
                consecutive_ready = 0
            time.sleep(poll_seconds)
        message = (
            "Factory reset applied defaults, but required services or management OpenAPI readiness did not stabilize. "
            "Reboot or run the factory-reset resume helper from the console."
        )
        _update_request("failed", message, applied_unit_count=unit_count)
        raise FactoryResetError(message)


def _preserve_database_ownership(source: Path, candidate: Path) -> None:
    """Apply the installed database ownership and mode to the replacement.

    Args:
        source: Installed database whose metadata is authoritative.
        candidate: Validated replacement database.
    """
    source_stat = source.stat()
    candidate.chmod(source_stat.st_mode & 0o777)
    if os.name == "posix":
        chown = cast(Callable[[Path, int, int], None], vars(os)["chown"])
        chown(candidate, source_stat.st_uid, source_stat.st_gid)


def _replace_database(source: Path, candidate: Path) -> None:
    """Atomically replace the appliance database and discard stale SQLite sidecars.

    Args:
        source: Installed database path to replace.
        candidate: Fully validated candidate database path.
    """
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
    credential_plan: dict[str, str] | None = None,
    report_progress: bool = True,
) -> int:
    """Build, preflight, activate, and baseline one clean candidate database.

    Args:
        source_path: Current database used to retain compatible baseline metadata.
        candidate_path: Private candidate database path.
        adapter: System adapter used for validation and activation.
        credential_plan: Validated keep-or-change password choices for admin and root.
        report_progress: Whether to update the durable appliance request marker.
    """
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
            previous_ca_private_key_paths = _ca_private_key_paths(source_db)
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
    password_plan = credential_plan or {"admin_action": "keep", "root_action": "keep"}
    try:
        with candidate_session() as db:
            seed_initial_data(
                db,
                include_examples=False,
                appliance_mode=False,
                factory_defaults=True,
                commit=False,
            )
            bootstrap_username = get_settings().bootstrap_admin_username
            bootstrap_user = db.execute(
                select(User).where(User.username == bootstrap_username)
            ).scalar_one()
            clear_pending_os_password(bootstrap_user)
            if password_plan["admin_action"] == "change":
                stage_user_os_password(
                    bootstrap_user,
                    password_plan["admin_password"],
                )
            if not adapter.dry_run:
                _seed_factory_host_interfaces(db, discover_host_physical_interfaces())
            db.add(Setting(key=SEED_EXAMPLES_SETTING_KEY, value="false"))
            save_appliance_apply_baselines(db, previous_baselines)
            db.commit()
            retired_ca_private_key_paths = previous_ca_private_key_paths - _ca_private_key_paths(db)

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
            if report_progress:
                _update_request("applying", "Factory default configuration validated; activating runtime defaults.")

            runtime_cleanup = adapter.reset_factory_network_runtime()
            if runtime_cleanup.returncode != 0:
                raise FactoryResetError("Factory reset could not clear Atlaso-managed network runtime state.")

            for unit in units:
                result = execute_appliance_apply_unit(unit, adapter=adapter, db=db)
                if not result["success"]:
                    raise FactoryResetError(f"Factory reset activation failed for {unit['label']}.")
                db.flush()
            if not adapter.dry_run:
                retained_runtime_cleanup = adapter.reset_factory_retained_runtime()
                if retained_runtime_cleanup.returncode != 0:
                    raise FactoryResetError("Factory reset could not remove retained credential-bearing runtime state.")
                root_password_result = adapter.apply_factory_reset_root_password()
                if root_password_result.returncode != 0:
                    raise FactoryResetError("Factory reset could not apply the selected root password action.")
                if password_plan["admin_action"] == "change":
                    write_bootstrap_admin_password_verifier(
                        password_plan["admin_password"]
                    )
                _remove_retired_ca_private_keys(retired_ca_private_key_paths)

            final_units = appliance_apply_units(db, reconcile=False)
            final_unit_ids = {unit["id"] for unit in final_units}
            save_appliance_apply_baselines(db, {})
            update_appliance_apply_baselines(
                db,
                final_units,
                final_unit_ids,
            )
            db.commit()
            verified_baselines = load_appliance_apply_baselines(db)
            if set(verified_baselines) != final_unit_ids:
                raise FactoryResetError(
                    "Factory reset could not replace the applied baseline inventory."
                )
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


def replace_database_with_factory_candidate(
    db: Session,
    *,
    database_url: str,
    adapter: SystemAdapter,
    credential_plan: dict[str, str] | None = None,
) -> int:
    """Validate an isolated candidate before transactionally replacing local data.

    Args:
        db: Active request database session to replace.
        database_url: Configured SQLite database URL.
        adapter: Dry-run adapter used by the non-appliance fallback.
        credential_plan: Validated keep-or-change password choices for admin and root.
    """
    source_path = _sqlite_database_path(database_url)
    descriptor, candidate_name = tempfile.mkstemp(
        prefix=".atlaso-factory-reset-candidate-",
        suffix=".db",
        dir=source_path.parent,
    )
    os.close(descriptor)
    candidate_path = Path(candidate_name)
    candidate_path.unlink(missing_ok=True)
    os_passwords = pending_os_password_snapshot()
    ldap_passwords = dict(LDAP_PENDING_PASSWORDS)
    ldap_recovery_payloads = dict(LDAP_PENDING_RECOVERY_PAYLOADS)
    clear_all_pending_os_passwords()
    LDAP_PENDING_PASSWORDS.clear()
    LDAP_PENDING_RECOVERY_PAYLOADS.clear()
    try:
        unit_count = _candidate_database(
            source_path,
            candidate_path,
            adapter=adapter,
            credential_plan=credential_plan,
            report_progress=False,
        )
        db.rollback()
        _replace_sqlite_database_contents(source_path, candidate_path)
        db.expire_all()
        return unit_count
    except Exception:
        db.rollback()
        restore_pending_os_password_snapshot(os_passwords)
        LDAP_PENDING_PASSWORDS.clear()
        LDAP_PENDING_PASSWORDS.update(ldap_passwords)
        LDAP_PENDING_RECOVERY_PAYLOADS.clear()
        LDAP_PENDING_RECOVERY_PAYLOADS.update(ldap_recovery_payloads)
        raise
    finally:
        candidate_path.unlink(missing_ok=True)
        for suffix in ("-wal", "-shm", "-journal"):
            Path(f"{candidate_path}{suffix}").unlink(missing_ok=True)


def _sqlite_table_inventory(
    connection: sqlite3.Connection,
    schema: str,
) -> dict[str, tuple[str, ...]]:
    """Return user-table columns from one attached SQLite schema.

    Args:
        connection: SQLite connection with the requested schema attached.
        schema: Fixed schema name, either ``main`` or ``candidate``.
    """
    if schema not in {"main", "candidate"}:
        raise FactoryResetError("Factory reset encountered an unsafe SQLite schema name.")
    rows = connection.execute(
        f"SELECT name FROM {schema}.sqlite_schema "
        "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    inventory: dict[str, tuple[str, ...]] = {}
    for row in rows:
        table_name = str(row[0])
        quoted_table = '"' + table_name.replace('"', '""') + '"'
        columns = tuple(
            str(column[1])
            for column in connection.execute(
                f"PRAGMA {schema}.table_xinfo({quoted_table})"
            ).fetchall()
            if int(column[6]) == 0
        )
        if not columns:
            raise FactoryResetError("Factory reset encountered a SQLite table without writable columns.")
        inventory[table_name] = columns
    return inventory


def _replace_sqlite_database_contents(source_path: Path, candidate_path: Path) -> None:
    """Copy factory data under one SQLite writer transaction.

    ``BEGIN IMMEDIATE`` waits for any earlier writer to finish, blocks later writers until the
    replacement commits, and makes a pre-reset transaction unable to commit after the factory
    contents. The candidate and installed schemas must expose the same writable table columns.

    Args:
        source_path: Installed SQLite database whose data must be replaced.
        candidate_path: Fully validated factory candidate database.
    """
    with closing(sqlite3.connect(source_path, timeout=30)) as destination_connection:
        destination_connection.execute("PRAGMA foreign_keys=OFF")
        destination_connection.execute(
            "ATTACH DATABASE ? AS candidate",
            (str(candidate_path),),
        )
        try:
            destination_connection.execute("BEGIN IMMEDIATE")
            installed = _sqlite_table_inventory(destination_connection, "main")
            candidate = _sqlite_table_inventory(destination_connection, "candidate")
            if installed != candidate:
                raise FactoryResetError(
                    "Factory reset cannot replace a development database with a different schema."
                )
            for table_name, columns in installed.items():
                quoted_table = '"' + table_name.replace('"', '""') + '"'
                quoted_columns = ", ".join(
                    '"' + column.replace('"', '""') + '"' for column in columns
                )
                destination_connection.execute(f"DELETE FROM main.{quoted_table}")
                destination_connection.execute(
                    f"INSERT INTO main.{quoted_table} ({quoted_columns}) "
                    f"SELECT {quoted_columns} FROM candidate.{quoted_table}"
                )
            installed_sequence = destination_connection.execute(
                "SELECT 1 FROM main.sqlite_schema WHERE type = 'table' AND name = 'sqlite_sequence'"
            ).fetchone()
            candidate_sequence = destination_connection.execute(
                "SELECT 1 FROM candidate.sqlite_schema WHERE type = 'table' AND name = 'sqlite_sequence'"
            ).fetchone()
            if bool(installed_sequence) != bool(candidate_sequence):
                raise FactoryResetError(
                    "Factory reset cannot replace a development database with a different sequence contract."
                )
            if installed_sequence:
                destination_connection.execute("DELETE FROM main.sqlite_sequence")
                destination_connection.execute(
                    "INSERT INTO main.sqlite_sequence (name, seq) "
                    "SELECT name, seq FROM candidate.sqlite_sequence"
                )
            foreign_key_failure = destination_connection.execute(
                "PRAGMA main.foreign_key_check"
            ).fetchone()
            if foreign_key_failure is not None:
                raise FactoryResetError(
                    "Factory reset candidate violates the installed SQLite foreign-key contract."
                )
            destination_connection.commit()
        except Exception:
            destination_connection.rollback()
            raise
        finally:
            destination_connection.execute("DETACH DATABASE candidate")


def _run_factory_reset_locked(
    *,
    database_url: str | None = None,
    adapter: SystemAdapter | None = None,
    manage_services: bool = True,
) -> dict[str, Any]:
    """Complete or resume the dedicated appliance factory-reset transaction.

    Args:
        database_url: Optional SQLite database URL override.
        adapter: Optional system adapter override.
        manage_services: Whether to quiesce and restart appliance services.
    """
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
        credential_plan = _factory_reset_credential_plan()
        if manage_services:
            _require_terminal_release_update()
            _stop_application_services(boot_resume=boot_resume)
        _update_request("building", "Building a clean factory database and validating packaged defaults.")
        unit_count = _candidate_database(
            source_path,
            candidate_path,
            adapter=adapter or SystemAdapter(dry_run=False),
            credential_plan=credential_plan,
        )
        _update_request("committing", "Replacing the Atlaso database with the validated factory database.")
        _replace_database(source_path, candidate_path)
        if not (adapter and adapter.dry_run):
            _clear_apply_staging()
            _scrub_retained_credentials()
        if not manage_services:
            return _mark_factory_reset_succeeded(request_payload, unit_count)
        awaiting_readiness = _update_request(
            "awaiting_readiness",
            "Factory defaults applied; waiting for required services and management OpenAPI readiness.",
            applied_unit_count=unit_count,
        )
        _remove_factory_reset_credentials()
        if manage_services:
            _schedule_readiness_finalizer()
        return awaiting_readiness
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
        failure_details: dict[str, Any] = {}
        try:
            current_request = json.loads(factory_reset_request_path().read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            current_request = {}
        if type(current_request.get("applied_unit_count")) is int:
            failure_details["applied_unit_count"] = current_request["applied_unit_count"]
        _update_request(
            "failed",
            safe_message + " Reboot or run the factory-reset resume helper from the console.",
            **failure_details,
        )
        raise


def run_factory_reset(
    *,
    database_url: str | None = None,
    adapter: SystemAdapter | None = None,
    manage_services: bool = True,
) -> dict[str, Any]:
    """Complete or resume one serialized appliance factory-reset transaction.

    Args:
        database_url: Optional SQLite database URL override.
        adapter: Optional system adapter override.
        manage_services: Whether to quiesce and restart appliance services.
    """
    with _factory_reset_transaction_lock(
        wait_seconds=FACTORY_RESET_RUNNER_LOCK_WAIT_SECONDS
    ):
        return _run_factory_reset_locked(
            database_url=database_url,
            adapter=adapter,
            manage_services=manage_services,
        )


def main(arguments: list[str] | None = None) -> int:
    """Run the appliance factory-reset entry point.

    Args:
        arguments: Optional command-line arguments for direct invocation or tests.
    """
    parsed_arguments = list(arguments if arguments is not None else sys.argv[1:])
    if os.name == "posix" and not _running_as_posix_root():
        raise SystemExit("atlaso-factory-reset must run as root")
    try:
        if parsed_arguments == ["finalize"]:
            result = finalize_factory_reset()
        elif not parsed_arguments:
            result = run_factory_reset()
        else:
            raise FactoryResetError("Unsupported factory-reset operation.")
    except Exception as exc:  # noqa: BLE001 - the durable marker carries the safe failure state.
        message = str(exc) if isinstance(exc, FactoryResetError) else "Factory reset failed unexpectedly."
        print(message, flush=True)
        return 1
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
