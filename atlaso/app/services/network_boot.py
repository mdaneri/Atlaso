from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import stat
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable

import pycdlib
from pycdlib import pycdlibexception
from sqlalchemy import delete, desc, func, select
from sqlalchemy.orm import Session

from atlaso.app.models import (
    EsxiPxeHost,
    NetworkBootDiscoveredHost,
    NetworkBootEnvironment,
    NetworkBootHostBootOverride,
    NetworkBootInventoryCommand,
    NetworkBootInventoryReport,
    NetworkBootInventorySession,
    NetworkBootMedia,
    Setting,
    utcnow,
)
from atlaso.app.services.esxi_pxe import esxi_http_base_url, normalize_pxe_mac
from atlaso.app.services.release_updates import verify_signed_json

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows development fallback
    fcntl = None


NETWORK_BOOT_SCHEMA_VERSION = 1
NETWORK_BOOT_REPORT_MAX_BYTES = 256 * 1024
NETWORK_BOOT_MAX_DISKS = 128
NETWORK_BOOT_MAX_INTERFACES = 64
NETWORK_BOOT_MAX_DIMMS = 256
NETWORK_BOOT_MAX_STORAGE_CONTROLLERS = 64
NETWORK_BOOT_MAX_PCI_DEVICES = 512
NETWORK_BOOT_MAX_USB_DEVICES = 256
NETWORK_BOOT_MAX_DEVICE_FLAGS = 32
NETWORK_BOOT_REPORTS_PER_HOST = 11
NETWORK_BOOT_MAX_HOSTS = 512
NETWORK_BOOT_MAX_REPORTS = 2048
NETWORK_BOOT_MAX_SESSIONS = 4096
NETWORK_BOOT_SESSION_LIFETIME = timedelta(hours=8)
NETWORK_BOOT_ONLINE_THRESHOLD = timedelta(seconds=30)
NETWORK_BOOT_OVERRIDE_LIFETIME = timedelta(minutes=30)
NETWORK_BOOT_OVERRIDE_CLAIM_GRACE = timedelta(minutes=5)
NETWORK_BOOT_MEDIA_ROOT = Path("/var/lib/atlaso/pxe/media")
NETWORK_BOOT_UPLOAD_ROOT = Path("/var/lib/atlaso/pxe/uploads")
NETWORK_BOOT_UPLOAD_MAX_BYTES = 2 * 1024 * 1024 * 1024
INVENTORY_LINUX_LATEST_MANIFEST_URL = (
    "https://mdaneri.github.io/Atlaso/updates/inventory-linux/latest/manifest.json"
)
INVENTORY_LINUX_LATEST_SIGNATURE_URL = f"{INVENTORY_LINUX_LATEST_MANIFEST_URL}.sig"
NETWORK_BOOT_SHREDOS_KERNEL_MAX_BYTES = 512 * 1024 * 1024
NETWORK_BOOT_HTTP_ROOT = Path("/var/lib/atlaso/pxe/http")
NETWORK_BOOT_STAGED_CONFIG_PATH = "/var/lib/atlaso/apply/esxi-pxe/atlaso-esxi-pxe.json"
NETWORK_BOOT_UNIT_ID = "esxi_pxe"
APPLIANCE_APPLY_BASELINES_KEY = "appliance_apply.baselines.v1"
_MEDIA_SWAP_THREAD_LOCK = threading.Lock()
_MEDIA_STAGING_THREAD_LOCK = threading.Lock()
_ACTIVE_MEDIA_STAGING_DIRECTORIES: set[str] = set()
_AVAILABLE_VERSION_CACHE_LOCK = threading.Lock()
_AVAILABLE_VERSION_CACHE: dict[str, dict[str, Any]] = {}
AVAILABLE_VERSION_CACHE_SECONDS = 15 * 60
AVAILABLE_VERSION_ERROR_CACHE_SECONDS = 60

UUID_PLACEHOLDERS = {
    "00000000-0000-0000-0000-000000000000",
    "ffffffff-ffff-ffff-ffff-ffffffffffff",
    "03000200-0400-0500-0006-000700080009",
}
MAC_PATTERN = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")
VERSION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,118}[A-Za-z0-9]$")
WAKE_ON_LAN_PORT = 9


@dataclass(frozen=True)
class EnvironmentCatalogEntry:
    key: str
    label: str
    description: str
    risk: str
    license_name: str
    verification_method: str
    source_label: str
    release_page: str
    signing_fingerprint: str = ""
    signing_key_url: str = ""


ENVIRONMENT_CATALOG: tuple[EnvironmentCatalogEntry, ...] = (
    EnvironmentCatalogEntry(
        key="inventory",
        label="Atlaso Inventory Linux",
        description="Read-only hardware inventory that runs from RAM.",
        risk="safe",
        license_name="GPL-2.0-or-later and bundled component licenses",
        verification_method="signed Atlaso Inventory Linux manifest and package SHA-256",
        source_label="Atlaso Inventory Linux releases",
        release_page="https://github.com/mdaneri/Atlaso/releases?q=inventory-linux-v&expanded=true",
    ),
    EnvironmentCatalogEntry(
        key="memtest86plus",
        label="Memtest86+",
        description="Interactive memory diagnostics.",
        risk="diagnostic",
        license_name="GPL-2.0-only",
        verification_method="upstream-published SHA-256",
        source_label="Memtest86+ official site",
        release_page="https://www.memtest.org/",
    ),
    EnvironmentCatalogEntry(
        key="shredos",
        label="ShredOS",
        description="Interactive disk erasure with an independent warning menu.",
        risk="destructive",
        license_name="GPL-3.0-or-later and bundled component licenses",
        verification_method="GitHub release-asset SHA-256 digest",
        source_label="ShredOS GitHub releases",
        release_page="https://github.com/PartialVolume/shredos.x86_64/releases/latest",
    ),
    EnvironmentCatalogEntry(
        key="gparted",
        label="GParted Live",
        description="Interactive partition management.",
        risk="destructive",
        license_name="GPL-2.0-or-later and bundled component licenses",
        verification_method="signed checksum file and SHA-256",
        source_label="GParted official downloads",
        release_page="https://gparted.org/download.php",
        signing_fingerprint="EB1DD5BF6F88820BBCF5356C8E94C9CD163E3FB0",
        signing_key_url="https://keys.openpgp.org/vks/v1/by-fingerprint/EB1DD5BF6F88820BBCF5356C8E94C9CD163E3FB0",
    ),
    EnvironmentCatalogEntry(
        key="clonezilla",
        label="Clonezilla Live",
        description="Interactive imaging and restoration.",
        risk="destructive",
        license_name="GPL-2.0-or-later and bundled component licenses",
        verification_method="signed checksum file and SHA-256",
        source_label="Clonezilla official downloads",
        release_page="https://clonezilla.org/downloads.php",
        signing_fingerprint="54C0821A48715DAFD61BFCAF667857D045599AFD",
        signing_key_url="https://keyserver.ubuntu.com/pks/lookup?op=get&options=mr&search=0x54C0821A48715DAFD61BFCAF667857D045599AFD",
    ),
)
CATALOG_BY_KEY = {entry.key: entry for entry in ENVIRONMENT_CATALOG}


class NetworkBootMediaSyncCancelled(RuntimeError):
    """Raised when an operator cancels media acquisition before installation."""


@dataclass(frozen=True)
class ActiveNetworkBootMedia:
    environment_key: str
    version: str
    public_version: str
    installed_path: str
    manifest_json: str
    artifact_sha256: str = ""


@dataclass
class DeferredNetworkBootMediaSync:
    media: NetworkBootMedia
    final_dir: Path
    backup_dir: Path | None
    superseded_dirs: tuple[Path, ...] = ()
    journal_path: Path | None = None
    filesystem_changed: bool = True
    recovery_lock: _MediaSwapRecoveryLock | None = None

    def commit_filesystem(self) -> None:
        try:
            if self.backup_dir is not None and self.backup_dir.exists():
                shutil.rmtree(self.backup_dir)
            for directory in self.superseded_dirs:
                if directory.exists():
                    shutil.rmtree(directory)
            _fsync_directory(self.final_dir.parent)
            if self.journal_path is not None:
                self.journal_path.unlink(missing_ok=True)
                _fsync_directory(self.final_dir.parent)
        finally:
            self._release_recovery_lock()

    def rollback_filesystem(self) -> None:
        try:
            if not self.filesystem_changed:
                return
            if self.final_dir.exists():
                shutil.rmtree(self.final_dir)
            if self.backup_dir is not None and self.backup_dir.exists():
                self.backup_dir.replace(self.final_dir)
            _fsync_directory(self.final_dir.parent)
            if self.journal_path is not None:
                self.journal_path.unlink(missing_ok=True)
                _fsync_directory(self.final_dir.parent)
        finally:
            self._release_recovery_lock()

    def _release_recovery_lock(self) -> None:
        if self.recovery_lock is not None:
            self.recovery_lock.release()
            self.recovery_lock = None


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def ensure_environment_rows(db: Session) -> list[NetworkBootEnvironment]:
    existing = {
        row.key: row
        for row in db.execute(select(NetworkBootEnvironment)).scalars().all()
    }
    for entry in ENVIRONMENT_CATALOG:
        if entry.key in existing:
            continue
        row = NetworkBootEnvironment(
            key=entry.key,
            enabled=False,
        )
        db.add(row)
        existing[entry.key] = row
    db.flush()
    return [existing[entry.key] for entry in ENVIRONMENT_CATALOG]


def catalog_rows(db: Session) -> list[dict[str, Any]]:
    states = {row.key: row for row in ensure_environment_rows(db)}
    media = db.execute(
        select(NetworkBootMedia).order_by(
            NetworkBootMedia.environment_key,
            desc(NetworkBootMedia.installed_at),
        )
    ).scalars().all()
    installed: dict[str, list[NetworkBootMedia]] = {}
    for row in media:
        installed.setdefault(row.environment_key, []).append(row)
    result: list[dict[str, Any]] = []
    for entry in ENVIRONMENT_CATALOG:
        state = states[entry.key]
        versions = installed.get(entry.key, [])
        active = next(
            (row for row in versions if row.version == state.active_version),
            None,
        )
        result.append(
            {
                "key": entry.key,
                "label": entry.label,
                "description": entry.description,
                "risk": entry.risk,
                "license": entry.license_name,
                "verification_method": entry.verification_method,
                "source_label": entry.source_label,
                "signing_fingerprint": entry.signing_fingerprint,
                "release_page": entry.release_page,
                "enabled": bool(state.enabled),
                "desired_version": state.desired_version,
                "active_version": state.active_version,
                "available_version": "",
                "available_status": "checking",
                "available_checked_at": "",
                "ready": bool(state.enabled and active),
                "media_ready": bool(versions),
                "installed_versions": [media_to_dict(row) for row in versions],
            }
        )
    return result


def desired_environment_manifest_rows(db: Session) -> list[dict[str, Any]]:
    states = ensure_environment_rows(db)
    rows: list[dict[str, Any]] = []
    for state in states:
        media = None
        if state.desired_version:
            media = db.execute(
                select(NetworkBootMedia).where(
                    NetworkBootMedia.environment_key == state.key,
                    NetworkBootMedia.version == state.desired_version,
                )
            ).scalar_one_or_none()
        rows.append(
            {
                "key": state.key,
                "enabled": bool(state.enabled),
                "desired_version": state.desired_version,
                "active_version": state.active_version,
                "installed_path": media.installed_path if media else "",
                "artifact_sha256": media.artifact_sha256 if media else "",
                "manifest": (
                    json.loads(media.manifest_json or "{}") if media else {}
                ),
            }
        )
    return rows


def mark_network_boot_environments_applied(db: Session) -> None:
    for state in ensure_environment_rows(db):
        state.active_version = state.desired_version if state.enabled else ""
        state.updated_at = utcnow()
        db.add(state)


def register_bundled_inventory_media(
    db: Session,
    *,
    media_root: Path = NETWORK_BOOT_MEDIA_ROOT,
) -> NetworkBootMedia | None:
    inventory_root = media_root / "inventory"
    if not inventory_root.is_dir():
        return None
    candidates = [
        path
        for path in inventory_root.iterdir()
        if path.is_dir() and (path / "manifest.json").is_file()
    ]
    existing_media = db.execute(
        select(NetworkBootMedia.id)
        .where(NetworkBootMedia.environment_key == "inventory")
        .limit(1)
    ).first()
    registered: list[NetworkBootMedia] = []
    for path in candidates:
        try:
            manifest = json.loads((path / "manifest.json").read_text(encoding="utf-8"))
            version = normalize_version(str(manifest.get("version") or path.name))
            if (
                manifest.get("kind") != "atlaso-inventory-linux"
                or manifest.get("schema_version") != 1
                or version != path.name
            ):
                continue
            artifacts = manifest.get("artifacts")
            if not isinstance(artifacts, dict):
                continue
            artifact_hashes: list[str] = []
            for filename in ("bzImage", "rootfs.cpio.gz"):
                expected = str(artifacts.get(filename) or "").lower()
                target = path / filename
                if not target.is_file() or not re.fullmatch(r"[0-9a-f]{64}", expected):
                    raise ValueError("Bundled inventory artifact manifest is incomplete.")
                actual = hashlib.sha256(target.read_bytes()).hexdigest()
                if not secrets.compare_digest(actual, expected):
                    raise ValueError(f"Bundled inventory artifact {filename} failed SHA-256 verification.")
                artifact_hashes.append(actual)
            aggregate = hashlib.sha256("".join(artifact_hashes).encode()).hexdigest()
            media = record_verified_media(
                db,
                environment_key="inventory",
                version=version,
                source_url=str((manifest.get("buildroot") or {}).get("source") or CATALOG_BY_KEY["inventory"].release_page),
                artifact_sha256=aggregate,
                installed_path=str(path.resolve()),
                manifest=manifest,
            )
            registered.append(media)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
    if not registered:
        return None
    latest = max(registered, key=lambda row: _natural_version_key(row.version))
    state = db.get(NetworkBootEnvironment, "inventory")
    if (
        state is not None
        and existing_media is None
        and not state.desired_version
        and not state.active_version
    ):
        state.enabled = True
        state.desired_version = latest.version
        state.updated_at = utcnow()
        db.add(state)
    return latest


def media_to_dict(row: NetworkBootMedia) -> dict[str, Any]:
    try:
        manifest = json.loads(row.manifest_json or "{}")
    except json.JSONDecodeError:
        manifest = {}
    return {
        "id": row.id,
        "environment": row.environment_key,
        "version": row.version,
        "source_url": row.source_url,
        "license": row.license_name,
        "sha256": row.artifact_sha256,
        "verification_method": row.verification_method,
        "installed_path": row.installed_path,
        "manifest": manifest,
        "verified_at": row.verified_at.isoformat() if row.verified_at else "",
        "installed_at": row.installed_at.isoformat() if row.installed_at else "",
    }


def normalize_environment_key(value: str) -> str:
    key = (value or "").strip().lower()
    if key not in CATALOG_BY_KEY:
        raise ValueError("Boot environment is not in the Atlaso allowlist.")
    return key


def normalize_version(value: str) -> str:
    version = (value or "").strip()
    if not VERSION_PATTERN.fullmatch(version):
        raise ValueError("Boot media version is invalid.")
    return version


def _natural_version_key(value: str) -> tuple[tuple[int, int | str], ...]:
    return tuple(
        (0, int(part)) if part.isdigit() else (1, part.casefold())
        for part in re.split(r"([0-9]+)", value)
        if part
    )


def set_environment_desired_state(
    db: Session,
    *,
    environment_key: str,
    enabled: bool,
    desired_version: str = "",
) -> NetworkBootEnvironment:
    key = normalize_environment_key(environment_key)
    state = next(row for row in ensure_environment_rows(db) if row.key == key)
    version = normalize_version(desired_version) if desired_version else ""
    if enabled and not version:
        installed = db.execute(
            select(NetworkBootMedia)
            .where(NetworkBootMedia.environment_key == key)
            .order_by(desc(NetworkBootMedia.installed_at))
        ).scalars().first()
        if installed is None:
            raise ValueError("Download and verify this environment before enabling it.")
        version = installed.version
    if version:
        installed = db.execute(
            select(NetworkBootMedia).where(
                NetworkBootMedia.environment_key == key,
                NetworkBootMedia.version == version,
            )
        ).scalar_one_or_none()
        if installed is None:
            raise ValueError("The selected boot media version is not installed and verified.")
    state.enabled = bool(enabled)
    state.desired_version = version
    state.updated_at = utcnow()
    db.add(state)
    db.flush()
    return state


def normalize_mac(value: Any, *, required: bool = False) -> str:
    raw = str(value or "").strip().lower().replace("-", ":")
    if not raw:
        if required:
            raise ValueError("A MAC address is required.")
        return ""
    if not MAC_PATTERN.fullmatch(raw):
        raise ValueError("MAC address must contain six hexadecimal octets.")
    compact = raw.replace(":", "")
    if compact in {"000000000000", "ffffffffffff"}:
        raise ValueError("MAC address must not be all-zero or broadcast.")
    return raw


def _normalize_optional_inventory_mac(value: Any) -> str:
    raw = str(value or "").strip().lower().replace("-", ":")
    if raw.replace(":", "") in {"000000000000", "ffffffffffff"}:
        return ""
    return normalize_mac(raw)


def normalize_dmi_uuid(value: Any) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    try:
        normalized = str(uuid.UUID(raw))
    except ValueError:
        return ""
    return "" if normalized in UUID_PLACEHOLDERS else normalized


def _bounded_string(value: Any, field: str, *, maximum: int = 512) -> str:
    normalized = str(value or "").strip()
    if len(normalized) > maximum:
        raise ValueError(f"{field} must be {maximum} characters or fewer.")
    return normalized


def _bounded_integer(
    value: Any,
    field: str,
    *,
    minimum: int = 0,
    maximum: int = 2**63 - 1,
) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be an integer.")
    if value in (None, ""):
        normalized = 0
    elif isinstance(value, int):
        normalized = value
    elif isinstance(value, str) and re.fullmatch(r"[+-]?\d+", value.strip()):
        normalized = int(value.strip())
    else:
        raise ValueError(f"{field} must be an integer.")
    if normalized < minimum or normalized > maximum:
        raise ValueError(f"{field} is outside the supported range.")
    return normalized


def _string_list(value: Any, field: str, *, maximum_items: int, maximum_length: int = 128) -> list[str]:
    if value in (None, ""):
        return []
    if not isinstance(value, list) or len(value) > maximum_items:
        raise ValueError(f"{field} must contain at most {maximum_items} values.")
    return [_bounded_string(item, field, maximum=maximum_length) for item in value]


def _bounded_bool(value: Any, field: str) -> bool:
    if isinstance(value, bool):
        return value
    if value in (0, 1):
        return bool(value)
    raise ValueError(f"{field} must be a boolean.")


def _object_list(value: Any, field: str, *, maximum_items: int) -> list[dict[str, Any]]:
    if value in (None, ""):
        return []
    if not isinstance(value, list) or len(value) > maximum_items:
        raise ValueError(f"{field} must contain at most {maximum_items} objects.")
    for index, row in enumerate(value):
        if not isinstance(row, dict):
            raise ValueError(f"{field}[{index}] must be an object.")
    return value


def _hardware_string(value: Any, field: str, *, maximum: int = 240) -> str:
    return _bounded_string(value, field, maximum=maximum)


def _pci_id(value: Any, field: str) -> str:
    normalized = _bounded_string(value, field, maximum=6).lower().removeprefix("0x")
    if normalized and not re.fullmatch(r"[0-9a-f]{4}", normalized):
        raise ValueError(f"{field} must contain four hexadecimal digits.")
    return normalized


def _pci_class_id(value: Any, field: str) -> str:
    normalized = _bounded_string(value, field, maximum=8).lower().removeprefix("0x")
    if normalized and not re.fullmatch(r"[0-9a-f]{6}", normalized):
        raise ValueError(f"{field} must contain six hexadecimal digits.")
    return normalized


def _usb_id(value: Any, field: str) -> str:
    return _pci_id(value, field)


def _human_size(value: Any, field: str) -> str:
    return _bounded_string(value, field, maximum=32)


def normalize_inventory_report(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("Inventory report must be a JSON object.")
    encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(encoded) > NETWORK_BOOT_REPORT_MAX_BYTES:
        raise ValueError("Inventory report exceeds the 256 KiB limit.")
    source_schema_version = _bounded_integer(
        payload.get("schema_version"), "schema_version", minimum=1, maximum=2
    )
    system = payload.get("system")
    cpu = payload.get("cpu")
    memory = payload.get("memory")
    if not isinstance(system, dict) or not isinstance(cpu, dict) or not isinstance(memory, dict):
        raise ValueError("Inventory report requires system, cpu, and memory objects.")
    baseboard = system.get("baseboard")
    chassis = system.get("chassis")
    if baseboard is None:
        baseboard = {}
    if chassis is None:
        chassis = {}
    if not isinstance(baseboard, dict) or not isinstance(chassis, dict):
        raise ValueError("system.baseboard and system.chassis must be objects.")
    disk_rows = payload.get("disks", [])
    interface_rows = payload.get("interfaces", [])
    if not isinstance(disk_rows, list) or len(disk_rows) > NETWORK_BOOT_MAX_DISKS:
        raise ValueError(f"Inventory report supports at most {NETWORK_BOOT_MAX_DISKS} disks.")
    if not isinstance(interface_rows, list) or len(interface_rows) > NETWORK_BOOT_MAX_INTERFACES:
        raise ValueError(
            f"Inventory report supports at most {NETWORK_BOOT_MAX_INTERFACES} interfaces."
        )
    disks = _object_list(disk_rows, "disks", maximum_items=NETWORK_BOOT_MAX_DISKS)
    interfaces = _object_list(
        interface_rows,
        "interfaces",
        maximum_items=NETWORK_BOOT_MAX_INTERFACES,
    )
    dimms = _object_list(memory.get("dimms", []), "memory.dimms", maximum_items=NETWORK_BOOT_MAX_DIMMS)
    storage_controllers = _object_list(
        payload.get("storage_controllers", []),
        "storage_controllers",
        maximum_items=NETWORK_BOOT_MAX_STORAGE_CONTROLLERS,
    )
    pci_devices = _object_list(
        payload.get("pci_devices", []),
        "pci_devices",
        maximum_items=NETWORK_BOOT_MAX_PCI_DEVICES,
    )
    usb_devices = _object_list(
        payload.get("usb_devices", []),
        "usb_devices",
        maximum_items=NETWORK_BOOT_MAX_USB_DEVICES,
    )

    normalized_interfaces: list[dict[str, Any]] = []
    for index, row in enumerate(interfaces):
        if not isinstance(row, dict):
            raise ValueError(f"interfaces[{index}] must be an object.")
        permanent_mac = _normalize_optional_inventory_mac(row.get("permanent_mac"))
        current_mac = _normalize_optional_inventory_mac(row.get("current_mac"))
        normalized_interfaces.append(
            {
                "name": _bounded_string(row.get("name"), f"interfaces[{index}].name", maximum=64),
                "permanent_mac": permanent_mac,
                "current_mac": current_mac,
                "driver": _bounded_string(row.get("driver"), f"interfaces[{index}].driver", maximum=120),
                "pci_address": _bounded_string(
                    row.get("pci_address"), f"interfaces[{index}].pci_address", maximum=32
                ),
                "vendor_id": _pci_id(row.get("vendor_id"), f"interfaces[{index}].vendor_id"),
                "device_id": _pci_id(row.get("device_id"), f"interfaces[{index}].device_id"),
                "vendor": _hardware_string(row.get("vendor"), f"interfaces[{index}].vendor"),
                "device": _hardware_string(row.get("device"), f"interfaces[{index}].device"),
                "link_state": _bounded_string(row.get("link_state"), f"interfaces[{index}].link_state", maximum=32),
                "speed_mbps": _bounded_integer(
                    row.get("speed_mbps"),
                    f"interfaces[{index}].speed_mbps",
                    maximum=10_000_000,
                ),
                "addresses": _string_list(
                    row.get("addresses"),
                    f"interfaces[{index}].addresses",
                    maximum_items=64,
                ),
                "boot_interface": _bounded_bool(
                    row.get("boot_interface", False), f"interfaces[{index}].boot_interface"
                ),
            }
        )

    boot_rows = [row for row in normalized_interfaces if row["boot_interface"]]
    if len(boot_rows) > 1:
        raise ValueError("Only one interface may be marked as the boot interface.")
    boot_mac = _normalize_optional_inventory_mac(payload.get("boot_mac"))
    if not boot_mac and boot_rows:
        boot_mac = boot_rows[0]["permanent_mac"] or boot_rows[0]["current_mac"]
    macs = sorted(
        {
            mac
            for row in normalized_interfaces
            for mac in (row["permanent_mac"], row["current_mac"])
            if mac
        }
        | ({boot_mac} if boot_mac else set())
    )
    dmi_uuid = normalize_dmi_uuid(system.get("dmi_uuid"))
    if not dmi_uuid and not macs:
        raise ValueError("Inventory report requires a valid DMI UUID or permanent/boot MAC.")

    normalized_disks: list[dict[str, Any]] = []
    for index, row in enumerate(disks):
        if not isinstance(row, dict):
            raise ValueError(f"disks[{index}] must be an object.")
        normalized_disks.append(
            {
                "device": _bounded_string(row.get("device"), f"disks[{index}].device", maximum=120),
                "model": _bounded_string(row.get("model"), f"disks[{index}].model", maximum=240),
                "serial": _bounded_string(row.get("serial"), f"disks[{index}].serial", maximum=240),
                "wwn": _bounded_string(row.get("wwn"), f"disks[{index}].wwn", maximum=240),
                "transport": _bounded_string(row.get("transport"), f"disks[{index}].transport", maximum=64),
                "size_bytes": _bounded_integer(row.get("size_bytes"), f"disks[{index}].size_bytes"),
                "size_human": _human_size(row.get("size_human"), f"disks[{index}].size_human"),
                "type": _bounded_string(row.get("type"), f"disks[{index}].type", maximum=32),
                "flags": _string_list(
                    row.get("flags"),
                    f"disks[{index}].flags",
                    maximum_items=NETWORK_BOOT_MAX_DEVICE_FLAGS,
                    maximum_length=32,
                ),
                "controller_pci_address": _bounded_string(
                    row.get("controller_pci_address"),
                    f"disks[{index}].controller_pci_address",
                    maximum=32,
                ),
                "rotational": _bounded_bool(
                    row.get("rotational", False), f"disks[{index}].rotational"
                ),
                "removable": _bounded_bool(
                    row.get("removable", False), f"disks[{index}].removable"
                ),
                "read_only": _bounded_bool(
                    row.get("read_only", False), f"disks[{index}].read_only"
                ),
            }
        )

    normalized_dimms = [
        {
            "locator": _hardware_string(row.get("locator"), f"memory.dimms[{index}].locator"),
            "bank": _hardware_string(row.get("bank"), f"memory.dimms[{index}].bank"),
            "size_bytes": _bounded_integer(
                row.get("size_bytes"), f"memory.dimms[{index}].size_bytes"
            ),
            "size_human": _human_size(
                row.get("size_human"), f"memory.dimms[{index}].size_human"
            ),
            "type": _hardware_string(row.get("type"), f"memory.dimms[{index}].type"),
            "speed_mts": _bounded_integer(
                row.get("speed_mts"), f"memory.dimms[{index}].speed_mts", maximum=1_000_000
            ),
            "manufacturer": _hardware_string(
                row.get("manufacturer"), f"memory.dimms[{index}].manufacturer"
            ),
            "part_number": _hardware_string(
                row.get("part_number"), f"memory.dimms[{index}].part_number"
            ),
            "serial": _hardware_string(row.get("serial"), f"memory.dimms[{index}].serial"),
        }
        for index, row in enumerate(dimms)
    ]

    normalized_controllers = [
        {
            "pci_address": _bounded_string(
                row.get("pci_address"), f"storage_controllers[{index}].pci_address", maximum=32
            ),
            "type": _hardware_string(row.get("type"), f"storage_controllers[{index}].type"),
            "vendor_id": _pci_id(row.get("vendor_id"), f"storage_controllers[{index}].vendor_id"),
            "device_id": _pci_id(row.get("device_id"), f"storage_controllers[{index}].device_id"),
            "vendor": _hardware_string(row.get("vendor"), f"storage_controllers[{index}].vendor"),
            "device": _hardware_string(row.get("device"), f"storage_controllers[{index}].device"),
            "driver": _hardware_string(row.get("driver"), f"storage_controllers[{index}].driver", maximum=120),
        }
        for index, row in enumerate(storage_controllers)
    ]

    normalized_pci = [
        {
            "pci_address": _bounded_string(
                row.get("pci_address"), f"pci_devices[{index}].pci_address", maximum=32
            ),
            "class_id": _pci_class_id(row.get("class_id"), f"pci_devices[{index}].class_id"),
            "class": _hardware_string(row.get("class"), f"pci_devices[{index}].class"),
            "vendor_id": _pci_id(row.get("vendor_id"), f"pci_devices[{index}].vendor_id"),
            "device_id": _pci_id(row.get("device_id"), f"pci_devices[{index}].device_id"),
            "vendor": _hardware_string(row.get("vendor"), f"pci_devices[{index}].vendor"),
            "device": _hardware_string(row.get("device"), f"pci_devices[{index}].device"),
            "subsystem_vendor_id": _pci_id(
                row.get("subsystem_vendor_id"), f"pci_devices[{index}].subsystem_vendor_id"
            ),
            "subsystem_device_id": _pci_id(
                row.get("subsystem_device_id"), f"pci_devices[{index}].subsystem_device_id"
            ),
            "driver": _hardware_string(row.get("driver"), f"pci_devices[{index}].driver", maximum=120),
        }
        for index, row in enumerate(pci_devices)
    ]

    normalized_usb = [
        {
            "bus": _bounded_integer(row.get("bus"), f"usb_devices[{index}].bus", maximum=65535),
            "device_number": _bounded_integer(
                row.get("device_number"), f"usb_devices[{index}].device_number", maximum=65535
            ),
            "port": _bounded_string(row.get("port"), f"usb_devices[{index}].port", maximum=64),
            "vendor_id": _usb_id(row.get("vendor_id"), f"usb_devices[{index}].vendor_id"),
            "product_id": _usb_id(row.get("product_id"), f"usb_devices[{index}].product_id"),
            "manufacturer": _hardware_string(
                row.get("manufacturer"), f"usb_devices[{index}].manufacturer"
            ),
            "product": _hardware_string(row.get("product"), f"usb_devices[{index}].product"),
            "serial": _hardware_string(row.get("serial"), f"usb_devices[{index}].serial"),
            "class": _hardware_string(row.get("class"), f"usb_devices[{index}].class"),
            "driver": _hardware_string(row.get("driver"), f"usb_devices[{index}].driver", maximum=120),
        }
        for index, row in enumerate(usb_devices)
    ]

    normalized = {
        "schema_version": 2,
        "source_schema_version": source_schema_version,
        "boot_interface": _bounded_string(payload.get("boot_interface"), "boot_interface", maximum=64),
        "boot_mac": boot_mac,
        "assigned_addresses": _string_list(
            payload.get("assigned_addresses"),
            "assigned_addresses",
            maximum_items=64,
        ),
        "firmware_mode": _bounded_string(payload.get("firmware_mode"), "firmware_mode", maximum=32),
        "system": {
            "dmi_uuid": dmi_uuid,
            "manufacturer": _bounded_string(system.get("manufacturer"), "system.manufacturer", maximum=240),
            "product_name": _bounded_string(system.get("product_name"), "system.product_name", maximum=240),
            "serial_number": _bounded_string(system.get("serial_number"), "system.serial_number", maximum=240),
            "product_version": _hardware_string(system.get("product_version"), "system.product_version"),
            "product_sku": _hardware_string(system.get("product_sku"), "system.product_sku"),
            "product_family": _hardware_string(system.get("product_family"), "system.product_family"),
            "bios_vendor": _bounded_string(system.get("bios_vendor"), "system.bios_vendor", maximum=240),
            "bios_version": _bounded_string(system.get("bios_version"), "system.bios_version", maximum=240),
            "bios_date": _bounded_string(system.get("bios_date"), "system.bios_date", maximum=64),
            "bios_release": _hardware_string(system.get("bios_release"), "system.bios_release", maximum=64),
            "baseboard": {
                "manufacturer": _hardware_string(
                    baseboard.get("manufacturer"),
                    "system.baseboard.manufacturer",
                ),
                "product": _hardware_string(
                    baseboard.get("product"), "system.baseboard.product"
                ),
                "version": _hardware_string(
                    baseboard.get("version"), "system.baseboard.version"
                ),
                "serial": _hardware_string(
                    baseboard.get("serial"), "system.baseboard.serial"
                ),
                "asset_tag": _hardware_string(
                    baseboard.get("asset_tag"), "system.baseboard.asset_tag"
                ),
            },
            "chassis": {
                "manufacturer": _hardware_string(
                    chassis.get("manufacturer"),
                    "system.chassis.manufacturer",
                ),
                "type": _hardware_string(
                    chassis.get("type"), "system.chassis.type"
                ),
                "version": _hardware_string(
                    chassis.get("version"), "system.chassis.version"
                ),
                "serial": _hardware_string(
                    chassis.get("serial"), "system.chassis.serial"
                ),
                "asset_tag": _hardware_string(
                    chassis.get("asset_tag"), "system.chassis.asset_tag"
                ),
            },
        },
        "cpu": {
            "architecture": _bounded_string(cpu.get("architecture"), "cpu.architecture", maximum=64),
            "vendor": _bounded_string(cpu.get("vendor"), "cpu.vendor", maximum=120),
            "model": _bounded_string(cpu.get("model"), "cpu.model", maximum=500),
            "sockets": _bounded_integer(cpu.get("sockets"), "cpu.sockets", maximum=4096),
            "cores": _bounded_integer(cpu.get("cores"), "cpu.cores", maximum=65536),
            "threads": _bounded_integer(cpu.get("threads"), "cpu.threads", maximum=131072),
            "cores_per_socket": _bounded_integer(
                cpu.get("cores_per_socket"), "cpu.cores_per_socket", maximum=65536
            ),
            "threads_per_core": _bounded_integer(
                cpu.get("threads_per_core"), "cpu.threads_per_core", maximum=4096
            ),
        },
        "memory": {
            "total_bytes": _bounded_integer(memory.get("total_bytes"), "memory.total_bytes"),
            "total_human": _human_size(memory.get("total_human"), "memory.total_human"),
            "dimms": normalized_dimms,
        },
        "disks": normalized_disks,
        "interfaces": normalized_interfaces,
        "storage_controllers": normalized_controllers,
        "pci_devices": normalized_pci,
        "usb_devices": normalized_usb,
    }
    normalized_encoded = json.dumps(
        normalized, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    if len(normalized_encoded) > NETWORK_BOOT_REPORT_MAX_BYTES:
        raise ValueError("Normalized inventory report exceeds the 256 KiB limit.")
    return normalized


def report_identity(report: dict[str, Any]) -> tuple[str, str, list[str]]:
    dmi_uuid = str(report["system"].get("dmi_uuid") or "")
    boot_mac = str(report.get("boot_mac") or "")
    macs = sorted(
        {
            boot_mac,
            *[
                str(row.get("permanent_mac") or row.get("current_mac") or "")
                for row in report.get("interfaces", [])
            ],
        }
        - {""}
    )
    if dmi_uuid:
        return f"uuid:{dmi_uuid}:{hashlib.sha256('|'.join(macs).encode()).hexdigest()[:16]}", dmi_uuid, macs
    primary_mac = boot_mac or (macs[0] if macs else "")
    return f"mac:{primary_mac}", "", macs


def _macs(row: NetworkBootDiscoveredHost) -> set[str]:
    try:
        values = json.loads(row.macs_json or "[]")
    except json.JSONDecodeError:
        values = []
    return {str(value) for value in values if value}


def _prune_inventory_storage(
    db: Session,
    *,
    preserve_host_id: int,
) -> None:
    now = utcnow()
    heartbeat_cutoff = now - NETWORK_BOOT_ONLINE_THRESHOLD
    protected_host_ids = {
        int(host_id)
        for host_id in db.execute(
            select(NetworkBootInventorySession.host_id).where(
                NetworkBootInventorySession.host_id.is_not(None),
                NetworkBootInventorySession.revoked_at.is_(None),
                NetworkBootInventorySession.expires_at > now.replace(tzinfo=None),
                NetworkBootInventorySession.heartbeat_at.is_not(None),
                NetworkBootInventorySession.heartbeat_at
                >= heartbeat_cutoff.replace(tzinfo=None),
            )
        ).scalars()
        if host_id is not None
    }
    protected_host_ids.update(
        int(host_id)
        for host_id in db.execute(
            select(NetworkBootInventoryCommand.host_id).where(
                NetworkBootInventoryCommand.status.in_(("queued", "delivered")),
                NetworkBootInventoryCommand.expires_at > now.replace(tzinfo=None),
            )
        ).scalars()
    )
    protected_host_ids.add(preserve_host_id)
    host_rows = db.execute(
        select(
            NetworkBootDiscoveredHost.id,
            func.count(NetworkBootInventoryReport.id),
        )
        .outerjoin(
            NetworkBootInventoryReport,
            NetworkBootInventoryReport.host_id == NetworkBootDiscoveredHost.id,
        )
        .group_by(NetworkBootDiscoveredHost.id)
        .order_by(
            desc(NetworkBootDiscoveredHost.last_seen_at),
            desc(NetworkBootDiscoveredHost.id),
        )
    ).all()
    report_counts = {
        int(host_id): int(report_count or 0)
        for host_id, report_count in host_rows
    }
    retained_hosts = [
        int(host_id) for host_id, _report_count in host_rows
        if int(host_id) in protected_host_ids
    ]
    retained_reports = sum(report_counts[host_id] for host_id in retained_hosts)
    if (
        len(retained_hosts) > NETWORK_BOOT_MAX_HOSTS
        or retained_reports > NETWORK_BOOT_MAX_REPORTS
    ):
        raise ValueError(
            "Inventory storage capacity is occupied by live clients; retry later."
        )
    for host_id, report_count in host_rows:
        host_id = int(host_id)
        if host_id in protected_host_ids:
            continue
        count = int(report_count or 0)
        if (
            len(retained_hosts) < NETWORK_BOOT_MAX_HOSTS
            and retained_reports + count <= NETWORK_BOOT_MAX_REPORTS
        ):
            retained_hosts.append(host_id)
            retained_reports += count
    pruned_hosts = [host_id for host_id, _count in host_rows if host_id not in retained_hosts]
    if not pruned_hosts:
        return
    db.execute(
        delete(NetworkBootInventoryCommand).where(
            NetworkBootInventoryCommand.host_id.in_(pruned_hosts)
        )
    )
    db.execute(
        delete(NetworkBootInventorySession).where(
            NetworkBootInventorySession.host_id.in_(pruned_hosts)
        )
    )
    db.execute(
        delete(NetworkBootInventoryReport).where(
            NetworkBootInventoryReport.host_id.in_(pruned_hosts)
        )
    )
    db.execute(
        delete(NetworkBootDiscoveredHost).where(
            NetworkBootDiscoveredHost.id.in_(pruned_hosts)
        )
    )


def store_inventory_report(
    db: Session,
    *,
    session: NetworkBootInventorySession,
    payload: Any,
) -> tuple[NetworkBootDiscoveredHost, NetworkBootInventoryReport]:
    if session.report_submitted_at is not None:
        raise ValueError("This inventory session has already submitted its report.")
    report = normalize_inventory_report(payload)
    identity_key, dmi_uuid, macs = report_identity(report)
    candidates: list[NetworkBootDiscoveredHost] = []
    if dmi_uuid:
        candidates = db.execute(
            select(NetworkBootDiscoveredHost).where(NetworkBootDiscoveredHost.dmi_uuid == dmi_uuid)
        ).scalars().all()
    else:
        candidates = db.execute(
            select(NetworkBootDiscoveredHost).where(NetworkBootDiscoveredHost.identity_key == identity_key)
        ).scalars().all()
    if dmi_uuid and not macs and len(candidates) > 1:
        raise ValueError(
            "Inventory report DMI UUID matches multiple hosts; a valid MAC is required."
        )
    intersecting = next((row for row in candidates if not macs or _macs(row).intersection(macs)), None)
    collision = bool(dmi_uuid and candidates and intersecting is None)
    host = intersecting
    if host is None:
        host = NetworkBootDiscoveredHost(
            identity_key=identity_key,
            dmi_uuid=dmi_uuid,
            collision=collision,
        )
        db.add(host)
        db.flush()
    if collision:
        for row in candidates:
            row.collision = True
            db.add(row)
    if session.bound_identity_key and session.bound_identity_key != host.identity_key:
        raise ValueError("Inventory session identity does not match the submitted host.")
    now = utcnow()
    if macs or not candidates:
        host.boot_mac = str(report.get("boot_mac") or "")
        host.macs_json = json.dumps(macs)
    host.manufacturer = report["system"]["manufacturer"]
    host.product_name = report["system"]["product_name"]
    host.serial_number = report["system"]["serial_number"]
    host.cpu_model = report["cpu"]["model"]
    host.total_memory_bytes = report["memory"]["total_bytes"]
    host.disk_count = len(report["disks"])
    host.interface_count = len(report["interfaces"])
    host.last_seen_at = now
    db.add(host)
    db.flush()
    stored = NetworkBootInventoryReport(
        host_id=host.id,
        session_id=session.id,
        schema_version=report["schema_version"],
        payload_json=json.dumps(report, separators=(",", ":"), sort_keys=True),
        received_at=now,
    )
    db.add(stored)
    db.flush()
    host.latest_report_id = stored.id
    session.bound_identity_key = host.identity_key
    session.host_id = host.id
    session.report_submitted_at = now
    session.heartbeat_at = now
    db.add_all([host, session])
    retained_ids = db.execute(
        select(NetworkBootInventoryReport.id)
        .where(NetworkBootInventoryReport.host_id == host.id)
        .order_by(desc(NetworkBootInventoryReport.received_at), desc(NetworkBootInventoryReport.id))
        .limit(NETWORK_BOOT_REPORTS_PER_HOST)
    ).scalars().all()
    if retained_ids:
        db.execute(
            delete(NetworkBootInventoryReport).where(
                NetworkBootInventoryReport.host_id == host.id,
                NetworkBootInventoryReport.id.not_in(retained_ids),
            )
        )
    _prune_inventory_storage(db, preserve_host_id=host.id)
    db.flush()
    return host, stored


def issue_inventory_session(db: Session) -> tuple[NetworkBootInventorySession, str]:
    token = secrets.token_urlsafe(32)
    now = utcnow()
    db.execute(
        delete(NetworkBootInventorySession).where(
            NetworkBootInventorySession.expires_at <= now
        )
    )
    sessions = db.execute(
        select(NetworkBootInventorySession).order_by(
            NetworkBootInventorySession.created_at,
            NetworkBootInventorySession.id,
        )
    ).scalars().all()
    protected_command_sessions = set(
        db.execute(
            select(NetworkBootInventoryCommand.session_id).where(
                NetworkBootInventoryCommand.status.in_(("queued", "delivered")),
                NetworkBootInventoryCommand.expires_at > now.replace(tzinfo=None),
            )
        ).scalars()
    )
    heartbeat_cutoff = now - NETWORK_BOOT_ONLINE_THRESHOLD
    evictable = [
        session
        for session in sessions
        if not (
            session.revoked_at is None
            and (
                (
                    session.heartbeat_at is not None
                    and _as_utc(session.heartbeat_at) >= heartbeat_cutoff
                )
                or session.id in protected_command_sessions
            )
        )
    ]
    required = max(0, len(sessions) - (NETWORK_BOOT_MAX_SESSIONS - 1))
    if len(evictable) < required:
        raise ValueError(
            "Inventory session capacity is occupied by live clients; retry later."
        )
    evicted_ids = [session.id for session in evictable[:required]]
    if evicted_ids:
        db.execute(
            delete(NetworkBootInventorySession).where(
                NetworkBootInventorySession.id.in_(evicted_ids)
            )
        )
    session = NetworkBootInventorySession(
        id=f"nbs_{uuid.uuid4().hex}",
        token_hash=hashlib.sha256(token.encode()).hexdigest(),
        created_at=now,
        expires_at=now + NETWORK_BOOT_SESSION_LIFETIME,
    )
    db.add(session)
    db.flush()
    return session, token


def inventory_session_for_token(
    db: Session,
    token: str,
    *,
    require_report: bool = False,
) -> NetworkBootInventorySession:
    token_hash = hashlib.sha256((token or "").encode()).hexdigest()
    session = db.execute(
        select(NetworkBootInventorySession).where(
            NetworkBootInventorySession.token_hash == token_hash
        )
    ).scalar_one_or_none()
    now = utcnow()
    if session is None or session.revoked_at is not None or _as_utc(session.expires_at) <= now:
        raise ValueError("Inventory session is invalid or expired.")
    if require_report and (session.report_submitted_at is None or session.host_id is None):
        raise ValueError("Inventory report must be submitted before this operation.")
    return session


def touch_inventory_heartbeat(
    session: NetworkBootInventorySession,
    *,
    identity_key: str = "",
) -> None:
    if identity_key and session.bound_identity_key != identity_key:
        raise ValueError("Inventory heartbeat identity does not match this session.")
    session.heartbeat_at = utcnow()


def host_is_online(host: NetworkBootDiscoveredHost, session: NetworkBootInventorySession | None) -> bool:
    return bool(
        session
        and session.revoked_at is None
        and _as_utc(session.expires_at) > utcnow()
        and session.heartbeat_at
        and utcnow() - _as_utc(session.heartbeat_at) <= NETWORK_BOOT_ONLINE_THRESHOLD
        and session.host_id == host.id
    )


def latest_live_session(
    db: Session,
    host_id: int,
) -> NetworkBootInventorySession | None:
    candidates = db.execute(
        select(NetworkBootInventorySession)
        .where(
            NetworkBootInventorySession.host_id == host_id,
            NetworkBootInventorySession.revoked_at.is_(None),
        )
        .order_by(desc(NetworkBootInventorySession.heartbeat_at))
    ).scalars().all()
    host = db.get(NetworkBootDiscoveredHost, host_id)
    if host is None:
        return None
    return next((row for row in candidates if host_is_online(host, row)), None)


def queue_reboot_command(
    db: Session,
    *,
    host: NetworkBootDiscoveredHost,
    requested_by: str,
) -> NetworkBootInventoryCommand:
    session = latest_live_session(db, host.id)
    if session is None:
        raise ValueError("Host does not have a live inventory session.")
    existing = db.execute(
        select(NetworkBootInventoryCommand).where(
            NetworkBootInventoryCommand.session_id == session.id,
            NetworkBootInventoryCommand.action == "reboot",
            NetworkBootInventoryCommand.status.in_(("queued", "delivered")),
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing
    command = NetworkBootInventoryCommand(
        id=f"nbc_{uuid.uuid4().hex}",
        session_id=session.id,
        host_id=host.id,
        action="reboot",
        status="queued",
        requested_by=requested_by,
        expires_at=session.expires_at,
    )
    db.add(command)
    db.flush()
    return command


def poll_inventory_command(
    db: Session,
    *,
    session: NetworkBootInventorySession,
) -> NetworkBootInventoryCommand | None:
    now = utcnow()
    command = db.execute(
        select(NetworkBootInventoryCommand)
        .where(
            NetworkBootInventoryCommand.session_id == session.id,
            NetworkBootInventoryCommand.status.in_(("queued", "delivered")),
            NetworkBootInventoryCommand.expires_at > now.replace(tzinfo=None),
        )
        .order_by(NetworkBootInventoryCommand.created_at)
    ).scalars().first()
    if command is not None and command.status == "queued":
        command.status = "delivered"
        command.delivered_at = now
        db.add(command)
    session.heartbeat_at = now
    db.add(session)
    db.flush()
    return command


def acknowledge_inventory_command(
    db: Session,
    *,
    session: NetworkBootInventorySession,
    command_id: str,
) -> NetworkBootInventoryCommand:
    command = db.get(NetworkBootInventoryCommand, command_id)
    if (
        command is None
        or command.session_id != session.id
        or command.status not in {"delivered", "acknowledged"}
        or _as_utc(command.expires_at) <= utcnow()
    ):
        raise ValueError("Inventory command is missing, expired, or was not delivered.")
    if command.status == "delivered":
        command.status = "acknowledged"
        command.acknowledged_at = utcnow()
        db.add(command)
        db.flush()
    return command


def host_to_dict(
    db: Session,
    host: NetworkBootDiscoveredHost,
    *,
    include_report: bool = False,
    assignments_by_mac: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    session = latest_live_session(db, host.id)
    if assignments_by_mac is None:
        assignments_by_mac = esxi_host_assignments_by_mac(db)
    assignments: list[dict[str, Any]] = []
    assigned_ids: set[int] = set()
    for mac_address in sorted({*_macs(host), host.boot_mac} - {""}):
        try:
            normalized_mac = normalize_mac(mac_address)
        except ValueError:
            continue
        assignment = assignments_by_mac.get(normalized_mac)
        if assignment is not None and assignment["id"] not in assigned_ids:
            assignments.append(assignment)
            assigned_ids.add(assignment["id"])
    assignment = assignments[0] if assignments else None
    payload: dict[str, Any] = {
        "id": host.id,
        "identity_key": host.identity_key,
        "dmi_uuid": host.dmi_uuid,
        "boot_mac": host.boot_mac,
        "macs": sorted(_macs(host)),
        "manufacturer": host.manufacturer,
        "product_name": host.product_name,
        "serial_number": host.serial_number,
        "cpu_model": host.cpu_model,
        "total_memory_bytes": host.total_memory_bytes,
        "disk_count": host.disk_count,
        "interface_count": host.interface_count,
        "collision": bool(host.collision),
        "first_seen_at": host.first_seen_at.isoformat() if host.first_seen_at else "",
        "last_seen_at": host.last_seen_at.isoformat() if host.last_seen_at else "",
        "session_state": "online" if session else "offline",
        "assigned_to_esxi": bool(assignment),
        "esxi_host_id": assignment["id"] if assignment else None,
        "esxi_hostname": assignment["hostname"] if assignment else "",
        "esxi_ip_address": assignment["ip_address"] if assignment else "",
        "esxi_assignments": assignments,
    }
    if include_report and host.latest_report_id:
        report = db.get(NetworkBootInventoryReport, host.latest_report_id)
        payload["latest_report"] = (
            json.loads(report.payload_json) if report is not None else None
        )
    return payload


def esxi_host_assignments_by_mac(db: Session) -> dict[str, dict[str, Any]]:
    assignments: dict[str, dict[str, Any]] = {}
    rows = db.execute(select(EsxiPxeHost).order_by(EsxiPxeHost.hostname, EsxiPxeHost.id)).scalars().all()
    for host in rows:
        try:
            mac_address = normalize_mac(host.mac_address)
        except ValueError:
            continue
        assignments[mac_address] = {
            "id": host.id,
            "hostname": host.hostname,
            "ip_address": host.ip_address or "",
            "mac_address": mac_address,
            "enabled": bool(host.enabled),
        }
    return assignments


def report_history(
    db: Session,
    host_id: int,
) -> list[dict[str, Any]]:
    rows = db.execute(
        select(NetworkBootInventoryReport)
        .where(NetworkBootInventoryReport.host_id == host_id)
        .order_by(desc(NetworkBootInventoryReport.received_at))
        .limit(NETWORK_BOOT_REPORTS_PER_HOST)
    ).scalars().all()
    return [
        {
            "id": row.id,
            "schema_version": row.schema_version,
            "received_at": row.received_at.isoformat(),
            "report": json.loads(row.payload_json),
        }
        for row in rows
    ]


def wake_on_lan_packet(mac_address: str) -> bytes:
    """Return the standard magic packet for one server-owned MAC address."""
    try:
        normalized = normalize_mac(mac_address, required=True)
    except ValueError as exc:
        raise ValueError("Wake-on-LAN requires a valid host MAC address.") from exc
    hardware_address = bytes.fromhex(normalized.replace(":", ""))
    return (b"\xff" * 6) + (hardware_address * 16)


class WakeOnLanDeliveryError(OSError):
    """Record broadcasts sent before a later UDP delivery failed."""

    def __init__(self, failed_target: str, sent_targets: list[str], cause: OSError):
        super().__init__(str(cause))
        self.failed_target = failed_target
        self.sent_targets = list(sent_targets)


def wake_on_lan_broadcast_targets(db: Session) -> list[str]:
    """Return distinct IPv4 broadcasts for the applied Network Boot zones."""
    targets: set[str] = set()
    boot, _artifacts = _applied_esxi_pxe_runtime(db)
    for scope in boot.get("dhcp_scopes") or []:
        if not isinstance(scope, dict) or scope.get("address_family") != "ipv4":
            continue
        address = str(scope.get("site_address") or "").strip()
        prefix = scope.get("prefix_length")
        try:
            network = ip_network(f"{address}/{prefix}", strict=False)
        except ValueError:
            continue
        if network.version == 4:
            targets.add(str(network.broadcast_address))
    return sorted(targets, key=lambda value: int(ip_address(value)))


def send_wake_on_lan(
    mac_address: str,
    broadcast_targets: Iterable[str],
    *,
    socket_factory: Callable[..., Any] = socket.socket,
) -> list[str]:
    """Send one magic packet to each distinct validated IPv4 broadcast."""
    packet = wake_on_lan_packet(mac_address)
    normalized_targets: set[str] = set()
    for target in broadcast_targets:
        try:
            address = ip_address(str(target).strip())
        except ValueError as exc:
            raise ValueError("Wake-on-LAN broadcast target is invalid.") from exc
        if address.version != 4:
            raise ValueError("Wake-on-LAN requires an IPv4 broadcast target.")
        normalized_targets.add(str(address))
    if not normalized_targets:
        raise ValueError(
            "Configure an IPv4 Network Boot DHCP zone before waking hosts."
        )
    ordered_targets = sorted(normalized_targets, key=lambda value: int(ip_address(value)))
    sent_targets: list[str] = []
    with socket_factory(socket.AF_INET, socket.SOCK_DGRAM) as transport:
        transport.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for target in ordered_targets:
            try:
                transport.sendto(packet, (target, WAKE_ON_LAN_PORT))
            except OSError as exc:
                if not sent_targets:
                    raise
                raise WakeOnLanDeliveryError(target, sent_targets, exc) from exc
            sent_targets.append(target)
    return sent_targets


def _applied_esxi_pxe_manifest(db: Session) -> dict[str, Any]:
    setting = db.execute(
        select(Setting).where(Setting.key == APPLIANCE_APPLY_BASELINES_KEY)
    ).scalar_one_or_none()
    if setting is None:
        return {}
    try:
        baselines = json.loads(setting.value or "{}")
        baseline = baselines.get(NETWORK_BOOT_UNIT_ID)
        runtime_preview = (baseline or {}).get(
            "runtime_config_preview",
            (baseline or {}).get("config_preview"),
        )
        manifest = json.loads(str(runtime_preview or "{}"))
    except (AttributeError, TypeError, ValueError, json.JSONDecodeError):
        return {}
    if (
        not isinstance(manifest, dict)
        or manifest.get("kind") != "atlaso-esxi-pxe"
    ):
        return {}
    return manifest


def _has_explicit_esxi_pxe_runtime_preview(db: Session) -> bool:
    setting = db.execute(
        select(Setting).where(Setting.key == APPLIANCE_APPLY_BASELINES_KEY)
    ).scalar_one_or_none()
    if setting is None:
        return False
    try:
        baseline = json.loads(setting.value or "{}").get(NETWORK_BOOT_UNIT_ID)
    except (AttributeError, TypeError, json.JSONDecodeError):
        return False
    return isinstance(baseline, dict) and "runtime_config_preview" in baseline


def _applied_network_boot_media(
    db: Session,
    *,
    environment_key: str,
    version: str,
) -> ActiveNetworkBootMedia | None:
    manifest = _applied_esxi_pxe_manifest(db)
    network_boot = manifest.get("network_boot")
    environments = (
        network_boot.get("environments")
        if isinstance(network_boot, dict)
        else None
    )
    if not isinstance(environments, list):
        return None
    for row in environments[: len(ENVIRONMENT_CATALOG)]:
        if (
            not isinstance(row, dict)
            or row.get("key") != environment_key
            or not row.get("enabled")
            or row.get("desired_version") != version
            or not isinstance(row.get("installed_path"), str)
            or not isinstance(row.get("manifest"), dict)
        ):
            continue
        return ActiveNetworkBootMedia(
            environment_key=environment_key,
            version=version,
            public_version=Path(row["installed_path"]).name,
            installed_path=row["installed_path"],
            manifest_json=json.dumps(row["manifest"], sort_keys=True),
            artifact_sha256=str(row.get("artifact_sha256") or ""),
        )
    return None


def active_network_boot_media(
    db: Session,
    *,
    environment_key: str,
    public_version: str = "",
) -> ActiveNetworkBootMedia | NetworkBootMedia | None:
    state = db.get(NetworkBootEnvironment, environment_key)
    if state is None or not state.active_version:
        return None
    applied = _applied_network_boot_media(
        db,
        environment_key=environment_key,
        version=state.active_version,
    )
    if applied is not None:
        return (
            applied
            if not public_version or applied.public_version == public_version
            else None
        )
    if _has_explicit_esxi_pxe_runtime_preview(db):
        return None
    media = db.execute(
        select(NetworkBootMedia).where(
            NetworkBootMedia.environment_key == environment_key,
            NetworkBootMedia.version == state.active_version,
        )
    ).scalar_one_or_none()
    if media is None:
        return None
    installed_name = Path(media.installed_path).name
    return (
        media
        if not public_version or installed_name == public_version
        else None
    )


def _active_media(
    db: Session,
) -> dict[str, ActiveNetworkBootMedia | NetworkBootMedia]:
    states = ensure_environment_rows(db)
    result: dict[str, ActiveNetworkBootMedia | NetworkBootMedia] = {}
    for state in states:
        if not state.active_version:
            continue
        media = active_network_boot_media(
            db,
            environment_key=state.key,
        )
        if media is not None:
            result[state.key] = media
    return result


def _applied_esxi_pxe_runtime(db: Session) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    manifest = _applied_esxi_pxe_manifest(db)
    if (
        not isinstance(manifest.get("boot"), dict)
        or not isinstance(manifest.get("artifacts"), list)
    ):
        return {}, []
    artifacts = [row for row in manifest["artifacts"] if isinstance(row, dict)]
    return dict(manifest["boot"]), artifacts


def _chain_line(
    media: ActiveNetworkBootMedia | NetworkBootMedia,
    *,
    http_origin: str,
) -> str:
    manifest = json.loads(media.manifest_json or "{}")
    boot = manifest.get("boot") if isinstance(manifest.get("boot"), dict) else {}
    kernel = str(boot.get("kernel") or "")
    initrd = str(boot.get("initrd") or "")
    arguments = str(boot.get("arguments") or "").strip()
    if kernel.startswith("/"):
        kernel = f"{http_origin}{kernel}"
    if initrd.startswith("/"):
        initrd = f"{http_origin}{initrd}"
    arguments = arguments.replace("fetch=/", f"fetch={http_origin}/")
    if media.environment_key in {"gparted", "clonezilla"}:
        tokens = [token for token in arguments.split() if token != "ip=dhcp"]
        if "username=user" not in tokens:
            tokens.append("username=user")
        if "vga=788" not in tokens:
            tokens.append("vga=788")
        arguments = " ".join(tokens)
    if media.environment_key == "inventory":
        arguments = (
            f"{arguments} atlaso.url={http_origin} "
            "atlaso.boot_mac=${net0/mac}"
        ).strip()
    if kernel:
        lines = [f"kernel {kernel}" + (f" {arguments}" if arguments else "")]
        if initrd:
            lines.append(f"initrd {initrd}")
        lines.append("boot")
        return "\n".join(lines)
    script = str(boot.get("script") or "")
    if script.startswith("/"):
        script = f"{http_origin}{script}"
    return f"chain {script}" if script else "echo Environment media is incomplete\nsleep 3\ngoto menu"


def _request_http_origin(boot: dict[str, Any], requested_origin: str) -> str:
    default_base = esxi_http_base_url(boot)
    default = urllib.parse.urlsplit(default_base)
    fallback = (
        f"{default.scheme}://{default.netloc}"
        if default.scheme and default.netloc
        else ""
    )
    requested = urllib.parse.urlsplit(requested_origin)
    if (
        requested.scheme != "http"
        or not requested.hostname
        or requested.username is not None
        or requested.password is not None
    ):
        return fallback
    port = requested.port or 80
    if port != int(boot.get("http_port") or 8080):
        return fallback
    allowed_hosts = {
        line.strip().lower()
        for line in str(boot.get("listen_address") or "").replace(",", "\n").splitlines()
        if line.strip()
    }
    hostname = requested.hostname.lower()
    try:
        hostname = str(ip_address(hostname))
        allowed_hosts = {
            str(ip_address(value)) if value else value
            for value in allowed_hosts
        }
    except ValueError:
        allowed_hosts.add(str(boot.get("hostname") or "").strip().lower())
    if hostname not in allowed_hosts:
        return fallback
    rendered_host = f"[{hostname}]" if ":" in hostname else hostname
    return f"http://{rendered_host}:{port}"


def render_network_boot_menu(
    db: Session,
    *,
    mac_address: str = "",
    firmware: str = "",
    request_origin: str = "",
    default_environment_key: str = "",
) -> str:
    mac = normalize_mac(mac_address) if mac_address else ""
    mac_key = normalize_pxe_mac(mac) if mac else ""
    boot, artifacts = _applied_esxi_pxe_runtime(db)
    http_origin = _request_http_origin(boot, request_origin)
    esxi_base_url = f"{http_origin}/pxe/esxi" if http_origin else ""
    assigned = next(
        (
            artifact
            for artifact in artifacts
            if not artifact.get("is_default") and artifact.get("mac_key") == mac_key
        ),
        None,
    )
    undefined = next((artifact for artifact in artifacts if artifact.get("is_default")), None)
    active = _active_media(db)
    inventory = active.get("inventory")
    requested_default = (
        default_environment_key
        if default_environment_key in active
        else ""
    )
    default_label = (
        f"env_{requested_default}"
        if requested_default and requested_default != "inventory"
        else "inventory"
        if requested_default == "inventory"
        else "esxi_assigned"
        if assigned
        else "inventory"
        if inventory
        else "local"
    )
    lines = [
        "#!ipxe",
        ":menu",
        "menu Atlaso Network Boot",
    ]

    def esxi_loader_lines(
        artifact: dict[str, Any],
        *,
        label: str,
    ) -> list[str]:
        mac_key = str(artifact.get("mac_key") or "default")
        normalized_firmware = firmware.strip().lower()
        uefi_lines = [
            f"chain {esxi_base_url}/{mac_key}/mboot.efi || goto menu",
        ]
        bios_lines = [
            f"set 209:string pxelinux.cfg/{mac_key}",
            "set 210:string tftp://${next-server}/",
            "chain tftp://${next-server}/pxelinux.0 || goto menu",
        ]
        if normalized_firmware == "efi":
            return uefi_lines
        if normalized_firmware in {"bios", "pcbios"}:
            return bios_lines
        return [
            f"iseq ${{platform}} efi && goto {label}_uefi || goto {label}_bios",
            f":{label}_uefi",
            *uefi_lines,
            f":{label}_bios",
            *bios_lines,
        ]
    if inventory:
        lines.extend(
            [
                "item --gap -- ---------------- Safe inventory ----------------",
                "item inventory Atlaso Inventory Linux",
            ]
        )
    if assigned:
        lines.extend(
            [
                "item --gap -- ---------------- Assigned host ----------------",
                f"item esxi_assigned ESXi: {assigned['hostname']}",
            ]
        )
    maintenance = [
        (key, entry)
        for key, entry in CATALOG_BY_KEY.items()
        if key not in {"inventory"} and key in active
    ]
    if maintenance:
        lines.append("item --gap -- ---------------- Maintenance ----------------")
        for key, entry in maintenance:
            lines.append(f"item env_{key} {entry.label} [{entry.risk}]")
    esxi_manual = [
        artifact
        for artifact in artifacts
        if not artifact.get("is_default") and artifact is not assigned
    ]
    if esxi_manual or undefined:
        lines.append("item --gap -- ---------------- ESXi manual entries ----------------")
        for artifact in esxi_manual:
            lines.append(f"item esxi_{artifact['host_id']} ESXi: {artifact['hostname']}")
        if undefined:
            lines.append("item esxi_default ESXi: Default / undefined MACs")
    lines.extend(
        [
            "item --gap -- ---------------- Exit ----------------",
            "item local Exit to local disk or firmware",
            f"choose --timeout 10000 --default {default_label} selected || goto local",
            "goto ${selected}",
            "",
            ":inventory",
        ]
    )
    if inventory:
        lines.extend([_chain_line(inventory, http_origin=http_origin), ""])
    else:
        lines.extend(
            [
                "echo Atlaso Inventory Linux is not active.",
                "sleep 3",
                "goto menu",
                "",
            ]
        )
    if assigned:
        lines.extend(
            [
                ":esxi_assigned",
                *esxi_loader_lines(assigned, label="esxi_assigned"),
                "",
            ]
        )
    for artifact in esxi_manual:
        lines.extend(
            [
                f":esxi_{artifact['host_id']}",
                *esxi_loader_lines(
                    artifact,
                    label=f"esxi_{artifact['host_id']}",
                ),
                "",
            ]
        )
    if undefined:
        lines.extend(
            [
                ":esxi_default",
                *esxi_loader_lines(undefined, label="esxi_default"),
                "",
            ]
        )
    for key, _entry in maintenance:
        lines.append(f":env_{key}")
        if key == "shredos":
            lines.extend(
                [
                    "menu ShredOS can permanently erase selected disks",
                    "item cancel Cancel",
                    "item continue Continue to interactive ShredOS",
                    "choose --default cancel shred_choice || goto menu",
                    "iseq ${shred_choice} continue || goto menu",
                ]
            )
        lines.extend([_chain_line(active[key], http_origin=http_origin), ""])
    lines.extend(
        [
            ":local",
            "exit || sanboot --no-describe --drive 0x80 || shell",
            "",
        ]
    )
    return "\n".join(lines)


def request_host_boot_override(
    db: Session,
    *,
    host_id: int,
    mac_address: str,
    environment_key: str,
    requested_by: str,
) -> NetworkBootHostBootOverride:
    now = utcnow()
    override = db.get(NetworkBootHostBootOverride, host_id)
    if override is None:
        override = NetworkBootHostBootOverride(host_id=host_id)
    override.mac_address = normalize_mac(mac_address)
    override.environment_key = environment_key
    override.requested_by = requested_by
    override.requested_at = now
    override.expires_at = now + NETWORK_BOOT_OVERRIDE_LIFETIME
    override.claimed_at = None
    db.add(override)
    db.flush()
    return override


def claim_host_boot_override(
    db: Session,
    *,
    mac_address: str,
) -> str:
    if not mac_address:
        return ""
    now = utcnow()
    normalized = normalize_mac(mac_address)
    override = db.execute(
        select(NetworkBootHostBootOverride).where(
            NetworkBootHostBootOverride.mac_address == normalized,
            NetworkBootHostBootOverride.expires_at > now,
        )
    ).scalar_one_or_none()
    if override is None:
        return ""
    active = _active_media(db)
    if override.environment_key not in active:
        return ""
    if override.claimed_at is not None:
        claimed_at = override.claimed_at
        if claimed_at.tzinfo is None:
            claimed_at = claimed_at.replace(tzinfo=timezone.utc)
        if claimed_at + NETWORK_BOOT_OVERRIDE_CLAIM_GRACE <= now:
            return ""
    else:
        override.claimed_at = now
        db.add(override)
        db.flush()
    return override.environment_key


class _BoundedHttpsRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, max_redirects: int):
        super().__init__()
        self.max_redirects = max_redirects

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        redirects = int(req.headers.get("X-Atlaso-Redirect-Count", "0")) + 1
        if redirects > self.max_redirects:
            raise ValueError("Boot media download exceeded the redirect limit.")
        resolved = urllib.parse.urljoin(req.full_url, newurl)
        parsed = urllib.parse.urlparse(resolved)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("Boot media download redirected away from HTTPS.")
        redirected = super().redirect_request(req, fp, code, msg, headers, resolved)
        if redirected is not None:
            redirected.add_header("X-Atlaso-Redirect-Count", str(redirects))
        return redirected


class BoundedHttpsDownloader:
    def __init__(
        self,
        *,
        max_bytes: int = 2 * 1024 * 1024 * 1024,
        timeout_seconds: int = 300,
        max_redirects: int = 5,
        open_attempts: int = 3,
    ):
        self.max_bytes = max_bytes
        self.timeout_seconds = timeout_seconds
        self.max_redirects = max_redirects
        self.open_attempts = open_attempts

    def download(
        self,
        url: str,
        destination: Path,
        *,
        cancelled: Callable[[], bool] | None = None,
    ) -> tuple[str, str]:
        if cancelled and cancelled():
            raise NetworkBootMediaSyncCancelled(
                "Network Boot media task was cancelled."
            )
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("Boot media downloads require HTTPS.")
        digest = hashlib.sha256()
        response = None
        for attempt in range(1, self.open_attempts + 1):
            request = urllib.request.Request(
                url,
                headers={"User-Agent": "Atlaso-Network-Boot/1"},
            )
            opener = urllib.request.build_opener(
                _BoundedHttpsRedirectHandler(self.max_redirects)
            )
            try:
                response = opener.open(request, timeout=self.timeout_seconds)
                break
            except urllib.error.HTTPError:
                raise
            except urllib.error.URLError:
                if attempt >= self.open_attempts:
                    raise
                time.sleep(attempt)
        if response is None:
            raise ValueError("Boot media download did not return a response.")
        final_url = response.geturl()
        if urllib.parse.urlparse(final_url).scheme != "https":
            response.close()
            raise ValueError("Boot media download redirected away from HTTPS.")
        declared = response.headers.get("Content-Length", "")
        if declared.isdigit() and int(declared) > self.max_bytes:
            response.close()
            raise ValueError("Boot media asset exceeds the size limit.")
        total = 0
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            with response, destination.open("wb") as output:
                while chunk := response.read(1024 * 1024):
                    if cancelled and cancelled():
                        raise NetworkBootMediaSyncCancelled(
                            "Network Boot media task was cancelled."
                        )
                    total += len(chunk)
                    if total > self.max_bytes:
                        raise ValueError("Boot media asset exceeds the size limit.")
                    digest.update(chunk)
                    output.write(chunk)
        except Exception:
            destination.unlink(missing_ok=True)
            raise
        return final_url, digest.hexdigest()


def checksum_for_filename(checksum_text: str, filename: str) -> str:
    for raw_line in checksum_text.splitlines():
        parts = raw_line.strip().split()
        if len(parts) < 2:
            continue
        digest = parts[0].lower()
        candidate = PurePosixPath(parts[-1].lstrip("*")).name
        if candidate == filename and re.fullmatch(r"[0-9a-f]{64}", digest):
            return digest
    raise ValueError(f"Signed checksum file does not contain {filename}.")


def verify_gpg_signature(
    checksum_path: Path,
    signature_path: Path,
    *,
    fingerprint: str,
    keyring_path: Path,
) -> None:
    gpg = shutil.which("gpg")
    if not gpg:
        raise ValueError("GnuPG is required to verify signed boot media checksums.")
    result = subprocess.run(
        [
            gpg,
            "--batch",
            "--no-default-keyring",
            "--keyring",
            str(keyring_path),
            "--status-fd",
            "1",
            "--verify",
            str(signature_path),
            str(checksum_path),
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    normalized = fingerprint.replace(" ", "").upper()
    valid = any(
        line.startswith("[GNUPG:] VALIDSIG ") and line.split()[2].upper() == normalized
        for line in result.stdout.splitlines()
        if len(line.split()) >= 3
    )
    if result.returncode != 0 or not valid:
        raise ValueError("Boot media checksum signature did not match the pinned signing key.")


def verify_signed_checksum(
    checksum_path: Path,
    signature_path: Path,
    public_key_path: Path,
    *,
    fingerprint: str,
) -> None:
    gpg = shutil.which("gpg")
    if not gpg:
        raise ValueError("GnuPG is required to verify signed boot media checksums.")
    with tempfile.TemporaryDirectory(prefix="atlaso-network-boot-gpg-") as home:
        imported = subprocess.run(
            [gpg, "--batch", "--homedir", home, "--import", str(public_key_path)],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if imported.returncode != 0:
            raise ValueError("Pinned boot-media signing key could not be imported.")
        result = subprocess.run(
            [
                gpg,
                "--batch",
                "--homedir",
                home,
                "--status-fd",
                "1",
                "--verify",
                str(signature_path),
                str(checksum_path),
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    normalized = fingerprint.replace(" ", "").upper()
    valid = any(
        line.startswith("[GNUPG:] VALIDSIG ") and line.split()[2].upper() == normalized
        for line in result.stdout.splitlines()
        if len(line.split()) >= 3
    )
    if result.returncode != 0 or not valid:
        raise ValueError("Boot media checksum signature did not match the pinned signing key.")


def safe_archive_member(member_name: str) -> bool:
    path = PurePosixPath(member_name.replace("\\", "/"))
    return bool(
        member_name
        and not path.is_absolute()
        and ".." not in path.parts
        and not re.match(r"^[A-Za-z]:", member_name)
    )


def record_verified_media(
    db: Session,
    *,
    environment_key: str,
    version: str,
    source_url: str,
    artifact_sha256: str,
    installed_path: str,
    manifest: dict[str, Any],
) -> NetworkBootMedia:
    key = normalize_environment_key(environment_key)
    normalized_version = normalize_version(version)
    entry = CATALOG_BY_KEY[key]
    if not re.fullmatch(r"[0-9a-f]{64}", artifact_sha256.lower()):
        raise ValueError("Boot media SHA-256 digest is invalid.")
    ensure_environment_rows(db)
    existing = db.execute(
        select(NetworkBootMedia).where(
            NetworkBootMedia.environment_key == key,
            NetworkBootMedia.version == normalized_version,
        )
    ).scalar_one_or_none()
    if existing is not None:
        if existing.artifact_sha256 != artifact_sha256.lower():
            raise ValueError("Installed immutable media version has a different digest.")
        return existing
    row = NetworkBootMedia(
        environment_key=key,
        version=normalized_version,
        source_url=source_url,
        license_name=entry.license_name,
        artifact_sha256=artifact_sha256.lower(),
        verification_method=entry.verification_method,
        installed_path=installed_path,
        manifest_json=json.dumps(manifest, sort_keys=True),
    )
    db.add(row)
    db.flush()
    return row


def _fetch_https_bytes(url: str, *, max_bytes: int = 2 * 1024 * 1024) -> bytes:
    with tempfile.TemporaryDirectory(prefix="atlaso-network-boot-resolve-") as temp_dir:
        path = Path(temp_dir) / "response"
        BoundedHttpsDownloader(
            max_bytes=max_bytes,
            timeout_seconds=30,
            max_redirects=3,
        ).download(url, path)
        return path.read_bytes()


def _fetch_https_text(url: str, *, max_bytes: int = 2 * 1024 * 1024) -> str:
    return _fetch_https_bytes(url, max_bytes=max_bytes).decode("utf-8")


def _release_descriptor(environment_key: str) -> dict[str, str]:
    key = normalize_environment_key(environment_key)
    if key == "inventory":
        try:
            raw_manifest = _fetch_https_bytes(INVENTORY_LINUX_LATEST_MANIFEST_URL)
            raw_signature = _fetch_https_bytes(INVENTORY_LINUX_LATEST_SIGNATURE_URL)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise ValueError(
                    "No Atlaso Inventory Linux release has been published. "
                    "Publish one with the Inventory Linux release workflow, then retry."
                ) from exc
            raise
        payload = verify_signed_json(
            raw_manifest,
            raw_signature,
            document_kind="inventory",
        )
        package = payload["package"]
        return {
            "version": str(payload["version"]),
            "filename": str(package["name"]),
            "asset_url": str(package["url"]),
            "sha256": str(package["sha256"]),
            "size": str(package["size"]),
        }
    if key == "memtest86plus":
        html = _fetch_https_text("https://www.memtest.org/")
        match = re.search(r"/download/v(?P<version>[0-9.]+)/mt86plus_(?P<fileversion>[0-9.]+)\.binaries\.zip", html)
        if not match:
            match = re.search(r"/download/v(?P<version>[0-9.]+)/mt86plus_(?P<fileversion>[0-9]+)\.binaries\.zip", html)
        if not match:
            raise ValueError("Memtest86+ stable binary link could not be resolved.")
        version = match.group("version")
        filename = Path(match.group(0)).name
        base = f"https://www.memtest.org/download/v{version}"
        return {
            "version": version,
            "filename": filename,
            "asset_url": f"{base}/{filename}",
            "checksum_url": f"{base}/sha256sum.txt",
        }
    if key == "gparted":
        html = _fetch_https_text("https://gparted.org/download.php")
        match = re.search(r"gparted-live-([0-9][A-Za-z0-9.-]+)-amd64\.iso", html)
        if not match:
            raise ValueError("GParted Live stable version could not be resolved.")
        version = match.group(1)
        filename = f"gparted-live-{version}-amd64.zip"
        return {
            "version": version,
            "filename": filename,
            "asset_url": f"https://downloads.sourceforge.net/gparted/{filename}",
            "checksum_url": "https://gparted.org/gparted-live/stable/CHECKSUMS.TXT",
            "signature_url": "https://gparted.org/gparted-live/stable/CHECKSUMS.TXT.gpg",
        }
    if key == "clonezilla":
        html = _fetch_https_text("https://clonezilla.org/downloads.php")
        match = re.search(
            r"branch=stable\b.*?<font[^>]*>\s*([0-9]+\.[0-9]+\.[0-9]+-[0-9]+)\s*</font>",
            html,
            flags=re.IGNORECASE | re.DOTALL,
        )
        if not match:
            raise ValueError("Clonezilla Live stable version could not be resolved.")
        version = match.group(1)
        filename = f"clonezilla-live-{version}-amd64.zip"
        return {
            "version": version,
            "filename": filename,
            "asset_url": (
                "https://downloads.sourceforge.net/clonezilla/"
                f"clonezilla_live_stable/{version}/{filename}"
            ),
            "checksum_url": "https://clonezilla.org/downloads/stable/data/CHECKSUMS.TXT",
            "signature_url": "https://clonezilla.org/downloads/stable/data/CHECKSUMS.TXT.gpg",
        }
    if key == "shredos":
        payload = json.loads(
            _fetch_https_text(
                "https://api.github.com/repos/PartialVolume/shredos.x86_64/releases/latest"
            )
        )
        if payload.get("draft") or payload.get("prerelease"):
            raise ValueError("ShredOS latest GitHub release is not stable.")
        assets = payload.get("assets")
        if not isinstance(assets, list):
            raise ValueError("ShredOS stable release has no assets.")
        asset = next(
            (
                row
                for row in assets
                if isinstance(row, dict)
                and re.search(r"x86-64.*\.iso$", str(row.get("name") or ""))
                and "lite" not in str(row.get("name") or "").lower()
                and "plus-partition" not in str(row.get("name") or "").lower()
            ),
            None,
        )
        digest = str((asset or {}).get("digest") or "")
        if not asset or not digest.startswith("sha256:"):
            raise ValueError("ShredOS stable ISO does not publish a SHA-256 asset digest.")
        return {
            "version": str(payload.get("tag_name") or "").removeprefix("v"),
            "filename": str(asset["name"]),
            "asset_url": str(asset["browser_download_url"]),
            "sha256": digest.removeprefix("sha256:").lower(),
        }
    raise ValueError("Unsupported Network Boot environment.")


def available_network_boot_versions(*, force_refresh: bool = False) -> list[dict[str, str]]:
    """Resolve current upstream versions without downloading media artifacts."""
    now = time.monotonic()
    with _AVAILABLE_VERSION_CACHE_LOCK:
        missing = [
            entry
            for entry in ENVIRONMENT_CATALOG
            if force_refresh
            or entry.key not in _AVAILABLE_VERSION_CACHE
            or float(_AVAILABLE_VERSION_CACHE[entry.key].get("expires_at") or 0) <= now
        ]
        if missing:
            resolved: dict[str, str] = {}
            failures: set[str] = set()
            with ThreadPoolExecutor(max_workers=len(missing)) as executor:
                futures = {
                    executor.submit(_release_descriptor, entry.key): entry.key
                    for entry in missing
                }
                for future in as_completed(futures):
                    key = futures[future]
                    try:
                        resolved[key] = str(future.result()["version"])
                    except (KeyError, OSError, ValueError, json.JSONDecodeError):
                        failures.add(key)
            checked_at = datetime.now(timezone.utc).isoformat()
            for entry in missing:
                previous = _AVAILABLE_VERSION_CACHE.get(entry.key, {})
                if entry.key in resolved:
                    _AVAILABLE_VERSION_CACHE[entry.key] = {
                        "available_version": resolved[entry.key],
                        "available_status": "current",
                        "available_checked_at": checked_at,
                        "expires_at": now + AVAILABLE_VERSION_CACHE_SECONDS,
                    }
                elif entry.key in failures and previous.get("available_version"):
                    _AVAILABLE_VERSION_CACHE[entry.key] = {
                        "available_version": str(previous["available_version"]),
                        "available_status": "stale",
                        "available_checked_at": str(previous.get("available_checked_at") or ""),
                        "expires_at": now + AVAILABLE_VERSION_ERROR_CACHE_SECONDS,
                    }
                else:
                    _AVAILABLE_VERSION_CACHE[entry.key] = {
                        "available_version": "",
                        "available_status": "unavailable",
                        "available_checked_at": checked_at,
                        "expires_at": now + AVAILABLE_VERSION_ERROR_CACHE_SECONDS,
                    }
        return [
            {
                "key": entry.key,
                "available_version": str(
                    _AVAILABLE_VERSION_CACHE.get(entry.key, {}).get("available_version") or ""
                ),
                "available_status": str(
                    _AVAILABLE_VERSION_CACHE.get(entry.key, {}).get("available_status")
                    or "unavailable"
                ),
                "available_checked_at": str(
                    _AVAILABLE_VERSION_CACHE.get(entry.key, {}).get("available_checked_at") or ""
                ),
            }
            for entry in ENVIRONMENT_CATALOG
        ]


def _extract_zip_allowlist(
    archive: Path,
    destination: Path,
    *,
    allowed_names: dict[str, str],
) -> list[str]:
    extracted: list[str] = []
    with zipfile.ZipFile(archive) as rows:
        members = {info.filename: info for info in rows.infolist()}
        if any(not safe_archive_member(name) for name in members):
            raise ValueError("Boot media archive contains an unsafe path.")
        for source_name, target_name in allowed_names.items():
            info = members.get(source_name)
            if info is None or info.is_dir():
                raise ValueError(f"Boot media archive is missing {source_name}.")
            target = destination / target_name
            target.parent.mkdir(parents=True, exist_ok=True)
            with rows.open(info) as source, target.open("wb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)
            target.chmod(0o644)
            extracted.append(target_name)
    return extracted


def _extract_shredos_kernel(
    archive: Path,
    destination: Path,
) -> list[str]:
    iso = pycdlib.PyCdlib()
    opened = False
    try:
        iso.open(str(archive))
        opened = True
        selected: dict[str, str] | None = None
        record = None
        for candidate in (
            {"rr_path": "/boot/bzImage"},
            {"joliet_path": "/boot/bzImage"},
            {"iso_path": "/BOOT/BZIMAGE.;1"},
            {"iso_path": "/BOOT/BZIMAGE;1"},
        ):
            try:
                record = iso.get_record(**candidate)
            except (pycdlibexception.PyCdlibException, IndexError):
                continue
            selected = candidate
            break
        if selected is None or record is None or record.is_dir():
            raise ValueError("ShredOS ISO is missing the /boot/bzImage kernel.")
        size = int(record.data_length)
        if size <= 0 or size > NETWORK_BOOT_SHREDOS_KERNEL_MAX_BYTES:
            raise ValueError("ShredOS kernel size is outside the supported range.")
        target = destination / "shredos"
        with target.open("xb") as output:
            iso.get_file_from_iso_fp(output, **selected)
        if target.stat().st_size != size:
            target.unlink(missing_ok=True)
            raise ValueError("ShredOS kernel extraction was incomplete.")
        target.chmod(0o644)
        return ["shredos"]
    except pycdlibexception.PyCdlibException as exc:
        raise ValueError("ShredOS release asset is not a valid ISO image.") from exc
    finally:
        if opened:
            iso.close()


def _media_boot_manifest(
    environment_key: str,
    version: str,
    *,
    extracted: Iterable[str],
) -> dict[str, Any]:
    base = f"/pxe/media/{environment_key}/{version}"
    files = list(extracted)
    if environment_key == "inventory":
        return {
            "boot": {
                "kernel": f"{base}/bzImage",
                "initrd": f"{base}/rootfs.cpio.gz",
                "arguments": (
                    "rdinit=/sbin/init console=tty0 quiet loglevel=3 "
                    "logo.nologo vt.global_cursor_default=0 vga=791 "
                    "video=1024x768 fbcon=font:VGA8x16 atlaso.inventory=1"
                ),
            },
            "files": files,
        }
    if environment_key == "memtest86plus":
        return {
            "boot": {"kernel": f"{base}/memtest86plus", "arguments": ""},
            "files": files,
        }
    if environment_key in {"gparted", "clonezilla"}:
        arguments = [
            "boot=live",
            "union=overlay",
            "config",
            "components",
            "username=user",
            "noswap",
            "noeject",
            "vga=788",
            f"fetch={base}/filesystem.squashfs",
        ]
        if environment_key == "clonezilla":
            arguments.extend(
                [
                    "ocs_live_batch=no",
                    "ocs_live_run=ocs-live-general",
                    "noprompt",
                ]
            )
        return {
            "boot": {
                "kernel": f"{base}/vmlinuz",
                "initrd": f"{base}/initrd.img",
                "arguments": " ".join(arguments),
            },
            "files": files,
        }
    if environment_key == "shredos":
        return {
            "boot": {"script": f"{base}/boot.ipxe"},
            "files": files,
        }
    raise ValueError("Unsupported downloaded environment.")


def _enumerated_media_directory(
    *,
    environment_key: str,
    version: str,
    media_root: Path,
) -> Path | None:
    environment_root = (media_root / normalize_environment_key(environment_key)).resolve()
    if not environment_root.is_dir() or environment_root.is_symlink():
        return None
    normalized_version = normalize_version(version)
    for index, candidate in enumerate(environment_root.iterdir()):
        if index >= 256:
            return None
        if (
            candidate.name == normalized_version
            and candidate.is_dir()
            and not candidate.is_symlink()
        ):
            resolved = candidate.resolve()
            if resolved.is_relative_to(environment_root):
                return resolved
    return None


def _enumerated_regular_files(root: Path) -> dict[str, Path] | None:
    files: dict[str, Path] = {}
    pending = [root]
    visited = 0
    while pending:
        directory = pending.pop()
        for child in directory.iterdir():
            visited += 1
            if visited > 256 or child.is_symlink():
                return None
            resolved = child.resolve()
            if not resolved.is_relative_to(root):
                return None
            if child.is_dir():
                pending.append(resolved)
            elif child.is_file():
                files[resolved.relative_to(root).as_posix()] = resolved
            else:
                return None
    return files


def _verified_cached_media(
    media: NetworkBootMedia,
    *,
    media_root: Path,
) -> Path | None:
    environment_root = (
        media_root / normalize_environment_key(media.environment_key)
    ).resolve()
    expected = Path(media.installed_path)
    directory: Path | None = None
    if environment_root.is_dir() and not environment_root.is_symlink():
        for index, candidate in enumerate(environment_root.iterdir()):
            if index >= 256:
                return None
            if candidate.is_symlink() or not candidate.is_dir():
                continue
            resolved = candidate.resolve()
            if (
                resolved.is_relative_to(environment_root)
                and resolved.parent == environment_root
                and str(resolved) == str(expected)
            ):
                directory = resolved
                break
    if directory is None:
        return None
    files = _enumerated_regular_files(directory)
    manifest_path = (files or {}).get("manifest.json")
    if manifest_path is None or manifest_path.stat().st_size > 2 * 1024 * 1024:
        return None
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if (
        not isinstance(manifest, dict)
        or manifest.get("kind") != "atlaso-network-boot-media"
        or manifest.get("schema_version") != NETWORK_BOOT_SCHEMA_VERSION
        or manifest.get("environment") != media.environment_key
        or manifest.get("version") != media.version
        or manifest.get("sha256") != media.artifact_sha256
    ):
        return None
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        return None
    if media.environment_key == "shredos" and set(artifacts) != {
        "boot.ipxe",
        "shredos",
    }:
        return None
    for filename, expected_sha256 in artifacts.items():
        if (
            not isinstance(filename, str)
            or not safe_archive_member(filename)
            or not isinstance(expected_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)
        ):
            return None
        artifact = (files or {}).get(PurePosixPath(filename).as_posix())
        if artifact is None:
            return None
        actual_sha256 = _file_sha256(artifact)
        if not secrets.compare_digest(
            actual_sha256,
            expected_sha256,
        ):
            return None
    return directory


def prune_superseded_shredos_media(
    db: Session,
    *,
    media_root: Path = NETWORK_BOOT_MEDIA_ROOT,
) -> int:
    """Remove immutable ShredOS snapshots no longer referenced by desired or applied state."""
    root = media_root.resolve()
    environment_root = (root / "shredos").resolve()
    if (
        media_root.is_symlink()
        or not media_root.is_dir()
        or environment_root.is_symlink()
        or not environment_root.is_dir()
        or environment_root.parent != root
    ):
        return 0

    removed = 0
    with _MediaSwapRecoveryLock(root):
        protected: set[str] = set()
        installed_paths = db.execute(
            select(NetworkBootMedia.installed_path).where(
                NetworkBootMedia.environment_key == "shredos"
            )
        ).scalars()
        for installed_path in installed_paths:
            try:
                resolved = Path(installed_path).resolve()
            except OSError:
                continue
            if resolved.parent == environment_root:
                protected.add(str(resolved))

        applied = _applied_esxi_pxe_manifest(db).get("network_boot")
        applied_environments = (
            applied.get("environments")
            if isinstance(applied, dict)
            else None
        )
        if isinstance(applied_environments, list):
            for row in applied_environments[: len(ENVIRONMENT_CATALOG)]:
                if not isinstance(row, dict) or row.get("key") != "shredos":
                    continue
                installed_path = row.get("installed_path")
                if not isinstance(installed_path, str):
                    continue
                try:
                    resolved = Path(installed_path).resolve()
                except OSError:
                    continue
                if resolved.parent == environment_root:
                    protected.add(str(resolved))

        for index, candidate in enumerate(environment_root.iterdir()):
            if index >= 256:
                break
            if candidate.is_symlink() or not candidate.is_dir():
                continue
            resolved = candidate.resolve()
            if (
                resolved.parent != environment_root
                or str(resolved) in protected
            ):
                continue
            manifest_path = resolved / "manifest.json"
            try:
                if (
                    manifest_path.is_symlink()
                    or not manifest_path.is_file()
                    or manifest_path.stat().st_size > 2 * 1024 * 1024
                ):
                    continue
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                if not isinstance(manifest, dict):
                    continue
                version = normalize_version(str(manifest.get("version") or ""))
            except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError):
                continue
            artifact_sha256 = str(manifest.get("sha256") or "")
            if (
                manifest.get("kind") != "atlaso-network-boot-media"
                or manifest.get("schema_version") != NETWORK_BOOT_SCHEMA_VERSION
                or manifest.get("environment") != "shredos"
                or re.fullmatch(r"[0-9a-f]{64}", artifact_sha256) is None
                or re.fullmatch(
                    rf"{re.escape(version)}"
                    rf"(?:\.sha256-{re.escape(artifact_sha256[:12])}-[0-9a-f]{{12}})?",
                    candidate.name,
                )
                is None
            ):
                continue
            shutil.rmtree(resolved)
            _fsync_directory(environment_root)
            removed += 1
    return removed


def _write_media_swap_journal(
    environment_root: Path,
    *,
    environment_key: str,
    version: str,
    final_directory: str,
    transaction_id: str,
    staging_directory: str,
) -> Path:
    journal_path = environment_root / f".atlaso-media-sync-{transaction_id}.json"
    with journal_path.open("x", encoding="utf-8") as journal:
        json.dump(
            {
                "environment": environment_key,
                "final_directory": final_directory,
                "staging_directory": staging_directory,
                "version": version,
            },
            journal,
            sort_keys=True,
        )
        journal.write("\n")
        journal.flush()
        os.fsync(journal.fileno())
    _fsync_directory(environment_root)
    return journal_path


def _fsync_directory(directory: Path) -> None:
    if os.name == "nt":
        return
    directory_fd = os.open(
        directory,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _fsync_media_tree(root: Path) -> None:
    files = _enumerated_regular_files(root)
    if files is None:
        raise ValueError("Boot media staging tree is unsafe.")
    if os.name == "nt":
        return
    directories = {root}
    for artifact in files.values():
        with artifact.open("rb") as stream:
            os.fsync(stream.fileno())
        parent = artifact.parent
        while parent.is_relative_to(root):
            directories.add(parent)
            if parent == root:
                break
            parent = parent.parent
    for directory in sorted(
        directories,
        key=lambda candidate: len(candidate.parts),
        reverse=True,
    ):
        _fsync_directory(directory)


class _MediaSwapRecoveryLock:
    def __init__(self, media_root: Path):
        self.lock_path = media_root / ".atlaso-media-swap-recovery.lock"
        self.lock_fd: int | None = None
        self.thread_acquired = False
        self.process_acquired = False

    def acquire(self) -> None:
        _MEDIA_SWAP_THREAD_LOCK.acquire()
        self.thread_acquired = True
        lock_acquired = False
        try:
            flags = (
                os.O_CREAT
                | os.O_RDWR
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            self.lock_fd = os.open(self.lock_path, flags, 0o600)
            metadata = os.fstat(self.lock_fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ValueError("Network Boot media recovery lock is unsafe.")
            if fcntl is not None:
                fcntl.flock(self.lock_fd, fcntl.LOCK_EX)
                lock_acquired = True
                self.process_acquired = True
        except Exception:
            if fcntl is not None and lock_acquired and self.lock_fd is not None:
                fcntl.flock(self.lock_fd, fcntl.LOCK_UN)
            if self.lock_fd is not None:
                os.close(self.lock_fd)
                self.lock_fd = None
            self._release_thread()
            raise

    def release(self) -> None:
        if (
            fcntl is not None
            and self.process_acquired
            and self.lock_fd is not None
        ):
            fcntl.flock(self.lock_fd, fcntl.LOCK_UN)
            self.process_acquired = False
        if self.lock_fd is not None:
            os.close(self.lock_fd)
            self.lock_fd = None
        self._release_thread()

    def _release_thread(self) -> None:
        if self.thread_acquired:
            self.thread_acquired = False
            _MEDIA_SWAP_THREAD_LOCK.release()

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, _exc_type, _exc_value, _traceback):
        self.release()


class _MediaStagingLease:
    def __init__(self, staging_directory: Path):
        self.staging_directory = staging_directory
        self.lock_path = staging_directory / ".atlaso-staging.lock"
        self.lock_fd: int | None = None
        self.process_acquired = False
        self.identity = str(staging_directory.resolve())

    def __enter__(self):
        flags = (
            os.O_CREAT
            | os.O_EXCL
            | os.O_RDWR
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        media_root = self.staging_directory.parent.parent
        publication_lock = _MediaSwapRecoveryLock(media_root)
        publication_lock.acquire()
        try:
            with _MEDIA_STAGING_THREAD_LOCK:
                _ACTIVE_MEDIA_STAGING_DIRECTORIES.add(self.identity)
            try:
                self.lock_fd = os.open(self.lock_path, flags, 0o600)
                metadata = os.fstat(self.lock_fd)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise ValueError("Network Boot media staging lock is unsafe.")
                if fcntl is not None:
                    fcntl.flock(self.lock_fd, fcntl.LOCK_EX)
                    self.process_acquired = True
                os.fsync(self.lock_fd)
                _fsync_directory(self.staging_directory)
                _fsync_directory(self.staging_directory.parent)
                return self
            except Exception:
                self._release()
                raise
        finally:
            publication_lock.release()

    def __exit__(self, _exc_type, _exc_value, _traceback):
        self._release()

    def _release(self) -> None:
        with _MEDIA_STAGING_THREAD_LOCK:
            _ACTIVE_MEDIA_STAGING_DIRECTORIES.discard(self.identity)
        if (
            fcntl is not None
            and self.process_acquired
            and self.lock_fd is not None
        ):
            fcntl.flock(self.lock_fd, fcntl.LOCK_UN)
            self.process_acquired = False
        if self.lock_fd is not None:
            os.close(self.lock_fd)
            self.lock_fd = None


def _remove_orphan_media_staging_directories(
    environment_root: Path,
    *,
    environment_key: str,
) -> int:
    staging_pattern = re.compile(
        rf"^\.atlaso-{re.escape(environment_key)}-[0-9a-f]{{32}}-"
        r"[A-Za-z0-9_-]{1,64}$"
    )
    removed = 0
    for index, candidate in enumerate(environment_root.iterdir()):
        if index >= 256:
            break
        if (
            staging_pattern.fullmatch(candidate.name) is None
            or candidate.is_symlink()
            or not candidate.is_dir()
        ):
            continue
        resolved = candidate.resolve()
        if not resolved.is_relative_to(environment_root):
            continue
        identity = str(resolved)
        with _MEDIA_STAGING_THREAD_LOCK:
            if identity in _ACTIVE_MEDIA_STAGING_DIRECTORIES:
                continue
        lock_path = resolved / ".atlaso-staging.lock"
        if lock_path.is_symlink() or not lock_path.is_file():
            continue
        flags = (
            os.O_RDWR
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            lock_fd = os.open(lock_path, flags)
        except OSError:
            continue
        process_acquired = False
        try:
            metadata = os.fstat(lock_fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                continue
            if fcntl is not None:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    continue
                process_acquired = True
        finally:
            if fcntl is not None and process_acquired:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
        shutil.rmtree(resolved)
        _fsync_directory(environment_root)
        removed += 1
    return removed


def recover_interrupted_network_boot_media_swaps(
    db: Session,
    *,
    media_root: Path = NETWORK_BOOT_MEDIA_ROOT,
) -> int:
    if media_root.is_symlink() or not media_root.is_dir():
        return 0
    with _MediaSwapRecoveryLock(media_root):
        return _recover_interrupted_network_boot_media_swaps(
            db,
            media_root=media_root,
        )


def _recover_interrupted_network_boot_media_swaps(
    db: Session,
    *,
    media_root: Path,
) -> int:
    recovered = 0
    journal_pattern = re.compile(r"^\.atlaso-media-sync-([0-9a-f]{32})\.json$")
    for entry in ENVIRONMENT_CATALOG:
        environment_root = media_root / entry.key
        if environment_root.is_symlink() or not environment_root.is_dir():
            continue
        _remove_orphan_media_staging_directories(
            environment_root,
            environment_key=entry.key,
        )
        for journal_path in environment_root.iterdir():
            match = journal_pattern.fullmatch(journal_path.name)
            if (
                match is None
                or journal_path.is_symlink()
                or not journal_path.is_file()
            ):
                continue
            try:
                journal = json.loads(journal_path.read_text(encoding="utf-8"))
                if not isinstance(journal, dict):
                    continue
                version = normalize_version(str(journal.get("version") or ""))
            except (OSError, ValueError, json.JSONDecodeError):
                continue
            if journal.get("environment") != entry.key:
                continue
            transaction_id = match.group(1)
            staging_name = journal.get("staging_directory")
            staging_dir: Path | None = None
            if staging_name is not None:
                expected_staging = re.compile(
                    rf"^\.atlaso-{re.escape(entry.key)}-{transaction_id}-"
                    r"[A-Za-z0-9_-]{1,64}$"
                )
                if (
                    not isinstance(staging_name, str)
                    or expected_staging.fullmatch(staging_name) is None
                ):
                    continue
                staging_dir = environment_root / staging_name
                if staging_dir.is_symlink() or (
                    staging_dir.exists() and not staging_dir.is_dir()
                ):
                    continue
            final_directory = journal.get("final_directory", version)
            if (
                not isinstance(final_directory, str)
                or re.fullmatch(
                    rf"{re.escape(version)}"
                    r"(?:\.sha256-[0-9a-f]{12}-[0-9a-f]{12})?",
                    final_directory,
                )
                is None
            ):
                continue
            final_dir = environment_root / final_directory
            backup_dir = (
                environment_root / f".{version}.replacement-{transaction_id}"
            )
            media = db.execute(
                select(NetworkBootMedia).where(
                    NetworkBootMedia.environment_key == entry.key,
                    NetworkBootMedia.version == version,
                )
            ).scalar_one_or_none()
            verified_directory = (
                _verified_cached_media(media, media_root=media_root)
                if media is not None
                else None
            )
            if (
                verified_directory is not None
                and verified_directory == final_dir.resolve()
            ):
                if (
                    backup_dir.exists()
                    and not backup_dir.is_symlink()
                    and backup_dir.is_dir()
                ):
                    shutil.rmtree(backup_dir)
                if staging_dir is not None and staging_dir.exists():
                    shutil.rmtree(staging_dir)
                _fsync_directory(environment_root)
                journal_path.unlink(missing_ok=True)
                _fsync_directory(environment_root)
                recovered += 1
                continue
            installed = None
            if final_dir.is_dir() and not final_dir.is_symlink():
                resolved_final = final_dir.resolve()
                if (
                    resolved_final.is_relative_to(environment_root.resolve())
                    and resolved_final.parent == environment_root.resolve()
                ):
                    installed = resolved_final
            if final_dir.is_symlink() or (
                final_dir.exists() and installed is None
            ):
                continue
            backup_present = backup_dir.exists() or backup_dir.is_symlink()
            if backup_present and (
                backup_dir.is_symlink() or not backup_dir.is_dir()
            ):
                continue
            if installed is not None:
                shutil.rmtree(installed)
            if backup_present:
                backup_dir.replace(final_dir)
            if staging_dir is not None and staging_dir.exists():
                shutil.rmtree(staging_dir)
            _fsync_directory(environment_root)
            journal_path.unlink(missing_ok=True)
            _fsync_directory(environment_root)
            recovered += 1
    return recovered


def _file_sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def network_boot_upload_path(
    job_id: str,
    *,
    upload_root: Path | None = None,
) -> Path:
    if not re.fullmatch(r"job_[0-9a-f]{32}", job_id):
        raise ValueError("Network Boot upload task identifier is invalid.")
    return (upload_root or NETWORK_BOOT_UPLOAD_ROOT).resolve() / job_id / "artifact"


def cleanup_network_boot_upload(
    job_id: str,
    *,
    upload_root: Path | None = None,
) -> None:
    upload_path = network_boot_upload_path(job_id, upload_root=upload_root)
    upload_path.unlink(missing_ok=True)
    try:
        upload_path.parent.rmdir()
    except FileNotFoundError:
        pass


def sync_network_boot_media(
    db: Session,
    *,
    environment_key: str,
    media_root: Path = NETWORK_BOOT_MEDIA_ROOT,
    uploaded_artifact: Path | None = None,
    uploaded_filename: str = "",
    cancelled: Callable[[], bool] | None = None,
    defer_filesystem_commit: bool = False,
) -> NetworkBootMedia | DeferredNetworkBootMediaSync:
    def raise_if_cancelled() -> None:
        if cancelled and cancelled():
            raise NetworkBootMediaSyncCancelled(
                "Network Boot media task was cancelled."
            )

    raise_if_cancelled()
    key = normalize_environment_key(environment_key)
    descriptor = _release_descriptor(key)
    raise_if_cancelled()
    version = normalize_version(descriptor["version"])
    entry = CATALOG_BY_KEY[key]
    transaction_id = uuid.uuid4().hex
    environment_root = (media_root / key).resolve()
    state = db.get(NetworkBootEnvironment, key)
    active_snapshot = (
        _applied_network_boot_media(
            db,
            environment_key=key,
            version=version,
        )
        if state is not None and state.active_version == version
        else None
    )
    final_directory_name = version
    existing = db.execute(
        select(NetworkBootMedia).where(
            NetworkBootMedia.environment_key == key,
            NetworkBootMedia.version == version,
        )
    ).scalar_one_or_none()
    replaced_directory: Path | None = None
    superseded_directories: list[Path] = []
    if existing is not None:
        if _verified_cached_media(existing, media_root=media_root) is not None:
            if defer_filesystem_commit:
                return DeferredNetworkBootMediaSync(
                    media=existing,
                    final_dir=Path(existing.installed_path),
                    backup_dir=None,
                    filesystem_changed=False,
                )
            return existing
        if (
            key == "shredos"
            and state is not None
            and state.active_version == version
        ):
            if active_snapshot is None:
                raise ValueError(
                    "Active same-version media cannot be repaired until its "
                    "applied snapshot is available."
                )
            if active_snapshot.installed_path != existing.installed_path:
                pending_directory = Path(existing.installed_path)
                if (
                    not pending_directory.is_symlink()
                    and pending_directory.is_dir()
                ):
                    resolved_pending = pending_directory.resolve()
                    if resolved_pending.parent == environment_root:
                        superseded_directories.append(resolved_pending)
            descriptor_sha256 = str(descriptor.get("sha256") or "")
            if not re.fullmatch(r"[0-9a-f]{64}", descriptor_sha256):
                raise ValueError(
                    "Active same-version media requires a verified replacement digest."
                )
            final_directory_name = (
                f"{version}.sha256-{descriptor_sha256[:12]}-"
                f"{transaction_id[:12]}"
            )
        else:
            replaced_directory = _enumerated_media_directory(
                environment_key=key,
                version=version,
                media_root=media_root,
            )
    else:
        replaced_directory = _enumerated_media_directory(
            environment_key=key,
            version=version,
            media_root=media_root,
        )
    final_dir = (environment_root / final_directory_name).resolve()
    if not final_dir.is_relative_to(environment_root):
        raise ValueError("Boot media install path escaped the environment cache.")
    if (
        existing is None
        and replaced_directory is None
        and final_dir.exists()
    ):
        raise ValueError(
            "Boot media cache path is unsafe; remove it manually before retrying."
        )
    if (
        final_directory_name != version
        and final_dir.exists()
    ):
        raise ValueError(
            "The verified same-version media replacement already exists."
        )
    media_root_path = environment_root.parent
    media_root_exists = media_root_path.exists()
    media_root_path.mkdir(parents=True, exist_ok=True)
    if not media_root_exists:
        _fsync_directory(media_root_path.parent)
    environment_root_exists = environment_root.exists()
    environment_root.mkdir(exist_ok=True)
    if not environment_root_exists:
        _fsync_directory(media_root_path)
    media_swap_lock: _MediaSwapRecoveryLock | None = None
    with (
        tempfile.TemporaryDirectory(
            prefix=f".atlaso-{key}-{transaction_id}-",
            dir=environment_root,
        ) as temp_dir,
        _MediaStagingLease(Path(temp_dir)),
    ):
        temporary = Path(temp_dir)
        artifact = temporary / descriptor["filename"]
        acquisition = "download"
        if uploaded_artifact is not None:
            if (
                uploaded_artifact.is_symlink()
                or not uploaded_artifact.is_file()
                or uploaded_artifact.stat().st_size <= 0
                or uploaded_artifact.stat().st_size > NETWORK_BOOT_UPLOAD_MAX_BYTES
            ):
                raise ValueError(
                    "Uploaded boot media is empty, unsafe, or exceeds the 2 GiB limit."
                )
            digest = hashlib.sha256()
            with uploaded_artifact.open("rb") as source, artifact.open("wb") as target:
                while chunk := source.read(1024 * 1024):
                    raise_if_cancelled()
                    digest.update(chunk)
                    target.write(chunk)
            artifact_sha256 = digest.hexdigest()
            acquisition = "upload"
        else:
            _final_url, artifact_sha256 = BoundedHttpsDownloader().download(
                descriptor["asset_url"],
                artifact,
                cancelled=cancelled,
            )
        expected_sha256 = descriptor.get("sha256", "")
        if descriptor.get("checksum_url"):
            checksum_path = temporary / "CHECKSUMS.TXT"
            signature_path = temporary / "CHECKSUMS.TXT.gpg"
            public_key_path = temporary / "signing-key.asc"
            BoundedHttpsDownloader(max_bytes=4 * 1024 * 1024).download(
                descriptor["checksum_url"],
                checksum_path,
                cancelled=cancelled,
            )
            if descriptor.get("signature_url"):
                BoundedHttpsDownloader(max_bytes=4 * 1024 * 1024).download(
                    descriptor["signature_url"],
                    signature_path,
                    cancelled=cancelled,
                )
                BoundedHttpsDownloader(max_bytes=4 * 1024 * 1024).download(
                    entry.signing_key_url,
                    public_key_path,
                    cancelled=cancelled,
                )
                verify_signed_checksum(
                    checksum_path,
                    signature_path,
                    public_key_path,
                    fingerprint=entry.signing_fingerprint,
                )
            expected_sha256 = checksum_for_filename(
                checksum_path.read_text(encoding="utf-8"),
                descriptor["filename"],
            )
        if not secrets.compare_digest(artifact_sha256, expected_sha256):
            raise ValueError("Boot media artifact did not match its verified SHA-256 digest.")
        expected_size = descriptor.get("size")
        if expected_size is not None and artifact.stat().st_size != int(expected_size):
            raise ValueError("Boot media artifact did not match its verified size.")
        staging = temporary / "install"
        staging.mkdir()
        extracted: list[str]
        if key == "inventory":
            with zipfile.ZipFile(artifact) as archive:
                try:
                    source_manifest = json.loads(archive.read("manifest.json"))
                except (KeyError, json.JSONDecodeError, UnicodeDecodeError) as exc:
                    raise ValueError(
                        "Atlaso Inventory Linux package manifest is missing or invalid."
                    ) from exc
            if (
                source_manifest.get("kind") != "atlaso-inventory-linux"
                or source_manifest.get("schema_version") != 1
                or normalize_version(str(source_manifest.get("version") or "")) != version
            ):
                raise ValueError("Atlaso Inventory Linux package identity is invalid.")
            source_hashes = source_manifest.get("artifacts")
            if not isinstance(source_hashes, dict):
                raise ValueError("Atlaso Inventory Linux package artifact manifest is invalid.")
            source_boot = source_manifest.get("boot")
            source_boot_arguments = (
                source_boot.get("arguments")
                if isinstance(source_boot, dict)
                else None
            )
            if source_boot_arguments is not None and (
                not isinstance(source_boot_arguments, str)
                or not source_boot_arguments
                or len(source_boot_arguments) > 4096
                or re.search(r"[\x00-\x1f\x7f]", source_boot_arguments)
            ):
                raise ValueError(
                    "Atlaso Inventory Linux package boot arguments are invalid."
                )
            extracted = _extract_zip_allowlist(
                artifact,
                staging,
                allowed_names={
                    "bzImage": "bzImage",
                    "rootfs.cpio.gz": "rootfs.cpio.gz",
                },
            )
            for filename in extracted:
                expected = str(source_hashes.get(filename) or "").lower()
                if not secrets.compare_digest(_file_sha256(staging / filename), expected):
                    raise ValueError(
                        f"Atlaso Inventory Linux package artifact {filename} failed SHA-256 verification."
                    )
        elif key == "memtest86plus":
            member = next(
                (
                    name
                    for name in zipfile.ZipFile(artifact).namelist()
                    if name.endswith("_x86_64")
                ),
                "",
            )
            if not member:
                raise ValueError("Memtest86+ archive is missing the x86-64 PXE binary.")
            extracted = _extract_zip_allowlist(
                artifact,
                staging,
                allowed_names={member: "memtest86plus"},
            )
        elif key in {"gparted", "clonezilla"}:
            extracted = _extract_zip_allowlist(
                artifact,
                staging,
                allowed_names={
                    "live/vmlinuz": "vmlinuz",
                    "live/initrd.img": "initrd.img",
                    "live/filesystem.squashfs": "filesystem.squashfs",
                },
            )
        else:
            extracted = _extract_shredos_kernel(artifact, staging)
            boot_script = staging / "boot.ipxe"
            boot_script.write_text(
                "#!ipxe\n"
                f"kernel /pxe/media/{key}/{final_directory_name}/shredos "
                "console=tty3 loglevel=3 || exit\n"
                "boot || exit\n",
                encoding="utf-8",
            )
            boot_script.chmod(0o644)
            extracted.append("boot.ipxe")
        manifest = _media_boot_manifest(
            key,
            final_directory_name,
            extracted=extracted,
        )
        if key == "inventory" and source_boot_arguments is not None:
            manifest["boot"]["arguments"] = source_boot_arguments
        manifest.update(
            {
                "kind": "atlaso-network-boot-media",
                "schema_version": NETWORK_BOOT_SCHEMA_VERSION,
                "environment": key,
                "version": version,
                "source_url": descriptor["asset_url"],
                "sha256": artifact_sha256,
                "verification_method": entry.verification_method,
                "license": entry.license_name,
                "verified_at": utcnow().isoformat(),
                "acquisition": acquisition,
                "uploaded_filename": Path(uploaded_filename).name
                if acquisition == "upload"
                else "",
                "artifacts": {
                    filename: _file_sha256(staging / filename)
                    for filename in extracted
                },
            }
        )
        (staging / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        raise_if_cancelled()
        _fsync_media_tree(staging)
        final_dir.parent.mkdir(parents=True, exist_ok=True)
        media_swap_lock = _MediaSwapRecoveryLock(media_root_path)
        media_swap_lock.acquire()
        try:
            journal_path = _write_media_swap_journal(
                final_dir.parent,
                environment_key=key,
                version=version,
                final_directory=final_dir.name,
                transaction_id=transaction_id,
                staging_directory=temporary.name,
            )
        except Exception:
            media_swap_lock.release()
            raise
        backup_dir: Path | None = None
        backup_moved = False
        replacement_published = False
        try:
            if replaced_directory is not None:
                backup_dir = (
                    final_dir.parent
                    / f".{version}.replacement-{transaction_id}"
                )
                replaced_directory.replace(backup_dir)
                backup_moved = True
            staging.replace(final_dir)
            replacement_published = True
            _fsync_directory(final_dir.parent)
        except OSError as exc:
            if replacement_published and final_dir.exists():
                shutil.rmtree(final_dir)
            if backup_moved and backup_dir is not None and backup_dir.exists():
                backup_dir.replace(final_dir)
            _fsync_directory(final_dir.parent)
            journal_path.unlink(missing_ok=True)
            _fsync_directory(final_dir.parent)
            media_swap_lock.release()
            if replacement_published or final_dir.exists():
                raise ValueError("Immutable boot media version already exists.") from exc
            raise
    filesystem_sync: DeferredNetworkBootMediaSync | None = None
    try:
        if existing is not None:
            db.delete(existing)
            db.flush()
        media = record_verified_media(
            db,
            environment_key=key,
            version=version,
            source_url=descriptor["asset_url"],
            artifact_sha256=artifact_sha256,
            installed_path=str(final_dir),
            manifest=manifest,
        )
        filesystem_sync = DeferredNetworkBootMediaSync(
            media=media,
            final_dir=final_dir,
            backup_dir=backup_dir,
            superseded_dirs=tuple(superseded_directories),
            journal_path=journal_path,
            recovery_lock=media_swap_lock,
        )
    except Exception:
        if final_dir.exists():
            shutil.rmtree(final_dir)
        if backup_dir is not None and backup_dir.exists():
            backup_dir.replace(final_dir)
        _fsync_directory(final_dir.parent)
        journal_path.unlink(missing_ok=True)
        _fsync_directory(final_dir.parent)
        if media_swap_lock is not None:
            media_swap_lock.release()
        raise
    if defer_filesystem_commit:
        return filesystem_sync
    try:
        db.commit()
    except Exception:
        db.rollback()
        filesystem_sync.rollback_filesystem()
        raise
    filesystem_sync.commit_filesystem()
    return media
