from __future__ import annotations

import hashlib
import json
import re
import secrets
import shutil
import subprocess
import tempfile
import urllib.parse
import urllib.request
import uuid
import zipfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable

from sqlalchemy import delete, desc, func, select
from sqlalchemy.orm import Session

from atlaso.app.models import (
    EsxiPxeHost,
    NetworkBootDiscoveredHost,
    NetworkBootEnvironment,
    NetworkBootInventoryCommand,
    NetworkBootInventoryReport,
    NetworkBootInventorySession,
    NetworkBootMedia,
    utcnow,
)
from atlaso.app.services.esxi_pxe import (
    esxi_http_base_url,
    esxi_pxe_boot_settings,
    esxi_pxe_default_host_settings,
    esxi_pxe_host_artifacts,
    normalize_pxe_mac,
)


NETWORK_BOOT_SCHEMA_VERSION = 1
NETWORK_BOOT_REPORT_MAX_BYTES = 256 * 1024
NETWORK_BOOT_MAX_DISKS = 128
NETWORK_BOOT_MAX_INTERFACES = 64
NETWORK_BOOT_REPORTS_PER_HOST = 11
NETWORK_BOOT_MAX_HOSTS = 512
NETWORK_BOOT_MAX_REPORTS = 2048
NETWORK_BOOT_MAX_SESSIONS = 4096
NETWORK_BOOT_SESSION_LIFETIME = timedelta(hours=8)
NETWORK_BOOT_ONLINE_THRESHOLD = timedelta(seconds=30)
NETWORK_BOOT_MEDIA_ROOT = Path("/var/lib/atlaso/pxe/media")
NETWORK_BOOT_UPLOAD_ROOT = Path("/var/lib/atlaso/pxe/uploads")
NETWORK_BOOT_UPLOAD_MAX_BYTES = 2 * 1024 * 1024 * 1024
NETWORK_BOOT_HTTP_ROOT = Path("/var/lib/atlaso/pxe/http")
NETWORK_BOOT_STAGED_CONFIG_PATH = "/var/lib/atlaso/apply/esxi-pxe/atlaso-esxi-pxe.json"
NETWORK_BOOT_UNIT_ID = "esxi_pxe"

UUID_PLACEHOLDERS = {
    "00000000-0000-0000-0000-000000000000",
    "ffffffff-ffff-ffff-ffff-ffffffffffff",
    "03000200-0400-0500-0006-000700080009",
}
MAC_PATTERN = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")
VERSION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,118}[A-Za-z0-9]$")


@dataclass(frozen=True)
class EnvironmentCatalogEntry:
    key: str
    label: str
    description: str
    risk: str
    license_name: str
    verification_method: str
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
        verification_method="Atlaso reproducible build manifest and SHA-256",
        release_page="https://buildroot.org/download.html",
    ),
    EnvironmentCatalogEntry(
        key="memtest86plus",
        label="Memtest86+",
        description="Interactive memory diagnostics.",
        risk="diagnostic",
        license_name="GPL-2.0-only",
        verification_method="upstream-published SHA-256",
        release_page="https://www.memtest.org/",
    ),
    EnvironmentCatalogEntry(
        key="shredos",
        label="ShredOS",
        description="Interactive disk erasure with an independent warning menu.",
        risk="destructive",
        license_name="GPL-3.0-or-later and bundled component licenses",
        verification_method="GitHub release-asset SHA-256 digest",
        release_page="https://github.com/PartialVolume/shredos.x86_64/releases/latest",
    ),
    EnvironmentCatalogEntry(
        key="gparted",
        label="GParted Live",
        description="Interactive partition management.",
        risk="destructive",
        license_name="GPL-2.0-or-later and bundled component licenses",
        verification_method="signed checksum file and SHA-256",
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
        release_page="https://clonezilla.org/downloads.php",
        signing_fingerprint="54C0821A48715DAFD61BFCAF667857D045599AFD",
        signing_key_url="https://keyserver.ubuntu.com/pks/lookup?op=get&options=mr&search=0x54C0821A48715DAFD61BFCAF667857D045599AFD",
    ),
)
CATALOG_BY_KEY = {entry.key: entry for entry in ENVIRONMENT_CATALOG}


class NetworkBootMediaSyncCancelled(RuntimeError):
    """Raised when an operator cancels media acquisition before installation."""


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
                "signing_fingerprint": entry.signing_fingerprint,
                "release_page": entry.release_page,
                "enabled": bool(state.enabled),
                "desired_version": state.desired_version,
                "active_version": state.active_version,
                "ready": bool(state.enabled and active),
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
    candidates = sorted(
        (
            path
            for path in inventory_root.iterdir()
            if path.is_dir() and (path / "manifest.json").is_file()
        ),
        reverse=True,
    )
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
            state = db.get(NetworkBootEnvironment, "inventory")
            if state is not None and not state.desired_version and not state.active_version:
                state.enabled = True
                state.desired_version = version
                state.updated_at = utcnow()
                db.add(state)
            return media
        except (OSError, ValueError, json.JSONDecodeError):
            continue
    return None


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
    try:
        normalized = int(value or 0)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be an integer.") from exc
    if normalized < minimum or normalized > maximum:
        raise ValueError(f"{field} is outside the supported range.")
    return normalized


def _string_list(value: Any, field: str, *, maximum_items: int, maximum_length: int = 128) -> list[str]:
    if value in (None, ""):
        return []
    if not isinstance(value, list) or len(value) > maximum_items:
        raise ValueError(f"{field} must contain at most {maximum_items} values.")
    return [_bounded_string(item, field, maximum=maximum_length) for item in value]


def normalize_inventory_report(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("Inventory report must be a JSON object.")
    encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(encoded) > NETWORK_BOOT_REPORT_MAX_BYTES:
        raise ValueError("Inventory report exceeds the 256 KiB limit.")
    schema_version = _bounded_integer(payload.get("schema_version"), "schema_version", minimum=1, maximum=1)
    system = payload.get("system")
    cpu = payload.get("cpu")
    memory = payload.get("memory")
    disks = payload.get("disks", [])
    interfaces = payload.get("interfaces", [])
    if not isinstance(system, dict) or not isinstance(cpu, dict) or not isinstance(memory, dict):
        raise ValueError("Inventory report requires system, cpu, and memory objects.")
    if not isinstance(disks, list) or len(disks) > NETWORK_BOOT_MAX_DISKS:
        raise ValueError(f"Inventory report supports at most {NETWORK_BOOT_MAX_DISKS} disks.")
    if not isinstance(interfaces, list) or len(interfaces) > NETWORK_BOOT_MAX_INTERFACES:
        raise ValueError(f"Inventory report supports at most {NETWORK_BOOT_MAX_INTERFACES} interfaces.")

    normalized_interfaces: list[dict[str, Any]] = []
    for index, row in enumerate(interfaces):
        if not isinstance(row, dict):
            raise ValueError(f"interfaces[{index}] must be an object.")
        permanent_mac = normalize_mac(row.get("permanent_mac"))
        current_mac = normalize_mac(row.get("current_mac"))
        normalized_interfaces.append(
            {
                "name": _bounded_string(row.get("name"), f"interfaces[{index}].name", maximum=64),
                "permanent_mac": permanent_mac,
                "current_mac": current_mac,
                "driver": _bounded_string(row.get("driver"), f"interfaces[{index}].driver", maximum=120),
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
                "boot_interface": bool(row.get("boot_interface")),
            }
        )

    boot_rows = [row for row in normalized_interfaces if row["boot_interface"]]
    if len(boot_rows) > 1:
        raise ValueError("Only one interface may be marked as the boot interface.")
    boot_mac = normalize_mac(payload.get("boot_mac"))
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
                "rotational": bool(row.get("rotational")),
                "removable": bool(row.get("removable")),
                "read_only": bool(row.get("read_only")),
            }
        )

    return {
        "schema_version": schema_version,
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
            "bios_vendor": _bounded_string(system.get("bios_vendor"), "system.bios_vendor", maximum=240),
            "bios_version": _bounded_string(system.get("bios_version"), "system.bios_version", maximum=240),
            "bios_date": _bounded_string(system.get("bios_date"), "system.bios_date", maximum=64),
        },
        "cpu": {
            "architecture": _bounded_string(cpu.get("architecture"), "cpu.architecture", maximum=64),
            "vendor": _bounded_string(cpu.get("vendor"), "cpu.vendor", maximum=120),
            "model": _bounded_string(cpu.get("model"), "cpu.model", maximum=500),
            "sockets": _bounded_integer(cpu.get("sockets"), "cpu.sockets", maximum=4096),
            "cores": _bounded_integer(cpu.get("cores"), "cpu.cores", maximum=65536),
            "threads": _bounded_integer(cpu.get("threads"), "cpu.threads", maximum=131072),
        },
        "memory": {
            "total_bytes": _bounded_integer(memory.get("total_bytes"), "memory.total_bytes"),
        },
        "disks": normalized_disks,
        "interfaces": normalized_interfaces,
    }


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
    retained_hosts: list[int] = []
    retained_reports = 0
    for host_id, report_count in host_rows:
        count = int(report_count or 0)
        if host_id == preserve_host_id or (
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
        or command.status != "delivered"
        or _as_utc(command.expires_at) <= utcnow()
    ):
        raise ValueError("Inventory command is missing, expired, or was not delivered.")
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
) -> dict[str, Any]:
    session = latest_live_session(db, host.id)
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
    }
    if include_report and host.latest_report_id:
        report = db.get(NetworkBootInventoryReport, host.latest_report_id)
        payload["latest_report"] = (
            json.loads(report.payload_json) if report is not None else None
        )
    return payload


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


def _active_media(
    db: Session,
) -> dict[str, NetworkBootMedia]:
    states = ensure_environment_rows(db)
    result: dict[str, NetworkBootMedia] = {}
    for state in states:
        if not state.enabled or not state.active_version:
            continue
        media = db.execute(
            select(NetworkBootMedia).where(
                NetworkBootMedia.environment_key == state.key,
                NetworkBootMedia.version == state.active_version,
            )
        ).scalar_one_or_none()
        if media is not None:
            result[state.key] = media
    return result


def _chain_line(
    media: NetworkBootMedia,
    *,
    http_origin: str,
) -> str:
    manifest = json.loads(media.manifest_json or "{}")
    boot = manifest.get("boot") if isinstance(manifest.get("boot"), dict) else {}
    if media.environment_key == "shredos":
        return (
            "sanboot --no-describe "
            f"{http_origin}/pxe/media/shredos/{media.version}/shredos.img"
        )
    kernel = str(boot.get("kernel") or "")
    initrd = str(boot.get("initrd") or "")
    arguments = str(boot.get("arguments") or "").strip()
    if kernel.startswith("/"):
        kernel = f"{http_origin}{kernel}"
    if initrd.startswith("/"):
        initrd = f"{http_origin}{initrd}"
    arguments = arguments.replace("fetch=/", f"fetch={http_origin}/")
    if media.environment_key == "inventory":
        arguments = f"{arguments} atlaso.url={http_origin}".strip()
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


def render_network_boot_menu(
    db: Session,
    *,
    mac_address: str = "",
    firmware: str = "",
) -> str:
    mac = normalize_mac(mac_address) if mac_address else ""
    mac_key = normalize_pxe_mac(mac) if mac else ""
    hosts = db.execute(select(EsxiPxeHost).order_by(EsxiPxeHost.hostname)).scalars().all()
    boot = esxi_pxe_boot_settings(db)
    default_host = esxi_pxe_default_host_settings(db)
    artifacts = esxi_pxe_host_artifacts(hosts, boot, default_host)
    esxi_base_url = esxi_http_base_url(boot)
    parsed_base = urllib.parse.urlsplit(esxi_base_url)
    http_origin = (
        f"{parsed_base.scheme}://{parsed_base.netloc}"
        if parsed_base.scheme and parsed_base.netloc
        else ""
    )
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
    default_label = "esxi_assigned" if assigned else "inventory"
    lines = [
        "#!ipxe",
        ":menu",
        "menu Atlaso Network Boot",
        "item --gap -- ---------------- Safe inventory ----------------",
        "item inventory Atlaso Inventory Linux",
    ]
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
    inventory = active.get("inventory")
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
                f"chain {esxi_base_url}/{assigned['mac_key']}/boot.cfg || goto menu",
                "",
            ]
        )
    for artifact in esxi_manual:
        lines.extend(
            [
                f":esxi_{artifact['host_id']}",
                f"chain {esxi_base_url}/{artifact['mac_key']}/boot.cfg || goto menu",
                "",
            ]
        )
    if undefined:
        lines.extend(
            [
                ":esxi_default",
                f"chain {esxi_base_url}/boot.cfg || goto menu",
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
    ):
        self.max_bytes = max_bytes
        self.timeout_seconds = timeout_seconds
        self.max_redirects = max_redirects

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
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "Atlaso-Network-Boot/1"},
        )
        opener = urllib.request.build_opener(
            _BoundedHttpsRedirectHandler(self.max_redirects)
        )
        response = opener.open(request, timeout=self.timeout_seconds)
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
        candidate = parts[-1].lstrip("*")
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


def _fetch_https_text(url: str, *, max_bytes: int = 2 * 1024 * 1024) -> str:
    with tempfile.TemporaryDirectory(prefix="atlaso-network-boot-resolve-") as temp_dir:
        path = Path(temp_dir) / "response"
        BoundedHttpsDownloader(
            max_bytes=max_bytes,
            timeout_seconds=30,
            max_redirects=3,
        ).download(url, path)
        return path.read_text(encoding="utf-8")


def _release_descriptor(environment_key: str) -> dict[str, str]:
    key = normalize_environment_key(environment_key)
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
                and re.search(r"x86-64.*\.img$", str(row.get("name") or ""))
                and "lite" not in str(row.get("name") or "").lower()
            ),
            None,
        )
        digest = str((asset or {}).get("digest") or "")
        if not asset or not digest.startswith("sha256:"):
            raise ValueError("ShredOS stable image does not publish a SHA-256 asset digest.")
        return {
            "version": str(payload.get("tag_name") or "").removeprefix("v"),
            "filename": str(asset["name"]),
            "asset_url": str(asset["browser_download_url"]),
            "sha256": digest.removeprefix("sha256:").lower(),
        }
    raise ValueError("Atlaso Inventory Linux is built and shipped with the appliance.")


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


def _media_boot_manifest(
    environment_key: str,
    version: str,
    *,
    extracted: Iterable[str],
) -> dict[str, Any]:
    base = f"/pxe/media/{environment_key}/{version}"
    files = list(extracted)
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
            "noswap",
            "noeject",
            "ip=dhcp",
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
    directory = _enumerated_media_directory(
        environment_key=media.environment_key,
        version=media.version,
        media_root=media_root,
    )
    if directory is None or str(directory) != media.installed_path:
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


def sync_network_boot_media(
    db: Session,
    *,
    environment_key: str,
    media_root: Path = NETWORK_BOOT_MEDIA_ROOT,
    uploaded_artifact: Path | None = None,
    uploaded_filename: str = "",
    cancelled: Callable[[], bool] | None = None,
) -> NetworkBootMedia:
    def raise_if_cancelled() -> None:
        if cancelled and cancelled():
            raise NetworkBootMediaSyncCancelled(
                "Network Boot media task was cancelled."
            )

    raise_if_cancelled()
    key = normalize_environment_key(environment_key)
    if key == "inventory":
        raise ValueError("Atlaso Inventory Linux is built and shipped with the appliance.")
    descriptor = _release_descriptor(key)
    raise_if_cancelled()
    version = normalize_version(descriptor["version"])
    entry = CATALOG_BY_KEY[key]
    final_dir = (media_root / key / version).resolve()
    environment_root = (media_root / key).resolve()
    if not final_dir.is_relative_to(environment_root):
        raise ValueError("Boot media install path escaped the environment cache.")
    existing = db.execute(
        select(NetworkBootMedia).where(
            NetworkBootMedia.environment_key == key,
            NetworkBootMedia.version == version,
        )
    ).scalar_one_or_none()
    if existing is not None:
        if _verified_cached_media(existing, media_root=media_root) is not None:
            return existing
        stale_directory = _enumerated_media_directory(
            environment_key=key,
            version=version,
            media_root=media_root,
        )
        if stale_directory is not None:
            shutil.rmtree(stale_directory)
        db.delete(existing)
        db.flush()
    else:
        orphaned_directory = _enumerated_media_directory(
            environment_key=key,
            version=version,
            media_root=media_root,
        )
        if orphaned_directory is not None:
            shutil.rmtree(orphaned_directory)
        elif final_dir.exists():
            raise ValueError(
                "Boot media cache path is unsafe; remove it manually before retrying."
            )
    with tempfile.TemporaryDirectory(prefix=f"atlaso-{key}-") as temp_dir:
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
        staging = temporary / "install"
        staging.mkdir()
        extracted: list[str]
        if key == "memtest86plus":
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
            target = staging / "shredos.img"
            shutil.copy2(artifact, target)
            target.chmod(0o644)
            boot_script = staging / "boot.ipxe"
            boot_script.write_text(
                "#!ipxe\nsanboot --no-describe "
                f"/pxe/media/{key}/{version}/shredos.img || exit\n",
                encoding="utf-8",
            )
            boot_script.chmod(0o644)
            extracted = ["shredos.img", "boot.ipxe"]
        manifest = _media_boot_manifest(key, version, extracted=extracted)
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
        final_dir.parent.mkdir(parents=True, exist_ok=True)
        try:
            staging.replace(final_dir)
        except OSError as exc:
            if final_dir.exists():
                raise ValueError("Immutable boot media version already exists.") from exc
            raise
    raise_if_cancelled()
    return record_verified_media(
        db,
        environment_key=key,
        version=version,
        source_url=descriptor["asset_url"],
        artifact_sha256=artifact_sha256,
        installed_path=str(final_dir),
        manifest=manifest,
    )
