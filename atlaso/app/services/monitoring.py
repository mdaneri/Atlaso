from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import threading
import time
from typing import Any

from sqlalchemy import desc, delete, select
from sqlalchemy.orm import Session, selectinload

from atlaso.app.config import Settings, get_settings
from atlaso.app.database import SessionLocal
from atlaso.app.models import MonitorCpuSample, MonitorDiskSample, MonitorNetworkSample, MonitorSample, utcnow


SECTOR_SIZE = 512
VIRTUAL_FILESYSTEMS = {
    "autofs",
    "binfmt_misc",
    "bpf",
    "cgroup",
    "cgroup2",
    "configfs",
    "debugfs",
    "devpts",
    "devtmpfs",
    "efivarfs",
    "fusectl",
    "hugetlbfs",
    "mqueue",
    "proc",
    "pstore",
    "securityfs",
    "selinuxfs",
    "sysfs",
    "tmpfs",
    "tracefs",
}


@dataclass(frozen=True)
class CpuCounters:
    total: int
    idle: int


@dataclass(frozen=True)
class CpuCoreCounters:
    name: str
    total: int
    idle: int


@dataclass(frozen=True)
class NetworkCounters:
    name: str
    rx_bytes: int
    tx_bytes: int
    rx_packets: int
    tx_packets: int
    rx_errors: int
    tx_errors: int
    rx_dropped: int
    tx_dropped: int
    oper_state: str = "unknown"


@dataclass(frozen=True)
class DiskCounters:
    device: str
    read_bytes: int
    write_bytes: int


@dataclass(frozen=True)
class DiskUsage:
    mount_point: str
    device: str
    filesystem: str
    total_bytes: int
    used_bytes: int
    free_bytes: int
    used_percent: float | None
    read_bytes: int = 0
    write_bytes: int = 0


@dataclass(frozen=True)
class MonitorSnapshot:
    sampled_at: datetime
    cpu: CpuCounters | None = None
    cpus: list[CpuCoreCounters] = field(default_factory=list)
    cpu_count: int = 0
    load: tuple[float | None, float | None, float | None] = (None, None, None)
    memory_total_bytes: int = 0
    memory_available_bytes: int = 0
    memory_used_percent: float | None = None
    swap_total_bytes: int = 0
    swap_used_bytes: int = 0
    networks: list[NetworkCounters] = field(default_factory=list)
    disks: list[DiskUsage] = field(default_factory=list)


def ensure_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def parse_proc_stat_cpu(text: str) -> CpuCounters | None:
    for line in text.splitlines():
        if not line.startswith("cpu "):
            continue
        values = [int(value) for value in line.split()[1:] if value.isdigit()]
        if len(values) < 4:
            return None
        idle = values[3] + (values[4] if len(values) > 4 else 0)
        total = sum(values[:8]) if len(values) >= 8 else sum(values)
        return CpuCounters(total=total, idle=idle)
    return None


def parse_proc_stat_cpus(text: str) -> list[CpuCoreCounters]:
    cpus: list[CpuCoreCounters] = []
    for line in text.splitlines():
        parts = line.split()
        if not parts or not parts[0].startswith("cpu") or not parts[0][3:].isdigit():
            continue
        try:
            values = [int(value) for value in parts[1:]]
        except ValueError:
            continue
        if len(values) < 4:
            continue
        idle = values[3] + (values[4] if len(values) > 4 else 0)
        total = sum(values[:8]) if len(values) >= 8 else sum(values)
        cpus.append(CpuCoreCounters(name=parts[0], total=total, idle=idle))
    return cpus


def cpu_percent(previous: CpuCounters | None, current: CpuCounters | None) -> float | None:
    if previous is None or current is None:
        return None
    total_delta = current.total - previous.total
    idle_delta = current.idle - previous.idle
    if total_delta <= 0 or idle_delta < 0:
        return None
    return round(max(0.0, min(100.0, 100.0 * (1.0 - idle_delta / total_delta))), 2)


def parse_loadavg(text: str) -> tuple[float | None, float | None, float | None]:
    parts = text.split()
    values: list[float | None] = []
    for raw in parts[:3]:
        try:
            values.append(float(raw))
        except ValueError:
            values.append(None)
    while len(values) < 3:
        values.append(None)
    return values[0], values[1], values[2]


def parse_meminfo(text: str) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, raw_value = line.split(":", 1)
        parts = raw_value.strip().split()
        if not parts:
            continue
        try:
            amount = int(parts[0])
        except ValueError:
            continue
        values[key] = amount * 1024
    return values


def parse_net_dev(text: str) -> list[NetworkCounters]:
    rows: list[NetworkCounters] = []
    for line in text.splitlines():
        if ":" not in line:
            continue
        name, raw_values = line.split(":", 1)
        values = raw_values.split()
        if len(values) < 16:
            continue
        try:
            rows.append(
                NetworkCounters(
                    name=name.strip(),
                    rx_bytes=int(values[0]),
                    rx_packets=int(values[1]),
                    rx_errors=int(values[2]),
                    rx_dropped=int(values[3]),
                    tx_bytes=int(values[8]),
                    tx_packets=int(values[9]),
                    tx_errors=int(values[10]),
                    tx_dropped=int(values[11]),
                )
            )
        except ValueError:
            continue
    return rows


def parse_diskstats(text: str) -> dict[str, DiskCounters]:
    counters: dict[str, DiskCounters] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 10:
            continue
        device = parts[2]
        try:
            read_sectors = int(parts[5])
            write_sectors = int(parts[9])
        except ValueError:
            continue
        counters[device] = DiskCounters(
            device=device,
            read_bytes=read_sectors * SECTOR_SIZE,
            write_bytes=write_sectors * SECTOR_SIZE,
        )
    return counters


def rate_per_second(previous_value: int, current_value: int, elapsed_seconds: float) -> float | None:
    if elapsed_seconds <= 0 or current_value < previous_value:
        return None
    return round((current_value - previous_value) / elapsed_seconds, 2)


class SystemMetricsCollector:
    def __init__(self, *, proc_path: Path | None = None, sys_path: Path | None = None, settings: Settings | None = None) -> None:
        self.proc_path = proc_path or Path("/proc")
        self.sys_path = sys_path or Path("/sys")
        self.settings = settings or get_settings()

    def collect(self, sampled_at: datetime | None = None) -> MonitorSnapshot:
        sampled_at = sampled_at or utcnow()
        cpu, cpus = self._read_cpu()
        memory = self._read_memory()
        return MonitorSnapshot(
            sampled_at=sampled_at,
            cpu=cpu,
            cpus=cpus,
            cpu_count=len(cpus) or os.cpu_count() or 0,
            load=self._read_load(),
            memory_total_bytes=memory["total"],
            memory_available_bytes=memory["available"],
            memory_used_percent=memory["used_percent"],
            swap_total_bytes=memory["swap_total"],
            swap_used_bytes=memory["swap_used"],
            networks=self._read_networks(),
            disks=self._read_disks(),
        )

    def collect_virtualization(self) -> dict[str, Any]:
        dmi_root = self.sys_path / "class" / "dmi" / "id"
        dmi = {
            key: self._read_text(dmi_root / key)
            for key in ("sys_vendor", "product_name", "product_version", "product_serial", "chassis_asset_tag")
        }
        virt = self._run_text(["systemd-detect-virt", "--vm"])
        vmtools_version = self._run_text(["vmtoolsd", "-v"])
        vendor = dmi.get("sys_vendor") or ""
        product = dmi.get("product_name") or ""
        detected = virt or ("vmware" if "vmware" in f"{vendor} {product}".lower() else "")
        return {
            "detected": detected or "unknown",
            "sys_vendor": vendor,
            "product_name": product,
            "product_version": dmi.get("product_version") or "",
            "product_serial": dmi.get("product_serial") or "",
            "chassis_asset_tag": dmi.get("chassis_asset_tag") or "",
            "vmtools_version": vmtools_version or "",
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
        }

    def _read_cpu(self) -> tuple[CpuCounters | None, list[CpuCoreCounters]]:
        text = self._read_text(self.proc_path / "stat")
        if not text:
            return None, []
        return parse_proc_stat_cpu(text), parse_proc_stat_cpus(text)

    def _read_load(self) -> tuple[float | None, float | None, float | None]:
        text = self._read_text(self.proc_path / "loadavg")
        return parse_loadavg(text) if text else (None, None, None)

    def _read_memory(self) -> dict[str, int | float | None]:
        text = self._read_text(self.proc_path / "meminfo")
        values = parse_meminfo(text) if text else {}
        total = int(values.get("MemTotal", 0))
        available = int(values.get("MemAvailable", values.get("MemFree", 0)))
        used_percent = round(100.0 * (total - available) / total, 2) if total > 0 else None
        swap_total = int(values.get("SwapTotal", 0))
        swap_free = int(values.get("SwapFree", 0))
        return {
            "total": total,
            "available": available,
            "used_percent": used_percent,
            "swap_total": swap_total,
            "swap_used": max(0, swap_total - swap_free),
        }

    def _read_networks(self) -> list[NetworkCounters]:
        text = self._read_text(self.proc_path / "net" / "dev")
        rows = parse_net_dev(text) if text else []
        with_state: list[NetworkCounters] = []
        for row in rows:
            if row.name == "lo":
                continue
            state = self._read_text(self.sys_path / "class" / "net" / row.name / "operstate") or row.oper_state
            with_state.append(
                NetworkCounters(
                    name=row.name,
                    rx_bytes=row.rx_bytes,
                    tx_bytes=row.tx_bytes,
                    rx_packets=row.rx_packets,
                    tx_packets=row.tx_packets,
                    rx_errors=row.rx_errors,
                    tx_errors=row.tx_errors,
                    rx_dropped=row.rx_dropped,
                    tx_dropped=row.tx_dropped,
                    oper_state=state.strip() or "unknown",
                )
            )
        return with_state

    def _read_disks(self) -> list[DiskUsage]:
        diskstats = parse_diskstats(self._read_text(self.proc_path / "diskstats") or "")
        mounts = self._read_mounts()
        rows: list[DiskUsage] = []
        seen_mounts: set[str] = set()
        for device, mount_point, filesystem in mounts:
            if mount_point in seen_mounts:
                continue
            seen_mounts.add(mount_point)
            try:
                usage = shutil.disk_usage(mount_point)
            except OSError:
                continue
            stats = diskstats.get(Path(device).name)
            used = usage.total - usage.free
            used_percent = round(100.0 * used / usage.total, 2) if usage.total > 0 else None
            rows.append(
                DiskUsage(
                    mount_point=mount_point,
                    device=device,
                    filesystem=filesystem,
                    total_bytes=usage.total,
                    used_bytes=used,
                    free_bytes=usage.free,
                    used_percent=used_percent,
                    read_bytes=stats.read_bytes if stats else 0,
                    write_bytes=stats.write_bytes if stats else 0,
                )
            )
        return rows

    def _read_mounts(self) -> list[tuple[str, str, str]]:
        text = self._read_text(self.proc_path / "mounts")
        mounts: list[tuple[str, str, str]] = []
        if text:
            for line in text.splitlines():
                parts = line.split()
                if len(parts) < 3:
                    continue
                device, mount_point, filesystem = parts[0], parts[1].replace("\\040", " "), parts[2]
                if filesystem in VIRTUAL_FILESYSTEMS or not mount_point.startswith("/"):
                    continue
                mounts.append((device, mount_point, filesystem))
        else:
            anchor = str(Path.cwd().anchor or Path.cwd())
            mounts.append((anchor, anchor, "host"))
        important_paths = [Path("/"), Path("/var/lib/atlaso"), self.settings.repository_path, self.settings.vcf_backup_path]
        known_mounts = {mount for _device, mount, _filesystem in mounts}
        for path in important_paths:
            raw = str(path)
            if raw not in known_mounts and path.exists():
                mounts.append((raw, raw, "path"))
        return mounts

    @staticmethod
    def _read_text(path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8").strip()
        except OSError:
            return ""

    @staticmethod
    def _run_text(command: list[str]) -> str:
        try:
            completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=2)
        except (OSError, subprocess.SubprocessError):
            return ""
        if completed.returncode != 0:
            return ""
        return completed.stdout.strip() or completed.stderr.strip()


def record_monitor_sample(db: Session, *, collector: SystemMetricsCollector | None = None, sampled_at: datetime | None = None) -> MonitorSample:
    settings = get_settings()
    collector = collector or SystemMetricsCollector(settings=settings)
    snapshot = collector.collect(sampled_at=sampled_at)
    previous = db.execute(
        select(MonitorSample)
        .options(selectinload(MonitorSample.cpu_samples), selectinload(MonitorSample.network_samples), selectinload(MonitorSample.disk_samples))
        .order_by(desc(MonitorSample.sampled_at), desc(MonitorSample.id))
    ).scalars().first()
    previous_cpu = CpuCounters(previous.cpu_total_jiffies, previous.cpu_idle_jiffies) if previous else None
    elapsed = (ensure_aware(snapshot.sampled_at) - ensure_aware(previous.sampled_at)).total_seconds() if previous else 0
    sample = MonitorSample(
        sampled_at=snapshot.sampled_at,
        cpu_percent=cpu_percent(previous_cpu, snapshot.cpu),
        cpu_count=snapshot.cpu_count,
        cpu_total_jiffies=snapshot.cpu.total if snapshot.cpu else 0,
        cpu_idle_jiffies=snapshot.cpu.idle if snapshot.cpu else 0,
        load1=snapshot.load[0],
        load5=snapshot.load[1],
        load15=snapshot.load[2],
        memory_total_bytes=snapshot.memory_total_bytes,
        memory_available_bytes=snapshot.memory_available_bytes,
        memory_used_percent=snapshot.memory_used_percent,
        swap_total_bytes=snapshot.swap_total_bytes,
        swap_used_bytes=snapshot.swap_used_bytes,
    )
    previous_cpus = {row.cpu_name: row for row in previous.cpu_samples} if previous else {}
    for row in snapshot.cpus:
        old = previous_cpus.get(row.name)
        sample.cpu_samples.append(
            MonitorCpuSample(
                cpu_name=row.name,
                percent=cpu_percent(CpuCounters(old.total_jiffies, old.idle_jiffies), CpuCounters(row.total, row.idle)) if old else None,
                total_jiffies=row.total,
                idle_jiffies=row.idle,
            )
        )
    previous_networks = {row.interface_name: row for row in previous.network_samples} if previous and elapsed > 0 else {}
    for row in snapshot.networks:
        old = previous_networks.get(row.name)
        sample.network_samples.append(
            MonitorNetworkSample(
                interface_name=row.name,
                rx_bytes=row.rx_bytes,
                tx_bytes=row.tx_bytes,
                rx_bytes_per_sec=rate_per_second(old.rx_bytes, row.rx_bytes, elapsed) if old else None,
                tx_bytes_per_sec=rate_per_second(old.tx_bytes, row.tx_bytes, elapsed) if old else None,
                rx_packets=row.rx_packets,
                tx_packets=row.tx_packets,
                rx_errors=row.rx_errors,
                tx_errors=row.tx_errors,
                rx_dropped=row.rx_dropped,
                tx_dropped=row.tx_dropped,
                oper_state=row.oper_state,
            )
        )
    previous_disks = {row.mount_point: row for row in previous.disk_samples} if previous and elapsed > 0 else {}
    for row in snapshot.disks:
        old = previous_disks.get(row.mount_point)
        sample.disk_samples.append(
            MonitorDiskSample(
                mount_point=row.mount_point,
                device=row.device,
                filesystem=row.filesystem,
                total_bytes=row.total_bytes,
                used_bytes=row.used_bytes,
                free_bytes=row.free_bytes,
                used_percent=row.used_percent,
                read_bytes=row.read_bytes,
                write_bytes=row.write_bytes,
                read_bytes_per_sec=rate_per_second(old.read_bytes, row.read_bytes, elapsed) if old else None,
                write_bytes_per_sec=rate_per_second(old.write_bytes, row.write_bytes, elapsed) if old else None,
            )
        )
    db.add(sample)
    db.flush()
    prune_monitor_samples(db, retention_hours=settings.monitor_retention_hours + 1)
    db.commit()
    db.refresh(sample)
    return sample


def prune_monitor_samples(db: Session, *, retention_hours: int) -> int:
    cutoff = utcnow() - timedelta(hours=max(1, retention_hours))
    old_ids = list(db.execute(select(MonitorSample.id).where(MonitorSample.sampled_at < cutoff)).scalars().all())
    if not old_ids:
        return 0
    db.execute(delete(MonitorCpuSample).where(MonitorCpuSample.sample_id.in_(old_ids)))
    db.execute(delete(MonitorNetworkSample).where(MonitorNetworkSample.sample_id.in_(old_ids)))
    db.execute(delete(MonitorDiskSample).where(MonitorDiskSample.sample_id.in_(old_ids)))
    db.execute(delete(MonitorSample).where(MonitorSample.id.in_(old_ids)))
    return len(old_ids)


def ensure_recent_monitor_sample(db: Session, *, collector: SystemMetricsCollector | None = None) -> MonitorSample:
    settings = get_settings()
    latest = db.execute(select(MonitorSample).order_by(desc(MonitorSample.sampled_at), desc(MonitorSample.id))).scalars().first()
    if latest is None:
        return record_monitor_sample(db, collector=collector)
    age = (utcnow() - ensure_aware(latest.sampled_at)).total_seconds()
    if age >= max(5, settings.monitor_sample_interval_seconds):
        return record_monitor_sample(db, collector=collector)
    return latest


def monitor_payload(db: Session, *, hours: int = 6, collector: SystemMetricsCollector | None = None) -> dict[str, Any]:
    settings = get_settings()
    hours = max(1, min(24, int(hours)))
    if settings.monitor_enabled:
        collector = collector or SystemMetricsCollector(settings=settings)
        ensure_recent_monitor_sample(db, collector=collector)
    else:
        collector = None
    cutoff = utcnow() - timedelta(hours=hours)
    samples = db.execute(
        select(MonitorSample)
        .options(selectinload(MonitorSample.cpu_samples), selectinload(MonitorSample.network_samples), selectinload(MonitorSample.disk_samples))
        .where(MonitorSample.sampled_at >= cutoff)
        .order_by(MonitorSample.sampled_at, MonitorSample.id)
    ).scalars().all()
    latest = samples[-1] if samples else None
    generated_at = utcnow()
    return {
        "enabled": settings.monitor_enabled,
        "window_hours": hours,
        "sample_interval_seconds": settings.monitor_sample_interval_seconds,
        "generated_at": generated_at.isoformat(),
        "server_time": generated_at.isoformat(),
        "last_sample_at": latest.sampled_at.isoformat() if latest else None,
        "sample_count": len(samples),
        "summary": _summary(samples),
        "virtualization": collector.collect_virtualization() if collector else {"detected": "disabled"},
        "cpu": [
            {"sampled_at": sample.sampled_at.isoformat(), "percent": sample.cpu_percent, "load1": sample.load1, "load5": sample.load5, "load15": sample.load15}
            for sample in samples
        ],
        "cpu_cores": _cpu_cores(samples),
        "memory": [
            {
                "sampled_at": sample.sampled_at.isoformat(),
                "used_percent": sample.memory_used_percent,
                "available_bytes": sample.memory_available_bytes,
                "total_bytes": sample.memory_total_bytes,
                "swap_used_bytes": sample.swap_used_bytes,
                "swap_total_bytes": sample.swap_total_bytes,
            }
            for sample in samples
        ],
        "network_totals": _network_totals(samples),
        "networks": _networks(samples),
        "disk_io": _disk_totals(samples),
        "disk_devices": _disk_devices(samples),
        "disks": _disks(samples),
    }


def _cpu_cores(samples: list[MonitorSample]) -> list[dict[str, Any]]:
    by_name: dict[str, list[MonitorCpuSample]] = {}
    for sample in samples:
        for row in sample.cpu_samples:
            by_name.setdefault(row.cpu_name, []).append(row)
    return [
        {
            "name": name,
            "current_percent": rows[-1].percent,
            "points": [
                {"sampled_at": row.sample.sampled_at.isoformat(), "percent": row.percent}
                for row in rows
            ],
        }
        for name, rows in sorted(by_name.items(), key=lambda item: (0, int(item[0][3:])) if item[0][3:].isdigit() else (1, item[0]))
    ]


def _summary(samples: list[MonitorSample]) -> dict[str, Any]:
    latest = samples[-1] if samples else None
    latest_networks = latest.network_samples if latest else []
    latest_disks = latest.disk_samples if latest else []
    cpu_values = [sample.cpu_percent for sample in samples if sample.cpu_percent is not None]
    memory_values = [sample.memory_used_percent for sample in samples if sample.memory_used_percent is not None]
    total_rx = sum(row.rx_bytes_per_sec or 0 for row in latest_networks)
    total_tx = sum(row.tx_bytes_per_sec or 0 for row in latest_networks)
    busiest_disk = max(latest_disks, key=lambda row: row.used_percent or -1, default=None)
    return {
        "cpu": {
            "current_percent": latest.cpu_percent if latest else None,
            "average_percent": round(sum(cpu_values) / len(cpu_values), 2) if cpu_values else None,
            "peak_percent": max(cpu_values) if cpu_values else None,
            "load1": latest.load1 if latest else None,
            "cpu_count": latest.cpu_count if latest else 0,
        },
        "memory": {
            "current_percent": latest.memory_used_percent if latest else None,
            "average_percent": round(sum(memory_values) / len(memory_values), 2) if memory_values else None,
            "peak_percent": max(memory_values) if memory_values else None,
            "available_bytes": latest.memory_available_bytes if latest else 0,
            "total_bytes": latest.memory_total_bytes if latest else 0,
        },
        "network": {
            "rx_bytes_per_sec": round(total_rx, 2),
            "tx_bytes_per_sec": round(total_tx, 2),
            "interface_count": len(latest_networks),
            "error_count": sum(row.rx_errors + row.tx_errors for row in latest_networks),
            "drop_count": sum(row.rx_dropped + row.tx_dropped for row in latest_networks),
        },
        "disk": {
            "highest_used_percent": busiest_disk.used_percent if busiest_disk else None,
            "highest_used_mount": busiest_disk.mount_point if busiest_disk else "",
            "mount_count": len(latest_disks),
        },
    }


def _network_totals(samples: list[MonitorSample]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for sample in samples:
        rows.append(
            {
                "sampled_at": sample.sampled_at.isoformat(),
                "rx_bytes_per_sec": round(sum(row.rx_bytes_per_sec or 0 for row in sample.network_samples), 2),
                "tx_bytes_per_sec": round(sum(row.tx_bytes_per_sec or 0 for row in sample.network_samples), 2),
            }
        )
    return rows


def _networks(samples: list[MonitorSample]) -> list[dict[str, Any]]:
    by_name: dict[str, list[MonitorNetworkSample]] = {}
    for sample in samples:
        for row in sample.network_samples:
            by_name.setdefault(row.interface_name, []).append(row)
    result: list[dict[str, Any]] = []
    for name in sorted(by_name):
        rows = by_name[name]
        latest = rows[-1]
        result.append(
            {
                "name": name,
                "oper_state": latest.oper_state,
                "rx_bytes_per_sec": latest.rx_bytes_per_sec,
                "tx_bytes_per_sec": latest.tx_bytes_per_sec,
                "rx_errors": latest.rx_errors,
                "tx_errors": latest.tx_errors,
                "rx_dropped": latest.rx_dropped,
                "tx_dropped": latest.tx_dropped,
                "points": [
                    {
                        "sampled_at": row.sample.sampled_at.isoformat(),
                        "rx_bytes_per_sec": row.rx_bytes_per_sec,
                        "tx_bytes_per_sec": row.tx_bytes_per_sec,
                    }
                    for row in rows
                ],
            }
        )
    return result


def _disk_totals(samples: list[MonitorSample]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for sample in samples:
        devices = _disk_rates_by_device(sample)
        rows.append(
            {
                "sampled_at": sample.sampled_at.isoformat(),
                "read_bytes_per_sec": round(sum(row["read_bytes_per_sec"] or 0 for row in devices.values()), 2),
                "write_bytes_per_sec": round(sum(row["write_bytes_per_sec"] or 0 for row in devices.values()), 2),
            }
        )
    return rows


def _disk_rates_by_device(sample: MonitorSample) -> dict[str, dict[str, float | None]]:
    devices: dict[str, dict[str, float | None]] = {}
    for row in sorted(sample.disk_samples, key=lambda item: (item.device, item.mount_point)):
        if row.filesystem in VIRTUAL_FILESYSTEMS:
            continue
        device = row.device or row.mount_point
        rates = devices.setdefault(device, {"read_bytes_per_sec": None, "write_bytes_per_sec": None, "used_percent": None})
        if rates["read_bytes_per_sec"] is None and row.read_bytes_per_sec is not None:
            rates["read_bytes_per_sec"] = row.read_bytes_per_sec
        if rates["write_bytes_per_sec"] is None and row.write_bytes_per_sec is not None:
            rates["write_bytes_per_sec"] = row.write_bytes_per_sec
        if rates["used_percent"] is None and row.used_percent is not None:
            rates["used_percent"] = row.used_percent
    return devices


def _disk_devices(samples: list[MonitorSample]) -> list[dict[str, Any]]:
    by_device: dict[str, list[dict[str, Any]]] = {}
    for sample in samples:
        for device, rates in _disk_rates_by_device(sample).items():
            by_device.setdefault(device, []).append(
                {
                    "sampled_at": sample.sampled_at.isoformat(),
                    "read_bytes_per_sec": rates["read_bytes_per_sec"],
                    "write_bytes_per_sec": rates["write_bytes_per_sec"],
                    "used_percent": rates["used_percent"],
                }
            )
    return [
        {
            "name": device,
            "device": device,
            "read_bytes_per_sec": points[-1]["read_bytes_per_sec"],
            "write_bytes_per_sec": points[-1]["write_bytes_per_sec"],
            "used_percent": points[-1]["used_percent"],
            "points": points,
        }
        for device, points in sorted(by_device.items())
    ]


def _disks(samples: list[MonitorSample]) -> list[dict[str, Any]]:
    by_mount: dict[str, list[MonitorDiskSample]] = {}
    for sample in samples:
        for row in sample.disk_samples:
            if row.filesystem in VIRTUAL_FILESYSTEMS:
                continue
            by_mount.setdefault(row.mount_point, []).append(row)
    result: list[dict[str, Any]] = []
    for mount in sorted(by_mount):
        rows = by_mount[mount]
        latest = rows[-1]
        result.append(
            {
                "mount_point": mount,
                "device": latest.device,
                "filesystem": latest.filesystem,
                "total_bytes": latest.total_bytes,
                "used_bytes": latest.used_bytes,
                "free_bytes": latest.free_bytes,
                "used_percent": latest.used_percent,
                "read_bytes_per_sec": latest.read_bytes_per_sec,
                "write_bytes_per_sec": latest.write_bytes_per_sec,
                "points": [
                    {
                        "sampled_at": row.sample.sampled_at.isoformat(),
                        "used_percent": row.used_percent,
                        "read_bytes_per_sec": row.read_bytes_per_sec,
                        "write_bytes_per_sec": row.write_bytes_per_sec,
                    }
                    for row in rows
                ],
            }
        )
    return result


class MonitorSampler:
    def __init__(self, *, interval_seconds: int | None = None) -> None:
        settings = get_settings()
        self.interval_seconds = max(5, interval_seconds or settings.monitor_sample_interval_seconds)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, name="atlaso-monitor-sampler", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                with SessionLocal() as db:
                    record_monitor_sample(db)
            except Exception:
                pass
            self._stop.wait(self.interval_seconds)


def start_monitor_sampler() -> MonitorSampler | None:
    settings = get_settings()
    if not settings.monitor_enabled:
        return None
    sampler = MonitorSampler(interval_seconds=settings.monitor_sample_interval_seconds)
    sampler.start()
    return sampler
