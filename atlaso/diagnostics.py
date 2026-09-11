"""Collect bounded, allowlisted support evidence without importing the web application.

Raw command output is held only in bounded memory. Each source projects known
fields before evidence, hashes, summaries, or archives are written. The collector
never imports database startup, loads credentials, or performs recovery actions.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import ipaddress
import json
import os
import platform
import re
import shutil
import sqlite3
import stat
import subprocess
import threading
import time
import zipfile
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from functools import partial
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from atlaso import __build_git_commit__, __version__

TASK_ID_PATTERN = r"(?:job_[0-9a-fA-F]{12}|job_[0-9a-fA-F]{32}|job_schedule_[0-9]{1,20}_(?:[0-9a-fA-F]{12}|[0-9]{1,20})|[0-9a-fA-F]{32}|[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})"
SCHEMA_VERSION = 1
SCOPES = ("network", "terminal", "update", "pxe")
SOURCE_LIMIT = 262_144
TOTAL_LIMIT = 8 * 1024 * 1024
TOTAL_SECONDS = 60
DATABASE_PATH = Path("/var/lib/atlaso/atlaso.db")
UNITS = ("atlaso", "atlaso-worker", "nginx", "systemd-networkd", "systemd-resolved")
SERVICE_FIELDS = {
    "ActiveState": {"active", "inactive", "failed", "activating", "deactivating", "reloading"},
    "SubState": {"running", "dead", "failed", "exited", "start", "stop", "auto-restart"},
    "LoadState": {"loaded", "not-found", "error", "masked", "bad-setting"},
    "Result": {"success", "exit-code", "signal", "timeout", "resources", "start-limit-hit", "oom-kill"},
}


class EvidenceError(Exception):
    """Carry only a fixed public status, never a source exception or stderr."""

    def __init__(self, status: str) -> None:
        """Initialize the capture-local collector state.

        Args:
            status: Fixed public failure category with no source content.
        """
        super().__init__(status)
        self.status = status


def utc_now() -> datetime:
    """Return an aware capture time."""
    return datetime.now(timezone.utc)


def timestamp(value: str) -> datetime:
    """Require an ISO timestamp with an explicit timezone.

    Args:
        value: Candidate source value to validate before serialization.
    """
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Incident times must include a timezone.")
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class Options:
    """Share the same validated selections across recovery and browser entry points."""

    since: str
    until: str
    scopes: tuple[str, ...] = ()
    detailed_logs: bool = False
    anonymize: bool = False
    correlation_id: str = ""
    log_lines: int = 500

    @classmethod
    def parse(cls, values: dict[str, Any]) -> Options:
        """Reject unrecognized scope, unbounded windows, and free-form identifiers.

        Args:
            values: Untrusted option fields to validate.
        """
        until = timestamp(str(values["until"])) if values.get("until") else utc_now()
        since = timestamp(str(values["since"])) if values.get("since") else until - timedelta(minutes=30)
        if not timedelta(0) < until - since <= timedelta(days=7) or until > utc_now() + timedelta(minutes=1):
            raise ValueError("Choose a past incident window of at most seven days.")
        scopes = tuple(sorted(set(values.get("scopes") or ())))
        if any(scope not in SCOPES for scope in scopes):
            raise ValueError("Unknown diagnostic scope.")
        correlation = str(values.get("correlation_id") or "")
        # Task/correlation identifiers are opaque UUIDs, never arbitrary log queries.
        if correlation and not re.fullmatch(TASK_ID_PATTERN, correlation):
            raise ValueError("Use an Atlaso task ID or correlation UUID.")
        lines = int(values.get("log_lines", 500))
        if not 1 <= lines <= 2000:
            raise ValueError("Log limit must be between 1 and 2000 events.")
        return cls(since.isoformat(), until.isoformat(), scopes,
                   bool(values.get("detailed_logs")), bool(values.get("anonymize")), correlation, lines)


def json_bytes(value: Any) -> bytes:
    """Serialize only projected evidence in a deterministic inspectable form.

    Args:
        value: Candidate source value to validate before serialization.
    """
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def ordinary_path(path: Path) -> None:
    """Reject symlinks/reparse points throughout an existing absolute path.

    Args:
        path: Fixed source or task-owned output path.
    """
    if not path.is_absolute():
        raise EvidenceError("failed")
    for parent in reversed((path, *path.parents)):
        info = parent.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise EvidenceError("permission_denied")


def private_directory(path: Path) -> None:
    """Require an ordinary private directory owned by the current process user.

    Args:
        path: Configured diagnostic spool directory to validate without creating it.
    """
    ordinary_path(path)
    info = path.stat()
    effective_uid = getattr(os, "geteuid", lambda: -1)
    if not stat.S_ISDIR(info.st_mode) or (os.name == "posix" and (info.st_mode & 0o077 or info.st_uid != effective_uid())):
        raise EvidenceError("permission_denied")


def read_source(path: Path, limit: int = SOURCE_LIMIT) -> bytes:
    """Read one fixed ordinary file without following a final-component link.

    Args:
        path: Fixed source or task-owned output path.
        limit: Maximum permitted read size in bytes.
    """
    ordinary_path(path)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise EvidenceError("permission_denied")
        data = source.read(limit + 1)
    if len(data) > limit:
        raise EvidenceError("truncated")
    return data


def write_new(path: Path, content: bytes) -> None:
    """Exclusively publish a private artifact into a verified existing directory.

    Args:
        path: Fixed source or task-owned output path.
        content: Already sanitized archive bytes.
    """
    ordinary_path(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


class Projection:
    """Keep consistent identifier aliases in memory for exactly one capture."""

    def __init__(self, anonymize: bool) -> None:
        """Initialize the capture-local collector state.

        Args:
            anonymize: Whether to assign capture-local hostname and account aliases.
        """
        self.anonymize = anonymize
        self.aliases: dict[tuple[str, str], str] = {}
        self.counts = {"hostname": 0, "user": 0}

    def identifier(self, value: Any, kind: str) -> str | None:
        """Accept only bounded hostname/account tokens; optionally substitute aliases.

        Args:
            value: Candidate source value to validate before serialization.
            kind: Identifier category or numeric firewall field type.
        """
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}", value):
            return None
        if kind == "hostname":
            try:
                return str(ipaddress.ip_address(value))
            except ValueError:
                pass
        if not self.anonymize:
            return value
        key = (kind, value.lower().rstrip(".") if kind == "hostname" else value)
        if key not in self.aliases:
            self.counts[kind] += 1
            self.aliases[key] = f"{kind}{self.counts[kind]:04d}"
        return self.aliases[key]


def address(value: Any) -> str | None:
    """Preserve only valid literal addresses, networks, or MAC addresses.

    Args:
        value: Candidate source value to validate before serialization.
    """
    if not isinstance(value, str):
        return None
    if re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", value):
        return value.lower()
    try:
        return str(ipaddress.ip_interface(value) if "/" in value else ipaddress.ip_address(value))
    except ValueError:
        return None


def token(value: Any, pattern: str = r"[a-zA-Z0-9_.:-]{1,80}") -> str | None:
    """Validate machine-owned identifiers without accepting arbitrary text.

    Args:
        value: Candidate source value to validate before serialization.
        pattern: Allowlisted full-token syntax.
    """
    return value if isinstance(value, str) and re.fullmatch(pattern, value) else None


def number(value: Any) -> int | None:
    """Accept bounded nonnegative machine counters.

    Args:
        value: Candidate source value to validate before serialization.
    """
    try:
        result = int(value)
        return result if 0 <= result <= 2**63 - 1 else None
    except (ValueError, TypeError, OverflowError):
        return None


class Collector:
    """Run serial observational collectors with one overall deadline and cancellation."""

    def __init__(self, options: Options, *, database: Path = DATABASE_PATH,
                 cancelled: Callable[[], bool] = lambda: False,
                 progress: Callable[[int, str], None] = lambda percent, source: None) -> None:
        """Initialize the capture-local collector state.

        Args:
            options: Validated capture selections shared by the UI and CLI.
            database: Existing appliance SQLite path opened read-only.
            cancelled: Callback checking whether collection must stop.
            progress: Callback publishing safe collection progress.
        """
        self.options = options
        self.database = database
        self.cancelled = cancelled
        self.progress = progress
        self.projection = Projection(options.anonymize)
        self.deadline = time.monotonic() + TOTAL_SECONDS
        self.first_configuration: dict[str, Any] | None = None

    def check(self) -> None:
        """Stop before another observation when cancellation or the deadline wins."""
        if self.cancelled():
            raise EvidenceError("cancelled")
        if time.monotonic() >= self.deadline:
            raise EvidenceError("timed_out")

    def command(self, args: list[str]) -> str:
        """Bound pipe reads and runtime; never persist command stderr or environment.

        Args:
            args: Fixed command arguments or synthetic helper invocation.
        """
        self.check()
        executable = shutil.which(args[0], path="/usr/sbin:/usr/bin:/sbin:/bin" if os.name == "posix" else None)
        if not executable:
            raise EvidenceError("unavailable")
        buffer = bytearray()
        overflow = threading.Event()
        with subprocess.Popen([executable, *args[1:]], stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                              env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}) as process:
            assert process.stdout is not None
            stdout = process.stdout

            def drain() -> None:
                while chunk := stdout.read(4096):
                    if len(buffer) + len(chunk) > SOURCE_LIMIT:
                        overflow.set()
                        break
                    buffer.extend(chunk)

            reader = threading.Thread(target=drain, daemon=True)
            reader.start()
            end = min(self.deadline, time.monotonic() + 5)
            try:
                while process.poll() is None:
                    self.check()
                    if overflow.is_set():
                        raise EvidenceError("truncated")
                    if time.monotonic() >= end:
                        raise EvidenceError("timed_out")
                    time.sleep(0.1)
                reader.join(timeout=1)
                if overflow.is_set():
                    raise EvidenceError("truncated")
                if process.returncode:
                    raise EvidenceError("unavailable")
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=2)
                reader.join(timeout=2)
        return buffer.decode("utf-8", errors="strict")

    def baseline(self) -> dict[str, Any]:
        """Capture safe version, clock, resource, and boot metadata."""
        disk = shutil.disk_usage(self.database.parent if self.database.parent.exists() else Path.cwd())
        result: dict[str, Any] = {
            "version": token(__version__), "commit": token(__build_git_commit__, r"[0-9a-f]{40}"),
            "python": platform.python_version(), "os": platform.system(),
            "kernel": token(platform.release()), "hostname": self.projection.identifier(platform.node(), "hostname"),
            "timezone": token(str(utc_now().astimezone().tzinfo)),
            "disk_total_bytes": disk.total, "disk_free_bytes": disk.free,
            "cpu_count": os.cpu_count(), "snapshot_is_atomic": False,
        }
        if hasattr(os, "getloadavg"):
            result["load_average"] = list(os.getloadavg())
        if hasattr(os, "statvfs"):
            usage = os.statvfs(self.database.parent if self.database.parent.exists() else "/")
            result["inodes_free"] = usage.f_favail
        for name, path in (("boot_id", "/proc/sys/kernel/random/boot_id"), ("uptime", "/proc/uptime")):
            try:
                value = read_source(Path(path), 1024).decode().strip().split()[0]
                result[name] = token(value, r"[0-9a-f.-]{1,40}")
            except (OSError, EvidenceError, UnicodeError, IndexError):
                result[name] = None
        try:
            memory = read_source(Path("/proc/meminfo"), 16384).decode()
            result["memory_kib"] = {key: int(value) for key, value in re.findall(
                r"^(MemTotal|MemAvailable|SwapTotal|SwapFree):\s+(\d+) kB$", memory, re.M)}
        except (OSError, EvidenceError, UnicodeError):
            result["memory_kib"] = None
        return result

    def service(self, unit: str) -> dict[str, Any]:
        """Project fixed service state fields; never read command lines or environment.

        Args:
            unit: Fixed systemd unit selected by the collector.
        """
        fields = [*SERVICE_FIELDS, "NRestarts", "ExecMainStatus", "User"]
        raw = self.command(["systemctl", "show", f"{unit}.service", "--no-pager", "--property=" + ",".join(fields)])
        values = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
        return {"unit": unit, **{key: values.get(key) if values.get(key) in allowed else None
                                for key, allowed in SERVICE_FIELDS.items()},
                "NRestarts": number(values.get("NRestarts")),
                "ExecMainStatus": number(values.get("ExecMainStatus")),
                "user": self.projection.identifier(values.get("User"), "user")}

    def network(self) -> dict[str, Any]:
        """Project numeric address/link/route observations without process details."""
        links = json.loads(self.command(["ip", "-j", "address", "show"]))
        routes = json.loads(self.command(["ip", "-j", "route", "show", "table", "all"]))
        routes += json.loads(self.command(["ip", "-6", "-j", "route", "show", "table", "all"]))
        return {
            "interfaces": [{"name": token(row.get("ifname")), "mtu": number(row.get("mtu")),
                            "mac": address(row.get("address")),
                            "operstate": row.get("operstate") if row.get("operstate") in {"UP", "DOWN", "UNKNOWN", "DORMANT", "LOWERLAYERDOWN"} else None,
                            "addresses": [{"address": address(item.get("local")), "prefix": number(item.get("prefixlen"))}
                                          for item in row.get("addr_info", [])[:100]]} for row in links[:100]],
            "routes": [{"destination": "default" if row.get("dst") == "default" else address(row.get("dst")),
                        "gateway": address(row.get("gateway")), "interface": token(row.get("dev")),
                        "metric": number(row.get("metric")), "table": number(row.get("table"))} for row in routes[:500]],
        }

    def listeners(self) -> dict[str, Any]:
        """Retain only numeric socket endpoints, excluding users and owning processes."""
        raw = self.command(["ss", "-H", "-lntu"])
        rows = []
        for line in raw.splitlines()[:500]:
            parts = line.split()
            if len(parts) >= 6 and parts[0] in {"tcp", "udp"}:
                endpoint = parts[4]
                if re.fullmatch(r"[0-9a-fA-F:.\[\]*%]+", endpoint):
                    rows.append({"protocol": parts[0], "local": endpoint})
        return {"listeners": rows}

    def resolver(self) -> dict[str, Any]:
        """Use networkd/resolved's numeric status without dumping resolv.conf symlinks."""
        raw = self.command(["resolvectl", "dns"])
        servers = set()
        for word in raw.split():
            try:
                servers.add(str(ipaddress.ip_address(word)))
            except ValueError:
                continue
        return {"servers": sorted(servers)}

    def firewall(self) -> dict[str, Any]:
        """Project Atlaso's native inet table, excluding comments and unknown expressions."""
        if os.name == "posix" and getattr(os, "geteuid", lambda: -1)() != 0:
            return self.privileged("firewall-nftables")
        payload = json.loads(self.command(["nft", "-j", "-nn", "list", "table", "inet", "atlaso"]))
        chains, rules = [], []
        for entry in payload["nftables"][:1000]:
            chain = entry.get("chain")
            if isinstance(chain, dict) and chain.get("family") == "inet" and chain.get("table") == "atlaso" and chain.get("name") in {"input", "output", "forward"}:
                chains.append({"name": chain["name"], "policy": chain.get("policy") if chain.get("policy") in {"accept", "drop"} else None})
            rule = entry.get("rule")
            if not isinstance(rule, dict) or rule.get("family") != "inet" or rule.get("table") != "atlaso" or rule.get("chain") not in {"input", "output", "forward"}:
                continue
            expressions = []
            omitted = 0
            for expression in rule.get("expr", [])[:100]:
                if len(expression) == 1 and next(iter(expression)) in {"accept", "drop", "return", "reject"}:
                    expressions.append({"verdict": next(iter(expression))})
                elif "match" in expression:
                    match = expression["match"]
                    left = match.get("left", {})
                    field = left.get("payload", {})
                    protocol, name = field.get("protocol"), field.get("field")
                    kind = "address" if protocol in {"ip", "ip6"} and name in {"saddr", "daddr"} else "port" if protocol in {"tcp", "udp"} and name in {"sport", "dport"} else None
                    if kind and match.get("op") in {"==", "!=", "in"}:
                        value = self.firewall_value(match.get("right"), kind)
                        if value is not None:
                            expressions.append({"protocol": protocol, "field": name, "op": match["op"], "value": value})
                            continue
                    omitted += 1
                else:
                    omitted += 1
            rules.append({"chain": rule["chain"], "expressions": expressions, "omitted_expressions": omitted})
        return {"family": "inet", "table": "atlaso", "chains": chains, "rules": rules,
                "omitted": "Comments, counters, other tables and unsupported expressions are excluded; this is not a complete ruleset."}

    @staticmethod
    def firewall_value(value: Any, kind: str, depth: int = 0) -> Any:
        """Validate bounded numeric address/port expressions, including sets and ranges.

        Args:
            value: Candidate nftables right-hand expression.
            kind: Address or port projection selected from a known packet field.
            depth: Current nesting bound for structured expressions.
        """
        if depth > 3:
            return None
        if isinstance(value, dict):
            if set(value) == {"prefix"} and kind == "address":
                prefix = value["prefix"]
                return address(str(prefix.get("addr")) + "/" + str(prefix.get("len")))
            for key in ("set", "range"):
                if set(value) == {key} and isinstance(value[key], list) and len(value[key]) <= 100:
                    items = [Collector.firewall_value(item, kind, depth + 1) for item in value[key]]
                    return {key: items} if all(item is not None for item in items) else None
            return None
        if kind == "address":
            return address(value)
        return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 65535 else None

    def update(self) -> dict[str, Any]:
        """Project fixed durable update records without commands, URLs or credentials."""
        if os.name == "posix" and getattr(os, "geteuid", lambda: -1)() != 0:
            return self.privileged("release-update")
        result: dict[str, Any] = {}
        current = Path("/opt/atlaso/current")
        try:
            ordinary_path(current.parent)
            result["active_release"] = token(Path(os.readlink(current)).name, r"[0-9a-zA-Z_.-]{1,100}")
        except OSError:
            result["active_release"] = None
        paths = {
            "finalizer": "/var/lib/atlaso/apply/appliance-update/finalizer-status.json",
            "restart_receipt": "/var/lib/atlaso-privileged/appliance-update-status/restart-receipt.json",
            "recovery": "/var/lib/atlaso-privileged/appliance-update-status/status.json",
            "worker_startup": "/var/lib/atlaso/worker-startup.json",
        }
        for label, path in paths.items():
            try:
                payload = json.loads(read_source(Path(path)))
                item: dict[str, Any] = {"availability": "available"}
                for key in ("status", "state", "phase"):
                    allowed = {"succeeded", "failed", "running", "pending", "completed", "held", "restored",
                               "transaction_pending", "restart_pending", "activation_committed", "rollback_pending"}
                    item[key] = payload.get(key) if payload.get(key) in allowed else None
                for key in ("rolled_back", "service_health", "no_change", "terminal", "status_activated"):
                    item[key] = payload.get(key) if isinstance(payload.get(key), bool) else None
                for key in ("job_id", "task_id"):
                    item[key] = token(payload.get(key), TASK_ID_PATTERN)
                item["candidate_version"] = token(payload.get("candidate_version"), r"\d+\.\d+\.\d+")
                restoration = payload.get("ui_restoration", {})
                item["ui_restoration"] = restoration.get("state") if restoration.get("state") in {"held", "pending", "restored"} else None
                result[label] = item
            except PermissionError:
                result[label] = {"availability": "permission_denied"}
            except (OSError, EvidenceError):
                result[label] = {"availability": "unavailable"}
            except (ValueError, TypeError, AttributeError):
                result[label] = {"availability": "failed"}
        return result

    def nginx(self) -> dict[str, Any]:
        """Inspect only listener and WebSocket directives from the fixed managed file."""
        raw = read_source(Path("/etc/nginx/conf.d/atlaso.conf")).decode()
        rows = []
        for line in raw.splitlines():
            words = line.strip().removesuffix(";").split()
            if not words or line.lstrip().startswith("#"):
                continue
            key, args = words[0], words[1:]
            if key == "listen" and args and re.fullmatch(r"[0-9a-fA-F:.\[\]]+", args[0]):
                rows.append({"directive": key, "address": args[0], "tls": "ssl" in args})
            elif key == "server_name":
                rows.append({"directive": key, "hostnames": [self.projection.identifier(value, "hostname") for value in args]})
            elif key == "proxy_http_version" and args in [["1.1"], ["1.0"]]:
                rows.append({"directive": key, "value": args[0]})
            elif key == "proxy_pass" and len(args) == 1:
                upstream = urlsplit(args[0])
                if upstream.scheme in {"http", "https"} and not upstream.username and not upstream.password:
                    rows.append({"directive": key, "scheme": upstream.scheme,
                                 "host": address(upstream.hostname) or self.projection.identifier(upstream.hostname, "hostname"),
                                 "port": upstream.port})
            elif key == "proxy_set_header" and len(args) == 2:
                header, value = args
                if header.lower() in {"upgrade", "connection", "x-atlaso-listener", "x-atlaso-listener-address", "x-forwarded-proto"}:
                    allowed = {"$http_upgrade", "$connection_upgrade", '"upgrade"', "upgrade", "$scheme", "$server_addr", "management", "public", "http", "https"}
                    rows.append({"directive": key, "header": header.lower(),
                                 "value": value if value in allowed else address(value),
                                 "recognized": value in allowed or address(value) is not None})
        return {"directives": rows, "omitted": "Other directives, paths, comments and arbitrary values are excluded."}

    def database_evidence(self) -> dict[str, Any]:
        """Open existing SQLite read-only and select explicit nonsecret columns only."""
        ordinary_path(self.database)
        if not self.database.is_file():
            raise EvidenceError("unavailable")
        result: dict[str, Any] = {"availability": "available"}
        with sqlite3.connect(self.database.as_uri() + "?mode=ro", uri=True, timeout=1) as db:
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, SOURCE_LIMIT)
            db.execute("PRAGMA query_only=ON")
            db.set_progress_handler(lambda: int(time.monotonic() >= self.deadline), 1000)
            result["sqlite_schema_version"] = db.execute("PRAGMA user_version").fetchone()[0]
            result["schema_tables"] = [name for (name,) in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('jobs','settings','physical_interfaces','vlan_interfaces')")]
            if "network" in self.options.scopes or "terminal" in self.options.scopes:
                cols = "name,mac_address,ip_cidr,ipv6_cidr,role,admin_state,access_management_ui_enabled"
                result["desired_interfaces"] = [{"name": token(row[0]), "mac": address(row[1]),
                    "ipv4": address(row[2]), "ipv6": address(row[3]),
                    "role": row[4] if row[4] in {"access", "management", "route", "unused"} else None,
                    "admin_state": row[5] if row[5] in {"up", "down"} else None,
                    "management_ui": bool(row[6])} for row in db.execute(f"SELECT {cols} FROM physical_interfaces LIMIT 100")]
                baseline = db.execute("SELECT substr(value,1,262145) FROM settings WHERE key=?", ("appliance_apply.baselines.v1",)).fetchone()
                result["applied_interfaces"] = None
                if baseline and len(baseline[0]) <= SOURCE_LIMIT:
                    payload = json.loads(baseline[0])
                    network = payload.get("network", {})
                    preview = network.get("config_preview", "")
                    result["applied_interfaces"] = self.network_preview(preview)
                result["desired_vlans"] = [{"name": token(name), "parent": token(parent),
                    "ipv4": address(ipv4), "ipv6": address(ipv6),
                    "role": role if role in {"access", "management", "route", "unused"} else None,
                    "management_ui": bool(management)} for name, parent, ipv4, ipv6, role, management in db.execute(
                        "SELECT name,parent_interface,ip_cidr,ipv6_cidr,role,access_management_ui_enabled FROM vlan_interfaces LIMIT 100")]
            if "pxe" in self.options.scopes:
                result["network_boot_environments"] = [
                    {"key": token(key), "enabled": bool(enabled)}
                    for key, enabled in db.execute("SELECT key,enabled FROM network_boot_environments LIMIT 100")
                ]
            if self.options.scopes:
                rows = db.execute("SELECT id,type,status,created_at,started_at,finished_at FROM jobs "
                    "WHERE created_at >= ? AND created_at <= ? AND (? = '' OR id = ?) ORDER BY created_at DESC LIMIT 100",
                    (timestamp(self.options.since).replace(tzinfo=None).isoformat(" "),
                     timestamp(self.options.until).replace(tzinfo=None).isoformat(" "),
                     self.options.correlation_id, self.options.correlation_id))
                result["tasks"] = [{"id": token(row[0], TASK_ID_PATTERN), "type": token(row[1]),
                    "status": row[2] if row[2] in {"pending", "running", "succeeded", "failed", "cancelled"} else None,
                    "timestamps": [token(v, r"[0-9T :.+Z-]{1,40}") for v in row[3:]]} for row in rows]
        configuration: dict[str, Any] = {key: result[key] for key in ("desired_interfaces", "desired_vlans", "applied_interfaces") if key in result}
        if self.first_configuration is None:
            self.first_configuration = configuration or None
        return result

    @staticmethod
    def network_preview(raw: str) -> list[dict[str, Any]]:
        """Project only declared interface fields from the last-applied preview.

        Args:
            raw: Bounded last-applied configuration preview.
        """
        if not isinstance(raw, str) or len(raw) > SOURCE_LIMIT:
            raise EvidenceError("failed")
        rows: list[dict[str, Any]] = []
        section = ""
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("["):
                section = line
            if section not in {"[physical_interfaces]", "[vlan_interfaces]"} or "=" not in line:
                continue
            key, value = (part.strip() for part in line.split("=", 1))
            if key in {"interface", "vlan"}:
                rows.append({"name": token(value)})
            elif rows and key in {"ip_cidr", "ipv6_cidr", "gateway", "ipv6_gateway"}:
                rows[-1][key] = address(value)
            elif rows and key in {"role", "mode", "admin_state", "access_management_ui_enabled"}:
                rows[-1][key] = value if value in {"management", "access", "route", "unused", "up", "down", "true", "false", "yes", "no", "1", "0"} else None
        return rows[:200]

    def journal(self, unit: str) -> dict[str, Any]:
        """Export timestamp/severity and fixed categories, never arbitrary log messages.

        Args:
            unit: Fixed systemd unit selected by the collector.
        """
        if os.name == "posix" and getattr(os, "geteuid", lambda: -1)() != 0:
            return self.privileged("journal-" + unit)
        raw = self.command(["journalctl", "--unit=" + unit + ".service", "--no-pager", "--output=json",
                            "--since=" + self.options.since, "--until=" + self.options.until,
                            "--lines=" + str(self.options.log_lines)])
        events = []
        for line in raw.splitlines():
            item = json.loads(line)
            # MESSAGE is intentionally never copied or regex-scrubbed. Unknown text
            # can contain passwords, payload bodies or terminal transcripts.
            message = item.get("MESSAGE", "")
            category = "message_omitted"
            if isinstance(message, str):
                for fragment, label in (("Connection refused", "connection_refused"), ("upstream timed out", "upstream_timeout"),
                                        ("permission denied", "permission_denied"), ("WebSocket", "websocket_event"),
                                        ("Out of memory", "out_of_memory")):
                    if fragment.lower() in message.lower():
                        category = label
                        break
            events.append({"timestamp_us": number(item.get("__REALTIME_TIMESTAMP")),
                           "priority": number(item.get("PRIORITY")), "unit": unit, "category": category,
                           "hostname": self.projection.identifier(item.get("_HOSTNAME"), "hostname")})
        return {"events": events, "limit": self.options.log_lines,
                "possibly_truncated": len(events) >= self.options.log_lines,
                "omitted": "All free-form messages, stderr, bodies, session data and unknown fields."}

    def privileged(self, source: str) -> dict[str, Any]:
        """Ask the fixed helper for one projected read-only source, never raw output.

        Args:
            source: Fixed allowlisted collector identifier.
        """
        raw = self.command(["sudo", "-n", "/opt/atlaso/bin/atlaso-helper", "diagnostics", "source", source,
                            self.options.since, self.options.until, str(self.options.log_lines)])
        payload = json.loads(raw)
        if not isinstance(payload, dict) or payload.get("source") != source or not isinstance(payload.get("evidence"), dict):
            raise EvidenceError("failed")
        evidence: dict[str, Any] = payload["evidence"]
        # The helper uses the same projections but has no per-bundle alias map.
        # Apply the parent's map before any evidence bytes leave memory.
        if source.startswith("journal-"):
            for event in evidence.get("events", []):
                event["hostname"] = self.projection.identifier(event.get("hostname"), "hostname")
        return evidence

    def capture(self, bundle_id: str | None = None) -> tuple[bytes, dict[str, Any]]:
        """Produce an inspectable archive containing only sanitized projected evidence.

        Args:
            bundle_id: Server-generated diagnostic bundle UUID.
        """
        started = utc_now()
        bundle_id = bundle_id or str(uuid4())
        if not re.fullmatch(r"[0-9a-f-]{36}", bundle_id):
            raise ValueError("Invalid bundle identifier.")
        sources: list[tuple[str, str, Callable[[], dict[str, Any]]]] = [
            ("baseline", "runtime metadata and bounded proc counters", self.baseline),
            ("database", "read-only SQLite field projections", self.database_evidence),
        ]
        for unit in UNITS:
            sources.append(("service-" + unit, "systemctl selected properties: " + unit, partial(self.service, unit)))
        if {"network", "terminal"} & set(self.options.scopes):
            sources.extend([("network-observed", "ip JSON projection", self.network),
                            ("listeners", "ss numeric listening sockets", self.listeners),
                            ("resolver", "resolvectl numeric DNS addresses", self.resolver)])
            sources.append(("firewall-nftables", "nft inet atlaso field projection", self.firewall))
        if "terminal" in self.options.scopes:
            sources.append(("nginx", "/etc/nginx/conf.d/atlaso.conf safe directives", self.nginx))
        if "update" in self.options.scopes:
            sources.append(("release-update", "active release link and finalizer projection", self.update))
        if "pxe" in self.options.scopes:
            sources.append(("service-dnsmasq", "systemctl selected properties: dnsmasq", lambda: self.service("dnsmasq")))
        if self.options.detailed_logs:
            for unit in UNITS:
                sources.append(("journal-" + unit, "bounded journal metadata: " + unit, partial(self.journal, unit)))
        entries: list[dict[str, Any]] = []
        files: dict[str, bytes] = {}
        for index, (name, provenance, run) in enumerate(sources):
            begin = utc_now()
            self.progress(index * 95 // len(sources), name)
            entry: dict[str, Any] = {"collector": name, "provenance": provenance, "started_at": begin.isoformat()}
            try:
                self.check()
                data = json_bytes(run())
                if len(data) > SOURCE_LIMIT or sum(map(len, files.values())) + len(data) > TOTAL_LIMIT:
                    raise EvidenceError("truncated")
                filename = "evidence/" + name + ".json"
                files[filename] = data
                entry.update(status="success", path=filename, size_bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
            except EvidenceError as exc:
                if exc.status == "cancelled":
                    raise
                entry.update(status=exc.status, reason="Evidence unavailable within the selected safe collection limits.")
            except PermissionError:
                entry.update(status="permission_denied", reason="Source is not readable by this collector identity.")
            except (OSError, sqlite3.Error):
                entry.update(status="unavailable", reason="Source is absent, unavailable, or busy.")
            except (ValueError, TypeError, KeyError, IndexError, AttributeError, UnicodeError, RecursionError, OverflowError, subprocess.SubprocessError):
                entry.update(status="failed", reason="Source did not match the allowlisted schema; raw content omitted.")
            entry["ended_at"] = utc_now().isoformat()
            entries.append(entry)
        if self.cancelled():
            raise EvidenceError("cancelled")
        configuration_changed = None
        if self.first_configuration is not None and time.monotonic() < self.deadline:
            try:
                latest = self.database_evidence()
                configuration_changed = self.first_configuration != {key: latest[key] for key in self.first_configuration}
            except (OSError, sqlite3.Error, ValueError, EvidenceError, TypeError, KeyError):
                pass
        omissions = [entry["collector"] + ": " + entry["status"] for entry in entries if entry["status"] != "success"]
        omissions.extend(["Free-form log messages and arbitrary configuration are excluded.",
                          "Browser handshake status and close codes require separate browser evidence.",
                          "Capture is not atomic; configuration comparison covers selected database interface fields only."])
        if configuration_changed is None:
            omissions.append("Configuration change detection was unavailable.")
        observations = []
        for name, data in files.items():
            if name.startswith("evidence/service-"):
                service = json.loads(data)
                if service.get("ActiveState") in {"failed", "inactive"}:
                    observations.append(f"{service['unit']}: observed {service['ActiveState']}.")
        if self.first_configuration:
            desired = self.first_configuration.get("desired_interfaces", [])
            applied = self.first_configuration.get("applied_interfaces")
            if applied is None:
                observations.append("No usable last-applied network evidence was recorded.")
            else:
                applied_by_name = {row.get("name"): row for row in applied}
                for row in desired:
                    previous = applied_by_name.get(row.get("name"))
                    if previous is None or any(row.get(key) != previous.get(key) for key in ("role",)):
                        observations.append(f"Interface {row.get('name')}: desired role differs from last-applied evidence.")
        if configuration_changed:
            observations.append("Selected database interface fields changed during collection.")
        manifest: dict[str, Any] = {"schema_version": SCHEMA_VERSION, "collector_version": 1, "bundle_id": bundle_id,
                    "source_version": token(__version__), "capture_started_at": started.isoformat(),
                    "capture_ended_at": utc_now().isoformat(), "selection": asdict(self.options),
                    "configuration_changed_during_capture": configuration_changed, "collectors": entries,
                    "observations": observations,
                    "omissions": omissions, "status": "ready_with_omissions" if any(e["status"] != "success" for e in entries) else "ready",
                    "integrity_note": "Hashes verify archived evidence bytes, not source authenticity.",
                    "privacy": {"hostnames_usernames_anonymized": self.options.anonymize, "ip_mac_preserved": True,
                                "secrets_excluded": True, "mapping_included": False}}
        summary = ["Atlaso diagnostic support bundle", "", "Bundle: " + bundle_id,
                   "Status: " + manifest["status"], "Capture: " + started.isoformat(),
                   "Hostnames/usernames anonymized: " + str(self.options.anonymize),
                   "IP and MAC addresses are unchanged. Sharing is manual; review before sharing.",
                   "This is operational evidence, not an anonymous public report or a backup.", "", "Evidence:"]
        summary.extend(f"- {e['collector']}: {e['status']}" for e in entries)
        summary.extend(["", "Observed states (not root-cause conclusions):", *["- " + item for item in observations]])
        summary.extend(["", "Omissions:", *["- " + item for item in omissions]])
        files["summary.txt"] = ("\n".join(summary) + "\n").encode()
        manifest["inventory"] = [{"path": name, "size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()} for name, data in files.items()]
        files["manifest.json"] = json_bytes(manifest)
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in files.items():
                archive.writestr(name, data)
        self.progress(100, "complete")
        return output.getvalue(), manifest


def main() -> int:
    """Recover diagnostics without starting web, worker, database, or credential helpers."""
    parser = argparse.ArgumentParser(description="Collect private Atlaso support evidence; no upload or repair.")
    parser.add_argument("--output", type=Path, help="New absolute archive path in an existing private directory.")
    parser.add_argument("--source", choices=["firewall-nftables", "release-update", *["journal-" + unit for unit in UNITS]], help=argparse.SUPPRESS)
    parser.add_argument("--since", help="ISO timestamp with timezone; defaults to 30 minutes before --until.")
    parser.add_argument("--until", help="ISO timestamp with timezone; defaults to now.")
    parser.add_argument("--scope", dest="scopes", action="append", choices=SCOPES, default=[])
    parser.add_argument("--detailed-logs", action="store_true", help="Include bounded journal metadata and classified events; free text excluded.")
    parser.add_argument("--anonymize", action="store_true", help="Replace hostnames/usernames consistently; preserve IP/MAC addresses.")
    parser.add_argument("--correlation-id", default="")
    parser.add_argument("--log-lines", type=int, default=500)
    args = parser.parse_args()
    try:
        options = Options.parse(vars(args))
        if args.source:
            if args.output or os.name != "posix" or getattr(os, "geteuid", lambda: -1)() != 0:
                raise ValueError("Privileged source mode is helper-only.")
            collector = Collector(options)
            if args.source == "release-update":
                evidence = collector.update()
            else:
                evidence = collector.journal(args.source.removeprefix("journal-")) if args.source.startswith("journal-") else collector.firewall()
            data = json_bytes({"source": args.source, "evidence": evidence})
            if len(data) > SOURCE_LIMIT:
                raise EvidenceError("truncated")
            print(data.decode(), end="")
            return 0
        if args.output is None:
            raise ValueError("An output destination is required.")
        ordinary_path(args.output.parent)
        if shutil.disk_usage(args.output.parent).free < TOTAL_LIMIT * 2:
            raise EvidenceError("insufficient_space")
        archive, manifest = Collector(options).capture()
        write_new(args.output, archive)
    except (ValueError, OSError, EvidenceError):
        print("Diagnostic collection failed. Check arguments, source permissions, free space and the new output destination.")
        return 1
    print("Diagnostic bundle created: " + manifest["status"] + ". Review its summary before sharing.")
    return 2 if manifest["status"] == "ready_with_omissions" else 0


if __name__ == "__main__":
    raise SystemExit(main())
