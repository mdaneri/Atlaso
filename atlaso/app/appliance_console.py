"""Implement appliance console behavior."""

from __future__ import annotations

import json
import os
import platform
import re
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from ipaddress import ip_address, ip_interface
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4


ENV_PATH = Path("/etc/atlaso/atlaso.env")


def _load_environment() -> None:
    """Return environment."""
    if not ENV_PATH.exists():
        return
    try:
        lines = ENV_PATH.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


_load_environment()

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, OperationalError as SQLAlchemyOperationalError

from atlaso.app.audit import record_audit
from atlaso.app.database import SessionLocal
from atlaso.app.models import ApplianceSettings, FirewallSettings, Job, JobStatus, JobStep, PhysicalInterface, utcnow
from atlaso.app.services.dnsmasq import join_servers, split_servers


HELPER_PATH = Path("/opt/atlaso/bin/atlaso-helper")
PHOTON_RELEASE_PATH = Path("/etc/photon-release")
MAINTENANCE_STATE_PATH = Path("/var/lib/atlaso/console/services.json")
CONSOLE_ACTOR = "console:root"
CONSOLE_REFRESH_ENV = "ATLASO_CONSOLE_REFRESH_SECONDS"
CONSOLE_STARTUP_GRACE_SECONDS = 30
BASH_PATH = "/usr/bin/bash"
SERVICE_CATALOG = (
    ("Authentication", "auth", None),
    ("Certificate Authority", "ca", None),
    ("DHCP", "dhcp", None),
    ("DNS", "dns", None),
    ("ESXi PXE", "esxi-pxe", None),
    ("ESX Storage NFS", "esx-storage", "nfs-server.service"),
    ("Firewall", "firewall", "atlaso-firewall.service"),
    ("KMS / KMIP", "kms", "atlaso-kmip.service"),
    ("Managed LDAP", "ldap", "slapd.service"),
    ("NTP / NTS", "ntpd", "ntpd.service"),
    ("Routing", "routing", None),
    ("VCF Backup SFTP", "vcf-backups", None),
    ("VCF Offline Depot", "repository", None),
    ("VCF Private Registry", "vcf-private-registry", None),
)
ENABLED_UNIT_FILE_STATES = {"enabled", "enabled-runtime", "linked", "linked-runtime", "alias"}
HELP_PAGES = (
    (
        "Screen overview",
        (
            "System identity:",
            "  Appliance version, Photon release, kernel, CPU, memory, and load.",
            "  Load turns amber at 75% and red at 100% of logical CPU count.",
            "",
            "Management access:",
            "  URLs show where the Atlaso web interface can be reached.",
            "",
            "Management network:",
            "  Interface, IPv4/IPv6 address, gateway, mode, and DNS state.",
            "",
            "Appliance services:",
            "  Desired enablement and current runtime state for every service.",
        ),
    ),
    (
        "Service states",
        (
            "The symbol reports runtime; on/off reports desired enablement.",
            "",
            "  ▶ on    Running and enabled",
            "  ▶ off   Running while disabled",
            "  ■ on    Stopped while enabled",
            "  ■ off   Stopped and disabled",
            "  ! crashed  Runtime failed",
            "  ? on    Enabled but its runtime is unavailable",
            "",
            "Blue is healthy, amber needs attention, red is failed,",
            "and gray is unavailable.",
            "Firewall '▶ off' means persistence is ready while rules are off.",
        ),
    ),
    (
        "Function keys",
        (
            "F1 Help:",
            "  Opens this guide. No authentication is required.",
            "F2 Customize:",
            "  Root-authenticated management network, Firewall, and isolation.",
            "F3 Top:",
            "  Root-authenticated process viewer. Press q to return.",
            "F4 Console:",
            "  Root-authenticated, audited Bash session. Use exit to return.",
            "F12 Shut down / Restart:",
            "  Root-authenticated, confirmed, delayed, and audited power action.",
            "",
            "Authentication is single-use and is never shared between actions.",
        ),
    ),
    (
        "Dialogs and navigation",
        (
            "Tab or Up/Down moves between fields and buttons.",
            "Left/Right changes selectors or moves within editable text.",
            "Enter activates Apply or the selected action; Esc cancels.",
            "Home/End, Backspace, and Delete work in editable fields.",
            "",
            "In Help, use Left/Right, PageUp/PageDown, Previous/Next,",
            "or n/p to change pages. Esc or F1 closes Help.",
            "",
            "Dialogs put their title on the frame. Destructive actions require",
            "confirmation and return to a freshly redrawn main screen.",
        ),
    ),
    (
        "Recovery and safety",
        (
            "This is a bounded recovery console, not the complete web UI.",
            "F2 changes desired state through validated appliance-apply tasks.",
            "Maintenance isolation preserves networking, Firewall persistence,",
            "and this console while stopping application services.",
            "",
            "Ctrl+Alt+Del is blocked. Use authenticated F12 for power actions.",
            "Other virtual terminals retain Photon login prompts (Alt+F2+).",
            "",
            "The screen refreshes automatically and after completed actions.",
            "Normal layout is 80x30; the minimum supported size is 72x22.",
        ),
    ),
)


def _console_refresh_seconds() -> int:
    """Return console refresh seconds."""
    try:
        value = int(os.environ.get(CONSOLE_REFRESH_ENV, "5"))
    except ValueError:
        return 5
    return min(max(value, 1), 300)


CONSOLE_REFRESH_SECONDS = _console_refresh_seconds()


class ConsoleOperationError(RuntimeError):
    """Report a console operation error."""
    pass


class ConsoleNetworkInventoryUnavailable(ConsoleOperationError):
    """Represent console network inventory unavailable."""
    pass


def _console_status_failure(
    exc: Exception,
    *,
    started_at: float,
    now: float | None = None,
) -> tuple[str, bool]:
    """Return console status failure.

    Args:
        exc: Exception that caused the current failure path.
        started_at: Started at consumed by console status failure.
        now: Current UTC time used for deterministic lifecycle evaluation.
    """
    current = time.monotonic() if now is None else now
    if isinstance(exc, ConsoleNetworkInventoryUnavailable) and current - started_at < CONSOLE_STARTUP_GRACE_SECONDS:
        return "Initializing appliance networking...", False
    return f"Status unavailable: {exc}", True


@dataclass(frozen=True)
class ServiceStatus:
    """Represent service status.

    Attributes:
        label: Label maintained by this servicestatus.
        unit: Unit maintained by this servicestatus.
        load_state: Load state maintained by this servicestatus.
        unit_file_state: Unit file state maintained by this servicestatus.
        active_state: Active state maintained by this servicestatus.
        desired_enabled: Whether desired is enabled.
        runtime_label: Return runtime label.
        enabled_label: Return enabled label.
        display_label: Return display label.
    """
    label: str
    unit: str
    load_state: str
    unit_file_state: str
    active_state: str
    desired_enabled: bool | None = None

    @property
    def runtime_label(self) -> str:
        """Return runtime label."""
        if self.load_state != "loaded":
            return "unavailable"
        if self.active_state in {"active", "reloading", "activating"}:
            return "running"
        if self.active_state == "failed":
            return "failed"
        return "stopped"

    @property
    def enabled_label(self) -> str:
        """Return enabled label."""
        if self.desired_enabled is not None:
            return "enabled" if self.desired_enabled else "disabled"
        return "enabled" if self.unit_file_state in ENABLED_UNIT_FILE_STATES else "disabled"

    @property
    def display_label(self) -> str:
        """Return display label."""
        runtime = self.runtime_label
        if self.label == "Firewall" and runtime == "running":
            runtime = "ready"
        if runtime == "failed":
            return "! crashed"
        runtime_symbol = {"running": "▶", "ready": "▶", "stopped": "■", "unavailable": "?"}[runtime]
        enablement = "on" if self.enabled_label == "enabled" else "off"
        return f"{runtime_symbol} {enablement}"


@dataclass(frozen=True)
class ConsoleStatus:
    """Represent console status.

    Attributes:
        hostname: Hostname maintained by this consolestatus.
        release: Release maintained by this consolestatus.
        architecture: Architecture maintained by this consolestatus.
        version: Version maintained by this consolestatus.
        kernel: Kernel maintained by this consolestatus.
        cpu: Cpu maintained by this consolestatus.
        memory: Memory maintained by this consolestatus.
        load: Load maintained by this consolestatus.
        load_severity: Load severity maintained by this consolestatus.
        interface: Interface maintained by this consolestatus.
        ipv4_method: Ipv4 method maintained by this consolestatus.
        ipv4_cidr: Ipv4 cidr maintained by this consolestatus.
        gateway: Gateway maintained by this consolestatus.
        ipv6_mode: Ipv6 mode maintained by this consolestatus.
        ipv6_cidr: Ipv6 cidr maintained by this consolestatus.
        ipv6_gateway: Ipv6 gateway maintained by this consolestatus.
        dns_servers: Dns servers maintained by this consolestatus.
        firewall_enabled: Whether firewall is enabled.
        maintenance_isolation: Maintenance isolation maintained by this consolestatus.
        services: Services maintained by this consolestatus.
        urls: Urls maintained by this consolestatus.
    """
    hostname: str
    release: str
    architecture: str
    version: str
    kernel: str
    cpu: str
    memory: str
    load: str
    load_severity: str
    interface: str
    ipv4_method: str
    ipv4_cidr: str
    gateway: str
    ipv6_mode: str
    ipv6_cidr: str
    ipv6_gateway: str
    dns_servers: tuple[str, ...]
    firewall_enabled: bool
    maintenance_isolation: bool
    services: tuple[ServiceStatus, ...]
    urls: tuple[str, ...]


def _run(
    command: list[str],
    *,
    input_text: str | None = None,
    timeout: float = 10,
    check: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run operation.

    Args:
        command: Command and arguments to execute or validate.
        input_text: Untrusted input text to parse or validate.
        timeout: Maximum time to wait for completion.
        check: Validation or readiness check to execute.

    Returns:
        The run result.

    Raises:
        ConsoleOperationError: If the operation encounters an invalid state.
    """
    result = subprocess.run(
        command,
        input=input_text,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout or f"command exited with {result.returncode}").strip()
        raise ConsoleOperationError(detail)
    return result


def _read_text(path: Path, fallback: str = "") -> str:
    """Return text.

    Args:
        path: Filesystem or URL path to read, validate, or update.
        fallback: Fallback supplied by the caller.
    """
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return fallback


def _first_display_line(value: str, fallback: str = "") -> str:
    """Return first display line.

    Args:
        value: Candidate value consumed by first display line.
        fallback: Fallback consumed by first display line.
    """
    return next((line.strip() for line in value.splitlines() if line.strip()), fallback)


def _systemd_unit_states(units: list[str]) -> dict[str, dict[str, str]]:
    """Return systemd unit states.

    Args:
        units: Units consumed by systemd unit states.
    """
    try:
        result = _run(
            [
                "systemctl",
                "show",
                "--no-pager",
                "--property=Id,LoadState,UnitFileState,ActiveState",
                *units,
            ],
            timeout=3,
        )
    except (OSError, subprocess.TimeoutExpired):
        result = subprocess.CompletedProcess([], 1, "", "")

    by_unit: dict[str, dict[str, str]] = {}
    for block in re.split(r"\r?\n\r?\n", result.stdout.strip()):
        values = {}
        for line in block.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value
        if values.get("Id"):
            by_unit[values["Id"]] = values

    return by_unit


def _appliance_service_statuses(db: Any, *, firewall_enabled: bool) -> tuple[ServiceStatus, ...]:
    # Reuse the Services page projections so the web UI and tty describe the
    # same desired state. Systemd is only an additional runtime truth source.
    """Return appliance service statuses.

    Args:
        db: Active database session.
        firewall_enabled: Firewall enabled supplied by the caller.
    """
    from atlaso.app.ui import services_template_context

    rows = {str(row["service"]): row for row in services_template_context(db)["service_rows"]}
    units = list(dict.fromkeys(unit for _label, _service_id, unit in SERVICE_CATALOG if unit))
    unit_states = _systemd_unit_states(units)
    statuses: list[ServiceStatus] = []
    for label, service_id, unit in SERVICE_CATALOG:
        row = rows.get(service_id, {})
        desired_enabled = firewall_enabled if service_id == "firewall" else bool(row.get("enabled", False))
        logical_running = bool(row.get("running", False))
        values = unit_states.get(unit, {}) if unit else {}
        load_state = values.get("LoadState", "loaded" if not unit else "not-found")
        active_state = values.get("ActiveState", "active" if logical_running else "inactive")
        unit_file_state = values.get("UnitFileState", "enabled" if desired_enabled else "disabled")

        # An absent optional unit is a normal stopped state while its desired
        # state is disabled. It becomes unavailable only if the operator has
        # enabled the service and its runtime cannot be provided.
        if unit and load_state != "loaded" and not desired_enabled:
            load_state = "loaded"
            active_state = "inactive"
        statuses.append(
            ServiceStatus(
                label=label,
                unit=unit or service_id,
                load_state=load_state,
                unit_file_state=unit_file_state,
                active_state=active_state,
                desired_enabled=desired_enabled,
            )
        )
    return tuple(statuses)


def _cpu_summary() -> str:
    """Return cpu summary."""
    model = ""
    count = os.cpu_count() or 0
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.lower().startswith("model name"):
                model = line.split(":", 1)[1].strip()
                break
    except OSError:
        model = platform.processor()
    return f"{count} x {model}" if model else f"{count} CPU"


def _memory_summary() -> str:
    """Return memory summary."""
    try:
        values: dict[str, int] = {}
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            key, raw = line.split(":", 1)
            if key in {"MemTotal", "MemAvailable"}:
                values[key] = int(raw.strip().split()[0]) * 1024
        total = values.get("MemTotal", 0)
        available = values.get("MemAvailable", 0)
        used = max(total - available, 0)
        if total:
            return f"{used / (1024 ** 3):.1f} / {total / (1024 ** 3):.1f} GiB used"
    except (OSError, ValueError):
        pass
    return "Unavailable"


def _load_summary() -> str:
    """Return summary."""
    return _load_status()[0]


def _load_status(
    values: tuple[float, float, float] | None = None,
    cpu_count: int | None = None,
) -> tuple[str, str]:
    """Return status.

    Args:
        values: Candidate values consumed by load status.
        cpu_count: Number of CPU entries.
    """
    try:
        one, five, fifteen = values if values is not None else os.getloadavg()
    except (AttributeError, OSError):
        return "Unavailable", "normal"
    logical_cpus = max(cpu_count if cpu_count is not None else (os.cpu_count() or 1), 1)
    peak_ratio = max(one, five, fifteen) / logical_cpus
    severity = "critical" if peak_ratio >= 1.0 else "warning" if peak_ratio >= 0.75 else "normal"
    return f"1 min {one:.2f} | 5 min {five:.2f} | 15 min {fifteen:.2f}", severity


def _package_version() -> str:
    """Return package version."""
    try:
        return version("atlaso")
    except PackageNotFoundError:
        return "development"


def _architecture_label(machine: str | None = None) -> str:
    """Return architecture label.

    Args:
        machine: Machine consumed by architecture label.
    """
    reported = (machine if machine is not None else platform.machine()).strip().lower()
    aliases = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
        "armv7l": "armv7",
        "armv7": "armv7",
        "armv6l": "armv6",
        "i386": "x86",
        "i486": "x86",
        "i586": "x86",
        "i686": "x86",
    }
    return aliases.get(reported, reported or "unknown")


def _management_interface(db: Any) -> PhysicalInterface:
    """Return management interface.

    Args:
        db: Active database session.

    Raises:
        ConsoleNetworkInventoryUnavailable: If the operation encounters an invalid state.
    """
    interface = db.scalar(
        select(PhysicalInterface)
        .where(PhysicalInterface.role == "management")
        .order_by(PhysicalInterface.id)
    )
    if interface is None:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth0"))
    if interface is None:
        raise ConsoleNetworkInventoryUnavailable(
            "No management interface is available. Discover appliance interfaces in Atlaso first."
        )
    return interface


def _fallback_gateway(interface_name: str, version: int = 4) -> str:
    """Return fallback gateway.

    Args:
        interface_name: Host network-interface name affected by the operation.
        version: Atlaso or artifact version being validated or produced.
    """
    try:
        result = _run(["ip", "-6" if version == 6 else "-4", "route", "show", "default", "dev", interface_name], timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    tokens = result.stdout.split()
    return tokens[tokens.index("via") + 1] if "via" in tokens and tokens.index("via") + 1 < len(tokens) else ""


def _fallback_cidr(interface_name: str, version: int = 4) -> str:
    """Return fallback cidr.

    Args:
        interface_name: Host network-interface name affected by the operation.
        version: Atlaso or artifact version being validated or produced.
    """
    try:
        result = _run(["ip", "-6" if version == 6 else "-4", "-o", "addr", "show", "dev", interface_name, "scope", "global"], timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    tokens = result.stdout.split()
    family_token = "inet6" if version == 6 else "inet"
    return tokens[tokens.index(family_token) + 1] if family_token in tokens and tokens.index(family_token) + 1 < len(tokens) else ""


def _fallback_dns_servers(interface_name: str) -> tuple[str, ...]:
    """Return fallback dns servers.

    Args:
        interface_name: Host network-interface name affected by the operation.
    """
    candidates: list[str] = []
    try:
        result = _run(["resolvectl", "dns", interface_name], timeout=2)
        candidates.extend(re.split(r"[\s,]+", result.stdout))
    except (OSError, subprocess.TimeoutExpired):
        pass
    if not candidates:
        try:
            for line in Path("/etc/resolv.conf").read_text(encoding="utf-8").splitlines():
                if line.strip().startswith("nameserver "):
                    candidates.append(line.split(None, 1)[1].strip())
        except OSError:
            pass
    servers: list[str] = []
    for candidate in candidates:
        normalized = candidate.strip("[](),;").split("#", 1)[0].split("%", 1)[0]
        try:
            parsed = ip_address(normalized)
        except ValueError:
            continue
        if parsed.is_loopback:
            continue
        value = str(parsed)
        if value not in servers:
            servers.append(value)
    return tuple(servers)


def management_urls(
    fqdn: str,
    ipv4_cidr: str,
    ipv6_cidr: str,
    *,
    https_enabled: bool = True,
) -> tuple[str, ...]:
    """Return management urls.

    Args:
        fqdn: Fqdn consumed by management urls.
        ipv4_cidr: Ipv4 cidr consumed by management urls.
        ipv6_cidr: Ipv6 cidr consumed by management urls.
        https_enabled: Whether HTTPS is enabled.
    """
    scheme = "https" if https_enabled else "http"
    urls: list[str] = []
    if fqdn:
        urls.append(f"{scheme}://{fqdn}/")
    for candidate, ipv6 in ((ipv4_cidr, False), (ipv6_cidr, True)):
        if not candidate:
            continue
        try:
            parsed_address = ip_interface(candidate).ip
        except ValueError:
            continue
        if parsed_address.is_link_local:
            continue
        urls.append(f"{scheme}://[{parsed_address}]/" if ipv6 else f"{scheme}://{parsed_address}/")
    return tuple(dict.fromkeys(urls))


def load_console_status() -> ConsoleStatus:
    """Return console status.

    Raises:
        ConsoleNetworkInventoryUnavailable: If the operation encounters an invalid state.
    """
    try:
        with SessionLocal() as db:
            interface = _management_interface(db)
            settings = db.scalar(select(ApplianceSettings).order_by(ApplianceSettings.id))
            firewall = db.scalar(select(FirewallSettings).order_by(FirewallSettings.id))
            method = (interface.ipv4_method or "static").strip().lower()
            cidr = (interface.host_ip_cidr if method == "dhcp" else interface.ip_cidr) or _fallback_cidr(interface.name, 4)
            gateway = interface.gateway or _fallback_gateway(interface.name, 4)
            ipv6_mode = "disabled" if not interface.ipv6_enabled else ("static" if interface.ipv6_cidr else "automatic")
            ipv6_cidr = (
                interface.ipv6_cidr
                if ipv6_mode == "static"
                else ((interface.host_ipv6_cidr or _fallback_cidr(interface.name, 6)) if ipv6_mode == "automatic" else "")
            )
            ipv6_gateway = interface.ipv6_gateway or (
                _fallback_gateway(interface.name, 6) if ipv6_mode == "automatic" else ""
            )
            dns_servers = tuple(split_servers(settings.external_dns_servers if settings else "")) or _fallback_dns_servers(
                interface.name
            )
            fqdn = settings.fqdn if settings and settings.fqdn else socket.getfqdn()

            firewall_enabled = bool(firewall and firewall.enabled)
            services = _appliance_service_statuses(db, firewall_enabled=firewall_enabled)
    except SQLAlchemyOperationalError as exc:
        if "no such table: physical_interfaces" in str(exc).lower():
            raise ConsoleNetworkInventoryUnavailable("Management interface inventory is initializing.") from exc
        raise

    urls = management_urls(
        fqdn,
        cidr,
        ipv6_cidr,
        https_enabled=bool(settings and settings.management_https_enabled),
    )
    load_summary, load_severity = _load_status()
    return ConsoleStatus(
        hostname=fqdn or socket.gethostname(),
        release=_first_display_line(_read_text(PHOTON_RELEASE_PATH), platform.system()),
        architecture=_architecture_label(),
        version=_package_version(),
        kernel=platform.release(),
        cpu=_cpu_summary(),
        memory=_memory_summary(),
        load=load_summary,
        load_severity=load_severity,
        interface=interface.name,
        ipv4_method=method,
        ipv4_cidr=cidr,
        gateway=gateway,
        ipv6_mode=ipv6_mode,
        ipv6_cidr=ipv6_cidr,
        ipv6_gateway=ipv6_gateway,
        dns_servers=dns_servers,
        firewall_enabled=firewall_enabled,
        maintenance_isolation=MAINTENANCE_STATE_PATH.exists(),
        services=services,
        urls=urls,
    )


def authenticate_root(password: str) -> bool:
    """Return authenticate root.

    Args:
        password: Password supplied for the immediate authenticated operation.
    """
    if not password:
        return False
    try:
        result = _run(
            [str(HELPER_PATH), "local-users", "authenticate", "--real", "root"],
            input_text=f"{password}\n",
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def validate_management_values(ipv4_method: str, ipv4_cidr: str, gateway: str) -> tuple[str, str, str]:
    """Validate management values.

    Args:
        ipv4_method: Candidate IPv4 method to validate.
        ipv4_cidr: Candidate IPv4 CIDR to validate.
        gateway: Candidate gateway to validate.


    Returns:
        The validate management values result.

    Raises:
        ConsoleOperationError: If the operation encounters an invalid state.
    """
    method = ipv4_method.strip().lower()
    if method not in {"dhcp", "static"}:
        raise ConsoleOperationError("Management IPv4 method must be DHCP or static.")
    if method == "dhcp":
        if ipv4_cidr.strip() or gateway.strip():
            raise ConsoleOperationError("DHCP management networking cannot include a static address or gateway.")
        return method, "", ""
    try:
        parsed_interface = ip_interface(ipv4_cidr.strip())
    except ValueError as exc:
        raise ConsoleOperationError("Management IPv4 must be an IPv4 CIDR such as 192.168.49.1/24.") from exc
    if parsed_interface.version != 4:
        raise ConsoleOperationError("Management IP must use IPv4.")
    gateway_value = gateway.strip()
    if gateway_value:
        try:
            parsed_gateway = ip_address(gateway_value)
        except ValueError as exc:
            raise ConsoleOperationError("Management gateway must be a valid IPv4 address.") from exc
        if parsed_gateway.version != 4 or parsed_gateway not in parsed_interface.network:
            raise ConsoleOperationError("Management gateway must be an on-link IPv4 address.")
        if parsed_gateway == parsed_interface.ip:
            raise ConsoleOperationError("Management gateway cannot equal the management IP.")
    return method, str(parsed_interface), gateway_value


def validate_ipv6_management_values(ipv6_mode: str, ipv6_cidr: str, ipv6_gateway: str) -> tuple[str, str, str]:
    """Validate ipv6 management values.

    Args:
        ipv6_mode: Candidate IPv6 mode to validate.
        ipv6_cidr: Candidate IPv6 CIDR to validate.
        ipv6_gateway: Candidate IPv6 gateway to validate.


    Returns:
        The validate ipv6 management values result.

    Raises:
        ConsoleOperationError: If the operation encounters an invalid state.
    """
    mode = ipv6_mode.strip().lower()
    if mode not in {"disabled", "automatic", "static"}:
        raise ConsoleOperationError("Management IPv6 mode must be disabled, automatic, or static.")
    cidr_value = ipv6_cidr.strip()
    gateway_value = ipv6_gateway.strip()
    if mode != "static":
        if cidr_value or gateway_value:
            raise ConsoleOperationError("Disabled or automatic IPv6 cannot include a static address or gateway.")
        return mode, "", ""
    try:
        parsed_interface = ip_interface(cidr_value)
    except ValueError as exc:
        raise ConsoleOperationError("Management IPv6 must be an IPv6 CIDR such as fd00:49::1/64.") from exc
    if parsed_interface.version != 6:
        raise ConsoleOperationError("Management IPv6 CIDR must use IPv6.")
    if gateway_value:
        try:
            parsed_gateway = ip_address(gateway_value)
        except ValueError as exc:
            raise ConsoleOperationError("Management IPv6 gateway must be a valid IPv6 address.") from exc
        if parsed_gateway.version != 6:
            raise ConsoleOperationError("Management IPv6 gateway must use IPv6.")
        if not parsed_gateway.is_link_local and parsed_gateway not in parsed_interface.network:
            raise ConsoleOperationError("Management IPv6 gateway must be link-local or on-link.")
        if parsed_gateway == parsed_interface.ip:
            raise ConsoleOperationError("Management IPv6 gateway cannot equal the management IPv6 address.")
        gateway_value = str(parsed_gateway)
    return mode, str(parsed_interface), gateway_value


def validate_dns_servers(raw: str) -> list[str]:
    """Validate dns servers.

    Args:
        raw: Candidate raw to validate.


    Returns:
        The validate dns servers result.

    Raises:
        ConsoleOperationError: If the operation encounters an invalid state.
    """
    servers = [item for item in re.split(r"[\s,]+", raw.strip()) if item]
    if not servers:
        raise ConsoleOperationError("At least one DNS server is required.")
    for server in servers:
        try:
            ip_address(server)
        except ValueError as exc:
            raise ConsoleOperationError(f"DNS server {server} must be an IPv4 or IPv6 address.") from exc
    return servers


def _captured_apply_payload(units: list[dict[str, Any]], selected_ids: set[str]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Return captured apply payload.

    Args:
        units: Units consumed by captured apply payload.
        selected_ids: Stable identifiers of the associated selected resources.


    Raises:
        ConsoleOperationError: If the operation encounters an invalid state.
    """
    selected = [unit for unit in units if unit["id"] in selected_ids]
    invalid = [unit["label"] for unit in selected if unit["validation_errors"]]
    if invalid:
        raise ConsoleOperationError(f"Desired state validation failed for: {', '.join(invalid)}.")
    if not selected:
        raise ConsoleOperationError("No appliance apply unit matched this console change.")
    payload = {
        "selected_units": [unit["id"] for unit in selected],
        "skipped_changed_units": [
            {"unit_id": unit["id"], "label": unit["label"], "summary": unit["summary"]}
            for unit in units
            if unit["changed"] and unit["id"] not in selected_ids
        ],
        "captured_units": [
            {
                "unit_id": unit["id"],
                "label": unit["label"],
                "snapshot_hash": unit["snapshot_hash"],
                "summary": unit["summary"],
                "validation_errors": unit["validation_errors"],
                "validation_warnings": unit["validation_warnings"],
                "config_path": unit["config_path"],
                "config_preview": unit["config_preview"],
                "config_diff": unit["config_diff"],
            }
            for unit in selected
        ],
        "units": [],
        "dry_run": False,
        "source": "local_appliance_console",
    }
    return selected, payload


def _console_unit_hashes(unit_ids: set[str]) -> dict[str, str]:
    """Return console unit hashes.

    Args:
        unit_ids: Stable identifiers of the associated unit resources.
    """
    from atlaso.app.ui import appliance_apply_units

    with SessionLocal() as db:
        return {
            str(unit["id"]): str(unit["snapshot_hash"])
            for unit in appliance_apply_units(db)
            if unit["id"] in unit_ids
        }


def _ensure_no_active_apply() -> None:
    """Ensure no active apply.

    Raises:
        ConsoleOperationError: If the operation encounters an invalid state.
    """
    from atlaso.app.ui import active_appliance_apply_job

    with SessionLocal() as db:
        active = active_appliance_apply_job(db)
        if active is not None:
            raise ConsoleOperationError(f"Appliance apply task {active.id} is already {active.status}.")


def _submit_console_apply(required_ids: set[str], *, changed_dependents: dict[str, str] | None = None) -> str:
    # Imported lazily so read-only status remains available even if the web stack has a startup issue.
    """Return submit console apply.

    Args:
        required_ids: Stable identifiers of the associated required resources.
        changed_dependents: Changed dependents consumed by submit console apply.


    Raises:
        ConsoleOperationError: If the operation encounters an invalid state.
    """
    from atlaso.app.ui import (
        active_appliance_apply_job,
        active_vcf_depot_execution_job,
        appliance_apply_units,
        run_appliance_apply_job,
    )

    with SessionLocal() as db:
        active = active_appliance_apply_job(db)
        if active is not None:
            raise ConsoleOperationError(f"Appliance apply task {active.id} is already {active.status}.")
        units = appliance_apply_units(db)
        selected_ids = set(required_ids)
        if changed_dependents:
            selected_ids.update(
                str(unit["id"])
                for unit in units
                if (
                    unit["id"] in changed_dependents
                    and str(unit["snapshot_hash"]) != changed_dependents[unit["id"]]
                    and not unit["validation_errors"]
                )
            )
        selected, payload = _captured_apply_payload(units, selected_ids)
        job_id = f"job_{uuid4().hex[:12]}"
        job = Job(
            id=job_id,
            type="appliance-apply",
            status=JobStatus.PENDING.value,
            vcf_depot_operation="vcf_offline_depot" in selected_ids,
            created_by=CONSOLE_ACTOR,
            progress_percent=0,
            result=json.dumps(payload, indent=2),
        )
        db.add(job)
        for position, unit in enumerate(selected, start=1):
            captured = next(item for item in payload["captured_units"] if item["unit_id"] == unit["id"])
            db.add(
                JobStep(
                    id=f"{job_id}:{unit['id']}",
                    job=job,
                    component_key=unit["id"],
                    label=unit["label"],
                    position=position,
                    status=JobStatus.PENDING.value,
                    progress_percent=0,
                    result=json.dumps(captured, indent=2, sort_keys=True),
                )
            )
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            active_vcf_job = active_vcf_depot_execution_job(db)
            if "vcf_offline_depot" in selected_ids and active_vcf_job is not None:
                raise ConsoleOperationError(
                    f"VCFDT task {active_vcf_job.id} is already {active_vcf_job.status}."
                ) from exc
            raise
        record_audit(
            db,
            actor=CONSOLE_ACTOR,
            action="create_appliance_apply_task",
            resource_type="job",
            resource_id=job_id,
            detail=f"source=local_console; selected_units={','.join(payload['selected_units'])}",
        )

    run_appliance_apply_job(job_id, force_real=True)
    with SessionLocal() as db:
        job = db.get(Job, job_id)
        if job is None or job.status != JobStatus.SUCCEEDED.value:
            detail = job.error if job is not None else "task record disappeared"
            raise ConsoleOperationError(f"Appliance apply task {job_id} failed: {detail or 'unknown failure'}")
    return job_id


def configure_management(
    ipv4_method: str,
    ipv4_cidr: str,
    gateway: str,
    ipv6_mode: str,
    ipv6_cidr: str,
    ipv6_gateway: str,
    raw_dns_servers: str,
) -> str:
    """Update management.

    Args:
        ipv4_method: Ipv4 method supplied by the caller.
        ipv4_cidr: Ipv4 cidr supplied by the caller.
        gateway: Gateway supplied by the caller.
        ipv6_mode: Ipv6 mode supplied by the caller.
        ipv6_cidr: IPv6 network or address in CIDR notation.
        ipv6_gateway: Ipv6 gateway supplied by the caller.
        raw_dns_servers: Raw dns servers supplied by the caller.

    Returns:
        The configure management result.

    Raises:
        ConsoleOperationError: If the operation encounters an invalid state.
    """
    method, cidr, gateway_value = validate_management_values(ipv4_method, ipv4_cidr, gateway)
    mode, ipv6_cidr_value, ipv6_gateway_value = validate_ipv6_management_values(ipv6_mode, ipv6_cidr, ipv6_gateway)
    dns_servers = validate_dns_servers(raw_dns_servers)
    _ensure_no_active_apply()
    dependent_hashes = _console_unit_hashes({"firewall"})
    with SessionLocal() as db:
        interface = _management_interface(db)
        settings = db.scalar(select(ApplianceSettings).order_by(ApplianceSettings.id))
        if settings is None:
            raise ConsoleOperationError("Appliance Settings desired state is unavailable.")
        interface.ipv4_method = method
        interface.ip_cidr = cidr or None
        interface.gateway = gateway_value or None
        interface.ipv6_enabled = mode != "disabled"
        interface.ipv6_cidr = ipv6_cidr_value or None
        interface.ipv6_gateway = ipv6_gateway_value or None
        interface.desired_state_source = "console"
        settings.external_dns_servers = join_servers(dns_servers)
        db.commit()
        record_audit(
            db,
            actor=CONSOLE_ACTOR,
            action="console_update_management_network",
            resource_type="interface",
            resource_id=interface.name,
            detail=f"ipv4_method={method}; ipv6_mode={mode}; dns_servers={len(dns_servers)}",
        )
    return _submit_console_apply({"network", "appliance_settings"}, changed_dependents=dependent_hashes)


def configure_dns(raw_servers: str) -> str:
    """Update dns.

    Args:
        raw_servers: Raw servers consumed by configure DNS.


    Returns:
        The configure dns result.

    Raises:
        ConsoleOperationError: If the operation encounters an invalid state.
    """
    servers = validate_dns_servers(raw_servers)
    _ensure_no_active_apply()
    with SessionLocal() as db:
        settings = db.scalar(select(ApplianceSettings).order_by(ApplianceSettings.id))
        if settings is None:
            raise ConsoleOperationError("Appliance Settings desired state is unavailable.")
        settings.external_dns_servers = join_servers(servers)
        db.commit()
        record_audit(db, actor=CONSOLE_ACTOR, action="console_update_dns", resource_type="appliance_settings", resource_id=str(settings.id))
    return _submit_console_apply({"appliance_settings"})


def configure_firewall(enabled: bool) -> str:
    """Update firewall.

    Args:
        enabled: Whether the associated resource or behavior is enabled.


    Returns:
        The configure firewall result.
    """
    _ensure_no_active_apply()
    with SessionLocal() as db:
        firewall = db.scalar(select(FirewallSettings).order_by(FirewallSettings.id))
        if firewall is None:
            firewall = FirewallSettings(enabled=enabled)
            db.add(firewall)
        else:
            firewall.enabled = enabled
        db.commit()
        db.refresh(firewall)
        record_audit(
            db,
            actor=CONSOLE_ACTOR,
            action="console_enable_firewall" if enabled else "console_disable_firewall",
            resource_type="firewall",
            resource_id=str(firewall.id),
        )
    return _submit_console_apply({"firewall"})


def set_maintenance_isolation(enabled: bool) -> dict[str, Any]:
    """Update maintenance isolation.

    Args:
        enabled: Whether the associated resource or behavior is enabled.


    Returns:
        The set maintenance isolation result.
    """
    action = "disable-services" if enabled else "restore-services"
    result = _run([str(HELPER_PATH), "console", action, "--real"], timeout=60, check=True)
    payload_lines = [line for line in result.stdout.splitlines() if line.strip().startswith("{")]
    payload = json.loads(payload_lines[-1]) if payload_lines else {"action": action}
    with SessionLocal() as db:
        record_audit(
            db,
            actor=CONSOLE_ACTOR,
            action=f"console_{action.replace('-', '_')}",
            resource_type="appliance",
            detail="Local console maintenance isolation; management networking, firewall, and console preserved.",
        )
    return payload


def schedule_power(action: str) -> str:
    """Return schedule power.

    Args:
        action: Action consumed by schedule power.


    Raises:
        ConsoleOperationError: If the operation encounters an invalid state.
    """
    if action not in {"reboot", "shutdown"}:
        raise ConsoleOperationError("Unsupported appliance power action.")
    job_id = f"job_{uuid4().hex[:12]}"
    with SessionLocal() as db:
        job = Job(
            id=job_id,
            type=f"appliance-{action}",
            status=JobStatus.PENDING.value,
            created_by=CONSOLE_ACTOR,
            progress_percent=0,
        )
        db.add(job)
        db.commit()
        record_audit(
            db,
            actor=CONSOLE_ACTOR,
            action=f"submit_appliance_{action}",
            resource_type="job",
            resource_id=job_id,
            detail=f"Confirmed local console appliance {action} task submitted.",
        )
        job.status = JobStatus.RUNNING.value
        job.started_at = utcnow()
        db.commit()

    result = _run([str(HELPER_PATH), "appliance-power", action, "--real"], timeout=10)
    succeeded = result.returncode == 0
    with SessionLocal() as db:
        job = db.get(Job, job_id)
        if job is None:
            raise ConsoleOperationError("Appliance power task record disappeared before scheduling completed.")
        job.status = JobStatus.SUCCEEDED.value if succeeded else JobStatus.FAILED.value
        job.finished_at = utcnow()
        job.progress_percent = 100
        job.result = json.dumps(
            {
                "action": action,
                "state": "scheduled" if succeeded else "failed",
                "status": job.status,
                "success": succeeded,
                "scheduled": succeeded,
                "delay_seconds": 5,
                "dry_run": False,
            },
            indent=2,
            sort_keys=True,
        )
        job.error = None if succeeded else f"Appliance {action} scheduling failed."
        db.commit()
        record_audit(
            db,
            actor=CONSOLE_ACTOR,
            action=f"schedule_appliance_{action}",
            resource_type="job",
            resource_id=job_id,
            detail=f"atlaso-helper appliance-power {action}",
            success=succeeded,
        )
    if not succeeded:
        raise ConsoleOperationError(f"Appliance {action} scheduling failed. Review task {job_id} after recovery.")
    return job_id


def record_console_shell(action: str) -> None:
    """Persist console shell.

    Args:
        action: Action consumed by record console shell.


    Raises:
        ValueError: If an input value is invalid.
    """
    if action not in {"open", "close"}:
        raise ValueError("Unsupported console shell audit action.")
    with SessionLocal() as db:
        record_audit(
            db,
            actor=CONSOLE_ACTOR,
            action=f"console_root_shell_{action}",
            resource_type="local_console",
            resource_id="tty1",
            detail="Authenticated local root Bash session",
        )
        db.commit()


class CursesConsole:
    """Represent curses console.

    Attributes:
        curses: Curses maintained by this cursesconsole.
        stdscr: Stdscr maintained by this cursesconsole.
        message: Message maintained by this cursesconsole.
        message_error: Message error maintained by this cursesconsole.
    """
    def __init__(self, stdscr: Any) -> None:
        """Initialize the curses console.

        Args:
            stdscr: Stdscr consumed by init.
        """
        import curses

        self.curses = curses
        self.stdscr = stdscr
        self.message = ""
        self.message_error = False
        self._force_clear = True
        self._force_redraw = False
        self._started_at = time.monotonic()
        self._initialize_screen()

    def _initialize_screen(self) -> None:
        """Handle initialize screen."""
        curses = self.curses
        curses.curs_set(0)
        curses.noecho()
        curses.cbreak()
        self.stdscr.keypad(True)
        self.stdscr.timeout(1000)
        curses.start_color()
        curses.use_default_colors()
        # Closest terminal representation of the web palette: slate, pale blue, white,
        # Atlaso blue, green, amber, and red. Custom RGB is used when supported.
        if curses.can_change_color() and curses.COLORS >= 16:
            palette = {
                8: (59, 72, 89),     # #0f172a-ish slate
                9: (933, 949, 969),  # #eef2f7
                10: (145, 388, 922), # #2563eb
                11: (396, 455, 545), # #64748b
                12: (82, 502, 239),  # #15803d
                13: (706, 325, 35),  # #b45309
                14: (725, 110, 110), # #b91c1c
                15: (859, 918, 996), # #dbeafe
            }
            for color_id, rgb in palette.items():
                try:
                    curses.init_color(color_id, *rgb)
                except curses.error:
                    break
            slate, soft, blue, muted, good, warn, bad, pale_blue = 8, 9, 10, 11, 12, 13, 14, 15
        elif curses.can_change_color() and curses.COLORS >= 8:
            # TERM=linux commonly advertises only eight slots. Reuse cyan for the
            # web UI's pale-blue header instead of falling back to a black banner.
            try:
                curses.init_color(curses.COLOR_CYAN, 859, 918, 996)
            except curses.error:
                pass
            slate, soft, blue, muted, good, warn, bad, pale_blue = (
                curses.COLOR_BLACK,
                curses.COLOR_WHITE,
                curses.COLOR_BLUE,
                curses.COLOR_BLACK,
                curses.COLOR_GREEN,
                curses.COLOR_YELLOW,
                curses.COLOR_RED,
                curses.COLOR_CYAN,
            )
        else:
            slate, soft, blue, muted, good, warn, bad, pale_blue = (
                curses.COLOR_BLACK,
                curses.COLOR_WHITE,
                curses.COLOR_BLUE,
                curses.COLOR_CYAN,
                curses.COLOR_GREEN,
                curses.COLOR_YELLOW,
                curses.COLOR_RED,
                curses.COLOR_CYAN,
            )
        curses.init_pair(1, slate, pale_blue)
        curses.init_pair(2, slate, soft)
        curses.init_pair(3, curses.COLOR_WHITE, blue)
        curses.init_pair(4, muted, soft)
        curses.init_pair(5, good, soft)
        curses.init_pair(6, warn, soft)
        curses.init_pair(7, bad, soft)
        curses.init_pair(8, curses.COLOR_WHITE, slate)
        curses.init_pair(9, slate, pale_blue)
        curses.init_pair(10, blue, soft)

    @staticmethod
    def _recovery_redraws(now: float) -> list[float]:
        """Bounded redraw window for late tty writes while systemd jobs settle.

        Args:
            now: Current UTC time used for deterministic lifecycle evaluation.
        """
        return [now + 1, now + 3, now + 8]

    def _safe_add(self, y: int, x: int, text: str, attr: int = 0, width: int | None = None) -> None:
        """Handle safe add.

        Args:
            y: Y supplied by the caller.
            x: X supplied by the caller.
            text: Text to parse, render, or persist.
            attr: Attr supplied by the caller.
            width: Width supplied by the caller.
        """
        height, screen_width = self.stdscr.getmaxyx()
        if y < 0 or y >= height or x < 0 or x >= screen_width:
            return
        available = max((width if width is not None else screen_width - x) - 1, 0)
        try:
            self.stdscr.addnstr(y, x, text, available, attr)
        except self.curses.error:
            pass

    def _fill_line(self, y: int, attr: int) -> None:
        """Handle fill line.

        Args:
            y: Y consumed by fill line.
            attr: Attr consumed by fill line.
        """
        _, width = self.stdscr.getmaxyx()
        self._safe_add(y, 0, " " * width, attr, width + 1)

    def _refresh_screen(self) -> None:
        """Handle refresh screen."""
        if self._force_redraw:
            self.stdscr.touchwin()
            self._force_redraw = False
        self.stdscr.refresh()

    def draw_main(self) -> None:
        """Handle draw main."""
        curses = self.curses
        if self._force_clear:
            self.stdscr.clear()
            self._force_clear = False
        else:
            self.stdscr.erase()
        height, width = self.stdscr.getmaxyx()
        if height < 22 or width < 72:
            self._safe_add(1, 2, "Atlaso appliance console requires at least 72 x 22 characters.", curses.color_pair(7) | curses.A_BOLD)
            self._refresh_screen()
            return
        # Keep a complete pale-blue spacer row below Load, followed by a body
        # spacer row, so the management URLs do not visually touch host status.
        header_height = 9
        for y in range(header_height):
            self._fill_line(y, curses.color_pair(1))
        for y in range(header_height, height - 1):
            self._fill_line(y, curses.color_pair(2))
        try:
            status = load_console_status()
        except Exception as exc:  # noqa: BLE001 - recovery console must remain visible.
            status_message, message_error = _console_status_failure(exc, started_at=self._started_at)
            self._safe_add(2, 4, "Atlaso Appliance", curses.color_pair(1) | curses.A_BOLD)
            message_attr = curses.color_pair(7) if message_error else curses.color_pair(1) | curses.A_BOLD
            self._safe_add(5, 4, status_message, message_attr)
            self._draw_footer(height, width)
            self._refresh_screen()
            return

        self._safe_add(1, 4, f"Atlaso Appliance {status.version}", curses.color_pair(1) | curses.A_BOLD)
        self._safe_add(3, 4, f"{status.release} ({status.architecture})", curses.color_pair(1))
        self._safe_add(4, 4, f"Kernel: {status.kernel}", curses.color_pair(1))
        self._safe_add(5, 4, f"CPU: {status.cpu}", curses.color_pair(1))
        self._safe_add(6, 4, f"Memory: {status.memory}", curses.color_pair(1))
        self._safe_add(7, 4, "Load:", curses.color_pair(1))
        self._safe_add(7, 10, status.load, self._load_attr(status.load_severity))

        self._safe_add(10, 4, "Manage this appliance at:", curses.color_pair(2) | curses.A_BOLD)
        row = 11
        for url in status.urls[:3]:
            self._safe_add(row, 6, url, curses.color_pair(2))
            row += 1
        self._safe_add(14, 4, "Management network", curses.color_pair(2) | curses.A_BOLD)
        address = "DHCP" if status.ipv4_method == "dhcp" and not status.ipv4_cidr else (status.ipv4_cidr or "Not configured")
        self._safe_add(15, 6, self._network_table_row("Interface", status.interface, width), curses.color_pair(2))
        ipv4 = self._network_table_row(
            "IPv4",
            address,
            width,
            gateway=status.gateway or "none",
            mode=status.ipv4_method,
        )
        self._safe_add(16, 6, ipv4, curses.color_pair(2))
        ipv6_address = status.ipv6_cidr or ("Not configured" if status.ipv6_mode == "disabled" else "Awaiting RA/SLAAC")
        ipv6 = self._network_table_row(
            "IPv6",
            ipv6_address,
            width,
            gateway=status.ipv6_gateway or "none",
            mode=status.ipv6_mode,
        )
        self._safe_add(17, 6, ipv6, curses.color_pair(2))
        self._safe_add(
            18,
            6,
            self._network_table_row("DNS", ", ".join(status.dns_servers) or "Not configured", width),
            curses.color_pair(2),
        )
        services_heading = "Appliance services"
        if status.maintenance_isolation:
            services_heading += " | Maintenance isolation enabled"
        # The normal 80x30 tty has room to visually separate networking from
        # service health. Preserve the denser arrangement on compact terminals.
        full_service_grid = self._service_grid_fits(height, len(status.services))
        services_row = 20 if full_service_grid else 19
        self._safe_add(services_row, 4, services_heading, curses.color_pair(2) | curses.A_BOLD)
        if full_service_grid:
            column_width = max((width - 4) // 2, 1)
            split_at = (len(status.services) + 1) // 2
            columns = (status.services[:split_at], status.services[split_at:])
            for column_index, services in enumerate(columns):
                x = 4 + column_index * column_width
                for service_index, service in enumerate(services):
                    self._safe_add(
                        services_row + 1 + service_index,
                        x,
                        self._service_cell(service, column_width),
                        self._service_attr(service),
                        column_width,
                    )
        else:
            self._safe_add(services_row + 1, 6, self._service_summary(status.services), curses.color_pair(2), width - 10)
        if self.message:
            message_row = height - 2 if height > 22 else 19
            self._safe_add(message_row, 4, self.message, curses.color_pair(7 if self.message_error else 5) | curses.A_BOLD)
        self._draw_footer(height, width)
        self._refresh_screen()

    @staticmethod
    def _service_grid_fits(height: int, service_count: int) -> bool:
        """Keep the full grid above the message and footer rows.

        Args:
            height: Height consumed by service grid fits.
            service_count: Number of service entries.
        """
        grid_last_row = 20 + ((service_count + 1) // 2)
        message_row = height - 2
        return grid_last_row < message_row

    def _service_attr(self, service: ServiceStatus) -> int:
        """Return service attr.

        Args:
            service: Atlaso or host service affected by the operation.
        """
        curses = self.curses
        if service.runtime_label == "failed":
            return curses.color_pair(7) | curses.A_BOLD
        if service.runtime_label == "unavailable":
            return curses.color_pair(4)
        if service.runtime_label == "running":
            if service.label == "Firewall" or service.enabled_label == "enabled":
                # Brand blue retains strong contrast on the Linux console's
                # gray representation of white without the glare of bright green.
                return curses.color_pair(10)
            return curses.color_pair(6) | curses.A_BOLD
        return curses.color_pair(6)

    def _load_attr(self, severity: str) -> int:
        """Return attr.

        Args:
            severity: Severity consumed by load attr.
        """
        curses = self.curses
        return {
            "warning": curses.color_pair(6) | curses.A_BOLD,
            "critical": curses.color_pair(7) | curses.A_BOLD,
        }.get(severity, curses.color_pair(1))

    @staticmethod
    def _service_cell(service: ServiceStatus, width: int) -> str:
        """Return service cell.

        Args:
            service: Atlaso or host service affected by the operation.
            width: Width consumed by service cell.
        """
        label_width = min(21, max(width - 3, 1))
        return f"{service.label:<{label_width}} {service.display_label}"[: max(width - 1, 1)].rstrip()

    @staticmethod
    def _service_summary(services: tuple[ServiceStatus, ...]) -> str:
        """Return service summary.

        Args:
            services: Services consumed by service summary.
        """
        counts = {label: sum(service.runtime_label == label for service in services) for label in ("running", "failed", "stopped", "unavailable")}
        firewall = next((service.enabled_label for service in services if service.label == "Firewall"), "unavailable")
        return (
            f"{counts['running']} running | {counts['failed']} failed | {counts['stopped']} stopped | "
            f"{counts['unavailable']} unavailable | Firewall {firewall}"
        )

    @staticmethod
    def _network_table_row(
        label: str,
        value: str,
        screen_width: int,
        *,
        gateway: str | None = None,
        mode: str | None = None,
        auxiliary: tuple[str, str] | None = None,
    ) -> str:
        """Format management state with stable columns for the current tty width.

        Args:
            label: Human-readable label used to identify the result.
            value: Candidate value consumed by network table row.
            screen_width: Screen width consumed by network table row.
            gateway: Gateway consumed by network table row.
            mode: Mode consumed by network table row.
            auxiliary: Auxiliary consumed by network table row.
        """
        content_width = max(screen_width - 8, 1)
        label_width = 10
        if gateway is not None or mode is not None:
            address_width, gateway_width = (
                (36, 22)
                if screen_width >= 100
                else (24, 16)
                if screen_width >= 80
                else (18, 14)
            )
            address = value[:address_width]
            gateway_value = (gateway or "none")[:gateway_width]
            row = (
                f"{label:<{label_width}}{address:<{address_width}}"
                f" GW {gateway_value:<{gateway_width}} Mode {mode or 'none'}"
            )
            return row[:content_width].rstrip()
        if auxiliary:
            auxiliary_text = f"{auxiliary[0]}: {auxiliary[1]}"
            value_width = max(content_width - label_width - len(auxiliary_text) - 1, 1)
            row = f"{label:<{label_width}}{value[:value_width]:<{value_width}} {auxiliary_text}"
            return row[:content_width].rstrip()
        return f"{label:<{label_width}}{value}"[:content_width].rstrip()

    def _draw_footer(self, height: int, width: int) -> None:
        """Handle draw footer.

        Args:
            height: Height consumed by draw footer.
            width: Width consumed by draw footer.
        """
        curses = self.curses
        self._fill_line(height - 1, curses.color_pair(3))
        self._safe_add(height - 1, 1, "<F1> Help", curses.color_pair(3) | curses.A_BOLD)
        self._safe_add(height - 1, 12, "<F2> Customize", curses.color_pair(3) | curses.A_BOLD)
        self._safe_add(height - 1, 29, "<F3> Top", curses.color_pair(3) | curses.A_BOLD)
        self._safe_add(height - 1, 40, "<F4> Console", curses.color_pair(3) | curses.A_BOLD)
        label = "<F12> Power"
        self._safe_add(height - 1, max(width - len(label) - 2, 54), label, curses.color_pair(3) | curses.A_BOLD)

    def show_help(self) -> None:
        """Handle show help."""
        curses = self.curses
        height, width = self.stdscr.getmaxyx()
        box_width = min(74, width - 4)
        box_height = min(24, height - 4)
        top = max((height - box_height) // 2, 1)
        left = max((width - box_width) // 2, 1)
        window = curses.newwin(box_height, box_width, top, left)
        window.keypad(True)
        page = 0
        selected = 1
        buttons = ("Previous", "Next", "Close")
        button_width = 14
        button_start = max((box_width - button_width * len(buttons)) // 2, 2)

        while True:
            page_title, lines = HELP_PAGES[page]
            window.erase()
            window.bkgd(" ", curses.color_pair(2))
            window.box()
            self._draw_dialog_title(window, f"Console help {page + 1}/{len(HELP_PAGES)} - {page_title}", box_width)
            for row, line in enumerate(lines[: box_height - 6], start=2):
                attr = curses.color_pair(2) | curses.A_BOLD if line.endswith(":") else curses.color_pair(4)
                window.addnstr(row, 3, line, box_width - 6, attr)

            for index, button in enumerate(buttons):
                available = index == 2 or (index == 0 and page > 0) or (index == 1 and page < len(HELP_PAGES) - 1)
                if index == selected and available:
                    attr = curses.color_pair(3) | curses.A_BOLD
                else:
                    attr = curses.color_pair(9 if available else 4)
                window.addnstr(box_height - 3, button_start + index * button_width, f"< {button} >", button_width - 1, attr)
            window.addnstr(
                box_height - 2,
                3,
                "Left/Right/PgUp/PgDn: page  Enter: select  Esc/F1: close",
                box_width - 6,
                curses.color_pair(4),
            )
            window.refresh()
            key = window.getch()
            if key in {27, curses.KEY_F1, curses.KEY_RESIZE}:
                return
            if key in {curses.KEY_LEFT, curses.KEY_PPAGE, ord("p")}:
                page = max(page - 1, 0)
                selected = 0 if page > 0 else 1
                continue
            if key in {curses.KEY_RIGHT, curses.KEY_NPAGE, ord("n"), ord(" ")}:
                page = min(page + 1, len(HELP_PAGES) - 1)
                selected = 1 if page < len(HELP_PAGES) - 1 else 2
                continue
            if key in {9, curses.KEY_DOWN}:
                selected = (selected + 1) % len(buttons)
                continue
            if key in {curses.KEY_BTAB, curses.KEY_UP}:
                selected = (selected - 1) % len(buttons)
                continue
            if key in {10, 13, curses.KEY_ENTER}:
                if selected == 0 and page > 0:
                    page -= 1
                elif selected == 1 and page < len(HELP_PAGES) - 1:
                    page += 1
                    if page == len(HELP_PAGES) - 1:
                        selected = 2
                elif selected == 2:
                    return

    def _draw_dialog_title(self, window: Any, title: str, box_width: int) -> None:
        """Handle draw dialog title.

        Args:
            window: Window consumed by draw dialog title.
            title: Title consumed by draw dialog title.
            box_width: Box width consumed by draw dialog title.
        """
        framed_title = f" {title} "
        window.addnstr(
            0,
            max((box_width - len(framed_title)) // 2, 2),
            framed_title,
            box_width - 4,
            self.curses.color_pair(2) | self.curses.A_BOLD,
        )

    def _dialog(self, title: str, lines: list[str], options: list[str]) -> int:
        """Return dialog.

        Args:
            title: Title consumed by dialog.
            lines: Source or output lines being parsed.
            options: Options controlling the operation.
        """
        curses = self.curses
        height, width = self.stdscr.getmaxyx()
        box_width = min(max(max([len(title), *[len(line) for line in lines], *[len(option) for option in options]]) + 8, 48), width - 4)
        box_height = min(len(lines) + len(options) + 6, height - 4)
        top = max((height - box_height) // 2, 1)
        left = max((width - box_width) // 2, 1)
        window = curses.newwin(box_height, box_width, top, left)
        window.keypad(True)
        selected = 0
        while True:
            window.erase()
            window.bkgd(" ", curses.color_pair(2))
            window.box()
            self._draw_dialog_title(window, title, box_width)
            row = 3
            for line in lines:
                window.addnstr(row, 3, line, box_width - 6, curses.color_pair(4))
                row += 1
            for index, option in enumerate(options):
                attr = curses.color_pair(3) | curses.A_BOLD if index == selected else curses.color_pair(9)
                window.addnstr(row + index, 3, f" < {option} > ", box_width - 6, attr)
            window.addnstr(
                box_height - 2,
                3,
                "Up/Down: move   Enter: select   Esc: cancel",
                box_width - 6,
                curses.color_pair(4),
            )
            window.refresh()
            key = window.getch()
            if key in {curses.KEY_UP, ord("k")}:
                selected = (selected - 1) % len(options)
            elif key in {curses.KEY_DOWN, ord("j")}:
                selected = (selected + 1) % len(options)
            elif key in {10, 13, curses.KEY_ENTER}:
                return selected
            elif key in {27, curses.KEY_F2, curses.KEY_F12}:
                return len(options) - 1

    def _prompt(self, title: str, label: str, initial: str = "", *, secret: bool = False) -> str | None:
        """Return prompt.

        Args:
            title: Title consumed by prompt.
            label: Human-readable label used to identify the result.
            initial: Initial consumed by prompt.
            secret: Whether secret applies to the operation.
        """
        curses = self.curses
        height, width = self.stdscr.getmaxyx()
        box_width = min(max(len(label) + 8, 64), width - 4)
        box_height = 10
        window = curses.newwin(box_height, box_width, max((height - box_height) // 2, 1), max((width - box_width) // 2, 1))
        window.keypad(True)
        window.bkgd(" ", curses.color_pair(2))
        window.box()
        self._draw_dialog_title(window, title, box_width)
        window.addnstr(2, 3, label, box_width - 6, curses.color_pair(4) | curses.A_BOLD)
        value = initial
        cursor = len(value)
        focus = "field"
        while True:
            field_width = box_width - 7
            start = max(min(cursor - field_width + 1, max(len(value) - field_width, 0)), 0)
            visible_value = value[start : start + field_width]
            shown = "*" * len(visible_value) if secret else visible_value
            # Match the light editable fields in Network customization. The old
            # inverse pair rendered the password entry as a black bar on tty1.
            window.addnstr(3, 3, " " * (box_width - 6), box_width - 6, curses.color_pair(9))
            window.addnstr(3, 3, shown, box_width - 6, curses.color_pair(9))
            apply_attr = curses.color_pair(3 if focus == "apply" else 9) | (curses.A_BOLD if focus == "apply" else 0)
            cancel_attr = curses.color_pair(3 if focus == "cancel" else 9) | (curses.A_BOLD if focus == "cancel" else 0)
            window.addnstr(5, box_width // 2 - 12, " < Apply > ", 11, apply_attr)
            window.addnstr(5, box_width // 2 + 2, " < Cancel > ", 12, cancel_attr)
            window.addnstr(
                7,
                3,
                "Tab/Up/Down: move   Enter: apply   Esc: cancel",
                box_width - 6,
                curses.color_pair(4),
            )
            if focus == "field":
                window.move(3, min(3 + cursor - start, box_width - 4))
                curses.curs_set(1)
            else:
                curses.curs_set(0)
            window.refresh()
            key = window.get_wch()
            if key in {27, "\x1b"}:
                curses.curs_set(0)
                return None
            if key in {9, "\t", curses.KEY_DOWN}:
                focus = {"field": "apply", "apply": "cancel", "cancel": "field"}[focus]
                continue
            if key in {curses.KEY_BTAB, curses.KEY_UP}:
                focus = {"field": "cancel", "cancel": "apply", "apply": "field"}[focus]
                continue
            if focus != "field" and key in {curses.KEY_LEFT, curses.KEY_RIGHT}:
                focus = "cancel" if focus == "apply" else "apply"
                continue
            if key in {10, 13, "\n", "\r", curses.KEY_ENTER} or (focus != "field" and key in {" ", ord(" ")}):
                curses.curs_set(0)
                return None if focus == "cancel" else value
            if focus == "field":
                value, cursor = self._edit_prompt_text(value, cursor, key)

    def _edit_prompt_text(self, value: str, cursor: int, key: str | int, *, limit: int = 500) -> tuple[str, int]:
        """Edit password text using decoded characters from curses.get_wch().

        Args:
            value: Candidate value consumed by edit prompt text.
            cursor: Cursor consumed by edit prompt text.
            key: Stable key identifying the setting, secret, or mapping entry.
            limit: Limit consumed by edit prompt text.
        """
        if isinstance(key, str):
            if key in {"\b", "\x7f"} and cursor > 0:
                return value[: cursor - 1] + value[cursor:], cursor - 1
            if key.isprintable() and len(value) < limit:
                return value[:cursor] + key + value[cursor:], cursor + len(key)
            return value, cursor
        return self._edit_text(value, cursor, key, limit=limit)

    def _edit_text(self, value: str, cursor: int, key: int, *, limit: int = 500) -> tuple[str, int]:
        """Return edit text.

        Args:
            value: Candidate value consumed by edit text.
            cursor: Cursor consumed by edit text.
            key: Stable key identifying the setting, secret, or mapping entry.
            limit: Limit consumed by edit text.
        """
        curses = self.curses
        if key == curses.KEY_LEFT:
            return value, max(cursor - 1, 0)
        if key == curses.KEY_RIGHT:
            return value, min(cursor + 1, len(value))
        if key == curses.KEY_HOME:
            return value, 0
        if key == curses.KEY_END:
            return value, len(value)
        if key in {curses.KEY_BACKSPACE, 127, 8} and cursor > 0:
            return value[: cursor - 1] + value[cursor:], cursor - 1
        if key == curses.KEY_DC and cursor < len(value):
            return value[:cursor] + value[cursor + 1 :], cursor
        if 32 <= key <= 126 and len(value) < limit:
            return value[:cursor] + chr(key) + value[cursor:], cursor + 1
        return value, cursor

    def _management_form(self, status: ConsoleStatus) -> tuple[str, str, str, str, str, str, str] | None:
        """Return management form.

        Args:
            status: Lifecycle or operation status to record or evaluate.
        """
        curses = self.curses
        height, width = self.stdscr.getmaxyx()
        box_height = min(20, height - 2)
        box_width = min(68, width - 4)
        top = max((height - box_height) // 2, 1)
        left = max((width - box_width) // 2, 1)
        window = curses.newwin(box_height, box_width, top, left)
        window.keypad(True)

        values = {
            "ipv4_method": status.ipv4_method,
            "ipv4_cidr": status.ipv4_cidr,
            "gateway": status.gateway,
            "ipv6_mode": status.ipv6_mode,
            "ipv6_cidr": status.ipv6_cidr,
            "ipv6_gateway": status.ipv6_gateway,
            "dns_servers": ", ".join(status.dns_servers),
        }
        cursors = {name: len(value) for name, value in values.items()}
        order = [
            "ipv4_method",
            "ipv4_cidr",
            "gateway",
            "ipv6_mode",
            "ipv6_cidr",
            "ipv6_gateway",
            "dns_servers",
            "apply",
            "cancel",
        ]
        selected = 0
        modes = {"ipv4_method": ("dhcp", "static"), "ipv6_mode": ("disabled", "automatic", "static")}

        def enabled(name: str) -> bool:
            """Return enabled.

            Args:
                name: Stable name identifying the resource or operation.
            """
            if name in {"ipv4_cidr", "gateway"}:
                return values["ipv4_method"] == "static"
            if name in {"ipv6_cidr", "ipv6_gateway"}:
                return values["ipv6_mode"] == "static"
            return True

        def move(delta: int) -> None:
            """Handle move.

            Args:
                delta: Delta consumed by move.
            """
            nonlocal selected
            for _ in order:
                selected = (selected + delta) % len(order)
                if enabled(order[selected]):
                    return

        field_rows = {
            "ipv4_method": (4, "Mode"),
            "ipv4_cidr": (5, "Address / prefix"),
            "gateway": (6, "Gateway"),
            "ipv6_mode": (10, "Mode"),
            "ipv6_cidr": (11, "Address / prefix"),
            "ipv6_gateway": (12, "Gateway"),
            "dns_servers": (14, "DNS servers"),
        }
        label_x = 5
        field_x = 25
        field_width = box_width - field_x - 4

        while True:
            active_name = order[selected]
            window.erase()
            window.bkgd(" ", curses.color_pair(2))
            window.box()
            title = " Management IP, gateways, and DNS "
            window.addnstr(0, max((box_width - len(title)) // 2, 2), title, len(title), curses.color_pair(2) | curses.A_BOLD)
            window.addnstr(2, 3, "IPv4 configuration", box_width - 6, curses.color_pair(3) | curses.A_BOLD)
            window.addnstr(8, 3, "IPv6 configuration", box_width - 6, curses.color_pair(3) | curses.A_BOLD)

            for name, (row, label) in field_rows.items():
                is_enabled = enabled(name)
                label_attr = curses.color_pair(2 if is_enabled else 4)
                window.addnstr(row, label_x, f"{label}:", field_x - label_x - 2, label_attr | curses.A_BOLD)
                if name in modes:
                    display = f"< {values[name].upper()} >"
                else:
                    inner_width = field_width - 2
                    cursor = cursors[name]
                    start = max(min(cursor - inner_width + 1, max(len(values[name]) - inner_width, 0)), 0)
                    display = values[name][start : start + inner_width]
                field_attr = curses.color_pair(3 if name == active_name else (9 if is_enabled else 4))
                if name == active_name:
                    field_attr |= curses.A_BOLD
                window.addnstr(row, field_x, " " * field_width, field_width, field_attr)
                window.addnstr(row, field_x + 1, display, field_width - 2, field_attr)

            apply_attr = curses.color_pair(3 if active_name == "apply" else 9) | (curses.A_BOLD if active_name == "apply" else 0)
            cancel_attr = curses.color_pair(3 if active_name == "cancel" else 9) | (curses.A_BOLD if active_name == "cancel" else 0)
            window.addnstr(16, box_width // 2 - 12, " < Apply > ", 11, apply_attr)
            window.addnstr(16, box_width // 2 + 2, " < Cancel > ", 12, cancel_attr)
            window.addnstr(18, 3, "Tab/Up/Down: move   Left/Right: edit/select   Esc: cancel", box_width - 6, curses.color_pair(4))

            if active_name in field_rows and active_name not in modes:
                row, _ = field_rows[active_name]
                value = values[active_name]
                cursor = cursors[active_name]
                inner_width = field_width - 2
                start = max(min(cursor - inner_width + 1, max(len(value) - inner_width, 0)), 0)
                window.move(row, min(field_x + 1 + cursor - start, field_x + field_width - 2))
                curses.curs_set(1)
            else:
                curses.curs_set(0)
            window.refresh()
            key = window.getch()
            if key == 27:
                curses.curs_set(0)
                return None
            if key in {curses.KEY_DOWN, 9}:
                move(1)
                continue
            if key in {curses.KEY_UP, curses.KEY_BTAB}:
                move(-1)
                continue
            if active_name in modes:
                choices = modes[active_name]
                if key in {curses.KEY_LEFT, curses.KEY_RIGHT, 10, 13, curses.KEY_ENTER, ord(" ")}:
                    offset = -1 if key == curses.KEY_LEFT else 1
                    values[active_name] = choices[(choices.index(values[active_name]) + offset) % len(choices)]
                    if active_name == "ipv4_method" and values[active_name] == "dhcp":
                        values["ipv4_cidr"] = values["gateway"] = ""
                        cursors["ipv4_cidr"] = cursors["gateway"] = 0
                    if active_name == "ipv6_mode" and values[active_name] != "static":
                        values["ipv6_cidr"] = values["ipv6_gateway"] = ""
                        cursors["ipv6_cidr"] = cursors["ipv6_gateway"] = 0
                continue
            if active_name == "apply" and key in {10, 13, curses.KEY_ENTER, ord(" ")}:
                curses.curs_set(0)
                return (
                    values["ipv4_method"],
                    values["ipv4_cidr"] if values["ipv4_method"] == "static" else "",
                    values["gateway"] if values["ipv4_method"] == "static" else "",
                    values["ipv6_mode"],
                    values["ipv6_cidr"] if values["ipv6_mode"] == "static" else "",
                    values["ipv6_gateway"] if values["ipv6_mode"] == "static" else "",
                    values["dns_servers"],
                )
            if active_name == "cancel" and key in {10, 13, curses.KEY_ENTER, ord(" ")}:
                curses.curs_set(0)
                return None
            if active_name in field_rows:
                values[active_name], cursors[active_name] = self._edit_text(
                    values[active_name], cursors[active_name], key, limit=200
                )

    def _require_authentication(self) -> bool:
        """Return require authentication."""
        password = self._prompt("Photon OS root authentication", "Root password:", secret=True)
        if password is None:
            return False
        authenticated = authenticate_root(password)
        password = ""
        if not authenticated:
            self._dialog(
                "Root authentication failed",
                ["The Photon OS root password was incorrect."],
                ["OK"],
            )
            # Authentication errors are modal and must not linger in the main
            # console message row after the operator dismisses the dialog.
            self.message = ""
            self.message_error = False
        return authenticated

    def _apply_action(self, operation: Callable[[], str | dict[str, Any] | None], success: str) -> None:
        """Update action.

        Args:
            operation: Operation consumed by apply action.
            success: Success consumed by apply action.
        """
        try:
            result = operation()
            suffix = f" ({result})" if isinstance(result, str) else ""
            self.message = f"{success}{suffix}"
            self.message_error = False
        except Exception as exc:  # noqa: BLE001 - show safe operation failure in recovery console.
            self.message = str(exc)
            self.message_error = True
        finally:
            # Service actions can change the active console while systemd settles. Force a
            # physical clear when the menu closes instead of trusting the curses diff buffer.
            self._force_clear = True

    def _run_interactive(self, command: list[str], label: str) -> int | None:
        """Run interactive.

        Args:
            command: Command and arguments to execute.
            label: Human-readable label used to identify the result.


        Returns:
            The run interactive result.
        """
        curses = self.curses
        try:
            curses.def_prog_mode()
            curses.endwin()
            self._clear_terminal()
            # The service sends its own stderr to the journal. Interactive child
            # programs must explicitly bind all three streams to tty1 so Bash's
            # prompt and errors remain visible to the local operator.
            result = subprocess.run(
                command,
                check=False,
                stdin=sys.stdin,
                stdout=sys.stdout,
                stderr=sys.stdout,
            )
            if result.returncode not in {0, 130}:
                self.message = f"{label} exited with status {result.returncode}."
                self.message_error = True
            return result.returncode
        except FileNotFoundError:
            self.message = f"{label} is not installed on this appliance."
            self.message_error = True
            return None
        except KeyboardInterrupt:
            return 130
        except OSError as exc:
            self.message = f"Unable to start {label}: {exc}"
            self.message_error = True
            return None
        finally:
            self._clear_terminal()
            try:
                curses.reset_prog_mode()
            except curses.error:
                pass
            self._initialize_screen()
            self._force_clear = True

    @staticmethod
    def _clear_terminal() -> None:
        """Clear the physical tty before and after an interactive handoff."""
        try:
            sys.stdout.write("\x1b[2J\x1b[H")
            sys.stdout.flush()
        except OSError:
            pass

    def show_top(self) -> None:
        """Temporarily hand tty1 to top, then restore the curses console."""
        self._run_interactive(["top"], "top")

    def show_authenticated_top(self) -> None:
        """Open top only after a fresh Photon root-password check."""
        if self._require_authentication():
            self.show_top()

    def show_shell(self) -> None:
        """Open an authenticated, auditable root login shell on tty1."""
        try:
            record_console_shell("open")
        except Exception as exc:  # noqa: BLE001 - fail closed when the audit cannot be persisted.
            self.message = f"Unable to audit console access: {exc}"
            self.message_error = True
            return
        try:
            self._run_interactive([BASH_PATH, "--login"], "Bash console")
        finally:
            try:
                record_console_shell("close")
            except Exception as exc:  # noqa: BLE001 - preserve the local recovery surface.
                self.message = f"Bash console closed; audit close failed: {exc}"
                self.message_error = True

    def customize(self) -> None:
        """Handle customize."""
        if not self._require_authentication():
            return
        while True:
            status = load_console_status()
            isolation_label = "Restore appliance services" if status.maintenance_isolation else "Disable all appliance services"
            choice = self._dialog(
                "Customize Atlaso",
                ["Only management recovery settings are available from the local console."],
                ["Management IP, gateways, and DNS", "Enable firewall" if not status.firewall_enabled else "Disable firewall", isolation_label, "Back"],
            )
            if choice == 3:
                return
            if choice == 0:
                management = self._management_form(status)
                if management is None:
                    self._restore_main_surface()
                    continue
                ipv4_method, cidr, gateway, ipv6_mode, ipv6_cidr, ipv6_gateway, dns_servers = management
                confirm = self._dialog(
                    "Apply management network and DNS",
                    [
                        f"IPv4: {ipv4_method} {cidr}",
                        f"IPv4 gateway: {gateway or 'none'}",
                        f"IPv6: {ipv6_mode} {ipv6_cidr}",
                        f"IPv6 gateway: {ipv6_gateway or 'none'}",
                        f"DNS: {dns_servers}",
                    ],
                    ["Apply", "Cancel"],
                )
                if confirm == 0:
                    self._apply_action(
                        lambda: configure_management(
                            ipv4_method,
                            cidr,
                            gateway,
                            ipv6_mode,
                            ipv6_cidr,
                            ipv6_gateway,
                            dns_servers,
                        ),
                        "Management networking and DNS applied",
                    )
                self._restore_main_surface()
            elif choice == 1:
                enabling_firewall = not status.firewall_enabled
                firewall_label = "Enable firewall" if enabling_firewall else "Disable firewall"
                warning = (
                    "Rebuilds and applies the current Atlaso nftables rules."
                    if enabling_firewall
                    else "Clears the active nftables ruleset and persists that state across reboot."
                )
                confirm = self._dialog(firewall_label, [warning], [firewall_label, "Cancel"])
                if confirm == 0:
                    self._apply_action(lambda: configure_firewall(enabling_firewall), f"{firewall_label} completed")
            elif choice == 2:
                enabling = not status.maintenance_isolation
                warning = (
                    "Stops and disables appliance application services."
                    if enabling
                    else "Restores only the services that were enabled before isolation."
                )
                confirm = self._dialog(
                    isolation_label,
                    [warning, "Management networking, firewall, and this console stay available."],
                    [isolation_label, "Cancel"],
                )
                if confirm == 0:
                    self._apply_action(lambda: set_maintenance_isolation(enabling), f"{isolation_label} completed")

    def _restore_main_surface(self) -> None:
        """Physically clear nested form remnants before rebuilding a parent menu."""
        self._force_clear = True
        self.draw_main()

    def power_menu(self) -> None:
        """Handle power menu."""
        if not self._require_authentication():
            return
        choice = self._dialog(
            "Shut down / Restart",
            ["The selected power action is scheduled after this console records it."],
            ["Restart appliance", "Shut down appliance", "Cancel"],
        )
        if choice == 0:
            if self._dialog("Confirm restart", ["The appliance will restart after a short delay."], ["Restart appliance", "Cancel"]) == 0:
                self._apply_action(lambda: schedule_power("reboot"), "Restart scheduled")
        elif choice == 1:
            if self._dialog("Confirm shutdown", ["The appliance will shut down after a short delay."], ["Shut down appliance", "Cancel"]) == 0:
                self._apply_action(lambda: schedule_power("shutdown"), "Shutdown scheduled")

    def run(self) -> None:
        """Run operation."""
        curses = self.curses
        self.draw_main()
        last_refresh = time.monotonic()
        recovery_redraws = self._recovery_redraws(last_refresh)
        while True:
            key = self.stdscr.getch()
            if key == curses.KEY_F1:
                self.show_help()
                self.draw_main()
                last_refresh = time.monotonic()
                recovery_redraws = self._recovery_redraws(last_refresh)
            elif key == curses.KEY_F2:
                self.customize()
                self.draw_main()
                last_refresh = time.monotonic()
                recovery_redraws = self._recovery_redraws(last_refresh)
            elif key == curses.KEY_F3:
                self.show_authenticated_top()
                self.draw_main()
                last_refresh = time.monotonic()
                recovery_redraws = self._recovery_redraws(last_refresh)
            elif key == curses.KEY_F4:
                if self._require_authentication():
                    self.show_shell()
                self.draw_main()
                last_refresh = time.monotonic()
                recovery_redraws = self._recovery_redraws(last_refresh)
            elif key == curses.KEY_F12:
                self.power_menu()
                self.draw_main()
                last_refresh = time.monotonic()
                recovery_redraws = self._recovery_redraws(last_refresh)
            elif recovery_redraws and time.monotonic() >= recovery_redraws[0]:
                recovery_redraws.pop(0)
                # Repaint every cell without clearing to black first. This repairs
                # out-of-band tty writes without exposing a blank intermediate frame.
                self._force_redraw = True
                self.draw_main()
                last_refresh = time.monotonic()
            elif key == curses.KEY_RESIZE or time.monotonic() - last_refresh >= CONSOLE_REFRESH_SECONDS:
                self.draw_main()
                last_refresh = time.monotonic()


def main() -> int:
    """Run the command-line entry point.

    Returns:
        The main result.
    """
    if os.name != "posix":
        print("Atlaso appliance console is available only on the Photon OS appliance.", file=sys.stderr)
        return 2
    if os.geteuid() != 0:
        print("Atlaso appliance console must run as root on the local virtual console.", file=sys.stderr)
        return 2
    # Database/config modules may already have been imported by the entrypoint, so refresh their cached settings.
    from atlaso.app.config import get_settings

    get_settings.cache_clear()
    try:
        import curses

        curses.wrapper(lambda stdscr: CursesConsole(stdscr).run())
    except KeyboardInterrupt:
        return 0
    except Exception as exc:  # noqa: BLE001 - systemd will restart the recovery console.
        print(f"Atlaso appliance console failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
