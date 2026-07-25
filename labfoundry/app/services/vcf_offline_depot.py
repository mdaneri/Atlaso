from __future__ import annotations

import json
import re
import shlex
import shutil
import subprocess
import tarfile
from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path

from labfoundry.app.models import Setting, User, VcfDepotDownloadProfile, VcfOfflineDepotSettings
from labfoundry.app.services.dnsmasq import split_addresses, split_interfaces
from labfoundry.app.services.nginx import format_nginx_listen


VCF_DEPOT_DEFAULT_HOSTNAME = "depot.labfoundry.internal"
VCF_DEPOT_LEGACY_STORE_PATH = "/srv/repository"
VCF_DEPOT_DEFAULT_STORE_PATH = "/mnt/labfoundry-vcf-offline-depot"
VCF_DEPOT_DEFAULT_CONFIG_PATH = "/etc/labfoundry/nginx/sites.d/vcf-offline-depot.conf"
VCF_DEPOT_STAGED_CONFIG_PATH = "/var/lib/labfoundry/apply/vcf-offline-depot/labfoundry-vcf-offline-depot.conf"
VCF_DEPOT_DEFAULT_USERNAME = "vcf-depot"
VCF_DEPOT_HTPASSWD_PATH = "/etc/labfoundry/nginx/htpasswd/vcf-offline-depot.htpasswd"
VCF_DEPOT_APPLICATION_PROPERTIES_NAME = "application-prodv2.properties"
VCF_DEPOT_APPLICATION_PROPERTIES_CONTENT_KEY = "vcf_depot_application_properties_content"
VCF_DEPOT_APPLICATION_PROPERTIES_SOURCE_KEY = "vcf_depot_application_properties_source"
VCF_DEPOT_APPLICATION_PROPERTIES_UPDATED_AT_KEY = "vcf_depot_application_properties_updated_at"
VCF_DEPOT_STAGED_APPLICATION_PROPERTIES_PATH = f"/var/lib/labfoundry/apply/vcf-offline-depot/{VCF_DEPOT_APPLICATION_PROPERTIES_NAME}"
VCF_DEPOT_STAGED_TOOL_DIR = "/opt/labfoundry/vcf-download-tool"
VCF_DEPOT_RUNTIME_TOOL_DIR = "/var/lib/labfoundry/vcfDownloadTool/active-tool"
VCF_DEPOT_UPLOAD_DIR = Path("vcfDownloadTool")
VCF_DEPOT_EXTRACT_DIR = VCF_DEPOT_UPLOAD_DIR / "active-tool"
VCF_DEPOT_ARCHIVE_PATTERN = "vcf-download-tool-*.tar.gz"
VCF_DEPOT_TOKEN_NAME_KEY = "vcf_depot_download_token_name"
VCF_DEPOT_TOKEN_VALUE_KEY = "vcf_depot_download_token_value"
VCF_DEPOT_ACTIVATION_NAME_KEY = "vcf_depot_activation_code_name"
VCF_DEPOT_ACTIVATION_VALUE_KEY = "vcf_depot_activation_code_value"
VCF_DEPOT_TOOL_VERSION_SOURCE_KEY = "vcf_depot_tool_version_source"
VCF_DEPOT_TOOL_VERSION_SOURCE_COMMAND = "vcf-download-tool --version"
VCF_DEPOT_RUNTIME_RESET_PENDING_KEY = "vcf_depot_runtime_reset_pending"
VCF_DEPOT_SOFTWARE_DEPOT_ID_KEY = "vcf_depot_software_depot_id"
VCF_DEPOT_SOFTWARE_DEPOT_ID_GENERATED_AT_KEY = "vcf_depot_software_depot_id_generated_at"
VCF_DEPOT_SOFTWARE_DEPOT_ID_ERROR_KEY = "vcf_depot_software_depot_id_error"
VCF_DEPOT_STAGED_TOKEN_FILE = f"{VCF_DEPOT_RUNTIME_TOOL_DIR}/secrets/download-token.txt"
VCF_DEPOT_STAGED_ACTIVATION_FILE = f"{VCF_DEPOT_RUNTIME_TOOL_DIR}/secrets/activation-code.txt"
VCF_DEPOT_GET_SOFTWARE_DEPOT_ID_COMMAND = ["vcf-download-tool", "configuration", "get", "--software-depot-id"]
VCF_DEPOT_STATUS_VALUES = {"planned", "ready", "synced", "blocked"}
VCF_DEPOT_PROFILE_TYPES = {"binaries", "metadata", "esx"}
VCF_DEPOT_SKUS = {"VCF", "VVF"}
VCF_DEPOT_BINARY_TYPES = {"INSTALL", "UPGRADE"}
VCF_DEPOT_ESX_DISABLED_PLATFORMS = (
    "esxio-9.1-INTL",
    "armEsx-9.1-INTL",
    "embeddedEsx-8.0-INTL",
    "embeddedEsx-7.0-INTL",
    "embeddedEsx-9.0-INTL",
    "embeddedEsx-9.1-INTL",
    "esxio-8.0-INTL",
    "esxio-9.0-INTL",
    "embeddedEsx-6.7-INT",
)
VCF_DEPOT_COMPONENTS: dict[str, str] = {
    "DEPOT_SERVICE": "Software depot",
    "ESX_HOST": "VMware ESX",
    "HCX": "VCF Operations HCX",
    "NSX_T_MANAGER": "NSX Manager",
    "SDDC_MANAGER_VCF": "SDDC Manager",
    "TELEMETRY_ACCEPTOR": "Telemetry",
    "VCF_CONSUMPTION_CLI": "VCF Consumption CLI",
    "VCF_CONSUMPTION_CLI_PLUGINS": "VCF Consumption CLI Plugins",
    "VCF_FLEET_LCM": "Fleet lifecycle",
    "VCF_LICENSE_SERVER": "License server",
    "VCF_OBSERVABILITY_DATA_PLATFORM": "Observability Data Platform",
    "VCF_OPS_CLOUD_PROXY": "Cloud proxy",
    "VCF_SALT": "Salt Master",
    "VCF_SALT_RAAS": "Salt RaaS",
    "VCF_SDDC_LCM": "SDDC lifecycle",
    "VCF_SERVICE_VCD_MIGRATION_BACKEND": "VCF Service VCD Migration Backend",
    "VCFDT": "VCF Download Tool",
    "VCFMS_METRICS_STORE": "VCF Management Services Metrics Store",
    "VCENTER": "VMware vCenter",
    "VIDB": "Identity broker",
    "VMRC": "VMware Remote Console",
    "VMTOOLS": "VMware Tools",
    "VRA": "VCF Automation",
    "VRLI": "Log management",
    "VRNI": "VCF Operations for networks",
    "VRO": "VCF Operations orchestrator",
    "VROPS": "VCF Operations",
    "VRSLCM": "VCF Operations fleet management (9.0 only)",
    "VSP": "vSphere Supervisor Platform",
    "VSAN_ESA_WITNESS": "vSAN ESA Witness",
    "VSAN_FILE_SERVICES": "vSAN File Services",
    "VSAN_OSA_WITNESS": "vSAN OSA Witness",
}
VCF_DEPOT_LIFECYCLE_MANAGERS: dict[str, str] = {
    "SDDC_MANAGER_VCF": "SDDC Manager",
    "VRSLCM": "VCF Operations Fleet Management",
    "VCF_FLEET_LCM": "Fleet Lifecycle",
    "SELF": "Self-managed",
}
HOSTNAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{1,251}[A-Za-z0-9]$")
VCF_DEPOT_INVALID_ARCHIVE_MESSAGE = "VCF Download Tool archive appears incomplete or invalid. Upload the full vcf-download-tool-*.tar.gz file again."


@dataclass(frozen=True)
class SecretState:
    present: bool
    filename: str = ""
    updated_at: str = ""


@dataclass(frozen=True)
class SoftwareDepotIdResult:
    success: bool
    software_depot_id: str
    command: list[str]
    error: str = ""


def find_local_vcf_download_tool_archive(upload_dir: Path = VCF_DEPOT_UPLOAD_DIR) -> Path | None:
    if not upload_dir.exists():
        return None
    archives = sorted(upload_dir.glob(VCF_DEPOT_ARCHIVE_PATTERN), key=lambda path: path.stat().st_mtime, reverse=True)
    return archives[0] if archives else None


def detect_vcf_download_tool_version(archive_path: str | Path) -> str:
    path = Path(archive_path)
    if not path.exists():
        return ""
    try:
        with tarfile.open(path, "r:gz") as archive:
            version_file = archive.extractfile("conf/tool-version.txt")
            if version_file is None:
                return ""
            return version_file.read(200).decode("utf-8", errors="replace").strip()
    except (EOFError, tarfile.TarError, OSError):
        return ""


def parse_vcf_download_tool_version(output: str) -> str:
    match = re.search(r"\b\d+(?:\.\d+){2,}(?:[-+][A-Za-z0-9._-]+)?\b", output or "")
    return match.group(0) if match else ""


def _read_properties_from_archive(archive_path: str | Path) -> str:
    path = Path(archive_path)
    if not path.exists():
        return ""
    try:
        with tarfile.open(path, "r:gz") as archive:
            members = [member for member in archive.getmembers() if member.isfile()]
            for suffix in [
                f"conf/{VCF_DEPOT_APPLICATION_PROPERTIES_NAME}",
                VCF_DEPOT_APPLICATION_PROPERTIES_NAME,
            ]:
                for archive_member in members:
                    member_name = archive_member.name.replace("\\", "/").strip("/")
                    if member_name == suffix or member_name.endswith(f"/{suffix}"):
                        member = archive.extractfile(archive_member)
                        if member is not None:
                            return member.read(512 * 1024).decode("utf-8", errors="replace")
    except (EOFError, KeyError, tarfile.TarError, OSError):
        return ""
    return ""


def default_vcf_depot_application_properties() -> str:
    default_path = Path(__file__).resolve().parents[1] / "static" / "defaults" / VCF_DEPOT_APPLICATION_PROPERTIES_NAME
    try:
        return default_path.read_text(encoding="utf-8")
    except OSError:
        return "\n".join(
            [
                "spring.profiles.active=depot",
                "spring.main.web-environment=false",
                "",
                "lcm.bundle.download.root.dir=${user.home}",
                "lcm.depot.adapter.host=dl.broadcom.com",
                "lcm.depot.adapter.remote.v2.rootDir=/PROD",
                "lcm.depot.adapter.remote.repoDir=/COMP/SDDC_MANAGER_VCF",
                "lcm.depot.download.tool.name=vcf-download-tool",
                "",
            ]
        )


def vcf_depot_application_properties_from_tool(settings: VcfOfflineDepotSettings) -> tuple[str, str]:
    return default_vcf_depot_application_properties(), "LabFoundry default"


def safe_archive_upload_name(filename: str) -> str:
    name = Path(filename or "").name
    if not re.fullmatch(r"vcf-download-tool-[A-Za-z0-9._-]+\.tar\.gz", name):
        raise ValueError("Upload the VCF Download Tool file named vcf-download-tool-*.tar.gz.")
    return name


def _validate_tar_members(members: list[tarfile.TarInfo], destination: Path) -> None:
    destination_resolved = destination.resolve()
    for member in members:
        target = (destination / member.name).resolve()
        if target != destination_resolved and destination_resolved not in target.parents:
            raise ValueError("VCF Download Tool archive contains an unsafe path.")


def validate_vcf_download_tool_archive(archive_path: Path) -> None:
    try:
        with tarfile.open(archive_path, "r:gz") as archive:
            members = archive.getmembers()
    except (EOFError, tarfile.TarError, OSError) as exc:
        raise ValueError(VCF_DEPOT_INVALID_ARCHIVE_MESSAGE) from exc
    _validate_tar_members(members, Path("vcf-download-tool-validation"))


def validate_vcf_download_tool_upload_envelope(archive_path: Path) -> None:
    validate_vcf_download_tool_archive(archive_path)


def _safe_extract_tar_gz(archive_path: Path, destination: Path) -> None:
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(archive_path, "r:gz") as archive:
            members = archive.getmembers()
            _validate_tar_members(members, destination)
            archive.extractall(destination, filter="data")
    except (EOFError, tarfile.TarError, OSError) as exc:
        raise ValueError(VCF_DEPOT_INVALID_ARCHIVE_MESSAGE) from exc


def _find_vcf_download_tool_binary(extraction_dir: Path) -> Path:
    candidates = [
        extraction_dir / "vcf-download-tool",
        extraction_dir / "bin" / "vcf-download-tool",
    ]
    candidates.extend(path for path in extraction_dir.rglob("vcf-download-tool") if path.is_file())
    for candidate in candidates:
        if candidate.is_file():
            candidate.chmod(candidate.stat().st_mode | 0o111)
            return candidate.resolve()
    raise FileNotFoundError("The uploaded VCF Download Tool archive does not contain a vcf-download-tool executable.")


def parse_software_depot_id(output: str) -> str:
    uuid_match = re.search(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", output)
    if uuid_match:
        return uuid_match.group(0)
    for line in output.splitlines():
        if "vcf-download-tool" in line:
            continue
        if "software" not in line.lower() or "depot" not in line.lower() or "id" not in line.lower():
            continue
        match = re.search(r"([A-Za-z0-9][A-Za-z0-9._:-]{7,})\s*$", line.strip())
        if match:
            return match.group(1)
    for line in output.splitlines():
        stripped = line.strip()
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,}", stripped) and "vcf-download-tool" not in stripped:
            return stripped
    return ""


def generate_vcf_software_depot_id(
    archive_path: str | Path,
    *,
    extraction_dir: Path = VCF_DEPOT_EXTRACT_DIR,
    timeout_seconds: int = 90,
) -> SoftwareDepotIdResult:
    archive = Path(archive_path)
    command = ["vcf-download-tool", "configuration", "generate", "--software-depot-id"]
    if not archive.is_file():
        return SoftwareDepotIdResult(False, "", command, f"VCF Download Tool archive does not exist: {archive}")
    try:
        _safe_extract_tar_gz(archive, extraction_dir)
        tool = _find_vcf_download_tool_binary(extraction_dir)
        completed = subprocess.run(
            [str(tool), "configuration", "generate", "--software-depot-id"],
            cwd=str(tool.parent),
            capture_output=True,
            check=False,
            input="Y\n",
            text=True,
            timeout=timeout_seconds,
        )
    except (OSError, tarfile.TarError, ValueError, subprocess.SubprocessError) as exc:
        return SoftwareDepotIdResult(False, "", command, str(exc))
    output = "\n".join(part for part in [completed.stdout, completed.stderr] if part)
    software_depot_id = parse_software_depot_id(output)
    if completed.returncode != 0:
        return SoftwareDepotIdResult(False, software_depot_id, command, f"VCFDT exited with code {completed.returncode}.")
    if not software_depot_id:
        return SoftwareDepotIdResult(False, "", command, "VCFDT did not print a software depot ID.")
    return SoftwareDepotIdResult(True, software_depot_id, command)


def vcf_depot_endpoint(settings: VcfOfflineDepotSettings) -> str:
    port = settings.port or 443
    host = settings.hostname.strip()
    return host if port == 443 else f"{host}:{port}"


def vcf_depot_settings_to_dict(settings: VcfOfflineDepotSettings) -> dict[str, object]:
    return {
        "id": settings.id,
        "enabled": settings.enabled,
        "hostname": settings.hostname,
        "endpoint": vcf_depot_endpoint(settings),
        "listen_interface": settings.listen_interface,
        "listen_address": settings.listen_address,
        "port": settings.port,
        "http_user_id": settings.http_user_id,
        "http_username": settings.http_user.username if settings.http_user else "",
        "allow_unauthenticated_access": settings.allow_unauthenticated_access,
        "server_certificate": settings.server_certificate,
        "depot_store_path": settings.depot_store_path,
        "tool_archive_path": settings.tool_archive_path,
        "tool_archive_name": Path(settings.tool_archive_path).name if settings.tool_archive_path else "",
        "tool_version": settings.tool_version,
        "config_path": settings.config_path,
        "updated_at": settings.updated_at.isoformat() if settings.updated_at else "",
    }


def vcf_depot_service_state(settings: VcfOfflineDepotSettings, *, nginx_active: bool | None = None) -> dict[str, object]:
    desired_enabled = bool(settings.enabled)
    running = bool(nginx_active) if nginx_active is not None else desired_enabled
    if running and desired_enabled:
        health = "healthy"
        label = "live"
        pill = "good"
    elif running:
        health = "degraded"
        label = "running"
        pill = "warn"
    elif desired_enabled:
        health = "degraded"
        label = "enabled"
        pill = "warn"
    else:
        health = "disabled"
        label = "disabled"
        pill = "muted"
    return {
        "running": running,
        "enabled": desired_enabled,
        "health": health,
        "label": label,
        "pill": pill,
    }


def vcf_depot_profile_start_blocker(
    profile: VcfDepotDownloadProfile,
    *,
    download_token_present: bool = False,
    activation_code_present: bool = False,
) -> str:
    if not profile.enabled:
        return "Enable the VCFDT download profile before starting a download."
    profile_type = (profile.profile_type or "binaries").strip() or "binaries"
    if profile_type == "esx" and not activation_code_present:
        return "Upload a Broadcom activation code before starting this ESX profile."
    if profile_type in {"binaries", "metadata"} and not (download_token_present or activation_code_present):
        return "Upload a Broadcom download token or activation code before starting this profile."
    if profile_type not in VCF_DEPOT_PROFILE_TYPES:
        return "Choose a supported VCFDT profile type before starting a download."
    return ""


def vcf_depot_profile_to_dict(
    profile: VcfDepotDownloadProfile,
    *,
    download_token_present: bool = False,
    activation_code_present: bool = False,
) -> dict[str, object]:
    component = profile.component or ""
    start_blocker = vcf_depot_profile_start_blocker(
        profile,
        download_token_present=download_token_present,
        activation_code_present=activation_code_present,
    )
    download_mode = (
        "patches_only"
        if profile.patches_only
        else "upgrades_only"
        if profile.upgrades_only
        else "automated_install"
    )
    return {
        "id": profile.id,
        "name": profile.name,
        "profile_type": profile.profile_type,
        "sku": profile.sku,
        "vcf_version": profile.vcf_version,
        "binary_type": profile.binary_type,
        "automated_install": profile.automated_install,
        "upgrades_only": profile.upgrades_only,
        "patches_only": profile.patches_only,
        "download_mode": download_mode,
        "component": component,
        "component_label": VCF_DEPOT_COMPONENTS.get(component, component),
        "component_version": profile.component_version,
        "disabled_platforms": profile.disabled_platforms,
        "enabled": profile.enabled,
        "status": profile.status,
        "notes": profile.notes or "",
        "can_start": not start_blocker,
        "start_blocker": start_blocker,
        "created_at": profile.created_at.isoformat() if profile.created_at else "",
        "updated_at": profile.updated_at.isoformat() if profile.updated_at else "",
    }


def setting_secret_state(name_setting: Setting | None, value_setting: Setting | None) -> SecretState:
    present = bool(value_setting and value_setting.value.strip())
    filename = name_setting.value if name_setting else ""
    updated_at = value_setting.updated_at.isoformat() if value_setting and value_setting.updated_at else ""
    return SecretState(present=present, filename=filename, updated_at=updated_at)


def render_nginx_depot_config(
    settings: VcfOfflineDepotSettings,
    *,
    certificate_path: str = "",
    key_path: str = "",
    upstream_host: str = "127.0.0.1",
    upstream_port: int = 8000,
) -> str:
    certificate_name = settings.server_certificate or settings.hostname or VCF_DEPOT_DEFAULT_HOSTNAME
    certificate_path = certificate_path or "/etc/labfoundry/vcf-offline-depot/certs/" + certificate_name + ".crt"
    key_path = key_path or "/etc/labfoundry/vcf-offline-depot/certs/" + certificate_name + ".key"
    username = settings.http_user.username if settings.http_user else VCF_DEPOT_DEFAULT_USERNAME
    auth_required = not bool(settings.allow_unauthenticated_access)
    if not settings.enabled:
        return "\n".join(
            [
                "# Managed by LabFoundry. Local changes may be overwritten.",
                "# VCF Offline Depot HTTPS endpoint is disabled.",
                "",
            ]
        )
    lines = [
        "# Managed by LabFoundry. Local changes may be overwritten.",
        "# Desired HTTPS endpoint for the VCF Offline Depot.",
        f"# Depot store: {settings.depot_store_path}",
        f"# VCF endpoint: https://{vcf_depot_endpoint(settings)}/PROD/",
        f"# Listen interfaces: {', '.join(split_interfaces(settings.listen_interface)) or 'none'}",
        f"# Listen addresses: {', '.join(split_addresses(settings.listen_address)) or 'none'}",
        f"# LabFoundry VCF Offline Depot unauthenticated access: {str(settings.allow_unauthenticated_access).lower()}",
        f"# LabFoundry VCF Offline Depot user: {username if auth_required else 'none'}",
        "",
        "server {",
        *[
            f"  listen {format_nginx_listen(address, settings.port)} ssl;"
            for address in (split_addresses(settings.listen_address) or ["0.0.0.0"])
        ],
        f"  server_name {settings.hostname};",
        f"  ssl_certificate {certificate_path};",
        f"  ssl_certificate_key {key_path};",
        "",
        "  location = / {",
        f"    proxy_pass http://{upstream_host}:{upstream_port};",
        "    proxy_set_header Host $host;",
        "    proxy_set_header X-Real-IP $remote_addr;",
        "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "    proxy_set_header X-Forwarded-Proto https;",
        "  }",
        "",
        "  location ^~ /static/ {",
        f"    proxy_pass http://{upstream_host}:{upstream_port};",
        "    proxy_set_header Host $host;",
        "    proxy_set_header X-Real-IP $remote_addr;",
        "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "    proxy_set_header X-Forwarded-Proto https;",
        "  }",
        "",
        "  location = /favicon.ico {",
        f"    proxy_pass http://{upstream_host}:{upstream_port};",
        "    proxy_set_header Host $host;",
        "    proxy_set_header X-Real-IP $remote_addr;",
        "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "    proxy_set_header X-Forwarded-Proto https;",
        "  }",
        "",
        "  location = /manifest.webmanifest {",
        f"    proxy_pass http://{upstream_host}:{upstream_port};",
        "    proxy_set_header Host $host;",
        "    proxy_set_header X-Real-IP $remote_addr;",
        "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "    proxy_set_header X-Forwarded-Proto https;",
        "  }",
        "",
        "  location = /service-worker.js {",
        f"    proxy_pass http://{upstream_host}:{upstream_port};",
        "    proxy_set_header Host $host;",
        "    proxy_set_header X-Real-IP $remote_addr;",
        "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "    proxy_set_header X-Forwarded-Proto https;",
        "  }",
        "",
        "  location = /PROD {",
        "    return 301 /PROD/;",
        "  }",
        "",
        "  location = /PROD/login {",
        f"    proxy_pass http://{upstream_host}:{upstream_port};",
        "    proxy_set_header Host $host;",
        "    proxy_set_header X-Real-IP $remote_addr;",
        "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "    proxy_set_header X-Forwarded-Proto https;",
        "  }",
        "",
        "  location = /PROD/logout {",
        f"    proxy_pass http://{upstream_host}:{upstream_port};",
        "    proxy_set_header Host $host;",
        "    proxy_set_header X-Real-IP $remote_addr;",
        "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "    proxy_set_header X-Forwarded-Proto https;",
        "  }",
        "",
        "  location = /_labfoundry_depot_auth {",
        "    internal;",
        f"    proxy_pass http://{upstream_host}:{upstream_port}/PROD/auth-check;",
        "    proxy_pass_request_body off;",
        "    proxy_set_header Content-Length \"\";",
        "    proxy_set_header Host $host;",
        "    proxy_set_header X-Original-URI $request_uri;",
        "    proxy_set_header X-Real-IP $remote_addr;",
        "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "    proxy_set_header X-Forwarded-Proto https;",
        "  }",
        "",
        "  location = /_labfoundry_depot_login {",
        "    internal;",
        f"    proxy_pass http://{upstream_host}:{upstream_port}/PROD/auth-failure;",
        "    proxy_pass_request_body off;",
        "    proxy_set_header Content-Length \"\";",
        "    proxy_set_header Host $host;",
        "    proxy_set_header X-Original-URI $request_uri;",
        "    proxy_set_header X-Forwarded-Proto https;",
        "  }",
        "",
        "  location = /PROD/ {",
        *(
            [
                "    satisfy any;",
                '    auth_basic "VCF Offline Depot";',
                f"    auth_basic_user_file {VCF_DEPOT_HTPASSWD_PATH};",
                "    auth_request /_labfoundry_depot_auth;",
                "    error_page 401 = /_labfoundry_depot_login;",
            ]
            if auth_required
            else []
        ),
        f"    proxy_pass http://{upstream_host}:{upstream_port};",
        "    proxy_set_header Host $host;",
        "    proxy_set_header X-Real-IP $remote_addr;",
        "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "    proxy_set_header X-Forwarded-Proto https;",
        "    proxy_set_header X-LabFoundry-Depot-Basic-User $remote_user;",
        "  }",
        "",
        "  location ~ ^/PROD/.*/$ {",
        *(
            [
                "    satisfy any;",
                '    auth_basic "VCF Offline Depot";',
                f"    auth_basic_user_file {VCF_DEPOT_HTPASSWD_PATH};",
                "    auth_request /_labfoundry_depot_auth;",
                "    error_page 401 = /_labfoundry_depot_login;",
            ]
            if auth_required
            else []
        ),
        f"    proxy_pass http://{upstream_host}:{upstream_port};",
        "    proxy_set_header Host $host;",
        "    proxy_set_header X-Real-IP $remote_addr;",
        "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "    proxy_set_header X-Forwarded-Proto https;",
        "    proxy_set_header X-LabFoundry-Depot-Basic-User $remote_user;",
        "  }",
        "",
        "  location ~ ^/PROD/(?!login$|logout$|auth-check$)(.+[^/])$ {",
        *(
            [
                "    satisfy any;",
                '    auth_basic "VCF Offline Depot";',
                f"    auth_basic_user_file {VCF_DEPOT_HTPASSWD_PATH};",
                "    auth_request /_labfoundry_depot_auth;",
                "    error_page 401 = /_labfoundry_depot_login;",
            ]
            if auth_required
            else []
        ),
        f"    alias {settings.depot_store_path.rstrip('/')}/PROD/$1;",
        "    sendfile on;",
        "    tcp_nopush on;",
        "    directio 8m;",
        "    autoindex off;",
        "    types { }",
        "    default_type application/octet-stream;",
        "  }",
        "",
        "  location / {",
        "    return 404;",
        "  }",
        "}",
    ]
    return "\n".join(lines).strip() + "\n"


def _append_optional_flag(command: list[str], flag: str, value: str | None) -> None:
    stripped = (value or "").strip()
    if stripped:
        command.append(f"{flag}={stripped}")


def split_vcf_depot_lines(value: str | None) -> list[str]:
    return [item.strip() for item in (value or "").splitlines() if item.strip()]


def vcf_depot_download_credential_flag(download_token_present: bool = True, activation_code_present: bool = False) -> str:
    if download_token_present or not activation_code_present:
        return f"--depot-download-token-file={VCF_DEPOT_STAGED_TOKEN_FILE}"
    return f"--depot-download-activation-code-file={VCF_DEPOT_STAGED_ACTIVATION_FILE}"


def vcfdt_commands_for_profile(
    settings: VcfOfflineDepotSettings,
    profile: VcfDepotDownloadProfile,
    *,
    download_token_present: bool = True,
    activation_code_present: bool = False,
) -> list[list[str]]:
    if not profile.enabled:
        return []
    profile_type = (profile.profile_type or "binaries").strip() or "binaries"
    download_credential_flag = vcf_depot_download_credential_flag(download_token_present, activation_code_present)
    if profile_type == "metadata":
        return [
            [
                "vcf-download-tool",
                "metadata",
                "download",
                f"--depot-store={settings.depot_store_path}",
                download_credential_flag,
            ]
        ]
    if profile_type == "esx":
        commands: list[list[str]] = []
        disabled_platforms = split_vcf_depot_lines(profile.disabled_platforms)
        if disabled_platforms:
            configuration = ["vcf-download-tool", "esx", "configuration"]
            for platform in disabled_platforms:
                configuration.extend(["-D", platform])
            commands.append(configuration)
        commands.append(
            [
                "vcf-download-tool",
                "esx",
                "download",
                f"--depot-store={settings.depot_store_path}",
                f"--depot-download-activation-code-file={VCF_DEPOT_STAGED_ACTIVATION_FILE}",
            ]
        )
        return commands

    base = [
        download_credential_flag,
        f"--vcf-version={(profile.vcf_version or '9.1.0').strip()}",
        f"--sku={(profile.sku or 'VCF').strip() or 'VCF'}",
        f"--type={(profile.binary_type or 'INSTALL').strip() or 'INSTALL'}",
    ]
    if profile.automated_install:
        base.append("--automated-install")
    if profile.upgrades_only:
        base.append("--upgrades-only")
    if profile.patches_only:
        base.append("--patches-only")
    _append_optional_flag(base, "--component", profile.component)
    _append_optional_flag(base, "--component-version", profile.component_version)
    return [["vcf-download-tool", "binaries", "download", f"--depot-store={settings.depot_store_path}", *base]]


def _shell_arg(arg: str, settings: VcfOfflineDepotSettings) -> str:
    if arg == f"--depot-store={settings.depot_store_path}":
        return '"--depot-store=${DEPOT_STORE}"'
    if arg == f"--depot-download-token-file={VCF_DEPOT_STAGED_TOKEN_FILE}":
        return '"--depot-download-token-file=${TOKEN_FILE}"'
    if arg == f"--depot-download-activation-code-file={VCF_DEPOT_STAGED_ACTIVATION_FILE}":
        return '"--depot-download-activation-code-file=${ACTIVATION_CODE_FILE}"'
    return shlex.quote(arg)


def _shell_command(command: list[str], settings: VcfOfflineDepotSettings) -> str:
    return " ".join(_shell_arg(arg, settings) for arg in command)


def _json_string_array(values: list[str]) -> list[str]:
    lines = ['{', '  "disabledPlatforms": [']
    for index, value in enumerate(values):
        comma = "," if index < len(values) - 1 else ""
        lines.append(f"    {json.dumps(value)}{comma}")
    lines.extend(["  ]", "}"])
    return lines


def _printf_json_to_file_command(lines: list[str], target: str) -> str:
    quoted_lines = " ".join(shlex.quote(line) for line in lines)
    return f"printf '%s\\n' {quoted_lines} > {target}"


def render_vcfdt_command_preview(
    settings: VcfOfflineDepotSettings,
    profiles: list[VcfDepotDownloadProfile],
    *,
    vmware_ceip_enabled: bool = False,
    download_token_present: bool = True,
    activation_code_present: bool = False,
    include_disabled_profiles: bool = False,
) -> str:
    enabled_profiles = profiles if include_disabled_profiles else [profile for profile in profiles if profile.enabled]
    if not enabled_profiles:
        return "# No enabled VCFDT download profiles are configured.\n"
    lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "",
        "# Generated by LabFoundry. Token and activation-code contents are staged as files and are not rendered here.",
        f"# VCF Download Tool: {Path(settings.tool_archive_path).name if settings.tool_archive_path else 'not uploaded'}",
        f"# VCFDT version: {settings.tool_version or 'unknown'}",
        f"# Resolved depot-store flag: --depot-store={settings.depot_store_path}",
        f"# Resolved download-token flag: --depot-download-token-file={VCF_DEPOT_STAGED_TOKEN_FILE}",
        f"# Resolved activation-code flag: --depot-download-activation-code-file={VCF_DEPOT_STAGED_ACTIVATION_FILE}",
        "",
        f"VCFDT_HOME={shlex.quote(VCF_DEPOT_RUNTIME_TOOL_DIR)}",
        f"DEPOT_STORE={shlex.quote(settings.depot_store_path)}",
        f"TOKEN_FILE={shlex.quote(VCF_DEPOT_STAGED_TOKEN_FILE)}",
        f"ACTIVATION_CODE_FILE={shlex.quote(VCF_DEPOT_STAGED_ACTIVATION_FILE)}",
        'VCFDT="${VCFDT_HOME}/bin/vcf-download-tool"',
        'vcf-download-tool() { "${VCFDT}" "$@"; }',
        "",
        'mkdir -p "${DEPOT_STORE}"',
    ]
    telemetry_choice = "ENABLE" if vmware_ceip_enabled else "DISABLE"
    lines.extend(
        [
            'mkdir -p "${VCFDT_HOME}/conf/telemetry"',
            f"printf '%s\\n' {shlex.quote('obtu.telemetry.config=' + telemetry_choice)} > \"${{VCFDT_HOME}}/conf/telemetry/telemetry.flag\"",
        ]
    )
    if any((profile.profile_type or "binaries") == "esx" for profile in enabled_profiles):
        lines.extend(
            [
                "",
                "# ESX patch/update downloads require an activation code. Generate/register this ID once if activation is not complete:",
                "# vcf-download-tool configuration generate --software-depot-id",
            ]
        )
    for profile in enabled_profiles:
        lines.extend(["", f"# {profile.name}"])
        command_profile = profile
        if include_disabled_profiles and not profile.enabled:
            command_profile = VcfDepotDownloadProfile(
                name=profile.name,
                profile_type=profile.profile_type,
                sku=profile.sku,
                vcf_version=profile.vcf_version,
                binary_type=profile.binary_type,
                automated_install=profile.automated_install,
                upgrades_only=profile.upgrades_only,
                patches_only=profile.patches_only,
                component=profile.component,
                component_version=profile.component_version,
                disabled_platforms=profile.disabled_platforms,
                enabled=True,
                status=profile.status,
                notes=profile.notes,
            )
        if (profile.profile_type or "binaries") == "esx":
            disabled_platforms = split_vcf_depot_lines(profile.disabled_platforms)
            if disabled_platforms:
                lines.extend(
                    [
                        'mkdir -p "${VCFDT_HOME}/conf"',
                        _printf_json_to_file_command(
                            _json_string_array(disabled_platforms),
                            '"${VCFDT_HOME}/conf/esxUserConfig.json"',
                        ),
                    ]
                )
        for command in vcfdt_commands_for_profile(
            settings,
            command_profile,
            download_token_present=download_token_present,
            activation_code_present=activation_code_present,
        ):
            if command[:3] == ["vcf-download-tool", "esx", "configuration"]:
                lines.append("# Equivalent ESX exclusion command if you prefer not to write conf/esxUserConfig.json:")
                lines.append("# " + " ".join(shlex.quote(arg) for arg in command))
                continue
            lines.append(_shell_command(command, settings))
    return "\n".join(lines).strip() + "\n"


def validate_vcf_depot_state(
    settings: VcfOfflineDepotSettings,
    profiles: list[VcfDepotDownloadProfile],
    interface_names: set[str] | None = None,
    download_token_present: bool = False,
    activation_code_present: bool = False,
    management_interface_names: set[str] | None = None,
    users: list[User] | None = None,
) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []

    hostname = settings.hostname.strip()
    if not hostname or not HOSTNAME_PATTERN.match(hostname) or "." not in hostname:
        errors.append("Depot hostname must be a fully qualified DNS name.")
    if hostname.endswith(".local"):
        warnings.append("Avoid .local for VCF labs; use labfoundry.internal or another non-.local internal domain.")
    if settings.enabled:
        if not settings.allow_unauthenticated_access:
            user_by_id = {user.id: user for user in users or []}
            selected_user = user_by_id.get(settings.http_user_id or -1) or settings.http_user
            if selected_user is None:
                errors.append("Select a VCF Offline Depot HTTP user or enable unauthenticated access.")
            elif not selected_user.enabled:
                errors.append(f"VCF Offline Depot HTTP user {selected_user.username} is disabled.")
        listen_interfaces = split_interfaces(settings.listen_interface)
        listen_addresses = split_addresses(settings.listen_address)
        if not listen_interfaces:
            errors.append("Listen interface is required.")
        else:
            for interface in listen_interfaces:
                if management_interface_names and interface in management_interface_names:
                    errors.append(f"Listen interface {interface} uses the management role. Choose a non-management service interface for VCF Offline Depot.")
                elif interface_names is not None and interface not in interface_names:
                    errors.append(f"Listen interface {interface} is not configured as an access physical or VLAN interface with an IP address.")
        if not listen_addresses:
            errors.append("Listen address is required.")
        for address in listen_addresses:
            try:
                ip_address(address)
            except ValueError:
                errors.append(f"Listen address {address} is not a valid IP address.")
    if settings.port < 1 or settings.port > 65535:
        errors.append("Depot HTTPS port must be between 1 and 65535.")
    for path_label, path_value in [
        ("Depot store path", settings.depot_store_path),
        ("HTTPS config path", settings.config_path),
    ]:
        if not path_value.startswith("/"):
            errors.append(f"{path_label} must be an absolute Linux path.")
    if not settings.server_certificate.strip():
        errors.append("Server certificate name is required.")
    enabled_profiles = [profile for profile in profiles if profile.enabled]
    if enabled_profiles and not settings.tool_archive_path.strip():
        errors.append("Upload the VCF Download Tool before generating or syncing enabled VCFDT download profiles.")
    elif settings.tool_archive_path and not Path(settings.tool_archive_path).exists():
        errors.append("The configured VCF Download Tool file is not present on disk.")
    if settings.tool_archive_path and not settings.tool_version:
        warnings.append("The VCF Download Tool version will be detected with vcf-download-tool --version during appliance apply.")

    seen_names: set[str] = set()
    for profile in profiles:
        name = profile.name.strip()
        if not name:
            errors.append("Every VCFDT download profile needs a name.")
        elif name.lower() in seen_names:
            errors.append(f"VCFDT download profile {name} is duplicated.")
        seen_names.add(name.lower())
        profile_type = profile.profile_type or "binaries"
        profile_status = profile.status or "planned"
        if profile_type not in VCF_DEPOT_PROFILE_TYPES:
            errors.append(f"VCFDT download profile {name or profile.id} has unsupported type {profile_type}.")
        if profile_status not in VCF_DEPOT_STATUS_VALUES:
            errors.append(f"VCFDT download profile {name or profile.id} has unsupported status {profile_status}.")
        if not profile.enabled:
            continue
        if profile_type == "esx":
            unsupported_platforms = [
                platform
                for platform in split_vcf_depot_lines(profile.disabled_platforms)
                if platform not in VCF_DEPOT_ESX_DISABLED_PLATFORMS
            ]
            for platform in unsupported_platforms:
                errors.append(f"VCFDT ESX profile {name or profile.id} has unsupported disabled platform {platform}.")
        if profile_type == "binaries":
            if (profile.sku or "VCF") not in VCF_DEPOT_SKUS:
                errors.append(f"VCFDT binaries profile {name or profile.id} must use SKU VCF or VVF.")
            if (profile.binary_type or "INSTALL") not in VCF_DEPOT_BINARY_TYPES:
                errors.append(f"VCFDT binaries profile {name or profile.id} must use type INSTALL or UPGRADE.")
            if not (profile.vcf_version or "").strip():
                errors.append(f"VCFDT binaries profile {name or profile.id} needs a VCF version.")
            component = (profile.component or "").strip()
            if component and component not in VCF_DEPOT_COMPONENTS:
                errors.append(f"VCFDT binaries profile {name or profile.id} has unsupported component {component}.")

    return errors, warnings
