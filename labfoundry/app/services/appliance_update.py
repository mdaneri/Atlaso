from __future__ import annotations

import configparser
import hashlib
import json
import os
import platform
import re
import subprocess
from datetime import datetime, timezone
from functools import lru_cache
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from labfoundry import __version__
from labfoundry.app.models import Job, JobStatus, JobStep


APPLIANCE_UPDATE_SETTINGS_KEY = "appliance_update.settings.v1"
APPLIANCE_UPDATE_STAGED_CONFIG_PATH = "/var/lib/labfoundry/apply/appliance-update/labfoundry-update.json"
APPLIANCE_UPDATE_STAGED_CREDENTIALS_PATH = "/var/lib/labfoundry/apply/appliance-update/labfoundry-update-credentials.json"
APPLIANCE_UPDATE_INFO_PATH = "/etc/labfoundry/update-info"
APPLIANCE_UPDATE_FINALIZER_PATH = "/var/lib/labfoundry/apply/appliance-update/finalizer-status.json"
PHOTON_REPOSITORY_DIR = Path("/etc/yum.repos.d")
DEFAULT_LABFOUNDRY_RELEASE_URL = "https://mdaneri.github.io/LabFoundry/updates"
DEFAULT_LABFOUNDRY_MANIFEST_URL = f"{DEFAULT_LABFOUNDRY_RELEASE_URL}/channels/stable/manifest.json"
UPDATE_STREAMS = ("photon_os", "powershell_modules", "labfoundry_release")
APPLIANCE_UPDATE_EXECUTION_ORDER = ("labfoundry_release", "powershell_modules", "photon_os")
UPDATE_STREAM_LABELS = {
    "photon_os": "Photon OS",
    "powershell_modules": "PowerShell Modules",
    "labfoundry_release": "LabFoundry Release",
}


def ensure_appliance_update_job_steps(
    db: Session,
    *,
    job: Job,
    selected_streams: list[str] | tuple[str, ...],
) -> list[JobStep]:
    selected = set(selected_update_streams(selected_streams))
    existing = {step.component_key: step for step in job.steps}
    steps: list[JobStep] = []
    for position, stream in enumerate(
        (stream for stream in APPLIANCE_UPDATE_EXECUTION_ORDER if stream in selected),
        start=1,
    ):
        step = existing.get(stream)
        if step is None:
            step = JobStep(
                id=f"{job.id}:{stream}",
                job=job,
                component_key=stream,
                label=UPDATE_STREAM_LABELS[stream],
                position=position,
                status=JobStatus.PENDING.value,
                progress_percent=0,
                result=json.dumps(
                    {
                        "unit_id": stream,
                        "label": UPDATE_STREAM_LABELS[stream],
                        "status": JobStatus.PENDING.value,
                        "success": False,
                        "commands": [],
                    },
                    indent=2,
                    sort_keys=True,
                ),
            )
            db.add(step)
        else:
            step.position = position
            step.label = UPDATE_STREAM_LABELS[stream]
        steps.append(step)
    return steps


DEFAULT_UPDATE_SETTINGS = {
    "photon_source": "configured Photon repositories",
    "labfoundry_manifest_url": DEFAULT_LABFOUNDRY_MANIFEST_URL,
    "powershell_repository_name": "",
    "powershell_repository_url": "",
}
def _git_value(args: list[str]) -> str:
    try:
        result = subprocess.run(["git", *args], cwd=Path(__file__).resolve().parents[3], check=False, capture_output=True, text=True)
    except OSError:
        return ""
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


@lru_cache(maxsize=1)
def _installed_record_sha256() -> str:
    try:
        distribution = importlib_metadata.distribution("labfoundry")
    except importlib_metadata.PackageNotFoundError:
        return ""
    record_text = distribution.read_text("RECORD") or ""
    if not record_text:
        return ""
    return hashlib.sha256(record_text.encode("utf-8")).hexdigest()


def current_version_info() -> dict[str, str]:
    full_commit = getattr(__import__("labfoundry"), "__build_git_commit__", "") or _git_value(["rev-parse", "HEAD"])
    short_commit = full_commit[:12] if full_commit else ""
    built_at = getattr(__import__("labfoundry"), "__build_time_utc__", "")
    source_dirty = _git_value(["status", "--short"]) != "" if not built_at else False
    public_label = f"{short_commit[:7]} (branch wheel)" if built_at and short_commit else short_commit
    installed_sha256 = _installed_record_sha256()
    if not public_label and installed_sha256:
        public_label = f"installed sha {installed_sha256[:12]}"
    return {
        "version": __version__,
        "base_version": __version__.split("+", 1)[0],
        "git_commit": full_commit,
        "git_short": short_commit,
        "public_label": public_label,
        "installed_sha256": installed_sha256,
        "built_at": built_at,
        "source_dirty": "true" if source_dirty else "false",
        "python": platform.python_version(),
        "platform": platform.platform(),
    }


def version_with_git(base_version: str, git_commit: str) -> str:
    normalized = base_version.strip()
    if not normalized:
        normalized = "0.0.0"
    if "+" in normalized:
        normalized = normalized.split("+", 1)[0]
    short = re.sub(r"[^0-9A-Fa-f]", "", git_commit or "")[:12]
    return f"{normalized}+g{short}" if short else normalized


def update_settings_from_json(raw_value: str) -> dict[str, Any]:
    settings = dict(DEFAULT_UPDATE_SETTINGS)
    if raw_value:
        try:
            payload = json.loads(raw_value)
        except json.JSONDecodeError:
            payload = {}
        if isinstance(payload, dict):
            for key in settings:
                value = payload.get(key)
                if isinstance(value, str):
                    settings[key] = value.strip()
    return settings


def update_settings_to_json(settings: dict[str, Any]) -> str:
    normalized = dict(DEFAULT_UPDATE_SETTINGS)
    for key in normalized:
        normalized[key] = str(settings.get(key) or "").strip()
    return json.dumps(normalized, indent=2, sort_keys=True)


def validate_update_url(value: str, label: str) -> list[str]:
    if not value.strip():
        return []
    parsed = urlparse(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return [f"{label} must be an http or https URL."]
    if parsed.username or parsed.password:
        return [f"{label} must not include embedded credentials."]
    return []


def validate_update_settings(settings: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    errors.extend(validate_update_url(settings.get("labfoundry_manifest_url", ""), "LabFoundry manifest URL"))
    release_url = urlparse(str(settings.get("labfoundry_manifest_url") or ""))
    if release_url.scheme and release_url.scheme != "https":
        errors.append("LabFoundry manifest URL must use HTTPS.")
    errors.extend(validate_update_url(settings.get("powershell_repository_url", ""), "PowerShell repository URL"))
    return errors


def selected_update_streams(raw_streams: list[str] | tuple[str, ...]) -> list[str]:
    normalized = {"labfoundry_release" if stream == "labfoundry_wheel" else stream for stream in raw_streams}
    selected = [stream for stream in UPDATE_STREAMS if stream in normalized]
    return selected


def redact_url_userinfo(value: str) -> str:
    parsed = urlparse(value or "")
    if not parsed.scheme or not parsed.netloc or not (parsed.username or parsed.password):
        return value
    host = parsed.hostname or ""
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return parsed._replace(netloc=f"[redacted]@{host}").geturl()


def render_update_manifest(
    *,
    selected_streams: list[str],
    settings: dict[str, Any],
    actor: str,
    job_id: str = "",
) -> str:
    payload = {
        "schema_version": 2,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_by": actor,
        "job_id": job_id,
        "selected_streams": selected_streams,
        "sources": {
            "photon_os": settings.get("photon_source") or DEFAULT_UPDATE_SETTINGS["photon_source"],
            "labfoundry_manifest_url": redact_url_userinfo(settings.get("labfoundry_manifest_url") or DEFAULT_LABFOUNDRY_MANIFEST_URL),
            "labfoundry_manifest_urls": [
                redact_url_userinfo(str(value)) for value in settings.get("labfoundry_manifest_urls", []) if str(value).strip()
            ],
            "powershell_repository_name": str(settings.get("powershell_repository_name") or ""),
            "powershell_repository_url": redact_url_userinfo(str(settings.get("powershell_repository_url") or "")),
        },
        "powershell_modules": settings.get("powershell_modules") if isinstance(settings.get("powershell_modules"), list) else [],
        "source_definitions": settings.get("source_definitions") if isinstance(settings.get("source_definitions"), list) else [],
        "current": current_version_info(),
        "policy": {
            "auto_reboot": False,
            "release_install_mode": "signed-offline-transactional",
            "supported_python_abis": ["cp312", "cp313", "cp314"],
            "runtime_python_indexes": False,
            "vmware_ceip_enabled": bool(settings.get("vmware_ceip_enabled", False)),
        },
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def update_result_excerpt(value: str, *, limit: int = 4000) -> str:
    text = str(value or "")
    if len(text) <= limit:
        return text
    return text[: limit - 20] + "\n[output truncated]"


def parse_latest_update_result(job: Job | None) -> dict[str, Any] | None:
    if job is None or not job.result:
        return None
    try:
        payload = json.loads(job.result)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def read_appliance_file(path_value: str) -> dict[str, Any]:
    path = Path(path_value)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return {"path": path_value, "available": False, "content": "", "error": str(exc)}
    return {"path": path_value, "available": True, "content": text, "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()}


def photon_repository_details(repository_dir: Path | None = None) -> list[dict[str, str]]:
    directory = repository_dir or PHOTON_REPOSITORY_DIR
    rows: list[dict[str, str]] = []
    try:
        paths = sorted(directory.glob("*.repo"))
    except OSError:
        paths = []
    for path in paths:
        parser = configparser.ConfigParser(interpolation=None, strict=False)
        try:
            parser.read(path, encoding="utf-8")
        except (OSError, configparser.Error):
            continue
        for section in parser.sections():
            enabled = parser.get(section, "enabled", fallback="1").strip().lower()
            if enabled in {"0", "false", "no", "off"}:
                continue
            location = ""
            location_type = ""
            for option in ("baseurl", "mirrorlist", "metalink"):
                candidate = " ".join(parser.get(section, option, fallback="").split())
                if candidate:
                    location = candidate
                    location_type = option
                    break
            rows.append(
                {
                    "id": section,
                    "name": parser.get(section, "name", fallback=section).strip() or section,
                    "location": location,
                    "location_type": location_type,
                    "file": path.name,
                }
            )
    return rows


def photon_repository_summary(repository_dir: Path | None = None) -> str:
    rows = photon_repository_details(repository_dir)
    if not rows:
        return f"No enabled repositories found in {repository_dir or PHOTON_REPOSITORY_DIR}"
    return "\n".join(
        f"{row['id']} | {row['name']} | {row['location_type']}={row['location']}"
        if row["location"]
        else f"{row['id']} | {row['name']} | {row['file']}"
        for row in rows
    )
