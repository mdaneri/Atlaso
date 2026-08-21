"""Implement appliance update service behavior."""

from __future__ import annotations

import configparser
import hashlib
import json
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

from atlaso import __version__
from atlaso.app.models import Job, JobStatus, JobStep

APPLIANCE_UPDATE_SETTINGS_KEY = "appliance_update.settings.v1"
APPLIANCE_UPDATE_AVAILABILITY_KEY = "appliance_update.availability.v1"
APPLIANCE_UPDATE_STAGED_CONFIG_PATH = "/var/lib/atlaso/apply/appliance-update/atlaso-update.json"
APPLIANCE_UPDATE_STAGED_CREDENTIALS_PATH = "/var/lib/atlaso/apply/appliance-update/atlaso-update-credentials.json"
APPLIANCE_UPDATE_INFO_PATH = "/etc/atlaso/update-info"
APPLIANCE_UPDATE_FINALIZER_PATH = "/var/lib/atlaso/apply/appliance-update/finalizer-status.json"
APPLIANCE_UPDATE_RESTART_GATE_PATH = Path("/run/atlaso-release-restart-gate")
ATLASO_CURRENT_RELEASE_PATH = Path("/opt/atlaso/current")
ATLASO_COMPATIBILITY_VENV_PATH = Path("/opt/atlaso/.venv")
PHOTON_REPOSITORY_DIR = Path("/etc/yum.repos.d")
DEFAULT_ATLASO_RELEASE_URL = "https://mdaneri.github.io/Atlaso/updates"
DEFAULT_ATLASO_MANIFEST_URL = f"{DEFAULT_ATLASO_RELEASE_URL}/channels/stable/manifest.json"
UPDATE_STREAMS = ("photon_os", "powershell_modules", "atlaso_release")
APPLIANCE_UPDATE_EXECUTION_ORDER = ("atlaso_release", "powershell_modules", "photon_os")
UPDATE_STREAM_LABELS = {
    "photon_os": "Photon OS",
    "powershell_modules": "PowerShell Modules",
    "atlaso_release": "Atlaso Release",
}

AVAILABILITY_CHANGE_LIMIT = 100
AVAILABILITY_VISIBLE_CHANGE_LIMIT = 20
AVAILABILITY_TEXT_LIMIT = 500


def _bounded_availability_text(value: Any, *, limit: int = AVAILABILITY_TEXT_LIMIT) -> str:
    """Return one bounded line of public-safe availability text.

    Args:
        value: Candidate value to normalize into one line.
        limit: Maximum number of returned characters.
    """
    text = " ".join(str(value or "").split())
    return text if len(text) <= limit else f"{text[: limit - 1]}…"


def empty_update_availability() -> dict[str, Any]:
    """Return the persisted Appliance Update availability envelope."""
    return {"schema_version": 1, "streams": {}}


def update_availability_from_json(raw_value: str) -> dict[str, Any]:
    """Parse persisted availability while rejecting unknown envelope shapes.

    Args:
        raw_value: Serialized operational availability state.
    """
    try:
        payload = json.loads(raw_value or "{}")
    except json.JSONDecodeError:
        return empty_update_availability()
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        return empty_update_availability()
    streams = payload.get("streams")
    if not isinstance(streams, dict):
        return empty_update_availability()
    return {
        "schema_version": 1,
        "streams": {
            stream: value
            for stream, value in streams.items()
            if stream in UPDATE_STREAMS and isinstance(value, dict)
        },
    }


def update_availability_to_json(value: dict[str, Any]) -> str:
    """Serialize the bounded availability envelope.

    Args:
        value: Operational availability envelope to serialize.
    """
    return json.dumps(value, indent=2, sort_keys=True)


def update_stream_configuration_fingerprint(stream: str, settings: dict[str, Any]) -> str:
    """Bind a confirmation to the configuration used to produce it.

    Args:
        stream: Update stream identifier to fingerprint.
        settings: Effective Appliance Update settings.
    """
    definitions = settings.get("source_definitions")
    modules = (
        settings.get("powershell_modules")
        if isinstance(settings.get("powershell_modules"), list)
        else []
    )
    default_powershell_repository = str(
        settings.get("powershell_repository_name") or ""
    ).strip()
    referenced_powershell_repositories = {
        str(module.get("repository_name") or default_powershell_repository).strip()
        for module in modules
        if isinstance(module, dict)
        and str(module.get("repository_name") or default_powershell_repository).strip()
    }
    source_kind = {
        "photon_os": "photon",
        "powershell_modules": "powershell",
        "atlaso_release": "atlaso",
    }.get(stream, "")
    sources = [
        {
            "id": source.get("id"),
            "kind": source.get("kind"),
            "name": source.get("name"),
            "url": source.get("url"),
            "enabled": source.get("enabled"),
            "priority": source.get("priority"),
            "settings": source.get("settings") if isinstance(source.get("settings"), dict) else {},
            "credential_present": bool(source.get("credential_present")),
            "updated_at": source.get("updated_at"),
            "validation_status": source.get("validation_status"),
        }
        for source in definitions or []
        if isinstance(source, dict) and source.get("kind") == source_kind
        and (
            stream != "powershell_modules"
            or str(source.get("name") or "").strip()
            in referenced_powershell_repositories
        )
    ] if isinstance(definitions, list) else []
    payload: dict[str, Any] = {"stream": stream, "sources": sources}
    if stream == "powershell_modules":
        payload["modules"] = modules
    elif stream == "atlaso_release" and not sources:
        payload["manifest_urls"] = settings.get("atlaso_manifest_urls") or [settings.get("atlaso_manifest_url")]
    elif stream == "photon_os" and not sources:
        payload["source"] = settings.get("photon_source")
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def update_stream_configuration_fingerprints(settings: dict[str, Any]) -> dict[str, str]:
    """Return current fingerprints for every update stream.

    Args:
        settings: Effective Appliance Update settings.
    """
    return {
        stream: update_stream_configuration_fingerprint(stream, settings)
        for stream in UPDATE_STREAMS
    }


def normalized_availability_result(value: Any) -> dict[str, Any]:
    """Normalize one helper result before it enters durable browser-visible state.

    Args:
        value: Raw helper result to sanitize and bound.
    """
    source = value if isinstance(value, dict) else {}
    state = str(source.get("state") or "failed")
    if state not in {"available", "up_to_date", "failed"}:
        state = "failed"
    changes = source.get("changes") if isinstance(source.get("changes"), list) else []
    bounded_changes = []
    for change in changes[:AVAILABILITY_CHANGE_LIMIT]:
        if not isinstance(change, dict):
            continue
        bounded_changes.append(
            {
                key: _bounded_availability_text(change.get(key), limit=160)
                for key in ("name", "current", "target", "action", "summary")
                if change.get(key) not in (None, "")
            }
        )
    release_notes_url = str(source.get("release_notes_url") or "").strip()
    try:
        parsed_notes = urlparse(release_notes_url)
    except ValueError:
        parsed_notes = None
    if (
        parsed_notes is None
        or parsed_notes.scheme != "https"
        or not parsed_notes.netloc
        or parsed_notes.username
        or parsed_notes.password
        or any(character.isspace() or ord(character) < 32 for character in release_notes_url)
    ):
        release_notes_url = ""
    try:
        change_count = int(source.get("change_count") or len(changes))
    except (TypeError, ValueError):
        change_count = len(changes)
    return {
        "state": state,
        "update_available": state == "available",
        "current": _bounded_availability_text(source.get("current"), limit=200),
        "target": _bounded_availability_text(source.get("target"), limit=200),
        "change_count": min(max(0, change_count), 1_000_000),
        "changes": bounded_changes,
        "details_incomplete": bool(source.get("details_incomplete")) or len(changes) > AVAILABILITY_CHANGE_LIMIT,
        "summary": _bounded_availability_text(source.get("summary"), limit=240),
        "release_notes_url": release_notes_url,
        "remediation": _bounded_availability_text(source.get("remediation"), limit=300),
    }


def record_update_availability_attempt(
    state: dict[str, Any],
    *,
    stream: str,
    job_id: str,
    checked_at: datetime,
    fingerprint: str,
    result: dict[str, Any],
) -> dict[str, Any]:
    """Record a check without erasing an earlier confirmation when it fails.

    Args:
        state: Existing operational availability envelope.
        stream: Checked update stream identifier.
        job_id: Appliance Update job identifier.
        checked_at: Timestamp associated with the completed check.
        fingerprint: Configuration fingerprint used by the check.
        result: Raw normalized-stream helper result.
    """
    envelope = update_availability_from_json(update_availability_to_json(state))
    normalized = normalized_availability_result(result)
    stream_state = dict(envelope["streams"].get(stream) or {})
    successful = normalized["state"] in {"available", "up_to_date"}
    stream_state["last_attempt"] = {
        "job_id": _bounded_availability_text(job_id, limit=100),
        "checked_at": checked_at.isoformat(),
        "success": successful,
        "state": normalized["state"],
        "fingerprint": fingerprint,
        "remediation": normalized["remediation"],
    }
    if successful:
        stream_state["confirmed"] = {
            "fingerprint": fingerprint,
            "checked_at": checked_at.isoformat(),
            **{key: normalized[key] for key in (
                "state", "update_available", "current", "target", "change_count", "changes",
                "details_incomplete", "summary", "release_notes_url",
            )},
        }
    envelope["streams"][stream] = stream_state
    return envelope


def clear_installed_update_availability(
    state: dict[str, Any], *, successful_streams: list[str] | tuple[str, ...]
) -> dict[str, Any]:
    """Clear only confirmations for streams whose installation succeeded.

    Args:
        state: Existing operational availability envelope.
        successful_streams: Streams whose real installation succeeded.
    """
    envelope = update_availability_from_json(update_availability_to_json(state))
    for stream in successful_streams:
        stream_state = envelope["streams"].get(stream)
        if isinstance(stream_state, dict):
            stream_state.pop("confirmed", None)
    return envelope


def update_availability_summary(
    state: dict[str, Any],
    settings: dict[str, Any],
    *,
    result_streams: list[str] | tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Project sanitized current availability for the UI and install gate.

    Args:
        state: Persisted operational availability envelope.
        settings: Effective Appliance Update settings.
        result_streams: Optional stream subset for the composite result summary.
    """
    envelope = update_availability_from_json(update_availability_to_json(state))
    fingerprints = update_stream_configuration_fingerprints(settings)
    rows: list[dict[str, Any]] = []
    for stream in UPDATE_STREAMS:
        stored = envelope["streams"].get(stream)
        stored = stored if isinstance(stored, dict) else {}
        attempt = stored.get("last_attempt") if isinstance(stored.get("last_attempt"), dict) else {}
        confirmed = stored.get("confirmed") if isinstance(stored.get("confirmed"), dict) else {}
        stale = bool(confirmed) and confirmed.get("fingerprint") != fingerprints[stream]
        attempt_state = str(attempt.get("state") or "")
        if attempt_state not in {"available", "up_to_date", "failed"}:
            attempt_state = ""
        row = {
            "id": stream,
            "label": UPDATE_STREAM_LABELS[stream],
            "last_attempt": {
                "checked_at": _bounded_availability_text(attempt.get("checked_at"), limit=80),
                "success": attempt.get("success") is True,
                "state": attempt_state,
                "current": "",
                "target": "",
                "remediation": _bounded_availability_text(attempt.get("remediation"), limit=300),
            },
            "confirmed": None,
            "stale": stale,
        }
        if confirmed:
            row["last_attempt"]["current"] = _bounded_availability_text(confirmed.get("current"), limit=200)
            row["last_attempt"]["target"] = _bounded_availability_text(confirmed.get("target"), limit=200)
        if confirmed and not stale:
            normalized = normalized_availability_result(confirmed)
            normalized["checked_at"] = _bounded_availability_text(
                confirmed.get("checked_at"), limit=80
            )
            normalized["details_incomplete"] = bool(
                normalized.get("details_incomplete")
            ) or len(normalized["changes"]) > AVAILABILITY_VISIBLE_CHANGE_LIMIT
            normalized["changes"] = normalized["changes"][:AVAILABILITY_VISIBLE_CHANGE_LIMIT]
            row["confirmed"] = normalized
        rows.append(row)
    available = [row for row in rows if row["confirmed"] and row["confirmed"]["update_available"]]
    selected_result_streams = set(
        UPDATE_STREAMS
        if result_streams is None
        else selected_update_streams(result_streams)
    )
    result_rows = [row for row in rows if row["id"] in selected_result_streams]
    result_available = [
        row
        for row in result_rows
        if row["confirmed"] and row["confirmed"]["update_available"]
    ]
    result_failed = [
        row for row in result_rows if row["last_attempt"]["state"] == "failed"
    ]
    result_confirmed = [
        row for row in result_rows if row["confirmed"] and not row["stale"]
    ]
    result_summary = {
        "pill": "Not checked",
        "pill_class": "muted",
        "title": "Check the selected streams for current update information",
        "description": "Each stream keeps its latest result independently.",
    }
    if result_failed:
        count = len(result_failed)
        result_summary = {
            "pill": "Check failed",
            "pill_class": "error",
            "title": (
                f"{count} selected update "
                f"{'stream needs' if count == 1 else 'streams need'} attention"
            ),
            "description": "Successful and failed stream results remain independently visible below.",
        }
    elif result_available:
        count = len(result_available)
        result_summary = {
            "pill": "Updates available",
            "pill_class": "warn",
            "title": (
                f"{count} selected update "
                f"{'stream has' if count == 1 else 'streams have'} changes"
            ),
            "description": "Review each stream’s current, target, and What’s new details before installation.",
        }
    elif result_rows and len(result_confirmed) == len(result_rows):
        result_summary = {
            "pill": "Up to date",
            "pill_class": "good",
            "title": "The selected streams are current",
            "description": "No installation is needed for the latest confirmed checks.",
        }
    return {
        "schema_version": 1,
        "available": bool(available),
        "affected_stream_count": len(available),
        "streams": rows,
        "result_summary": result_summary,
        "url": "/ui/management/appliance-update#appliance-update-streams",
    }


def manual_install_gate(
    summary: dict[str, Any], selected_streams: list[str] | tuple[str, ...]
) -> tuple[bool, str]:
    """Require a successful current check for every selected install stream.

    Args:
        summary: Sanitized availability projection for the current configuration.
        selected_streams: Requested manual-install stream identifiers.
    """
    selected = selected_update_streams(selected_streams)
    if not selected:
        return False, "Select at least one update stream."
    rows = {str(row.get("id")): row for row in summary.get("streams", []) if isinstance(row, dict)}
    for stream in selected:
        row = rows.get(stream) or {}
        attempt = row.get("last_attempt") if isinstance(row.get("last_attempt"), dict) else {}
        confirmed = row.get("confirmed") if isinstance(row.get("confirmed"), dict) else None
        if row.get("stale"):
            return False, f"Check {UPDATE_STREAM_LABELS[stream]} again because its update configuration changed."
        if attempt.get("success") is not True or confirmed is None:
            remediation = str(attempt.get("remediation") or "").strip()
            return False, remediation or f"Check {UPDATE_STREAM_LABELS[stream]} successfully before installing it."
    if not any(
        isinstance((rows.get(stream) or {}).get("confirmed"), dict)
        and bool((rows.get(stream) or {})["confirmed"].get("update_available"))
        for stream in selected
    ):
        return False, "The selected streams are up to date."
    return True, ""


def reconcile_release_success_finalizer(finalizer: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Validate a success finalizer against live release and running-version state.

    Args:
        finalizer: Root-owned release transaction evidence to reconcile.
    """
    if str(finalizer.get("status") or "") != JobStatus.SUCCEEDED.value:
        return finalizer, True

    expected_version = str(finalizer.get("candidate_version") or finalizer.get("release") or "").split("+", 1)[0]
    activation = finalizer.get("active_release_verification")
    worker_restart = finalizer.get("worker_restart")
    legacy_success = bool(
        finalizer.get("rolled_back") is False
        and "active_release_verification" not in finalizer
        and "worker_restart" not in finalizer
        and (finalizer.get("service_health") is True or finalizer.get("no_change") is True)
    )
    errors: list[str] = []
    if not expected_version:
        errors.append("candidate version is missing")
    if not legacy_success and (not isinstance(activation, dict) or activation.get("success") is not True):
        errors.append("definitive activation evidence is missing")
    if not finalizer.get("no_change") and not legacy_success:
        if not isinstance(worker_restart, dict) or worker_restart.get("success") is not True:
            errors.append("candidate worker restart evidence is missing")
        elif str(worker_restart.get("worker_version") or "").split("+", 1)[0] != expected_version:
            errors.append("recorded worker restart version does not match the finalizer")
        elif str(worker_restart.get("release_job_id") or "") != str(finalizer.get("job_id") or ""):
            errors.append("recorded worker restart job does not match the finalizer")
    try:
        if not ATLASO_CURRENT_RELEASE_PATH.is_symlink():
            raise ValueError("active release link is missing")
        current_root = ATLASO_CURRENT_RELEASE_PATH.resolve(strict=True)
    except (OSError, ValueError) as exc:
        current_root = None
        errors.append(str(exc))
    try:
        if not ATLASO_COMPATIBILITY_VENV_PATH.is_symlink():
            raise ValueError("compatibility virtualenv link is missing")
        compatibility_venv = ATLASO_COMPATIBILITY_VENV_PATH.resolve(strict=True)
    except (OSError, ValueError) as exc:
        compatibility_venv = None
        errors.append(str(exc))
    if current_root is not None and compatibility_venv != (current_root / ".venv").resolve():
        errors.append("compatibility virtualenv does not resolve through the active release")
    if (
        current_root is not None
        and isinstance(worker_restart, dict)
        and not finalizer.get("no_change")
    ):
        try:
            worker_release = Path(str(worker_restart.get("worker_release") or "")).resolve(strict=True)
        except (OSError, ValueError):
            worker_release = None
        if worker_release != current_root:
            errors.append("recorded worker restart release does not match the active release")

    receipt: dict[str, Any] = {}
    if current_root is not None:
        try:
            parsed = json.loads((current_root / ".release-manifest.json").read_text(encoding="utf-8"))
            receipt = parsed if isinstance(parsed, dict) else {}
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            receipt = {}
    if not receipt:
        errors.append("active signed-release receipt is missing or invalid")
    receipt_version = str(receipt.get("version") or "").split("+", 1)[0]
    if receipt_version != expected_version:
        errors.append("active signed-release receipt version does not match the finalizer")
    receipt_sha256 = hashlib.sha256(
        json.dumps(receipt, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest() if receipt else ""
    if receipt_sha256 != str(finalizer.get("release_manifest_sha256") or ""):
        errors.append("active signed-release receipt identity does not match the finalizer")
    if str(receipt.get("git_commit") or "") != str(finalizer.get("git_commit") or ""):
        errors.append("active signed-release commit does not match the finalizer")
    receipt_bundle = receipt.get("bundle")
    if not isinstance(receipt_bundle, dict):
        errors.append("active signed-release receipt bundle is missing or invalid")
        receipt_bundle = {}
    if str(receipt_bundle.get("sha256") or "") != str(finalizer.get("bundle_sha256") or ""):
        errors.append("active signed-release bundle does not match the finalizer")
    running_version = __version__.split("+", 1)[0]
    if running_version != expected_version:
        errors.append("running Atlaso version does not match the finalizer")
    if isinstance(activation, dict):
        for field in ("candidate_version", "receipt_version", "internal_version", "host_facing_version"):
            if str(activation.get(field) or "").split("+", 1)[0] != expected_version:
                errors.append(f"recorded {field.replace('_', ' ')} does not match the finalizer")

    if not errors and legacy_success:
        reconciled = dict(finalizer)
        reconciled["startup_reconciliation"] = {
            "success": True,
            "legacy_finalizer": True,
            "candidate_version": expected_version,
            "current_release": str(current_root),
            "compatibility_venv": str(compatibility_venv),
            "receipt_version": receipt_version,
            "running_version": running_version,
        }
        return reconciled, True
    if not errors:
        return finalizer, True
    reconciled = dict(finalizer)
    reconciled.update(
        {
            "status": JobStatus.FAILED.value,
            "success": False,
            "failure_layer": "startup_reconciliation",
            "startup_consistent": False,
            "error": "Successful Atlaso release finalizer is inconsistent with the durable active release: "
            + "; ".join(dict.fromkeys(errors))
            + ".",
        }
    )
    return reconciled, False


def ensure_appliance_update_job_steps(
    db: Session,
    *,
    job: Job,
    selected_streams: list[str] | tuple[str, ...],
) -> list[JobStep]:
    """Ensure appliance update job steps.

    Args:
        db: Active database session.
        job: Job being processed.
        selected_streams: Update streams selected for the job.

    Returns:
        The ensure appliance update job steps result.
    """
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
    "atlaso_manifest_url": DEFAULT_ATLASO_MANIFEST_URL,
    "powershell_repository_name": "",
    "powershell_repository_url": "",
}
def _git_value(args: list[str]) -> str:
    """Return git value.

    Args:
        args: Parsed command-line options consumed by the operation.
    """
    try:
        result = subprocess.run(["git", *args], cwd=Path(__file__).resolve().parents[3], check=False, capture_output=True, text=True)
    except OSError:
        return ""
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


@lru_cache(maxsize=1)
def _installed_record_sha256() -> str:
    """Return installed record sha256."""
    try:
        distribution = importlib_metadata.distribution("atlaso")
    except importlib_metadata.PackageNotFoundError:
        return ""
    record_text = distribution.read_text("RECORD") or ""
    if not record_text:
        return ""
    return hashlib.sha256(record_text.encode("utf-8")).hexdigest()


def current_version_info() -> dict[str, str]:
    """Return current version info."""
    full_commit = getattr(__import__("atlaso"), "__build_git_commit__", "") or _git_value(["rev-parse", "HEAD"])
    short_commit = full_commit[:12] if full_commit else ""
    built_at = getattr(__import__("atlaso"), "__build_time_utc__", "")
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
    """Return version with git.

    Args:
        base_version: Base version consumed by version with git.
        git_commit: Git commit consumed by version with git.
    """
    normalized = base_version.strip()
    if not normalized:
        normalized = "0.0.0"
    if "+" in normalized:
        normalized = normalized.split("+", 1)[0]
    short = re.sub(r"[^0-9A-Fa-f]", "", git_commit or "")[:12]
    return f"{normalized}+g{short}" if short else normalized


def update_settings_from_json(raw_value: str) -> dict[str, Any]:
    """Update settings from json.

    Args:
        raw_value: Raw value consumed by update settings from JSON.


    Returns:
        The update settings from json result.
    """
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
    """Update settings to json.

    Args:
        settings: Current Atlaso settings used to configure the operation.


    Returns:
        The update settings to json result.
    """
    normalized = dict(DEFAULT_UPDATE_SETTINGS)
    for key in normalized:
        normalized[key] = str(settings.get(key) or "").strip()
    return json.dumps(normalized, indent=2, sort_keys=True)


def validate_update_url(value: str, label: str) -> list[str]:
    """Validate update url.

    Args:
        value: Candidate value consumed by validate update URL.
        label: Human-readable label used to identify the result.


    Returns:
        The validate update url result.
    """
    if not value.strip():
        return []
    parsed = urlparse(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return [f"{label} must be an http or https URL."]
    if parsed.username or parsed.password:
        return [f"{label} must not include embedded credentials."]
    return []


def validate_update_settings(settings: dict[str, Any]) -> list[str]:
    """Validate update settings.

    Args:
        settings: Current Atlaso settings used to configure the operation.


    Returns:
        The validate update settings result.
    """
    errors: list[str] = []
    errors.extend(validate_update_url(settings.get("atlaso_manifest_url", ""), "Atlaso manifest URL"))
    release_url = urlparse(str(settings.get("atlaso_manifest_url") or ""))
    if release_url.scheme and release_url.scheme != "https":
        errors.append("Atlaso manifest URL must use HTTPS.")
    errors.extend(validate_update_url(settings.get("powershell_repository_url", ""), "PowerShell repository URL"))
    return errors


def selected_update_streams(raw_streams: list[str] | tuple[str, ...]) -> list[str]:
    """Return selected update streams.

    Args:
        raw_streams: Raw streams consumed by selected update streams.
    """
    normalized = set(raw_streams)
    selected = [stream for stream in UPDATE_STREAMS if stream in normalized]
    return selected


def redact_url_userinfo(value: str) -> str:
    """Return redact url userinfo.

    Args:
        value: Candidate value consumed by redact URL userinfo.
    """
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
    """Render update manifest.

    Args:
        selected_streams: Update streams selected for the job.
        settings: Desired or runtime settings consumed by the operation.
        actor: Authenticated identity attributed to the audit record.
        job_id: Identifier of the job.

    Returns:
        The rendered update manifest.
    """
    payload = {
        "schema_version": 2,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_by": actor,
        "job_id": job_id,
        "selected_streams": selected_streams,
        "sources": {
            "photon_os": settings.get("photon_source") or DEFAULT_UPDATE_SETTINGS["photon_source"],
            "atlaso_manifest_url": redact_url_userinfo(settings.get("atlaso_manifest_url") or DEFAULT_ATLASO_MANIFEST_URL),
            "atlaso_manifest_urls": [
                redact_url_userinfo(str(value)) for value in settings.get("atlaso_manifest_urls", []) if str(value).strip()
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
            "supported_python_abis": ["cp314"],
            "runtime_python_indexes": False,
            "vmware_ceip_enabled": bool(settings.get("vmware_ceip_enabled", False)),
        },
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def update_result_excerpt(value: str, *, limit: int = 4000) -> str:
    """Update result excerpt.

    Args:
        value: Candidate value consumed by update result excerpt.
        limit: Limit consumed by update result excerpt.


    Returns:
        The update result excerpt result.
    """
    text = str(value or "")
    if len(text) <= limit:
        return text
    return text[: limit - 20] + "\n[output truncated]"


def parse_latest_update_result(job: Job | None) -> dict[str, Any] | None:
    """Parse latest update result.

    Args:
        job: Background job record affected by the operation.


    Returns:
        The parsed latest update result.
    """
    if job is None or not job.result:
        return None
    try:
        payload = json.loads(job.result)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def read_appliance_file(path_value: str) -> dict[str, Any]:
    """Return appliance file.

    Args:
        path_value: Path value consumed by read appliance file.
    """
    path = Path(path_value)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return {"path": path_value, "available": False, "content": "", "error": str(exc)}
    return {"path": path_value, "available": True, "content": text, "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()}


def photon_repository_details(repository_dir: Path | None = None) -> list[dict[str, str]]:
    """Return photon repository details.

    Args:
        repository_dir: Filesystem path associated with repository dir.
    """
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
    """Return photon repository summary.

    Args:
        repository_dir: Filesystem path associated with repository dir.
    """
    rows = photon_repository_details(repository_dir)
    if not rows:
        return f"No enabled repositories found in {repository_dir or PHOTON_REPOSITORY_DIR}"
    return "\n".join(
        f"{row['id']} | {row['name']} | {row['location_type']}={row['location']}"
        if row["location"]
        else f"{row['id']} | {row['name']} | {row['file']}"
        for row in rows
    )
