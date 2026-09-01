"""Implement update sources service behavior."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from atlaso.app.models import ManagedPackage, UpdateSource
from atlaso.app.secrets import decrypt_secret

UPDATE_SOURCE_KINDS = {"photon", "powershell", "atlaso"}
ATLASO_CHANNELS = {"stable", "preview", "development"}
PSGALLERY_NAME = "PSGallery"
PSGALLERY_SOURCE_URL = "https://www.powershellgallery.com/api/v2"
POWERSHELL_SOURCE_HOME_VALIDATION_MESSAGE = (
    "Repository synchronized with the secured privileged PowerShell home."
)


def is_reserved_psgallery_name(value: str) -> bool:
    """Return whether a source name is the PowerShellGet reserved gallery name.

    Args:
        value: Candidate PowerShell repository name.
    """
    return value.strip().casefold() == PSGALLERY_NAME.casefold()


def is_canonical_psgallery_url(value: str) -> bool:
    """Return whether a URL is the canonical PowerShell Gallery endpoint.

    Args:
        value: Candidate PowerShell repository URL.
    """
    parsed = urlparse(value.strip())
    try:
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme.casefold() == "https"
        and (parsed.hostname or "").casefold() == "www.powershellgallery.com"
        and port is None
        and parsed.path in {"/api/v2", "/api/v2/"}
        and not parsed.params
        and not parsed.query
        and not parsed.fragment
        and parsed.username is None
        and parsed.password is None
    )


def validate_reserved_psgallery(name: str, url: str) -> list[str]:
    """Reject a reserved PSGallery identity that targets a custom endpoint.

    Args:
        name: Candidate PowerShell repository name.
        url: Candidate PowerShell repository URL.
    """
    if not is_reserved_psgallery_name(name) or is_canonical_psgallery_url(url):
        return []
    return [
        f"{PSGALLERY_NAME} is reserved for the built-in PowerShell Gallery. "
        f"Use {PSGALLERY_SOURCE_URL}, or choose a different repository name for a custom endpoint."
    ]


def update_source_settings(source: UpdateSource) -> dict[str, Any]:
    """Update source settings.

    Args:
        source: Source object or location from which data is obtained.


    Returns:
        The update source settings result.
    """
    try:
        payload = json.loads(source.settings_json or "{}")
    except json.JSONDecodeError:
        payload = {}
    return payload if isinstance(payload, dict) else {}


def validate_http_url(value: str, *, label: str, required: bool) -> list[str]:
    """Validate http url.

    Args:
        value: Candidate value consumed by validate HTTP URL.
        label: Human-readable label used to identify the result.
        required: Whether required applies to the operation.


    Returns:
        The validate http url result.
    """
    normalized = value.strip()
    if not normalized:
        return [f"{label} is required."] if required else []
    parsed = urlparse(normalized)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return [f"{label} must be an HTTP(S) URL."]
    if parsed.username or parsed.password:
        return [f"{label} must not contain embedded credentials."]
    return []


def validate_update_source(source: UpdateSource) -> list[str]:
    """Validate update source.

    Args:
        source: Source object or location from which data is obtained.


    Returns:
        The validate update source result.
    """
    if source.kind not in UPDATE_SOURCE_KINDS:
        return ["Unsupported update source kind."]
    settings = update_source_settings(source)
    if source.kind == "photon" and not bool(settings.get("managed")):
        return []
    required = source.kind in {"photon", "powershell"}
    errors = validate_http_url(source.url, label=f"{source.name} URL", required=required)
    if source.kind == "powershell":
        errors.extend(validate_reserved_psgallery(source.name, source.url))
    if source.kind == "atlaso":
        parsed = urlparse(source.url.strip())
        if source.url.strip() and parsed.scheme != "https":
            errors.append("Atlaso release sources must use HTTPS.")
        channel = str(settings.get("channel") or "stable")
        if channel not in ATLASO_CHANNELS:
            errors.append("Atlaso channel must be stable, preview, or development.")
    if not 0 <= int(source.priority) <= 100:
        errors.append("Source priority must be between 0 and 100.")
    return errors


def atlaso_manifest_url(source: UpdateSource) -> str:
    """Return atlaso manifest url.

    Args:
        source: Source object or location from which data is obtained.
    """
    base = source.url.strip()
    if not base:
        return ""
    if base.lower().endswith(".json"):
        return base
    channel = str(update_source_settings(source).get("channel") or "stable")
    return f"{base.rstrip('/')}/channels/{channel}/manifest.json"


def source_rows(db: Session) -> list[UpdateSource]:
    """Return source rows.

    Args:
        db: Active database session.
    """
    return db.execute(select(UpdateSource).order_by(UpdateSource.kind, UpdateSource.priority, UpdateSource.name)).scalars().all()


def managed_package_rows(db: Session) -> list[ManagedPackage]:
    """Return managed package rows.

    Args:
        db: Active database session.
    """
    return db.execute(select(ManagedPackage).order_by(ManagedPackage.ecosystem, ManagedPackage.name)).scalars().all()


def effective_update_settings(db: Session, *, stored: dict[str, str] | None = None) -> dict[str, Any]:
    """Return effective update settings.

    Args:
        db: Active database session.
        stored: Stored supplied by the caller.
    """
    stored = stored or {}
    sources = [source for source in source_rows(db) if source.enabled]
    photon = next((source for source in sources if source.kind == "photon"), None)
    powershell = next((source for source in sources if source.kind == "powershell"), None)
    atlaso_sources = [source for source in sources if source.kind == "atlaso"]
    packages = [package for package in managed_package_rows(db) if package.enabled]
    manifest_urls = [url for source in atlaso_sources if (url := atlaso_manifest_url(source))]
    if not manifest_urls and str(stored.get("atlaso_manifest_url") or "").strip():
        manifest_urls.append(str(stored["atlaso_manifest_url"]).strip())
    return {
        "photon_source": photon.name if photon is not None else "configured Photon repositories",
        "atlaso_manifest_url": manifest_urls[0] if manifest_urls else "",
        "atlaso_manifest_urls": manifest_urls,
        "powershell_repository_name": powershell.name if powershell is not None else "",
        "powershell_repository_url": powershell.url.strip() if powershell is not None else "",
        "powershell_repository_trusted": bool(update_source_settings(powershell).get("trusted")) if powershell is not None else False,
        "powershell_modules": [
            {
                "name": package.name,
                "policy": package.policy,
                "target_version": package.target_version,
                "repository_name": package.source.name,
            }
            for package in packages
            if package.ecosystem == "powershell"
            and package.source is not None
            and package.source.kind == "powershell"
            and package.source.enabled
        ],
        "source_definitions": [update_source_payload(source) for source in sources],
    }


def unsynchronized_powershell_repositories(settings: dict[str, Any]) -> list[str]:
    """Handle unsynchronized powershell repositories.

    Args:
        settings: Current Atlaso settings used to configure the operation.
    """
    modules = settings.get("powershell_modules")
    referenced = {
        str(module.get("repository_name") or "").strip()
        for module in modules
        if isinstance(module, dict) and str(module.get("repository_name") or "").strip()
    } if isinstance(modules, list) else set()
    definitions = settings.get("source_definitions")
    if not isinstance(definitions, list):
        return sorted(referenced)
    synchronized = {
        str(source.get("name") or "").strip()
        for source in definitions
        if isinstance(source, dict)
        and source.get("kind") == "powershell"
        and source.get("enabled") is True
        and source.get("validation_status") == "valid"
        and source.get("validation_message")
        == POWERSHELL_SOURCE_HOME_VALIDATION_MESSAGE
    }
    return sorted(referenced - synchronized)


def unsynchronized_photon_repositories(settings: dict[str, Any]) -> list[str]:
    """Handle unsynchronized photon repositories.

    Args:
        settings: Current Atlaso settings used to configure the operation.
    """
    definitions = settings.get("source_definitions")
    if not isinstance(definitions, list):
        return []
    return sorted(
        str(source.get("name") or "configured Photon repositories").strip()
        for source in definitions
        if isinstance(source, dict)
        and source.get("kind") == "photon"
        and source.get("enabled") is True
        and isinstance(source.get("settings"), dict)
        and source["settings"].get("managed") is True
        and source.get("validation_status") != "valid"
    )


def update_source_credentials(db: Session) -> dict[str, dict[str, str]]:
    """Return decrypted credentials for the protected helper runtime channel only.

    Args:
        db: Active database session used by the operation.
    """
    credentials: dict[str, dict[str, str]] = {}
    for source in source_rows(db):
        if not source.enabled or not source.credential_encrypted or source.id is None:
            continue
        try:
            payload = json.loads(decrypt_secret(source.credential_encrypted))
        except (ValueError, json.JSONDecodeError) as exc:
            raise ValueError(f"Credentials for update source {source.name} could not be decrypted.") from exc
        if not isinstance(payload, dict) or not str(payload.get("secret") or ""):
            continue
        credentials[str(source.id)] = {
            "username": str(payload.get("username") or ""),
            "secret": str(payload["secret"]),
        }
    return credentials


def default_source_settings(kind: str) -> dict[str, Any]:
    """Return default source settings.

    Args:
        kind: Kind consumed by default source settings.
    """
    return {
        "photon": {"managed": True, "gpgcheck": True, "gpgkey": "", "tls_verify": True},
        "powershell": {"trusted": False},
        "atlaso": {"channel": "stable"},
    }.get(kind, {})


def validate_managed_package(package: ManagedPackage) -> list[str]:
    """Validate managed package.

    Args:
        package: Candidate package to validate.


    Returns:
        The validate managed package result.
    """
    errors: list[str] = []
    if package.ecosystem != "powershell":
        errors.append("Only PowerShell modules are supported as operator-managed packages.")
    if not package.name.strip():
        errors.append("Module name is required.")
    if package.policy not in {"latest", "pinned"}:
        errors.append("Module policy must be latest or pinned.")
    if package.policy == "pinned" and not package.target_version.strip():
        errors.append("Pinned modules require a target version.")
    if package.source is None or package.source.kind != "powershell":
        errors.append("Choose a PowerShell repository for this module.")
    elif package.enabled and not package.source.enabled:
        errors.append("An enabled module must use an enabled PowerShell repository.")
    return errors


def update_source_payload(source: UpdateSource) -> dict[str, Any]:
    """Update source payload.

    Args:
        source: Source object or location from which data is obtained.


    Returns:
        The update source payload result.
    """
    return {
        "id": source.id,
        "kind": source.kind,
        "name": source.name,
        "url": source.url,
        "enabled": source.enabled,
        "priority": source.priority,
        "settings": update_source_settings(source),
        "credential_present": bool(source.credential_encrypted),
        "validation_status": source.validation_status,
        "validation_message": source.validation_message,
        "validated_at": source.validated_at.isoformat() if source.validated_at else "",
        "updated_at": source.updated_at.isoformat() if source.updated_at else "",
    }
