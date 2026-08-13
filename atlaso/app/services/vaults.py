"""Implement vaults service behavior."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from atlaso.app.models import Vault, VaultEntry, utcnow
from atlaso.app.secrets import decrypt_secret, encrypt_secret

VAULT_KEY_PATTERN = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*$")
VAULT_SECRET_TYPES = {"vcf_password", "esx_password"}
VAULT_SOURCE_TYPES = {"manual", "sddc_manager", "vcf_installer"}
VAULT_URI_SCHEMES = {"http", "https", "ssh", "sftp"}
VAULT_URI_LIMIT = 9


@dataclass(frozen=True)
class VaultEntryInput:
    """Represent vault entry input.

    Attributes:
        key: Key maintained by this vaultentryinput.
        secret_type: Secret type maintained by this vaultentryinput.
        value: Value maintained by this vaultentryinput.
        description: Operator-facing purpose or context for the resource.
        username: Username maintained by this vaultentryinput.
        resource_name: Resource name maintained by this vaultentryinput.
        source_type: Source type maintained by this vaultentryinput.
        source_endpoint: Source endpoint maintained by this vaultentryinput.
        uris: Uris maintained by this vaultentryinput.
        imported_at: UTC timestamp associated with imported.
    """
    key: str
    secret_type: str
    value: str
    description: str = ""
    username: str = ""
    resource_name: str = ""
    source_type: str = "manual"
    source_endpoint: str = ""
    uris: tuple[str, ...] = ()
    imported_at: datetime | None = None


def vault_scope_identity(vault: Vault) -> str:
    """Return a stable identity that does not survive SQLite primary-key reuse.

    Args:
        vault: Vault consumed by vault scope identity.
    """
    created_at = vault.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    normalized_created_at = created_at.astimezone(timezone.utc).isoformat(timespec="microseconds")
    payload = f"{vault.id}\0{normalized_created_at}\0{vault.created_by}"
    return sha256(payload.encode("utf-8")).hexdigest()


def normalize_vault_key(value: str) -> str:
    """Normalize vault key.

    Args:
        value: Candidate value consumed by normalize vault key.


    Returns:
        The normalize vault key result.

    Raises:
        ValueError: If an input value is invalid.
    """
    key = value.strip().lower()
    if not VAULT_KEY_PATTERN.fullmatch(key):
        raise ValueError(
            "Vault keys must use lowercase dotted segments containing letters, numbers, or underscores."
        )
    if len(key) > 180:
        raise ValueError("Vault keys must be 180 characters or fewer.")
    return key


def vault_marker_name(value: str) -> str:
    """Return vault marker name.

    Args:
        value: Candidate value consumed by vault marker name.


    Raises:
        ValueError: If an input value is invalid.
    """
    marker = re.sub(r"[^a-z0-9_]+", "_", value.strip().lower()).strip("_")
    if not marker:
        raise ValueError("Vault names must contain at least one letter or number.")
    if marker[0].isdigit():
        marker = f"vault_{marker}"
    return marker


def normalize_vault_uris(values: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    """Normalize vault uris.

    Args:
        values: Candidate values consumed by normalize vault uris.


    Returns:
        The normalize vault uris result.

    Raises:
        ValueError: If an input value is invalid.
    """
    if len(values) > VAULT_URI_LIMIT:
        raise ValueError("Vault entries support at most 9 URIs.")
    normalized: list[str] = []
    for raw_value in values:
        value = str(raw_value or "").strip()
        if not value:
            continue
        if len(value) > 2048 or any(character.isspace() for character in value):
            raise ValueError("Vault URIs must be 2048 characters or fewer and contain no whitespace.")
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        if scheme not in VAULT_URI_SCHEMES:
            raise ValueError("Vault URIs must use http, https, ssh, or sftp.")
        if not parsed.hostname:
            raise ValueError("Vault URIs must include a hostname.")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("Vault URIs must not contain credentials; use the entry username and password.")
        try:
            _ = parsed.port
        except ValueError as exc:
            raise ValueError("Vault URI ports must be valid numbers.") from exc
        normalized_value = urlunsplit((scheme, parsed.netloc, parsed.path, parsed.query, parsed.fragment))
        if normalized_value in normalized:
            raise ValueError("Vault URIs must be unique within an entry.")
        normalized.append(normalized_value)
    return tuple(normalized)


def vault_entry_uris(entry: VaultEntry) -> tuple[str, ...]:
    """Return vault entry uris.

    Args:
        entry: Entry consumed by vault entry uris.
    """
    try:
        values = json.loads(entry.uris_json or "[]")
    except json.JSONDecodeError:
        return ()
    if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
        return ()
    try:
        return normalize_vault_uris(values)
    except ValueError:
        return ()


def parse_vault_uris_json(value: str) -> tuple[str, ...]:
    """Parse vault uris json.

    Args:
        value: Candidate value consumed by parse vault uris JSON.


    Returns:
        The parsed vault uris json.

    Raises:
        ValueError: If an input value is invalid.
    """
    try:
        values = json.loads(value or "[]")
    except json.JSONDecodeError as exc:
        raise ValueError("Vault URIs must be a valid list.") from exc
    if not isinstance(values, list) or any(not isinstance(item, str) for item in values):
        raise ValueError("Vault URIs must be a list of strings.")
    return normalize_vault_uris(values)


def validate_entry_input(entry: VaultEntryInput, *, require_value: bool = True) -> VaultEntryInput:
    """Validate entry input.

    Args:
        entry: Candidate entry to validate.
        require_value: Whether require value applies to the operation.


    Returns:
        The validate entry input result.

    Raises:
        ValueError: If an input value is invalid.
    """
    key = normalize_vault_key(entry.key)
    secret_type = entry.secret_type.strip().lower()
    if secret_type not in VAULT_SECRET_TYPES:
        raise ValueError("Vault entries are limited to VCF passwords and ESX passwords.")
    source_type = entry.source_type.strip().lower() or "manual"
    if source_type not in VAULT_SOURCE_TYPES:
        raise ValueError("The vault entry source is not supported.")
    if require_value and not entry.value:
        raise ValueError("Enter a password.")
    return VaultEntryInput(
        key=key,
        secret_type=secret_type,
        value=entry.value,
        description=entry.description.strip(),
        username=entry.username.strip(),
        resource_name=entry.resource_name.strip(),
        source_type=source_type,
        source_endpoint=entry.source_endpoint.strip(),
        uris=normalize_vault_uris(entry.uris),
        imported_at=entry.imported_at,
    )


def list_vaults(db: Session) -> list[Vault]:
    """Return vaults.

    Args:
        db: Active database session.
    """
    return list(
        db.execute(
            select(Vault).options(selectinload(Vault.entries)).order_by(Vault.name)
        )
        .scalars()
        .all()
    )


def create_vault(db: Session, *, name: str, description: str, actor: str) -> Vault:
    """Create vault.

    Args:
        db: Active database session.
        name: Name of the target object.
        description: Human-readable description of the resource.
        actor: Authenticated identity attributed to the audit record.

    Returns:
        The created vault.

    Raises:
        ValueError: If an input value is invalid.
    """
    normalized_name = name.strip()
    if not normalized_name:
        raise ValueError("Enter a vault name.")
    vault_marker_name(normalized_name)
    vault = Vault(
        name=normalized_name,
        description=description.strip(),
        created_by=actor,
        created_at=utcnow(),
        updated_at=utcnow(),
    )
    db.add(vault)
    db.flush()
    return vault


def upsert_vault_entry(
    db: Session,
    *,
    vault: Vault,
    entry: VaultEntryInput,
    actor: str,
) -> tuple[VaultEntry, bool]:
    """Return upsert vault entry.

    Args:
        db: Active database session.
        vault: Vault supplied by the caller.
        entry: Vault, configuration, or collection entry to process.
        actor: Authenticated identity attributed to the audit record.
    """
    normalized = validate_entry_input(entry)
    current = db.execute(
        select(VaultEntry).where(
            VaultEntry.vault_id == vault.id,
            VaultEntry.key == normalized.key,
        )
    ).scalar_one_or_none()
    created = current is None
    if current is None:
        current = VaultEntry(
            vault_id=vault.id,
            key=normalized.key,
            secret_type=normalized.secret_type,
            encrypted_value=encrypt_secret(normalized.value),
            created_by=actor,
            created_at=utcnow(),
            updated_at=utcnow(),
        )
        db.add(current)
    else:
        current.encrypted_value = encrypt_secret(normalized.value)
        current.updated_at = utcnow()
    current.description = normalized.description
    current.secret_type = normalized.secret_type
    current.username = normalized.username
    current.resource_name = normalized.resource_name
    current.source_type = normalized.source_type
    current.source_endpoint = normalized.source_endpoint
    current.uris_json = json.dumps(normalized.uris)
    current.imported_at = normalized.imported_at
    db.flush()
    return current, created


def update_vault_entry(
    entry: VaultEntry,
    *,
    key: str,
    secret_type: str,
    value: str,
    username: str,
    resource_name: str,
    description: str,
    uris: tuple[str, ...],
) -> None:
    """Update vault entry.

    Args:
        entry: Vault, configuration, or collection entry to process.
        key: Stable setting, vault, or mapping key.
        secret_type: Secret type supplied by the caller.
        value: Value to process.
        username: Account name used for authentication or lookup.
        resource_name: Resource name supplied by the caller.
        description: Human-readable description of the resource.
        uris: Uris supplied by the caller.
    """
    normalized = validate_entry_input(
        VaultEntryInput(
            key=key,
            secret_type=secret_type,
            value=value,
            description=description,
            username=username,
            resource_name=resource_name,
            source_type=entry.source_type,
            source_endpoint=entry.source_endpoint,
            uris=uris,
            imported_at=entry.imported_at,
        ),
        require_value=False,
    )
    entry.key = normalized.key
    entry.description = normalized.description
    entry.secret_type = normalized.secret_type
    entry.username = normalized.username
    entry.resource_name = normalized.resource_name
    entry.uris_json = json.dumps(normalized.uris)
    if normalized.value:
        entry.encrypted_value = encrypt_secret(normalized.value)
    entry.updated_at = utcnow()


def decrypted_vault_values(db: Session, vault_id: int) -> dict[str, str]:
    """Return decrypted vault values.

    Args:
        db: Active database session.
        vault_id: Identifier of the vault.
    """
    entries = db.execute(
        select(VaultEntry).where(VaultEntry.vault_id == vault_id).order_by(VaultEntry.key)
    ).scalars()
    return {entry.key: decrypt_secret(entry.encrypted_value) for entry in entries}


def _kickstart_vault_marker_sources(
    db: Session,
) -> tuple[dict[str, tuple[VaultEntry, str, str, str]], set[str]]:
    """Return kickstart vault marker sources.

    Args:
        db: Active database session.
    """
    available: dict[str, tuple[VaultEntry, str, str, str]] = {}
    ambiguous: set[str] = set()
    for vault in list_vaults(db):
        vault_name = vault_marker_name(vault.name)
        for entry in vault.entries:
            prefix = f"vault.{vault_name}.{entry.key}"
            candidates = [
                (f"{prefix}.username", (entry, "username", "", f"Username from {vault.name} / {entry.key}")),
                (f"{prefix}.password", (entry, "password", "", f"Password from {vault.name} / {entry.key}")),
                *[
                    (f"{prefix}.uri{index}", (entry, "uri", uri, f"URI {index} from {vault.name} / {entry.key}"))
                    for index, uri in enumerate(vault_entry_uris(entry), start=1)
                ],
            ]
            for marker, source in candidates:
                if marker in available:
                    ambiguous.add(marker)
                else:
                    available[marker] = source
    return available, ambiguous


def validate_kickstart_vault_markers(db: Session, marker_names: set[str]) -> None:
    """Validate kickstart vault markers.

    Args:
        db: Active database session.
        marker_names: Marker names supplied by the caller.

    Raises:
        ValueError: If an input value is invalid.
    """
    requested = {name for name in marker_names if name.startswith("vault.")}
    if not requested:
        return
    available, ambiguous = _kickstart_vault_marker_sources(db)
    ambiguous_requested = sorted(requested & ambiguous)
    if ambiguous_requested:
        raise ValueError(f"Kickstart vault marker {ambiguous_requested[0]} is ambiguous.")
    missing = sorted(requested - available.keys())
    if missing:
        raise ValueError(f"Kickstart vault marker {missing[0]} is not available.")


def kickstart_vault_marker_catalog(db: Session) -> list[list[str]]:
    """Return kickstart vault marker catalog.

    Args:
        db: Active database session.
    """
    available, ambiguous = _kickstart_vault_marker_sources(db)
    return [
        [marker, source[3]]
        for marker, source in sorted(available.items())
        if marker not in ambiguous
    ]


def kickstart_vault_values_for_markers(db: Session, marker_names: set[str]) -> dict[str, str]:
    """Return kickstart vault values for markers.

    Args:
        db: Active database session.
        marker_names: Marker names supplied by the caller.
    """
    requested = {name for name in marker_names if name.startswith("vault.")}
    validate_kickstart_vault_markers(db, requested)
    available, _ambiguous = _kickstart_vault_marker_sources(db)
    values: dict[str, str] = {}
    for marker in requested:
        entry, subkey, uri, _detail = available[marker]
        if subkey == "password":
            value = decrypt_secret(entry.encrypted_value)
        elif subkey == "username":
            value = entry.username or ""
        else:
            value = uri
        values[marker.removeprefix("vault.")] = value
    return values


def vault_entry_metadata(entry: VaultEntry) -> dict[str, object]:
    """Return vault entry metadata.

    Args:
        entry: Entry consumed by vault entry metadata.
    """
    return {
        "id": entry.id,
        "key": entry.key,
        "description": entry.description,
        "secret_type": entry.secret_type,
        "secret_type_label": "VCF password" if entry.secret_type == "vcf_password" else "ESX password",
        "username": entry.username,
        "resource_name": entry.resource_name,
        "source_type": entry.source_type,
        "source_endpoint": entry.source_endpoint,
        "uris": list(vault_entry_uris(entry)),
        "has_value": bool(entry.encrypted_value),
        "updated_at": entry.updated_at.isoformat() if entry.updated_at else "",
    }


def redact_secret_values(text: str, values: dict[str, str] | list[str]) -> str:
    """Return redact secret values.

    Args:
        text: Text content consumed by the operation.
        values: Candidate values consumed by redact secret values.
    """
    result = text
    candidates = values.values() if isinstance(values, dict) else values
    for value in sorted({item for item in candidates if item}, key=len, reverse=True):
        result = result.replace(value, "[redacted]")
    return result
