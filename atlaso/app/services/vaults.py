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
    """Return a stable identity that does not survive SQLite primary-key reuse."""
    created_at = vault.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    normalized_created_at = created_at.astimezone(timezone.utc).isoformat(timespec="microseconds")
    payload = f"{vault.id}\0{normalized_created_at}\0{vault.created_by}"
    return sha256(payload.encode("utf-8")).hexdigest()


def normalize_vault_key(value: str) -> str:
    key = value.strip().lower()
    if not VAULT_KEY_PATTERN.fullmatch(key):
        raise ValueError(
            "Vault keys must use lowercase dotted segments containing letters, numbers, or underscores."
        )
    if len(key) > 180:
        raise ValueError("Vault keys must be 180 characters or fewer.")
    return key


def vault_marker_name(value: str) -> str:
    marker = re.sub(r"[^a-z0-9_]+", "_", value.strip().lower()).strip("_")
    if not marker:
        raise ValueError("Vault names must contain at least one letter or number.")
    if marker[0].isdigit():
        marker = f"vault_{marker}"
    return marker


def normalize_vault_uris(values: list[str] | tuple[str, ...]) -> tuple[str, ...]:
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
            parsed.port
        except ValueError as exc:
            raise ValueError("Vault URI ports must be valid numbers.") from exc
        normalized_value = urlunsplit((scheme, parsed.netloc, parsed.path, parsed.query, parsed.fragment))
        if normalized_value in normalized:
            raise ValueError("Vault URIs must be unique within an entry.")
        normalized.append(normalized_value)
    return tuple(normalized)


def vault_entry_uris(entry: VaultEntry) -> tuple[str, ...]:
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
    try:
        values = json.loads(value or "[]")
    except json.JSONDecodeError as exc:
        raise ValueError("Vault URIs must be a valid list.") from exc
    if not isinstance(values, list) or any(not isinstance(item, str) for item in values):
        raise ValueError("Vault URIs must be a list of strings.")
    return normalize_vault_uris(values)


def validate_entry_input(entry: VaultEntryInput, *, require_value: bool = True) -> VaultEntryInput:
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
    return list(
        db.execute(
            select(Vault).options(selectinload(Vault.entries)).order_by(Vault.name)
        )
        .scalars()
        .all()
    )


def create_vault(db: Session, *, name: str, description: str, actor: str) -> Vault:
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
    entries = db.execute(
        select(VaultEntry).where(VaultEntry.vault_id == vault_id).order_by(VaultEntry.key)
    ).scalars()
    return {entry.key: decrypt_secret(entry.encrypted_value) for entry in entries}


def kickstart_vault_values(db: Session, vault_id: int) -> dict[str, str]:
    vault = db.get(Vault, vault_id)
    if vault is None:
        raise ValueError("The selected vault does not exist.")
    prefix = vault_marker_name(vault.name)
    entries = db.execute(
        select(VaultEntry).where(VaultEntry.vault_id == vault_id).order_by(VaultEntry.key)
    ).scalars()
    values: dict[str, str] = {}
    for entry in entries:
        values[f"{prefix}.{entry.key}.username"] = entry.username or ""
        values[f"{prefix}.{entry.key}.password"] = decrypt_secret(entry.encrypted_value)
        for index, uri in enumerate(vault_entry_uris(entry), start=1):
            values[f"{prefix}.{entry.key}.uri{index}"] = uri
    return values


def vault_entry_metadata(entry: VaultEntry) -> dict[str, object]:
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
    result = text
    candidates = values.values() if isinstance(values, dict) else values
    for value in sorted({item for item in candidates if item}, key=len, reverse=True):
        result = result.replace(value, "[redacted]")
    return result
