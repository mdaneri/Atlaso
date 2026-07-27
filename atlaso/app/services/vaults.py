from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from atlaso.app.models import Vault, VaultEntry, utcnow
from atlaso.app.secrets import decrypt_secret, encrypt_secret


VAULT_KEY_PATTERN = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*$")
VAULT_SECRET_TYPES = {"vcf_password", "esx_password"}
VAULT_SOURCE_TYPES = {"manual", "sddc_manager", "vcf_installer"}


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
    imported_at: datetime | None = None


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
            imported_at=entry.imported_at,
        ),
        require_value=False,
    )
    entry.key = normalized.key
    entry.description = normalized.description
    entry.secret_type = normalized.secret_type
    entry.username = normalized.username
    entry.resource_name = normalized.resource_name
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
        "has_value": bool(entry.encrypted_value),
        "updated_at": entry.updated_at.isoformat() if entry.updated_at else "",
    }


def redact_secret_values(text: str, values: dict[str, str] | list[str]) -> str:
    result = text
    candidates = values.values() if isinstance(values, dict) else values
    for value in sorted({item for item in candidates if item}, key=len, reverse=True):
        result = result.replace(value, "[redacted]")
    return result
