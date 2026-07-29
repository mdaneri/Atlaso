from __future__ import annotations

import json
from ipaddress import ip_address
from uuid import UUID, uuid4

from atlaso.app.models import KmsClient, KmsKey, KmsSettings
from atlaso.app.services.ca import safe_certificate_name
from atlaso.app.services.dnsmasq import split_addresses, split_interfaces


KMS_BACKENDS = ["atlaso-kmip"]
KMS_CLIENT_ROLES = ["admin", "service", "readonly"]
KMS_KEY_ALGORITHMS = ["AES"]
KMS_KEY_STATES = ["pre-active", "active"]
KMS_DEFAULT_OPERATIONS = [
    "locate",
    "get",
    "create",
    "activate",
    "get-attributes",
    "get-attribute-list",
    "query",
    "discover-versions",
]
KMS_DEFAULT_DATABASE_PATH = "/var/lib/atlaso/kmip/store.db"
KMS_DEFAULT_KEK_PATH = "/var/lib/atlaso/kmip/kek.json"
KMS_DEFAULT_CONFIG_PATH = "/etc/atlaso/kmip/server.json"
KMS_STAGED_CONFIG_PATH = "/var/lib/atlaso/apply/kms/server.json"
KMS_LOG_PATH = "/var/log/atlaso/kmip/server.log"
KMS_SERVER_CERT_BASE = "/etc/atlaso/kmip/certs"
KMS_CLIENT_CERT_BASE = "/etc/atlaso/kmip/clients/certs"
KMS_DNS_RECORD_DESCRIPTION = "Atlaso app-owned KMS/KMIP endpoint record."


def split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    items: list[str] = []
    for item in value.replace("\n", ",").split(","):
        normalized = item.strip()
        if normalized and normalized not in items:
            items.append(normalized)
    return items


def join_csv(values: list[str]) -> str:
    return ",".join(split_csv(",".join(values)))


def ensure_kms_provider_id(settings: KmsSettings) -> bool:
    try:
        normalized = str(UUID(settings.provider_id))
    except (AttributeError, TypeError, ValueError):
        normalized = str(uuid4())
    changed = settings.provider_id != normalized
    settings.provider_id = normalized
    return changed


def kms_client_to_dict(client: KmsClient) -> dict:
    return {
        "id": client.id,
        "name": client.name,
        "certificate_subject": client.certificate_subject,
        "certificate_fingerprint": client.certificate_fingerprint,
        "role": client.role,
        "allowed_operations": client.allowed_operations,
        "enabled": client.enabled,
        "description": client.description or "",
    }


def kms_key_to_dict(key: KmsKey) -> dict:
    return {
        "id": key.id,
        "name": key.name,
        "algorithm": key.algorithm,
        "length": key.length,
        "usage": key.usage,
        "state": key.state,
        "owner_client_id": key.owner_client_id or "",
        "owner_client_name": key.owner_client.name if key.owner_client else "Unassigned",
        "exportable": key.exportable,
        "enabled": key.enabled,
        "description": key.description or "",
    }


def render_kms_config(
    *,
    settings: KmsSettings,
    clients: list[KmsClient],
    keys: list[KmsKey],
) -> str:
    ensure_kms_provider_id(settings)
    certificate_name = safe_certificate_name(settings.server_certificate or settings.hostname)
    listen_addresses = split_addresses(settings.listen_address)
    host = listen_addresses[0] if settings.enabled and listen_addresses else "127.0.0.1"
    enabled_clients = [client for client in clients if client.enabled]
    provider = {
        "id": settings.provider_id,
        "name": settings.hostname,
        "client_fingerprints": sorted(
            {
                client.certificate_fingerprint.casefold()
                for client in enabled_clients
                if client.certificate_fingerprint
            }
        ),
        "client_certificate_paths": [
            f"{KMS_CLIENT_CERT_BASE}/{safe_certificate_name(client.name)}.crt"
            for client in enabled_clients
            if not client.certificate_fingerprint
        ],
    }
    document = {
        "schema_version": 1,
        "enabled": bool(settings.enabled),
        "listen": {"host": host, "port": settings.port},
        "tls": {
            "certificate_path": f"{KMS_SERVER_CERT_BASE}/{certificate_name}.crt",
            "private_key_path": f"{KMS_SERVER_CERT_BASE}/{certificate_name}.key",
            "ca_path": settings.ca_certificate_path,
        },
        "store": {
            "database_path": KMS_DEFAULT_DATABASE_PATH,
            "kek_path": KMS_DEFAULT_KEK_PATH,
        },
        "limits": {
            "max_request_bytes": 1_048_576,
            "max_connections": 32,
            "idle_timeout_seconds": 30,
            "max_requests_per_connection": 128,
        },
        "providers": [provider] if enabled_clients else [],
        "interop_trace_path": "",
    }
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def validate_kms_state(
    *,
    settings: KmsSettings,
    clients: list[KmsClient],
    keys: list[KmsKey],
) -> list[str]:
    errors: list[str] = []
    if settings.backend not in KMS_BACKENDS:
        errors.append("KMS backend must be atlaso-kmip.")
    if settings.enabled:
        if not split_interfaces(settings.listen_interface):
            errors.append("KMS listen interface is required.")
        listen_addresses = split_addresses(settings.listen_address)
        if not listen_addresses:
            errors.append("KMS listen address is required.")
        for address in listen_addresses:
            try:
                ip_address(address)
            except ValueError:
                errors.append(f"KMS listen address {address} must be a valid IPv4 or IPv6 address.")
    if settings.port < 1 or settings.port > 65535:
        errors.append("KMS port must be between 1 and 65535.")
    if not settings.hostname.strip():
        errors.append("KMS hostname is required.")
    if settings.require_client_cert and not settings.ca_certificate_path.strip():
        errors.append("KMS client certificate validation requires a CA certificate path.")
    if not settings.config_path.strip():
        errors.append("KMS config path is required.")
    if not settings.database_path.strip():
        errors.append("KMS database path is required.")

    client_ids = {client.id for client in clients}
    seen_fingerprints: set[str] = set()
    for client in clients:
        if not client.name.strip():
            errors.append("KMS client name is required.")
        if client.role not in KMS_CLIENT_ROLES:
            errors.append(f"KMS client {client.name or client.id} has an unsupported role.")
        if not client.certificate_subject.strip():
            errors.append(f"KMS client {client.name or client.id} requires a certificate subject.")
        if not split_csv(client.allowed_operations):
            errors.append(f"KMS client {client.name or client.id} needs at least one allowed operation.")
        unsupported_operations = sorted(
            set(split_csv(client.allowed_operations)) - set(KMS_DEFAULT_OPERATIONS)
        )
        if unsupported_operations:
            errors.append(
                f"KMS client {client.name or client.id} operations are outside the bounded contract: "
                f"{', '.join(unsupported_operations)}."
            )
        fingerprint = client.certificate_fingerprint.casefold()
        if fingerprint:
            if len(fingerprint) != 64 or any(character not in "0123456789abcdef" for character in fingerprint):
                errors.append(f"KMS client {client.name or client.id} fingerprint must be a SHA-256 digest.")
            elif fingerprint in seen_fingerprints:
                errors.append(f"KMS client {client.name or client.id} fingerprint is already trusted.")
            else:
                seen_fingerprints.add(fingerprint)

    for key in keys:
        label = key.name or str(key.id)
        if not key.name.strip():
            errors.append("KMS key name is required.")
        if key.algorithm not in KMS_KEY_ALGORITHMS:
            errors.append(f"KMS key {label} has an unsupported algorithm.")
        if key.algorithm == "AES" and key.length != 256:
            errors.append(f"KMS key {label} AES length must be 256 bits.")
        if key.state not in KMS_KEY_STATES:
            errors.append(f"KMS key {label} has an unsupported lifecycle state.")
        if key.owner_client_id is not None and key.owner_client_id not in client_ids:
            errors.append(f"KMS key {label} references a missing client.")
    return errors
