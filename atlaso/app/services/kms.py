from __future__ import annotations

from ipaddress import ip_address

from atlaso.app.models import KmsClient, KmsKey, KmsSettings
from atlaso.app.services.ca import safe_certificate_name
from atlaso.app.services.dnsmasq import split_addresses, split_interfaces


KMS_BACKENDS = ["pykmip"]
KMS_CLIENT_ROLES = ["admin", "service", "readonly"]
KMS_KEY_ALGORITHMS = ["AES", "RSA", "ECDSA"]
KMS_KEY_STATES = ["pre-active", "active", "deactivated", "compromised", "destroyed"]
KMS_DEFAULT_OPERATIONS = ["locate", "get", "register", "create"]
KMS_DEFAULT_DATABASE_PATH = "/var/lib/atlaso/kms/pykmip.db"
KMS_DEFAULT_CONFIG_PATH = "/etc/atlaso/kms/pykmip.conf"
KMS_STAGED_CONFIG_PATH = "/var/lib/atlaso/apply/kms/pykmip.conf"
KMS_POLICY_PATH = "/etc/atlaso/kms/policies"
KMS_LOG_PATH = "/var/log/atlaso/kms/server.log"
KMS_SERVER_CERT_BASE = "/etc/atlaso/kms/certs"
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


def kms_client_to_dict(client: KmsClient) -> dict:
    return {
        "id": client.id,
        "name": client.name,
        "certificate_subject": client.certificate_subject,
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
    certificate_name = safe_certificate_name(settings.server_certificate or settings.hostname)
    listen_addresses = split_addresses(settings.listen_address)
    host = listen_addresses[0] if settings.enabled and listen_addresses else "127.0.0.1"
    lines = [
        "# Managed by Atlaso. Local changes may be overwritten.",
        f"# Atlaso KMS enabled: {str(bool(settings.enabled)).lower()}",
        f"# Atlaso KMS endpoint hostname: {settings.hostname}",
        f"# Atlaso KMS listen interfaces: {', '.join(split_interfaces(settings.listen_interface)) or 'none'}",
        f"# Atlaso KMS listen addresses: {', '.join(listen_addresses) or 'none'}",
        "# PyKMIP accepts one bind host; Atlaso uses the first selected listen address.",
        "# Backend: PyKMIP lab KMIP server desired state.",
        "[server]",
        f"hostname={host}",
        f"port={settings.port}",
        f"certificate_path={KMS_SERVER_CERT_BASE}/{certificate_name}.crt",
        f"key_path={KMS_SERVER_CERT_BASE}/{certificate_name}.key",
        f"ca_path={settings.ca_certificate_path}",
        "auth_suite=TLS1.2",
        f"policy_path={KMS_POLICY_PATH}",
        f"enable_tls_client_auth={str(bool(settings.require_client_cert))}",
        "logging_level=INFO",
        f"database_path={settings.database_path}",
        "",
        "# Atlaso policy intent:",
        f"# allow_register={'yes' if settings.allow_register else 'no'}",
        f"# allow_destroy={'yes' if settings.allow_destroy else 'no'}",
        "",
        "# Atlaso KMIP clients:",
    ]
    for client in clients:
        if not client.enabled:
            continue
        lines.extend(
            [
                f"# client={client.name}",
                f"#   subject={client.certificate_subject}",
                f"#   role={client.role}",
                f"#   operations={join_csv(split_csv(client.allowed_operations))}",
            ]
        )
    lines.extend(["", "# Atlaso staged KMS keys:"])
    for key in keys:
        if not key.enabled:
            continue
        owner = key.owner_client.name if key.owner_client else "unassigned"
        lines.extend(
            [
                f"# key={key.name}",
                f"#   algorithm={key.algorithm}",
                f"#   length={key.length}",
                f"#   usage={join_csv(split_csv(key.usage))}",
                f"#   state={key.state}",
                f"#   owner={owner}",
                f"#   exportable={'yes' if key.exportable else 'no'}",
            ]
        )
    return "\n".join(lines).strip() + "\n"


def validate_kms_state(
    *,
    settings: KmsSettings,
    clients: list[KmsClient],
    keys: list[KmsKey],
) -> list[str]:
    errors: list[str] = []
    if settings.backend not in KMS_BACKENDS:
        errors.append("KMS backend must be pykmip for the MVP scaffold.")
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
    for client in clients:
        if not client.name.strip():
            errors.append("KMS client name is required.")
        if client.role not in KMS_CLIENT_ROLES:
            errors.append(f"KMS client {client.name or client.id} has an unsupported role.")
        if not client.certificate_subject.strip():
            errors.append(f"KMS client {client.name or client.id} requires a certificate subject.")
        if not split_csv(client.allowed_operations):
            errors.append(f"KMS client {client.name or client.id} needs at least one allowed operation.")

    for key in keys:
        label = key.name or str(key.id)
        if not key.name.strip():
            errors.append("KMS key name is required.")
        if key.algorithm not in KMS_KEY_ALGORITHMS:
            errors.append(f"KMS key {label} has an unsupported algorithm.")
        if key.algorithm == "AES" and key.length not in {128, 192, 256}:
            errors.append(f"KMS key {label} AES length must be 128, 192, or 256 bits.")
        if key.algorithm == "RSA" and key.length < 2048:
            errors.append(f"KMS key {label} RSA length must be at least 2048 bits.")
        if key.algorithm == "ECDSA" and key.length not in {256, 384, 521}:
            errors.append(f"KMS key {label} ECDSA length must be 256, 384, or 521.")
        if key.state not in KMS_KEY_STATES:
            errors.append(f"KMS key {label} has an unsupported lifecycle state.")
        if key.owner_client_id is not None and key.owner_client_id not in client_ids:
            errors.append(f"KMS key {label} references a missing client.")
    return errors
