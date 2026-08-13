"""Define the fixed internal KMS apply and runtime paths."""

from __future__ import annotations

KMS_DEFAULT_DATABASE_PATH = "/var/lib/atlaso/kmip/store.db"
KMS_DEFAULT_KEK_PATH = "/var/lib/atlaso/kmip/kek.json"
KMS_DEFAULT_CONFIG_PATH = "/etc/atlaso/kmip/server.json"
KMS_STAGED_CONFIG_PATH = "/var/lib/atlaso/apply/kms/server.json"
KMS_STAGED_CLIENT_TRUST_PATH = "/var/lib/atlaso/apply/kms/client-trust.pem"
KMS_LOG_PATH = "/var/log/atlaso/kmip/server.log"
KMS_SERVER_CERT_BASE = "/etc/atlaso/kmip/certs"
KMS_CLIENT_TRUST_PATH = "/etc/atlaso/kmip/client-trust.pem"
KMS_DNS_RECORD_DESCRIPTION = "Atlaso app-owned KMS/KMIP endpoint record."


def split_csv(value: str | None) -> list[str]:
    """Return unique non-empty comma-separated values.

    Args:
        value: Comma- or newline-separated values.

    Returns:
        Values in their first-seen order.
    """
    if not value:
        return []
    items: list[str] = []
    for item in value.replace("\n", ",").split(","):
        normalized = item.strip()
        if normalized and normalized not in items:
            items.append(normalized)
    return items


def join_csv(values: list[str]) -> str:
    """Return unique values as a comma-separated string.

    Args:
        values: Values to normalize.

    Returns:
        Normalized comma-separated values.
    """
    return ",".join(split_csv(",".join(values)))
