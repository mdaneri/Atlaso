"""Implement service registry service behavior."""

import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from atlaso.app.models import Setting

APPLIANCE_APPLY_BASELINES_KEY = "appliance_apply.baselines.v1"


def dns_requires_authoritative_backend(db: Session, *, desired_authoritative: bool) -> bool:
    """Require the backend until a non-authoritative DNS configuration is applied.

    Args:
        db: Database session containing the applied DNS baseline.
        desired_authoritative: Whether the current desired DNS settings need the backend.
    """
    if desired_authoritative:
        return True
    setting = db.execute(
        select(Setting).where(Setting.key == APPLIANCE_APPLY_BASELINES_KEY)
    ).scalar_one_or_none()
    if setting is None or not setting.value:
        return False
    try:
        baselines = json.loads(setting.value)
    except json.JSONDecodeError:
        return False
    if not isinstance(baselines, dict):
        return False
    dns_baseline = baselines.get("dnsmasq")
    if not isinstance(dns_baseline, dict):
        return False
    applied_authoritative = dns_baseline.get("dns_authoritative")
    if isinstance(applied_authoritative, bool):
        return applied_authoritative
    preview = dns_baseline.get("config_preview")
    return isinstance(preview, str) and any(
        line.startswith("# atlaso-authoritative-config: auth-zone=")
        for line in preview.splitlines()
    )

SERVICE_STATE_DEFAULTS = [
    {"service": "routing", "display_name": "Routing", "running": False, "enabled": False, "health": "disabled"},
    {"service": "firewall", "display_name": "Firewall", "running": True, "enabled": True, "health": "healthy"},
    {"service": "dns", "display_name": "DNS", "running": False, "enabled": False, "health": "disabled"},
    {"service": "dhcp", "display_name": "DHCP", "running": False, "enabled": False, "health": "disabled"},
    {
        "service": "ntpd",
        "display_name": "NTP / NTS",
        "running": False,
        "enabled": False,
        "health": "disabled",
        "detail": "ntpd.service / UDP 123",
    },
    {
        "service": "kms",
        "display_name": "KMS / KMIP",
        "running": False,
        "enabled": False,
        "health": "planned",
        "detail": "Bounded experimental VCF 9.1 provider",
    },
    {
        "service": "repository",
        "display_name": "VCF Offline Depot",
        "running": False,
        "enabled": False,
        "health": "planned",
        "detail": "/mnt/atlaso-vcf-offline-depot",
    },
    {
        "service": "esxi-pxe",
        "display_name": "ESXi PXE",
        "running": False,
        "enabled": False,
        "health": "planned",
        "detail": "/var/lib/atlaso/pxe/http/esxi/ks",
    },
    {
        "service": "esx-storage",
        "display_name": "ESX Storage NFS",
        "running": False,
        "enabled": False,
        "health": "disabled",
        "detail": "NFS 3 / 4.1 · IPv4 / IPv6",
    },
    {
        "service": "vcf-private-registry",
        "display_name": "VCF Private Registry",
        "running": False,
        "enabled": False,
        "health": "planned",
        "detail": "Harbor / vcf-supervisor-services",
    },
    {
        "service": "vcf-backups",
        "display_name": "VCF Backup SFTP",
        "running": False,
        "enabled": False,
        "health": "disabled",
        "detail": "/mnt/atlaso-vcf-backups",
    },
    {"service": "ca", "display_name": "Certificate Authority", "running": False, "enabled": False, "health": "planned"},
    {
        "service": "ldap",
        "display_name": "Managed LDAP",
        "running": False,
        "enabled": False,
        "health": "disabled",
        "detail": "OpenLDAP / configurable LDAP and LDAPS listeners",
    },
    {"service": "auth", "display_name": "Authentication", "running": True, "enabled": True, "health": "healthy"},
]

SERVICE_STATE_IDS = frozenset(row["service"] for row in SERVICE_STATE_DEFAULTS)
RETIRED_SERVICE_IDS = frozenset({"chronyd"})
SERVICE_SYSTEMD_UNITS = {
    "ntpd": "ntpd.service",
    "kms": "atlaso-kmip.service",
    "ldap": "slapd.service",
    "esx-storage": "nfs-server.service",
}
