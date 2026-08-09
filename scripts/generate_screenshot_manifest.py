"""Generate the checked-in screenshot manifest from reviewed Atlaso captures."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCREENSHOTS = ROOT / "docs" / "assets" / "screenshots"
MANIFEST = SCREENSHOTS / "manifest.json"
SOURCE_COMMIT = "0247c34bc85e+working-tree"
ATLASO_VERSION = "0.9.21"

CAPTURE_OVERRIDES = {
    "dhcp-ip-zone-wizard-services-desktop": {
        "source_commit": "1c7f6f653ffd+working-tree",
        "atlaso_version": "0.9.70",
        "capture_method": "edge-browser",
    },
    "dhcp-ip-zone-wizard-services-narrow": {
        "source_commit": "1c7f6f653ffd+working-tree",
        "atlaso_version": "0.9.70",
        "capture_method": "edge-browser",
    },
    "dns-domain-tools-desktop": {
        "source_commit": "1c7f6f653ffd+working-tree",
        "atlaso_version": "0.9.70",
        "capture_method": "edge-browser",
    },
    "dns-domain-tools-narrow": {
        "source_commit": "1c7f6f653ffd+working-tree",
        "atlaso_version": "0.9.70",
        "capture_method": "edge-browser",
    },
    "esxi-custom-variable-description-desktop": {
        "source_commit": "1c7f6f653ffd+working-tree",
        "atlaso_version": "0.9.70",
        "capture_method": "edge-browser",
    },
    "esxi-custom-variable-description-narrow": {
        "source_commit": "1c7f6f653ffd+working-tree",
        "atlaso_version": "0.9.70",
        "capture_method": "edge-browser",
    },
    "managed-ldap-group-members-desktop": {
        "source_commit": "1c7f6f653ffd+working-tree",
        "atlaso_version": "0.9.70",
        "capture_method": "edge-browser",
    },
    "managed-ldap-group-members-narrow": {
        "source_commit": "1c7f6f653ffd+working-tree",
        "atlaso_version": "0.9.70",
        "capture_method": "edge-browser",
    },
    "authentication-clean-desktop": {
        "source_commit": "fd88ffe+working-tree",
        "atlaso_version": "0.9.37",
        "capture_method": "codex-in-app-browser",
    },
    "authentication-clean-responsive": {
        "source_commit": "fd88ffe+working-tree",
        "atlaso_version": "0.9.37",
        "capture_method": "codex-in-app-browser",
    },
    "authentication-group-mappings-desktop": {
        "source_commit": "3083851+working-tree",
        "atlaso_version": "0.9.24",
        "capture_method": "playwright-chromium",
    },
    "authentication-group-mappings-responsive": {
        "source_commit": "3083851+working-tree",
        "atlaso_version": "0.9.24",
        "capture_method": "playwright-chromium",
    },
    "vaults-clean-desktop": {
        "source_commit": "341825a+working-tree",
        "atlaso_version": "0.9.38",
        "capture_method": "codex-in-app-browser",
    },
    "vaults-clean-responsive": {
        "source_commit": "341825a+working-tree",
        "atlaso_version": "0.9.38",
        "capture_method": "codex-in-app-browser",
    },
    "swagger-clean-responsive": {
        "source_commit": "15caa646452",
        "atlaso_version": "0.9.22",
    },
    "terminal-clean-desktop": {
        "source_commit": "d10ffe3e2959+installed-record",
        "atlaso_version": "0.9.26",
        "capture_method": "chrome-browser",
    },
    "terminal-clean-responsive": {
        "source_commit": "d10ffe3e2959+installed-record",
        "atlaso_version": "0.9.26",
        "capture_method": "chrome-browser",
    },
    "automation-vcf-schedule-wizard-desktop": {
        "source_commit": "3b10df0+working-tree",
        "atlaso_version": "0.9.80",
        "capture_method": "edge-browser",
    },
    "automation-vcf-schedule-wizard-responsive": {
        "source_commit": "3b10df0+working-tree",
        "atlaso_version": "0.9.80",
        "capture_method": "edge-browser",
    },
    "vcf-offline-depot-schedule-action-desktop": {
        "source_commit": "3b10df0+working-tree",
        "atlaso_version": "0.9.80",
        "capture_method": "edge-browser",
    },
}

DOCUMENTATION_PAGES = {
    "getting-started/index.md": ("login-", "services-"),
    "operate/dashboard.md": ("about-", "dashboard-"),
    "operate/audit-log.md": ("audit-log-",),
    "operate/logs.md": ("logs-",),
    "operate/monitor.md": ("monitor-",),
    "operate/appliance-apply.md": ("appliance-review-",),
    "operate/appliance-settings.md": ("settings-",),
    "operate/tasks.md": ("tasks-",),
    "operate/appliance-console.md": ("appliance-console-",),
    "operate/appliance-update.md": ("appliance-update-",),
    "operate/backup-restore.md": ("backup-restore-",),
    "operate/automation.md": ("automation-",),
    "operate/networking.md": ("physical-interfaces-", "routes-wan-", "vlan-interfaces-"),
    "operate/web-terminal.md": ("terminal-",),
    "services/dns.md": ("dns-",),
    "services/dhcp.md": ("dhcp-",),
    "services/firewall.md": ("firewall-",),
    "services/ntp.md": ("ntp-",),
    "services/esx-storage.md": ("esx-storage-",),
    "services/ipxe.md": ("esxi-pxe-", "esxi-custom-variable-"),
    "services/kms.md": ("kms-",),
    "services/local-users.md": ("users-",),
    "services/managed-ldap.md": ("ldap-", "managed-ldap-"),
    "services/oidc-provider.md": ("authentication-",),
    "services/certificate-authority.md": ("ca-public-", "ca-requests-", "certificate-authority-"),
    "services/vcf-backups.md": ("vcf-backups-",),
    "services/vcf-helper.md": ("vcf-helper-",),
    "services/vaults.md": ("vaults-",),
    "services/vcf-offline-depot.md": ("vcf-offline-depot-",),
    "services/vcf-private-registry.md": ("vcf-private-registry-",),
    "reference/api.md": ("swagger-",),
}

ROUTES = {
    "appliance-update": ("/appliance-update", "Appliance Update"),
    "audit-log": ("/audit-log", "Audit Events"),
    "authentication": ("/authentication", "Authentication"),
    "automation": ("/automation", "Automation"),
    "backup-restore": ("/backup-restore", "Backup and Restore"),
    "ca-public": ("/ca", "Public certificate portal"),
    "ca-requests": ("/requests", "Certificate requests"),
    "certificate-authority": ("/certificate-authority", "Certificate Authority"),
    "dashboard": ("/dashboard", "Dashboard"),
    "dhcp": ("/dhcp", "DHCP"),
    "dns": ("/dns", "DNS"),
    "esx-storage": ("/esx-storage", "ESX Storage"),
    "esxi-pxe": ("/network-boot", "Network Boot"),
    "firewall": ("/firewall", "Firewall"),
    "kms": ("/kms", "KMS and KMIP"),
    "ldap": ("/ldap", "Managed LDAP"),
    "login": ("/login", "Appliance sign-in"),
    "logs": ("/logs", "Logs"),
    "monitor": ("/monitor", "Monitor"),
    "ntp": ("/ntp", "NTP and NTS"),
    "physical-interfaces": ("/physical-interfaces", "Physical Interfaces"),
    "routes-wan": ("/routes-wan", "Routes and WAN Simulation"),
    "services": ("/services", "Services"),
    "settings": ("/settings", "Settings"),
    "swagger": ("/api/docs", "Swagger API reference"),
    "tasks": ("/tasks", "Tasks"),
    "terminal": ("/terminal", "Web terminal"),
    "users": ("/users", "Users"),
    "vcf-backups": ("/vcf-backups", "VCF Backups"),
    "vcf-helper": ("/vcf-helper", "VCF Helper"),
    "vaults": ("/vaults", "Vaults"),
    "vcf-offline-depot": ("/vcf-offline-depot", "VCF Offline Depot"),
    "vcf-private-registry": ("/vcf-private-registry", "VCF Private Registry"),
    "vlan-interfaces": ("/vlan-interfaces", "VLAN Interfaces"),
}

SPECIAL = {
    "about-modal-desktop": (
        "/dashboard",
        "about-modal",
        "Atlaso About dialog with the deployed version and build identity.",
        "Atlaso About dialog showing version 0.9.21, build identity, and Python version.",
    ),
    "appliance-console-applied": (
        "vmware-console",
        "applied",
        "VMware console after a successful appliance apply.",
        "Atlaso Photon appliance console showing management networking and service status.",
    ),
    "appliance-review-modal-desktop": (
        "/dashboard#appliance-apply-review",
        "review-modal",
        "Appliance change review with valid and invalid desired-state units.",
        "Review appliance changes dialog with selected valid units and one unit needing attention.",
    ),
    "automation-vcf-schedule-wizard-desktop": (
        "/automation#schedules",
        "vcf-schedule-wizard",
        "VCF Offline Depot profile scheduling in the shared Automation wizard.",
        "Atlaso Automation schedule wizard with VCF Offline Depot profile download selected at the desktop viewport.",
    ),
    "automation-vcf-schedule-wizard-responsive": (
        "/automation#schedules",
        "vcf-schedule-wizard",
        "VCF Offline Depot profile scheduling in the shared Automation wizard at the responsive viewport.",
        "Atlaso Automation schedule wizard with VCF Offline Depot profile download selected at the responsive viewport.",
    ),
    "authentication-clean-desktop": (
        "/openid-connect#oidc-provider",
        "oidc-provider-settings",
        "OIDC provider status and issuer information with service settings in the right column.",
        "Atlaso OpenID Connect provider status with right-column service settings.",
    ),
    "authentication-clean-responsive": (
        "/openid-connect#oidc-provider",
        "oidc-provider-settings",
        "OIDC provider settings with status and issuer information stacked at the responsive viewport.",
        "Atlaso OpenID Connect provider settings stacked with status and issuer information at a narrow viewport.",
    ),
    "authentication-group-mappings-desktop": (
        "/openid-connect#oidc-group-mappings",
        "group-mappings",
        "OIDC external group mappings in the desktop direct-edit collection.",
        "Atlaso OpenID Connect page showing the external group mapping grid at the desktop viewport.",
    ),
    "authentication-group-mappings-responsive": (
        "/openid-connect#oidc-group-mappings",
        "group-mappings",
        "OIDC external group mappings in the responsive direct-edit collection.",
        "Atlaso OpenID Connect page showing the external group mapping grid at the responsive viewport.",
    ),
    "dashboard-applied-desktop": (
        "/dashboard",
        "applied",
        "Dashboard after a successful DNS appliance apply.",
        "Atlaso dashboard after a successful DNS appliance apply.",
    ),
    "dashboard-apply-failed-desktop": (
        "/dashboard",
        "failed",
        "Dashboard reporting a failed appliance apply task.",
        "Atlaso dashboard with a failed appliance apply task in actionable exceptions.",
    ),
    "dashboard-pending-desktop": (
        "/dashboard",
        "pending",
        "Dashboard with valid pending changes and a unit needing attention.",
        "Atlaso dashboard showing pending appliance changes and a validation exception.",
    ),
    "dhcp-ip-zone-wizard-services-desktop": (
        "/dhcp#ip-zone-services",
        "ip-zone-services-wizard",
        "DHCP IP zone Services step with aligned service fields and a framed Lease time group.",
        "Atlaso DHCP IP zone wizard Services step showing a framed Lease time group and aligned Domain, DNS server, and NTP server fields.",
    ),
    "dhcp-ip-zone-wizard-services-narrow": (
        "/dhcp#ip-zone-services",
        "ip-zone-services-wizard",
        "DHCP IP zone Services step in the verified narrow viewport.",
        "Atlaso DHCP IP zone wizard Services step in a narrow viewport without page overflow.",
    ),
    "dns-domain-tools-desktop": (
        "/dns#managed-domain",
        "domain-tools",
        "DNS domain tools with the Enabled switch beside the tabs and compact generated authoritative records.",
        "Atlaso DNS managed domain showing Records, Import Hosts, and Import Zone File tabs with Domain enabled on the right and compact generated authoritative records above.",
    ),
    "dns-domain-tools-narrow": (
        "/dns#managed-domain",
        "domain-tools",
        "DNS domain tools in the verified narrow viewport.",
        "Atlaso DNS managed domain in a narrow viewport with Domain enabled aligned to the right of the tool tabs.",
    ),
    "esxi-custom-variable-description-desktop": (
        "/network-boot#custom-variables",
        "custom-variable-wizard",
        "ESXi custom variable wizard with Description on its own full-width row.",
        "Atlaso ESXi custom variable wizard showing full-width Description and Default value rows below Name.",
    ),
    "esxi-custom-variable-description-narrow": (
        "/network-boot#custom-variables",
        "custom-variable-wizard",
        "ESXi custom variable wizard in the verified narrow viewport.",
        "Atlaso ESXi custom variable wizard in a narrow viewport with full-width Description and Default value fields.",
    ),
    "dns-applied-desktop": (
        "/dns",
        "applied",
        "DNS desired state after a successful dnsmasq apply.",
        "Atlaso DNS page after the desired dnsmasq configuration was applied successfully.",
    ),
    "monitor-applied-desktop": (
        "/monitor",
        "applied",
        "Runtime monitoring after a successful appliance apply.",
        "Atlaso Monitor page showing live appliance runtime metrics after apply.",
    ),
    "managed-ldap-group-members-desktop": (
        "/ldap#groups",
        "group-members-wizard",
        "Managed LDAP group wizard populated with selectable users and nested groups.",
        "Atlaso Managed LDAP group wizard Members step showing selectable organization users and nested groups.",
    ),
    "managed-ldap-group-members-narrow": (
        "/ldap#groups",
        "group-members-wizard",
        "Managed LDAP group Members step in the verified narrow viewport.",
        "Atlaso Managed LDAP group wizard Members step in a narrow viewport with populated membership options.",
    ),
    "settings-pending-desktop": (
        "/settings",
        "pending",
        "Valid Appliance Settings waiting for global appliance apply.",
        "Atlaso Settings page with valid pending appliance identity changes.",
    ),
    "settings-preview-modal-desktop": (
        "/settings",
        "preview-modal",
        "Rendered Appliance Settings configuration preview.",
        "Atlaso configuration preview dialog with the rendered Appliance Settings JSON.",
    ),
    "settings-validation-error-desktop": (
        "/settings",
        "validation-error",
        "Appliance Settings validation error for an invalid FQDN.",
        "Atlaso Settings validation card explaining that the appliance FQDN is invalid.",
    ),
    "tasks-apply-failed-detail-desktop": (
        "/tasks",
        "failed-detail",
        "Failed appliance apply task with redacted operator detail.",
        "Atlaso task detail dialog for a failed appliance apply.",
    ),
    "tasks-apply-succeeded-detail-desktop": (
        "/tasks",
        "succeeded-detail",
        "Successful appliance apply task with verified dnsmasq output.",
        "Atlaso task detail dialog showing a successful DNS appliance apply.",
    ),
    "tasks-apply-succeeded-log-desktop": (
        "/tasks",
        "succeeded-log",
        "Successful appliance apply log with captured commands and audit events.",
        "Atlaso task log showing successful dnsmasq validation, apply, and reload.",
    ),
    "vcf-offline-depot-schedule-action-desktop": (
        "/vcf-offline-depot",
        "schedule-action",
        "VCF Offline Depot profile scheduling action with the disabled-profile reason.",
        "VCF Offline Depot profile row menu showing Schedule download disabled until the profile is enabled.",
    ),
    "terminal-clean-desktop": (
        "/terminal",
        "enabled-connected",
        "Web terminal connected to the verified Photon appliance in the desktop viewport.",
        "Atlaso Web terminal connected as the admin user in the desktop viewport.",
    ),
    "terminal-clean-responsive": (
        "/terminal",
        "enabled-connected",
        "Web terminal connected to the verified Photon appliance in the responsive viewport.",
        "Atlaso Web terminal connected as the admin user in the responsive viewport.",
    ),
}


def documentation_page(stem: str) -> str:
    """Return documentation page.

    Args:
        stem: Stem consumed by documentation page.


    Raises:
        ValueError: If an input value is invalid.
    """
    matches = [
        page
        for page, prefixes in DOCUMENTATION_PAGES.items()
        if any(stem.startswith(prefix) for prefix in prefixes)
    ]
    if len(matches) != 1:
        raise ValueError(f"{stem} must map to exactly one documentation page; found {matches}")
    return matches[0]


def clean_entry(stem: str) -> tuple[str, str, str, str]:
    """Return clean entry.

    Args:
        stem: Stem consumed by clean entry.
    """
    suffix = "-clean-responsive" if stem.endswith("-clean-responsive") else "-clean-desktop"
    slug = stem.removesuffix(suffix)
    route, title = ROUTES[slug]
    viewport_name = "responsive" if suffix.endswith("responsive") else "desktop"
    caption = f"{title} in the verified clean-appliance {viewport_name} state."
    alt = f"Atlaso {title} page in the clean-appliance {viewport_name} viewport."
    return route, "clean", caption, alt


def metadata(path: Path) -> dict[str, object]:
    """Return metadata.

    Args:
        path: Filesystem or URL path to read, validate, or update.
    """
    stem = path.stem
    if stem in SPECIAL:
        route, state, caption, alt = SPECIAL[stem]
    elif stem in {"login-desktop", "login-responsive"}:
        route, title = ROUTES["login"]
        state = "signed-out"
        viewport_name = "responsive" if stem.endswith("responsive") else "desktop"
        caption = f"{title} in the verified {viewport_name} viewport."
        alt = f"Atlaso sign-in page in the {viewport_name} viewport."
    else:
        route, state, caption, alt = clean_entry(stem)
    responsive = "responsive" in stem or "narrow" in stem
    entry = {
        "path": path.relative_to(ROOT / "docs").as_posix(),
        "route": route,
        "state": state,
        "viewport": "900x1200" if responsive else "1600x1000",
        "source_commit": SOURCE_COMMIT,
        "atlaso_version": ATLASO_VERSION,
        "caption": caption,
        "alt": alt,
        "capture_method": (
            "vmware-workstation-console"
            if stem == "appliance-console-applied"
            else "chrome-browser"
        ),
        "documentation_page": documentation_page(stem),
        "brand_variant": "console-light" if stem == "appliance-console-applied" else "light",
        "sensitive_data_reviewed": True,
    }
    entry.update(CAPTURE_OVERRIDES.get(stem, {}))
    return entry


def main() -> None:
    """Run the command-line entry point."""
    screenshots = [metadata(path) for path in sorted(SCREENSHOTS.glob("*.webp"))]
    MANIFEST.write_text(
        json.dumps({"schema_version": 1, "screenshots": screenshots}, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"Wrote {len(screenshots)} screenshot records to {MANIFEST.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
