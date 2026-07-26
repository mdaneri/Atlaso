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
    "authentication-clean-desktop": {
        "source_commit": "3083851+working-tree",
        "atlaso_version": "0.9.24",
        "capture_method": "playwright-chromium",
    },
    "authentication-clean-responsive": {
        "source_commit": "3083851+working-tree",
        "atlaso_version": "0.9.24",
        "capture_method": "playwright-chromium",
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
    "swagger-clean-responsive": {
        "source_commit": "15caa646452",
        "atlaso_version": "0.9.22",
    },
}

DOCUMENTATION_PAGES = {
    "getting-started/index.md": ("login-", "services-"),
    "operate/dashboard.md": ("about-", "audit-log-", "dashboard-", "logs-", "monitor-"),
    "operate/appliance-apply.md": ("appliance-review-", "settings-", "tasks-"),
    "operate/appliance-console.md": ("appliance-console-",),
    "operate/appliance-update.md": ("appliance-update-", "backup-restore-", "vcf-backups-"),
    "operate/automation.md": ("automation-",),
    "operate/web-terminal.md": ("terminal-",),
    "services/dns.md": ("dhcp-", "dns-", "firewall-", "ntp-"),
    "services/esx-storage.md": ("esx-storage-",),
    "services/ipxe.md": ("esxi-pxe-",),
    "services/managed-ldap.md": ("ldap-",),
    "services/oidc-provider.md": ("authentication-",),
    "services/vcf-helper.md": (
        "kms-",
        "users-",
        "vcf-helper-",
        "vcf-offline-depot-",
        "vcf-private-registry-",
    ),
    "services/vcf-trust.md": ("ca-public-", "ca-requests-", "certificate-authority-"),
    "reference/full-technical-reference.md": (
        "physical-interfaces-",
        "routes-wan-",
        "swagger-",
        "vlan-interfaces-",
    ),
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
    "esxi-pxe": ("/esxi-pxe", "ESXi PXE"),
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
    "authentication-group-mappings-desktop": (
        "/authentication#oidc-group-mappings",
        "group-mappings",
        "OIDC external group mappings in the desktop direct-edit collection.",
        "Atlaso Authentication page showing the OIDC external group mapping grid at the desktop viewport.",
    ),
    "authentication-group-mappings-responsive": (
        "/authentication#oidc-group-mappings",
        "group-mappings",
        "OIDC external group mappings in the responsive direct-edit collection.",
        "Atlaso Authentication page showing the OIDC external group mapping grid at the responsive viewport.",
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
}


def documentation_page(stem: str) -> str:
    matches = [
        page
        for page, prefixes in DOCUMENTATION_PAGES.items()
        if any(stem.startswith(prefix) for prefix in prefixes)
    ]
    if len(matches) != 1:
        raise ValueError(f"{stem} must map to exactly one documentation page; found {matches}")
    return matches[0]


def clean_entry(stem: str) -> tuple[str, str, str, str]:
    suffix = "-clean-responsive" if stem.endswith("-clean-responsive") else "-clean-desktop"
    slug = stem.removesuffix(suffix)
    route, title = ROUTES[slug]
    viewport_name = "responsive" if suffix.endswith("responsive") else "desktop"
    caption = f"{title} in the verified clean-appliance {viewport_name} state."
    alt = f"Atlaso {title} page in the clean-appliance {viewport_name} viewport."
    return route, "clean", caption, alt


def metadata(path: Path) -> dict[str, object]:
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
    responsive = "responsive" in stem
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
    screenshots = [metadata(path) for path in sorted(SCREENSHOTS.glob("*.webp"))]
    MANIFEST.write_text(
        json.dumps({"schema_version": 1, "screenshots": screenshots}, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"Wrote {len(screenshots)} screenshot records to {MANIFEST.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
