"""Generate the checked-in screenshot manifest from reviewed Atlaso captures."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
SCREENSHOTS = ROOT / "docs" / "assets" / "screenshots"
MANIFEST = SCREENSHOTS / "manifest.json"
SOURCE_COMMIT = "0247c34bc85e+working-tree"
ATLASO_VERSION = "0.9.21"
CANONICAL_BROWSER_ROOTS = {
    "management": "/ui/management",
    "public": "/ui/public",
    "note": "Per-image route values preserve the URL used for the historical capture; documentation generators publish the canonical issue 287 route.",
}

CAPTURE_OVERRIDES = {
    **{
        stem: {
            "route": "/ui/management/routes-wan",
            "state": "suspended-nat",
            "source_commit": "45b4c2c2d640+working-tree",
            "atlaso_version": "0.9.275",
            "caption": (
                "Routes and WAN Simulation with global routing disabled and the saved "
                "NAT choice visibly suspended."
            ),
            "alt": (
                "Atlaso Routes and WAN Simulation showing disabled routing, a checked "
                "but unavailable NAT switch, and the suspended status."
            ),
            "capture_method": "codex-in-app-browser",
        }
        for stem in (
            "routes-wan-clean-desktop",
            "routes-wan-clean-responsive",
        )
    },
    **{
        stem: {
            "source_commit": "1d5bf935b499+working-tree",
            "atlaso_version": "0.9.84",
            "capture_method": "codex-in-app-browser",
        }
        for stem in (
            "ca-management-requests-clean-desktop",
            "ca-management-requests-clean-responsive",
            "ca-requests-clean-desktop",
            "ca-requests-clean-responsive",
            "monitor-clean-desktop",
            "monitor-clean-responsive",
            "monitor-detail-grids-clean-desktop",
            "monitor-detail-grids-clean-responsive",
            "vcf-depot-browser-clean-desktop",
            "vcf-depot-browser-clean-responsive",
        )
    },
    **{
        stem: {
            "source_commit": "6400eb6618fa+working-tree",
            "atlaso_version": "0.9.115",
            "capture_method": "codex-in-app-browser",
        }
        for stem in (
            "physical-interfaces-clean-desktop",
            "physical-interfaces-clean-responsive",
            "routes-wan-policy-wizard-responsive",
            "routes-wan-static-route-wizard-desktop",
            "vlan-interfaces-clean-desktop",
            "vlan-interfaces-clean-responsive",
        )
    },
    **{
        stem: {
            "source_commit": "d4b407eb37f7+working-tree",
            "atlaso_version": "0.9.88",
            "capture_method": "codex-in-app-browser",
        }
        for stem in ("ntp-clean-desktop", "ntp-clean-responsive")
    },
    **{
        stem: {
            "source_commit": "48af0ffc51a6+working-tree",
            "atlaso_version": "0.9.80",
            "capture_method": "codex-in-app-browser",
        }
        for stem in (
            "vcf-offline-depot-clean-desktop",
            "vcf-offline-depot-clean-responsive",
        )
    },
    "vcf-offline-depot-configuration-wizard": {
        "source_commit": "01a995e62e4a+working-tree",
        "atlaso_version": "0.9.80",
        "capture_method": "codex-in-app-browser",
    },
    "vcf-offline-depot-schedule-action-desktop": {
        "source_commit": "5673a8d9+working-tree",
        "atlaso_version": "0.9.127",
        "capture_method": "codex-in-app-browser",
    },
    "network-objects-clean-desktop": {
        "source_commit": "0df3b4b3f873+working-tree",
        "atlaso_version": "0.9.195",
        "capture_method": "codex-in-app-browser",
    },
    "network-objects-clean-responsive": {
        "source_commit": "0df3b4b3f873+working-tree",
        "atlaso_version": "0.9.195",
        "capture_method": "codex-in-app-browser",
    },
    "appliance-update-repository-setup-required-desktop": {
        "source_commit": "dba0a41c4b07+working-tree",
        "atlaso_version": "0.9.186",
        "capture_method": "codex-in-app-browser",
    },
    "appliance-update-repository-setup-required-responsive": {
        "source_commit": "dba0a41c4b07+working-tree",
        "atlaso_version": "0.9.186",
        "capture_method": "codex-in-app-browser",
    },
    "primary-navigation-expanded-desktop": {
        "source_commit": "230f8534+working-tree",
        "atlaso_version": "0.9.199",
        "capture_method": "codex-in-app-browser",
    },
    "primary-navigation-collapsed-desktop": {
        "source_commit": "230f8534+working-tree",
        "atlaso_version": "0.9.199",
        "capture_method": "codex-in-app-browser",
    },
    "primary-navigation-collapsed-responsive": {
        "source_commit": "230f8534+working-tree",
        "atlaso_version": "0.9.199",
        "capture_method": "codex-in-app-browser",
    },
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
}

DOCUMENTATION_PAGES = {
    "getting-started/index.md": ("login-", "services-"),
    "operate/dashboard.md": ("about-", "dashboard-"),
    "operate/navigation.md": ("primary-navigation-",),
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
    "operate/network-objects.md": ("network-objects-",),
    "operate/web-terminal.md": ("terminal-",),
    "services/dns.md": ("dns-",),
    "services/dhcp.md": ("dhcp-",),
    "services/firewall.md": ("firewall-",),
    "services/ntp.md": ("ntp-",),
    "services/esx-storage.md": ("esx-storage-",),
    "services/ipxe.md": ("esxi-pxe-", "esxi-custom-variable-"),
    "services/vsphere-key-providers.md": ("vsphere-key-providers-",),
    "services/local-users.md": ("users-",),
    "services/managed-ldap.md": ("ldap-", "managed-ldap-"),
    "services/oidc-provider.md": ("authentication-",),
    "services/certificate-authority.md": (
        "ca-management-requests-",
        "ca-public-",
        "ca-requests-",
        "certificate-authority-",
    ),
    "services/vcf-backups.md": ("vcf-backups-",),
    "services/vcf-helper.md": ("vcf-helper-",),
    "services/vaults.md": ("vaults-",),
    "services/vcf-offline-depot.md": ("vcf-depot-browser-", "vcf-offline-depot-"),
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
    "vsphere-key-providers": ("/vsphere-key-providers", "vSphere Key Providers"),
    "ldap": ("/ldap", "Managed LDAP"),
    "login": ("/login", "Appliance sign-in"),
    "logs": ("/logs", "Logs"),
    "monitor": ("/monitor", "Monitor"),
    "network-objects": ("/network-objects", "Network Objects"),
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
    "appliance-update-repository-setup-required-desktop": (
        "/appliance-update#appliance-update-streams",
        "repository-setup-required",
        "Appliance Update with a repository-backed stream blocked until synchronization.",
        "Atlaso Appliance Update showing PowerShell Modules disabled with Repository setup required and an Open Update Sources action.",
    ),
    "appliance-update-repository-setup-required-responsive": (
        "/appliance-update#appliance-update-streams",
        "repository-setup-required",
        "Appliance Update repository readiness at the responsive viewport.",
        "Atlaso Appliance Update responsive view showing the disabled PowerShell Modules stream, repository prerequisite, and remediation action.",
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
    "ca-management-requests-clean-desktop": (
        "/ca/requests",
        "clean",
        "Management certificate requests rendered through the shared read-only grid in the desktop viewport.",
        "Atlaso management Certificate Requests page showing issued certificates in a read-only grid.",
    ),
    "ca-management-requests-clean-responsive": (
        "/ca/requests",
        "clean",
        "Management certificate requests remain contained in the narrow viewport.",
        "Atlaso management Certificate Requests page showing its read-only grid in the narrow viewport.",
    ),
    "ca-requests-clean-desktop": (
        "/requests",
        "clean",
        "Public certificate requests rendered through the shared read-only grid in the desktop viewport.",
        "Atlaso public Certificate Request Portal showing issued certificates in a read-only grid.",
    ),
    "ca-requests-clean-responsive": (
        "/requests",
        "clean",
        "Public certificate requests remain contained in the narrow viewport.",
        "Atlaso public Certificate Request Portal showing its read-only grid in the narrow viewport.",
    ),
    "monitor-clean-desktop": (
        "/monitor",
        "clean",
        "Monitor summary and live charts in the verified desktop state.",
        "Atlaso Monitor page showing live appliance metrics in the desktop viewport.",
    ),
    "monitor-clean-responsive": (
        "/monitor",
        "clean",
        "Monitor summary and live charts in the verified narrow state.",
        "Atlaso Monitor page showing live appliance metrics in the narrow viewport.",
    ),
    "monitor-detail-grids-clean-desktop": (
        "/monitor",
        "live-detail-grids",
        "Network-interface and disk-device activity use read-only grids beneath their live charts.",
        "Atlaso Monitor desktop page showing read-only network interface and disk activity detail grids.",
    ),
    "monitor-detail-grids-clean-responsive": (
        "/monitor",
        "live-detail-grids",
        "Network-interface and disk-device grids remain readable without page overflow in the narrow viewport.",
        "Atlaso Monitor narrow page showing read-only network interface and disk activity detail grids.",
    ),
    "routes-wan-policy-wizard-responsive": (
        "/ui/management/routes-wan#policies",
        "wan-policy-wizard",
        "Shared WAN policy wizard in the verified responsive viewport.",
        "Atlaso WAN policy wizard using the standard responsive rail and five reviewed configuration steps.",
    ),
    "routes-wan-static-route-wizard-desktop": (
        "/ui/management/routes-wan#routes",
        "static-route-wizard-review",
        "Shared static route wizard review with the complete path and appliance-apply boundary.",
        "Atlaso static route wizard using the standard rail while reviewing the destination, interface path, WAN Simulation selection, and enabled state.",
    ),
    "physical-interfaces-clean-desktop": (
        "/ui/management/physical-interfaces",
        "clean",
        "Physical Interfaces showing the standard Atlaso false glyph for disabled IPv6 and canonical network roles.",
        "Atlaso Physical Interfaces page showing false glyphs in the IPv6 column and canonical interface roles.",
    ),
    "physical-interfaces-clean-responsive": (
        "/ui/management/physical-interfaces",
        "clean",
        "Physical Interfaces showing the standard Atlaso IPv6 glyphs at the responsive viewport.",
        "Responsive Atlaso Physical Interfaces page showing false glyphs for disabled IPv6.",
    ),
    "vcf-depot-browser-clean-desktop": (
        "/PROD/",
        "published-content",
        "The public VCF Offline Depot directory renders exact artifact paths as safe native links in a read-only grid.",
        "Atlaso public VCF Offline Depot browser showing a directory link in the desktop read-only grid.",
    ),
    "vcf-depot-browser-clean-responsive": (
        "/PROD/",
        "published-content",
        "The public VCF Offline Depot browser remains contained in the narrow viewport.",
        "Atlaso public VCF Offline Depot browser showing its read-only contents grid in the narrow viewport.",
    ),
    "vcf-offline-depot-configuration-wizard": (
        "/vcf-offline-depot",
        "software-depot-id-review",
        "VCFDT Software Depot ID generation ends at Review, which immediately dispatches a dedicated identity task.",
        "Atlaso two-step VCFDT Software Depot ID wizard Review with a Queue Software Depot ID task action and no additional confirmation dialog.",
    ),
    "vcf-offline-depot-clean-desktop": (
        "/vcf-offline-depot",
        "staged-configuration",
        "VCF Offline Depot with metadata first and the compact VCFDT configuration summary in the desktop settings rail.",
        "Atlaso VCF Offline Depot desktop page showing Metadata before Binaries and ESX profiles and the combined VCFDT configuration action.",
    ),
    "vcf-offline-depot-clean-responsive": (
        "/vcf-offline-depot",
        "staged-configuration",
        "VCF Offline Depot profile ordering and staging state in the responsive viewport.",
        "Atlaso VCF Offline Depot responsive page showing Metadata first with the add-profile row pinned last.",
    ),
    "vcf-offline-depot-schedule-action-desktop": (
        "/vcf-offline-depot",
        "contextual-schedule-review",
        "VCF Offline Depot review binds the selected profile in the contextual schedule flow.",
        "VCF Offline Depot contextual Schedule wizard Review showing Schedule, Timing, State, and Review steps with Binaries fixed as the selected profile.",
    ),
    "vlan-interfaces-clean-desktop": (
        "/ui/management/vlan-interfaces",
        "clean",
        "VLAN Interfaces shared Role step defaulting a new VLAN to the canonical access role.",
        "Atlaso VLAN Interfaces add wizard Role step showing access as the default role with the Management UI switch.",
    ),
    "vlan-interfaces-clean-responsive": (
        "/ui/management/vlan-interfaces",
        "clean",
        "VLAN Interfaces with canonical role data in the verified responsive state.",
        "Responsive Atlaso VLAN Interfaces page backed by the canonical management, access, route, and unused roles.",
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
    "primary-navigation-collapsed-desktop": (
        "/dashboard",
        "navigation-collapsed",
        "Authenticated primary navigation with every authorized section collapsed and the shared bulk control.",
        "Atlaso Dashboard with all navigation sections collapsed and the double-right-angle expand control available.",
    ),
    "primary-navigation-collapsed-responsive": (
        "/dashboard",
        "navigation-collapsed",
        "Responsive navigation with all sections collapsed and expand-all above both columns.",
        "Collapsed responsive navigation with expand-all.",
    ),
    "primary-navigation-expanded-desktop": (
        "/dashboard",
        "navigation-expanded",
        "Authenticated primary navigation with every authorized section expanded and the shared bulk control.",
        "Atlaso Dashboard with all authorized navigation sections expanded and the double-left-angle collapse control available.",
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
    suffix = (
        "-clean-responsive" if stem.endswith("-clean-responsive") else "-clean-desktop"
    )
    slug = stem.removesuffix(suffix)
    route_metadata = ROUTES.get(slug)
    if route_metadata is None:
        raise ValueError(f"unknown screenshot slug: {stem}")
    route, title = route_metadata
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


def render_manifest(paths: Iterable[Path] | None = None) -> str:
    """Render the canonical screenshot manifest without changing the checkout.

    Args:
        paths: Optional screenshot paths used instead of the checked-in captures.
    """
    screenshot_paths = paths if paths is not None else SCREENSHOTS.glob("*.webp")
    screenshots = [metadata(path) for path in sorted(screenshot_paths)]
    return (
        json.dumps(
            {
                "schema_version": 1,
                "canonical_browser_roots": CANONICAL_BROWSER_ROOTS,
                "screenshots": screenshots,
            },
            indent=2,
        )
        + "\n"
    )


def main(argv: list[str] | None = None) -> int:
    """Run the command-line entry point.

    Args:
        argv: Optional command-line arguments for tests and embedded callers.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail without writing when the checked-in manifest is stale",
    )
    args = parser.parse_args(argv)
    rendered = render_manifest()
    if args.check:
        if not MANIFEST.exists() or MANIFEST.read_text(encoding="utf-8") != rendered:
            parser.error(
                "screenshot manifest is out of date; run "
                "python scripts/generate_screenshot_manifest.py"
            )
        print(f"Verified {MANIFEST.relative_to(ROOT)}")
        return 0

    MANIFEST.write_text(rendered, encoding="utf-8", newline="\n")
    screenshot_count = sum(1 for _ in SCREENSHOTS.glob("*.webp"))
    print(
        f"Wrote {screenshot_count} screenshot records to {MANIFEST.relative_to(ROOT)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
