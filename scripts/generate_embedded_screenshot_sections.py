"""Embed every reviewed screenshot into the documentation page that explains it."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
MANIFEST = DOCS / "assets" / "screenshots" / "manifest.json"
OVERVIEW_HEADING = "## Interface overview"
ADDITIONAL_HEADING = "## Additional verified states"
OVERVIEW_BEGIN = "<!-- BEGIN GENERATED INTERFACE OVERVIEW -->"
OVERVIEW_END = "<!-- END GENERATED INTERFACE OVERVIEW -->"
ADDITIONAL_BEGIN = "<!-- BEGIN GENERATED ADDITIONAL SCREENSHOTS -->"
ADDITIONAL_END = "<!-- END GENERATED ADDITIONAL SCREENSHOTS -->"

PRIMARY_IMAGES = {
    "getting-started/index.md": "login-desktop.webp",
    "operate/dashboard.md": "dashboard-clean-desktop.webp",
    "operate/appliance-apply.md": "appliance-review-modal-desktop.webp",
    "operate/appliance-console.md": "appliance-console-applied.webp",
    "operate/appliance-update.md": "appliance-update-clean-desktop.webp",
    "operate/automation.md": "automation-clean-desktop.webp",
    "operate/web-terminal.md": "terminal-clean-desktop.webp",
    "services/dns.md": "dns-clean-desktop.webp",
    "services/esx-storage.md": "esx-storage-clean-desktop.webp",
    "services/ipxe.md": "esxi-pxe-clean-desktop.webp",
    "services/managed-ldap.md": "ldap-clean-desktop.webp",
    "services/oidc-provider.md": "authentication-clean-desktop.webp",
    "services/vcf-helper.md": "vcf-helper-clean-desktop.webp",
    "services/vcf-trust.md": "certificate-authority-clean-desktop.webp",
    "reference/full-technical-reference.md": "physical-interfaces-clean-desktop.webp",
}

ROUTE_TITLES = {
    "/api/docs": "API reference",
    "/appliance-update": "Appliance Update",
    "/audit-log": "Audit events",
    "/authentication": "Authentication",
    "/automation": "Automation",
    "/backup-restore": "Backup and restore",
    "/ca": "Public certificate portal",
    "/certificate-authority": "Certificate Authority",
    "/dashboard": "Dashboard",
    "/dhcp": "DHCP",
    "/dns": "DNS",
    "/esx-storage": "ESX Storage",
    "/esxi-pxe": "ESXi PXE",
    "/firewall": "Firewall",
    "/kms": "KMS and KMIP",
    "/ldap": "Managed LDAP",
    "/login": "Sign in",
    "/logs": "Logs",
    "/monitor": "Monitor",
    "/ntp": "NTP and NTS",
    "/physical-interfaces": "Physical interfaces",
    "/requests": "Certificate requests",
    "/routes-wan": "Routes and WAN simulation",
    "/services": "Services",
    "/settings": "Appliance Settings",
    "/tasks": "Tasks",
    "/terminal": "Web terminal",
    "/users": "Users",
    "/vcf-backups": "VCF backups",
    "/vcf-helper": "VCF Helper",
    "/vcf-offline-depot": "VCF Offline Depot",
    "/vcf-private-registry": "VCF Private Registry",
    "/vlan-interfaces": "VLAN interfaces",
    "vmware-console": "VMware console",
}


def route_title(route: str) -> str:
    if route in ROUTE_TITLES:
        return ROUTE_TITLES[route]
    path, separator, fragment = route.partition("#")
    title = path.strip("/").replace("-", " ").replace("/", " / ").title() or "Home"
    if separator:
        title = f"{title}: {fragment.replace('-', ' ').title()}"
    return title


def figure(entry: dict[str, object]) -> list[str]:
    path = Path(str(entry["path"]))
    return [
        f"![{entry['alt']}](../assets/screenshots/{path.name})",
        "",
        f"*Figure: {entry['caption']}*",
        "",
    ]


def remove_generated_sections(text: str) -> str:
    overview = re.compile(
        rf"\n{re.escape(OVERVIEW_BEGIN)}\n.*?\n{re.escape(OVERVIEW_END)}\n?",
        re.DOTALL,
    )
    additional = re.compile(
        rf"\n{re.escape(ADDITIONAL_BEGIN)}\n.*?\n{re.escape(ADDITIONAL_END)}\n?",
        re.DOTALL,
    )
    return additional.sub("", overview.sub("", text)).rstrip() + "\n"


def insert_after_intro(text: str, section: str) -> str:
    h1 = re.search(r"^# .+$", text, re.MULTILINE)
    if not h1:
        raise ValueError("page has no level-one heading")
    intro_end = text.find("\n\n", h1.end())
    if intro_end == -1:
        raise ValueError("page has no introductory paragraph")
    intro_end = text.find("\n\n", intro_end + 2)
    if intro_end == -1:
        intro_end = len(text)
    return f"{text[:intro_end].rstrip()}\n\n{section}\n\n{text[intro_end:].lstrip()}"


def main() -> None:
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    grouped: dict[str, list[dict[str, object]]] = defaultdict(list)
    for screenshot in payload["screenshots"]:
        grouped[str(screenshot["documentation_page"])].append(screenshot)

    if set(grouped) != set(PRIMARY_IMAGES):
        missing = sorted(set(PRIMARY_IMAGES) - set(grouped))
        extra = sorted(set(grouped) - set(PRIMARY_IMAGES))
        raise ValueError(f"page mapping mismatch; missing={missing}, extra={extra}")

    for relative, screenshots in sorted(grouped.items()):
        page = DOCS / relative
        text = remove_generated_sections(page.read_text(encoding="utf-8"))
        primary_name = PRIMARY_IMAGES[relative]
        primary = next(
            (entry for entry in screenshots if Path(str(entry["path"])).name == primary_name),
            None,
        )
        if primary is None:
            raise ValueError(f"{relative} has no primary screenshot {primary_name}")

        overview_lines = [
            OVERVIEW_BEGIN,
            OVERVIEW_HEADING,
            "",
            "This verified appliance view provides visual orientation before you begin.",
            "",
            *figure(primary),
            OVERVIEW_END,
        ]
        text = insert_after_intro(text, "\n".join(overview_lines).rstrip())

        additional = [entry for entry in screenshots if entry is not primary]
        if additional:
            additional_lines = [
                ADDITIONAL_BEGIN,
                ADDITIONAL_HEADING,
                "",
                "These captures show responsive layouts and useful operational states referenced by this page.",
                "",
            ]
            by_route: dict[str, list[dict[str, object]]] = defaultdict(list)
            for entry in additional:
                by_route[str(entry["route"])].append(entry)
            for route in sorted(by_route, key=lambda value: (route_title(value), value)):
                additional_lines.extend([f"### {route_title(route)}", ""])
                for entry in by_route[route]:
                    additional_lines.extend(figure(entry))
            additional_lines.append(ADDITIONAL_END)
            text = f"{text.rstrip()}\n\n" + "\n".join(additional_lines).rstrip() + "\n"

        page.write_text(text, encoding="utf-8", newline="\n")
        print(f"Embedded {len(screenshots)} screenshot(s) in {relative}")


if __name__ == "__main__":
    main()
