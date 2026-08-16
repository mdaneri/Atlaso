"""Enforce router, facade, and framework-independent service imports."""

from __future__ import annotations

import ast
from importlib.util import resolve_name
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SERVICES_ROOT = ROOT / "atlaso" / "app" / "services"
DOMAIN_ROUTER_ROOTS = (
    ROOT / "atlaso" / "app" / "routers" / "ui",
    ROOT / "atlaso" / "app" / "routers" / "api_v1",
)
FACADE_MODULES = ("atlaso.app.ui", "atlaso.app.api.v1")
SERVICE_FORBIDDEN_MODULES = (*FACADE_MODULES, "atlaso.app.main", "atlaso.app.routers")
EXTRACTED_DOMAIN_MODULES = {
    ROOT / "atlaso" / "app" / "ui.py": (
        "atlaso.app.routers.ui.appliance_apply",
        "atlaso.app.routers.ui.dns_dhcp",
        "atlaso.app.routers.ui.firewall",
        "atlaso.app.routers.ui.identity",
        "atlaso.app.routers.ui.network_boot",
        "atlaso.app.routers.ui.physical_vlans",
        "atlaso.app.routers.ui.routes_wan",
        "atlaso.app.routers.ui.settings_backup",
        "atlaso.app.routers.ui.vcf_workflows",
    ),
    ROOT / "atlaso" / "app" / "api" / "v1.py": (
        "atlaso.app.routers.api_v1.dns_dhcp",
        "atlaso.app.routers.api_v1.firewall",
        "atlaso.app.routers.api_v1.identity",
        "atlaso.app.routers.api_v1.network_boot",
        "atlaso.app.routers.api_v1.physical_vlans",
        "atlaso.app.routers.api_v1.routes_wan",
        "atlaso.app.routers.api_v1.settings",
        "atlaso.app.routers.api_v1.vcf_workflows",
    ),
}


def _module_name(path: Path) -> str:
    """Return the dotted repository module name for a Python path.

    Args:
        path: Python source path under the repository root.

    Returns:
        Dotted module name without the source suffix.
    """
    return ".".join(path.relative_to(ROOT).with_suffix("").parts)


def _imported_modules(path: Path) -> set[str]:
    """Return absolute module targets imported by one source file.

    Args:
        path: Python source file to inspect.

    Returns:
        Absolute imports, including imported members for ``from`` statements.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    package = _module_name(path).rpartition(".")[0]
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            relative = f"{'.' * node.level}{node.module or ''}"
            base = resolve_name(relative, package) if node.level else node.module or ""
            imported.update(f"{base}.{alias.name}" if base else alias.name for alias in node.names)
    return imported


def _matches_forbidden(imported: str, forbidden: str) -> bool:
    """Return whether an import reaches a forbidden module boundary.

    Args:
        imported: Absolute imported module or member.
        forbidden: Forbidden module prefix.

    Returns:
        Whether the imported target equals or descends from the boundary.
    """
    return imported == forbidden or imported.startswith(f"{forbidden}.")


def test_services_do_not_import_routers_or_facades():
    """Keep framework-independent services below transport and assembly code."""
    violations: list[str] = []
    for path in sorted(SERVICES_ROOT.rglob("*.py")):
        for imported in sorted(_imported_modules(path)):
            if any(_matches_forbidden(imported, forbidden) for forbidden in SERVICE_FORBIDDEN_MODULES):
                violations.append(f"{path.relative_to(ROOT).as_posix()}: {imported}")

    assert violations == []


def test_domain_routers_do_not_import_monolithic_facades():
    """Prevent future domain routers from depending back on compatibility facades."""
    violations: list[str] = []
    for root in DOMAIN_ROUTER_ROOTS:
        for path in sorted(root.rglob("*.py")):
            for imported in sorted(_imported_modules(path)):
                if any(_matches_forbidden(imported, facade) for facade in FACADE_MODULES):
                    violations.append(f"{path.relative_to(ROOT).as_posix()}: {imported}")

    assert violations == []


def test_facades_import_extracted_domain_router_modules():
    """Require each stable facade to assemble its extracted domain router."""
    missing: list[str] = []
    for facade, domain_modules in EXTRACTED_DOMAIN_MODULES.items():
        imported = _imported_modules(facade)
        for domain_module in domain_modules:
            if not any(_matches_forbidden(target, domain_module) for target in imported):
                missing.append(f"{facade.relative_to(ROOT).as_posix()}: {domain_module}")

    assert missing == []
