"""Define canonical browser UI namespaces and legacy compatibility rules."""

from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit

MANAGEMENT_UI_ROOT = "/ui/management"
PUBLIC_UI_ROOT = "/ui/public"

MANAGEMENT_ROUTE_ROOTS = frozenset(
    {
        "appliance",
        "appliance-apply",
        "appliance-update",
        "audit-log",
        "authentication",
        "automation",
        "backup-restore",
        "certificate-authority",
        "dashboard",
        "dhcp",
        "dns",
        "esx-storage",
        "esxi-pxe",
        "firewall",
        "https-repository",
        "ldap",
        "ldap-users",
        "login",
        "logout",
        "logs",
        "monitor",
        "network-boot",
        "ntp",
        "openid-connect",
        "physical-interfaces",
        "routes-wan",
        "server-time",
        "services",
        "settings",
        "tasks",
        "users",
        "vaults",
        "vcf-backups",
        "vcf-helper",
        "vcf-offline-depot",
        "vcf-private-registry",
        "vcf-trust",
        "vlan-interfaces",
        "vsphere-key-providers",
    }
)

PUBLIC_LEGACY_PATHS = {
    "/ca": "/ca",
    "/ca/login": "/ca/login",
    "/requests": "/ca/requests",
    "/requests/login": "/ca/requests/login",
    "/requests/logout": "/ca/requests/logout",
}

PUBLIC_LEGACY_PREFIXES = {
    "/requests/certificates/": "/ca/requests/certificates/",
    "/certificates/": "/ca/requests/certificates/",
}

MANAGEMENT_LEGACY_PATHS = {
    "/ca/requests": "/ca/requests",
}

MANAGEMENT_LEGACY_PREFIXES = {
    "/ca/certificates/": "/ca/certificates/",
}

PROTOCOL_PATH_PREFIXES = (
    "/api/",
    "/ca/downloads/",
    "/certificate-authority/downloads/",
    "/oauth/",
    "/openid/",
    "/oidc/",
    "/PROD",
    "/pxe/",
    "/static/",
)

PROTOCOL_EXACT_PATHS = frozenset(
    {
        "/api",
        "/favicon.ico",
        "/manifest.webmanifest",
        "/openapi.json",
        "/service-worker.js",
        "/terminal/remote-launches",
        "/terminal/tickets",
        "/terminal/ws",
    }
)


def _plane_path(root: str, path: str = "") -> str:
    """Return a normalized path beneath one browser UI root.

    Args:
        root: Canonical browser-plane root.
        path: Relative or already-canonical browser path.
    """
    candidate = str(path or "").strip()
    if not candidate or candidate == "/":
        return root
    if candidate == root or candidate.startswith(f"{root}/"):
        return candidate
    if not candidate.startswith("/"):
        candidate = f"/{candidate}"
    return f"{root}{candidate}"


def management_ui_path(path: str = "") -> str:
    """Return a canonical management-browser path.

    Args:
        path: Relative or already-canonical browser path.
    """
    return _plane_path(MANAGEMENT_UI_ROOT, path)


def public_ui_path(path: str = "") -> str:
    """Return a canonical public-browser path.

    Args:
        path: Relative or already-canonical browser path.
    """
    return _plane_path(PUBLIC_UI_ROOT, path)


def is_protocol_path(path: str) -> bool:
    """Return whether a path belongs to a stable non-UI contract.

    Args:
        path: Absolute request path to classify.
    """
    return (
        path in PROTOCOL_EXACT_PATHS
        or any(path.startswith(prefix) for prefix in PROTOCOL_PATH_PREFIXES)
        or bool(re.fullmatch(r"/certificate-authority/certificates/[^/]+/downloads/[^/]+", path))
    )


def legacy_browser_target(path: str, *, public_terminal: bool = False) -> tuple[str, str] | None:
    """Return ``(plane, canonical_path)`` for a retired browser path.

    Args:
        path: Retired absolute browser path.
        public_terminal: Whether terminal and authentication paths belong to the public plane.
    """
    if not path.startswith("/") or path.startswith("//") or is_protocol_path(path):
        return None
    if public_terminal and path in {"/login", "/logout"}:
        return "public", public_ui_path(path)
    if path == "/terminal" or path.startswith("/terminal/"):
        plane = "public" if public_terminal else "management"
        target = public_ui_path(path) if public_terminal else management_ui_path(path)
        return plane, target
    management_path = MANAGEMENT_LEGACY_PATHS.get(path)
    if management_path is not None:
        return "management", management_ui_path(management_path)
    for prefix, replacement in MANAGEMENT_LEGACY_PREFIXES.items():
        if path.startswith(prefix):
            return "management", management_ui_path(f"{replacement}{path.removeprefix(prefix)}")
    public_path = PUBLIC_LEGACY_PATHS.get(path)
    if public_path is not None:
        return "public", public_ui_path(public_path)
    for prefix, replacement in PUBLIC_LEGACY_PREFIXES.items():
        if path.startswith(prefix):
            return "public", public_ui_path(f"{replacement}{path.removeprefix(prefix)}")
    root = path.lstrip("/").split("/", 1)[0]
    if root in MANAGEMENT_ROUTE_ROOTS:
        return "management", management_ui_path(path)
    return None


def canonical_browser_location(location: str, *, plane: str) -> str:
    """Canonicalize a same-host redirect emitted by an existing UI handler.

    Args:
        location: Redirect target emitted by the route handler.
        plane: Browser plane that owns the current request.
    """
    parsed = urlsplit(str(location or ""))
    if parsed.scheme or parsed.netloc or not parsed.path.startswith("/") or parsed.path.startswith("//"):
        return location
    if parsed.path.startswith(f"{MANAGEMENT_UI_ROOT}/") or parsed.path == MANAGEMENT_UI_ROOT:
        return location
    if parsed.path.startswith(f"{PUBLIC_UI_ROOT}/") or parsed.path == PUBLIC_UI_ROOT:
        return location
    if is_protocol_path(parsed.path) or parsed.path == "/":
        return location
    target = legacy_browser_target(parsed.path, public_terminal=plane == "public")
    if target is None:
        return location
    target_plane, target_path = target
    if target_plane != plane:
        return location
    return urlunsplit(("", "", target_path, parsed.query, parsed.fragment))


def safe_management_return_path(value: str | None) -> str:
    """Normalize a login return target to the management namespace.

    Args:
        value: Candidate same-host return target.
    """
    target = str(value or "").strip()
    if not target.startswith("/") or target.startswith("//") or "\\" in target:
        return MANAGEMENT_UI_ROOT
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc:
        return MANAGEMENT_UI_ROOT
    if parsed.path == MANAGEMENT_UI_ROOT or parsed.path.startswith(f"{MANAGEMENT_UI_ROOT}/"):
        return urlunsplit(("", "", parsed.path, parsed.query, parsed.fragment))
    if re.fullmatch(r"/certificate-authority(?:/certificates/[^/]+)?/downloads/[^/]+", parsed.path):
        return urlunsplit(("", "", parsed.path, parsed.query, parsed.fragment))
    legacy = legacy_browser_target(parsed.path)
    if legacy is None or legacy[0] != "management":
        return MANAGEMENT_UI_ROOT
    return urlunsplit(("", "", legacy[1], parsed.query, parsed.fragment))


def safe_public_return_path(value: str | None, *, default: str = "/") -> str:
    """Normalize a return target to the public namespace.

    Args:
        value: Candidate same-host return target.
        default: Public-plane fallback when the candidate is unsafe.
    """
    target = str(value or "").strip()
    if not target.startswith("/") or target.startswith("//") or "\\" in target:
        return public_ui_path(default)
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc:
        return public_ui_path(default)
    if parsed.path == PUBLIC_UI_ROOT or parsed.path.startswith(f"{PUBLIC_UI_ROOT}/"):
        return urlunsplit(("", "", parsed.path, parsed.query, parsed.fragment))
    legacy = legacy_browser_target(parsed.path, public_terminal=True)
    if legacy is None or legacy[0] != "public":
        return public_ui_path(default)
    return urlunsplit(("", "", legacy[1], parsed.query, parsed.fragment))
