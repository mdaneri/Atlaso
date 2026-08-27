"""Generate the published screenshot gallery from the reviewed manifest."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "docs" / "assets" / "screenshots" / "manifest.json"
GALLERY = ROOT / "docs" / "reference" / "interface-gallery.md"


def canonical_route(route: str) -> str:
    """Return the current browser route for historical screenshot metadata.

    Args:
        route: Historical screenshot route recorded in the manifest.
    """
    if route.startswith(("/ui/management", "/ui/public")):
        return route
    if route == "/ca":
        return "/ui/public/ca"
    if route == "/requests":
        return "/ui/public/ca/requests"
    if route == "/ca/requests":
        return "/ui/management/ca/requests"
    if route.startswith("/") and not route.startswith(("/api/", "/PROD/")):
        return f"/ui/management{route}"
    return route


def route_title(route: str) -> str:
    """Return route title.

    Args:
        route: Route consumed by route title.
    """
    if route == "vmware-console":
        return "VMware console"
    if route == "/ui/management/ca/requests":
        return "Management CA / Requests"
    if route == "/ui/management/vsphere-key-providers":
        return "vSphere Key Providers"
    if route == "/ui/public/ca/requests":
        return "Public CA / Requests"
    display_route = route
    if route.startswith("/ui/management/"):
        display_route = route.removeprefix("/ui/management")
    elif route == "/ui/management":
        display_route = "/"
    elif route.startswith("/ui/public/"):
        display_route = route.removeprefix("/ui/public")
    path, separator, fragment = display_route.partition("#")
    if path == "/":
        return "Home"
    title = path.strip("/").replace("-", " ").replace("/", " / ").title()
    if separator:
        title = f"{title}: {fragment.replace('-', ' ').title()}"
    return title


def render_gallery(payload: dict[str, object]) -> str:
    """Render the canonical gallery without changing the checkout.

    Args:
        payload: Parsed screenshot manifest.
    """
    grouped: dict[str, list[dict[str, object]]] = defaultdict(list)
    screenshots = payload.get("screenshots")
    if not isinstance(screenshots, list):
        raise ValueError("screenshot manifest must contain a screenshots list")
    for screenshot in screenshots:
        if not isinstance(screenshot, dict):
            raise ValueError("screenshot manifest entries must be objects")
        grouped[canonical_route(str(screenshot["route"]))].append(screenshot)

    lines = [
        "---",
        "title: Verified interface gallery",
        "description: Reviewed Atlaso appliance screenshots captured from the dedicated documentation VM.",
        "audience:",
        "  - operator",
        "status: current",
        "---",
        "",
        "# Verified interface gallery",
        "",
        "These images were captured from the dedicated `Atlaso-Docs` VMware Workstation VM. The frozen baseline",
        "runs Atlaso 0.9.21; individually recaptured images record their exact later version and source revision in",
        "the screenshot manifest alongside viewport, capture method, brand variant, and sensitive-data review status.",
        "",
        "The clean, configured, pending, failed, and applied labels describe observed appliance states. A",
        "successful state is shown only where the corresponding task completed successfully.",
        "",
    ]
    for route in sorted(grouped, key=lambda value: (route_title(value), value)):
        lines.extend([f"## {route_title(route)}", "", f"Route: `{route}`", ""])
        for screenshot in grouped[route]:
            image_name = Path(str(screenshot["path"])).name
            lines.extend(
                [
                    f"![{screenshot['alt']}](../assets/screenshots/{image_name})",
                    "",
                    f"Figure: {screenshot['caption']}",
                    "",
                ]
            )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """Run the command-line entry point.

    Args:
        argv: Optional command-line arguments for tests and embedded callers.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail without writing when the checked-in gallery is stale",
    )
    args = parser.parse_args(argv)
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    rendered = render_gallery(payload)
    if args.check:
        if not GALLERY.exists() or GALLERY.read_text(encoding="utf-8") != rendered:
            parser.error(
                "screenshot gallery is out of date; run "
                "python scripts/generate_screenshot_gallery.py"
            )
        print(f"Verified {GALLERY.relative_to(ROOT)}")
        return 0

    GALLERY.write_text(rendered, encoding="utf-8", newline="\n")
    screenshots = payload["screenshots"]
    print(f"Wrote {len(screenshots)} images to {GALLERY.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
