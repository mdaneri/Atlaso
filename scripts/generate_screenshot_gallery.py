"""Generate the published screenshot gallery from the reviewed manifest."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "docs" / "assets" / "screenshots" / "manifest.json"
GALLERY = ROOT / "docs" / "reference" / "interface-gallery.md"


def route_title(route: str) -> str:
    if route == "vmware-console":
        return "VMware console"
    path, separator, fragment = route.partition("#")
    if path == "/":
        return "Home"
    title = path.strip("/").replace("-", " ").replace("/", " / ").title()
    if separator:
        title = f"{title}: {fragment.replace('-', ' ').title()}"
    return title


def main() -> None:
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    grouped: dict[str, list[dict[str, object]]] = defaultdict(list)
    for screenshot in payload["screenshots"]:
        grouped[str(screenshot["route"])].append(screenshot)

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
        "These images were captured from the dedicated `Atlaso-Docs` VMware Workstation VM running Atlaso",
        "0.9.21. Every image is listed in the screenshot manifest with its viewport, source revision, capture",
        "method, brand variant, and sensitive-data review status.",
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
    GALLERY.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {len(payload['screenshots'])} images to {GALLERY.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
