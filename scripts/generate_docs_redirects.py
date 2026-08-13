#!/usr/bin/env python3
"""Replace built documentation redirect stubs with dependency-free redirects."""

from __future__ import annotations

import html
import sys
from pathlib import Path

from check_docs import DOCS, ROOT, parse_front_matter

SITE = ROOT / "site" / "docs"


def output_path(source: Path) -> Path:
    """Return output path.

    Args:
        source: Source object or location from which data is obtained.
    """
    relative = source.relative_to(DOCS)
    if relative.name == "index.md":
        return SITE / relative.with_suffix(".html")
    return SITE / relative.with_suffix("") / "index.html"


def main() -> int:
    """Run the command-line entry point.

    Returns:
        The main result.
    """
    count = 0
    for source in sorted(DOCS.rglob("*.md")):
        meta, _, _ = parse_front_matter(source, source.read_text(encoding="utf-8"))
        if meta.get("status") != "redirect":
            continue
        target = str(meta["redirect_to"])
        relative_prefix = "../" * len(source.relative_to(DOCS).with_suffix("").parts)
        url = f"{relative_prefix}{target.removesuffix('.md')}/"
        destination = output_path(source)
        destination.parent.mkdir(parents=True, exist_ok=True)
        escaped = html.escape(url, quote=True)
        destination.write_text(
            "<!doctype html>\n"
            '<html lang="en"><head><meta charset="utf-8">\n'
            f'<meta http-equiv="refresh" content="0; url={escaped}">\n'
            f'<link rel="canonical" href="{escaped}"><title>Documentation moved</title></head>\n'
            f'<body><p>This page moved to <a href="{escaped}">{escaped}</a>.</p></body></html>\n',
            encoding="utf-8",
        )
        count += 1
    print(f"Generated {count} documentation redirect page(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
