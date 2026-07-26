#!/usr/bin/env python3
"""Overlay a built Atlaso documentation site without touching release content."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path


def overlay(built_docs: Path, pages_root: Path) -> None:
    if not (built_docs / "index.html").is_file():
        raise ValueError(f"built documentation index is missing: {built_docs / 'index.html'}")
    destination = pages_root / "docs"
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(built_docs, destination)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--built-docs", type=Path, required=True)
    parser.add_argument("--pages-root", type=Path, required=True)
    args = parser.parse_args()
    overlay(args.built_docs.resolve(), args.pages_root.resolve())
    print(f"Overlaid documentation at {(args.pages_root / 'docs').resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
