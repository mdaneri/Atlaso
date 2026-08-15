#!/usr/bin/env python3
"""Build Atlaso documentation with an isolated Zensical cache lifecycle."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CACHE_MARKER_NAME = ".atlaso-zensical-cache"
CACHE_MARKER_CONTENT = "atlaso-zensical-cache-v1"
LEGACY_ZENSICAL_METADATA = {"autorefs.json", "objects.inv"}


def is_legacy_zensical_cache(cache: Path) -> bool:
    """Return whether an unclaimed cache has Zensical's exact legacy layout.

    Args:
        cache: Existing repository-local cache directory.

    Returns:
        Whether every entry is a known Zensical cache artifact.
    """
    entries = list(cache.iterdir())
    names = {entry.name for entry in entries}
    required = LEGACY_ZENSICAL_METADATA | {".gitignore"}
    if not required.issubset(names):
        return False
    gitignore = cache / ".gitignore"
    if gitignore.is_symlink() or gitignore.read_bytes().strip() != b"*":
        return False
    return all(
        not entry.is_symlink()
        and entry.is_file()
        and (entry.name in required or entry.name.isdecimal())
        for entry in entries
    )


def reset_zensical_cache(root: Path = ROOT) -> None:
    """Remove only the disposable repository-local Zensical cache.

    Args:
        root: Atlaso checkout root containing Zensical's ``.cache`` directory.

    Raises:
        RuntimeError: If the cache path does not match Zensical's owned layout.
    """
    resolved_root = root.resolve(strict=True)
    cache = resolved_root / ".cache"
    if not cache.exists():
        return
    if cache.is_symlink() or not cache.is_dir():
        raise RuntimeError(f"refusing to replace non-directory Zensical cache: {cache}")
    marker = cache / CACHE_MARKER_NAME
    owned = (
        not marker.is_symlink()
        and marker.is_file()
        and marker.read_bytes().strip() == CACHE_MARKER_CONTENT.encode("utf-8")
    )
    if not owned and not is_legacy_zensical_cache(cache):
        raise RuntimeError(f"refusing to replace unrecognized Zensical cache: {cache}")
    shutil.rmtree(cache)


def initialize_zensical_cache(root: Path = ROOT) -> None:
    """Create an empty cache with an Atlaso-specific ownership marker.

    Args:
        root: Atlaso checkout root that will contain Zensical's cache.
    """
    cache = root.resolve(strict=True) / ".cache"
    cache.mkdir()
    (cache / ".gitignore").write_text("*\n", encoding="utf-8")
    mark_zensical_cache(cache)


def mark_zensical_cache(cache: Path) -> None:
    """Persist Atlaso's ownership marker in an existing cache directory.

    Args:
        cache: Repository-local cache directory created for Zensical.

    Raises:
        RuntimeError: If Zensical replaced the cache with an unsafe path type.
    """
    if cache.is_symlink() or not cache.is_dir():
        raise RuntimeError(f"refusing to mark unsafe Zensical cache: {cache}")
    (cache / CACHE_MARKER_NAME).write_text(CACHE_MARKER_CONTENT, encoding="utf-8")


def main() -> int:
    """Run the deterministic strict documentation build.

    Returns:
        The first failed command status, or zero after redirect generation succeeds.
    """
    try:
        reset_zensical_cache()
        initialize_zensical_cache()
    except (OSError, RuntimeError) as exc:
        print(f"Documentation build failed: {exc}", file=sys.stderr)
        return 1
    build = subprocess.run(
        [sys.executable, "-m", "zensical", "build", "--clean", "--strict"],
        cwd=ROOT,
        check=False,
    )
    try:
        mark_zensical_cache(ROOT / ".cache")
    except (OSError, RuntimeError) as exc:
        print(f"Documentation build failed: {exc}", file=sys.stderr)
        return 1
    if build.returncode:
        return build.returncode
    redirects = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "generate_docs_redirects.py")],
        cwd=ROOT,
        check=False,
    )
    return redirects.returncode


if __name__ == "__main__":
    raise SystemExit(main())
