#!/usr/bin/env python3
"""Build Atlaso documentation with an isolated Zensical cache lifecycle."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


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
    marker = cache / ".gitignore"
    if not marker.is_file() or marker.read_text(encoding="utf-8").strip() != "*":
        raise RuntimeError(f"refusing to replace unrecognized Zensical cache: {cache}")
    shutil.rmtree(cache)


def main() -> int:
    """Run the deterministic strict documentation build.

    Returns:
        The first failed command status, or zero after redirect generation succeeds.
    """
    try:
        reset_zensical_cache()
    except (OSError, RuntimeError) as exc:
        print(f"Documentation build failed: {exc}", file=sys.stderr)
        return 1
    build = subprocess.run(
        [sys.executable, "-m", "zensical", "build", "--clean", "--strict"],
        cwd=ROOT,
        check=False,
    )
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
