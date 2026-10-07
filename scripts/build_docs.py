#!/usr/bin/env python3
"""Build Atlaso documentation with an isolated Zensical cache lifecycle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from contextlib import nullcontext
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


def report_owned_manifest(manifest: Path) -> None:
    """Write the sealed manifest identity as one machine-readable stdout record.

    Args:
        manifest: Exact durable manifest path returned by the cache owner.
    """
    from scripts.completed_task_files import read_bounded_regular

    digest = hashlib.sha256(read_bounded_regular(manifest, 262_144)).hexdigest()
    print(json.dumps({"ownership_manifest": {"path": str(manifest), "sha256": digest}},
                     sort_keys=True, separators=(",", ":")))


def main(argv: list[str] | None = None) -> int:
    """Run the deterministic strict documentation build.

    Args:
        argv: Optional creation-bound local cache ownership arguments.

    Returns:
        The first failed command status, or zero after redirect generation succeeds.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-receipt", type=Path)
    parser.add_argument("--task-id")
    parser.add_argument("--resource-id")
    parser.add_argument("--source-commit")
    args = parser.parse_args(argv)
    owner = None
    try:
        ownership = (args.cache_receipt, args.task_id, args.resource_id, args.source_commit)
        if any(value is not None for value in ownership):
            if not all(value is not None for value in ownership):
                raise RuntimeError("cache ownership requires receipt, task, resource, and source commit")
            # Local task cleanup is Windows-only; ordinary hosted CI uses the portable wrapper.
            sys.path.insert(0, str(ROOT))
            from scripts.zensical_cache import ZensicalCache

            config = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))) / "config.toml"
            owner = ZensicalCache(config, args.cache_receipt, {
                "id": args.resource_id, "task_id": args.task_id, "repository": "mdaneri/Atlaso",
                "source_commit": args.source_commit, "path": str(ROOT / ".cache"),
            })
    except (OSError, RuntimeError) as exc:
        print(f"Documentation build failed: {exc}", file=sys.stderr)
        return 1
    try:
        # Keep one task claim from cache initialization through all outputs. The
        # cache lifecycle methods acquire the same mutex reentrantly.
        claim = owner.claim() if owner else nullcontext()
        with claim:
            if owner:
                owner.begin()
            else:
                reset_zensical_cache()
                initialize_zensical_cache()

            # The wrapper already starts from an empty cache. In owned mode, prevent
            # the native builder from replacing the creation-bound root with an
            # unreceipted one.
            pin = owner.pin() if owner else nullcontext()
            with pin:
                command = [sys.executable, "-m", "zensical", "build", "--strict"]
                if owner is None:
                    command.append("--clean")
                if owner:
                    try:
                        build = subprocess.run(command, cwd=ROOT, check=False)
                    finally:
                        report_owned_manifest(owner.seal())
                else:
                    build = subprocess.run(command, cwd=ROOT, check=False)
            if owner is None:
                mark_zensical_cache(ROOT / ".cache")
            if build.returncode:
                return build.returncode
            redirects = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "generate_docs_redirects.py")],
                cwd=ROOT,
                check=False,
            )
            return redirects.returncode
    except (OSError, RuntimeError) as exc:
        print(f"Documentation build failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
