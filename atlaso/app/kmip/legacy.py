"""Read-only admission proof for retained legacy PyKMIP stores.

Never open a legacy store through an ORM, upgrade its schema, or create a missing
database. A missing configuration is not permission to ignore retained files.
"""

from __future__ import annotations

import configparser
import sqlite3
import stat
import subprocess
from contextlib import closing
from pathlib import Path


class LegacyStoreError(ValueError):
    """Legacy data or unavailable evidence prevents native replacement."""


def assert_legacy_empty(
    state: Path = Path("/var/lib/atlaso/kms"),
    config: Path = Path("/etc/atlaso/kms/pykmip.conf"),
) -> None:
    """Prove every retained/configured legacy database has no application rows.

    Args:
        state: Canonical legacy state directory, never modified.
        config: Optional old server configuration naming its database.
    """
    paths: set[Path] = set()
    try:
        if config.exists() or config.is_symlink():
            _ordinary(config)
            if config.stat().st_size > 65536:
                raise LegacyStoreError("Legacy configuration evidence is unavailable.")
            parser = configparser.ConfigParser(interpolation=None)
            parser.read_string(config.read_text(encoding="utf-8"))
            value = parser.get("server", "database_path").strip()
            selected = Path(value)
            if not selected.is_absolute():
                raise LegacyStoreError("Legacy database location is ambiguous.")
            paths.add(selected)
            if not selected.exists():
                raise LegacyStoreError("Configured legacy database evidence is unavailable.")
        if state.exists() or state.is_symlink():
            if state.is_symlink() or not state.is_dir():
                raise LegacyStoreError("Legacy state directory is unsafe.")
            for entry in state.iterdir():
                if entry.name.endswith(("-wal", "-shm", "-journal")):
                    # A retained sidecar requires offline reconciliation, never immutable reads.
                    raise LegacyStoreError("Legacy store has unresolved journal evidence.")
                if entry.suffix not in {".db", ".sqlite", ".sqlite3"}:
                    raise LegacyStoreError("Unrecognized retained legacy data blocks replacement.")
                paths.add(entry)
        for path in sorted(paths):
            if any(path.with_name(path.name + suffix).exists() for suffix in ("-wal", "-shm", "-journal")):
                raise LegacyStoreError("Legacy store has unresolved journal evidence.")
            _ordinary(path)
            before = path.stat()
            # mode=ro prevents schema creation and immutable avoids sidecar creation.
            with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro&immutable=1", uri=True)) as db:
                db.execute("PRAGMA query_only=ON")
                db.execute("PRAGMA trusted_schema=OFF")
                if db.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                    raise LegacyStoreError("Legacy database integrity is unavailable.")
                tables = db.execute("SELECT name,type FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall()
                if any(kind != "table" for _, kind in tables):
                    raise LegacyStoreError("Legacy database schema cannot prove emptiness.")
                for name, _kind in tables:
                    if name == "alembic_version":
                        continue
                    quoted = '"' + name.replace('"', '""') + '"'
                    if db.execute(f"SELECT 1 FROM {quoted} LIMIT 1").fetchone():
                        raise LegacyStoreError("Legacy PyKMIP data must be preserved; use a new appliance and VMware-supported rekeying.")
            after = path.stat()
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
            ):
                raise LegacyStoreError("Legacy database changed during admission.")
    except (OSError, sqlite3.Error, configparser.Error, UnicodeError) as exc:
        raise LegacyStoreError("Legacy store evidence is unavailable; replacement blocked.") from exc


def _ordinary(path: Path) -> None:
    """Reject redirected or shared filesystem evidence before opening it.

    Args:
        path: Filesystem entry whose ownership and contents are checked.
    """
    for parent in (path, *path.parents):
        info = parent.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise LegacyStoreError("Legacy path is redirected; replacement blocked.")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise LegacyStoreError("Legacy database is not an ordinary private file.")


def assert_release_admission(
    state: Path = Path("/var/lib/atlaso/kms"),
    config: Path = Path("/etc/atlaso/kms/pykmip.conf"),
) -> None:
    """Guard the existing candidate-import hook before active release switching.

    Args:
        state: Canonical retained legacy state directory.
        config: Optional legacy configuration naming the old database.
    """
    assert_legacy_empty(state, config)
    if not state.exists() and not config.exists():
        return
    try:
        probe = subprocess.run(
            ["systemctl", "show", "atlaso-kms.service", "--property=LoadState,ActiveState"],
            check=False, capture_output=True, text=True, timeout=30,
        )
        properties = dict(line.split("=", 1) for line in probe.stdout.splitlines() if "=" in line)
        if probe.returncode != 0 or not (
            properties.get("LoadState") == "not-found"
            or properties.get("LoadState") == "loaded" and properties.get("ActiveState") in {"inactive", "failed"}
        ):
            raise LegacyStoreError("Stop the empty legacy KMS writer before native release admission.")
        # Stop proof precedes the final database check, including a late old-writer commit.
        assert_legacy_empty(state, config)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise LegacyStoreError("Legacy writer quiescence is unavailable; release admission blocked.") from exc


if __name__ == "__main__":
    import sys

    try:
        assert_legacy_empty()
    except LegacyStoreError:
        print("Legacy store admission failed; preserve data and reconcile before replacement.", file=sys.stderr)
        sys.exit(2)
    sys.exit(0)
