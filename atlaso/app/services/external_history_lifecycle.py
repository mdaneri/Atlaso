"""Install and operate fixed external producer capture through root-owned services.

Nginx keeps regular file writes and its existing master PID. Old files become
capture input only after USR1 and full service descriptor closure. All raw
generations and imported legacy files are retained: the appliance's default
Nginx package has no rotation policy. A detected external rotation owner blocks
this migration instead of silently replacing that owner's retention contract.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import importlib
import json
import os
import re
import sqlite3
import stat
import subprocess
import sys
from collections.abc import Iterator
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Any

from atlaso.app.services import producer_log_history as history
from atlaso.app.services.app_history_cutover import (
    _ordinary,
    _sync_directory,
    inventory,
)
from atlaso.app.services.nginx_log_capture import capture_generation
from atlaso.app.services.nginx_log_sealing import (
    nginx_writers_closed,
    reopen_nginx_logs,
    seal_generation,
)

ROOT = Path("/var/lib/atlaso-privileged/log-history")
NGINX_LOGS = Path("/var/log/nginx")
NGINX_GENERATIONS = NGINX_LOGS / ".atlaso-history"
NGINX_STORE = ROOT / "nginx.sqlite"
KMS_LOGS = Path("/var/log/atlaso/kmip")
KMS_HISTORY_ROOT = Path("/var/lib/atlaso-kmip-log-history")
KMS_STORE = KMS_HISTORY_ROOT / "history.sqlite"
KMS_ENVIRONMENT = Path("/etc/atlaso/kmip/history.env")
UNIT_ROOT = Path("/etc/systemd/system")
SERVICE = "atlaso-nginx-log-capture.service"
TIMER = "atlaso-nginx-log-capture.timer"
MANAGED = "# Managed by Atlaso external log history."


class RotationConflict(ValueError):
    """An existing external owner requires explicit retention migration."""


def _write(path: Path, value: dict[str, Any] | str, *, mode: int = 0o600) -> None:
    """Atomically publish bounded trusted metadata without following links.

    Args:
        path: Fixed lifecycle-owned metadata path.
        value: Metadata object or fixed service/environment text.
        mode: Required permissions for the published regular file.
    """
    if path.is_symlink() or path.with_name(path.name + ".pending").is_symlink():
        raise ValueError("Linked external history metadata.")
    temporary = path.with_name(path.name + ".pending")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC |
                         getattr(os, "O_NOFOLLOW", 0), mode)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(value if isinstance(value, str) else json.dumps(value, sort_keys=True))
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temporary, mode)
    os.replace(temporary, path)
    _sync_directory(path.parent)


def _private(path: Path) -> None:
    """Prepare a root-owned private directory beneath a trusted ancestor.

    Args:
        path: Fixed external history state or generation directory.
    """
    if not path.exists():
        parent = _ordinary(path.parent, directory=True)
        if os.name == "posix" and (parent.st_uid != int(importlib.import_module("os").geteuid()) or
                                   stat.S_IMODE(parent.st_mode) & 0o022):
            raise ValueError("External history parent must exclude unrelated writers.")
        path.mkdir(mode=0o700)
        _sync_directory(path.parent)
    info = _ordinary(path, directory=True)
    if os.name == "posix":
        uid = int(importlib.import_module("os").geteuid())
        if info.st_uid != uid or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError("External history state must be private and collector-owned.")


def _systemctl(*arguments: str) -> str:
    """Run one fixed bounded service operation without exposing service output.

    Args:
        *arguments: Lifecycle-owned systemctl operation and fixed unit names.
    """
    result = subprocess.run(["/usr/bin/systemctl", *arguments], check=False,
                            capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise ValueError("External history service operation failed.")
    return result.stdout


@contextmanager
def lifecycle_lock(root: Path) -> Iterator[None]:
    """Serialize install, cutover and every timer invocation across processes.

    Args:
        root: Prepared trusted state root.
    """
    path = root / "collector-lock.sqlite"
    if path.is_symlink():
        raise ValueError("Linked external history lifecycle lock.")
    with closing(sqlite3.connect(path, timeout=1)) as db, db:
        db.execute("CREATE TABLE IF NOT EXISTS guard(slot INTEGER PRIMARY KEY)")
        db.execute("BEGIN IMMEDIATE")
        yield


def check_rotation_owners(root: Path = Path("/"), *, package_files: tuple[str, ...] = ()) -> None:
    """Reject known file, cron, vendor, or systemd Nginx rotation ownership.

    Args:
        root: Filesystem root, replaced only by isolated tests.
        package_files: Installed Nginx RPM paths used to discover vendor schedules.
    """
    roots = ("etc/logrotate.conf", "etc/logrotate.d", "usr/lib/logrotate.d", "usr/share/logrotate",
             "etc/crontab", "etc/cron.d", "etc/cron.hourly", "etc/cron.daily", "etc/cron.weekly",
             "etc/cron.monthly", "var/spool/cron", "etc/systemd/system", "usr/lib/systemd/system",
             "run/systemd/system")
    pending = [root / value for value in roots]
    pending.extend(root / value.lstrip("/") for value in package_files
                   if any(part in value.casefold() for part in ("logrotate", "/cron")))
    seen: set[Path] = set()
    read_bytes = 0
    while pending:
        path = pending.pop()
        if path in seen or not path.exists():
            continue
        seen.add(path)
        if len(seen) > 16384:
            raise RotationConflict("Rotation ownership inventory exceeds its safety bound.")
        if path.is_symlink():
            # Enabled systemd links are redundant with the regular unit sources.
            if path.parent.name.endswith((".wants", ".requires")):
                continue
            target = path.resolve()
            if target == Path("/dev/null"):
                continue
            if not target.is_relative_to(root.resolve()):
                raise RotationConflict("Rotation ownership contains an external link.")
            pending.append(target)
            continue
        if path.is_dir():
            pending.extend(path.iterdir())
            continue
        if not path.is_file() or path.stat().st_size > 1024 * 1024:
            raise RotationConflict("Rotation ownership contains an unreadable or oversized entry.")
        if path.name in {SERVICE, TIMER}:
            continue
        text = path.read_text(encoding="utf-8", errors="strict")
        read_bytes += len(text.encode("utf-8"))
        if read_bytes > 32 * 1024 * 1024:
            raise RotationConflict("Rotation ownership content exceeds its safety bound.")
        lines = [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
        content = "\n".join(lines)
        logrotate = "logrotate" in str(path).casefold()
        if logrotate:
            for line in lines:
                if line.startswith("include "):
                    value = line.removeprefix("include ").strip().strip('"')
                    if not value.startswith("/"):
                        raise RotationConflict("Relative logrotate include requires explicit migration.")
                    pending.append(root / value.lstrip("/"))
            patterns = re.findall(r"/[^\s{}\"']+", content)
            if any("nginx" in pattern.casefold() or any(fnmatch.fnmatchcase(target, pattern) for target in (
                    "/var/log/nginx/access.log", "/var/log/nginx/error.log")) for pattern in patterns):
                raise RotationConflict("Existing Nginx logrotate policy requires explicit migration.")
        elif ("nginx" in content.casefold() and re.search(r"logrotate|rotate|reopen|USR1", content, re.IGNORECASE)):
            raise RotationConflict("Existing scheduled Nginx rotation requires explicit migration.")
        elif (re.search(r"(?:^|\s|=)/[^\s]*logrotate(?:\s|$)", content) and
              not re.search(r"(?:^|\s)/etc/logrotate\.conf(?:\s|$)", content)):
            raise RotationConflict("Custom logrotate invocation requires explicit migration.")


def _vendor_rotation_check() -> None:
    """Include the installed RPM's vendor rotation paths in ownership admission."""
    result = subprocess.run(["/usr/bin/rpm", "-ql", "nginx"], check=False,
                            capture_output=True, text=True, timeout=15)
    if result.returncode or len(result.stdout) > 1024 * 1024:
        raise RotationConflict("Installed Nginx RPM ownership could not be verified.")
    check_rotation_owners(package_files=tuple(result.stdout.splitlines()))


def _copy_snapshot(source: Path, target: Path) -> str:
    """Copy a stable retained file, proving descriptor and final source identity.

    Args:
        source: Cooperatively closed original file or immutable numbered archive.
        target: Private preserved snapshot path.
    """
    before = _ordinary(source)
    if target.exists():
        _ordinary(target)
    temporary = target.with_name(target.name + ".pending")
    if temporary.is_symlink():
        raise ValueError("Linked external snapshot staging file.")
    digest = hashlib.sha256()
    source_fd = _open_source(source)
    target_fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC |
                        getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(source_fd, "rb") as reader, os.fdopen(target_fd, "wb") as writer:
        opened = os.fstat(reader.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
                before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns):
            raise ValueError("External legacy source changed before preservation.")
        while block := reader.read(65536):
            digest.update(block)
            writer.write(block)
        writer.flush()
        os.fsync(writer.fileno())
    after = _ordinary(source)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError("External legacy source changed during preservation.")
    os.replace(temporary, target)
    _sync_directory(target.parent)
    return digest.hexdigest()


def _open_source(path: Path) -> int:
    """Pin every Linux parent directory before opening a legacy source file.

    Args:
        path: Fixed inventory source whose final descriptor must exclude links.
    """
    if os.name != "posix":
        return os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0)
    parent_fd = os.open("/", flags)
    try:
        for component in path.absolute().parent.parts[1:]:
            child_fd = os.open(component, flags, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = child_fd
        return os.open(path.name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
    finally:
        os.close(parent_fd)


def _import_once(store: Path, source: str, snapshots: list[tuple[Path, str]]) -> None:
    """Resume exactly the same imported legacy manifest after an interrupted cutover.

    Args:
        store: Prepared fixed producer database.
        source: Fixed external source identifier.
        snapshots: Preserved oldest-first files and their authenticated digests.
    """
    with closing(sqlite3.connect(store.resolve().as_uri() + "?mode=ro", uri=True)) as db:
        previous = db.execute("SELECT manifest FROM legacy_import WHERE source=?", (source,)).fetchone()
    if previous:
        if json.loads(previous[0]) != [digest for _, digest in snapshots]:
            raise ValueError("Interrupted external legacy import manifest changed.")
    else:
        history.import_legacy(store, source, snapshots)


def _activate(store: Path, source: str) -> None:
    """Publish a verified complete legacy source without replacing existing capture.

    Args:
        store: Prepared external producer store.
        source: Fixed source whose import is complete.
    """
    if history.source_active(store, source):
        return
    with closing(sqlite3.connect(store.resolve().as_uri() + "?mode=ro", uri=True)) as db:
        if db.execute("PRAGMA integrity_check").fetchone() != ("ok",):
            raise ValueError("External history integrity validation failed.")
    page = history.read_page(store, source, limit=1)
    history.activate_source(store, source, generation=page.generation, through=page.through)


def collect_nginx() -> None:
    """Import the complete initial inventory or collect the next immutable pair."""
    _vendor_rotation_check()
    _private(NGINX_GENERATIONS)
    state_path = ROOT / "nginx-state.json"
    if state_path.exists():
        _ordinary(state_path)
        if state_path.stat().st_size > 1024 * 1024:
            raise ValueError("Oversized Nginx collection state.")
        state = json.loads(state_path.read_text(encoding="utf-8"))
    else:
        if NGINX_STORE.exists():
            raise ValueError("Unbound Nginx history requires recovery.")
        archived: dict[str, list[str]] = {}
        for name in ("access.log", "error.log"):
            archived[name] = [path.name for path in inventory(NGINX_LOGS / name) if path.name != name]
        state = {"schema": 1, "phase": "initial", "next": 0, "pending": None, "archives": archived}
        _write(state_path, state)
    if state.get("schema") != 1 or state.get("phase") not in {"initial", "active"}:
        raise ValueError("Invalid Nginx collection recovery state.")
    if state["phase"] == "active":
        if (any(not history.source_active(NGINX_STORE, source) for source in ("nginx-access", "nginx-error")) or
                history.read_page(NGINX_STORE, "nginx-access", limit=1).generation != state.get("store_generation")):
            raise ValueError("Selected Nginx history changed after activation.")
    if state["phase"] == "active" and state["pending"] is None and all(
            _ordinary(NGINX_LOGS / name).st_size == 0 for name in ("access.log", "error.log")):
        return
    sequence = state.get("next")
    if type(sequence) is not int or not 0 <= sequence < 10**16:
        raise ValueError("Invalid Nginx generation sequence.")
    name = f"{sequence:016d}"
    if state.get("pending") not in (None, name):
        raise ValueError("Nginx pending generation identity changed.")
    generation = NGINX_GENERATIONS / name
    _private(generation)
    if state["pending"] is None:
        state["pending"] = name
        _write(state_path, state)
    archived_identities: set[tuple[int, int]] = set()
    if state["phase"] == "initial":
        for names in state["archives"].values():
            for archived in names:
                if not isinstance(archived, str) or not re.fullmatch(r"(?:access|error)\.log\.[1-9][0-9]*(?:\.gz)?", archived):
                    raise ValueError("Invalid initial Nginx archive identity.")
                info = _ordinary(NGINX_LOGS / archived)
                archived_identities.add((info.st_dev, info.st_ino))

    def all_writers_closed(current: set[tuple[int, int]]) -> bool:
        """Include old numbered archives that a pre-cutover worker may still hold.

        Args:
            current: Current file identities retained by this seal operation.
        """
        return nginx_writers_closed(current | archived_identities)

    seal_generation(NGINX_LOGS, generation, reopen=reopen_nginx_logs, writers_closed=all_writers_closed)
    if state["phase"] == "initial":
        history.initialize(NGINX_STORE)
        for basename, source in (("access.log", "nginx-access"), ("error.log", "nginx-error")):
            paths = [path for path in inventory(NGINX_LOGS / basename) if path.name != basename]
            if [path.name for path in paths] != state["archives"][basename]:
                raise ValueError("Nginx archive inventory changed during cutover.")
            preserved = generation / (basename + "-legacy")
            _private(preserved)
            snapshots = [(preserved / path.name, _copy_snapshot(path, preserved / path.name)) for path in paths]
            current = generation / basename
            with current.open("rb") as stream:
                snapshots.append((current, hashlib.file_digest(stream, "sha256").hexdigest()))
            _import_once(NGINX_STORE, source, snapshots)
        for source in ("nginx-access", "nginx-error"):
            _activate(NGINX_STORE, source)
        state["phase"] = "active"
        state["store_generation"] = history.read_page(NGINX_STORE, "nginx-access", limit=1).generation
    else:
        capture_generation(NGINX_STORE, generation)
    state["pending"], state["next"] = None, sequence + 1
    _write(state_path, state)


def _kms_stopped() -> None:
    """Require the fixed KMS unit to have no service or control process."""
    raw = _systemctl("show", "atlaso-kmip.service", "--property=ActiveState,MainPID,ControlPID,Job")
    state = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
    if (state.get("ActiveState") not in {"inactive", "failed"} or state.get("MainPID") != "0" or
            state.get("ControlPID") != "0" or state.get("Job") not in {"", "0"}):
        raise ValueError("KMS must be fully stopped for history cutover.")


def prepare_kms(*, resume: bool) -> None:
    """Preserve legacy KMS logs before selecting its in-process durable handler.

    Args:
        resume: Restore a previously running service after successful publication.
    """
    raw = _systemctl("show", "atlaso-kmip.service", "--property=LoadState,ActiveState")
    observed = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
    if observed.get("LoadState") == "not-found":
        return
    if observed.get("LoadState") != "loaded" or observed.get("ActiveState") not in {"active", "inactive", "failed"}:
        raise ValueError("KMS cutover requires a stable installed service.")
    environment_files = _systemctl("show", "atlaso-kmip.service", "--property=EnvironmentFiles", "--value")
    if str(KMS_ENVIRONMENT) + " (ignore_errors=yes)" not in environment_files:
        raise ValueError("KMS service must load its optional history environment.")
    state_path = ROOT / "kms-state.json"
    if state_path.exists():
        _ordinary(state_path)
        if state_path.stat().st_size > 4096:
            raise ValueError("Oversized KMS cutover state.")
        state = json.loads(state_path.read_text(encoding="utf-8"))
        if (state.get("schema") != 1 or state.get("phase") not in {"preparing", "published", "complete"} or
                type(state.get("previous_active")) is not bool):
            raise ValueError("Invalid KMS cutover recovery state.")
    else:
        state = {"schema": 1, "phase": "preparing", "previous_active": observed["ActiveState"] == "active"}
        _write(state_path, state)
    if KMS_ENVIRONMENT.exists():
        _ordinary(KMS_ENVIRONMENT)
        if KMS_ENVIRONMENT.read_text(encoding="utf-8") != f"ATLASO_KMS_LOG_HISTORY_PATH={KMS_STORE}\n":
            raise ValueError("Unexpected KMS history environment.")
        lock_path = KMS_STORE.with_suffix(".capture-lock.sqlite")
        _ordinary(lock_path)
        with closing(sqlite3.connect(lock_path.resolve().as_uri() + "?mode=rw", uri=True, timeout=5)) as lock, lock:
            lock.execute("BEGIN IMMEDIATE")
            if not history.source_active(KMS_STORE, "kms"):
                raise ValueError("Selected KMS history is not active.")
            # A durable formatted batch can be replayed, but a formatter failure
            # has unknown input and must block a successful cutover acknowledgment.
            history._finish_prepared_capture(KMS_STORE, "kms")
        if state["phase"] != "complete":
            if resume and state["previous_active"]:
                _systemctl("start", "atlaso-kmip.service")
            state["phase"] = "complete"
            _write(state_path, state)
        return
    if state["phase"] != "preparing":
        raise ValueError("KMS history environment disappeared after publication.")
    _systemctl("stop", "atlaso-kmip.service")
    _kms_stopped()
    _ordinary(KMS_LOGS, directory=True)
    account = importlib.import_module("pwd").getpwnam("atlaso-kmip")
    if not KMS_HISTORY_ROOT.exists():
        _ordinary(KMS_HISTORY_ROOT.parent, directory=True)
        KMS_HISTORY_ROOT.mkdir(mode=0o700)
        _sync_directory(KMS_HISTORY_ROOT.parent)
    runtime = _ordinary(KMS_HISTORY_ROOT, directory=True)
    if os.name == "posix" and (runtime.st_uid not in {0, account.pw_uid} or stat.S_IMODE(runtime.st_mode) & 0o077):
        raise ValueError("KMS history runtime ownership is invalid.")
    preserved = ROOT / "kms-legacy"
    _private(preserved)
    paths = inventory(KMS_LOGS / "server.log")
    snapshots = [(preserved / path.name, _copy_snapshot(path, preserved / path.name)) for path in paths]
    _kms_stopped()
    history.initialize(KMS_STORE)
    _import_once(KMS_STORE, "kms", snapshots)
    _activate(KMS_STORE, "kms")
    for name in ("history.sqlite", "history.sqlite-wal", "history.sqlite-shm", "history.capture-lock.sqlite",
                 "history.capture-lock.sqlite-journal"):
        path = KMS_HISTORY_ROOT / name
        if not path.exists():
            continue
        _ordinary(path)
        importlib.import_module("os").chown(path, account.pw_uid, account.pw_gid)
        os.chmod(path, 0o600)
    importlib.import_module("os").chown(KMS_HISTORY_ROOT, account.pw_uid, account.pw_gid)
    _kms_stopped()
    _write(KMS_ENVIRONMENT, f"ATLASO_KMS_LOG_HISTORY_PATH={KMS_STORE}\n")
    state["phase"] = "published"
    _write(state_path, state)
    if resume and state["previous_active"]:
        _systemctl("start", "atlaso-kmip.service")
    state["phase"] = "complete"
    _write(state_path, state)


def install_units() -> None:
    """Install only collector-owned fixed units, preserving Nginx service identity."""
    service = f"""{MANAGED}
[Unit]
Description=Capture sealed Atlaso Nginx log generations
After=nginx.service
Requisite=nginx.service
RequiresMountsFor=/var/log/nginx /var/lib/atlaso-privileged

[Service]
Type=oneshot
ExecStart=/opt/atlaso/.venv/bin/python -I -m atlaso.app.services.external_history_lifecycle collect
TimeoutStartSec=120
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/log/nginx /var/lib/atlaso-privileged/log-history
ProtectHome=true
"""
    timer = f"""{MANAGED}
[Unit]
Description=Keep Atlaso Nginx log history current

[Timer]
OnBootSec=20s
OnUnitInactiveSec=5s
AccuracySec=1s
Unit={SERVICE}

[Install]
WantedBy=timers.target
"""
    for name, value in ((SERVICE, service), (TIMER, timer)):
        path = UNIT_ROOT / name
        if path.exists() and not path.read_text(encoding="utf-8").startswith(MANAGED + "\n"):
            raise ValueError("External history unit has another owner.")
        _write(path, value, mode=0o644)
    dropin_root = UNIT_ROOT / "atlaso-kmip.service.d"
    if not dropin_root.exists():
        dropin_root.mkdir(mode=0o755)
    _ordinary(dropin_root, directory=True)
    dropin = dropin_root / "atlaso-log-history.conf"
    if dropin.exists() and not dropin.read_text(encoding="utf-8").startswith(MANAGED + "\n"):
        raise ValueError("KMS history service configuration has another owner.")
    _write(dropin, f"{MANAGED}\n[Service]\nEnvironmentFile=-{KMS_ENVIRONMENT}\n"
           "ReadWritePaths=/var/lib/atlaso-kmip-log-history\n", mode=0o644)


def main(argv: list[str] | None = None) -> int:
    """Run only the fixed install, periodic collection, or KMS cutover operation.

    Args:
        argv: Explicit lifecycle arguments, or normal process arguments.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("install", "collect", "kms-cutover"))
    arguments = parser.parse_args(argv)
    if os.name != "posix":
        print("External history lifecycle requires the appliance root account.", file=sys.stderr)
        return 2
    if importlib.import_module("os").geteuid() != 0:
        print("External history lifecycle requires the appliance root account.", file=sys.stderr)
        return 2
    try:
        _private(ROOT)
        with lifecycle_lock(ROOT):
            if arguments.operation == "kms-cutover":
                prepare_kms(resume=False)
            elif arguments.operation == "collect":
                collect_nginx()
            else:
                _vendor_rotation_check()
                install_units()
                _systemctl("daemon-reload")
                collect_nginx()
                prepare_kms(resume=True)
                _systemctl("enable", "--now", TIMER)
    except RotationConflict:
        print("External Nginx rotation ownership requires explicit history migration.", file=sys.stderr)
        return 3
    except (OSError, ValueError, KeyError, TypeError, AttributeError, sqlite3.Error, subprocess.SubprocessError):
        print("External history lifecycle failed; retained recovery state was preserved.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
