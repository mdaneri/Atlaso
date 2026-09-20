"""Preserve and activate App history while both in-process producers are stopped.

Run from an independent lifecycle process, never from the worker being stopped.
The owning deployment path installs the same optional EnvironmentFile in both
units. Publication of that file is the commit point: before it, failures restore
legacy operation; after it, failures retain the new history and stop producers.
"""

import argparse
import hashlib
import importlib
import json
import os
import re
import sqlite3
import stat
import subprocess
from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from atlaso.app.services import producer_log_history as history

UNITS = ("atlaso.service", "atlaso-worker.service")


class Controller(Protocol):
    """Provide the deployment-owned quiescence and configuration boundaries."""

    def active_units(self) -> tuple[str, ...]:
        """Return exactly the previously active producer units."""
        ...

    def stop(self) -> None:
        """Stop both producers, including a partially started producer."""
        ...

    def assert_stopped(self) -> None:
        """Prove both producer units have no process or pending start job."""
        ...

    def configured_store(self) -> Path | None:
        """Return the previously atomically selected store, if any."""
        ...

    def publish(self, path: Path) -> None:
        """Atomically select a fully activated store for both producer units.

        Args:
            path: Validated producer database to select.
        """
        ...

    def resume(self, units: tuple[str, ...]) -> None:
        """Start only the producer units which were active on entry.

        Args:
            units: Previously active fixed producer unit names.
        """
        ...


@dataclass(frozen=True)
class Snapshot:
    """Bind one preserved legacy file to its original inventory identity."""

    name: str
    path: Path
    sha256: str
    size: int


@dataclass(frozen=True)
class Cutover:
    """Describe the selected immutable history and private preserved inventory."""

    store: Path
    generation: str
    through: int
    preservation: Path | None


def _ordinary(path: Path, *, directory: bool = False) -> os.stat_result:
    """Reject symlinks and special files throughout a trusted runtime path.

    Args:
        path: Deployment-owned path to inspect without following symlinks.
        directory: Whether the final component must be an ordinary directory.
    """
    for parent in path.absolute().parents:
        if parent.is_symlink():
            raise ValueError("History path has a linked ancestor.")
    info = path.lstat()
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(info.st_mode) or (not directory and info.st_nlink != 1):
        raise ValueError("History path is not an ordinary owned filesystem entry.")
    return info


def _identity(path: Path) -> tuple[int, int, int, int, int]:
    """Identify an unchanged ordinary inventory file.

    Args:
        path: Original legacy or preserved file.
    """
    info = _ordinary(path)
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def inventory(legacy: Path) -> list[Path]:
    """Return every supported rotation, oldest first, refusing ambiguous siblings.

    Args:
        legacy: Active App log file configured by the appliance.
    """
    _ordinary(legacy.parent, directory=True)
    rotated: dict[int, Path] = {}
    active: Path | None = None
    for candidate in legacy.parent.iterdir():
        if candidate.name == legacy.name:
            _ordinary(candidate)
            active = candidate
        elif candidate.name.startswith(legacy.name + "."):
            match = re.fullmatch(re.escape(legacy.name) + r"\.([1-9][0-9]*)(\.gz)?", candidate.name)
            if match is None:
                raise ValueError("Unsupported App log rotation requires reconciliation.")
            number = int(match[1])
            if number in rotated:
                raise ValueError("Ambiguous compressed and plain App log rotation.")
            _ordinary(candidate)
            rotated[number] = candidate
    if rotated and (active is None or sorted(rotated) != list(range(1, len(rotated) + 1))):
        raise ValueError("Incomplete App log rotation inventory.")
    return [rotated[number] for number in sorted(rotated, reverse=True)] + ([active] if active else [])


def _sync_directory(path: Path) -> None:
    """Persist a directory entry on the appliance filesystem.

    Args:
        path: Directory whose entries were updated.
    """
    if os.name == "posix":
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _write_new(path: Path, data: bytes) -> None:
    """Write private durable evidence without replacing an existing attempt.

    Args:
        path: New evidence pathname within a private root.
        data: Exact evidence bytes, never emitted to stdout.
    """
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    _sync_directory(path.parent)


def preserve(legacy: Path, destination: Path, assert_stopped: Callable[[], None]) -> list[Snapshot]:
    """Preserve the entire stable inventory without modifying original log files.

    Args:
        legacy: Active App log pathname.
        destination: Newly created private directory owned by the lifecycle caller.
        assert_stopped: Fresh deployment proof that neither producer can write.
    """
    assert_stopped()
    paths = inventory(legacy)
    identities = {path: _identity(path) for path in paths}
    snapshots: list[Snapshot] = []
    for source in paths:
        target = destination / source.name
        digest = hashlib.sha256()
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with source.open("rb") as reader, os.fdopen(descriptor, "wb") as writer:
            current = os.fstat(reader.fileno())
            # Windows fstat and lstat expose different legacy ctime semantics;
            # inode, size and modification time still bind the opened input.
            if (current.st_dev, current.st_ino, current.st_size,
                    current.st_mtime_ns) != identities[source][:4]:
                raise ValueError("App log identity changed before preservation.")
            while block := reader.read(65536):
                digest.update(block)
                writer.write(block)
            writer.flush()
            os.fsync(writer.fileno())
        if _identity(source) != identities[source]:
            raise ValueError("App log changed during preservation.")
        snapshots.append(Snapshot(source.name, target, digest.hexdigest(), identities[source][2]))
    assert_stopped()
    if inventory(legacy) != paths or any(_identity(path) != identities[path] for path in paths):
        raise ValueError("App log inventory changed during preservation.")
    manifest = [{"name": item.name, "sha256": item.sha256, "bytes": item.size,
                 "identity": list(identities[paths[index]])} for index, item in enumerate(snapshots)]
    _write_new(destination / "inventory.json", json.dumps(manifest, sort_keys=True).encode("utf-8"))
    return snapshots


def _validate(path: Path) -> tuple[str, int]:
    """Verify database integrity and every imported row before publishing.

    Args:
        path: Quiescent prepared producer store.
    """
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=rw", uri=True)) as connection:
        if connection.execute("PRAGMA integrity_check").fetchone() != ("ok",):
            raise ValueError("App history integrity validation failed.")
        if connection.execute("SELECT 1 FROM capture_pending WHERE source='app'").fetchone():
            raise ValueError("App history has unfinished capture.")
    page = history.read_page(path, "app")
    generation, through, after = page.generation, page.through, page.after
    while page.more:
        page = history.read_page(path, "app", after=after, through=through, generation=generation)
        if page.after <= after:
            raise ValueError("App history validation did not advance.")
        after = page.after
    return generation, through


def _validate_selected(path: Path) -> tuple[str, int]:
    """Validate an active store between captures without stopping its producers.

    Args:
        path: Existing selected producer store within the verified runtime root.
    """
    lock_path = path.with_suffix(".capture-lock.sqlite")
    _ordinary(lock_path)
    with closing(sqlite3.connect(lock_path.resolve().as_uri() + "?mode=rw", uri=True, timeout=5)) as lock, lock:
        lock.execute("BEGIN IMMEDIATE")
        with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=rw", uri=True)) as connection:
            connection.execute("BEGIN")
            if connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
                raise ValueError("Configured App history integrity validation failed.")
            if not connection.execute("SELECT 1 FROM cutover WHERE source='app'").fetchone():
                raise ValueError("Configured App history was not activated.")
            # The capture lock excludes live formatting; NULL now proves an
            # interrupted input, rather than a producer between its two commits.
            if connection.execute("SELECT 1 FROM capture_pending WHERE source='app' AND prepared IS NULL").fetchone():
                raise ValueError("App history requires interrupted-record recovery.")
            boundary = connection.execute(
                "SELECT identity.generation,producer.sequence FROM identity,producer "
                "WHERE identity.slot=1 AND producer.source='app' AND EXISTS "
                "(SELECT 1 FROM legacy_import WHERE source='app')"
            ).fetchone()
            if boundary is None:
                raise ValueError("Configured App history has no verified import boundary.")
            generation, through = str(boundary[0]), int(boundary[1])
    return generation, through


def run_cutover(legacy: Path, history_root: Path, preservation_root: Path, controller: Controller,
                *, already_stopped: bool = False,
                if_needed: bool = False,
                prepare_runtime: Callable[[Path], None] | None = None) -> Cutover:
    """Import retained App logs and atomically select producer capture.

    A failure before configuration publication restores the original running
    services. After publication, recovery keeps the new store and both producers
    stopped; reverting to legacy after acknowledged capture would lose history.
    Every failed attempt retains its own snapshots and database for reconciliation.

    Args:
        legacy: Deployment-owned active App log pathname.
        history_root: Prepared private runtime root writable by the App account.
        preservation_root: Prepared private root accessible only to the lifecycle owner.
        controller: Independent deployment service/configuration adapter.
        already_stopped: Verify caller-owned shutdown without starting any service.
        if_needed: Validate an existing selection without restarting healthy producers.
        prepare_runtime: Apply service ownership to the newly prepared SQLite files.
    """
    _ordinary(history_root, directory=True)
    _ordinary(preservation_root, directory=True)
    previous = controller.active_units()
    if already_stopped:
        controller.assert_stopped()
    if if_needed:
        try:
            selected = controller.configured_store()
            if selected is not None:
                _ordinary(selected)
                if not selected.resolve().is_relative_to(history_root.resolve()):
                    raise ValueError("Configured App history is outside its owning root.")
                generation, through = _validate_selected(selected)
                return Cutover(selected, generation, through, None)
        except (OSError, ValueError, sqlite3.Error):
            controller.stop()
            controller.assert_stopped()
            raise
    if already_stopped:
        controller.assert_stopped()
    else:
        controller.stop()
    published = False
    try:
        controller.assert_stopped()
        # An existing or unreadable selection is already a publication decision.
        # Validation failure must not restart producers against a broken store.
        published = True
        selected = controller.configured_store()
        if selected is not None:
            _ordinary(selected)
            if not selected.resolve().is_relative_to(history_root.resolve()):
                raise ValueError("Configured App history is outside its owning root.")
            if not history.source_active(selected, "app"):
                raise ValueError("Configured App history was not activated.")
            generation, through = _validate(selected)
            published = True
            result = Cutover(selected, generation, through, None)
        else:
            published = False
            attempt = uuid4().hex
            preserved = preservation_root / attempt
            runtime = history_root / attempt
            preserved.mkdir(mode=0o700)
            runtime.mkdir(mode=0o700)
            _sync_directory(preservation_root)
            _sync_directory(history_root)
            snapshots = preserve(legacy, preserved, controller.assert_stopped)
            store = runtime / "app.sqlite"
            history.initialize(store)
            history.import_legacy(store, "app", [(item.path, item.sha256) for item in snapshots])
            generation, through = _validate(store)
            controller.assert_stopped()
            history.activate_source(store, "app", generation=generation, through=through)
            if prepare_runtime is not None:
                prepare_runtime(runtime)
            _write_new(preserved / "activation.json", json.dumps({
                "store": str(store), "generation": generation, "through": through,
            }, sort_keys=True).encode("utf-8"))
            controller.assert_stopped()
            # Mark before publication: a rename may succeed before its fsync fails.
            published = True
            controller.publish(store)
            result = Cutover(store, generation, through, preserved)
        if not already_stopped:
            controller.resume(previous)
        return result
    except (OSError, EOFError, ValueError, sqlite3.Error, subprocess.SubprocessError):
        controller.stop()
        controller.assert_stopped()
        if not published and not already_stopped:
            controller.resume(previous)
        raise


class SystemdController:
    """Control the fixed App producers from an independent privileged process."""

    def __init__(self, environment: Path) -> None:
        """Bind the shared optional EnvironmentFile installed by deployment.

        Args:
            environment: Root-owned App-history-only environment file.
        """
        self.environment = environment

    def _run(self, *arguments: str) -> str:
        """Run a bounded fixed systemctl operation without emitting raw output.

        Args:
            *arguments: Explicit systemctl arguments owned by this controller.
        """
        result = subprocess.run(["systemctl", *arguments], check=False, capture_output=True,
                                text=True, timeout=120)
        if result.returncode:
            raise ValueError("App history service operation failed.")
        return result.stdout

    def _state(self, unit: str) -> dict[str, str]:
        """Read the process and job state for one fixed producer unit.

        Args:
            unit: Fixed App service name.
        """
        raw = self._run("show", unit, "--property=ActiveState,MainPID,ControlPID,Job")
        return dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)

    def active_units(self) -> tuple[str, ...]:
        """Reject transitions and preserve the exact previously running unit set."""
        active = []
        for unit in UNITS:
            files = self._run("show", unit, "--property=EnvironmentFiles", "--value").strip()
            required = re.escape(str(self.environment)) + r" \(ignore_errors=yes\)"
            if not re.search(r"(?:^|\s)" + required + r"(?:\s|$)", files):
                raise ValueError("Both App units must load the shared history environment.")
            state = self._state(unit)
            if state.get("ActiveState") not in {"active", "inactive", "failed"}:
                raise ValueError("App history cutover requires stable service state.")
            if state["ActiveState"] == "active":
                active.append(unit)
        return tuple(active)

    def stop(self) -> None:
        """Stop both producers in one systemd operation."""
        self._run("stop", *UNITS)
        self.assert_stopped()

    def assert_stopped(self) -> None:
        """Require zero main/control PIDs and no outstanding systemd job."""
        for unit in UNITS:
            state = self._state(unit)
            if (state.get("ActiveState") not in {"inactive", "failed"}
                    or state.get("MainPID") != "0" or state.get("ControlPID") != "0"
                    or state.get("Job") not in {"", "0"}):
                raise ValueError("Both App producers must be fully stopped for history cutover.")

    def configured_store(self) -> Path | None:
        """Read only the dedicated non-secret one-line history configuration."""
        if not self.environment.exists():
            if self.environment.is_symlink():
                raise ValueError("App history environment must not be a symlink.")
            return None
        _ordinary(self.environment)
        content = self.environment.read_text(encoding="utf-8")
        match = re.fullmatch(r'ATLASO_APP_LOG_HISTORY_PATH="([^"\n\r\\]+)"\n', content)
        if match is None:
            raise ValueError("App history environment requires reconciliation.")
        return Path(match[1])

    def publish(self, path: Path) -> None:
        """Publish both services' shared selection as one durable atomic rename.

        Args:
            path: Verified activated store whose runtime ownership is prepared.
        """
        _ordinary(self.environment.parent, directory=True)
        if self.environment.exists() or self.environment.is_symlink():
            raise ValueError("App history configuration changed before publication.")
        pathname = path.as_posix()
        if any(character in pathname for character in '\n\r"\\'):
            raise ValueError("Unsupported App history environment pathname.")
        staging = self.environment.with_name(self.environment.name + "." + uuid4().hex)
        _write_new(staging, f'ATLASO_APP_LOG_HISTORY_PATH="{pathname}"\n'.encode("utf-8"))
        # Link gives no-replacement publication; retained staging also survives an
        # ambiguous directory flush for explicit deployment reconciliation.
        os.link(staging, self.environment)
        staging.unlink()
        _sync_directory(self.environment.parent)

    def resume(self, units: tuple[str, ...]) -> None:
        """Restart the prior producer set and verify every requested unit is active.

        Args:
            units: Exact fixed unit names active when the migration began.
        """
        if any(unit not in UNITS for unit in units):
            raise ValueError("Unsupported App producer service.")
        if units:
            self._run("start", *units)
        if any(self._state(unit).get("ActiveState") != "active" for unit in units):
            raise ValueError("App history producer failed to resume.")


@contextmanager
def _migration_lock(path: Path) -> Iterator[None]:
    """Serialize lifecycle cutovers without deleting the shared lock inode.

    Args:
        path: Fixed root-owned coordination path within the private system run directory.
    """
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "rb+") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0:
            raise ValueError("App history lifecycle lock requires an ordinary root-owned file.")
        locking = importlib.import_module("fcntl")
        locking.flock(stream.fileno(), locking.LOCK_EX | locking.LOCK_NB)
        yield


def _prepare_root(path: Path, uid: int, gid: int, mode: int) -> None:
    """Create a fixed installation root or validate an existing root unchanged.

    Args:
        path: Fixed owning root selected by appliance deployment.
        uid: Expected owner identifier.
        gid: Expected group identifier.
        mode: Exact private directory mode required by its data classification.
    """
    _ordinary(path.parent, directory=True)
    try:
        path.mkdir(mode=mode)
    except FileExistsError:
        pass
    else:
        chown = getattr(os, "chown", None)
        if chown is None:
            raise ValueError("App history root installation requires POSIX ownership.")
        chown(path, uid, gid)
        path.chmod(mode)
        _sync_directory(path.parent)
    info = _ordinary(path, directory=True)
    if info.st_uid != uid or info.st_gid != gid or stat.S_IMODE(info.st_mode) != mode:
        raise ValueError("App history root has unsupported ownership or permissions.")


def main() -> int:
    """Run the fixed appliance migration with no raw log or credential output."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--already-stopped", action="store_true")
    parser.add_argument("--prepare-roots", action="store_true")
    parser.add_argument("--if-needed", action="store_true")
    options = parser.parse_args()
    get_euid = getattr(os, "geteuid", None)
    chown = getattr(os, "chown", None)
    if os.name != "posix" or get_euid is None or get_euid() != 0 or chown is None:
        parser.error("App history cutover requires the independent root lifecycle process.")
    account = importlib.import_module("pwd").getpwnam("atlaso")
    runtime_root = Path("/var/lib/atlaso/log-history/app")
    preserved_root = Path("/var/lib/atlaso/log-history/legacy-app")

    def prepare_runtime(directory: Path) -> None:
        """Assign only the new generation's known SQLite files to the App account.

        Args:
            directory: Newly created and validated runtime generation directory.
        """
        for item in directory.iterdir():
            _ordinary(item)
            if item.name not in {"app.sqlite", "app.sqlite-wal", "app.sqlite-shm",
                                 "app.capture-lock.sqlite"}:
                raise ValueError("Unexpected file in App history runtime generation.")
            chown(item, account.pw_uid, account.pw_gid)
            item.chmod(0o600)
        chown(directory, account.pw_uid, account.pw_gid)

    controller = SystemdController(Path("/etc/atlaso/app-history.env"))
    from atlaso.app.config import get_settings

    with _migration_lock(Path("/run/atlaso-app-history-cutover.lock")):
        if options.prepare_roots:
            _prepare_root(runtime_root.parent, 0, 0, 0o755)
            _prepare_root(runtime_root, account.pw_uid, account.pw_gid, 0o700)
            _prepare_root(preserved_root, 0, 0, 0o700)
        for root, owner in ((runtime_root, account.pw_uid), (preserved_root, 0)):
            info = _ordinary(root, directory=True)
            if info.st_uid != owner or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError("App history root has unsupported ownership or permissions.")
        run_cutover(get_settings().app_log_path, runtime_root, preserved_root,
                    controller, already_stopped=options.already_stopped,
                    if_needed=options.if_needed, prepare_runtime=prepare_runtime)
    print("App history cutover verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
