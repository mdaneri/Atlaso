"""Privileged, offline recovery publication with durable pending-trust custody.

The journal and candidates live under a root-owned anchor outside the
application-writable state parent. Publication only moves directory entries;
no pre-existing target database or KEK is rewritten or removed.
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
import sqlite3
import stat
import sys
import uuid
from pathlib import Path
from typing import Any, cast

from atlaso.app.kmip.recovery import (
    MAX_ARCHIVE_BYTES,
    RecoveryError,
    _exclusive_file,
    build_candidate,
    capture,
    decrypt,
    encrypt,
)
from atlaso.app.kmip.store import KeyStoreError, WrappedKeyStore

O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
FCHOWN = getattr(os, "fchown", None)

ANCHOR = Path("/var/lib/atlaso-kmip-recovery")
STATE = Path("/var/lib/atlaso/kmip")


def _rename_absent(source: str, destination: str, source_fd: int, destination_fd: int) -> None:
    """Atomically rename without replacing any concurrent target entry.

    Args:
        source: Source entry name beneath the pinned source descriptor.
        destination: Destination entry name that must not already exist.
        source_fd: Pinned parent descriptor containing the source entry.
        destination_fd: Pinned parent descriptor receiving the entry.
    """
    if sys.platform != "linux":
        raise RecoveryError("Recovery publication requires the appliance Linux filesystem contract.")
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameat2
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(source_fd, os.fsencode(source), destination_fd, os.fsencode(destination), 1) != 0:
        error = ctypes.get_errno()
        raise OSError(error, "Recovery publication could not reserve its target.")
    os.fsync(destination_fd)
    os.fsync(source_fd)


def _secure_anchor(anchor: Path) -> int:
    """Pin a root-only journal/candidate parent, rejecting redirected ancestors.

    Args:
        anchor: Protected root directory for pending recovery custody.
    """
    if not anchor.is_absolute():
        raise RecoveryError("Recovery anchor must be absolute.")
    fd = os.open("/", os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
    try:
        for part in anchor.parts[1:]:
            try:
                child = os.open(part, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                if part != anchor.name:
                    raise
                os.mkdir(part, 0o711, dir_fd=fd)
                os.fsync(fd)
                child = os.open(part, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            if info.st_uid != 0 or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX):
                raise RecoveryError("Recovery anchor ownership is unsafe.")
        if os.fstat(fd).st_mode & 0o066:
            raise RecoveryError("Recovery anchor must permit only root to read or write.")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _journal(anchor: Path, document: dict[str, Any]) -> None:
    """Flush a complete journal before any active directory entry is moved.

    Args:
        anchor: Protected root directory for pending recovery custody.
        document: Complete checkpoint document to publish durably.
    """
    temporary = anchor / ("journal-" + uuid.uuid4().hex)
    _exclusive_file(temporary, json.dumps(document, sort_keys=True).encode())
    os.replace(temporary, anchor / "pending.json")
    fd = os.open(anchor, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def pending() -> bool:
    """Fail closed on any journal, including an invalid/incomplete one."""
    return os.path.lexists(ANCHOR / "pending.json")


def assert_startup_allowed(config_path: Path) -> None:
    """Require root-recorded approval of this exact runtime during pending import.

    Args:
        config_path: Installed runtime configuration bound to recovery approval.
    """
    if not pending():
        return
    try:
        approval = json.loads((ANCHOR / "approved.json").read_bytes())
        active = STATE.stat()
        if (approval["config_sha256"] == hashlib.sha256(config_path.read_bytes()).hexdigest()
                and approval["identity"] == [active.st_dev, active.st_ino]):
            return
    except (OSError, ValueError, KeyError, TypeError):
        pass
    raise RecoveryError("KMIP recovery is pending public trust review and global Appliance Apply.")


def authorize(config_path: Path, *, complete: bool = False) -> None:
    """Bind reviewed Apply to the imported provider/fingerprint graph and inode.

    Args:
        config_path: Installed runtime configuration bound to recovery approval.
        complete: Whether to archive the pending journal after successful Apply.
    """
    fd = _secure_anchor(ANCHOR)
    try:
        if not pending():
            return
        journal = json.loads((ANCHOR / "pending.json").read_bytes())
        active = STATE.stat()
        if journal["identity"] != [active.st_dev, active.st_ino]:
            raise RecoveryError("Recovery active identity requires reconciliation.")
        # Read only public trust; never open operational files by an untrusted path.
        trust = journal["trust"]
        config = json.loads(config_path.read_bytes())
        certificates = {v["id"]: v for v in trust["vcenters"]}
        usable_fingerprints = set()
        for certificate in trust["certificates"]:
            from atlaso.app.services.vsphere_key_providers import (
                parse_public_certificate,
            )

            try:
                parse_public_certificate(certificate["certificate_pem"], require_current=True)
            except ValueError:
                continue  # Historical public trust remains archived, never implicitly usable.
            usable_fingerprints.add(certificate["fingerprint_sha256"])
        expected = {
            provider["id"]: sorted(cert["fingerprint_sha256"] for cert in trust["certificates"]
                                   if cert["fingerprint_sha256"] in usable_fingerprints
                                   and certificates[cert["trusted_vcenter_id"]]["provider_id"] == provider["id"]
                                   and certificates[cert["trusted_vcenter_id"]]["enabled"])
            for provider in trust["providers"] if provider["enabled"]
        }
        expected = {key: value for key, value in expected.items() if value}
        observed = {row["id"]: sorted(row["client_fingerprints"]) for row in config["providers"]}
        if expected != observed or not config["enabled"]:
            raise RecoveryError("Review and restore the imported provider/fingerprint graph before Apply.")
        approved = {"config_sha256": hashlib.sha256(config_path.read_bytes()).hexdigest(),
                    "identity": [active.st_dev, active.st_ino]}
        if complete:
            assert_startup_allowed(config_path)
            _rename_absent("pending.json", "completed-" + journal["archive"] + ".json", fd, fd)
            if (ANCHOR / "service.json").exists():
                _rename_absent("service.json", "service-completed-" + uuid.uuid4().hex + ".json", fd, fd)
        else:
            temporary = ANCHOR / ("approval-" + uuid.uuid4().hex)
            _exclusive_file(temporary, json.dumps(approved, sort_keys=True).encode())
            temporary.chmod(0o644)
            os.replace(temporary, ANCHOR / "approved.json")
            os.fsync(fd)
    finally:
        os.close(fd)


def service_checkpoint(request: dict[str, Any], *, finish: bool = False) -> dict[str, Any]:
    """Persist original service posture before quiescence and retain failed retries.

    Args:
        request: Validated helper request containing operation and service posture.
        finish: Whether to archive the completed service checkpoint.
    """
    fd = _secure_anchor(ANCHOR)
    try:
        path = ANCHOR / "service.json"
        if finish:
            if path.exists():
                _rename_absent("service.json", "service-completed-" + uuid.uuid4().hex + ".json", fd, fd)
            return {"status": "complete"}
        states = request["states"]
        if (not isinstance(states, dict) or set(states) != {"atlaso-kmip.service", "atlaso-kms.service"}
                or any(not isinstance(value, list) or len(value) != 2 or any(type(v) is not bool for v in value)
                       for value in states.values())):
            raise RecoveryError("Recovery service posture is invalid.")
        if path.exists():
            saved = json.loads(path.read_bytes())
            if saved["binding"] != request["binding"] or saved["operation"] != request["operation"]:
                raise RecoveryError("A different recovery operation requires service reconciliation.")
            return {"states": saved["states"]}
        document = {"schema": 1, "states": states, "operation": request["operation"], "binding": request["binding"]}
        temporary = ANCHOR / ("service-checkpoint-" + uuid.uuid4().hex)
        _exclusive_file(temporary, json.dumps(document, sort_keys=True).encode())
        _rename_absent(temporary.name, path.name, fd, fd)
        return {"states": states}
    finally:
        os.close(fd)


def _empty_target(directory: Path, secrets_key: str) -> None:
    """Authenticate zero native keys without creating a missing store.

    Args:
        directory: Private store directory to validate without modifying active state.
        secrets_key: Target appliance credential used only for encrypted master custody.
    """
    entries = {entry.name for entry in directory.iterdir()}
    if not entries:
        return
    if entries - {"store.db", "kek.json", "store.db-wal", "store.db-shm"} or not {"store.db", "kek.json"} <= entries:
        raise RecoveryError("Recovery requires a complete authenticated empty target.")
    for entry in directory.iterdir():
        info = entry.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RecoveryError("Recovery target contains unsafe entries.")
    store = WrappedKeyStore(directory / "store.db", directory / "kek.json", secrets_key=secrets_key, read_only=True)
    try:
        if any(counts["total"] for counts in store.lifecycle_counts([]).values()):
            raise RecoveryError("Recovery requires an empty native target; preserve existing keys.")
    finally:
        store.close()


def _discard_unjournaled_candidate(name: str, candidate_fd: int, anchor_fd: int) -> None:
    """Remove only the pinned, unpublished flat candidate and flush its parent.

    Args:
        name: Candidate entry name beneath the pinned recovery anchor.
        candidate_fd: Pinned descriptor of the newly created candidate directory.
        anchor_fd: Pinned descriptor of the protected recovery anchor.
    """
    identity = os.fstat(candidate_fd)
    entry = os.stat(name, dir_fd=anchor_fd, follow_symlinks=False)
    if (entry.st_dev, entry.st_ino) != (identity.st_dev, identity.st_ino):
        raise RecoveryError("Recovery candidate identity changed; preserve it for reconciliation.")
    for filename in os.listdir(candidate_fd):
        # unlink never follows a substituted symlink. Unexpected directories fail
        # closed rather than granting recursive deletion beyond candidate files.
        os.unlink(filename, dir_fd=candidate_fd)
    os.fsync(candidate_fd)
    entry = os.stat(name, dir_fd=anchor_fd, follow_symlinks=False)
    if (entry.st_dev, entry.st_ino) != (identity.st_dev, identity.st_ino):
        raise RecoveryError("Recovery candidate identity changed; preserve it for reconciliation.")
    os.rmdir(name, dir_fd=anchor_fd)
    os.fsync(anchor_fd)


def import_archive(archive: bytes, passphrase: str, secrets_key: str, *, uid: int, gid: int) -> dict[str, Any]:
    """Validate, journal, and publish an offline candidate, retaining old state.

    The helper owns daemon quiescence and the appliance transaction lock. Retry
    after a crash uses the same archive; conflicting state remains preserved.

    Args:
        archive: Bounded encrypted recovery bundle supplied by the caller.
        passphrase: Request-bound recovery passphrase, never retained or logged.
        secrets_key: Target appliance credential used only for encrypted master custody.
        uid: Appliance service owner for imported operational files.
        gid: Appliance service group for imported operational files.
    """
    snapshot = decrypt(archive, passphrase)
    digest = hashlib.sha256(archive).hexdigest()
    # Refuse an ordinary populated target before publishing any pending marker.
    # The post-move proof below is still required to catch late writes/substitution.
    if not pending() and STATE.exists():
        if STATE.is_symlink() or not STATE.is_dir():
            raise RecoveryError("Recovery target is not an ordinary directory.")
        _empty_target(STATE, secrets_key)
    anchor_fd = _secure_anchor(ANCHOR)
    parent_fd = os.open(STATE.parent, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
    try:
        journal_path = ANCHOR / "pending.json"
        if journal_path.exists():
            journal = json.loads(journal_path.read_bytes())
            if journal.get("archive") != digest:
                raise RecoveryError("A different recovery is pending; preserve it before retrying.")
            candidate = str(journal["candidate"])
            old = str(journal["old"])
            if not all(isinstance(name, str) and name.startswith(prefix) and len(name) == len(prefix) + 32
                       and all(c in "0123456789abcdef" for c in name[len(prefix):])
                       for name, prefix in ((candidate, "candidate-"), (old, "previous-"))):
                raise RecoveryError("Recovery journal is invalid; reconciliation is required.")
            identity = tuple(journal["identity"])
        else:
            candidate, old = "candidate-" + uuid.uuid4().hex, "previous-" + uuid.uuid4().hex
            os.mkdir(candidate, 0o700, dir_fd=anchor_fd)
            preparing_fd = os.open(candidate, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW, dir_fd=anchor_fd)
            try:
                info = os.fstat(preparing_fd)
                identity = (info.st_dev, info.st_ino)
                try:
                    build_candidate(snapshot, ANCHOR / candidate, secrets_key=secrets_key)
                    journal = {"schema": 1, "archive": digest, "candidate": candidate, "old": old,
                               "identity": identity, "trust": snapshot["trust"]}
                    _journal(ANCHOR, journal)
                except BaseException:
                    # A journal published before a failed fsync still owns the
                    # candidate for retry. Without it, remove this exact candidate.
                    if not os.path.lexists(journal_path):
                        _discard_unjournaled_candidate(candidate, preparing_fd, anchor_fd)
                    raise
            finally:
                os.close(preparing_fd)
        # If publication completed before the previous process stopped, returning
        # the same trust graph is idempotent; the pending marker still blocks I/O.
        try:
            active = os.stat(STATE.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            active = None
        if active is not None and (active.st_dev, active.st_ino) == identity:
            return cast(dict[str, Any], snapshot["trust"])
        if not (ANCHOR / old).exists() and active is not None:
            if not stat.S_ISDIR(active.st_mode):
                raise RecoveryError("Recovery target is not an ordinary directory.")
            # Move first, then validate the exact retained directory under the
            # protected anchor. A concurrent substitution is preserved, not edited.
            _rename_absent(STATE.name, old, parent_fd, anchor_fd)
        if (ANCHOR / old).exists():
            try:
                _empty_target(ANCHOR / old, secrets_key)
            except Exception:
                try:
                    _rename_absent(old, STATE.name, anchor_fd, parent_fd)
                    _rename_absent("pending.json", "rejected-" + uuid.uuid4().hex + ".json", anchor_fd, anchor_fd)
                except OSError:
                    pass  # Preserve both the journal and original for reconciliation.
                raise
        candidate_fd = os.open(candidate, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW, dir_fd=anchor_fd)
        try:
            info = os.fstat(candidate_fd)
            if (info.st_dev, info.st_ino) != identity:
                raise RecoveryError("Recovery candidate identity changed.")
            for name in os.listdir(candidate_fd):
                file_fd = os.open(name, os.O_RDONLY | O_NOFOLLOW, dir_fd=candidate_fd)
                try:
                    info = os.fstat(file_fd)
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                        raise RecoveryError("Recovery candidate ownership is unsafe.")
                    os.fchmod(file_fd, 0o600)
                    if FCHOWN is None:
                        raise RecoveryError("Recovery ownership requires the appliance filesystem contract.")
                    FCHOWN(file_fd, uid, gid)
                    os.fsync(file_fd)
                finally:
                    os.close(file_fd)
            os.fchmod(candidate_fd, 0o700)
            assert FCHOWN is not None
            FCHOWN(candidate_fd, uid, gid)
            os.fsync(candidate_fd)
        finally:
            os.close(candidate_fd)
        _rename_absent(candidate, STATE.name, anchor_fd, parent_fd)
        return cast(dict[str, Any], snapshot["trust"])
    finally:
        os.close(parent_fd)
        os.close(anchor_fd)


def main() -> int:
    """Serve a single bounded helper request; secret values never enter errors."""
    try:
        request = json.loads(sys.stdin.buffer.read(MAX_ARCHIVE_BYTES * 2 + 1))
        if request["action"] in {"service-capture", "service-finish"}:
            print(json.dumps(service_checkpoint(request, finish=request["action"] == "service-finish")))
        elif request["action"] in {"authorize", "complete"}:
            authorize(Path("/etc/atlaso/kmip/server.json"), complete=request["action"] == "complete")
            print(json.dumps({"status": "authorized"}))
        elif request["action"] == "import":
            trust = import_archive(base64.b64decode(request["archive"], validate=True), request["passphrase"],
                                   request["secrets_key"], uid=request["uid"], gid=request["gid"])
            print(json.dumps({"status": "pending-trust-review", "trust": trust}))
        elif request["action"] == "export":
            store = WrappedKeyStore(STATE / "store.db", STATE / "kek.json", secrets_key=request["secrets_key"], read_only=True)
            try:
                archive = encrypt(capture(store, request["trust"]), request["passphrase"])
            finally:
                store.close()
            print(json.dumps({"archive": base64.b64encode(archive).decode("ascii")}))
        else:
            raise RecoveryError("Unsupported recovery operation.")
        return 0
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error, KeyStoreError) as exc:
        del exc
        print("KMIP recovery failed; active and retained state require reconciliation before retry.", file=sys.stderr)
        return 2



if __name__ == "__main__":
    sys.exit(main())
